//! Notificação de mudança de diretório do FsRtl.
//!
//! ntoskrnl 10.0.19045: FsRtlNotifyInitializeSync 0x675fa0 (REAL_NOTIFY_SYNC de
//! 0x48 bytes 'FSrN': FAST_MUTEX, OwningThread, OwnerCount),
//! FsRtlNotifyUninitializeSync 0x6a2c10, FsRtlNotifyFilterChangeDirectory 0x675020
//! (FsRtlNotifyFullChangeDirectory 0x88d5e0 = ele sem FilterCallback),
//! FsRtlNotifyFilterReportChange 0x6746f0 (FsRtlNotifyFullReportChange 0x88d650
//! = ele sem FilterContext), FsRtlNotifyCleanup 0x675b00 e a variante Lite
//! (FsRtlNotifyFilterChangeDirectoryLite 0x675b90,
//! FsRtlNotifyFilterReportChangeLiteEx 0x675380; seção no fim do arquivo).
//!
//! NOTIFY_CHANGE (0x98, PagedPool|RAISE, 'FSrN'; [`NotifyChange`]) ligado em
//! NotifyList pelo seu LIST_ENTRY; os IRPs pendentes ficam na sua segunda
//! lista por Irp->Tail.Overlay.ListEntry. Flags (USHORT): 1 WATCH_TREE,
//! 2 NOTIFY_ENUM_DIR pendente, 4 CLEANUP_CALLED, 8 IGNORE_BUFFER, 0x10 raiz,
//! 0x20 DELETE_PENDING. O IRP pendente guarda o NOTIFY_CHANGE em
//! IoStatus.Information.
//!
//! Os registros acumulados sem IRP pendente (FILE_NOTIFY_INFORMATION) ficam
//! numa tabela por NOTIFY_CHANGE; `buffer` é publicado não nulo enquanto há dados.
//! Ao concluir, o buffer vai num SystemBuffer novo com IRP_BUFFERED_IO |
//! IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION (o I/O Manager copia para o
//! UserBuffer). O IRP pendente não ganha rotina de cancelamento (o NT instala
//! FsRtlCancelNotify): o cancelamento chega pelo cleanup do diretório.
//! Nomes ANSI (CharacterSize 1) são registrados como bytes alargados a WCHAR.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::Ordering;

use crate::hal::amd64::native_call;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{FastMutex, FileObject, IoStackLocation, Irp, Kthread, ListEntry, String as AnsiString};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::io::io_manager;
use crate::ntos::ke::{critical_region, fast_mutex};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u32 = 0;
const STATUS_NOTIFY_CLEANUP: u32 = 0x10B;
const STATUS_NOTIFY_ENUM_DIR: u32 = 0x10C;
const STATUS_DELETE_PENDING: u32 = 0xC000_0056;
const NOTIFY_TAG: u32 = 0x4E72_5346; // 'FSrN'
const WATCH_TREE: u16 = 0x01;
const ENUM_DIR: u16 = 0x02;
const CLEANUP_CALLED: u16 = 0x04;
const IGNORE_BUFFER: u16 = 0x08;
const ROOT_DIRECTORY: u16 = 0x10;
const DELETE_PENDING: u16 = 0x20;
const IRP_BUFFERED_IO: u32 = 0x10;
const IRP_DEALLOCATE_BUFFER: u32 = 0x20;
const IRP_INPUT_OPERATION: u32 = 0x40;
const FO_CLEANUP_COMPLETE: u32 = 0x4000;
const SL_PENDING_RETURNED: u8 = 0x01;
/// Irp->Tail.Overlay.ListEntry: o elo de um IRP na lista do NOTIFY_CHANGE.
const IRP_LIST_ENTRY: u64 = offset_of!(Irp, tail.overlay.list_entry) as u64;
/// NOTIFY_CHANGE.NotifyList: o elo de um NOTIFY_CHANGE na NotifyList do FS.
const NOTIFY_LINKS: u64 = offset_of!(NotifyChange, notify_list) as u64;

/// REAL_NOTIFY_SYNC (privado do FsRtl; o PNOTIFY_SYNC opaco do ntifs.h).
#[repr(C)]
struct RealNotifySync {
    fast_mutex: FastMutex,
    owning_thread: Field<u64>,
    owner_count: Field<u32>,
    _pad_44: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for RealNotifySync {}

/// NOTIFY_CHANGE (privado do FsRtl, layout do 19045; +0x50 e +0x64 não são
/// usados por este motor).
#[repr(C)]
struct NotifyChange {
    notify_sync: Field<u64>,
    fs_context: Field<u64>,
    traverse_callback: Field<u64>,
    subject_context: Field<u64>,
    notify_list: ListEntry,
    notify_irps: ListEntry,
    filter_callback: Field<u64>,
    flags: Field<u16>,
    _pad_4a: Reserved<0x2>,
    completion_filter: Field<u32>,
    _pad_50: Reserved<0x10>,
    this_buffer_length: Field<u32>,
    /// Limite capturado com o primeiro registro pendente (Lite).
    buffer_limit: Field<u32>,
    buffer: Field<u64>,
    reference_count: Field<u32>,
    _pad_74: Reserved<0x4>,
    owning_process: Field<u64>,
    file_fs_context: Field<u64>,
    full_directory_name: Field<u64>,
    character_size: Field<u8>,
    _pad_91: Reserved<0x7>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for NotifyChange {}

const _: () = {
    assert!(core::mem::size_of::<RealNotifySync>() == 0x48);
    assert!(core::mem::offset_of!(RealNotifySync, owning_thread) == 0x38);
    assert!(core::mem::offset_of!(RealNotifySync, owner_count) == 0x40);
    assert!(core::mem::size_of::<NotifyChange>() == 0x98);
    assert!(core::mem::offset_of!(NotifyChange, notify_list) == 0x20);
    assert!(core::mem::offset_of!(NotifyChange, notify_irps) == 0x30);
    assert!(core::mem::offset_of!(NotifyChange, flags) == 0x48);
    assert!(core::mem::offset_of!(NotifyChange, completion_filter) == 0x4C);
    assert!(core::mem::offset_of!(NotifyChange, this_buffer_length) == 0x60);
    assert!(core::mem::offset_of!(NotifyChange, buffer) == 0x68);
    assert!(core::mem::offset_of!(NotifyChange, reference_count) == 0x70);
    assert!(core::mem::offset_of!(NotifyChange, owning_process) == 0x78);
    assert!(core::mem::offset_of!(NotifyChange, full_directory_name) == 0x88);
    assert!(core::mem::offset_of!(NotifyChange, character_size) == 0x90);
};

/// Registros FILE_NOTIFY_INFORMATION ainda sem IRP, por NOTIFY_CHANGE.
static PENDING: SpinLock<BTreeMap<u64, Vec<u8>>> = SpinLock::new(BTreeMap::new());

fn sync_at(address: u64) -> &'static RealNotifySync {
    // SAFETY: o PNOTIFY_SYNC criado por `initialize_sync`.
    unsafe { RealNotifySync::at(address) }
}

fn notify_at(address: u64) -> &'static NotifyChange {
    // SAFETY: NOTIFY_CHANGE criado por `create_notify` e ainda referenciado.
    unsafe { NotifyChange::at(address) }
}

fn list_at(address: u64) -> &'static ListEntry {
    // SAFETY: elos de uma lista viva do FsRtl (NotifyList do FS ou a lista de IRPs).
    unsafe { ListEntry::at(address) }
}

fn irp_at(address: u64) -> &'static Irp {
    // SAFETY: IRP_MJ_DIRECTORY_CONTROL vivo, do FS ou da lista de pendentes.
    unsafe { Irp::at(address) }
}

fn current_stack(irp: &Irp) -> &'static IoStackLocation {
    // SAFETY: o slot corrente do IRP que o FS está processando.
    unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) }
}

// ---- NOTIFY_SYNC ------------------------------------------------------------------

/// FsRtlNotifyInitializeSync(*NotifySync).
pub fn initialize_sync(output: &Field<u64>) -> Result<(), KernelError> {
    output.set(0);
    let address = pool_allocation::allocate_tagged(0x210, RealNotifySync::SIZE, NOTIFY_TAG)?;
    if address == 0 {
        return Err(KernelError::with_status("FsRtlNotifyInitializeSync: no memory", 0xC000_009A));
    }
    let sync = sync_at(address);
    fast_mutex::initialize(sync.fast_mutex.address());
    sync.owning_thread.set(0);
    sync.owner_count.set(0);
    output.set(address);
    Ok(())
}

/// FsRtlNotifyUninitializeSync(*NotifySync).
pub fn uninitialize_sync(pointer: &Field<u64>) -> Result<(), KernelError> {
    let sync = pointer.get();
    if sync != 0 {
        invoke_handler("ExFreePool", &[sync])?;
        pointer.set(0);
    }
    Ok(())
}

/// AcquireNotifySync: recursivo para a thread dona. O ExAcquireFastMutexUnsafe
/// do NT supõe APCs desligadas pelo chamador (os FSs chamam dentro de região
/// crítica); a região crítica aqui garante o mesmo para quem não o faz.
fn acquire(sync: &RealNotifySync) -> Result<(), KernelError> {
    let thread = process::get_current_thread();
    critical_region::enter_critical()?;
    if sync.owning_thread.atomic().load(Ordering::Acquire) != thread {
        fast_mutex::acquire_unsafe(sync.fast_mutex.address())?;
        sync.owning_thread.atomic().store(thread, Ordering::Release);
    }
    sync.owner_count.atomic().fetch_add(1, Ordering::AcqRel);
    Ok(())
}

fn release(sync: &RealNotifySync) -> Result<(), KernelError> {
    if sync.owner_count.atomic().fetch_sub(1, Ordering::AcqRel) == 1 {
        sync.owning_thread.atomic().store(0, Ordering::Release);
        fast_mutex::release_unsafe(sync.fast_mutex.address())?;
    }
    critical_region::leave_critical()
}

fn with_sync<T>(sync: u64, body: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    let sync = sync_at(sync);
    acquire(sync)?;
    let result = body();
    release(sync)?;
    result
}

// ---- listas -----------------------------------------------------------------------

fn list_entries(head: &ListEntry) -> Vec<u64> {
    let mut entries = Vec::new();
    let mut cursor = head.flink.get();
    while cursor != head.address() && cursor != 0 && entries.len() < 0x10000 {
        entries.push(cursor);
        cursor = list_at(cursor).flink.get();
    }
    entries
}

fn insert_tail(head: &ListEntry, entry: &ListEntry) -> Result<(), KernelError> {
    let last = list_at(head.blink.get());
    if last.flink.get() != head.address() {
        return Err(KernelError::new("FAST_FAIL_CORRUPT_LIST_ENTRY in a notify list"));
    }
    entry.flink.set(head.address());
    entry.blink.set(last.address());
    last.flink.set(entry.address());
    head.blink.set(entry.address());
    Ok(())
}

fn remove_entry(entry: &ListEntry) {
    let (next, previous) = (list_at(entry.flink.get()), list_at(entry.blink.get()));
    previous.flink.set(next.address());
    next.blink.set(previous.address());
    entry.flink.set(entry.address());
    entry.blink.set(entry.address());
}

fn set_flags(notify: &NotifyChange, set: u16, clear: u16) {
    let _ = notify.flags.atomic().try_update(Ordering::AcqRel, Ordering::Acquire, |flags| Some((flags | set) & !clear));
}

/// FsRtlIsNotifyOnList: o NOTIFY_CHANGE do FsContext.
fn notify_on_list(list: &ListEntry, fs_context: u64) -> Option<&'static NotifyChange> {
    list_entries(list).into_iter().map(|links| notify_at(links - NOTIFY_LINKS)).find(|notify| notify.fs_context.get() == fs_context)
}

fn mark_pending(irp: &Irp) {
    current_stack(irp).control.atomic().fetch_or(SL_PENDING_RETURNED, Ordering::SeqCst);
}

fn complete(irp: &Irp, status: u32, information: u64) {
    mark_pending(irp);
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(information);
    io_manager::iof_complete_request(irp.address());
}

/// FsRtlNotifyCompleteIrp: o buffer num SystemBuffer novo (buffered I/O de saída).
fn complete_with_data(irp: &Irp, data: &[u8]) -> Result<(), KernelError> {
    if data.is_empty() {
        complete(irp, STATUS_SUCCESS, 0);
        return Ok(());
    }
    let buffer = guest::alloc_bytes(data.len() as u64);
    if buffer == 0 {
        complete(irp, STATUS_NOTIFY_ENUM_DIR, 0);
        return Ok(());
    }
    guest::write_bytes(buffer, data);
    irp.associated_irp.system_buffer.set(buffer);
    irp.flags.atomic().fetch_or(IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION, Ordering::SeqCst);
    complete(irp, STATUS_SUCCESS, data.len() as u64);
    Ok(())
}

fn take_pending(notify: &NotifyChange) -> Vec<u8> {
    notify.buffer.set(0);
    PENDING.lock().remove(&notify.address()).unwrap_or_default()
}

/// Retira o primeiro IRP pendente (o elo vira lista vazia, como RemoveHeadList).
fn first_irp(notify: &NotifyChange) -> Option<&'static Irp> {
    let entry = *list_entries(&notify.notify_irps).first()?;
    remove_entry(list_at(entry));
    Some(irp_at(entry - IRP_LIST_ENTRY))
}

/// Retira e conclui os IRPs pendentes de um NOTIFY_CHANGE.
fn complete_all(notify: &NotifyChange, status: u32) {
    while let Some(irp) = first_irp(notify) {
        complete(irp, status, 0);
        dereference(notify);
    }
}

/// Solta uma referência; a última libera o SubjectContext e o bloco.
fn dereference(notify: &NotifyChange) {
    let previous = notify.reference_count.atomic().try_update(Ordering::AcqRel, Ordering::Acquire, |count| Some(count.saturating_sub(1))).unwrap_or(0);
    if previous > 1 {
        return;
    }
    PENDING.lock().remove(&notify.address());
    let subject = notify.subject_context.get();
    if subject != 0 {
        let _ = invoke_handler("SeReleaseSubjectContext", &[subject]);
        let _ = invoke_handler("ExFreePool", &[subject]);
    }
    let _ = invoke_handler("ExFreePool", &[notify.address()]);
}

// ---- FsRtlNotifyFilterChangeDirectory ----------------------------------------------

/// Parâmetros de FsRtlNotifyFilterChangeDirectory (os de FullChangeDirectory
/// com FilterCallback 0). `notify_sync`, os callbacks, o SubjectContext e o
/// nome ficam como ponteiros opacos guardados no NOTIFY_CHANGE.
pub struct ChangeDirectory<'a> {
    pub notify_sync: u64,
    pub notify_list: &'a ListEntry,
    pub fs_context: u64,
    pub full_directory_name: u64,
    pub watch_tree: bool,
    pub ignore_buffer: bool,
    pub completion_filter: u32,
    pub irp: Option<&'a Irp>,
    pub traverse_callback: u64,
    pub subject_context: u64,
    pub filter_callback: u64,
}

fn queue_irp(notify: &NotifyChange, irp: &Irp) -> Result<(), KernelError> {
    irp.io_status.information.set(notify.address());
    mark_pending(irp);
    insert_tail(&notify.notify_irps, &irp.tail.overlay.list_entry)?;
    notify.reference_count.atomic().fetch_add(1, Ordering::AcqRel);
    Ok(())
}

/// STRING/UNICODE_STRING do nome do diretório: (Length, primeira unidade
/// tem byte alto zero?) para decidir CharacterSize.
fn directory_name_shape(name: u64) -> Option<(u16, bool)> {
    if name == 0 {
        return None;
    }
    // SAFETY: o PSTRING FullDirectoryName do FS (mesmo layout de UNICODE_STRING).
    let string = unsafe { AnsiString::at(name) };
    let length = string.length.get();
    let wide = length >= 2 && guest::read_bytes(string.buffer.get(), 2).get(1) == Some(&0);
    Some((length, wide))
}

fn create_notify(change: &ChangeDirectory, irp: &Irp, stack: &IoStackLocation) -> Result<&'static NotifyChange, KernelError> {
    let address = pool_allocation::allocate_tagged(0x11, NotifyChange::SIZE, NOTIFY_TAG)?;
    guest::write_bytes(address, &[0u8; NotifyChange::SIZE as usize]);
    let notify = notify_at(address);
    notify.notify_sync.set(change.notify_sync);
    notify.fs_context.set(change.fs_context);
    let file = stack.file_object.get();
    // SAFETY: o FILE_OBJECT do diretório no slot corrente.
    notify.file_fs_context.set(if file != 0 { unsafe { FileObject::at(file) }.fs_context.get() } else { 0 });
    notify.traverse_callback.set(change.traverse_callback);
    notify.subject_context.set(change.subject_context);
    notify.filter_callback.set(change.filter_callback);
    notify.full_directory_name.set(change.full_directory_name);
    notify.notify_irps.flink.set(notify.notify_irps.address());
    notify.notify_irps.blink.set(notify.notify_irps.address());
    let mut flags = if change.watch_tree { WATCH_TREE } else { 0 };
    let mut character_size: u16 = 1;
    if let Some((length, wide)) = directory_name_shape(change.full_directory_name) {
        if wide {
            character_size = 2;
        }
        if length == character_size {
            flags |= ROOT_DIRECTORY;
        }
    }
    if change.ignore_buffer {
        flags |= IGNORE_BUFFER;
    } else {
        notify.this_buffer_length.set(stack.parameters.notify_directory.length.get());
    }
    notify.character_size.set(character_size as u8);
    notify.flags.set(flags);
    notify.completion_filter.set(change.completion_filter);
    let thread = irp.tail.overlay.thread.get();
    // SAFETY: a thread do IRP (KTHREAD.Process = o processo dono).
    notify.owning_process.set(if thread != 0 { unsafe { Kthread::at(thread) }.process.get() } else { 0 });
    insert_tail(change.notify_list, &notify.notify_list)?;
    notify.reference_count.set(1);
    Ok(notify)
}

/// FsRtlCheckNotifyForDelete: o stream sumiu; os IRPs pendentes recebem
/// STATUS_DELETE_PENDING e o NOTIFY_CHANGE fica marcado.
fn check_for_delete(list: &ListEntry, fs_context: u64) {
    if let Some(notify) = notify_on_list(list, fs_context) {
        set_flags(notify, DELETE_PENDING, 0);
        complete_all(notify, STATUS_DELETE_PENDING);
    }
}

/// FsRtlNotifyFilterChangeDirectory / FsRtlNotifyFullChangeDirectory.
pub fn filter_change_directory(change: &ChangeDirectory) -> Result<(), KernelError> {
    if change.irp.is_none() && change.notify_list.flink.get() == change.notify_list.address() {
        return Ok(());
    }
    let mut subject_taken = false;
    let result = with_sync(change.notify_sync, || {
        let Some(irp) = change.irp else {
            check_for_delete(change.notify_list, change.fs_context);
            return Ok(());
        };
        irp.io_status.status.set(0);
        irp.io_status.information.set(0);
        let stack = current_stack(irp);
        let file = stack.file_object.get();
        // SAFETY: o FILE_OBJECT do diretório no slot corrente.
        if file != 0 && unsafe { FileObject::at(file) }.flags.get() & FO_CLEANUP_COMPLETE != 0 {
            complete(irp, STATUS_NOTIFY_CLEANUP, 0);
            return Ok(());
        }
        let notify = match notify_on_list(change.notify_list, change.fs_context) {
            Some(notify) => {
                let current = notify.flags.get();
                if current & CLEANUP_CALLED != 0 {
                    complete(irp, STATUS_NOTIFY_CLEANUP, 0);
                    return Ok(());
                }
                if current & DELETE_PENDING != 0 {
                    complete(irp, STATUS_DELETE_PENDING, 0);
                    return Ok(());
                }
                if current & ENUM_DIR != 0 && current & IGNORE_BUFFER == 0 {
                    set_flags(notify, 0, ENUM_DIR);
                    complete(irp, STATUS_NOTIFY_ENUM_DIR, 0);
                    return Ok(());
                }
                if notify.buffer.get() != 0 && current & IGNORE_BUFFER == 0 {
                    let data = take_pending(notify);
                    return complete_with_data(irp, &data);
                }
                notify
            }
            None => {
                subject_taken = true;
                create_notify(change, irp, stack)?
            }
        };
        queue_irp(notify, irp)
    });
    if !subject_taken && change.subject_context != 0 && change.full_directory_name != 0 {
        invoke_handler("SeReleaseSubjectContext", &[change.subject_context])?;
        invoke_handler("ExFreePool", &[change.subject_context])?;
    }
    result
}

// ---- FsRtlNotifyFullReportChange ---------------------------------------------------

fn read_units(string: u64, character_size: u8) -> Vec<u16> {
    if string == 0 {
        return Vec::new();
    }
    // SAFETY: PSTRING/PUNICODE_STRING do FS (mesmo layout).
    let string = unsafe { AnsiString::at(string) };
    let bytes = guest::read_bytes(string.buffer.get(), string.length.get() as usize);
    if character_size == 1 {
        bytes.iter().map(|&byte| byte as u16).collect()
    } else {
        bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()
    }
}

/// O nome relativo ao diretório observado, ou `None` se a mudança não é dele.
fn relative_name(notify: &NotifyChange, target: &[u16], offset: usize, parent: &[u16]) -> Option<Vec<u16>> {
    let directory = read_units(notify.full_directory_name.get(), notify.character_size.get());
    let flags = notify.flags.get();
    let (watch_tree, root) = (flags & WATCH_TREE != 0, flags & ROOT_DIRECTORY != 0);
    if parent == directory.as_slice() {
        return Some(target[offset..].to_vec());
    }
    if !watch_tree {
        return None;
    }
    if root {
        return Some(target.get(1..)?.to_vec());
    }
    let prefixed = target.len() > directory.len() && target[..directory.len()] == directory[..] && target[directory.len()] == b'\\' as u16;
    if !prefixed || offset <= directory.len() {
        return None;
    }
    Some(target[directory.len() + 1..].to_vec())
}

/// FILE_NOTIFY_INFORMATION sem preenchimento final (o DataLength do NT soma
/// o registro inteiro; o alinhamento a 4 vem antes do próximo).
fn notify_record(action: u32, name: &[u16]) -> Vec<u8> {
    let mut record = alloc::vec![0u8; 12 + name.len() * 2];
    record[4..8].copy_from_slice(&action.to_le_bytes());
    record[8..12].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        record[12 + index * 2..14 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    record
}

/// Alinha o fim dos dados a 4 (zeros), encadeia o NextEntryOffset do último
/// registro até ali e acrescenta o novo, como o FsRtlNotifyUpdateBuffer.
fn append_record(buffer: &mut Vec<u8>, record: &[u8]) {
    if !buffer.is_empty() {
        let mut cursor = 0;
        loop {
            let next = u32::from_le_bytes([buffer[cursor], buffer[cursor + 1], buffer[cursor + 2], buffer[cursor + 3]]) as usize;
            if next == 0 {
                break;
            }
            cursor += next;
        }
        buffer.resize(aligned_length(buffer.len()), 0);
        let distance = (buffer.len() - cursor) as u32;
        buffer[cursor..cursor + 4].copy_from_slice(&distance.to_le_bytes());
    }
    buffer.extend_from_slice(record);
}

/// O DataLength arredondado para 4 (o início do próximo registro).
fn aligned_length(length: usize) -> usize {
    (length + 3) & !3
}

/// Parâmetros de FsRtlNotifyFilterReportChange (FsRtlNotifyFullReportChange
/// é ele com FilterContext NULL). Os nomes são PSTRING opacos, lidos conforme
/// o CharacterSize de cada NOTIFY_CHANGE.
pub struct ReportChange<'a> {
    pub notify_sync: u64,
    pub notify_list: &'a ListEntry,
    pub full_target_name: u64,
    pub target_name_offset: u16,
    pub stream_name: u64,
    pub normalized_parent_name: u64,
    pub filter_match: u32,
    pub action: u32,
    pub target_context: u64,
    pub filter_context: u64,
}

/// Sem espaço (IgnoreBuffer ou buffer cheio): o IRP pendente sai com
/// STATUS_NOTIFY_ENUM_DIR; sem IRP, o NOTIFY_CHANGE guarda o ENUM_DIR.
fn overflow(notify: &NotifyChange) {
    match first_irp(notify) {
        Some(irp) => {
            complete(irp, STATUS_NOTIFY_ENUM_DIR, 0);
            dereference(notify);
        }
        None => set_flags(notify, ENUM_DIR, 0),
    }
}

/// O nome registrado para um NOTIFY_CHANGE com FullTargetName, ou `None` se a
/// mudança não é dele (CompletionFilter, caminho, TraverseCallback ou
/// FilterCallback recusam).
fn matching_name(notify: &NotifyChange, report: &ReportChange) -> Option<Vec<u16>> {
    if notify.completion_filter.get() & report.filter_match == 0 {
        return None;
    }
    let character_size = notify.character_size.get().max(1);
    let target = read_units(report.full_target_name, character_size);
    let offset = (report.target_name_offset / character_size as u16) as usize;
    if offset > target.len() {
        return None;
    }
    let parent: Vec<u16> = if report.normalized_parent_name != 0 {
        read_units(report.normalized_parent_name, character_size)
    } else if offset <= 1 {
        target[..offset.min(1)].to_vec()
    } else {
        target[..offset - 1].to_vec()
    };
    let mut name = relative_name(notify, &target, offset, &parent)?;
    // Mudança numa subárvore: o TraverseCallback do FS (BOOLEAN) decide a
    // visibilidade.
    let traverse = notify.traverse_callback.get();
    if traverse != 0 && name.len() != target.len() - offset && native_call::call(traverse, &[notify.fs_context.get(), report.target_context, notify.subject_context.get()]) & 0xFF == 0 {
        return None;
    }
    // O FilterCallback só é consultado com FilterContext (o FullReportChange
    // passa NULL e nunca o chama).
    let filter = notify.filter_callback.get();
    if filter != 0 && report.filter_context != 0 && native_call::call(filter, &[notify.fs_context.get(), report.filter_context]) & 0xFF == 0 {
        return None;
    }
    let stream = read_units(report.stream_name, character_size);
    if !stream.is_empty() {
        name.push(b':' as u16);
        name.extend_from_slice(&stream);
    }
    Some(name)
}

/// FsRtlNotifyFilterReportChange / FsRtlNotifyFullReportChange: para cada
/// NOTIFY_CHANGE do diretório (ou de um ancestral com WatchTree) cujo
/// CompletionFilter casa, monta o FILE_NOTIFY_INFORMATION e conclui o IRP
/// pendente ou acumula. TargetNameOffset 0 com nome é ignorado. Sem
/// FullTargetName, o NOTIFY_CHANGE é o de SubjectContext == TargetContext e o
/// registro leva só o StreamName (sem filtro nem callbacks), como no NT.
pub fn full_report_change(report: &ReportChange) -> Result<(), KernelError> {
    if report.target_name_offset == 0 && report.full_target_name != 0 {
        return Ok(());
    }
    if report.notify_list.flink.get() == report.notify_list.address() {
        return Ok(());
    }
    with_sync(report.notify_sync, || {
        for links in list_entries(report.notify_list) {
            let notify = notify_at(links - NOTIFY_LINKS);
            let current = notify.flags.get();
            if current & (CLEANUP_CALLED | DELETE_PENDING) != 0 {
                continue;
            }
            let name = if report.full_target_name == 0 {
                if notify.subject_context.get() != report.target_context {
                    continue;
                }
                read_units(report.stream_name, notify.character_size.get().max(1))
            } else {
                let Some(name) = matching_name(notify, report) else { continue };
                name
            };
            if current & IGNORE_BUFFER != 0 {
                overflow(notify);
                continue;
            }
            let record = notify_record(report.action, &name);
            let mut data = take_pending(notify);
            append_record(&mut data, &record);
            if data.len() > notify.this_buffer_length.get() as usize {
                overflow(notify);
                continue;
            }
            match first_irp(notify) {
                Some(irp) => {
                    complete_with_data(irp, &data)?;
                    dereference(notify);
                }
                None => {
                    notify.buffer.set(1);
                    PENDING.lock().insert(notify.address(), data);
                }
            }
        }
        Ok(())
    })
}

/// FsRtlNotifyCleanup(NotifySync, NotifyList, FsContext): CLEANUP_CALLED, IRPs
/// pendentes com STATUS_NOTIFY_CLEANUP e o NOTIFY_CHANGE sai da lista.
pub fn cleanup(sync: u64, list: &ListEntry, fs_context: u64) -> Result<(), KernelError> {
    with_sync(sync, || {
        let Some(notify) = notify_on_list(list, fs_context) else { return Ok(()) };
        set_flags(notify, CLEANUP_CALLED, 0);
        complete_all(notify, STATUS_NOTIFY_CLEANUP);
        remove_entry(&notify.notify_list);
        dereference(notify);
        Ok(())
    })
}

// ---- Variante Lite -----------------------------------------------------------------
//
// ntoskrnl 10.0.19041: FsRtlNotifyFilterChangeDirectoryLite 0x675b90 e
// FsRtlNotifyFilterReportChangeLiteEx 0x675380 (com FsRtlCheckNotifyForDeleteLite
// 0x88d404, FsRtlNotifyCompleteIrpList 0x6758e8 e FsRtlNotifyCompleteIrp
// 0x675984). O NOTIFY_CHANGE Lite tem só os primeiros 0x80 bytes (sem nome de
// diretório: a casa é pelo FsContext e pela flag "no próprio diretório" do
// relato) e leva a flag 0x40. O PNOTIFY_SYNC vem por ponteiro e é criado na
// primeira chamada (InterlockedCompareExchange; quem perde a corrida
// libera o seu). Flags da criação: 1 WatchTree, 2 sem buffer (BufferLength
// fica 0, todo relato vira STATUS_NOTIFY_ENUM_DIR), 4 registros estendidos
// (FILE_NOTIFY_EXTENDED_INFORMATION, flag 0x80 no NOTIFY_CHANGE). No relato,
// o bit 8 do NOTIFY_CHANGE segura a conclusão entre um
// FILE_ACTION_RENAMED_OLD_NAME e o próximo registro. O NT escreve os
// registros direto no buffer do IRP pendente ou num pool cobrado do processo
// dono; aqui eles ficam na tabela de pendentes deste motor e vão ao IRP pelo
// SystemBuffer na conclusão, como no resto do arquivo.

const LITE: u16 = 0x40;
const RENAME_HOLD: u16 = 0x08;
const EXTENDED_RECORDS: u16 = 0x80;
const LITE_NOTIFY_SIZE: u64 = 0x80;
const LITE_WATCH_TREE: u32 = 0x01;
const LITE_NO_BUFFER: u32 = 0x02;
const LITE_EXTENDED: u32 = 0x04;
/// No relato: a mudança é no próprio diretório observado (sem WatchTree nem
/// TraverseCallback).
const LITE_REPORT_IN_DIRECTORY: u32 = 0x01;
const FILE_ACTION_RENAMED_OLD_NAME: u32 = 4;
/// FILE_NOTIFY_EXTENDED_INFORMATION até FileName.
const EXTENDED_RECORD_HEADER: usize = 0x54;
/// FILE_NOTIFY_INFORMATION até FileName.
const RECORD_HEADER: usize = 0x0C;
/// O bloco de informação estendida do relato tem pelo menos 0x50 bytes.
const EXTENDED_INFORMATION_MINIMUM: u32 = 0x50;

/// *NotifySync, criado na primeira chamada.
fn lite_sync(pointer: &Field<u64>) -> Result<u64, KernelError> {
    if pointer.get() == 0 {
        let created = guest::alloc_bytes(8);
        // SAFETY: célula de rascunho recém-alocada.
        let cell = unsafe { Field::<u64>::at(created) };
        let result = initialize_sync(cell).map(|()| cell.get());
        guest::free_bytes(created);
        let sync = result?;
        if pointer.atomic().compare_exchange(0, sync, Ordering::AcqRel, Ordering::Acquire).is_err() {
            invoke_handler("ExFreePool", &[sync])?;
        }
    }
    Ok(pointer.get())
}

/// Parâmetros de FsRtlNotifyFilterChangeDirectoryLite.
pub struct ChangeDirectoryLite<'a> {
    pub notify_sync: &'a Field<u64>,
    pub notify_list: &'a ListEntry,
    pub fs_context: u64,
    pub flags: u32,
    pub completion_filter: u32,
    pub irp: Option<&'a Irp>,
    pub traverse_callback: u64,
    pub subject_context: u64,
    pub filter_callback: u64,
}

/// FsRtlNotifyCompleteIrp com status 0: sem dados ou com mais dados que o
/// buffer do pedido, STATUS_NOTIFY_ENUM_DIR; senão os registros.
fn complete_lite(irp: &Irp, data: &[u8]) -> Result<(), KernelError> {
    let length = current_stack(irp).parameters.notify_directory.length.get() as usize;
    if data.is_empty() || data.len() > length {
        complete(irp, STATUS_NOTIFY_ENUM_DIR, 0);
        return Ok(());
    }
    complete_with_data(irp, data)
}

/// Retira os registros pendentes de um NOTIFY_CHANGE Lite (o limite
/// capturado volta a zero).
fn take_pending_lite(notify: &NotifyChange) -> Vec<u8> {
    notify.buffer_limit.set(0);
    take_pending(notify)
}

/// FsRtlNotifyCompleteIrpList(Notify, 0): ENUM_DIR sai, e o primeiro IRP
/// pendente leva os registros (ou STATUS_NOTIFY_ENUM_DIR sem eles).
fn complete_first_lite(notify: &NotifyChange) -> Result<(), KernelError> {
    let data = take_pending_lite(notify);
    set_flags(notify, 0, ENUM_DIR);
    if let Some(irp) = first_irp(notify) {
        complete_lite(irp, &data)?;
        dereference(notify);
    }
    Ok(())
}

fn create_notify_lite(change: &ChangeDirectoryLite, irp: &Irp, stack: &IoStackLocation) -> Result<&'static NotifyChange, KernelError> {
    let address = pool_allocation::allocate_tagged(0x11, LITE_NOTIFY_SIZE, NOTIFY_TAG)?;
    guest::write_bytes(address, &[0u8; LITE_NOTIFY_SIZE as usize]);
    let notify = notify_at(address);
    let mut flags = LITE;
    notify.notify_sync.set(change.notify_sync.get());
    notify.fs_context.set(change.fs_context);
    notify.traverse_callback.set(change.traverse_callback);
    notify.subject_context.set(change.subject_context);
    notify.filter_callback.set(change.filter_callback);
    notify.notify_irps.flink.set(notify.notify_irps.address());
    notify.notify_irps.blink.set(notify.notify_irps.address());
    if change.flags & LITE_WATCH_TREE != 0 {
        flags |= WATCH_TREE;
    }
    if change.flags & LITE_EXTENDED != 0 {
        flags |= EXTENDED_RECORDS;
    }
    notify.completion_filter.set(change.completion_filter);
    if change.flags & LITE_NO_BUFFER == 0 {
        notify.this_buffer_length.set(stack.parameters.notify_directory.length.get());
    }
    notify.flags.set(flags);
    let thread = irp.tail.overlay.thread.get();
    // SAFETY: a thread do IRP (KTHREAD.Process = o processo dono).
    notify.owning_process.set(if thread != 0 { unsafe { Kthread::at(thread) }.process.get() } else { 0 });
    insert_tail(change.notify_list, &notify.notify_list)?;
    notify.reference_count.set(1);
    Ok(notify)
}

/// FsRtlCheckNotifyForDeleteLite: todo NOTIFY_CHANGE da lista fica
/// DELETE_PENDING e os IRPs pendentes saem com STATUS_DELETE_PENDING.
fn check_for_delete_lite(list: &ListEntry) {
    for links in list_entries(list) {
        let notify = notify_at(links - NOTIFY_LINKS);
        set_flags(notify, DELETE_PENDING, 0);
        complete_all(notify, STATUS_DELETE_PENDING);
    }
}

/// FsRtlNotifyFilterChangeDirectoryLite.
pub fn filter_change_directory_lite(change: &ChangeDirectoryLite) -> Result<(), KernelError> {
    if change.irp.is_none() && change.notify_list.flink.get() == change.notify_list.address() {
        return Ok(());
    }
    let sync = lite_sync(change.notify_sync)?;
    let mut subject_taken = false;
    let result = with_sync(sync, || {
        let Some(irp) = change.irp else {
            check_for_delete_lite(change.notify_list);
            return Ok(());
        };
        irp.io_status.status.set(0);
        irp.io_status.information.set(0);
        let stack = current_stack(irp);
        let file = stack.file_object.get();
        // SAFETY: o FILE_OBJECT do diretório no slot corrente.
        if file != 0 && unsafe { FileObject::at(file) }.flags.get() & FO_CLEANUP_COMPLETE != 0 {
            complete(irp, STATUS_NOTIFY_CLEANUP, 0);
            return Ok(());
        }
        let notify = match notify_on_list(change.notify_list, change.fs_context) {
            Some(notify) => {
                let current = notify.flags.get();
                if current & CLEANUP_CALLED != 0 {
                    complete(irp, STATUS_NOTIFY_CLEANUP, 0);
                    return Ok(());
                }
                if current & DELETE_PENDING != 0 {
                    complete(irp, STATUS_DELETE_PENDING, 0);
                    return Ok(());
                }
                let held = current & RENAME_HOLD != 0;
                if current & ENUM_DIR != 0 && !held {
                    set_flags(notify, 0, ENUM_DIR);
                    complete(irp, STATUS_NOTIFY_ENUM_DIR, 0);
                    return Ok(());
                }
                if notify.buffer.get() != 0 && !held {
                    let data = take_pending_lite(notify);
                    return complete_lite(irp, &data);
                }
                notify
            }
            None => {
                subject_taken = true;
                create_notify_lite(change, irp, stack)?
            }
        };
        queue_irp(notify, irp)
    });
    if !subject_taken && change.subject_context != 0 {
        invoke_handler("SeReleaseSubjectContext", &[change.subject_context])?;
        invoke_handler("ExFreePool", &[change.subject_context])?;
    }
    result
}

/// Parâmetros de FsRtlNotifyFilterReportChangeLiteEx. `name` e `stream_name`
/// são PUNICODE_STRING; `extended_information` aponta os campos copiados para
/// um FILE_NOTIFY_EXTENDED_INFORMATION (Size >= 0x50 no primeiro ULONG).
pub struct ReportChangeLite<'a> {
    pub notify_sync: &'a Field<u64>,
    pub notify_list: &'a ListEntry,
    pub name: u64,
    pub stream_name: u64,
    pub filter_match: u32,
    pub action: u32,
    pub target_context: u64,
    pub filter_context: u64,
    pub flags: u32,
    pub extended_information: u64,
}

fn unicode_bytes(string: u64) -> Vec<u8> {
    if string == 0 {
        return Vec::new();
    }
    // SAFETY: PUNICODE_STRING do FS (mesmo layout de STRING).
    let string = unsafe { AnsiString::at(string) };
    guest::read_bytes(string.buffer.get(), string.length.get() as usize)
}

/// FILE_NOTIFY_INFORMATION ou FILE_NOTIFY_EXTENDED_INFORMATION com o nome e,
/// havendo, ':' e o stream.
fn lite_record(report: &ReportChangeLite, extended: bool) -> Vec<u8> {
    let mut name = unicode_bytes(report.name);
    if report.stream_name != 0 {
        name.extend_from_slice(&(b':' as u16).to_le_bytes());
        name.extend_from_slice(&unicode_bytes(report.stream_name));
    }
    let header = if extended { EXTENDED_RECORD_HEADER } else { RECORD_HEADER };
    let mut record = alloc::vec![0u8; header];
    record[4..8].copy_from_slice(&report.action.to_le_bytes());
    if extended {
        // CreationTime..ParentFileId: os bytes 8..0x50 do bloco do chamador.
        record[8..0x50].copy_from_slice(&guest::read_bytes(report.extended_information + 8, 0x48));
    }
    record[header - 4..header].copy_from_slice(&(name.len() as u32).to_le_bytes());
    record.extend_from_slice(&name);
    record
}

/// O limite do buffer de um relato: o capturado com o primeiro registro
/// pendente, senão o comprimento do primeiro IRP pendente, senão o
/// BufferLength da criação.
fn lite_limit(notify: &NotifyChange) -> u32 {
    let captured = notify.buffer_limit.get();
    if captured != 0 {
        return captured;
    }
    match list_entries(&notify.notify_irps).first() {
        Some(&entry) => current_stack(irp_at(entry - IRP_LIST_ENTRY)).parameters.notify_directory.length.get(),
        None => notify.this_buffer_length.get(),
    }
}

/// Acrescenta o registro ou, sem espaço, liga ENUM_DIR e descarta o pendente.
fn record_lite(notify: &NotifyChange, report: &ReportChangeLite) {
    let record = lite_record(report, notify.flags.get() & EXTENDED_RECORDS != 0);
    let limit = lite_limit(notify) as usize;
    let mut data = take_pending(notify);
    if record.len() > limit || aligned_length(data.len()) + record.len() > limit {
        set_flags(notify, ENUM_DIR, 0);
        notify.buffer_limit.set(0);
        return;
    }
    append_record(&mut data, &record);
    notify.buffer_limit.set(limit as u32);
    notify.buffer.set(1);
    PENDING.lock().insert(notify.address(), data);
}

/// FsRtlNotifyFilterReportChangeLiteEx.
pub fn filter_report_change_lite(report: &ReportChangeLite) -> Result<(), KernelError> {
    if report.notify_list.flink.get() == report.notify_list.address() {
        return Ok(());
    }
    // SAFETY: o bloco de informação estendida do FS (o primeiro ULONG é o tamanho).
    if report.extended_information != 0 && unsafe { Field::<u32>::at(report.extended_information) }.get() < EXTENDED_INFORMATION_MINIMUM {
        return Ok(());
    }
    let sync = lite_sync(report.notify_sync)?;
    with_sync(sync, || {
        for links in list_entries(report.notify_list) {
            let notify = notify_at(links - NOTIFY_LINKS);
            if notify.completion_filter.get() & report.filter_match == 0 {
                continue;
            }
            let fs_context = notify.fs_context.get();
            if report.flags & LITE_REPORT_IN_DIRECTORY == 0 {
                if notify.flags.get() & WATCH_TREE == 0 {
                    continue;
                }
                let traverse = notify.traverse_callback.get();
                if traverse != 0 && native_call::call(traverse, &[fs_context, report.target_context, notify.subject_context.get()]) & 0xFF == 0 {
                    continue;
                }
            }
            let filter = notify.filter_callback.get();
            if filter != 0 && report.filter_context != 0 && native_call::call(filter, &[fs_context, report.filter_context]) & 0xFF == 0 {
                continue;
            }
            if notify.flags.get() & ENUM_DIR == 0 && notify.this_buffer_length.get() != 0 {
                record_lite(notify, report);
            }
            if report.action == FILE_ACTION_RENAMED_OLD_NAME {
                set_flags(notify, RENAME_HOLD, 0);
                continue;
            }
            set_flags(notify, 0, RENAME_HOLD);
            if notify.notify_irps.flink.get() != notify.notify_irps.address() {
                complete_first_lite(notify)?;
            }
        }
        Ok(())
    })
}
