//! Notificação de mudança de diretório — fsrtl\notify.c.
//!
//! ntoskrnl 10.0.19045: FsRtlNotifyInitializeSync 0x675fa0 (REAL_NOTIFY_SYNC de
//! 0x48 bytes 'FSrN': FAST_MUTEX, OwningThread, OwnerCount),
//! FsRtlNotifyUninitializeSync 0x6a2c10, FsRtlNotifyFilterChangeDirectory 0x675020
//! (FsRtlNotifyFullChangeDirectory 0x88d5e0 = ele sem FilterCallback),
//! FsRtlNotifyFilterReportChange 0x6746f0 (FsRtlNotifyFullReportChange 0x88d650
//! = ele sem FilterContext), FsRtlNotifyCleanup 0x675b00.
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
    _pad_64: Reserved<0x4>,
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

fn notify_record(action: u32, name: &[u16]) -> Vec<u8> {
    let length = 12 + name.len() * 2;
    let padded = (length + 3) & !3;
    let mut record = alloc::vec![0u8; padded];
    record[4..8].copy_from_slice(&action.to_le_bytes());
    record[8..12].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        record[12 + index * 2..14 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    record
}

/// Encadeia NextEntryOffset dos registros já no buffer e acrescenta o novo.
fn append_record(buffer: &mut Vec<u8>, record: &[u8]) {
    let mut cursor = 0;
    if !buffer.is_empty() {
        loop {
            let next = u32::from_le_bytes([buffer[cursor], buffer[cursor + 1], buffer[cursor + 2], buffer[cursor + 3]]) as usize;
            if next == 0 {
                break;
            }
            cursor += next;
        }
        let distance = (buffer.len() - cursor) as u32;
        buffer[cursor..cursor + 4].copy_from_slice(&distance.to_le_bytes());
    }
    buffer.extend_from_slice(record);
}

/// Parâmetros de FsRtlNotifyFullReportChange (os nomes são PSTRING opacos,
/// lidos conforme o CharacterSize de cada NOTIFY_CHANGE).
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

/// FsRtlNotifyFullReportChange: para cada NOTIFY_CHANGE do diretório (ou de
/// um ancestral com WatchTree) cujo CompletionFilter casa, monta o
/// FILE_NOTIFY_INFORMATION e conclui o IRP pendente ou acumula.
pub fn full_report_change(report: &ReportChange) -> Result<(), KernelError> {
    if report.notify_list.flink.get() == report.notify_list.address() {
        return Ok(());
    }
    with_sync(report.notify_sync, || {
        for links in list_entries(report.notify_list) {
            let notify = notify_at(links - NOTIFY_LINKS);
            let current = notify.flags.get();
            if current & (CLEANUP_CALLED | DELETE_PENDING) != 0 || notify.completion_filter.get() & report.filter_match == 0 {
                continue;
            }
            let character_size = notify.character_size.get().max(1);
            let target = read_units(report.full_target_name, character_size);
            let offset = (report.target_name_offset / character_size as u16) as usize;
            if offset > target.len() {
                continue;
            }
            let parent: Vec<u16> = if report.normalized_parent_name != 0 {
                read_units(report.normalized_parent_name, character_size)
            } else if offset <= 1 {
                target[..offset.min(1)].to_vec()
            } else {
                target[..offset - 1].to_vec()
            };
            let Some(mut name) = relative_name(notify, &target, offset, &parent) else { continue };
            // Mudança numa subárvore: o TraverseCallback do FS decide a visibilidade.
            let traverse = notify.traverse_callback.get();
            if traverse != 0 && name.len() != target.len() - offset {
                let status = native_call::call(traverse, &[notify.fs_context.get(), report.target_context, notify.subject_context.get()]) as u32;
                if status & 0x8000_0000 != 0 {
                    continue;
                }
            }
            let filter = notify.filter_callback.get();
            if filter != 0 && native_call::call(filter, &[notify.fs_context.get(), 0]) & 0xFF == 0 {
                continue;
            }
            let stream = read_units(report.stream_name, character_size);
            if !stream.is_empty() {
                name.push(b':' as u16);
                name.extend_from_slice(&stream);
            }
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
