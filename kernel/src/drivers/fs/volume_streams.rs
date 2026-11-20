//! O estado por stream que o file system embutido guarda no lugar do SCB do
//! NTFS: o FILE_LOCK das travas de faixa de bytes (Scb->FileLock, criado no
//! primeiro uso pelo NtfsCreateFileLock 0x1530fc = FsRtlAllocateFileLock(NULL,
//! NULL)) e a lista de notificação de mudança de um diretório (Scb+0x2d0
//! NotifyList e Scb+0x2e0 *NotifySync).
//!
//! - IRP_MN_NOTIFY_CHANGE_DIRECTORY(_EX) ([`notify_change_directory`]): o
//!   NtfsNotifyChangeDirectory sobre o FsRtl Lite (`fsrtl/notify.rs`); as
//!   mudanças do volume chegam pelo [`report`] (o NtfsReportDirNotify) da
//!   criação, da remoção e da renomeação (`ntfs_write.rs`), o relato
//!   FILE_ACTION_MODIFIED de um arquivo escrito sai no cleanup dele, e um
//!   diretório removido conclui os pedidos com STATUS_DELETE_PENDING
//!   ([`directory_removed`]).
//!
//! - IRP_MJ_LOCK_CONTROL ([`lock_control`]): o NtfsCommonLockControl
//!   (ntfs.sys 19041 0x22f3f8) sobre o FsRtl (`fsrtl/file_lock.rs`): só uma
//!   abertura de arquivo de dados tem travas (diretório e abertura de volume
//!   dão STATUS_INVALID_PARAMETER, 0x22f47e) e o FsRtlProcessFileLock conclui
//!   o IRP ou o deixa na fila de espera, com LockRequestsInProgress contado em
//!   volta (0x22f679).
//! - Leitura e escrita ([`transfer_allowed`]): o FsRtlCheckLockForReadAccess
//!   do NtfsCommonRead (0xee7c) e o FsRtlCheckLockForWriteAccess do
//!   NtfsCommonWrite (0x1fc50), que dão STATUS_FILE_LOCK_CONFLICT.
//! - Cleanup ([`cleanup`]): o FsRtlFastUnlockAll(FileLock, FileObject,
//!   IoGetRequestorProcess(Irp)) do NtfsCommonCleanup (0x11a914); o
//!   IRP_MN_UNLOCK_ALL que o IopCloseFile (0x64a35a) manda quando um processo
//!   fecha o último handle dele para o arquivo ([`unlock_for_process`]).
//!
//! A chave do stream é a identidade do registro (referência e sequência do
//! volume de boot), que sobrevive à renomeação; um registro reutilizado tem
//! outra sequência. O FILE_LOCK sai no cleanup quando não tem mais travas
//! concedidas, pedidos em espera nem pedidos em andamento (o NTFS o libera
//! com o SCB; aqui não há SCB).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::ntfs::{Ntfs, Stat};
use super::volume::{self, FileSystem};
use super::volume_files;
use crate::ntos::fsrtl::{file_lock, notify};
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::extra_fsrtl::FileLock;
use crate::ntos::inc::types::{DirectoryNotifyInformationClass, FileObject, IoStackLocation, Irp, ListEntry, NtStruct};
use crate::ntos::io::io_manager;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::file as file_objects;
use crate::rtl::SpinLock;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_PENDING: u32 = 0x103;
const STATUS_DELETE_PENDING: u32 = 0xC000_0056;
/// FILE_OBJECT.Flags: FO_VOLUME_OPEN e FO_CLEANUP_COMPLETE.
const FO_VOLUME_OPEN: u32 = 0x40_0000;
const FO_CLEANUP_COMPLETE: u32 = 0x4000;
/// IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX.
const IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX: u8 = 0x03;
/// IO_STACK_LOCATION.Flags: SL_WATCH_TREE.
const SL_WATCH_TREE: u8 = 0x01;
/// Os flags do FsRtlNotifyFilterChangeDirectoryLite: registros estendidos.
const LITE_EXTENDED: u32 = 0x04;
/// FILE_ACTION_*.
pub const FILE_ACTION_ADDED: u32 = 1;
pub const FILE_ACTION_REMOVED: u32 = 2;
pub const FILE_ACTION_MODIFIED: u32 = 3;
pub const FILE_ACTION_RENAMED_OLD_NAME: u32 = 4;
pub const FILE_ACTION_RENAMED_NEW_NAME: u32 = 5;
/// FILE_NOTIFY_CHANGE_FILE_NAME e FILE_NOTIFY_CHANGE_DIR_NAME.
pub const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x1;
pub const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x2;

/// A identidade do stream (o SCB): o registro do volume de boot.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StreamKey {
    reference: u64,
    sequence: u16,
}

/// O FILE_LOCK de cada stream com travas.
static LOCKS: SpinLock<BTreeMap<StreamKey, u64>> = SpinLock::new(BTreeMap::new());

fn file_lock_at(address: u64) -> &'static FileLock {
    // SAFETY: FILE_LOCK alocado por `pin`, vivo enquanto está em LOCKS ou
    // retido por LockRequestsInProgress.
    unsafe { FileLock::at(address) }
}

/// O stream de um FILE_OBJECT de arquivo do volume de boot: a chave e se é
/// diretório. `None` para outros arquivos.
fn stream(file_object: u64) -> Option<(StreamKey, bool)> {
    let source = file_objects::source(file_object)?;
    let boot: &'static dyn FileSystem = volume_files::fixed_volume()?;
    if !volume::same(source.volume()?, boot) {
        return None;
    }
    let stat = source.stat()?;
    Some((StreamKey { reference: stat.reference?, sequence: stat.sequence }, stat.directory))
}

/// O FILE_LOCK do stream retido para um pedido (LockRequestsInProgress + 1,
/// que impede a liberação em [`release_if_idle`]); `create` cria o primeiro
/// (FsRtlAllocateFileLock(NULL, NULL)).
fn pin(key: StreamKey, create: bool) -> Option<&'static FileLock> {
    let mut created = 0;
    loop {
        {
            let mut locks = LOCKS.lock();
            let existing = locks.get(&key).copied();
            let address = match existing {
                Some(existing) => existing,
                None if created != 0 => {
                    locks.insert(key, created);
                    core::mem::take(&mut created)
                }
                None => 0,
            };
            if address != 0 {
                let lock = file_lock_at(address);
                lock.lock_requests_in_progress.atomic().fetch_add(1, Ordering::SeqCst);
                drop(locks);
                if created != 0 {
                    // Outro pedido criou o do stream antes.
                    file_lock::free_file_lock(file_lock_at(created));
                }
                return Some(lock);
            }
        }
        if !create {
            return None;
        }
        created = file_lock::allocate_file_lock(0, 0);
        if created == 0 {
            return None;
        }
    }
}

fn unpin(lock: &FileLock) {
    lock.lock_requests_in_progress.atomic().fetch_sub(1, Ordering::SeqCst);
}

/// Libera o FILE_LOCK do stream sem travas concedidas, sem pedidos em
/// espera e sem pedidos em andamento.
fn release_if_idle(key: StreamKey) {
    let idle = {
        let mut locks = LOCKS.lock();
        let Some(address) = locks.get(&key).copied() else { return };
        let lock = file_lock_at(address);
        if lock.lock_requests_in_progress.atomic().load(Ordering::SeqCst) != 0 || file_lock::current_or_in_progress_locks(lock) || file_lock::waiting_locks(Some(lock)) {
            return;
        }
        locks.remove(&key);
        address
    };
    file_lock::free_file_lock(file_lock_at(idle));
}

/// Conclui o IRP com `status` (IoStatus {status, 0}) e devolve o status.
pub fn complete(packet: u64, irp: &Irp, status: u32) -> i32 {
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(0);
    io_manager::iof_complete_request(packet);
    status as i32
}

/// IRP_MJ_LOCK_CONTROL de um arquivo do volume, como o NtfsCommonLockControl
/// (0x22f3f8): sem stream, STATUS_INVALID_HANDLE; abertura de volume ou
/// diretório, STATUS_INVALID_PARAMETER (0x22f47e), concluído aqui; senão o
/// FILE_LOCK do stream (criado no primeiro uso, 0x153122) e o
/// FsRtlProcessFileLock (0x22f6ae), que conclui o IRP ou o deixa pendente
/// (STATUS_PENDING), com LockRequestsInProgress contado em volta (0x22f679).
pub fn lock_control(packet: u64, irp: &Irp, stack: &IoStackLocation) -> i32 {
    let file_object = stack.file_object.get();
    if file_object == 0 {
        return complete(packet, irp, STATUS_INVALID_HANDLE);
    }
    // SAFETY: o FILE_OBJECT da stack location do IRP vivo.
    if unsafe { FileObject::at(file_object) }.flags.get() & FO_VOLUME_OPEN != 0 {
        return complete(packet, irp, STATUS_INVALID_PARAMETER);
    }
    let Some((key, directory)) = stream(file_object) else { return complete(packet, irp, STATUS_INVALID_HANDLE) };
    if directory {
        return complete(packet, irp, STATUS_INVALID_PARAMETER);
    }
    let Some(lock) = pin(key, true) else { return complete(packet, irp, STATUS_INSUFFICIENT_RESOURCES) };
    let status = file_lock::process_file_lock(lock, irp, 0);
    unpin(lock);
    match status {
        Ok(status) => status as i32,
        // Só a falta de memória antes de tocar no IRP volta como erro.
        Err(error) => complete(packet, irp, if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES }),
    }
}

/// A leitura (`write` = false) ou a escrita de [offset, offset + length) do
/// arquivo pelo dono (FileObject, processo, Key) não esbarra numa trava:
/// FsRtlCheckLockForReadAccess / ForWriteAccess. Sem travas no stream, true.
pub fn transfer_allowed(file_object: u64, offset: u64, length: u64, key: u32, process: u64, write: bool) -> bool {
    if LOCKS.lock().is_empty() {
        return true;
    }
    let Some((stream_key, _)) = stream(file_object) else { return true };
    let Some(lock) = pin(stream_key, false) else { return true };
    let allowed = if write { file_lock::check_write_range(lock, offset, length, key, file_object, process) } else { file_lock::check_read_range(lock, offset, length, key, file_object, process) };
    unpin(lock);
    allowed
}

/// O FsRtlFastUnlockAll(FileLock, FileObject, Process) das travas de
/// `process` no arquivo; o FILE_LOCK ocioso sai depois.
pub fn unlock_for_process(file_object: u64, process: u64) {
    if LOCKS.lock().is_empty() {
        return;
    }
    let Some((key, _)) = stream(file_object) else { return };
    if let Some(lock) = pin(key, false) {
        let _ = file_lock::fast_unlock_all(lock, file_object, process, 0);
        unpin(lock);
    }
    release_if_idle(key);
}

/// O cleanup do FILE_OBJECT (último handle), como o NtfsCommonCleanup
/// (0x11a914): as travas do processo que fecha saem; o diretório com lista
/// de notificação conclui os pedidos do FILE_OBJECT com
/// STATUS_NOTIFY_CLEANUP; e o arquivo escrito relata FILE_ACTION_MODIFIED.
pub fn cleanup(file_object: u64, process: u64) {
    unlock_for_process(file_object, process);
    if DIRECTORIES.lock().is_empty() {
        MODIFIED.lock().clear();
        return;
    }
    let Some((key, directory)) = stream(file_object) else { return };
    if directory {
        directory_cleanup(file_object, key);
    } else {
        report_modified(file_object, key);
    }
}

// ---- notificação de mudança de diretório ------------------------------------

/// O Scb+0x2d0 NotifyList e o Scb+0x2e0 *NotifySync de um diretório
/// (ntfs.sys 0x15907f): a lista dos NOTIFY_CHANGE do FsRtl Lite e o
/// NOTIFY_SYNC criado no primeiro pedido.
#[repr(C)]
struct DirectoryNotify {
    list: ListEntry,
    sync: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for DirectoryNotify {}

/// Os diretórios com lista de notificação, pelo stream.
static DIRECTORIES: SpinLock<BTreeMap<StreamKey, u64>> = SpinLock::new(BTreeMap::new());

fn directory_notify_at(address: u64) -> &'static DirectoryNotify {
    // SAFETY: bloco alocado por `directory_block`, vivo enquanto está em
    // DIRECTORIES.
    unsafe { DirectoryNotify::at(address) }
}

/// O bloco de notificação do diretório `key`, criado no primeiro pedido.
fn directory_block(key: StreamKey) -> Option<u64> {
    let mut directories = DIRECTORIES.lock();
    if let Some(&block) = directories.get(&key) {
        return Some(block);
    }
    let block = guest::alloc_bytes(core::mem::size_of::<DirectoryNotify>() as u64);
    if block == 0 {
        return None;
    }
    let notify = directory_notify_at(block);
    notify.list.flink.set(notify.list.address());
    notify.list.blink.set(notify.list.address());
    notify.sync.set(0);
    directories.insert(key, block);
    Some(block)
}

/// IRP_MN_NOTIFY_CHANGE_DIRECTORY(_EX) de um arquivo do volume, como o
/// NtfsCommonDirectoryControl e o NtfsNotifyChangeDirectory: sem stream,
/// STATUS_INVALID_HANDLE; um arquivo que não é diretório (0x1ca315) ou um
/// FILE_OBJECT depois do cleanup (0xf8afa), STATUS_INVALID_PARAMETER; um
/// diretório que já saiu do volume, STATUS_DELETE_PENDING (0x159130). Senão
/// o FsRtlNotifyFilterChangeDirectoryLite com a lista do diretório (os
/// flags: SL_WATCH_TREE e, no minor EX com a classe 2, os registros
/// estendidos), que enfileira o IRP ou o conclui com os registros
/// pendentes, e STATUS_PENDING (0x159117), como o NTFS. Sem
/// TraverseCallback nem SubjectContext: o comportamento do NTFS quando quem
/// abre tem o SeChangeNotifyPrivilege.
pub fn notify_change_directory(packet: u64, irp: &Irp, stack: &IoStackLocation) -> i32 {
    let file_object = stack.file_object.get();
    if file_object == 0 {
        return complete(packet, irp, STATUS_INVALID_HANDLE);
    }
    let Some((key, directory)) = stream(file_object) else { return complete(packet, irp, STATUS_INVALID_HANDLE) };
    // SAFETY: o FILE_OBJECT da stack location do IRP vivo.
    let flags = unsafe { FileObject::at(file_object) }.flags.get();
    if !directory || flags & FO_CLEANUP_COMPLETE != 0 {
        return complete(packet, irp, STATUS_INVALID_PARAMETER);
    }
    let alive = file_objects::source(file_object).and_then(|source| source.volume_path()).zip(volume_files::fixed_volume()).is_some_and(|(path, volume)| volume.stat(&path).ok().flatten().is_some_and(|stat| stat.reference == key.reference && stat.sequence == key.sequence));
    if !alive {
        return complete(packet, irp, STATUS_DELETE_PENDING);
    }
    let minor = stack.minor_function.get();
    let extended = minor == IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX && stack.parameters.notify_directory_ex.directory_notify_information_class.get() == DirectoryNotifyInformationClass::DIRECTORY_NOTIFY_EXTENDED_INFORMATION;
    let lite_flags = u32::from(stack.flags.get() & SL_WATCH_TREE) | if extended { LITE_EXTENDED } else { 0 };
    let Some(block) = directory_block(key) else { return complete(packet, irp, STATUS_INSUFFICIENT_RESOURCES) };
    let notify = directory_notify_at(block);
    let change = notify::ChangeDirectoryLite { notify_sync: &notify.sync, notify_list: &notify.list, fs_context: file_object, flags: lite_flags, completion_filter: stack.parameters.notify_directory.completion_filter.get(), irp: Some(irp), traverse_callback: 0, subject_context: 0, filter_callback: 0 };
    match notify::filter_change_directory_lite(&change) {
        Ok(()) => STATUS_PENDING as i32,
        Err(error) => complete(packet, irp, if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES }),
    }
}

/// O bloco de informação estendida de um relato (o FILE_NOTIFY_EXTENDED_
/// INFORMATION sem NextEntryOffset e Action, como o NtfsNotifyFilterReportChange
/// o monta): o tamanho 0x50, os quatro tempos na ordem do registro
/// (criação, escrita, mudança, acesso), o tamanho alocado e o real, os
/// atributos, a tag de reparse, o id do arquivo e o do pai.
fn extended_block(target: &Stat, parent: u64) -> [u8; 0x50] {
    let mut block = [0u8; 0x50];
    block[0..4].copy_from_slice(&0x50u32.to_le_bytes());
    let times = target.times.get(..32).unwrap_or(&[0; 32]);
    block[8..0x28].copy_from_slice(times);
    block[0x28..0x30].copy_from_slice(&target.allocated.to_le_bytes());
    block[0x30..0x38].copy_from_slice(&target.size.to_le_bytes());
    block[0x38..0x3C].copy_from_slice(&target.attributes.to_le_bytes());
    block[0x3C..0x40].copy_from_slice(&target.reparse_tag.to_le_bytes());
    block[0x40..0x48].copy_from_slice(&(target.reference | (target.sequence as u64) << 48).to_le_bytes());
    block[0x48..0x50].copy_from_slice(&parent.to_le_bytes());
    block
}

/// O id de arquivo (referência e sequência) de `path` no volume.
fn file_id(volume: &Ntfs, path: &str) -> Option<u64> {
    volume.stat(path).ok().flatten().map(|stat| stat.reference | (stat.sequence as u64) << 48)
}

fn is_boot_volume(volume: &Ntfs) -> bool {
    volume_files::fixed_volume().is_some_and(|fixed| core::ptr::eq(fixed, volume))
}

/// O relato de uma mudança em `path` (o NtfsReportDirNotify e o
/// NtfsNotifyFilterReportChange): para cada diretório acima, do pai direto à
/// raiz, que tem lista de notificação, o FsRtlNotifyFilterReportChangeLiteEx
/// com o nome relativo a ele (os componentes separados por `\`), o
/// FILTER_MATCH, a ação e, no pai direto, o "no próprio diretório"; com o
/// alvo, o bloco de informação estendida. Chamado fora do escritor do
/// volume (o FsRtl toma o NOTIFY_SYNC e pode concluir IRPs).
pub fn report(volume: &Ntfs, path: &str, target: Option<&Stat>, filter_match: u32, action: u32) {
    if DIRECTORIES.lock().is_empty() || !is_boot_volume(volume) {
        return;
    }
    let components: Vec<&str> = path.split('/').filter(|component| !component.is_empty()).collect();
    let count = components.len();
    if count == 0 {
        return;
    }
    let parent_path = alloc::format!("/{}", components[..count - 1].join("/"));
    let extended = target.map(|target| extended_block(target, file_id(volume, &parent_path).unwrap_or(0)));
    for index in (0..count).rev() {
        let directory = alloc::format!("/{}", components[..index].join("/"));
        let Some(stat) = volume.stat(&directory).ok().flatten() else { continue };
        let key = StreamKey { reference: stat.reference, sequence: stat.sequence };
        let Some(block) = DIRECTORIES.lock().get(&key).copied() else { continue };
        let name = components[index..].join("\\");
        let in_directory = index == count - 1;
        report_to(block, &name, filter_match, action, in_directory, extended.as_ref());
    }
}

/// Um FsRtlNotifyFilterReportChangeLiteEx na lista de `block`, com o nome e
/// o bloco estendido (alinhado a 8) em memória de pool.
fn report_to(block: u64, name: &str, filter_match: u32, action: u32, in_directory: bool, extended: Option<&[u8; 0x50]>) {
    let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let buffer = guest::alloc_bytes(16 + units.len() as u64 + 8 + 0x50);
    if buffer == 0 {
        return;
    }
    let text = buffer + 16;
    guest::write_bytes(text, &units);
    // UNICODE_STRING {Length, MaximumLength, Buffer}.
    guest::write16(buffer, units.len() as u16);
    guest::write16(buffer + 2, units.len() as u16);
    guest::write64(buffer + 8, text);
    let extended_at = match extended {
        Some(bytes) => {
            // Alinhado a 8, como o bloco de pool do ntfs.sys: o FsRtl lê os
            // tempos e os ids como LARGE_INTEGER.
            let at = (text + units.len() as u64 + 7) & !7;
            guest::write_bytes(at, bytes);
            at
        }
        None => 0,
    };
    let notify = directory_notify_at(block);
    let report = notify::ReportChangeLite { notify_sync: &notify.sync, notify_list: &notify.list, name: buffer, stream_name: 0, filter_match, action, target_context: 0, filter_context: 0, flags: u32::from(in_directory), extended_information: extended_at };
    let _ = notify::filter_report_change_lite(&report);
    guest::free_bytes(buffer);
}

/// O diretório `stat` saiu do volume: o FsRtlNotifyFilterChangeDirectoryLite
/// sem IRP (0x11982d), que conclui os pedidos pendentes com
/// STATUS_DELETE_PENDING e marca os NOTIFY_CHANGE.
pub fn directory_removed(volume: &Ntfs, stat: &Stat) {
    if !stat.directory || !is_boot_volume(volume) {
        return;
    }
    let key = StreamKey { reference: stat.reference, sequence: stat.sequence };
    let Some(block) = DIRECTORIES.lock().get(&key).copied() else { return };
    let notify = directory_notify_at(block);
    let change = notify::ChangeDirectoryLite { notify_sync: &notify.sync, notify_list: &notify.list, fs_context: 0, flags: 0, completion_filter: 0, irp: None, traverse_callback: 0, subject_context: 0, filter_callback: 0 };
    let _ = notify::filter_change_directory_lite(&change);
}

/// O cleanup de um diretório com lista de notificação (o FsRtlNotifyCleanup
/// do NtfsCommonCleanup, 0x11a1a0): o NOTIFY_CHANGE do FILE_OBJECT sai e os
/// pedidos dele terminam com STATUS_NOTIFY_CLEANUP; a lista vazia libera o
/// bloco.
fn directory_cleanup(file_object: u64, key: StreamKey) {
    let Some(block) = DIRECTORIES.lock().get(&key).copied() else { return };
    let notify = directory_notify_at(block);
    let sync = notify.sync.get();
    if sync != 0 {
        let _ = notify::cleanup(sync, &notify.list, file_object);
    }
    let mut directories = DIRECTORIES.lock();
    if notify.list.flink.get() == notify.list.address() && directories.get(&key) == Some(&block) {
        directories.remove(&key);
        drop(directories);
        if sync != 0 {
            let _ = notify::uninitialize_sync(&notify.sync);
        }
        guest::free_bytes(block);
    }
}

/// As mudanças de um arquivo que o relato do cleanup leva (o Fcb->InfoFlags
/// do NTFS): os FILE_NOTIFY_CHANGE_* acumulados desde o último cleanup.
static MODIFIED: SpinLock<BTreeMap<StreamKey, u32>> = SpinLock::new(BTreeMap::new());

/// Acumula `flags` (FILE_NOTIFY_CHANGE_*) no arquivo, para o relato
/// FILE_ACTION_MODIFIED do cleanup.
pub fn mark_modified(file_object: u64, flags: u32) {
    if DIRECTORIES.lock().is_empty() {
        return;
    }
    let Some((key, _)) = stream(file_object) else { return };
    *MODIFIED.lock().entry(key).or_insert(0) |= flags;
}

/// O relato FILE_ACTION_MODIFIED adiado do cleanup (0x11ca8a): os
/// FILE_NOTIFY_CHANGE_* acumulados do arquivo, com o nome atual dele.
fn report_modified(file_object: u64, key: StreamKey) {
    let Some(flags) = MODIFIED.lock().remove(&key) else { return };
    let flags = flags & 0x1FC;
    if flags == 0 {
        return;
    }
    let Some(path) = file_objects::source(file_object).and_then(|source| source.volume_path()) else { return };
    let Some(volume) = volume_files::fixed_volume() else { return };
    let Some(stat) = volume.stat(&path).ok().flatten() else { return };
    report(volume, &path, Some(&stat), flags, FILE_ACTION_MODIFIED);
}
