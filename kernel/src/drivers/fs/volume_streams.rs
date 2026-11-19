//! O estado por stream que o file system embutido guarda no lugar do SCB do
//! NTFS: o FILE_LOCK das travas de faixa de bytes (Scb->FileLock, criado no
//! primeiro uso pelo NtfsCreateFileLock 0x1530fc = FsRtlAllocateFileLock(NULL,
//! NULL)).
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
use core::sync::atomic::Ordering;

use super::volume::{self, FileSystem};
use super::volume_files;
use crate::ntos::fsrtl::file_lock;
use crate::ntos::inc::types::extra_fsrtl::FileLock;
use crate::ntos::inc::types::{FileObject, IoStackLocation, Irp, NtStruct};
use crate::ntos::io::io_manager;
use crate::ntos::ob::objects::file as file_objects;
use crate::rtl::SpinLock;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// FILE_OBJECT.Flags: FO_VOLUME_OPEN.
const FO_VOLUME_OPEN: u32 = 0x40_0000;

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
/// (0x11a914): as travas do processo que fecha saem.
pub fn cleanup(file_object: u64, process: u64) {
    unlock_for_process(file_object, process);
}
