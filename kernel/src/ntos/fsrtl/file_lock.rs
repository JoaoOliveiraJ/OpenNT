//! Byte-range locks do FsRtl (FILE_LOCK) — o assunto do `fsrtl\filelock.c`
//! do NT. Concessão, conflito, IRPs de trava pendentes e desbloqueio com as
//! regras do ntoskrnl 10.0.19045 (RVAs abaixo).
//!
//! Contrato:
//! * `FileLock` (FILE_LOCK, `inc::types::extra_fsrtl`) é do FS; o FsRtl só
//!   grava as rotinas, `FastIoIsQuestionable` e `LockInformation`
//!   (FsRtlInitializeFileLock 0x201850).
//! * `LockInformation` aponta para um [`LockInfo`] com o prefixo real do NT
//!   (+0 LowestLockOffset, +8 CompleteLockIrpRoutine, +0x10 UnlockRoutine;
//!   FsRtlPrivateInitializeFileLock 0x328b78); as travas concedidas e as
//!   pendentes ficam numa tabela Rust indexada por esse bloco (as splay trees
//!   do NT são privadas do FsRtl).
//! * Regras de conflito (FsRtlPrivateCheckForSharedLockAccess 0x2d9e4c,
//!   ...ExclusiveLockAccess 0x3052a4, FsRtlCheckNoExclusiveConflict 0x36b5e8):
//!   pedido compartilhado conflita com trava EXCLUSIVA sobreposta de outro
//!   dono (FileObject, ProcessId, Key); pedido exclusivo conflita com
//!   QUALQUER trava sobreposta; duas faixas de tamanho zero nunca conflitam.
//!   Leitura: bloqueada só por exclusiva de outro dono. Escrita: por qualquer
//!   compartilhada ou por exclusiva de outro dono. EndingByte = Start +
//!   Length - 1 (com volta, como o NT); faixa que dá a volta com Length != 0
//!   é STATUS_INVALID_LOCK_RANGE.
//! * Conclusão de IRP (FsRtlCompleteLockIrpReal 0x4ef5b0): rotina própria do
//!   FS (zerando FileObject->LastLock) ou IofCompleteRequest.
//!
//! Limitações (sinalizadas): IRPs pendentes não recebem rotina de
//! cancelamento (o NT instala FsRtlPrivateCancelFileLockIrp) e
//! FILE_OBJECT.LastLock, um cache de consulta, nunca é preenchido.
//!
//! Motor estável para os file systems (FAT/NTFS): `initialize_file_lock`,
//! `allocate_file_lock`, `uninitialize_file_lock`, `free_file_lock`,
//! `lock_count`, `fast_check_lock_for_read`, `fast_check_lock_for_write`,
//! `check_read_range`, `check_write_range`, `private_lock`,
//! `fast_unlock_single`, `fast_unlock_all`, `fast_unlock_all_by_key`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_fsrtl::{FileLock, FileLockInfo};
use crate::ntos::inc::types::{FileObject, IoStackLocation, IoStatusBlock, Irp, LargeInteger};
use crate::ntos::io::io_manager;
use crate::ntos::mm::guest_memory as guest;
#[allow(unused_imports)] // usado pelo anexo fsrtl-file-lock-irp
use crate::rtl::KernelError;
use crate::rtl::SpinLock;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_LOCK_NOT_GRANTED: u32 = 0xC000_0055;
pub const STATUS_RANGE_NOT_LOCKED: u32 = 0xC000_007E;
pub const STATUS_INVALID_LOCK_RANGE: u32 = 0xC000_01A1;

/// IO_STACK_LOCATION.Control: SL_PENDING_RETURNED (IoMarkIrpPending).
const SL_PENDING_RETURNED: u8 = 0x01;

/// Offsets derivados dos tipos, para o anexo `fsrtl-file-lock-irp` (ainda no
/// modelo antigo), que os usa por nome junto com `guest` e `KernelError`.
pub const FL_COMPLETE_ROUTINE: u64 = core::mem::offset_of!(FileLock, complete_lock_irp_routine) as u64;
pub const FL_LOCK_INFORMATION: u64 = core::mem::offset_of!(FileLock, lock_information) as u64;
pub const FL_LOCK_REQUESTS_IN_PROGRESS: u64 = core::mem::offset_of!(FileLock, lock_requests_in_progress) as u64;
pub const LI_LOWEST_LOCK_OFFSET: u64 = core::mem::offset_of!(LockInfo, lowest_lock_offset) as u64;

/// LOCK_INFO do FsRtl: o prefixo que o NT grava (FsRtlPrivateInitializeFileLock)
/// e a LOCK_QUEUE que aqui fica sem uso (o estado vive em [`QUEUES`]).
#[repr(C)]
pub struct LockInfo {
    pub lowest_lock_offset: Field<u64>,
    pub complete_lock_irp_routine: Field<u64>,
    pub unlock_routine: Field<u64>,
    _lock_queue: Reserved<0x28>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for LockInfo {}

const _: () = {
    assert!(core::mem::size_of::<LockInfo>() == 0x40);
    assert!(core::mem::offset_of!(LockInfo, complete_lock_irp_routine) == 0x8);
    assert!(core::mem::offset_of!(LockInfo, unlock_routine) == 0x10);
};

/// Uma trava concedida ou pedida (o FILE_LOCK_INFO do NT).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Range {
    start: u64,
    length: u64,
    end: u64,
    exclusive: bool,
    key: u32,
    file_object: u64,
    process_id: u64,
}

impl Range {
    fn new(start: u64, length: u64, exclusive: bool, key: u32, file_object: u64, process_id: u64) -> Range {
        Range { start, length, end: start.wrapping_add(length).wrapping_sub(1), exclusive, key, file_object, process_id }
    }

    fn overlaps(&self, other: &Range) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    fn same_owner(&self, other: &Range) -> bool {
        self.file_object == other.file_object && self.process_id == other.process_id && self.key == other.key
    }
}

struct Waiter {
    irp: u64,
    context: u64,
    range: Range,
}

#[derive(Default)]
struct Queue {
    locks: Vec<Range>,
    waiting: VecDeque<Waiter>,
}

/// Conjuntos por LOCK_INFO (o `FileLock.lock_information` do convidado).
static QUEUES: SpinLock<BTreeMap<u64, Queue>> = SpinLock::new(BTreeMap::new());

fn lock_info(address: u64) -> &'static LockInfo {
    // SAFETY: só chamado com o LockInformation criado por `create_lock_info`.
    unsafe { LockInfo::at(address) }
}

fn file_object_at(address: u64) -> &'static FileObject {
    // SAFETY: FILE_OBJECT vivo passado pelo FS dono do FILE_LOCK.
    unsafe { FileObject::at(address) }
}

fn irp_at(address: u64) -> &'static Irp {
    // SAFETY: IRP vivo guardado na fila de espera (o FS o pendeu aqui).
    unsafe { Irp::at(address) }
}

/// FsRtlPrivateCheckFor{Shared,Exclusive}LockAccess.
fn grantable(queue: &Queue, request: &Range) -> bool {
    queue.locks.iter().all(|lock| {
        if !lock.overlaps(request) || (request.length == 0 && lock.length == 0) {
            return true;
        }
        !request.exclusive && (!lock.exclusive || lock.same_owner(request))
    })
}

fn write_lowest(info: u64, queue: &Queue) {
    let lowest = queue.locks.iter().map(|lock| lock.start).min().unwrap_or(u64::MAX);
    lock_info(info).lowest_lock_offset.set(lowest);
}

/// FsRtlPrivateInitializeFileLock: LOCK_INFO com LowestLockOffset = ~0 e as
/// duas rotinas copiadas; zera LastReturnedLock*. 0 se faltar memória.
fn create_lock_info(file_lock: &FileLock) -> u64 {
    let address = guest::alloc_bytes(LockInfo::SIZE);
    if address == 0 {
        return 0;
    }
    let info = lock_info(address);
    info.lowest_lock_offset.set(u64::MAX);
    info.complete_lock_irp_routine.set(file_lock.complete_lock_irp_routine.get());
    info.unlock_routine.set(file_lock.unlock_routine.get());
    file_lock.last_returned_lock_info.file_object.set(0);
    file_lock.last_returned_lock.set(0);
    QUEUES.lock().insert(address, Queue::default());
    file_lock.lock_information.set(address);
    address
}

/// FsRtlCompleteLockIrpReal (RVA 0x4ef5b0): devolve o status final.
fn complete_lock_irp(info: u64, context: u64, irp: u64, status: u32, file_object: u64) -> u32 {
    let routine = lock_info(info).complete_lock_irp_routine.get();
    irp_at(irp).io_status.status.set(status as i32);
    if routine != 0 {
        if file_object != 0 {
            file_object_at(file_object).last_lock.set(0);
        }
        return native_call::call(routine, &[context, irp]) as u32;
    }
    io_manager::iof_complete_request(irp);
    status
}

/// UnlockRoutine(Context, &FILE_LOCK_INFO) com um FILE_LOCK_INFO temporário.
fn call_unlock_routine(routine: u64, context: u64, lock: &Range) {
    if routine == 0 {
        return;
    }
    let address = guest::alloc_bytes(FileLockInfo::SIZE);
    // SAFETY: bloco recém-alocado do tamanho de FILE_LOCK_INFO.
    let record = unsafe { FileLockInfo::at(address) };
    record.starting_byte.quad_part.set(lock.start as i64);
    record.length.quad_part.set(lock.length as i64);
    record.exclusive_lock.set(lock.exclusive as u8);
    record.key.set(lock.key);
    record.file_object.set(lock.file_object);
    record.process_id.set(lock.process_id);
    record.ending_byte.quad_part.set(lock.end as i64);
    native_call::call(routine, &[context, address]);
    guest::free_bytes(address);
}

fn remove_exact(info: u64, lock: &Range) -> bool {
    let mut queues = QUEUES.lock();
    let Some(queue) = queues.get_mut(&info) else { return false };
    let Some(index) = queue.locks.iter().position(|candidate| candidate == lock) else { return false };
    queue.locks.remove(index);
    write_lowest(info, queue);
    true
}

/// FsRtlPrivateCheckWaitingLocks: concede em ordem FIFO os IRPs que não
/// conflitam mais e os conclui com STATUS_SUCCESS (a trava sai se a rotina de
/// conclusão do FS falhar).
fn check_waiting_locks(info: u64) {
    loop {
        let granted = {
            let mut queues = QUEUES.lock();
            let Some(queue) = queues.get_mut(&info) else { return };
            let position = queue.waiting.iter().position(|waiter| grantable(queue, &waiter.range));
            match position.and_then(|index| queue.waiting.remove(index)) {
                Some(waiter) => {
                    queue.locks.push(waiter.range);
                    write_lowest(info, queue);
                    waiter
                }
                None => return,
            }
        };
        irp_at(granted.irp).io_status.information.set(0);
        let status = complete_lock_irp(info, granted.context, granted.irp, STATUS_SUCCESS, granted.range.file_object);
        if (status as i32) < 0 {
            remove_exact(info, &granted.range);
        }
    }
}

/// FsRtlInitializeFileLock (RVA 0x201850).
pub fn initialize_file_lock(file_lock: &FileLock, complete_routine: u64, unlock_routine: u64) {
    file_lock.complete_lock_irp_routine.set(complete_routine);
    file_lock.lock_information.set(0);
    file_lock.fast_io_is_questionable.set(0);
    file_lock.unlock_routine.set(unlock_routine);
    file_lock.lock_requests_in_progress.set(0);
}

/// FsRtlAllocateFileLock (RVA 0x32a500): FILE_LOCK novo já inicializado, ou 0.
pub fn allocate_file_lock(complete_routine: u64, unlock_routine: u64) -> u64 {
    let address = guest::alloc_bytes(FileLock::SIZE);
    if address != 0 {
        // SAFETY: bloco recém-alocado do tamanho de FILE_LOCK.
        initialize_file_lock(unsafe { FileLock::at(address) }, complete_routine, unlock_routine);
    }
    address
}

/// FsRtlUninitializeFileLock (RVA 0x2f6110): descarta as travas, conclui os
/// IRPs pendentes com STATUS_RANGE_NOT_LOCKED e libera o LOCK_INFO.
pub fn uninitialize_file_lock(file_lock: &FileLock) {
    let info = file_lock.lock_information.get();
    if info == 0 {
        return;
    }
    let queue = QUEUES.lock().remove(&info).unwrap_or_default();
    for waiter in queue.waiting {
        irp_at(waiter.irp).io_status.information.set(0);
        complete_lock_irp(info, waiter.context, waiter.irp, STATUS_RANGE_NOT_LOCKED, 0);
    }
    guest::free_bytes(info);
    file_lock.lock_information.set(0);
}

/// FsRtlFreeFileLock (RVA 0x2f5350).
pub fn free_file_lock(file_lock: &FileLock) {
    uninitialize_file_lock(file_lock);
    guest::free_bytes(file_lock.address());
}

/// Travas concedidas no FILE_LOCK (0 sem LockInformation).
pub fn lock_count(file_lock: &FileLock) -> usize {
    QUEUES.lock().get(&file_lock.lock_information.get()).map_or(0, |queue| queue.locks.len())
}

/// Leitura de [start, start+length) liberada para o dono dado
/// (FsRtlCheckNoExclusiveConflict).
pub fn check_read_range(file_lock: &FileLock, start: u64, length: u64, key: u32, file_object: u64, process_id: u64) -> bool {
    let info = file_lock.lock_information.get();
    if info == 0 || length == 0 {
        return true;
    }
    let request = Range::new(start, length, false, key, file_object, process_id);
    let queues = QUEUES.lock();
    let Some(queue) = queues.get(&info) else { return true };
    !queue.locks.iter().any(|lock| lock.exclusive && lock.overlaps(&request) && !lock.same_owner(&request))
}

/// Escrita de [start, start+length) liberada para o dono dado
/// (FsRtlCheckNoSharedConflict + FsRtlCheckNoExclusiveConflict).
pub fn check_write_range(file_lock: &FileLock, start: u64, length: u64, key: u32, file_object: u64, process_id: u64) -> bool {
    let info = file_lock.lock_information.get();
    if info == 0 || length == 0 {
        return true;
    }
    let request = Range::new(start, length, true, key, file_object, process_id);
    let queues = QUEUES.lock();
    let Some(queue) = queues.get(&info) else { return true };
    !queue.locks.iter().any(|lock| lock.overlaps(&request) && (!lock.exclusive || !lock.same_owner(&request)))
}

/// FsRtlFastCheckLockForRead(FileLock, StartingByte, Length, Key,
/// FileObject, ProcessId) (RVA 0x2d9800).
pub fn fast_check_lock_for_read(file_lock: &FileLock, starting_byte: &LargeInteger, length: &LargeInteger, key: u32, file_object: u64, process_id: u64) -> bool {
    check_read_range(file_lock, starting_byte.quad_part.get() as u64, length.quad_part.get() as u64, key, file_object, process_id)
}

/// FsRtlFastCheckLockForWrite (RVA 0x315f30).
pub fn fast_check_lock_for_write(file_lock: &FileLock, starting_byte: &LargeInteger, length: &LargeInteger, key: u32, file_object: u64, process_id: u64) -> bool {
    check_write_range(file_lock, starting_byte.quad_part.get() as u64, length.quad_part.get() as u64, key, file_object, process_id)
}

/// FsRtlPrivateLock(FileLock, FileObject, StartingByte, Length, ProcessId,
/// Key, FailImmediately, ExclusiveLock, Iosb, Irp, Context,
/// AlreadySynchronized) -> BOOLEAN (RVA 0x2d8b40). FALSE quando falta
/// memória para o LOCK_INFO ou quando o pedido conflitante vem do fast I/O
/// (sem IRP e sem FailImmediately); senão TRUE com o status em Iosb->Status
/// (e o IRP concluído, salvo STATUS_PENDING).
#[allow(clippy::too_many_arguments)]
pub fn private_lock(file_lock: &FileLock, file_object: u64, starting_byte: &LargeInteger, length: &LargeInteger, process_id: u64, key: u32, fail_immediately: bool, exclusive: bool, iosb: &IoStatusBlock, irp: Option<&Irp>, context: u64) -> bool {
    let mut info = file_lock.lock_information.get();
    if info == 0 {
        info = create_lock_info(file_lock);
        if info == 0 {
            return false;
        }
        file_lock.fast_io_is_questionable.set(1);
    }
    let request = Range::new(starting_byte.quad_part.get() as u64, length.quad_part.get() as u64, exclusive, key, file_object, process_id);

    let mut inserted = false;
    let status = if request.end < request.start && request.length != 0 {
        STATUS_INVALID_LOCK_RANGE
    } else {
        let mut queues = QUEUES.lock();
        let queue = queues.entry(info).or_default();
        if grantable(queue, &request) {
            queue.locks.push(request);
            write_lowest(info, queue);
            inserted = true;
            STATUS_SUCCESS
        } else if fail_immediately {
            STATUS_LOCK_NOT_GRANTED
        } else if let Some(irp) = irp {
            // IoMarkIrpPending; o LOCK_INFO fica em IoStatus.Information como no NT.
            // SAFETY: o slot corrente de um IRP vivo.
            let stack = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
            stack.control.atomic().fetch_or(SL_PENDING_RETURNED, Ordering::SeqCst);
            irp.io_status.information.set(info);
            queue.waiting.push_back(Waiter { irp: irp.address(), context, range: request });
            STATUS_PENDING
        } else {
            // Fast I/O não espera: o chamador repete pelo caminho do IRP.
            return false;
        }
    };
    iosb.status.set(status as i32);

    if let Some(irp) = irp {
        if status != STATUS_PENDING {
            let final_status = complete_lock_irp(info, context, irp.address(), status, file_object);
            if (final_status as i32) < 0 && (status as i32) >= 0 && inserted {
                remove_exact(info, &request);
            }
            iosb.status.set(final_status as i32);
        }
    }
    true
}

/// FsRtlFastUnlockSingle(FileLock, FileObject, FileOffset, Length,
/// ProcessId, Key, Context, AlreadySynchronized) -> NTSTATUS (RVA 0x2d9660):
/// a exclusiva exata é procurada primeiro, depois a compartilhada.
pub fn fast_unlock_single(file_lock: &FileLock, file_object: u64, file_offset: &LargeInteger, length: &LargeInteger, process_id: u64, key: u32, context: u64) -> u32 {
    let info = file_lock.lock_information.get();
    if info == 0 {
        return STATUS_RANGE_NOT_LOCKED;
    }
    let (start, bytes) = (file_offset.quad_part.get() as u64, length.quad_part.get() as u64);
    let target = Range::new(start, bytes, false, key, file_object, process_id);
    if target.end < target.start && bytes != 0 {
        return STATUS_INVALID_LOCK_RANGE;
    }
    let removed = {
        let mut queues = QUEUES.lock();
        let Some(queue) = queues.get_mut(&info) else { return STATUS_RANGE_NOT_LOCKED };
        let matches = |lock: &Range, exclusive: bool| lock.exclusive == exclusive && lock.start == start && lock.length == bytes && lock.same_owner(&target);
        let index = queue.locks.iter().position(|lock| matches(lock, true)).or_else(|| queue.locks.iter().position(|lock| matches(lock, false)));
        let Some(index) = index else { return STATUS_RANGE_NOT_LOCKED };
        let lock = queue.locks.remove(index);
        write_lowest(info, queue);
        lock
    };
    call_unlock_routine(lock_info(info).unlock_routine.get(), context, &removed);
    check_waiting_locks(info);
    STATUS_SUCCESS
}

/// FsRtlPrivateFastUnlockAll (RVA 0x2f7db4): sem travas concedidas ->
/// STATUS_RANGE_NOT_LOCKED; senão remove as do dono (chamando UnlockRoutine),
/// conclui os IRPs pendentes do dono com STATUS_RANGE_NOT_LOCKED e reavalia
/// a fila.
fn unlock_all(file_lock: &FileLock, file_object: u64, process_id: u64, key: Option<u32>, context: u64) -> u32 {
    let info = file_lock.lock_information.get();
    if info == 0 {
        return STATUS_RANGE_NOT_LOCKED;
    }
    file_object_at(file_object).last_lock.set(0);
    let owned = |lock: &Range| lock.file_object == file_object && lock.process_id == process_id && key.map_or(true, |key| lock.key == key);
    let (removed, cancelled) = {
        let mut queues = QUEUES.lock();
        let Some(queue) = queues.get_mut(&info) else { return STATUS_RANGE_NOT_LOCKED };
        if queue.locks.is_empty() {
            return STATUS_RANGE_NOT_LOCKED;
        }
        let (removed, kept): (Vec<Range>, Vec<Range>) = queue.locks.drain(..).partition(|lock| owned(lock));
        queue.locks = kept;
        let (cancelled, waiting): (Vec<Waiter>, Vec<Waiter>) = queue.waiting.drain(..).partition(|waiter| owned(&waiter.range));
        queue.waiting = waiting.into_iter().collect();
        write_lowest(info, queue);
        (removed, cancelled)
    };
    let unlock_routine = lock_info(info).unlock_routine.get();
    for lock in &removed {
        call_unlock_routine(unlock_routine, context, lock);
    }
    for waiter in cancelled {
        irp_at(waiter.irp).io_status.information.set(0);
        complete_lock_irp(info, waiter.context, waiter.irp, STATUS_RANGE_NOT_LOCKED, 0);
    }
    check_waiting_locks(info);
    STATUS_SUCCESS
}

/// FsRtlFastUnlockAll(FileLock, FileObject, ProcessId, Context) (RVA 0x2f7d90).
pub fn fast_unlock_all(file_lock: &FileLock, file_object: u64, process_id: u64, context: u64) -> u32 {
    unlock_all(file_lock, file_object, process_id, None, context)
}

/// FsRtlFastUnlockAllByKey(FileLock, FileObject, ProcessId, Key, Context) (RVA 0x4ef610).
pub fn fast_unlock_all_by_key(file_lock: &FileLock, file_object: u64, process_id: u64, key: u32, context: u64) -> u32 {
    unlock_all(file_lock, file_object, process_id, Some(key), context)
}

// ---- Caminho de IRP e consultas do FILE_LOCK (fsrtl-file-lock-irp) ---------------
//
// ntoskrnl 10.0.19045: FsRtlProcessFileLock 0x4efc10, FsRtlCheckLockForReadAccess
// 0x2d9910, FsRtlCheckLockForWriteAccess 0x315e90, FsRtlCheckLockForOplockRequest
// 0x36c850, FsRtlAreThereCurrentOrInProgressFileLocks 0x4ef560,
// FsRtlAreThereWaitingFileLocks 0x4ef590. IO_STACK_LOCATION.Parameters.LockControl
// = { PLARGE_INTEGER Length; ULONG Key; LARGE_INTEGER ByteOffset }; as checagens
// de IRP leem Parameters.Read (o Write tem o mesmo layout); Flags:
// SL_FAIL_IMMEDIATELY 1, SL_EXCLUSIVE_LOCK 2. O NT olha as árvores privadas do
// LOCK_INFO (compartilhadas, exclusivas, fila de espera); aqui os mesmos fatos
// vêm dos conjuntos QUEUES deste módulo e do LowestLockOffset do LockInfo.

const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const IRP_MN_LOCK: u8 = 1;
const IRP_MN_UNLOCK_SINGLE: u8 = 2;
const IRP_MN_UNLOCK_ALL: u8 = 3;
const IRP_MN_UNLOCK_ALL_BY_KEY: u8 = 4;
const SL_FAIL_IMMEDIATELY: u8 = 1;
const SL_EXCLUSIVE_LOCK: u8 = 2;

fn requestor_process(irp: &Irp) -> Result<u64, KernelError> {
    crate::ntos::init::exports::invoke_handler("IoGetRequestorProcess", &[irp.address()])
}

fn current_stack(irp: &Irp) -> &'static IoStackLocation {
    // SAFETY: o IRP_MJ_LOCK_CONTROL/READ/WRITE que o FS está processando tem o
    // slot corrente em Tail.Overlay.CurrentStackLocation.
    unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) }
}

/// LowestLockOffset do LOCK_INFO publicado em FileLock->LockInformation.
fn lowest_lock_offset(info: u64) -> u64 {
    // SAFETY: LockInformation não nulo é o LOCK_INFO criado por este módulo.
    unsafe { LockInfo::at(info) }.lowest_lock_offset.get()
}

/// FsRtlCompleteLockIrpReal com a rotina do FILE_LOCK: a do FS (que devolve
/// o status final) ou IofCompleteRequest.
fn complete_with_file_lock_routine(file_lock: &FileLock, context: u64, irp: &Irp, status: u32) -> u32 {
    let routine = file_lock.complete_lock_irp_routine.get();
    irp.io_status.status.set(status as i32);
    if routine != 0 {
        return native_call::call(routine, &[context, irp.address()]) as u32;
    }
    io_manager::iof_complete_request(irp.address());
    status
}

/// FsRtlProcessFileLock(FileLock, Irp, Context) -> NTSTATUS: o IRP_MJ_LOCK_CONTROL
/// pelo MinorFunction; minor desconhecido -> STATUS_INVALID_DEVICE_REQUEST
/// (IRP concluído com ele).
pub fn process_file_lock(file_lock: &FileLock, irp: &Irp, context: u64) -> Result<u32, KernelError> {
    let stack = current_stack(irp);
    let parameters = &stack.parameters.lock_control;
    let file_object = stack.file_object.get();
    let key = parameters.key.get();
    match stack.minor_function.get() {
        IRP_MN_LOCK => {
            let flags = stack.flags.get();
            let scratch = guest::alloc_bytes(IoStatusBlock::SIZE);
            if scratch == 0 {
                return Err(KernelError::with_status("FsRtlProcessFileLock: no memory", 0xC000_009A));
            }
            // SAFETY: IO_STATUS_BLOCK local (o NT usa um da pilha) e o PLARGE_INTEGER Length do IRP.
            let (iosb, length) = unsafe { (IoStatusBlock::at(scratch), LargeInteger::at(parameters.length.get())) };
            let process = requestor_process(irp)?;
            private_lock(file_lock, file_object, &parameters.byte_offset, length, process, key, flags & SL_FAIL_IMMEDIATELY != 0, flags & SL_EXCLUSIVE_LOCK != 0, iosb, Some(irp), context);
            let status = iosb.status.get() as u32;
            guest::free_bytes(scratch);
            Ok(status)
        }
        IRP_MN_UNLOCK_SINGLE => {
            // SAFETY: o PLARGE_INTEGER Length do IRP.
            let length = unsafe { LargeInteger::at(parameters.length.get()) };
            let status = fast_unlock_single(file_lock, file_object, &parameters.byte_offset, length, requestor_process(irp)?, key, context);
            Ok(complete_with_file_lock_routine(file_lock, context, irp, status))
        }
        IRP_MN_UNLOCK_ALL => {
            let status = fast_unlock_all(file_lock, file_object, requestor_process(irp)?, context);
            Ok(complete_with_file_lock_routine(file_lock, context, irp, status))
        }
        IRP_MN_UNLOCK_ALL_BY_KEY => {
            let status = fast_unlock_all_by_key(file_lock, file_object, requestor_process(irp)?, key, context);
            Ok(complete_with_file_lock_routine(file_lock, context, irp, status))
        }
        _ => {
            irp.io_status.status.set(STATUS_INVALID_DEVICE_REQUEST as i32);
            io_manager::iof_complete_request(irp.address());
            Ok(STATUS_INVALID_DEVICE_REQUEST)
        }
    }
}

fn has_locks(info: u64) -> bool {
    info != 0 && QUEUES.lock().get(&info).is_some_and(|queue| !queue.locks.is_empty())
}

/// FsRtlCheckLockForReadAccess / ForWriteAccess(FileLock, Irp): sem travas, ou
/// a faixa toda abaixo de LowestLockOffset -> TRUE; senão o teste do fast I/O
/// com Key, FileObject e o processo do IRP.
pub fn check_lock_for_irp(file_lock: &FileLock, irp: &Irp, write: bool) -> Result<bool, KernelError> {
    let info = file_lock.lock_information.get();
    if !has_locks(info) {
        return Ok(true);
    }
    let stack = current_stack(irp);
    let parameters = &stack.parameters.read;
    let offset = parameters.byte_offset.quad_part.get() as u64;
    let length = parameters.length.get() as u64;
    if offset.wrapping_add(length) <= lowest_lock_offset(info) {
        return Ok(true);
    }
    let (key, file_object) = (parameters.key.get(), stack.file_object.get());
    let process = requestor_process(irp)?;
    Ok(if write { check_write_range(file_lock, offset, length, key, file_object, process) } else { check_read_range(file_lock, offset, length, key, file_object, process) })
}

/// FsRtlCheckLockForOplockRequest(FileLock, *AllocationSize): nenhuma trava em
/// [0, AllocationSize) e nenhum pedido de trava em andamento.
pub fn check_lock_for_oplock_request(file_lock: &FileLock, allocation_size: &LargeInteger) -> bool {
    let info = file_lock.lock_information.get();
    let size = allocation_size.quad_part.get() as u64;
    if !has_locks(info) || size == 0 {
        return true;
    }
    if file_lock.lock_requests_in_progress.atomic().load(Ordering::Acquire) != 0 {
        return false;
    }
    let last = size - 1;
    if last < lowest_lock_offset(info) {
        return true;
    }
    let queues = QUEUES.lock();
    let Some(queue) = queues.get(&info) else { return true };
    !queue.locks.iter().any(|lock| lock.start <= last)
}

/// FsRtlAreThereCurrentOrInProgressFileLocks(FileLock).
pub fn current_or_in_progress_locks(file_lock: &FileLock) -> bool {
    has_locks(file_lock.lock_information.get()) || file_lock.lock_requests_in_progress.atomic().load(Ordering::Acquire) != 0
}

/// FsRtlAreThereWaitingFileLocks(FileLock): FileLock NULL -> FALSE.
pub fn waiting_locks(file_lock: Option<&FileLock>) -> bool {
    let Some(file_lock) = file_lock else { return false };
    let info = file_lock.lock_information.get();
    info != 0 && QUEUES.lock().get(&info).is_some_and(|queue| !queue.waiting.is_empty())
}
