//! O objeto Job: criação, abertura e as rotinas do tipo, como no ntoskrnl
//! 19041.
//!
//! - NtCreateJobObject(JobHandle, DesiredAccess, ObjectAttributes) (rva
//!   0x71e280): JobHandle sondado e zerado; o corpo de 0x640 bytes vem do
//!   ObCreateObject com PsJobType e é zerado; RootJob aponta o próprio job,
//!   as listas (processos, filhos, irmãos, iteradores) ficam vazias, o KEVENT
//!   do início é de notificação e não sinalizado, as afinidades têm Count 1 e
//!   Size 0x14, SessionId -1, CompletionFilter 0x3FFE, SiloHardReferenceCount
//!   1, SchedulingClass 5 e EffectiveSchedulingClass 10; o JobLock é um
//!   ERESOURCE (ExInitializeResourceLite), o job entra no fim da PspJobList,
//!   JobFlags ganha EmptyJobNotified, o ContainerId é um UUID novo e o JobId
//!   sai da PspUniqueJobIdTable; o handle vem do ObInsertObject.
//! - NtOpenJobObject(JobHandle, DesiredAccess, ObjectAttributes) (rva
//!   0x5d8f10): JobHandle sondado e zerado, ObOpenObjectByName com PsJobType.
//! - PspJobClose (rva 0x6989c0), a CloseProcedure: só o último handle
//!   (SystemHandleCount 1) age — CloseDone liga; com
//!   JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE o job fecha a processos novos
//!   (DisallowNewProcesses) e todo processo da hierarquia termina com
//!   STATUS_SUCCESS; a porta de conclusão é desassociada e solta.
//! - PspJobDelete (rva 0x2dd320), a DeleteProcedure: esvazia o conjunto de
//!   propriedades, zera LimitFlags, solta a porta, sai da PspJobList, sai da
//!   lista de filhos do pai (soltando a referência dele), apaga o ERESOURCE,
//!   libera o vetor de ancestrais e devolve o JobId.
//!
//! O callout de job do win32k na deleção (PsW32JobCalloutTerminate) só roda
//! com uma sessão válida, como no NT.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{ejob, flags, job_type, limit, membership, Outbox, JOBS};
use super::{STATUS_ACCESS_VIOLATION, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER};
use crate::ntos::ex::{list_entry, resource as eresource, uuid};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Ejob, ListEntry};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::{object_create, object_header, object_open, object_reference};
use crate::ntos::ps::{property_set, user_probe};
use crate::rtl::{KernelError, SpinLock};

/// A cabeça da PspJobList (uma LIST_ENTRY do kernel), criada no primeiro
/// job; os jobs se ligam por EJOB.JobLinks.
static JOB_LIST: AtomicU64 = AtomicU64::new(0);

/// PspUniqueJobIdTable: id → job. O ExCreateHandle dá o primeiro valor livre
/// (múltiplos de 4 a partir de 4).
static JOB_IDS: SpinLock<BTreeMap<u32, u64>> = SpinLock::new(BTreeMap::new());

/// KAFFINITY_EX vazia: Count 1, Size 0x14 (o qword 0x140001 do NT).
const AFFINITY_COUNT: u16 = 1;
const AFFINITY_SIZE: u16 = 0x14;
const DEFAULT_COMPLETION_FILTER: u32 = 0x3FFE;
const DEFAULT_SCHEDULING_CLASS: u32 = 5;
const DEFAULT_EFFECTIVE_SCHEDULING_CLASS: u32 = 10;
/// SessionId de um job sem sessão.
const NO_SESSION: u32 = u32::MAX;

fn list_at(address: u64) -> &'static ListEntry {
    // SAFETY: a cabeça e os vínculos da PspJobList são LIST_ENTRYs vivas.
    unsafe { ListEntry::at(address) }
}

/// A cabeça da PspJobList (alocada e inicializada na primeira vez).
fn job_list() -> Option<&'static ListEntry> {
    let current = JOB_LIST.load(Ordering::Acquire);
    if current != 0 {
        return Some(list_at(current));
    }
    let head = guest::alloc_bytes(ListEntry::SIZE);
    if head == 0 {
        return None;
    }
    list_entry::initialize(list_at(head));
    match JOB_LIST.compare_exchange(0, head, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(list_at(head)),
        Err(winner) => {
            guest::free_bytes(head);
            Some(list_at(winner))
        }
    }
}

/// O primeiro id livre da PspUniqueJobIdTable.
fn allocate_job_id(job: u64) -> u32 {
    let mut ids = JOB_IDS.lock();
    let mut id = 4u32;
    while ids.contains_key(&id) {
        id += 4;
    }
    ids.insert(id, job);
    id
}

/// Inicializa um corpo novo, zerado, como o NtCreateJobObject.
fn initialize(job: &Ejob) -> Result<(), KernelError> {
    job.root_job.set(job.address());
    for list in [&job.process_list_head, &job.child_job_list_head, &job.sibling_job_links, &job.iterator_list_head] {
        list_entry::initialize(list);
    }
    dispatcher::initialize_event(job.event.address(), 0, false);
    job.memory_limits_lock.value.set(0);
    for affinity in [&job.affinity, &job.effective_affinity] {
        affinity.count.set(AFFINITY_COUNT);
        affinity.size.set(AFFINITY_SIZE);
    }
    list_entry::initialize(&job.property_set.list_head);
    job.property_set.lock.set(0);
    job.session_id.set(NO_SESSION);
    job.completion_filter.set(DEFAULT_COMPLETION_FILTER);
    job.silo_hard_reference_count.set(1);
    job.effective_scheduling_class.set(DEFAULT_EFFECTIVE_SCHEDULING_CLASS);
    job.scheduling_class.set(DEFAULT_SCHEDULING_CLASS);
    eresource::initialize(job.job_lock.address())?;
    {
        let _guard = JOBS.lock();
        if let Some(head) = job_list() {
            list_entry::insert_tail(head, &job.job_links);
        } else {
            list_entry::initialize(&job.job_links);
        }
    }
    job.job_flags.atomic().fetch_or(flags::EMPTY_JOB_NOTIFIED, Ordering::SeqCst);
    uuid::create(job.container_id.address());
    job.job_id.set(allocate_job_id(job.address()));
    Ok(())
}

/// Grava um HANDLE de saída do chamador (sondado em UserMode).
fn write_handle(mode: u8, address: u64, handle: u64) -> bool {
    if mode != 0 {
        return guest::try_write::<u64>(address, handle).is_ok();
    }
    // SAFETY: PHANDLE de um chamador de modo kernel.
    unsafe { Field::<u64>::at(address) }.set(handle);
    true
}

/// NtCreateJobObject no modo `mode`. Devolve o NTSTATUS.
pub fn create(handle_out: u64, access: u32, attributes: u64, mode: u8) -> Result<u32, KernelError> {
    if mode != 0 && !user_probe::probe_user_write(handle_out, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if !write_handle(mode, handle_out, 0) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: as duas células PVOID/HANDLE alocadas acima.
    let (object_cell, handle_cell) = unsafe { (Field::<u64>::at(cells), Field::<u64>::at(cells + 8)) };
    object_cell.set(0);
    let status = object_create::create(mode, job_type(), attributes, mode, Ejob::SIZE as u32, 0, 0, cells);
    let result = (|| -> Result<u32, KernelError> {
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let job = object_cell.get();
        guest::write_bytes(job, &[0u8; Ejob::SIZE as usize]);
        initialize(ejob(job))?;
        // A referência de quem cria atravessa o ObInsertObject (que solta a
        // de criação numa falha).
        object_header::reference(job, 1);
        let status = object_create::insert(job, access, 0, 0, handle_cell.address())?;
        if status & 0x8000_0000 == 0 && !write_handle(mode, handle_out, handle_cell.get()) {
            object_header::dereference(job, false);
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        object_header::dereference(job, false);
        Ok(status)
    })();
    guest::free_bytes(cells);
    result
}

/// NtOpenJobObject no modo `mode`. Devolve o NTSTATUS.
pub fn open(handle_out: u64, access: u32, attributes: u64, mode: u8) -> Result<u32, KernelError> {
    if mode != 0 && !user_probe::probe_user_write(handle_out, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if !write_handle(mode, handle_out, 0) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if attributes == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let captured = if mode != 0 {
        match object_open::capture_user_attributes(attributes) {
            Ok(block) => Some(block),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        if let Some(block) = captured {
            guest::free_bytes(block);
        }
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cell, 0);
    let status = object_open::open_by_name(captured.unwrap_or(attributes), job_type(), mode, access, cell).map(|value| value as u32);
    let handle = guest::read64(cell);
    guest::free_bytes(cell);
    if let Some(block) = captured {
        guest::free_bytes(block);
    }
    let status = status?;
    if status & 0x8000_0000 == 0 && !write_handle(mode, handle_out, handle) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(status)
}

/// ObReferenceObjectByHandle(handle, access, PsJobType, mode): o EJOB com
/// uma referência, ou o NTSTATUS da recusa.
pub fn reference_by_handle(handle: u64, access: u32, mode: u8) -> Result<u64, u32> {
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cell, 0);
    let status = object_reference::reference_by_handle(handle, access, job_type(), mode, cell, 0);
    let job = guest::read64(cell);
    guest::free_bytes(cell);
    match status {
        Ok(0) => Ok(job),
        Ok(status) => Err(status as u32),
        Err(error) => Err(if error.status != 0 { error.status } else { super::STATUS_INVALID_HANDLE }),
    }
}

/// PspJobClose(Process, Job, ProcessHandleCount, SystemHandleCount).
pub fn close_procedure(job: u64, system_handle_count: u64) {
    if system_handle_count > 1 {
        return;
    }
    let body = ejob(job);
    body.job_flags.atomic().fetch_or(flags::CLOSE_DONE, Ordering::SeqCst);
    let kill = {
        let _guard = JOBS.lock();
        let kill = body.limit_flags.get() & limit::KILL_ON_JOB_CLOSE != 0;
        if kill {
            body.job_flags.atomic().fetch_or(flags::DISALLOW_NEW_PROCESSES, Ordering::SeqCst);
        }
        kill
    };
    if kill {
        membership::terminate_hierarchy(job, 0, false);
    }
    let port = {
        let _guard = JOBS.lock();
        let port = body.completion_port.get();
        body.completion_port.set(0);
        port
    };
    if port != 0 {
        let _ = dispatcher_objects::dereference(port);
    }
}

/// PspJobDelete(Job).
pub fn delete_procedure(job: u64) {
    let body = ejob(job);
    property_set::clear(job);
    membership::job_delete_callout(body);
    let (port, parent) = {
        let _guard = JOBS.lock();
        body.limit_flags.set(0);
        let port = body.completion_port.get();
        body.completion_port.set(0);
        if JOB_LIST.load(Ordering::Acquire) != 0 {
            let _ = list_entry::remove(&body.job_links);
        }
        let parent = body.parent_job.get();
        if parent != 0 {
            let _ = list_entry::remove(&body.sibling_job_links);
            list_entry::initialize(&body.sibling_job_links);
            body.parent_job.set(0);
        }
        (port, parent)
    };
    if port != 0 {
        let _ = dispatcher_objects::dereference(port);
    }
    let mut outbox = Outbox::default();
    if parent != 0 {
        outbox.release_job(parent);
    }
    let _ = eresource::delete(body.job_lock.address());
    let ancestors = body.ancestors.get();
    if body.ancestor_count.get() > 2 && ancestors != 0 {
        guest::free_bytes(ancestors);
        body.ancestors.set(0);
    }
    let id = body.job_id.get();
    if id != 0 {
        JOB_IDS.lock().remove(&id);
    }
    outbox.deliver();
}
