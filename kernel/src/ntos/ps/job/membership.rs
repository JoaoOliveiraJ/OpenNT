//! A pertença de um processo a um job, como no ntoskrnl 19041.
//!
//! - PsAssignProcessToJobObject (rva 0x71e6a0): a disposição
//!   (PspGetJobAssignmentDisposition, 0x71f968) e a atribuição
//!   (PspAssignProcessToJob, 0x71e720), repetida enquanto a disposição muda
//!   (STATUS_RETRY); uma disposição recusada é STATUS_ACCESS_DENIED. As
//!   disposições: o processo sem job (1); já no job, ou num descendente dele
//!   (2, sucesso sem nada a fazer); o job dele é ancestral do novo e o
//!   processo desce (3); o job novo, sem processos e sem pai, vira filho do
//!   job do processo (4, os jobs aninhados do Windows 8; até 100 níveis);
//!   senão STATUS_NOT_SUPPORTED, salvo um job movível (5, com partição de
//!   memória própria, que não existe aqui).
//! - PspValidateJobChainLimits/PspValidateJobAssignmentProcessLimits: em
//!   cada job da cadeia, JOB_OBJECT_LIMIT_ACTIVE_PROCESS estourado é
//!   STATUS_QUOTA_EXCEEDED com JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT;
//!   JOB_OBJECT_LIMIT_JOB_TIME vencido também; um job fechado a processos
//!   novos é STATUS_INVALID_PARAMETER e um job em término
//!   STATUS_PROCESS_IS_TERMINATING.
//! - PspEstablishJobHierarchy (0x71ecfc): a sessão do job (a do processo,
//!   ou STATUS_ACCESS_DENIED se já é de outra), MmLinkJobProcess (o processo
//!   na ProcessListHead, EPROCESS.Job e a referência do job) e, ao aninhar,
//!   os vínculos de filho, RootJob, NestingDepth, o vetor de ancestrais além
//!   do segundo, os limites efetivos e os bits herdados do pai.
//! - PspIncrementJobChainProcessCounts: TotalProcesses, ActiveProcesses e
//!   ShadowActiveProcessCount sobem em cada job da cadeia, EmptyJobNotified
//!   desliga e JOB_OBJECT_MSG_NEW_PROCESS (contexto = PID) vai para cada
//!   porta.
//! - PspImplicitAssignProcessToJob (0x605fb0): o processo criado por um
//!   membro herda o job do pai; os jobs com JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
//!   são pulados, e com PROCESS_CREATE_FLAGS_BREAKAWAY também os com
//!   JOB_OBJECT_LIMIT_BREAKAWAY_OK; pedir breakaway de um job que não deixa
//!   é STATUS_ACCESS_DENIED. PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY só fica em
//!   silos (nenhum aqui).
//! - PspAssignProcessToJobList: PS_ATTRIBUTE_JOB_LIST atribui o processo
//!   novo a cada job da lista, na ordem.
//! - PspRundownSingleProcess (0x604738): na saída, JOB_OBJECT_MSG_EXIT_PROCESS
//!   (ou ABNORMAL_EXIT_PROCESS para os status de exceção) para cada job da
//!   cadeia; depois PspRemoveProcessFromJobChain (ActiveProcesses desce e a
//!   contabilidade do processo é somada a cada job,
//!   PspFoldProcessAccountingIntoJob) e PspNotifyEmptyJobsInJobChain
//!   (ShadowActiveProcessCount desce; no zero, JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO,
//!   e um job em término é sinalizado).
//! - PspProcessDelete: o processo sai da ProcessListHead e solta o job.
//! - PspTerminateAllProcessesInJobHierarchy (0x698b28), o
//!   NtTerminateJobObject e o fechamento com KILL_ON_JOB_CLOSE: cada processo
//!   da hierarquia sai do job e termina com o status pedido.
//! - NtIsProcessInJob (0x71c420): STATUS_PROCESS_IN_JOB se o job está na
//!   cadeia do processo (sem handle de job, o job do processo).
//!
//! O callout de job do win32k (PsW32JobCalloutAddProcess) roda na atribuição
//! de um job com classe de restrições de UI e sessão válida, como no NT.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::limits::{self, set_clear_flags2};
use super::{ejob, eprocess, flags, limit, message, Outbox, JOBS, PARENT_LOCKED};
use super::{STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_PROCESS_IN_JOB, STATUS_PROCESS_IS_TERMINATING, STATUS_PROCESS_NOT_IN_JOB, STATUS_QUOTA_EXCEEDED, STATUS_RETRY, STATUS_SUCCESS};
use crate::ntos::ex::{list_entry, rundown};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Ejob, Eprocess};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// PROCESS_CREATE_FLAGS_BREAKAWAY e PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY.
pub const CREATE_BREAKAWAY: u32 = 0x1;
pub const CREATE_FORCE_BREAKAWAY: u32 = 0x400;
/// O maior NestingDepth de um job (PspAssignProcessToJob).
const MAXIMUM_NESTING_DEPTH: u32 = 100;
/// SessionId de um job sem sessão e o de um job misto.
const NO_SESSION: u32 = u32::MAX;
const MIXED_SESSION: u32 = 0xFFFF_FFFE;
/// EPROCESS.Flags3.AuxiliaryProcess, SubsystemProcess e SystemProcess.
const AUXILIARY_PROCESS: u32 = 1 << 5;
const SUBSYSTEM_PROCESS: u32 = 1 << 6;
const SYSTEM_PROCESS: u32 = 1 << 12;
/// PsW32JobCallout e os tipos do WIN32_JOBCALLOUT_PARAMETERS.
const PS_W32_JOB_CALLOUT: i32 = 6;
const JOB_CALLOUT_SET_INFORMATION: u32 = 0;
const JOB_CALLOUT_ADD_PROCESS: u32 = 1;
const JOB_CALLOUT_TERMINATE: u32 = 2;
/// PROCESS_QUERY_LIMITED_INFORMATION, o direito do NtIsProcessInJob.
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
/// STATUS_THREAD_IS_TERMINATING.
const STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;

/// As disposições do PspGetJobAssignmentDisposition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Disposition {
    Simple = 1,
    Already = 2,
    MoveDown = 3,
    Nest = 4,
    Move = 5,
}

fn parent_of(job: u64) -> u64 {
    ejob(job).parent_job.get()
}

/// PsIsJobParentImmutable: ParentLocked ou já com pai.
fn parent_immutable(job: &Ejob) -> bool {
    job.job_flags2.get() & PARENT_LOCKED != 0 || job.parent_job.get() != 0
}

/// PspIsJobMovable: dono da própria partição, sem pai fixo nem filhos, com
/// um único processo, ativo.
fn movable(job: &Ejob) -> bool {
    job.partition_owner_job.get() == job.address() && !parent_immutable(job) && job.child_job_list_head.flink.get() == job.child_job_list_head.address() && job.active_processes.get() == 1 && job.total_processes.get() == 1
}

/// PspIsProcessInJob(Process, Job).
pub(crate) fn is_process_in_job(process: u64, job: u64) -> u32 {
    let mut walk = eprocess(process).job.get();
    while walk != 0 {
        if walk == job {
            return STATUS_PROCESS_IN_JOB;
        }
        walk = parent_of(walk);
    }
    STATUS_PROCESS_NOT_IN_JOB
}

/// A disposição, sem a proteção de rundown (o chamador a tem).
fn disposition(job: u64, process: u64) -> Result<Disposition, u32> {
    let target = eprocess(process);
    if target.flags.get() & Eprocess::PROCESS_DELETE_MASK != 0 {
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    let current = target.job.get();
    if current == 0 {
        return Ok(Disposition::Simple);
    }
    if is_process_in_job(process, job) == STATUS_PROCESS_IN_JOB {
        return Ok(Disposition::Already);
    }
    let mut walk = job;
    while walk != 0 {
        if walk == current {
            return Ok(Disposition::MoveDown);
        }
        walk = parent_of(walk);
    }
    let body = ejob(job);
    if parent_immutable(body) || body.total_processes.get() != 0 {
        return if movable(body) { Ok(Disposition::Move) } else { Err(STATUS_NOT_SUPPORTED) };
    }
    Ok(Disposition::Nest)
}

/// PspGetJobAssignmentDisposition(Job, Process).
fn assignment_disposition(job: u64, process: u64) -> Result<Disposition, u32> {
    let rundown_pointer = eprocess(process).rundown_protect.address();
    if !rundown::acquire(rundown_pointer).unwrap_or(false) {
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    let result = {
        let _guard = JOBS.lock();
        disposition(job, process)
    };
    let _ = rundown::release(rundown_pointer);
    result
}

/// PspValidateJobAssignmentProcessLimits(Job, Process, Increment), com a
/// [`JOBS`].
fn validate_process_limits(job: u64, process: u64, increment: u32, outbox: &mut Outbox) -> u32 {
    let body = ejob(job);
    if body.shadow_active_process_count.get() == u32::MAX {
        return STATUS_QUOTA_EXCEEDED;
    }
    let limits = body.limit_flags.get();
    if limits & limit::ACTIVE_PROCESS != 0 {
        let active = body.active_processes.get().wrapping_sub(body.active_auxiliary_process_count.get()).wrapping_add(increment);
        if active > body.active_process_limit.get() {
            eprocess(process).flags2.atomic().fetch_and(!Eprocess::LAST_REPORT_MEMORY_MASK, Ordering::SeqCst);
            outbox.notify_filtered(body, message::ACTIVE_PROCESS_LIMIT, message::ACTIVE_PROCESS_LIMIT, 0, true);
            return STATUS_QUOTA_EXCEEDED;
        }
    }
    if limits & limit::JOB_TIME != 0 && body.event.header.signal_state.get() != 0 {
        return STATUS_QUOTA_EXCEEDED;
    }
    let job_flags = body.job_flags.get();
    if job_flags & flags::DISALLOW_NEW_PROCESSES != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if job_flags & flags::TERMINATING != 0 {
        return STATUS_PROCESS_IS_TERMINATING;
    }
    STATUS_SUCCESS
}

/// PspValidateJobChainLimits(Job, StopJob, Process, Flags), com a [`JOBS`].
fn validate_chain_limits(job: u64, stop: u64, process: u64, outbox: &mut Outbox) -> u32 {
    let mut walk = job;
    while walk != stop && walk != 0 {
        let status = validate_process_limits(walk, process, 1, outbox);
        if status & 0x8000_0000 != 0 {
            return status;
        }
        walk = parent_of(walk);
    }
    STATUS_SUCCESS
}

/// PspBindProcessSessionToJob(Job, Process), com a [`JOBS`].
fn bind_session(job: &Ejob, process: u64) -> u32 {
    let session = crate::ntos::mm::session::session_id(process);
    let current = job.session_id.get();
    if current == session {
        return STATUS_SUCCESS;
    }
    if current == NO_SESSION {
        job.session_id.set(session);
        return STATUS_SUCCESS;
    }
    // PspConvertJobToMixed(Job, FALSE).
    if current == MIXED_SESSION {
        return STATUS_SUCCESS;
    }
    if job.job_flags.get() & flags::UI_LIMITS != 0 {
        return STATUS_ACCESS_DENIED;
    }
    let partition = job.partition_object.get();
    if job.job_flags.get() & flags::SILO != 0 || partition.wrapping_add(1) & !1 != 0 {
        job.session_id.set(MIXED_SESSION);
        return STATUS_SUCCESS;
    }
    STATUS_ACCESS_DENIED
}

/// MmLinkJobProcess(Job, Process), com a [`JOBS`].
fn link_process(job: &Ejob, process: u64) {
    let target = eprocess(process);
    list_entry::insert_tail(&job.process_list_head, &target.job_links);
    target.job.set(job.address());
    target.flags3.atomic().fetch_or(Eprocess::JOB_VADS_ARE_TRACKED_MASK, Ordering::SeqCst);
}

/// PspUnlinkJobProcess(Job, Process), com a [`JOBS`].
fn unlink_process(process: u64) {
    let links = &eprocess(process).job_links;
    if links.flink.get() != 0 && list_entry::remove(links).is_some() {
        list_entry::initialize(links);
    }
}

/// PspDoesJobHierarchyPermitUILimits(Job, 1): nenhum ancestral com
/// restrições de UI.
fn hierarchy_permits_ui_limits(job: u64) -> bool {
    let mut walk = parent_of(job);
    while walk != 0 {
        if ejob(walk).job_flags.get() & flags::UI_LIMITS != 0 {
            return false;
        }
        walk = parent_of(walk);
    }
    true
}

/// PspEstablishJobHierarchy(Job, Process, CurrentJob, Disposition), com a
/// [`JOBS`].
fn establish_hierarchy(job: u64, process: u64, current: u64, disposition: Disposition, outbox: &mut Outbox) -> u32 {
    let body = ejob(job);
    match disposition {
        Disposition::Simple => {
            let status = bind_session(body, process);
            if status & 0x8000_0000 == 0 {
                super::reference_job(job);
                link_process(body, process);
            }
            status
        }
        Disposition::Already | Disposition::Move => STATUS_SUCCESS,
        Disposition::MoveDown => {
            unlink_process(process);
            link_process(body, process);
            super::reference_job(job);
            outbox.release_job(current);
            STATUS_SUCCESS
        }
        Disposition::Nest => {
            let parent = ejob(current);
            let count = parent.ancestor_count.get() + 1;
            let ancestors = if count > 2 {
                let array = guest::alloc_bytes((count - 2) * 8);
                if array == 0 {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                Some(array)
            } else {
                None
            };
            let status = bind_session(body, process);
            if status & 0x8000_0000 != 0 {
                if let Some(array) = ancestors {
                    guest::free_bytes(array);
                }
                return status;
            }
            // A referência do processo vai para o job novo; a que ele tinha
            // no job atual passa a ser a do filho no pai.
            super::reference_job(job);
            list_entry::insert_tail(&parent.child_job_list_head, &body.sibling_job_links);
            body.parent_job.set(current);
            body.root_job.set(parent.root_job.get());
            body.ancestor_count.set(count);
            body.nesting_depth.set(parent.nesting_depth.get().wrapping_add(1));
            if let Some(array) = ancestors {
                for index in 1..count - 2 {
                    guest::write64(array + index * 8, guest::read64(parent.ancestors.get() + (index - 1) * 8));
                }
                guest::write64(array, parent.parent_job.get());
                body.ancestors.set(array);
            }
            unlink_process(process);
            link_process(body, process);
            limits::set_effective_limits(job);
            body.effective_freeze_count.set(body.effective_freeze_count.get().wrapping_add(parent.effective_freeze_count.get()));
            body.effective_swap_count.set(body.effective_swap_count.get().wrapping_add(parent.effective_swap_count.get()));
            body.effective_background_count.set(body.effective_background_count.get().wrapping_add(parent.effective_background_count.get()));
            body.effective_notification_limit_count.set(body.effective_notification_limit_count.get().wrapping_add(parent.effective_notification_limit_count.get()));
            body.energy_tracking_state.value.set(parent.energy_tracking_state.value.get());
            let inherited = parent.job_flags.get() & flags::INHERITED;
            if inherited != 0 {
                body.job_flags.atomic().fetch_or(inherited, Ordering::SeqCst);
            }
            STATUS_SUCCESS
        }
    }
}

/// PspIncrementJobChainProcessCounts(Job, StopJob, Process), com a [`JOBS`].
fn increment_counts(job: u64, stop: u64, process: u64, outbox: &mut Outbox) {
    let target = eprocess(process);
    let auxiliary = target.flags3.get() & AUXILIARY_PROCESS != 0;
    let mut walk = job;
    while walk != stop && walk != 0 {
        let body = ejob(walk);
        if body.total_processes.get() != u32::MAX {
            body.total_processes.set(body.total_processes.get() + 1);
        }
        body.active_processes.set(body.active_processes.get().wrapping_add(1));
        body.shadow_active_process_count.set(body.shadow_active_process_count.get().wrapping_add(1));
        if auxiliary {
            body.active_auxiliary_process_count.set(body.active_auxiliary_process_count.get().wrapping_add(1));
        }
        walk = parent_of(walk);
    }
    let mut walk = job;
    while walk != stop && walk != 0 {
        let body = ejob(walk);
        body.job_flags.atomic().fetch_and(!flags::EMPTY_JOB_NOTIFIED, Ordering::SeqCst);
        outbox.notify_filtered(body, message::NEW_PROCESS, message::NEW_PROCESS, target.unique_process_id.get(), false);
        walk = parent_of(walk);
    }
}

/// WIN32_JOBCALLOUT_PARAMETERS {Job, CalloutType, Data} para o win32k
/// (PsInvokeWin32Callout(PsW32JobCallout)).
fn job_callout(job: &Ejob, callout_type: u32, data: u64) -> u32 {
    let block = guest::alloc_bytes(0x18);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write64(block, job.address());
    guest::write64(block + 8, callout_type as u64);
    guest::write64(block + 0x10, data);
    let status = crate::ntos::ps::win32::invoke_callout(PS_W32_JOB_CALLOUT, block);
    guest::free_bytes(block);
    status
}

/// O callout PsW32JobCalloutSetInformation da mudança da classe de UI.
pub(crate) fn job_set_information_callout(job: &Ejob, value: u32) -> u32 {
    job_callout(job, JOB_CALLOUT_SET_INFORMATION, value as u64)
}

/// O callout PsW32JobCalloutTerminate do PspJobDelete (sessão válida).
pub(crate) fn job_delete_callout(job: &Ejob) {
    if job.session_id.get() <= 0xFFFF_FFFD {
        let _ = job_callout(job, JOB_CALLOUT_TERMINATE, 0);
    }
}

/// PspAssignProcessToJob(Job, Process, Disposition).
fn assign(job: u64, process: u64, expected: Disposition) -> u32 {
    let target = eprocess(process);
    let rundown_pointer = target.rundown_protect.address();
    if !rundown::acquire(rundown_pointer).unwrap_or(false) {
        return STATUS_PROCESS_IS_TERMINATING;
    }
    let mut outbox = Outbox::default();
    let mut counted = false;
    let status = (|| -> u32 {
        let (current, disposition) = {
            let _guard = JOBS.lock();
            let disposition = match disposition(job, process) {
                Ok(disposition) => disposition,
                Err(_) => return STATUS_ACCESS_DENIED,
            };
            if disposition != expected {
                return STATUS_RETRY;
            }
            match disposition {
                Disposition::Already => return STATUS_SUCCESS,
                // Sem partições de memória nenhum job é movível aqui.
                Disposition::Move => return STATUS_NOT_SUPPORTED,
                _ => {}
            }
            let current = target.job.get();
            let body = ejob(job);
            if disposition == Disposition::Nest {
                let parent = ejob(current);
                if body.job_flags.get() & flags::UI_LIMITS != 0 && (parent.job_flags.get() & flags::UI_LIMITS != 0 || !hierarchy_permits_ui_limits(current)) {
                    return STATUS_NOT_SUPPORTED;
                }
                if parent.nesting_depth.get() as u32 + 1 > MAXIMUM_NESTING_DEPTH {
                    return STATUS_NOT_SUPPORTED;
                }
                if body.job_flags.get() & flags::NET_RATE_CONTROL_ACTIVE != 0 && parent.job_flags.get() & flags::NET_RATE_CONTROL_ACTIVE != 0 {
                    return STATUS_NOT_SUPPORTED;
                }
                let attributed = |job: &Ejob| job.disk_io_attribution_ref_count.get() != 0 || job.disk_io_attribution_context.get() != 0;
                if attributed(parent) && attributed(body) {
                    return STATUS_NOT_SUPPORTED;
                }
            }
            // A cadeia validada e contada: do job até o atual (que já conta
            // o processo); ao aninhar o job novo ainda não tem pai.
            let stop = if disposition == Disposition::Nest { 0 } else { current };
            let status = validate_chain_limits(job, stop, process, &mut outbox);
            if status & 0x8000_0000 != 0 {
                return status;
            }
            let status = establish_hierarchy(job, process, current, disposition, &mut outbox);
            if status & 0x8000_0000 != 0 {
                return status;
            }
            increment_counts(job, current, process, &mut outbox);
            counted = true;
            limits::apply_chain_limits(process);
            (current, disposition)
        };
        let _ = disposition;
        if !limits::assign_commit(process, current) {
            return STATUS_QUOTA_EXCEEDED;
        }
        let body = ejob(job);
        if body.ui_restrictions_class.get() != 0 && body.session_id.get() <= 0xFFFF_FFFD {
            let status = job_callout(body, JOB_CALLOUT_ADD_PROCESS, process);
            if status & 0x8000_0000 != 0 {
                return status;
            }
        }
        STATUS_SUCCESS
    })();
    outbox.deliver();
    if counted && status & 0x8000_0000 != 0 {
        let exit_status = if status == STATUS_PROCESS_IS_TERMINATING { status } else { STATUS_QUOTA_EXCEEDED };
        remove_from_chain(process, 0xA, exit_status);
    }
    let _ = rundown::release(rundown_pointer);
    status
}

/// PsAssignProcessToJobObject(Job, Process).
pub fn assign_process(job: u64, process: u64) -> u32 {
    loop {
        let expected = match assignment_disposition(job, process) {
            Ok(disposition) => disposition,
            Err(_) => return STATUS_ACCESS_DENIED,
        };
        let status = assign(job, process, expected);
        if status != STATUS_RETRY {
            return status;
        }
    }
}

/// PspImplicitAssignProcessToJob(ParentJob, Process, Flags): o processo
/// novo de um pai membro. 0 também quando ele fica sem job.
pub fn implicit_assign(parent_job: u64, process: u64, create_flags: u32) -> u32 {
    if parent_job == 0 {
        return STATUS_SUCCESS;
    }
    let mut outbox = Outbox::default();
    let target = {
        let _guard = JOBS.lock();
        // FORCE_BREAKAWAY só deixa o processo num silo.
        if create_flags & CREATE_FORCE_BREAKAWAY != 0 {
            return STATUS_SUCCESS;
        }
        let mut target = parent_job;
        while target != 0 {
            let limits = ejob(target).limit_flags.get();
            if limits & limit::SILENT_BREAKAWAY_OK != 0 || (create_flags & CREATE_BREAKAWAY != 0 && limits & limit::BREAKAWAY_OK != 0) {
                target = parent_of(target);
                continue;
            }
            break;
        }
        if create_flags & CREATE_BREAKAWAY != 0 && target == parent_job && ejob(target).job_flags.get() & flags::SILO == 0 {
            return STATUS_ACCESS_DENIED;
        }
        if target == 0 {
            return STATUS_SUCCESS;
        }
        let status = validate_chain_limits(target, 0, process, &mut outbox);
        if status & 0x8000_0000 != 0 {
            drop(_guard);
            outbox.deliver();
            return status;
        }
        let status = establish_hierarchy(target, process, 0, Disposition::Simple, &mut outbox);
        if status & 0x8000_0000 != 0 {
            drop(_guard);
            outbox.deliver();
            return status;
        }
        increment_counts(target, 0, process, &mut outbox);
        limits::apply_chain_limits(process);
        target
    };
    let _ = target;
    outbox.deliver();
    if !limits::assign_commit(process, 0) {
        return STATUS_QUOTA_EXCEEDED;
    }
    STATUS_SUCCESS
}

/// PspAssignProcessToJobList(Process, Jobs, Count): o PS_ATTRIBUTE_JOB_LIST.
pub fn assign_job_list(process: u64, jobs: &[u64]) -> u32 {
    for &job in jobs {
        let thread = process::get_current_thread();
        if thread != 0 && process::thread_record(thread).is_some_and(|record| record.exiting) {
            return STATUS_THREAD_IS_TERMINATING;
        }
        let status = assign_process(job, process);
        if status & 0x8000_0000 != 0 {
            return status;
        }
    }
    STATUS_SUCCESS
}

/// Os valores do PsQueryStatisticsProcess (EPROCESS_VALUES): tempos de
/// kernel e de usuário (100 ns), trocas de contexto e os seis contadores de
/// E/S do processo.
#[derive(Default, Clone, Copy)]
pub(crate) struct ProcessValues {
    pub kernel_time: u64,
    pub user_time: u64,
    pub context_switches: u64,
    pub io: [u64; 6],
    pub page_faults: u32,
}

/// PsQueryStatisticsProcess: os tempos do registro do processo e as trocas
/// de contexto das threads dele.
pub(crate) fn process_values(process: u64) -> ProcessValues {
    let target = eprocess(process);
    let (kernel_time, user_time, context_switches) = process::statistics(process);
    ProcessValues {
        kernel_time,
        user_time,
        context_switches,
        io: [
            target.read_operation_count.quad_part.get() as u64,
            target.write_operation_count.quad_part.get() as u64,
            target.other_operation_count.quad_part.get() as u64,
            target.read_transfer_count.quad_part.get() as u64,
            target.write_transfer_count.quad_part.get() as u64,
            target.other_transfer_count.quad_part.get() as u64,
        ],
        page_faults: target.vm.instance.page_fault_count.get(),
    }
}

/// PspFoldProcessAccountingIntoJob(Job, Process, Values), com a [`JOBS`].
fn fold_accounting(job: &Ejob, process: u64, values: &ProcessValues) {
    let add = |cell: &crate::ntos::inc::field::Field<i64>, value: u64| cell.set(cell.get().wrapping_add(value as i64));
    add(&job.total_user_time.quad_part, values.user_time);
    add(&job.this_period_total_user_time.quad_part, values.user_time);
    add(&job.total_kernel_time.quad_part, values.kernel_time);
    add(&job.this_period_total_kernel_time.quad_part, values.kernel_time);
    job.total_context_switches.set(job.total_context_switches.get().wrapping_add(values.context_switches));
    let counters = [&job.read_operation_count, &job.write_operation_count, &job.other_operation_count, &job.read_transfer_count, &job.write_transfer_count, &job.other_transfer_count];
    for (cell, value) in counters.iter().zip(values.io) {
        cell.set(cell.get().wrapping_add(value));
    }
    job.total_page_fault_count.set(job.total_page_fault_count.get().wrapping_add(values.page_faults));
    let peak = eprocess(process).commit_charge_peak.get();
    if peak > job.peak_process_memory_used.get() {
        job.peak_process_memory_used.set(peak);
    }
}

/// PspRemoveProcessFromJobChain(Process, NULL, Flags, ExitStatus): bit 0 o
/// processo sai da ProcessListHead, bit 1 ele termina, bit 2 a
/// contabilidade dele vai para os jobs, bit 3 conta um término.
pub(crate) fn remove_from_chain(process: u64, request: u32, exit_status: u32) {
    let target = eprocess(process);
    if target.flags3.get() & SYSTEM_PROCESS != 0 && request & 1 == 0 {
        return;
    }
    let first = target.flags2.atomic().fetch_or(Eprocess::JOB_NOT_REALLY_ACTIVE_MASK, Ordering::SeqCst) & Eprocess::JOB_NOT_REALLY_ACTIVE_MASK == 0;
    if request & 2 != 0 && target.flags.get() & Eprocess::PROCESS_INSERTED_MASK != 0 && target.flags3.get() & SUBSYSTEM_PROCESS == 0 {
        crate::ntos::ps::create::exit_process(process, exit_status);
    }
    let _guard = JOBS.lock();
    let fold = request & 4 != 0 && target.flags2.atomic().fetch_or(Eprocess::ACCOUNTING_FOLDED_MASK, Ordering::SeqCst) & Eprocess::ACCOUNTING_FOLDED_MASK == 0;
    let values = if fold {
        target.flags2.atomic().fetch_and(!Eprocess::LAST_REPORT_MEMORY_MASK, Ordering::SeqCst);
        Some(process_values(process))
    } else {
        None
    };
    let auxiliary = target.flags3.get() & AUXILIARY_PROCESS != 0;
    let mut walk = target.job.get();
    while walk != 0 {
        let body = ejob(walk);
        if first {
            body.active_processes.set(body.active_processes.get().wrapping_sub(1));
            if auxiliary {
                body.active_auxiliary_process_count.set(body.active_auxiliary_process_count.get().wrapping_sub(1));
            }
            if request & 8 != 0 {
                body.total_terminated_processes.set(body.total_terminated_processes.get().wrapping_add(1));
            }
        }
        if let Some(values) = &values {
            fold_accounting(body, process, values);
        }
        walk = parent_of(walk);
    }
    if request & 1 != 0 && target.job.get() != 0 {
        unlink_process(process);
    }
}

/// PspEvaluateAndNotifyEmptyJob(Job, Decrement, Notify), com a [`JOBS`]:
/// devolve se o job em término deve ser sinalizado.
fn evaluate_empty(job: u64, decrement: bool, notify: bool, outbox: &mut Outbox) -> bool {
    let body = ejob(job);
    let mut count = body.shadow_active_process_count.get();
    if decrement {
        count = count.wrapping_sub(1);
        body.shadow_active_process_count.set(count);
    }
    if count != 0 {
        return false;
    }
    let signal = body.job_flags.atomic().fetch_and(!flags::TERMINATING, Ordering::SeqCst) & flags::TERMINATING != 0;
    if body.job_flags.atomic().fetch_or(flags::EMPTY_JOB_NOTIFIED, Ordering::SeqCst) & flags::EMPTY_JOB_NOTIFIED == 0 && notify {
        // PspSendReliableJobNotification: ApcContext 0.
        outbox.notify_filtered(body, message::ACTIVE_PROCESS_ZERO, message::ACTIVE_PROCESS_ZERO, 0, false);
    }
    signal
}

/// Sinaliza os jobs cujo término acabou (KeSetEvent no KEVENT do EJOB).
fn signal_jobs(jobs: Vec<u64>) {
    for job in jobs {
        dispatcher::set_event(ejob(job).event.address());
        super::dereference_job(job);
    }
}

/// PspNotifyEmptyJobsInJobChain(Process).
fn notify_empty_jobs(process: u64) {
    let target = eprocess(process);
    let first = target.flags2.atomic().fetch_or(Eprocess::EMPTY_JOB_EVALUATED_MASK, Ordering::SeqCst) & Eprocess::EMPTY_JOB_EVALUATED_MASK == 0;
    let mut outbox = Outbox::default();
    let mut signaled = Vec::new();
    {
        let _guard = JOBS.lock();
        let mut walk = target.job.get();
        while walk != 0 {
            if evaluate_empty(walk, first, true, &mut outbox) {
                super::reference_job(walk);
                signaled.push(walk);
            }
            walk = parent_of(walk);
        }
    }
    outbox.deliver();
    signal_jobs(signaled);
}

/// Os status de saída que o PspRundownSingleProcess trata como término
/// anormal (as exceções que derrubam um processo).
fn abnormal_exit(status: u32) -> bool {
    matches!(status, 0xC000_008C..=0xC000_0096 | 0x8000_0001..=0x8000_0004 | 0xC000_0005 | 0xC000_0006 | 0xC000_001D | 0xC000_0025 | 0xC000_0026 | 0xC000_00FD | 0xC000_013A | 0xC000_02B4 | 0xC000_02B5 | 0xC000_02C9)
}

/// A primeira parte do PspRundownSingleProcess de um membro, antes dos
/// handles: JOB_OBJECT_MSG_EXIT_PROCESS ou ABNORMAL_EXIT_PROCESS para cada
/// job da cadeia (uma rotina de saída de processo).
pub fn process_exit_notify(process: u64) {
    let target = eprocess(process);
    if target.job.get() == 0 || target.flags2.get() & Eprocess::JOB_NOT_REALLY_ACTIVE_MASK != 0 {
        return;
    }
    let message = if abnormal_exit(target.exit_status.get() as u32) { message::ABNORMAL_EXIT_PROCESS } else { message::EXIT_PROCESS };
    set_clear_flags2(target, Eprocess::EXIT_PROCESS_REPORTED_MASK, Eprocess::LAST_REPORT_MEMORY_MASK);
    let mut outbox = Outbox::default();
    {
        let _guard = JOBS.lock();
        let mut walk = target.job.get();
        while walk != 0 {
            outbox.notify_filtered(ejob(walk), message, message, target.unique_process_id.get(), false);
            walk = parent_of(walk);
        }
    }
    outbox.deliver();
}

/// O fim do PspRundownSingleProcess, com o KPROCESS já sinalizado: o
/// processo sai da cadeia (contabilidade somada) e os jobs vazios avisam.
pub fn process_exited(process: u64) {
    if eprocess(process).job.get() == 0 {
        return;
    }
    remove_from_chain(process, 4, 0);
    notify_empty_jobs(process);
}

/// A parte do PspProcessDelete: o resto do commit volta aos jobs (o
/// MmDeleteProcessAddressSpace), o processo sai da ProcessListHead e solta
/// o job; EPROCESS.Job e CommitChargeJob voltam a NULL.
pub fn process_deleted(process: u64) {
    let target = eprocess(process);
    let remaining = target.commit_charge.get();
    if remaining != 0 {
        crate::ntos::mm::process_commit::release(process, remaining);
    }
    let job = target.job.get();
    if job == 0 {
        return;
    }
    remove_from_chain(process, 1, 0);
    {
        let _guard = JOBS.lock();
        target.job.set(0);
        target.commit_charge_job.set(0);
    }
    super::dereference_job(job);
}

/// PspTerminateAllProcessesInJobHierarchy(Job, ExitStatus, CountTermination):
/// todo processo do job e dos descendentes sai do job e termina; sem
/// processo à espera da avaliação de vazio, o job é avaliado (e
/// sinalizado) na hora.
pub fn terminate_hierarchy(job: u64, exit_status: u32, count_termination: bool) {
    let body = ejob(job);
    body.job_flags.atomic().fetch_or(flags::TERMINATING, Ordering::SeqCst);
    let mut pending = false;
    let processes: Vec<u64> = {
        let _guard = JOBS.lock();
        let mut collected = Vec::new();
        for member in limits::hierarchy(job) {
            for process in limits::processes_of(member) {
                if process::reference(process).is_some() {
                    if eprocess(process).flags2.get() & Eprocess::EMPTY_JOB_EVALUATED_MASK == 0 {
                        pending = true;
                    }
                    collected.push(process);
                }
            }
        }
        collected
    };
    let request = 6 | if count_termination { 8 } else { 0 };
    for process in processes {
        remove_from_chain(process, request, exit_status);
        let _ = process::dereference(process);
    }
    if !pending {
        let mut outbox = Outbox::default();
        let signal = {
            let _guard = JOBS.lock();
            evaluate_empty(job, false, false, &mut outbox)
        };
        outbox.deliver();
        if signal {
            dispatcher::set_event(body.event.address());
        }
    }
}

/// NtTerminateJobObject(JobHandle, ExitStatus) no modo `mode`.
pub fn terminate_job(handle: u64, exit_status: u32, mode: u8) -> u32 {
    let job = match super::object::reference_by_handle(handle, super::JOB_OBJECT_TERMINATE, mode) {
        Ok(job) => job,
        Err(status) => return status,
    };
    terminate_hierarchy(job, exit_status, false);
    super::dereference_job(job);
    STATUS_SUCCESS
}

/// NtAssignProcessToJobObject(JobHandle, ProcessHandle) no modo `mode`.
pub fn assign_by_handles(job_handle: u64, process_handle: u64, mode: u8) -> Result<u32, KernelError> {
    let job = match super::object::reference_by_handle(job_handle, super::JOB_OBJECT_ASSIGN_PROCESS, mode) {
        Ok(job) => job,
        Err(status) => return Ok(status),
    };
    // ProcessHandle -7: o processo corrente, sem referência.
    let (process, referenced) = if process_handle as i64 == -7 {
        (process::get_current_process(), false)
    } else {
        match reference_process(process_handle, 0x101, mode) {
            Ok(process) => (process, true),
            Err(status) => {
                super::dereference_job(job);
                return Ok(status);
            }
        }
    };
    let status = assign_process(job, process);
    if referenced {
        let _ = process::dereference(process);
    }
    super::dereference_job(job);
    Ok(status)
}

/// ObReferenceObjectByHandle(ProcessHandle, Access, PsProcessType, Mode): o
/// pseudo-handle é o processo corrente.
fn reference_process(handle: u64, access: u32, mode: u8) -> Result<u64, u32> {
    if handle == u64::MAX || handle == 0xFFFF_FFFF {
        let current = process::get_current_process();
        process::reference(current);
        return Ok(current);
    }
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cell, 0);
    let status = crate::ntos::ob::object_reference::reference_by_handle(handle, access, crate::ntos::ob::object_types::process_type().pointer, mode, cell, 0);
    let pointer = guest::read64(cell);
    guest::free_bytes(cell);
    match status {
        // A referência do Ob num EPROCESS é a do registro do processo.
        Ok(0) => Ok(pointer),
        Ok(status) => Err(status as u32),
        Err(error) => Err(if error.status != 0 { error.status } else { super::STATUS_INVALID_HANDLE }),
    }
}

/// NtIsProcessInJob(ProcessHandle, JobHandle) no modo `mode`.
pub fn is_process_in_job_by_handles(process_handle: u64, job_handle: u64, mode: u8) -> u32 {
    let process = match reference_process(process_handle, PROCESS_QUERY_LIMITED_INFORMATION, mode) {
        Ok(process) => process,
        Err(status) => return status,
    };
    let status = if job_handle != 0 {
        match super::object::reference_by_handle(job_handle, super::JOB_OBJECT_QUERY, mode) {
            Ok(job) => {
                let status = is_process_in_job(process, job);
                super::dereference_job(job);
                status
            }
            Err(status) => status,
        }
    } else {
        is_process_in_job(process, eprocess(process).job.get())
    };
    let _ = process::dereference(process);
    status
}
