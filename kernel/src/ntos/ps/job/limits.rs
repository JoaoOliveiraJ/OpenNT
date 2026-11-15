//! Limites dos jobs, como no ntoskrnl 19041.
//!
//! - PspSetEffectiveJobLimits (rva 0x6937d4): os limites efetivos de um job
//!   combinam os dele com os efetivos do pai — afinidade (a do job contida
//!   na do pai, senão a do pai), classe de prioridade (a de menor posto na
//!   PspPriorityClassRank), classe de escalonamento (a menor), working set,
//!   memória por processo e tempo de usuário por processo (o limite menor, e
//!   o job que o impõe); EffectiveLimitFlags = LimitFlags | os efetivos do
//!   pai.
//! - PspApplyJobLimitsToProcess (rva 0x60596c): o teto de commit do processo
//!   (EPROCESS.CommitChargeLimit, em páginas) é o EffectiveProcessMemoryLimit
//!   com JOB_OBJECT_LIMIT_PROCESS_MEMORY efetivo, senão 0; a classe de
//!   prioridade efetiva vai para EPROCESS.PriorityClass. A afinidade, a
//!   prioridade de base e o quantum ficam com o escalonador, que não os lê
//!   do job aqui.
//! - PspChangeJobMemoryUsageByProcess (rva 0x65dd10): o commit de um
//!   processo cobrado em cada job da cadeia, de EPROCESS.CommitChargeJob até
//!   o job de parada; acima de JobMemoryLimit (ou do limite total interno)
//!   a cobrança falha, ou é forçada (bit 0 das flags, o MmAssignProcessToJob)
//!   — nos dois casos com JOB_OBJECT_MSG_JOB_MEMORY_LIMIT (filtrada pelo bit
//!   9 do CompletionFilter, como no NT) uma vez por processo; o pico do job
//!   e o do processo sobem; uma falha desfaz a cobrança nos jobs abaixo.
//! - PsReportProcessMemoryLimitViolation (rva 0x908884): o processo corrente
//!   passou do teto: JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT para o job que
//!   impõe o limite.
//! - MmAssignProcessToJob (rva 0x605c30): o commit inteiro do processo vai
//!   para o job novo (cobrança forçada) e EPROCESS.Flags2.ReportCommitChanges
//!   liga.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{ejob, eprocess, limit, message, Outbox, JOBS};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, KaffinityEx};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;

/// PspPriorityClassRank: o posto de cada PROCESS_PRIORITY_CLASS (0..7).
const PRIORITY_CLASS_RANK: [u8; 8] = [6, 0, 2, 4, 5, 1, 3, 0];
/// EffectiveSchedulingClass de um job raiz sem a classe própria.
const ROOT_SCHEDULING_CLASS: u32 = 10;
/// Os bits da CompletionFilter que liberam as violações de memória (os dois
/// usam o bit 9, como o NT).
const MEMORY_LIMIT_FILTER_BIT: u32 = 9;

fn parent_of(job: u64) -> u64 {
    ejob(job).parent_job.get()
}

/// Copia uma KAFFINITY_EX inteira.
fn copy_affinity(destination: &KaffinityEx, source: &KaffinityEx) {
    let bytes = guest::read_bytes(source.address(), KaffinityEx::SIZE as usize);
    guest::write_bytes(destination.address(), &bytes);
}

fn affinity_empty(affinity: &KaffinityEx) -> bool {
    let count = (affinity.count.get() as usize).min(affinity.bitmap.len());
    affinity.bitmap[..count].iter().all(|group| group.get() == 0)
}

/// PspSetEffectiveJobLimits(Job, NULL), com a [`JOBS`].
pub(crate) fn set_effective_limits(job: u64) {
    let body = ejob(job);
    let parent = parent_of(job);
    let own = body.limit_flags.get();
    // Afinidade.
    if own & limit::AFFINITY != 0 {
        let parent_affinity = (parent != 0).then(|| &ejob(parent).effective_affinity).filter(|affinity| !affinity_empty(affinity));
        match parent_affinity {
            Some(parent_affinity) => {
                let count = (body.affinity.count.get() as usize).max(parent_affinity.count.get() as usize).min(body.affinity.bitmap.len());
                let contained = (0..count).all(|group| body.affinity.bitmap[group].get() & parent_affinity.bitmap[group].get() == body.affinity.bitmap[group].get());
                if contained && !affinity_empty(&body.affinity) {
                    copy_affinity(&body.effective_affinity, &body.affinity);
                } else {
                    copy_affinity(&body.effective_affinity, parent_affinity);
                }
            }
            None => copy_affinity(&body.effective_affinity, &body.affinity),
        }
    } else if parent != 0 {
        copy_affinity(&body.effective_affinity, &ejob(parent).effective_affinity);
    } else {
        guest::write_bytes(body.effective_affinity.address(), &[0u8; KaffinityEx::SIZE as usize]);
        body.effective_affinity.count.set(1);
        body.effective_affinity.size.set(0x14);
    }
    // Classe de prioridade.
    let inherited = if parent != 0 { ejob(parent).effective_priority_class.get() } else { 0 };
    let class = if own & limit::PRIORITY_CLASS != 0 {
        let own_class = body.priority_class.get();
        if PRIORITY_CLASS_RANK[inherited as usize & 7] >= PRIORITY_CLASS_RANK[own_class as usize & 7] { own_class } else { inherited }
    } else {
        inherited
    };
    body.effective_priority_class.set(class);
    // Classe de escalonamento.
    let inherited = if parent != 0 { ejob(parent).effective_scheduling_class.get() } else { ROOT_SCHEDULING_CLASS };
    let scheduling = if own & limit::SCHEDULING_CLASS != 0 && body.scheduling_class.get() < inherited { body.scheduling_class.get() } else { inherited };
    body.effective_scheduling_class.set(scheduling);
    // Working set.
    let (minimum, maximum) = if parent != 0 { (ejob(parent).effective_minimum_working_set_size.get(), ejob(parent).effective_maximum_working_set_size.get()) } else { (0, 0) };
    let (minimum, maximum) = if own & limit::WORKINGSET != 0 && (body.maximum_working_set_size.get() < maximum || maximum == 0) {
        (body.minimum_working_set_size.get(), body.maximum_working_set_size.get())
    } else {
        (minimum, maximum)
    };
    body.effective_minimum_working_set_size.set(minimum);
    body.effective_maximum_working_set_size.set(maximum);
    // Memória por processo (páginas) e o job que a impõe.
    let (memory, memory_job) = if parent != 0 { (ejob(parent).effective_process_memory_limit.get(), ejob(parent).effective_process_memory_limit_job.get()) } else { (0, 0) };
    let (memory, memory_job) = if own & limit::PROCESS_MEMORY != 0 && (body.process_memory_limit.get() < memory || memory == 0) { (body.process_memory_limit.get(), job) } else { (memory, memory_job) };
    body.effective_process_memory_limit.set(memory);
    body.effective_process_memory_limit_job.set(memory_job);
    // Tempo de usuário por processo.
    let (time, time_job) = if parent != 0 { (ejob(parent).effective_per_process_user_time_limit.quad_part.get(), ejob(parent).effective_per_process_user_time_limit_job.get()) } else { (0, 0) };
    let own_time = body.per_process_user_time_limit.quad_part.get();
    let (time, time_job) = if own & limit::PROCESS_TIME != 0 && (own_time < time || time == 0) { (own_time, job) } else { (time, time_job) };
    body.effective_per_process_user_time_limit.quad_part.set(time);
    body.effective_per_process_user_time_limit_job.set(time_job);
    let inherited_flags = if parent != 0 { ejob(parent).effective_limit_flags.get() } else { 0 };
    body.effective_limit_flags.set(own | inherited_flags);
}

/// PspApplyJobLimitsToProcess(Process, 0), com a [`JOBS`].
pub(crate) fn apply_job_limits(process: u64) {
    let target = eprocess(process);
    let job = target.job.get();
    if job == 0 {
        return;
    }
    let body = ejob(job);
    let effective = body.effective_limit_flags.get();
    if effective & limit::PRIORITY_CLASS != 0 {
        target.priority_class.set(body.effective_priority_class.get());
    }
    let ceiling = if effective & limit::PROCESS_MEMORY != 0 { body.effective_process_memory_limit.get() } else { 0 };
    target.commit_charge_limit.set(ceiling);
}

/// PspApplyJobChainLimitsToProcess, com a [`JOBS`]: os limites e, no fim,
/// NewProcessReported liga e LastReportMemory desliga.
pub(crate) fn apply_chain_limits(process: u64) {
    apply_job_limits(process);
    set_clear_flags2(eprocess(process), Eprocess::NEW_PROCESS_REPORTED_MASK, Eprocess::LAST_REPORT_MEMORY_MASK);
}

/// RtlInterlockedSetClearBits sobre EPROCESS.Flags2.
pub(crate) fn set_clear_flags2(target: &Eprocess, set: u32, clear: u32) {
    let cell = target.flags2.atomic();
    let mut current = cell.load(Ordering::SeqCst);
    loop {
        match cell.compare_exchange(current, (current | set) & !clear, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(seen) => current = seen,
        }
    }
}

/// O job e os descendentes, em pré-ordem (PspEnumJobsAndProcessesInJobHierarchy),
/// com a [`JOBS`].
pub(crate) fn hierarchy(job: u64) -> Vec<u64> {
    let mut jobs = alloc::vec![job];
    let mut index = 0;
    while index < jobs.len() {
        let current = ejob(jobs[index]);
        let head = current.child_job_list_head.address();
        let mut link = current.child_job_list_head.flink.get();
        let mut children = Vec::new();
        while link != head && link != 0 {
            children.push(link - core::mem::offset_of!(crate::ntos::inc::types::Ejob, sibling_job_links) as u64);
            // SAFETY: os vínculos da lista de filhos são LIST_ENTRYs vivas.
            link = unsafe { <crate::ntos::inc::types::ListEntry as crate::ntos::inc::field::NtStruct>::at(link) }.flink.get();
        }
        jobs.splice(index + 1..index + 1, children);
        index += 1;
    }
    jobs
}

/// Os processos ligados a um job (a ProcessListHead), com a [`JOBS`].
pub(crate) fn processes_of(job: u64) -> Vec<u64> {
    let body = ejob(job);
    let head = body.process_list_head.address();
    let mut link = body.process_list_head.flink.get();
    let mut processes = Vec::new();
    while link != head && link != 0 {
        let process = link - core::mem::offset_of!(Eprocess, job_links) as u64;
        processes.push(process);
        link = eprocess(process).job_links.flink.get();
    }
    processes
}

/// Os efetivos de toda a hierarquia e os limites de cada processo dela
/// (PspSetJobLimitsJobPreCallback e PspSetJobLimitsProcessCallback), com a
/// [`JOBS`].
pub(crate) fn refresh_hierarchy(job: u64) {
    for member in hierarchy(job) {
        set_effective_limits(member);
        for process in processes_of(member) {
            apply_job_limits(process);
        }
    }
}

/// PspChangeJobMemoryUsageByProcess(Flags, Delta, Process, StopJob), com a
/// [`JOBS`]. `delta` em páginas. Devolve se a cobrança coube.
pub(crate) fn change_job_memory_usage(flags: u32, delta: i64, process: u64, stop: u64, outbox: &mut Outbox) -> bool {
    let target = eprocess(process);
    if flags & 2 == 0 || target.job.get() == 0 {
        return true;
    }
    let start = target.commit_charge_job.get();
    let mut success = true;
    let mut failed_at = 0;
    let mut job = start;
    while job != stop && job != 0 {
        let body = ejob(job);
        let used = body.current_job_memory_used.get();
        let updated = used.wrapping_add(delta as u64);
        let overflow = if delta > 0 { updated < used } else { updated > used };
        if overflow {
            if success {
                failed_at = job;
                success = false;
            }
            job = parent_of(job);
            continue;
        }
        let total = body.shared_commit_charge.get().wrapping_add(updated);
        let limits = body.limit_flags.get();
        let violated = delta > 0 && ((limits & limit::JOB_TOTAL_MEMORY != 0 && total > body.job_total_memory_limit.get()) || (limits & limit::JOB_MEMORY != 0 && updated > body.job_memory_limit.get()));
        if violated {
            if flags & 1 != 0 {
                body.current_job_memory_used.set(updated);
            } else if success {
                failed_at = job;
                success = false;
            }
            let reported = target.flags2.get() & (Eprocess::NEW_PROCESS_REPORTED_MASK | Eprocess::LAST_REPORT_MEMORY_MASK);
            if body.completion_port.get() != 0 && body.completion_filter.get() & (1 << MEMORY_LIMIT_FILTER_BIT) != 0 && reported == Eprocess::NEW_PROCESS_REPORTED_MASK {
                target.flags2.atomic().fetch_or(Eprocess::LAST_REPORT_MEMORY_MASK, Ordering::SeqCst);
                outbox.notify(body, message::JOB_MEMORY_LIMIT, target.unique_process_id.get(), true);
            }
        }
        if success {
            body.current_job_memory_used.set(updated);
        }
        if delta > 0 {
            if updated > body.peak_job_memory_used.get() {
                body.peak_job_memory_used.set(updated);
            }
            let commit = target.commit_charge.get();
            if commit != 0 && commit > body.peak_process_memory_used.get() {
                body.peak_process_memory_used.set(commit);
            }
        }
        job = parent_of(job);
    }
    if !success {
        let mut job = start;
        while job != failed_at && job != 0 {
            let body = ejob(job);
            body.current_job_memory_used.set(body.current_job_memory_used.get().wrapping_sub(delta as u64));
            job = parent_of(job);
        }
    }
    success
}

/// A cobrança (ou devolução) de commit de um processo nos jobs dele, com a
/// trava e a entrega das notificações: o papel das chamadas do
/// MiChargeFullProcessCommitment e do MiReturnFullProcessCharges, que só
/// cobram com EPROCESS.Flags2.ReportCommitChanges.
pub fn charge_jobs(process: u64, delta: i64) -> bool {
    if eprocess(process).flags2.get() & Eprocess::REPORT_COMMIT_CHANGES_MASK == 0 {
        return true;
    }
    let mut outbox = Outbox::default();
    let charged = {
        let _guard = JOBS.lock();
        change_job_memory_usage(2, delta, process, 0, &mut outbox)
    };
    outbox.deliver();
    charged
}

/// MmAssignProcessToJob(Process, StopJob): CommitChargeJob passa a ser o job
/// do processo, o commit dele é cobrado (forçado) da cadeia até StopJob e
/// ReportCommitChanges liga. FALSE quando o espaço do processo já não existe.
pub(crate) fn assign_commit(process: u64, stop: u64) -> bool {
    if crate::ntos::ps::user::process_state::get(process).is_none() && process != process::get_system_process() {
        return false;
    }
    let target = eprocess(process);
    let mut outbox = Outbox::default();
    {
        let _guard = JOBS.lock();
        target.commit_charge_job.set(target.job.get());
        change_job_memory_usage(3, target.commit_charge.get() as i64, process, stop, &mut outbox);
        target.flags2.atomic().fetch_or(Eprocess::REPORT_COMMIT_CHANGES_MASK, Ordering::SeqCst);
    }
    outbox.deliver();
    true
}

/// PsReportProcessMemoryLimitViolation: o processo corrente passou do teto
/// de commit.
pub fn report_process_memory_limit_violation() {
    let current = eprocess(process::get_current_process());
    let job = current.job.get();
    if job == 0 {
        return;
    }
    let mut outbox = Outbox::default();
    {
        let _guard = JOBS.lock();
        let limiting = ejob(job).effective_process_memory_limit_job.get();
        if limiting == 0 {
            return;
        }
        let body = ejob(limiting);
        if body.limit_flags.get() & limit::PROCESS_MEMORY == 0 {
            return;
        }
        let reported = current.flags2.get() & (Eprocess::NEW_PROCESS_REPORTED_MASK | Eprocess::LAST_REPORT_MEMORY_MASK);
        if body.completion_port.get() != 0 && body.completion_filter.get() & (1 << MEMORY_LIMIT_FILTER_BIT) != 0 && reported == Eprocess::NEW_PROCESS_REPORTED_MASK {
            current.flags2.atomic().fetch_or(Eprocess::LAST_REPORT_MEMORY_MASK, Ordering::SeqCst);
            outbox.notify(body, message::PROCESS_MEMORY_LIMIT, current.unique_process_id.get(), true);
        }
    }
    outbox.deliver();
}
