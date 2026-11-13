//! Acessores de silo do NT 19041.
//!
//! O host é NULL; -3 em ETHREAD.Silo significa herdar do processo dono. A
//! anexação de espaço de endereço (ApcState.Process) não muda esse dono.
//! Só se inspecionam os campos reais; nenhum contêiner é fabricado.

use crate::ntos::ps::process;
use crate::ntos::ke::pcr;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{ejob, eprocess, kthread};

pub const INHERIT: u64 = 0xFFFF_FFFF_FFFF_FFFD;

/// O silo hospedeiro é representado por NULL na ABI.
pub const HOST_SILO: u64 = 0;

/// PsGetHostSilo.
pub fn host_silo() -> u64 {
    HOST_SILO
}

/// PsIsHostSilo.
pub fn is_host_silo(silo: u64) -> bool {
    silo == HOST_SILO
}

pub fn job_silo(job: u64) -> u64 {
    let mut job = job;
    while job != 0 && guest::read32(job + ejob::FLAGS) & 0x4000_0000 == 0 {
        job = guest::read64(job + ejob::PARENT);
    }
    job
}

pub fn effective_server_silo(silo: u64) -> u64 {
    let mut silo = silo;
    while silo != 0 && guest::read64(silo + ejob::SERVER_SILO_GLOBALS) == 0 {
        silo = guest::read64(silo + ejob::PARENT);
    }
    silo
}

pub fn process_server_silo(process: u64) -> u64 {
    guest::read64(process + eprocess::SERVER_SILO)
}

pub fn thread_server_silo(thread: u64) -> u64 {
    let silo = guest::read64(thread + kthread::SILO);
    if silo == INHERIT { process_server_silo(guest::read64(thread + kthread::PROCESS)) } else { effective_server_silo(silo) }
}

/// PsGetCurrentSilo.
pub fn current_silo() -> u64 {
    let thread = process::get_current_thread();
    let silo = guest::read64(thread + kthread::SILO);
    if silo == INHERIT { job_silo(guest::read64(guest::read64(thread + kthread::PROCESS) + eprocess::JOB)) } else { silo }
}

/// PsGetCurrentServerSilo: NULL dentro de DPC.
pub fn current_server_silo() -> u64 {
    if pcr::get_nesting_level() != 0 { 0 } else { thread_server_silo(process::get_current_thread()) }
}

/// PsIsCurrentThreadInServerSilo.
pub fn is_current_thread_in_server_silo() -> bool {
    current_server_silo() != 0
}

/// PsAttachSiloToCurrentThread: devolve o silo anterior.
pub fn attach(silo: u64) -> u64 {
    let field = process::get_current_thread() + kthread::SILO;
    let previous = guest::read64(field);
    guest::write64(field, silo);
    previous
}

pub fn detach(previous: u64) {
    guest::write64(process::get_current_thread() + kthread::SILO, previous);
}

/// PsGetJobSilo: STATUS_JOB_NO_CONTAINER sem silo.
pub fn get_job_silo(job: u64, output: u64) -> u32 {
    if job == 0 {
        return 0xC000_000D;
    }
    let silo = job_silo(job);
    if silo == 0 {
        return 0xC000_0509;
    }
    guest::write64(output, silo);
    0
}

/// PsGetJobServerSilo: o 19041 limpa a saída até com job NULL.
pub fn get_job_server_silo(job: u64, output: u64) -> u32 {
    guest::write64(output, effective_server_silo(job));
    if job != 0 { 0 } else { 0xC000_000D }
}

/// PsIsCurrentThreadPrefetching (bit 6 de SameThreadApcFlags).
pub fn is_prefetching() -> bool {
    (guest::read8(process::get_current_thread() + kthread::SAME_THREAD_APC_FLAGS) >> 6) & 1 != 0
}
