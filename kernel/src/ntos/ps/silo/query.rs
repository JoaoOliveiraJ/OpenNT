//! Acessores de silo do NT 19041.
//!
//! O host é NULL; -3 em ETHREAD.Silo significa herdar do processo dono. A
//! anexação de espaço de endereço (ApcState.Process) não muda esse dono.
//! Só se inspecionam os campos reais; nenhum contêiner é fabricado.

use crate::ntos::ps::process;
use crate::ntos::ke::pcr;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Ejob, Eprocess, Ethread};

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

fn ejob(job: u64) -> &'static Ejob {
    // SAFETY: jobs vivos (o do processo, um pai na cadeia ou o do chamador).
    unsafe { Ejob::at(job) }
}

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: processo vivo (dono da thread ou o do chamador).
    unsafe { Eprocess::at(process) }
}

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: thread viva (a corrente ou a do chamador).
    unsafe { Ethread::at(thread) }
}

pub fn job_silo(job: u64) -> u64 {
    let mut job = job;
    while job != 0 && ejob(job).silo() == 0 {
        job = ejob(job).parent_job.get();
    }
    job
}

pub fn effective_server_silo(silo: u64) -> u64 {
    let mut silo = silo;
    while silo != 0 && ejob(silo).server_silo_globals.get() == 0 {
        silo = ejob(silo).parent_job.get();
    }
    silo
}

pub fn process_server_silo(process: u64) -> u64 {
    eprocess(process).server_silo.get()
}

pub fn thread_server_silo(thread: u64) -> u64 {
    let thread = ethread(thread);
    let silo = thread.silo.get();
    if silo == INHERIT { process_server_silo(thread.tcb.process.get()) } else { effective_server_silo(silo) }
}

/// PsGetCurrentSilo.
pub fn current_silo() -> u64 {
    let thread = ethread(process::get_current_thread());
    let silo = thread.silo.get();
    if silo == INHERIT { job_silo(eprocess(thread.tcb.process.get()).job.get()) } else { silo }
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
    let field = &ethread(process::get_current_thread()).silo;
    let previous = field.get();
    field.set(silo);
    previous
}

pub fn detach(previous: u64) {
    ethread(process::get_current_thread()).silo.set(previous);
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
    // SAFETY: PESILO* de saída do chamador de kernel.
    unsafe { Field::<u64>::at(output) }.set(silo);
    0
}

/// PsGetJobServerSilo: o 19041 limpa a saída até com job NULL.
pub fn get_job_server_silo(job: u64, output: u64) -> u32 {
    // SAFETY: PESILO* de saída do chamador de kernel.
    unsafe { Field::<u64>::at(output) }.set(effective_server_silo(job));
    if job != 0 { 0 } else { 0xC000_000D }
}

/// PsIsCurrentThreadPrefetching (bit 6 de SameThreadApcFlags).
pub fn is_prefetching() -> bool {
    ethread(process::get_current_thread()).prefetching() != 0
}

// ---- ps-process-info: sessão de serviço do silo (ntoskrnl 19041) -----------

/// PsGetServerSiloServiceSessionId (0x32d5c0): SILO_USER_SHARED_DATA.
/// ServiceSessionId do silo (ESERVERSILO_GLOBALS.UserSharedData). O host
/// (NULL) usa PspHostSiloGlobals, cujo SILO_USER_SHARED_DATA o
/// PspInitializeSiloStructures zera (só +0x18 recebe -1): a sessão de serviço
/// do host é 0, a mesma que PsIsServiceSession(0) aceita sem consulta.
pub fn service_session_id(silo: u64) -> u32 {
    user_shared_data(silo).map_or(0, |data| data.service_session_id.get())
}

/// SILO_USER_SHARED_DATA de um silo de servidor
/// (ESERVERSILO_GLOBALS.UserSharedData); o host (NULL) não tem.
pub fn user_shared_data(silo: u64) -> Option<&'static crate::ntos::inc::types::SiloUserSharedData> {
    use crate::ntos::inc::types::{EserversiloGlobals, SiloUserSharedData};
    if silo == HOST_SILO {
        return None;
    }
    // SAFETY: um silo de servidor tem ESERVERSILO_GLOBALS e o seu
    // SILO_USER_SHARED_DATA vivos enquanto o job vive.
    let globals = unsafe { EserversiloGlobals::at(ejob(silo).server_silo_globals.get()) };
    Some(unsafe { SiloUserSharedData::at(globals.user_shared_data.get()) })
}
