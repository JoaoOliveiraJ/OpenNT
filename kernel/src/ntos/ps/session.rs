//! PsGetProcessSessionId.

use super::process;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Ethread, MmSessionSpace};

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: PEPROCESS do chamador (vivo ou retido).
    unsafe { Eprocess::at(process) }
}

/// Sessão NULL ou processo de sistema = 0; -1 também vira 0.
pub fn query(process: u64) -> u32 {
    let object = eprocess(process);
    let session = object.session.get();
    if session == 0 || object.system_process() != 0 {
        return 0;
    }
    // SAFETY: EPROCESS.Session aponta para o MM_SESSION_SPACE da sessão.
    match unsafe { MmSessionSpace::at(session) }.session_id.get() {
        0xFFFF_FFFF => 0,
        id => id,
    }
}

/// PsGetProcessDebugPort: acessor opaco exato, sem referência nem
/// substituição pelo processo corrente.
pub fn debug_port(process: u64) -> u64 {
    eprocess(process).debug_port.get()
}

/// PsIsProcessBeingDebugged: há uma porta de depuração no EPROCESS.
pub fn is_being_debugged(process: u64) -> bool {
    debug_port(process) != 0
}

/// PsGetProcessSessionIdEx: no ntoskrnl 19041 (0x315400) é o
/// MmGetSessionIdEx, (ULONG)-1 para um processo sem sessão (Session NULL,
/// como o smss mestre) e para o processo de sistema.
pub fn query_ex(process: u64) -> u32 {
    crate::ntos::mm::session::session_id_ex(process)
}

/// PsGetThreadSessionId: a sessão do processo dono da thread.
pub fn thread_session_id(thread: u64) -> u32 {
    // SAFETY: PETHREAD do chamador.
    query(unsafe { Ethread::at(thread) }.tcb.process.get())
}

/// PsGetCurrentProcessSessionId: a sessão do processo corrente (o anexado).
pub fn current_process_session_id() -> u32 {
    query(process::get_current_process())
}

/// O NTSTATUS que o PsQueryCpuQuotaInformation devolve sem o DFSS.
const STATUS_DFSS_DISABLED: u32 = 0xC000_01A9;

/// PsQueryCpuQuotaInformation (ntoskrnl 19041, rva 0x3cf8b4), a
/// SystemCpuQuotaInformation (113): sem o Dynamic Fair Share Scheduling
/// entre sessões (PsCpuFairShareEnabled zero, o caso do OpenNT, que não tem
/// cotas de CPU por sessão), devolve 0xC00001A9 sem tocar no buffer nem no
/// tamanho. O psmsrv!PsmpIsDfssActive conclui por esse status que o DFSS
/// está desligado.
pub fn query_cpu_quota_information() -> u32 {
    STATUS_DFSS_DISABLED
}
