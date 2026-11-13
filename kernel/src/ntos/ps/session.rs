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

/// PsGetProcessSessionIdEx: (ULONG)-1 para quem não pertence a uma sessão
/// (o processo de sistema).
pub fn query_ex(process: u64) -> u32 {
    if eprocess(process).system_process() != 0 {
        return 0xFFFF_FFFF;
    }
    query(process)
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
