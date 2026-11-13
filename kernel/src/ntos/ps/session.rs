//! PsGetProcessSessionId — `system32/ntos/ps/session.js` e `debug-state.js`.

use super::process;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{eprocess, kthread};

/// Sessão NULL ou processo de sistema = 0; -1 também vira 0.
pub fn query(process: u64) -> u32 {
    let session = guest::read64(process + eprocess::SESSION);
    if session == 0 || guest::read32(process + eprocess::FLAGS3) & eprocess::SYSTEM_PROCESS_FLAG != 0 {
        return 0;
    }
    match guest::read32(session + 8) {
        0xFFFF_FFFF => 0,
        id => id,
    }
}

/// PsGetProcessDebugPort: acessor opaco exato, sem referência nem
/// substituição pelo processo corrente.
pub fn debug_port(process: u64) -> u64 {
    guest::read64(process + eprocess::DEBUG_PORT)
}

/// PsIsProcessBeingDebugged: há uma porta de depuração no EPROCESS.
pub fn is_being_debugged(process: u64) -> bool {
    debug_port(process) != 0
}

/// PsGetProcessSessionIdEx: (ULONG)-1 para quem não pertence a uma sessão
/// (o processo de sistema).
pub fn query_ex(process: u64) -> u32 {
    if guest::read32(process + eprocess::FLAGS3) & eprocess::SYSTEM_PROCESS_FLAG != 0 {
        return 0xFFFF_FFFF;
    }
    query(process)
}

/// PsGetThreadSessionId: a sessão do processo dono da thread.
pub fn thread_session_id(thread: u64) -> u32 {
    query(guest::read64(thread + kthread::PROCESS))
}

/// PsGetCurrentProcessSessionId: a sessão do processo corrente (o anexado).
pub fn current_process_session_id() -> u32 {
    query(process::get_current_process())
}
