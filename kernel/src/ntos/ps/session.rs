//! PsGetProcessSessionId — `system32/ntos/ps/session.js` e `debug-state.js`.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::eprocess;

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
