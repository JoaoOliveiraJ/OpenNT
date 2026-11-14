//! Classes do NtSetInformationProcess que mudam o EPROCESS.
//!
//! ProcessBreakOnTermination (29): o processo crítico, cujo fim derruba o
//! sistema (o RtlSetProcessIsCritical da ntdll; o smss marca assim o csrss
//! que cria). Como no NT: o buffer é um ULONG (outro tamanho dá
//! STATUS_INFO_LENGTH_MISMATCH), quem pede precisa de SeDebugPrivilege
//! (STATUS_PRIVILEGE_NOT_HELD), o handle precisa de PROCESS_SET_INFORMATION,
//! e o valor liga ou desliga EPROCESS.Flags.BreakOnTermination.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
/// SeDebugPrivilege.
const DEBUG_PRIVILEGE: u64 = 20;

/// ProcessBreakOnTermination de modo usuário: `process_of` resolve o handle
/// com o acesso pedido para o EPROCESS.
pub fn break_on_termination(buffer: u64, length: u32, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    if length != 4 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    if !user_probe::probe_user_read(buffer, 4) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let value = guest::try_read::<u32>(buffer)?;
    if !crate::ntos::se::privilege::single_privilege_check(DEBUG_PRIVILEGE, 1) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    // PROCESS_SET_INFORMATION.
    let process = match process_of(0x200) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
    unsafe { Eprocess::at(process) }.set_break_on_termination((value != 0) as u32);
    Ok(0)
}
