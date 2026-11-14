//! Classes do NtSetInformationProcess que mudam o EPROCESS, para o modo
//! usuário e para os drivers (ZwSetInformationProcess, PreviousMode
//! KernelMode).
//!
//! - ProcessBreakOnTermination (29): o processo crítico, cujo fim derruba o
//!   sistema (o RtlSetProcessIsCritical da ntdll; o smss marca assim o csrss
//!   que cria; o win32kfull marca o processo corrente). Como no NT: o buffer
//!   é um ULONG (outro tamanho dá STATUS_INFO_LENGTH_MISMATCH), quem pede
//!   precisa de SeDebugPrivilege no modo anterior (STATUS_PRIVILEGE_NOT_HELD;
//!   KernelMode sempre passa), o handle precisa de PROCESS_SET_INFORMATION, e
//!   o valor liga ou desliga EPROCESS.Flags.BreakOnTermination.
//! - ProcessDebugFlags (31): um ULONG com só o bit PROCESS_DEBUG_INHERIT
//!   (outro bit dá STATUS_INVALID_PARAMETER, conferido depois de referenciar
//!   o handle com PROCESS_SET_INFORMATION); o bit ligado desliga
//!   EPROCESS.Flags.NoDebugInherit e vice-versa (o condrv.sys desliga a
//!   herança do depurador do processo corrente em volta de uma operação e
//!   restaura depois).
//!
//! O resto das classes ainda não é tratado aqui: STATUS_INVALID_INFO_CLASS.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::Eprocess;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::{query_process, user_probe};
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// SeDebugPrivilege.
const DEBUG_PRIVILEGE: u64 = 20;
/// PROCESS_SET_INFORMATION.
const PROCESS_SET_INFORMATION: u32 = 0x200;
/// PROCESSINFOCLASS.
pub const PROCESS_BREAK_ON_TERMINATION: u32 = 29;
pub const PROCESS_DEBUG_FLAGS: u32 = 31;
/// PROCESS_DEBUG_INHERIT, o único bit de ProcessDebugFlags.
const PROCESS_DEBUG_INHERIT: u32 = 1;

/// O ULONG da classe: sondado em UserMode, direto em KernelMode.
fn read_ulong(mode: u8, buffer: u64) -> Result<Result<u32, u32>, KernelError> {
    if mode != 0 {
        if !user_probe::probe_user_read(buffer, 4) {
            return Ok(Err(STATUS_ACCESS_VIOLATION));
        }
        return Ok(Ok(guest::try_read::<u32>(buffer)?));
    }
    // SAFETY: buffer de entrada de um chamador de modo kernel.
    Ok(Ok(unsafe { Field::<u32>::at(buffer) }.get()))
}

/// NtSetInformationProcess das classes que mudam o EPROCESS. `mode` é o
/// PreviousMode; `process_of` resolve o handle com o acesso pedido para o
/// EPROCESS (retido enquanto dura a chamada).
pub fn set_information(mode: u8, class: u32, buffer: u64, length: u32, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    match class {
        PROCESS_BREAK_ON_TERMINATION => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let value = match read_ulong(mode, buffer)? {
                Ok(value) => value,
                Err(status) => return Ok(status),
            };
            if !crate::ntos::se::privilege::single_privilege_check(DEBUG_PRIVILEGE, mode as u32) {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
            unsafe { Eprocess::at(process) }.set_break_on_termination((value != 0) as u32);
            Ok(0)
        }
        PROCESS_DEBUG_FLAGS => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            let value = match read_ulong(mode, buffer)? {
                Ok(value) => value,
                Err(status) => return Ok(status),
            };
            if value & !PROCESS_DEBUG_INHERIT != 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            // SAFETY: EPROCESS retido pelo handle que o nomeou.
            unsafe { Eprocess::at(process) }.set_no_debug_inherit((value & PROCESS_DEBUG_INHERIT == 0) as u32);
            Ok(0)
        }
        _ => {
            crate::debug_print!("[ps] NtSetInformationProcess classe {} (sem suporte)", class);
            Ok(STATUS_INVALID_INFO_CLASS)
        }
    }
}

/// ZwSetInformationProcess(ProcessHandle, Class, Information, Length): o
/// NtSetInformationProcess com PreviousMode KernelMode. O handle é
/// referenciado como o ObReferenceObjectByHandleWithTag do NT (PsProcessType,
/// KernelMode: o pseudo-handle do processo corrente e os handles de kernel) e
/// solto no fim.
pub fn set_information_kernel(handle: u64, class: u32, buffer: u64, length: u32) -> Result<u32, KernelError> {
    let mut referenced = 0u64;
    let mut failure: Result<(), KernelError> = Ok(());
    let status = set_information(0, class, buffer, length, |access| match query_process::reference_process(handle, access) {
        Ok(Ok(process)) => {
            referenced = process;
            Ok(process)
        }
        Ok(Err(status)) => Err(status),
        Err(error) => {
            failure = Err(error);
            Err(STATUS_INSUFFICIENT_RESOURCES)
        }
    });
    if referenced != 0 {
        query_process::release_process(referenced)?;
    }
    failure?;
    status
}
