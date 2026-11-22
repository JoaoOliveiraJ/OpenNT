//! As opções de execução de um processo (KPROCESS.Flags, o
//! KEXECUTE_OPTIONS), a classe ProcessExecuteFlags (34) do
//! NtQueryInformationProcess e do NtSetInformationProcess.
//!
//! Só um processo WoW64 x86 tem opções próprias: o código de 32 bits pode
//! ter sido feito para um x86 sem NX, e o wow64.dll pergunta por elas
//! (Wow64CheckIfNXEnabled) antes de decidir como tratar a memória de dados
//! que o programa executa. Um processo de 64 bits sempre tem o NX ligado e
//! permanente.
//!
//! - [`get`] é o KeGetExecuteOptions (19041 0x691af8): num processo WoW64
//!   x86, os sete bits do KEXECUTE_OPTIONS (ExecuteDisable, ExecuteEnable,
//!   DisableThunkEmulation, Permanent, ExecuteDispatchEnable,
//!   ImageDispatchEnable e DisableExceptionChainValidation); noutro,
//!   MEM_EXECUTE_OPTION_DISABLE | MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION
//!   | MEM_EXECUTE_OPTION_PERMANENT (0xD).
//! - [`set`] é o KeSetExecuteOptions (0x3251cc): só num processo WoW64 x86 e
//!   só com os sete bits (senão STATUS_INVALID_PARAMETER); sob o
//!   KPROCESS.ProcessLock, opções já permanentes dão STATUS_ACCESS_DENIED.
//!   ExecuteDisable sai e só volta pedido (e então desliga ExecuteEnable);
//!   os outros bits pedidos se somam aos que já estavam, e ExecuteEnable
//!   liga também ExecuteDispatchEnable e ImageDispatchEnable.
//!
//! O valor inicial de um processo WoW64 é o do PspApplyMitigationOptions
//! (o PspDecodeMitigationExecuteOptions do mapa de mitigações do processo);
//! sem mapa de mitigações neste kernel, um processo WoW64 começa com 0 (sem
//! opções pedidas).

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, KexecuteOptions};
use crate::rtl::KernelError;

/// Os sete bits do KEXECUTE_OPTIONS.
const VALID: u32 = 0x7F;
const EXECUTE_DISABLE: u8 = 0x1;
const EXECUTE_ENABLE: u8 = 0x2;
const PERMANENT: u8 = 0x8;
/// ExecuteDispatchEnable e ImageDispatchEnable.
const DISPATCH_ENABLE: u8 = 0x30;
/// MEM_EXECUTE_OPTION_DISABLE, DISABLE_THUNK_EMULATION e PERMANENT: o que
/// um processo nativo responde.
const NATIVE: u32 = 0xD;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

fn options(process: u64) -> &'static KexecuteOptions {
    // SAFETY: o EPROCESS vivo, retido por quem pergunta.
    &unsafe { Eprocess::at(process) }.pcb.flags
}

/// KeGetExecuteOptions(Process).
pub fn get(process: u64) -> u32 {
    if !crate::ntos::ps::wow64::is_x86_process(process) {
        return NATIVE;
    }
    options(process).execute_options.get() as u32 & VALID
}

/// KeSetExecuteOptions(Process, Options): o NTSTATUS.
pub fn set(process: u64, value: u32) -> Result<u32, KernelError> {
    if value & !VALID != 0 || !crate::ntos::ps::wow64::is_x86_process(process) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: o EPROCESS vivo, retido por quem pede.
    let lock = unsafe { Eprocess::at(process) }.pcb.process_lock.address();
    let previous = crate::ntos::ex::spin_lock::acquire_exclusive(lock);
    let field = &options(process).execute_options;
    let current = field.get();
    let status = if current & PERMANENT != 0 {
        STATUS_ACCESS_DENIED
    } else {
        let requested = value as u8;
        let mut next = current & !EXECUTE_DISABLE;
        if requested & EXECUTE_DISABLE != 0 {
            next = (next & !EXECUTE_ENABLE) | EXECUTE_DISABLE;
        }
        // DisableThunkEmulation, ExecuteEnable, ExecuteDispatchEnable,
        // ImageDispatchEnable, DisableExceptionChainValidation e Permanent.
        next |= requested & 0x7E;
        if next & EXECUTE_ENABLE != 0 {
            next |= DISPATCH_ENABLE;
        }
        field.set(next);
        0
    };
    crate::ntos::ex::spin_lock::release_exclusive(lock, previous)?;
    Ok(status)
}
