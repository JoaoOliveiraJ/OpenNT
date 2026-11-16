//! Erros graves (hard errors): ExRaiseHardError, como no ntoskrnl 19041.
//!
//! Um componente do kernel pede ao subsistema que mostre um erro e espere
//! a resposta do usuário. O NT confere o pedido (mais de cinco parâmetros:
//! STATUS_INVALID_PARAMETER_2; OptionShutdownSystem exige
//! SeShutdownPrivilege), copia as UNICODE_STRING dos parâmetros para a
//! memória do processo e manda a mensagem à porta de erros do processo ou à
//! padrão (ExpDefaultErrorPort, que o csrss registra). Sem porta, a
//! resposta é ResponseReturnToCaller e o resultado STATUS_SUCCESS.
//!
//! NtSetDefaultHardErrorPort ([`set_default_port`]) registra a porta padrão
//! como o 19041: exige SeTcbPrivilege (STATUS_PRIVILEGE_NOT_HELD), só uma
//! vez (STATUS_UNSUCCESSFUL na segunda), referencia a porta com acesso zero e
//! guarda o processo que a registrou (o csrss da sessão 0 registra a
//! \Windows\ApiPort). O pedido ao subsistema por essa porta (o
//! HARDERROR_MSG com a espera da resposta) ainda não sai do kernel: o erro
//! é registrado na serial com o status e os parâmetros, e o chamador recebe
//! a resposta de sem porta.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::previous_mode;
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::privilege;
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
/// SeTcbPrivilege.
const SE_TCB_PRIVILEGE: u64 = 7;
/// MAXIMUM_HARDERROR_PARAMETERS.
const MAXIMUM_PARAMETERS: u32 = 5;
/// HARDERROR_RESPONSE_OPTION.OptionShutdownSystem.
const OPTION_SHUTDOWN_SYSTEM: u32 = 6;
/// HARDERROR_RESPONSE.ResponseReturnToCaller.
const RESPONSE_RETURN_TO_CALLER: u32 = 0;

/// ExRaiseHardError(ErrorStatus, NumberOfParameters,
/// UnicodeStringParameterMask, Parameters, ValidResponseOptions,
/// Response*).
pub fn raise_hard_error(error_status: u32, count: u32, string_mask: u32, parameters: u64, options: u32, response: u64) -> u32 {
    if count > MAXIMUM_PARAMETERS {
        return STATUS_INVALID_PARAMETER_2;
    }
    let mode = previous_mode::get().unwrap_or(0);
    // OptionShutdownSystem exige SeShutdownPrivilege.
    if options == OPTION_SHUTDOWN_SYSTEM && !privilege::single_privilege_check(19, mode as u32) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    let described: Vec<String> = (0..count as u64)
        .map(|index| {
            let value = if parameters != 0 { guest::read64(parameters + index * 8) } else { 0 };
            if string_mask & (1 << index) != 0 && value != 0 { guest_strings::read_unicode_string(value) } else { alloc::format!("{value:#x}") }
        })
        .collect();
    crate::debug_print!("[hard-error] {:#x} opcoes={} parametros={:?}: sem porta de erros, ResponseReturnToCaller", error_status, options, described);
    if response != 0 {
        // SAFETY: o PULONG de resposta do chamador de kernel.
        unsafe { Field::<u32>::at(response) }.set(RESPONSE_RETURN_TO_CALLER);
    }
    0
}

/// ExpDefaultErrorPort e ExpDefaultErrorPortProcess: o corpo da porta
/// (referenciado) e o EPROCESS de quem a registrou.
static DEFAULT_PORT: SpinLock<Option<(u64, u64)>> = SpinLock::new(None);

/// NtSetDefaultHardErrorPort(DefaultHardErrorPort). Devolve o NTSTATUS.
pub fn set_default_port(handle: u64) -> Result<u32, KernelError> {
    let mode = previous_mode::get().unwrap_or(1);
    if !privilege::single_privilege_check(SE_TCB_PRIVILEGE, mode as u32) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    let mut registered = DEFAULT_PORT.lock();
    if registered.is_some() {
        return Ok(STATUS_UNSUCCESSFUL);
    }
    let reference = match crate::ntos::alpc::port_reference::reference(handle, 0, mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    // A referência fica com o ExpDefaultErrorPort.
    *registered = Some((reference.port.pointer, crate::ntos::ps::process::get_current_process()));
    crate::debug_print!("[hard-error] porta de erros padrao registrada pelo pid {}", crate::ntos::ps::process::get_current_process_id());
    Ok(0)
}
