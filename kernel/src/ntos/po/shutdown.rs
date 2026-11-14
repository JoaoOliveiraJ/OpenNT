//! Desligamento do sistema (NtShutdownSystem).
//!
//! Como no ntoskrnl 19041, NtShutdownSystem(Action) traduz a ação e chama o
//! NtSetSystemPowerState(SystemAction, PowerSystemSleeping3, Flags =
//! POWER_ACTION_CRITICAL | POWER_ACTION_DISABLE_WAKES | POWER_ACTION_OVERRIDE_APPS):
//! ShutdownNoReboot (0) = PowerActionShutdown, ShutdownReboot (1) =
//! PowerActionShutdownReset, ShutdownPowerOff (2) = PowerActionShutdownOff.
//! A ação 3 (reinício para recuperação) exige o SeShutdownPrivilege de quem
//! chama do modo usuário e vai ao ExRebootSystemForRecovery, que não volta;
//! outra ação dá STATUS_INVALID_PARAMETER.
//!
//! O NtSetSystemPowerState de uma ação de desligamento também exige o
//! SeShutdownPrivilege do modo usuário e faz o desligamento ordenado
//! (PopGracefulShutdown): IRP_MJ_SHUTDOWN a cada dispositivo do
//! IoRegisterShutdownNotification, depois os do
//! IoRegisterLastChanceShutdownNotification, e o HalReturnToFirmware
//! (parada, reinício ou desligamento). Com sucesso nada volta.

use crate::hal::firmware_return::{self, Routine};
use crate::ntos::io::shutdown as last_chance;
use crate::ntos::io::small::shutdown_notification;
use crate::ntos::ob::object_access;
use crate::ntos::ps::previous_mode;
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
/// SE_SHUTDOWN_PRIVILEGE.
const SE_SHUTDOWN_PRIVILEGE: u64 = 19;

/// POWER_ACTION das ações de desligamento.
pub const POWER_ACTION_SHUTDOWN: u32 = 4;
pub const POWER_ACTION_SHUTDOWN_RESET: u32 = 5;
pub const POWER_ACTION_SHUTDOWN_OFF: u32 = 6;

/// Ação pedida ao NtShutdownSystem, já traduzida.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// NtSetSystemPowerState com a POWER_ACTION.
    PowerAction(u32),
    /// ExRebootSystemForRecovery.
    RebootForRecovery,
}

/// SHUTDOWN_ACTION -> pedido; `None` = STATUS_INVALID_PARAMETER.
pub fn translate(action: u32) -> Option<Request> {
    Some(match action {
        0 => Request::PowerAction(POWER_ACTION_SHUTDOWN),
        1 => Request::PowerAction(POWER_ACTION_SHUTDOWN_RESET),
        2 => Request::PowerAction(POWER_ACTION_SHUTDOWN_OFF),
        3 => Request::RebootForRecovery,
        _ => return None,
    })
}

/// SeSinglePrivilegeCheck(SeShutdownPrivilege, PreviousMode).
fn holds_shutdown_privilege(mode: u8) -> bool {
    mode == 0 || object_access::subject().and_then(|token| tokens::with(token, |token| token.privileges.iter().any(|privilege| privilege.id == SE_SHUTDOWN_PRIVILEGE && privilege.attributes & 2 != 0))).unwrap_or(false)
}

/// PopGracefulShutdown e HalReturnToFirmware.
fn graceful_shutdown(routine: Routine) -> ! {
    debug_print!("[po] desligamento ordenado ({:?})", routine);
    shutdown_notification::run_shutdown_notifications();
    if let Err(error) = last_chance::run_last_chance_shutdown_notifications() {
        debug_print!("[po] last chance: {}", error);
    }
    firmware_return::return_to_firmware(routine)
}

/// NtShutdownSystem(Action): só volta em falha.
pub fn shutdown_system(action: u32) -> Result<u32, KernelError> {
    let Some(request) = translate(action) else { return Ok(STATUS_INVALID_PARAMETER) };
    let mode = previous_mode::get()?;
    if !holds_shutdown_privilege(mode) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    match request {
        Request::PowerAction(POWER_ACTION_SHUTDOWN_RESET) | Request::RebootForRecovery => graceful_shutdown(Routine::Reboot),
        Request::PowerAction(POWER_ACTION_SHUTDOWN_OFF) => graceful_shutdown(Routine::PowerOff),
        Request::PowerAction(_) => graceful_shutdown(Routine::Halt),
    }
}
