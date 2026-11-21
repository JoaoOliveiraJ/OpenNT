//! Os callouts do Po ao win32k (ntoskrnl 19041), pelo despachante que o
//! win32k registra no PsEstablishWin32Callouts (`ps/win32.rs`).
//!
//! - PopInvokeWin32Callout(CalloutType, Parameter, Scope, SessionId*)
//!   0x6f44d8: com o escopo 2, o callout vai a cada sessão
//!   (MmGetNextSession) com o id dela; com os outros, uma vez: na sessão
//!   corrente (escopo 0) ou na sessão dada (escopo 1; sem id, -1). O vigia
//!   de tempo do callout (PowerInformationInternal 0x15,
//!   PopWin32kCalloutWatchdogTimeoutSeconds) não existe no OpenNT. Devolve o
//!   status do último PsInvokeWin32Callout.
//! - PopEventCalloutDispatch(EventNumber, Code) 0x3a707c: só depois de
//!   PsWin32CalloutsEstablished; o WIN32_POWEREVENT_PARAMETERS {EventNumber,
//!   Code} vai no callout de evento (tipo 3) a todas as sessões, menos o
//!   PsW32EventCode (1), que vai só à sessão 0, e o PsW32GdiPrepareResumeUI
//!   (0xA), só à corrente. O win32kbase (W32CalloutDispatch →
//!   QueuePowerRequest) copia o bloco para a fila da thread de energia dele
//!   e volta sem esperar.
//! - PopPolicyTimeChange 0x77a110, o trabalho de política da troca de hora:
//!   depois do WNF_PO_SYSTEM_TIME_CHANGED (`po/time_change.rs`), o evento 3
//!   (PsW32SystemTime) com código 0, o WM_TIMECHANGE do win32k.
//! - O PopDispatchShutdownEvent 0x8f13e0 (o evento 1, PsW32EventCode, com
//!   o PopShutdownEventCode que o PopExecutePowerAction grava, 0x20 num
//!   desligamento) ainda não tem caminho: o OpenNT não tem o
//!   PopExecutePowerAction.
//! - PopDispatchStateCallout(Parameters, SessionId*) 0x7259b4: o
//!   WIN32_POWERSTATE_PARAMETERS no callout de estado (tipo 4) à sessão dada
//!   ou, sem id, a todas.
//! - PoPowerOffMonitor 0x382960 (NtPowerInformation 28): os estados com
//!   MinSystemState = PowerSystemWorking, na ordem do NT: o bloqueio da troca
//!   de console (PoBlockConsoleSwitch: tarefa 0 na sessão do console,
//!   repetida a cada 10 ms até haver console e o callout dar certo), o
//!   começo das tarefas (1, todas as sessões), a tela apagada (0xC, na
//!   sessão bloqueada; o status devolvido), o fim das tarefas (8) e o
//!   desbloqueio (7, na sessão bloqueada).
//! - PopNotifyConsoleUserPresent(Present, Unused, Reason) 0x772ce0: com os
//!   callouts estabelecidos e um console ativo (RtlGetActiveConsoleId), o
//!   callout de informação (tipo 5) à sessão do console com a informação 1
//!   e a entrada de 8 bytes {Present, Reason}. Com o TTM ligado vai ao
//!   TtmNotifyConsoleUserPresent; o OpenNT é um desktop sem TTM.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_obpsse::{Win32ConsoleUserPresent, Win32PowerEventParameters, Win32PowerInfoParameters, Win32PowerStateParameters};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::win32;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// PSW32CALLOUTTYPE: o evento e a informação de energia.
const POWER_EVENT_CALLOUT: i32 = 3;
const POWER_STATE_CALLOUT: i32 = 4;
const POWER_INFO_CALLOUT: i32 = 5;
/// POWERSTATETASK do PoPowerOffMonitor.
const TASK_BLOCK_CONSOLE_SWITCH: u32 = 0;
const TASK_START_POWER_STATE_TASKS: u32 = 1;
const TASK_UNBLOCK_CONSOLE_SWITCH: u32 = 7;
const TASK_END_POWER_STATE_TASKS: u32 = 8;
const TASK_MONITOR_OFF: u32 = 0xC;
/// SYSTEM_POWER_STATE PowerSystemWorking.
const POWER_SYSTEM_WORKING: u32 = 1;
/// O intervalo relativo do KeDelayExecutionThread do PoBlockConsoleSwitch
/// (10 ms).
const CONSOLE_SWITCH_RETRY: i64 = -100_000;
/// PSPOWEREVENTTYPE.
const EVENT_CODE: u32 = 1;
const EVENT_SYSTEM_TIME: u32 = 3;
const EVENT_GDI_PREPARE_RESUME_UI: u32 = 0xA;
/// O escopo de sessão do PopInvokeWin32Callout.
const SCOPE_CURRENT: u32 = 0;
const SCOPE_SESSION: u32 = 1;
const SCOPE_ALL_SESSIONS: u32 = 2;
/// A informação de presença do usuário no console do callout tipo 5.
const CONSOLE_USER_PRESENT: u32 = 1;
/// O motivo do NtSetThreadExecutionState(ES_DISPLAY_REQUIRED).
pub const USER_PRESENT_EXECUTION_STATE: u32 = 8;

/// PsWin32CalloutsEstablished.
fn callouts_established() -> bool {
    win32::win32_callout().is_some()
}

/// PopInvokeWin32Callout.
fn invoke(callout_type: i32, parameter: u64, scope: u32, session: Option<u32>) -> u32 {
    match scope {
        SCOPE_ALL_SESSIONS => {
            let mut status = STATUS_INVALID_PARAMETER;
            for id in crate::ntos::mm::session::ids() {
                status = win32::invoke_callout_for_session(callout_type, parameter, id);
            }
            status
        }
        SCOPE_CURRENT => win32::invoke_callout(callout_type, parameter),
        _ => win32::invoke_callout_for_session(callout_type, parameter, session.unwrap_or(u32::MAX)),
    }
}

/// PopEventCalloutDispatch(EventNumber, Code).
pub fn event_callout(event_number: u32, code: u64) -> u32 {
    if !callouts_established() {
        return 0;
    }
    let block = guest::alloc_bytes(Win32PowerEventParameters::SIZE);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(block, &[0u8; Win32PowerEventParameters::SIZE as usize]);
    // SAFETY: o bloco zerado de 0x10 bytes acima.
    let parameters = unsafe { Win32PowerEventParameters::at(block) };
    parameters.event_number.set(event_number);
    parameters.code.set(code);
    let status = match event_number {
        EVENT_CODE => invoke(POWER_EVENT_CALLOUT, block, SCOPE_SESSION, Some(0)),
        EVENT_GDI_PREPARE_RESUME_UI => invoke(POWER_EVENT_CALLOUT, block, SCOPE_CURRENT, None),
        _ => invoke(POWER_EVENT_CALLOUT, block, SCOPE_ALL_SESSIONS, None),
    };
    guest::free_bytes(block);
    status
}

/// O fim do PopPolicyTimeChange: o aviso de troca de hora ao win32k.
pub fn system_time_changed() {
    let _ = event_callout(EVENT_SYSTEM_TIME, 0);
}

/// PopNotifyConsoleUserPresent(Present, _, Reason).
pub fn notify_console_user_present(present: bool, reason: u32) {
    if !callouts_established() || crate::ntos::ttm::device::enabled() {
        return;
    }
    let Ok(console) = crate::ntos::rtl::shared_data::active_console_id() else { return };
    if console == u32::MAX {
        return;
    }
    let block = guest::alloc_bytes(Win32PowerInfoParameters::SIZE + Win32ConsoleUserPresent::SIZE);
    if block == 0 {
        return;
    }
    guest::write_bytes(block, &[0u8; (Win32PowerInfoParameters::SIZE + Win32ConsoleUserPresent::SIZE) as usize]);
    let input = block + Win32PowerInfoParameters::SIZE;
    // SAFETY: os dois blocos zerados acima (0x28 + 8 bytes).
    let (parameters, data) = unsafe { (Win32PowerInfoParameters::at(block), Win32ConsoleUserPresent::at(input)) };
    data.present.set(present as u8);
    data.reason.set(reason);
    parameters.information_type.set(CONSOLE_USER_PRESENT);
    parameters.input_length.set(Win32ConsoleUserPresent::SIZE as u32);
    parameters.input.set(input);
    let _ = invoke(POWER_INFO_CALLOUT, block, SCOPE_SESSION, Some(console));
    guest::free_bytes(block);
}

/// PopDispatchStateCallout(Parameters, SessionId*).
fn state_callout(parameters: u64, session: Option<u32>) -> u32 {
    match session {
        Some(id) => invoke(POWER_STATE_CALLOUT, parameters, SCOPE_SESSION, Some(id)),
        None => invoke(POWER_STATE_CALLOUT, parameters, SCOPE_ALL_SESSIONS, None),
    }
}

/// PoBlockConsoleSwitch: a sessão do console bloqueada.
fn block_console_switch(parameters: &Win32PowerStateParameters, interval: u64) -> u32 {
    loop {
        if let Ok(console) = crate::ntos::rtl::shared_data::active_console_id() {
            if console != u32::MAX {
                parameters.power_state_task.set(TASK_BLOCK_CONSOLE_SWITCH);
                if state_callout(parameters.address(), Some(console)) as i32 >= 0 {
                    return crate::ntos::rtl::shared_data::active_console_id().unwrap_or(console);
                }
            }
        }
        let _ = crate::ntos::ke::timer::delay_execution_thread(interval, 0, false);
    }
}

/// PoPowerOffMonitor: o status do callout da tela apagada.
pub fn power_off_monitor() -> u32 {
    let size = Win32PowerStateParameters::SIZE + 8;
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    let interval = block + Win32PowerStateParameters::SIZE;
    guest::write64(interval, CONSOLE_SWITCH_RETRY as u64);
    // SAFETY: o bloco zerado de 0x18 bytes acima.
    let parameters = unsafe { Win32PowerStateParameters::at(block) };
    parameters.min_system_state.set(POWER_SYSTEM_WORKING);
    let session = block_console_switch(parameters, interval);
    parameters.power_state_task.set(TASK_START_POWER_STATE_TASKS);
    let _ = state_callout(block, None);
    parameters.power_state_task.set(TASK_MONITOR_OFF);
    let status = state_callout(block, Some(session));
    parameters.power_state_task.set(TASK_END_POWER_STATE_TASKS);
    let _ = state_callout(block, None);
    parameters.power_state_task.set(TASK_UNBLOCK_CONSOLE_SWITCH);
    let _ = state_callout(block, Some(session));
    guest::free_bytes(block);
    status
}

/// O WIN32_POWERSTATE_PARAMETERS zerado com MinSystemState =
/// PowerSystemWorking e o intervalo do PoBlockConsoleSwitch depois dele.
fn working_state_block() -> Option<u64> {
    let size = Win32PowerStateParameters::SIZE + 8;
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return None;
    }
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    guest::write64(block + Win32PowerStateParameters::SIZE, CONSOLE_SWITCH_RETRY as u64);
    // SAFETY: o bloco zerado de 0x18 bytes acima.
    unsafe { Win32PowerStateParameters::at(block) }.min_system_state.set(POWER_SYSTEM_WORKING);
    Some(block)
}

/// PopBlockSessionSwitch(Bloquear, SessãoId*) 0x779b80, a rotina 8 que o
/// PopPdcRegister entrega ao pdc.sys (`po/pdc.rs`): bloquear é o
/// PoBlockConsoleSwitch, com a sessão bloqueada gravada em *SessãoId;
/// desbloquear é o callout de estado com a tarefa 7 à sessão de *SessãoId.
/// Devolve o valor que fica em EAX: a sessão bloqueada ou o status do
/// callout.
pub fn block_session_switch(block: bool, session: u64) -> u32 {
    let Some(parameters_block) = working_state_block() else { return STATUS_INSUFFICIENT_RESOURCES };
    // SAFETY: o bloco de `working_state_block`.
    let parameters = unsafe { Win32PowerStateParameters::at(parameters_block) };
    let result = if block {
        let blocked = block_console_switch(parameters, parameters_block + Win32PowerStateParameters::SIZE);
        guest::write32(session, blocked);
        blocked
    } else {
        parameters.power_state_task.set(TASK_UNBLOCK_CONSOLE_SWITCH);
        state_callout(parameters_block, Some(guest::read32(session)))
    };
    guest::free_bytes(parameters_block);
    result
}

/// A informação 3 do callout de informação de energia (o pedido de tela do
/// PopControlMonitor).
const CONTROL_MONITOR: u32 = 3;

/// PopControlMonitor(Entrada, SessãoId) 0x779dc0, a rotina 9 do PDC: o
/// callout de informação (tipo 5) com a informação 3 e a entrada de 8 bytes
/// do PDC à sessão dada; com o TTM ligado o 19041 vai ao TTM (o OpenNT é um
/// desktop sem TTM). Devolve o status do callout.
pub fn control_monitor(input: u64, session: u32) -> u32 {
    let block = guest::alloc_bytes(Win32PowerInfoParameters::SIZE);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(block, &[0u8; Win32PowerInfoParameters::SIZE as usize]);
    // SAFETY: o bloco zerado de 0x28 bytes acima.
    let parameters = unsafe { Win32PowerInfoParameters::at(block) };
    parameters.information_type.set(CONTROL_MONITOR);
    parameters.input_length.set(8);
    parameters.input.set(input);
    let status = invoke(POWER_INFO_CALLOUT, block, SCOPE_SESSION, Some(session));
    guest::free_bytes(block);
    status
}
