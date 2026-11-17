//! Os adaptadores de modo usuário dos timers: o ETIMER do Executive
//! (NtCreateTimer, NtSetTimer, NtCancelTimer e NtQueryTimer, sobre
//! `ex/timer_object.rs` com PreviousMode UserMode) e o IRTimer do
//! NtCreateTimer2 (NtCreateTimer2, NtCreateIRTimer, NtSetTimer2,
//! NtSetIRTimer e NtCancelTimer2, sobre `ex/ir_timer.rs`). Aqui ficam só a
//! leitura dos argumentos e a captura dos parâmetros de usuário.

use super::state;
use crate::ntos::ex::{ir_timer, timer_object};
use crate::ntos::inc::types::{NtStruct, T2SetParameters};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// PreviousMode dos adaptadores do ETIMER.
const USER_MODE: u8 = 1;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;

/// NtCreateTimer2(TimerHandle, Reserved, ObjectAttributes, Attributes,
/// DesiredAccess).
fn nt_create_timer2(out: u64, reserved: u64, attributes: u64, timer_attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    ir_timer::create_from_user(out, reserved, attributes, timer_attributes as u32, state::stack_arg32(rsp, 5))
}

/// O T2_SET_PARAMETERS de usuário capturado: (Version, NoWakeTolerance); o
/// DWORD em +4 é preenchimento e não é lido.
fn capture_set_parameters(parameters: u64) -> Result<Option<(u32, i64)>, u32> {
    if parameters == 0 {
        return Ok(None);
    }
    if !state::probe_user_read(parameters, T2SetParameters::SIZE) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    // A cópia do original não exige alinhamento.
    let version = guest::try_read::<u32>(parameters + core::mem::offset_of!(T2SetParameters, version) as u64);
    let tolerance = guest::try_read::<i64>(parameters + core::mem::offset_of!(T2SetParameters, no_wake_tolerance) as u64);
    match (version, tolerance) {
        (Ok(version), Ok(tolerance)) => Ok(Some((version, tolerance))),
        _ => Err(STATUS_ACCESS_VIOLATION),
    }
}

/// NtSetTimer2(TimerHandle, DueTime*, Period*, Parameters*), como o
/// ExpSetTimer2 19041: DueTime NULL dá STATUS_INVALID_PARAMETER_2; o prazo,
/// o período e os parâmetros são capturados antes do handle.
fn nt_set_timer2(handle: u64, due: u64, period: u64, parameters: u64, _rsp: u64) -> Result<u32, KernelError> {
    if due == 0 {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    let captured = (|| {
        let due = state::capture_large_integer(due)?;
        let period = if period != 0 { state::capture_large_integer(period)? } else { 0 };
        Ok((due, period, capture_set_parameters(parameters)?))
    })();
    Ok(match captured {
        Ok((due, period, parameters)) => ir_timer::set(handle, Some(due), period, parameters),
        Err(status) => status,
    })
}

/// NtCreateIRTimer(TimerHandle, IrTimerId, DesiredAccess): o NtCreateTimer2
/// sem OBJECT_ATTRIBUTES e com o atributo IR (2).
fn nt_create_ir_timer(out: u64, id: u64, access: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    ir_timer::create_from_user(out, id, 0, ir_timer::ATTRIBUTE_IR, access as u32)
}

/// NtSetIRTimer(TimerHandle, DueTime): o NtSetTimer2 sem período nem
/// parâmetros.
fn nt_set_ir_timer(handle: u64, due: u64, _a3: u64, _a4: u64, rsp: u64) -> Result<u32, KernelError> {
    nt_set_timer2(handle, due, 0, 0, rsp)
}

/// NtCancelTimer2(TimerHandle, Parameters): o Parameters não é lido.
fn nt_cancel_timer2(handle: u64, _parameters: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(ir_timer::cancel(handle))
}

/// NtQueryTimer(TimerHandle, TimerInformationClass, TimerInformation,
/// TimerInformationLength, ReturnLength).
fn nt_query_timer(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    timer_object::query(handle, class as u32, out, length as u32, state::stack_arg(rsp, 5), USER_MODE)
}

/// NtCreateTimer(TimerHandle, DesiredAccess, ObjectAttributes, TimerType).
fn nt_create_timer(out: u64, access: u64, attributes: u64, timer_type: u64, _rsp: u64) -> Result<u32, KernelError> {
    timer_object::create(out, access as u32, attributes, timer_type as u32, USER_MODE)
}

/// NtSetTimer(TimerHandle, DueTime, TimerApcRoutine, TimerContext,
/// ResumeTimer, Period, PreviousState): os três últimos na pilha.
fn nt_set_timer(handle: u64, due: u64, apc_routine: u64, apc_context: u64, rsp: u64) -> Result<u32, KernelError> {
    let resume = state::stack_arg(rsp, 5) as u8 != 0;
    let period = state::stack_arg32(rsp, 6) as i32;
    let previous_state = state::stack_arg(rsp, 7);
    timer_object::set(handle, due, apc_routine, apc_context, resume, period, previous_state, USER_MODE)
}

/// NtCancelTimer(TimerHandle, CurrentState).
fn nt_cancel_timer(handle: u64, current_state: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    timer_object::cancel(handle, current_state, USER_MODE)
}

pub fn init() {
    state::register_handler("NtCreateTimer", nt_create_timer);
    state::register_handler("NtSetTimer", nt_set_timer);
    state::register_handler("NtCancelTimer", nt_cancel_timer);
    state::register_handler("NtCreateTimer2", nt_create_timer2);
    state::register_handler("NtSetTimer2", nt_set_timer2);
    state::register_handler("NtCancelTimer2", nt_cancel_timer2);
    state::register_handler("NtQueryTimer", nt_query_timer);
    state::register_handler("NtCreateIRTimer", nt_create_ir_timer);
    state::register_handler("NtSetIRTimer", nt_set_ir_timer);
}
