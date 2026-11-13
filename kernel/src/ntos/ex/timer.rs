//! Timers do Executive (EX_TIMER): ExAllocateTimer, ExSetTimer,
//! ExCancelTimer e ExDeleteTimer sobre o KTIMER e o KDPC do Ke.
//!
//! O EX_TIMER (0x100 bytes) guarda o KTIMER, um KDPC interno, o callback e o
//! contexto; o DPC repassa (exTimer, context) ao PEXT_CALLBACK do driver.

use crate::hal::amd64::native_call;
use crate::ntos::ke::{dpc, timer};
use crate::ntos::mm::guest_memory as guest;

/// EX_TIMER (0x100 bytes): KTIMER, KDPC interno, callback e contexto. O DPC
/// repassa (exTimer, context) ao PEXT_CALLBACK do driver.
mod ex_timer {
    pub const KTIMER: u64 = 0x00;
    pub const KDPC: u64 = 0x40;
    pub const CALLBACK: u64 = 0x80;
    pub const CONTEXT: u64 = 0x88;
    pub const STRUCT_SIZE: u64 = 0x100;
}

/// DPC interno do EX_TIMER: o ponteiro recebido é o KDPC embutido.
fn ex_timer_dpc(dpc_pointer: u64, _context: u64, _first: u64, _second: u64) {
    let timer_pointer = dpc_pointer - ex_timer::KDPC;
    let callback = guest::read64(timer_pointer + ex_timer::CALLBACK);
    let context = guest::read64(timer_pointer + ex_timer::CONTEXT);
    native_call::call(callback, &[timer_pointer, context]);
}

/// ExAllocateTimer(callback, context): 0 quando falta memória.
pub fn allocate(callback: u64, context: u64) -> u64 {
    let timer_pointer = guest::alloc_bytes(ex_timer::STRUCT_SIZE);
    if timer_pointer == 0 {
        return 0;
    }
    timer::initialize_timer(timer_pointer + ex_timer::KTIMER, 0);
    guest::write64(timer_pointer + ex_timer::CALLBACK, callback);
    guest::write64(timer_pointer + ex_timer::CONTEXT, context);
    // O KDPC embutido identifica o EX_TIMER que guarda rotina e contexto.
    dpc::initialize_kernel_dpc(timer_pointer + ex_timer::KDPC, ex_timer_dpc, 0);
    timer_pointer
}

/// ExSetTimer(timer, dueTime, periodMs, parameters): o período dos
/// parâmetros, quando não nulo, prevalece.
pub fn set(timer_pointer: u64, due_time: i64, period: u32, parameters: u64) -> bool {
    let mut period = period;
    if parameters != 0 {
        let parameter_period = guest::read32(parameters);
        if parameter_period != 0 {
            period = parameter_period;
        }
    }
    timer::set_timer(timer_pointer + ex_timer::KTIMER, due_time, timer_pointer + ex_timer::KDPC, period)
}

/// ExCancelTimer: TRUE se o timer estava na fila.
pub fn cancel(timer_pointer: u64) -> bool {
    timer::cancel_timer(timer_pointer + ex_timer::KTIMER)
}

/// ExDeleteTimer(timer, cancel): cancela quando pedido e libera o EX_TIMER.
pub fn delete(timer_pointer: u64, cancel: bool) -> bool {
    let was_queued = cancel && timer::cancel_timer(timer_pointer + ex_timer::KTIMER);
    guest::free_bytes(timer_pointer);
    was_queued
}
