//! Os serviços de hora do modo usuário: NtSetSystemTime,
//! NtQueryTimerResolution e NtSetTimerResolution. A lógica mora em
//! `ex/system_time.rs` e `ex/timer_resolution.rs`; aqui só os argumentos da
//! syscall.

use core::sync::atomic::{AtomicU64, Ordering};

use super::state;
use crate::rtl::KernelError;

/// Chamadas do NtQueryPerformanceCounter (o caminho da ntdll sem o atalho
/// do TSC), para o autoteste.
static PERFORMANCE_COUNTER_CALLS: AtomicU64 = AtomicU64::new(0);

/// Quantas vezes o modo usuário chamou o NtQueryPerformanceCounter.
pub fn performance_counter_calls() -> u64 {
    PERFORMANCE_COUNTER_CALLS.load(Ordering::Relaxed)
}

/// Conta uma chamada do NtQueryPerformanceCounter.
pub fn count_performance_counter_call() {
    PERFORMANCE_COUNTER_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// NtSetSystemTime(SystemTime, PreviousTime).
fn nt_set_system_time(system_time: u64, previous_time: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::ex::system_time::set_system_time(system_time, previous_time, true))
}

/// NtQueryTimerResolution(MaximumTime*, MinimumTime*, CurrentTime*).
fn nt_query_timer_resolution(maximum: u64, minimum: u64, current: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::ex::timer_resolution::nt_query_timer_resolution(maximum, minimum, current, true))
}

/// NtSetTimerResolution(DesiredTime, SetResolution, ActualTime*).
fn nt_set_timer_resolution(desired: u64, set: u64, actual: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::ex::timer_resolution::nt_set_timer_resolution(desired as u32, set as u8 != 0, actual, true))
}

pub fn init() {
    let handlers: [(&'static str, state::SyscallHandler); 3] = [("NtSetSystemTime", nt_set_system_time), ("NtQueryTimerResolution", nt_query_timer_resolution), ("NtSetTimerResolution", nt_set_timer_resolution)];
    for (name, handler) in handlers {
        state::register_handler(name, handler);
    }
}
