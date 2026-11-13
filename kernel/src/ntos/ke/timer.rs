//! Temporizadores KTIMER pelo relógio TSC.
//!
//! A fila conserva os endereços virtuais do timer e da DPC. Prazos em
//! unidades de 100 ns: relativos contra o uptime, absolutos contra a hora do
//! sistema (época de 1601).

use alloc::vec::Vec;

use super::{clock, dpc, thread_alert};
use crate::ntos::io::work_items;
use crate::ntos::ps::{process, scheduler};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::ktimer as layout;

struct TimerEntry {
    timer: u64,
    due: u64,
    relative: bool,
    period_ms: u32,
    dpc: u64,
}

static TIMERS: SpinLock<Vec<TimerEntry>> = SpinLock::new(Vec::new());
static LAST_DELAY_TICK: SpinLock<u64> = SpinLock::new(0);

/// Negativo = intervalo relativo; positivo = hora absoluta do sistema.
fn due_time(value: i64) -> (u64, bool) {
    if value < 0 {
        (clock::uptime_100ns() + value.unsigned_abs(), true)
    } else {
        (value as u64, false)
    }
}

/// KeInitializeTimerEx.
pub fn initialize_timer(timer: u64, timer_type: u32) {
    guest::write32(timer + layout::TYPE, timer_type);
    guest::write32(timer + layout::SIGNAL_STATE, 0);
    guest::write64(timer + layout::DPC, 0);
    guest::write32(timer + layout::PERIOD, 0);
}

/// KeInitializeTimer: timer de notificação.
pub fn initialize_notification_timer(timer: u64) {
    initialize_timer(timer, layout::TIMER_NOTIFICATION as u32);
}

/// KeInitializeTimerEx com o TIMER_TYPE do chamador: 0 é NotificationTimer,
/// qualquer outro valor SynchronizationTimer.
pub fn initialize_timer_of_type(timer: u64, timer_type: u64) {
    initialize_timer(timer, if timer_type != 0 { layout::TIMER_SYNCHRONIZATION } else { layout::TIMER_NOTIFICATION } as u32);
}

/// KeReadStateTimer.
pub fn read_state(timer: u64) -> u32 {
    guest::read32(timer + layout::SIGNAL_STATE)
}

/// KeSetTimerEx: remove o agendamento anterior e insere o novo. Devolve se
/// havia entrada na fila.
pub fn set_timer(timer: u64, due_value: i64, dpc_pointer: u64, period_ms: u32) -> bool {
    let was_queued = cancel_timer(timer);
    guest::write32(timer + layout::SIGNAL_STATE, 0);
    guest::write64(timer + layout::DPC, dpc_pointer);
    guest::write32(timer + layout::PERIOD, period_ms);
    let (due, relative) = due_time(due_value);
    TIMERS.lock().push(TimerEntry { timer, due, relative, period_ms, dpc: dpc_pointer });
    was_queued
}

/// KeCancelTimer: o corpo continua pertencendo ao chamador.
pub fn cancel_timer(timer: u64) -> bool {
    let mut timers = TIMERS.lock();
    match timers.iter().position(|entry| entry.timer == timer) {
        Some(index) => {
            timers.remove(index);
            true
        }
        None => false,
    }
}

/// Sinaliza vencidos e enfileira suas DPCs. Periódicos rearmam a partir do
/// prazo anterior, pulando para agora + período se ficarem no passado.
pub fn check_timers() {
    // O papel do KeUpdateSystemTime antes da expiração: InterruptTime,
    // SystemTime e TickCount da KUSER_SHARED_DATA acompanham o relógio que
    // vence os timers (drivers medem tempo por KeQueryTickCount, que lê a
    // página direto).
    crate::ntos::mm::shared_user_data::update_system_times();
    let system_now = clock::system_time_100ns();
    let uptime_now = clock::uptime_100ns();
    let mut fired = Vec::new();
    {
        let mut timers = TIMERS.lock();
        let mut index = timers.len();
        while index > 0 {
            index -= 1;
            let entry = &mut timers[index];
            let now = if entry.relative { uptime_now } else { system_now };
            if entry.due > now {
                continue;
            }
            fired.push((entry.timer, entry.dpc));
            if entry.period_ms > 0 {
                let period = entry.period_ms as u64 * 10_000;
                entry.due = (uptime_now + entry.due + period).saturating_sub(now);
                entry.relative = true;
                if entry.due <= uptime_now {
                    entry.due = uptime_now + period;
                }
            } else {
                timers.remove(index);
            }
        }
    }
    for (timer, dpc_pointer) in fired {
        guest::write32(timer + layout::SIGNAL_STATE, 1);
        if dpc_pointer != 0 {
            dpc::insert_queue_dpc(dpc_pointer, 0, 0);
        }
    }
}

fn delay_pump() {
    check_timers();
    let _ = dpc::run_queue();
    work_items::run_queue();
    scheduler::tick(-1);
}

/// KeDelayExecutionThread cooperativo: o prazo relativo usa o uptime, o
/// absoluto acompanha a hora do sistema.
pub fn delay_execution_thread(interval_pointer: u64, wait_mode: u8, alertable: bool) -> Result<u32, KernelError> {
    let interval = guest::try_read64(interval_pointer)? as i64;
    let relative_deadline = (interval <= 0).then(|| clock::uptime_100ns() + interval.unsigned_abs());
    let expired = move || match relative_deadline {
        Some(deadline) => clock::uptime_100ns() >= deadline,
        None => clock::system_time_100ns() >= interval as u64,
    };
    if alertable {
        return Ok(thread_alert::cooperate(process::get_current_thread(), wait_mode, true, &mut || expired().then_some(0), delay_pump));
    }
    loop {
        check_timers();
        let _ = dpc::run_queue();
        // Trabalho pendente pode produzir a condição de outra operação.
        work_items::run_queue();
        let now = clock::uptime_ms();
        let tick = {
            let mut last = LAST_DELAY_TICK.lock();
            let due = now - *last >= 2;
            if due {
                *last = now;
            }
            due
        };
        if tick {
            scheduler::tick(-1);
        }
        if expired() {
            return Ok(0);
        }
    }
}

pub fn pending_count() -> usize {
    TIMERS.lock().len()
}
