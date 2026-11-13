//! Objetos de espera do dispatcher.
//!
//! Eventos, semáforos, mutants, timers e threads sinalizadas. As esperas são
//! cooperativas: drenam timers, DPCs, work items e o escalonador enquanto
//! aguardam o estado ou o prazo.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::{clock, dpc, thread_alert, timer};
use crate::ntos::io::work_items;
use crate::ntos::ps::{process, scheduler};
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::dispatcher_header as header;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_TIMEOUT: u32 = 0x102;

/// KeInitializeEvent: tipo, tamanho, estado e lista de espera vazia.
pub fn initialize_event(event: u64, event_type: u8, initial_state: bool) {
    guest::write8(event + header::TYPE, event_type);
    guest::write8(event + 2, 0x18 / 4);
    guest::write32(event + header::SIGNAL_STATE, initial_state as u32);
    guest::write64(event + 8, event + 8);
    guest::write64(event + 16, event + 8);
}

/// KeSetEvent: devolve o estado anterior.
pub fn set_event(event: u64) -> u32 {
    let previous = guest::read32(event + header::SIGNAL_STATE);
    guest::write32(event + header::SIGNAL_STATE, 1);
    previous
}

pub fn clear_event(event: u64) {
    guest::write32(event + header::SIGNAL_STATE, 0);
}

pub fn reset_event(event: u64) -> u32 {
    let previous = guest::read32(event + header::SIGNAL_STATE);
    guest::write32(event + header::SIGNAL_STATE, 0);
    previous
}

pub fn read_state(object: u64) -> u32 {
    guest::read32(object + header::SIGNAL_STATE)
}

/// KePulseEvent: sinaliza (libera os waiters) e volta a não sinalizado num
/// único passo, devolvendo o estado anterior — KeSetEvent + KeResetEvent.
pub fn pulse_event(event: u64) -> u32 {
    let previous = set_event(event);
    reset_event(event);
    previous
}

pub fn initialize_semaphore(semaphore: u64, count: u32, limit: u32) {
    guest::write8(semaphore + header::TYPE, 5);
    guest::write8(semaphore + 2, 0x20 / 4);
    guest::write32(semaphore + header::SIGNAL_STATE, count);
    guest::write32(semaphore + 0x18, limit);
    guest::write64(semaphore + 8, semaphore + 8);
    guest::write64(semaphore + 16, semaphore + 8);
}

/// KeReleaseSemaphore: `Ok(contagem anterior)` ou `Err(NTSTATUS)`.
pub fn release_semaphore(semaphore: u64, release_count: i64) -> Result<u32, u32> {
    let previous = read_state(semaphore);
    let limit = guest::read32(semaphore + 0x18);
    if release_count <= 0 {
        return Err(0xC000_000D);
    }
    if release_count > limit as i64 - previous as i64 {
        return Err(0xC000_0047);
    }
    guest::write32(semaphore + header::SIGNAL_STATE, previous + release_count as u32);
    Ok(previous)
}

pub fn semaphore_limit(semaphore: u64) -> u32 {
    guest::read32(semaphore + 0x18)
}

/// KeInitializeSemaphore dos drivers: KSEMAPHORE com Type 5, SignalState =
/// contagem e Limit em +0x18 (sem tocar no tamanho nem na lista de espera).
pub fn initialize_driver_semaphore(semaphore: u64, count: u32, limit: u32) {
    guest::write8(semaphore + header::TYPE, 5);
    guest::write32(semaphore + header::SIGNAL_STATE, count);
    guest::write32(semaphore + 0x18, limit);
}

/// KeReleaseSemaphore dos drivers: devolve o SignalState anterior; o novo é
/// anterior + ajuste, limitado ao Limit.
pub fn release_driver_semaphore(semaphore: u64, adjustment: i32) -> i32 {
    let state = semaphore + header::SIGNAL_STATE;
    let previous = guest::read32(state) as i32;
    let limit = guest::read32(semaphore + 0x18) as i32;
    let released = previous.wrapping_add(adjustment).min(limit);
    guest::write32(state, released as u32);
    previous
}

/// Mutants deste caminho começam sem desabilitar APCs de kernel.
pub fn initialize_mutant(mutex: u64, initial_owner: bool) {
    guest::write8(mutex + header::TYPE, header::TYPE_MUTANT);
    guest::write8(mutex + 2, 0x38 / 4);
    guest::write32(mutex + header::SIGNAL_STATE, if initial_owner { 0 } else { 1 });
    for offset in [8u64, 0x18] {
        guest::write64(mutex + offset, mutex + offset);
        guest::write64(mutex + offset + 8, mutex + offset);
    }
    guest::write64(mutex + header::MUTEX_OWNER, if initial_owner { process::get_current_thread() } else { 0 });
    guest::write8(mutex + 0x30, 0);
    guest::write8(mutex + 0x31, 0);
}

/// KeInitializeMutex: o nível é ignorado pelo contrato atual.
pub fn initialize_mutex(mutex: u64, _level: u32) {
    initialize_mutant(mutex, false);
}

/// Exige a posse (salvo abandono explícito). `Ok(estado anterior)`.
pub fn release_mutant(mutex: u64, abandon: bool) -> Result<i32, u32> {
    let previous = guest::read32(mutex + header::SIGNAL_STATE) as i32;
    if !abandon && (previous > 0 || guest::read64(mutex + header::MUTEX_OWNER) != process::get_current_thread()) {
        return Err(0xC000_0046);
    }
    let next = if abandon { 1 } else { previous + 1 };
    guest::write32(mutex + header::SIGNAL_STATE, next as u32);
    if next == 1 {
        guest::write64(mutex + header::MUTEX_OWNER, 0);
    }
    if abandon {
        guest::write8(mutex + 0x30, 1);
    }
    Ok(previous)
}

/// KeReleaseMutex: erro ou estado anterior.
pub fn release_mutex(mutex: u64) -> u32 {
    match release_mutant(mutex, false) {
        Ok(previous) => previous as u32,
        Err(status) => status,
    }
}

/// Consulta ou consome o estado. `None` = indisponível; senão sucesso,
/// abandono (0x80) ou erro de limite.
pub fn acquire_status(object: u64, consume: bool) -> Option<u32> {
    let object_type = guest::read8(object + header::TYPE);
    let state = guest::read32(object + header::SIGNAL_STATE);
    match object_type {
        // Semáforos consomem uma permissão.
        5 => {
            if state == 0 {
                return None;
            }
            if consume {
                guest::write32(object + header::SIGNAL_STATE, state - 1);
            }
            Some(0)
        }
        // Eventos de notificação, timers de notificação e threads terminadas.
        header::TYPE_EVENT_NOTIFICATION | 8 | 6 => (state != 0).then_some(0),
        // Eventos e timers de sincronização consomem o sinal.
        header::TYPE_EVENT_SYNCHRONIZATION | 9 => {
            if state == 0 {
                return None;
            }
            if consume {
                guest::write32(object + header::SIGNAL_STATE, 0);
            }
            Some(0)
        }
        header::TYPE_MUTANT => {
            let owner = process::get_current_thread();
            let recursion = state as i32;
            if recursion <= 0 && guest::read64(object + header::MUTEX_OWNER) != owner {
                return None;
            }
            if recursion == i32::MIN {
                return Some(0xC000_0191);
            }
            let abandoned = guest::read8(object + 0x30) & 1;
            if consume {
                guest::write32(object + header::SIGNAL_STATE, (recursion - 1) as u32);
                guest::write64(object + header::MUTEX_OWNER, owner);
                guest::write8(object + 0x30, 0);
            }
            Some(if abandoned != 0 { 0x80 } else { 0 })
        }
        _ => None,
    }
}

/// LARGE_INTEGER de prazo em unidades de 100 ns: `None` = infinito, zero =
/// consulta imediata, negativo = relativo, positivo = absoluto.
pub fn timeout_to_100ns(timeout_pointer: u64) -> Option<u64> {
    if timeout_pointer == 0 {
        return None;
    }
    let value = guest::read64(timeout_pointer) as i64;
    if value == 0 {
        return Some(0);
    }
    if value < 0 {
        return Some(value.unsigned_abs());
    }
    Some((value as u64).saturating_sub(clock::system_time_100ns()))
}

/// Prazo apontado por `timeout_pointer`, em ms inteiros.
pub fn timeout_pointer_to_ms(timeout_pointer: u64) -> Option<u64> {
    timeout_to_100ns(timeout_pointer).map(|value| value / 10_000)
}

static LAST_SCHEDULER_TICK: SpinLock<u64> = SpinLock::new(0);
static COMPLETION_PUMPS: SpinLock<Vec<fn()>> = SpinLock::new(Vec::new());

/// Um tick do escalonador a cada 2 ms no máximo, para não sufocar timers.
fn pump_scheduler() {
    let now = clock::now_ms();
    {
        let mut last = LAST_SCHEDULER_TICK.lock();
        if now - *last < 2 {
            return;
        }
        *last = now;
    }
    scheduler::tick(-1);
}

/// Timers, DPCs, work items, conclusões registradas e escalonador.
pub fn pump_kernel() {
    timer::check_timers();
    let _ = dpc::run_queue();
    work_items::run_queue();
    let pumps = COMPLETION_PUMPS.lock().clone();
    for pump in pumps {
        pump();
    }
    // Numa espera de driver, threads de sistema podem produzir o evento.
    pump_scheduler();
}

pub fn register_completion_pump(pump: fn()) {
    let mut pumps = COMPLETION_PUMPS.lock();
    if !pumps.iter().any(|&existing| existing as usize == pump as usize) {
        pumps.push(pump);
    }
}

fn deadline(timeout_pointer: u64) -> (Option<u64>, Option<u64>) {
    let timeout = timeout_to_100ns(timeout_pointer);
    (timeout, timeout.map(|timeout| clock::uptime_100ns() + timeout))
}

/// KeWaitForSingleObject cooperativo.
pub fn wait_for_single_object(object: u64, timeout_pointer: u64, wait_mode: u8, alertable: bool) -> u32 {
    let (timeout, deadline) = deadline(timeout_pointer);
    if alertable {
        return thread_alert::cooperate(
            process::get_current_thread(),
            wait_mode,
            true,
            &mut || {
                acquire_status(object, true)
                    .or_else(|| deadline.is_some_and(|deadline| clock::uptime_100ns() >= deadline).then_some(STATUS_TIMEOUT))
            },
            pump_kernel,
        );
    }
    loop {
        if let Some(status) = acquire_status(object, true) {
            return status;
        }
        if timeout == Some(0) || deadline.is_some_and(|deadline| clock::uptime_100ns() >= deadline) {
            return STATUS_TIMEOUT;
        }
        pump_kernel();
    }
}

/// Tentativa sem espera. WaitAny (1) devolve o primeiro índice satisfeito;
/// WaitAll (0) consulta todos antes de consumir.
pub fn try_wait_objects(objects: &[u64], wait_type: u32) -> Option<u32> {
    if wait_type == 1 {
        for (index, &object) in objects.iter().enumerate() {
            if let Some(status) = acquire_status(object, true) {
                return Some(if status & 0x8000_0000 != 0 { status } else { status + index as u32 });
            }
        }
        return None;
    }
    let states: Vec<Option<u32>> = objects.iter().map(|&object| acquire_status(object, false)).collect();
    if let Some(error) = states.iter().flatten().find(|&&status| status & 0x8000_0000 != 0) {
        return Some(*error);
    }
    if states.iter().all(Option::is_some) {
        for &object in objects {
            acquire_status(object, true);
        }
        // Um mutant abandonado preserva STATUS_ABANDONED no resultado conjunto.
        return Some(if states.contains(&Some(0x80)) { 0x80 } else { STATUS_SUCCESS });
    }
    None
}

/// KeWaitForMultipleObjects: até 64 ponteiros distintos.
pub fn wait_for_multiple_objects(count: u32, objects_pointer: u64, wait_type: u32, timeout_pointer: u64, wait_mode: u8, alertable: bool) -> u32 {
    if count == 0 || count > 64 || wait_type > 1 {
        return 0xC000_000D;
    }
    let objects: Vec<u64> = (0..count as u64).map(|index| guest::read64(objects_pointer + index * 8)).collect();
    if objects.iter().collect::<BTreeSet<_>>().len() != objects.len() {
        return 0xC000_000D;
    }
    let (timeout, deadline) = deadline(timeout_pointer);
    if alertable {
        return thread_alert::cooperate(
            process::get_current_thread(),
            wait_mode,
            true,
            &mut || {
                try_wait_objects(&objects, wait_type)
                    .or_else(|| deadline.is_some_and(|deadline| clock::uptime_100ns() >= deadline).then_some(STATUS_TIMEOUT))
            },
            pump_kernel,
        );
    }
    loop {
        if let Some(status) = try_wait_objects(&objects, wait_type) {
            return status;
        }
        if timeout == Some(0) || deadline.is_some_and(|deadline| clock::uptime_100ns() >= deadline) {
            return STATUS_TIMEOUT;
        }
        pump_kernel();
    }
}
