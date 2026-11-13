//! Objetos de espera do dispatcher.
//!
//! Eventos, semáforos, mutants, timers e threads sinalizadas. As esperas são
//! cooperativas: drenam timers, DPCs, work items e o escalonador enquanto
//! aguardam o estado ou o prazo.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{clock, dpc, thread_alert, timer};
use crate::ntos::inc::types::{DispatcherHeader, Field, Kevent, Kmutant, Ksemaphore, LargeInteger, ListEntry, NtStruct};
use crate::ntos::io::work_items;
use crate::ntos::ps::{process, scheduler};
use crate::rtl::SpinLock;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_TIMEOUT: u32 = 0x102;

/// KOBJECTS: o DISPATCHER_HEADER.Type de cada objeto de espera.
mod object_type {
    pub const EVENT_NOTIFICATION: u8 = 0;
    pub const EVENT_SYNCHRONIZATION: u8 = 1;
    pub const MUTANT: u8 = 2;
    pub const SEMAPHORE: u8 = 5;
    pub const THREAD: u8 = 6;
    pub const TIMER_NOTIFICATION: u8 = 8;
    pub const TIMER_SYNCHRONIZATION: u8 = 9;
}

/// LIST_ENTRY vazia (aponta para si mesma).
fn initialize_list_head(head: &ListEntry) {
    head.flink.set(head.address());
    head.blink.set(head.address());
}

/// O objeto de espera do chamador (evento, semáforo, mutant, timer, thread).
fn header_at(object: u64) -> &'static DispatcherHeader {
    // SAFETY: os exports recebem um ponteiro para um objeto de despacho vivo.
    unsafe { DispatcherHeader::at(object) }
}

/// KeInitializeEvent: tipo, tamanho, estado e lista de espera vazia.
pub fn initialize_event(event: u64, event_type: u8, initial_state: bool) {
    // SAFETY: KEVENT do chamador.
    let event = unsafe { Kevent::at(event) };
    event.header.type_.set(event_type);
    event.header.size.set((Kevent::SIZE / 4) as u8);
    event.header.signal_state.set(initial_state as i32);
    initialize_list_head(&event.header.wait_list_head);
}

/// KeSetEvent: devolve o estado anterior (troca atômica do SignalState).
pub fn set_event(event: u64) -> u32 {
    header_at(event).signal_state.atomic().swap(1, Ordering::SeqCst) as u32
}

pub fn clear_event(event: u64) {
    header_at(event).signal_state.set(0);
}

/// KeResetEvent: devolve o estado anterior (troca atômica do SignalState).
pub fn reset_event(event: u64) -> u32 {
    header_at(event).signal_state.atomic().swap(0, Ordering::SeqCst) as u32
}

pub fn read_state(object: u64) -> u32 {
    header_at(object).signal_state.get() as u32
}

/// KePulseEvent: sinaliza (libera os waiters) e volta a não sinalizado num
/// único passo, devolvendo o estado anterior — KeSetEvent + KeResetEvent.
pub fn pulse_event(event: u64) -> u32 {
    let previous = set_event(event);
    reset_event(event);
    previous
}

fn semaphore_at(semaphore: u64) -> &'static Ksemaphore {
    // SAFETY: KSEMAPHORE do chamador.
    unsafe { Ksemaphore::at(semaphore) }
}

pub fn initialize_semaphore(semaphore: u64, count: u32, limit: u32) {
    let semaphore = semaphore_at(semaphore);
    semaphore.header.type_.set(object_type::SEMAPHORE);
    semaphore.header.size.set((Ksemaphore::SIZE / 4) as u8);
    semaphore.header.signal_state.set(count as i32);
    semaphore.limit.set(limit as i32);
    initialize_list_head(&semaphore.header.wait_list_head);
}

/// KeReleaseSemaphore: `Ok(contagem anterior)` ou `Err(NTSTATUS)`. A soma
/// ao SignalState é um compare-exchange: duas liberações simultâneas nunca
/// perdem uma permissão nem ultrapassam o Limit.
pub fn release_semaphore(semaphore: u64, release_count: i64) -> Result<u32, u32> {
    let semaphore = semaphore_at(semaphore);
    let state = &semaphore.header.signal_state;
    let limit = semaphore.limit.get() as u32;
    if release_count <= 0 {
        return Err(0xC000_000D);
    }
    let mut previous = state.get();
    loop {
        if release_count > limit as i64 - previous as u32 as i64 {
            return Err(0xC000_0047);
        }
        let next = (previous as u32).wrapping_add(release_count as u32) as i32;
        match state.atomic().compare_exchange(previous, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(previous as u32),
            Err(observed) => previous = observed,
        }
    }
}

pub fn semaphore_limit(semaphore: u64) -> u32 {
    semaphore_at(semaphore).limit.get() as u32
}

/// KeInitializeSemaphore dos drivers: KSEMAPHORE com Type 5, SignalState =
/// contagem e Limit (sem tocar no tamanho nem na lista de espera).
pub fn initialize_driver_semaphore(semaphore: u64, count: u32, limit: u32) {
    let semaphore = semaphore_at(semaphore);
    semaphore.header.type_.set(object_type::SEMAPHORE);
    semaphore.header.signal_state.set(count as i32);
    semaphore.limit.set(limit as i32);
}

/// KeReleaseSemaphore dos drivers: devolve o SignalState anterior; o novo é
/// anterior + ajuste, limitado ao Limit (num compare-exchange).
pub fn release_driver_semaphore(semaphore: u64, adjustment: i32) -> i32 {
    let semaphore = semaphore_at(semaphore);
    let limit = semaphore.limit.get();
    let state = semaphore.header.signal_state.atomic();
    let mut previous = state.load(Ordering::SeqCst);
    loop {
        let released = previous.wrapping_add(adjustment).min(limit);
        match state.compare_exchange(previous, released, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return previous,
            Err(observed) => previous = observed,
        }
    }
}

fn mutant_at(mutex: u64) -> &'static Kmutant {
    // SAFETY: KMUTANT do chamador.
    unsafe { Kmutant::at(mutex) }
}

/// Mutants deste caminho começam sem desabilitar APCs de kernel.
pub fn initialize_mutant(mutex: u64, initial_owner: bool) {
    let mutant = mutant_at(mutex);
    mutant.header.type_.set(object_type::MUTANT);
    mutant.header.size.set((Kmutant::SIZE / 4) as u8);
    mutant.header.signal_state.set(if initial_owner { 0 } else { 1 });
    initialize_list_head(&mutant.header.wait_list_head);
    initialize_list_head(&mutant.mutant_list_entry);
    mutant.owner_thread.set(if initial_owner { process::get_current_thread() } else { 0 });
    mutant.mutant_flags.set(0);
    mutant.apc_disable.set(0);
}

/// KeInitializeMutex: o nível é ignorado pelo contrato atual.
pub fn initialize_mutex(mutex: u64, _level: u32) {
    initialize_mutant(mutex, false);
}

/// Exige a posse (salvo abandono explícito). `Ok(estado anterior)`. O novo
/// SignalState entra por compare-exchange.
pub fn release_mutant(mutex: u64, abandon: bool) -> Result<i32, u32> {
    let mutant = mutant_at(mutex);
    let state = mutant.header.signal_state.atomic();
    let mut previous = state.load(Ordering::SeqCst);
    let next = loop {
        if !abandon && (previous > 0 || mutant.owner_thread.get() != process::get_current_thread()) {
            return Err(0xC000_0046);
        }
        let next = if abandon { 1 } else { previous + 1 };
        match state.compare_exchange(previous, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break next,
            Err(observed) => previous = observed,
        }
    };
    if next == 1 {
        mutant.owner_thread.set(0);
    }
    if abandon {
        mutant.mutant_flags.set(1);
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
/// abandono (0x80) ou erro de limite. Consumir é um compare-exchange no
/// SignalState: dois waiters nunca satisfazem a mesma permissão ou sinal.
pub fn acquire_status(object: u64, consume: bool) -> Option<u32> {
    let header = header_at(object);
    let state = &header.signal_state;
    match header.type_.get() {
        // Semáforos consomem uma permissão.
        object_type::SEMAPHORE => {
            let mut current = state.get();
            loop {
                if current == 0 {
                    return None;
                }
                if !consume {
                    return Some(0);
                }
                match state.atomic().compare_exchange(current, current.wrapping_sub(1), Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(_) => return Some(0),
                    Err(observed) => current = observed,
                }
            }
        }
        // Eventos de notificação, timers de notificação e threads terminadas.
        object_type::EVENT_NOTIFICATION | object_type::TIMER_NOTIFICATION | object_type::THREAD => (state.get() != 0).then_some(0),
        // Eventos e timers de sincronização consomem o sinal.
        object_type::EVENT_SYNCHRONIZATION | object_type::TIMER_SYNCHRONIZATION => {
            let signalled = if consume { state.atomic().swap(0, Ordering::SeqCst) } else { state.get() };
            (signalled != 0).then_some(0)
        }
        object_type::MUTANT => {
            let mutant = mutant_at(object);
            let owner = process::get_current_thread();
            let mut recursion = state.get();
            loop {
                if recursion <= 0 && mutant.owner_thread.get() != owner {
                    return None;
                }
                if recursion == i32::MIN {
                    return Some(0xC000_0191);
                }
                let status = if mutant.mutant_flags.get() & 1 != 0 { 0x80 } else { 0 };
                if !consume {
                    return Some(status);
                }
                match state.atomic().compare_exchange(recursion, recursion - 1, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(_) => {
                        mutant.owner_thread.set(owner);
                        mutant.mutant_flags.set(0);
                        return Some(status);
                    }
                    Err(observed) => recursion = observed,
                }
            }
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
    // SAFETY: PLARGE_INTEGER Timeout do chamador.
    let value = unsafe { LargeInteger::at(timeout_pointer) }.quad_part.get();
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
    // SAFETY: vetor PVOID Object[Count] do chamador.
    let objects: Vec<u64> = unsafe { Field::<u64>::array_at(objects_pointer, count as usize) }.iter().map(Field::get).collect();
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
