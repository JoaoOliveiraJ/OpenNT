//! Objetos de espera do dispatcher.
//!
//! Eventos, semáforos, mutants, timers e threads e processos sinalizados.
//! Toda mudança que pode satisfazer uma espera (KeSetEvent, KePulseEvent,
//! KeReleaseSemaphore, KeReleaseMutex) testa as esperas registradas no
//! objeto (`wait::signal`, o KiWaitTest), que aprontam as threads de kernel
//! paradas nele. A espera de uma thread de kernel registra os blocos e deixa
//! a CPU (`ke::wait`); a de uma thread de usuário numa syscall bloqueia
//! (`context_switch`) e é sondada pelo despachante de usuário; a do contexto
//! de boot drena timers, DPCs, work items e o escalonador enquanto aguarda o
//! estado ou o prazo.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{clock, context_switch, dpc, thread_alert, timer, wait};
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
    pub const PROCESS: u8 = 3;
    pub const QUEUE: u8 = 4;
    pub const SEMAPHORE: u8 = 5;
    pub const THREAD: u8 = 6;
    pub const TIMER_NOTIFICATION: u8 = 8;
    pub const TIMER_SYNCHRONIZATION: u8 = 9;
    pub const TIMER2_NOTIFICATION: u8 = 0x18;
    pub const TIMER2_SYNCHRONIZATION: u8 = 0x19;
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

/// KeSetEvent: devolve o estado anterior (troca atômica do SignalState) e
/// satisfaz quem espera no evento (o de sincronização volta a não
/// sinalizado ao entregar o sinal a uma thread).
pub fn set_event(event: u64) -> u32 {
    let previous = header_at(event).signal_state.atomic().swap(1, Ordering::SeqCst) as u32;
    wait::signal(event);
    previous
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

/// KePulseEvent (ntoskrnl 19041, 0x33AAD0): com o evento não sinalizado,
/// SignalState = 1 e o KiTryUnwaitThread das esperas WaitAny da
/// WaitListHead (no evento de sincronização, até uma consumir o sinal);
/// depois SignalState = 0, devolvendo o estado anterior. Aqui o KeSetEvent
/// satisfaz as esperas registradas (os blocos das threads de kernel, em
/// `wait::signal`). As esperas sondadas não têm bloco na WaitListHead e
/// veriam o evento já não sinalizado: o pulso fica anotado para elas
/// ([`PolledObjects`]).
pub fn pulse_event(event: u64) -> u32 {
    let previous = set_event(event);
    // Ainda sinalizado: nenhuma espera consumiu o sinal (o de sincronização).
    let unclaimed = reset_event(event) != 0;
    if previous == 0 {
        note_pulse(event, unclaimed);
    }
    previous
}

/// O último pulso de um evento, na contagem global de pulsos, e, no evento
/// de sincronização, os pulsos cujo sinal nenhuma espera consumiu (0 =
/// vazio).
struct PulseRecord {
    last: u64,
    unclaimed: [u64; 4],
}

/// A contagem de pulsos anotados (o relógio das esperas sondadas).
static PULSE_COUNT: AtomicU64 = AtomicU64::new(0);
/// Os eventos pulsados, pelo endereço do KEVENT.
static PULSES: SpinLock<BTreeMap<u64, PulseRecord>> = SpinLock::new(BTreeMap::new());
/// Eventos lembrados: além disso sai o de pulso mais antigo.
const PULSED_EVENTS: usize = 256;

/// Anota um pulso que achou o evento não sinalizado.
fn note_pulse(event: u64, unclaimed: bool) {
    let mut pulses = PULSES.lock();
    let pulse = PULSE_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    if !pulses.contains_key(&event) && pulses.len() >= PULSED_EVENTS {
        if let Some(oldest) = pulses.iter().min_by_key(|(_, record)| record.last).map(|(&address, _)| address) {
            pulses.remove(&oldest);
        }
    }
    let record = pulses.entry(event).or_insert(PulseRecord { last: 0, unclaimed: [0; 4] });
    record.last = pulse;
    if unclaimed && header_at(event).type_.get() == object_type::EVENT_SYNCHRONIZATION {
        // Sem lugar, o pulso mais antigo cede o dele.
        let slot = record.unclaimed.iter().position(|&value| value == 0).unwrap_or_else(|| record.unclaimed.iter().enumerate().min_by_key(|(_, &value)| value).map_or(0, |(index, _)| index));
        record.unclaimed[slot] = pulse;
    }
}

/// Os objetos de uma espera sondada (a thread de usuário parada numa
/// syscall, o contexto de boot) e a contagem de pulsos no começo dela. Como
/// as esperas registradas que o KePulseEvent satisfaz, a espera WaitAny que
/// já esperava quando o pulso veio é satisfeita por ele: num evento de
/// notificação, toda espera; num de sincronização, uma só por pulso. O
/// WaitAll não conta pulsos.
pub struct PolledObjects {
    objects: Vec<u64>,
    wait_type: u32,
    since: u64,
}

impl PolledObjects {
    /// A espera começa aqui (antes da primeira tentativa, para nenhum pulso
    /// escapar entre ela e o bloqueio).
    pub fn new(objects: Vec<u64>, wait_type: u32) -> Self {
        Self { objects, wait_type, since: PULSE_COUNT.load(Ordering::SeqCst) }
    }

    /// A tentativa pela thread `owner`: o estado dos objetos e, sem ele, o
    /// primeiro evento pulsado desde o começo da espera.
    pub fn try_for(&self, owner: u64) -> Option<u32> {
        try_wait_objects_for(&self.objects, self.wait_type, owner).or_else(|| self.pulsed())
    }

    /// [`PolledObjects::try_for`] pela thread corrente.
    pub fn try_now(&self) -> Option<u32> {
        self.try_for(process::get_current_thread())
    }

    fn pulsed(&self) -> Option<u32> {
        if self.wait_type != 1 || PULSE_COUNT.load(Ordering::SeqCst) == self.since {
            return None;
        }
        let mut pulses = PULSES.lock();
        for (index, object) in self.objects.iter().enumerate() {
            let Some(record) = pulses.get_mut(object) else { continue };
            match header_at(*object).type_.get() {
                object_type::EVENT_NOTIFICATION if record.last > self.since => return Some(index as u32),
                object_type::EVENT_SYNCHRONIZATION => {
                    if let Some(slot) = record.unclaimed.iter_mut().filter(|value| **value > self.since).min_by_key(|value| **value) {
                        *slot = 0;
                        return Some(index as u32);
                    }
                }
                _ => {}
            }
        }
        None
    }
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
            Ok(_) => {
                wait::signal(semaphore.address());
                return Ok(previous as u32);
            }
            Err(observed) => previous = observed,
        }
    }
}

pub fn semaphore_limit(semaphore: u64) -> u32 {
    semaphore_at(semaphore).limit.get() as u32
}

/// KeInitializeSemaphore dos drivers: KSEMAPHORE com Type 5, SignalState =
/// contagem, Limit e a lista de espera vazia (sem tocar no tamanho).
pub fn initialize_driver_semaphore(semaphore: u64, count: u32, limit: u32) {
    let semaphore = semaphore_at(semaphore);
    semaphore.header.type_.set(object_type::SEMAPHORE);
    semaphore.header.signal_state.set(count as i32);
    semaphore.limit.set(limit as i32);
    initialize_list_head(&semaphore.header.wait_list_head);
}

/// KeReleaseSemaphore dos drivers: devolve o SignalState anterior; o novo é
/// anterior + ajuste, limitado ao Limit (num compare-exchange).
pub fn release_driver_semaphore(semaphore: u64, adjustment: i32) -> i32 {
    let object = semaphore;
    let semaphore = semaphore_at(semaphore);
    let limit = semaphore.limit.get();
    let state = semaphore.header.signal_state.atomic();
    let mut previous = state.load(Ordering::SeqCst);
    loop {
        let released = previous.wrapping_add(adjustment).min(limit);
        match state.compare_exchange(previous, released, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => {
                if released > 0 {
                    wait::signal(object);
                }
                return previous;
            }
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
    if next == 1 {
        wait::signal(mutex);
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

/// Consulta ou consome o estado pela thread corrente.
pub fn acquire_status(object: u64, consume: bool) -> Option<u32> {
    acquire_status_for(object, consume, process::get_current_thread())
}

/// Consulta ou consome o estado pela thread `owner` (a que espera: um mutant
/// passa a ser dela). `None` = indisponível; senão sucesso, abandono (0x80)
/// ou erro de limite. Consumir é um compare-exchange no SignalState: dois
/// waiters nunca satisfazem a mesma permissão ou sinal.
pub fn acquire_status_for(object: u64, consume: bool, owner: u64) -> Option<u32> {
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
        // Eventos de notificação, timers de notificação e threads e processos
        // terminados.
        object_type::EVENT_NOTIFICATION | object_type::TIMER_NOTIFICATION | object_type::TIMER2_NOTIFICATION | object_type::THREAD | object_type::PROCESS => (state.get() != 0).then_some(0),
        // Uma fila (KQUEUE, o corpo do IoCompletion) com entradas satisfaz a
        // espera sem consumir: as entradas saem só pela retirada.
        object_type::QUEUE => (state.get() > 0).then_some(0),
        // Eventos e timers de sincronização consomem o sinal.
        object_type::EVENT_SYNCHRONIZATION | object_type::TIMER_SYNCHRONIZATION | object_type::TIMER2_SYNCHRONIZATION => {
            let signalled = if consume { state.atomic().swap(0, Ordering::SeqCst) } else { state.get() };
            (signalled != 0).then_some(0)
        }
        object_type::MUTANT => {
            let mutant = mutant_at(object);
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
    Some(timeout_value_to_100ns(unsafe { LargeInteger::at(timeout_pointer) }.quad_part.get()))
}

/// O intervalo até o prazo `value` (o LARGE_INTEGER já capturado), em
/// unidades de 100 ns: zero = consulta imediata, negativo = relativo,
/// positivo = absoluto na hora do sistema (zero se já passou).
pub fn timeout_value_to_100ns(value: i64) -> u64 {
    if value <= 0 {
        return value.unsigned_abs();
    }
    (value as u64).saturating_sub(clock::system_time_100ns())
}

/// Prazo apontado por `timeout_pointer`, em ms inteiros arredondados para
/// cima: um prazo não nulo abaixo de 1 ms espera até o próximo ms (como o
/// NT, que nunca vence um prazo não nulo antes do próximo tick), em vez de
/// vencer de imediato.
pub fn timeout_pointer_to_ms(timeout_pointer: u64) -> Option<u64> {
    timeout_to_100ns(timeout_pointer).map(|value| value.div_ceil(10_000))
}

/// O prazo capturado de uma espera de modo usuário (`None` = sem prazo), em
/// ms inteiros arredondados para cima, como [`timeout_pointer_to_ms`].
pub fn timeout_value_to_ms(value: Option<i64>) -> Option<u64> {
    value.map(|value| timeout_value_to_100ns(value).div_ceil(10_000))
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

/// Interrupções de dispositivo, timers, DPCs, o gerenciador das worker
/// threads, conclusões registradas e escalonador: o trabalho do despachante,
/// que só o contexto de boot gira (os work items rodam nas workers que o
/// escalonador entra, nunca aqui). Numa thread de kernel o pump não aninha o despachante na
/// pilha dela: a thread cede a vez (em DISPATCH_LEVEL ou acima, só os
/// timers e as DPCs andam).
pub fn pump_kernel() {
    if context_switch::in_kernel_thread() {
        if context_switch::kernel_thread_can_block() {
            context_switch::yield_kernel_thread(false);
        } else {
            timer::check_timers();
            let _ = dpc::run_queue();
        }
        return;
    }
    super::interrupt_object::service_during_wait();
    timer::check_timers();
    let _ = dpc::run_queue();
    work_items::balance();
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

/// O prazo da espera venceu (zero vence de imediato).
fn expired(timeout: Option<u64>, deadline: Option<u64>) -> bool {
    timeout == Some(0) || deadline.is_some_and(|deadline| clock::uptime_100ns() >= deadline)
}

/// KeWaitForSingleObject. Uma thread de kernel registra o bloco e deixa a
/// CPU até o sinal ou o prazo (`ke::wait`); numa syscall a thread bloqueia
/// até o objeto ser sinalizado (ou pulsado, [`PolledObjects`]) ou o prazo
/// vencer (`context_switch::wait_until`); no contexto de boot a espera gira
/// o `pump_kernel`.
pub fn wait_for_single_object(object: u64, timeout_pointer: u64, wait_mode: u8, alertable: bool) -> u32 {
    if context_switch::kernel_thread_can_block() {
        return wait::wait_for_objects(&[object], false, wait::Deadline::after(timeout_to_100ns(timeout_pointer)), wait_mode, alertable, wait::reason::EXECUTIVE);
    }
    let (timeout, deadline) = deadline(timeout_pointer);
    let polled = PolledObjects::new(alloc::vec![object], 1);
    if alertable {
        let mut poll = || polled.try_now().or_else(|| expired(timeout, deadline).then_some(STATUS_TIMEOUT));
        return thread_alert::cooperate(process::get_current_thread(), wait_mode, true, &mut poll, pump_kernel);
    }
    // Não alertável: uma espera de UserMode ainda sai com UserApcPending (o
    // KiCheckAlertability), como a da thread de kernel em `ke::wait`.
    let thread = process::get_current_thread();
    let mut poll = || thread_alert::consume(thread, wait_mode, false).or_else(|| polled.try_now()).or_else(|| expired(timeout, deadline).then_some(STATUS_TIMEOUT));
    context_switch::wait_until(&mut poll, pump_kernel)
}

/// Tentativa sem espera pela thread corrente.
pub fn try_wait_objects(objects: &[u64], wait_type: u32) -> Option<u32> {
    try_wait_objects_for(objects, wait_type, process::get_current_thread())
}

/// Tentativa sem espera pela thread `owner`. WaitAny (1) devolve o primeiro
/// índice satisfeito; WaitAll (0) consulta todos antes de consumir.
pub fn try_wait_objects_for(objects: &[u64], wait_type: u32, owner: u64) -> Option<u32> {
    if wait_type == 1 {
        for (index, &object) in objects.iter().enumerate() {
            if let Some(status) = acquire_status_for(object, true, owner) {
                return Some(if status & 0x8000_0000 != 0 { status } else { status + index as u32 });
            }
        }
        return None;
    }
    let states: Vec<Option<u32>> = objects.iter().map(|&object| acquire_status_for(object, false, owner)).collect();
    if let Some(error) = states.iter().flatten().find(|&&status| status & 0x8000_0000 != 0) {
        return Some(*error);
    }
    if states.iter().all(Option::is_some) {
        for &object in objects {
            acquire_status_for(object, true, owner);
        }
        // Um mutant abandonado preserva STATUS_ABANDONED no resultado conjunto.
        return Some(if states.contains(&Some(0x80)) { 0x80 } else { STATUS_SUCCESS });
    }
    None
}

/// KeWaitForMultipleObjects: até 64 ponteiros. Como no 19041, um objeto
/// repetido não é recusado aqui (o ObWaitForMultipleObjects recusa o
/// repetido só no WaitAll): cada posição tem o seu bloco de espera, e no
/// WaitAny o primeiro índice satisfeito vence.
pub fn wait_for_multiple_objects(count: u32, objects_pointer: u64, wait_type: u32, timeout_pointer: u64, wait_mode: u8, alertable: bool) -> u32 {
    if count == 0 || count > 64 || wait_type > 1 {
        return 0xC000_000D;
    }
    // SAFETY: vetor PVOID Object[Count] do chamador.
    let objects: Vec<u64> = unsafe { Field::<u64>::array_at(objects_pointer, count as usize) }.iter().map(Field::get).collect();
    if context_switch::kernel_thread_can_block() {
        return wait::wait_for_objects(&objects, wait_type == 0, wait::Deadline::after(timeout_to_100ns(timeout_pointer)), wait_mode, alertable, wait::reason::EXECUTIVE);
    }
    let (timeout, deadline) = deadline(timeout_pointer);
    let polled = PolledObjects::new(objects, wait_type);
    if alertable {
        let mut poll = || polled.try_now().or_else(|| expired(timeout, deadline).then_some(STATUS_TIMEOUT));
        return thread_alert::cooperate(process::get_current_thread(), wait_mode, true, &mut poll, pump_kernel);
    }
    let thread = process::get_current_thread();
    let mut poll = || thread_alert::consume(thread, wait_mode, false).or_else(|| polled.try_now()).or_else(|| expired(timeout, deadline).then_some(STATUS_TIMEOUT));
    context_switch::wait_until(&mut poll, pump_kernel)
}
