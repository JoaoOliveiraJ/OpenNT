//! Estado de despacho de uma CPU.
//!
//! Filas nativas de 32 prioridades na KPRCB, contagem de ciclos próprios e
//! entrega de contextos. As filas não possuem a ETHREAD: o runtime dono a
//! retém (aqui identificado por um número opaco, como o pid do escalonador).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{clock, pcr};
use crate::hal::cpu;
use crate::ntos::inc::types::{Ethread, Field, Kprcb, Kthread, ListEntry, NtStruct};
use crate::rtl::{KernelError, SpinLock};

pub mod state {
    pub const INITIALIZED: u8 = 0;
    pub const READY: u8 = 1;
    pub const RUNNING: u8 = 2;
    pub const STANDBY: u8 = 3;
    pub const TERMINATED: u8 = 4;
    pub const WAITING: u8 = 5;
    pub const DEFERRED_READY: u8 = 7;
}

/// KTHREAD.WaitListEntry: o vínculo das filas prontas (KiReadyThread).
const WAIT_LIST_ENTRY: u64 = core::mem::offset_of!(Kthread, wait_list_entry) as u64;

/// Runtime das threads de usuário (`domain: 'user'`); os demais são
/// processos do escalonador de kernel.
pub const USER_RUNTIME: u64 = 1 << 63;

/// Dono executável de uma thread.
#[derive(Clone, Copy, Debug)]
pub struct Owner {
    pub runtime: u64,
    pub yield_requested: bool,
    /// Porta de conclusão de I/O associada (worker factories, fase 7).
    pub io_completion_port: Option<u64>,
}

struct Execution {
    pointer: u64,
    started: u64,
}

struct Dispatch {
    owners: BTreeMap<u64, Owner>,
    stack: Vec<Option<Execution>>,
    active: Option<Execution>,
    queues_initialized: bool,
    priority_observer: Option<fn()>,
    /// Notificação de atividade da porta de conclusão (porta, runtime, ativo).
    port_activity: Option<fn(u64, u64, bool)>,
}

static STATE: SpinLock<Dispatch> = SpinLock::new(Dispatch {
    owners: BTreeMap::new(),
    stack: Vec::new(),
    active: None,
    queues_initialized: false,
    priority_observer: None,
    port_activity: None,
});

pub fn processor_address() -> u64 {
    let address = pcr::get_pcr_address();
    assert!(address != 0, "thread dispatch requires initialized PCR");
    address + core::mem::offset_of!(crate::ntos::inc::types::Kpcr, prcb) as u64
}

/// A KPRCB do processador corrente (embutida na KPCR).
fn processor() -> &'static Kprcb {
    // SAFETY: a KPCR está mapeada desde `pcr::init`.
    unsafe { Kprcb::at(processor_address()) }
}

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: as filas só recebem KTHREADs vivas.
    unsafe { Kthread::at(thread) }
}

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: toda KTHREAD do escalonador é o Tcb de uma ETHREAD.
    unsafe { Ethread::at(thread) }
}

fn list_entry(address: u64) -> &'static ListEntry {
    // SAFETY: vínculos de uma fila pronta conferida.
    unsafe { ListEntry::at(address) }
}

pub fn priority(thread: u64) -> u8 {
    kthread(thread).priority.get() as u8
}

pub fn thread_state(thread: u64) -> u8 {
    kthread(thread).state.get()
}

/// Mesma unidade de ms de KUSER_SHARED_DATA.TickCount e KeQueryTickCount.
pub fn tick_count() -> u32 {
    clock::uptime_ms() as u32
}

/// Três unidades de quantum por tick, pela frequência TSC calibrada.
pub fn cycles_per_quantum() -> u32 {
    let frequency = clock::tsc_frequency_hz();
    assert!(frequency > 0, "uncalibrated scheduler clock");
    (frequency / 300).max(1) as u32
}

pub fn initialize_queues() {
    if STATE.lock().queues_initialized {
        return;
    }
    let processor = processor();
    for head in &processor.dispatcher_ready_list_head {
        head.flink.set(head.address());
        head.blink.set(head.address());
    }
    processor.ready_summary.set(0);
    processor.ready_thread_count.set(0);
    processor.ready_queue_expected_run_time.set(0);
    STATE.lock().queues_initialized = true;
}

/// Confere os dois vínculos antes de remover; corrupção nunca vira sucesso.
/// As filas são da CPU corrente (o PrcbLock do NT não tem disputa aqui).
pub fn remove_ready(thread: u64) -> Result<(), KernelError> {
    let processor = processor();
    let entry = &kthread(thread).wait_list_entry;
    let next = entry.flink.get();
    let previous = entry.blink.get();
    if next == 0 || previous == 0 || list_entry(next).blink.get() != entry.address() || list_entry(previous).flink.get() != entry.address() {
        return Err(KernelError::new("corrupt native ready queue"));
    }
    list_entry(previous).flink.set(next);
    list_entry(next).blink.set(previous);
    if next == previous {
        processor.ready_summary.set(processor.ready_summary.get() & !(1u32 << priority(thread)));
    }
    let count = processor.ready_thread_count.get();
    if count == 0 {
        return Err(KernelError::new("native ready count underflow"));
    }
    processor.ready_thread_count.set(count - 1);
    let expected = &processor.ready_queue_expected_run_time;
    expected.set(expected.get().wrapping_sub(ethread(thread).last_expected_run_time.get() as u64));
    Ok(())
}

pub fn enqueue_ready(thread: u64, at_front: bool, preserve_wait_time: bool) {
    initialize_queues();
    let processor = processor();
    let kthread = kthread(thread);
    let head = &processor.dispatcher_ready_list_head[priority(thread) as usize];
    let entry = &kthread.wait_list_entry;
    let next = if at_front { head.flink.get() } else { head.address() };
    let previous = if at_front { head.address() } else { head.blink.get() };
    entry.flink.set(next);
    entry.blink.set(previous);
    list_entry(previous).flink.set(entry.address());
    list_entry(next).blink.set(entry.address());
    processor.ready_summary.set(processor.ready_summary.get() | (1u32 << priority(thread)));
    processor.ready_thread_count.set(processor.ready_thread_count.get() + 1);
    let expected = &processor.ready_queue_expected_run_time;
    expected.set(expected.get().wrapping_add(ethread(thread).last_expected_run_time.get() as u64));
    kthread.state.set(state::READY);
    if !preserve_wait_time {
        kthread.wait_time.set(tick_count());
    }
}

pub fn highest_ready() -> Result<u64, KernelError> {
    let processor = processor();
    let summary = processor.ready_summary.get();
    if summary == 0 {
        return Ok(0);
    }
    let highest = 31 - summary.leading_zeros() as usize;
    let head = &processor.dispatcher_ready_list_head[highest];
    let entry = head.flink.get();
    if entry == head.address() || entry == 0 {
        return Err(KernelError::new("ready summary disagrees with native list"));
    }
    Ok(entry - WAIT_LIST_ENTRY)
}

pub fn take_ready_above(minimum_priority: i32) -> Result<u64, KernelError> {
    let thread = highest_ready()?;
    if thread == 0 || priority(thread) as i32 <= minimum_priority {
        return Ok(0);
    }
    remove_ready(thread)?;
    Ok(thread)
}

pub fn next_thread() -> u64 {
    processor().next_thread.get()
}

pub fn reserve_next(thread: u64) {
    let kthread = kthread(thread);
    if kthread.state.get() == state::READY {
        let waited = tick_count().wrapping_sub(kthread.wait_time.get());
        kthread.ready_time.set(kthread.ready_time.get().wrapping_add(waited));
    }
    kthread.state.set(state::STANDBY);
    processor().next_thread.set(thread);
}

pub fn defer_ready(thread: u64, deferred: &mut Vec<u64>) {
    let kthread = kthread(thread);
    if kthread.state.get() == state::READY {
        // MiscFlags.ReadyTransition: CAS atômico (outros bits do mesmo
        // DWORD mudam por outros caminhos).
        kthread.set_ready_transition(1);
    }
    kthread.state.set(state::DEFERRED_READY);
    let previous = deferred.last().map_or(0, |&last| last + WAIT_LIST_ENTRY);
    kthread.wait_list_entry.flink.set(previous);
    deferred.push(thread);
}

pub fn ensure_minimum_quantum(thread: u64) {
    let kthread = kthread(thread);
    let cycles = kthread.cycle_time.get();
    let target = kthread.quantum_target.get();
    let minimum = cycles_per_quantum() as u64;
    if cycles > target || target - cycles < minimum {
        kthread.quantum_target.set(cycles.wrapping_add(minimum));
    }
}

/// O dono do contexto decide o momento seguro da entrega.
pub fn complete_priority_change(deferred: &[u64]) {
    for &thread in deferred.iter().rev() {
        let kthread = kthread(thread);
        enqueue_ready(thread, false, kthread.ready_transition() != 0);
        kthread.set_ready_transition(0);
    }
    let observer = STATE.lock().priority_observer;
    if let Some(observer) = observer {
        observer();
    }
}

/// Soma só os intervalos em que o contexto esteve ativo.
fn account_active_cycles(dispatch: &mut Dispatch) {
    let Some(active) = dispatch.active.as_mut() else { return };
    let now = cpu::rdtsc();
    let elapsed = now.wrapping_sub(active.started);
    let cycles = &kthread(active.pointer).cycle_time;
    cycles.set(cycles.get().wrapping_add(elapsed));
    active.started = now;
}

pub fn sample_cycles(thread: u64) -> u64 {
    let mut dispatch = STATE.lock();
    let nesting = processor().nesting_level.get();
    if dispatch.active.as_ref().is_some_and(|active| active.pointer == thread) && nesting == 0 {
        account_active_cycles(&mut dispatch);
    }
    kthread(thread).cycle_time.get()
}

/// KeQueryRuntimeThread: tempo de kernel devolvido e de usuário gravado na
/// saída opcional, em ticks do relógio (KeQueryTimeIncrement).
pub fn query_runtime_thread(thread: u64, user_time: u64) -> u64 {
    let (kernel, user) = crate::ntos::ps::process::thread_record(thread).map_or((0, 0), |record| (record.kernel_time, record.user_time));
    if user_time != 0 {
        // SAFETY: PULONG UserTime opcional do chamador.
        unsafe { Field::<u32>::at(user_time) }.set((user / clock::TIME_INCREMENT) as u32);
    }
    kernel / clock::TIME_INCREMENT & 0xFFFF_FFFF
}

/// A thread de boot do System não é o processo Idle.
pub fn is_idle_thread(thread: u64) -> bool {
    let idle = processor().idle_thread.get();
    idle != 0 && kthread(idle).process.get() == kthread(thread).process.get()
}

pub fn register(thread: u64, runtime: u64) -> Result<(), KernelError> {
    {
        let mut dispatch = STATE.lock();
        if dispatch.owners.contains_key(&thread) {
            return Err(KernelError::new("thread already has scheduler owner"));
        }
        dispatch.owners.insert(thread, Owner { runtime, yield_requested: false, io_completion_port: None });
    }
    make_ready(thread)
}

pub fn make_ready(thread: u64) -> Result<(), KernelError> {
    let current = thread_state(thread);
    if current == state::READY || current == state::STANDBY {
        return Ok(());
    }
    if current == state::TERMINATED {
        return Err(KernelError::new("cannot ready a terminated thread"));
    }
    enqueue_ready(thread, false, false);
    Ok(())
}

pub fn suspend(thread: u64, new_state: u8) -> Result<(), KernelError> {
    if thread_state(thread) == state::READY {
        remove_ready(thread)?;
    }
    if next_thread() == thread {
        processor().next_thread.set(0);
    }
    let kthread = kthread(thread);
    kthread.state.set(new_state);
    kthread.wait_time.set(tick_count());
    let (owner, notify) = {
        let dispatch = STATE.lock();
        (dispatch.owners.get(&thread).copied(), dispatch.port_activity)
    };
    if new_state == state::WAITING {
        if let (Some(Owner { runtime, io_completion_port: Some(port), .. }), Some(notify)) = (owner, notify) {
            notify(port, runtime, false);
        }
    }
    Ok(())
}

pub fn unregister(thread: u64) -> Result<(), KernelError> {
    suspend(thread, state::TERMINATED)?;
    STATE.lock().owners.remove(&thread);
    Ok(())
}

/// NextThread é uma reserva real: uma thread de prioridade maior a substitui.
pub fn peek() -> Result<Option<(u64, Owner)>, KernelError> {
    initialize_queues();
    let mut reserved = next_thread();
    let ready = highest_ready()?;
    if ready != 0 && (reserved == 0 || priority(ready) > priority(reserved)) {
        if reserved != 0 {
            enqueue_ready(reserved, true, false);
        }
        remove_ready(ready)?;
        reserve_next(ready);
        reserved = ready;
    }
    if reserved == 0 {
        return Ok(None);
    }
    let owner = STATE.lock().owners.get(&reserved).copied();
    owner.map(|owner| Some((reserved, owner))).ok_or_else(|| KernelError::new("ready thread has no executable owner"))
}

pub fn begin_execution(thread: u64) -> Result<(), KernelError> {
    let (owner, notify) = {
        let mut dispatch = STATE.lock();
        account_active_cycles(&mut dispatch);
        let previous = dispatch.active.take();
        dispatch.stack.push(previous);
        dispatch.active = Some(Execution { pointer: thread, started: cpu::rdtsc() });
        (dispatch.owners.get(&thread).copied(), dispatch.port_activity)
    };
    if let (Some(Owner { runtime, io_completion_port: Some(port), .. }), Some(notify)) = (owner, notify) {
        notify(port, runtime, true);
    }
    if thread_state(thread) == state::READY {
        remove_ready(thread)?;
    }
    if next_thread() == thread {
        processor().next_thread.set(0);
    }
    let kthread = kthread(thread);
    kthread.state.set(state::RUNNING);
    kthread.running.set(1);
    let cycles = kthread.cycle_time.get();
    if cycles >= kthread.quantum_target.get() {
        let reset = kthread.quantum_reset.get() as u32;
        kthread.quantum_target.set(cycles.wrapping_add(reset.wrapping_mul(cycles_per_quantum()) as u64));
    }
    Ok(())
}

/// KiComputeNewPriority, com separação de foreground desligada. O fim do
/// quantum retira o boost sem baixar da base nem dos pisos ativos.
pub fn compute_quantum_end_priority(thread: u64) -> u8 {
    let previous = priority(thread) as i32;
    if previous >= 16 {
        return previous as u8;
    }
    let kthread = kthread(thread);
    let decrement = kthread.priority_decrement.get() as u8 as i32;
    let base = kthread.base_priority.get() as i32;
    let candidate = ((previous - (decrement >> 4) - (decrement & 15) - 1) as i8) as i32;
    if decrement & 15 != 0 {
        kthread.foreground_loss_time.set(tick_count());
    }
    if decrement != 0 {
        kthread.priority_decrement.set(0);
    }
    let floor = kthread.priority_floor_summary.get();
    let floor_priority = if floor != 0 { 31 - floor.leading_zeros() as i32 } else { 0 };
    base.max(candidate).max(floor_priority) as u8
}

pub fn end_execution(thread: u64, new_state: u8) -> Result<(), KernelError> {
    let voluntary_yield = {
        let mut dispatch = STATE.lock();
        if dispatch.active.as_ref().map(|active| active.pointer) != Some(thread) {
            return Err(KernelError::new("thread execution stack mismatch"));
        }
        account_active_cycles(&mut dispatch);
        match dispatch.owners.get_mut(&thread) {
            Some(owner) => core::mem::replace(&mut owner.yield_requested, false),
            None => false,
        }
    };
    let kthread = kthread(thread);
    kthread.running.set(0);
    let cycles = kthread.cycle_time.get();
    let quantum_disabled = kthread.disable_quantum() != 0;
    let expired = !quantum_disabled && cycles >= kthread.quantum_target.get();
    if expired && new_state == state::READY {
        kthread.priority.set(compute_quantum_end_priority(thread) as i8);
    }
    // Yield explícito entrega a vez mesmo com quantum restante.
    if voluntary_yield {
        kthread.quantum_target.set(cycles);
    }
    if new_state == state::READY {
        enqueue_ready(thread, !expired && !voluntary_yield, false);
    } else {
        suspend(thread, new_state)?;
    }
    let mut dispatch = STATE.lock();
    dispatch.active = dispatch.stack.pop().flatten();
    if let Some(active) = dispatch.active.as_mut() {
        active.started = cpu::rdtsc();
    }
    Ok(())
}

pub fn request_yield(thread: u64) -> Result<bool, KernelError> {
    if !STATE.lock().owners.contains_key(&thread) {
        return Ok(false);
    }
    let candidates = [next_thread(), highest_ready()?];
    let contested = candidates.iter().any(|&candidate| candidate != 0 && candidate != thread && priority(candidate) >= priority(thread));
    if !contested {
        return Ok(false);
    }
    if let Some(owner) = STATE.lock().owners.get_mut(&thread) {
        owner.yield_requested = true;
    }
    Ok(true)
}

pub fn register_priority_change_observer(observer: fn()) -> Result<(), KernelError> {
    let mut dispatch = STATE.lock();
    if dispatch.priority_observer.is_some() {
        return Err(KernelError::new("priority change observer already registered"));
    }
    dispatch.priority_observer = Some(observer);
    Ok(())
}

pub fn set_port_activity_observer(observer: Option<fn(u64, u64, bool)>) {
    STATE.lock().port_activity = observer;
}

pub fn set_io_completion_port(thread: u64, port: Option<u64>) {
    if let Some(owner) = STATE.lock().owners.get_mut(&thread) {
        owner.io_completion_port = port;
    }
}

pub fn owner(thread: u64) -> Option<Owner> {
    STATE.lock().owners.get(&thread).copied()
}
