//! Estado de despacho de uma CPU.
//!
//! Filas nativas de 32 prioridades na KPRCB, contagem de ciclos próprios e
//! entrega de contextos. As filas não possuem a ETHREAD: o runtime dono a
//! retém (aqui identificado por um número opaco, como o pid do escalonador).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{clock, pcr};
use crate::hal::cpu;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread as layout;

pub mod state {
    pub const INITIALIZED: u8 = 0;
    pub const READY: u8 = 1;
    pub const RUNNING: u8 = 2;
    pub const STANDBY: u8 = 3;
    pub const TERMINATED: u8 = 4;
    pub const WAITING: u8 = 5;
    pub const DEFERRED_READY: u8 = 7;
}

/// Layout 19041 conferido no PDB, dentro da reserva real da PCR (KPRCB).
pub mod processor {
    pub const CURRENT_THREAD: u64 = 8;
    pub const NEXT_THREAD: u64 = 0x10;
    pub const IDLE_THREAD: u64 = 0x18;
    pub const NESTING: u64 = 0x20;
    pub const READY_SUMMARY: u64 = 0x7C18;
    pub const READY_LISTS: u64 = 0x7C80;
    pub const READY_COUNT: u64 = 0x7EB4;
    pub const EXPECTED_RUN_TIME: u64 = 0x7EB8;
}

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
    address + 0x180
}

pub fn priority(thread: u64) -> u8 {
    guest::read8(thread + layout::PRIORITY)
}

pub fn thread_state(thread: u64) -> u8 {
    guest::read8(thread + layout::STATE)
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
    let processor = processor_address();
    for index in 0..32 {
        let head = processor + processor::READY_LISTS + index * 16;
        guest::write64(head, head);
        guest::write64(head + 8, head);
    }
    guest::write32(processor + processor::READY_SUMMARY, 0);
    guest::write32(processor + processor::READY_COUNT, 0);
    guest::write64(processor + processor::EXPECTED_RUN_TIME, 0);
    STATE.lock().queues_initialized = true;
}

/// Confere os dois vínculos antes de remover; corrupção nunca vira sucesso.
pub fn remove_ready(thread: u64) -> Result<(), KernelError> {
    let processor = processor_address();
    let entry = thread + layout::WAIT_LIST_ENTRY;
    let next = guest::read64(entry);
    let previous = guest::read64(entry + 8);
    if next == 0 || previous == 0 || guest::read64(next + 8) != entry || guest::read64(previous) != entry {
        return Err(KernelError::new("corrupt native ready queue"));
    }
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
    if next == previous {
        let summary = processor + processor::READY_SUMMARY;
        guest::write32(summary, guest::read32(summary) & !(1u32 << priority(thread)));
    }
    let count_address = processor + processor::READY_COUNT;
    let count = guest::read32(count_address);
    if count == 0 {
        return Err(KernelError::new("native ready count underflow"));
    }
    guest::write32(count_address, count - 1);
    let expected = processor + processor::EXPECTED_RUN_TIME;
    guest::write64(expected, guest::read64(expected).wrapping_sub(guest::read32(thread + layout::EXPECTED_RUN_TIME) as u64));
    Ok(())
}

pub fn enqueue_ready(thread: u64, at_front: bool, preserve_wait_time: bool) {
    initialize_queues();
    let processor = processor_address();
    let head = processor + processor::READY_LISTS + priority(thread) as u64 * 16;
    let entry = thread + layout::WAIT_LIST_ENTRY;
    let next = if at_front { guest::read64(head) } else { head };
    let previous = if at_front { head } else { guest::read64(head + 8) };
    guest::write64(entry, next);
    guest::write64(entry + 8, previous);
    guest::write64(previous, entry);
    guest::write64(next + 8, entry);
    let summary = processor + processor::READY_SUMMARY;
    guest::write32(summary, guest::read32(summary) | (1u32 << priority(thread)));
    let count = processor + processor::READY_COUNT;
    guest::write32(count, guest::read32(count) + 1);
    let expected = processor + processor::EXPECTED_RUN_TIME;
    guest::write64(expected, guest::read64(expected).wrapping_add(guest::read32(thread + layout::EXPECTED_RUN_TIME) as u64));
    guest::write8(thread + layout::STATE, state::READY);
    if !preserve_wait_time {
        guest::write32(thread + layout::WAIT_TIME, tick_count());
    }
}

pub fn highest_ready() -> Result<u64, KernelError> {
    let processor = processor_address();
    let summary = guest::read32(processor + processor::READY_SUMMARY);
    if summary == 0 {
        return Ok(0);
    }
    let highest = 31 - summary.leading_zeros() as u64;
    let head = processor + processor::READY_LISTS + highest * 16;
    let entry = guest::read64(head);
    if entry == head || entry == 0 {
        return Err(KernelError::new("ready summary disagrees with native list"));
    }
    Ok(entry - layout::WAIT_LIST_ENTRY)
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
    guest::read64(processor_address() + processor::NEXT_THREAD)
}

pub fn reserve_next(thread: u64) {
    if thread_state(thread) == state::READY {
        let ready_time = thread + layout::READY_TIME;
        let waited = tick_count().wrapping_sub(guest::read32(thread + layout::WAIT_TIME));
        guest::write32(ready_time, guest::read32(ready_time).wrapping_add(waited));
    }
    guest::write8(thread + layout::STATE, state::STANDBY);
    guest::write64(processor_address() + processor::NEXT_THREAD, thread);
}

pub fn defer_ready(thread: u64, deferred: &mut Vec<u64>) {
    if thread_state(thread) == state::READY {
        let flags = thread + layout::MISC_FLAGS;
        guest::write32(flags, guest::read32(flags) | 2);
    }
    guest::write8(thread + layout::STATE, state::DEFERRED_READY);
    let previous = deferred.last().map_or(0, |&last| last + layout::WAIT_LIST_ENTRY);
    guest::write64(thread + layout::WAIT_LIST_ENTRY, previous);
    deferred.push(thread);
}

pub fn ensure_minimum_quantum(thread: u64) {
    let cycles = guest::read64(thread + layout::CYCLE_TIME);
    let target_address = thread + layout::QUANTUM_TARGET;
    let target = guest::read64(target_address);
    let minimum = cycles_per_quantum() as u64;
    if cycles > target || target - cycles < minimum {
        guest::write64(target_address, cycles.wrapping_add(minimum));
    }
}

/// O dono do contexto decide o momento seguro da entrega.
pub fn complete_priority_change(deferred: &[u64]) {
    for &thread in deferred.iter().rev() {
        let flags_address = thread + layout::MISC_FLAGS;
        let flags = guest::read32(flags_address);
        enqueue_ready(thread, false, flags & 2 != 0);
        guest::write32(flags_address, flags & !2);
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
    let address = active.pointer + layout::CYCLE_TIME;
    guest::write64(address, guest::read64(address).wrapping_add(elapsed));
    active.started = now;
}

pub fn sample_cycles(thread: u64) -> u64 {
    let mut dispatch = STATE.lock();
    let nesting = guest::read8(processor_address() + processor::NESTING);
    if dispatch.active.as_ref().is_some_and(|active| active.pointer == thread) && nesting == 0 {
        account_active_cycles(&mut dispatch);
    }
    guest::read64(thread + layout::CYCLE_TIME)
}

/// KeQueryRuntimeThread: tempo de kernel devolvido e de usuário gravado na
/// saída opcional, em ticks do relógio (KeQueryTimeIncrement).
pub fn query_runtime_thread(thread: u64, user_time: u64) -> u64 {
    let (kernel, user) = crate::ntos::ps::process::thread_record(thread).map_or((0, 0), |record| (record.kernel_time, record.user_time));
    if user_time != 0 {
        guest::write32(user_time, (user / clock::TIME_INCREMENT) as u32);
    }
    kernel / clock::TIME_INCREMENT & 0xFFFF_FFFF
}

/// A thread de boot do System não é o processo Idle.
pub fn is_idle_thread(thread: u64) -> bool {
    let idle = guest::read64(processor_address() + processor::IDLE_THREAD);
    idle != 0 && guest::read64(idle + layout::PROCESS) == guest::read64(thread + layout::PROCESS)
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
        guest::write64(processor_address() + processor::NEXT_THREAD, 0);
    }
    guest::write8(thread + layout::STATE, new_state);
    guest::write32(thread + layout::WAIT_TIME, tick_count());
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
        guest::write64(processor_address() + processor::NEXT_THREAD, 0);
    }
    guest::write8(thread + layout::STATE, state::RUNNING);
    guest::write8(thread + layout::RUNNING, 1);
    let cycles = guest::read64(thread + layout::CYCLE_TIME);
    let target_address = thread + layout::QUANTUM_TARGET;
    if cycles >= guest::read64(target_address) {
        let reset = guest::read8(thread + layout::QUANTUM_RESET) as u32;
        guest::write64(target_address, cycles.wrapping_add(reset.wrapping_mul(cycles_per_quantum()) as u64));
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
    let decrement_address = thread + layout::PRIORITY_DECREMENT;
    let decrement = guest::read8(decrement_address) as i32;
    let base = guest::read8(thread + layout::BASE_PRIORITY) as i8 as i32;
    let candidate = ((previous - (decrement >> 4) - (decrement & 15) - 1) as i8) as i32;
    if decrement & 15 != 0 {
        guest::write32(thread + layout::FOREGROUND_LOSS_TIME, tick_count());
    }
    if decrement != 0 {
        guest::write8(decrement_address, 0);
    }
    let floor = guest::read32(thread + layout::PRIORITY_FLOOR_SUMMARY);
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
    guest::write8(thread + layout::RUNNING, 0);
    let cycles = guest::read64(thread + layout::CYCLE_TIME);
    let quantum_disabled = guest::read32(thread + layout::THREAD_FLAGS) & 0x100 != 0;
    let expired = !quantum_disabled && cycles >= guest::read64(thread + layout::QUANTUM_TARGET);
    if expired && new_state == state::READY {
        guest::write8(thread + layout::PRIORITY, compute_quantum_end_priority(thread));
    }
    // Yield explícito entrega a vez mesmo com quantum restante.
    if voluntary_yield {
        guest::write64(thread + layout::QUANTUM_TARGET, cycles);
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
