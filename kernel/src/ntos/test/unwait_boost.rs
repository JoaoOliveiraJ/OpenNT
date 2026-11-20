//! O ajuste de prioridade de quem sai de uma espera (o AdjustUnwait do
//! KiDeferredReadySingleThread do 19041, `ke/thread_dispatch.rs`).
//!
//! Uma thread de sistema real repete um KeWaitForSingleObject alertável num
//! evento de sincronização. A cada caso, parada (Waiting, fora da fila), o
//! teste grava na KTHREAD dela a base, a prioridade, o PriorityDecrement, o
//! DisableBoost, o WaitTime (a espera curta ou de dois ticks ou mais) e o
//! QuantumTarget (gasto ou não), e no EPROCESS dono o MemoryPriority (o
//! processo de primeiro plano). Então a tira da espera pelo export (o
//! KeSetEvent com um Increment, o KeAlertThread) e, antes de ela rodar,
//! confere a prioridade, o PriorityDecrement e o quantum com que ela entrou
//! na fila, calculados pelas regras do binário: a base mais o incremento
//! (mais o PsPrioritySeparation no primeiro plano, só essa parte no
//! ForegroundBoost) até 15 quando isso sobe a prioridade; o decaimento de um
//! ponto, com o quantum renovado, depois do quantum gasto, com a base em 14
//! ou mais ou depois de uma espera longa sem impulso em curso; nada sem
//! DisableBoost, com um impulso incomum em curso ou em tempo real; o
//! incremento 2 do alerta.

use core::sync::atomic::{AtomicU64, Ordering};

use super::phase6::call_export;
use crate::ntos::inc::types::{Eprocess, Kthread, NtStruct};
use crate::ntos::ke::{clock, dispatcher, thread_dispatch, wait};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::{kernel_threads, scheduler};

type Assert = fn(bool, &str);

/// O bloco da thread: [0] o KEVENT de sincronização, [0x20] voltas da
/// espera, [0x28] fim pedido, [0x30] o último status.
const ROUNDS: u64 = 0x20;
const STOP: u64 = 0x28;
const STATUS: u64 = 0x30;

/// Os sinais já dados à thread: parada de novo, ela completou tantas voltas.
static SIGNALED: AtomicU64 = AtomicU64::new(0);

extern "win64" fn waiter(block: u64) {
    loop {
        // KeWaitForSingleObject(Event, Executive, KernelMode, Alertable, NULL).
        let status = call_export("KeWaitForSingleObject", &[block, 0, 0, 1, 0]).unwrap_or(u64::MAX);
        guest::write64(block + STATUS, status);
        guest::write64(block + ROUNDS, guest::read64(block + ROUNDS) + 1);
        if guest::read64(block + STOP) != 0 {
            return;
        }
    }
}

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: a KTHREAD da thread de sistema retida pelo teste.
    unsafe { Kthread::at(thread) }
}

/// Roda o escalonador até `done` (com limite de tempo).
fn pump(milliseconds: u64, done: &dyn Fn() -> bool) -> bool {
    let deadline = clock::uptime_ms() + milliseconds;
    while clock::uptime_ms() < deadline {
        if done() {
            return true;
        }
        scheduler::tick(-1);
    }
    done()
}

/// O estado da KTHREAD parada antes do sinal.
#[derive(Clone, Copy)]
struct Before {
    base: i8,
    priority: i8,
    decrement: u8,
    disable_boost: bool,
    /// ms desde o começo da espera (WaitTime).
    waited: u32,
    quantum_spent: bool,
    foreground: bool,
}

/// Como a thread entrou na fila.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct After {
    priority: i8,
    decrement: u8,
    /// O QuantumTarget foi renovado (CycleTime + QuantumReset unidades).
    quantum_renewed: bool,
}

/// O sinal do caso.
#[derive(Clone, Copy)]
enum Signal {
    SetEvent(i8),
    Alert,
}

/// Um caso: espera a thread parada, grava `before`, sinaliza e devolve o
/// que ela levou para a fila (`None` se ela não parou ou não ficou Ready).
fn case(thread: u64, block: u64, before: Before, signal: Signal) -> Option<After> {
    if !parked(thread, block) {
        return None;
    }
    let target = kthread(thread);
    // SAFETY: o processo dono de uma thread viva (o System).
    let process = unsafe { Eprocess::at(target.process.get()) };
    let saved_memory_priority = process.vm.instance.flags.memory_priority.get();
    target.base_priority.set(before.base);
    target.priority.set(before.priority);
    target.priority_decrement.set(before.decrement as i8);
    target.set_disable_boost(before.disable_boost as u32);
    let cycles = target.cycle_time.get();
    let quantum_target = if before.quantum_spent { cycles } else { cycles + (1u64 << 40) };
    target.quantum_target.set(quantum_target);
    target.wait_time.set(thread_dispatch::tick_count().wrapping_sub(before.waited));
    process.vm.instance.flags.memory_priority.set(if before.foreground { 2 } else { 0 });
    match signal {
        Signal::SetEvent(increment) => {
            call_export("KeSetEvent", &[block, increment as u8 as u64, 0]);
        }
        Signal::Alert => {
            call_export("KeAlertThread", &[thread, 0]);
        }
    }
    SIGNALED.fetch_add(1, Ordering::SeqCst);
    process.vm.instance.flags.memory_priority.set(saved_memory_priority);
    target.set_disable_boost(0);
    if thread_dispatch::thread_state(thread) != thread_dispatch::state::READY {
        return None;
    }
    let renewed = cycles.wrapping_add(target.quantum_reset.get() as u64 * thread_dispatch::cycles_per_quantum() as u64);
    Some(After { priority: target.priority.get(), decrement: target.priority_decrement.get() as u8, quantum_renewed: target.quantum_target.get() == renewed && quantum_target != renewed })
}

/// A thread completou a volta de cada sinal e parou de novo no evento.
fn parked(thread: u64, block: u64) -> bool {
    pump(5_000, &|| wait::is_waiting(thread) && thread_dispatch::thread_state(thread) == thread_dispatch::state::WAITING && guest::read64(block + ROUNDS) == SIGNALED.load(Ordering::SeqCst))
}

fn short(base: i8, priority: i8) -> Before {
    Before { base, priority, decrement: 0, disable_boost: false, waited: 0, quantum_spent: false, foreground: false }
}

pub fn run(assert: Assert) {
    let block = guest::alloc_bytes(0x40);
    if block == 0 {
        assert(false, "impulso: bloco da thread");
        return;
    }
    guest::write_bytes(block, &[0; 0x40]);
    dispatcher::initialize_event(block, 1, false);
    SIGNALED.store(0, Ordering::SeqCst);
    let handle = kernel_threads::create_system_thread(0, waiter as *const () as usize as u64, block, 0x1F_FFFF, 0, None).unwrap_or(0);
    let thread = kernel_threads::of_handle(handle).unwrap_or(0);
    if thread == 0 {
        assert(false, "impulso: thread de sistema criada");
        return;
    }
    let (original_base, original_priority) = (kthread(thread).base_priority.get(), kthread(thread).priority.get());
    let separation = crate::ntos::ps::quantum::priority_separation() as i8;
    let none = |priority: i8| Some(After { priority, decrement: 0, quantum_renewed: false });

    let plain = case(thread, block, short(8, 8), Signal::SetEvent(1));
    assert(plain == none(9), "impulso: o KeSetEvent com Increment 1 tira da espera curta uma thread de base 8 com prioridade 9 (Base + Increment), sem ForegroundBoost e sem renovar o quantum");
    let zero = case(thread, block, short(8, 8), Signal::SetEvent(0));
    assert(zero == none(8), "impulso: com Increment 0 (o vencimento de um timer, os sinais internos) a prioridade fica na base");
    let foreground = case(thread, block, Before { foreground: true, ..short(8, 8) }, Signal::SetEvent(1));
    assert(
        foreground == Some(After { priority: 8 + 1 + separation, decrement: separation as u8, quantum_renewed: false }),
        "impulso: no processo de primeiro plano (MemoryPriority 2) soma o PsPrioritySeparation, que fica no ForegroundBoost (PriorityDecrement bits 0..3)",
    );
    let capped = case(thread, block, short(12, 12), Signal::SetEvent(6));
    assert(capped == none(15), "impulso: Base + Increment acima de 15 para em 15");
    let high_base = case(thread, block, short(14, 14), Signal::SetEvent(1));
    assert(high_base == Some(After { priority: 15, decrement: 0, quantum_renewed: true }), "impulso: com a base em 14 a prioridade decai e o impulso a leva a 15, com o quantum renovado");
    let realtime = case(thread, block, short(16, 16), Signal::SetEvent(1));
    assert(realtime == none(16), "impulso: uma thread de tempo real (16) nao muda");
    let disabled = case(thread, block, Before { disable_boost: true, ..short(8, 8) }, Signal::SetEvent(1));
    assert(disabled == none(8), "impulso: com DisableBoost a prioridade fica");
    let long_wait = case(thread, block, Before { waited: 100, ..short(8, 10) }, Signal::SetEvent(1));
    assert(long_wait == Some(After { priority: 9, decrement: 0, quantum_renewed: true }), "impulso: depois de uma espera de dois ticks ou mais sem impulso em curso a prioridade 10 decai um ponto (9 = Base + Increment), com o quantum renovado");
    let spent = case(thread, block, Before { quantum_spent: true, ..short(8, 10) }, Signal::SetEvent(1));
    assert(spent == Some(After { priority: 9, decrement: 0, quantum_renewed: true }), "impulso: com o quantum gasto numa espera curta a prioridade decai um ponto sem impulso, com o quantum renovado");
    let unusual = case(thread, block, Before { decrement: 0x40, ..short(8, 12) }, Signal::SetEvent(1));
    assert(unusual == Some(After { priority: 12, decrement: 0x40, quantum_renewed: false }), "impulso: com um impulso incomum em curso (PriorityDecrement bits 4..7) nada muda");
    let alerted = case(thread, block, short(8, 8), Signal::Alert);
    assert(alerted == none(10) && pump(5_000, &|| guest::read64(block + STATUS) == wait::STATUS_ALERTED as u64), "impulso: o KeAlertThread tira a espera alertavel com STATUS_ALERTED e o incremento 2");
    crate::debug_print!(
        "[impulso] {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        plain,
        zero,
        foreground,
        capped,
        high_base,
        realtime,
        disabled,
        long_wait,
        spent,
        unusual,
        alerted
    );

    // A thread volta à prioridade de antes e sai.
    let parked = parked(thread, block);
    if parked {
        kthread(thread).base_priority.set(original_base);
        kthread(thread).priority.set(original_priority);
        kthread(thread).priority_decrement.set(0);
    }
    guest::write64(block + STOP, 1);
    dispatcher::set_event(block);
    let finished = pump(5_000, &|| kernel_threads::is_terminated(thread));
    assert(parked && finished, "impulso: a thread de sistema sai no fim");
    let _ = object_manager::close(handle as u32);
    guest::free_bytes(block);
}
