//! KeRemoveQueue bloqueia como as outras esperas do kernel (`ke/queue.rs`):
//! dentro de uma syscall a thread sai da fila de prontas e deixa a CPU até
//! a entrada chegar, o prazo vencer ou um alerta a interromper.
//!
//! Duas threads de usuário de um processo real, no despachante de verdade. A
//! 1 faz uma syscall de teste (tabela 1 do Shadow, threads GUI) cujo serviço
//! chama KeRemoveQueue numa KQUEUE; a 2 só fica pronta quando a 1 já está
//! nesse serviço. Três cenários:
//!
//! - inserção (prazo de 10 s): a 2 vê a 1 bloqueada no kernel (KTHREAD em
//!   Waiting, quadro salvo na pilha dela), gira 50 ms sem que o CycleTime da
//!   1 mude e insere uma entrada; a 1 volta com a entrada, bem antes do
//!   prazo, tendo gastado menos da metade do tempo da espera em ciclos;
//! - prazo (100 ms, ninguém insere): a 2 roda com a 1 bloqueada, e a 1 volta
//!   com STATUS_TIMEOUT depois de 100 ms, de novo sem gastar a espera em
//!   ciclos, e com a vaga da fila de volta;
//! - alerta (KeRemoveQueueEx alertável em UserMode, prazo de 10 s): a 2
//!   chama NtAlertThread na 1, que volta com STATUS_ALERTED e a vaga de
//!   volta.
//!
//! No código que girava o pump dentro do serviço, a 2 nunca roda durante a
//! espera: a inserção não chega (a 1 só sai com STATUS_TIMEOUT depois de
//! 10 s), a 2 não vê a 1 bloqueada, a espera gasta todo o tempo em ciclos e
//! o alerta não chega.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::blocking_wait::{self, EXIT_SERVICE, KTHREAD_WAITING};
use super::identity::with_test_process;
use crate::hal::amd64::usermode;
use crate::ntos::ex::service_table;
use crate::ntos::inc::types::{Kqueue, Kthread, LargeInteger, ListEntry, NtStruct};
use crate::ntos::ke::{clock, queue, thread_dispatch};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ps::user::threads::{self, KernelState, UserThread};
use crate::ntos::ps::user::{memory, state};
use crate::ntos::ps::process;
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

/// Os serviços de teste: índices 0-2 da tabela 1 (o 2 é a saída).
const WAIT_SERVICE: u32 = 0x1000;
const PARTNER_SERVICE: u32 = 0x1001;
const UNSET: u64 = u64::MAX;
const STATUS_TIMEOUT: u64 = 0x102;
const STATUS_ALERTED: u64 = 0x101;
/// THREAD_ALERT.
const THREAD_ALERT: u32 = 0x0004;
/// Quanto a parceira gira, no cenário da inserção, antes de inserir.
const PARTNER_SPIN_MS: u64 = 50;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Insert,
    Timeout,
    Alert,
}

static SERVICE_TABLE: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static SERVICE_ARGUMENTS: [AtomicU8; 3] = [const { AtomicU8::new(0) }; 3];

static SCENARIO: AtomicU8 = AtomicU8::new(0);
static QUEUE: AtomicU64 = AtomicU64::new(0);
static ENTRY: AtomicU64 = AtomicU64::new(0);
static TIMEOUT: AtomicU64 = AtomicU64::new(0);
static WAITER: AtomicU64 = AtomicU64::new(0);
static PARTNER: SpinLock<Option<Arc<UserThread>>> = SpinLock::new(None);
/// Handle (no processo de teste) da thread que o alerta interrompe.
static TARGET: AtomicU64 = AtomicU64::new(0);
/// O que os serviços observaram.
static RESULT: AtomicU64 = AtomicU64::new(UNSET);
static ELAPSED_MS: AtomicU64 = AtomicU64::new(0);
static WAIT_CYCLES: AtomicU64 = AtomicU64::new(0);
static SLOT_RESTORED: AtomicBool = AtomicBool::new(false);
static SAW_BLOCKED: AtomicBool = AtomicBool::new(false);
static IDLE_WHILE_BLOCKED: AtomicBool = AtomicBool::new(false);
static PARTNER_STATUS: AtomicU64 = AtomicU64::new(UNSET);

fn scenario() -> Scenario {
    match SCENARIO.load(Ordering::SeqCst) {
        0 => Scenario::Insert,
        1 => Scenario::Timeout,
        _ => Scenario::Alert,
    }
}

fn kthread(pointer: u64) -> &'static Kthread {
    // SAFETY: KTHREAD viva, criada e retida pelo teste.
    unsafe { Kthread::at(pointer) }
}

fn kqueue() -> &'static Kqueue {
    // SAFETY: a KQUEUE do cenário, alocada pelo teste e viva até o fim dele.
    unsafe { Kqueue::at(QUEUE.load(Ordering::SeqCst)) }
}

/// A 1 está bloqueada no kernel: espera pendente, KTHREAD em Waiting e o
/// quadro de troca salvo em KernelStack, dentro da pilha dela.
fn waiter_blocked() -> bool {
    let waiter = WAITER.load(Ordering::SeqCst);
    let blocked = threads::find_by_pointer(waiter).is_some_and(|thread| thread.kernel_state() == KernelState::Blocked { status: None });
    let tcb = kthread(waiter);
    let saved = tcb.kernel_stack.get();
    blocked && tcb.state.get() == KTHREAD_WAITING && saved > tcb.stack_limit.get() && saved < tcb.initial_stack.get() && RESULT.load(Ordering::SeqCst) == UNSET
}

/// KeRemoveQueue (KeRemoveQueueEx alertável em UserMode no cenário do
/// alerta). Só depois de entrar aqui a parceira fica pronta.
extern "win64" fn wait_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let partner = PARTNER.lock().take();
    if let Some(partner) = partner {
        partner.with(|thread| thread.suspend_count = 0);
    }
    let thread = process::get_current_thread();
    let (cycles_before, started) = (thread_dispatch::sample_cycles(thread), clock::uptime_ms());
    let alert = scenario() == Scenario::Alert;
    let entries = queue::remove_entries(kqueue(), TIMEOUT.load(Ordering::SeqCst), 1, alert as u8, alert);
    let (cycles_after, finished) = (thread_dispatch::sample_cycles(thread), clock::uptime_ms());
    let result = entries.ok().and_then(|entries| entries.first().copied()).unwrap_or(0);
    ELAPSED_MS.store(finished - started, Ordering::SeqCst);
    WAIT_CYCLES.store(cycles_after.wrapping_sub(cycles_before), Ordering::SeqCst);
    SLOT_RESTORED.store(kqueue().current_count.get() == 1, Ordering::SeqCst);
    RESULT.store(result, Ordering::SeqCst);
    // A thread não sai associada a uma fila que o teste vai liberar.
    queue::rundown(kqueue());
    0
}

/// Confere a 1 bloqueada e, conforme o cenário, gira e insere, só observa
/// ou alerta.
extern "win64" fn partner_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    SAW_BLOCKED.store(waiter_blocked(), Ordering::SeqCst);
    let status = match scenario() {
        Scenario::Insert => {
            let waiter = kthread(WAITER.load(Ordering::SeqCst));
            let before = waiter.cycle_time.get();
            clock::spin_ms(PARTNER_SPIN_MS);
            IDLE_WHILE_BLOCKED.store(waiter_blocked() && waiter.cycle_time.get() == before, Ordering::SeqCst);
            // SAFETY: a LIST_ENTRY do cenário, alocada pelo teste.
            queue::insert_entry(kqueue(), unsafe { ListEntry::at(ENTRY.load(Ordering::SeqCst)) }, false) as u64
        }
        Scenario::Timeout => 0,
        Scenario::Alert => state::handler("NtAlertThread").map_or(0xC000_0001, |handler| handler(TARGET.load(Ordering::SeqCst), 0, 0, 0, 0).unwrap_or(0xC000_0001)) as u64,
    };
    PARTNER_STATUS.store(status, Ordering::SeqCst);
    0
}

/// O que um cenário observou.
struct Outcome {
    ran: bool,
    result: u64,
    elapsed_ms: u64,
    wait_cycles: u64,
    slot_restored: bool,
    saw_blocked: bool,
    idle_while_blocked: bool,
    partner_status: u64,
    dead: bool,
}

fn run_scenario(which: Scenario, timeout_100ns: i64) -> Option<Outcome> {
    with_test_process("fila-espera.exe", None, |test| {
        let (code, stacks) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x8000, 4));
        let block = guest::alloc_bytes(0x100);
        let waiter = blocking_wait::user_thread(test.process, code);
        let partner = blocking_wait::user_thread(test.process, code + 0x100);
        let mut outcome = Outcome { ran: false, result: UNSET, elapsed_ms: 0, wait_cycles: 0, slot_restored: false, saw_blocked: false, idle_while_blocked: false, partner_status: UNSET, dead: false };
        let mut handle = 0;
        if let (Some(waiter), Some(partner), true) = (waiter.as_ref(), partner.as_ref(), block != 0 && code != 0 && stacks != 0) {
            guest::write_bytes(code, &blocking_wait::program(WAIT_SERVICE, 0, true));
            guest::write_bytes(code + 0x100, &blocking_wait::program(PARTNER_SERVICE, 0x100, false));
            let (queue_address, entry, timeout) = (block, block + 0x80, block + 0xC0);
            // SAFETY: a KQUEUE do cenário, recém-alocada.
            queue::initialize(unsafe { Kqueue::at(queue_address) }, 1);
            // SAFETY: o LARGE_INTEGER do prazo, recém-alocado.
            unsafe { LargeInteger::at(timeout) }.quad_part.set(timeout_100ns);
            SCENARIO.store(which as u8, Ordering::SeqCst);
            QUEUE.store(queue_address, Ordering::SeqCst);
            ENTRY.store(entry, Ordering::SeqCst);
            TIMEOUT.store(timeout, Ordering::SeqCst);
            WAITER.store(waiter.pointer(), Ordering::SeqCst);
            for cell in [&RESULT, &PARTNER_STATUS] {
                cell.store(UNSET, Ordering::SeqCst);
            }
            for flag in [&SLOT_RESTORED, &SAW_BLOCKED, &IDLE_WHILE_BLOCKED] {
                flag.store(false, Ordering::SeqCst);
            }
            if which == Scenario::Alert {
                handle = threads::thread_handle(waiter, THREAD_ALERT, 0).unwrap_or(0);
                TARGET.store(handle, Ordering::SeqCst);
            }
            if blocking_wait::prepare_partner(partner, code + 0x100, stacks + 0x8000 - 0x28) && (handle != 0 || which != Scenario::Alert) {
                *PARTNER.lock() = Some(partner.clone());
                outcome.ran = threads::run(waiter, code, stacks + 0x4000 - 0x28, 0, 0).is_ok();
            }
            outcome.result = RESULT.load(Ordering::SeqCst);
            outcome.elapsed_ms = ELAPSED_MS.load(Ordering::SeqCst);
            outcome.wait_cycles = WAIT_CYCLES.load(Ordering::SeqCst);
            outcome.slot_restored = SLOT_RESTORED.load(Ordering::SeqCst);
            outcome.saw_blocked = SAW_BLOCKED.load(Ordering::SeqCst);
            outcome.idle_while_blocked = IDLE_WHILE_BLOCKED.load(Ordering::SeqCst);
            outcome.partner_status = PARTNER_STATUS.load(Ordering::SeqCst);
            outcome.dead = waiter.dead() && partner.dead() && !waiter.blocked_in_kernel() && !partner.blocked_in_kernel();
            if handle != 0 {
                let _ = state::close_user_handle(handle, true, false);
            }
            *PARTNER.lock() = None;
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        if block != 0 {
            guest::free_bytes(block);
        }
        for base in [code, stacks] {
            if let Some(region) = memory::find_region(base).filter(|_| base != 0) {
                memory::release_private_region(&region);
            }
        }
        outcome
    })
}

/// A espera não gastou o tempo dela em ciclos de CPU: menos da metade dos
/// ciclos transcorridos entre a entrada e a saída do KeRemoveQueue.
fn cheap(outcome: &Outcome) -> bool {
    let elapsed_cycles = outcome.elapsed_ms * (clock::tsc_frequency_hz() / 1000);
    outcome.wait_cycles.saturating_mul(2) < elapsed_cycles
}

pub fn run(assert: Assert) {
    if !usermode::ready() {
        assert(false, "fila: anel 3 armado");
        return;
    }
    if threads::all().iter().any(|thread| !thread.dead()) {
        assert(false, "fila: nenhuma thread de usuario de outro teste viva");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "fila: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; 3] = [wait_service, partner_service, blocking_wait::exit_service];
    let mut encoded = true;
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => encoded = false,
        }
    }
    if !encoded || EXIT_SERVICE != 0x1002 || service_table::publish_shadow_second_table(table, 3, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
        assert(false, "fila: tabela 1 de teste");
        let _ = service_table::restore_shadow_second_table(saved_shadow);
        return;
    }

    // Prazo de 100 ms (relativo, em unidades de 100 ns) sem inserção.
    let timed = run_scenario(Scenario::Timeout, -1_000_000);
    let ok = timed.as_ref().is_some_and(|outcome| outcome.ran && outcome.dead);
    assert(ok, "fila: cenario do prazo com as duas threads no despachante");
    if let Some(outcome) = timed.filter(|_| ok) {
        assert(outcome.saw_blocked, "fila: com KeRemoveQueue esperando, a outra thread roda e a ve bloqueada no kernel");
        assert(outcome.result == STATUS_TIMEOUT && outcome.elapsed_ms >= 100 && outcome.slot_restored, "fila: o prazo de 100 ms devolve STATUS_TIMEOUT e a vaga volta");
        assert(cheap(&outcome), "fila: a espera ate o prazo nao gasta o tempo dela em ciclos de CPU");
    }

    // Inserção depois de 50 ms, prazo de 10 s.
    let inserted = run_scenario(Scenario::Insert, -100_000_000);
    let ok = inserted.as_ref().is_some_and(|outcome| outcome.ran && outcome.dead);
    assert(ok, "fila: cenario da insercao com as duas threads no despachante");
    if let Some(outcome) = inserted.filter(|_| ok) {
        assert(outcome.saw_blocked && outcome.idle_while_blocked, "fila: a thread bloqueada fica parada (CycleTime constante) enquanto a outra gira 50 ms");
        assert(outcome.result == ENTRY.load(Ordering::SeqCst) && outcome.partner_status == 0 && outcome.elapsed_ms >= PARTNER_SPIN_MS && outcome.elapsed_ms < 5_000, "fila: KeInsertQueue acorda a thread com a entrada, bem antes do prazo");
        assert(cheap(&outcome), "fila: a espera ate a insercao nao gasta o tempo dela em ciclos de CPU");
    }

    // KeRemoveQueueEx alertável em UserMode, interrompido por NtAlertThread.
    let alerted = run_scenario(Scenario::Alert, -100_000_000);
    let ok = alerted.as_ref().is_some_and(|outcome| outcome.ran && outcome.dead);
    assert(ok, "fila: cenario do alerta com as duas threads no despachante");
    if let Some(outcome) = alerted.filter(|_| ok) {
        assert(outcome.saw_blocked && outcome.partner_status == 0, "fila: NtAlertThread na thread bloqueada no KeRemoveQueueEx alertavel");
        assert(outcome.result == STATUS_ALERTED && outcome.elapsed_ms < 5_000 && outcome.slot_restored, "fila: o alerta interrompe a espera com STATUS_ALERTED e a vaga volta");
    }

    let _ = service_table::restore_shadow_second_table(saved_shadow);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
}
