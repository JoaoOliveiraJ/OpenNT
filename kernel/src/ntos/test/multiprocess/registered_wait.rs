//! As esperas de serviço das threads de usuário registradas no despachante
//! (`ps/user/threads::Registered`, `ke::wait`), como no 19041: o
//! NtWaitForSingleObject liga os KWAIT_BLOCKs da KTHREAD ao objeto, e o
//! sinal apronta a thread dentro dele (o KiUnwaitThread -> KiReadyThread,
//! 0x247fb0), sem sondagem.
//!
//! Uma thread de usuário de um processo real repete um serviço de espera
//! (tabela 1 do Shadow) e, depois de cada um, um serviço que registra o
//! status que voltou ao anel 3. Por fases:
//!
//! - a espera adiada num evento de notificação (o `threads::wait_objects`):
//!   a cada sinal-e-limpa do teste a thread já está pronta logo depois do
//!   KeSetEvent, antes de qualquer volta do despachante, e a espera conclui
//!   com 0; nenhuma espera é sondada (`dispatch_perf::POLLS`), e o anel 3
//!   nunca vê STATUS_PENDING;
//! - o mesmo pelo KeWaitForSingleObject dentro do serviço: a thread bloqueia
//!   no kernel com a espera registrada, e o sinal a apronta e retoma o
//!   serviço;
//! - suspensa na espera, o sinal não a roda; a retomada conclui a espera;
//! - o NtWaitForAlertByThreadId: o NtAlertThreadByThreadId do teste a
//!   apronta na hora e ela volta com STATUS_ALERTED;
//! - o NtDelayExecution de 20 ms: só o timer da thread, STATUS_SUCCESS depois
//!   do prazo;
//! - o fim do processo com a thread parada na espera: nenhum bloco fica na
//!   WaitListHead do evento.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::blocking_wait::{self, EXIT_SERVICE};
use super::identity::with_test_process;
use crate::hal::amd64::usermode;
use crate::ntos::ex::service_table;
use crate::ntos::inc::types::{DispatcherHeader, Kthread, NtStruct};
use crate::ntos::ke::{clock, dispatcher, thread_dispatch};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ps::dispatch_perf;
use crate::ntos::ps::scheduler;
use crate::ntos::ps::user::{memory, state, threads};

type Assert = fn(bool, &str);

/// Os serviços de teste: 0 espera (pela fase), 1 registra o status, 2 é a
/// saída.
const WAIT_SERVICE: u32 = 0x1000;
const RECORD_SERVICE: u32 = 0x1001;
const SERVICES: usize = 3;
/// As esperas por sinal-e-limpa e por alerta.
const PAIRS: u64 = 40;
const ALERTS: u64 = 10;
const DELAYS: u64 = 3;
const DELAY_MS: u64 = 20;
const UNSET: u64 = u64::MAX;
/// O KTHREAD.ThreadCounters da thread durante as esperas: o SparePtr do
/// WaitBlock[0] embutido, na mesma memória.
const OVERLAY_SENTINEL: u64 = 0x5EED_0B1E_C7ED_0001;

/// A fase: a espera que o serviço 0 faz.
const MODE_EVENT: u32 = 0;
const MODE_ALERT: u32 = 1;
const MODE_DELAY: u32 = 2;
const MODE_KERNEL: u32 = 3;
/// As esperas de kernel (KeWaitForSingleObject dentro do serviço).
const KERNEL_PAIRS: u64 = 10;

static SERVICE_TABLE: [AtomicU32; SERVICES] = [const { AtomicU32::new(0) }; SERVICES];
static SERVICE_ARGUMENTS: [AtomicU8; SERVICES] = [const { AtomicU8::new(0) }; SERVICES];

static MODE: AtomicU32 = AtomicU32::new(MODE_EVENT);
/// O evento (memória do kernel) e o LARGE_INTEGER do atraso (memória de
/// usuário).
static EVENT: AtomicU64 = AtomicU64::new(0);
static INTERVAL: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static RECORDS: AtomicU64 = AtomicU64::new(0);
static LAST_STATUS: AtomicU64 = AtomicU64::new(UNSET);
static PENDING_SEEN: AtomicBool = AtomicBool::new(false);
/// Uptime (ms) da entrada no último serviço de espera, e quanto a última
/// espera durou até o anel 3 registrar o status.
static WAIT_STARTED: AtomicU64 = AtomicU64::new(0);
static LAST_WAITED: AtomicU64 = AtomicU64::new(0);

/// A espera da fase corrente, de dentro do serviço (a thread corrente é a
/// de usuário).
extern "win64" fn wait_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    if STOP.load(Ordering::SeqCst) {
        return 0;
    }
    WAIT_STARTED.store(clock::uptime_ms(), Ordering::SeqCst);
    let call = |name: &str, a: u64, b: u64| state::handler(name).map_or(0xC000_0001, |handler| handler(a, b, 0, 0, 0).unwrap_or(0xC000_0001)) as u64;
    match MODE.load(Ordering::SeqCst) {
        MODE_ALERT => call("NtWaitForAlertByThreadId", 0, 0),
        MODE_DELAY => call("NtDelayExecution", 0, INTERVAL.load(Ordering::SeqCst)),
        // O KeWaitForSingleObject de KernelMode, sem prazo, no serviço: a
        // thread bloqueia no kernel com a espera registrada.
        MODE_KERNEL => dispatcher::wait_for_single_object(EVENT.load(Ordering::SeqCst), 0, 0, false) as u64,
        _ => threads::wait_objects(Vec::new(), alloc::vec![EVENT.load(Ordering::SeqCst)], 1, 0, false) as u64,
    }
}

/// O status que a espera devolveu ao anel 3: 0 segue o laço, 1 o encerra.
extern "win64" fn record_service(status: u64, _: u64, _: u64, _: u64) -> u64 {
    let status = status & 0xFFFF_FFFF;
    if status == 0x103 {
        PENDING_SEEN.store(true, Ordering::SeqCst);
    }
    LAST_STATUS.store(status, Ordering::SeqCst);
    LAST_WAITED.store(clock::uptime_ms().saturating_sub(WAIT_STARTED.load(Ordering::SeqCst)), Ordering::SeqCst);
    RECORDS.fetch_add(1, Ordering::SeqCst);
    STOP.load(Ordering::SeqCst) as u64
}

/// `laço: espera; mov ecx, eax; registra(ecx); test eax, eax; jz laço`, a
/// syscall de saída e `jmp $`.
fn looping_program() -> Vec<u8> {
    let syscall = |program: &mut Vec<u8>, number: u32| {
        program.push(0xB8);
        program.extend_from_slice(&number.to_le_bytes());
        program.extend_from_slice(&[0x49, 0x89, 0xCA, 0x0F, 0x05]);
    };
    let mut program = Vec::new();
    syscall(&mut program, WAIT_SERVICE);
    program.extend_from_slice(&[0x89, 0xC1]);
    syscall(&mut program, RECORD_SERVICE);
    program.extend_from_slice(&[0x85, 0xC0, 0x74]);
    program.push((-(program.len() as i8) - 1) as u8);
    syscall(&mut program, EXIT_SERVICE);
    program.extend_from_slice(&[0xEB, 0xFE]);
    program
}

#[derive(Debug, Default)]
struct Outcome {
    started: bool,
    pairs: u64,
    ready_on_signal: u64,
    zero_statuses: u64,
    polls: u64,
    overlay_kept: bool,
    kernel_pairs: u64,
    kernel_ready: u64,
    kernel_zero: u64,
    held_while_suspended: bool,
    resumed_status: u64,
    alerts: u64,
    alerted_ready: u64,
    alert_statuses: u64,
    delays: u64,
    delays_on_time: u64,
    exited: bool,
    list_empty: bool,
}

/// Gira o despachante até `done` valer ou passar `limit_ms`.
fn tick_until(limit_ms: u64, done: impl Fn() -> bool) -> bool {
    let deadline = clock::uptime_ms() + limit_ms;
    while !done() && clock::uptime_ms() < deadline {
        scheduler::tick(-1);
    }
    done()
}

/// A thread está parada na espera, confirmada (Waiting, fora da CPU), e o
/// anel 3 já registrou `records` esperas.
fn parked(waiter: &threads::UserThread, records: u64) -> bool {
    waiter.waiting() && RECORDS.load(Ordering::SeqCst) == records && thread_dispatch::thread_state(waiter.pointer()) == thread_dispatch::state::WAITING
}

fn run_phases() -> Option<Outcome> {
    with_test_process("espera-registrada.exe", None, |test| {
        let (code, stacks, data) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x8000, 4), blocking_wait::allocate(0x1000, 4));
        let event = guest::alloc_bytes(0x40);
        let mut outcome = Outcome::default();
        let waiter = blocking_wait::user_thread(test.process, code);
        if let (Some(waiter), true) = (waiter.as_ref(), event != 0 && code != 0 && stacks != 0 && data != 0) {
            guest::write_bytes(code, &looping_program());
            guest::write_bytes(event, &[0; 0x40]);
            dispatcher::initialize_event(event, 0, false);
            guest::write64(data, (-((DELAY_MS * 10_000) as i64)) as u64);
            EVENT.store(event, Ordering::SeqCst);
            INTERVAL.store(data, Ordering::SeqCst);
            MODE.store(MODE_EVENT, Ordering::SeqCst);
            STOP.store(false, Ordering::SeqCst);
            RECORDS.store(0, Ordering::SeqCst);
            LAST_STATUS.store(UNSET, Ordering::SeqCst);
            PENDING_SEEN.store(false, Ordering::SeqCst);
            let pointer = waiter.pointer();
            if threads::start(waiter, code, stacks + 0x8000 - 0x28, 0, 0).is_ok() {
                outcome.started = true;
                // Fase 1: sinal-e-limpa, a thread pronta pelo próprio sinal.
                // O registro grava só os campos do KWAIT_BLOCK: o
                // ThreadCounters, sobreposto ao WaitBlock[0], fica intacto.
                // SAFETY: a KTHREAD da thread de teste, viva durante a fase.
                let tcb = unsafe { Kthread::at(pointer) };
                tcb.thread_counters.set(OVERLAY_SENTINEL);
                let polls = dispatch_perf::POLLS.load(Ordering::SeqCst);
                while outcome.pairs < PAIRS && !PENDING_SEEN.load(Ordering::SeqCst) {
                    let records = outcome.pairs;
                    if !tick_until(2_000, || parked(waiter, records)) {
                        break;
                    }
                    if outcome.pairs + 1 == PAIRS {
                        MODE.store(MODE_KERNEL, Ordering::SeqCst);
                    }
                    dispatcher::set_event(event);
                    if thread_dispatch::thread_state(pointer) == thread_dispatch::state::READY {
                        outcome.ready_on_signal += 1;
                    }
                    dispatcher::reset_event(event);
                    outcome.pairs += 1;
                    if !tick_until(2_000, || RECORDS.load(Ordering::SeqCst) == records + 1) {
                        break;
                    }
                    if LAST_STATUS.load(Ordering::SeqCst) == 0 {
                        outcome.zero_statuses += 1;
                    }
                }
                // Fase 1b: o mesmo pelo KeWaitForSingleObject, com o serviço
                // bloqueado no kernel.
                while outcome.kernel_pairs < KERNEL_PAIRS && outcome.pairs == PAIRS {
                    let records = PAIRS + outcome.kernel_pairs;
                    if !tick_until(2_000, || parked(waiter, records) && waiter.blocked_in_kernel()) {
                        break;
                    }
                    if outcome.kernel_pairs + 1 == KERNEL_PAIRS {
                        MODE.store(MODE_EVENT, Ordering::SeqCst);
                    }
                    dispatcher::set_event(event);
                    if thread_dispatch::thread_state(pointer) == thread_dispatch::state::READY {
                        outcome.kernel_ready += 1;
                    }
                    dispatcher::reset_event(event);
                    outcome.kernel_pairs += 1;
                    if !tick_until(2_000, || RECORDS.load(Ordering::SeqCst) == records + 1) {
                        break;
                    }
                    if LAST_STATUS.load(Ordering::SeqCst) == 0 {
                        outcome.kernel_zero += 1;
                    }
                }
                outcome.polls = dispatch_perf::POLLS.load(Ordering::SeqCst) - polls;
                outcome.overlay_kept = tcb.thread_counters.get() == OVERLAY_SENTINEL;
                tcb.thread_counters.set(0);
                // Fase 2: suspensa na espera, o sinal não a roda.
                let records = RECORDS.load(Ordering::SeqCst);
                if tick_until(2_000, || parked(waiter, records)) {
                    threads::suspend_thread(pointer);
                    dispatcher::set_event(event);
                    for _ in 0..10 {
                        scheduler::tick(-1);
                    }
                    outcome.held_while_suspended = RECORDS.load(Ordering::SeqCst) == records;
                    MODE.store(MODE_ALERT, Ordering::SeqCst);
                    threads::resume_thread(pointer);
                    if tick_until(2_000, || RECORDS.load(Ordering::SeqCst) == records + 1) {
                        outcome.resumed_status = LAST_STATUS.load(Ordering::SeqCst);
                    }
                    dispatcher::reset_event(event);
                }
                // Fase 3: o NtWaitForAlertByThreadId acordado pelo alerta.
                let alert = state::handler("NtAlertThreadByThreadId");
                while outcome.alerts < ALERTS {
                    let records = RECORDS.load(Ordering::SeqCst);
                    if outcome.alerts + 1 == ALERTS {
                        MODE.store(MODE_DELAY, Ordering::SeqCst);
                    }
                    if !tick_until(2_000, || parked(waiter, records)) {
                        break;
                    }
                    let _ = alert.map(|handler| handler(waiter.thread_id, 0, 0, 0, 0));
                    if thread_dispatch::thread_state(pointer) == thread_dispatch::state::READY {
                        outcome.alerted_ready += 1;
                    }
                    outcome.alerts += 1;
                    if !tick_until(2_000, || RECORDS.load(Ordering::SeqCst) == records + 1) {
                        break;
                    }
                    if LAST_STATUS.load(Ordering::SeqCst) == 0x101 {
                        outcome.alert_statuses += 1;
                    }
                }
                // Fase 4: o atraso de 20 ms.
                while outcome.delays < DELAYS {
                    let records = RECORDS.load(Ordering::SeqCst);
                    if outcome.delays + 1 == DELAYS {
                        MODE.store(MODE_EVENT, Ordering::SeqCst);
                    }
                    if !tick_until(2_000, || RECORDS.load(Ordering::SeqCst) == records + 1) {
                        break;
                    }
                    outcome.delays += 1;
                    if LAST_STATUS.load(Ordering::SeqCst) == 0 && LAST_WAITED.load(Ordering::SeqCst) >= DELAY_MS {
                        outcome.delays_on_time += 1;
                    }
                }
                // Fase 5: o fim do processo com a thread parada no evento.
                let records = RECORDS.load(Ordering::SeqCst);
                if tick_until(2_000, || parked(waiter, records)) {
                    crate::ntos::ps::create::exit_process(test.process, 0x55);
                    outcome.exited = threads::wait_for_process(test.process).is_ok();
                    // SAFETY: o KEVENT do teste, vivo até o fim da fase.
                    let head = &unsafe { DispatcherHeader::at(event) }.wait_list_head;
                    outcome.list_empty = head.flink.get() == head.address() && head.blink.get() == head.address();
                }
            }
            STOP.store(true, Ordering::SeqCst);
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        EVENT.store(0, Ordering::SeqCst);
        if event != 0 {
            guest::free_bytes(event);
        }
        for base in [code, stacks, data] {
            if let Some(region) = memory::find_region(base).filter(|_| base != 0) {
                memory::release_private_region(&region);
            }
        }
        outcome
    })
}

pub fn run(assert: Assert) {
    if !usermode::ready() {
        assert(false, "espera-registrada: anel 3 armado");
        return;
    }
    if threads::all().iter().any(|thread| !thread.dead()) {
        assert(false, "espera-registrada: nenhuma thread de usuario de outro teste viva");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "espera-registrada: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; SERVICES] = [wait_service, record_service, blocking_wait::exit_service];
    let mut encoded = true;
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => encoded = false,
        }
    }
    if !encoded || EXIT_SERVICE != 0x1002 || service_table::publish_shadow_second_table(table, SERVICES as u32, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
        assert(false, "espera-registrada: tabela 1 de teste");
        let _ = service_table::restore_shadow_second_table(saved_shadow);
        return;
    }
    let outcome = run_phases();
    crate::debug_print!("[espera-registrada] {:?}", outcome);
    let Some(outcome) = outcome else {
        assert(false, "espera-registrada: processo de teste");
        let _ = service_table::restore_shadow_second_table(saved_shadow);
        return;
    };
    assert(outcome.started && outcome.pairs == PAIRS && outcome.zero_statuses == PAIRS && !PENDING_SEEN.load(Ordering::SeqCst), "espera-registrada: cada sinal-e-limpa conclui a espera adiada com 0 e o anel 3 nunca ve STATUS_PENDING");
    assert(outcome.ready_on_signal == PAIRS && outcome.polls == 0, "espera-registrada: o KeSetEvent apronta a thread dentro do sinal (KiUnwaitThread), sem nenhuma espera sondada");
    assert(outcome.overlay_kept, "espera-registrada: os blocos de espera embutidos na KTHREAD nao apagam os campos sobrepostos a eles (ThreadCounters, Win32Thread)");
    assert(outcome.kernel_pairs == KERNEL_PAIRS && outcome.kernel_ready == KERNEL_PAIRS && outcome.kernel_zero == KERNEL_PAIRS, "espera-registrada: o KeWaitForSingleObject dentro do servico bloqueia com a espera registrada, e o sinal apronta a thread e retoma o servico com 0");
    assert(outcome.held_while_suspended && outcome.resumed_status == 0, "espera-registrada: suspensa, o sinal nao a roda; a retomada conclui a espera com 0");
    assert(outcome.alerts == ALERTS && outcome.alerted_ready == ALERTS && outcome.alert_statuses == ALERTS, "espera-registrada: o NtAlertThreadByThreadId apronta a thread na hora e o NtWaitForAlertByThreadId volta com STATUS_ALERTED");
    assert(outcome.delays == DELAYS && outcome.delays_on_time == DELAYS, "espera-registrada: o NtDelayExecution conclui com 0 depois do prazo, pelo timer da thread");
    assert(outcome.exited && outcome.list_empty, "espera-registrada: o fim do processo desliga o bloco de espera da thread do evento");
    let _ = service_table::restore_shadow_second_table(saved_shadow);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
}
