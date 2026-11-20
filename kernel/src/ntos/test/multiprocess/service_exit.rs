//! A volta do serviço ao anel 3 no mesmo intervalo (o KiSystemServiceExit,
//! `hal/amd64/usermode.rs::continues_in_interval`).
//!
//! Uma thread de usuário de um processo real repete um serviço de teste
//! (tabela 1 do Shadow) que só conta e devolve: os serviços voltam ao anel 3
//! sem fim de intervalo, e num tempo fixo há muitas chamadas por intervalo
//! (os intervalos acabam pelo tique de 10 ms). Antes, cada serviço acabava o
//! intervalo e passava pelo despachante.
//!
//! Depois, a mesma thread repete um serviço que sinaliza um evento de
//! sincronização, que uma segunda thread, de prioridade maior, espera num
//! serviço (a espera sondada): o sinal move a época dos sinais, o serviço
//! acaba o intervalo e o despachante dá a CPU à que espera, como o
//! KiUnwaitThread e a preempção do 19041. Quase toda sinalização acorda a
//! que espera; sem o fim do intervalo, as sinalizações seguintes do mesmo
//! intervalo achariam o evento ainda sinalizado.
//!
//! Por fim, uma thread repete uma espera adiada (a do NtWaitFor*, que devolve
//! STATUS_PENDING com a espera instalada) num evento de notificação, ao lado
//! de outra que só conta, na mesma prioridade; o teste sinaliza e limpa o
//! evento a cada vez que ela volta a esperar. Toda espera conclui com 0 (o
//! reset de um evento sinalizado fica como pulso), e o anel 3 nunca vê o
//! STATUS_PENDING: a saída do serviço que instalou a espera acaba o
//! intervalo.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::blocking_wait::{self, EXIT_SERVICE};
use super::identity::with_test_process;
use crate::hal::amd64::usermode;
use crate::ntos::ex::service_table;
use crate::ntos::ke::{clock, dispatcher, thread_priority};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ps::user::memory;
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::{dispatch_perf, scheduler};
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

/// Os serviços de teste: 0 conta, 1 sinaliza, 2 é a saída, 3 espera, 4
/// espera adiada, 5 registra o STATUS_PENDING visto no anel 3.
const COUNT_SERVICE: u32 = 0x1000;
const SIGNAL_SERVICE: u32 = 0x1001;
const WAIT_SERVICE: u32 = 0x1003;
const DEFERRED_SERVICE: u32 = 0x1004;
const PENDING_SEEN_SERVICE: u32 = 0x1005;
const SERVICES: usize = 6;
/// Os pares sinaliza-limpa da fase da espera adiada.
const PAIRS: u64 = 40;
/// A janela medida de cada fase, em ms.
const WINDOW_MS: u64 = 200;
/// Chamadas por intervalo que a volta direta tem de dar no mínimo (sem ela,
/// uma).
const MINIMUM_CALLS_PER_SLICE: u64 = 20;
/// Sinalizações que a fase da espera tem de ver no mínimo.
const MINIMUM_SIGNALS: u64 = 50;

static SERVICE_TABLE: [AtomicU32; SERVICES] = [const { AtomicU32::new(0) }; SERVICES];
static SERVICE_ARGUMENTS: [AtomicU8; SERVICES] = [const { AtomicU8::new(0) }; SERVICES];

/// O evento da fase da espera e o prazo de cada espera.
static BLOCK: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicU64 = AtomicU64::new(0);
static SIGNALS: AtomicU64 = AtomicU64::new(0);
static WAKES: AtomicU64 = AtomicU64::new(0);
static DEFERRED_CALLS: AtomicU64 = AtomicU64::new(0);
static PENDING_SEEN: AtomicBool = AtomicBool::new(false);
static PARTNER: SpinLock<Option<Arc<UserThread>>> = SpinLock::new(None);

fn stop() -> u64 {
    STOP.load(Ordering::SeqCst) as u64
}

/// Conta e devolve: 0 segue o laço, 1 o encerra.
extern "win64" fn count_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    CALLS.fetch_add(1, Ordering::SeqCst);
    stop()
}

/// Solta a que espera (na primeira chamada) e sinaliza o evento.
extern "win64" fn signal_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let partner = PARTNER.lock().take();
    if let Some(partner) = partner {
        partner.with(|thread| thread.suspend_count = 0);
    }
    if stop() == 0 {
        dispatcher::set_event(BLOCK.load(Ordering::SeqCst));
        SIGNALS.fetch_add(1, Ordering::SeqCst);
    }
    stop()
}

/// Espera o evento (sondada, dentro do serviço) e conta o despertar.
extern "win64" fn wait_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let block = BLOCK.load(Ordering::SeqCst);
    if stop() == 0 && dispatcher::wait_for_single_object(block, block + 0x20, 0, false) == 0 {
        WAKES.fetch_add(1, Ordering::SeqCst);
    }
    stop()
}

/// A espera adiada num evento de notificação, sem prazo: STATUS_PENDING com
/// a espera instalada; o despachante a conclui e grava o status no CONTEXT.
/// Cada chamada depois da primeira quer dizer que a anterior concluiu com 0.
extern "win64" fn deferred_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    DEFERRED_CALLS.fetch_add(1, Ordering::SeqCst);
    if stop() != 0 {
        return 1;
    }
    threads::wait_objects(Vec::new(), alloc::vec![BLOCK.load(Ordering::SeqCst)], 1, 0, false) as u64
}

/// O anel 3 viu STATUS_PENDING na volta de um serviço.
extern "win64" fn pending_seen_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    PENDING_SEEN.store(true, Ordering::SeqCst);
    1
}

/// `laço: mov eax, serviço; mov r10, rcx; syscall; cmp eax, 0x103; je visto;
/// test eax, eax; jz laço`, a syscall de saída e `jmp $`; em `visto`, o
/// serviço que registra o STATUS_PENDING e `jmp $`.
fn looping_program(service: u32) -> Vec<u8> {
    let syscall = |program: &mut Vec<u8>, number: u32| {
        program.push(0xB8);
        program.extend_from_slice(&number.to_le_bytes());
        program.extend_from_slice(&[0x49, 0x89, 0xCA, 0x0F, 0x05]);
    };
    let mut program = Vec::new();
    syscall(&mut program, service);
    // cmp eax, 0x103; je visto (+16); test eax, eax; jz laço.
    program.extend_from_slice(&[0x3D, 0x03, 0x01, 0x00, 0x00, 0x74, 16, 0x85, 0xC0, 0x74]);
    program.push((-(program.len() as i8) - 1) as u8);
    syscall(&mut program, EXIT_SERVICE);
    program.extend_from_slice(&[0xEB, 0xFE]);
    syscall(&mut program, PENDING_SEEN_SERVICE);
    program.extend_from_slice(&[0xEB, 0xFE]);
    program
}

/// O que as duas fases observaram.
#[derive(Debug, Default)]
struct Outcome {
    counted: bool,
    calls: u64,
    slices: u64,
    signalled: bool,
    signals: u64,
    wakes: u64,
    deferred: bool,
    pairs: u64,
    completed: u64,
    counted_beside: u64,
}

/// Gira o despachante por `WINDOW_MS` e devolve os intervalos que ele deu.
fn window() -> u64 {
    let slices = dispatch_perf::slices();
    let deadline = clock::uptime_ms() + WINDOW_MS;
    while clock::uptime_ms() < deadline {
        scheduler::tick(-1);
    }
    dispatch_perf::slices() - slices
}

/// Pede o fim, solta as esperas e espera o processo sair.
fn finish(process: u64) -> bool {
    STOP.store(true, Ordering::SeqCst);
    let block = BLOCK.load(Ordering::SeqCst);
    if block != 0 {
        dispatcher::set_event(block);
    }
    threads::wait_for_process(process).is_ok()
}

fn run_phases() -> Option<Outcome> {
    BLOCK.store(0, Ordering::SeqCst);
    let first = with_test_process("servico-direto.exe", None, |test| {
        let (code, stacks) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x8000, 4));
        let mut outcome = Outcome::default();
        let counter = blocking_wait::user_thread(test.process, code);
        if let (Some(counter), true) = (counter.as_ref(), code != 0 && stacks != 0) {
            guest::write_bytes(code, &looping_program(COUNT_SERVICE));
            STOP.store(false, Ordering::SeqCst);
            CALLS.store(0, Ordering::SeqCst);
            if threads::start(counter, code, stacks + 0x4000 - 0x28, 0, 0).is_ok() {
                let warm = clock::uptime_ms() + 5_000;
                while CALLS.load(Ordering::SeqCst) == 0 && clock::uptime_ms() < warm {
                    scheduler::tick(-1);
                }
                let before = CALLS.load(Ordering::SeqCst);
                outcome.slices = window();
                outcome.calls = CALLS.load(Ordering::SeqCst) - before;
                outcome.counted = finish(test.process);
            }
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        release(code, stacks);
        outcome
    })?;
    let second = with_test_process("servico-sinal.exe", None, |test| {
        let (code, stacks) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x8000, 4));
        let block = guest::alloc_bytes(0x40);
        let mut outcome = Outcome::default();
        let signaller = blocking_wait::user_thread(test.process, code);
        let waiter = blocking_wait::user_thread(test.process, code + 0x100);
        if let (Some(signaller), Some(waiter), true) = (signaller.as_ref(), waiter.as_ref(), block != 0 && code != 0 && stacks != 0) {
            guest::write_bytes(code, &looping_program(SIGNAL_SERVICE));
            guest::write_bytes(code + 0x100, &looping_program(WAIT_SERVICE));
            guest::write_bytes(block, &[0; 0x40]);
            dispatcher::initialize_event(block, 1, false);
            // Prazo de 2 s em cada espera: o teste não fica preso.
            guest::write64(block + 0x20, (-20_000_000i64) as u64);
            BLOCK.store(block, Ordering::SeqCst);
            STOP.store(false, Ordering::SeqCst);
            SIGNALS.store(0, Ordering::SeqCst);
            WAKES.store(0, Ordering::SeqCst);
            if blocking_wait::prepare_partner(waiter, code + 0x100, stacks + 0x8000 - 0x28) && thread_priority::set_priority(waiter.pointer(), 14).is_ok() {
                *PARTNER.lock() = Some(waiter.clone());
                if threads::start(signaller, code, stacks + 0x4000 - 0x28, 0, 0).is_ok() {
                    let warm = clock::uptime_ms() + 5_000;
                    while WAKES.load(Ordering::SeqCst) == 0 && clock::uptime_ms() < warm {
                        scheduler::tick(-1);
                    }
                    let (signals, wakes) = (SIGNALS.load(Ordering::SeqCst), WAKES.load(Ordering::SeqCst));
                    window();
                    outcome.signals = SIGNALS.load(Ordering::SeqCst) - signals;
                    outcome.wakes = WAKES.load(Ordering::SeqCst) - wakes;
                    outcome.signalled = finish(test.process);
                }
            }
            *PARTNER.lock() = None;
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        if block != 0 {
            guest::free_bytes(block);
        }
        release(code, stacks);
        outcome
    })?;
    let third = with_test_process("servico-espera.exe", None, |test| {
        let (code, stacks) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x8000, 4));
        let block = guest::alloc_bytes(0x40);
        let mut outcome = Outcome::default();
        let counter = blocking_wait::user_thread(test.process, code);
        let waiter = blocking_wait::user_thread(test.process, code + 0x100);
        if let (Some(counter), Some(waiter), true) = (counter.as_ref(), waiter.as_ref(), block != 0 && code != 0 && stacks != 0) {
            guest::write_bytes(code, &looping_program(COUNT_SERVICE));
            guest::write_bytes(code + 0x100, &looping_program(DEFERRED_SERVICE));
            guest::write_bytes(block, &[0; 0x40]);
            dispatcher::initialize_event(block, 0, false);
            BLOCK.store(block, Ordering::SeqCst);
            STOP.store(false, Ordering::SeqCst);
            CALLS.store(0, Ordering::SeqCst);
            DEFERRED_CALLS.store(0, Ordering::SeqCst);
            PENDING_SEEN.store(false, Ordering::SeqCst);
            if blocking_wait::prepare_partner(waiter, code + 0x100, stacks + 0x8000 - 0x28) {
                waiter.with(|thread| thread.suspend_count = 0);
                if threads::start(counter, code, stacks + 0x4000 - 0x28, 0, 0).is_ok() {
                    let deadline = clock::uptime_ms() + 20_000;
                    let calls = CALLS.load(Ordering::SeqCst);
                    while outcome.pairs < PAIRS && clock::uptime_ms() < deadline && !PENDING_SEEN.load(Ordering::SeqCst) {
                        // Um par só com a espera instalada e todas as
                        // anteriores concluídas.
                        if waiter.waiting() && DEFERRED_CALLS.load(Ordering::SeqCst) == outcome.pairs + 1 {
                            dispatcher::set_event(block);
                            dispatcher::reset_event(block);
                            outcome.pairs += 1;
                        }
                        scheduler::tick(-1);
                    }
                    let settle = clock::uptime_ms() + 2_000;
                    while DEFERRED_CALLS.load(Ordering::SeqCst) <= outcome.pairs && clock::uptime_ms() < settle {
                        scheduler::tick(-1);
                    }
                    outcome.completed = DEFERRED_CALLS.load(Ordering::SeqCst).saturating_sub(1);
                    outcome.counted_beside = CALLS.load(Ordering::SeqCst) - calls;
                    outcome.deferred = finish(test.process);
                }
            }
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        BLOCK.store(0, Ordering::SeqCst);
        if block != 0 {
            guest::free_bytes(block);
        }
        release(code, stacks);
        outcome
    })?;
    Some(Outcome { signalled: second.signalled, signals: second.signals, wakes: second.wakes, deferred: third.deferred, pairs: third.pairs, completed: third.completed, counted_beside: third.counted_beside, ..first })
}

fn release(code: u64, stacks: u64) {
    for base in [code, stacks] {
        if let Some(region) = memory::find_region(base).filter(|_| base != 0) {
            memory::release_private_region(&region);
        }
    }
}

pub fn run(assert: Assert) {
    if !usermode::ready() {
        assert(false, "servico-direto: anel 3 armado");
        return;
    }
    if threads::all().iter().any(|thread| !thread.dead()) {
        assert(false, "servico-direto: nenhuma thread de usuario de outro teste viva");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "servico-direto: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; SERVICES] = [count_service, signal_service, blocking_wait::exit_service, wait_service, deferred_service, pending_seen_service];
    let mut encoded = true;
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => encoded = false,
        }
    }
    if !encoded || EXIT_SERVICE != 0x1002 || service_table::publish_shadow_second_table(table, SERVICES as u32, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
        assert(false, "servico-direto: tabela 1 de teste");
        let _ = service_table::restore_shadow_second_table(saved_shadow);
        return;
    }
    let outcome = run_phases();
    crate::debug_print!("[servico-direto] {:?}", outcome);
    let counted = outcome.as_ref().is_some_and(|outcome| outcome.counted && outcome.slices != 0 && outcome.calls >= outcome.slices * MINIMUM_CALLS_PER_SLICE);
    assert(counted, "servico-direto: o servico que nao bloqueou volta ao anel 3 no mesmo intervalo (muitas chamadas por intervalo)");
    let signalled = outcome.as_ref().is_some_and(|outcome| outcome.signalled && outcome.signals >= MINIMUM_SIGNALS && outcome.wakes * 10 >= outcome.signals * 9);
    assert(signalled, "servico-direto: o servico que sinaliza acaba o intervalo e a thread de prioridade maior que esperava roda antes da sinalizacao seguinte");
    let deferred = outcome.as_ref().is_some_and(|outcome| outcome.deferred && outcome.pairs == PAIRS && outcome.completed == PAIRS && outcome.counted_beside != 0) && !PENDING_SEEN.load(Ordering::SeqCst);
    assert(deferred, "servico-direto: a espera adiada acaba o intervalo, conclui a cada sinal-e-limpa sem perder nenhum e o anel 3 nunca ve STATUS_PENDING");
    let _ = service_table::restore_shadow_second_table(saved_shadow);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
}
