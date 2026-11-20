//! A espera de usuário sondada que o intervalo que acabou de rodar satisfez
//! entra no mesmo tique (`ps/scheduler.rs`), como no 19041, em que o
//! KiUnwaitThread apronta quem espera dentro do sinal (KiReadyThread,
//! 0x247fb0).
//!
//! Duas threads de usuário de um processo real jogam pingue-pongue por dois
//! eventos de sincronização, cada uma num serviço de teste (tabela 1 do
//! Shadow) que sinaliza o evento da outra e espera o seu: o
//! KeWaitForSingleObject de uma thread de usuário dentro de uma syscall é
//! sondado, e quem acorda a outra bloqueia na mesma syscall. O teste dá ao
//! despachante um número fixo de tiques (`scheduler::tick`) e conta as
//! voltas. Com a sondagem antes de o tique ficar ocioso, cada tique dá até
//! USER_SLICES_PER_TICK intervalos (meia volta cada); sem ela, um intervalo
//! por tique, e a outra thread só é vista pronta no tique seguinte.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::blocking_wait::{self, EXIT_SERVICE};
use super::identity::with_test_process;
use crate::hal::amd64::usermode;
use crate::ntos::ex::service_table;
use crate::ntos::ke::{clock, dispatcher};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ps::scheduler;
use crate::ntos::ps::user::memory;
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

/// Os serviços de teste: índices 0-2 da tabela 1 (o 2 é a saída).
const PING_SERVICE: u32 = 0x1000;
const PONG_SERVICE: u32 = 0x1001;
/// Os tiques contados.
const TICKS: u64 = 20;
/// Sem a sondagem, no máximo uma volta a cada dois tiques (10 em 20); com
/// ela, até oito por tique.
const MINIMUM_ROUNDS: u64 = 40;
const UNSET: u64 = u64::MAX;

static SERVICE_TABLE: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static SERVICE_ARGUMENTS: [AtomicU8; 3] = [const { AtomicU8::new(0) }; 3];

/// [0] o evento da 1 (ping), [0x20] o da 2 (pong), [0x40] o prazo de cada
/// espera.
static BLOCK: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static ROUNDS: AtomicU64 = AtomicU64::new(0);
static PING_STATUS: AtomicU64 = AtomicU64::new(UNSET);
static PONG_STATUS: AtomicU64 = AtomicU64::new(UNSET);
static PARTNER: SpinLock<Option<Arc<UserThread>>> = SpinLock::new(None);

fn events() -> (u64, u64, u64) {
    let block = BLOCK.load(Ordering::SeqCst);
    (block, block + 0x20, block + 0x40)
}

/// A 1: solta a 2 e, até o fim pedido, sinaliza o ping e espera o pong.
extern "win64" fn ping_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let partner = PARTNER.lock().take();
    if let Some(partner) = partner {
        partner.with(|thread| thread.suspend_count = 0);
    }
    let (ping, pong, timeout) = events();
    let mut status = 0;
    while !STOP.load(Ordering::SeqCst) {
        dispatcher::set_event(ping);
        status = dispatcher::wait_for_single_object(pong, timeout, 0, false);
        if status != 0 {
            break;
        }
        ROUNDS.fetch_add(1, Ordering::SeqCst);
    }
    PING_STATUS.store(status as u64, Ordering::SeqCst);
    0
}

/// A 2: espera o ping e responde com o pong, até o fim pedido.
extern "win64" fn pong_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let (ping, pong, timeout) = events();
    let status = loop {
        let status = dispatcher::wait_for_single_object(ping, timeout, 0, false);
        if status != 0 || STOP.load(Ordering::SeqCst) {
            break status;
        }
        dispatcher::set_event(pong);
    };
    PONG_STATUS.store(status as u64, Ordering::SeqCst);
    0
}

/// O que o pingue-pongue observou.
struct Outcome {
    started: bool,
    warmed: bool,
    rounds: u64,
    ping_status: u64,
    pong_status: u64,
    finished: bool,
}

fn run_ping_pong() -> Option<Outcome> {
    with_test_process("pingue-pongue.exe", None, |test| {
        let (code, stacks) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x8000, 4));
        let block = guest::alloc_bytes(0x80);
        let ping = blocking_wait::user_thread(test.process, code);
        let pong = blocking_wait::user_thread(test.process, code + 0x100);
        let mut outcome = Outcome { started: false, warmed: false, rounds: 0, ping_status: UNSET, pong_status: UNSET, finished: false };
        if let (Some(ping), Some(pong), true) = (ping.as_ref(), pong.as_ref(), block != 0 && code != 0 && stacks != 0) {
            guest::write_bytes(code, &blocking_wait::program(PING_SERVICE, 0, false));
            guest::write_bytes(code + 0x100, &blocking_wait::program(PONG_SERVICE, 0x100, false));
            guest::write_bytes(block, &[0; 0x80]);
            dispatcher::initialize_event(block, 1, false);
            dispatcher::initialize_event(block + 0x20, 1, false);
            // Prazo de 2 s em cada espera: o teste não fica preso.
            guest::write64(block + 0x40, (-20_000_000i64) as u64);
            BLOCK.store(block, Ordering::SeqCst);
            STOP.store(false, Ordering::SeqCst);
            ROUNDS.store(0, Ordering::SeqCst);
            PING_STATUS.store(UNSET, Ordering::SeqCst);
            PONG_STATUS.store(UNSET, Ordering::SeqCst);
            if blocking_wait::prepare_partner(pong, code + 0x100, stacks + 0x8000 - 0x28) {
                *PARTNER.lock() = Some(pong.clone());
                outcome.started = threads::start(ping, code, stacks + 0x4000 - 0x28, 0, 0).is_ok();
            }
            if outcome.started {
                // As duas no laço: a primeira volta completa.
                let deadline = clock::uptime_ms() + 5_000;
                while ROUNDS.load(Ordering::SeqCst) < 2 && clock::uptime_ms() < deadline {
                    scheduler::tick(-1);
                }
                outcome.warmed = ROUNDS.load(Ordering::SeqCst) >= 2;
                let before = ROUNDS.load(Ordering::SeqCst);
                for _ in 0..TICKS {
                    scheduler::tick(-1);
                }
                outcome.rounds = ROUNDS.load(Ordering::SeqCst) - before;
                STOP.store(true, Ordering::SeqCst);
                dispatcher::set_event(block);
                dispatcher::set_event(block + 0x20);
                outcome.finished = threads::wait_for_process(test.process).is_ok();
            }
            outcome.ping_status = PING_STATUS.load(Ordering::SeqCst);
            outcome.pong_status = PONG_STATUS.load(Ordering::SeqCst);
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

pub fn run(assert: Assert) {
    if !usermode::ready() {
        assert(false, "pingue-pongue: anel 3 armado");
        return;
    }
    if threads::all().iter().any(|thread| !thread.dead()) {
        assert(false, "pingue-pongue: nenhuma thread de usuario de outro teste viva");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "pingue-pongue: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; 3] = [ping_service, pong_service, blocking_wait::exit_service];
    let mut encoded = true;
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => encoded = false,
        }
    }
    if !encoded || EXIT_SERVICE != 0x1002 || service_table::publish_shadow_second_table(table, 3, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
        assert(false, "pingue-pongue: tabela 1 de teste");
        let _ = service_table::restore_shadow_second_table(saved_shadow);
        return;
    }
    let outcome = run_ping_pong();
    crate::debug_print!(
        "[pingue-pongue] voltas em {} tiques: {:?}",
        TICKS,
        outcome.as_ref().map(|outcome| (outcome.started, outcome.warmed, outcome.rounds, outcome.ping_status, outcome.pong_status, outcome.finished))
    );
    let ran = outcome.as_ref().is_some_and(|outcome| outcome.started && outcome.warmed && outcome.finished && outcome.ping_status == 0 && outcome.pong_status == 0);
    assert(ran, "pingue-pongue: as duas threads de usuario no laco e de volta ao fim pedido");
    assert(
        outcome.is_some_and(|outcome| outcome.rounds >= MINIMUM_ROUNDS),
        "pingue-pongue: a thread que o intervalo acabou de acordar roda no mesmo tique (a sondagem antes de o tique ficar ocioso)",
    );
    let _ = service_table::restore_shadow_second_table(saved_shadow);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
}
