//! O despacho de usuário sem o trabalho que não lhe cabe
//! (`ps/user/threads.rs`, `ke/dispatcher.rs`).
//!
//! - O tick não aninha no despacho: com uma thread de sistema pronta e
//!   nenhuma de usuário, o `dispatch_one` roda os pumps e a escolha, mas não
//!   a thread de kernel (antes um tick aninhado a cada 2 ms a rodava fora da
//!   prioridade dela, contada como despacho de usuário); a volta de quem
//!   espera fora do tick (`dispatch_round`) a roda.
//! - A sondagem das esperas de usuário só roda quando tem o que achar: no
//!   mesmo tique do relógio e sem a época de despertar andar, as sondagens
//!   seguidas são dispensadas; um despertar (o sinal de um objeto, uma
//!   entrega ALPC, uma APC) ou o tique seguinte a fazem rodar de novo.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::amd64::usermode;
use crate::nano::interrupts;
use crate::ntos::ke::{clock, dispatcher};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::user::threads;
use crate::ntos::ps::{dispatch_perf, kernel_threads, scheduler};
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

/// O bloco da thread de sistema: [0] voltas, [8] fim pedido.
static BLOCK: AtomicU64 = AtomicU64::new(0);

/// Conta uma volta e cede a vez (ZwYieldExecution), até o fim pedido: fica
/// sempre pronta.
extern "win64" fn spinner(block: u64) {
    while guest::read64(block + 8) == 0 {
        guest::write64(block, guest::read64(block) + 1);
        call_export("ZwYieldExecution", &[]);
    }
}

fn nested_tick(assert: Assert) {
    let block = guest::alloc_bytes(0x10);
    if block == 0 {
        assert(false, "despacho: bloco da thread de sistema");
        return;
    }
    guest::write_bytes(block, &[0; 0x10]);
    BLOCK.store(block, Ordering::SeqCst);
    let handle = kernel_threads::create_system_thread(0, spinner as *const () as usize as u64, block, 0x1F_FFFF, 0, None).unwrap_or(0);
    let thread = kernel_threads::of_handle(handle).unwrap_or(0);
    // A primeira volta (pelo tick, que alterna kernel e usuário).
    let deadline = clock::uptime_ms() + 5_000;
    while thread != 0 && guest::read64(block) == 0 && clock::uptime_ms() < deadline {
        scheduler::tick(-1);
    }
    let started = guest::read64(block) != 0;
    // 20 ms de despachos de usuário: dez vezes o intervalo do tick aninhado.
    let before = guest::read64(block);
    let (mut dispatches, mut idle) = (0u32, true);
    let window = clock::uptime_ms() + 20;
    while clock::uptime_ms() < window {
        idle &= threads::dispatch_one().is_ok_and(|dispatched| dispatched == threads::Dispatched::Idle);
        dispatches += 1;
    }
    let untouched = guest::read64(block) == before;
    // A volta de fora do tick roda os passos de kernel.
    let mut ran = false;
    for _ in 0..64 {
        let _ = threads::dispatch_round();
        if guest::read64(block) != before {
            ran = true;
            break;
        }
    }
    crate::debug_print!("[despacho] tick aninhado: partida={} despachos={} ociosos={} intocada={} volta={}", started, dispatches, idle, untouched, ran);
    assert(started && dispatches > 0 && idle && untouched, "despacho: o dispatch_one com uma thread de sistema pronta e nenhuma de usuario roda os pumps sem aninhar o tick (a thread de kernel nao roda)");
    assert(ran, "despacho: a volta de quem espera fora do tick (dispatch_round) roda a thread de kernel pronta");
    guest::write64(block + 8, 1);
    let deadline = clock::uptime_ms() + 5_000;
    while !kernel_threads::is_terminated(thread) && clock::uptime_ms() < deadline {
        scheduler::tick(-1);
    }
    assert(kernel_threads::is_terminated(thread), "despacho: a thread de sistema sai no fim");
    let _ = object_manager::close(handle as u32);
    guest::free_bytes(block);
    BLOCK.store(0, Ordering::SeqCst);
}

/// As sondagens dispensadas por `body`, medidas dentro de um mesmo tique do
/// relógio (`None` se o tique virou no meio, nas 16 tentativas).
fn within_one_tick(body: &dyn Fn()) -> Option<u64> {
    for _ in 0..16 {
        let tick = interrupts::tick_count();
        // O começo de um tique: a medida cabe folgada nele.
        while interrupts::tick_count() == tick {
            core::hint::spin_loop();
        }
        let tick = interrupts::tick_count();
        let skipped = dispatch_perf::POLLS_SKIPPED.load(Ordering::SeqCst);
        body();
        let delta = dispatch_perf::POLLS_SKIPPED.load(Ordering::SeqCst) - skipped;
        if interrupts::tick_count() == tick {
            return Some(delta);
        }
    }
    None
}

fn poll_gating(assert: Assert) {
    if !threads::can_dispatch() {
        assert(false, "sondagem: o despacho de usuario cabe no contexto do teste");
        return;
    }
    // A primeira do tique sonda (o tique andou); as duas seguintes, sem
    // despertar, são dispensadas.
    let quiet = within_one_tick(&|| {
        threads::refresh_waiting();
        threads::refresh_waiting();
        threads::refresh_waiting();
    });
    assert(quiet == Some(2), "sondagem: no mesmo tique e sem despertar, as sondagens seguidas das esperas de usuario sao dispensadas");
    // Um despertar entre duas: a segunda sonda.
    let woken = within_one_tick(&|| {
        threads::refresh_waiting();
        dispatcher::note_wake();
        threads::refresh_waiting();
    });
    assert(woken == Some(0), "sondagem: depois de um despertar (a epoca andou) a sondagem roda de novo");
    // O tique seguinte faz a sondagem rodar (o prazo das esperas sondadas).
    threads::refresh_waiting();
    let skipped = dispatch_perf::POLLS_SKIPPED.load(Ordering::SeqCst);
    let tick = interrupts::tick_count();
    let deadline = clock::uptime_ms() + 1_000;
    while interrupts::tick_count() == tick && clock::uptime_ms() < deadline {
        core::hint::spin_loop();
    }
    threads::refresh_waiting();
    assert(interrupts::tick_count() != tick && dispatch_perf::POLLS_SKIPPED.load(Ordering::SeqCst) == skipped, "sondagem: o tique seguinte do relogio faz a sondagem rodar");
}

pub fn run(assert: Assert) {
    if !usermode::ready() {
        assert(false, "despacho: anel 3 armado");
        return;
    }
    nested_tick(assert);
    poll_gating(assert);
}
