//! Esperas de IPI medidas em tempo (`ke/smp.rs`): a entrega pelo ICR e as
//! confirmações do shootdown de TLB esperam pelo contador de desempenho
//! (`smp::stall_on_targets`), não por um número de voltas, e um alvo que não
//! responde no prazo vira o diagnóstico de IPI sem resposta
//! (IPI_WATCHDOG_TIMEOUT, com a frequência e os contadores do início e da
//! detecção).
//!
//! - uma resposta que chega 50 ms depois, num prazo de 200 ms, é aceita: uma
//!   espera por voltas (100 000 leituras) desiste antes, porque cada volta
//!   custa só o que a CPU (ou o hipervisor) gasta nela;
//! - um alvo que nunca responde é detectado depois de 30 ms, não antes, com a
//!   máscara dos pendentes, a frequência do TSC e os dois contadores
//!   coerentes com o tempo medido;
//! - o shootdown real, com todos os APs respondendo, conclui;
//! - os prazos são os do NT em hardware e sob hipervisor (100 ms para o ICR,
//!   5 s para as confirmações) e maiores num emulador, em que uma CPU
//!   virtual fica segundos sem rodar com o hospedeiro carregado;
//! - um AP girando com as interrupções desligadas em HIGH_LEVEL (CR8 = 15)
//!   confirma 64 shootdowns seguidos: a confirmação vem pela NMI, que nem o
//!   IF nem o IRQL do alvo retêm.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::cpu;
use crate::ntos::ke::{clock, irql, smp};

type Assert = fn(bool, &str);

/// Folga para o vCPU descalonado pelo host entre duas leituras do contador.
const HOST_SLACK_MS: u64 = 2_000;

pub fn run(assert: Assert) {
    let start = clock::uptime_ms();
    let arrival = start + 50;
    let late = smp::stall_on_targets(200, || if clock::uptime_ms() < arrival { 0b10 } else { 0 });
    let waited = clock::uptime_ms() - start;
    assert(late.is_ok() && waited >= 50, "ipi: resposta que chega em 50 ms, no prazo de 200 ms, e aceita (a espera e medida em tempo)");

    let start = clock::uptime_ms();
    let stalled = smp::stall_on_targets(30, || 0b100);
    let waited = clock::uptime_ms() - start;
    assert(waited >= 30 && waited < 30 + HOST_SLACK_MS, "ipi: alvo sem resposta detectado depois do prazo de 30 ms, nao antes");
    let coherent = stalled.is_err_and(|stall| {
        stall.pending == 0b100
            && stall.frequency == clock::tsc_frequency_hz()
            && stall.current.wrapping_sub(stall.start) >= stall.frequency / 1000 * 30
            && (30..30 + HOST_SLACK_MS).contains(&stall.elapsed_ms())
    });
    assert(coherent, "ipi: o atraso traz os pendentes, a frequencia do TSC e os contadores do inicio e da deteccao (parametros do IPI_WATCHDOG_TIMEOUT)");

    if smp::ap_slot_count() > 0 {
        assert(smp::flush_remote_tlb(false).is_ok(), "ipi: shootdown de TLB com todos os APs respondendo");
    }

    let scale = if crate::hal::hypervisor::is_emulator() { 12 } else { 1 };
    assert(smp::interrupt_delivery_timeout_ms() == 100 * scale && smp::shootdown_timeout_ms() == 5_000 * scale, "ipi: prazos de 100 ms (ICR) e 5 s (shootdown) em hardware e sob hipervisor, 12 vezes maiores num emulador");

    if smp::ap_slot_count() > 0 {
        masked_target_acknowledges(assert);
    }
}

/// [0] o AP está girando mascarado, [1] pedido de parada.
static MASKED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// Job de AP: gira com IF = 0 e o CR8 em HIGH_LEVEL até o pedido de parada
/// (ou 30 s); devolve 1 se girou mascarado.
extern "win64" fn spin_masked(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let flags = cpu::save_and_disable_interrupts();
    let previous = irql::raise_irql(irql::HIGH_LEVEL);
    let masked = !cpu::interrupts_enabled() && irql::get_irql() == irql::HIGH_LEVEL;
    MASKED[0].store(1, Ordering::SeqCst);
    let deadline = clock::uptime_ms() + 30_000;
    while MASKED[1].load(Ordering::SeqCst) == 0 && clock::uptime_ms() < deadline {
        core::hint::spin_loop();
    }
    irql::lower_irql(previous as u64);
    cpu::restore_interrupts(flags);
    masked as u64
}

fn masked_target_acknowledges(assert: Assert) {
    let Some(slot) = smp::ap_slot(0) else { return };
    MASKED[0].store(0, Ordering::SeqCst);
    MASKED[1].store(0, Ordering::SeqCst);
    let routine = spin_masked as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
    let started = smp::start_job(slot, routine, [0; 4]).is_ok_and(|started| started);
    let deadline = clock::uptime_ms() + 10_000;
    while started && MASKED[0].load(Ordering::SeqCst) == 0 && clock::uptime_ms() < deadline {
        core::hint::spin_loop();
    }
    let spinning = MASKED[0].load(Ordering::SeqCst) == 1;
    let frequency = clock::tsc_frequency_hz().max(1);
    let (mut acknowledged, mut longest, mut total) = (0u32, 0u64, 0u64);
    if spinning {
        for _ in 0..64 {
            let start = cpu::rdtsc();
            if smp::flush_remote_tlb(false).is_ok() {
                acknowledged += 1;
            }
            let elapsed = cpu::rdtsc().wrapping_sub(start);
            longest = longest.max(elapsed);
            total += elapsed;
        }
    }
    MASKED[1].store(1, Ordering::SeqCst);
    let masked = started && smp::wait_job(slot, 40_000).is_ok_and(|result| result == 1);
    debug_print!("[ipi] AP mascarado em HIGH_LEVEL: {} de 64 shootdowns confirmados, media {} us, maior {} us", acknowledged, total * 1_000_000 / 64 / frequency, longest * 1_000_000 / frequency);
    assert(spinning && masked && acknowledged == 64, "ipi: um AP girando com IF = 0 em HIGH_LEVEL confirma os shootdowns (a NMI nao e retida pelo IF nem pelo CR8)");
}
