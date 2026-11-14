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
//! - o shootdown real, com todos os APs respondendo, conclui.

use crate::ntos::ke::{clock, smp};

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
}
