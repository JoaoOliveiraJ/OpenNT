//! Esperas de IPI medidas em tempo (`ke/smp.rs`): a entrega pelo ICR na
//! partida dos APs espera com prazo pelo contador de desempenho
//! (`smp::stall_on_targets`), não por um número de voltas; as confirmações
//! do shootdown de TLB esperam sem prazo (`smp::wait_on_targets`), como o
//! PacketBarrier do flush de TLB do 19041, e o alvo lento só vai à serial.
//!
//! - uma resposta que chega 50 ms depois, num prazo de 200 ms, é aceita: uma
//!   espera por voltas (100 000 leituras) desiste antes, porque cada volta
//!   custa só o que a CPU (ou o hipervisor) gasta nela;
//! - o prazo vence só depois da hora, pela comparação exata e estrita do
//!   KiIpiGenericCallTarget: na unidade de baixo de um prazo que não cai
//!   numa unidade inteira do contador (o TSC a 3 393 626 637 Hz dá
//!   101 808 799,11 unidades em 30 ms) ainda não venceu, e na de cima o
//!   atraso já soma os 30 ms; com o prazo pela unidade de baixo do TSC, a
//!   leitura que caía exatamente nela (cerca de 1 espera em 100 no QEMU sob
//!   WHPX, voltas de ~90 ciclos) dava um alvo detectado com 29 ms;
//! - um alvo que nunca responde é detectado depois de 30 ms, não antes, com a
//!   máscara dos pendentes, a frequência do contador de desempenho (a do
//!   KeQueryPerformanceCounter, 10 MHz) e os dois contadores coerentes com o
//!   tempo medido;
//! - o shootdown real, com todos os APs respondendo, conclui;
//! - a espera sem prazo de um alvo que responde 60 ms depois, com o
//!   diagnóstico em 20 ms, conclui com o alvo dado como lento (sem parada do
//!   sistema), e a de um que responde antes do diagnóstico, sem;
//! - o prazo do ICR na partida é 100 ms e o diagnóstico de um IPI lento 5 s,
//!   em hardware e sob hipervisor, e maiores num emulador, em que uma CPU
//!   virtual fica segundos sem rodar com o hospedeiro carregado;
//! - um AP girando com as interrupções desligadas em HIGH_LEVEL (CR8 = 15)
//!   confirma 64 shootdowns seguidos: a confirmação vem pela NMI, que nem o
//!   IF nem o IRQL do alvo retêm;
//! - o KeFlushProcessWriteBuffers interrompe o KPROCESS.ActiveProcessors
//!   menos o processador corrente: a NMI alcança só os alvos (com dois APs,
//!   o primeiro confirma e o segundo não), e com AllProcessors todos
//!   confirmam.

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

    // (frequência do contador, prazo): o TSC calibrado de uma máquina do
    // QEMU sob WHPX em que um alvo foi detectado com 29 ms, outro TSC
    // calibrado e o contador de desempenho de 10 MHz, em que o prazo cai
    // numa unidade inteira e só vence na seguinte (`ja`).
    let boundaries = [(3_393_626_637u64, 30u64), (3_393_623_006, 30), (3_393_626_637, 5_000), (clock::QPC_FREQUENCY, 30), (clock::QPC_FREQUENCY, 100), (clock::QPC_FREQUENCY, 5_000)];
    let exact = boundaries.iter().all(|&(frequency, timeout)| {
        let below = (frequency as u128 * timeout as u128 / 1000) as u64;
        let detected = smp::IpiStall { frequency, current: below + 1, start: 0, pending: 1 };
        !smp::deadline_passed(below, frequency, timeout) && smp::deadline_passed(below + 1, frequency, timeout) && detected.elapsed_ms() >= timeout
    });
    assert(exact, "ipi: o prazo vence so depois da hora (comparacao exata e estrita): o contador na unidade de baixo de um prazo fracionario ainda nao venceu e o atraso detectado soma o prazo inteiro");

    let start = clock::uptime_ms();
    let stalled = smp::stall_on_targets(30, || 0b100);
    let waited = clock::uptime_ms() - start;
    assert(waited >= 30 && waited < 30 + HOST_SLACK_MS, "ipi: alvo sem resposta detectado depois do prazo de 30 ms, nao antes");
    let coherent = stalled.is_err_and(|stall| {
        stall.pending == 0b100
            && stall.frequency == clock::QPC_FREQUENCY
            && smp::deadline_passed(stall.current.wrapping_sub(stall.start), stall.frequency, 30)
            && (30..30 + HOST_SLACK_MS).contains(&stall.elapsed_ms())
    });
    assert(coherent, "ipi: o atraso traz os pendentes, a frequencia do contador de desempenho e os contadores do inicio e da deteccao");

    if smp::ap_slot_count() > 0 {
        assert(smp::flush_remote_tlb(false).is_ok(), "ipi: shootdown de TLB com todos os APs respondendo");
    }

    // A espera sem prazo: o alvo que responde depois do diagnóstico ainda
    // conclui (o flush de TLB do 19041 gira no PacketBarrier sem limite).
    let start = clock::uptime_ms();
    let arrival = start + 60;
    let slow = smp::wait_on_targets(20, "autoteste de IPI lento", || if clock::uptime_ms() < arrival { 0b100 } else { 0 });
    let waited = clock::uptime_ms() - start;
    assert(slow.slow == 0b100 && slow.elapsed_ms >= 60 && waited >= 60, "ipi: o alvo que responde depois do diagnostico conclui a espera sem prazo, dado como lento, sem parar o sistema");
    let arrival = clock::uptime_ms() + 5;
    let prompt = smp::wait_on_targets(2_000, "autoteste de IPI", || if clock::uptime_ms() < arrival { 0b10 } else { 0 });
    assert(prompt.slow == 0 && prompt.elapsed_ms < 2_000, "ipi: o alvo que responde antes do diagnostico conclui a espera sem ser dado como lento");

    let scale = if crate::hal::hypervisor::is_emulator() { 12 } else { 1 };
    assert(smp::interrupt_delivery_timeout_ms() == 100 * scale && smp::slow_interrupt_report_ms() == 5_000 * scale, "ipi: prazo de 100 ms (ICR na partida) e diagnostico de 5 s (IPI lento) em hardware e sob hipervisor, 12 vezes maiores num emulador");

    if smp::ap_slot_count() > 0 {
        masked_target_acknowledges(assert);
    }
    process_write_buffers(assert);
}

/// KeFlushProcessWriteBuffers: os alvos são o KPROCESS.ActiveProcessors
/// menos o processador corrente; a NMI alcança só os alvos e cada um
/// confirma; com AllProcessors, todos os APs confirmam.
fn process_write_buffers(assert: Assert) {
    assert(smp::write_buffer_targets(0b1011, 0b1) == 0b1010 && smp::write_buffer_targets(0b1, 0b1) == 0 && smp::write_buffer_targets(0b110, 0b100) == 0b10, "ipi: KeFlushProcessWriteBuffers interrompe o ActiveProcessors menos o processador corrente");
    if smp::ap_slot_count() < 2 {
        return;
    }
    // Só o processador 1 (o AP da posição 0). As interrupções desligadas no
    // BSP: nenhum outro shootdown começa entre o envio e as leituras.
    let flags = cpu::save_and_disable_interrupts();
    let targeted = smp::interrupt_processors(0b10).is_ok();
    let first = smp::shootdown_generations(0);
    let second = smp::shootdown_generations(1);
    cpu::restore_interrupts(flags);
    let reached = matches!((first, second), (Some((generation, first)), Some((_, second))) if first == generation && second != generation);
    assert(targeted && reached, "ipi: o IPI do KeFlushProcessWriteBuffers alcanca so os processadores alvo, que confirmam");
    let all = smp::flush_process_write_buffers(true).is_ok();
    let confirmed = (0..smp::ap_slot_count()).all(|index| smp::shootdown_generations(index).is_some_and(|(generation, acknowledged)| acknowledged == generation));
    assert(all && confirmed, "ipi: KeFlushProcessWriteBuffers(AllProcessors) espera a confirmacao de todos os APs");
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
