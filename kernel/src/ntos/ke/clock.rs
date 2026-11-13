//! Relógio do kernel baseado no TSC — `system32/ntos/ke/clock.js`.
//!
//! A frequência vem da folha CPUID 0x15, quando válida, ou de calibração com
//! o PIT. O RTC fornece apenas a referência inicial do relógio de parede.
//! Os cálculos são inteiros: o kernel Rust é compilado sem SSE.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::{cpu, physical, port};
use crate::rtl::text::fixed1;
use crate::rtl::time;

static FREQUENCY_HERTZ: AtomicU64 = AtomicU64::new(0);
static TSC_AT_BOOT: AtomicU64 = AtomicU64::new(0);
static WALL_CLOCK_MS_AT_BOOT: AtomicU64 = AtomicU64::new(0);

// Células físicas compartilhadas com a atualização preemptiva de
// KUSER_SHARED_DATA no caminho nativo do timer.
const CELL_TSC_FREQUENCY: u64 = 0x81534;
const CELL_TSC_AT_BOOT: u64 = 0x81538;
const CELL_BOOT_TIME: u64 = 0x81540;

/// Programa o canal zero do PIT para 11931 contagens e mede quantos ticks de
/// TSC transcorreram até OUT indicar término.
fn calibrate_with_interval_timer() -> u64 {
    const INTERVAL_TIMER_COUNT: u64 = 11931;

    // Canal zero, byte baixo/alto, modo one-shot, depois o divisor.
    port::write8(0x43, 0x30);
    port::write8(0x40, (INTERVAL_TIMER_COUNT & 0xFF) as u8);
    port::write8(0x40, ((INTERVAL_TIMER_COUNT >> 8) & 0xFF) as u8);

    let start = cpu::rdtsc();
    loop {
        // No read-back, a seleção do contador é ativa em um: 0xE2 lê o
        // status do canal zero (0xE0 não selecionaria canal algum).
        port::write8(0x43, 0xE2);
        if port::read8(0x40) & 0x80 != 0 {
            break;
        }
    }
    let elapsed = cpu::rdtsc() - start;
    (elapsed as u128 * 1_193_182 / INTERVAL_TIMER_COUNT as u128) as u64
}

/// Descobre ou mede a frequência, captura as referências de boot e publica
/// os valores usados pelo caminho nativo de atualização de tempo.
pub fn init() {
    // Folhas não suportadas podem devolver dados da última folha existente.
    let maximum_basic_leaf = cpu::cpuid(0)[0];
    let frequency_leaf = if maximum_basic_leaf >= 0x15 { cpu::cpuid(0x15) } else { [0; 4] };

    let mut frequency = 0u64;
    if frequency_leaf[2] != 0 && frequency_leaf[0] != 0 && frequency_leaf[1] != 0 {
        frequency = frequency_leaf[2] as u64 * frequency_leaf[1] as u64 / frequency_leaf[0] as u64;
    }
    if frequency == 0 {
        debug_print!("[clock] CPUID.15 ausente — calibrando TSC via PIT");
        frequency = calibrate_with_interval_timer().max(1);
    }
    FREQUENCY_HERTZ.store(frequency, Ordering::Relaxed);

    let tsc_at_boot = cpu::rdtsc();
    let wall_clock = time::rtc_unix_milliseconds();
    TSC_AT_BOOT.store(tsc_at_boot, Ordering::Relaxed);
    WALL_CLOCK_MS_AT_BOOT.store(wall_clock, Ordering::Relaxed);

    physical::write32(CELL_TSC_FREQUENCY, frequency.min(u32::MAX as u64) as u32);
    physical::write64(CELL_TSC_AT_BOOT, tsc_at_boot);
    // Milissegundos desde 1970 -> unidades de 100 ns desde 1601.
    physical::write64(CELL_BOOT_TIME, time::unix_milliseconds_to_nt_time(wall_clock));
    debug_print!("[clock] TSC = {} MHz", fixed1(frequency, 1_000_000));
}

/// Milissegundos desde o boot pelo TSC.
pub fn uptime_ms() -> u64 {
    let frequency = FREQUENCY_HERTZ.load(Ordering::Relaxed).max(1);
    let elapsed = cpu::rdtsc().wrapping_sub(TSC_AT_BOOT.load(Ordering::Relaxed));
    (elapsed as u128 * 1000 / frequency as u128) as u64
}

/// Unidades de 100 ns desde o boot (prazos de timers e esperas).
pub fn uptime_100ns() -> u64 {
    let frequency = FREQUENCY_HERTZ.load(Ordering::Relaxed).max(1);
    let elapsed = cpu::rdtsc().wrapping_sub(TSC_AT_BOOT.load(Ordering::Relaxed));
    (elapsed as u128 * 10_000_000 / frequency as u128) as u64
}

/// Hora do sistema no formato NT: 100 ns desde 1601.
pub fn system_time_100ns() -> u64 {
    time::unix_milliseconds_to_nt_time(WALL_CLOCK_MS_AT_BOOT.load(Ordering::Relaxed)) + uptime_100ns()
}

/// Relógio de parede: amostra inicial do RTC + tempo transcorrido.
pub fn now_ms() -> u64 {
    WALL_CLOCK_MS_AT_BOOT.load(Ordering::Relaxed) + uptime_ms()
}

/// Espera ativa até o prazo; não drena tarefas do dispatcher.
pub fn spin_ms(milliseconds: u64) {
    let deadline = uptime_ms() + milliseconds;
    while uptime_ms() < deadline {
        cpu::pause();
    }
}

pub fn tsc_frequency_hz() -> u64 {
    FREQUENCY_HERTZ.load(Ordering::Relaxed)
}
