//! Relógio do kernel baseado no TSC.
//!
//! A frequência vem da folha CPUID 0x15, quando válida, ou de calibração com
//! o PIT. O RTC fornece apenas a referência inicial do relógio de parede.
//! Os cálculos são inteiros: o kernel Rust é compilado sem SSE.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::{cpu, physical, port};
use crate::ntos::inc::types::{Field, LargeInteger, NtStruct};
use crate::rtl::text::fixed1;
use crate::rtl::time;

/// KeQueryTimeIncrement: quantum do timer do LAPIC, 100 Hz = 10 ms =
/// 100000 × 100 ns.
pub const TIME_INCREMENT: u64 = 100_000;

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

/// KeBootTime: a hora do sistema no boot (100 ns desde 1601), a amostra do
/// RTC que serve de origem ao relógio de parede.
pub fn boot_time() -> u64 {
    time::unix_milliseconds_to_nt_time(WALL_CLOCK_MS_AT_BOOT.load(Ordering::Relaxed))
}

/// KeQueryBootTimeValues (RVA 0x317088): (CurrentTime, BootTime,
/// BootTimeBias) lidos juntos. CurrentTime é o KUSER_SHARED_DATA.SystemTime;
/// KeBootTimeBias acumula os ajustes de hora feitos depois do boot, e o
/// OpenNT não ajusta a hora (NtSetSystemTime não existe): zero.
pub fn query_boot_time_values() -> (u64, u64, u64) {
    let current = match crate::ntos::mm::shared_user_data::data() {
        Some(shared) => crate::ntos::mm::shared_user_data::read_shared_time(&shared.system_time),
        None => system_time_100ns(),
    };
    (current, boot_time(), 0)
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

/// Hora do sistema vista pelos drivers: o relógio de parede em milissegundos
/// convertido para 100 ns desde 1601.
fn driver_system_time() -> u64 {
    now_ms() * 10_000 + 116_444_736_000_000_000
}

/// KeQuerySystemTime / KeQuerySystemTimePrecise.
pub fn query_system_time(current_time: u64) {
    // SAFETY: PLARGE_INTEGER CurrentTime do driver.
    unsafe { LargeInteger::at(current_time) }.quad_part.set(driver_system_time() as i64);
}

/// KeQueryTickCount: milissegundos desde o boot.
pub fn query_tick_count(tick_count: u64) {
    // SAFETY: PLARGE_INTEGER TickCount do driver.
    unsafe { LargeInteger::at(tick_count) }.quad_part.set(uptime_ms() as i64);
}

/// KeQueryPerformanceCounter: contador TSC; a frequência sai no ponteiro
/// opcional.
pub fn query_performance_counter(frequency: u64) -> u64 {
    if frequency != 0 {
        // SAFETY: PLARGE_INTEGER PerformanceFrequency opcional do driver.
        unsafe { LargeInteger::at(frequency) }.quad_part.set(tsc_frequency_hz() as i64);
    }
    cpu::rdtsc()
}

/// KeStallExecutionProcessor: espera ocupada medida pelo TSC.
pub fn stall_execution_processor(microseconds: u32) {
    let ticks = tsc_frequency_hz() / 1_000_000 * (microseconds as u64);
    let start = cpu::rdtsc();
    while cpu::rdtsc().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// KeQueryUnbiasedInterruptTime: sem suspensão, unbiased == interrupt time.
pub fn unbiased_interrupt_time() -> u64 {
    uptime_ms() * 10_000
}

/// KeQueryUnbiasedInterruptTimePrecise: o tempo vai para o ponteiro.
pub fn query_unbiased_interrupt_time_precise(time: u64) {
    // SAFETY: PULONG64 do driver.
    unsafe { Field::<u64>::at(time) }.set(uptime_ms() * 10_000);
}

/// KeQueryInterruptTimePrecise(PULONGLONG QpcValue): devolve o tempo de
/// interrupção (100 ns) e grava o contador de desempenho (QPC == TSC, como
/// KeQueryPerformanceCounter) no ponteiro. Mesma fonte de relógio por trás
/// de KeQueryUnbiasedInterruptTimePrecise.
pub fn query_interrupt_time_precise(qpc_value: u64) -> u64 {
    if qpc_value != 0 {
        // SAFETY: PULONGLONG QpcValue opcional do driver.
        unsafe { Field::<u64>::at(qpc_value) }.set(cpu::rdtsc());
    }
    uptime_100ns()
}

// ---- ExQueryTimerResolution -------------------------------------------------
//
// ExQueryTimerResolution (ntoskrnl 19041 rva 0x3cf850)(MaximumTime*,
// MinimumTime*, CurrentTime*): KeMaximumIncrement, KeMinimumIncrement e
// KeTimeIncrement, em unidades de 100 ns. O relógio do OpenNT é o timer do
// LAPIC a 100 Hz fixos (o mesmo incremento de KeQueryTimeIncrement) e não há
// ExSetTimerResolution: máximo, mínimo e corrente são o mesmo período.

/// Período do tick do relógio, em 100 ns (10 ms).
pub const CLOCK_TIME_INCREMENT: u32 = 100_000;

/// ExQueryTimerResolution(MaximumTime*, MinimumTime*, CurrentTime*).
pub fn query_timer_resolution(maximum: &Field<u32>, minimum: &Field<u32>, current: &Field<u32>) {
    maximum.set(CLOCK_TIME_INCREMENT);
    minimum.set(CLOCK_TIME_INCREMENT);
    current.set(CLOCK_TIME_INCREMENT);
}

// ---- ExSetTimerResolution ---------------------------------------------------
//
// ExSetTimerResolution (ntoskrnl 19041 rva 0x5b22d0)(DesiredTime,
// SetResolution) conta os pedidos de resolução do kernel sob
// ExpKernelResolutionLock: o primeiro pedido (ou um mais fino que o vigente)
// grava KeNonHrTimeIncrement e ExpKernelRequestedTimerResolution e chama o
// ExpUpdateTimerResolution (0x35defc); o último cancelamento volta
// KeNonHrTimeIncrement a KeMaximumIncrement e pede a resolução padrão; os
// demais só devolvem KeTimeIncrement. O ExpUpdateTimerResolution limita o
// pedido a [KeMinimumIncrement, KeMaximumIncrement] e só reprograma o
// relógio quando o resultado difere de ExpLastRequestedTime; com o timer do
// LAPIC fixo em 100 Hz os dois limites são o mesmo período, então o relógio
// nunca muda e a resposta é sempre KeTimeIncrement.

/// Estado dos pedidos de resolução do kernel (ExpKernelResolution*).
struct KernelResolution {
    /// ExpKernelResolutionCount.
    count: u32,
    /// ExpKernelRequestedTimerResolution.
    requested: u32,
    /// KeNonHrTimeIncrement.
    non_hr_increment: u32,
    /// ExpLastRequestedTime.
    last_requested: u32,
}

static KERNEL_RESOLUTION: crate::rtl::SpinLock<KernelResolution> = crate::rtl::SpinLock::new(KernelResolution { count: 0, requested: 0, non_hr_increment: CLOCK_TIME_INCREMENT, last_requested: CLOCK_TIME_INCREMENT });

/// ExpUpdateTimerResolution: limita o pedido ao intervalo do relógio e o
/// registra; devolve o KeTimeIncrement resultante.
fn update_timer_resolution(state: &mut KernelResolution, set: bool, desired: u32) -> u32 {
    let wanted = if set { desired } else { CLOCK_TIME_INCREMENT };
    if set && (wanted >= state.last_requested || wanted >= CLOCK_TIME_INCREMENT) {
        return CLOCK_TIME_INCREMENT;
    }
    // cmovb KeMinimumIncrement: o mínimo do relógio é o próprio período.
    state.last_requested = wanted.max(CLOCK_TIME_INCREMENT);
    CLOCK_TIME_INCREMENT
}

/// ExSetTimerResolution(DesiredTime, SetResolution): a resolução do relógio
/// em vigor, em 100 ns.
pub fn set_timer_resolution(desired: u32, set: bool) -> u32 {
    let mut state = KERNEL_RESOLUTION.lock();
    if !set {
        if state.count == 0 {
            return CLOCK_TIME_INCREMENT;
        }
        state.count -= 1;
        if state.count != 0 {
            return CLOCK_TIME_INCREMENT;
        }
        state.non_hr_increment = CLOCK_TIME_INCREMENT;
        state.requested = 0;
        return update_timer_resolution(&mut state, false, 0);
    }
    state.count += 1;
    if state.count != 1 && desired >= state.requested {
        return CLOCK_TIME_INCREMENT;
    }
    state.non_hr_increment = desired;
    state.requested = desired;
    update_timer_resolution(&mut state, true, desired)
}

/// Pedidos de resolução do kernel em vigor, o último valor pedido e o
/// KeNonHrTimeIncrement (ExpKernelResolutionCount,
/// ExpKernelRequestedTimerResolution, KeNonHrTimeIncrement).
pub fn kernel_resolution_requests() -> (u32, u32, u32) {
    let state = KERNEL_RESOLUTION.lock();
    (state.count, state.requested, state.non_hr_increment)
}
