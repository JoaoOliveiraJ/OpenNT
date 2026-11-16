//! Relógio do kernel baseado no TSC.
//!
//! A frequência vem da folha CPUID 0x15, quando ela traz o cristal e a
//! razão; senão é medida contra o timer de gerenciamento de energia do ACPI
//! (o PM_TMR_BLK do FADT, 3,579545 MHz, contador livre), como a calibração
//! do HAL: cada ponta da janela lê o contador entre duas leituras do TSC e
//! fica com a leitura de colchete mais estreito, e a janela é longa (100 ms),
//! então uma CPU virtual tirada de execução pelo hospedeiro no meio da
//! medida não a distorce (os dois relógios andam juntos enquanto ela está
//! parada). Três janelas, e vale a mediana. Sem o timer do ACPI, o canal 0
//! do PIT na mesma forma: contagem lida por latch entre duas leituras do
//! TSC. O RTC fornece apenas a referência inicial do relógio de parede. Os
//! cálculos são inteiros: o kernel Rust é compilado sem SSE.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::{acpi, cpu, physical, port};
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

/// Frequência do timer de gerenciamento de energia do ACPI.
const PM_TIMER_HERTZ: u64 = 3_579_545;
/// Frequência de entrada do PIT 8254.
const PIT_HERTZ: u64 = 1_193_182;
/// Duração de cada janela de calibração, em ms.
const CALIBRATION_WINDOW_MS: u64 = 100;
/// Janelas de calibração (vale a mediana).
const CALIBRATION_WINDOWS: usize = 3;
/// Leituras de colchete por ponta de janela (fica a mais estreita).
const BRACKET_TRIES: usize = 16;

/// Um contador de referência livre: lê o valor corrente, a largura em bits
/// e a frequência; o valor sobe (o PIT, que desce, é invertido na leitura).
#[derive(Clone, Copy)]
enum Reference {
    /// ACPI PM timer: porta e largura (24 ou 32 bits, FADT.TMR_VAL_EXT).
    PmTimer { port: u16, bits: u32 },
    /// Canal 0 do PIT em modo 2 com recarga 0x10000 (16 bits).
    Pit,
}

impl Reference {
    fn hertz(self) -> u64 {
        match self {
            Reference::PmTimer { .. } => PM_TIMER_HERTZ,
            Reference::Pit => PIT_HERTZ,
        }
    }

    fn bits(self) -> u32 {
        match self {
            Reference::PmTimer { bits, .. } => bits,
            Reference::Pit => 16,
        }
    }

    fn read(self) -> u64 {
        match self {
            Reference::PmTimer { port, bits } => port::read32(port) as u64 & ((1u64 << bits) - 1),
            Reference::Pit => {
                // Latch do canal 0 e leitura byte baixo/alto; a contagem desce.
                port::write8(0x43, 0x00);
                let low = port::read8(0x40) as u64;
                let high = port::read8(0x40) as u64;
                0xFFFF - ((high << 8) | low)
            }
        }
    }

    /// Diferença `later - earlier` no módulo do contador.
    fn delta(self, earlier: u64, later: u64) -> u64 {
        later.wrapping_sub(earlier) & ((1u64 << self.bits()) - 1)
    }
}

/// O timer do ACPI pelo FADT: PM_TMR_BLK (+76), PM_TMR_LEN (+91) e
/// TMR_VAL_EXT (bit 8 das flags em +112).
fn pm_timer_reference() -> Option<Reference> {
    let fadt = acpi::get_table("FACP", 0, false)?;
    let bytes = &fadt.bytes;
    if bytes.len() < 116 {
        return None;
    }
    let port = u32::from_le_bytes(bytes[76..80].try_into().ok()?);
    let length = bytes[91];
    let flags = u32::from_le_bytes(bytes[112..116].try_into().ok()?);
    if port == 0 || port > 0xFFFC || length < 4 {
        return None;
    }
    Some(Reference::PmTimer { port: port as u16, bits: if flags & (1 << 8) != 0 { 32 } else { 24 } })
}

/// Uma leitura do contador entre duas do TSC: (TSC no meio do colchete,
/// valor), da tentativa de colchete mais estreito.
fn bracketed_sample(reference: Reference) -> (u64, u64) {
    let mut best = (u64::MAX, 0u64, 0u64);
    for _ in 0..BRACKET_TRIES {
        let before = cpu::rdtsc();
        let value = reference.read();
        let after = cpu::rdtsc();
        let width = after.wrapping_sub(before);
        if width < best.0 {
            best = (width, before + width / 2, value);
        }
    }
    (best.1, best.2)
}

/// Uma janela: TSC e contador nas duas pontas, com o contador andando
/// `CALIBRATION_WINDOW_MS` entre elas (em passos menores que meia volta,
/// para atravessar as voltas de um contador curto).
fn measure_window(reference: Reference) -> u64 {
    let target = reference.hertz() * CALIBRATION_WINDOW_MS / 1000;
    let half_turn = 1u64 << (reference.bits() - 1);
    let (start_tsc, start_value) = bracketed_sample(reference);
    let mut elapsed = 0u64;
    let mut last = start_value;
    while elapsed < target {
        let now = reference.read();
        let step = reference.delta(last, now);
        if step < half_turn {
            elapsed += step;
            last = now;
        }
        core::hint::spin_loop();
    }
    let (end_tsc, end_value) = bracketed_sample(reference);
    let counted = elapsed + reference.delta(last, end_value);
    if counted == 0 {
        return 0;
    }
    (end_tsc.wrapping_sub(start_tsc) as u128 * reference.hertz() as u128 / counted as u128) as u64
}

/// A mediana de `CALIBRATION_WINDOWS` janelas contra `reference`.
fn calibrate_against(reference: Reference) -> u64 {
    if let Reference::Pit = reference {
        // Canal 0, byte baixo/alto, modo 2 (gerador de taxa), recarga 0x10000.
        port::write8(0x43, 0x34);
        port::write8(0x40, 0);
        port::write8(0x40, 0);
    }
    let mut samples = [0u64; CALIBRATION_WINDOWS];
    for sample in samples.iter_mut() {
        *sample = measure_window(reference);
    }
    if let Reference::Pit = reference {
        // De volta ao modo 0 (um disparo só), como o canal ficava antes.
        port::write8(0x43, 0x30);
        port::write8(0x40, 0xFF);
        port::write8(0x40, 0xFF);
    }
    samples.sort_unstable();
    samples[CALIBRATION_WINDOWS / 2]
}

/// A frequência do TSC pela folha CPUID 0x15 (cristal × razão), quando a
/// folha traz os três valores.
fn cpuid_frequency() -> u64 {
    // Folhas não suportadas podem devolver dados da última folha existente.
    let maximum_basic_leaf = cpu::cpuid(0)[0];
    let leaf = if maximum_basic_leaf >= 0x15 { cpu::cpuid(0x15) } else { [0; 4] };
    if leaf[2] != 0 && leaf[0] != 0 && leaf[1] != 0 {
        leaf[2] as u64 * leaf[1] as u64 / leaf[0] as u64
    } else {
        0
    }
}

/// Mede de novo a frequência do TSC contra a mesma referência do boot (o
/// timer do ACPI ou o PIT): o autoteste confere que ela concorda com a do
/// boot. `None` quando o boot usou a folha CPUID 0x15.
pub fn remeasure_tsc_frequency() -> Option<u64> {
    if cpuid_frequency() != 0 {
        return None;
    }
    Some(calibrate_against(pm_timer_reference().unwrap_or(Reference::Pit)))
}

/// Descobre ou mede a frequência, captura as referências de boot e publica
/// os valores usados pelo caminho nativo de atualização de tempo.
pub fn init() {
    let mut frequency = cpuid_frequency();
    if frequency == 0 {
        let (reference, name) = match pm_timer_reference() {
            Some(reference) => (reference, "timer do ACPI"),
            None => (Reference::Pit, "PIT"),
        };
        debug_print!("[clock] CPUID.15 ausente — calibrando TSC contra o {}", name);
        frequency = calibrate_against(reference).max(1);
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

/// O KeStallExecutionProcessor dos drivers: a mesma espera ocupada, com as
/// interrupções de dispositivo e as DPCs que o NT entregaria durante ela
/// (`interrupt_object::service_during_stall`).
pub fn stall_execution_processor_for_driver(microseconds: u32) {
    let ticks = tsc_frequency_hz() / 1_000_000 * (microseconds as u64);
    let start = cpu::rdtsc();
    loop {
        super::interrupt_object::service_during_stall();
        if cpu::rdtsc().wrapping_sub(start) >= ticks {
            break;
        }
        core::hint::spin_loop();
    }
}

/// KeQueryUnbiasedInterruptTime: sem suspensão, unbiased == interrupt time.
pub fn unbiased_interrupt_time() -> u64 {
    uptime_ms() * 10_000
}

/// KeQueryUnbiasedInterruptTimePrecise(PULONG64 QpcTimeStamp), como o do
/// ntoskrnl 19041 (rva 0x2e09e0): devolve o tempo de interrupção sem
/// suspensão (100 ns) e grava no ponteiro o contador de desempenho lido
/// junto (QPC == TSC, como KeQueryPerformanceCounter).
pub fn query_unbiased_interrupt_time_precise(qpc_time_stamp: u64) -> u64 {
    if qpc_time_stamp != 0 {
        // SAFETY: PULONG64 do driver.
        unsafe { Field::<u64>::at(qpc_time_stamp) }.set(cpu::rdtsc());
    }
    uptime_100ns()
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
