//! O relógio do kernel: o contador de desempenho (QPC) sobre o TSC, o tempo
//! de interrupção, a hora do sistema e a atualização da KUSER_SHARED_DATA
//! que o tick do relógio faz no NT.
//!
//! A frequência do TSC vem da folha CPUID 0x15, quando ela traz o cristal e
//! a razão; senão é medida contra o timer de gerenciamento de energia do
//! ACPI (o PM_TMR_BLK do FADT, 3,579545 MHz, contador livre), como a
//! calibração do HAL: cada ponta da janela lê o contador entre duas leituras
//! do TSC e fica com a leitura de colchete mais estreito, e a janela é longa
//! (100 ms), então uma CPU virtual tirada de execução pelo hospedeiro no
//! meio da medida não a distorce (os dois relógios andam juntos enquanto ela
//! está parada). Três janelas, e vale a mediana. Sem o timer do ACPI, o
//! canal 0 do PIT na mesma forma: contagem lida por latch entre duas
//! leituras do TSC. Os cálculos são inteiros: o kernel Rust é compilado sem
//! SSE.
//!
//! O QPC é o do HAL 19041 com o TSC como contador de desempenho (o timer de
//! tipo 5, com a página de referência do HalpTimerCreateReferencePage):
//! KeQueryPerformanceCounter = alto(TSC × TscScale) + QpcBias, com
//! TscScale = 10^7 × 2^64 / frequência do TSC (o RtlUdiv128 da página) e
//! frequência fixa de 10 MHz. O QpcBias da KUSER_SHARED_DATA põe o contador
//! em zero na inicialização do relógio, então o QPC conta unidades de 100 ns
//! desde o boot: é o tempo de interrupção.
//!
//! O tick do relógio (KiUpdateTime/KeUpdateSystemTime) é o laço de
//! [`update_shared_times`]: a cada KeTimeIncrement de tempo de interrupção,
//! InterruptTime e SystemTime da KUSER_SHARED_DATA avançam do incremento, as
//! linhas de base QPC acompanham (BaselineSystemTimeQpc e
//! BaselineInterruptTimeQpc, sob o TimeUpdateLock) e o KiTickOffset desconta
//! o incremento; quando ele chega a zero o TickCount soma um e o KiTickOffset
//! volta a KeMaximumIncrement — o TickCount conta períodos de
//! KeMaximumIncrement (15,625 ms), qualquer que seja a resolução corrente.
//! As leituras precisas (RtlGetSystemTimePrecise, RtlGetInterruptTimePrecise)
//! somam ao valor do último tick o QPC decorrido desde a linha de base, pelo
//! QpcSystemTimeIncrement (2^63 com deslocamento 1 a 10 MHz: um tick de QPC
//! é 100 ns).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::hal::{acpi, cpu, port};
use crate::ntos::inc::types::{Field, KuserSharedData, LargeInteger, NtStruct};
use crate::rtl::text::fixed1;
use crate::rtl::SpinLock;

/// Frequência do QPC: o TSC escalado pela página de referência (10 MHz).
pub const QPC_FREQUENCY: u64 = 10_000_000;
/// KeMaximumIncrement e KeMinimumIncrement do KiSetupTimeIncrement 19041
/// (os limites do relógio do HAL, 15,625 ms e 0,5 ms, em 100 ns).
pub const MAXIMUM_INCREMENT: u32 = 156_250;
pub const MINIMUM_INCREMENT: u32 = 5_000;
/// TscSequence da página de referência do HAL ('HalT').
pub const REFERENCE_PAGE_SEQUENCE: u32 = 0x546C_6148;
/// QpcSystemTimeIncrement e o deslocamento a 10 MHz
/// (RtlGenerateQpcToIncrementConstants(10^7): 1,0 em 2^64 não cabe, então
/// 2^63 com deslocamento 1).
const QPC_TIME_INCREMENT: u64 = 1 << 63;
const QPC_TIME_INCREMENT_SHIFT: u8 = 1;

/// Frequência do TSC.
static FREQUENCY_HERTZ: AtomicU64 = AtomicU64::new(0);
/// TscScale da página de referência.
static TSC_SCALE: AtomicU64 = AtomicU64::new(0);
/// KUSER_SHARED_DATA.QpcBias (o contador em zero no boot).
static QPC_BIAS: AtomicU64 = AtomicU64::new(0);
/// A hora do sistema no QPC zero: SystemTime = deslocamento + tempo de
/// interrupção (cada KeSetSystemTime o refaz).
static SYSTEM_TIME_OFFSET: AtomicU64 = AtomicU64::new(0);
/// KeBootTime e KeBootTimeBias.
static BOOT_TIME: AtomicU64 = AtomicU64::new(0);
static BOOT_TIME_BIAS: AtomicU64 = AtomicU64::new(0);
/// KeTimeIncrement: o incremento corrente do relógio (100 ns).
static TIME_INCREMENT: AtomicU32 = AtomicU32::new(MAXIMUM_INCREMENT);

/// Estado do tick do relógio (o que o KiUpdateTime guarda entre ticks).
struct Tick {
    /// Tempo de interrupção do último tick (o QPC dele).
    interrupt_time: u64,
    /// KiTickOffset: o que falta do período de KeMaximumIncrement corrente.
    tick_offset: i64,
    /// TickCount.
    tick_count: u64,
    /// Linha de base da hora do sistema (BaselineSystemTimeQpc) e a hora
    /// do sistema publicada nela.
    system_baseline: u64,
    system_time: u64,
}

static TICK: SpinLock<Tick> = SpinLock::new(Tick { interrupt_time: 0, tick_offset: MAXIMUM_INCREMENT as i64, tick_count: 0, system_baseline: 0, system_time: 0 });

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

/// alto(TSC × TscScale): o TSC em unidades de 100 ns.
fn scaled(tsc: u64) -> u64 {
    ((tsc as u128 * TSC_SCALE.load(Ordering::Relaxed) as u128) >> 64) as u64
}

/// Descobre ou mede a frequência, monta a escala da página de referência,
/// zera o QPC e toma a hora do relógio da CMOS como hora do sistema. Na
/// fase 0 o fuso ainda não foi lido: como no NT, a data do relógio entra
/// como está e a fase 1 a corrige ([`crate::ntos::ex::time_zone::initialize`]).
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
    // RtlUdiv128(10^7 << 64, frequência): cabe em 64 bits com TSC > 10 MHz.
    let scale = ((QPC_FREQUENCY as u128) << 64) / frequency.max(QPC_FREQUENCY + 1) as u128;
    TSC_SCALE.store(scale as u64, Ordering::Relaxed);
    QPC_BIAS.store(0u64.wrapping_sub(scaled(cpu::rdtsc_ordered())), Ordering::Relaxed);

    let rtc = crate::hal::rtc::read();
    let fields = crate::ntos::rtl::time::Fields { year: rtc.year as i16, month: rtc.month as i16, day: rtc.day as i16, hour: rtc.hour as i16, minute: rtc.minute as i16, second: rtc.second as i16, milliseconds: rtc.milliseconds as i16, weekday: rtc.weekday as i16 };
    let boot = crate::ntos::rtl::time::fields_to_time(&fields).unwrap_or(0) as u64;
    let now = query_performance_counter_value();
    SYSTEM_TIME_OFFSET.store(boot.wrapping_sub(now), Ordering::Relaxed);
    BOOT_TIME.store(boot, Ordering::Relaxed);
    BOOT_TIME_BIAS.store(0, Ordering::Relaxed);
    {
        let mut tick = TICK.lock();
        tick.system_baseline = now;
        tick.system_time = boot;
    }
    debug_print!("[clock] TSC = {} MHz; relogio CMOS {:04}-{:02}-{:02} {:02}:{:02}:{:02}", fixed1(frequency, 1_000_000), rtc.year, rtc.month, rtc.day, rtc.hour, rtc.minute, rtc.second);
}

/// O contador de desempenho (KeQueryPerformanceCounter): alto(TSC ×
/// TscScale) + QpcBias, com o TSC lido na ordem das instruções anteriores
/// (`cpu::rdtsc_ordered`, o QueryCounter do temporizador TSC do NT): um
/// valor que outra CPU publicou antes nunca é maior que o lido depois.
pub fn query_performance_counter_value() -> u64 {
    scaled(cpu::rdtsc_ordered()).wrapping_add(QPC_BIAS.load(Ordering::Relaxed))
}

/// Unidades de 100 ns desde o boot (o QPC a 10 MHz: o tempo de interrupção
/// preciso).
pub fn uptime_100ns() -> u64 {
    query_performance_counter_value()
}

/// Milissegundos desde o boot.
pub fn uptime_ms() -> u64 {
    uptime_100ns() / 10_000
}

/// Hora do sistema no formato NT (100 ns desde 1601), precisa.
pub fn system_time_100ns() -> u64 {
    SYSTEM_TIME_OFFSET.load(Ordering::Relaxed).wrapping_add(uptime_100ns())
}

/// Relógio de parede em milissegundos Unix.
pub fn now_ms() -> u64 {
    crate::rtl::time::nt_time_to_unix_milliseconds(system_time_100ns())
}

/// KeBootTime: a hora do sistema do boot (refeita pela correção do fuso na
/// fase 1 e deslocada por cada acerto de hora).
pub fn boot_time() -> u64 {
    BOOT_TIME.load(Ordering::Relaxed)
}

/// KeBootTimeBias: a soma dos acertos de hora depois do boot.
pub fn boot_time_bias() -> u64 {
    BOOT_TIME_BIAS.load(Ordering::Relaxed)
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

/// TscScale da página de referência (10^7 × 2^64 / frequência do TSC).
pub fn tsc_scale() -> u64 {
    TSC_SCALE.load(Ordering::Relaxed)
}

/// QpcBias da KUSER_SHARED_DATA.
pub fn qpc_bias() -> u64 {
    QPC_BIAS.load(Ordering::Relaxed)
}

/// KeTimeIncrement corrente.
pub fn time_increment() -> u32 {
    TIME_INCREMENT.load(Ordering::Relaxed)
}

/// HalSetTimeIncrement do ExpUpdateTimerConfiguration: o relógio passa a
/// avançar `increment` (já limitado a [KeMinimumIncrement,
/// KeMaximumIncrement]) por tick; devolve o incremento em vigor.
pub fn set_time_increment(increment: u32) -> u32 {
    let increment = increment.clamp(MINIMUM_INCREMENT, MAXIMUM_INCREMENT);
    TIME_INCREMENT.store(increment, Ordering::Relaxed);
    increment
}

// ---- KUSER_SHARED_DATA ------------------------------------------------------

fn shared() -> Option<&'static KuserSharedData> {
    crate::ntos::mm::shared_user_data::data()
}

/// Protocolo do KSYSTEM_TIME: High2Time, LowPart e por último High1Time.
fn write_shared_time(time: &crate::ntos::inc::types::KsystemTime, value: u64) {
    let high = (value >> 32) as i32;
    time.high2_time.set(high);
    time.low_part.set(value as u32);
    time.high1_time.set(high);
}

/// A publicação de um tick (ou de um acerto de hora) sob o TimeUpdateLock:
/// ímpar durante a escrita, par depois.
fn publish(data: &KuserSharedData, tick: &Tick) {
    let lock = data.time_update_lock.atomic();
    lock.fetch_add(1, Ordering::SeqCst);
    write_shared_time(&data.interrupt_time, tick.interrupt_time.wrapping_add(data.interrupt_time_bias.get()));
    data.baseline_interrupt_time_qpc.set(tick.interrupt_time);
    write_shared_time(&data.system_time, tick.system_time);
    data.baseline_system_time_qpc.set(tick.system_baseline);
    write_shared_time(&data.tick_count, tick.tick_count);
    data.tick_count_low_deprecated.set(tick.tick_count as u32);
    lock.fetch_add(1, Ordering::SeqCst);
}

/// Os campos constantes do relógio na KUSER_SHARED_DATA (KiSetupTimeIncrement
/// e HalpTimerConfigureQpcBypass): QpcFrequency, os incrementos QPC→tempo,
/// TickCountMultiplier = KeMaximumIncrement × 2^24 / 10000, QpcBias e o
/// atalho do TSC em modo usuário (QpcBypassEnabled com a página de
/// referência e o modo de leitura do TSC, QpcShift zero).
pub fn publish_shared_constants(data: &KuserSharedData) {
    data.qpc_frequency.set(QPC_FREQUENCY as i64);
    data.qpc_system_time_increment.set(QPC_TIME_INCREMENT);
    data.qpc_interrupt_time_increment.set(QPC_TIME_INCREMENT);
    data.qpc_system_time_increment_shift.set(QPC_TIME_INCREMENT_SHIFT);
    data.qpc_interrupt_time_increment_shift.set(QPC_TIME_INCREMENT_SHIFT);
    data.tick_count_multiplier.set((((MAXIMUM_INCREMENT as u64) << 24) / 10_000) as u32);
    data.qpc_bias.set(qpc_bias());
    data.qpc_data.set(qpc_bypass_flags() as u16);
    let tick = TICK.lock();
    publish(data, &tick);
}

/// QpcBypassEnabled do HalpTimerConfigureQpcBypass para o TSC com a página
/// de referência: QPC_BYPASS_ENABLED (1) | USE_HV_PAGE (2) e a leitura do
/// TSC — RDTSCP (0x80) quando o processador tem, senão LFENCE (0x20) na
/// Intel ou MFENCE (0x10) na AMD antes do RDTSC.
pub fn qpc_bypass_flags() -> u8 {
    const QPC_BYPASS_ENABLED: u8 = 0x01;
    const QPC_BYPASS_USE_HV_PAGE: u8 = 0x02;
    const QPC_BYPASS_USE_MFENCE: u8 = 0x10;
    const QPC_BYPASS_USE_LFENCE: u8 = 0x20;
    const QPC_BYPASS_USE_RDTSCP: u8 = 0x80;
    // A mesma leitura do contador do kernel.
    let read = match cpu::tsc_read_method() {
        cpu::TscRead::Rdtscp => QPC_BYPASS_USE_RDTSCP,
        cpu::TscRead::Lfence => QPC_BYPASS_USE_LFENCE,
        cpu::TscRead::Mfence => QPC_BYPASS_USE_MFENCE,
    };
    QPC_BYPASS_ENABLED | QPC_BYPASS_USE_HV_PAGE | read
}

/// O tick do relógio: se passou ao menos um KeTimeIncrement desde o último,
/// avança InterruptTime, SystemTime e o KiTickOffset dos incrementos
/// inteiros decorridos, conta os TickCounts dos períodos de
/// KeMaximumIncrement completados e publica. Uma CPU por vez (as outras
/// voltam: o tick é do dono do relógio).
pub fn update_shared_times() {
    let Some(data) = shared() else { return };
    let Some(mut tick) = TICK.try_lock() else { return };
    let now = uptime_100ns();
    let increment = time_increment() as u64;
    if now < tick.interrupt_time.wrapping_add(increment) {
        return;
    }
    let advanced = (now - tick.interrupt_time) / increment * increment;
    tick.interrupt_time += advanced;
    tick.tick_offset -= advanced as i64;
    if tick.tick_offset <= 0 {
        let periods = (-tick.tick_offset) as u64 / MAXIMUM_INCREMENT as u64 + 1;
        tick.tick_count += periods;
        tick.tick_offset += (periods * MAXIMUM_INCREMENT as u64) as i64;
    }
    tick.system_baseline = tick.interrupt_time;
    tick.system_time = SYSTEM_TIME_OFFSET.load(Ordering::Relaxed).wrapping_add(tick.interrupt_time);
    publish(data, &tick);
}

/// Leitura do KSYSTEM_TIME: High1Time, LowPart, High2Time, repetida enquanto
/// as duas metades altas diferem (atualização no meio).
pub fn read_shared_time(time: &crate::ntos::inc::types::KsystemTime) -> u64 {
    loop {
        let high = time.high1_time.get();
        let low = time.low_part.get();
        if high == time.high2_time.get() {
            return (high as u32 as u64) << 32 | low as u64;
        }
    }
}

/// KUSER_SHARED_DATA.SystemTime (o valor do último tick).
pub fn shared_system_time() -> i64 {
    match shared() {
        Some(data) => read_shared_time(&data.system_time) as i64,
        None => system_time_100ns() as i64,
    }
}

/// O valor do último tick mais o QPC decorrido desde a linha de base, como o
/// RtlGetSystemTimePrecise e o RtlGetInterruptTimePrecise: sob o
/// TimeUpdateLock par, lê o tempo e a linha de base, lê o QPC e confere que
/// o lock não mudou; soma alto(((QPC − base − 1) << deslocamento) ×
/// incremento) quando o QPC passou da base. Devolve (tempo, QPC lido).
fn precise(data: &KuserSharedData, interrupt: bool) -> (u64, u64) {
    loop {
        let stamp = data.time_update_lock.get();
        if stamp & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let (base_time, baseline, increment, shift) = if interrupt {
            (read_shared_time(&data.interrupt_time), data.baseline_interrupt_time_qpc.get(), data.qpc_interrupt_time_increment.get(), data.qpc_interrupt_time_increment_shift.get())
        } else {
            (read_shared_time(&data.system_time), data.baseline_system_time_qpc.get(), data.qpc_system_time_increment.get(), data.qpc_system_time_increment_shift.get())
        };
        let counter = query_performance_counter_value();
        if data.time_update_lock.get() != stamp {
            core::hint::spin_loop();
            continue;
        }
        let elapsed = if counter > baseline { (((counter - baseline - 1) << shift) as u128 * increment as u128 >> 64) as u64 } else { 0 };
        return (base_time.wrapping_add(elapsed), counter);
    }
}

/// RtlGetSystemTimePrecise / KeQuerySystemTimePrecise.
pub fn system_time_precise() -> u64 {
    match shared() {
        Some(data) => precise(data, false).0,
        None => system_time_100ns(),
    }
}

/// KeQuerySystemTime: a hora do último tick (KUSER_SHARED_DATA.SystemTime).
pub fn query_system_time(current_time: u64) {
    // SAFETY: PLARGE_INTEGER CurrentTime do driver.
    unsafe { LargeInteger::at(current_time) }.quad_part.set(shared_system_time());
}

/// KeQuerySystemTimePrecise(CurrentTime*).
pub fn query_system_time_precise(current_time: u64) {
    // SAFETY: PLARGE_INTEGER CurrentTime do driver.
    unsafe { LargeInteger::at(current_time) }.quad_part.set(system_time_precise() as i64);
}

/// KeQueryTickCount: o TickCount da KUSER_SHARED_DATA (períodos de
/// KeQueryTimeIncrement).
pub fn query_tick_count(tick_count: u64) {
    let ticks = shared().map_or(0, |data| read_shared_time(&data.tick_count));
    // SAFETY: PLARGE_INTEGER TickCount do driver.
    unsafe { LargeInteger::at(tick_count) }.quad_part.set(ticks as i64);
}

/// KeQueryPerformanceCounter: o QPC; a frequência (10 MHz) sai no ponteiro
/// opcional.
pub fn query_performance_counter(frequency: u64) -> u64 {
    if frequency != 0 {
        // SAFETY: PLARGE_INTEGER PerformanceFrequency opcional do driver.
        unsafe { LargeInteger::at(frequency) }.quad_part.set(QPC_FREQUENCY as i64);
    }
    query_performance_counter_value()
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

/// KeQueryUnbiasedInterruptTime (rva 0x35ade0): InterruptTime do último
/// tick menos InterruptTimeBias (o tempo dormido; zero sem suspensão).
pub fn unbiased_interrupt_time() -> u64 {
    match shared() {
        Some(data) => read_shared_time(&data.interrupt_time).wrapping_sub(data.interrupt_time_bias.get()),
        None => uptime_100ns(),
    }
}

/// KeQueryInterruptTimePrecise(PULONGLONG QpcValue) (rva 0x318820, o
/// RtlGetInterruptTimePrecise): o tempo de interrupção preciso; o QPC lido
/// junto sai no ponteiro.
pub fn query_interrupt_time_precise(qpc_value: u64) -> u64 {
    let (time, counter) = match shared() {
        Some(data) => precise(data, true),
        None => (uptime_100ns(), query_performance_counter_value()),
    };
    if qpc_value != 0 {
        // SAFETY: PULONGLONG QpcValue do driver.
        unsafe { Field::<u64>::at(qpc_value) }.set(counter);
    }
    time
}

/// KeQueryUnbiasedInterruptTimePrecise(PULONG64 QpcTimeStamp): o mesmo
/// tempo preciso sem o InterruptTimeBias.
pub fn query_unbiased_interrupt_time_precise(qpc_time_stamp: u64) -> u64 {
    let bias = shared().map_or(0, |data| data.interrupt_time_bias.get());
    query_interrupt_time_precise(qpc_time_stamp).wrapping_sub(bias)
}

/// KeQueryBootTimeValues (RVA 0x317088): (CurrentTime, BootTime,
/// BootTimeBias) lidos juntos; CurrentTime é o KUSER_SHARED_DATA.SystemTime.
pub fn query_boot_time_values() -> (u64, u64, u64) {
    (shared_system_time() as u64, boot_time(), boot_time_bias())
}

// ---- KeSetSystemTime --------------------------------------------------------
//
// KeSetSystemTime(NewTime, OldTime, Flags, HalTimeFields) do 19041 (rva
// 0x3a7348) roda o KiSetSystemTimeDpc em todas as CPUs: OldTime recebe o
// SystemTime corrente, o delta é NewTime − OldTime e o KiUpdateSystemTime
// publica SystemTime = SystemTime + delta com a linha de base no QPC do
// momento, sob o TimeUpdateLock. Sem flags, KeBootTime e KeBootTimeBias
// somam o delta; com o bit 2 (a correção do fuso na fase 1) KeBootTime passa
// a ser a hora nova e KeBootTimeBias zera. O bit 0 (ajustar o tempo de
// interrupção) não tem chamador que o OpenNT atenda e é ignorado. Os timers
// absolutos (`ke::timer`, `ke::timer2`) se comparam à hora corrente, então
// vencem pela hora nova sem ajuste (o KiAdjustTimerDueTimes).

/// KeSetSystemTime: devolve a hora anterior (o SystemTime do último tick).
pub fn set_system_time(new_time: u64, flags: u32) -> u64 {
    const BOOT_TIME_RESET: u32 = 4;
    let mut tick = TICK.lock();
    let old = shared_system_time() as u64;
    let delta = new_time.wrapping_sub(old);
    let counter = query_performance_counter_value();
    SYSTEM_TIME_OFFSET.store(new_time.wrapping_sub(counter), Ordering::Relaxed);
    tick.system_baseline = counter;
    tick.system_time = new_time;
    if flags & BOOT_TIME_RESET != 0 {
        BOOT_TIME.store(new_time, Ordering::Relaxed);
        BOOT_TIME_BIAS.store(0, Ordering::Relaxed);
    } else {
        BOOT_TIME.fetch_add(delta, Ordering::Relaxed);
        BOOT_TIME_BIAS.fetch_add(delta, Ordering::Relaxed);
    }
    if let Some(data) = shared() {
        publish(data, &tick);
    }
    old
}
