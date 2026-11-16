//! Autoteste do relógio (`hal/rtc.rs`, `ke/clock.rs`, `ex/time_zone.rs`,
//! `ex/system_time.rs`, `ex/timer_resolution.rs`), pelos exports do
//! ntoskrnl (trampolins nativos, ABI MS x64):
//!
//! - o relógio da CMOS contra a hora do sistema (a hora local do relógio
//!   mais o viés do fuso lido do Registro), o HalQueryRealTimeClock e a
//!   linha `[time] ... UTC=` que o test-boot compara com o relógio do
//!   hospedeiro;
//! - o fuso calculado dos valores do Registro (viés, TIME_ZONE_ID_UNKNOWN
//!   sem datas de troca, a KUSER_SHARED_DATA com TimeZoneBias, TimeZoneId,
//!   o carimbo e TimeZoneBiasEffectiveEnd no ano novo − 1 ms), as conversões
//!   Ex/Rtl de hora local, as classes 44, 102, 124 e 197 do
//!   ZwQuerySystemInformation e a troca de fuso pelo ZwSetSystemInformation
//!   (um fuso com horário de verão e a volta ao da máquina);
//! - datas de troca do RtlCutoverTimeToSystemTime contra o calendário (as
//!   regras de horário de verão dos EUA em 2026: 8 de março e 1º de
//!   novembro; o último domingo de outubro de 2026, dia 25) e os segundos
//!   desde 1970/1980;
//! - o tick da KUSER_SHARED_DATA (TickCount = InterruptTime /
//!   KeMaximumIncrement, TickCountMultiplier, os incrementos QPC, o QPC de
//!   10 MHz e o atalho do modo usuário anunciado) e a monotonicidade do QPC
//!   entre CPUs (o BSP e um AP leem ao mesmo tempo e publicam o maior valor
//!   visto: nenhum lê um QPC menor que um já publicado);
//! - o ZwSetSystemTime ida e volta (KeBootTime e KeBootTimeBias, o relógio
//!   da CMOS reescrito, o ExCbSetSystemTime só com os callouts do win32k,
//!   hora inválida) e o pedido de releitura (NULL);
//! - a resolução do relógio: ZwQueryTimerResolution, os pedidos do processo
//!   pelo ZwSetTimerResolution e os do kernel pelo ExSetTimerResolution.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::rtc;
use crate::ntos::ex::{time_zone, timer_resolution};
use crate::ntos::inc::types::{Eprocess, KuserSharedData, NtStruct};
use crate::ntos::ke::{clock, smp};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::shared_user_data;
use crate::ntos::rtl::time::{self, Fields};

type Assert = fn(bool, &str);

const SECOND: i64 = 10_000_000;
const MINUTE: i64 = 60 * SECOND;

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(0xDEAD_DEAD_DEAD_DEAD)
}

fn status(name: &str, arguments: &[u64]) -> u32 {
    call(name, arguments) as u32
}

fn shared() -> Option<&'static KuserSharedData> {
    shared_user_data::data()
}

fn dword_value(name: &str) -> Option<u32> {
    crate::ntos::cm::registry::read_value_by_path(time_zone::TIME_ZONE_KEY, name).filter(|value| value.value_type == 4).map(|value| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
}

fn binary_value(name: &str) -> Option<Fields> {
    crate::ntos::cm::registry::read_value_by_path(time_zone::TIME_ZONE_KEY, name).filter(|value| value.value_type == 3).map(|value| Fields::from_bytes(&value.data))
}

/// KeQuerySystemTimePrecise pelo trampolim.
fn precise_now(block: u64) -> i64 {
    call("KeQuerySystemTimePrecise", &[block]);
    guest::read64(block) as i64
}

/// A hora local do relógio da CMOS.
fn cmos_local() -> i64 {
    let now = rtc::read();
    time::fields_to_time(&Fields { year: now.year as i16, month: now.month as i16, day: now.day as i16, hour: now.hour as i16, minute: now.minute as i16, second: now.second as i16, milliseconds: now.milliseconds as i16, weekday: 0 }).unwrap_or(0)
}

/// O viés esperado dos valores do Registro: sem datas de troca, Bias.
fn registry_bias() -> Option<i64> {
    let bias = dword_value("Bias")? as i32 as i64;
    let standard = binary_value("StandardStart")?;
    let daylight = binary_value("DaylightStart")?;
    (standard.month == 0 || daylight.month == 0).then_some(bias * MINUTE)
}

fn rtc_and_zone(assert: Assert, block: u64) {
    let Some(bias) = registry_bias() else {
        assert(false, "time: TimeZoneInformation do Registro com Bias e as datas de troca");
        return;
    };
    assert(time_zone::time_zone_bias() == bias && time_zone::time_zone_id() == time_zone::TIME_ZONE_ID_UNKNOWN && !time_zone::real_time_is_universal() && dword_value("ActiveTimeBias") == Some((bias / MINUTE) as u32), "time: o vies do fuso e o Bias do Registro (sem troca: TIME_ZONE_ID_UNKNOWN) e o ActiveTimeBias acompanha");
    let now = precise_now(block);
    let universal = cmos_local() + bias;
    assert((now - universal).abs() <= 2 * SECOND, "time: o relogio da CMOS (hora local) mais o vies e a hora do sistema, a menos de 2 s");
    crate::debug_print!("[time] autoteste: hora do sistema UTC={}", crate::rtl::time::nt_time_to_unix_milliseconds(now as u64));
    // HalQueryRealTimeClock: os campos da hora local, milissegundos 500.
    let fields = block + 0x40;
    let hal = call("HalQueryRealTimeClock", &[fields]) & 0xFF;
    // SAFETY: TIME_FIELDS de saída no bloco do teste.
    let read = Fields::read(unsafe { crate::ntos::inc::types::TimeFields::at(fields) });
    let local = time::fields_to_time(&read).unwrap_or(0);
    assert(hal == 1 && read.milliseconds == 500 && (local - cmos_local()).abs() <= SECOND && call("ExRealTimeIsUniversal", &[]) & 0xFF == 0, "time: HalQueryRealTimeClock devolve a hora local da CMOS e ExRealTimeIsUniversal e FALSE");
    // Os formatos do relógio: com o registrador B em binário e 12 horas (o
    // chip converte na leitura), a mesma data.
    let format = rtc::cmos_read(0x0B);
    let in_bcd = cmos_local();
    rtc::cmos_write(0x0B, (format | 0x04) & !0x02);
    let in_binary_12h = cmos_local();
    let raw_hour = rtc::cmos_read(0x04);
    rtc::cmos_write(0x0B, format);
    let pm_flag = (raw_hour & 0x80 != 0) == (time::time_to_fields(in_binary_12h).hour >= 12);
    assert(format & 0x06 == 0x02 && (in_binary_12h - in_bcd).abs() <= SECOND && pm_flag && (cmos_local() - in_bcd).abs() <= SECOND, "time: a CMOS lida em BCD de 24 horas e em binario de 12 horas (bit PM) da a mesma hora");
    // KUSER_SHARED_DATA.
    let Some(data) = shared() else { return };
    let effective_end = time::fields_to_time(&Fields { year: time::time_to_fields(now - bias).year + 1, month: 1, day: 1, ..Fields::default() }).unwrap_or(0) + bias - 10_000;
    assert(clock::read_shared_time(&data.time_zone_bias) as i64 == bias && data.time_zone_id.get() == 0 && data.time_zone_bias_stamp.get() % 2 == 0 && data.time_zone_bias_stamp.get() >= 2 && data.time_zone_bias_effective_end.quad_part.get() == effective_end && data.time_zone_bias_effective_start.quad_part.get() <= now, "time: TimeZoneBias, TimeZoneId, o carimbo par e TimeZoneBiasEffectiveEnd no ano novo local menos 1 ms");
    // Conversões.
    guest::write64(block, now as u64);
    call("ExSystemTimeToLocalTime", &[block, block + 8]);
    call("ExLocalTimeToSystemTime", &[block + 8, block + 0x10]);
    let rtl_local = status("RtlSystemTimeToLocalTime", &[block, block + 0x18]);
    let rtl_system = status("RtlLocalTimeToSystemTime", &[block + 0x18, block + 0x20]);
    assert(guest::read64(block + 8) as i64 == now - bias && guest::read64(block + 0x10) as i64 == now && rtl_local == 0 && guest::read64(block + 0x18) as i64 == now - bias && rtl_system == 0 && guest::read64(block + 0x20) as i64 == now, "time: Ex/RtlSystemTimeToLocalTime subtraem o vies e Ex/RtlLocalTimeToSystemTime somam");
    let boot = clock::boot_time() as i64;
    assert(boot > 0 && boot <= now && clock::boot_time_bias() == 0, "time: KeBootTime da correcao do fuso e KeBootTimeBias zero");
}

fn information_classes(assert: Assert, block: u64) {
    let output = block + 0x100;
    let returned = block + 0x2F8;
    let short = status("ZwQuerySystemInformation", &[44, output, 0x40, returned]);
    let short_length = guest::read32(returned);
    let full = status("ZwQuerySystemInformation", &[44, output, 0xAC, returned]);
    let length = guest::read32(returned);
    let bias = guest::read32(output) as i32;
    let name: alloc::vec::Vec<u16> = (0..32).map(|index| guest::read16(output + 4 + index * 2)).take_while(|&unit| unit != 0).collect();
    let daylight_bias = guest::read32(output + 0xA8) as i32;
    let standard_month = guest::read16(output + 0x44 + 2);
    assert(short == 0xC000_0004 && short_length == 0xAC && full == 0 && length == 0xAC && Some(bias as u32) == dword_value("Bias") && alloc::string::String::from_utf16_lossy(&name) == crate::ntos::cm::time_zone_information::STANDARD_NAME && Some(daylight_bias as u32) == dword_value("DaylightBias") && standard_month == 0, "time: SystemCurrentTimeZoneInformation (44) copia o fuso do Registro e recusa menos de 0xAC");
    let dynamic = status("ZwQuerySystemInformation", &[102, output, 0x1B0, returned]);
    let key: alloc::vec::Vec<u16> = (0..128).map(|index| guest::read16(output + 0xAC + index * 2)).take_while(|&unit| unit != 0).collect();
    assert(dynamic == 0 && guest::read32(returned) == 0x1B0 && alloc::string::String::from_utf16_lossy(&key) == crate::ntos::cm::time_zone_information::TIME_ZONE_KEY_NAME && guest::read8(output + 0x1AC) == 0, "time: SystemDynamicTimeZoneInformation (102) com a chave do fuso");
    let rtl = block + 0x400;
    let queried = status("RtlQueryDynamicTimeZoneInformation", &[rtl]);
    assert(queried == 0 && guest::read_bytes(rtl, 0x1B0) == guest::read_bytes(output, 0x1B0), "time: RtlQueryDynamicTimeZoneInformation le o mesmo fuso do Registro");
    // 124: Version 1; Flags sem KernelTransition (o atalho do TSC).
    guest::write32(output, 1);
    let counter = status("ZwQuerySystemInformation", &[124, output, 0xC, returned]);
    guest::write32(output + 0x10, 2);
    let version = status("ZwQuerySystemInformation", &[124, output + 0x10, 0xC, 0]);
    assert(counter == 0 && guest::read32(returned) == 0xC && guest::read32(output + 4) == 0 && guest::read32(output + 8) == 1 && version == 0xC000_00BB, "time: SystemQueryPerformanceCounterInformation sem transicao ao kernel e Version 1");
    let page = status("ZwQuerySystemInformation", &[197, output, 8, returned]);
    let va = guest::read64(output);
    assert(page == 0 && guest::read32(returned) == 8 && va == shared_user_data::hypervisor_shared_user_va() && (0x7FFE_1000..=0x7FFE_F000).contains(&va) && va & 0xFFF == 0, "time: SystemHypervisorSharedPageInformation devolve a pagina de referencia acima da KUSER_SHARED_DATA");
}

/// As datas de troca e os segundos desde as épocas.
fn calendar(assert: Assert, block: u64) {
    let current = time::fields_to_time(&Fields { year: 2026, month: 6, day: 15, hour: 12, ..Fields::default() }).unwrap_or(0);
    let at = |year, month, day, hour| time::fields_to_time(&Fields { year, month, day, hour, ..Fields::default() });
    let us_daylight = Fields { month: 3, day: 2, hour: 2, ..Fields::default() };
    let us_standard = Fields { month: 11, day: 1, hour: 2, ..Fields::default() };
    let last_october = Fields { month: 10, day: 5, hour: 3, ..Fields::default() };
    let absolute = Fields { year: 2027, month: 4, day: 3, hour: 1, ..Fields::default() };
    assert(time::cutover_time_to_system_time(&us_daylight, current) == at(2026, 3, 8, 2) && time::cutover_time_to_system_time(&us_standard, current) == at(2026, 11, 1, 2) && time::cutover_time_to_system_time(&last_october, current) == at(2026, 10, 25, 3) && time::cutover_time_to_system_time(&absolute, current) == at(2027, 4, 3, 1) && time::cutover_time_to_system_time(&Fields { month: 3, day: 6, ..Fields::default() }, current).is_none(), "time: RtlCutoverTimeToSystemTime (segundo domingo de marco, primeiro de novembro, ultimo de outubro, data absoluta, semana invalida)");
    let epoch_1970 = 116_444_736_000_000_000u64;
    guest::write64(block, epoch_1970 + 1234 * 10_000_000 + 9_999_999);
    let since_1970 = call("RtlTimeToSecondsSince1970", &[block, block + 8]) & 0xFF == 1 && guest::read32(block + 8) == 1234;
    guest::write64(block, epoch_1970 - 1);
    guest::write32(block + 8, 0x5A5A);
    let before_1970 = call("RtlTimeToSecondsSince1970", &[block, block + 8]) & 0xFF == 0 && guest::read32(block + 8) == 0x5A5A;
    call("RtlSecondsSince1980ToTime", &[5, block]);
    let from_1980 = guest::read64(block) == 119_600_064_000_000_000 + 5 * 10_000_000;
    let since_1980 = call("RtlTimeToSecondsSince1980", &[block, block + 8]) & 0xFF == 1 && guest::read32(block + 8) == 5;
    guest::write64(block, 119_600_064_000_000_000 + (1u64 << 32) * 10_000_000);
    let past_1980 = call("RtlTimeToSecondsSince1980", &[block, block + 8]) & 0xFF == 0;
    assert(since_1970 && before_1970 && from_1980 && since_1980 && past_1980, "time: RtlTimeToSecondsSince1970/1980 e RtlSecondsSince1980ToTime (fora do ULONG e FALSE)");
}

/// O que o AP e o BSP viram no teste de monotonicidade.
static PUBLISHED: AtomicU64 = AtomicU64::new(0);
static VIOLATIONS: AtomicU64 = AtomicU64::new(0);
const MONOTONIC_ROUNDS: u64 = 200_000;

/// Lê o maior QPC publicado, depois o próprio; o próprio nunca é menor.
extern "win64" fn monotonic_rounds(rounds: u64, _: u64, _: u64, _: u64) -> u64 {
    for _ in 0..rounds {
        let seen = PUBLISHED.load(Ordering::SeqCst);
        let own = clock::query_performance_counter_value();
        if own < seen {
            VIOLATIONS.fetch_add(1, Ordering::SeqCst);
        }
        PUBLISHED.fetch_max(own, Ordering::SeqCst);
    }
    0
}

fn tick_and_counters(assert: Assert, block: u64) {
    let Some(data) = shared() else {
        assert(false, "time: KUSER_SHARED_DATA publicada");
        return;
    };
    let bypass = data.qpc_data.get();
    assert(data.tick_count_multiplier.get() == 0x0FA0_0000 && data.qpc_frequency.get() == 10_000_000 && data.qpc_system_time_increment.get() == 1 << 63 && data.qpc_system_time_increment_shift.get() == 1 && data.qpc_interrupt_time_increment.get() == 1 << 63 && bypass & 0x03 == 0x03 && bypass & 0xFF00 == 0 && data.qpc_bias.get() == clock::qpc_bias(), "time: TickCountMultiplier, QpcFrequency, os incrementos QPC e o atalho do TSC com a pagina de referencia (QpcShift zero)");
    // A página de referência: 'HalT', TscScale = 10^7 << 64 / frequência.
    let frame = shared_user_data::reference_frame();
    let scale = ((10_000_000u128) << 64) / clock::tsc_frequency_hz() as u128;
    assert(frame != 0 && crate::hal::physical::read32(frame) == 0x546C_6148 && crate::hal::physical::read64(frame + 8) == scale as u64 && crate::hal::physical::read64(frame + 0x10) == 0, "time: pagina de referencia com TscSequence, TscScale e TscOffset");
    // O tick: TickCount = InterruptTime / KeMaximumIncrement.
    shared_user_data::update_system_times();
    let interrupt = clock::read_shared_time(&data.interrupt_time);
    let ticks = clock::read_shared_time(&data.tick_count);
    let precise = call("KeQueryInterruptTimePrecise", &[block]);
    let counter = guest::read64(block);
    let increment = clock::time_increment() as u64;
    // O preciso é o tick mais o QPC decorrido desde a linha de base menos 1.
    assert(ticks == interrupt / 156_250 && interrupt <= precise && precise < interrupt + increment + 10_000 && (precise + 1 == counter || precise == counter), "time: TickCount conta periodos de KeMaximumIncrement e o tempo de interrupcao preciso e o QPC lido junto");
    call("KeQueryTickCount", &[block + 8]);
    let tick_count = guest::read64(block + 8);
    let milliseconds = (ticks as u128 * data.tick_count_multiplier.get() as u128 >> 24) as u64;
    assert(tick_count >= ticks && (milliseconds as i64 - (interrupt / 10_000) as i64).abs() <= 16, "time: KeQueryTickCount e o GetTickCount pelo multiplicador (ms)");
    let frequency = block + 0x10;
    let first = call("KeQueryPerformanceCounter", &[frequency]);
    let second = call("KeQueryPerformanceCounter", &[0]);
    assert(guest::read64(frequency) == 10_000_000 && second >= first && call("KeQueryTimeIncrement", &[]) == 156_250, "time: KeQueryPerformanceCounter a 10 MHz e KeQueryTimeIncrement = KeMaximumIncrement");
    // Monotonicidade entre CPUs.
    let Some(slot) = smp::ap_slot(0) else {
        crate::debug_print!("[time] sem AP: monotonicidade so no BSP");
        return;
    };
    PUBLISHED.store(clock::query_performance_counter_value(), Ordering::SeqCst);
    VIOLATIONS.store(0, Ordering::SeqCst);
    let routine = monotonic_rounds as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
    let started = smp::start_job(slot, routine, [MONOTONIC_ROUNDS, 0, 0, 0]).is_ok_and(|started| started);
    monotonic_rounds(MONOTONIC_ROUNDS, 0, 0, 0);
    let finished = started && smp::wait_job(slot, 30_000).is_ok();
    assert(finished && VIOLATIONS.load(Ordering::SeqCst) == 0, "time: o QPC nunca volta atras entre o BSP e um AP lendo ao mesmo tempo");
}

static NOTIFIED: AtomicU64 = AtomicU64::new(0);

/// O callback de \Callback\SetSystemTime.
extern "win64" fn time_changed(_context: u64, first: u64, second: u64) {
    NOTIFIED.fetch_add(1 + first + second, Ordering::SeqCst);
}

fn set_system_time(assert: Assert, block: u64) {
    let Some(callback) = crate::ntos::ex::callbacks::system_callback("SetSystemTime") else {
        assert(false, "time: o objeto \\Callback\\SetSystemTime");
        return;
    };
    let routine = time_changed as extern "win64" fn(u64, u64, u64) as usize as u64;
    let registration = crate::ntos::ex::callbacks::register(callback, routine, 0).unwrap_or(0);
    NOTIFIED.store(0, Ordering::SeqCst);
    let callouts = crate::ntos::ps::win32::win32_callout().is_some();
    let bias = time_zone::time_zone_bias();
    let (boot, boot_bias) = (clock::boot_time() as i64, clock::boot_time_bias() as i64);
    let hour = 60 * MINUTE;
    let target = precise_now(block) + hour;
    guest::write64(block + 8, target as u64);
    guest::write64(block + 0x10, 0);
    let set = status("ZwSetSystemTime", &[block + 8, block + 0x10]);
    let previous = guest::read64(block + 0x10) as i64;
    let after = precise_now(block);
    let delta = target - previous;
    let cmos = cmos_local() + bias;
    assert(set == 0 && (previous - (target - hour)).abs() < SECOND && after >= target && after - target < SECOND && clock::boot_time() as i64 == boot + delta && clock::boot_time_bias() as i64 == boot_bias + delta && (cmos - target).abs() <= 2 * SECOND, "time: ZwSetSystemTime adianta a hora, devolve a anterior, soma o delta a KeBootTime/KeBootTimeBias e grava a hora local na CMOS");
    assert(NOTIFIED.load(Ordering::SeqCst) == if callouts { 1 } else { 0 }, "time: o ExCbSetSystemTime so e avisado com os callouts do win32k (PoNotifySystemTimeSet)");
    let back = precise_now(block) - hour;
    guest::write64(block + 8, back as u64);
    let restored = status("ZwSetSystemTime", &[block + 8, 0]);
    let now = precise_now(block);
    assert(restored == 0 && (now - back).abs() < SECOND && ((clock::boot_time_bias() as i64) - boot_bias).abs() < SECOND && (cmos_local() + bias - now).abs() <= 2 * SECOND, "time: ZwSetSystemTime de volta: hora, KeBootTimeBias e CMOS restaurados");
    guest::write64(block + 8, 0x2000_0001u64 << 32);
    let invalid = status("ZwSetSystemTime", &[block + 8, 0]);
    let refresh = status("ZwSetSystemTime", &[0, 0]);
    assert(invalid == 0xC000_000D && refresh == 0 && (cmos_local() + bias - precise_now(block)).abs() <= 2 * SECOND && time_zone::time_zone_bias() == bias, "time: hora acima de 0x20000000 no DWORD alto e o pedido de releitura (NULL) com o relogio reescrito");
    if registration != 0 {
        let _ = crate::ntos::ex::callbacks::unregister(registration);
    }
    crate::debug_print!("[time] depois do acerto: hora do sistema UTC={}", crate::rtl::time::nt_time_to_unix_milliseconds(precise_now(block) as u64));
}

/// Um fuso com horário de verão pelo ZwSetSystemInformation(102) e a volta
/// ao fuso da máquina.
fn change_zone(assert: Assert, block: u64) {
    let original = block + 0x400;
    if status("ZwQuerySystemInformation", &[102, original, 0x1B0, 0]) != 0 {
        assert(false, "time: o fuso corrente pela classe 102");
        return;
    }
    let zone = block + 0x600;
    guest::write_bytes(zone, &[0; 0x1B0]);
    guest::write32(zone, 300);
    let name = |at: u64, text: &str| {
        for (index, unit) in text.encode_utf16().enumerate() {
            guest::write16(at + index as u64 * 2, unit);
        }
    };
    name(zone + 4, "Eastern Standard Time");
    guest::write_bytes(zone + 0x44, &Fields { month: 11, day: 1, hour: 2, ..Fields::default() }.to_bytes());
    name(zone + 0x58, "Eastern Daylight Time");
    guest::write_bytes(zone + 0x98, &Fields { month: 3, day: 2, hour: 2, ..Fields::default() }.to_bytes());
    guest::write32(zone + 0xA8, (-60i32) as u32);
    name(zone + 0xAC, "Eastern Standard Time");
    let old_bias = time_zone::time_zone_bias();
    let wrong = status("ZwSetSystemInformation", &[102, zone, 0xAC]);
    let set = status("ZwSetSystemInformation", &[102, zone, 0x1B0]);
    let now = precise_now(block);
    // A hora local pelo viés anterior decide o horário (o
    // ExpRefreshTimeZoneInformation): de verão entre as duas trocas do ano.
    let local_standard = now - old_bias;
    let daylight_start = time::cutover_time_to_system_time(&Fields { month: 3, day: 2, hour: 2, ..Fields::default() }, local_standard).unwrap_or(0);
    let standard_start = time::cutover_time_to_system_time(&Fields { month: 11, day: 1, hour: 2, ..Fields::default() }, local_standard).unwrap_or(0);
    let daylight = local_standard >= daylight_start && local_standard < standard_start;
    let (id, minutes) = if daylight { (2, 240) } else { (1, 300) };
    let shared_bias = shared().map_or(0, |data| clock::read_shared_time(&data.time_zone_bias) as i64);
    assert(wrong == 0xC000_0004 && set == 0 && time_zone::time_zone_id() == id && time_zone::time_zone_bias() == minutes * MINUTE && shared_bias == minutes * MINUTE && shared().is_some_and(|data| data.time_zone_id.get() == id) && dword_value("ActiveTimeBias") == Some(minutes as u32) && dword_value("Bias") == Some(300) && (cmos_local() + minutes * MINUTE - now).abs() <= 2 * SECOND, "time: ZwSetSystemInformation(102) grava o fuso, escolhe o horario pelas datas de troca e reescreve a CMOS com a hora local nova");
    let restore = status("ZwSetSystemInformation", &[102, original, 0x1B0]);
    let bias = registry_bias().unwrap_or(-1);
    assert(restore == 0 && time_zone::time_zone_bias() == bias && time_zone::time_zone_id() == 0 && dword_value("ActiveTimeBias") == Some((bias / MINUTE) as u32) && (cmos_local() + bias - precise_now(block)).abs() <= 2 * SECOND, "time: de volta ao fuso da maquina, com o ActiveTimeBias e a CMOS");
}

fn timer_resolution(assert: Assert, block: u64) {
    let (maximum, minimum, current, actual) = (block, block + 4, block + 8, block + 0xC);
    let query = |_: ()| (status("ZwQueryTimerResolution", &[maximum, minimum, current]), guest::read32(maximum), guest::read32(minimum), guest::read32(current));
    assert(query(()) == (0, 156_250, 5000, 156_250), "time: ZwQueryTimerResolution = 15,625 ms, 0,5 ms e o corrente");
    let set = |time: u32, enable: u64| (status("ZwSetTimerResolution", &[time as u64, enable, actual]), guest::read32(actual));
    let process = crate::ntos::ps::process::get_current_process();
    // SAFETY: o EPROCESS corrente.
    let object = unsafe { Eprocess::at(process) };
    assert(set(0, 0) == (timer_resolution::STATUS_TIMER_RESOLUTION_NOT_SET, 156_250), "time: cancelar sem pedido e STATUS_TIMER_RESOLUTION_NOT_SET");
    let requested = set(10_000, 1) == (0, 10_000) && query(()).3 == 10_000 && object.flags.get() & Eprocess::SET_TIMER_RESOLUTION_MASK != 0 && object.flags.get() & Eprocess::SET_TIMER_RESOLUTION_LINK_MASK != 0 && object.requested_timer_resolution.get() == 10_000 && timer_resolution::process_request_count() == 1;
    assert(requested, "time: o pedido do processo liga SetTimerResolution, entra na lista e afina o relogio para 1 ms");
    let kernel = call("ExSetTimerResolution", &[5000, 1]) == 5000 && clock::time_increment() == 5000;
    let coarser = set(20_000, 1) == (0, 5000) && object.requested_timer_resolution.get() == 20_000;
    let kernel_off = call("ExSetTimerResolution", &[0, 0]) == 20_000 && clock::time_increment() == 20_000;
    assert(kernel && coarser && kernel_off, "time: o menor pedido vale (o do kernel em 0,5 ms) e sem ele o do processo (2 ms)");
    let off = set(0, 0) == (0, 156_250) && object.flags.get() & Eprocess::SET_TIMER_RESOLUTION_MASK == 0 && object.requested_timer_resolution.get() == 0 && timer_resolution::process_request_count() == 0 && clock::time_increment() == 156_250;
    assert(off, "time: o cancelamento do processo volta o relogio a KeMaximumIncrement");
    // O tick no incremento corrente: o tempo de interrupção avança de 0,5 ms.
    call("ExSetTimerResolution", &[5000, 1]);
    shared_user_data::update_system_times();
    let Some(data) = shared() else { return };
    let start = clock::read_shared_time(&data.interrupt_time);
    let deadline = clock::uptime_ms() + 50;
    let mut steps_fine = true;
    let mut previous = start;
    while clock::uptime_ms() < deadline {
        shared_user_data::update_system_times();
        let value = clock::read_shared_time(&data.interrupt_time);
        if value != previous {
            steps_fine &= (value - previous) % 5000 == 0;
            previous = value;
        }
    }
    call("ExSetTimerResolution", &[0, 0]);
    assert(steps_fine && previous > start, "time: com 0,5 ms o InterruptTime avanca em multiplos de 5000");
}

pub fn run(assert: Assert) {
    let block = guest::alloc_bytes(0x800);
    if block == 0 {
        assert(false, "time: bloco do teste");
        return;
    }
    guest::write_bytes(block, &[0; 0x800]);
    rtc_and_zone(assert, block);
    information_classes(assert, block);
    calendar(assert, block);
    tick_and_counters(assert, block);
    set_system_time(assert, block);
    change_zone(assert, block);
    timer_resolution(assert, block);
    guest::free_bytes(block);
    // Uma asserção falha já imprimiu SELFTEST FALHOU antes deste marcador.
    crate::debug_print!("TIME_KEEPING_OK");
}
