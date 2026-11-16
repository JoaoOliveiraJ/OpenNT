//! Relógio de tempo real via CMOS (portas 0x70/0x71) e as rotinas
//! HalQueryRealTimeClock/HalSetRealTimeClock.
//!
//! O índice (0x70) e o dado (0x71) formam uma transação: quem lê ou grava um
//! registrador da CMOS o faz sob o lock da CMOS (o HalpSystemHardwareLock que
//! o HalpAcquireCmosSpinLock do NT toma), com interrupções desligadas: o
//! relógio e o emulador do BIOS de vídeo (`hal::x86bios`).
//!
//! A leitura do relógio é a do HalpReadCmosTime do ntoskrnl 19041: sob o
//! lock, espera o bit UIP (registrador A, bit 7) cair, como o
//! HalpAcquireCmosSpinLockAndWait, e lê segundos (0), minutos (2), horas (4),
//! dia da semana (6), dia (7), mês (8), o século no registrador que o FADT
//! aponta (CENTURY, byte 108; 0x32 quando o FADT não traz, como o
//! HalpTimerInitSystem grava em HalpCmosCenturyOffset) e o ano (9); o ano
//! completo é século × 100 + ano, mais 100 quando cai em 1900–1919, e os
//! milissegundos ficam em 500 (o meio do segundo que o relógio não conta).
//! O NT assume BCD e 24 horas; o registrador B diz o formato de verdade
//! (bit 2: binário, bit 1: 24 horas, e no modo de 12 horas o bit 7 da hora
//! é PM), e a leitura e a gravação seguem o formato que o relógio usa.

use super::port;
use crate::rtl::SpinLock;

/// Lock da CMOS: uma transação índice + dado de cada vez.
static CMOS_LOCK: SpinLock<()> = SpinLock::new(());

/// Registradores do relógio.
const REGISTER_SECONDS: u8 = 0x00;
const REGISTER_MINUTES: u8 = 0x02;
const REGISTER_HOURS: u8 = 0x04;
const REGISTER_WEEKDAY: u8 = 0x06;
const REGISTER_DAY: u8 = 0x07;
const REGISTER_MONTH: u8 = 0x08;
const REGISTER_YEAR: u8 = 0x09;
const REGISTER_A: u8 = 0x0A;
const REGISTER_B: u8 = 0x0B;
/// Registrador A: atualização em andamento.
const UPDATE_IN_PROGRESS: u8 = 0x80;
/// Registrador B: dados em binário (senão BCD) e 24 horas (senão 12).
const BINARY_MODE: u8 = 0x04;
const HOUR_24_MODE: u8 = 0x02;
/// Bit PM da hora no modo de 12 horas.
const HOUR_PM: u8 = 0x80;
/// O registrador de século padrão (HalpCmosCenturyOffset sem FADT.CENTURY).
const DEFAULT_CENTURY_REGISTER: u8 = 0x32;
/// Byte CENTURY do FADT.
const FADT_CENTURY_OFFSET: usize = 108;

/// Lê o registrador `register` da CMOS (índice em 0x70, dado em 0x71).
pub fn cmos_read(register: u8) -> u8 {
    let _held = CMOS_LOCK.lock();
    port::write8(0x70, register);
    port::read8(0x71)
}

/// Grava o registrador `register` da CMOS.
pub fn cmos_write(register: u8, value: u8) {
    let _held = CMOS_LOCK.lock();
    port::write8(0x70, register);
    port::write8(0x71, value);
}

/// Uma data do relógio (os campos de um TIME_FIELDS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub milliseconds: u16,
    /// Dia da semana como o relógio guarda (registrador 6).
    pub weekday: u8,
}

fn from_bcd(value: u8) -> u8 {
    (value & 0x0F) + (value >> 4) * 10
}

fn to_bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}

/// O registrador de século: o CENTURY do FADT, ou 0x32.
fn century_register() -> u8 {
    crate::hal::acpi::get_table("FACP", 0, false).and_then(|fadt| fadt.bytes.get(FADT_CENTURY_OFFSET).copied()).filter(|&register| register != 0).unwrap_or(DEFAULT_CENTURY_REGISTER)
}

/// Leitura sem lock (o chamador o tem).
fn raw_read(register: u8) -> u8 {
    port::write8(0x70, register);
    port::read8(0x71)
}

fn raw_write(register: u8, value: u8) {
    port::write8(0x70, register);
    port::write8(0x71, value);
}

/// HalpReadCmosTime: a data do relógio no formato que ele usa.
pub fn read() -> RealTime {
    let century_index = century_register();
    let _held = CMOS_LOCK.lock();
    // HalpAcquireCmosSpinLockAndWait: só lê fora de uma atualização.
    while raw_read(REGISTER_A) & UPDATE_IN_PROGRESS != 0 {
        core::hint::spin_loop();
    }
    let format = raw_read(REGISTER_B);
    let decode = |value: u8| if format & BINARY_MODE != 0 { value } else { from_bcd(value) };
    let second = decode(raw_read(REGISTER_SECONDS));
    let minute = decode(raw_read(REGISTER_MINUTES));
    let raw_hour = raw_read(REGISTER_HOURS);
    let hour = if format & HOUR_24_MODE != 0 {
        decode(raw_hour)
    } else {
        let hour = decode(raw_hour & !HOUR_PM) % 12;
        if raw_hour & HOUR_PM != 0 { hour + 12 } else { hour }
    };
    let weekday = decode(raw_read(REGISTER_WEEKDAY));
    let day = decode(raw_read(REGISTER_DAY));
    let month = decode(raw_read(REGISTER_MONTH));
    let century = decode(raw_read(century_index)) as u16;
    let year_of_century = decode(raw_read(REGISTER_YEAR)) as u16;
    let mut year = century * 100 + year_of_century;
    if year.wrapping_sub(1900) <= 19 {
        year += 100;
    }
    RealTime { year, month, day, hour, minute, second, milliseconds: 500, weekday }
}

/// HalpWriteCmosTime: grava a data no formato que o relógio usa.
pub fn write(time: &RealTime) {
    let century_index = century_register();
    let _held = CMOS_LOCK.lock();
    while raw_read(REGISTER_A) & UPDATE_IN_PROGRESS != 0 {
        core::hint::spin_loop();
    }
    let format = raw_read(REGISTER_B);
    let encode = |value: u8| if format & BINARY_MODE != 0 { value } else { to_bcd(value) };
    let hour = if format & HOUR_24_MODE != 0 {
        encode(time.hour)
    } else {
        let twelve = match time.hour % 12 {
            0 => 12,
            hour => hour,
        };
        encode(twelve) | if time.hour >= 12 { HOUR_PM } else { 0 }
    };
    raw_write(REGISTER_SECONDS, encode(time.second));
    raw_write(REGISTER_MINUTES, encode(time.minute));
    raw_write(REGISTER_HOURS, hour);
    raw_write(REGISTER_WEEKDAY, encode(time.weekday));
    raw_write(REGISTER_DAY, encode(time.day));
    raw_write(REGISTER_MONTH, encode(time.month));
    raw_write(century_index, encode((time.year / 100) as u8));
    raw_write(REGISTER_YEAR, encode((time.year % 100) as u8));
}

// ---- HalQueryRealTimeClock / HalSetRealTimeClock ---------------------------
//
// HalQueryRealTimeClock(PTIME_FIELDS) do 19041 (rva 0x30ccc0), no caminho de
// uma plataforma com o relógio da CMOS (HalpPlatformFlags bit 2): lê a CMOS,
// converte em tempo; sem ExpRealTimeIsUniversal o relógio guarda a hora
// local e o tempo vira UTC somando ExpTimeZoneBias; se a hora do sistema
// (KUSER_SHARED_DATA.SystemTime) passa do relógio + 1 dia, vale a hora do
// sistema (HalpTimerRtcErrorCode |= 1); por fim volta à hora local e sai em
// TIME_FIELDS. Devolve TRUE com a data válida.
//
// HalSetRealTimeClock(PTIME_FIELDS) (rva 0x4b6a90): a data (hora local, sem
// ExpRealTimeIsUniversal) vira UTC pelo viés; com a CMOS, o HalpWriteCmosTime
// grava os campos como vieram; o HalpSetVirtualRtc guarda a referência UTC.
// Devolve TRUE.

/// Um dia em unidades de 100 ns (a folga do HalQueryRealTimeClock).
const ONE_DAY: i64 = 864_000_000_000;

fn fields_of(time: &RealTime) -> crate::ntos::rtl::time::Fields {
    crate::ntos::rtl::time::Fields { year: time.year as i16, month: time.month as i16, day: time.day as i16, hour: time.hour as i16, minute: time.minute as i16, second: time.second as i16, milliseconds: time.milliseconds as i16, weekday: time.weekday as i16 }
}

/// O relógio em UTC (100 ns desde 1601): a leitura da CMOS, com o viés do
/// fuso quando o relógio guarda a hora local; `None` com data inválida.
pub fn query_universal_time() -> Option<i64> {
    let local = crate::ntos::rtl::time::fields_to_time(&fields_of(&read()))?;
    Some(if crate::ntos::ex::time_zone::real_time_is_universal() { local } else { local.wrapping_add(crate::ntos::ex::time_zone::time_zone_bias()) })
}

/// HalQueryRealTimeClock: os campos da data do relógio (hora local sem
/// ExpRealTimeIsUniversal); `None` = FALSE.
pub fn query_real_time_clock() -> Option<crate::ntos::rtl::time::Fields> {
    let mut universal = query_universal_time()?;
    let system_time = crate::ntos::ke::clock::shared_system_time();
    if system_time > universal.wrapping_add(ONE_DAY) {
        universal = system_time;
    }
    let local = if crate::ntos::ex::time_zone::real_time_is_universal() { universal } else { universal.wrapping_sub(crate::ntos::ex::time_zone::time_zone_bias()) };
    Some(crate::ntos::rtl::time::time_to_fields(local))
}

/// HalSetRealTimeClock: grava os campos (hora local sem
/// ExpRealTimeIsUniversal) na CMOS; FALSE com data inválida.
pub fn set_real_time_clock(fields: &crate::ntos::rtl::time::Fields) -> bool {
    if crate::ntos::rtl::time::fields_to_time(fields).is_none() {
        return false;
    }
    write(&RealTime {
        year: fields.year as u16,
        month: fields.month as u8,
        day: fields.day as u8,
        hour: fields.hour as u8,
        minute: fields.minute as u8,
        second: fields.second as u8,
        milliseconds: fields.milliseconds as u16,
        weekday: fields.weekday as u8,
    });
    true
}
