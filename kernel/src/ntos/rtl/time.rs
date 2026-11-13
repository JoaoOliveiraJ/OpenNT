//! Conversões de tempo do Rtl — RtlTimeToTimeFields e RtlTimeFieldsToTime.
//!
//! TIME_FIELDS são oito CSHORT (ano, mês, dia, hora, minuto, segundo,
//! milissegundo, dia da semana); o tempo do sistema conta intervalos de
//! 100 ns desde 1601-01-01, no calendário civil gregoriano.

use crate::ntos::inc::types::{LargeInteger, NtStruct, TimeFields};

// SAFETY (conversões deste arquivo): PLARGE_INTEGER e PTIME_FIELDS do
// chamador, vivos e alinhados.
fn time_at(time: u64) -> &'static LargeInteger {
    unsafe { LargeInteger::at(time) }
}
fn fields_at(fields: u64) -> &'static TimeFields {
    unsafe { TimeFields::at(fields) }
}

/// RtlTimeToTimeFields: calendário civil a partir de 1601 (dia da semana incluso).
pub fn time_to_time_fields(time: u64, time_fields: u64) {
    let filetime = time_at(time).quad_part.get() as u64;
    let total_seconds = (filetime / 10_000_000) as i64;
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);
    let march_days = days - 134_774 + 719_468;
    let era = march_days.div_euclid(146_097);
    let day_of_era = march_days - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let full_year = year + if month <= 2 { 1 } else { 0 };
    let output = fields_at(time_fields);
    output.year.set(full_year as i16);
    output.month.set(month as i16);
    output.day.set(day as i16);
    output.hour.set((seconds_of_day / 3600) as i16);
    output.minute.set(((seconds_of_day % 3600) / 60) as i16);
    output.second.set((seconds_of_day % 60) as i16);
    output.milliseconds.set(((filetime % 10_000_000) / 10_000) as i16);
    output.weekday.set((days + 1).rem_euclid(7) as i16);
}

/// RtlTimeFieldsToTime: campos validados (1601–30827) → 100 ns desde 1601;
/// FALSE (sem escrever) com campos inválidos.
pub fn time_fields_to_time(time_fields: u64, time: u64) -> bool {
    let input = fields_at(time_fields);
    let (year, month, day, hour, minute, second, millisecond) = (
        input.year.get() as i64,
        input.month.get() as i64,
        input.day.get() as i64,
        input.hour.get() as i64,
        input.minute.get() as i64,
        input.second.get() as i64,
        input.milliseconds.get() as i64,
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1601..=30827).contains(&year) || !(1..=12).contains(&month) || day < 1 || day > months[month as usize - 1] || !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=59).contains(&second) || !(0..=999).contains(&millisecond) {
        return false;
    }
    let previous = year - 1;
    let mut days = previous * 365 + previous / 4 - previous / 100 + previous / 400 - 584_388 + day - 1;
    for length in months.iter().take(month as usize - 1) {
        days += length;
    }
    let seconds = days as u64 * 86_400 + (hour * 3600 + minute * 60 + second) as u64;
    time_at(time).quad_part.set((seconds * 10_000_000 + millisecond as u64 * 10_000) as i64);
    true
}

/// Segundos entre 1601-01-01 e 1970-01-01 (SecondsToStartOf1970 do ntoskrnl).
pub const SECONDS_TO_START_OF_1970: u64 = 11_644_473_600;

/// RtlSecondsSince1970ToTime (RVA 0x3ccef0): (ULONG + 11644473600) * 10^7.
pub fn seconds_since_1970_to_time(seconds: u32, time: &LargeInteger) {
    time.quad_part.set((seconds as u64 + SECONDS_TO_START_OF_1970).wrapping_mul(10_000_000) as i64);
}

/// RtlSystemTimeToLocalTime (RVA 0x7cd960): o NT lê TimeZoneBias de
/// ZwQuerySystemInformation(SystemTimeOfDayInformation) e grava
/// SystemTime - TimeZoneBias; o viés vem da mesma fonte do Executive.
pub fn system_time_to_local_time(system_time: &LargeInteger, local_time: &LargeInteger) -> u32 {
    let bias = crate::ntos::ex::system_time::time_zone_bias();
    local_time.quad_part.set(system_time.quad_part.get().wrapping_sub(bias));
    0
}
