//! Conversões de tempo do Rtl — RtlTimeToTimeFields e RtlTimeFieldsToTime.
//!
//! TIME_FIELDS são oito CSHORT (ano, mês, dia, hora, minuto, segundo,
//! milissegundo, dia da semana); o tempo do sistema conta intervalos de
//! 100 ns desde 1601-01-01, no calendário civil gregoriano.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;

/// RtlTimeToTimeFields: calendário civil a partir de 1601 (dia da semana incluso).
pub fn time_to_time_fields(time: u64, time_fields: u64) {
    let filetime = guest::read64(time);
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
    let fields = [full_year, month, day, seconds_of_day / 3600, (seconds_of_day % 3600) / 60, seconds_of_day % 60, ((filetime % 10_000_000) / 10_000) as i64, (days + 1).rem_euclid(7)];
    for (index, value) in fields.iter().enumerate() {
        guest::write16(time_fields + index as u64 * 2, *value as u16);
    }
}

/// RtlTimeFieldsToTime: campos validados (1601–30827) → 100 ns desde 1601;
/// FALSE (sem escrever) com campos inválidos.
pub fn time_fields_to_time(time_fields: u64, time: u64) -> bool {
    let fields: Vec<i64> = (0..7).map(|index| guest::read16(time_fields + index * 2) as i16 as i64).collect();
    let (year, month, day, hour, minute, second, millisecond) = (fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]);
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
    guest::write64(time, seconds * 10_000_000 + millisecond as u64 * 10_000);
    true
}
