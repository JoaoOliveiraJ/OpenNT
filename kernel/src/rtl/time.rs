//! Relógio de parede a partir do RTC — o que o `Date.now()` do QuickJS
//! obtinha pela libc shim (`hal/rtl/time.c` sobre `hal/rtc/rtc.c`).

use crate::hal::rtc;

/// Milissegundos entre 1601-01-01 e 1970-01-01 (época do NT vs. Unix).
pub const UNIX_TO_NT_EPOCH_MILLISECONDS: u64 = 11_644_473_600_000;

/// Dias desde 1970-01-01 para uma data do calendário gregoriano
/// (algoritmo `days_from_civil` de Howard Hinnant).
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `Date.now()`: milissegundos Unix lidos do CMOS (resolução de segundos).
pub fn rtc_unix_milliseconds() -> u64 {
    let now = rtc::read();
    let days = days_from_civil(now.year as i64, now.month as u32, now.day as u32);
    let seconds = days * 86_400 + now.hour as i64 * 3_600 + now.minute as i64 * 60 + now.second as i64;
    if seconds < 0 {
        0
    } else {
        seconds as u64 * 1_000
    }
}

/// Converte milissegundos Unix em unidades de 100 ns desde 1601 (formato
/// de tempo do Windows).
pub fn unix_milliseconds_to_nt_time(milliseconds: u64) -> u64 {
    (milliseconds + UNIX_TO_NT_EPOCH_MILLISECONDS) * 10_000
}
