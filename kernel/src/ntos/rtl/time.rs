//! Conversões de tempo do Rtl — RtlTimeToTimeFields, RtlTimeFieldsToTime,
//! os segundos desde 1970/1980, a hora local e as datas de troca de fuso
//! (RtlCutoverTimeToSystemTime).
//!
//! TIME_FIELDS são oito CSHORT (ano, mês, dia, hora, minuto, segundo,
//! milissegundo, dia da semana); o tempo do sistema conta intervalos de
//! 100 ns desde 1601-01-01, no calendário civil gregoriano. As conversões
//! puras ([`time_to_fields`], [`fields_to_time`]) servem ao HAL e ao
//! Executive; os exports leem e gravam as estruturas do chamador.

use crate::ntos::inc::types::{LargeInteger, NtStruct, TimeFields};

/// Os campos de um TIME_FIELDS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fields {
    pub year: i16,
    pub month: i16,
    pub day: i16,
    pub hour: i16,
    pub minute: i16,
    pub second: i16,
    pub milliseconds: i16,
    pub weekday: i16,
}

impl Fields {
    /// Lê um TIME_FIELDS.
    pub fn read(fields: &TimeFields) -> Fields {
        Fields { year: fields.year.get(), month: fields.month.get(), day: fields.day.get(), hour: fields.hour.get(), minute: fields.minute.get(), second: fields.second.get(), milliseconds: fields.milliseconds.get(), weekday: fields.weekday.get() }
    }

    /// Grava num TIME_FIELDS.
    pub fn write(&self, fields: &TimeFields) {
        fields.year.set(self.year);
        fields.month.set(self.month);
        fields.day.set(self.day);
        fields.hour.set(self.hour);
        fields.minute.set(self.minute);
        fields.second.set(self.second);
        fields.milliseconds.set(self.milliseconds);
        fields.weekday.set(self.weekday);
    }

    /// Os oito WORDs de um TIME_FIELDS em memória (StandardStart e
    /// DaylightStart do RTL_TIME_ZONE_INFORMATION e os valores binários de
    /// mesmo nome do Registro têm este formato).
    pub fn from_bytes(bytes: &[u8]) -> Fields {
        let word = |index: usize| bytes.get(index * 2..index * 2 + 2).map_or(0, |pair| i16::from_le_bytes([pair[0], pair[1]]));
        Fields { year: word(0), month: word(1), day: word(2), hour: word(3), minute: word(4), second: word(5), milliseconds: word(6), weekday: word(7) }
    }

    /// Os 16 bytes do TIME_FIELDS.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        for (index, word) in [self.year, self.month, self.day, self.hour, self.minute, self.second, self.milliseconds, self.weekday].iter().enumerate() {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}

// SAFETY (conversões deste arquivo): PLARGE_INTEGER e PTIME_FIELDS do
// chamador, vivos e alinhados.
fn time_at(time: u64) -> &'static LargeInteger {
    unsafe { LargeInteger::at(time) }
}
fn fields_at(fields: u64) -> &'static TimeFields {
    unsafe { TimeFields::at(fields) }
}

/// Os campos de um tempo (100 ns desde 1601), dia da semana incluso
/// (domingo = 0).
pub fn time_to_fields(time: i64) -> Fields {
    let filetime = time as u64;
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
    Fields {
        year: full_year as i16,
        month: month as i16,
        day: day as i16,
        hour: (seconds_of_day / 3600) as i16,
        minute: ((seconds_of_day % 3600) / 60) as i16,
        second: (seconds_of_day % 60) as i16,
        milliseconds: ((filetime % 10_000_000) / 10_000) as i16,
        weekday: (days + 1).rem_euclid(7) as i16,
    }
}

/// Campos validados (1601–30827) → 100 ns desde 1601; `None` com campos
/// inválidos (o dia da semana não entra).
pub fn fields_to_time(fields: &Fields) -> Option<i64> {
    let (year, month, day, hour, minute, second, millisecond) = (fields.year as i64, fields.month as i64, fields.day as i64, fields.hour as i64, fields.minute as i64, fields.second as i64, fields.milliseconds as i64);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1601..=30827).contains(&year) || !(1..=12).contains(&month) || day < 1 || day > months[month as usize - 1] || !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=59).contains(&second) || !(0..=999).contains(&millisecond) {
        return None;
    }
    let previous = year - 1;
    let mut days = previous * 365 + previous / 4 - previous / 100 + previous / 400 - 584_388 + day - 1;
    for length in months.iter().take(month as usize - 1) {
        days += length;
    }
    let seconds = days as u64 * 86_400 + (hour * 3600 + minute * 60 + second) as u64;
    Some((seconds * 10_000_000 + millisecond as u64 * 10_000) as i64)
}

/// RtlTimeToTimeFields: calendário civil a partir de 1601 (dia da semana incluso).
pub fn time_to_time_fields(time: u64, time_fields: u64) {
    time_to_fields(time_at(time).quad_part.get()).write(fields_at(time_fields));
}

/// RtlTimeFieldsToTime: campos validados (1601–30827) → 100 ns desde 1601;
/// FALSE (sem escrever) com campos inválidos.
pub fn time_fields_to_time(time_fields: u64, time: u64) -> bool {
    match fields_to_time(&Fields::read(fields_at(time_fields))) {
        Some(value) => {
            time_at(time).quad_part.set(value);
            true
        }
        None => false,
    }
}

/// Segundos entre 1601-01-01 e 1970-01-01 (SecondsToStartOf1970 do ntoskrnl).
pub const SECONDS_TO_START_OF_1970: u64 = 11_644_473_600;
/// Segundos entre 1601-01-01 e 1980-01-01 (SecondsToStartOf1980).
pub const SECONDS_TO_START_OF_1980: u64 = 11_960_006_400;

/// RtlSecondsSince1970ToTime (RVA 0x3ccef0): (ULONG + 11644473600) * 10^7.
pub fn seconds_since_1970_to_time(seconds: u32, time: &LargeInteger) {
    time.quad_part.set((seconds as u64 + SECONDS_TO_START_OF_1970).wrapping_mul(10_000_000) as i64);
}

/// RtlSecondsSince1980ToTime (RVA 0x585240): (ULONG + 11960006400) * 10^7.
pub fn seconds_since_1980_to_time(seconds: u32, time: &LargeInteger) {
    time.quad_part.set((seconds as u64 + SECONDS_TO_START_OF_1980).wrapping_mul(10_000_000) as i64);
}

/// RtlTimeToSecondsSince1970/1980 (RVA 0x585270 e 0x394d60): o tempo
/// dividido por 10^7 (RtlExtendedMagicDivide, truncado para zero) menos o
/// início da época; FALSE sem escrever quando o resultado não cabe num ULONG.
pub fn time_to_seconds_since(time: &LargeInteger, epoch_seconds: u64, seconds: &crate::ntos::inc::types::Field<u32>) -> bool {
    let elapsed = (time.quad_part.get() / 10_000_000).wrapping_sub(epoch_seconds as i64) as u64;
    if elapsed >> 32 != 0 {
        return false;
    }
    seconds.set(elapsed as u32);
    true
}

/// RtlSystemTimeToLocalTime (RVA 0x7cd960): o NT lê TimeZoneBias de
/// ZwQuerySystemInformation(SystemTimeOfDayInformation) e grava
/// SystemTime - TimeZoneBias; o viés vem da mesma fonte do Executive.
pub fn system_time_to_local_time(system_time: &LargeInteger, local_time: &LargeInteger) -> u32 {
    let bias = crate::ntos::ex::system_time::time_zone_bias();
    local_time.quad_part.set(system_time.quad_part.get().wrapping_sub(bias));
    0
}

/// RtlLocalTimeToSystemTime (RVA 0x90ffe0): o mesmo SystemTimeOfDayInformation,
/// LocalTime + TimeZoneBias.
pub fn local_time_to_system_time(local_time: &LargeInteger, system_time: &LargeInteger) -> u32 {
    let bias = crate::ntos::ex::system_time::time_zone_bias();
    system_time.quad_part.set(local_time.quad_part.get().wrapping_add(bias));
    0
}

/// RtlCutoverTimeToSystemTime (ntoskrnl 19041 rva 0x7aa020): a data de troca
/// `cutover` (um TIME_FIELDS, como o StandardStart do fuso) no ano de
/// `current` (hora local). Com ano, a data é absoluta. Senão o "dia" é a
/// semana (1–5, 5 = a última) e o "dia da semana" o dia da semana da troca:
/// parte do dia 1 do mês no ano corrente, acha o primeiro dia com aquele dia
/// da semana e avança semanas enquanto a data existir no mês. `None` com
/// campos inválidos.
pub fn cutover_time_to_system_time(cutover: &Fields, current: i64) -> Option<i64> {
    let now = time_to_fields(current);
    if cutover.year != 0 {
        return fields_to_time(cutover);
    }
    let week = cutover.day;
    if !(1..=5).contains(&week) {
        return None;
    }
    let mut candidate = Fields { year: now.year, month: cutover.month, day: 1, hour: cutover.hour, minute: cutover.minute, second: cutover.second, milliseconds: cutover.milliseconds, weekday: 0 };
    let first = time_to_fields(fields_to_time(&candidate)?).weekday;
    let target = cutover.weekday;
    let mut day = if first > target { target - first + 8 } else if first < target { target - first + 1 } else { 1 };
    let mut chosen = day;
    let mut counted = 1;
    while counted < week {
        day += 7;
        candidate.day = day;
        let Some(time) = fields_to_time(&candidate) else { break };
        chosen = time_to_fields(time).day;
        counted += 1;
    }
    candidate.day = chosen;
    fields_to_time(&candidate)
}
