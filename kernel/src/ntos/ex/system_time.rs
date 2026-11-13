//! Hora do sistema e hora local do Executive (ExSystemTimeToLocalTime).
//!
//! Sem fuso horário configurado, o deslocamento entre UTC e a hora local é
//! zero.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::LargeInteger;

/// UTC para a hora local do runtime: sem fuso configurado o deslocamento é
/// zero.
pub fn system_time_to_local_time(system_time: u64, local_time: u64) {
    const TIMEZONE_OFFSET_MINUTES: i64 = 0;
    // SAFETY: os PLARGE_INTEGER do chamador (modo kernel).
    let (universal, local_time) = unsafe { (LargeInteger::at(system_time), LargeInteger::at(local_time)) };
    let local = universal.quad_part.get() - TIMEZONE_OFFSET_MINUTES * 60 * 10_000_000;
    local_time.quad_part.set(local);
}
