//! Hora do sistema e hora local do Executive (ExSystemTimeToLocalTime).
//!
//! Sem fuso horário configurado, o deslocamento entre UTC e a hora local é
//! zero.

use crate::ntos::mm::guest_memory as guest;

/// UTC para a hora local do runtime: sem fuso configurado o deslocamento é
/// zero.
pub fn system_time_to_local_time(system_time: u64, local_time: u64) {
    const TIMEZONE_OFFSET_MINUTES: i64 = 0;
    let universal = guest::read64(system_time) as i64;
    let local = universal - TIMEZONE_OFFSET_MINUTES * 60 * 10_000_000;
    guest::write64(local_time, local as u64);
}
