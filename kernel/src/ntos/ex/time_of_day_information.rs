//! SystemTimeOfDayInformation (classe 3 do NtQuerySystemInformation).
//!
//! O ExpQuerySystemInformation 19041 (o ramo da classe 3): um comprimento
//! maior que o SYSTEM_TIMEOFDAY_INFORMATION (0x30) é
//! STATUS_INFO_LENGTH_MISMATCH com 0x30 em ReturnLength. Senão a estrutura é
//! montada numa cópia zerada — BootTime, CurrentTime e BootTimeBias do
//! KeQueryBootTimeValues, TimeZoneBias e TimeZoneId dos globais de fuso do
//! silo, SleepTimeBias do KUSER_SHARED_DATA.InterruptTimeBias — e só os
//! primeiros Length bytes vão ao buffer (não há mínimo: o basesrv e o
//! RtlSystemTimeToLocalTime pedem a estrutura inteira, outros pedem só o
//! começo); ReturnLength recebe Length. Do modo usuário o buffer passa pelo
//! ProbeForWrite com alinhamento 4 e o ReturnLength é sondado antes.

use core::mem::size_of;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_ps_user::SystemTimeofdayInformation;
use crate::ntos::ke::clock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::shared_user_data;
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;

use super::system_time;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const SIZE: u64 = size_of::<SystemTimeofdayInformation>() as u64;

/// A estrutura completa, montada como o ramo do NT: os bytes do
/// SYSTEM_TIMEOFDAY_INFORMATION (Reserved zero).
pub fn snapshot() -> [u8; SIZE as usize] {
    let mut bytes = [0u8; SIZE as usize];
    let (current, boot, boot_bias) = clock::query_boot_time_values();
    let sleep_bias = shared_user_data::data().map_or(0, |shared| shared.interrupt_time_bias.get());
    // SAFETY: cópia local do tamanho exato da estrutura.
    let info = unsafe { SystemTimeofdayInformation::at(bytes.as_mut_ptr() as u64) };
    info.boot_time.set(boot as i64);
    info.current_time.set(current as i64);
    info.time_zone_bias.set(system_time::time_zone_bias());
    info.time_zone_id.set(system_time::time_zone_id());
    info.boot_time_bias.set(boot_bias);
    info.sleep_time_bias.set(sleep_bias);
    bytes
}

/// A consulta: (buffer, capacidade, PULONG ReturnLength, modo de usuário).
pub fn query(output: u64, buffer_length: u64, output_length: u64, from_user_mode: bool) -> Result<u32, KernelError> {
    let length = buffer_length as u32 as u64;
    if from_user_mode {
        if length != 0 && output & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if (length != 0 && !user_probe::probe_user_write(output, length)) || (output_length != 0 && !user_probe::probe_user_write(output_length, 4)) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let set_returned = |value: u64| if output_length != 0 { guest::try_write::<u32>(output_length, value as u32) } else { Ok(()) };
    if length > SIZE {
        return Ok(set_returned(SIZE).map_or(STATUS_ACCESS_VIOLATION, |()| STATUS_INFO_LENGTH_MISMATCH));
    }
    let bytes = snapshot();
    let written = guest::try_write_bytes(output, &bytes[..length as usize]).and_then(|()| set_returned(length));
    Ok(written.map_or(STATUS_ACCESS_VIOLATION, |()| 0))
}
