//! SystemManufacturingInformation (classe 157 do NtQuerySystemInformation).
//!
//! O ExpQuerySystemInformation 19041 devolve o ExpManufacturingInformation:
//! o tamanho pedido é o SYSTEM_MANUFACTURING_INFORMATION (0x18) mais o
//! MaximumLength do ProfileName, e um buffer menor recebe
//! STATUS_INFO_LENGTH_MISMATCH com esse tamanho em ReturnLength (o smss
//! pergunta com buffer nulo e depois aloca). Na saída vão Options, o
//! ProfileName apontando para logo depois da estrutura e o texto. O OpenNT
//! não tem modo de fabricação (o MfgInitSystem não acha a chave
//! `Control\ManufacturingMode`): Options 0 e perfil vazio.

use core::mem::{offset_of, size_of};

use crate::ntos::inc::types::extra_ps_user::SystemManufacturingInformation;
use crate::ntos::inc::types::UnicodeString;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;

/// O ExpManufacturingInformation do OpenNT: Options e o perfil (UTF-16).
fn current() -> (u32, &'static [u16]) {
    (0, &[])
}

/// A consulta: (buffer, capacidade, PULONG ReturnLength, modo de usuário).
pub fn query(output: u64, buffer_length: u64, output_length: u64, from_user_mode: bool) -> Result<u32, KernelError> {
    let capacity = buffer_length as u32 as u64;
    if from_user_mode {
        if capacity != 0 && output & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if (capacity != 0 && !user_probe::probe_user_write(output, capacity)) || (output_length != 0 && !user_probe::probe_user_write(output_length, 4)) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let (options, profile) = current();
    let profile_bytes = (profile.len() * 2) as u64;
    let required = size_of::<SystemManufacturingInformation>() as u64 + profile_bytes;
    let set_returned = || if output_length != 0 { guest::try_write::<u32>(output_length, required as u32) } else { Ok(()) };
    if capacity < required {
        return Ok(set_returned().map_or(STATUS_ACCESS_VIOLATION, |()| STATUS_INFO_LENGTH_MISMATCH));
    }
    let written = (|| -> Result<(), KernelError> {
        let name = output + offset_of!(SystemManufacturingInformation, profile_name) as u64;
        guest::try_write::<u32>(output + offset_of!(SystemManufacturingInformation, options) as u64, options)?;
        guest::try_write::<u16>(name + offset_of!(UnicodeString, length) as u64, profile_bytes as u16)?;
        guest::try_write::<u16>(name + offset_of!(UnicodeString, maximum_length) as u64, profile_bytes as u16)?;
        let text = output + size_of::<SystemManufacturingInformation>() as u64;
        guest::try_write::<u64>(name + offset_of!(UnicodeString, buffer) as u64, if profile.is_empty() { 0 } else { text })?;
        let bytes: alloc::vec::Vec<u8> = profile.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        guest::try_write_bytes(text, &bytes)?;
        set_returned()
    })();
    Ok(written.map_or(STATUS_ACCESS_VIOLATION, |()| 0))
}
