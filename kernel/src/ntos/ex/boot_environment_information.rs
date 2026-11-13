//! SystemBootEnvironmentInformation (90).
//!
//! Compartilhado por Nt/Zw e modo usuário.

use super::boot_environment;
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;
use core::mem::offset_of;

use crate::ntos::inc::types::SystemBootEnvironmentInformation as Information;
use crate::ntos::mm::guest_memory as guest;

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

pub fn query(output: u64, buffer_length: u64, output_length: u64, from_user_mode: bool) -> Result<u32, KernelError> {
    let capacity = buffer_length as u32;
    if from_user_mode {
        if capacity != 0 && output & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_write(output, capacity as u64) || (output_length != 0 && !user_probe::probe_user_write(output_length, 4)) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if capacity < 20 {
        // O caminho curto informa o tamanho atual e conserva LENGTH_MISMATCH
        // mesmo se a escrita de ReturnLength falhar.
        if output_length != 0 {
            let _ = guest::try_write::<u32>(output_length, size_of::<Information>() as u32);
        }
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let information = boot_environment::get_information()?;
    if output == 0 {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    // GUID + FirmwareType existem também no formato antigo de 20 bytes; o
    // padding 20..23 pertence ao chamador.
    let written = (|| -> Result<(), KernelError> {
        // Só os campos que cabem na capacidade (20 bytes sem BootFlags).
        guest::try_write_bytes(output + offset_of!(Information, boot_identifier) as u64, &information[..16])?;
        guest::try_write::<i32>(output + offset_of!(Information, firmware_type) as u64, i32::from_le_bytes([information[16], information[17], information[18], information[19]]))?;
        if capacity >= size_of::<Information>() as u32 {
            guest::try_write::<u64>(output + offset_of!(Information, boot_flags) as u64, u64::from_le_bytes(information[24..32].try_into().unwrap()))?;
        }
        Ok(())
    })();
    if written.is_err() {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    // A contagem vem depois dos dados; sobreposição com a saída é permitida.
    if output_length != 0 && guest::try_write::<u32>(output_length, if capacity < size_of::<Information>() as u32 { 20 } else { size_of::<Information>() as u32 }).is_err() {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(0)
}
