//! SystemBootEnvironmentInformation (90).
//!
//! Compartilhado por Nt/Zw e modo usuário.

use super::boot_environment;
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;
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
            let _ = guest::try_write32(output_length, 32);
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
        guest::try_write_bytes(output, &information[..16])?;
        guest::try_write32(output + 16, u32::from_le_bytes([information[16], information[17], information[18], information[19]]))?;
        if capacity >= 32 {
            guest::try_write64(output + 24, u64::from_le_bytes(information[24..32].try_into().unwrap()))?;
        }
        Ok(())
    })();
    if written.is_err() {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    // A contagem vem depois dos dados; sobreposição com a saída é permitida.
    if output_length != 0 && guest::try_write32(output_length, if capacity < 32 { 20 } else { 32 }).is_err() {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(0)
}
