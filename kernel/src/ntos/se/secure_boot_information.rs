//! SystemSecureBootPolicyInformation (143).
//!
//! Metadados reais da política do loader.

use super::secure_boot_policy;
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_SECUREBOOT_NOT_ENABLED: u32 = 0x8043_0006;
const INFORMATION_BYTE_LENGTH: u32 = 24;

pub fn query(output: u64, buffer_length: u64, output_length: u64, from_user_mode: bool) -> Result<u32, KernelError> {
    let capacity = buffer_length as u32;
    if from_user_mode {
        // A sondagem vem antes da política; ReturnLength aceita desalinhamento.
        if capacity != 0 && output & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_write(output, capacity as u64) || (output_length != 0 && !user_probe::probe_user_write(output_length, 4)) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let (mut status, returned) = match secure_boot_policy::get_information()? {
        // A ausência da política precede a validação de capacidade; nenhum
        // byte do buffer é tocado.
        None => (STATUS_SECUREBOOT_NOT_ENABLED, 0),
        Some(information) => {
            let status = if capacity < INFORMATION_BYTE_LENGTH {
                STATUS_INFO_LENGTH_MISMATCH
            } else if output == 0 || guest::try_write_bytes(output, &information).is_err() {
                STATUS_ACCESS_VIOLATION
            } else {
                0
            };
            (status, INFORMATION_BYTE_LENGTH)
        }
    };
    // A contagem é escrita depois da saída, inclusive nas falhas de capacidade.
    if output_length != 0 && guest::try_write::<u32>(output_length, returned).is_err() {
        status = STATUS_ACCESS_VIOLATION;
    }
    Ok(status)
}
