//! Informações de energia em modo kernel (ZwPowerInformation).
//!
//! O nível 94 vai ao gravador black box do kernel; o nível 4 descreve um
//! desktop (SYSTEM_POWER_CAPABILITIES sem bateria, AC ligado); o 66
//! (PlatformInformation) devolve o POWER_PLATFORM_INFORMATION. Os demais
//! níveis devolvem STATUS_INVALID_PARAMETER.

use crate::ntos::inc::types::{NtStruct, SystemPowerCapabilities};
use crate::ntos::po::black_box;
use crate::rtl::KernelError;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// POWER_INFORMATION_LEVEL PlatformInformation.
const PLATFORM_INFORMATION: u32 = 66;

/// PlatformInformation: sem entrada e com saída, POWER_PLATFORM_INFORMATION
/// { BOOLEAN AoAc } com o PopPlatformAoAc, FALSE numa plataforma sem
/// Modern Standby (o padrão do 19041 e o desta máquina).
fn platform_information(input: u64, output: u64, output_length: u32) -> u32 {
    if input != 0 || output_length == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: o BOOLEAN de saída do chamador (Zw, KernelMode).
    unsafe { crate::ntos::inc::field::Field::<u8>::at(output) }.set(0);
    0
}

/// ZwPowerInformation: 94 = black box do kernel; 4 = SystemPowerCapabilities
/// de desktop (sem bateria, AC ligado). Devolve o NTSTATUS.
pub fn query(level: u32, input: u64, input_length: u32, output: u64, output_length: u32) -> Result<u32, KernelError> {
    if level == 94 {
        return black_box::update_from_kernel(input, input_length, output, output_length);
    }
    if level == PLATFORM_INFORMATION {
        return Ok(platform_information(input, output, output_length));
    }
    if level != 4 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if output_length < 0x40 {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    // SAFETY: buffer SYSTEM_POWER_CAPABILITIES do chamador (Zw, KernelMode).
    let capabilities = unsafe { SystemPowerCapabilities::at(output) };
    capabilities.power_button_present.set(1);
    capabilities.sleep_button_present.set(1);
    capabilities.lid_present.set(0);
    capabilities.system_s1.set(1);
    capabilities.system_s5.set(1);
    capabilities.ups_present.set(1);
    Ok(0)
}
