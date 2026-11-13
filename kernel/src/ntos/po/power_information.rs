//! Informações de energia em modo kernel (ZwPowerInformation).
//!
//! O nível 94 vai ao gravador black box do kernel; o nível 4 descreve um
//! desktop (SYSTEM_POWER_CAPABILITIES sem bateria, AC ligado). Os demais
//! níveis devolvem STATUS_INVALID_PARAMETER.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::black_box;
use crate::rtl::KernelError;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// ZwPowerInformation: 94 = black box do kernel; 4 = SystemPowerCapabilities
/// de desktop (sem bateria, AC ligado). Devolve o NTSTATUS.
pub fn query(level: u32, input: u64, input_length: u32, output: u64, output_length: u32) -> Result<u32, KernelError> {
    if level == 94 {
        return black_box::update_from_kernel(input, input_length, output, output_length);
    }
    if level != 4 {
        return Ok(0xC000_000D);
    }
    if output_length < 0x40 {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let destination = output;
    guest::write8(destination, 1);
    guest::write8(destination + 1, 1);
    guest::write8(destination + 2, 0);
    guest::write8(destination + 3, 1);
    guest::write8(destination + 7, 1);
    guest::write8(destination + 0x0C, 1);
    Ok(0)
}
