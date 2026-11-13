//! Saída de rastreamento WMI do ntoskrnl (WmiTraceMessage e
//! WmiQueryTraceInformation).
//!
//! As limitações estão descritas em cada operação.

use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// WmiTraceMessage(handle, level, guid, msgId, fmt, ...): texto formatado
/// para a serial com os quatro primeiros argumentos variáveis.
pub fn trace_message(format: u64, arguments: [u64; 4]) -> Result<(), KernelError> {
    let format_text = guest_strings::read_c_string(format);
    let text = guest_strings::format_guest_text(&format_text, &mut |index| arguments.get(index).copied().unwrap_or(0), false)?;
    let text = text.strip_suffix('\n').map(|rest| rest.strip_suffix('\r').unwrap_or(rest)).unwrap_or(&text);
    debug_print!("[wmitrace] {}", text);
    Ok(())
}

/// WmiQueryTraceInformation(class, buffer, length, &required, ...): zera até
/// 0x30 bytes em palavras de quatro bytes, sem distinguir classes.
pub fn query_trace_information(buffer: u64, length: u32, required_out: u64) {
    let reported = length.min(0x30);
    // Zera em DWORDs inteiros, como antes (um resto menor que 4 também).
    guest::write_bytes(buffer, &alloc::vec![0u8; reported.div_ceil(4) as usize * 4]);
    if required_out != 0 {
        // SAFETY: PULONG de saída do driver.
        unsafe { Field::<u32>::at(required_out) }.set(reported);
    }
}
