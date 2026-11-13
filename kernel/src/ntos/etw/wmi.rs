//! Biblioteca WMI: despacho de IRP_MJ_SYSTEM_CONTROL, conclusão de IRPs e
//! saída de rastreamento (WmiSystemControl, WmiCompleteRequest,
//! WmiTraceMessage, WmiQueryTraceInformation).
//!
//! As limitações estão descritas em cada operação.

use crate::ntos::inc::types::{Field, Irp, NtStruct};
use crate::ntos::io::io_manager;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// WmiSystemControl(..., &disposition): escreve disposição zero; ainda não
/// consulta os GUIDs nem despacha os callbacks do bloco de controle.
pub fn system_control(disposition: u64) {
    // SAFETY: PSYSCTL_IRP_DISPOSITION de saída do driver.
    unsafe { Field::<u32>::at(disposition) }.set(0);
}

/// WmiCompleteRequest(device, irp, status, information, increment): grava
/// status e bytes no IRP e conclui; dispositivo e incremento de prioridade
/// não são usados.
pub fn complete_request(packet: u64, status: u32, information: u32) {
    // SAFETY: IRP vivo do driver.
    let request = unsafe { Irp::at(packet) };
    request.io_status.status.set(status as i32);
    request.io_status.information.set(u64::from(information));
    io_manager::iof_complete_request(packet);
}

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
