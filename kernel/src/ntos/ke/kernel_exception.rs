//! Despacho de primeira chance de traps reais do anel 0.
//!
//! O provedor materializa EXCEPTION_RECORD e CONTEXT; filtros SEH podem
//! pedir continuação ou desenrolar a pilha.

use crate::ntos::inc::types::{Context, ExceptionRecord, NtStruct};
use crate::ntos::mm::small as mm_small;
use crate::ntos::ps::context::kernel_frame as kernel_context_frame;
use crate::ntos::rtl::{exceptions, native_context};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Vetores cujo frame nativo traz o código de erro antes do estado de retorno.
fn has_error_code(vector: u32) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30)
}

/// NTSTATUS dos vetores reconhecidos; #GP exige classificação adicional.
fn status_by_vector(vector: u32) -> Option<u32> {
    Some(match vector {
        0 => 0xC000_0094,
        3 => 0x8000_0003,
        4 => 0xC000_0095,
        5 => 0xC000_008C,
        6 => 0xC000_001D,
        14 => 0xC000_0005,
        0x2D => 0x8000_0003,
        _ => return None,
    })
}

/// RDMSR/WRMSR no endereço de uma #GP com código zero; não usa o índice do
/// MSR nem o retorno do driver para adivinhar o motivo.
fn is_model_specific_register_fault(rip: u64, error_code: u64) -> bool {
    if error_code != 0 {
        return false;
    }
    // Grupos de prefixo já vistos; repetição ou instrução ilegível deixa a
    // proteção geral sem classificação.
    let mut seen = 0u32;
    for offset in 0..14u64 {
        let Ok(byte) = guest::try_read::<u8>(rip + offset) else { return false };
        if byte == 0x0F {
            return matches!(guest::try_read::<u8>(rip + offset + 1), Ok(0x30 | 0x32));
        }
        let group = match byte {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => 1,
            0x66 => 2,
            0x67 => 4,
            0xF2 | 0xF3 => 8,
            0x40..=0x4F => 16,
            _ => 0,
        };
        if group == 0 || seen & group != 0 {
            return false;
        }
        seen |= group;
    }
    false
}

/// Só vetores suportados: captura o frame de interrupção, monta a exceção e
/// encaminha ao SEH; uma continuação válida é confirmada no frame nativo.
pub fn dispatch(vector: u32, registers: u64, fx: u64, interrupt: u64, workspace: u64) -> Result<bool, KernelError> {
    if vector != 13 && status_by_vector(vector).is_none() {
        return Ok(false);
    }
    let hardware_offset = if has_error_code(vector) { 8 } else { 0 };
    kernel_context_frame::with_interrupt(
        registers,
        fx,
        interrupt,
        workspace,
        || -> Result<bool, KernelError> {
            let Some(context) = kernel_context_frame::current_context() else { return Ok(false) };
            // SAFETY: CONTEXT materializado pelo dono do frame no workspace.
            let frame = unsafe { Context::at(context) };
            // O registro temporário fica em workspace+0xA00, separado do
            // CONTEXT capturado pelo dono do frame.
            let record = workspace + 0xA00;
            // SAFETY: área própria do workspace de trap, livre durante o despacho.
            let exception = unsafe { ExceptionRecord::at(record) };
            let rip = frame.rip.get();
            // Bloco de estado da interrupção do OpenNT: código de erro e CR2.
            let error_code = guest::read64(interrupt + 64);
            let fault_address = guest::read64(interrupt + 72);
            let page_failure = if vector == 14 { mm_small::consume_page_fault_failure(fault_address, error_code as u32) } else { None };
            if vector == 13 && !is_model_specific_register_fault(rip, error_code) {
                return Ok(false);
            }
            let status = if page_failure.is_some() { 0xC000_0006 } else if vector == 13 { 0xC000_0096 } else { status_by_vector(vector).unwrap_or(0) };
            exception.exception_code.set(status as i32);
            exception.exception_flags.set(0);
            exception.exception_record.set(0);
            exception.number_parameters.set(0);
            exception.exception_address.set(rip);
            let information = &exception.exception_information;
            if vector == 0x2D {
                // O serviço de depuração ajusta o endereço do breakpoint pelo
                // caminho nativo observado; este boot não tem transporte KD.
                let service = frame.rax.get();
                exception.exception_address.set(rip + 1);
                exception.number_parameters.set(1);
                information[0].set(service);
                // Com KD inativo esses serviços avançam o CONTEXT sem
                // fabricar resposta de depurador.
                if matches!(service, 1 | 3 | 4 | 5) {
                    frame.rip.set(rip + 1);
                    kernel_context_frame::commit_current()?;
                    return Ok(true);
                }
            } else if vector == 3 {
                frame.rip.set(rip.wrapping_sub(1));
            } else if vector == 14 {
                // Bit 4 = execução, bit 1 = escrita; o endereço vem do frame
                // capturado da CPU.
                exception.number_parameters.set(if page_failure.is_some() { 3 } else { 2 });
                information[0].set(if error_code & 16 != 0 { 8 } else if error_code & 2 != 0 { 1 } else { 0 });
                information[1].set(fault_address);
                // O KiPageFault original publica o status de I/O como ULONG.
                if let Some(failure) = page_failure {
                    information[2].set(failure.status as u64);
                }
            }
            native_context::invoke(context, || exceptions::dispatch_exception(record, context))?;
            // Voltar do despachante sem continuação deixaria a CPU com
            // estado de retorno indefinido.
            // Ação de continuação: célula do OpenNT logo depois do CONTEXT.
            if guest::read32(context + native_context::ACTION) == 0 {
                return Err(KernelError::new("kernel exception dispatch returned without a continuation"));
            }
            kernel_context_frame::commit_current()?;
            Ok(true)
        },
        hardware_offset,
    )?
}
