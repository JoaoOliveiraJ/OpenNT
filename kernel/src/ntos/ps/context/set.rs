//! Operação por trás dos wrappers x64 públicos/privados.
//!
//! O modo de sondagem descreve o buffer de entrada; o modo de contexto
//! escolhe o estado de execução de destino. A interrupção da HAL já salvou
//! cada registrador não volátil e possui o local de restauração; um frame de
//! kernel ausente continua uma falha real.

use alloc::boxed::Box;

use crate::ntos::ps::context::apc::{self as context_apc, Request};
use crate::ntos::ps::context::input::{self as thread_context_input, Captured};
use crate::ntos::ps::context::kernel_frame as kernel_context_frame;
use crate::ntos::ps::process;
use crate::ntos::ke::{dispatcher, irql};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Context, Ethread};

/// Operação em andamento; a entrada capturada sai na conclusão.
pub enum Operation {
    Completed(u32),
    Pending { request: Request, captured: alloc::sync::Arc<SpinLock<Captured>> },
}

impl Operation {
    pub fn poll(&mut self) -> Result<Option<u32>, KernelError> {
        match self {
            Operation::Completed(status) => Ok(Some(*status)),
            Operation::Pending { request, captured } => {
                let result = request.poll();
                if !matches!(result, Ok(None)) {
                    captured.lock().release();
                }
                result
            }
        }
    }

    pub fn cancel(&mut self) -> Result<(), KernelError> {
        if let Operation::Pending { request, captured } = self {
            let result = request.cancel();
            captured.lock().release();
            return result;
        }
        Ok(())
    }
}

pub fn begin(thread: u64, input: u64, probe_mode: u8, context_mode: u8, flags: u32) -> Result<Operation, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("context operation requires IRQL <= APC_LEVEL"));
    }
    let Some(record) = process::thread_record(thread) else { return Err(KernelError::new("context operation requires an existing ETHREAD")) };
    let mut captured = match thread_context_input::capture(input, probe_mode)? {
        Ok(captured) => captured,
        Err(status) => return Ok(Operation::Completed(status)),
    };
    // A captura e a validação precedem o teste de SystemThread.
    // SAFETY: ETHREAD existente (conferido pelo registro acima).
    if context_mode != 0 && unsafe { Ethread::at(thread) }.tcb.system_thread() != 0 {
        captured.release();
        return Ok(Operation::Completed(0xC000_0030));
    }
    let caller = process::thread_record(process::get_current_thread());
    if context_mode != 0 && flags & 2 == 0 && caller.is_some_and(|caller| caller.process == record.process) && captured.flags & 0x10_0001 == 0x10_0001 {
        // CONTEXT.SegCs da entrada capturada (a cópia própria ou o buffer de
        // KernelMode, sem exigência de alinhamento).
        guest::write::<u16>(captured.source + core::mem::offset_of!(Context, seg_cs) as u64, 0x33);
    }
    let source = captured.source;
    let captured = alloc::sync::Arc::new(SpinLock::new(captured));
    let operation: context_apc::Operation = Box::new(move || if context_mode != 0 { crate::ntos::ps::user::set_thread_context::apply(thread, source) } else { kernel_context_frame::apply_kernel(source) });
    match context_apc::begin(thread, operation) {
        Ok(request) => Ok(Operation::Pending { request, captured }),
        Err(error) => {
            captured.lock().release();
            Err(error)
        }
    }
}

pub fn execute(thread: u64, input: u64, probe_mode: u8, context_mode: u8, flags: u32) -> Result<u32, KernelError> {
    let mut operation = begin(thread, input, probe_mode, context_mode, flags)?;
    let result = loop {
        match operation.poll() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => dispatcher::pump_kernel(),
            Err(error) => break Err(error),
        }
    };
    operation.cancel()?;
    result
}
