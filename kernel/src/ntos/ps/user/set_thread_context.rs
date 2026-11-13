//! Ramo de execução de usuário da operação de contexto.
//!
//! O escalonador possui o CONTEXT arquitetural completo salvo pela HAL,
//! inclusive os não voláteis.

use super::{context_frame, threads};
use crate::hal::cpu;
use crate::hal::amd64::usermode;
use crate::ntos::ke::irql;
use crate::ntos::ps::process;
use crate::ntos::ps::context::{set as set_thread_context, registers as registers};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Context, Kthread, NtStruct, XsaveFormat};

pub fn apply(thread: u64, source: u64) -> Result<u32, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("context operation requires IRQL <= APC_LEVEL"));
    }
    if process::get_current_thread() != thread {
        return Err(KernelError::new("user context operation delivered to another thread"));
    }
    let exiting = process::thread_record(thread).is_none_or(|record| record.exiting);
    let runtime = threads::find_by_pointer(thread);
    let context = runtime.as_ref().filter(|runtime| !runtime.dead()).map_or(0, |runtime| runtime.with(|thread| thread.context));
    if exiting || context == 0 {
        return Ok(0xC000_0001);
    }
    // Reserva todo o armazenamento antes de alterar o destino; o FXSAVE
    // mede a máscara real e o MXCSR atual, sem adivinhar pela entrada.
    let fx = guest::alloc_aligned(512, 16, false);
    if fx == 0 {
        return Ok(0xC000_009A);
    }
    let result = (|| -> Result<u32, KernelError> {
        cpu::fxsave(fx);
        // SAFETY: CONTEXT capturado em memória do kernel pelo `begin`, a
        // imagem FXSAVE recém-gravada e o CONTEXT salvo da thread corrente.
        let (captured, image, live) = unsafe { (Context::at(source), XsaveFormat::at(fx), Context::at(context)) };
        let selected = captured.context_flags.get();
        let prepared = context_frame::prepare(context, selected);
        let mask = match image.mx_csr_mask.get() {
            0 => 0xFFBF,
            mask => mask,
        };
        registers::write_saved_context(context, source, 1, mask, image.mx_csr.get())?;
        let debug = selected & 0x10_0010 == 0x10_0010;
        if debug {
            // Header.DebugActive.ActiveDR7: CAS atômico no byte (os bits
            // vizinhos do mesmo byte não se perdem).
            // SAFETY: KTHREAD da thread corrente.
            unsafe { Kthread::at(thread) }.header.set_active_dr7((live.dr7.get() & 0x355 != 0) as u8);
        }
        if prepared.retain() && debug {
            usermode::set_user_debug_registers(context + 0x48);
        }
        Ok(0)
    })();
    guest::free_bytes(fx);
    result
}

pub fn begin(thread: u64, input: u64, probe_mode: u8, flags: u32) -> Result<set_thread_context::Operation, KernelError> {
    set_thread_context::begin(thread, input, probe_mode, 1, flags)
}

pub fn execute(thread: u64, input: u64, probe_mode: u8, flags: u32) -> Result<u32, KernelError> {
    set_thread_context::execute(thread, input, probe_mode, 1, flags)
}
