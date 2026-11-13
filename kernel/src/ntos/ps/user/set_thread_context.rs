//! Ramo de execução de usuário da operação de contexto — `system32/ntos/ps/user/set-thread-context.js`.
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
        let selected = guest::read32(source + 0x30);
        let prepared = context_frame::prepare(context, selected);
        let mask = match guest::read32(fx + 0x1C) {
            0 => 0xFFBF,
            mask => mask,
        };
        registers::write_saved_context(context, source, 1, mask, guest::read32(fx + 0x18))?;
        let debug = selected & 0x10_0010 == 0x10_0010;
        if debug {
            let active = guest::read64(context + 0x70) & 0x355 != 0;
            guest::write8(thread + 3, (guest::read8(thread + 3) & !1) | active as u8);
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
