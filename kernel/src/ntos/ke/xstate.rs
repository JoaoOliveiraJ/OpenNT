//! Estado estendido do processador salvo pelos drivers
//! (KeSaveExtendedProcessorState / KeRestoreExtendedProcessorState).
//!
//! O XSTATE_SAVE é do chamador (0x38 bytes): o kernel preenche Thread, Level
//! e o XSTATE_CONTEXT, cuja Area aponta uma área FXSAVE de 512 bytes
//! alinhada a 16. A máscara de recursos estendidos ainda não seleciona nada
//! além do FXSAVE.

use crate::hal::cpu;
use crate::ntos::inc::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::ntos::inc::types::{NtStruct, XsaveFormat, XstateSave};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;

use super::irql;

/// KeSaveExtendedProcessorState(Mask, XStateSave): salva o FXSAVE numa área
/// nova descrita no XSTATE_SAVE do chamador.
pub fn save(mask: u64, state: u64) {
    // SAFETY: PXSTATE_SAVE do chamador.
    let save = unsafe { XstateSave::at(state) };
    let area = guest::alloc_aligned(XsaveFormat::SIZE, 16, true);
    cpu::fxsave(area);
    save.prev.set(0);
    save.thread.set(process::get_current_thread());
    save.level.set(irql::get_irql());
    save.x_state_context.mask.set(mask);
    save.x_state_context.length.set(XsaveFormat::SIZE as u32);
    save.x_state_context.reserved1.set(0);
    save.x_state_context.area.set(area);
    save.x_state_context.buffer.set(area);
}

/// KeRestoreExtendedProcessorState(XStateSave): restaura a área descrita no
/// XSTATE_SAVE e a libera (o XSTATE_SAVE continua do chamador). Devolve o
/// NTSTATUS.
pub fn restore(state: u64) -> u32 {
    if state == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: o XSTATE_SAVE preenchido por `save`.
    let save = unsafe { XstateSave::at(state) };
    let area = save.x_state_context.area.get();
    if area == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    cpu::fxrstor(area);
    save.x_state_context.area.set(0);
    save.x_state_context.buffer.set(0);
    guest::free_bytes(area);
    STATUS_SUCCESS
}
