//! Estado estendido do processador salvo pelos drivers
//! (KeSaveExtendedProcessorState / KeRestoreExtendedProcessorState).
//!
//! XSTATE_SAVE próprio: assinatura 'XS' em +0 e uma área FXSAVE de 512
//! bytes alinhada a 16 em +8. A máscara de recursos estendidos ainda não
//! seleciona nada além do FXSAVE.

use crate::hal::cpu;
use crate::ntos::inc::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::ntos::mm::guest_memory as guest;

/// KeSaveExtendedProcessorState: salva o FXSAVE num bloco novo e grava o
/// ponteiro do bloco na saída.
pub fn save(state_out: u64) {
    let state = guest::alloc_bytes(0x20);
    let area = guest::alloc_aligned(0x200, 16, true);
    guest::write32(state, 0x5358);
    guest::write64(state + 8, area);
    cpu::fxsave(area);
    guest::write64(state_out, state);
}

/// KeRestoreExtendedProcessorState: restaura a área do bloco e libera os
/// dois. Devolve o NTSTATUS.
pub fn restore(state: u64) -> u32 {
    if state == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let area = guest::read64(state + 8);
    cpu::fxrstor(area);
    guest::free_bytes(area);
    guest::free_bytes(state);
    STATUS_SUCCESS
}
