//! Rotinas do chamador executadas pelo kernel num contexto pedido:
//! KeExpandKernelStackAndCalloutEx, KeIpiGenericCall e KeGenericCallDpc
//! (com KeSignalCallDpcDone e KeSignalCallDpcSynchronize).
//!
//! A pilha do kernel já garante os bytes pedidos, então o callout é chamado
//! de verdade. Os drivers rodam no processador de boot: o broadcast do
//! KeIpiGenericCall é local, e a rotina do KeGenericCallDpc roda como DPC
//! (DISPATCH_LEVEL) nesse processador, com SystemArgument1 apontando a
//! contagem de pendentes (KeSignalCallDpcDone) e SystemArgument2 a barreira
//! (KeSignalCallDpcSynchronize). As duas contam os participantes reais,
//! então a espera sempre termina.

use super::{dpc, irql};
use crate::hal::amd64::native_call;
use crate::ntos::inc::nt_abi::kdpc;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// Bloco da chamada: +0 pendentes, +8 barreira { restantes, participantes, sentido }.
const CALL_DPC_BLOCK: u64 = 0x20;
const CALL_DPC_BARRIER: u64 = 8;

/// KeExpandKernelStackAndCalloutEx: chama `callout(parameter, context)` na
/// pilha atual e devolve o resultado em 32 bits.
pub fn expand_kernel_stack_and_callout(callout: u64, parameter: u64, context: u64) -> i32 {
    native_call::call(callout, &[parameter, context]) as i32
}

/// KeIpiGenericCall: a rotina roda uma vez, no processador corrente.
pub fn ipi_generic_call(routine: u64, context: u64) -> u64 {
    native_call::call(routine, &[context, 0])
}

fn atomic_add32(pointer: u64, delta: i32) -> i32 {
    loop {
        let value = guest::read32(pointer);
        let next = (value as i32).wrapping_add(delta);
        if guest::compare_exchange32(pointer, value, next as u32).unwrap_or_else(|error| panic!("{error}")) == value {
            return next;
        }
    }
}

/// KeGenericCallDpc: roda `routine` como DPC em cada participante e espera
/// todos avisarem o fim.
pub fn generic_call_dpc(routine: u64, context: u64) -> Result<(), KernelError> {
    let participants = 1u32;
    let block = guest::alloc_bytes(CALL_DPC_BLOCK);
    let dpc = guest::alloc_bytes(kdpc::SIZE);
    if block == 0 || dpc == 0 {
        return Err(KernelError::new("KeGenericCallDpc: sem memoria para a DPC"));
    }
    guest::write_bytes(block, &[0; CALL_DPC_BLOCK as usize]);
    guest::write32(block, participants);
    guest::write32(block + CALL_DPC_BARRIER, participants);
    guest::write32(block + CALL_DPC_BARRIER + 4, participants);
    dpc::initialize_dpc(dpc, routine, context);
    guest::write64(dpc + kdpc::SYSARG1, block);
    guest::write64(dpc + kdpc::SYSARG2, block + CALL_DPC_BARRIER);
    let previous = irql::raise_at_least(irql::DISPATCH_LEVEL);
    native_call::call(routine, &[dpc, context, block, block + CALL_DPC_BARRIER]);
    irql::lower_irql(previous as u64);
    // Todos os participantes avisam o fim antes de a chamada voltar.
    while guest::read32(block) as i32 > 0 {
        core::hint::spin_loop();
    }
    guest::free_bytes(dpc);
    guest::free_bytes(block);
    Ok(())
}

/// KeSignalCallDpcDone: um participante a menos.
pub fn signal_call_dpc_done(pending: u64) {
    atomic_add32(pending, -1);
}

/// KeSignalCallDpcSynchronize: barreira entre os participantes; TRUE para
/// exatamente um (o último a chegar), que rearma a barreira.
pub fn signal_call_dpc_synchronize(barrier: u64) -> bool {
    let sense = guest::read32(barrier + 8);
    if atomic_add32(barrier, -1) == 0 {
        guest::write32(barrier, guest::read32(barrier + 4));
        guest::write32(barrier + 8, sense ^ 1);
        return true;
    }
    while guest::read32(barrier + 8) == sense {
        core::hint::spin_loop();
    }
    false
}
