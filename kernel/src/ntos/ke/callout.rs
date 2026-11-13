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

use core::sync::atomic::Ordering;

use super::{dpc, irql};
use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::Kdpc;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// Barreira de KeSignalCallDpcSynchronize (SystemArgument2 da DPC).
#[repr(C)]
struct CallDpcBarrier {
    remaining: Field<i32>,
    participants: Field<i32>,
    sense: Field<u32>,
    _pad_0c: Reserved<4>,
}

/// Bloco da chamada (memória do OpenNT): pendentes (SystemArgument1 da DPC,
/// para KeSignalCallDpcDone) e a barreira.
#[repr(C)]
struct CallDpcBlock {
    pending: Field<i32>,
    _pad_04: Reserved<4>,
    barrier: CallDpcBarrier,
    _pad_18: Reserved<8>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CallDpcBarrier {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CallDpcBlock {}

const _: () = {
    assert!(core::mem::size_of::<CallDpcBlock>() == 0x20);
    assert!(core::mem::offset_of!(CallDpcBlock, barrier) == 8);
};

/// KeExpandKernelStackAndCalloutEx: chama `callout(parameter, context)` na
/// pilha atual e devolve o resultado em 32 bits.
pub fn expand_kernel_stack_and_callout(callout: u64, parameter: u64, context: u64) -> i32 {
    native_call::call(callout, &[parameter, context]) as i32
}

/// KeIpiGenericCall: a rotina roda uma vez, no processador corrente.
pub fn ipi_generic_call(routine: u64, context: u64) -> u64 {
    native_call::call(routine, &[context, 0])
}

/// KeGenericCallDpc: roda `routine` como DPC em cada participante e espera
/// todos avisarem o fim.
pub fn generic_call_dpc(routine: u64, context: u64) -> Result<(), KernelError> {
    let participants = 1i32;
    let block = guest::alloc_bytes(CallDpcBlock::SIZE);
    let dpc = guest::alloc_bytes(Kdpc::SIZE);
    if block == 0 || dpc == 0 {
        return Err(KernelError::new("KeGenericCallDpc: sem memoria para a DPC"));
    }
    guest::write_bytes(block, &[0; CallDpcBlock::SIZE as usize]);
    // SAFETY: blocos recém-alocados dos tamanhos dos tipos.
    let (call, object) = unsafe { (CallDpcBlock::at(block), Kdpc::at(dpc)) };
    call.pending.set(participants);
    call.barrier.remaining.set(participants);
    call.barrier.participants.set(participants);
    dpc::initialize_dpc(dpc, routine, context);
    object.system_argument1.set(call.pending.address());
    object.system_argument2.set(call.barrier.address());
    let previous = irql::raise_at_least(irql::DISPATCH_LEVEL);
    native_call::call(routine, &[dpc, context, call.pending.address(), call.barrier.address()]);
    irql::lower_irql(previous as u64);
    // Todos os participantes avisam o fim antes de a chamada voltar.
    while call.pending.atomic().load(Ordering::Acquire) > 0 {
        core::hint::spin_loop();
    }
    guest::free_bytes(dpc);
    guest::free_bytes(block);
    Ok(())
}

/// KeSignalCallDpcDone: um participante a menos (LOCK XADD).
pub fn signal_call_dpc_done(pending: u64) {
    // SAFETY: o SystemArgument1 que KeGenericCallDpc entregou à DPC.
    unsafe { Field::<i32>::at(pending) }.atomic().fetch_sub(1, Ordering::SeqCst);
}

/// KeSignalCallDpcSynchronize: barreira entre os participantes; TRUE para
/// exatamente um (o último a chegar), que rearma a barreira.
pub fn signal_call_dpc_synchronize(barrier: u64) -> bool {
    // SAFETY: o SystemArgument2 que KeGenericCallDpc entregou à DPC.
    let barrier = unsafe { CallDpcBarrier::at(barrier) };
    let sense = barrier.sense.atomic().load(Ordering::Acquire);
    if barrier.remaining.atomic().fetch_sub(1, Ordering::SeqCst) == 1 {
        barrier.remaining.set(barrier.participants.get());
        barrier.sense.atomic().store(sense ^ 1, Ordering::Release);
        return true;
    }
    while barrier.sense.atomic().load(Ordering::Acquire) == sense {
        core::hint::spin_loop();
    }
    false
}
