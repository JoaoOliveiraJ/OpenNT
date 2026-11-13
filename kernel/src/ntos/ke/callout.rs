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

// ---- pilha de kernel: expansão, troca e contextos de pilha de callout -----
//
// (append de `ke-kernel-stacks` ao ke/callout.rs. Usa o que o arquivo já
// importa — `irql`, `native_call`, `Field`, `NtStruct`, `Reserved`, `guest`,
// `KernelError` — e caminhos completos para o resto, sem linhas `use` novas.)
//
// KeExpandKernelStackAndCalloutInternal (Wait=2, Context=NULL): Size acima de
// MAXIMUM_EXPANSION_SIZE -> STATUS_INVALID_PARAMETER_3; IRQL acima de
// DISPATCH_LEVEL -> KeBugCheckEx(0xA, 2, irql, 0, 0); quando a pilha corrente
// basta, o callout roda no lugar com KTHREAD.MiscFlags.CalloutActive ligado
// e o IRQL tem de voltar igual (senão KeBugCheckEx(0xC8, ...)). A pilha de
// kernel do OpenNT já cobre o tamanho máximo, então é sempre esse caminho.
// Não há MmCreateKernelStack: os contextos de KeAllocateCalloutStackEx têm o
// layout real, mas as entradas de pilha ficam NULL (os callouts usam a pilha
// corrente, como o KeExpandKernelStackAndCalloutEx acima).

const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
/// MAXIMUM_EXPANSION_SIZE do KiExpandKernelStackAndCalloutSwitchStack.
const MAXIMUM_EXPANSION_SIZE: u64 = 0x11800;
/// IRQL_NOT_LESS_OR_EQUAL e IRQL_UNEXPECTED_VALUE.
const IRQL_NOT_LESS_OR_EQUAL: u32 = 0xA;
const IRQL_UNEXPECTED_VALUE: u32 = 0xC8;
/// NonPagedPoolNx e a tag 'KeSc' do KeAllocateCalloutStackEx.
const CALLOUT_STACK_POOL: u32 = 0x200;
const CALLOUT_STACK_TAG: u32 = 0x6353_654B;
/// 'Stak'.
const CALLOUT_STACK_SIGNATURE: u32 = 0x6B61_7453;

/// Cabeçalho do contexto de pilhas de callout (KeAllocateCalloutStackEx);
/// os ponteiros de pilha seguem em +0x40, um por nível de recursão. Layout
/// interno do ntoskrnl (não é do WDK), conferido no binário.
#[repr(C)]
pub struct CalloutStackContext {
    pub signature: Field<u32>,
    pub large_stack: Field<u8>,
    pub recursion_depth: Field<u8>,
    pub reserved: Field<u8>,
    _pad_7: Reserved<1>,
    pub mutex: crate::ntos::inc::types::Kmutant,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for CalloutStackContext {}

const _: () = {
    assert!(core::mem::size_of::<CalloutStackContext>() == 0x40);
    assert!(core::mem::offset_of!(CalloutStackContext, large_stack) == 0x4);
    assert!(core::mem::offset_of!(CalloutStackContext, recursion_depth) == 0x5);
    assert!(core::mem::offset_of!(CalloutStackContext, mutex) == 0x8);
};

impl CalloutStackContext {
    /// Os `recursion_depth` ponteiros de pilha depois do cabeçalho.
    pub fn stacks(&self) -> &'static [Field<u64>] {
        // SAFETY: o bloco foi alocado com 8 bytes por nível depois do cabeçalho.
        unsafe { Field::<u64>::array_at(self.address() + Self::SIZE, self.recursion_depth.get() as usize) }
    }
}

/// KeExpandKernelStackAndCallout: NTSTATUS.
pub fn expand_kernel_stack_and_callout_internal(callout: u64, parameter: u64, size: u64) -> u32 {
    use crate::ntos::ke::bugcheck;
    if size > MAXIMUM_EXPANSION_SIZE {
        return STATUS_INVALID_PARAMETER_3;
    }
    let level = irql::get_irql();
    if level > irql::DISPATCH_LEVEL {
        bugcheck::bug_check_ex(IRQL_NOT_LESS_OR_EQUAL, 2, level as u64, 0, 0);
    }
    let address = crate::ntos::ps::process::get_current_thread();
    // SAFETY: a KTHREAD corrente está viva durante a chamada.
    let thread = (address != 0).then(|| unsafe { crate::ntos::inc::types::Kthread::at(address) });
    // CalloutActive já ligado = callout aninhado: quem ligou é quem desliga.
    let owner = thread.filter(|thread| thread.callout_active() == 0);
    if let Some(thread) = owner {
        thread.set_callout_active(1);
    }
    native_call::call(callout, &[parameter]);
    if let Some(thread) = owner {
        thread.set_callout_active(0);
    }
    let after = irql::get_irql();
    if after != level {
        bugcheck::bug_check_ex(IRQL_UNEXPECTED_VALUE, (after as u64) << 16 | (level as u64) << 8 | 2, callout, parameter, 0);
    }
    0
}

/// KeSetKernelStackSwapEnable: devolve o EnableStackSwap anterior da thread
/// corrente; só escreve quando muda (CAS no ThreadFlags, como o `lock bts/btr`).
pub fn set_kernel_stack_swap_enable(thread: &crate::ntos::inc::types::Kthread, enable: bool) -> bool {
    let previous = thread.enable_stack_swap() != 0;
    if previous != enable {
        thread.set_enable_stack_swap(enable as u32);
    }
    previous
}

/// KeAllocateCalloutStackEx(Type, Depth, Reserved): o contexto ou o NTSTATUS
/// de falha. Tipo 0/1 (1 = pilha grande), profundidade != 0, reservado 0;
/// bloco NonPagedPoolNx de 0x40 + 8*Depth com 'Stak', Large, Depth e um
/// KMUTEX inicializado.
pub fn allocate_callout_stack_context(kind: u32, depth: u8, reserved: u64) -> Result<Result<&'static CalloutStackContext, u32>, KernelError> {
    let large = match kind {
        0 => false,
        1 => true,
        _ => return Ok(Err(STATUS_INVALID_PARAMETER_1)),
    };
    if depth == 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER_2));
    }
    if reserved != 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER_3));
    }
    let size = CalloutStackContext::SIZE + depth as u64 * 8;
    let address = crate::ntos::ex::pool_allocation::allocate_tagged(CALLOUT_STACK_POOL, size, CALLOUT_STACK_TAG)?;
    if address == 0 {
        return Ok(Err(STATUS_NO_MEMORY));
    }
    guest::write_bytes(address, &alloc::vec![0u8; size as usize]);
    // SAFETY: bloco recém-alocado com o cabeçalho e `depth` ponteiros.
    let context = unsafe { CalloutStackContext::at(address) };
    context.signature.set(CALLOUT_STACK_SIGNATURE);
    context.large_stack.set(large as u8);
    context.recursion_depth.set(depth);
    context.reserved.set(0);
    crate::ntos::ke::dispatcher::initialize_mutex(context.mutex.address(), 0);
    Ok(Ok(context))
}

/// KeAllocateCalloutStackEx: grava o contexto na saída; devolve o NTSTATUS.
pub fn allocate_callout_stack_ex(kind: u32, depth: u8, reserved: u64, context_out: &Field<u64>) -> Result<u32, KernelError> {
    Ok(match allocate_callout_stack_context(kind, depth, reserved)? {
        Ok(context) => {
            context_out.set(context.address());
            0
        }
        Err(status) => status,
    })
}

/// KeAllocateCalloutStack(LargeStack) = Ex(Large ? 1 : 0, 1, 0); NULL na falha.
pub fn allocate_callout_stack(large: bool) -> Result<u64, KernelError> {
    Ok(allocate_callout_stack_context(large as u32, 1, 0)?.map_or(0, |context| context.address()))
}

/// KeFreeCalloutStack: as pilhas (NULL no OpenNT) e o bloco voltam ao pool
/// (ExFreePool).
pub fn free_callout_stack(context: &CalloutStackContext) -> Result<(), KernelError> {
    for stack in context.stacks() {
        stack.set(0);
    }
    crate::ntos::ex::pool_allocation::free(context.address(), 0)
}
