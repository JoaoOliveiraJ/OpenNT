//! APCs de modo usuário: NtQueueApcThread(Ex/Ex2), NtTestAlert e o frame do
//! KiUserApcDispatcher (o KiInitializeUserApc sobre o CONTEXT salvo).
//!
//! A KAPC de modo usuário entra na fila nativa da KTHREAD (`ke::apc`). A
//! entrega acontece no retorno ao modo usuário (`threads::run`, antes de
//! retomar o CONTEXT salvo — o KiInitiateUserApc do KiSystemServiceExit)
//! quando ApcState.UserApcPendingAll tem UserApcPending (espera alertável
//! interrompida, NtTestAlert, NtContinue com TestAlert) ou
//! SpecialUserApcPending (APC especial). O frame na pilha de usuário segue o
//! contrato do KiInitializeUserApc com o KiUserApcDispatcher da 19045
//! ([`UserApcFrame`]); o despachante chama a rotina e volta pelo
//! NtContinueEx(CONTEXT, CONTEXT+0x4F0): com TEST_ALERT|DELIVER_APC e outra
//! APC pendente, ela entra no mesmo CONTEXT ([`deliver_in_place`]) e o
//! serviço devolve 0, que o despachante trata como "repetir".

use alloc::sync::Arc;
use core::mem::offset_of;

use super::state;
use super::threads::{self, UserThread};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_usermode::{ApcCallbackData, KcontinueArgument, KCONTINUE_FLAG_DELIVER_APC, KCONTINUE_RESUME};
use crate::ntos::inc::types::{Context, ContextEx, Kapc, Kthread, MachineFrame, XsaveFormat};
use crate::ntos::io::file::request as file_request;
use crate::ntos::ke::apc::{self, UserApc, USER_APC_CALLBACK_DATA, USER_APC_TEST_ALERT};
use crate::ntos::ke::test_alert;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::context::registers;
use crate::rtl::KernelError;

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_STACK_OVERFLOW: u32 = 0xC000_00FD;
const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xC000_0139;
const STATUS_ALERTED: u32 = 0x101;
/// 'Psap' (ExAllocatePoolWithQuotaTag do NtQueueApcThreadEx2).
const TAG: u32 = 0x7061_7350;
/// QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC e QUEUE_USER_APC_CALLBACK_DATA_CONTEXT.
const SPECIAL_USER_APC: u32 = 1;
const CALLBACK_DATA_CONTEXT: u32 = 0x1_0000;
/// THREAD_SET_CONTEXT.
const THREAD_SET_CONTEXT: u32 = 0x10;
/// CONTEXT_CONTROL|INTEGER|FLOATING_POINT|DEBUG_REGISTERS do KiInitializeUserApc.
const APC_CONTEXT_FLAGS: u32 = 0x10_001B;
/// Dr7 com algum comparador habilitado (L0-L3/G0-G3, LE/GE): DebugActive.
const DR7_ACTIVE: u64 = 0x355;

/// Frame que o KiInitializeUserApc monta na pilha de usuário e o
/// KiUserApcDispatcher consome (contrato kernel/ntdll da 19045, sem nome
/// público): o CONTEXT (P1Home..P5Home = NormalContext, SystemArgument1,
/// SystemArgument2, NormalRoutine, flags), CONTEXT_EX, KCONTINUE_ARGUMENT,
/// APC_CALLBACK_DATA e o MACHINE_FRAME logo abaixo da pilha original.
#[repr(C)]
struct UserApcFrame {
    context: Context,
    context_ex: ContextEx,
    _pad_4e8: Reserved<0x8>,
    continue_argument: KcontinueArgument,
    _pad_508: Reserved<0x8>,
    callback_data: ApcCallbackData,
    machine: MachineFrame,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for UserApcFrame {}

const _: () = {
    assert!(core::mem::size_of::<UserApcFrame>() == 0x558);
    assert!(offset_of!(UserApcFrame, context_ex) == 0x4D0);
    assert!(offset_of!(UserApcFrame, continue_argument) == 0x4F0);
    assert!(offset_of!(UserApcFrame, callback_data) == 0x510);
    assert!(offset_of!(UserApcFrame, machine) == 0x530);
};

fn kthread(pointer: u64) -> &'static Kthread {
    // SAFETY: KTHREAD viva de uma thread de usuário resolvida.
    unsafe { Kthread::at(pointer) }
}

/// KeInitializeApc + KeInsertQueueApc de uma APC de modo usuário na thread
/// (OriginalApcEnvironment; KernelRoutine e RundownRoutine devolvem a KAPC
/// ao pool). A especial publica SpecialUserApcPending (ver `ke::apc`).
pub fn queue(thread: &Arc<UserThread>, routine: u64, argument1: u64, argument2: u64, argument3: u64, special: bool, callback_data: bool) -> Result<u32, KernelError> {
    let pointer = thread.pointer();
    // ApcQueueable cai na saída da thread: KeInsertQueueApc devolve FALSE.
    if pointer == 0 || thread.dead() {
        return Ok(STATUS_UNSUCCESSFUL);
    }
    let free = file_request::free_routine()?;
    let kernel_routine = if special { apc::special_user_apc_routine()? } else { free };
    if free == 0 || kernel_routine == 0 {
        return Ok(STATUS_NO_MEMORY);
    }
    let Ok(packet) = kernel_pool::allocate(Kapc::SIZE, AllocateOptions { paged: false, tag: TAG, zero: true, ..Default::default() }) else {
        return Ok(STATUS_NO_MEMORY);
    };
    if packet == 0 {
        return Ok(STATUS_NO_MEMORY);
    }
    apc::initialize(packet, pointer, 0, kernel_routine, free, routine, 1, argument1);
    // SAFETY: KAPC recém-alocada e inicializada acima.
    unsafe { Kapc::at(packet) }.all_flags.set(callback_data as u8);
    if !apc::insert(packet, argument2, argument3) {
        kernel_pool::free(packet, None)?;
        return Ok(STATUS_UNSUCCESSFUL);
    }
    // Sem rotina normal a KAPC virou APC de kernel (KeInitializeApc).
    if special && routine != 0 {
        apc::mark_special_user_apc(pointer);
    }
    // KiSignalThreadForApc: a espera alertável de UserMode volta com
    // STATUS_USER_APC na próxima sondagem (`thread_alert::consume`).
    Ok(0)
}

/// NtQueueApcThreadEx2(thread, reserve, flags, routine, arg1, arg2, arg3):
/// o núcleo das três entradas, na ordem do original.
#[allow(clippy::too_many_arguments)]
fn queue_apc_thread(handle: u64, reserve: u64, flags: u32, routine: u64, argument1: u64, argument2: u64, argument3: u64) -> Result<u32, KernelError> {
    if flags & 0xFFFE_FFFE != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let special = flags & SPECIAL_USER_APC != 0;
    if special && reserve != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let thread = match threads::resolve(handle, THREAD_SET_CONTEXT) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    let pointer = thread.pointer();
    if pointer == 0 || kthread(pointer).system_thread() != 0 {
        return Ok(STATUS_INVALID_HANDLE);
    }
    // Sem WoW64 neste kernel: a checagem da rotina x86 codificada não se
    // aplica. Objetos de reserva (NtAllocateReserveObject) não existem: um
    // handle de outro tipo é OBJECT_TYPE_MISMATCH, um ausente é inválido.
    if reserve != 0 {
        return Ok(if state::get_user_handle(reserve).is_some() { STATUS_OBJECT_TYPE_MISMATCH } else { STATUS_INVALID_HANDLE });
    }
    queue(&thread, routine, argument1, argument2, argument3, special, flags & CALLBACK_DATA_CONTEXT != 0)
}

/// NtQueueApcThread(thread, routine, arg1, arg2, arg3) =
/// NtQueueApcThreadEx2(thread, 0, 0, routine, arg1, arg2, arg3).
fn nt_queue_apc_thread(handle: u64, routine: u64, argument1: u64, argument2: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    queue_apc_thread(handle, 0, 0, routine, argument1, argument2, state::stack_arg(rsp, 5))
}

/// NtQueueApcThreadEx(thread, reserveOrOption, routine, arg1, arg2, arg3):
/// o valor 1 (QueueUserApcFlagsSpecialUserApc) pede a APC especial; outro
/// valor é o handle de reserva.
fn nt_queue_apc_thread_ex(handle: u64, reserve: u64, routine: u64, argument1: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 16) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let (reserve, flags) = if reserve == 1 { (0, SPECIAL_USER_APC) } else { (reserve, 0) };
    queue_apc_thread(handle, reserve, flags, routine, argument1, state::stack_arg(rsp, 5), state::stack_arg(rsp, 6))
}

/// NtQueueApcThreadEx2(thread, reserve, flags, routine, arg1, arg2, arg3).
fn nt_queue_apc_thread_ex2(handle: u64, reserve: u64, flags: u64, routine: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 24) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    queue_apc_thread(handle, reserve, flags as u32, routine, state::stack_arg(rsp, 5), state::stack_arg(rsp, 6), state::stack_arg(rsp, 7))
}

/// NtTestAlert: KeTestAlertThread(UserMode) da thread corrente; o alerta de
/// usuário é consumido (STATUS_ALERTED), senão uma fila de usuário não vazia
/// publica UserApcPending e a APC sai no retorno da syscall.
fn nt_test_alert(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(if test_alert::test(1)? != 0 { STATUS_ALERTED } else { 0 })
}

/// UserApcPending publicado na thread (o teste do KiContinueEx).
pub fn user_apc_pending(pointer: u64) -> bool {
    pointer != 0 && apc::user_apc_pending(pointer)
}

/// P1Home..P5Home do CONTEXT e APC_CALLBACK_DATA {Parameter, ContextRecord}
/// (KiInitializeUserApc): com CallbackDataContext, o endereço do bloco
/// substitui o SystemArgument1. `context_address` é o endereço de usuário
/// do CONTEXT; `probed` escolhe escritas sondadas (CONTEXT do chamador) ou
/// diretas (imagem montada no kernel).
fn write_homes(context: &Context, callback: &ApcCallbackData, context_address: u64, apc: &UserApc, probed: bool) -> Result<(), KernelError> {
    let put = |field: &Field<u64>, value: u64| -> Result<(), KernelError> {
        if probed {
            field.probe_set(value)
        } else {
            field.set(value);
            Ok(())
        }
    };
    for field in [&callback.parameter, &callback.context_record, &callback.reserved0, &callback.reserved1] {
        put(field, 0)?;
    }
    let mut argument1 = apc.system_argument1;
    if apc.flags & USER_APC_CALLBACK_DATA != 0 {
        put(&callback.parameter, argument1)?;
        put(&callback.context_record, context_address)?;
        argument1 = context_address + offset_of!(UserApcFrame, callback_data) as u64;
    }
    put(&context.p1_home, apc.normal_context)?;
    put(&context.p2_home, argument1)?;
    put(&context.p3_home, apc.system_argument2)?;
    put(&context.p4_home, apc.normal_routine)?;
    put(&context.p5_home, apc.flags as u64)
}

/// KiInitializeUserApc (ExceptionFrame presente): a imagem do frame é
/// montada no kernel — o CONTEXT do KeContextFromKframes com
/// CONTROL|INTEGER|FLOATING_POINT|DEBUG_REGISTERS, MACHINE_FRAME e
/// KCONTINUE_ARGUMENT — e copiada em bloco para a pilha de usuário; o
/// CONTEXT salvo passa a retomar no despachante.
fn build_frame(live: &Context, frame: u64, apc: &UserApc, dispatcher: u64) -> Result<(), KernelError> {
    let scratch = guest::alloc_aligned(UserApcFrame::SIZE, 16, true);
    if scratch == 0 {
        return Err(KernelError::with_status("user APC frame", STATUS_NO_MEMORY));
    }
    // SAFETY: bloco do kernel recém-alocado e zerado do tamanho do frame.
    let image = unsafe { UserApcFrame::at(scratch) };
    let context = &image.context;
    context.context_flags.set(APC_CONTEXT_FLAGS);
    context.rip.set(live.rip.get());
    context.seg_cs.set(live.seg_cs.get());
    context.seg_ss.set(live.seg_ss.get());
    context.rsp.set(live.rsp.get());
    context.e_flags.set(live.e_flags.get());
    for (target, source) in registers::integer_registers(context).into_iter().zip(registers::integer_registers(live)) {
        target.set(source.get());
    }
    // A imagem FXSAVE inteira: o NtContinue deste kernel restaura os 512
    // bytes, então x87/MMX atravessam a APC intactos.
    context.mx_csr.set(live.mx_csr.get());
    registers::copy(context.flt_save.address(), live.flt_save.address(), XsaveFormat::SIZE);
    if live.dr7.get() & DR7_ACTIVE != 0 {
        for (target, source) in [&context.dr0, &context.dr1, &context.dr2, &context.dr3, &context.dr6, &context.dr7].into_iter().zip([&live.dr0, &live.dr1, &live.dr2, &live.dr3, &live.dr6, &live.dr7]) {
            target.set(source.get());
        }
    }
    image.machine.rip.set(live.rip.get());
    image.machine.rsp.set(live.rsp.get());
    image.continue_argument.continue_type.set(KCONTINUE_RESUME);
    image.continue_argument.continue_flags.set(KCONTINUE_FLAG_DELIVER_APC | (apc.flags & USER_APC_TEST_ALERT));
    write_homes(context, &image.callback_data, frame, apc, false)?;
    let written = guest::try_write_bytes(frame, &guest::read_bytes(scratch, UserApcFrame::SIZE as usize));
    guest::free_bytes(scratch);
    written?;
    live.rsp.set(frame);
    live.rip.set(dispatcher);
    live.seg_cs.set(0x33);
    Ok(())
}

/// Retorno ao modo usuário da thread (KiInitiateUserApc): com
/// UserApcPendingAll publicado, uma APC é entregue sobre o CONTEXT salvo.
/// Devolve 0 ou o status fatal (ntdll sem despachante, pilha de usuário sem
/// espaço para o frame).
pub fn deliver(thread: &UserThread) -> u32 {
    let (pointer, context, dead) = thread.with(|thread| (thread.thread_pointer, thread.context, thread.dead));
    if pointer == 0 || context == 0 || dead || apc::user_apc_pending_all(pointer) & 3 == 0 {
        return 0;
    }
    let dispatcher = state::with(|state| state.ntdll_exports.as_ref().and_then(|exports| exports.get("KiUserApcDispatcher").copied()));
    let Some(dispatcher) = dispatcher.filter(|&dispatcher| state::probe_user_read(dispatcher, 1)) else { return STATUS_ENTRYPOINT_NOT_FOUND };
    // SAFETY: o CONTEXT salvo pelo runtime da thread (memória do kernel).
    let live = unsafe { Context::at(context) };
    let rsp = live.rsp.get();
    let machine = rsp.wrapping_sub(MachineFrame::SIZE) & !15;
    let frame = machine.wrapping_sub(offset_of!(UserApcFrame, machine) as u64);
    // A sonda precede a retirada: a pilha cheia não consome a APC (o
    // crescimento da pilha/guard page exige o suporte separado do Mm).
    if frame >= rsp || !state::probe_user_write(frame, rsp - frame) {
        return STATUS_STACK_OVERFLOW;
    }
    let selected = match apc::deliver_user(pointer) {
        Ok(Some(selected)) => selected,
        Ok(None) => return 0,
        Err(error) => return if error.status != 0 { error.status } else { STATUS_UNSUCCESSFUL },
    };
    match build_frame(live, frame, &selected, dispatcher) {
        Ok(()) => {
            crate::debug_print!("[apc] user APC {:#x} -> KiUserApcDispatcher, frame={:#x}", selected.normal_routine, frame);
            0
        }
        Err(error) => if error.status != 0 { error.status } else { STATUS_UNSUCCESSFUL },
    }
}

/// KiContinueEx com TEST_ALERT|DELIVER_APC e UserApcPending: a próxima APC
/// entra no próprio CONTEXT do chamador (KiInitializeUserApc com
/// ExceptionFrame nulo; o APC_CALLBACK_DATA em +0x510 precisa ser gravável).
/// `None`: nada a entregar, o chamador segue com a restauração do CONTEXT.
pub fn deliver_in_place(pointer: u64, context: u64) -> Option<u32> {
    let frame = match state::user_struct::<UserApcFrame>(context) {
        Ok(frame) => frame,
        Err(error) => return Some(error.status),
    };
    if !state::probe_user_write(frame.callback_data.address(), ApcCallbackData::SIZE) {
        return Some(STATUS_ACCESS_VIOLATION);
    }
    match apc::deliver_user(pointer) {
        Ok(Some(selected)) => Some(write_homes(&frame.context, &frame.callback_data, context, &selected, true).map_or_else(|error| error.status, |()| 0)),
        Ok(None) => None,
        Err(error) => Some(if error.status != 0 { error.status } else { STATUS_UNSUCCESSFUL }),
    }
}

pub fn init() {
    state::register_handler("NtTestAlert", nt_test_alert);
    state::register_handler("NtQueueApcThread", nt_queue_apc_thread);
    state::register_handler("NtQueueApcThreadEx", nt_queue_apc_thread_ex);
    state::register_handler("NtQueueApcThreadEx2", nt_queue_apc_thread_ex2);
}
