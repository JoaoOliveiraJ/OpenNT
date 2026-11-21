//! Entrega de primeira chance à NTDLL instalada.
//!
//! O despacho VEH/SEH e as rotinas de desenrolamento da própria NTDLL rodam
//! no anel 3; nenhum tratador específico de aplicação aqui. O frame é o do
//! KiDispatchException do ntoskrnl 19041 (e do .pdata do
//! KiUserExceptionDispatcher): a partir do RSP novo, CONTEXT em 0, CONTEXT_EX
//! em 0x4D0, EXCEPTION_RECORD em 0x4F0 e machine frame em 0x590. Com
//! KF_XSTATE o CONTEXT leva CONTEXT_XSTATE (0x10005F) e o pedaço XSTATE fica
//! acima do machine frame, logo abaixo do RSP interrompido, alinhado a 64:
//! XState.Offset aponta para ele e XState.Length vai até o RSP original;
//! All cobre do CONTEXT ao RSP original.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use super::threads::{self, UserThread};
use super::{crash_report, index, state, syscalls_core};
use crate::hal::amd64::usermode;
use crate::ntos::inc::types::{Context, ContextEx, Eprocess, ExceptionRecord, MachineFrame, NtStruct, XsaveFormat};
use crate::ntos::kd::debug_service;
use crate::ntos::ke::{processor_identity, user_slist, xsave};
use crate::ntos::mm::{guard_page, page_residency};
use crate::ntos::ps::context::registers::{self, INTEGER};
use crate::ntos::ps::context::xstate::{self as context_xstate, Extended};
use crate::ntos::rtl::extended_context;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const CONTEXT_SIZE: u64 = Context::SIZE;
const RECORD_SIZE: u64 = ExceptionRecord::SIZE;
/// Frame do KiUserExceptionDispatcher: CONTEXT, CONTEXT_EX, EXCEPTION_RECORD
/// (alinhado a 16) e o machine frame.
const CONTEXT_EX_OFFSET: u64 = CONTEXT_SIZE;
const RECORD_OFFSET: u64 = 0x4F0;
const MACHINE_OFFSET: u64 = 0x590;
/// O machine frame (0x28 bytes) e o registro (0x98, numa faixa de 0xA0).
const MACHINE_SIZE: u64 = 0x28;
const RECORD_SLOT: u64 = 0xA0;
/// ContextFlags do frame: CONTEXT_CONTROL, INTEGER, SEGMENTS,
/// FLOATING_POINT e DEBUG_REGISTERS; com KF_XSTATE, CONTEXT_XSTATE também.
const FRAME_FLAGS: u32 = 0x10_001F;
const FRAME_FLAGS_XSTATE: u32 = 0x10_005F;
/// O CET_U, que só vai à máscara de compactação num processo com pilhas de
/// sombra de usuário.
const CET_USER: u64 = 1 << 11;
/// STATUS_ACCESS_VIOLATION.
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// A saída do intervalo de usuário pelo relógio (a HAL grava 2 no
/// UserExecutionBlock.ExitKind).
const EXIT_INTERVAL: u32 = 2;
/// O serviço de depuração (`int 0x2D`), que o anel 3 chama pelo portão de
/// DPL 3 da IDT.
const DEBUG_SERVICE_VECTOR: u32 = 0x2D;
/// O `__fastfail` (`int 0x29`), que a HAL salva como STATUS_STACK_BUFFER_OVERRUN.
const FAST_FAIL_VECTOR: u32 = 0x29;

const _: () = assert!(CONTEXT_EX_OFFSET + ContextEx::SIZE <= RECORD_OFFSET && RECORD_OFFSET + RECORD_SIZE <= MACHINE_OFFSET && MachineFrame::SIZE <= MACHINE_SIZE);
const _: () = assert!(RECORD_OFFSET + RECORD_SLOT == MACHINE_OFFSET && CONTEXT_EX_OFFSET + 0x20 == RECORD_OFFSET);

/// Exceção levantada pelo NtRaiseException, aplicada depois que a HAL salva
/// o retorno da syscall (por thread): o CONTEXT, o registro e, com
/// CONTEXT_XSTATE, o pedaço XSTATE capturado.
static PENDING: SpinLock<BTreeMap<u64, Pending>> = SpinLock::new(BTreeMap::new());

struct Pending {
    context: Vec<u8>,
    record: Vec<u8>,
    xstate: Option<Extended>,
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]))
}

/// O CONTEXT salvo da thread de usuário (memória do kernel).
fn live_context(thread: &UserThread) -> &'static Context {
    // SAFETY: a thread viva possui o CONTEXT alocado pelo runtime.
    unsafe { Context::at(thread.with(|thread| thread.context)) }
}

pub fn validate_context(pointer: u64) -> u32 {
    if pointer == 0 || !state::probe_user_read(pointer, CONTEXT_SIZE) {
        return 0xC000_0005;
    }
    let checked = (|| -> Result<u32, KernelError> {
        let context = state::user_struct::<Context>(pointer)?;
        let flags = context.context_flags.probe_get()?;
        if flags & 0x10_0003 != 0x10_0003 {
            return Ok(0xC000_000D);
        }
        // CONTEXT_XSTATE: os flags do RtlpValidateContextFlags (sem recursos
        // habilitados, STATUS_NOT_SUPPORTED).
        if flags & 0x40 != 0 {
            if let Err(status) = extended_context::validate_context_flags(flags) {
                return Ok(status);
            }
        }
        if flags & 8 != 0 && context.flt_save.mx_csr.probe_get()? & !0xFFFF != 0 {
            return Ok(0xC000_000D);
        }
        let rip = context.rip.probe_get()?;
        let rsp = context.rsp.probe_get()?;
        if rip == 0 || rip >= 0x8000_0000_0000 || rsp == 0 || rsp >= 0x8000_0000_0000 || context.seg_cs.probe_get()? != 0x33 || context.seg_ss.probe_get()? != 0x2B {
            return Ok(0xC000_000D);
        }
        Ok(0)
    })();
    checked.unwrap_or_else(|error| error.status)
}

/// A máscara de compactação do CONTEXT do despacho: com a compactação,
/// EnabledFeatures | supervisor visível, sem o CET_U fora de um processo com
/// pilhas de sombra; sem ela, zero (o tamanho é o XState.Size).
fn dispatch_compaction_mask(thread: &UserThread) -> u64 {
    if !xsave::compaction() {
        return 0;
    }
    let mut mask = xsave::enabled_features() | xsave::enabled_user_visible_supervisor_features();
    if mask & CET_USER != 0 {
        let process = thread.with(|thread| thread.process_pointer);
        // SAFETY: o EPROCESS dono da thread viva.
        let shadow = process != 0 && unsafe { Eprocess::at(process) }.mitigation_flags2_values.cet_user_shadow_stacks() != 0;
        if !shadow {
            mask &= !CET_USER;
        }
    }
    mask
}

/// Monta o frame do KiUserExceptionDispatcher na pilha de usuário e desvia
/// o CONTEXT salvo para ele. A exceção entregue fica anotada na thread; a
/// que não pôde ser entregue (o processo termina com o status) sai no
/// diagnóstico de falhas (`crash_report`).
pub fn deliver(thread: &UserThread, record: &[u8]) -> u32 {
    let fault = crash_report::Fault::capture(record, thread.with(|thread| thread.context));
    match deliver_frame(thread, record) {
        Ok(frame) => {
            crash_report::noted(thread, fault, frame);
            0
        }
        Err(status) => {
            crash_report::undeliverable(thread, &fault, status);
            // Sem entrega, é a segunda chance: o depurador do kernel a vê
            // antes do fim do processo (`monitor sx`).
            crate::ntos::kd::user_debug::second_chance(live_context(thread), thread.with(|thread| thread.teb_va), record);
            status
        }
    }
}

/// O corpo de [`deliver`]: o endereço do CONTEXT do frame, ou o status da
/// recusa (nada escrito na pilha).
fn deliver_frame(thread: &UserThread, record: &[u8]) -> Result<u64, u32> {
    let dispatcher = state::with(|state| state.ntdll_exports.as_ref().and_then(|exports| exports.get("KiUserExceptionDispatcher").copied()));
    let Some(dispatcher) = dispatcher.filter(|&dispatcher| state::probe_user_read(dispatcher, 1)) else { return Err(0xC000_0139) };
    let live = live_context(thread);
    let with_xstate = processor_identity::feature_bits() & processor_identity::kf::XSTATE != 0;
    let flags = if with_xstate { FRAME_FLAGS_XSTATE } else { FRAME_FLAGS };
    // O CONTEXT do kernel (RtlGetExtendedContextLength2 e
    // RtlInitializeExtendedContext2) com o estado da thread
    // (KeContextFromKframes).
    let mask = if with_xstate { dispatch_compaction_mask(thread) } else { 0 };
    let length = match extended_context::extended_context_length2(flags, mask) {
        Ok(length) => length,
        Err(status) => return Err(status),
    };
    let buffer = guest::alloc_aligned(length as u64, 16, true);
    if buffer == 0 {
        return Err(0xC000_0017);
    }
    let kernel = (buffer + 0xF) & !0xF;
    guest::write_bytes(kernel, &guest::read_bytes(live.address(), CONTEXT_SIZE as usize));
    let kernel_ex = match extended_context::initialize_extended_context2(buffer, flags, mask) {
        Ok(context_ex) => context_ex,
        Err(status) => {
            guest::free_bytes(buffer);
            return Err(status);
        }
    };
    let (kernel_chunk, chunk_length) = extended_context::xstate_chunk(kernel_ex);
    if with_xstate {
        let area = crate::ntos::ke::xstate::user_state_area(thread.pointer());
        crate::ntos::ke::xstate::copy_area(kernel_chunk - xsave::LEGACY_SIZE as u64, xsave::enabled_features() & !xsave::feature::LEGACY, area);
    }
    let user_rsp = live.rsp.get();
    let xstate_start = if with_xstate { user_rsp.wrapping_sub(chunk_length as u64) & !0x3F } else { user_rsp };
    let machine = xstate_start.wrapping_sub(MACHINE_SIZE) & !0xF;
    let stack = machine.wrapping_sub(MACHINE_OFFSET);
    let total = user_rsp.wrapping_sub(stack);
    // Falha sem escrever nada quando o usuário não pode receber o frame. A
    // sonda toca a página de guarda da pilha, que cresce (`mm/guard_page`).
    if stack > user_rsp || !state::probe_user_write(stack, total) {
        guest::free_bytes(buffer);
        return Err(0xC000_00FD);
    }
    // Um tratador nunca restaura IOPL/NT/VM/VIF/VIP pelo RtlRestoreContext.
    let eflags = (live.e_flags.get() & !0x1A_7000) | 0x202;
    // O frame inteiro num espelho do kernel, escrito de uma vez.
    let image = guest::alloc_bytes(total);
    if image == 0 {
        guest::free_bytes(buffer);
        return Err(0xC000_0017);
    }
    let at = |address: u64| image + (address - stack);
    guest::write_bytes(at(stack), &guest::read_bytes(kernel, CONTEXT_SIZE as usize));
    // SAFETY: o CONTEXT, o CONTEXT_EX e o machine frame do espelho.
    let (saved, extension, machine_frame) = unsafe { (Context::at(at(stack)), ContextEx::at(at(stack + CONTEXT_EX_OFFSET)), MachineFrame::at(at(machine))) };
    saved.e_flags.set(eflags);
    let context_ex = stack + CONTEXT_EX_OFFSET;
    extension.all.offset.set(-(CONTEXT_SIZE as i32));
    extension.all.length.set(total as u32);
    extension.legacy.offset.set(-(CONTEXT_SIZE as i32));
    extension.legacy.length.set(CONTEXT_SIZE as u32);
    extension.x_state.offset.set(xstate_start.wrapping_sub(context_ex) as i32);
    extension.x_state.length.set((user_rsp - xstate_start) as u32);
    guest::write_bytes(at(stack + RECORD_OFFSET), record);
    machine_frame.rip.set(live.rip.get());
    machine_frame.seg_cs.set(live.seg_cs.get());
    machine_frame.e_flags.set(eflags);
    machine_frame.rsp.set(user_rsp);
    machine_frame.seg_ss.set(live.seg_ss.get());
    // RtlpCopyExtendedContext(1, ...): o pedaço XSTATE do kernel no do frame.
    let copied = if with_xstate { extended_context::copy_xstate_chunk(at(context_ex), at(context_ex), kernel_ex, kernel_ex).err().unwrap_or(0) } else { 0 };
    let written = copied == 0 && guest::try_write_bytes(stack, &guest::read_bytes(image, total as usize)).is_ok();
    guest::free_bytes(image);
    guest::free_bytes(buffer);
    if !written {
        return Err(if copied != 0 { copied } else { 0xC000_00FD });
    }
    live.rsp.set(stack);
    live.rip.set(dispatcher);
    live.rcx.set(stack + RECORD_OFFSET);
    live.rdx.set(stack);
    // TF/DF/RF limpos na entrada do despachante; as flags originais ficam
    // no CONTEXT salvo para a decisão de continuação do tratador.
    live.e_flags.set(eflags & !0x1_0500);
    let information = offset_of!(ExceptionRecord, exception_information);
    crate::debug_print!(
        "[exception] first chance 0x{:x} em 0x{:x} (info 0x{:x} 0x{:x}) -> KiUserExceptionDispatcher, frame=0x{:x}",
        u32_at(record, offset_of!(ExceptionRecord, exception_code)),
        u64_at(record, offset_of!(ExceptionRecord, exception_address)),
        u64_at(record, information),
        u64_at(record, information + 8),
        stack
    );
    Ok(stack)
}

/// Exceção de hardware salva pela HAL nesta transição.
pub fn hardware(thread: &UserThread, status: u32) -> u32 {
    // A falta salva pela HAL no bloco de execução da CPU: vetor, código de
    // erro e CR2.
    let block = usermode::block();
    let vector = block.fault_vector.get();
    let live = live_context(thread);
    // A HAL capturou o banco de depuração real do usuário: fica disponível
    // ao VEH/SEH e ao NtContinue seguinte (CONTEXT da própria thread).
    live.context_flags.set(live.context_flags.get() | 0x10_0010);
    let mut address = live.rip.get();
    if vector == 3 {
        address = address.wrapping_sub(1);
        live.rip.set(address);
    }
    let mut record = alloc::vec![0u8; RECORD_SIZE as usize];
    let mut put = |offset: usize, bytes: &[u8]| record[offset..offset + bytes.len()].copy_from_slice(bytes);
    put(offset_of!(ExceptionRecord, exception_code), &status.to_le_bytes());
    if vector == FAST_FAIL_VECTOR {
        // O `__fastfail` não é entregue ao processo: o KiFastFailDispatch do
        // 19041 (0x412280) monta o registro (STATUS_STACK_BUFFER_OVERRUN,
        // EXCEPTION_NONCONTINUABLE, o RIP depois do `int 0x29` e o código do
        // RCX em ExceptionInformation[0]) e vai direto à segunda chance, que
        // termina o processo. O depurador do kernel a vê antes.
        put(offset_of!(ExceptionRecord, exception_flags), &1u32.to_le_bytes());
        put(offset_of!(ExceptionRecord, exception_address), &block.fault_rip.get().to_le_bytes());
        put(offset_of!(ExceptionRecord, number_parameters), &1u32.to_le_bytes());
        put(offset_of!(ExceptionRecord, exception_information), &block.fault_rcx.get().to_le_bytes());
        crate::ntos::kd::user_debug::second_chance(live, thread.with(|thread| thread.teb_va), &record);
        return status;
    }
    if vector == DEBUG_SERVICE_VECTOR {
        // KiDebugServiceTrap: o RIP salvo é o do `int3` depois do `int 0x2D`;
        // o endereço da exceção fica depois dele e o serviço (RAX) vai em
        // ExceptionInformation[0]. O KiDispatchException deixa o RIP do
        // CONTEXT no `int3` e, com um serviço, o KdTrap vem antes da entrega.
        let service = live.rax.get();
        address = address.wrapping_add(1);
        put(offset_of!(ExceptionRecord, number_parameters), &1u32.to_le_bytes());
        put(offset_of!(ExceptionRecord, exception_information), &service.to_le_bytes());
        if service != 0 && debug_service::user_trap(live) {
            return 0;
        }
    }
    put(offset_of!(ExceptionRecord, exception_address), &address.to_le_bytes());
    if vector == 14 {
        let error = block.error_code.get() as u32;
        if page_residency::fault(block.fault_cr2.get(), error) {
            return 0;
        }
        // Página de guarda ausente (o MiUserFault): a pilha que cresceu
        // repete a instrução; senão a exceção leva o status da guarda.
        if error & 1 == 0 {
            let access = if error & 16 != 0 { guard_page::Access::Execute } else if error & 2 != 0 { guard_page::Access::Write } else { guard_page::Access::Read };
            match guard_page::touch(block.fault_cr2.get(), access) {
                Some(guard_page::STATUS_PAGE_FAULT_GUARD_PAGE) => return 0,
                Some(code) => put(offset_of!(ExceptionRecord, exception_code), &code.to_le_bytes()),
                None => {}
            }
        }
        let information = offset_of!(ExceptionRecord, exception_information);
        put(offset_of!(ExceptionRecord, number_parameters), &2u32.to_le_bytes());
        let access: u64 = if error & 16 != 0 { 8 } else if error & 2 != 0 { 1 } else { 0 };
        put(information, &access.to_le_bytes());
        put(information + 8, &block.fault_cr2.get().to_le_bytes());
        // O ramo de SList do KiPreprocessFault: a falta de acesso no
        // ExpInterlockedPopEntrySListFault recomeça o pop, sem exceção.
        if u32_at(&record, offset_of!(ExceptionRecord, exception_code)) == STATUS_ACCESS_VIOLATION && user_slist::preprocess_access_violation(thread.pointer(), live, block.fault_cr2.get()) {
            return 0;
        }
    }
    // O depurador do kernel antes da entrega (breakpoints de usuário, passo,
    // o filtro por código).
    if crate::ntos::kd::user_debug::exception(live, vector, thread.with(|thread| thread.teb_va), &record) {
        return 0;
    }
    deliver(thread, &record)
}

/// NtRaiseException: segunda chance termina o processo; a primeira fica
/// pendente até a HAL salvar os registradores de retorno da syscall.
pub fn raise(record: u64, context: u64, first_chance: u64) -> Result<u32, KernelError> {
    if !state::probe_user_read(record, RECORD_SIZE) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        let user_record = state::user_struct::<ExceptionRecord>(record)?;
        if user_record.number_parameters.probe_get()? > 15 {
            return Ok(0xC000_000D);
        }
        let invalid = validate_context(context);
        if invalid != 0 {
            return Ok(invalid);
        }
        let captured = guest::try_read_bytes(record, RECORD_SIZE as usize)?;
        if !super::state::boolean(first_chance) {
            let code = u32_at(&captured, offset_of!(ExceptionRecord, exception_code));
            let rsp = state::user_struct::<Context>(context)?.rsp.probe_get()?;
            if let Some(thread) = threads::current() {
                thread.with(|thread| thread.termination_rsp = rsp);
            }
            crash_report::second_chance(&captured, context);
            // O depurador do kernel vê a segunda chance com uma cópia do
            // CONTEXT de quem levantou (`monitor sx`).
            if let Some(thread) = threads::current().filter(|_| crate::ntos::kd::session::attached()) {
                let copy = guest::alloc_bytes(CONTEXT_SIZE);
                if copy != 0 {
                    let saved = guest::try_read_bytes(context, CONTEXT_SIZE as usize);
                    if let Ok(saved) = saved {
                        guest::write_bytes(copy, &saved);
                        // SAFETY: cópia do kernel, alinhada a 16, do tamanho do CONTEXT.
                        crate::ntos::kd::user_debug::second_chance(unsafe { Context::at(copy) }, thread.with(|thread| thread.teb_va), &captured);
                    }
                    guest::free_bytes(copy);
                }
            }
            usermode::block().exit_code.set(code);
            return Ok(state::TERMINATE_MAGIC);
        }
        let Some(thread) = threads::current() else { return Ok(0xC000_00BB) };
        let saved = guest::try_read_bytes(context, CONTEXT_SIZE as usize)?;
        let flags = u32_at(&saved, offset_of!(Context, context_flags));
        let xstate = if context_xstate::requested(flags) {
            match context_xstate::capture_user(context, flags)? {
                Ok(extended) => Some(extended),
                Err(status) => return Ok(status),
            }
        } else {
            None
        };
        PENDING.lock().insert(thread.thread_id, Pending { context: saved, record: captured, xstate });
        thread.with(|thread| thread.pending_exception = true);
        Ok(0)
    })
}

/// Threads com um KeRaiseUserException a aplicar no retorno ao anel 3.
static RAISE_ON_RETURN: SpinLock<BTreeMap<u64, ()>> = SpinLock::new(BTreeMap::new());
const USER_CODE_SELECTOR: u16 = 0x33;

/// O KiRaiseUserExceptionDispatcher da NTDLL instalada (o
/// KeRaiseUserExceptionDispatcher do kernel), ou 0 sem NTDLL.
pub fn raise_dispatcher() -> u64 {
    state::with(|state| state.ntdll_exports.as_ref().and_then(|exports| exports.get("KiRaiseUserExceptionDispatcher").copied())).unwrap_or(0)
}

/// KeRaiseUserException dentro de uma chamada de sistema vinda do anel 3
/// (KTHREAD.PreviousMode UserMode na thread de usuário corrente): o código
/// vai para TEB.ExceptionCode e o retorno do serviço é desviado para o
/// KiRaiseUserExceptionDispatcher (SegCs 0x33). Devolve se havia esse retorno.
pub fn raise_on_return(kthread: u64, code: u32) -> bool {
    use crate::ntos::inc::types::{Kthread, Teb};
    let Some(thread) = threads::current() else { return false };
    let (pointer, teb) = thread.with(|thread| (thread.thread_pointer, thread.teb_va));
    // SAFETY: a KTHREAD corrente do chamador.
    if pointer != kthread || teb == 0 || unsafe { Kthread::at(kthread) }.previous_mode.get() != 1 {
        return false;
    }
    if state::user_struct::<Teb>(teb).and_then(|teb| teb.exception_code.probe_set(code as i32)).is_err() {
        return false;
    }
    RAISE_ON_RETURN.lock().insert(thread.thread_id, ());
    thread.with(|thread| thread.pending_exception = true);
    true
}

/// Aplica a exceção pendente ao CONTEXT vivo e a entrega.
pub fn pending(thread: &UserThread) -> u32 {
    thread.with(|thread| thread.pending_exception = false);
    if RAISE_ON_RETURN.lock().remove(&thread.thread_id).is_some() {
        let live = live_context(thread);
        live.seg_cs.set(USER_CODE_SELECTOR);
        live.rip.set(raise_dispatcher());
        return 0;
    }
    let Some(Pending { context: saved, record, xstate }) = PENDING.lock().remove(&thread.thread_id) else { return 0 };
    let live = live_context(thread);
    // O pedaço XSTATE vai à área da thread (KxContextToKframes; o intervalo
    // já terminou, então o estado não está na CPU).
    if let Some(extended) = xstate.as_ref() {
        context_xstate::apply_to_thread(extended, thread.pointer());
    }
    // RtlCaptureContext não inicializa todos os grupos (notavelmente
    // DR0..DR7): os campos não selecionados da thread viva são preservados.
    let flags = u32_at(&saved, offset_of!(Context, context_flags));
    let mut ranges: Vec<(usize, usize)> = alloc::vec![(offset_of!(Context, context_flags), 4)];
    if flags & 1 != 0 {
        // CONTEXT_CONTROL: SegCs, SegSs+EFlags, Rsp e Rip.
        ranges.extend([(offset_of!(Context, seg_cs), 2), (offset_of!(Context, seg_ss), 6), (offset_of!(Context, rsp), 8), (offset_of!(Context, rip), 8)]);
    }
    if flags & 2 != 0 {
        ranges.extend(INTEGER.iter().map(|&offset| (offset as usize, 8)));
    }
    if flags & 4 != 0 {
        // CONTEXT_SEGMENTS: SegDs, SegEs, SegFs, SegGs.
        ranges.push((offset_of!(Context, seg_ds), 8));
    }
    if flags & 8 != 0 {
        // CONTEXT_FLOATING_POINT: MxCsr e a área legada do FltSave.
        ranges.extend([(offset_of!(Context, mx_csr), 4), (offset_of!(Context, flt_save), offset_of!(XsaveFormat, reserved4))]);
    }
    for (offset, length) in ranges {
        guest::write_bytes(live.address() + offset as u64, &saved[offset..offset + length]);
    }
    if flags & 0x10 != 0 {
        let first = offset_of!(Context, dr0);
        let values: [u64; 6] = core::array::from_fn(|index| u64_at(&saved, first + index * 8));
        for (register, value) in [&live.dr0, &live.dr1, &live.dr2, &live.dr3, &live.dr6, &live.dr7].into_iter().zip(registers::debug_registers(values, 1)) {
            register.set(value);
        }
    }
    // A primeira chance de uma exceção de software passa pelo filtro do
    // depurador do kernel antes da entrega (`monitor sx`).
    if crate::ntos::kd::user_debug::raised(live, thread.with(|thread| thread.teb_va), &record) {
        return 0;
    }
    deliver(thread, &record)
}

/// Saída do intervalo de usuário: a captura de chamada é consumida e a
/// exceção real (de hardware ou pendente) é despachada.
fn exit_handler(thread: &Arc<UserThread>, kind: u32, status: u32) -> u32 {
    index::consume_capture();
    // O relógio encerrou o intervalo (a troca do KiDispatchInterrupt): um
    // pop de SList interrompido recomeça (KiCheckForSListAddress).
    if kind == EXIT_INTERVAL {
        user_slist::check_for_slist_address(live_context(thread));
    }
    if kind == 3 {
        return hardware(thread, status);
    }
    if thread.with(|thread| thread.pending_exception) {
        return pending(thread);
    }
    0
}

pub fn init() {
    syscalls_core::set_exception_raiser(raise);
    threads::set_exit_handler(exit_handler);
}
