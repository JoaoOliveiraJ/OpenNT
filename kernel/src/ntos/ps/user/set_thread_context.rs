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

// ---- NtGetContextThread / NtSetContextThread ----
//
// Medidos no ntoskrnl 19045:
//   NtGetContextThread: ObReferenceObjectByHandle(THREAD_GET_CONTEXT); thread
//   de sistema -> STATUS_INVALID_HANDLE; PspGetContextThreadInternal(thread,
//   context, UserMode, UserMode, 1): ContextFlags lido (antes do
//   alinhamento) e saneado (RtlpSanitizeContextFlags: flags inválidos de
//   UserMode viram CONTEXT_AMD64 com os grupos reconhecidos); o CONTEXT
//   legado inteiro (alinhado a 16) vai a uma cópia do kernel; a
//   PspGetSetContextSpecialApc roda na thread de destino (direto quando é a
//   corrente) com o lado de leitura do PspGetSetContextInternal/PspGetContext;
//   o RtlpWriteExtendedContext devolve só os grupos selecionados
//   (RtlpCopyLegacyContextAmd64).
//   NtSetContextThread: ObReferenceObjectByHandle(THREAD_SET_CONTEXT);
//   RestrictSetThreadContext do processo chamador com alvo do mesmo processo
//   -> STATUS_SET_CONTEXT_DENIED; thread de sistema ou Pico ->
//   STATUS_INVALID_HANDLE; PspSetContextThreadInternal(thread, context,
//   UserMode, UserMode, 1) (`execute`).
// CONTEXT_XSTATE devolve STATUS_NOT_SUPPORTED nos dois lados (sem XSAVE).

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::mem::offset_of;

use super::state;
use crate::ntos::inc::types::{ContextView1, Eprocess, Ethread, Field};
use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
use crate::ntos::ps::context::apc as context_apc;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_SET_CONTEXT_DENIED: u32 = 0xC000_060A;
/// THREAD_GET_CONTEXT e THREAD_SET_CONTEXT.
const THREAD_GET_CONTEXT: u32 = 8;
const THREAD_SET_CONTEXT: u32 = 0x10;
/// CONTEXT_EXCEPTION_REQUEST/REPORTING e SERVICE_ACTIVE.
const EXCEPTION_REQUEST: u32 = 0x4000_0000;
const EXCEPTION_REPORTING: u32 = 0x8000_0000;
const SERVICE_ACTIVE: u32 = 0x1000_0000;
/// Dr7 com algum comparador habilitado: DebugActive.
const DR7_ACTIVE: u64 = 0x355;
/// FltSave legado + Xmm0..Xmm15 (o que o RtlpCopyLegacyContextAmd64 copia
/// para CONTEXT_FLOATING_POINT).
const LEGACY_FLOAT_BYTES: usize = offset_of!(ContextView1, xmm15) + 16 - offset_of!(Context, flt_save);

const _: () = assert!(LEGACY_FLOAT_BYTES == 0x1A0);

fn selected(flags: u32, group: u32) -> bool {
    flags & (registers::AMD64 | group) == registers::AMD64 | group
}

fn debug_bank(context: &Context) -> [&Field<u64>; 6] {
    [&context.dr0, &context.dr1, &context.dr2, &context.dr3, &context.dr6, &context.dr7]
}

/// Leitura na thread de destino (PspGetSetContextSpecialApc com o lado de
/// leitura do PspGetSetContextInternal e PspGetContext): o CONTEXT salvo pelo
/// escalonador faz o papel do trap frame com os não voláteis.
fn read_saved(thread: u64, target: u64) -> Result<u32, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("context operation requires IRQL <= APC_LEVEL"));
    }
    if process::get_current_thread() != thread {
        return Err(KernelError::new("user context read delivered to another thread"));
    }
    let exiting = process::thread_record(thread).is_none_or(|record| record.exiting);
    let runtime = threads::find_by_pointer(thread).filter(|runtime| !runtime.dead());
    let context = runtime.as_ref().map_or(0, |runtime| runtime.with(|thread| thread.context));
    if exiting || context == 0 {
        return Ok(0xC000_0001);
    }
    // Numa syscall: a corrente (serviço em curso) ou uma espera instalada.
    let in_service = runtime.as_ref().is_some_and(|runtime| runtime.waiting() || threads::current().is_some_and(|current| Arc::ptr_eq(&current, runtime)));
    // SAFETY: a cópia do kernel feita por `get` e o CONTEXT salvo da thread.
    let (output, saved) = unsafe { (Context::at(target), Context::at(context)) };
    let flags = output.context_flags.get();
    if selected(flags, 1) {
        output.rip.set(saved.rip.get());
        output.seg_cs.set(saved.seg_cs.get());
        output.seg_ss.set(saved.seg_ss.get());
        output.rsp.set(saved.rsp.get());
        output.e_flags.set(saved.e_flags.get());
    }
    if selected(flags, 4) {
        // Segmentos fixos de modo usuário x64.
        output.seg_ds.set(0x2B);
        output.seg_es.set(0x2B);
        output.seg_fs.set(0x53);
        output.seg_gs.set(0x2B);
    }
    if selected(flags, 2) {
        for (to, from) in registers::integer_registers(output).into_iter().zip(registers::integer_registers(saved)) {
            to.set(from.get());
        }
    }
    if selected(flags, 8) {
        // O FXSAVE do original lê o estado vivo da thread de destino: aqui
        // é a imagem salva na saída de syscall/timer; MxCsr nos dois campos.
        registers::copy(output.flt_save.address(), saved.flt_save.address(), XsaveFormat::SIZE);
        let mxcsr = saved.mx_csr.get();
        output.mx_csr.set(mxcsr);
        output.flt_save.mx_csr.set(mxcsr);
    }
    if selected(flags, 0x10) {
        let active = saved.dr7.get() & DR7_ACTIVE != 0;
        for (to, from) in debug_bank(output).into_iter().zip(debug_bank(saved)) {
            to.set(if active { from.get() } else { 0 });
        }
        // Sem LBR: KeCopyLastBranchInformation devolve zeros.
        for field in [&output.last_branch_to_rip, &output.last_branch_from_rip, &output.last_exception_to_rip, &output.last_exception_from_rip] {
            field.set(0);
        }
    }
    if flags & EXCEPTION_REQUEST != 0 {
        output.context_flags.set((flags & 0xE7FF_FFFF) | EXCEPTION_REPORTING | if in_service { SERVICE_ACTIVE } else { 0 });
    }
    Ok(0)
}

/// RtlpCopyLegacyContextAmd64 da cópia do kernel para o CONTEXT de usuário:
/// ContextFlags e os grupos selecionados, com escritas sondadas.
fn write_back(source: &Context, target: &Context) -> Result<u32, KernelError> {
    let flags = source.context_flags.get();
    target.context_flags.probe_set(if flags & EXCEPTION_REQUEST != 0 { flags } else { flags & 0x67FF_FFFF })?;
    if selected(flags, 1) {
        target.rip.probe_set(source.rip.get())?;
        target.seg_cs.probe_set(source.seg_cs.get())?;
        target.seg_ss.probe_set(source.seg_ss.get())?;
        target.rsp.probe_set(source.rsp.get())?;
        target.e_flags.probe_set(source.e_flags.get())?;
    }
    if selected(flags, 2) {
        for (to, from) in registers::integer_registers(target).into_iter().zip(registers::integer_registers(source)) {
            to.probe_set(from.get())?;
        }
    }
    if selected(flags, 4) {
        for (to, from) in [&target.seg_ds, &target.seg_es, &target.seg_fs, &target.seg_gs].into_iter().zip([&source.seg_ds, &source.seg_es, &source.seg_fs, &source.seg_gs]) {
            to.probe_set(from.get())?;
        }
    }
    if selected(flags, 8) {
        target.mx_csr.probe_set(source.mx_csr.get())?;
        guest::try_write_bytes(target.flt_save.address(), &guest::read_bytes(source.flt_save.address(), LEGACY_FLOAT_BYTES))?;
    }
    if selected(flags, 0x10) {
        for (to, from) in debug_bank(target).into_iter().zip(debug_bank(source)) {
            to.probe_set(from.get())?;
        }
        for (to, from) in [&target.last_branch_to_rip, &target.last_branch_from_rip, &target.last_exception_to_rip, &target.last_exception_from_rip]
            .into_iter()
            .zip([&source.last_branch_to_rip, &source.last_branch_from_rip, &source.last_exception_to_rip, &source.last_exception_from_rip])
        {
            to.probe_set(from.get())?;
        }
    }
    Ok(0)
}

/// PspGetContextThreadInternal(thread, context, UserMode, UserMode, 1).
pub fn get(thread: u64, buffer: u64) -> Result<u32, KernelError> {
    let flag_address = buffer.wrapping_add(offset_of!(Context, context_flags) as u64);
    if !state::probe_user_read(flag_address.min(USER_ADDRESS_LIMIT), 4) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let requested = match guest::try_read::<u32>(flag_address) {
        Ok(flags) => flags,
        Err(error) => return Ok(error.status),
    };
    let (status, flags) = registers::validate(requested, 1, false);
    if status != 0 {
        return Ok(status);
    }
    if buffer & 15 != 0 {
        return Ok(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !state::probe_user_read(buffer, Context::SIZE) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let image = match guest::try_read_bytes(buffer, Context::SIZE as usize) {
        Ok(image) => image,
        Err(error) => return Ok(error.status),
    };
    let storage = guest::alloc_aligned(Context::SIZE, 16, false);
    if storage == 0 {
        return Ok(0xC000_009A);
    }
    guest::write_bytes(storage, &image);
    // SAFETY: a cópia do kernel recém-gravada.
    let copy = unsafe { Context::at(storage) };
    copy.context_flags.set(flags);
    let result = match context_apc::execute(thread, Box::new(move || read_saved(thread, storage))) {
        Ok(status) if status & 0x8000_0000 != 0 => Ok(status),
        Ok(_) if !state::probe_user_write(buffer, Context::SIZE) => Ok(STATUS_ACCESS_VIOLATION),
        Ok(_) => state::guarded(|| write_back(copy, state::user_struct::<Context>(buffer)?)),
        Err(error) => Err(error),
    };
    guest::free_bytes(storage);
    result
}

/// NtGetContextThread(thread, context).
pub fn nt_get_context_thread(handle: u64, context: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let thread = match threads::resolve(handle, THREAD_GET_CONTEXT) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    let pointer = thread.pointer();
    // SAFETY: KTHREAD viva da thread resolvida.
    if pointer == 0 || unsafe { Kthread::at(pointer) }.system_thread() != 0 {
        return Ok(STATUS_INVALID_HANDLE);
    }
    get(pointer, context)
}

/// NtSetContextThread(thread, context).
pub fn nt_set_context_thread(handle: u64, context: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let thread = match threads::resolve(handle, THREAD_SET_CONTEXT) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    let pointer = thread.pointer();
    if pointer == 0 {
        return Ok(STATUS_INVALID_HANDLE);
    }
    // SAFETY: a thread corrente e a resolvida são KTHREADs vivas.
    let target = unsafe { Kthread::at(pointer) };
    let current = process::get_current_thread();
    let caller = if current != 0 { unsafe { Kthread::at(current) }.process.get() } else { 0 };
    // SAFETY: KTHREAD.Process de uma thread viva é o EPROCESS dono.
    if caller != 0 && unsafe { Eprocess::at(caller) }.restrict_set_thread_context() != 0 && target.process.get() == caller {
        return Ok(STATUS_SET_CONTEXT_DENIED);
    }
    // SAFETY: a KTHREAD é a Tcb da ETHREAD.
    if target.system_thread() != 0 || unsafe { Ethread::at(pointer) }.pico_context.get() != 0 {
        return Ok(STATUS_INVALID_HANDLE);
    }
    execute(pointer, context, 1, 1)
}
