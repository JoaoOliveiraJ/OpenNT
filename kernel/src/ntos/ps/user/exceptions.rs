//! Entrega de primeira chance à NTDLL instalada.
//!
//! O despacho VEH/SEH e as rotinas de desenrolamento da própria NTDLL rodam
//! no anel 3; nenhum tratador específico de aplicação aqui. Layout do frame
//! verificado no KiUserExceptionDispatcher e no seu .pdata (19041): CONTEXT
//! em 0, CONTEXT_EX em 0x4D0, EXCEPTION_RECORD em 0x4F0 e machine frame em
//! 0x590.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use super::threads::{self, UserThread};
use super::{index, state, syscalls_core};
use crate::ntos::inc::types::{Context, ContextEx, ExceptionRecord, MachineFrame, NtStruct, XsaveFormat};
use crate::ntos::mm::page_residency;
use crate::ntos::ps::context::registers::{self, INTEGER};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const CONTEXT_SIZE: u64 = Context::SIZE;
const RECORD_SIZE: u64 = ExceptionRecord::SIZE;
/// Frame do KiUserExceptionDispatcher: CONTEXT, CONTEXT_EX, EXCEPTION_RECORD
/// (alinhado a 16) e o machine frame.
const CONTEXT_EX_OFFSET: u64 = CONTEXT_SIZE;
const RECORD_OFFSET: u64 = 0x4F0;
const MACHINE_OFFSET: u64 = 0x590;
const FRAME_SIZE: u64 = 0x5C0;
/// Células da HAL na saída de exceção: vetor, código de erro e CR2.
const FAULT_VECTOR: u64 = 0x8_F138;
const ERROR_CODE: u64 = 0x8_F1B8;
const FAULT_CR2: u64 = 0x8_F098;

const _: () = assert!(CONTEXT_EX_OFFSET + ContextEx::SIZE <= RECORD_OFFSET && RECORD_OFFSET + RECORD_SIZE <= MACHINE_OFFSET && MACHINE_OFFSET + MachineFrame::SIZE <= FRAME_SIZE);

/// Exceção levantada pelo NtRaiseException, aplicada depois que a HAL salva
/// o retorno da syscall (por thread).
static PENDING: SpinLock<BTreeMap<u64, (Vec<u8>, Vec<u8>)>> = SpinLock::new(BTreeMap::new());

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
        if flags & 0x10_0003 != 0x10_0003 || flags & 0x40 != 0 {
            return Ok(0xC000_000D);
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

/// Monta o frame do KiUserExceptionDispatcher na pilha de usuário e desvia
/// o CONTEXT salvo para ele.
pub fn deliver(thread: &UserThread, record: &[u8]) -> u32 {
    let dispatcher = state::with(|state| state.ntdll_exports.as_ref().and_then(|exports| exports.get("KiUserExceptionDispatcher").copied()));
    let Some(dispatcher) = dispatcher.filter(|&dispatcher| state::probe_user_read(dispatcher, 1)) else { return 0xC000_0139 };
    let live = live_context(thread);
    let stack = (live.rsp.get().wrapping_sub(FRAME_SIZE)) & !15;
    // Falha sem escrever nada quando o usuário não pode receber o frame; o
    // crescimento da pilha/guard page exige o suporte separado do Mm.
    if !state::probe_user_write(stack, FRAME_SIZE) {
        return 0xC000_00FD;
    }
    // Um tratador nunca restaura IOPL/NT/VM/VIF/VIP pelo RtlRestoreContext.
    let eflags = (live.e_flags.get() & !0x1A_7000) | 0x202;
    let written = (|| -> Result<(), KernelError> {
        guest::try_write_bytes(stack, &alloc::vec![0; FRAME_SIZE as usize])?;
        guest::try_write_bytes(stack, &guest::read_bytes(live.address(), CONTEXT_SIZE as usize))?;
        let saved = state::user_struct::<Context>(stack)?;
        saved.e_flags.probe_set(eflags)?;
        // Faixas relativas do CONTEXT_EX: bloco inteiro e CONTEXT legado, sem XSTATE.
        let extension = state::user_struct::<ContextEx>(stack + CONTEXT_EX_OFFSET)?;
        extension.all.offset.probe_set(-(CONTEXT_SIZE as i32))?;
        extension.all.length.probe_set(RECORD_OFFSET as u32)?;
        extension.legacy.offset.probe_set(-(CONTEXT_SIZE as i32))?;
        extension.legacy.length.probe_set(CONTEXT_SIZE as u32)?;
        guest::try_write_bytes(stack + RECORD_OFFSET, record)?;
        let machine = state::user_struct::<MachineFrame>(stack + MACHINE_OFFSET)?;
        machine.rip.probe_set(live.rip.get())?;
        machine.seg_cs.probe_set(live.seg_cs.get())?;
        machine.e_flags.probe_set(eflags)?;
        machine.rsp.probe_set(live.rsp.get())?;
        machine.seg_ss.probe_set(live.seg_ss.get())
    })();
    if written.is_err() {
        return 0xC000_00FD;
    }
    live.rsp.set(stack);
    live.rip.set(dispatcher);
    live.rcx.set(stack + RECORD_OFFSET);
    live.rdx.set(stack);
    // TF/DF/RF limpos na entrada do despachante; as flags originais ficam
    // no CONTEXT salvo para a decisão de continuação do tratador.
    live.e_flags.set(eflags & !0x1_0500);
    crate::debug_print!("[exception] first chance 0x{:x} -> KiUserExceptionDispatcher, frame=0x{:x}", u32_at(record, offset_of!(ExceptionRecord, exception_code)), stack);
    0
}

/// Exceção de hardware salva pela HAL nesta transição.
pub fn hardware(thread: &UserThread, status: u32) -> u32 {
    let vector = guest::read32(FAULT_VECTOR);
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
    put(offset_of!(ExceptionRecord, exception_address), &address.to_le_bytes());
    if vector == 14 {
        let error = guest::read32(ERROR_CODE);
        if page_residency::fault(guest::read64(FAULT_CR2), error) {
            return 0;
        }
        let information = offset_of!(ExceptionRecord, exception_information);
        put(offset_of!(ExceptionRecord, number_parameters), &2u32.to_le_bytes());
        let access: u64 = if error & 16 != 0 { 8 } else if error & 2 != 0 { 1 } else { 0 };
        put(information, &access.to_le_bytes());
        put(information + 8, &guest::read64(FAULT_CR2).to_le_bytes());
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
        if first_chance & 0xFF == 0 {
            let code = u32_at(&captured, offset_of!(ExceptionRecord, exception_code));
            let rsp = state::user_struct::<Context>(context)?.rsp.probe_get()?;
            state::with(|state| state.termination_rsp = rsp);
            crate::debug_print!("[exception] unhandled 0x{:x} @0x{:x}", code, u64_at(&captured, offset_of!(ExceptionRecord, exception_address)));
            guest::write32(state::EXIT_CODE_CELL, code);
            return Ok(state::TERMINATE_MAGIC);
        }
        let Some(thread) = threads::current() else { return Ok(0xC000_00BB) };
        let saved = guest::try_read_bytes(context, CONTEXT_SIZE as usize)?;
        PENDING.lock().insert(thread.thread_id, (saved, captured));
        thread.with(|thread| thread.pending_exception = true);
        Ok(0)
    })
}

/// Aplica a exceção pendente ao CONTEXT vivo e a entrega.
pub fn pending(thread: &UserThread) -> u32 {
    thread.with(|thread| thread.pending_exception = false);
    let Some((saved, record)) = PENDING.lock().remove(&thread.thread_id) else { return 0 };
    let live = live_context(thread);
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
    deliver(thread, &record)
}

/// Saída do intervalo de usuário: a captura de chamada é consumida e a
/// exceção real (de hardware ou pendente) é despachada.
fn exit_handler(thread: &Arc<UserThread>, kind: u32, status: u32) -> u32 {
    index::consume_capture();
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
