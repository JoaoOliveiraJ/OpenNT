//! Entrega de primeira chance à NTDLL instalada — `system32/ntos/ps/user/exceptions.js`.
//!
//! O despacho VEH/SEH e as rotinas de desenrolamento da própria NTDLL rodam
//! no anel 3; nenhum tratador específico de aplicação aqui. Layout do frame
//! verificado no KiUserExceptionDispatcher e no seu .pdata (19041): CONTEXT
//! em 0, CONTEXT_EX em 0x4D0, EXCEPTION_RECORD em 0x4F0 e machine frame em
//! 0x590.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::threads::{self, UserThread};
use super::{index, state, syscalls_core};
use crate::ntos::mm::page_residency;
use crate::ntos::ps::context::registers::{self, INTEGER};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const CONTEXT_SIZE: u64 = 0x4D0;
const RECORD_SIZE: u64 = 0x98;
const RECORD_OFFSET: u64 = 0x4F0;
const MACHINE_OFFSET: u64 = 0x590;
const FRAME_SIZE: u64 = 0x5C0;
/// Células da HAL na saída de exceção: vetor, código de erro e CR2.
const FAULT_VECTOR: u64 = 0x8_F138;
const ERROR_CODE: u64 = 0x8_F1B8;
const FAULT_CR2: u64 = 0x8_F098;

/// Exceção levantada pelo NtRaiseException, aplicada depois que a HAL salva
/// o retorno da syscall (por thread).
static PENDING: SpinLock<BTreeMap<u64, (Vec<u8>, Vec<u8>)>> = SpinLock::new(BTreeMap::new());

fn read_bytes(pointer: u64, length: u64) -> Vec<u8> {
    (0..length).map(|index| guest::read8(pointer + index)).collect()
}

fn write_bytes(pointer: u64, bytes: &[u8]) {
    for (index, &byte) in bytes.iter().enumerate() {
        guest::write8(pointer + index as u64, byte);
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

pub fn validate_context(pointer: u64) -> u32 {
    if pointer == 0 || !state::probe_user_read(pointer, CONTEXT_SIZE) {
        return 0xC000_0005;
    }
    let flags = guest::read32(pointer + 0x30);
    if flags & 0x10_0003 != 0x10_0003 || flags & 0x40 != 0 {
        return 0xC000_000D;
    }
    if flags & 8 != 0 && guest::read32(pointer + 0x118) & !0xFFFF != 0 {
        return 0xC000_000D;
    }
    let rip = guest::read64(pointer + 0xF8);
    let rsp = guest::read64(pointer + 0x98);
    if rip == 0 || rip >= 0x8000_0000_0000 || rsp == 0 || rsp >= 0x8000_0000_0000 || guest::read16(pointer + 0x38) != 0x33 || guest::read16(pointer + 0x42) != 0x2B {
        return 0xC000_000D;
    }
    0
}

/// Monta o frame do KiUserExceptionDispatcher na pilha de usuário e desvia
/// o CONTEXT salvo para ele.
pub fn deliver(thread: &UserThread, record: &[u8]) -> u32 {
    let dispatcher = state::with(|state| state.ntdll_exports.as_ref().and_then(|exports| exports.get("KiUserExceptionDispatcher").copied()));
    let Some(dispatcher) = dispatcher.filter(|&dispatcher| state::probe_user_read(dispatcher, 1)) else { return 0xC000_0139 };
    let context = thread.with(|thread| thread.context);
    let rsp = guest::read64(context + 0x98);
    let stack = (rsp.wrapping_sub(FRAME_SIZE)) & !15;
    // Falha sem escrever nada quando o usuário não pode receber o frame; o
    // crescimento da pilha/guard page exige o suporte separado do Mm.
    if !state::probe_user_write(stack, FRAME_SIZE) {
        return 0xC000_00FD;
    }
    let mut saved = read_bytes(context, CONTEXT_SIZE);
    // Um tratador nunca restaura IOPL/NT/VM/VIF/VIP pelo RtlRestoreContext.
    let eflags = (u32_at(&saved, 0x44) & !0x1A_7000) | 0x202;
    saved[0x44..0x48].copy_from_slice(&eflags.to_le_bytes());
    for index in (0..FRAME_SIZE).step_by(8) {
        guest::write64(stack + index, 0);
    }
    write_bytes(stack, &saved);
    // Faixas relativas do CONTEXT_EX: bloco inteiro e CONTEXT legado, sem XSTATE.
    guest::write32(stack + 0x4D0, (CONTEXT_SIZE as u32).wrapping_neg());
    guest::write32(stack + 0x4D4, 0x4F0);
    guest::write32(stack + 0x4D8, (CONTEXT_SIZE as u32).wrapping_neg());
    guest::write32(stack + 0x4DC, CONTEXT_SIZE as u32);
    write_bytes(stack + RECORD_OFFSET, record);
    for (destination, source, length) in [(0u64, 0xF8usize, 8usize), (8, 0x38, 2), (16, 0x44, 4), (24, 0x98, 8), (32, 0x42, 2)] {
        write_bytes(stack + MACHINE_OFFSET + destination, &saved[source..source + length]);
    }
    guest::write64(context + 0x98, stack);
    guest::write64(context + 0xF8, dispatcher);
    guest::write64(context + 0x80, stack + RECORD_OFFSET);
    guest::write64(context + 0x88, stack);
    // TF/DF/RF limpos na entrada do despachante; as flags originais ficam
    // no CONTEXT salvo para a decisão de continuação do tratador.
    guest::write32(context + 0x44, eflags & !0x1_0500);
    crate::debug_print!("[exception] first chance 0x{:x} -> KiUserExceptionDispatcher, frame=0x{:x}", u32_at(record, 0), stack);
    0
}

/// Exceção de hardware salva pela HAL nesta transição.
pub fn hardware(thread: &UserThread, status: u32) -> u32 {
    let vector = guest::read32(FAULT_VECTOR);
    let context = thread.with(|thread| thread.context);
    // A HAL capturou o banco de depuração real do usuário: fica disponível
    // ao VEH/SEH e ao NtContinue seguinte.
    guest::write32(context + 0x30, guest::read32(context + 0x30) | 0x10_0010);
    let mut address = guest::read64(context + 0xF8);
    if vector == 3 {
        address = address.wrapping_sub(1);
        guest::write64(context + 0xF8, address);
    }
    let mut record = alloc::vec![0u8; RECORD_SIZE as usize];
    record[0..4].copy_from_slice(&status.to_le_bytes());
    record[0x10..0x18].copy_from_slice(&address.to_le_bytes());
    if vector == 14 {
        let error = guest::read32(ERROR_CODE);
        if page_residency::fault(guest::read64(FAULT_CR2), error) {
            return 0;
        }
        record[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
        let access: u64 = if error & 16 != 0 { 8 } else if error & 2 != 0 { 1 } else { 0 };
        record[0x20..0x28].copy_from_slice(&access.to_le_bytes());
        record[0x28..0x30].copy_from_slice(&guest::read64(FAULT_CR2).to_le_bytes());
    }
    deliver(thread, &record)
}

/// NtRaiseException: segunda chance termina o processo; a primeira fica
/// pendente até a HAL salvar os registradores de retorno da syscall.
pub fn raise(record: u64, context: u64, first_chance: u64) -> Result<u32, KernelError> {
    if !state::probe_user_read(record, RECORD_SIZE) {
        return Ok(0xC000_0005);
    }
    if guest::read32(record + 0x18) > 15 {
        return Ok(0xC000_000D);
    }
    let invalid = validate_context(context);
    if invalid != 0 {
        return Ok(invalid);
    }
    let captured = read_bytes(record, RECORD_SIZE);
    if first_chance & 0xFF == 0 {
        let code = guest::read32(record);
        let rsp = guest::read64(context + 0x98);
        state::with(|state| state.termination_rsp = rsp);
        crate::debug_print!("[exception] unhandled 0x{:x} @0x{:x}", code, guest::read64(record + 0x10));
        guest::write32(state::EXIT_CODE_CELL, code);
        return Ok(state::TERMINATE_MAGIC);
    }
    let Some(thread) = threads::current() else { return Ok(0xC000_00BB) };
    PENDING.lock().insert(thread.thread_id, (read_bytes(context, CONTEXT_SIZE), captured));
    thread.with(|thread| thread.pending_exception = true);
    Ok(0)
}

/// Aplica a exceção pendente ao CONTEXT vivo e a entrega.
pub fn pending(thread: &UserThread) -> u32 {
    thread.with(|thread| thread.pending_exception = false);
    let Some((saved, record)) = PENDING.lock().remove(&thread.thread_id) else { return 0 };
    let context = thread.with(|thread| thread.context);
    // RtlCaptureContext não inicializa todos os grupos (notavelmente
    // DR0..DR7): os campos não selecionados da thread viva são preservados.
    let flags = u32_at(&saved, 0x30);
    let mut ranges: Vec<(usize, usize)> = alloc::vec![(0x30, 4)];
    if flags & 1 != 0 {
        ranges.extend([(0x38, 2), (0x42, 6), (0x98, 8), (0xF8, 8)]);
    }
    if flags & 2 != 0 {
        ranges.extend(INTEGER.iter().map(|&offset| (offset as usize, 8)));
    }
    if flags & 4 != 0 {
        ranges.push((0x3A, 8));
    }
    if flags & 8 != 0 {
        ranges.extend([(0x34, 4), (0x100, 0x1A0)]);
    }
    for (offset, length) in ranges {
        write_bytes(context + offset as u64, &saved[offset..offset + length]);
    }
    if flags & 0x10 != 0 {
        let values: [u64; 6] = core::array::from_fn(|index| u64::from_le_bytes(saved[0x48 + index * 8..0x50 + index * 8].try_into().unwrap_or([0; 8])));
        for (index, value) in registers::debug_registers(values, 1).iter().enumerate() {
            guest::write64(context + 0x48 + index as u64 * 8, *value);
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
