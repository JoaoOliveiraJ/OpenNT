//! Seleção e saneamento de registradores x64 — `system32/ntos/ps/thread-context-registers.js`.
//!
//! Medido contra PspSetContext e o validador de ContextFlags originais. O
//! agendamento e a captura ficam no provedor de contexto de thread; este
//! módulo nunca reporta a conclusão de uma API.

use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub const SIZE: u64 = 0x4D0;
pub const AMD64: u32 = 0x10_0000;
const INVALID_PARAMETER: u32 = 0xC000_000D;
const NOT_SUPPORTED: u32 = 0xC000_00BB;
/// Rax..R15 (sem Rsp) no CONTEXT.
pub const INTEGER: [u64; 15] = [0x78, 0x80, 0x88, 0x90, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0];

/// Dr0..Dr3, Dr6 e Dr7 saneados (também em KiContextToKframes, o escritor
/// comum de KiContinuePreviousModeUser e KiRaiseException).
pub fn debug_registers(values: [u64; 6], mode: u8) -> [u64; 6] {
    let mut result = [0u64; 6];
    for index in 0..4 {
        result[index] = if mode != 0 && values[index] > 0x7FFF_FFFE_FFFF { 0 } else { values[index] };
    }
    result[5] = values[5] & 0xFFFF_0355;
    result
}

/// (status, flags normalizados). UserMode converte flags inválidos em
/// CONTEXT_AMD64 com os grupos reconhecidos.
pub fn validate(flags: u32, mode: u8, xstate: bool) -> (u32, u32) {
    let architecture = flags & 0x27FF_FF80 == 0x1_0000 || flags & 0x27FF_FFA0 == AMD64 || flags & 0x07FF_FFF0 == 0x20_0000 || flags & 0x07FF_FFE0 == 0x40_0000;
    let mut status = if architecture { 0 } else { INVALID_PARAMETER };
    if status == 0 && (flags & 0x10_0040 == 0x10_0040 || flags & 0x1_0040 == 0x1_0040) && !xstate {
        status = NOT_SUPPORTED;
    }
    if status == 0 && flags & AMD64 == 0 {
        status = INVALID_PARAMETER;
    }
    if status == INVALID_PARAMETER && mode != 0 {
        return (0, (flags & 0xD810_001F) | AMD64);
    }
    (status, flags)
}

/// Cópia em QWORDs.
pub fn copy(to: u64, from: u64, size: u64) {
    let mut offset = 0;
    while offset < size {
        guest::write64(to + offset, guest::read64(from + offset));
        offset += 8;
    }
}

/// Captura um CONTEXT de usuário legado num armazenamento zerado do kernel:
/// copia os campos selecionados e publica os flags normalizados, sem tocar
/// homes, grupos não selecionados, padding ou a extensão vetorial.
pub fn capture_registers(target: u64, source: u64, flags: u32) -> Result<(), KernelError> {
    if flags & 0x40 != 0 {
        return Err(KernelError::new("thread context: XSTATE must be validated before capture"));
    }
    guest::write_bytes(target, &[0; SIZE as usize]);
    guest::write32(target + 0x30, flags);
    let word = |offset: u64| guest::write16(target + offset, guest::read16(source + offset));
    let dword = |offset: u64| guest::write32(target + offset, guest::read32(source + offset));
    if flags & 1 != 0 {
        copy(target + 0xF8, source + 0xF8, 8);
        copy(target + 0x98, source + 0x98, 8);
        word(0x38);
        word(0x42);
        dword(0x44);
    }
    if flags & 2 != 0 {
        for offset in INTEGER {
            copy(target + offset, source + offset, 8);
        }
    }
    if flags & 4 != 0 {
        for offset in [0x3A, 0x3C, 0x3E, 0x40] {
            word(offset);
        }
    }
    if flags & 8 != 0 {
        dword(0x34);
        copy(target + 0x100, source + 0x100, 0x1A0);
    }
    if flags & 0x10 != 0 {
        copy(target + 0x48, source + 0x48, 48);
        copy(target + 0x4B0, source + 0x4B0, 32);
    }
    Ok(())
}

/// Projeta o CONTEXT de entrada no CONTEXT salvo (trap frame real e não
/// voláteis). SEGMENTS sozinho não altera segmentos; CONTROL é dono de CS/SS.
pub fn write_registers(target: u64, source: u64, mode: u8, mxcsr_mask: u32, current_mxcsr: u32) -> Result<(), KernelError> {
    let flags = guest::read32(source + 0x30);
    let selected = |mask: u32| flags & (AMD64 | mask) == AMD64 | mask;
    if selected(0x40) {
        return Err(KernelError::new("thread context: XSTATE must be validated before register writes"));
    }
    if selected(1) {
        let mut rip = guest::read64(source + 0xF8);
        let cs: u16 = if mode == 1 { if guest::read16(source + 0x38) == 0x33 { 0x33 } else { 0x23 } } else { 0x10 };
        if mode == 1 {
            rip = if cs == 0x33 { ((rip << 16) as i64 >> 16) as u64 } else { rip & 0xFFFF_FFFF };
        }
        let eflags = (guest::read32(source + 0x44) & if mode != 0 { 0x21_0DD5 } else { 0x25_0FD5 }) | if mode != 0 { 0x200 } else { 0 };
        guest::write32(target + 0x44, eflags);
        guest::write64(target + 0xF8, rip);
        guest::write64(target + 0x98, guest::read64(source + 0x98));
        guest::write16(target + 0x38, cs);
        guest::write16(target + 0x42, if mode == 1 { 0x2B } else { 0 });
    }
    if selected(2) {
        for offset in INTEGER {
            copy(target + offset, source + offset, 8);
        }
    }
    if selected(8) {
        copy(target + 0x1A0, source + 0x1A0, 16 * 16);
        guest::write32(target + 0x34, guest::read32(source + 0x34) & mxcsr_mask);
        // PspSetContext prepara a imagem FXSAVE de entrada para o FXRSTOR
        // da APC especial; em KernelMode o buffer do chamador é a entrada.
        guest::write32(source + 0x118, current_mxcsr);
        guest::write16(source + 0x100, guest::read16(source + 0x100) & 0x1F3F);
    }
    if selected(0x10) {
        let values = [guest::read64(source + 0x48), guest::read64(source + 0x50), guest::read64(source + 0x58), guest::read64(source + 0x60), 0, guest::read64(source + 0x70)];
        for (index, value) in debug_registers(values, mode).into_iter().enumerate() {
            guest::write64(target + 0x48 + index as u64 * 8, value);
        }
    }
    Ok(())
}

/// O escalonador guarda uma imagem FXSAVE inteira em vez de MXCSR/XMM do
/// trap frame; só a APC especial de UserMode restaura x87/MMX.
pub fn write_saved_context(target: u64, source: u64, mode: u8, mxcsr_mask: u32, current_mxcsr: u32) -> Result<(), KernelError> {
    let flags = guest::read32(source + 0x30);
    write_registers(target, source, mode, mxcsr_mask, current_mxcsr)?;
    if flags & 0x10_0008 == 0x10_0008 {
        if mode == 1 {
            copy(target + 0x100, source + 0x100, 0xA0);
        }
        guest::write32(target + 0x118, guest::read32(target + 0x34));
    }
    Ok(())
}
