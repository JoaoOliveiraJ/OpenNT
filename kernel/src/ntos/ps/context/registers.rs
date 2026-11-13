//! Seleção e saneamento de registradores x64.
//!
//! Medido contra PspSetContext e o validador de ContextFlags originais. O
//! agendamento e a captura ficam no provedor de contexto de thread; este
//! módulo nunca reporta a conclusão de uma API.

use core::mem::offset_of;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Context, XsaveFormat};
use crate::ntos::mm::guest_memory::{self as guest, GuestScalar};
use crate::rtl::KernelError;

pub const SIZE: u64 = Context::SIZE;
pub const AMD64: u32 = 0x10_0000;
const INVALID_PARAMETER: u32 = 0xC000_000D;
const NOT_SUPPORTED: u32 = 0xC000_00BB;
/// Rax..R15 (sem Rsp) no CONTEXT.
pub const INTEGER: [u64; 15] = [
    offset_of!(Context, rax) as u64,
    offset_of!(Context, rcx) as u64,
    offset_of!(Context, rdx) as u64,
    offset_of!(Context, rbx) as u64,
    offset_of!(Context, rbp) as u64,
    offset_of!(Context, rsi) as u64,
    offset_of!(Context, rdi) as u64,
    offset_of!(Context, r8) as u64,
    offset_of!(Context, r9) as u64,
    offset_of!(Context, r10) as u64,
    offset_of!(Context, r11) as u64,
    offset_of!(Context, r12) as u64,
    offset_of!(Context, r13) as u64,
    offset_of!(Context, r14) as u64,
    offset_of!(Context, r15) as u64,
];

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

/// Cópia em QWORDs entre duas áreas de registradores (CONTEXT, KTRAP_FRAME,
/// quadro do HAL, imagem FXSAVE).
pub fn copy(to: u64, from: u64, size: u64) {
    let count = (size / 8) as usize;
    // SAFETY: os chamadores passam áreas de registradores do kernel de pelo
    // menos `size` bytes, alinhadas a 8.
    let (target, source) = unsafe { (Field::<u64>::array_at(to, count), Field::<u64>::array_at(from, count)) };
    for (target, source) in target.iter().zip(source) {
        target.set(source.get());
    }
}

fn context(address: u64) -> &'static Context {
    // SAFETY: CONTEXT do kernel (cópia capturada, buffer de KernelMode ou o
    // CONTEXT salvo do quadro).
    unsafe { Context::at(address) }
}

/// Rax..R15 sem Rsp, na ordem de [`INTEGER`].
pub(crate) fn integer_registers(context: &Context) -> [&Field<u64>; 15] {
    [
        &context.rax, &context.rcx, &context.rdx, &context.rbx, &context.rbp, &context.rsi, &context.rdi, &context.r8,
        &context.r9, &context.r10, &context.r11, &context.r12, &context.r13, &context.r14, &context.r15,
    ]
}

/// Lê um campo do CONTEXT de modo usuário com sonda (o `__try` do NT): a
/// página pode sumir entre a sondagem do intervalo e a leitura.
fn probe<T: GuestScalar>(source: u64, offset: usize) -> Result<T, KernelError> {
    guest::try_read(source + offset as u64)
}

/// Copia `length` bytes do CONTEXT de modo usuário para o do kernel.
fn probe_block(target: &Context, source: u64, offset: usize, length: usize) -> Result<(), KernelError> {
    let bytes = guest::try_read_bytes(source + offset as u64, length)?;
    guest::write_bytes(target.address() + offset as u64, &bytes);
    Ok(())
}

/// Captura um CONTEXT de usuário legado num armazenamento zerado do kernel:
/// copia os campos selecionados e publica os flags normalizados, sem tocar
/// homes, grupos não selecionados, padding ou a extensão vetorial. A origem
/// é memória de modo usuário: toda leitura dela é sondada.
pub fn capture_registers(target: u64, source: u64, flags: u32) -> Result<(), KernelError> {
    if flags & 0x40 != 0 {
        return Err(KernelError::new("thread context: XSTATE must be validated before capture"));
    }
    guest::write_bytes(target, &[0; SIZE as usize]);
    let target = context(target);
    target.context_flags.set(flags);
    if flags & 1 != 0 {
        target.rip.set(probe(source, offset_of!(Context, rip))?);
        target.rsp.set(probe(source, offset_of!(Context, rsp))?);
        target.seg_cs.set(probe(source, offset_of!(Context, seg_cs))?);
        target.seg_ss.set(probe(source, offset_of!(Context, seg_ss))?);
        target.e_flags.set(probe(source, offset_of!(Context, e_flags))?);
    }
    if flags & 2 != 0 {
        for (field, offset) in integer_registers(target).into_iter().zip(INTEGER) {
            field.set(probe(source, offset as usize)?);
        }
    }
    if flags & 4 != 0 {
        target.seg_ds.set(probe(source, offset_of!(Context, seg_ds))?);
        target.seg_es.set(probe(source, offset_of!(Context, seg_es))?);
        target.seg_fs.set(probe(source, offset_of!(Context, seg_fs))?);
        target.seg_gs.set(probe(source, offset_of!(Context, seg_gs))?);
    }
    if flags & 8 != 0 {
        target.mx_csr.set(probe(source, offset_of!(Context, mx_csr))?);
        // Parte legada do FltSave e Xmm0..15.
        probe_block(target, source, offset_of!(Context, flt_save), offset_of!(XsaveFormat, reserved4))?;
    }
    if flags & 0x10 != 0 {
        probe_block(target, source, offset_of!(Context, dr0), offset_of!(Context, rax) - offset_of!(Context, dr0))?;
        probe_block(target, source, offset_of!(Context, last_branch_to_rip), SIZE as usize - offset_of!(Context, last_branch_to_rip))?;
    }
    Ok(())
}

/// Projeta o CONTEXT de entrada no CONTEXT salvo (trap frame real e não
/// voláteis). SEGMENTS sozinho não altera segmentos; CONTROL é dono de CS/SS.
pub fn write_registers(target: u64, source: u64, mode: u8, mxcsr_mask: u32, current_mxcsr: u32) -> Result<(), KernelError> {
    let (target, source) = (context(target), context(source));
    let flags = source.context_flags.get();
    let selected = |mask: u32| flags & (AMD64 | mask) == AMD64 | mask;
    if selected(0x40) {
        return Err(KernelError::new("thread context: XSTATE must be validated before register writes"));
    }
    if selected(1) {
        let mut rip = source.rip.get();
        let cs: u16 = if mode == 1 { if source.seg_cs.get() == 0x33 { 0x33 } else { 0x23 } } else { 0x10 };
        if mode == 1 {
            rip = if cs == 0x33 { ((rip << 16) as i64 >> 16) as u64 } else { rip & 0xFFFF_FFFF };
        }
        let eflags = (source.e_flags.get() & if mode != 0 { 0x21_0DD5 } else { 0x25_0FD5 }) | if mode != 0 { 0x200 } else { 0 };
        target.e_flags.set(eflags);
        target.rip.set(rip);
        target.rsp.set(source.rsp.get());
        target.seg_cs.set(cs);
        target.seg_ss.set(if mode == 1 { 0x2B } else { 0 });
    }
    if selected(2) {
        for (target, source) in integer_registers(target).into_iter().zip(integer_registers(source)) {
            target.set(source.get());
        }
    }
    if selected(8) {
        for (target, source) in target.flt_save.xmm_registers.iter().zip(&source.flt_save.xmm_registers) {
            target.low.set(source.low.get());
            target.high.set(source.high.get());
        }
        target.mx_csr.set(source.mx_csr.get() & mxcsr_mask);
        // PspSetContext prepara a imagem FXSAVE de entrada para o FXRSTOR
        // da APC especial; em KernelMode o buffer do chamador é a entrada.
        source.flt_save.mx_csr.set(current_mxcsr);
        source.flt_save.control_word.set(source.flt_save.control_word.get() & 0x1F3F);
    }
    if selected(0x10) {
        let values = [source.dr0.get(), source.dr1.get(), source.dr2.get(), source.dr3.get(), 0, source.dr7.get()];
        let fields = [&target.dr0, &target.dr1, &target.dr2, &target.dr3, &target.dr6, &target.dr7];
        for (field, value) in fields.into_iter().zip(debug_registers(values, mode)) {
            field.set(value);
        }
    }
    Ok(())
}

/// O escalonador guarda uma imagem FXSAVE inteira em vez de MXCSR/XMM do
/// trap frame; só a APC especial de UserMode restaura x87/MMX.
pub fn write_saved_context(target: u64, source: u64, mode: u8, mxcsr_mask: u32, current_mxcsr: u32) -> Result<(), KernelError> {
    let flags = context(source).context_flags.get();
    write_registers(target, source, mode, mxcsr_mask, current_mxcsr)?;
    if flags & 0x10_0008 == 0x10_0008 {
        let (saved, input) = (context(target), context(source));
        if mode == 1 {
            // A parte x87/MMX da imagem FXSAVE (antes dos XMM).
            copy(saved.flt_save.address(), input.flt_save.address(), offset_of!(XsaveFormat, xmm_registers) as u64);
        }
        saved.flt_save.mx_csr.set(saved.mx_csr.get());
    }
    Ok(())
}
