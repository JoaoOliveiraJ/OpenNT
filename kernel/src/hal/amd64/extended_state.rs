//! Salvamento e restauração do estado estendido do processador (XSAVE).
//!
//! Duas famílias de primitivas:
//!
//! - as da troca de contexto ([`save`] e [`restore`]), as mesmas do
//!   SwapContext do ntoskrnl 19041: o XSAVES quando o KeFeatureBits tem o bit
//!   do XSAVES, senão o XSAVEOPT (bit do XSAVEOPT), senão o XSAVE (bit do
//!   XSTATE), e na volta o XRSTORS ou o XRSTOR. A máscara é a do NpxState de
//!   uma thread de sistema (`XState.EnabledFeatures & ~3`): o x87 e o SSE
//!   ficam no CONTEXT e nos quadros de troca, como o SSE fica fora do NpxState
//!   no NT. Os stubs de assembly chamam `opennt_xstate_save` e
//!   `opennt_xstate_restore` com a área em RCX (zero = nada a fazer); as duas
//!   preservam todos os registradores e o MXCSR vivo;
//! - as do Rtl ([`rtl_xsave`], [`rtl_xsave_s`], [`rtl_xrestore`] e
//!   [`rtl_xrestore_s`]), com a máscara do chamador, como o RtlXSave, o
//!   RtlXSaveS, o RtlXRestore e o RtlXRestoreS: o XSAVEC/XSAVES com a
//!   compactação; sem ela, o XSAVE e o XRSTOR com o cuidado do MXCSR quando a
//!   máscara tem o AVX e não o SSE (o formato padrão grava e lê o MXCSR nesse
//!   caso).
//!
//! A área tem 64 bytes de alinhamento e o tamanho de KiXSaveAreaLength.

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// Instrução da troca de contexto.
pub mod kind {
    pub const NONE: u8 = 0;
    pub const XSAVE: u8 = 1;
    pub const XSAVEOPT: u8 = 2;
    pub const XSAVES: u8 = 3;
}

/// A instrução e a máscara da troca, lidas pelos stubs.
#[no_mangle]
static opennt_xstate_kind: AtomicU8 = AtomicU8::new(kind::NONE);
#[no_mangle]
static opennt_xstate_mask: AtomicU64 = AtomicU64::new(0);

global_asm!(
    r#"
.pushsection .text.extended_state, "ax", @progbits

# opennt_xstate_save(area=rcx): o estado estendido da máscara da troca em
# [rcx]. Preserva todos os registradores (só as flags mudam).
.global opennt_xstate_save
opennt_xstate_save:
    test rcx, rcx
    jz 9f
    push rax
    push rdx
    mov eax, dword ptr [rip + opennt_xstate_mask]
    mov edx, dword ptr [rip + opennt_xstate_mask + 4]
    cmp byte ptr [rip + opennt_xstate_kind], 3
    je 3f
    cmp byte ptr [rip + opennt_xstate_kind], 2
    je 2f
    cmp byte ptr [rip + opennt_xstate_kind], 1
    jne 8f
    xsave64 [rcx]
    jmp 8f
2:
    xsaveopt64 [rcx]
    jmp 8f
3:
    xsaves64 [rcx]
8:
    pop rdx
    pop rax
9:
    ret

# opennt_xstate_restore(area=rcx): recarrega de [rcx] o estado estendido da
# máscara da troca. O MXCSR vivo volta intacto (o XRSTOR no formato padrão o
# leria da área). Preserva todos os registradores (só as flags mudam).
.global opennt_xstate_restore
opennt_xstate_restore:
    test rcx, rcx
    jz 9f
    push rax
    push rdx
    sub rsp, 8
    stmxcsr [rsp]
    mov eax, dword ptr [rip + opennt_xstate_mask]
    mov edx, dword ptr [rip + opennt_xstate_mask + 4]
    cmp byte ptr [rip + opennt_xstate_kind], 3
    je 3f
    cmp byte ptr [rip + opennt_xstate_kind], 0
    je 8f
    xrstor64 [rcx]
    jmp 8f
3:
    xrstors64 [rcx]
8:
    ldmxcsr [rsp]
    add rsp, 8
    pop rdx
    pop rax
9:
    ret
.popsection
"#
);

extern "C" {
    fn opennt_xstate_save();
    fn opennt_xstate_restore();
}

/// Liga as primitivas da troca: a instrução e a máscara.
pub fn configure(instruction: u8, mask: u64) {
    opennt_xstate_mask.store(mask, Ordering::Release);
    opennt_xstate_kind.store(instruction, Ordering::Release);
}

/// A instrução da troca ([`kind`]).
pub fn instruction() -> u8 {
    opennt_xstate_kind.load(Ordering::Acquire)
}

/// A máscara da troca.
pub fn mask() -> u64 {
    opennt_xstate_mask.load(Ordering::Acquire)
}

/// Salva o estado estendido da troca em `area` (zero = nada).
///
/// # Safety
///
/// `area` é zero ou uma área de XSAVE viva, alinhada a 64, com
/// KiXSaveAreaLength bytes e cabeçalho válido para a instrução da troca.
pub unsafe fn save(area: u64) {
    asm!("call {routine}", routine = sym opennt_xstate_save, in("rcx") area);
}

/// Recarrega o estado estendido da troca de `area` (zero = nada).
///
/// # Safety
///
/// Como em [`save`]; o cabeçalho precisa passar nas regras do XRSTOR(S).
pub unsafe fn restore(area: u64) {
    asm!("call {routine}", routine = sym opennt_xstate_restore, in("rcx") area);
}

fn split(mask: u64) -> (u32, u32) {
    (mask as u32, (mask >> 32) as u32)
}

/// RtlXSave(Area, Mask): XSAVEC com a compactação; senão XSAVE, preservando
/// o MXCSR e o MXCSR_MASK da área quando a máscara tem o AVX sem o SSE.
///
/// # Safety
///
/// `area` é uma área de XSAVE viva e alinhada a 64.
pub unsafe fn rtl_xsave(area: u64, mask: u64, compaction: bool) {
    let (low, high) = split(mask);
    if compaction {
        asm!("xsavec64 [{0}]", in(reg) area, in("eax") low, in("edx") high, options(nostack));
    } else if low & 6 == 4 {
        let mxcsr = core::ptr::read_volatile((area + 0x18) as *const u64);
        asm!("xsave64 [{0}]", in(reg) area, in("eax") low, in("edx") high, options(nostack));
        core::ptr::write_volatile((area + 0x18) as *mut u64, mxcsr);
    } else {
        asm!("xsave64 [{0}]", in(reg) area, in("eax") low, in("edx") high, options(nostack));
    }
}

/// RtlXSaveS(Area, Mask): XSAVES com a máscara restrita ao XCOMP_BV da área
/// quando há compactação; senão [`rtl_xsave`].
///
/// # Safety
///
/// Como em [`rtl_xsave`].
pub unsafe fn rtl_xsave_s(area: u64, mask: u64, compaction: bool) {
    if compaction {
        let compacted = core::ptr::read_volatile((area + 0x208) as *const u64) & mask;
        let (low, high) = split(compacted);
        asm!("xsaves64 [{0}]", in(reg) area, in("eax") low, in("edx") high, options(nostack));
    } else {
        rtl_xsave(area, mask, false);
    }
}

/// RtlXRestore(Area, Mask): no formato padrão com o AVX sem o SSE, o XRSTOR
/// lê o MXCSR corrente posto por um instante na área.
///
/// # Safety
///
/// `area` é uma área de XSAVE viva, alinhada a 64, com cabeçalho válido.
pub unsafe fn rtl_xrestore(area: u64, mask: u64) {
    let (low, high) = split(mask);
    let standard = (core::ptr::read_volatile((area + 0x208) as *const u64) as i64) >= 0;
    if standard && low & 6 == 4 {
        let saved = core::ptr::read_volatile((area + 0x18) as *const u32);
        let mut current: u32 = 0;
        asm!("stmxcsr [{0}]", in(reg) &mut current as *mut u32, options(nostack));
        core::ptr::write_volatile((area + 0x18) as *mut u32, current);
        asm!("xrstor64 [{0}]", in(reg) area, in("eax") low, in("edx") high, options(nostack));
        core::ptr::write_volatile((area + 0x18) as *mut u32, saved);
    } else {
        asm!("xrstor64 [{0}]", in(reg) area, in("eax") low, in("edx") high, options(nostack));
    }
}

/// RtlXRestoreS(Area, Mask): XRSTORS com a compactação; senão
/// [`rtl_xrestore`].
///
/// # Safety
///
/// Como em [`rtl_xrestore`].
pub unsafe fn rtl_xrestore_s(area: u64, mask: u64, compaction: bool) {
    if compaction {
        let (low, high) = split(mask);
        asm!("xrstors64 [{0}]", in(reg) area, in("eax") low, in("edx") high, options(nostack));
    } else {
        rtl_xrestore(area, mask);
    }
}
