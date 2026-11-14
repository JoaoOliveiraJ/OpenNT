//! Instruções privilegiadas e de identificação da CPU: CPUID, RDTSC, MSRs,
//! registradores de controle, IDT, interrupções, caches, FXSAVE, HLT e
//! RDRAND.

use core::arch::asm;

/// Resultado de CPUID na ordem `[eax, ebx, ecx, edx]`.
pub fn cpuid(leaf: u32) -> [u32; 4] {
    cpuid_subleaf(leaf, 0)
}

pub fn cpuid_subleaf(leaf: u32, subleaf: u32) -> [u32; 4] {
    let result = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    [result.eax, result.ebx, result.ecx, result.edx]
}

#[inline]
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

pub fn read_msr(index: u32) -> u64 {
    let (low, high): (u32, u32);
    unsafe { asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high, options(nomem, nostack)) }
    (high as u64) << 32 | low as u64
}

pub fn write_msr(index: u32, value: u64) {
    unsafe {
        asm!("wrmsr", in("ecx") index, in("eax") value as u32, in("edx") (value >> 32) as u32,
             options(nostack))
    }
}

pub fn read_cr0() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr0", out(reg) value, options(nomem, nostack)) }
    value
}

pub fn read_cr2() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr2", out(reg) value, options(nomem, nostack)) }
    value
}

pub fn read_cr3() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr3", out(reg) value, options(nomem, nostack)) }
    value
}

pub fn read_cr4() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr4", out(reg) value, options(nomem, nostack)) }
    value
}

/// Recarrega CR3 (esvazia a TLB não global).
pub fn reload_cr3() {
    unsafe { asm!("mov rax, cr3", "mov cr3, rax", out("rax") _, options(nostack)) }
}

/// Carrega CR3: outra raiz de tabelas de páginas (esvazia a TLB não global).
/// Sem `nomem`: os acessos à memória não atravessam a troca.
pub fn write_cr3(value: u64) {
    unsafe { asm!("mov cr3, {}", in(reg) value, options(nostack, preserves_flags)) }
}

/// Invalida a página de `address` na TLB (INVLPG).
pub fn invalidate_page(address: u64) {
    unsafe { asm!("invlpg [{}]", in(reg) address, options(nostack)) }
}

/// PAUSE (dica de espera ativa).
#[inline]
pub fn pause() {
    core::hint::spin_loop();
}

/// Devolve RFLAGS e executa CLI.
#[inline]
pub fn save_and_disable_interrupts() -> u64 {
    let flags: u64;
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) flags, options(nomem)) }
    flags
}

/// Reativa IF somente se estava ligada antes.
#[inline]
pub fn restore_interrupts(flags: u64) {
    if flags & 0x200 != 0 {
        unsafe { asm!("sti", options(nomem, nostack)) }
    }
}

pub fn enable_interrupts() {
    unsafe { asm!("sti", options(nomem, nostack)) }
}

/// Carrega a IDT e liga interrupções.
pub fn load_idt(base: u64, size: u16) {
    #[repr(C, packed)]
    struct TableRegister {
        limit: u16,
        base: u64,
    }
    let register = TableRegister { limit: size - 1, base };
    unsafe {
        asm!("lidt [{}]", in(reg) &register, options(readonly, nostack));
        asm!("sti", options(nomem, nostack));
    }
}

/// Recarrega o GDTR (sem tocar nos seletores carregados).
pub fn load_gdt(base: u64, limit: u16) {
    #[repr(C, packed)]
    struct TableRegister {
        limit: u16,
        base: u64,
    }
    let register = TableRegister { limit, base };
    unsafe { asm!("lgdt [{}]", in(reg) &register, options(readonly, nostack)) }
}

/// Esvazia os caches (WBINVD).
pub fn flush_caches() {
    unsafe { asm!("wbinvd", options(nostack)) }
}

/// CLFLUSH: grava de volta e invalida, em todo o domínio de coerência, a
/// linha de cache que contém o endereço virtual (mapeado) dado.
pub fn flush_cache_line(address: u64) {
    unsafe { asm!("clflush [{}]", in(reg) address, options(nostack, preserves_flags)) }
}

/// FXSAVE64: grava o estado x87/SSE em `address` (alinhado a 16).
pub fn fxsave(address: u64) {
    unsafe { asm!("fxsave64 [{}]", in(reg) address, options(nostack)) }
}

/// FXRSTOR64: restaura o estado x87/SSE de `address` (alinhado a 16).
pub fn fxrstor(address: u64) {
    unsafe { asm!("fxrstor64 [{}]", in(reg) address, options(nostack)) }
}

/// CLI + HLT eterno.
pub fn halt_forever() -> ! {
    unsafe { asm!("cli", options(nomem, nostack)) }
    loop {
        unsafe { asm!("hlt", options(nomem, nostack)) }
    }
}

/// RDRAND quando disponível.
pub fn hardware_random_u64() -> Option<u64> {
    if cpuid(1)[2] & (1 << 30) == 0 {
        return None;
    }
    for _ in 0..10 {
        let value: u64;
        let ok: u8;
        unsafe { asm!("rdrand {}", "setc {}", out(reg) value, out(reg_byte) ok, options(nomem, nostack)) }
        if ok != 0 {
            return Some(value);
        }
    }
    None
}
