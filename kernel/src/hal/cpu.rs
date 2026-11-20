//! Instruções privilegiadas e de identificação da CPU: CPUID, RDTSC (também
//! na ordem das instruções anteriores, a do contador de desempenho), MSRs,
//! registradores de controle e estendidos (XCR), IDT, interrupções, caches,
//! FXSAVE, HLT e RDRAND.

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

/// Como o contador de desempenho lê o TSC sem que a leitura suba acima das
/// instruções anteriores: o HalpTscQueryCounterOrdered do NT (RDTSCP)
/// quando o processador tem RDTSCP (CPUID.80000001H:EDX[27]), senão o
/// HalpTscQueryCounter com a cerca do HalpTscFenceRequired antes do RDTSC
/// (LFENCE na Intel, MFENCE na AMD). Um RDTSC sem ordem pode executar antes
/// de uma leitura de memória anterior, e um valor publicado por outra CPU
/// ficaria maior que o lido depois dele.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TscRead {
    Rdtscp = 1,
    Lfence = 2,
    Mfence = 3,
}

/// O [`TscRead`] decidido (0 = ainda não).
static TSC_READ: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

pub fn tsc_read_method() -> TscRead {
    use core::sync::atomic::Ordering;
    let method = match TSC_READ.load(Ordering::Relaxed) {
        1 => return TscRead::Rdtscp,
        2 => return TscRead::Lfence,
        3 => return TscRead::Mfence,
        _ => {
            let rdtscp = cpuid(0x8000_0000)[0] >= 0x8000_0001 && cpuid(0x8000_0001)[3] & (1 << 27) != 0;
            let amd = cpuid(0)[1] == u32::from_le_bytes(*b"Auth");
            if rdtscp {
                TscRead::Rdtscp
            } else if amd {
                TscRead::Mfence
            } else {
                TscRead::Lfence
            }
        }
    };
    TSC_READ.store(method as u8, Ordering::Relaxed);
    method
}

/// O TSC lido depois das instruções anteriores ([`TscRead`]).
#[inline]
pub fn rdtsc_ordered() -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: RDTSCP, LFENCE, MFENCE e RDTSC não tocam a memória nem a
    // pilha; o RDTSCP também escreve o IA32_TSC_AUX em ECX, descartado.
    unsafe {
        match tsc_read_method() {
            TscRead::Rdtscp => asm!("rdtscp", out("eax") low, out("edx") high, out("ecx") _, options(nomem, nostack, preserves_flags)),
            TscRead::Lfence => asm!("lfence", "rdtsc", out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags)),
            TscRead::Mfence => asm!("mfence", "rdtsc", out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags)),
        }
    }
    (high as u64) << 32 | low as u64
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

/// Grava CR4.
pub fn write_cr4(value: u64) {
    unsafe { asm!("mov cr4, {}", in(reg) value, options(nostack)) }
}

/// XGETBV: o registrador de controle estendido `index` (XCR0 = 0). Exige o
/// CR4.OSXSAVE.
pub fn read_xcr(index: u32) -> u64 {
    let (low, high): (u32, u32);
    unsafe { asm!("xgetbv", in("ecx") index, out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags)) }
    (high as u64) << 32 | low as u64
}

/// XSETBV: grava o registrador de controle estendido `index`.
pub fn write_xcr(index: u32, value: u64) {
    unsafe { asm!("xsetbv", in("ecx") index, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nostack)) }
}

/// CR8: a prioridade de tarefa (TPR[7:4] do LAPIC), o IRQL do x64.
pub fn read_cr8() -> u64 {
    let value: u64;
    unsafe { asm!("mov {}, cr8", out(reg) value, options(nomem, nostack, preserves_flags)) }
    value
}

/// Grava CR8. Sem `nomem`: os acessos à memória que o nível protege não
/// atravessam a troca.
pub fn write_cr8(value: u64) {
    unsafe { asm!("mov cr8, {}", in(reg) value, options(nostack, preserves_flags)) }
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

/// RFLAGS.IF da CPU corrente (o KeAreInterruptsEnabled).
#[inline]
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem)) }
    flags & 0x200 != 0
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

/// HalProcessorIdle (o `sti; hlt` que o KiIdleLoop do 19041 chama): o
/// chamador desligou as interrupções e conferiu que não há trabalho. A
/// sombra do STI cobre o HLT, então uma interrupção que chegou depois da
/// conferência acorda o processador logo em vez de esperar a próxima. Volta
/// com as interrupções ligadas. Sem `nomem`: os tratadores que acordam o
/// processador gravam memória (as contagens de IRQ), e nada lido antes do
/// HLT pode ser reaproveitado depois dele.
pub fn processor_idle() {
    unsafe { asm!("sti", "hlt", options(nostack)) }
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
