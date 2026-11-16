//! A identidade e os recursos de cada processador, na KPRCB dele, como o
//! ntoskrnl 19041 os monta no boot de cada CPU (o CPUID é do processador que
//! executa: cada CPU monta a própria KPRCB).
//!
//! - KiGetCpuVendor: VendorString (EBX, EDX e ECX do CPUID 0) e CpuVendor
//!   (1 = AuthenticAMD ou HygonGenuine, 2 = GenuineIntel, 3 = CentaurHauls,
//!   0 = os demais).
//! - KiGetProcessorSignature e KiInitializeBootStructures: CpuType (a
//!   família, com a estendida na 0xF), CpuID = 1 e CpuStep = modelo << 8 |
//!   stepping (o modelo estendido entra na família 6 da Intel/Centaur e em
//!   toda família 0xF).
//! - KiSetProcessorSignature: FeatureBits pela KiCpuFeatureTable (47 testes
//!   de bit do CPUID, com filtro de fabricante) e pelas tabelas de MSR (o
//!   IA32_ARCH_CAPABILITIES, quando o CPUID o anuncia); os bits do segundo
//!   conjunto vão para KeFeatureBits2 (do BSP); ProcessorFlags pela assinatura
//!   (a lista da Intel) e ProcessorSignature.
//! - KiSetFeatureBits: os recursos que o ntoskrnl exige ligados de uma vez,
//!   o bit do fabricante, SLAT e firmware de virtualização (VMX/EPT na Intel,
//!   SVM/NPT na AMD), InitialApicId, CFlushSize, LogicalProcessorsPerCore e
//!   CoresPerPhysicalProcessor (CPUID 0x1F/0xB, ou 4 e 1 legados; 0x80000008
//!   e 0x8000001E na AMD), as cópias de 8 bits, ApicMask, UpdateSignature
//!   (o MSR 0x8B) e o IA32_TSC_AUX = Group << 8 | GroupIndex.
//! - KiSetCacheInformation: Cache[]/CacheCount (`processor_topology`), o
//!   SecondLevelCacheSize/Associativity da KPCR e o maior LineSize e o maior
//!   Size dos caches L2+ (KeLargestCacheLine e KiLargestCacheSize).
//! - KiInitializeKernel: PackageProcessorSet, PackageId, CoreProcessorSet e
//!   CacheProcessorMask (os processadores com o mesmo InitialApicId sob as
//!   máscaras), KeFeatureBits (com NX e XSTATE), KeProcessorLevel/Revision e
//!   os ProcessorFeatures (PF_*) da KUSER_SHARED_DATA.
//! - HalpTimerSaveProcessorFrequency: MHz e StallScaleFactor = a frequência
//!   do TSC arredondada a MHz.
//!
//! O que o binário faz na mesma passagem e o OpenNT não repete, porque muda
//! a configuração da CPU com que o resto do kernel roda: os bits do CR4
//! (SMEP, FSGSBASE, SMAP, UMIP, PCIDE), o EFER.FFXSR (o FXSAVE em CPL0
//! deixaria de salvar os XMM), os MSRs de SYSENTER, o MISC_ENABLE da Intel e
//! o DE_CFG da AMD. Como o binário liga SMEP e FSGSBASE no CR4 sempre que
//! publica os bits, aqui os dois bits só ficam quando o CR4 corrente os tem.
//! O VM_CR da AMD só é lido com o SVM anunciado (nos emuladores o MSR falta
//! sem SVM); as checagens que param o sistema (UNSUPPORTED_PROCESSOR,
//! MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED) viram avisos.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::processor_topology::{self, Cache, Sharing};
use super::{clock, pcr, smp};
use crate::hal::cpu;
use crate::ntos::inc::types::{Kpcr, Kprcb, KuserSharedData, ProcessorCacheType};
use crate::rtl::{KernelError, SpinLock};

/// CPU_VENDORS (KiGetCpuVendor).
pub mod vendor {
    pub const UNKNOWN: u8 = 0;
    pub const AMD: u8 = 1;
    pub const INTEL: u8 = 2;
    pub const CENTAUR: u8 = 3;
}

/// Os bits KF_* do FeatureBits de 64 bits que esta passagem consulta.
pub mod kf {
    pub const SMEP: u64 = 1 << 0;
    pub const RDTSC: u64 = 1 << 1;
    pub const THREE_D_NOW: u64 = 1 << 14;
    pub const XSAVEOPT: u64 = 1 << 15;
    pub const BRANCH: u64 = 1 << 17;
    pub const SSE3: u64 = 1 << 19;
    pub const AUTHENTIC_AMD: u64 = 1 << 21;
    pub const XSTATE: u64 = 1 << 23;
    pub const GENUINE_INTEL: u64 = 1 << 24;
    pub const SLAT: u64 = 1 << 26;
    pub const VIRT_FIRMWARE_ENABLED: u64 = 1 << 27;
    pub const RDWRFSGSBASE: u64 = 1 << 28;
    pub const NX_DISABLED: u64 = 1 << 30;
    pub const NX_ENABLED: u64 = 1 << 31;
    pub const RDRAND: u64 = 1 << 32;
    pub const SMAP: u64 = 1 << 33;
    pub const RDTSCP: u64 = 1 << 34;
    pub const SGX: u64 = 1 << 40;
    pub const SGX_LAUNCH_CONTROL: u64 = 1 << 43;
    pub const RDT_ALLOCATION: u64 = 1 << 44;
    pub const SSSE3: u64 = 1 << 47;
    pub const SSE4_1: u64 = 1 << 48;
    pub const SSE4_2: u64 = 1 << 49;
    pub const AVX: u64 = 1 << 50;
    pub const AVX2: u64 = 1 << 51;
    pub const AVX512: u64 = 1 << 52;
    /// RDTSC, CR4, CMOV, GLOBAL_PAGE, LARGE_PAGE, MTRR, CMPXCHG8B, MMX, PAT,
    /// FXSR, FAST_SYSCALL, XMMI, XMMI64, CMPXCHG16B e NX_BIT: o que o
    /// KiSetFeatureBits exige do CPUID e liga de uma vez.
    pub const REQUIRED: u64 = 0x2011_3DFE;
}

/// Os bits do segundo conjunto (KeFeatureBits2) que a publicação consulta.
pub mod kf2 {
    pub const RDPID: u64 = 1 << 1;
    pub const UMIP: u64 = 1 << 2;
    pub const MONITORX: u64 = 1 << 13;
}

/// Os índices PF_* do ProcessorFeatures da KUSER_SHARED_DATA.
pub mod pf {
    pub const COMPARE_EXCHANGE_DOUBLE: usize = 2;
    pub const MMX_INSTRUCTIONS_AVAILABLE: usize = 3;
    pub const XMMI_INSTRUCTIONS_AVAILABLE: usize = 6;
    pub const THREE_D_NOW_INSTRUCTIONS_AVAILABLE: usize = 7;
    pub const RDTSC_INSTRUCTION_AVAILABLE: usize = 8;
    pub const PAE_ENABLED: usize = 9;
    pub const XMMI64_INSTRUCTIONS_AVAILABLE: usize = 10;
    pub const NX_ENABLED: usize = 12;
    pub const SSE3_INSTRUCTIONS_AVAILABLE: usize = 13;
    pub const COMPARE_EXCHANGE128: usize = 14;
    pub const XSAVE_ENABLED: usize = 17;
    pub const SECOND_LEVEL_ADDRESS_TRANSLATION: usize = 20;
    pub const VIRT_FIRMWARE_ENABLED: usize = 21;
    pub const RDWRFSGSBASE_AVAILABLE: usize = 22;
    pub const FASTFAIL_AVAILABLE: usize = 23;
    pub const RDRAND_INSTRUCTION_AVAILABLE: usize = 28;
    pub const RDTSCP_INSTRUCTION_AVAILABLE: usize = 32;
    pub const RDPID_INSTRUCTION_AVAILABLE: usize = 33;
    pub const MONITORX_INSTRUCTION_AVAILABLE: usize = 35;
    pub const SSSE3_INSTRUCTIONS_AVAILABLE: usize = 36;
    pub const SSE4_1_INSTRUCTIONS_AVAILABLE: usize = 37;
    pub const SSE4_2_INSTRUCTIONS_AVAILABLE: usize = 38;
    pub const AVX_INSTRUCTIONS_AVAILABLE: usize = 39;
    pub const AVX2_INSTRUCTIONS_AVAILABLE: usize = 40;
    pub const AVX512F_INSTRUCTIONS_AVAILABLE: usize = 41;
}

// ---- KiCpuFeatureTable ------------------------------------------------------

/// Flags de uma entrada das tabelas de recursos.
mod entry {
    /// Recurso exigido: sem ele o binário para com UNSUPPORTED_PROCESSOR.
    pub const REQUIRED: u32 = 1;
    /// Entrada desligada.
    pub const DISABLED: u32 = 2;
    /// Os APs precisam concordar com o BSP.
    pub const MATCH_BOOT: u32 = 4;
    /// Os bits vão para o FeatureBits.
    pub const FEATURE_BITS: u32 = 8;
    /// Os bits vão para o segundo conjunto (KeFeatureBits2).
    pub const FEATURE_BITS2: u32 = 0x10;
}

const EAX: u8 = 0;
const EBX: u8 = 1;
const ECX: u8 = 2;
const EDX: u8 = 3;

/// Um teste de bit do CPUID: (folha, subfolha, máscara, registrador, flags
/// com o filtro de fabricante nos bits 24..31, bits KF_).
#[derive(Clone, Copy)]
struct CpuidTest {
    leaf: u32,
    subleaf: u32,
    mask: u32,
    register: u8,
    flags: u32,
    bits: u64,
}

const fn test(leaf: u32, subleaf: u32, mask: u32, register: u8, flags: u32, bits: u64) -> CpuidTest {
    CpuidTest { leaf, subleaf, mask, register, flags, bits }
}

/// KiCpuFeatureTable (RVA 0x10540 do ntoskrnl 19041), na ordem do binário.
const CPUID_TESTS: [CpuidTest; 47] = [
    test(1, 0, 0x0000_0001, ECX, 0x0000_000C, 0x0000_0000_0008_0000),
    test(1, 0, 0x0000_0200, ECX, 0x0000_000C, 0x0000_8000_0000_0000),
    test(1, 0, 0x0000_2000, ECX, 0x0000_0001, 0),
    test(1, 0, 0x0002_0000, ECX, 0x0000_000C, 0x0000_0400_0000_0000),
    test(1, 0, 0x0008_0000, ECX, 0x0000_000C, 0x0001_0000_0000_0000),
    test(1, 0, 0x0010_0000, ECX, 0x0000_000C, 0x0002_0000_0000_0000),
    test(1, 0, 0x1000_0000, ECX, 0x0000_000C, 0x0004_0000_0000_0000),
    test(1, 0, 0x4000_0000, ECX, 0x0000_000C, 0x0000_0001_0000_0000),
    test(1, 0, 0x0020_0000, EDX, 0x0000_000C, 0x0000_0000_0000_0200),
    test(6, 0, 0x0000_2000, EAX, 0x0400_000C, 0x0000_0080_0000_0000),
    test(6, 0, 0x0000_0002, ECX, 0x0400_000C, 0x0000_0000_0040_0000),
    test(7, 0, 0x0000_0001, EBX, 0x0600_000C, 0x0000_0000_1000_0000),
    test(7, 0, 0x0000_0020, EBX, 0x0000_000C, 0x0008_0000_0000_0000),
    test(7, 0, 0x0000_0080, EBX, 0x0000_000C, 0x0000_0000_0000_0001),
    test(7, 0, 0x0000_0400, EBX, 0x0000_000C, 0x0000_2000_0000_0000),
    test(7, 0, 0x0001_0000, EBX, 0x0000_000C, 0x0010_0000_0000_0000),
    test(7, 0, 0x0010_0000, EBX, 0x0000_000C, 0x0000_0002_0000_0000),
    test(7, 0, 0x0080_0000, EBX, 0x0400_000C, 0x0000_0008_0000_0000),
    test(7, 0, 0x0100_0000, EBX, 0x0400_000C, 0x0000_0010_0000_0000),
    test(7, 0, 0x0000_0004, ECX, 0x0000_0014, 0x0000_0000_0000_0004),
    test(7, 0, 0x0040_0000, ECX, 0x0000_0014, 0x0000_0000_0000_0002),
    test(7, 0, 0x0000_0400, EDX, 0x0000_0014, 0x0000_0000_0000_0008),
    test(7, 0, 0x0000_8000, EDX, 0x0400_000C, 0x0020_0000_0000_0000),
    test(7, 0, 0x0400_0000, EDX, 0x0C00_0014, 0x0000_0000_0000_0A00),
    test(7, 0, 0x0800_0000, EDX, 0x0C00_0014, 0x0000_0000_0000_0C00),
    test(7, 0, 0x1000_0000, EDX, 0x0000_0014, 0x0000_0000_0000_0001),
    test(7, 0, 0x2000_0000, EDX, 0x0000_0014, 0x0000_0000_0000_0040),
    test(7, 0, 0x8000_0000, EDX, 0x0C00_0014, 0x0000_0000_0000_1000),
    test(7, 2, 0x0000_0010, EDX, 0x0400_0014, 0x0000_0000_0800_0000),
    test(0x8000_0001, 0, 0x0000_0001, ECX, 0x0000_0001, 0),
    test(0x8000_0001, 0, 0x2000_0000, ECX, 0x0200_0014, 0x0000_0000_0000_2000),
    test(0x8000_0001, 0, 0x0000_0800, EDX, 0x0000_0001, 0),
    test(0x8000_0001, 0, 0x0010_0000, EDX, 0x0400_0001, 0),
    test(0x8000_0001, 0, 0x0400_0000, EDX, 0x0000_000C, 0x0000_0020_0000_0000),
    test(0x8000_0001, 0, 0x0800_0000, EDX, 0x0000_000C, 0x0000_0004_0000_0000),
    test(0x8000_0001, 0, 0x8000_0000, EDX, 0x0000_000C, 0x0000_0000_0000_4000),
    test(0x8000_0008, 0, 0x0000_1000, EBX, 0x0200_0014, 0x0000_0000_0000_0800),
    test(0x8000_0008, 0, 0x0000_4000, EBX, 0x0200_0014, 0x0000_0000_0000_0200),
    test(0x8000_0008, 0, 0x0000_8000, EBX, 0x0200_0014, 0x0000_0000_0000_0400),
    test(0x8000_0008, 0, 0x1000_0000, EBX, 0x0200_0014, 0x0000_0000_0002_0000),
    test(0x8000_0008, 0, 0x2000_0000, EBX, 0x0200_0014, 0x0000_0000_0100_0000),
    test(0x8000_0008, 0, 0x4000_0000, EBX, 0x0200_0014, 0x0000_0000_0200_0000),
    test(0x8000_0021, 0, 0x0000_0020, EAX, 0x0200_0014, 0x0000_1000_0000_0000),
    test(0x8000_0021, 0, 0x1000_0000, EAX, 0x0200_0014, 0x0000_0002_0000_0000),
    test(0x8000_0021, 0, 0x2000_0000, EAX, 0x0200_0014, 0x0000_0004_0000_0000),
    test(0x8000_0021, 0, 0x0000_0002, ECX, 0x0200_0014, 0x0000_0400_0000_0000),
    test(0x8000_0021, 0, 0x0000_0004, ECX, 0x0200_0014, 0x0000_0800_0000_0000),
];

/// Um teste de bit de MSR: (máscara, flags, bits).
#[derive(Clone, Copy)]
struct MsrTest {
    mask: u64,
    flags: u32,
    bits: u64,
}

const fn msr_test(mask: u64, bits: u64) -> MsrTest {
    MsrTest { mask, flags: entry::FEATURE_BITS2 | entry::MATCH_BOOT, bits }
}

/// Uma tabela de MSR: lido só quando os bits `required` do conjunto que as
/// flags escolhem já estão ligados.
struct MsrTable {
    msr: u32,
    flags: u32,
    required: u64,
    tests: &'static [MsrTest],
}

/// IA32_ARCH_CAPABILITIES (RVA 0x22030).
const ARCH_CAPABILITIES_TESTS: [MsrTest; 14] = [
    msr_test(0x1, 0x10),
    msr_test(0x2, 0x80),
    msr_test(0x4, 0x100),
    msr_test(0x20, 0x20),
    msr_test(0x80, 0x8000),
    msr_test(0x100, 0x1_0000),
    msr_test(0x2000, 0x8_0000),
    msr_test(0x4000, 0x10_0000),
    msr_test(0x8000, 0x20_0000),
    msr_test(0x2_0000, 0x40_0000),
    msr_test(0x10_0000, 0x400_0000),
    msr_test(0x800_0000, 0x8_0000_0000),
    msr_test(0x1000_0000, 0x10_0000_0000),
    msr_test(0x8000_0000_0000_0000, 0x1000_0000),
];

/// O MSR 0x50000000 (RVA 0x22000), anunciado pelo bit 63 do anterior.
const EXTENDED_CAPABILITIES_TESTS: [MsrTest; 1] = [msr_test(0x1, 0x2000_0000)];

/// As tabelas de MSR (RVA 0x6160), na ordem do binário.
const MSR_TABLES: [MsrTable; 2] = [
    MsrTable { msr: 0x10A, flags: entry::FEATURE_BITS2, required: 0x40, tests: &ARCH_CAPABILITIES_TESTS },
    MsrTable { msr: 0x5000_0000, flags: entry::FEATURE_BITS2, required: 0x1000_0000, tests: &EXTENDED_CAPABILITIES_TESTS },
];

/// A tabela de ProcessorFlags por assinatura (RVA 0x21B60): todas as
/// entradas são da Intel; (assinatura, flags).
const INTEL_PROCESSOR_FLAGS: [(u32, u32); 58] = [
    (0x106A4, 2), (0x106A5, 2), (0x106E4, 2), (0x106E5, 2), (0x20652, 2), (0x20655, 2), (0x206A7, 1), (0x206C2, 2),
    (0x206D6, 1), (0x206D7, 1), (0x206E6, 2), (0x206F2, 2), (0x30673, 2), (0x30678, 2), (0x30679, 2), (0x306A9, 1),
    (0x306C3, 1), (0x306D4, 1), (0x306E4, 1), (0x306E7, 1), (0x306F2, 1), (0x306F4, 1), (0x40651, 1), (0x40661, 1),
    (0x406A8, 2), (0x406A9, 2), (0x406C3, 6), (0x406C4, 6), (0x406D8, 2), (0x406E3, 1), (0x406F1, 1), (0x40751, 1),
    (0x50653, 1), (0x50654, 1), (0x50662, 1), (0x50663, 1), (0x50664, 1), (0x50665, 1), (0x50671, 2), (0x506A0, 2),
    (0x506A1, 2), (0x506C2, 6), (0x506C9, 6), (0x506CA, 6), (0x506D1, 2), (0x506E3, 1), (0x506F1, 6), (0x60663, 1),
    (0x606E1, 6), (0x706A1, 6), (0x80650, 2), (0x806E9, 1), (0x806EA, 1), (0x806EB, 1), (0x906E9, 1), (0x906EA, 1),
    (0x906EB, 1), (0x906EC, 1),
];

// ---- estado global (o do BSP) ------------------------------------------------

/// KeFeatureBits: o FeatureBits do BSP com NX e XSTATE (KiInitializeKernel).
static FEATURE_BITS: AtomicU64 = AtomicU64::new(0);
/// KeFeatureBits2.
static FEATURE_BITS2: AtomicU64 = AtomicU64::new(0);
/// KeProcessorLevel e KeProcessorRevision.
static PROCESSOR_LEVEL: AtomicU16 = AtomicU16::new(0);
static PROCESSOR_REVISION: AtomicU16 = AtomicU16::new(0);
/// KeLargestCacheLine e KiLargestCacheSize (64 e 64 KB no .data).
static LARGEST_CACHE_LINE: AtomicU32 = AtomicU32::new(64);
static LARGEST_CACHE_SIZE: AtomicU32 = AtomicU32::new(0x1_0000);
/// KiVirtFlags (VirtualizationFlags da KUSER_SHARED_DATA).
static VIRT_FLAGS: AtomicU8 = AtomicU8::new(0);
/// O BSP já montou a identidade.
static BOOT_READY: AtomicU8 = AtomicU8::new(0);

/// Os caches de cada processador com o compartilhamento (de onde saem os
/// CacheProcessorMask), pelo número do processador.
static CACHES: SpinLock<Vec<(u32, Vec<Cache>)>> = SpinLock::new(Vec::new());

/// KeFeatureBits.
pub fn feature_bits() -> u64 {
    FEATURE_BITS.load(Ordering::Acquire)
}

/// KeFeatureBits2.
pub fn feature_bits2() -> u64 {
    FEATURE_BITS2.load(Ordering::Acquire)
}

/// KeProcessorLevel.
pub fn processor_level() -> u16 {
    PROCESSOR_LEVEL.load(Ordering::Acquire)
}

/// KeProcessorRevision.
pub fn processor_revision() -> u16 {
    PROCESSOR_REVISION.load(Ordering::Acquire)
}

/// KeLargestCacheLine.
pub fn largest_cache_line() -> u32 {
    LARGEST_CACHE_LINE.load(Ordering::Acquire)
}

/// KiLargestCacheSize.
pub fn largest_cache_size() -> u32 {
    LARGEST_CACHE_SIZE.load(Ordering::Acquire)
}

/// A identidade do BSP está montada.
pub fn ready() -> bool {
    BOOT_READY.load(Ordering::Acquire) != 0
}

// ---- KiGetCpuVendor / KiGetProcessorSignature --------------------------------

/// KiGetCpuVendor: grava VendorString (12 bytes e o NUL) e devolve o
/// CPU_VENDORS.
fn get_cpu_vendor(prcb: &Kprcb) -> u8 {
    let [_, ebx, ecx, edx] = cpu::cpuid(0);
    let mut text = [0u8; 12];
    for (chunk, register) in text.chunks_exact_mut(4).zip([ebx, edx, ecx]) {
        chunk.copy_from_slice(&register.to_le_bytes());
    }
    for (cell, &byte) in prcb.vendor_string.iter().zip(text.iter()) {
        cell.set(byte);
    }
    prcb.vendor_string[12].set(0);
    match &text {
        b"AuthenticAMD" | b"HygonGenuine" => vendor::AMD,
        b"GenuineIntel" => vendor::INTEL,
        b"CentaurHauls" => vendor::CENTAUR,
        _ => vendor::UNKNOWN,
    }
}

/// O que o KiGetProcessorSignature devolve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub vendor: u8,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    /// CPUID 1 EAX.
    pub value: u32,
}

/// KiGetProcessorSignature: família e modelo estendidos como o binário os
/// combina (o modelo estendido na família 0xF de qualquer fabricante e na 6
/// da Intel/Centaur).
pub fn decode_signature(vendor: u8, value: u32) -> Signature {
    let base_family = (value >> 8) & 0xF;
    let (family, mut model) = if base_family == 0xF { (((value >> 20) & 0xFF) + 0xF, (((value >> 8) & 0xF00) | (value & 0xF0)) >> 4) } else { (base_family, (value >> 4) & 0xF) };
    if (vendor == vendor::INTEL || vendor == vendor::CENTAUR) && family == 6 {
        model |= (value >> 12) & 0xF0;
    }
    Signature { vendor, family, model, stepping: value & 0xF, value }
}

// ---- KiSetProcessorSignature ---------------------------------------------------

/// A entrada vale para o fabricante (bits 24..31 das flags; 0 = todos).
fn applies(flags: u32, cpu_vendor: u8) -> bool {
    if flags & entry::DISABLED != 0 {
        return false;
    }
    let vendors = flags >> 24;
    vendors == 0 || vendors & (1 << (cpu_vendor & 31)) != 0
}

/// Os dois conjuntos acumulados por uma passagem.
#[derive(Default)]
struct Accumulated {
    bits: u64,
    bits2: u64,
    /// Um recurso exigido faltou.
    missing: bool,
}

impl Accumulated {
    /// Uma entrada presente (ou ausente com os bits dela já ligados) soma os
    /// bits no conjunto que as flags escolhem.
    fn record(&mut self, flags: u32, bits: u64, present: bool) {
        let covered = (flags & entry::FEATURE_BITS != 0 && bits & self.bits == bits) || (flags & entry::FEATURE_BITS2 != 0 && bits & self.bits2 == bits);
        if present || covered {
            if flags & entry::FEATURE_BITS != 0 {
                self.bits |= bits;
            } else if flags & entry::FEATURE_BITS2 != 0 {
                self.bits2 |= bits;
            }
        } else if flags & entry::REQUIRED != 0 {
            self.missing = true;
        }
    }
}

/// Os testes da KiCpuFeatureTable e das tabelas de MSR. O CPUID de uma folha
/// fora das máximas (básica e estendida) vale zero, e a mesma folha seguida
/// não repete a instrução.
fn feature_tests(cpu_vendor: u8) -> Accumulated {
    let maximum_basic = cpu::cpuid(0)[0];
    let maximum_extended = cpu::cpuid(0x8000_0000)[0];
    let mut accumulated = Accumulated::default();
    let mut cached: Option<(u32, u32, [u32; 4])> = None;
    for test in &CPUID_TESTS {
        if !applies(test.flags, cpu_vendor) {
            continue;
        }
        let registers = match cached {
            Some((leaf, subleaf, registers)) if leaf == test.leaf && subleaf == test.subleaf => registers,
            _ => {
                let valid = (test.leaf >= 0x8000_0000 && test.leaf <= maximum_extended) || test.leaf <= maximum_basic;
                let registers = if valid { cpu::cpuid_subleaf(test.leaf, test.subleaf) } else { [0; 4] };
                cached = Some((test.leaf, test.subleaf, registers));
                registers
            }
        };
        accumulated.record(test.flags, test.bits, registers[test.register as usize] & test.mask != 0);
    }
    for table in &MSR_TABLES {
        if !applies(table.flags, cpu_vendor) {
            continue;
        }
        let available = if table.flags & entry::FEATURE_BITS != 0 {
            accumulated.bits
        } else if table.flags & entry::FEATURE_BITS2 != 0 {
            accumulated.bits2
        } else {
            continue;
        };
        if table.required & available != table.required {
            continue;
        }
        let value = cpu::read_msr(table.msr);
        for test in table.tests {
            if applies(test.flags, cpu_vendor) {
                accumulated.record(test.flags, test.bits, value & test.mask != 0);
            }
        }
    }
    accumulated
}

/// KiSetProcessorSignature: FeatureBits |= os testes, ProcessorFlags,
/// ProcessorSignature; no BSP soma KeFeatureBits2, nos APs confere com ele.
fn set_processor_signature(prcb: &Kprcb, signature: u32, boot: bool) {
    let cpu_vendor = prcb.cpu_vendor.get();
    let accumulated = feature_tests(cpu_vendor);
    if accumulated.missing {
        debug_print!("[ke] processador {}: falta um recurso exigido pelo ntoskrnl (UNSUPPORTED_PROCESSOR no NT)", prcb.number.get());
    }
    if let Some(&(_, flags)) = INTEL_PROCESSOR_FLAGS.iter().find(|&&(entry, _)| cpu_vendor == vendor::INTEL && entry == signature) {
        prcb.processor_flags.set(flags);
    }
    // A família 0x10 e a 0x12 da AMD perdem o SSSE3.
    let family = prcb.cpu_type.get() as u8;
    let removed = if cpu_vendor == vendor::AMD && (family == 0x10 || family == 0x12) { kf::SSSE3 } else { 0 };
    prcb.processor_signature.set(signature);
    prcb.feature_bits.set(prcb.feature_bits.get() | (accumulated.bits & !removed));
    if boot {
        FEATURE_BITS2.fetch_or(accumulated.bits2, Ordering::AcqRel);
    } else if accumulated.bits2 != feature_bits2() {
        debug_print!("[ke] processador {}: KeFeatureBits2 {:#x} difere do BSP {:#x}", prcb.number.get(), accumulated.bits2, feature_bits2());
    }
}

// ---- KiSetFeatureBits -----------------------------------------------------------

/// bsr(value), value != 0.
fn highest_bit(value: u32) -> u32 {
    31 - value.leading_zeros()
}

/// LogicalProcessorsPerCore, CoresPerPhysicalProcessor e o InitialApicId
/// que a contagem traz (o x2APIC id da folha 0x1F/0xB, o estendido da
/// 0x8000001E na AMD), como o KiSetFeatureBits.
fn topology_counts(cpu_vendor: u8, initial_apic_id: u32, basic_edx: u32, basic_ebx: u32) -> (u32, u32, u32) {
    let (mut per_core, mut cores, mut apic) = (1u32, 1u32, initial_apic_id);
    if cpu_vendor == vendor::INTEL || cpu_vendor == vendor::CENTAUR {
        let maximum = cpu::cpuid(0)[0];
        let leaf = if maximum >= 0x1F && cpu::cpuid_subleaf(0x1F, 0)[1] != 0 {
            0x1F
        } else if maximum >= 0xB && cpu::cpuid_subleaf(0xB, 0)[1] != 0 {
            0xB
        } else {
            0
        };
        if leaf != 0 {
            apic = cpu::cpuid_subleaf(leaf, 0)[3];
            let mut package = 1u32;
            for subleaf in 0..256 {
                let [eax, ebx, ecx, _] = cpu::cpuid_subleaf(leaf, subleaf);
                let level_type = ecx >> 8;
                if level_type != 0 {
                    let shift = eax & 0x1F;
                    if level_type == 1 {
                        per_core = 1 << shift;
                    } else {
                        package = 1 << shift;
                    }
                }
                if ebx & 0xFFFF == 0 {
                    break;
                }
            }
            cores = package / per_core;
        } else {
            if maximum >= 4 {
                cores = 1 << highest_bit((cpu::cpuid_subleaf(4, 0)[0] >> 26) * 2 + 1);
            }
            if basic_edx & (1 << 28) != 0 {
                let logical = (basic_ebx >> 16) & 0xFF;
                per_core = (1u32 << highest_bit((logical * 2).wrapping_sub(1))) / cores;
            }
        }
    } else if cpu_vendor == vendor::AMD {
        let maximum_extended = cpu::cpuid(0x8000_0000)[0];
        if maximum_extended >= 0x8000_0008 {
            let ecx = cpu::cpuid_subleaf(0x8000_0008, 0)[2];
            let mut shift = (ecx >> 12) & 0xF;
            if shift == 0 {
                shift = highest_bit((ecx & 0xFF) * 2 + 1);
            }
            cores = 1 << shift;
            if maximum_extended >= 0x8000_001E && cpu::cpuid(0x8000_0001)[2] & (1 << 22) != 0 {
                let [eax, ebx, _, _] = cpu::cpuid_subleaf(0x8000_001E, 0);
                per_core = ((ebx >> 8) & 0xFF) + 1;
                cores /= per_core;
                apic = eax;
            }
        }
    }
    (per_core, cores, apic)
}

/// SLAT e firmware de virtualização: VMX com EPT e o FEATURE_CONTROL travado
/// com VMX ligado na Intel; NPT e o VM_CR sem SVMDIS na AMD.
fn virtualization_bits(cpu_vendor: u8, mut bits: u64) -> u64 {
    if cpu_vendor == vendor::INTEL {
        if cpu::cpuid(1)[2] & (1 << 5) != 0 {
            if cpu::read_msr(0x482) & (1 << 63) != 0 && cpu::read_msr(0x48B) & (1 << 33) != 0 {
                bits |= kf::SLAT;
            }
            let control = cpu::read_msr(0x3A);
            if control & 5 == 5 {
                bits |= kf::VIRT_FIRMWARE_ENABLED;
            }
            VIRT_FLAGS.fetch_or(((control & 4 != 0) as u8) | ((control & 1 != 0) as u8) << 1, Ordering::AcqRel);
        }
    } else if cpu_vendor == vendor::AMD {
        if cpu::cpuid(0x8000_0000)[0] >= 0x8000_000A && cpu::cpuid_subleaf(0x8000_000A, 0)[3] & 1 != 0 {
            bits |= kf::SLAT;
        }
        if cpu::cpuid(0x8000_0001)[2] & (1 << 2) != 0 && cpu::read_msr(0xC001_0114) & 0x10 == 0 {
            bits |= kf::VIRT_FIRMWARE_ENABLED;
            VIRT_FLAGS.fetch_or(1, Ordering::AcqRel);
        }
    }
    bits
}

/// KiSetFeatureBits sobre a KPRCB do processador corrente (o CpuVendor já
/// gravado pelo KiInitializeBootStructures); nos APs o KiSetProcessorSignature
/// roda aqui.
fn set_feature_bits(prcb: &Kprcb, boot: bool, signature: u32) {
    if !boot {
        set_processor_signature(prcb, signature, false);
    }
    let cpu_vendor = prcb.cpu_vendor.get();
    let maximum_basic = cpu::cpuid(0)[0];
    // MSR 0x8B: a revisão do microcódigo (zerada antes do CPUID 1 na Intel).
    if cpu_vendor == vendor::INTEL {
        cpu::write_msr(0x8B, 0);
        cpu::cpuid(1);
    }
    if cpu_vendor == vendor::INTEL || cpu_vendor == vendor::AMD {
        prcb.update_signature.quad_part.set(cpu::read_msr(0x8B) as i64);
    }
    let [_, basic_ebx, basic_ecx, basic_edx] = cpu::cpuid(1);
    let [_, _, extended_ecx, mut extended_edx] = cpu::cpuid(0x8000_0001);
    if cpu_vendor == vendor::AMD {
        extended_edx |= 1 << 20;
    }
    let initial_apic_id = basic_ebx >> 24;
    prcb.initial_apic_id.set(initial_apic_id);
    prcb.c_flush_size.set((basic_ebx >> 5) & 0x7F8);
    let supported = basic_edx & 0x0789_F3FD == 0x0789_F3FD && extended_edx & (1 << 11) != 0 && extended_edx & (1 << 20) != 0 && basic_ecx & (1 << 13) != 0 && extended_ecx & 1 != 0;
    if !supported {
        debug_print!("[ke] processador {}: CPUID sem os recursos exigidos (UNSUPPORTED_PROCESSOR no NT)", prcb.number.get());
    }
    let mut bits = prcb.feature_bits.get() | kf::REQUIRED;
    if bits & kf::RDTSCP != 0 {
        cpu::write_msr(0xC000_0103, (prcb.group.get() as u64) << 8 | prcb.group_index.get() as u64);
    }
    let (per_core, cores, apic) = topology_counts(cpu_vendor, initial_apic_id, basic_edx, basic_ebx);
    prcb.logical_processors_per_core.set(per_core);
    prcb.cores_per_physical_processor.set(cores);
    prcb.initial_apic_id.set(apic);
    match cpu_vendor {
        vendor::AMD => bits |= kf::AUTHENTIC_AMD,
        vendor::INTEL => bits |= kf::GENUINE_INTEL,
        _ => {}
    }
    prcb.legacy_cores_per_physical_processor.set(cores as u8);
    prcb.legacy_logical_processors_per_core.set(per_core as u8);
    // Sem hyperthreading habilitado na HAL um AP mascara o pacote inteiro;
    // a HAL do OpenNT não desliga o SMT.
    prcb.apic_mask.set(per_core.wrapping_neg());
    // O CR4 do OpenNT decide SMEP e FSGSBASE (veja o começo do arquivo).
    let control_register4 = cpu::read_cr4();
    if control_register4 & (1 << 20) == 0 {
        bits &= !kf::SMEP;
    }
    if control_register4 & (1 << 16) == 0 {
        bits &= !kf::RDWRFSGSBASE;
    }
    if cpu_vendor == vendor::INTEL && maximum_basic >= 7 && cpu::cpuid_subleaf(7, 0)[1] & (1 << 15) != 0 && cpu::cpuid_subleaf(0x10, 0)[1] & 2 != 0 {
        bits |= kf::RDT_ALLOCATION;
    }
    if cpu_vendor == vendor::AMD || cpu_vendor == vendor::INTEL {
        bits |= kf::BRANCH;
    }
    bits = virtualization_bits(cpu_vendor, bits);
    // SGX com o FEATURE_CONTROL travado e o SGX ligado.
    if cpu_vendor == vendor::INTEL && maximum_basic >= 7 && cpu::cpuid_subleaf(7, 0)[1] & 4 != 0 && cpu::read_msr(0x3A) & 0x4_0001 == 0x4_0001 {
        let capabilities = cpu::cpuid_subleaf(0x12, 0)[0];
        if capabilities & 1 != 0 {
            bits |= kf::SGX;
            if capabilities & 2 != 0 {
                bits |= kf::SGX_LAUNCH_CONTROL;
            }
        }
    }
    prcb.feature_bits.set(bits);
}

/// KiGetProcessorSignature + o que o KiInitializeBootStructures grava:
/// CpuVendor, CpuID, CpuType e CpuStep.
fn get_processor_signature(prcb: &Kprcb) -> Signature {
    let cpu_vendor = get_cpu_vendor(prcb);
    let signature = decode_signature(cpu_vendor, cpu::cpuid(1)[0]);
    prcb.cpu_vendor.set(cpu_vendor);
    prcb.cpu_id.set(1);
    prcb.cpu_type.set(signature.family as u8 as i8);
    prcb.cpu_step.set(((signature.model as u16) << 8) | signature.stepping as u16);
    signature
}

// ---- KiSetCacheInformation -------------------------------------------------------

/// Os descritores na KPRCB, o L2 da KPCR e os maiores line size e tamanho.
fn set_cache_information(kpcr: &Kpcr) {
    let prcb = &kpcr.prcb;
    let caches = processor_topology::cache_descriptors(prcb.cpu_vendor.get(), prcb.cpu_type.get() as u8 as u16);
    let count = caches.len().min(prcb.cache.len());
    for (descriptor, cache) in prcb.cache.iter().zip(&caches) {
        descriptor.level.set(cache.level);
        descriptor.associativity.set(cache.associativity);
        descriptor.line_size.set(cache.line_size);
        descriptor.size.set(cache.size);
        descriptor.type_.set(ProcessorCacheType(cache.kind as i32));
    }
    prcb.cache_count.set(count as u32);
    kpcr.second_level_cache_size.set(0);
    let mut best = 0u32;
    for cache in caches.iter().take(count) {
        if cache.level < 2 || cache.kind & !2 != 0 {
            continue;
        }
        let ways = if cache.associativity == 0xFF { 16 } else { cache.associativity };
        if ways != 0 && cache.size / ways as u32 > best {
            best = cache.size / ways as u32;
            kpcr.second_level_cache_size.set(cache.size);
            kpcr.second_level_cache_associativity.set(ways);
        }
        LARGEST_CACHE_LINE.fetch_max(cache.line_size as u32, Ordering::AcqRel);
        LARGEST_CACHE_SIZE.fetch_max(cache.size, Ordering::AcqRel);
    }
    let number = prcb.number.get();
    let mut table = CACHES.lock();
    table.retain(|(owner, _)| *owner != number);
    table.push((number, caches.into_iter().take(count).collect()));
}

// ---- a passagem de cada processador --------------------------------------------

/// A identidade do processador corrente na KPRCB dele: o KiConfigureProcessorBlock
/// (Group, GroupIndex, GroupSetMember), o KiInitializeBootStructures, o
/// KiSetFeatureBits, o KiSetCacheInformation e a frequência.
fn initialize_current(boot: bool) {
    let kpcr = pcr::current();
    let prcb = &kpcr.prcb;
    let number = prcb.number.get();
    prcb.group.set(0);
    prcb.group_index.set(number as u8);
    prcb.group_set_member.set(1u64 << (number & 63));
    // O KiInitializeBootStructures de todo processador: vendor e assinatura;
    // o do BSP já chama o KiSetProcessorSignature.
    let signature = get_processor_signature(prcb);
    if boot {
        set_processor_signature(prcb, signature.value, true);
    }
    set_feature_bits(prcb, boot, signature.value);
    set_cache_information(kpcr);
    // HalpTimerSaveProcessorFrequency: o TSC arredondado a MHz.
    let megahertz = ((clock::tsc_frequency_hz() + 500_000) / 1_000_000) as u32;
    prcb.m_hz.set(megahertz);
    kpcr.stall_scale_factor.set(megahertz);
}

/// O KiInitializeKernel do BSP: KeProcessorLevel/Revision e KeFeatureBits
/// (o FeatureBits com o NX — ligado pelo EFER.NXE com o recurso presente — e
/// o XSTATE, que o OpenNT não habilita: só FXSAVE).
pub fn initialize_boot_processor() -> Result<(), KernelError> {
    if pcr::get_pcr_address() == 0 {
        return Err(KernelError::new("identidade do processador antes da KPCR"));
    }
    initialize_current(true);
    let prcb = &pcr::current().prcb;
    let mut bits = prcb.feature_bits.get();
    if nx_enabled() {
        bits |= kf::NX_ENABLED;
    } else {
        bits = (bits & !kf::NX_ENABLED) | kf::NX_DISABLED;
    }
    PROCESSOR_LEVEL.store(prcb.cpu_type.get() as i16 as u16, Ordering::Release);
    PROCESSOR_REVISION.store(prcb.cpu_step.get(), Ordering::Release);
    FEATURE_BITS.store(bits, Ordering::Release);
    BOOT_READY.store(1, Ordering::Release);
    debug_print!(
        "[ke] CPU 0: {} familia {:#x} modelo {:#x} stepping {} ({} MHz), FeatureBits {:#x}",
        vendor_text(prcb),
        prcb.cpu_type.get() as u8,
        prcb.cpu_step.get() >> 8,
        prcb.cpu_step.get() & 0xFF,
        prcb.m_hz.get(),
        bits
    );
    Ok(())
}

/// O NX do KiInitializeNxSupportDiscard: anunciado (ou da AMD) e ligado no
/// EFER.
fn nx_enabled() -> bool {
    let announced = cpu::cpuid(0x8000_0000)[0] >= 0x8000_0001 && cpu::cpuid(0x8000_0001)[3] & (1 << 20) != 0;
    announced && cpu::read_msr(0xC000_0080) & 0x800 != 0
}

/// O VendorString de uma KPRCB.
pub fn vendor_text(prcb: &Kprcb) -> alloc::string::String {
    prcb.vendor_string.iter().map(|cell| cell.get()).take_while(|&byte| byte != 0).map(char::from).collect()
}

/// A passagem de um AP, como job no próprio AP.
extern "win64" fn initialize_on_application_processor(_: u64, _: u64, _: u64, _: u64) -> u64 {
    initialize_current(false);
    0
}

/// Os APs online montam a própria identidade (cada um no seu CPUID), e
/// então as máscaras entre processadores: pacote, núcleo e caches.
pub fn initialize_application_processors() -> Result<(), KernelError> {
    for index in 0..smp::ap_slot_count() {
        let Some(slot) = smp::ap_slot(index) else { continue };
        smp::run_on_ap(slot, initialize_on_application_processor as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, [0; 4])?;
        if let Some(prcb) = pcr::processor_block(index as u32 + 1) {
            let boot = pcr::processor_block(0).map_or(0, |boot| boot.feature_bits.get());
            if prcb.feature_bits.get() != boot {
                debug_print!("[ke] processador {}: FeatureBits {:#x} difere do BSP {:#x}", index + 1, prcb.feature_bits.get(), boot);
            }
        }
    }
    configure_processor_sets();
    crate::ntos::mm::shared_user_data::update_active_processor_count();
    Ok(())
}

/// PackageProcessorSet, PackageId e CoreProcessorSet do KiInitializeKernel
/// e o CacheProcessorMask do KiSetStandardizedCacheInformation, com todos os
/// processadores online: os que têm o mesmo InitialApicId sob
/// -(Lógicos por núcleo), sob -(Núcleos * Lógicos) e sob a máscara de cada
/// cache.
pub fn configure_processor_sets() {
    let blocks: Vec<&'static Kprcb> = (0..smp::online_cpu_count() as u32).filter_map(pcr::processor_block).collect();
    let caches = CACHES.lock().clone();
    for prcb in &blocks {
        let apic = prcb.initial_apic_id.get();
        let per_core = prcb.logical_processors_per_core.get().max(1);
        let package_width = per_core.wrapping_mul(prcb.cores_per_physical_processor.get().max(1));
        let core_mask = !(per_core - 1);
        let package_mask = !package_width.wrapping_sub(1);
        let members = |mask: u32| blocks.iter().filter(|other| other.initial_apic_id.get() & mask == apic & mask).fold(0u64, |set, other| set | other.group_set_member.get());
        let package = &prcb.package_processor_set;
        package.count.set(1);
        package.size.set(package.bitmap.len() as u16);
        package.reserved.set(0);
        for (group, cell) in package.bitmap.iter().enumerate() {
            cell.set(if group == 0 { members(package_mask) } else { 0 });
        }
        prcb.package_id.set(apic & package_mask);
        prcb.core_processor_set.set(members(core_mask));
        let mine = caches.iter().find(|(owner, _)| *owner == prcb.number.get()).map(|(_, caches)| caches.as_slice()).unwrap_or(&[]);
        for (index, cell) in prcb.cache_processor_mask.iter().enumerate() {
            let set = match mine.get(index).map(|cache| cache.sharing) {
                Some(Sharing::ApicMask(mask)) => members(mask),
                Some(Sharing::Package) => members(package_mask),
                Some(Sharing::Own) | None => 0,
            };
            cell.set(set);
        }
    }
}

// ---- os ProcessorFeatures da KUSER_SHARED_DATA ------------------------------------

/// O que o KiInitializeKernel, o KiInitializeNxSupportDiscard, o
/// InitBootProcessor e o KiPublishProcessorFeatures gravam na página: os
/// PF_* de KeFeatureBits/KeFeatureBits2, o VirtualizationFlags e o
/// TestRetInstruction.
pub fn publish_processor_features(data: &KuserSharedData) {
    let bits = feature_bits();
    let bits2 = feature_bits2();
    let set = |index: usize, value: bool| {
        if value {
            data.processor_features[index].set(1);
        }
    };
    data.test_ret_instruction.set(0xC3);
    for index in [pf::COMPARE_EXCHANGE_DOUBLE, pf::MMX_INSTRUCTIONS_AVAILABLE, pf::XMMI_INSTRUCTIONS_AVAILABLE, pf::RDTSC_INSTRUCTION_AVAILABLE, pf::PAE_ENABLED, pf::XMMI64_INSTRUCTIONS_AVAILABLE, pf::COMPARE_EXCHANGE128] {
        set(index, true);
    }
    set(pf::SSE3_INSTRUCTIONS_AVAILABLE, bits & kf::SSE3 != 0);
    set(pf::THREE_D_NOW_INSTRUCTIONS_AVAILABLE, bits & kf::THREE_D_NOW != 0);
    set(pf::XSAVE_ENABLED, bits & kf::XSTATE != 0);
    set(pf::RDWRFSGSBASE_AVAILABLE, bits & kf::RDWRFSGSBASE != 0);
    set(pf::SECOND_LEVEL_ADDRESS_TRANSLATION, bits & kf::SLAT != 0);
    set(pf::VIRT_FIRMWARE_ENABLED, bits & kf::VIRT_FIRMWARE_ENABLED != 0);
    set(pf::RDRAND_INSTRUCTION_AVAILABLE, bits & kf::RDRAND != 0);
    set(pf::RDTSCP_INSTRUCTION_AVAILABLE, bits & kf::RDTSCP != 0);
    set(pf::SSSE3_INSTRUCTIONS_AVAILABLE, bits & kf::SSSE3 != 0);
    set(pf::SSE4_1_INSTRUCTIONS_AVAILABLE, bits & kf::SSE4_1 != 0);
    set(pf::SSE4_2_INSTRUCTIONS_AVAILABLE, bits & kf::SSE4_2 != 0);
    let enabled = data.x_state.enabled_features.get();
    set(pf::AVX_INSTRUCTIONS_AVAILABLE, enabled & 4 != 0 && bits & kf::AVX != 0);
    set(pf::AVX2_INSTRUCTIONS_AVAILABLE, enabled & 4 != 0 && bits & kf::AVX2 != 0);
    set(pf::AVX512F_INSTRUCTIONS_AVAILABLE, enabled & 0xE0 != 0 && bits & kf::AVX512 != 0);
    data.virtualization_flags.set(VIRT_FLAGS.load(Ordering::Acquire));
    set(pf::NX_ENABLED, bits & kf::NX_ENABLED != 0);
    set(pf::FASTFAIL_AVAILABLE, true);
    set(pf::RDPID_INSTRUCTION_AVAILABLE, bits2 & kf2::RDPID != 0);
    set(pf::MONITORX_INSTRUCTION_AVAILABLE, bits2 & kf2::MONITORX != 0);
}
