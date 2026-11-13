//! Informações da CPU convidada — `system32/ntos/ke/processor-information.js`.
//!
//! Combina CPUID, CR4, EFER e o estado de salvamento de contexto. A máscara
//! KF_* do kernel é distinta dos bits brutos de CPUID; os índices PF_*
//! seguem a ABI publicada em KUSER_SHARED_DATA.

use alloc::string::String;

use super::smp;
use crate::hal::cpu;
use crate::ntos::ps::user_probe;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

#[derive(Clone, Debug)]
pub struct ProcessorSnapshot {
    pub architecture: u16,
    pub level: u16,
    pub revision: u16,
    pub vendor: String,
    pub feature_bits: u32,
    pub features: [u8; 64],
}

/// Decodifica fabricante, família e revisão e mapeia capacidades para KF/PF,
/// marcando recursos dependentes de estado só quando os controles os habilitam.
pub fn detect(
    query: impl Fn(u32, u32) -> [u32; 4],
    control_register4: u64,
    efer: u64,
    vector_control_mask: u32,
) -> ProcessorSnapshot {
    let basic_root = query(0, 0);
    let basic = if basic_root[0] >= 1 { query(1, 0) } else { [0; 4] };
    let extended_root = query(0x8000_0000, 0);
    let extended = if extended_root[0] >= 0x8000_0001 { query(0x8000_0001, 0) } else { [0; 4] };
    let structured = if basic_root[0] >= 7 { query(7, 0) } else { [0; 4] };

    let mut vendor = String::new();
    for value in [basic_root[1], basic_root[3], basic_root[2]] {
        for index in 0..4 {
            vendor.push(((value >> (index * 8)) & 255) as u8 as char);
        }
    }
    let signature = basic[0];
    let base_family = (signature >> 8) & 15;
    let family = if base_family == 15 { base_family + ((signature >> 20) & 255) } else { base_family };
    let mut model = (signature >> 4) & 15;
    if base_family == 6 || base_family == 15 {
        model |= (signature >> 12) & 240;
    }
    let revision = (model << 8) | (signature & 15);

    let (basic_edx, basic_ecx, extended_edx) = (basic[3], basic[2], extended[3]);
    // FXSAVE depende de CPUID e CR4.OSFXSR; SSE/SSE2 dependem dele. NX exige EFER.NXE.
    let fxsave_enabled = basic_edx & (1 << 24) != 0 && control_register4 & 0x200 != 0;
    let sse = fxsave_enabled && basic_edx & (1 << 25) != 0;
    let sse2 = sse && basic_edx & (1 << 26) != 0;
    let nx_enabled = extended_edx & (1 << 20) != 0 && efer & 0x800 != 0;

    let mut feature_bits: u32 = 4;
    for (bit, flag) in [(4, 2), (15, 8), (13, 16), (3, 32), (12, 64), (8, 128), (23, 256), (16, 1024)] {
        if basic_edx & (1 << bit) != 0 {
            feature_bits |= flag;
        }
    }
    if fxsave_enabled {
        feature_bits |= 0x800;
    }
    if extended_edx & (1 << 11) != 0 && efer & 1 != 0 {
        feature_bits |= 0x1000;
    }
    if sse {
        feature_bits |= 0x2000;
    }
    if extended_edx & (1 << 31) != 0 {
        feature_bits |= 0x4000;
    }
    if sse2 {
        feature_bits |= 0x10000;
    }
    if sse && basic_ecx & 1 != 0 {
        feature_bits |= 0x80000;
    }
    if basic_ecx & (1 << 13) != 0 {
        feature_bits |= 0x10_0000;
    }
    if vendor == "AuthenticAMD" {
        feature_bits |= 0x20_0000;
    }
    if vendor == "GenuineIntel" {
        feature_bits |= 0x100_0000;
    }
    if structured[1] & 128 != 0 && control_register4 & 0x10_0000 != 0 {
        feature_bits |= 1;
    }
    if structured[1] & 1 != 0 && control_register4 & 0x1_0000 != 0 {
        feature_bits |= 0x1000_0000;
    }
    if extended_edx & (1 << 20) != 0 {
        feature_bits |= 0x2000_0000;
    }
    feature_bits |= if nx_enabled { 0x8000_0000 } else { 0x4000_0000 };

    let mut features = [0u8; 64];
    let mut set = |index: usize, value: bool| features[index] = value as u8;
    set(2, basic_edx & (1 << 8) != 0);
    set(3, basic_edx & (1 << 23) != 0);
    set(6, sse);
    set(7, extended_edx & (1 << 31) != 0);
    set(8, basic_edx & (1 << 4) != 0);
    set(9, control_register4 & 0x20 != 0);
    set(10, sse2);
    set(11, sse && vector_control_mask & 0x40 != 0);
    set(12, nx_enabled);
    set(13, sse && basic_ecx & 1 != 0);
    set(14, basic_ecx & (1 << 13) != 0);
    set(15, basic_ecx & (1 << 13) != 0);
    set(22, feature_bits & 0x1000_0000 != 0);
    set(23, true); // int 0x29 (fast fail) implementado pelo runtime
    set(28, basic_ecx & (1 << 30) != 0);
    set(32, extended_edx & (1 << 27) != 0);
    set(33, structured[2] & (1 << 22) != 0);
    set(36, sse && basic_ecx & (1 << 9) != 0);
    set(37, sse && basic_ecx & (1 << 19) != 0);
    set(38, sse && basic_ecx & (1 << 20) != 0);
    set(42, structured[1] & (1 << 9) != 0);

    // FXSAVE/FXRSTOR preservam x87, MMX e SSE; XSAVE/AVX não são habilitados
    // só porque CPUID os anuncia.
    ProcessorSnapshot { architecture: 9, level: family as u16, revision: revision as u16, vendor, feature_bits, features }
}

struct Cache {
    snapshot: Option<ProcessorSnapshot>,
    control_register4: u64,
    efer: u64,
    vector_control_mask: Option<u32>,
}

static CACHE: SpinLock<Cache> = SpinLock::new(Cache { snapshot: None, control_register4: 0, efer: 0, vector_control_mask: None });

/// Captura a máscara MXCSR por FXSAVE uma vez e recalcula quando CR4 ou EFER
/// mudam durante o boot (a inicialização de usuário liga EFER.SCE).
pub fn snapshot() -> Result<ProcessorSnapshot, KernelError> {
    let mut cache = CACHE.lock();
    if cache.vector_control_mask.is_none() {
        let allocation = guest::alloc_bytes(528);
        if allocation == 0 {
            return Err(KernelError::new("CPU: cannot capture MXCSR mask"));
        }
        let aligned = allocation.div_ceil(16) * 16;
        cpu::fxsave(aligned);
        cache.vector_control_mask = Some(guest::read32(aligned + 28));
        guest::free_bytes(allocation);
    }
    let control_register4 = cpu::read_cr4();
    let efer = cpu::read_msr(0xC000_0080);
    if cache.snapshot.is_none() || cache.control_register4 != control_register4 || cache.efer != efer {
        let mask = cache.vector_control_mask.unwrap_or(0);
        cache.snapshot = Some(detect(cpu::cpuid_subleaf, control_register4, efer, mask));
        cache.control_register4 = control_register4;
        cache.efer = efer;
    }
    Ok(cache.snapshot.clone().unwrap())
}

/// SYSTEM_PROCESSOR_INFORMATION (12 bytes). A arquitetura emulada altera só
/// o identificador de arquitetura.
pub fn query(
    output: u64,
    buffer_length: u32,
    output_length_pointer: u64,
    from_user_mode: bool,
    report_emulated_architecture: bool,
) -> u32 {
    if from_user_mode {
        if buffer_length != 0 && output % 4 != 0 {
            return 0x8000_0002;
        }
        if !user_probe::probe_user_write(output, buffer_length as u64)
            || (output_length_pointer != 0 && !user_probe::probe_user_write(output_length_pointer, 4))
        {
            return 0xC000_0005;
        }
    }
    if buffer_length < 12 {
        if output_length_pointer != 0 {
            guest::write32(output_length_pointer, 12);
        }
        return 0xC000_0004;
    }
    if output == 0 {
        return 0xC000_0005;
    }
    let Ok(snapshot) = snapshot() else { return 0xC000_009A };
    guest::write16(output, if report_emulated_architecture { 0 } else { snapshot.architecture });
    guest::write16(output + 2, snapshot.level);
    guest::write16(output + 4, snapshot.revision);
    // Sem hot-add: a contagem vem dos processadores confirmados online.
    guest::write16(output + 6, smp::online_cpu_count() as u16);
    guest::write32(output + 8, snapshot.feature_bits);
    if output_length_pointer != 0 {
        guest::write32(output_length_pointer, 12);
    }
    0
}
