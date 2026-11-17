//! A configuração do estado estendido do processador (XSAVE) no boot de cada
//! CPU, como o ntoskrnl 19041 a monta:
//!
//! - KiInitializeXSave (no KiSystemStartup, antes do KiInitializeKernel). No
//!   BSP: o XSTATE_CONFIGURATION zerado, os recursos que o CPUID anuncia
//!   (KiGetXSaveSupportedFeatures), a máscara e os flags do carregador, a
//!   política do hwpolicy.sys (KiIntersectFeaturesWithPolicy), os tamanhos e
//!   os recursos voláteis (KiUpdateXSaveSizeAndVolatileFeatures) e
//!   KeXStateLength = KiXSaveAreaLength = AllFeatureSize. Num AP: o CPUID dele
//!   precisa cobrir a configuração do BSP (o binário para com
//!   UNSUPPORTED_PROCESSOR; aqui é um aviso, como no resto da identidade).
//! - O KiInitializeKernel de cada CPU liga KF_XSTATE no FeatureBits quando há
//!   recursos habilitados, e KF_XSAVEOPT e KF_XSAVES pelo
//!   KeGetXSaveFeatureFlags ([`kernel_feature_bits`]).
//! - KiEnableXSave ([`enable_processor`]): CR4.OSXSAVE, XCR0 =
//!   EnabledFeatures, IA32_XSS = EnabledSupervisorFeatures e, com um CONTEXT
//!   próprio na KPRCB, CONTEXT_XSTATE no ContextFlagsInit.
//!
//! O carregador do NT passa em LOADER_PARAMETER_EXTENSION a XsaveAllowedFeatures
//! e os XsaveFlags (0x8 mantém o OptimizedSave, 0x10 mantém a compactação). O
//! OpenNT é o próprio carregador e passa os valores de um boot sem opções de
//! BCD: todos os recursos e os dois bits.
//!
//! A política é o recurso 0x65, nome KeXSavePolicyId (1), do hwpolicy.sys, um
//! driver de boot que o carregador entrega (KeHwPolicyLocateResource). No
//! OpenNT ele é um arquivo do bundle do kernel, o equivalente da lista de
//! drivers de boot. Sem ele o binário desliga o XSAVE inteiro
//! (STATUS_DRIVER_UNABLE_TO_LOAD no KiLoadPolicyFromImage), e aqui também.
//!
//! A configuração fica numa cópia do kernel, publicada na KUSER_SHARED_DATA
//! (`XState`) por [`publish`].

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use crate::hal::cpu;
use crate::ntos::inc::types::{Kprcb, KuserSharedData, NtStruct, XstateConfiguration};

/// A área legada (x87 e SSE) e o cabeçalho de uma área de XSAVE.
pub const LEGACY_SIZE: u32 = 0x200;
pub const HEADER_SIZE: u32 = 0x40;
pub const LEGACY_AND_HEADER: u32 = LEGACY_SIZE + HEADER_SIZE;

/// Bits do ControlFlags.
pub mod control {
    pub const OPTIMIZED_SAVE: u32 = 1;
    pub const COMPACTION_ENABLED: u32 = 2;
}

/// Os recursos: x87, SSE, AVX e os três do AVX-512.
pub mod feature {
    pub const LEGACY_FLOATING_POINT: u64 = 1 << 0;
    pub const LEGACY_SSE: u64 = 1 << 1;
    pub const AVX: u64 = 1 << 2;
    pub const AVX512: u64 = 0xE0;
    pub const LEGACY: u64 = LEGACY_FLOATING_POINT | LEGACY_SSE;
    /// O bit 63 do XCOMP_BV: área no formato compactado.
    pub const COMPACTED_FORMAT: u64 = 1 << 63;
}

/// Os recursos que o KiUpdateXSaveSizeAndVolatileFeatures tira dos
/// voláteis (o BNDCSR do MPX e o LWP).
const NON_VOLATILE_FEATURES: u64 = !0xBFFF_FFFF_FFFF_FFEF;
/// Supervisor visível ao usuário: o CET_U.
const USER_VISIBLE_SUPERVISOR: u64 = 0x800;

/// XsaveAllowedFeatures e XsaveFlags do carregador sem opções de BCD.
const LOADER_ALLOWED_FEATURES: u64 = u64::MAX;
const LOADER_KEEP_OPTIMIZED_SAVE: u32 = 0x8;
const LOADER_KEEP_COMPACTION: u32 = 0x10;
const LOADER_XSAVE_FLAGS: u32 = LOADER_KEEP_OPTIMIZED_SAVE | LOADER_KEEP_COMPACTION;

/// KeXSavePolicyId e o tipo do recurso da política.
const POLICY_ID: u32 = 1;
const POLICY_RESOURCE_TYPE: u32 = 0x65;
/// O arquivo do driver de política no bundle.
const POLICY_DRIVER: &str = "apps/hwpolicy.sys";

/// KeGetXSaveFeatureFlags.
pub mod feature_flags {
    pub const OPTIMIZED_SAVE: u32 = 8;
    pub const COMPACTION: u32 = 0x10;
}

#[repr(C, align(8))]
struct Storage(UnsafeCell<[u8; XstateConfiguration::SIZE as usize]>);

// SAFETY: as células do XSTATE_CONFIGURATION são lidas e gravadas por
// `Field` (acessos voláteis); só o BSP grava, antes dos APs.
unsafe impl Sync for Storage {}

static CONFIGURATION: Storage = Storage(UnsafeCell::new([0; XstateConfiguration::SIZE as usize]));
/// KiXSaveAreaLength e KeXStateLength (0x200 no .data do binário).
static XSAVE_AREA_LENGTH: AtomicU32 = AtomicU32::new(LEGACY_SIZE);
static XSTATE_LENGTH: AtomicU32 = AtomicU32::new(LEGACY_SIZE);
/// A configuração do BSP está pronta.
static CONFIGURED: AtomicU8 = AtomicU8::new(0);

/// O XSTATE_CONFIGURATION do sistema (a cópia do kernel do que a
/// KUSER_SHARED_DATA publica).
pub fn configuration() -> &'static XstateConfiguration {
    // SAFETY: armazenamento estático do tamanho e alinhamento da estrutura.
    unsafe { XstateConfiguration::at(CONFIGURATION.0.get() as u64) }
}

/// XState.EnabledFeatures.
pub fn enabled_features() -> u64 {
    configuration().enabled_features.get()
}

/// XState.EnabledVolatileFeatures.
pub fn enabled_volatile_features() -> u64 {
    configuration().enabled_volatile_features.get()
}

/// XState.EnabledSupervisorFeatures.
pub fn enabled_supervisor_features() -> u64 {
    configuration().enabled_supervisor_features.get()
}

/// XState.EnabledUserVisibleSupervisorFeatures.
pub fn enabled_user_visible_supervisor_features() -> u64 {
    configuration().enabled_user_visible_supervisor_features.get()
}

/// XState.ControlFlags.CompactionEnabled.
pub fn compaction() -> bool {
    configuration().control_flags.get() & control::COMPACTION_ENABLED != 0
}

/// KiXSaveAreaLength: a área de XSAVE de cada thread.
pub fn xsave_area_length() -> u32 {
    XSAVE_AREA_LENGTH.load(Ordering::Acquire)
}

/// KeXStateLength.
pub fn xstate_length() -> u32 {
    XSTATE_LENGTH.load(Ordering::Acquire)
}

/// A configuração do BSP está montada.
pub fn configured() -> bool {
    CONFIGURED.load(Ordering::Acquire) != 0
}

/// KeGetXSaveFeatureFlags: sem recursos habilitados, zero; senão 8 com o
/// OptimizedSave e 0x10 com a compactação.
pub fn feature_flags() -> u32 {
    let config = configuration();
    if config.enabled_features.get() == 0 {
        return 0;
    }
    let flags = config.control_flags.get();
    let mut result = (flags & control::OPTIMIZED_SAVE) << 3;
    if flags & control::COMPACTION_ENABLED != 0 {
        result |= feature_flags::COMPACTION;
    }
    result
}

/// KiGetXSaveSupportedFeatures: os recursos do CPUID 0xD numa configuração
/// zerada. Sem XSAVE (CPUID 1 ECX.26) ou sem x87 e SSE, EnabledFeatures e
/// Size ficam zero.
fn supported_features(config: &XstateConfiguration) {
    let disabled = |config: &XstateConfiguration| {
        config.enabled_features.set(0);
        config.size.set(0);
    };
    if cpu::cpuid(1)[2] & (1 << 26) == 0 {
        disabled(config);
        return;
    }
    let [eax, _, _, edx] = cpu::cpuid_subleaf(0xD, 0);
    let supported = (edx as u64) << 32 | eax as u64;
    config.enabled_features.set(supported);
    if supported & feature::LEGACY != feature::LEGACY {
        disabled(config);
        return;
    }
    let [eax1, _, ecx1, edx1] = cpu::cpuid_subleaf(0xD, 1);
    // XSAVEC e XSAVES: compactação; XSAVEOPT: OptimizedSave.
    let mut flags = if eax1 & 0xA == 0xA { control::COMPACTION_ENABLED } else { 0 };
    flags |= eax1 & control::OPTIMIZED_SAVE;
    config.control_flags.set((config.control_flags.get() & !3) | flags);
    let compaction = flags & control::COMPACTION_ENABLED != 0;
    let supervisor = if compaction { (edx1 as u64) << 32 | ecx1 as u64 } else { 0 };
    config.enabled_supervisor_features.set(supervisor);
    config.features[0].offset.set(0);
    config.features[0].size.set(0xA0);
    config.features[1].offset.set(0xA0);
    config.features[1].size.set(0x100);
    let mut size = LEGACY_AND_HEADER;
    let mut aligned = config.aligned_features.get();
    for index in 2..64u32 {
        if supported & (1u64 << index) == 0 {
            continue;
        }
        let [eax, ebx, ecx, _] = cpu::cpuid_subleaf(0xD, index);
        config.features[index as usize].offset.set(ebx);
        config.features[index as usize].size.set(eax);
        size = size.max(ebx + eax);
        if ecx & 2 != 0 {
            aligned |= 1u64 << index;
        }
    }
    config.aligned_features.set(aligned);
    config.size.set(size);
    if compaction {
        for index in 0..64u32 {
            let value = if supervisor & (1u64 << index) != 0 {
                let [eax, _, ecx, _] = cpu::cpuid_subleaf(0xD, index);
                if ecx & 2 != 0 {
                    config.aligned_features.set(config.aligned_features.get() | 1u64 << index);
                }
                eax
            } else {
                config.features[index as usize].size.get()
            };
            config.all_features[index as usize].set(value);
        }
    }
}

/// KiUpdateXSaveSizeAndVolatileFeatures: Size e AllFeatureSize pelos
/// recursos habilitados (no formato compactado, os deslocamentos de cada
/// recurso também), EnabledVolatileFeatures e
/// EnabledUserVisibleSupervisorFeatures.
fn update_size_and_volatile(config: &XstateConfiguration) {
    let enabled = config.enabled_features.get();
    config.size.set(LEGACY_AND_HEADER);
    config.all_feature_size.set(LEGACY_AND_HEADER);
    let aligned = config.aligned_features.get();
    if config.control_flags.get() & control::COMPACTION_ENABLED != 0 {
        for index in 2..64usize {
            if enabled & (1u64 << index) == 0 {
                continue;
            }
            let mut offset = config.size.get();
            if aligned & (1u64 << index) != 0 {
                offset = (offset + 0x3F) & !0x3F;
                config.size.set(offset);
            }
            config.features[index].offset.set(offset);
            config.size.set(config.size.get() + config.features[index].size.get());
        }
        let all = config.enabled_supervisor_features.get() | enabled;
        for index in 2..64usize {
            if all & (1u64 << index) == 0 {
                continue;
            }
            let mut offset = config.all_feature_size.get();
            if aligned & (1u64 << index) != 0 {
                offset = (offset + 0x3F) & !0x3F;
                config.all_feature_size.set(offset);
            }
            config.all_feature_size.set(offset + config.all_features[index].get());
        }
    } else {
        for index in 0..64usize {
            if enabled & (1u64 << index) == 0 {
                continue;
            }
            let end = config.features[index].offset.get() + config.features[index].size.get();
            if config.size.get() < end {
                config.size.set(end);
            }
        }
        config.all_feature_size.set(config.size.get());
    }
    config.enabled_volatile_features.set(enabled & !NON_VOLATILE_FEATURES);
    config.enabled_user_visible_supervisor_features.set(config.enabled_supervisor_features.get() & USER_VISIBLE_SUPERVISOR);
}

// ---- a política do hwpolicy.sys -----------------------------------------------

/// O que o KiGetProcessorInformation e a KPRCB dão à política: o fabricante
/// (EBX, EDX, ECX do CPUID 0), a assinatura (CPUID 1 EAX) e a revisão do
/// microcódigo (KPRCB.UpdateSignature).
struct ProcessorInformation {
    vendor: [u8; 12],
    signature: u32,
    microcode: u64,
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes.get(offset..offset + 2).map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes.get(offset..offset + 4).map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|slice| u64::from_le_bytes(slice.try_into().unwrap_or([0; 8])))
}

/// O deslocamento no arquivo de um RVA de um PE cru (pelas seções).
fn file_offset(image: &[u8], rva: u32) -> Option<usize> {
    let header = read_u32(image, 0x3C)? as usize;
    if read_u32(image, header)? != 0x4550 {
        return None;
    }
    let sections = read_u16(image, header + 6)? as usize;
    let optional = read_u16(image, header + 20)? as usize;
    let table = header + 24 + optional;
    (0..sections).find_map(|index| {
        let entry = table + index * 40;
        let virtual_size = read_u32(image, entry + 8)?;
        let virtual_address = read_u32(image, entry + 12)?;
        let raw_size = read_u32(image, entry + 16)?;
        let raw_offset = read_u32(image, entry + 20)?;
        let extent = virtual_size.max(raw_size);
        (rva >= virtual_address && rva < virtual_address + extent && rva - virtual_address < raw_size).then(|| (raw_offset + rva - virtual_address) as usize)
    })
}

/// A entrada de um diretório de recursos com o id `id` (ou a primeira, sem
/// id): o deslocamento (com o bit de subdiretório) relativo à raiz.
fn resource_entry(image: &[u8], root: usize, directory: usize, id: Option<u32>) -> Option<u32> {
    let named = read_u16(image, root + directory + 12)? as usize;
    let numbered = read_u16(image, root + directory + 14)? as usize;
    (0..named + numbered).find_map(|index| {
        let entry = root + directory + 16 + index * 8;
        let name = read_u32(image, entry)?;
        let matches = id.is_none_or(|id| name & 0x8000_0000 == 0 && name == id);
        matches.then(|| read_u32(image, entry + 4)).flatten()
    })
}

/// KeHwPolicyLocateResource(LoaderBlock, 0x65, KeXSavePolicyId): o recurso
/// tipo 0x65, nome 1 (a primeira língua, a busca do LdrResSearchResource
/// com o fallback de língua) do driver de política.
fn locate_policy() -> Option<&'static [u8]> {
    let image = crate::hal::bundle::read(POLICY_DRIVER)?;
    let header = read_u32(image, 0x3C)? as usize;
    // IMAGE_DIRECTORY_ENTRY_RESOURCE do PE32+ (o cabeçalho opcional começa
    // em +24; os diretórios em +112 dele).
    let directory_rva = read_u32(image, header + 24 + 112 + 2 * 8)?;
    let root = file_offset(image, directory_rva)?;
    let types = resource_entry(image, root, 0, Some(POLICY_RESOURCE_TYPE))?;
    let names = resource_entry(image, root, (types & 0x7FFF_FFFF) as usize, Some(POLICY_ID))?;
    let language = resource_entry(image, root, (names & 0x7FFF_FFFF) as usize, None)?;
    if types & names & 0x8000_0000 == 0 || language & 0x8000_0000 != 0 {
        return None;
    }
    let data = root + language as usize;
    let start = file_offset(image, read_u32(image, data)?)?;
    let size = read_u32(image, data + 4)? as usize;
    image.get(start..start + size)
}

/// KiIsXSaveFeatureAllowed(Policy, Index, Information): a lista de
/// processadores da entrada; o primeiro do mesmo fabricante decide (uma
/// entrada sem o bloco específico aceita todos dele; com o bloco, um
/// processador diferente é aceito e o mesmo só com microcódigo mais novo
/// que o da entrada). Sem entrada do fabricante, recusado.
fn feature_allowed(policy: &[u8], index: usize, information: &ProcessorInformation) -> bool {
    let Some(list) = read_u64(policy, 0x20 + index * 0x10 + 8) else { return false };
    let list = list as usize;
    let Some(count) = read_u32(policy, list) else { return false };
    let vendor_low = u64::from_le_bytes(information.vendor[..8].try_into().unwrap_or([0; 8]));
    let vendor_high = u32::from_le_bytes(information.vendor[8..].try_into().unwrap_or([0; 4]));
    let signature = information.signature;
    for entry in (0..count as usize).map(|position| list + position * 0x38) {
        let (Some(low), Some(high)) = (read_u64(policy, entry + 8), read_u32(policy, entry + 0x10)) else { return false };
        if low != vendor_low || high != vendor_high {
            continue;
        }
        let specific = read_u64(policy, entry + 0x38).unwrap_or(0);
        if specific == 0 {
            return true;
        }
        let kind = policy.get(entry + 0x18).copied().unwrap_or(0);
        if (signature >> 12) & 3 != kind as u32 {
            return true;
        }
        let model = ((signature >> 10) & 0xF0) + ((signature >> 4) & 0xF);
        if model != read_u16(policy, entry + 0x1C).unwrap_or(0) as u32 {
            return true;
        }
        let family = ((signature >> 14) & 0xFF0) + ((signature >> 8) & 0xF);
        if family != read_u16(policy, entry + 0x1A).unwrap_or(0) as u32 {
            return true;
        }
        if signature & 0xF != read_u16(policy, entry + 0x1E).unwrap_or(0) as u32 {
            return true;
        }
        let microcode = read_u64(policy, entry + 0x28).unwrap_or(0);
        return microcode == 0 || information.microcode > microcode;
    }
    false
}

/// KiIntersectFeaturesWithPolicy: cada recurso habilitado (de usuário ou de
/// supervisor) fica só se a política o lista e alguma entrada dele aceita
/// este processador. Sem o driver de política, nada fica.
fn intersect_with_policy(config: &XstateConfiguration, prcb: &Kprcb) {
    if config.enabled_features.get() == 0 {
        return;
    }
    let Some(policy) = locate_policy() else {
        config.control_flags.set(config.control_flags.get() & !3);
        config.enabled_features.set(0);
        config.enabled_supervisor_features.set(0);
        return;
    };
    let [_, ebx, ecx, edx] = cpu::cpuid(0);
    let mut vendor = [0u8; 12];
    for (chunk, register) in vendor.chunks_mut(4).zip([ebx, edx, ecx]) {
        chunk.copy_from_slice(&register.to_le_bytes());
    }
    let information = ProcessorInformation { vendor, signature: cpu::cpuid(1)[0], microcode: prcb.update_signature.quad_part.get() as u64 };
    let listed = read_u64(policy, 0x10).unwrap_or(0);
    let count = read_u32(policy, 0x18).unwrap_or(0) as usize;
    let candidates = config.enabled_features.get() | config.enabled_supervisor_features.get();
    let mut allowed = 0u64;
    for bit in (0..64usize).filter(|&bit| candidates & (1u64 << bit) != 0 && listed & (1u64 << bit) != 0) {
        for index in 0..count {
            if read_u32(policy, 0x20 + index * 0x10) == Some(bit as u32) && feature_allowed(policy, index, &information) {
                allowed |= 1u64 << bit;
            }
        }
    }
    config.enabled_features.set(config.enabled_features.get() & allowed);
    config.enabled_supervisor_features.set(config.enabled_supervisor_features.get() & allowed);
}

// ---- KiInitializeXSave / KiInitializeKernel / KiEnableXSave ---------------------

/// KiInitializeXSave do processador corrente. No BSP monta e guarda a
/// configuração; num AP confere que o CPUID dele a cobre.
pub fn initialize_processor(boot: bool, prcb: &Kprcb) {
    let storage = Storage(UnsafeCell::new([0; XstateConfiguration::SIZE as usize]));
    // SAFETY: armazenamento local do tamanho e alinhamento da estrutura.
    let local = unsafe { XstateConfiguration::at(storage.0.get() as u64) };
    supported_features(local);
    if !boot {
        let shared = configuration();
        let covers = |wanted: u64, present: u64| present & wanted == wanted;
        let local_flags = local.control_flags.get();
        let shared_flags = shared.control_flags.get();
        let ok = covers(shared.enabled_features.get(), local.enabled_features.get())
            && covers(shared.enabled_supervisor_features.get(), local.enabled_supervisor_features.get())
            && (local_flags & control::OPTIMIZED_SAVE != 0 || shared_flags & control::OPTIMIZED_SAVE == 0)
            && (local_flags & control::COMPACTION_ENABLED != 0 || shared_flags & control::COMPACTION_ENABLED == 0);
        if !ok {
            crate::debug_print!("[ke] processador {}: o XSAVE nao cobre a configuracao do BSP (UNSUPPORTED_PROCESSOR no NT)", prcb.number.get());
        }
        return;
    }
    if local.enabled_features.get() != 0 {
        local.enabled_supervisor_features.set(local.enabled_supervisor_features.get() & LOADER_ALLOWED_FEATURES);
        local.enabled_features.set(local.enabled_features.get() & LOADER_ALLOWED_FEATURES);
        if LOADER_XSAVE_FLAGS & LOADER_KEEP_COMPACTION == 0 {
            local.control_flags.set(local.control_flags.get() & !control::COMPACTION_ENABLED);
        }
        if LOADER_XSAVE_FLAGS & LOADER_KEEP_OPTIMIZED_SAVE == 0 {
            local.control_flags.set(local.control_flags.get() & !control::OPTIMIZED_SAVE);
        }
    }
    intersect_with_policy(local, prcb);
    update_size_and_volatile(local);
    // SAFETY: as duas áreas têm o tamanho da estrutura; só o BSP grava, antes
    // de qualquer leitor.
    unsafe { core::ptr::copy_nonoverlapping(storage.0.get() as *const u8, CONFIGURATION.0.get() as *mut u8, XstateConfiguration::SIZE as usize) };
    let config = configuration();
    if config.enabled_features.get() != 0 {
        XSTATE_LENGTH.store(config.all_feature_size.get(), Ordering::Release);
        XSAVE_AREA_LENGTH.store(config.all_feature_size.get(), Ordering::Release);
    }
    CONFIGURED.store(1, Ordering::Release);
    crate::debug_print!(
        "[ke] XSAVE: EnabledFeatures {:#x} (supervisor {:#x}), ControlFlags {:#x}, Size {:#x}, AllFeatureSize {:#x}",
        config.enabled_features.get(),
        config.enabled_supervisor_features.get(),
        config.control_flags.get(),
        config.size.get(),
        config.all_feature_size.get()
    );
}

/// Os bits do FeatureBits que o KiInitializeKernel acrescenta com recursos
/// habilitados: KF_XSTATE e, pelo KeGetXSaveFeatureFlags, KF_XSAVEOPT e
/// KF_XSAVES.
pub fn kernel_feature_bits(mut bits: u64) -> u64 {
    use crate::ntos::ke::processor_identity::kf;
    if enabled_features() == 0 {
        return bits;
    }
    bits |= kf::XSTATE;
    let flags = feature_flags();
    if flags & feature_flags::OPTIMIZED_SAVE != 0 {
        bits |= kf::XSAVEOPT;
    }
    if flags & feature_flags::COMPACTION != 0 {
        bits |= kf::XSAVES;
    }
    bits
}

/// CR4.OSXSAVE.
const CR4_OSXSAVE: u64 = 1 << 18;
/// IA32_XSS.
const MSR_XSS: u32 = 0xDA0;
/// CONTEXT_AMD64 | CONTEXT_XSTATE.
const CONTEXT_XSTATE: u32 = 0x10_0040;

/// KiEnableXSave no processador corrente: com KF_XSTATE no KeFeatureBits,
/// liga o CR4.OSXSAVE, grava o XCR0 e o IA32_XSS; sem ele, desliga o
/// OSXSAVE.
pub fn enable_processor() {
    use crate::ntos::ke::processor_identity::{self, kf};
    let control4 = cpu::read_cr4();
    if processor_identity::feature_bits() & kf::XSTATE == 0 {
        if control4 & CR4_OSXSAVE != 0 {
            cpu::write_cr4(control4 & !CR4_OSXSAVE);
        }
        return;
    }
    if control4 & CR4_OSXSAVE == 0 {
        cpu::write_cr4(control4 | CR4_OSXSAVE);
    }
    let config = configuration();
    cpu::write_xcr(0, config.enabled_features.get());
    let supervisor = config.enabled_supervisor_features.get();
    if supervisor != 0 {
        cpu::write_msr(MSR_XSS, supervisor);
    }
    let prcb = &crate::ntos::ke::pcr::current().prcb;
    let context = prcb.context.get();
    if context != 0 && context != prcb.processor_state.context_frame.address() {
        prcb.context_flags_init.set(prcb.context_flags_init.get() | CONTEXT_XSTATE);
    }
}

/// Publica a configuração em KUSER_SHARED_DATA.XState (o fim do
/// KiInitializeXSave do BSP).
pub fn publish(data: &KuserSharedData) {
    // SAFETY: a página e a cópia do kernel têm o XSTATE_CONFIGURATION inteiro.
    unsafe { core::ptr::copy_nonoverlapping(CONFIGURATION.0.get() as *const u8, data.x_state.address() as *mut u8, XstateConfiguration::SIZE as usize) };
}
