//! Topologia lógica dos processadores: núcleos, pacotes, caches e o maior
//! line size (KeQueryLogicalProcessorRelationship e
//! KeGetRecommendedSharedDataAlignment).
//!
//! Segue o ntoskrnl 19041: o KiSetFeatureBits deriva LogicalProcessorsPerCore
//! e CoresPerPhysicalProcessor do CPUID (níveis 0x1F/0xB, CPUID 1/4 legado, ou
//! 0x80000008/0x8000001E na AMD) e o KiInitializeKernel agrupa os
//! InitialApicId sob -(LogicalPerCore) e -(Cores*LogicalPerCore). Os
//! descritores de cache vêm do KiSetStandardizedCacheInformation (folha 4, ou
//! 0x8000001D na AMD com TopoExt) ou do KiSetCacheInformationAmd legado
//! (0x80000005/0x80000006), e KeLargestCacheLine parte de 64 e sobe ao maior
//! LineSize dos caches L2+ unificados ou de dados (KiSetCacheInformation).
//!
//! O CPUID roda no processador corrente; os demais entram pelos APIC ids da
//! MADT (`smp`). Um grupo e um nó NUMA (sem SRAT nem mais de 64 CPUs);
//! EfficiencyClass 0 (núcleos homogêneos).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{processor_group, processor_information, smp};
use crate::hal::cpu;
use crate::ntos::inc::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use crate::ntos::inc::types::{Field, GroupAffinity, NtStruct, ProcessorGroupInfo, ProcessorNumber, SystemLogicalProcessorInformationEx};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
/// KiMaximumGroups = KiActiveGroups = KeNumberNodes no OpenNT.
const GROUP_COUNT: u16 = 1;
/// Valor inicial de KeLargestCacheLine no .data do ntoskrnl.
const DEFAULT_LARGEST_CACHE_LINE: u32 = 64;
/// KPRCB.Cache[5].
const MAXIMUM_CACHES: usize = 5;

/// LOGICAL_PROCESSOR_RELATIONSHIP.
pub mod relation {
    pub const CORE: u32 = 0;
    pub const NUMA_NODE: u32 = 1;
    pub const CACHE: u32 = 2;
    pub const PACKAGE: u32 = 3;
    pub const GROUP: u32 = 4;
    pub const ALL: u32 = 0xFFFF;
}

/// PROCESSOR_CACHE_TYPE.
pub mod cache_type {
    pub const UNIFIED: u32 = 0;
    pub const INSTRUCTION: u32 = 1;
    pub const DATA: u32 = 2;
    pub const TRACE: u32 = 3;
}

/// Quem compartilha um cache (KPRCB.CacheProcessorMask).
#[derive(Clone, Copy)]
enum Sharing {
    /// Máscara 0 na KPRCB: o registro sai só com o próprio processador.
    Own,
    /// Processadores cujo InitialApicId coincide sob a máscara.
    ApicMask(u32),
    /// L3 AMD legado (família <= 0x15): o pacote inteiro.
    Package,
}

/// CACHE_DESCRIPTOR mais o compartilhamento.
#[derive(Clone, Copy)]
struct Cache {
    level: u8,
    associativity: u8,
    line_size: u16,
    size: u32,
    kind: u32,
    sharing: Sharing,
}

static LARGEST_CACHE_LINE: AtomicU32 = AtomicU32::new(0);
/// Valor inicial de KiLargestCacheSize no .data do ntoskrnl.
const DEFAULT_LARGEST_CACHE_SIZE: u32 = 0x10000;
static LARGEST_CACHE_SIZE: AtomicU32 = AtomicU32::new(0);

fn is_amd(vendor: &str) -> bool {
    matches!(vendor, "AuthenticAMD" | "HygonGenuine")
}

/// bsr(value), value != 0.
fn highest_bit(value: u32) -> u32 {
    31 - value.leading_zeros()
}

/// KiSetStandardizedCacheInformation: até cinco descritores; tipos
/// desconhecidos são pulados, o tipo 0 encerra.
fn standardized_caches(leaf: u32) -> Vec<Cache> {
    let mut caches = Vec::new();
    let mut subleaf = 0u32;
    while caches.len() < MAXIMUM_CACHES && subleaf < 32 {
        let [eax, ebx, ecx, _] = cpu::cpuid_subleaf(leaf, subleaf);
        subleaf += 1;
        let kind = match eax & 0x1F {
            0 => break,
            1 => cache_type::DATA,
            2 => cache_type::INSTRUCTION,
            3 => cache_type::UNIFIED,
            5 => cache_type::TRACE,
            _ => continue,
        };
        let ways = (ebx >> 22) + 1;
        let partitions = ((ebx >> 12) & 0x3FF) + 1;
        let line = (ebx & 0xFFF) + 1;
        // EAX bit 9: totalmente associativo.
        let associativity = if eax & (1 << 9) != 0 { 0xFF } else { ((ebx >> 22) as u8).wrapping_add(1) };
        let size = partitions.wrapping_mul(line).wrapping_mul(ways).wrapping_mul(ecx.wrapping_add(1));
        // EAX[25:14] = lógicos que compartilham - 1; o binário desloca um
        // registrador de 8 bits (deslocamentos >= 8 dão 0, todos coincidem).
        let sharing_count = (eax >> 14) & 0xFFF;
        let sharing = if sharing_count == 0 {
            Sharing::ApicMask(u32::MAX)
        } else {
            let shift = highest_bit(sharing_count * 2 + 1);
            let bit = if shift < 8 { 1u32 << shift } else { 0 };
            Sharing::ApicMask(!bit.wrapping_sub(1))
        };
        caches.push(Cache { level: ((eax >> 5) & 7) as u8, associativity, line_size: line as u16, size, kind, sharing });
    }
    caches
}

/// KiGetL2L3AssociativityAmd.
fn amd_associativity(code: u32) -> u8 {
    match code {
        0 => 0,
        2 => 2,
        4 => 4,
        6 => 8,
        8 => 16,
        0xF => 0xFF,
        _ => 1,
    }
}

/// KiSetCacheInformationAmd sem TopoExt: L1D/L1I de 0x80000005, L2/L3 de
/// 0x80000006; L3 de tamanho zero encerra a lista.
fn amd_legacy_caches(family: u16) -> Vec<Cache> {
    let mut caches = Vec::new();
    let [_, _, l1_data, l1_code] = cpu::cpuid_subleaf(0x8000_0005, 0);
    for (register, kind) in [(l1_data, cache_type::DATA), (l1_code, cache_type::INSTRUCTION)] {
        caches.push(Cache { level: 1, associativity: (register >> 16) as u8, line_size: (register & 0xFF) as u16, size: (register >> 24) << 10, kind, sharing: Sharing::Own });
    }
    let [_, _, l2, l3] = cpu::cpuid_subleaf(0x8000_0006, 0);
    caches.push(Cache { level: 2, associativity: amd_associativity((l2 >> 12) & 0xF), line_size: (l2 & 0xFF) as u16, size: (l2 >> 16) << 10, kind: cache_type::UNIFIED, sharing: Sharing::Own });
    let l3_size = (l3 >> 18) << 19;
    if l3_size != 0 {
        let sharing = if family <= 0x15 { Sharing::Package } else { Sharing::Own };
        caches.push(Cache { level: 3, associativity: amd_associativity((l3 >> 12) & 0xF), line_size: (l3 & 0xFF) as u16, size: l3_size, kind: cache_type::UNIFIED, sharing });
    }
    caches
}

/// KiSetCacheInformation: AMD por 0x8000001D (TopoExt) ou legado; os demais
/// fabricantes pela folha 4 quando 4 <= máximo <= 0x7FFFFFFF.
fn cache_descriptors(amd: bool, family: u16) -> Vec<Cache> {
    if amd {
        if cpu::cpuid(0x8000_0001)[2] & (1 << 22) != 0 {
            return standardized_caches(0x8000_001D);
        }
        return amd_legacy_caches(family);
    }
    let maximum = cpu::cpuid(0)[0];
    if (4..=0x7FFF_FFFF).contains(&maximum) { standardized_caches(4) } else { Vec::new() }
}

/// KeLargestCacheLine: 64, ou o maior LineSize dos caches L2+ unificados ou
/// de dados.
fn largest_cache_line(caches: &[Cache]) -> u32 {
    caches
        .iter()
        .filter(|cache| cache.level >= 2 && (cache.kind == cache_type::UNIFIED || cache.kind == cache_type::DATA))
        .fold(DEFAULT_LARGEST_CACHE_LINE, |largest, cache| largest.max(cache.line_size as u32))
}

/// KiSetFeatureBits: (LogicalProcessorsPerCore, CoresPerPhysicalProcessor).
fn topology_counts(amd: bool) -> (u32, u32) {
    if amd {
        let maximum_extended = cpu::cpuid(0x8000_0000)[0];
        if maximum_extended < 0x8000_0008 {
            return (1, 1);
        }
        let ecx = cpu::cpuid_subleaf(0x8000_0008, 0)[2];
        let mut shift = (ecx >> 12) & 0xF;
        if shift == 0 {
            shift = highest_bit((ecx & 0xFF) * 2 + 1);
        }
        let mut cores = 1u32 << shift;
        let mut per_core = 1;
        if maximum_extended >= 0x8000_001E && cpu::cpuid(0x8000_0001)[2] & (1 << 22) != 0 {
            per_core = ((cpu::cpuid_subleaf(0x8000_001E, 0)[1] >> 8) & 0xFF) + 1;
            cores /= per_core;
        }
        return (per_core, cores.max(1));
    }
    let maximum = cpu::cpuid(0)[0];
    let leaf = if maximum >= 0x1F && cpu::cpuid_subleaf(0x1F, 0)[1] != 0 {
        0x1F
    } else if maximum >= 0xB && cpu::cpuid_subleaf(0xB, 0)[1] != 0 {
        0xB
    } else {
        0
    };
    if leaf != 0 {
        let (mut per_core, mut per_package) = (1u32, 1u32);
        for subleaf in 0..16 {
            let [eax, ebx, ecx, _] = cpu::cpuid_subleaf(leaf, subleaf);
            let level_type = ecx >> 8;
            if level_type != 0 {
                let shift = eax & 0x1F;
                if level_type == 1 {
                    per_core = 1 << shift;
                } else {
                    per_package = 1 << shift;
                }
            }
            if ebx & 0xFFFF == 0 {
                break;
            }
        }
        return (per_core, (per_package / per_core).max(1));
    }
    // CPUID legado: núcleos pela folha 4, lógicos por CPUID.1 com HTT.
    let cores = if maximum >= 4 { 1u32 << highest_bit((cpu::cpuid_subleaf(4, 0)[0] >> 26) * 2 + 1) } else { 1 };
    let [_, ebx, _, edx] = cpu::cpuid(1);
    let per_core = if edx & (1 << 28) != 0 {
        let logical = ((ebx >> 16) & 0xFF).max(1);
        ((1u32 << highest_bit(logical * 2 - 1)) / cores).max(1)
    } else {
        1
    };
    (per_core, cores)
}

/// APIC id de cada processador ativo na ordem dos índices: 0 = BSP, k = slot
/// k-1 dos APs (a numeração de `smp::init`). No máximo 64.
pub fn processor_apic_ids() -> Vec<u32> {
    let bootstrap = smp::bsp_apic_id();
    let mut others: Vec<u32> = Vec::new();
    for identifier in smp::discovered_apic_ids() {
        if identifier != bootstrap && !others.contains(&identifier) {
            others.push(identifier);
        }
    }
    let mut identifiers = alloc::vec![bootstrap];
    for index in 0..smp::ap_slot_count() {
        if let Some(slot) = smp::ap_slot(index) {
            identifiers.push(others.get(slot).copied().unwrap_or(u32::MAX));
        }
    }
    identifiers.truncate(64);
    identifiers
}

struct Topology {
    apic: Vec<u32>,
    core_mask: u32,
    package_mask: u32,
    caches: Vec<Cache>,
}

impl Topology {
    fn capture() -> Result<Topology, KernelError> {
        let snapshot = processor_information::snapshot()?;
        let amd = is_amd(&snapshot.vendor);
        let (per_core, cores) = topology_counts(amd);
        Ok(Topology {
            apic: processor_apic_ids(),
            core_mask: !(per_core - 1),
            package_mask: !(per_core.wrapping_mul(cores).wrapping_sub(1)),
            caches: cache_descriptors(amd, snapshot.level),
        })
    }

    /// Processadores (bits por índice no grupo 0) com o mesmo APIC id sob `mask`.
    fn siblings(&self, processor: usize, mask: u32) -> u64 {
        let mine = self.apic[processor] & mask;
        self.apic.iter().enumerate().filter(|&(_, &identifier)| identifier & mask == mine).fold(0, |set, (index, _)| set | 1u64 << index)
    }

    fn core_set(&self, processor: usize) -> u64 {
        self.siblings(processor, self.core_mask)
    }

    fn package_set(&self, processor: usize) -> u64 {
        self.siblings(processor, self.package_mask)
    }

    /// KPRCB.CacheProcessorMask[i]; 0 = só o próprio processador.
    fn cache_set(&self, processor: usize, cache: &Cache) -> u64 {
        match cache.sharing {
            Sharing::Own => 0,
            Sharing::ApicMask(mask) => self.siblings(processor, mask),
            Sharing::Package => self.package_set(processor),
        }
    }

    fn active_mask(&self) -> u64 {
        if self.apic.len() >= 64 { u64::MAX } else { (1u64 << self.apic.len()) - 1 }
    }
}

/// KiLargestCacheSize: 64 KB (o valor inicial no .data do ntoskrnl), ou o
/// maior Size dos caches L2+ unificados ou de dados (KiSetCacheInformation),
/// calculado uma vez.
pub fn largest_cache_size() -> u32 {
    let size = LARGEST_CACHE_SIZE.load(Ordering::Acquire);
    if size != 0 {
        return size;
    }
    let caches = match processor_information::snapshot() {
        Ok(snapshot) => cache_descriptors(is_amd(&snapshot.vendor), snapshot.level),
        Err(_) => Vec::new(),
    };
    let size = caches
        .iter()
        .filter(|cache| cache.level >= 2 && (cache.kind == cache_type::UNIFIED || cache.kind == cache_type::DATA))
        .fold(DEFAULT_LARGEST_CACHE_SIZE, |largest, cache| largest.max(cache.size));
    LARGEST_CACHE_SIZE.store(size, Ordering::Release);
    size
}

/// KeGetRecommendedSharedDataAlignment: KeLargestCacheLine, calculado uma vez.
pub fn recommended_shared_data_alignment() -> Result<u32, KernelError> {
    let line = LARGEST_CACHE_LINE.load(Ordering::Acquire);
    if line != 0 {
        return Ok(line);
    }
    let snapshot = processor_information::snapshot()?;
    let line = largest_cache_line(&cache_descriptors(is_amd(&snapshot.vendor), snapshot.level));
    LARGEST_CACHE_LINE.store(line, Ordering::Release);
    Ok(line)
}

/// Buffer de SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX: o tamanho exigido
/// cresce sempre; só grava o que cabe. Os registros são escritos pelas vistas
/// tipadas de `SystemLogicalProcessorInformationEx` (todos começam alinhados
/// a 8: os tamanhos são 0x30, 0x38 e 0x50).
struct Output {
    buffer: u64,
    available: u64,
    used: u64,
    status: u32,
}

impl Output {
    fn reserve(&mut self, relationship: u32, size: u64) -> Option<&'static SystemLogicalProcessorInformationEx> {
        let at = self.used;
        self.used += size;
        if self.used > self.available {
            self.status = STATUS_INFO_LENGTH_MISMATCH;
            return None;
        }
        let address = self.buffer + at;
        guest::write_bytes(address, &alloc::vec![0u8; size as usize]);
        // SAFETY: `size` bytes do buffer do chamador (modo kernel), conferidos
        // contra o Length; só os campos dentro de `size` são tocados.
        let record = unsafe { SystemLogicalProcessorInformationEx::at(address) };
        record.relationship.set(relationship as i32);
        record.size.set(size as u32);
        Some(record)
    }

    /// PROCESSOR_RELATIONSHIP: Flags, EfficiencyClass 0, GroupCount e
    /// GroupMask[0] (grupo 0).
    fn processor(&mut self, relationship: u32, flags: u8, mask: u64) {
        let size = (GroupAffinity::SIZE * GROUP_COUNT as u64 + 0x27) & !7;
        if let Some(record) = self.reserve(relationship, size) {
            record.processor.flags.set(flags);
            record.processor.group_count.set(GROUP_COUNT);
            record.processor.group_mask[0].mask.set(mask);
        }
    }

    /// CACHE_RELATIONSHIP (0x38). O GroupCount fica 0, como o binário 19041
    /// grava (o campo entrou em SDKs posteriores).
    fn cache(&mut self, cache: &Cache, mask: u64) {
        if let Some(record) = self.reserve(relation::CACHE, 0x38) {
            let relation = &record.cache;
            relation.level.set(cache.level);
            relation.associativity.set(cache.associativity);
            relation.line_size.set(cache.line_size);
            relation.cache_size.set(cache.size);
            relation.type_.set(cache.kind as i32);
            relation.group_mask.mask.set(mask);
        }
    }

    /// NUMA_NODE_RELATIONSHIP (0x30), GroupCount 0 como no binário 19041.
    fn numa_node(&mut self, node: u32, mask: u64) {
        if let Some(record) = self.reserve(relation::NUMA_NODE, 0x30) {
            record.numa_node.node_number.set(node);
            record.numa_node.group_mask.mask.set(mask);
        }
    }

    /// GROUP_RELATIONSHIP com um PROCESSOR_GROUP_INFO por grupo ativo.
    fn group(&mut self, active_mask: u64) {
        let size = (ProcessorGroupInfo::SIZE * GROUP_COUNT as u64 + 0x27) & !7;
        if let Some(record) = self.reserve(relation::GROUP, size) {
            let relation = &record.group;
            relation.maximum_group_count.set(GROUP_COUNT);
            relation.active_group_count.set(GROUP_COUNT);
            let information = &relation.group_info[0];
            information.maximum_processor_count.set(smp::discovered_cpu_count() as u8);
            information.active_processor_count.set(smp::online_cpu_count() as u8);
            information.active_processor_mask.set(active_mask);
        }
    }
}

/// KeQueryLogicalProcessorRelationship. Por processador: pacote, núcleo e
/// caches (com o acúmulo "já visto" do binário, desligado quando um
/// processador é pedido); depois o nó NUMA e o registro de grupo (este só
/// para RelationGroup ou RelationAll sem processador). STATUS_INFO_LENGTH_MISMATCH
/// com o tamanho exigido; nada emitido = STATUS_UNSUCCESSFUL; processador
/// inválido = STATUS_INVALID_PARAMETER sem tocar o Length.
pub fn query_logical_processor_relationship(number: Option<&ProcessorNumber>, relationship: u32, information: u64, length: u64) -> Result<u32, KernelError> {
    let topology = Topology::capture()?;
    let count = topology.apic.len();
    let (first, last, specific) = if let Some(number) = number {
        let index = processor_group::processor_index_from_number(number);
        if index >= count as u64 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        (index as usize, index as usize, true)
    } else {
        (0, count - 1, false)
    };
    let all = relationship == relation::ALL;
    // SAFETY: o PULONG Length do chamador (modo kernel).
    let length = unsafe { Field::<u32>::at(length) };
    let mut output = Output { buffer: information, available: length.get() as u64, used: 0, status: STATUS_SUCCESS };
    let (mut packages, mut cores) = (0u64, 0u64);
    let mut cache_sets = [0u64; MAXIMUM_CACHES];
    for processor in first..=last {
        let own = 1u64 << processor;
        if relationship == relation::PACKAGE || all {
            let set = topology.package_set(processor);
            if specific || packages & set == 0 {
                packages |= set;
                output.processor(relation::PACKAGE, 0, set);
            }
        }
        if relationship == relation::CORE || all {
            let set = topology.core_set(processor);
            if specific || cores & set == 0 {
                cores |= set;
                // LTP_PC_SMT quando o núcleo tem outros processadores lógicos.
                output.processor(relation::CORE, (set != own) as u8, set);
            }
        }
        if relationship == relation::CACHE || all {
            for (index, cache) in topology.caches.iter().enumerate() {
                let set = topology.cache_set(processor, cache);
                if set == 0 {
                    output.cache(cache, own);
                    continue;
                }
                if !specific && cache_sets[index] & set != 0 {
                    continue;
                }
                cache_sets[index] |= set;
                output.cache(cache, set);
            }
        }
    }
    if relationship == relation::NUMA_NODE || all {
        let mask = topology.active_mask();
        if !specific || mask & (1u64 << first) != 0 {
            output.numa_node(0, mask);
        }
    }
    if relationship == relation::GROUP || (all && !specific) {
        output.group(topology.active_mask());
    }
    let mut status = output.status;
    if status == STATUS_SUCCESS && output.used == 0 {
        status = STATUS_UNSUCCESSFUL;
    }
    length.set(output.used as u32);
    Ok(status)
}
