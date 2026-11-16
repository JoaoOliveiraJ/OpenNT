//! Topologia lógica dos processadores: núcleos, pacotes e caches
//! (KeQueryLogicalProcessorRelationship, o SystemLogicalProcessorInformation
//! do KeBuildLogicalProcessorSystemInformation e
//! KeGetRecommendedSharedDataAlignment).
//!
//! Os descritores de cache vêm do KiSetStandardizedCacheInformation (folha
//! 4, ou 0x8000001D na AMD com TopoExt) ou do KiSetCacheInformationAmd
//! legado (0x80000005/0x80000006); `processor_identity` os grava na KPRCB de
//! cada processador, com os conjuntos que o KiInitializeKernel monta
//! (PackageProcessorSet, CoreProcessorSet, CacheProcessorMask). As consultas
//! leem essas KPRCBs, como o binário. Um grupo e um nó NUMA (sem SRAT nem
//! mais de 64 CPUs); EfficiencyClass 0 (núcleos homogêneos).

use alloc::vec::Vec;

use super::processor_identity::vendor;
use super::{pcr, processor_group, processor_identity, smp};
use crate::hal::cpu;
use crate::ntos::inc::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};
use crate::ntos::inc::types::{CacheDescriptor, Field, GroupAffinity, Kprcb, NtStruct, ProcessorGroupInfo, ProcessorNumber, SystemLogicalProcessorInformationEx};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
/// KiMaximumGroups = KiActiveGroups = KeNumberNodes no OpenNT.
const GROUP_COUNT: u16 = 1;
/// KPRCB.Cache[5].
const MAXIMUM_CACHES: usize = 5;
/// sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION).
const LEGACY_RECORD_SIZE: u64 = 0x20;

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
pub(super) enum Sharing {
    /// Máscara 0 na KPRCB: o registro sai só com o próprio processador.
    Own,
    /// Processadores cujo InitialApicId coincide sob a máscara.
    ApicMask(u32),
    /// L3 AMD legado (família <= 0x15): o pacote inteiro.
    Package,
}

/// CACHE_DESCRIPTOR mais o compartilhamento.
#[derive(Clone, Copy)]
pub(super) struct Cache {
    pub(super) level: u8,
    pub(super) associativity: u8,
    pub(super) line_size: u16,
    pub(super) size: u32,
    pub(super) kind: u32,
    pub(super) sharing: Sharing,
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

/// KiSetCacheInformation: AMD por 0x8000001D (TopoExt) ou legado; Intel e
/// Centaur pela folha 4 quando 3 <= máximo <= 0x7FFFFFFF
/// (KiSetCacheInformationIntel); outro fabricante é UNSUPPORTED_PROCESSOR
/// no NT, e aqui fica sem caches.
pub(super) fn cache_descriptors(cpu_vendor: u8, family: u16) -> Vec<Cache> {
    match cpu_vendor {
        vendor::AMD if cpu::cpuid(0x8000_0001)[2] & (1 << 22) != 0 => standardized_caches(0x8000_001D),
        vendor::AMD => amd_legacy_caches(family),
        vendor::INTEL | vendor::CENTAUR if (3..=0x7FFF_FFFF).contains(&cpu::cpuid(0)[0]) => standardized_caches(4),
        _ => Vec::new(),
    }
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

/// As KPRCBs dos processadores ativos, na ordem dos números
/// (KiProcessorBlock[0..KeNumberProcessors)).
fn processor_blocks() -> Vec<&'static Kprcb> {
    (0..smp::online_cpu_count() as u32).filter_map(pcr::processor_block).collect()
}

/// Os conjuntos de cada processador, lidos da KPRCB dele.
struct Topology {
    blocks: Vec<&'static Kprcb>,
}

impl Topology {
    fn capture() -> Topology {
        Topology { blocks: processor_blocks() }
    }

    /// KPRCB.GroupSetMember.
    fn own(&self, processor: usize) -> u64 {
        self.blocks[processor].group_set_member.get()
    }

    /// KPRCB.CoreProcessorSet.
    fn core_set(&self, processor: usize) -> u64 {
        self.blocks[processor].core_processor_set.get()
    }

    /// KPRCB.PackageProcessorSet, a parte do grupo 0.
    fn package_set(&self, processor: usize) -> u64 {
        self.blocks[processor].package_processor_set.bitmap[0].get()
    }

    /// KPRCB.Cache[0..CacheCount] com o CacheProcessorMask de cada um (0 =
    /// só o próprio processador).
    fn caches(&self, processor: usize) -> impl Iterator<Item = (&'static CacheDescriptor, u64)> {
        let prcb = self.blocks[processor];
        let count = (prcb.cache_count.get() as usize).min(MAXIMUM_CACHES);
        prcb.cache[..count].iter().zip(prcb.cache_processor_mask.iter().map(|mask| mask.get()))
    }

    fn active_mask(&self) -> u64 {
        self.blocks.iter().fold(0, |mask, prcb| mask | prcb.group_set_member.get())
    }
}

/// KiLargestCacheSize: 64 KB (o valor inicial no .data do ntoskrnl) ou o
/// maior Size dos caches L2+ unificados ou de dados de todos os
/// processadores (KiSetCacheInformation).
pub fn largest_cache_size() -> u32 {
    processor_identity::largest_cache_size()
}

/// KeGetRecommendedSharedDataAlignment: KeLargestCacheLine (64, ou o maior
/// LineSize dos caches L2+ unificados ou de dados).
pub fn recommended_shared_data_alignment() -> Result<u32, KernelError> {
    Ok(processor_identity::largest_cache_line())
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
    fn cache(&mut self, cache: &CacheDescriptor, mask: u64) {
        if let Some(record) = self.reserve(relation::CACHE, 0x38) {
            let relation = &record.cache;
            relation.level.set(cache.level.get());
            relation.associativity.set(cache.associativity.get());
            relation.line_size.set(cache.line_size.get());
            relation.cache_size.set(cache.size.get());
            relation.type_.set(cache.type_.get().0);
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
    let topology = Topology::capture();
    let count = topology.blocks.len();
    if count == 0 {
        return Ok(STATUS_UNSUCCESSFUL);
    }
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
        let own = topology.own(processor);
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
            for (index, (cache, set)) in topology.caches(processor).enumerate() {
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

/// KeBuildLogicalProcessorSystemInformation(Group, Buffer, Length,
/// ReturnLength): os SYSTEM_LOGICAL_PROCESSOR_INFORMATION (0x20 bytes) de um
/// grupo. Por processador do grupo: o pacote e o núcleo quando ele é o
/// processador de número mais alto do conjunto (KeFindFirstSetLeftGroupAffinity),
/// os caches com máscara (idem) e os sem máscara com o próprio
/// processador; depois um registro por nó com processadores no grupo. O
/// tamanho exigido cresce sempre; só grava o que cabe. Devolve (status,
/// tamanho exigido).
pub fn build_logical_processor_information(group: u16, buffer: u64, length: u32, write: &mut dyn FnMut(u64, &[u8]) -> bool) -> (u32, u32) {
    let blocks = processor_blocks();
    let highest = |mask: u64| (mask != 0).then(|| 63 - mask.leading_zeros());
    let mut used = 0u64;
    let mut status = STATUS_SUCCESS;
    let mut emit = |mask: u64, relationship: u32, payload: [u8; 16]| {
        used += LEGACY_RECORD_SIZE;
        if used > length as u64 {
            status = STATUS_INFO_LENGTH_MISMATCH;
            return;
        }
        let mut record = [0u8; LEGACY_RECORD_SIZE as usize];
        record[..8].copy_from_slice(&mask.to_le_bytes());
        record[8..12].copy_from_slice(&relationship.to_le_bytes());
        record[16..].copy_from_slice(&payload);
        if !write(buffer + used - LEGACY_RECORD_SIZE, &record) {
            status = 0xC000_0005;
        }
    };
    for prcb in blocks.iter().filter(|prcb| prcb.group.get() as u16 == group) {
        let number = prcb.number.get();
        let package = prcb.package_processor_set.bitmap[(group as usize).min(19)].get();
        if highest(package) == Some(number) {
            emit(package, relation::PACKAGE, [0; 16]);
        }
        let core = prcb.core_processor_set.get();
        if highest(core) == Some(number) {
            let mut payload = [0u8; 16];
            // ProcessorCore.Flags: LTP_PC_SMT quando o núcleo tem outros
            // processadores lógicos.
            payload[0] = (prcb.group_set_member.get() != core) as u8;
            emit(core, relation::CORE, payload);
        }
        let count = (prcb.cache_count.get() as usize).min(MAXIMUM_CACHES);
        for (cache, mask) in prcb.cache[..count].iter().zip(prcb.cache_processor_mask.iter().map(|mask| mask.get())) {
            let set = if mask == 0 { prcb.group_set_member.get() } else { mask };
            if mask != 0 && highest(mask) != Some(number) {
                continue;
            }
            let mut payload = [0u8; 16];
            payload[..12].copy_from_slice(&guest::read_bytes(cache.address(), 12));
            emit(set, relation::CACHE, payload);
        }
    }
    // KeNodeBlock: um nó, o 0, com os processadores ativos do grupo 0.
    let node_mask = if group == 0 { blocks.iter().fold(0, |mask, prcb| mask | prcb.group_set_member.get()) } else { 0 };
    if node_mask != 0 {
        emit(node_mask, relation::NUMA_NODE, [0; 16]);
    }
    (status, used as u32)
}
