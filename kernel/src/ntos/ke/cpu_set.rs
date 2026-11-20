//! Os conjuntos de CPU (ntoskrnl 19041): o KeQueryCpuSetInformation
//! (0x7c6ec8) da SystemCpuSetInformation (classe 175 do
//! NtQuerySystemInformationEx).
//!
//! - O tamanho exigido, 0x20 vezes os conjuntos (um por processador ativo,
//!   KiTotalCpuSetCount), vai ao ReturnLength antes de tudo; uma saída menor
//!   é STATUS_BUFFER_TOO_SMALL. Senão a saída é zerada e recebe um
//!   SYSTEM_CPU_SET_INFORMATION por processador, grupo a grupo.
//! - Cada um: Size 0x20, Type CpuSetInformation (0), Id 0x100 + (grupo << 16)
//!   + índice no grupo, Group, e os dados do KiCpuSetData que o
//!   KiConfigureCpuSetSchedulingInformation (0x3b605c) grava da KPRCB:
//!   LogicalProcessorIndex (o índice no grupo), CoreIndex (o primeiro bit do
//!   CoreProcessorSet), LastLevelCacheIndex (o primeiro bit da última
//!   CacheProcessorMask não vazia das cinco), NumaNodeIndex (o primeiro
//!   processador do nó), EfficiencyClass (ArchitecturalEfficiencyClass) e
//!   SchedulingClass (PerformanceSchedulingClass) do PROCESSOR_POWER_STATE, e
//!   o AllocationTag do KeSetTagCpuSets.
//! - As flags: Parked para quem está fora de KiNonParkedCpuSets; fora de
//!   KiSystemAllowedCpuSets, Allocated | RealTime (e
//!   AllocatedToTargetProcess quando o conjunto padrão do processo alvo o
//!   tem). O OpenNT não estaciona processadores, não reserva conjuntos para o
//!   sistema e não tem conjuntos por processo nem marcas: as flags e o
//!   AllocationTag ficam zero, e o OpenNT tem um nó só (NumaNodeIndex 0).

use alloc::vec::Vec;

use crate::ntos::inc::types::extra_ps_user::SystemCpuSetInformation;
use crate::ntos::inc::types::NtStruct;
use crate::ntos::ke::{pcr, processor_group, smp};
use crate::ntos::mm::guest_memory as guest;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// O bit fixo do Id de um conjunto.
const CPU_SET_ID_BASE: u32 = 0x100;

/// Os conjuntos de CPU, montados num bloco de kernel.
fn build() -> Vec<u8> {
    let count = smp::online_cpu_count() as u32;
    let size = SystemCpuSetInformation::SIZE as u32;
    let block = guest::alloc_bytes((count * size) as u64);
    if block == 0 {
        return Vec::new();
    }
    for index in 0..count {
        // SAFETY: a entrada `index` do bloco zerado recém-alocado.
        let entry = unsafe { SystemCpuSetInformation::at(block + (index * size) as u64) };
        entry.size.set(size);
        entry.type_.set(0);
        entry.id.set(CPU_SET_ID_BASE | index);
        entry.group.set(0);
        entry.logical_processor_index.set(index as u8);
        if let Some(prcb) = pcr::processor_block(index) {
            let core = prcb.core_processor_set.get();
            entry.core_index.set(if core != 0 { core.trailing_zeros() as u8 } else { 0 });
            let last_cache = prcb.cache_processor_mask.iter().take(5).map(|cell| cell.get()).filter(|&mask| mask != 0).last();
            if let Some(mask) = last_cache {
                entry.last_level_cache_index.set(mask.trailing_zeros() as u8);
            }
            entry.efficiency_class.set(prcb.power_state.architectural_efficiency_class.get());
            entry.scheduling_class.set(prcb.power_state.performance_scheduling_class.get());
        }
        entry.numa_node_index.set(0);
        entry.all_flags.set(0);
        entry.allocation_tag.set(0);
    }
    let bytes = guest::read_bytes(block, (count * size) as usize);
    guest::free_bytes(block);
    bytes
}

/// KeQueryCpuSetInformation(Buffer, Length, &ReturnLength, Process): o
/// NTSTATUS e o tamanho exigido. `write` copia para a saída do chamador
/// (sondada no modo usuário); uma escrita recusada é
/// STATUS_ACCESS_VIOLATION. O processo alvo só pesaria na flag
/// AllocatedToTargetProcess, que o OpenNT não tem.
pub fn query(output: u64, length: u32, write: &mut dyn FnMut(u64, &[u8]) -> bool) -> (u32, u32) {
    let required = processor_group::active_processor_count_ex(0) as u32 * SystemCpuSetInformation::SIZE as u32;
    if length < required {
        return (STATUS_BUFFER_TOO_SMALL, required);
    }
    let data = build();
    if data.len() != required as usize {
        return (STATUS_INSUFFICIENT_RESOURCES, required);
    }
    if !write(output, &data) {
        return (STATUS_ACCESS_VIOLATION, required);
    }
    (0, required)
}
