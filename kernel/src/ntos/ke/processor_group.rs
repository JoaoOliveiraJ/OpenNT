//! Processadores, grupos e nós vistos pelos drivers.
//!
//! O código dos drivers roda no processador de boot (KeGetCurrentProcessorNumber
//! é 0). Os processadores ativos são os da MADT que subiram, todos no grupo 0
//! e no nó NUMA 0 (sem SRAT). KeNumberProcessors é uma célula u32 gravada no
//! primeiro acesso, depois do SMP.

use core::sync::atomic::{AtomicU64, Ordering};

use super::smp;
use crate::ntos::inc::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::ntos::inc::types::{Field, GroupAffinity, NtStruct, ProcessorNumber};
use crate::ntos::mm::guest_memory as guest;

/// ALL_PROCESSOR_GROUPS.
const ALL_PROCESSOR_GROUPS: u32 = 0xFFFF;

/// KeNumberProcessors: célula u32 gravada no primeiro acesso (depois do SMP).
static NUMBER_PROCESSORS: AtomicU64 = AtomicU64::new(0);

/// KeNumberProcessors: endereço da célula do export de dados.
pub fn number_processors_cell() -> u64 {
    let current = NUMBER_PROCESSORS.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let pointer = guest::alloc_bytes(4);
    // SAFETY: célula recém-alocada do export de dados.
    unsafe { Field::<u32>::at(pointer) }.set(smp::online_cpu_count() as u32);
    match NUMBER_PROCESSORS.compare_exchange(0, pointer, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => pointer,
        Err(existing) => {
            guest::free_bytes(pointer);
            existing
        }
    }
}

/// Bit N = processador N ativo (o BSP sempre).
pub fn active_mask() -> u64 {
    let mut mask = 1u64;
    for slot in 0..smp::ap_slot_count().min(63) as u32 {
        mask |= 1u64 << (slot + 1);
    }
    mask
}

/// GROUP_AFFINITY zerada com a máscara pedida.
pub fn write_group_affinity(pointer: u64, mask: u64) {
    // SAFETY: PGROUP_AFFINITY de saída do chamador.
    let affinity = unsafe { GroupAffinity::at(pointer) };
    affinity.mask.set(mask);
    affinity.group.set(0);
    for reserved in &affinity.reserved {
        reserved.set(0);
    }
}

/// KeGetCurrentProcessorNumber: todo código de driver roda no BSP.
pub fn current_processor_number() -> u32 {
    0
}

/// KeGetCurrentProcessorNumberEx: PROCESSOR_NUMBER do BSP (grupo 0, número 0)
/// na saída opcional; devolve o índice 0.
pub fn current_processor_number_ex(processor_number: u64) -> u32 {
    if processor_number != 0 {
        write_processor_number(processor_number, 0);
    }
    0
}

/// PROCESSOR_NUMBER de saída do chamador: grupo 0, número e Reserved zero.
fn write_processor_number(pointer: u64, number: u8) {
    // SAFETY: PPROCESSOR_NUMBER de saída do chamador.
    let target = unsafe { ProcessorNumber::at(pointer) };
    target.group.set(0);
    target.number.set(number);
    target.reserved.set(0);
}

/// KeQueryActiveProcessorCount.
pub fn active_processor_count() -> u64 {
    smp::online_cpu_count() as u64
}

/// KeQueryActiveProcessorCountEx: CPUs online; grupo inexistente devolve 0.
pub fn active_processor_count_ex(group: u32) -> u64 {
    if group != 0 && group != ALL_PROCESSOR_GROUPS {
        return 0;
    }
    smp::online_cpu_count() as u64
}

/// KeQueryActiveProcessors: bit N = CPU N online (o BSP sempre), em 32 bits
/// estendidos com sinal.
pub fn active_processors() -> u64 {
    let mut mask = 1u32;
    for slot in 0..smp::ap_slot_count() as u32 {
        mask |= 1u32.wrapping_shl(slot + 1);
    }
    mask as i32 as i64 as u64
}

/// KeGetProcessorNumberFromIndex: PROCESSOR_NUMBER (grupo 0) do índice na
/// saída opcional; índice fora dos processadores online é inválido.
/// Devolve o NTSTATUS.
pub fn processor_number_from_index(index: u64, processor_number: u64) -> u32 {
    if index >= smp::online_cpu_count() as u64 {
        return STATUS_INVALID_PARAMETER;
    }
    if processor_number != 0 {
        write_processor_number(processor_number, index as u8);
    }
    STATUS_SUCCESS
}

/// KeQueryMaximumProcessorCount: CPUs da MADT.
pub fn maximum_processor_count() -> u64 {
    smp::discovered_cpu_count() as u64
}

/// KeQueryMaximumProcessorCountEx: CPUs da MADT no grupo 0 (ou ALL_GROUPS).
pub fn maximum_processor_count_ex(group: u32) -> u64 {
    if group != 0 && group != ALL_PROCESSOR_GROUPS {
        return 0;
    }
    smp::discovered_cpu_count() as u64
}

/// KeQueryActiveGroupCount / KeQueryMaximumGroupCount: só o grupo 0.
pub fn group_count() -> u64 {
    1
}

/// KeQueryGroupAffinity: os processadores ativos no grupo 0; outro grupo, 0.
pub fn group_affinity(group: u16) -> u64 {
    if group == 0 { active_mask() } else { 0 }
}

/// KeGetCurrentNodeNumber / KeQueryHighestNodeNumber: sem SRAT, tudo no nó 0.
pub fn node_number() -> u64 {
    0
}

/// KeQueryNodeActiveAffinity: nó 0 com todos os processadores ativos; outro
/// nó volta vazio. As duas saídas são opcionais.
pub fn query_node_active_affinity(node: u16, affinity: u64, count: u64) {
    let (mask, processors) = if node == 0 { (active_mask(), smp::online_cpu_count() as u16) } else { (0, 0) };
    if affinity != 0 {
        write_group_affinity(affinity, mask);
    }
    if count != 0 {
        // SAFETY: PUSHORT Count opcional do chamador.
        unsafe { Field::<u16>::at(count) }.set(processors);
    }
}

/// KeQueryNodeMaximumProcessorCount: CPUs da MADT no nó 0; outro nó, 0.
pub fn node_maximum_processor_count(node: u16) -> u64 {
    if node == 0 { smp::discovered_cpu_count() as u64 } else { 0 }
}
