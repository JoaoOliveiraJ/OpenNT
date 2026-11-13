//! RAM admitida por este boot.
//!
//! RAM de firmware habilitada abaixo do limite do mapa direto do stage2.
//! Reservas de kernel/heap/imagens/PFN continuam sendo RAM física; reservas
//! de firmware e MMIO não. Uma consulta nunca relê o E820 mutável.

use alloc::vec::Vec;

use super::memory_map as map;
use crate::hal::physical;
use crate::rtl::{KernelError, SpinLock};

static ADMITTED: SpinLock<Option<Vec<(u64, u64)>>> = SpinLock::new(None);

pub fn init() -> Result<(), KernelError> {
    let count = physical::read16(map::E820_COUNT_PHYS) as u64;
    if count == 0 || count > map::E820_MAX_ENTRIES {
        return Err(KernelError::new("Invalid E820 table for physical memory initialization"));
    }
    let mut usable = Vec::new();
    let mut reserved = Vec::new();
    for index in 0..count {
        let at = map::E820_TABLE_PHYS + index * 24;
        if physical::read32(at + 20) & 1 == 0 {
            continue;
        }
        let base = physical::read64(at);
        let length = physical::read64(at + 8);
        let end = base.saturating_add(length);
        if length == 0 || base >= map::PHYSICAL_MEMORY_LIMIT {
            continue;
        }
        let range = (base, end.min(map::PHYSICAL_MEMORY_LIMIT));
        if physical::read32(at + 16) == 1 { usable.push(range) } else { reserved.push(range) }
    }
    let mut candidates = usable;
    for &(low, high) in &reserved {
        let mut remaining = Vec::new();
        for &(base, top) in &candidates {
            if high <= base || low >= top {
                remaining.push((base, top));
            } else {
                if base < low {
                    remaining.push((base, low));
                }
                if top > high {
                    remaining.push((high, top));
                }
            }
        }
        candidates = remaining;
    }
    // União antes do alinhamento: descritores parciais adjacentes podem
    // cobrir juntos um frame inteiro. Bytes reservados excluem o frame tocado.
    candidates.sort();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (base, top) in candidates {
        match merged.last_mut() {
            Some(last) if base <= last.1 => last.1 = last.1.max(top),
            _ => merged.push((base, top)),
        }
    }
    let page = map::PAGE_SIZE;
    let admitted = merged
        .into_iter()
        .map(|(base, top)| (base.div_ceil(page) * page, top / page * page))
        .filter(|(base, top)| base < top)
        .collect();
    *ADMITTED.lock() = Some(admitted);
    Ok(())
}

pub fn ranges() -> Vec<(u64, u64)> {
    ADMITTED.lock().clone().expect("Physical memory layout is not initialized")
}

/// Só autoriza cópias em bloco sobre RAM admitida pelo E820.
pub fn contains_ram_range(physical_address: u64, byte_count: u64) -> bool {
    let admitted = ADMITTED.lock();
    let Some(ranges) = admitted.as_ref() else { return false };
    if byte_count == 0 {
        return false;
    }
    let Some(end) = physical_address.checked_add(byte_count) else { return false };
    ranges.iter().any(|&(base, top)| physical_address >= base && end <= top)
}

// ---- Mm64BitPhysicalAddress (mm-physical-memory) ----------------------------
//
// BOOLEAN exportado: no x64 o MiMemoryLicense grava 1 incondicionalmente. A
// célula é a entrada "Mm64BitPhysicalAddress" de `kernel_data_layout` (valor
// inicial 1); o PE do kernel e a tabela de exports publicam os mesmos bytes.

/// Endereço da célula Mm64BitPhysicalAddress (export de dados).
pub fn sixty_four_bit_physical_address_cell() -> u64 {
    super::kernel_data::required_address("Mm64BitPhysicalAddress")
}
