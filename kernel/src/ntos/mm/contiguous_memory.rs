//! Faixas fisicamente contíguas.
//!
//! Um dono para a faixa física e sua reserva de VA de kernel. `allocate` é a
//! primitiva do MM; `allocate_default` implementa o contrato observado de
//! MmAllocateContiguousMemory sobre o mesmo backing e tempo de vida.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::paging::{self, MapOptions};
use super::{kernel_pool, memory_map as map, pfn};
use crate::ntos::mm::section::cache as section_cache;
use crate::hal::cpu;
use crate::ntos::ke::{bugcheck, irql, smp};
use crate::rtl::{KernelError, SpinLock};

#[derive(Clone, Debug)]
struct Record {
    base: u64,
    size: u64,
    bytes: u64,
    cache: u32,
    nx: bool,
    physical: u64,
    frames: Vec<u64>,
    mapped: u64,
    unmapped: u64,
    tables: Vec<u64>,
    retiring: bool,
}

struct State {
    records: BTreeMap<u64, Record>,
    ranges: Vec<(u64, u64)>,
    initialized: bool,
}

static STATE: SpinLock<State> = SpinLock::new(State { records: BTreeMap::new(), ranges: Vec::new(), initialized: false });

fn level() -> Result<(), KernelError> {
    if irql::get_irql() > 2 {
        return Err(KernelError::new("contiguous memory operation above DISPATCH_LEVEL"));
    }
    Ok(())
}

fn return_range(state: &mut State, base: u64, size: u64) {
    state.ranges.push((base, size));
    state.ranges.sort();
    let mut index = 0;
    while index + 1 < state.ranges.len() {
        if state.ranges[index].0 + state.ranges[index].1 == state.ranges[index + 1].0 {
            state.ranges[index].1 += state.ranges[index + 1].1;
            state.ranges.remove(index + 1);
        } else {
            index += 1;
        }
    }
}

/// Frames, tabelas destacadas e VA continuam possuídos até as confirmações.
fn release(base: u64) -> Result<(), KernelError> {
    let mut record = STATE.lock().records.get(&base).cloned().ok_or_else(|| KernelError::new("contiguous record missing"))?;
    record.retiring = true;
    while record.unmapped < record.mapped {
        let va = record.base + record.unmapped * 4096;
        if !paging::unmap_page(va, MapOptions { deferred_tables: Some(&mut record.tables), ..Default::default() }) {
            STATE.lock().records.insert(base, record);
            return Err(KernelError::new("contiguous memory unmap failed"));
        }
        record.unmapped += 1;
    }
    STATE.lock().records.insert(base, record.clone());
    if record.cache != 1 {
        section_cache::restore(&record.frames)?;
        cpu::flush_caches();
    }
    cpu::reload_cr3();
    smp::flush_remote_tlb(record.cache != 1)?;
    for &frame in record.tables.iter().chain(record.frames.iter()) {
        if !pfn::free_page(frame) {
            return Err(KernelError::new("contiguous memory lost PFN ownership"));
        }
    }
    let mut state = STATE.lock();
    state.records.remove(&base);
    return_range(&mut state, record.base, record.size);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct ContiguousOptions {
    /// 0 = não cacheado, 1 = cacheado, 2 = write-combine.
    pub cache: u32,
    pub highest_pfn: u64,
    pub lowest_pfn: u64,
    pub boundary_pages: u64,
    pub nx: bool,
}

impl Default for ContiguousOptions {
    fn default() -> Self {
        Self { cache: 1, highest_pfn: 0xF_FFFF_FFFF, lowest_pfn: 0, boundary_pages: 0, nx: true }
    }
}

pub fn allocate(bytes: u64, options: ContiguousOptions) -> Result<u64, KernelError> {
    level()?;
    if bytes == 0 || bytes > map::KERNEL_CONTIGUOUS_TOP - map::KERNEL_CONTIGUOUS_BASE || options.cache > 2 {
        return Ok(0);
    }
    let size = (bytes + 4095) & !4095;
    let count = size / 4096;
    {
        let mut state = STATE.lock();
        if !state.initialized {
            state.initialized = true;
            state.ranges.push((map::KERNEL_CONTIGUOUS_BASE, map::KERNEL_CONTIGUOUS_TOP - map::KERNEL_CONTIGUOUS_BASE));
        }
        if !state.ranges.iter().any(|&(_, length)| length >= size) {
            return Ok(0);
        }
    }
    let physical = pfn::alloc_contiguous(count, 1, options.highest_pfn, options.lowest_pfn, options.boundary_pages);
    if physical == 0 {
        return Ok(0);
    }
    let base = {
        let mut state = STATE.lock();
        let index = state.ranges.iter().position(|&(_, length)| length >= size).unwrap();
        let range = &mut state.ranges[index];
        let base = range.0;
        range.0 += size;
        range.1 -= size;
        if range.1 == 0 {
            state.ranges.remove(index);
        }
        let frames = (0..count).map(|index| physical + index * 4096).collect();
        state.records.insert(
            base,
            Record { base, size, bytes, cache: options.cache, nx: options.nx, physical, frames, mapped: 0, unmapped: 0, tables: Vec::new(), retiring: false },
        );
        base
    };
    let frames: Vec<u64> = (0..count).map(|index| physical + index * 4096).collect();
    let protection = match options.cache {
        0 => 0x200,
        2 => 0x400,
        _ => 0,
    };
    let outcome = (|| -> Result<bool, KernelError> {
        if !section_cache::set(&frames, protection)? {
            return Ok(false);
        }
        let cache_flags = match options.cache {
            0 => 0x18,
            2 => 0x80,
            _ => 0,
        };
        for (index, &frame) in frames.iter().enumerate() {
            if !paging::map_page(base + index as u64 * 4096, frame, 3 | cache_flags, MapOptions { nx: options.nx, ..Default::default() }) {
                return Ok(false);
            }
            STATE.lock().records.get_mut(&base).unwrap().mapped += 1;
        }
        Ok(true)
    })();
    match outcome {
        Ok(true) => Ok(base),
        Ok(false) => {
            release(base)?;
            Ok(0)
        }
        Err(error) => {
            release(base)?;
            Err(error)
        }
    }
}

/// Os dois argumentos são valores de 64 bits; o wrapper descarta os 12 bits
/// baixos e limita ao PFN máximo inclusivo de 36 bits. Proteção original 6:
/// cacheado e executável (sem HVCI).
pub fn allocate_default(bytes: u64, highest: u64) -> Result<u64, KernelError> {
    let highest_pfn = (highest >> 12).min(0xF_FFFF_FFFF);
    allocate(bytes, ContiguousOptions { cache: 1, highest_pfn, nx: false, ..Default::default() })
}

/// Wrapper de cache: 1 -> PAGE_EXECUTE_READWRITE, 2 -> READWRITE|WRITECOMBINE;
/// outros valores -> READWRITE|NOCACHE.
pub fn allocate_specify_cache(bytes: u64, lowest: u64, highest: u64, boundary: u64, cache_type: u32) -> Result<u64, KernelError> {
    level()?;
    if boundary != 0 && (boundary & 4095 != 0 || !boundary.is_power_of_two()) {
        return Ok(0);
    }
    let lowest_pfn = (lowest >> 12) + (lowest & 4095 != 0) as u64;
    let highest_pfn = (highest >> 12).min(0xF_FFFF_FFFF);
    if lowest_pfn > highest_pfn {
        return Ok(0);
    }
    let cache = match cache_type {
        1 => 1,
        2 => 2,
        _ => 0,
    };
    allocate(bytes, ContiguousOptions { cache, nx: cache != 1, lowest_pfn, highest_pfn, boundary_pages: boundary >> 12 })
}

pub fn free(address: u64) -> Result<(), KernelError> {
    level()?;
    // A rota NonPagedPool medida chama ExFreePoolWithTag(base, 0).
    if kernel_pool::info(address).is_some_and(|pool| !pool.paged) {
        return kernel_pool::free(address, None);
    }
    if !(map::KERNEL_CONTIGUOUS_BASE..map::KERNEL_CONTIGUOUS_TOP).contains(&address) {
        bugcheck::bug_check_ex(0xC2, 0x62, address, 0, 0);
    }
    if address & 4095 != 0 {
        bugcheck::bug_check_ex(0xC2, 0x61, address, 0, 0);
    }
    let Some(record) = STATE.lock().records.get(&address).cloned() else {
        bugcheck::bug_check_ex(0xC2, 0x60, address, 0, 0);
    };
    if !record.retiring {
        for index in 0..record.mapped {
            let owned = paging::query_page(address + index * 4096, true)
                .is_some_and(|page| page.page_size == 4096 && page.physical_address == record.frames[index as usize]);
            if !owned {
                return Err(KernelError::new("contiguous allocation mapping no longer belongs to its owner"));
            }
        }
    }
    release(address)
}

#[derive(Clone, Debug)]
pub struct ContiguousInfo {
    pub base: u64,
    pub bytes: u64,
    pub size: u64,
    pub physical: u64,
    pub cache: u32,
    pub nx: bool,
    pub retiring: bool,
}

pub fn info(address: u64) -> Option<ContiguousInfo> {
    STATE.lock().records.get(&address).map(|record| ContiguousInfo {
        base: record.base,
        bytes: record.bytes,
        size: record.size,
        physical: record.physical,
        cache: record.cache,
        nx: record.nx,
        retiring: record.retiring,
    })
}

pub fn count() -> usize {
    STATE.lock().records.len()
}

// ---- MmAllocateContiguousNodeMemory (mm-physical-memory) --------------------
//
// Contrato do ntoskrnl 19041: LowestPfn = ceil(Lowest / 4 KiB); Boundary com
// bits abaixo de 4 KiB -> NULL; PAGE_GUARD -> NULL; MiMakeProtectionMask
// inválida -> NULL; (mask & 5) != 4 (não leitura/escrita) -> NULL; executável
// com PAGE_NOCACHE -> NULL; HighestPfn = min(Highest >> 12, 0xFFFFFFFFF);
// LowestPfn > HighestPfn -> NULL; depois MiAllocateContiguousMemory(bytes,
// lowPfn, highPfn, Boundary >> 12, mask, nó). O cache vem de `mask >> 3`
// (0 cacheado, 1 não cacheado, 3 write-combine). O nó preferido é aceito e
// ignorado (KeNumberNodes = 1, o mesmo que o NT faz numa máquina de um nó).
// A liberação é a de MmFreeContiguousMemory (`free`).

/// MmAllocateContiguousNodeMemory: a VA de kernel ou 0.
pub fn allocate_node(bytes: u64, lowest: u64, highest: u64, boundary: u64, protect: u32, _preferred_node: u32) -> Result<u64, KernelError> {
    use super::protection;
    let lowest_pfn = (lowest >> 12) + (lowest & 0xFFF != 0) as u64;
    if boundary & 0xFFF != 0 || protect & protection::PAGE_GUARD != 0 {
        return Ok(0);
    }
    let Some(mask) = protection::make_mask(protect) else { return Ok(0) };
    if mask & 5 != 4 {
        return Ok(0);
    }
    if mask & 2 != 0 {
        match mask >> 3 {
            1 => return Ok(0),
            3 if mask & 7 != 0 => return Ok(0),
            _ => {}
        }
    }
    let highest_pfn = (highest >> 12).min(0xF_FFFF_FFFF);
    if lowest_pfn > highest_pfn {
        return Ok(0);
    }
    let cache = match mask >> 3 {
        1 => 0,
        3 => 2,
        _ => 1,
    };
    allocate(bytes, ContiguousOptions { cache, highest_pfn, lowest_pfn, boundary_pages: boundary >> 12, nx: mask & 2 == 0 })
}
