//! Páginas independentes.
//!
//! VA contínua, PFNs independentes. Diferente do pool ou de faixas
//! contíguas, todo frame continua possuído por este mapeamento.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::paging::{self, MapOptions};
use super::{memory_map as map, pfn};
use crate::hal::cpu;
use crate::ntos::ke::{irql, smp};
use crate::rtl::{KernelError, SpinLock};

#[derive(Clone, Debug)]
struct Record {
    base: u64,
    size: u64,
    bytes: u64,
    preferred_node: u32,
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
    if irql::get_irql() > 1 {
        return Err(KernelError::new("independent pages operation above APC_LEVEL"));
    }
    Ok(())
}

fn ensure(state: &mut State) {
    if !state.initialized {
        state.initialized = true;
        state.ranges.push((map::KERNEL_INDEPENDENT_BASE, map::KERNEL_INDEPENDENT_TOP - map::KERNEL_INDEPENDENT_BASE));
    }
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

/// Tabelas destacadas, frames e VA continuam possuídos até todas as CPUs
/// confirmarem; uma confirmação falha deixa um dono que pode tentar de novo.
fn release(base: u64) -> Result<(), KernelError> {
    let mut record = STATE.lock().records.get(&base).cloned().ok_or_else(|| KernelError::new("independent pages record missing"))?;
    record.retiring = true;
    while record.unmapped < record.mapped {
        let va = record.base + record.unmapped * 4096;
        let ok = paging::unmap_page(va, MapOptions { deferred_tables: Some(&mut record.tables), ..Default::default() });
        if !ok {
            STATE.lock().records.insert(base, record);
            return Err(KernelError::new("independent pages unmap failed"));
        }
        record.unmapped += 1;
    }
    STATE.lock().records.insert(base, record.clone());
    cpu::reload_cr3();
    smp::flush_remote_tlb(false)?;
    for &frame in record.tables.iter().chain(record.frames.iter()) {
        if !pfn::free_page(frame) {
            return Err(KernelError::new("independent pages lost PFN ownership"));
        }
    }
    let mut state = STATE.lock();
    state.records.remove(&base);
    return_range(&mut state, record.base, record.size);
    Ok(())
}

pub fn allocate(bytes: u64, preferred_node: u32) -> Result<u64, KernelError> {
    level()?;
    if bytes == 0 || bytes > map::KERNEL_INDEPENDENT_TOP - map::KERNEL_INDEPENDENT_BASE {
        return Ok(0);
    }
    let size = (bytes + 4095) & !4095;
    let count = size / 4096;
    let base = {
        let mut state = STATE.lock();
        ensure(&mut state);
        let Some(index) = state.ranges.iter().position(|&(_, length)| length >= size) else { return Ok(0) };
        if count > pfn::total_count() {
            return Ok(0);
        }
        // Um só nó NUMA: a preferência é consultiva; contiguidade não é exigida.
        let range = &mut state.ranges[index];
        let base = range.0;
        range.0 += size;
        range.1 -= size;
        if range.1 == 0 {
            state.ranges.remove(index);
        }
        state.records.insert(base, Record { base, size, bytes, preferred_node, frames: Vec::new(), mapped: 0, unmapped: 0, tables: Vec::new(), retiring: false });
        base
    };
    for index in 0..count {
        let frame = pfn::alloc_page();
        if frame == 0 {
            release(base)?;
            return Ok(0);
        }
        STATE.lock().records.get_mut(&base).unwrap().frames.push(frame);
        // Proteção original 4: supervisor, RW, WB, NX; sem garantia de zero.
        if !paging::map_page(base + index * 4096, frame, 3, MapOptions { nx: true, ..Default::default() }) {
            release(base)?;
            return Ok(0);
        }
        STATE.lock().records.get_mut(&base).unwrap().mapped += 1;
    }
    Ok(base)
}

fn owns_mapping(record: &Record) -> bool {
    (0..record.mapped).all(|index| {
        paging::query_page(record.base + index * 4096, true)
            .is_some_and(|page| page.page_size == 4096 && page.physical_address == record.frames[index as usize])
    })
}

pub fn free(address: u64) -> Result<(), KernelError> {
    level()?;
    let record = STATE.lock().records.get(&address).cloned();
    let record = record.ok_or_else(|| KernelError::new("independent pages address is not an owned allocation"))?;
    if !record.retiring && !owns_mapping(&record) {
        return Err(KernelError::new("independent pages mapping no longer belongs to its owner"));
    }
    release(address)
}

/// MmFreeIndependentPages: usa a PTE que contém `address` e arredonda o
/// tamanho de forma independente; pode liberar o interior de um mapeamento.
pub fn free_pages(address: u64, bytes: u64) -> Result<(), KernelError> {
    level()?;
    let base = address & !4095;
    let size = (bytes + 4095) & !4095;
    let end = base.wrapping_add(size);
    if bytes == 0 || base < map::KERNEL_INDEPENDENT_BASE || end > map::KERNEL_INDEPENDENT_TOP {
        return Err(KernelError::new("independent pages invalid release range"));
    }
    {
        let state = STATE.lock();
        if let Some(pending) = state.records.get(&base) {
            if pending.retiring && pending.size == size {
                drop(state);
                return release(base);
            }
        }
    }
    let fragment = |record: &Record, start: u64, stop: u64| -> Record {
        let first = ((start - record.base) / 4096) as usize;
        let count = ((stop - start) / 4096) as usize;
        let requested_end = record.base + record.bytes;
        Record {
            base: start,
            size: stop - start,
            bytes: requested_end.min(stop) - start,
            preferred_node: record.preferred_node,
            frames: record.frames[first..first + count].to_vec(),
            mapped: count as u64,
            unmapped: 0,
            tables: Vec::new(),
            retiring: false,
        }
    };
    let mut consumed = Vec::new();
    let mut survivors = Vec::new();
    let mut frames = Vec::new();
    {
        let state = STATE.lock();
        let mut at = base;
        while at < end {
            let record = state
                .records
                .values()
                .find(|record| at >= record.base && at < record.base + record.size)
                .filter(|record| !record.retiring && record.mapped == record.frames.len() as u64)
                .ok_or_else(|| KernelError::new("independent pages release range is not fully owned"))?;
            let stop = (record.base + record.size).min(end);
            let mut va = at;
            while va < stop {
                let frame = record.frames[((va - record.base) / 4096) as usize];
                let owned = paging::query_page(va, true).is_some_and(|page| page.page_size == 4096 && page.physical_address == frame);
                if !owned {
                    return Err(KernelError::new("independent pages mapping no longer belongs to its owner"));
                }
                frames.push(frame);
                va += 4096;
            }
            if record.base < at {
                survivors.push(fragment(record, record.base, at));
            }
            if stop < record.base + record.size {
                survivors.push(fragment(record, stop, record.base + record.size));
            }
            consumed.push(record.base);
            at = stop;
        }
    }
    // Prepara todos os descritores antes de mudar o mapa de posse vivo.
    let preferred_node = STATE.lock().records[&consumed[0]].preferred_node;
    let retiring = Record { base, size, bytes: size, preferred_node, mapped: frames.len() as u64, frames, unmapped: 0, tables: Vec::new(), retiring: false };
    {
        let mut state = STATE.lock();
        for record in consumed {
            state.records.remove(&record);
        }
        for record in survivors {
            state.records.insert(record.base, record);
        }
        state.records.insert(base, retiring);
    }
    release(base)
}

#[derive(Clone, Debug)]
pub struct IndependentInfo {
    pub base: u64,
    pub bytes: u64,
    pub size: u64,
    pub preferred_node: u32,
    pub frames: Vec<u64>,
    pub retiring: bool,
}

pub fn info(address: u64) -> Option<IndependentInfo> {
    STATE.lock().records.get(&address).map(|record| IndependentInfo {
        base: record.base,
        bytes: record.bytes,
        size: record.size,
        preferred_node: record.preferred_node,
        frames: record.frames.clone(),
        retiring: record.retiring,
    })
}

pub fn count() -> usize {
    STATE.lock().records.len()
}
