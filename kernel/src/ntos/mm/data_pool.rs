//! Alocações de dados do kernel lastreadas por páginas.
//! Nenhum alias executável ou de usuário é publicado; cada alocação é dona
//! de seus mapeamentos e frames.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::paging::{self, MapOptions};
use super::{memory_map as map, pfn};
use crate::hal::physical;
use crate::rtl::{KernelError, SpinLock};

struct DataPool {
    free_ranges: Vec<(u64, u64)>, // (base, tamanho)
    allocations: BTreeMap<u64, (u64, Vec<u64>)>,
}

static POOL: SpinLock<DataPool> = SpinLock::new(DataPool { free_ranges: Vec::new(), allocations: BTreeMap::new() });

fn ensure_initialized(pool: &mut DataPool) {
    if pool.free_ranges.is_empty() && pool.allocations.is_empty() {
        pool.free_ranges = vec![(map::KERNEL_DATA_POOL_BASE, map::KERNEL_DATA_POOL_TOP - map::KERNEL_DATA_POOL_BASE)];
    }
}

fn return_range(pool: &mut DataPool, base: u64, size: u64) {
    pool.free_ranges.push((base, size));
    pool.free_ranges.sort();
    let mut index = 0;
    while index + 1 < pool.free_ranges.len() {
        if pool.free_ranges[index].0 + pool.free_ranges[index].1 == pool.free_ranges[index + 1].0 {
            pool.free_ranges[index].1 += pool.free_ranges[index + 1].1;
            pool.free_ranges.remove(index + 1);
        } else {
            index += 1;
        }
    }
}

/// Base da alocação, ou 0 sem espaço/frames.
pub fn alloc(bytes: u64) -> u64 {
    let size = bytes.div_ceil(4096).max(1) * 4096;
    let base = {
        let mut pool = POOL.lock();
        ensure_initialized(&mut pool);
        let Some(index) = pool.free_ranges.iter().position(|&(_, length)| length >= size) else { return 0 };
        let range = &mut pool.free_ranges[index];
        let base = range.0;
        range.0 += size;
        range.1 -= size;
        if range.1 == 0 {
            pool.free_ranges.remove(index);
        }
        base
    };
    let mut frames = Vec::new();
    let mut mapped = 0;
    let mut failed = false;
    while mapped < size {
        let frame = pfn::alloc_page();
        if frame == 0 {
            failed = true;
            break;
        }
        frames.push(frame);
        physical::zero(frame, 4096);
        let options = MapOptions { nx: true, ..Default::default() };
        if !paging::map_page(base + mapped, frame, paging::PAGE_PRESENT | paging::PAGE_RW, options) {
            failed = true;
            break;
        }
        mapped += 4096;
    }
    if failed {
        for offset in (0..mapped).step_by(4096) {
            paging::unmap_page(base + offset, MapOptions::default());
        }
        for frame in frames {
            pfn::free_page(frame);
        }
        return_range(&mut POOL.lock(), base, size);
        return 0;
    }
    POOL.lock().allocations.insert(base, (size, frames));
    base
}

pub fn free(base: u64) -> Result<(), KernelError> {
    let (size, frames) = POOL.lock().allocations.remove(&base).ok_or_else(|| KernelError::new("invalid kernel data free"))?;
    for offset in (0..size).step_by(4096) {
        paging::unmap_page(base + offset, MapOptions::default());
    }
    for frame in frames {
        pfn::free_page(frame);
    }
    return_range(&mut POOL.lock(), base, size);
    Ok(())
}

pub fn owns(pointer: u64) -> bool {
    POOL.lock().allocations.contains_key(&pointer)
}
