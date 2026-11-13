//! Frames físicos de 4KB.
//!
//! Só RAM E820 habilitada dentro das arenas identity pertence a este
//! alocador; buracos de firmware/MMIO/reservados nunca. Depois do bootstrap,
//! o banco nativo de descritores (`native_frame_descriptors`) acompanha as
//! mesmas transições do bitmap.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{memory_map as map, native_frame_descriptors as descriptors, physical_layout};
use crate::rtl::{KernelError, SpinLock};

const FRAME_SIZE: u64 = map::PAGE_SIZE;

struct Range {
    base: u64,
    top: u64,
    next: usize,
    bitmap: Vec<u8>,
}

/// Contabilidade da partição de memória física.
#[derive(Clone, Copy, Debug, Default)]
pub struct Partition {
    pub available: u64,
    pub total: u64,
}

struct FrameDatabase {
    ranges: Vec<Range>,
    next_range: usize,
    partition: Partition,
    /// Corpo publicado da partição (`mm/partition`), espelho de total e
    /// disponível (+16/+24); 0 antes do init.
    partition_body: u64,
}

static DATABASE: SpinLock<FrameDatabase> = SpinLock::new(FrameDatabase {
    ranges: Vec::new(),
    next_range: 0,
    partition: Partition { available: 0, total: 0 },
    partition_body: 0,
});

/// Espelha o disponível no corpo da partição, quando publicado.
fn mirror(body: u64, available: u64) {
    if body != 0 {
        crate::ntos::mm::guest_memory::write64(body + 24, available);
    }
}

/// Liga o corpo da partição: total e disponível passam a ser lidos dele.
pub fn bind_partition(body: u64) {
    let mut database = DATABASE.lock();
    database.partition_body = body;
    crate::ntos::mm::guest_memory::write64(body + 16, database.partition.total);
    mirror(body, database.partition.available);
}

/// Solta o corpo (falha do init ou descarte), mantendo os contadores.
pub fn unbind_partition(body: u64) {
    let mut database = DATABASE.lock();
    if database.partition_body == body {
        database.partition_body = 0;
    }
}

/// Recuperador opcional (paginação de imagens/pool): recebe quantos frames
/// faltam e devolve se liberou algum.
static RECLAIMER: SpinLock<Option<fn(u64) -> bool>> = SpinLock::new(None);
static RECLAIMING: AtomicBool = AtomicBool::new(false);
/// Banco nativo instalado.
static OBSERVED: AtomicBool = AtomicBool::new(false);

pub fn init() -> Result<(), KernelError> {
    if OBSERVED.load(Ordering::Acquire) {
        return Err(KernelError::new("cannot reset PFN allocator after native publication"));
    }
    physical_layout::init()?;
    let usable = physical_layout::ranges();
    let mut candidates = Vec::new();
    for &(low, high) in &map::PFN_RANGES {
        for &(base, top) in &usable {
            if low.max(base) < high.min(top) {
                candidates.push((low.max(base), high.min(top)));
            }
        }
    }
    candidates.sort();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (base, top) in candidates {
        let base = base.div_ceil(FRAME_SIZE) * FRAME_SIZE;
        let top = top / FRAME_SIZE * FRAME_SIZE;
        if base >= top {
            continue;
        }
        match merged.last_mut() {
            Some(previous) if base <= previous.1 => previous.1 = previous.1.max(top),
            _ => merged.push((base, top)),
        }
    }
    let mut database = DATABASE.lock();
    database.ranges = merged
        .into_iter()
        .map(|(base, top)| Range { base, top, next: 0, bitmap: vec![0; ((top - base) / FRAME_SIZE) as usize] })
        .collect();
    database.next_range = 0;
    let total: u64 = database.ranges.iter().map(|range| range.bitmap.len() as u64).sum();
    database.partition = Partition { available: total, total };
    if total == 0 {
        return Err(KernelError::new("No usable E820 RAM in PFN arenas"));
    }
    debug_print!("[mm] PFN: {} frames ({} MB), {} E820 ranges", total, total / 256, database.ranges.len());
    Ok(())
}

fn try_allocate_page() -> u64 {
    let mut database = DATABASE.lock();
    let database = &mut *database;
    while database.next_range < database.ranges.len() {
        let range = &mut database.ranges[database.next_range];
        for index in range.next..range.bitmap.len() {
            if range.bitmap[index] == 0 {
                range.bitmap[index] = 1;
                range.next = index + 1;
                let physical_address = range.base + index as u64 * FRAME_SIZE;
                database.partition.available -= 1;
                mirror(database.partition_body, database.partition.available);
                if OBSERVED.load(Ordering::Acquire) {
                    descriptors::allocated(physical_address);
                }
                return physical_address;
            }
        }
        database.next_range += 1;
    }
    0
}

/// Recupera frames pelo recuperador registrado, sem reentrância.
fn reclaim(count: u64) -> bool {
    let reclaimer = *RECLAIMER.lock();
    let Some(reclaimer) = reclaimer else { return false };
    if RECLAIMING.swap(true, Ordering::AcqRel) {
        return false;
    }
    let reclaimed = reclaimer(count);
    RECLAIMING.store(false, Ordering::Release);
    reclaimed
}

/// Um frame de 4KB, ou 0 sem memória.
pub fn alloc_page() -> u64 {
    let address = try_allocate_page();
    if address == 0 && reclaim(16) {
        return alloc_page();
    }
    address
}

pub fn free_page(address: u64) -> bool {
    if address % FRAME_SIZE != 0 {
        return false;
    }
    let mut database = DATABASE.lock();
    let database = &mut *database;
    for range_index in 0..database.ranges.len() {
        let range = &mut database.ranges[range_index];
        if address < range.base || address >= range.top {
            continue;
        }
        let index = ((address - range.base) / FRAME_SIZE) as usize;
        if range.bitmap[index] != 1 {
            return false;
        }
        // Uma página ainda alcançável por uma PTE não volta à lista livre.
        let observed = OBSERVED.load(Ordering::Acquire);
        if observed && !descriptors::can_release(address) {
            return false;
        }
        range.bitmap[index] = 0;
        range.next = range.next.min(index);
        database.next_range = database.next_range.min(range_index);
        database.partition.available += 1;
        mirror(database.partition_body, database.partition.available);
        if observed {
            descriptors::released(address);
        }
        return true;
    }
    false
}

fn find_contiguous(count: u64, alignment: u64, highest_pfn: u64, lowest_pfn: u64, boundary: u64) -> u64 {
    let mut database = DATABASE.lock();
    let database = &mut *database;
    for range in database.ranges.iter_mut() {
        let first = (range.base / FRAME_SIZE).max(lowest_pfn).div_ceil(alignment) * alignment * FRAME_SIZE;
        let top = range.top.min((highest_pfn + 1) * FRAME_SIZE);
        let mut address = first;
        while address + count * FRAME_SIZE <= top {
            let frame = address / FRAME_SIZE;
            if boundary != 0 && frame / boundary != (frame + count - 1) / boundary {
                let next_boundary = (frame / boundary + 1) * boundary;
                address = (next_boundary.div_ceil(alignment) - 1) * alignment * FRAME_SIZE;
                address += alignment * FRAME_SIZE;
                continue;
            }
            let start = ((address - range.base) / FRAME_SIZE) as usize;
            let free = range.bitmap[start..start + count as usize].iter().all(|&used| used == 0);
            if free {
                range.bitmap[start..start + count as usize].fill(1);
                database.partition.available -= count;
                mirror(database.partition_body, database.partition.available);
                if OBSERVED.load(Ordering::Acquire) {
                    for index in 0..count {
                        descriptors::allocated(address + index * FRAME_SIZE);
                    }
                }
                return address;
            }
            address += alignment * FRAME_SIZE;
        }
    }
    0
}

/// Reserva a faixa física inteira só depois de conferir disponibilidade,
/// buracos de firmware, limites inclusivos de PFN, alinhamento e uma
/// fronteira opcional que a faixa não pode cruzar.
pub fn alloc_contiguous(count: u64, alignment: u64, highest_pfn: u64, lowest_pfn: u64, boundary_pages: u64) -> u64 {
    if count == 0
        || alignment == 0
        || highest_pfn > 0xF_FFFF_FFFF
        || lowest_pfn > highest_pfn
        || (boundary_pages != 0 && (count > boundary_pages || !boundary_pages.is_power_of_two()))
    {
        return 0;
    }
    let address = find_contiguous(count, alignment, highest_pfn, lowest_pfn, boundary_pages);
    if address == 0 && reclaim(count) {
        return find_contiguous(count, alignment, highest_pfn, lowest_pfn, boundary_pages);
    }
    address
}

/// `alloc_contiguous` com os limites padrão.
pub fn alloc_contiguous_default(count: u64, alignment: u64) -> u64 {
    alloc_contiguous(count, alignment, 0xF_FFFF_FFFF, 0, 0)
}

pub fn free_count() -> u64 {
    DATABASE.lock().partition.available
}

pub fn total_count() -> u64 {
    DATABASE.lock().partition.total
}

pub fn partition() -> Partition {
    DATABASE.lock().partition
}

/// Faixa do bitmap copiada no boot, antes dos APs.
pub struct AllocationSnapshot {
    pub base: u64,
    pub top: u64,
    pub bitmap: Vec<u8>,
}

pub fn snapshot_allocations() -> Vec<AllocationSnapshot> {
    DATABASE
        .lock()
        .ranges
        .iter()
        .map(|range| AllocationSnapshot { base: range.base, top: range.top, bitmap: range.bitmap.clone() })
        .collect()
}

pub fn set_observed(installed: bool) {
    OBSERVED.store(installed, Ordering::Release);
}

pub fn set_reclaimer(reclaimer: Option<fn(u64) -> bool>) {
    *RECLAIMER.lock() = reclaimer;
}
