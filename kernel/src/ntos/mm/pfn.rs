//! Frames físicos de 4KB.
//!
//! O alocador recebe toda a RAM do bloco de memória física
//! (`physical_layout`, a RAM que o firmware entrega) menos as faixas que o
//! kernel ocupa desde o boot (`memory_map::PFN_EXCLUDED`), como o
//! MiInitializePfnDatabase do NT põe na lista livre os descritores livres do
//! carregador; buracos de firmware/MMIO/reservados nunca. A partição conta
//! como total o MmNumberOfPhysicalPages (todo o bloco, a memória do kernel
//! incluída, que fica sempre em uso) e como disponíveis os frames livres
//! daqui. Cada faixa guarda um bit por frame. Depois do bootstrap, o banco
//! nativo de descritores (`native_frame_descriptors`) acompanha as mesmas
//! transições do bitmap.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{memory_map as map, native_frame_descriptors as descriptors, physical_layout};
use crate::rtl::{KernelError, SpinLock};

const FRAME_SIZE: u64 = map::PAGE_SIZE;

/// Uma faixa contígua de frames do alocador: um bit por frame (1 = em uso).
struct Range {
    base: u64,
    top: u64,
    /// Primeira palavra do bitmap que pode ter um frame livre.
    next: usize,
    words: Vec<u64>,
}

impl Range {
    fn new(base: u64, top: u64) -> Self {
        let frames = ((top - base) / FRAME_SIZE) as usize;
        let mut words = vec![0u64; frames.div_ceil(64)];
        // Os bits além do último frame ficam em uso: a busca nunca os entrega.
        if frames % 64 != 0 {
            *words.last_mut().unwrap() = !0u64 << (frames % 64);
        }
        Self { base, top, next: 0, words }
    }

    fn frames(&self) -> usize {
        ((self.top - self.base) / FRAME_SIZE) as usize
    }

    fn used(&self, index: usize) -> bool {
        self.words[index / 64] & (1 << (index % 64)) != 0
    }

    fn set(&mut self, index: usize, used: bool) {
        if used {
            self.words[index / 64] |= 1 << (index % 64);
        } else {
            self.words[index / 64] &= !(1 << (index % 64));
        }
    }

    /// Os frames [start, start + count) estão todos livres.
    fn run_free(&self, start: usize, count: usize) -> bool {
        (start..start + count).all(|index| !self.used(index))
    }
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
    /// Frames que o alocador gere (os do bloco fora de PFN_EXCLUDED).
    frames: u64,
    /// Corpo publicado da partição (`mm/partition`), espelho de total e
    /// disponível (+16/+24); 0 antes do init.
    partition_body: u64,
}

static DATABASE: SpinLock<FrameDatabase> = SpinLock::new(FrameDatabase {
    ranges: Vec::new(),
    next_range: 0,
    partition: Partition { available: 0, total: 0 },
    frames: 0,
    partition_body: 0,
});

/// Espelha o disponível no corpo da partição, quando publicado.
fn mirror(body: u64, available: u64) {
    if body != 0 {
        crate::ntos::mm::partition::PartitionBody::of(body).available.set(available);
    }
}

/// Liga o corpo da partição: total e disponível passam a ser lidos dele.
pub fn bind_partition(body: u64) {
    let mut database = DATABASE.lock();
    database.partition_body = body;
    crate::ntos::mm::partition::PartitionBody::of(body).total.set(database.partition.total);
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

/// As faixas do alocador: a RAM do bloco menos `excluded`, em frames
/// inteiros, ordenadas e unidas.
pub fn allocator_ranges(admitted: &[(u64, u64)], excluded: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut candidates: Vec<(u64, u64)> = admitted.to_vec();
    for &(low, high) in excluded {
        let mut remaining = Vec::new();
        for &(base, top) in &candidates {
            if high <= base || low >= top {
                remaining.push((base, top));
                continue;
            }
            if base < low {
                remaining.push((base, low));
            }
            if top > high {
                remaining.push((high, top));
            }
        }
        candidates = remaining;
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
    merged
}

pub fn init() -> Result<(), KernelError> {
    if OBSERVED.load(Ordering::Acquire) {
        return Err(KernelError::new("cannot reset PFN allocator after native publication"));
    }
    physical_layout::init()?;
    let merged = allocator_ranges(&physical_layout::ranges(), &map::PFN_EXCLUDED);
    let mut database = DATABASE.lock();
    database.ranges = merged.into_iter().map(|(base, top)| Range::new(base, top)).collect();
    database.next_range = 0;
    let frames: u64 = database.ranges.iter().map(|range| range.frames() as u64).sum();
    if frames == 0 {
        return Err(KernelError::new("No usable E820 RAM for the PFN"));
    }
    let total = physical_layout::number_of_physical_pages();
    database.frames = frames;
    database.partition = Partition { available: frames, total };
    debug_print!(
        "[mm] PFN: {} frames ({} MB) em {} faixas; memoria fisica {} paginas ({} MB), PFN {:#x}-{:#x}",
        frames,
        frames / 256,
        database.ranges.len(),
        total,
        total / 256,
        physical_layout::lowest_physical_page(),
        physical_layout::highest_physical_page()
    );
    Ok(())
}

fn try_allocate_page() -> u64 {
    let mut database = DATABASE.lock();
    let database = &mut *database;
    while database.next_range < database.ranges.len() {
        let range = &mut database.ranges[database.next_range];
        for word in range.next..range.words.len() {
            if range.words[word] == u64::MAX {
                continue;
            }
            let index = word * 64 + range.words[word].trailing_ones() as usize;
            range.set(index, true);
            range.next = word;
            let physical_address = range.base + index as u64 * FRAME_SIZE;
            database.partition.available -= 1;
            mirror(database.partition_body, database.partition.available);
            if OBSERVED.load(Ordering::Acquire) {
                descriptors::allocated(physical_address);
            }
            return physical_address;
        }
        range.next = range.words.len();
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
        if !range.used(index) {
            return false;
        }
        // Uma página ainda alcançável por uma PTE não volta à lista livre.
        let observed = OBSERVED.load(Ordering::Acquire);
        if observed && !descriptors::can_release(address) {
            return false;
        }
        range.set(index, false);
        range.next = range.next.min(index / 64);
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
            if range.run_free(start, count as usize) {
                for index in start..start + count as usize {
                    range.set(index, true);
                }
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

/// O total da partição: o MmNumberOfPhysicalPages (`physical_layout`).
pub fn total_count() -> u64 {
    DATABASE.lock().partition.total
}

/// Os frames que este alocador gere (o bloco de memória física menos
/// PFN_EXCLUDED).
pub fn frame_count() -> u64 {
    DATABASE.lock().frames
}

/// MmGetLowestPhysicalPage e MmGetHighestPhysicalPage: o primeiro e o último
/// PFN do bloco de memória física (0, 0 antes do init).
pub fn physical_page_bounds() -> (u64, u64) {
    (physical_layout::lowest_physical_page(), physical_layout::highest_physical_page())
}

/// As faixas do alocador, [base, top) (autotestes).
pub fn ranges() -> Vec<(u64, u64)> {
    DATABASE.lock().ranges.iter().map(|range| (range.base, range.top)).collect()
}

pub fn partition() -> Partition {
    DATABASE.lock().partition
}

/// Faixa do bitmap copiada no boot, antes dos APs: um bit por frame
/// (1 = em uso), `frames` frames a partir de `base`.
pub struct AllocationSnapshot {
    pub base: u64,
    pub frames: usize,
    pub words: Vec<u64>,
}

impl AllocationSnapshot {
    /// O frame `index` da faixa está em uso.
    pub fn used(&self, index: usize) -> bool {
        self.words[index / 64] & (1 << (index % 64)) != 0
    }
}

pub fn snapshot_allocations() -> Vec<AllocationSnapshot> {
    DATABASE
        .lock()
        .ranges
        .iter()
        .map(|range| AllocationSnapshot { base: range.base, frames: range.frames(), words: range.words.clone() })
        .collect()
}

/// A lista livre do banco nativo andada com o bitmap parado (os dois locks
/// na ordem das transições) e os frames livres do bitmap (autotestes).
pub fn native_free_list() -> (descriptors::FreeListWalk, u64) {
    let database = DATABASE.lock();
    (descriptors::walk_free_list(), database.partition.available)
}

pub fn set_observed(installed: bool) {
    OBSERVED.store(installed, Ordering::Release);
}

pub fn set_reclaimer(reclaimer: Option<fn(u64) -> bool>) {
    *RECLAIMER.lock() = reclaimer;
}
