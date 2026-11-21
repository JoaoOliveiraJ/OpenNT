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
//!
//! Medição: cada frame em uso leva o dono que o pediu ([`FrameUse`], um byte
//! por frame ao lado do bitmap), e a partição soma os frames de cada dono
//! ([`usage`]). O NT não tem essa conta (o mais próximo é o
//! MMPFN.u3.e1.PageLocation e o UsedPageTableEntries); ela serve à linha
//! `[mm] frames por dono` do diagnóstico de memória, a base de medida do
//! consumo por tipo de página.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{memory_map as map, native_frame_descriptors as descriptors, physical_layout};
use crate::rtl::{KernelError, SpinLock};

const FRAME_SIZE: u64 = map::PAGE_SIZE;

/// Quem usa um frame do alocador: a conta da linha `[mm] frames por dono`.
/// Um frame pedido por [`alloc_page`] é de `Other` até um [`set_use`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameUse {
    Other = 0,
    /// Páginas privadas que o corte do working set pode levar
    /// (NtAllocateVirtualMemory, pilhas das threads seguintes).
    PrivatePageable,
    /// Páginas privadas residentes que o kernel monta para o processo (pilha
    /// da 1ª thread, PEB, TEB, parâmetros, entradas do Ldr).
    PrivateResident,
    /// A ntdll, o apiset e o NLS na raiz do System e as fotografias deles.
    SystemDll,
    /// As cópias de sistema de cada processo com raiz própria.
    SystemDllCopy,
    /// Imagens de usuário carregadas pelo kernel (o exe, as DLLs do loader).
    UserImage,
    /// Páginas protótipo das control areas de imagem.
    ImagePrototype,
    /// Cópias privadas de páginas graváveis das vistas de imagem.
    ImageCopy,
    /// Seções de arquivo de dados (as páginas lidas e as cópias originais).
    DataSection,
    /// Seções do arquivo de paginação.
    PagefileSection,
    /// Cópias na escrita das vistas de dados.
    SectionCopy,
    /// Imagens de drivers e de sessão.
    DriverImage,
    /// Pool do kernel e de sessão.
    Pool,
    /// Pilhas de kernel.
    KernelStack,
    /// Tabelas de páginas e raízes.
    PageTable,
    /// Caches de arquivo e de setores do kernel.
    FileCache,
}

/// Donos de [`FrameUse`].
pub const FRAME_USES: usize = 16;

impl FrameUse {
    /// Todos, na ordem da linha de diagnóstico.
    pub const ALL: [FrameUse; FRAME_USES] = [
        FrameUse::PrivatePageable,
        FrameUse::PrivateResident,
        FrameUse::SystemDll,
        FrameUse::SystemDllCopy,
        FrameUse::UserImage,
        FrameUse::ImagePrototype,
        FrameUse::ImageCopy,
        FrameUse::DataSection,
        FrameUse::PagefileSection,
        FrameUse::SectionCopy,
        FrameUse::DriverImage,
        FrameUse::Pool,
        FrameUse::KernelStack,
        FrameUse::PageTable,
        FrameUse::FileCache,
        FrameUse::Other,
    ];

    /// O nome curto da linha de diagnóstico.
    pub fn label(self) -> &'static str {
        match self {
            FrameUse::Other => "outros",
            FrameUse::PrivatePageable => "privadas-paginaveis",
            FrameUse::PrivateResident => "privadas-residentes",
            FrameUse::SystemDll => "sistema-ntdll-nls",
            FrameUse::SystemDllCopy => "copias-de-sistema",
            FrameUse::UserImage => "imagens-do-loader",
            FrameUse::ImagePrototype => "prototipos-de-imagem",
            FrameUse::ImageCopy => "copias-de-imagem",
            FrameUse::DataSection => "secoes-de-arquivo",
            FrameUse::PagefileSection => "secoes-de-pagefile",
            FrameUse::SectionCopy => "copias-de-secao",
            FrameUse::DriverImage => "imagens-de-driver",
            FrameUse::Pool => "pool",
            FrameUse::KernelStack => "pilhas-de-kernel",
            FrameUse::PageTable => "tabelas-de-paginas",
            FrameUse::FileCache => "cache-de-arquivo",
        }
    }
}

/// Uma faixa contígua de frames do alocador: um bit por frame (1 = em uso).
struct Range {
    base: u64,
    top: u64,
    /// Primeira palavra do bitmap que pode ter um frame livre.
    next: usize,
    words: Vec<u64>,
    /// O [`FrameUse`] de cada frame em uso.
    uses: Vec<u8>,
}

impl Range {
    fn new(base: u64, top: u64) -> Self {
        let frames = ((top - base) / FRAME_SIZE) as usize;
        let mut words = vec![0u64; frames.div_ceil(64)];
        // Os bits além do último frame ficam em uso: a busca nunca os entrega.
        if frames % 64 != 0 {
            *words.last_mut().unwrap() = !0u64 << (frames % 64);
        }
        Self { base, top, next: 0, words, uses: vec![0u8; frames] }
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
    /// Frames em uso de cada [`FrameUse`].
    uses: [u64; FRAME_USES],
}

impl FrameDatabase {
    /// A faixa e o índice do frame `address`.
    fn locate(&mut self, address: u64) -> Option<(usize, usize)> {
        let range_index = self.ranges.iter().position(|range| address >= range.base && address < range.top)?;
        Some((range_index, ((address - self.ranges[range_index].base) / FRAME_SIZE) as usize))
    }

    /// O frame passa a ser de `owner`: um recém-alocado (`fresh`) entra na
    /// conta, um em uso sai da conta do dono anterior.
    fn tag(&mut self, range_index: usize, index: usize, owner: FrameUse, fresh: bool) {
        let previous = core::mem::replace(&mut self.ranges[range_index].uses[index], owner as u8);
        if !fresh {
            self.uses[previous as usize] = self.uses[previous as usize].saturating_sub(1);
        }
        self.uses[owner as usize] += 1;
    }

    /// O frame volta ao alocador: sai da conta do dono.
    fn untag(&mut self, range_index: usize, index: usize) {
        let previous = core::mem::replace(&mut self.ranges[range_index].uses[index], 0);
        self.uses[previous as usize] = self.uses[previous as usize].saturating_sub(1);
    }
}

static DATABASE: SpinLock<FrameDatabase> = SpinLock::new(FrameDatabase {
    ranges: Vec::new(),
    next_range: 0,
    partition: Partition { available: 0, total: 0 },
    frames: 0,
    partition_body: 0,
    uses: [0; FRAME_USES],
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
    database.uses = [0; FRAME_USES];
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

fn try_allocate_page(owner: FrameUse) -> u64 {
    let mut database = DATABASE.lock();
    let database = &mut *database;
    while database.next_range < database.ranges.len() {
        let range_index = database.next_range;
        let range = &mut database.ranges[range_index];
        for word in range.next..range.words.len() {
            if range.words[word] == u64::MAX {
                continue;
            }
            let index = word * 64 + range.words[word].trailing_ones() as usize;
            range.set(index, true);
            range.next = word;
            let physical_address = range.base + index as u64 * FRAME_SIZE;
            database.tag(range_index, index, owner, true);
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
    alloc_page_for(FrameUse::Other)
}

/// Um frame de 4KB de `owner` (a conta de [`usage`]), ou 0 sem memória.
pub fn alloc_page_for(owner: FrameUse) -> u64 {
    let address = try_allocate_page(owner);
    if address == 0 && reclaim(16) {
        return alloc_page_for(owner);
    }
    address
}

/// [`alloc_page_for`] sem a recuperação de memória: só um frame que já está
/// livre (a falta de zero sob demanda com spin locks retidos), ou 0.
pub fn try_alloc_page_for(owner: FrameUse) -> u64 {
    try_allocate_page(owner)
}

/// O frame em uso `address` passa a ser de `owner` (um frame contíguo, ou
/// um que muda de dono). Um frame fora do alocador, ou livre, fica como
/// está.
pub fn set_use(address: u64, owner: FrameUse) {
    let mut database = DATABASE.lock();
    if let Some((range_index, index)) = database.locate(address & !(FRAME_SIZE - 1)) {
        if database.ranges[range_index].used(index) {
            database.tag(range_index, index, owner, false);
        }
    }
}

/// Os frames em uso de cada [`FrameUse`] (pelo valor do dono).
pub fn usage() -> [u64; FRAME_USES] {
    DATABASE.lock().uses
}

/// [`usage`] e os frames que o alocador entregou (os geridos menos os
/// disponíveis), lidos juntos.
pub fn usage_and_allocated() -> ([u64; FRAME_USES], u64) {
    let database = DATABASE.lock();
    (database.uses, database.frames - database.partition.available)
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
        database.untag(range_index, index);
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
                    range.uses[index] = FrameUse::Other as u8;
                }
                database.uses[FrameUse::Other as usize] += count;
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
