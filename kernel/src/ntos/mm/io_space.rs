//! Mapeamentos de I/O space do Mm (MmMapIoSpace, MmMapIoSpaceEx,
//! MmUnmapIoSpace) e a atividade das páginas de I/O (MmIsIoSpaceActive).
//! Toda a faixa física já está no mapa direto da metade de sistema: mapear
//! devolve a VA de sistema `DIRECT_MAP_BASE + PA`, e a tabela rastreia os
//! mapeamentos ativos e o unmap, como o NT.
//!
//! Páginas de I/O são as que não são RAM (sem PFN no NT). Como o
//! MiFillSystemPtes do ntoskrnl 19041, mapear uma faixa referencia cada
//! página de I/O dela (MiReferenceIoPages) e o unmap tira a referência
//! (MiDereferenceIoPages); o MmIsIoSpaceActive (0x536e90) pergunta ao
//! MiIsProbeActive se alguma página da faixa tem referência. Páginas de RAM
//! nunca entram na contagem.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::hal::physical;
use crate::ntos::mm::physical_layout;
use crate::rtl::SpinLock;

const PAGE_SIZE: u64 = 0x1000;

/// Mapeamentos de I/O space ativos: VA -> (PA, tamanho) de cada mapeamento
/// (a mesma PA dá a mesma VA, então uma VA pode ter vários).
static IO_SPACE_MAPPINGS: SpinLock<BTreeMap<u64, Vec<(u64, u64)>>> = SpinLock::new(BTreeMap::new());

/// Referências por página de I/O (PFN -> contagem).
static IO_PAGE_REFERENCES: SpinLock<BTreeMap<u64, u32>> = SpinLock::new(BTreeMap::new());

/// VA de sistema da faixa física, ou 0 (NULL) fora do mapa direto.
fn system_address(physical_address: u64, size: u64) -> u64 {
    match physical_address.checked_add(size.max(1)) {
        Some(end) if end <= crate::ntos::mm::memory_map::PHYSICAL_MEMORY_LIMIT => physical::to_virtual(physical_address),
        _ => 0,
    }
}

/// PFNs de [PA, PA + tamanho), como o MmIsIoSpaceActive os calcula.
fn page_frames(physical_address: u64, size: u64) -> core::ops::Range<u64> {
    let first = physical_address / PAGE_SIZE;
    let last = physical_address.wrapping_add(size).wrapping_sub(1) / PAGE_SIZE;
    first..last.wrapping_add(1).max(first)
}

/// MiReferenceIoPages/MiDereferenceIoPages: só as páginas que não são RAM.
fn reference_io_pages(physical_address: u64, size: u64, delta: i32) {
    let mut references = IO_PAGE_REFERENCES.lock();
    for frame in page_frames(physical_address, size.max(1)) {
        if physical_layout::contains_ram_range(frame * PAGE_SIZE, PAGE_SIZE) {
            continue;
        }
        let count = references.entry(frame).or_insert(0);
        *count = count.saturating_add_signed(delta);
        if *count == 0 {
            references.remove(&frame);
        }
    }
}

fn record(address: u64, physical_address: u64, size: u64) {
    IO_SPACE_MAPPINGS.lock().entry(address).or_default().push((physical_address, size));
    reference_io_pages(physical_address, size, 1);
}

/// MmMapIoSpace — a VA do mapa direto; 0 fora da faixa física mapeada.
pub fn map(physical_address: u64, size: u64) -> u64 {
    let size = size as u32 as u64;
    let address = system_address(physical_address, size);
    if address != 0 {
        record(address, physical_address, size);
    }
    address
}

/// MmUnmapIoSpace(BaseAddress, NumberOfBytes): desfaz um mapeamento da VA
/// (o de mesmo tamanho, se houver) e tira as referências das páginas dele.
pub fn unmap(address: u64, size: u64) {
    let removed = {
        let mut mappings = IO_SPACE_MAPPINGS.lock();
        let Some(list) = mappings.get_mut(&address) else { return };
        let index = list.iter().position(|&(_, length)| length == size).unwrap_or(0);
        let removed = list.remove(index);
        if list.is_empty() {
            mappings.remove(&address);
        }
        removed
    };
    reference_io_pages(removed.0, removed.1, -1);
}

/// MmMapIoSpaceEx — a VA do mapa direto, com o mesmo registro do MmMapIoSpace.
pub fn map_ex(physical_address: u64, size: u64) -> u64 {
    let address = system_address(physical_address, size);
    if address != 0 {
        record(address, physical_address, size);
    }
    address
}

/// MmIsIoSpaceActive(PhysicalAddress, NumberOfBytes): TRUE se alguma página
/// de I/O da faixa está referenciada por um mapeamento ativo.
/// Como no MiIsProbeActive, a busca anda na árvore de páginas referenciadas,
/// não página a página (a faixa pode cobrir todo o espaço físico).
pub fn is_active(physical_address: u64, size: u64) -> bool {
    let frames = page_frames(physical_address, size);
    !frames.is_empty() && IO_PAGE_REFERENCES.lock().range(frames).any(|(_, &count)| count != 0)
}
