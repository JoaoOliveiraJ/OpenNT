//! Banco de frames legível por código nativo.
//!
//! O armazenamento pertence ao PFN; os descritores acompanham a alocação e
//! as tabelas de páginas do mesmo boot. Como o MiMapPfnDatabase do NT, a
//! janela (`memory_map::PFN_DATABASE_BASE`, MMPFN[pfn] em base + 48 * pfn)
//! só tem mapeadas as páginas que guardam descritores de frames do bloco de
//! memória física: os buracos (o de PCI abaixo de 4 GB, por exemplo) ficam
//! sem páginas, e as páginas não precisam ser contíguas na memória física.

use alloc::vec::Vec;

use super::native_frame_descriptors::{self as descriptors, Configuration, DESCRIPTOR_SIZE};
use super::paging::{self, MapOptions};
use super::{frame_mapping_tracker as tracker, memory_map as map, pfn, physical_layout, recursive_mapping};
use crate::hal::physical;
use crate::rtl::{KernelError, SpinLock};

const _: () = assert!(DESCRIPTOR_SIZE == map::PFN_DESCRIPTOR_SIZE);

#[derive(Clone, Copy, Debug)]
pub struct Published {
    pub base: u64,
    pub variable_address: u64,
    pub frame_count: u64,
    pub descriptor_size: u64,
    pub byte_length: u64,
}

static PUBLISHED: SpinLock<Option<Published>> = SpinLock::new(None);

pub fn information() -> Option<Published> {
    *PUBLISHED.lock()
}

/// Os índices das páginas da janela que guardam os descritores dos frames
/// de `ranges` (um descritor pode cruzar a divisa de duas páginas), em
/// ordem e sem repetição.
fn descriptor_pages(ranges: &[(u64, u64)]) -> Vec<u64> {
    let mut pages: Vec<u64> = Vec::new();
    for &(base, top) in ranges {
        let first = base / map::PAGE_SIZE * DESCRIPTOR_SIZE / map::PAGE_SIZE;
        let last = (top / map::PAGE_SIZE * DESCRIPTOR_SIZE - 1) / map::PAGE_SIZE;
        let start = pages.last().map_or(first, |&page| first.max(page + 1));
        pages.extend(start..=last);
    }
    pages
}

/// Desfaz o que `initialize` montou: os mapeamentos da janela (só
/// `mapped` primeiros) e os frames (todos os de `frames`).
fn uninstall(base: u64, pages: &[u64], frames: &[u64], mapped: usize) {
    for &page in pages[..mapped].iter().rev() {
        paging::unmap_page(base + page * map::PAGE_SIZE, MapOptions::default());
    }
    paging::set_observed(false);
    pfn::set_observed(false);
    tracker::reset();
    descriptors::reset();
    for &frame in frames {
        pfn::free_page(frame);
    }
}

/// Antes dos APs: nenhuma imagem recebe o endereço durante a montagem.
pub fn initialize() -> Result<Published, KernelError> {
    if let Some(published) = information() {
        return Ok(published);
    }
    if recursive_mapping::layout().is_none() {
        return Err(KernelError::new("native PFN database requires recursive mapping"));
    }
    let ranges = physical_layout::ranges();
    let Some(&(_, last_top)) = ranges.last() else {
        return Err(KernelError::new("native PFN database requires admitted RAM"));
    };
    let frame_count = last_top / map::PAGE_SIZE;
    let array_pages = (frame_count * DESCRIPTOR_SIZE).div_ceil(map::PAGE_SIZE);
    let byte_length = (array_pages + 1) * map::PAGE_SIZE;
    let base = map::PFN_DATABASE_BASE;
    if base + byte_length > map::PFN_DATABASE_TOP {
        return Err(KernelError::new("native PFN database exceeds reserved virtual range"));
    }
    if paging::find_mapping(base, byte_length).is_some() {
        return Err(KernelError::new("native PFN database virtual range already occupied"));
    }
    // As páginas dos descritores e, depois do array, a da variável
    // MmPfnDatabase; cada uma num frame zerado do PFN, mapeado antes de os
    // observadores existirem (o rastreador anda as tabelas no initialize).
    let mut pages = descriptor_pages(&ranges);
    pages.push(array_pages);
    let mut frames: Vec<u64> = Vec::with_capacity(pages.len());
    for (index, &page) in pages.iter().enumerate() {
        let frame = pfn::alloc_page();
        if frame == 0 {
            uninstall(base, &pages, &frames, index);
            return Err(KernelError::new("insufficient RAM for native PFN database"));
        }
        frames.push(frame);
        physical::zero(frame, map::PAGE_SIZE as usize);
        if !paging::map_page(base + page * map::PAGE_SIZE, frame, 3, MapOptions { nx: true, ..Default::default() }) {
            uninstall(base, &pages, &frames, index);
            return Err(KernelError::new("could not map native PFN database"));
        }
    }

    let configuration = Configuration {
        virtual_base: base,
        frame_count,
        physical_ranges: ranges,
        allocation_ranges: pfn::snapshot_allocations(),
        free_count: pfn::free_count(),
    };
    if let Err(error) = descriptors::initialize(configuration).and_then(|_| tracker::initialize()) {
        uninstall(base, &pages, &frames, pages.len());
        return Err(error);
    }
    pfn::set_observed(true);
    paging::set_observed(true);
    // KDBG aponta para esta variável; o cabeçalho do dump recebe o valor dela.
    let variable_frame = frames[frames.len() - 1];
    if physical::compare_exchange64(variable_frame, 0, base) != 0 {
        uninstall(base, &pages, &frames, pages.len());
        return Err(KernelError::new("native PFN database pointer publication failed"));
    }
    let published = Published {
        base,
        variable_address: base + array_pages * map::PAGE_SIZE,
        frame_count,
        descriptor_size: DESCRIPTOR_SIZE,
        byte_length,
    };
    *PUBLISHED.lock() = Some(published);
    debug_print!("[mm] native PFN: {} descriptors, base={:#x}, {} paginas mapeadas", frame_count, base, pages.len());
    Ok(published)
}

// ---- MmGetVirtualForPhysical (mm-physical-memory) ---------------------------
//
// Contrato do ntoskrnl 19041: MMPFN[pa >> 12].PteAddress (+8) volta a ser a VA
// que a PTE mapeia — sign-extend((PteAddress - PTE_BASE) << 9) + (pa & 0xFFF).
// O PTE_BASE do OpenNT é a janela recursiva (`recursive_mapping`); a
// PteAddress é a que o rastreador de frames grava no descritor. Um frame sem
// mapeamento dá o mesmo valor sem sentido que o NT daria; fora do bloco de
// memória física (ou sem banco publicado) devolve 0.

/// MmGetVirtualForPhysical(PhysicalAddress).
pub fn virtual_for_physical(physical_address: u64) -> u64 {
    let Some(layout) = recursive_mapping::layout() else { return 0 };
    let Some(descriptor) = descriptors::descriptor(physical_address >> 12) else { return 0 };
    let pte_address = descriptor.pte_address.get();
    let page = ((pte_address.wrapping_sub(layout.page_table_base) << 25) as i64 >> 16) as u64;
    page.wrapping_add(physical_address & 0xFFF)
}
