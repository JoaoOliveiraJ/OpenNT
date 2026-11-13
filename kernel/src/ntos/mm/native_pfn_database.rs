//! Banco de frames legível por código nativo.
//!
//! O armazenamento pertence ao PFN; os descritores acompanham a alocação e
//! as tabelas de páginas do mesmo boot.

use super::native_frame_descriptors::{self as descriptors, Configuration, DESCRIPTOR_SIZE};
use super::paging::{self, MapOptions};
use super::{frame_mapping_tracker as tracker, memory_map as map, pfn, physical_layout, recursive_mapping};
use crate::hal::physical;
use crate::rtl::{KernelError, SpinLock};

#[derive(Clone, Copy, Debug)]
pub struct Published {
    pub base: u64,
    pub variable_address: u64,
    pub physical_base: u64,
    pub frame_count: u64,
    pub descriptor_size: u64,
    pub byte_length: u64,
}

static PUBLISHED: SpinLock<Option<Published>> = SpinLock::new(None);

pub fn information() -> Option<Published> {
    *PUBLISHED.lock()
}

fn uninstall(base: u64, mapped_pages: u64, storage_pages: u64, physical_base: u64, observers_installed: bool) {
    // Desfaz mapeamentos antes de liberar os bytes usados pelos observadores.
    if observers_installed {
        let last = mapped_pages.min(storage_pages - 1);
        for page in (0..=last).rev() {
            paging::unmap_page(base + page * map::PAGE_SIZE, MapOptions::default());
        }
    }
    paging::set_observed(false);
    pfn::set_observed(false);
    tracker::reset();
    descriptors::reset();
    for page in 0..storage_pages {
        pfn::free_page(physical_base + page * map::PAGE_SIZE);
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
    let storage_pages = array_pages + 1;
    let byte_length = storage_pages * map::PAGE_SIZE;
    let base = map::PFN_DATABASE_BASE;
    if base + byte_length > map::PFN_DATABASE_TOP {
        return Err(KernelError::new("native PFN database exceeds reserved virtual range"));
    }
    if paging::find_mapping(base, byte_length).is_some() {
        return Err(KernelError::new("native PFN database virtual range already occupied"));
    }
    let physical_base = pfn::alloc_contiguous_default(storage_pages, 1);
    if physical_base == 0 {
        return Err(KernelError::new("insufficient contiguous RAM for native PFN database"));
    }

    let configuration = Configuration {
        physical_base,
        virtual_base: base,
        frame_count,
        physical_ranges: ranges,
        allocation_ranges: pfn::snapshot_allocations(),
        free_count: pfn::free_count(),
    };
    if let Err(error) = descriptors::initialize(configuration).and_then(|_| tracker::initialize()) {
        uninstall(base, 0, storage_pages, physical_base, false);
        return Err(error);
    }
    pfn::set_observed(true);
    paging::set_observed(true);
    for page in 0..storage_pages {
        let offset = page * map::PAGE_SIZE;
        if !paging::map_page(base + offset, physical_base + offset, 3, MapOptions { nx: true, ..Default::default() }) {
            uninstall(base, page, storage_pages, physical_base, true);
            return Err(KernelError::new("could not map native PFN database"));
        }
    }
    // KDBG aponta para esta variável; o cabeçalho do dump recebe o valor dela.
    let variable_offset = array_pages * map::PAGE_SIZE;
    physical::zero(physical_base + variable_offset, map::PAGE_SIZE as usize);
    if physical::compare_exchange64(physical_base + variable_offset, 0, base) != 0 {
        uninstall(base, storage_pages - 1, storage_pages, physical_base, true);
        return Err(KernelError::new("native PFN database pointer publication failed"));
    }
    let published = Published {
        base,
        variable_address: base + variable_offset,
        physical_base,
        frame_count,
        descriptor_size: DESCRIPTOR_SIZE,
        byte_length,
    };
    *PUBLISHED.lock() = Some(published);
    debug_print!("[mm] native PFN: {} descriptors, base={:#x}", frame_count, base);
    Ok(published)
}

// ---- MmGetVirtualForPhysical (mm-physical-memory) ---------------------------
//
// Contrato do ntoskrnl 19041: MMPFN[pa >> 12].PteAddress (+8) volta a ser a VA
// que a PTE mapeia — sign-extend((PteAddress - PTE_BASE) << 9) + (pa & 0xFFF).
// O PTE_BASE do OpenNT é a janela recursiva (`recursive_mapping`); a
// PteAddress é a que o rastreador de frames grava no descritor. Um frame sem
// mapeamento dá o mesmo valor sem sentido que o NT daria; fora do banco (ou
// sem banco publicado) devolve 0.

/// MmGetVirtualForPhysical(PhysicalAddress).
pub fn virtual_for_physical(physical_address: u64) -> u64 {
    let (Some(database), Some(layout)) = (information(), recursive_mapping::layout()) else { return 0 };
    let frame = physical_address >> 12;
    if frame >= database.frame_count {
        return 0;
    }
    let pte_address = physical::read64(database.physical_base + frame * database.descriptor_size + 8);
    let page = ((pte_address.wrapping_sub(layout.page_table_base) << 25) as i64 >> 16) as u64;
    page.wrapping_add(physical_address & 0xFFF)
}
