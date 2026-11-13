//! MDLs do Mm (o `iosup` do NT): sondar e travar as páginas de um buffer,
//! descrever pool não paginado, mapear as páginas travadas no espaço do
//! sistema (por identidade ou numa VA reservada por MmAllocateMappingAddress)
//! e alocar/devolver páginas físicas descritas por um MDL.
//!
//! O MDL é memória do convidado no layout x64 de `nt_abi::mdl`; o PFN array
//! guarda os frames reais das tabelas de página.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{paging, pfn};
use crate::ntos::inc::nt_abi::mdl;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// Regiões reservadas por MmAllocateMappingAddress: tamanho e tag.
static RESERVED_MAPPINGS: SpinLock<BTreeMap<u64, (u64, u32)>> = SpinLock::new(BTreeMap::new());

/// Preenche o PFN array do MDL andando as tabelas de página (um PFN por
/// página coberta pelo buffer).
fn fill_pfn_array(descriptor: u64) {
    let start = guest::read64(descriptor + mdl::START_VA);
    let offset = guest::read32(descriptor + mdl::BYTE_OFFSET) as u64;
    let count = guest::read32(descriptor + mdl::BYTE_COUNT) as u64;
    let first = start + offset;
    let pages = ((first & 0xFFF) + count).div_ceil(0x1000);
    for index in 0..pages {
        let physical = paging::translate((first & !0xFFF) + index * 0x1000);
        guest::write64(descriptor + mdl::PFN_ARRAY + index * 8, physical / 0x1000);
    }
}

fn set_flags(descriptor: u64, set: u16, clear: u16) {
    let flags = guest::read16(descriptor + mdl::MDL_FLAGS);
    guest::write16(descriptor + mdl::MDL_FLAGS, (flags | set) & !clear);
}

/// MmGetSystemAddressForMdlSafe: a VA de sistema gravada no MDL.
pub fn system_address(descriptor: u64) -> u64 {
    guest::read64(descriptor + mdl::MAPPED_SYSTEM_VA)
}

/// MmMapLockedPagesSpecifyCache — identidade: StartVa + ByteOffset (ou o
/// endereço pedido), gravado no MDL.
pub fn map_locked_pages(descriptor: u64, requested_address: u64) -> u64 {
    let mapped = if requested_address != 0 { requested_address } else { guest::read64(descriptor + mdl::START_VA) + guest::read32(descriptor + mdl::BYTE_OFFSET) as u64 };
    guest::write64(descriptor + mdl::MAPPED_SYSTEM_VA, mapped);
    set_flags(descriptor, mdl::FLAG_MAPPED_TO_SYSTEM_VA, 0);
    mapped
}

/// MmUnmapLockedPages.
pub fn unmap_locked_pages(descriptor: u64) {
    set_flags(descriptor, 0, mdl::FLAG_MAPPED_TO_SYSTEM_VA);
}

/// MmProbeAndLockPages — o pool é residente: as páginas já estão travadas;
/// o PFN array é real.
pub fn probe_and_lock_pages(descriptor: u64) {
    fill_pfn_array(descriptor);
    set_flags(descriptor, mdl::FLAG_PAGES_LOCKED, 0);
}

/// MmUnlockPages.
pub fn unlock_pages(descriptor: u64) {
    set_flags(descriptor, 0, mdl::FLAG_PAGES_LOCKED);
}

/// MmBuildMdlForNonPagedPool.
pub fn build_for_non_paged_pool(descriptor: u64) {
    fill_pfn_array(descriptor);
    set_flags(descriptor, mdl::FLAG_SOURCE_NONPAGED | mdl::FLAG_PAGES_LOCKED, 0);
}

/// MmAllocateMappingAddress — VA reservada, alinhada à página e fora do
/// alcance de outras alocações; 0 sem memória.
pub fn allocate_mapping_address(size: u64, tag: u32) -> u64 {
    let address = guest::alloc_aligned(size, 0x1000, true);
    if address == 0 {
        return 0;
    }
    RESERVED_MAPPINGS.lock().insert(address, (size as u32 as u64, tag));
    address
}

/// MmFreeMappingAddress.
pub fn free_mapping_address(address: u64) {
    RESERVED_MAPPINGS.lock().remove(&address);
    guest::free_bytes(address);
}

/// MmMapLockedPagesWithReservedMapping — exige a VA reservada e remapeia as
/// páginas dela para as do MDL; 0 em falha.
pub fn map_locked_pages_with_reserved_mapping(address: u64, descriptor: u64) -> u64 {
    if !RESERVED_MAPPINGS.lock().contains_key(&address) {
        return 0;
    }
    let count = guest::read32(descriptor + mdl::BYTE_COUNT) as u64;
    let offset = guest::read32(descriptor + mdl::BYTE_OFFSET) as u64;
    for index in 0..(offset + count).div_ceil(0x1000) {
        let frame = guest::read64(descriptor + mdl::PFN_ARRAY + index * 8);
        if !paging::map_page(address + index * 0x1000, frame * 0x1000, paging::PAGE_PRESENT | paging::PAGE_RW, paging::MapOptions::default()) {
            return 0;
        }
    }
    let mapped = address + offset;
    guest::write64(descriptor + mdl::MAPPED_SYSTEM_VA, mapped);
    set_flags(descriptor, mdl::FLAG_MAPPED_TO_SYSTEM_VA, 0);
    mapped
}

/// MmUnmapReservedMapping.
pub fn unmap_reserved_mapping(descriptor: u64) {
    let count = guest::read32(descriptor + mdl::BYTE_COUNT) as u64;
    let offset = guest::read32(descriptor + mdl::BYTE_OFFSET) as u64;
    let base = guest::read64(descriptor + mdl::MAPPED_SYSTEM_VA) - offset;
    for index in 0..(offset + count).div_ceil(0x1000) {
        paging::unmap_page(base + index * 0x1000, paging::MapOptions::default());
    }
    set_flags(descriptor, 0, mdl::FLAG_MAPPED_TO_SYSTEM_VA);
}

/// MmAllocatePagesForMdl — páginas físicas reais da arena PFN descritas num
/// MDL novo (sem mapear); 0 em falha.
pub fn allocate_pages(byte_count: u64) -> u64 {
    if byte_count == 0 || byte_count > 0x7FFF_FFFF {
        return 0;
    }
    let page_count = byte_count.div_ceil(0x1000);
    let mut frames = Vec::new();
    for _ in 0..page_count {
        let frame = pfn::alloc_page();
        if frame == 0 {
            for frame in frames {
                pfn::free_page(frame);
            }
            return 0;
        }
        frames.push(frame);
    }
    let descriptor = guest::alloc_bytes(mdl::PFN_ARRAY + page_count * 8);
    guest::write64(descriptor + mdl::NEXT, 0);
    guest::write16(descriptor + mdl::SIZE, (mdl::PFN_ARRAY + page_count * 8) as u16);
    guest::write16(descriptor + mdl::MDL_FLAGS, 0);
    guest::write64(descriptor + mdl::START_VA, 0);
    guest::write32(descriptor + mdl::BYTE_COUNT, byte_count as u32);
    guest::write32(descriptor + mdl::BYTE_OFFSET, 0);
    for (index, frame) in frames.iter().enumerate() {
        guest::write64(descriptor + mdl::PFN_ARRAY + index as u64 * 8, frame / 0x1000);
    }
    descriptor
}

/// MmFreePagesFromMdl — devolve as páginas físicas; o MDL continua vivo
/// (quem alocou libera).
pub fn free_pages(descriptor: u64) {
    let size = guest::read16(descriptor + mdl::SIZE) as u64;
    for index in 0..size.saturating_sub(mdl::PFN_ARRAY) / 8 {
        let frame = guest::read64(descriptor + mdl::PFN_ARRAY + index * 8);
        if frame != 0 {
            pfn::free_page(frame * 0x1000);
        }
    }
}
