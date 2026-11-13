//! MDLs dos exports Io* — IoAllocateMdl, IoBuildPartialMdl e IoFreeMdl, no
//! layout do wdm.h com os PFNs reais das tabelas de página.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::paging;
use crate::ntos::inc::nt_abi::mdl;

/// IoAllocateMdl: MDL do wdm.h com os PFNs reais das tabelas de página.
pub fn allocate_mdl(virtual_address: u64, length: u32) -> u64 {
    let start = virtual_address & !0xFFF;
    let byte_offset = virtual_address & 0xFFF;
    let pages = (byte_offset + length as u64).div_ceil(0x1000);
    let size = mdl::PFN_ARRAY + pages * 8;
    let descriptor = guest::alloc_bytes(size);
    if descriptor == 0 {
        return 0;
    }
    guest::write64(descriptor + mdl::NEXT, 0);
    guest::write16(descriptor + mdl::SIZE, size as u16);
    guest::write16(descriptor + mdl::MDL_FLAGS, mdl::FLAG_MAPPED_TO_SYSTEM_VA | mdl::FLAG_SOURCE_NONPAGED);
    // O mapeamento deste caminho é por identidade.
    guest::write64(descriptor + mdl::MAPPED_SYSTEM_VA, virtual_address);
    guest::write64(descriptor + mdl::START_VA, start);
    guest::write32(descriptor + mdl::BYTE_COUNT, length);
    guest::write32(descriptor + mdl::BYTE_OFFSET, byte_offset as u32);
    for page in 0..pages {
        guest::write64(descriptor + mdl::PFN_ARRAY + page * 8, paging::translate(start + page * 0x1000) / 0x1000);
    }
    descriptor
}

/// IoFreeMdl.
pub fn free_mdl(descriptor: u64) {
    guest::free_bytes(descriptor);
}

/// IoBuildPartialMdl: a janela do alvo dentro da origem, marcada MDL_PARTIAL.
pub fn build_partial_mdl(source: u64, target: u64, virtual_address: u64, length: u32) {
    let source_start = guest::read64(source + mdl::START_VA);
    let aligned = virtual_address & !0xFFF;
    guest::write64(target + mdl::START_VA, aligned);
    guest::write32(target + mdl::BYTE_OFFSET, (virtual_address & 0xFFF) as u32);
    guest::write32(target + mdl::BYTE_COUNT, length);
    guest::write16(target + mdl::MDL_FLAGS, guest::read16(target + mdl::MDL_FLAGS) | 0x10);
    let offset = aligned.wrapping_sub(source_start) / 0x1000;
    let pages = ((virtual_address & 0xFFF) + length as u64).div_ceil(0x1000);
    for page in 0..pages {
        guest::write64(target + mdl::PFN_ARRAY + page * 8, guest::read64(source + mdl::PFN_ARRAY + (offset + page) * 8));
    }
}
