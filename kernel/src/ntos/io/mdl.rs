//! MDLs dos exports Io* — IoAllocateMdl, IoBuildPartialMdl e IoFreeMdl, no
//! layout do wdm.h com os PFNs reais das tabelas de página.

use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{Mdl, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::paging;

/// MDL_MAPPED_TO_SYSTEM_VA, MDL_SOURCE_IS_NONPAGED_POOL e MDL_PARTIAL.
const MDL_MAPPED_TO_SYSTEM_VA: i16 = 0x0001;
const MDL_SOURCE_IS_NONPAGED_POOL: i16 = 0x0004;
const MDL_PARTIAL: i16 = 0x0010;

/// Vetor de PFN_NUMBER que segue o cabeçalho do MDL (MmGetMdlPfnArray).
fn pfn_array(descriptor: u64, pages: u64) -> &'static [Field<u64>] {
    // SAFETY: o MDL foi alocado/dimensionado com espaço para `pages` PFNs.
    unsafe { Field::<u64>::array_at(descriptor + Mdl::SIZE, pages as usize) }
}

/// IoAllocateMdl: MDL do wdm.h com os PFNs reais das tabelas de página.
pub fn allocate_mdl(virtual_address: u64, length: u32) -> u64 {
    let start = virtual_address & !0xFFF;
    let byte_offset = virtual_address & 0xFFF;
    let pages = (byte_offset + length as u64).div_ceil(0x1000);
    let size = Mdl::SIZE + pages * 8;
    let descriptor = guest::alloc_bytes(size);
    if descriptor == 0 {
        return 0;
    }
    // SAFETY: alocação zerada do MDL recém-criado.
    let mdl = unsafe { Mdl::at(descriptor) };
    mdl.next.set(0);
    mdl.size.set(size as i16);
    mdl.mdl_flags.set(MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL);
    // O mapeamento deste caminho é por identidade.
    mdl.mapped_system_va.set(virtual_address);
    mdl.start_va.set(start);
    mdl.byte_count.set(length);
    mdl.byte_offset.set(byte_offset as u32);
    for (page, pfn) in pfn_array(descriptor, pages).iter().enumerate() {
        pfn.set(paging::translate(start + page as u64 * 0x1000) / 0x1000);
    }
    descriptor
}

/// IoFreeMdl.
pub fn free_mdl(descriptor: u64) {
    guest::free_bytes(descriptor);
}

/// IoBuildPartialMdl: a janela do alvo dentro da origem, marcada MDL_PARTIAL.
pub fn build_partial_mdl(source: u64, target: u64, virtual_address: u64, length: u32) {
    // SAFETY: MDLs de origem e de destino do driver, dimensionados por ele.
    let (source_mdl, target_mdl) = unsafe { (Mdl::at(source), Mdl::at(target)) };
    let source_start = source_mdl.start_va.get();
    let aligned = virtual_address & !0xFFF;
    target_mdl.start_va.set(aligned);
    target_mdl.byte_offset.set((virtual_address & 0xFFF) as u32);
    target_mdl.byte_count.set(length);
    target_mdl.mdl_flags.set(target_mdl.mdl_flags.get() | MDL_PARTIAL);
    let offset = aligned.wrapping_sub(source_start) / 0x1000;
    let pages = ((virtual_address & 0xFFF) + length as u64).div_ceil(0x1000);
    for (page, pfn) in pfn_array(target, pages).iter().enumerate() {
        // SAFETY: entrada `offset + page` do vetor de PFNs do MDL de origem
        // (a janela pedida está dentro dele).
        let source_pfn = unsafe { Field::<u64>::at(source + Mdl::SIZE + (offset + page as u64) * 8) };
        pfn.set(source_pfn.get());
    }
}
