//! MDLs dos exports Io* — IoAllocateMdl, IoBuildPartialMdl e IoFreeMdl, no
//! layout do wdm.h, como no ntoskrnl 19041.
//!
//! O IoAllocateMdl só descreve o buffer: Size, StartVa, ByteOffset,
//! ByteCount e, nos MDLs de até 17 páginas (o tamanho da lookaside de MDLs),
//! MDL_ALLOCATED_FIXED_SIZE. O vetor de PFNs, Process e MappedSystemVa ficam
//! para quem descreve as páginas: MmBuildMdlForNonPagedPool,
//! MmProbeAndLockPages ou IoBuildPartialMdl (e o mapeamento, para o
//! MmMapLockedPagesSpecifyCache).

use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{Irp, Mdl, NtStruct};
use crate::ntos::mm::guest_memory as guest;

const MDL_ALLOCATED_FIXED_SIZE: i16 = 0x0008;
const MDL_PARTIAL: i16 = 0x0010;
/// Os bits que o IoBuildPartialMdl herda da origem: MDL_MAPPED_TO_SYSTEM_VA,
/// MDL_SOURCE_IS_NONPAGED_POOL, MDL_IO_PAGE_READ, MDL_WRITE_OPERATION,
/// MDL_IO_SPACE e MDL_PAGE_CONTENTS_INVARIANT.
const MDL_PARTIAL_INHERITED: i16 = 0x48C5;
/// Páginas que cabem num MDL da lookaside (0xB8 bytes).
const FIXED_SIZE_PAGES: u64 = 17;

/// Vetor de PFN_NUMBER que segue o cabeçalho do MDL (MmGetMdlPfnArray).
fn pfn_array(descriptor: u64, pages: u64) -> &'static [Field<u64>] {
    // SAFETY: o MDL foi alocado/dimensionado com espaço para `pages` PFNs.
    unsafe { Field::<u64>::array_at(descriptor + Mdl::SIZE, pages as usize) }
}

/// IoAllocateMdl(VirtualAddress, Length, ...) sem o IRP.
pub fn allocate_mdl(virtual_address: u64, length: u32) -> u64 {
    let byte_offset = virtual_address & 0xFFF;
    // ADDRESS_AND_SIZE_TO_SPAN_PAGES.
    let pages = (byte_offset + length as u64 + 0xFFF) >> 12;
    let fixed = pages <= FIXED_SIZE_PAGES;
    let allocation = Mdl::SIZE + if fixed { FIXED_SIZE_PAGES } else { pages } * 8;
    let descriptor = guest::alloc_bytes(allocation);
    if descriptor == 0 {
        return 0;
    }
    // SAFETY: alocação do MDL recém-criado, com espaço para os PFNs.
    let mdl = unsafe { Mdl::at(descriptor) };
    mdl.next.set(0);
    mdl.size.set(((pages as u16).wrapping_add(6) << 3) as i16);
    mdl.mdl_flags.set(if fixed { MDL_ALLOCATED_FIXED_SIZE } else { 0 });
    mdl.start_va.set(virtual_address & !0xFFF);
    mdl.byte_count.set(length);
    mdl.byte_offset.set(byte_offset as u32);
    descriptor
}

/// IoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp):
/// com IRP, o MDL vira o MdlAddress dele ou, como buffer secundário, entra
/// no fim da cadeia.
pub fn allocate_mdl_for_irp(virtual_address: u64, length: u32, secondary_buffer: bool, irp: u64) -> u64 {
    let descriptor = allocate_mdl(virtual_address, length);
    if descriptor == 0 || irp == 0 {
        return descriptor;
    }
    // SAFETY: o PIRP do chamador.
    let packet = unsafe { Irp::at(irp) };
    let mut last = packet.mdl_address.get();
    if !secondary_buffer || last == 0 {
        packet.mdl_address.set(descriptor);
        return descriptor;
    }
    loop {
        // SAFETY: cadeia de MDLs (MDL.Next) do IRP.
        let next = unsafe { Mdl::at(last) }.next.get();
        if next == 0 {
            break;
        }
        last = next;
    }
    // SAFETY: o último MDL da cadeia.
    unsafe { Mdl::at(last) }.next.set(descriptor);
    descriptor
}

/// IoFreeMdl.
pub fn free_mdl(descriptor: u64) {
    guest::free_bytes(descriptor);
}

/// IoBuildPartialMdl: a janela do alvo dentro da origem, com o Process, os
/// bits herdáveis da origem, MDL_PARTIAL, a VA de sistema deslocada e os
/// PFNs correspondentes. Length 0 vai até o fim da origem.
pub fn build_partial_mdl(source: u64, target: u64, virtual_address: u64, length: u32) {
    // SAFETY: MDLs de origem e de destino do driver, dimensionados por ele.
    let (source_mdl, target_mdl) = unsafe { (Mdl::at(source), Mdl::at(target)) };
    let source_start = source_mdl.start_va.get();
    let offset = (virtual_address as u32).wrapping_sub(source_mdl.byte_offset.get()).wrapping_sub(source_start as u32);
    let length = if length == 0 { source_mdl.byte_count.get().wrapping_sub(offset) } else { length };
    let aligned = virtual_address & !0xFFF;
    target_mdl.process.set(source_mdl.process.get());
    target_mdl.start_va.set(aligned);
    target_mdl.byte_offset.set((virtual_address & 0xFFF) as u32);
    target_mdl.byte_count.set(length);
    let kept = target_mdl.mdl_flags.get() & MDL_ALLOCATED_FIXED_SIZE;
    target_mdl.mdl_flags.set(kept | source_mdl.mdl_flags.get() & MDL_PARTIAL_INHERITED | MDL_PARTIAL);
    target_mdl.mapped_system_va.set(source_mdl.mapped_system_va.get().wrapping_add(offset as u64));
    let first = (aligned as u32).wrapping_sub(source_start as u32) as u64 >> 12;
    let pages = ((virtual_address & 0xFFF) + length as u64 + 0xFFF) >> 12;
    for (page, pfn) in pfn_array(target, pages).iter().enumerate() {
        // SAFETY: entrada `first + page` do vetor de PFNs do MDL de origem
        // (a janela pedida está dentro dele).
        let source_pfn = unsafe { Field::<u64>::at(source + Mdl::SIZE + (first + page as u64) * 8) };
        pfn.set(source_pfn.get());
    }
}
