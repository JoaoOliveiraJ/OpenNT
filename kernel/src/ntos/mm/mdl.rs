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

// ---- MDL Ex: alocação por faixa/nó, MmCreateMdl, estado do conteúdo e
// ---- sondagem em outro processo (mm-mdl-ex) ---------------------------------
//
// Contrato do ntoskrnl 19041:
// - MmAllocatePagesForMdlEx(Low, High, Skip, Total, CacheType, Flags) =
//   MmAllocatePartitionNodePagesForMdlEx(..., nó corrente, Flags, NULL);
//   MmAllocateNodePagesForMdlEx(..., IdealNode, Flags) o mesmo com o nó do
//   chamador. Nó >= KeNumberNodes -> NULL; CacheType -1 ou > 2 -> 3;
//   Flags & 0xFFFFF800 -> NULL; REQUIRE_CONTIGUOUS_CHUNKS sem FAST_LARGE_PAGES
//   liga PREFER_CONTIGUOUS e exige Skip 0 (-> FULLY_REQUIRED) ou potência de
//   dois >= 4 KiB que divida Total; AND_HOT_REMOVE recusa FULLY_REQUIRED e
//   IRQL != 0. MiValidateMdlAllocationRequest: Skip desalinhado -> NULL, Skip
//   não potência de dois -> 0 (NULL com FAST_LARGE_PAGES), Total > 0xFFFFE000
//   é limitado (NULL com FULLY_REQUIRED), zero páginas -> NULL, mais páginas
//   que as disponíveis é limitado (NULL com FULLY_REQUIRED). MiObtainMdlCharges
//   monta o MDL ('Mmdi', Size = (páginas + 6) * 8, ByteCount = páginas << 12,
//   StartVa/ByteOffset/MappedSystemVa = 0); MiInitializeMdlPages liga
//   MDL_PAGES_LOCKED e zera Process; as páginas são zeradas salvo
//   MM_DONT_ZERO_ALLOCATION.
// - MmCreateMdl(Mdl, Base, Length): Length >= 4 GiB -> NULL; Mdl NULL -> pool
//   'Mmdl' de páginas*8 + 0x30; grava Next, MdlFlags = 0, StartVa, ByteCount,
//   ByteOffset e Size = ((páginas + 6) << 3) como USHORT; Process e
//   MappedSystemVa ficam intocados.
// - MmMdlPageContentsState(Mdl, State): 2 consulta o bit 14
//   (MDL_PAGE_CONTENTS_INVARIANT), 1 liga, os demais desligam; devolve State.
// - MmProbeAndLockProcessPages(Mdl, Process, AccessMode, Operation):
//   Operation 0 = IoReadAccess, qualquer outra = IoWriteAccess;
//   KeStackAttachProcess quando Process != ApcState.Process,
//   MmProbeAndLockPages, KeUnstackDetachProcess.
//
// Lacunas: o CacheType só é validado (o atributo de cache pertence ao
// mapeamento de MmMapLockedPagesSpecifyCache); MM_ALLOCATE_FAST_LARGE_PAGES
// devolve NULL (sem alocador de blocos de 2 MiB; o NT também devolve NULL sem
// páginas grandes); PREFER_CONTIGUOUS é dica e não é honrada; a flag 0x400 é
// só validada.

const MDL_ALLOCATION_PAGE: u64 = 0x1000;
const MDL_ALLOCATION_PFN_LIMIT: u64 = 0xF_FFFF_FFFF;
const MDL_ALLOCATION_MAX_BYTES: u64 = 0xFFFF_E000;
/// KeNumberNodes: um nó NUMA.
const MDL_ALLOCATION_NODES: u32 = 1;
/// MDL_PAGE_CONTENTS_INVARIANT (bit 14 de MdlFlags).
const CONTENTS_INVARIANT_FLAG: u16 = 0x4000;

const MM_DONT_ZERO_ALLOCATION: u32 = 0x1;
const MM_ALLOCATE_FULLY_REQUIRED: u32 = 0x4;
const MM_ALLOCATE_PREFER_CONTIGUOUS: u32 = 0x10;
const MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS: u32 = 0x20;
const MM_ALLOCATE_FAST_LARGE_PAGES: u32 = 0x40;
const MM_ALLOCATE_AND_HOT_REMOVE: u32 = 0x100;
/// Bit interno que MiValidateMdlAllocationRequest liga quando a faixa pedida
/// começa no PFN 0 e alcança o maior PFN físico (o limite de 4 GiB do OpenNT).
const MM_ALLOCATE_WHOLE_RANGE: u32 = 0x1_0000;

fn free_allocated_frames(frames: &[u64]) {
    for &frame in frames {
        pfn::free_page(frame);
    }
}

/// MmAllocatePartitionNodePagesForMdlEx sobre a partição do sistema; 0 = NULL.
pub fn allocate_pages_ex(low: u64, high: u64, skip: u64, total: u64, cache_type: u32, node: u32, flags: u32) -> u64 {
    if node >= MDL_ALLOCATION_NODES {
        return 0;
    }
    let cache_type = if cache_type == u32::MAX || (cache_type as i32) > 2 { 3 } else { cache_type };
    if flags & 0xFFFF_F800 != 0 {
        return 0;
    }
    let mut flags = flags;
    if flags & (MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS | MM_ALLOCATE_FAST_LARGE_PAGES) == MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS {
        flags |= MM_ALLOCATE_PREFER_CONTIGUOUS;
        if skip == 0 {
            flags |= MM_ALLOCATE_FULLY_REQUIRED;
        } else if skip & skip.wrapping_sub(1) != 0 || (skip as i64) < 0x1000 || total % skip != 0 {
            return 0;
        }
    }
    if flags & MM_ALLOCATE_AND_HOT_REMOVE != 0 && (flags & MM_ALLOCATE_FULLY_REQUIRED != 0 || crate::ntos::ke::irql::get_irql() != 0) {
        return 0;
    }

    // MiValidateMdlAllocationRequest.
    let low_pfn = low >> 12;
    let high_pfn = (high >> 12).min(MDL_ALLOCATION_PFN_LIMIT);
    if low_pfn == 0 && high_pfn >= (super::memory_map::PHYSICAL_MEMORY_LIMIT >> 12) - 1 {
        flags |= MM_ALLOCATE_WHOLE_RANGE;
    }
    if skip & (MDL_ALLOCATION_PAGE - 1) != 0 {
        return 0;
    }
    let mut skip_pages = skip >> 12;
    if skip_pages & skip_pages.wrapping_sub(1) != 0 {
        if flags & MM_ALLOCATE_FAST_LARGE_PAGES != 0 {
            return 0;
        }
        skip_pages = 0;
    }
    if flags & 0x400 != 0 && (flags & 0x362 != 0 || flags & (MM_ALLOCATE_WHOLE_RANGE | MM_DONT_ZERO_ALLOCATION) == 0 || cache_type.wrapping_sub(1) & !2 != 0) {
        return 0;
    }
    let mut total = total;
    if total > MDL_ALLOCATION_MAX_BYTES {
        if flags & MM_ALLOCATE_FULLY_REQUIRED != 0 {
            return 0;
        }
        total = MDL_ALLOCATION_MAX_BYTES;
        if flags & 0x60 != 0 && skip_pages != 0 {
            total &= !((skip_pages << 12) - 1);
        }
    }
    let mut pages = (total + MDL_ALLOCATION_PAGE - 1) >> 12;
    if flags & MM_ALLOCATE_FAST_LARGE_PAGES != 0 {
        return 0;
    }
    let available = pfn::free_count();
    if available == 0 || pages == 0 {
        return 0;
    }
    if pages > available {
        if flags & MM_ALLOCATE_FULLY_REQUIRED != 0 {
            return 0;
        }
        pages = available;
    }

    // Frames reais da faixa pedida (o alocador comum quando a faixa é toda a RAM).
    let mut frames = Vec::new();
    while (frames.len() as u64) < pages {
        let frame = if flags & MM_ALLOCATE_WHOLE_RANGE != 0 { pfn::alloc_page() } else { pfn::alloc_contiguous(1, 1, high_pfn, low_pfn, 0) };
        if frame == 0 {
            break;
        }
        frames.push(frame);
    }
    if frames.is_empty() || ((frames.len() as u64) < pages && flags & MM_ALLOCATE_FULLY_REQUIRED != 0) {
        free_allocated_frames(&frames);
        return 0;
    }
    let descriptor = guest::alloc_bytes(mdl::PFN_ARRAY + pages * 8);
    if descriptor == 0 {
        free_allocated_frames(&frames);
        return 0;
    }
    if flags & MM_DONT_ZERO_ALLOCATION == 0 {
        for &frame in &frames {
            crate::hal::physical::zero(frame, MDL_ALLOCATION_PAGE as usize);
        }
    }
    guest::write64(descriptor + mdl::NEXT, 0);
    guest::write16(descriptor + mdl::SIZE, ((pages + 6) << 3) as u16);
    guest::write16(descriptor + mdl::MDL_FLAGS, mdl::FLAG_PAGES_LOCKED);
    guest::write64(descriptor + mdl::PROCESS, 0);
    guest::write64(descriptor + mdl::MAPPED_SYSTEM_VA, 0);
    guest::write64(descriptor + mdl::START_VA, 0);
    guest::write32(descriptor + mdl::BYTE_COUNT, (frames.len() as u64 * MDL_ALLOCATION_PAGE) as u32);
    guest::write32(descriptor + mdl::BYTE_OFFSET, 0);
    // PFNs não obtidos ficam 0 (MmFreePagesFromMdl os ignora).
    for index in 0..pages {
        let frame = frames.get(index as usize).copied().unwrap_or(0);
        guest::write64(descriptor + mdl::PFN_ARRAY + index * 8, frame / MDL_ALLOCATION_PAGE);
    }
    descriptor
}

/// MmCreateMdl: o MDL inicializado (alocado quando `descriptor` é 0) ou 0.
pub fn create(descriptor: u64, base: u64, length: u64) -> u64 {
    if length >= 0x1_0000_0000 {
        return 0;
    }
    let offset = base & (MDL_ALLOCATION_PAGE - 1);
    let pages = (length + (MDL_ALLOCATION_PAGE - 1) + offset) >> 12;
    let descriptor = if descriptor != 0 { descriptor } else { guest::alloc_bytes(pages * 8 + mdl::PFN_ARRAY) };
    if descriptor == 0 {
        return 0;
    }
    guest::write64(descriptor + mdl::NEXT, 0);
    guest::write16(descriptor + mdl::MDL_FLAGS, 0);
    guest::write32(descriptor + mdl::BYTE_COUNT, length as u32);
    guest::write64(descriptor + mdl::START_VA, base & !(MDL_ALLOCATION_PAGE - 1));
    guest::write16(descriptor + mdl::SIZE, ((pages as u16).wrapping_add(6)).wrapping_shl(3));
    guest::write32(descriptor + mdl::BYTE_OFFSET, offset as u32);
    descriptor
}

/// MmMdlPageContentsState: consulta (2) ou troca o bit e devolve State.
pub fn page_contents_state(descriptor: u64, state: u32) -> u32 {
    let flags = guest::read16(descriptor + mdl::MDL_FLAGS);
    if state == 2 {
        return ((flags >> 14) & 1) as u32;
    }
    let updated = if state == 1 { flags | CONTENTS_INVARIANT_FLAG } else { flags & !CONTENTS_INVARIANT_FLAG };
    guest::write16(descriptor + mdl::MDL_FLAGS, updated);
    state
}

/// MmProbeAndLockProcessPages: sonda no espaço de `target`, anexando quando
/// ele não é o processo corrente. O modo e a operação não mudam o caminho do
/// OpenNT (o pool é residente e as páginas já estão travadas).
pub fn probe_and_lock_process_pages(descriptor: u64, target: u64, _access_mode: u8, operation: u32) -> Result<(), crate::rtl::KernelError> {
    let _operation = if operation == 0 { 0u32 } else { 1 };
    if target == crate::ntos::ps::process::get_current_process() {
        probe_and_lock_pages(descriptor);
        return Ok(());
    }
    let state = guest::alloc_bytes(0x30);
    if state == 0 {
        return Err(crate::rtl::KernelError::with_status("MmProbeAndLockProcessPages: KAPC_STATE allocation failed", 0xC000_009A));
    }
    if let Err(error) = crate::ntos::ke::process_attachment::attach(target, state) {
        guest::free_bytes(state);
        return Err(error);
    }
    probe_and_lock_pages(descriptor);
    let detached = crate::ntos::ke::process_attachment::detach(state);
    guest::free_bytes(state);
    detached.map(|_| ())
}
