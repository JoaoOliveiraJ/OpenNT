//! Exports Mm* (memória não cacheada, I/O space, MDL, mapeamentos reservados,
//! sondagem de usuário) — `system32/win32/ntoskrnl/mm.js`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::init::exports::{self, Call, Group};
use crate::ntos::mm::{image_paging, kernel_data, memory_map, paging, pfn};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::nt_abi::mdl;
use crate::ntos::mm::pe_loader::ResolvedImport;

/// Mapeamentos de I/O space ativos (VA == PA: o mapa é identidade); a
/// tabela rastreia e valida o unmap, como o NT.
static IO_SPACE_MAPPINGS: SpinLock<BTreeMap<u64, (u64, u64)>> = SpinLock::new(BTreeMap::new());
/// Regiões reservadas por MmAllocateMappingAddress: tamanho e tag.
static RESERVED_MAPPINGS: SpinLock<BTreeMap<u64, (u64, u32)>> = SpinLock::new(BTreeMap::new());

/// Valida faixa e alinhamento de ProbeForRead/ProbeForWrite. Este caminho
/// ainda para a máquina em vez de levantar uma exceção NT capturável; a
/// permissão de escrita por página continua pendente.
fn probe_user_address(address: u64, length: u64, alignment: u64) {
    let alignment = if alignment == 0 { 1 } else { alignment };
    if length == 0 {
        return;
    }
    let highest = memory_map::USER_ADDRESS_LIMIT - 1;
    if address > highest || length > highest - address + 1 || address % alignment != 0 {
        debug_print!("[mm] ProbeForRead/Write: endereco invalido {:#x} len {:#x} — kernel SEH dispatch not implemented", address, length);
        crate::hal::cpu::halt_forever();
    }
}

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

fn allocate_non_cached_memory(call: &Call) -> Result<u64, KernelError> {
    Ok(guest::alloc_bytes(call.arg(1)))
}
fn free_non_cached_memory(call: &Call) -> Result<u64, KernelError> {
    guest::free_bytes(call.arg(1));
    Ok(0)
}
/// Identidade: a VA devolvida é o endereço físico.
fn map_io_space(call: &Call) -> Result<u64, KernelError> {
    IO_SPACE_MAPPINGS.lock().insert(call.arg(1), (call.arg(1), call.arg(2) as u32 as u64));
    Ok(call.arg(1))
}
fn unmap_io_space(call: &Call) -> Result<u64, KernelError> {
    IO_SPACE_MAPPINGS.lock().remove(&call.arg(1));
    Ok(0)
}
/// Anda as tabelas de página de verdade.
fn get_physical_address(call: &Call) -> Result<u64, KernelError> {
    Ok(paging::translate(call.arg(1)))
}
fn get_system_address_for_mdl_safe(call: &Call) -> Result<u64, KernelError> {
    Ok(guest::read64(call.arg(1) + mdl::MAPPED_SYSTEM_VA))
}
/// Endereço chamável do export (trampolim ou dado real), como o
/// GetProcAddress de kernel; nome desconhecido devolve NULL.
fn get_system_routine_address(call: &Call) -> Result<u64, KernelError> {
    let name = guest_strings::read_unicode_string(call.arg(1));
    match exports::lookup("", &name) {
        Some(ResolvedImport::Thunk(id)) => exports::thunk_address(id as u64),
        Some(ResolvedImport::Address { address, .. }) => Ok(address),
        None => {
            let length = guest::read16(call.arg(1));
            let buffer = guest::read64(call.arg(1) + 8);
            let raw: alloc::string::String = (0..length.min(32) as u64).map(|index| guest::read8(buffer + index) as char).collect();
            debug_print!("[mm] NAO ACHOU: \"{}\" (len={} buf={:#x} raw=\"{}\")", name, length, buffer, raw);
            Ok(0)
        }
    }
}
/// Identidade: StartVa + ByteOffset (ou o endereço pedido), gravado no MDL.
fn map_locked_pages_specify_cache(call: &Call) -> Result<u64, KernelError> {
    let descriptor = call.arg(1);
    let mapped = if call.arg(4) != 0 { call.arg(4) } else { guest::read64(descriptor + mdl::START_VA) + guest::read32(descriptor + mdl::BYTE_OFFSET) as u64 };
    guest::write64(descriptor + mdl::MAPPED_SYSTEM_VA, mapped);
    set_flags(descriptor, mdl::FLAG_MAPPED_TO_SYSTEM_VA, 0);
    Ok(mapped)
}
fn unmap_locked_pages(call: &Call) -> Result<u64, KernelError> {
    set_flags(call.arg(2), 0, mdl::FLAG_MAPPED_TO_SYSTEM_VA);
    Ok(0)
}
fn map_io_space_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(call.arg(1))
}
/// O pool é residente: as páginas já estão travadas; o PFN array é real.
fn probe_and_lock_pages(call: &Call) -> Result<u64, KernelError> {
    fill_pfn_array(call.arg(1));
    set_flags(call.arg(1), mdl::FLAG_PAGES_LOCKED, 0);
    Ok(0)
}
fn unlock_pages(call: &Call) -> Result<u64, KernelError> {
    set_flags(call.arg(1), 0, mdl::FLAG_PAGES_LOCKED);
    Ok(0)
}
fn build_mdl_for_non_paged_pool(call: &Call) -> Result<u64, KernelError> {
    fill_pfn_array(call.arg(1));
    set_flags(call.arg(1), mdl::FLAG_SOURCE_NONPAGED | mdl::FLAG_PAGES_LOCKED, 0);
    Ok(0)
}
/// VA reservada, alinhada à página e fora do alcance de outras alocações.
fn allocate_mapping_address(call: &Call) -> Result<u64, KernelError> {
    let address = guest::alloc_aligned(call.arg(1), 0x1000, true);
    if address == 0 {
        return Ok(0);
    }
    RESERVED_MAPPINGS.lock().insert(address, (call.arg(1) as u32 as u64, call.arg(2) as u32));
    Ok(address)
}
fn free_mapping_address(call: &Call) -> Result<u64, KernelError> {
    RESERVED_MAPPINGS.lock().remove(&call.arg(1));
    guest::free_bytes(call.arg(1));
    Ok(0)
}
/// Exige a VA reservada e remapeia as páginas dela para as do MDL.
fn map_locked_pages_with_reserved_mapping(call: &Call) -> Result<u64, KernelError> {
    let address = call.arg(1);
    let descriptor = call.arg(3);
    if !RESERVED_MAPPINGS.lock().contains_key(&address) {
        return Ok(0);
    }
    let count = guest::read32(descriptor + mdl::BYTE_COUNT) as u64;
    let offset = guest::read32(descriptor + mdl::BYTE_OFFSET) as u64;
    for index in 0..(offset + count).div_ceil(0x1000) {
        let frame = guest::read64(descriptor + mdl::PFN_ARRAY + index * 8);
        if !paging::map_page(address + index * 0x1000, frame * 0x1000, paging::PAGE_PRESENT | paging::PAGE_RW, paging::MapOptions::default()) {
            return Ok(0);
        }
    }
    let mapped = address + offset;
    guest::write64(descriptor + mdl::MAPPED_SYSTEM_VA, mapped);
    set_flags(descriptor, mdl::FLAG_MAPPED_TO_SYSTEM_VA, 0);
    Ok(mapped)
}
fn unmap_reserved_mapping(call: &Call) -> Result<u64, KernelError> {
    let descriptor = call.arg(3);
    let count = guest::read32(descriptor + mdl::BYTE_COUNT) as u64;
    let offset = guest::read32(descriptor + mdl::BYTE_OFFSET) as u64;
    let base = guest::read64(descriptor + mdl::MAPPED_SYSTEM_VA) - offset;
    for index in 0..(offset + count).div_ceil(0x1000) {
        paging::unmap_page(base + index * 0x1000, paging::MapOptions::default());
    }
    set_flags(descriptor, 0, mdl::FLAG_MAPPED_TO_SYSTEM_VA);
    Ok(0)
}
fn lock_pagable_data_section(call: &Call) -> Result<u64, KernelError> {
    image_paging::lock(call.arg(1))
}
fn unlock_pagable_image_section(call: &Call) -> Result<u64, KernelError> {
    image_paging::unlock(call.arg(1))
}
/// Confere só faixa e alinhamento, sem ler a memória do usuário.
fn probe_for_read(call: &Call) -> Result<u64, KernelError> {
    probe_user_address(call.arg(1), call.arg(2), call.arg(3) as u32 as u64);
    Ok(0)
}
fn probe_for_write(call: &Call) -> Result<u64, KernelError> {
    probe_user_address(call.arg(1), call.arg(2), call.arg(3) as u32 as u64);
    Ok(0)
}
/// Páginas físicas reais da arena PFN descritas num MDL novo (sem mapear).
fn allocate_pages_for_mdl(call: &Call) -> Result<u64, KernelError> {
    let byte_count = call.arg(4);
    if byte_count == 0 || byte_count > 0x7FFF_FFFF {
        return Ok(0);
    }
    let page_count = byte_count.div_ceil(0x1000);
    let mut frames = Vec::new();
    for _ in 0..page_count {
        let frame = pfn::alloc_page();
        if frame == 0 {
            for frame in frames {
                pfn::free_page(frame);
            }
            return Ok(0);
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
    Ok(descriptor)
}
/// Devolve as páginas físicas; o MDL continua vivo (quem alocou libera).
fn free_pages_from_mdl(call: &Call) -> Result<u64, KernelError> {
    let descriptor = call.arg(1);
    let size = guest::read16(descriptor + mdl::SIZE) as u64;
    for index in 0..size.saturating_sub(mdl::PFN_ARRAY) / 8 {
        let frame = guest::read64(descriptor + mdl::PFN_ARRAY + index * 8);
        if frame != 0 {
            pfn::free_page(frame * 0x1000);
        }
    }
    Ok(0)
}

fn data_address(name: &str) -> u64 {
    kernel_data::address(name).unwrap_or_else(|error| panic!("{name}: {error}"))
}
fn section_object_type_address() -> u64 {
    data_address("MmSectionObjectType")
}
fn user_probe_address() -> u64 {
    data_address("MmUserProbeAddress")
}
fn highest_user_address() -> u64 {
    data_address("MmHighestUserAddress")
}

pub static GROUP: Group = Group {
    name: "mm",
    names: &[
        "MmAllocateNonCachedMemory", "MmFreeNonCachedMemory", "MmMapIoSpace", "MmUnmapIoSpace", "MmGetPhysicalAddress", "MmGetSystemAddressForMdlSafe", "MmGetSystemRoutineAddress",
        "MmMapLockedPagesSpecifyCache", "MmUnmapLockedPages", "MmMapIoSpaceEx", "MmProbeAndLockPages", "MmUnlockPages", "MmBuildMdlForNonPagedPool",
        "MmAllocateMappingAddress", "MmFreeMappingAddress", "MmMapLockedPagesWithReservedMapping", "MmUnmapReservedMapping", "MmLockPagableDataSection", "MmUnlockPagableImageSection",
        "ProbeForRead", "ProbeForWrite", "MmAllocatePagesForMdl", "MmFreePagesFromMdl",
    ],
    handlers: &[
        allocate_non_cached_memory, free_non_cached_memory, map_io_space, unmap_io_space, get_physical_address, get_system_address_for_mdl_safe, get_system_routine_address,
        map_locked_pages_specify_cache, unmap_locked_pages, map_io_space_ex, probe_and_lock_pages, unlock_pages, build_mdl_for_non_paged_pool,
        allocate_mapping_address, free_mapping_address, map_locked_pages_with_reserved_mapping, unmap_reserved_mapping, lock_pagable_data_section, unlock_pagable_image_section,
        probe_for_read, probe_for_write, allocate_pages_for_mdl, free_pages_from_mdl,
    ],
    data_exports: &[("MmSectionObjectType", section_object_type_address), ("MmUserProbeAddress", user_probe_address), ("MmHighestUserAddress", highest_user_address)],
};

pub mod address_validity {
    //! MmIsAddressValid — `system32/win32/ntoskrnl/address-validity.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::mm::small;

    fn is_address_valid(call: &Call) -> Result<u64, KernelError> {
        Ok(small::is_address_valid(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "address-validity",
        names: &["MmIsAddressValid"],
        handlers: &[is_address_valid],
        data_exports: &[],
    };
}

pub mod create_section_object {
    //! MmCreateSection — `win32/ntoskrnl/create-section-object.js`. Entrega um
    //! SECTION referenciado; o construtor comum conserva o arquivo, as proteções
    //! e a vida do objeto sem criar handle oculto.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::section::create as create_section;
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn create_object(call: &Call) -> Result<u64, KernelError> {
        let mode = previous_mode::get()?;
        Ok(create_section::create_object(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u32, call.arg(7), call.arg(8), mode)? as u64)
    }

    pub static GROUP: Group = Group { name: "create-section-object", names: &["MmCreateSection"], handlers: &[create_object], data_exports: &[] };
}

pub mod dump_mdl {
    //! MmMapMemoryDumpMdl — `system32/win32/ntoskrnl/dump-mdl.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::mm::dump_mdl;

    fn map_memory_dump_mdl(call: &Call) -> Result<u64, KernelError> {
        dump_mdl::map(call.arg(1))?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "dump-mdl",
        names: &["MmMapMemoryDumpMdl"],
        handlers: &[map_memory_dump_mdl],
        data_exports: &[],
    };
}

pub mod free_contiguous {
    //! Memória física contígua — `system32/win32/ntoskrnl/free-contiguous.js`.
    //!
    //! O provedor mantém metadados e propriedade de cada alocação; a liberação
    //! com cache usa o tamanho e o cache dos metadados, não os argumentos.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::mm::contiguous_memory;

    fn free_contiguous_memory(call: &Call) -> Result<u64, KernelError> {
        contiguous_memory::free(call.arg(1))?;
        Ok(0)
    }

    fn allocate_contiguous_memory(call: &Call) -> Result<u64, KernelError> {
        contiguous_memory::allocate_default(call.arg(1), call.arg(2))
    }

    fn allocate_contiguous_memory_specify_cache(call: &Call) -> Result<u64, KernelError> {
        contiguous_memory::allocate_specify_cache(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32)
    }

    pub static GROUP: Group = Group {
        name: "free-contiguous",
        names: &["MmFreeContiguousMemory", "MmAllocateContiguousMemory", "MmFreeContiguousMemorySpecifyCache", "MmAllocateContiguousMemorySpecifyCache"],
        handlers: &[free_contiguous_memory, allocate_contiguous_memory, free_contiguous_memory, allocate_contiguous_memory_specify_cache],
        data_exports: &[],
    };
}

pub mod image_paging_exports {
    //! Paginação de imagens de drivers — `system32/win32/ntoskrnl/image-paging.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::image_paging;
    use crate::rtl::KernelError;

    fn page_entire_driver(call: &Call) -> Result<u64, KernelError> {
        image_paging::make_pageable(call.arg(1))
    }

    fn reset_driver_paging(call: &Call) -> Result<u64, KernelError> {
        image_paging::reset(call.arg(1))
    }

    fn lock_pagable_code_section(call: &Call) -> Result<u64, KernelError> {
        image_paging::lock(call.arg(1))
    }

    fn lock_pagable_section_by_handle(call: &Call) -> Result<u64, KernelError> {
        image_paging::lock_handle(call.arg(1))
    }

    pub static GROUP: Group = Group {
        name: "image-paging",
        names: &["MmPageEntireDriver", "MmResetDriverPaging", "MmLockPagableCodeSection", "MmLockPagableSectionByHandle"],
        handlers: &[page_entire_driver, reset_driver_paging, lock_pagable_code_section, lock_pagable_section_by_handle],
        data_exports: &[],
    };
}

pub mod map_section_in_system_space {
    //! MmMapViewInSystemSpace — `win32/ntoskrnl/map-section-in-system-space.js`
    //! (entrada de três argumentos, no fim da ABI para preservar os ids).

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::mm::section::map_system_view;
    use crate::rtl::KernelError;

    fn map(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("map-system-view", map_system_view::map_from_start(call.arg(1), call.arg(2), call.arg(3)))? as u64)
    }

    pub static GROUP: Group = Group { name: "map-section-in-system-space", names: &["MmMapViewInSystemSpace"], handlers: &[map], data_exports: &[] };
}

pub mod map_system_view {
    //! MmMapViewInSystemSpaceEx — `win32/ntoskrnl/map-system-view.js`; uma falha
    //! interna interrompe o convidado sem publicar endereço substituto.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::mm::section::map_system_view;
    use crate::rtl::KernelError;

    fn map_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("map-system-view", map_system_view::map(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5)))? as u64)
    }

    pub static GROUP: Group = Group { name: "map-system-view", names: &["MmMapViewInSystemSpaceEx"], handlers: &[map_ex], data_exports: &[] };
}

pub mod mdl_size {
    //! MmSizeOfMdl — `system32/win32/ntoskrnl/mdl-size.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::mm::small;

    fn size_of_mdl(call: &Call) -> Result<u64, KernelError> {
        Ok(small::size_of_memory_descriptor(call.arg(1), call.arg(2)))
    }

    pub static GROUP: Group = Group {
        name: "mdl-size",
        names: &["MmSizeOfMdl"],
        handlers: &[size_of_mdl],
        data_exports: &[],
    };
}

pub mod physical_ranges {
    //! MmGetPhysicalMemoryRanges — `system32/win32/ntoskrnl/physical-ranges.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::mm::module_queries;

    fn get_physical_memory_ranges(_: &Call) -> Result<u64, KernelError> {
        module_queries::query_physical_ranges()
    }

    pub static GROUP: Group = Group {
        name: "physical-ranges",
        names: &["MmGetPhysicalMemoryRanges"],
        handlers: &[get_physical_memory_ranges],
        data_exports: &[],
    };
}

pub mod protect_mdl {
    //! MmProtectMdlSystemAddress — `system32/win32/ntoskrnl/protect-mdl.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::mm::module_queries;

    fn protect_mdl_system_address(call: &Call) -> Result<u64, KernelError> {
        Ok(module_queries::protect_mdl(call.arg(1), call.arg(2) as u32)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "protect-mdl",
        names: &["MmProtectMdlSystemAddress"],
        handlers: &[protect_mdl_system_address],
        data_exports: &[],
    };
}

pub mod unmap_system_view {
    //! MmUnmapViewInSystemSpace — `win32/ntoskrnl/unmap-system-view.js`.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::mm::section::unmap_system_view;
    use crate::rtl::KernelError;

    fn unmap(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("unmap-system-view", unmap_system_view::unmap(call.arg(1)))? as u64)
    }

    pub static GROUP: Group = Group { name: "unmap-system-view", names: &["MmUnmapViewInSystemSpace"], handlers: &[unmap], data_exports: &[] };
}

pub mod create_section {
    //! ZwCreateSection — `win32/ntoskrnl/create-section.js`; o Zw usa KernelMode
    //! durante toda a operação e restaura o modo anterior.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::section::create as create_section;
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn create(call: &Call) -> Result<u64, KernelError> {
        let status = previous_mode::with_kernel(|| create_section::create(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u32, call.arg(7), 0, None))??;
        Ok(status as u64)
    }

    pub static GROUP: Group = Group { name: "create-section", names: &["ZwCreateSection"], handlers: &[create], data_exports: &[] };
}

pub mod open_section {
    //! ZwOpenSection — `win32/ntoskrnl/open-section.js`, em KernelMode.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::section::open as open_section;
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn open(call: &Call) -> Result<u64, KernelError> {
        Ok(previous_mode::with_kernel(|| open_section::open(call.arg(1), call.arg(2) as u32, call.arg(3), 0))?? as u64)
    }

    pub static GROUP: Group = Group { name: "open-section", names: &["ZwOpenSection"], handlers: &[open], data_exports: &[] };
}

pub mod map_view {
    //! ZwMapViewOfSection — `win32/ntoskrnl/map-view.js`, em KernelMode.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::section::map_view;
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn map(call: &Call) -> Result<u64, KernelError> {
        let status = previous_mode::with_kernel(|| map_view::map(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8) as u32, call.arg(9) as u32, call.arg(10) as u32, 0))??;
        Ok(status as u64)
    }

    pub static GROUP: Group = Group { name: "map-view", names: &["ZwMapViewOfSection"], handlers: &[map], data_exports: &[] };
}

pub mod unmap_view {
    //! ZwUnmapViewOfSection — `win32/ntoskrnl/unmap-view.js`, em KernelMode.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::section::unmap_view;
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn unmap(call: &Call) -> Result<u64, KernelError> {
        Ok(previous_mode::with_kernel(|| unmap_view::unmap(call.arg(1), call.arg(2), 0))?? as u64)
    }

    pub static GROUP: Group = Group { name: "unmap-view", names: &["ZwUnmapViewOfSection"], handlers: &[unmap], data_exports: &[] };
}

pub mod query_virtual {
    //! ZwQueryVirtualMemory — `win32/ntoskrnl/query-virtual.js`; a implementação
    //! e o estado pertencem ao `mm/query-virtual`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::query_virtual;
    use crate::rtl::KernelError;

    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(query_virtual::query(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6))? as u64)
    }

    pub static GROUP: Group = Group { name: "query-virtual", names: &["ZwQueryVirtualMemory"], handlers: &[query], data_exports: &[] };
}

pub mod view_of_section {
    //! MmMapViewOfSection/MmUnmapViewOfSection: as versões por ponteiro (objeto
    //! seção e EPROCESS) do Nt/ZwMapViewOfSection. O NT converte handles em
    //! objetos antes de chamar estas rotinas; aqui o caminho é o inverso, com o
    //! mesmo efeito: handles de kernel temporários abertos pelo
    //! ObOpenObjectByPointer em KernelMode, a mesma validação e o mesmo
    //! mapeamento do Nt, e os handles fechados no fim.

    use crate::ntos::init::exports::{invoke_handler, signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::mm::section::map_view;
    use crate::ntos::ob::{object_types, open_pointer};
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    const OBJ_KERNEL_HANDLE: u32 = 0x200;
    const SECTION_ALL_ACCESS: u32 = 0xF_001F;
    const PROCESS_ALL_ACCESS: u32 = 0x1F_FFFF;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

    /// Handle de kernel para `object` (Ok(handle) ou Err(status)).
    fn kernel_handle(object: u64, access: u32, object_type: u64) -> Result<Result<u64, u32>, KernelError> {
        let slot = guest::alloc_bytes(8);
        if slot == 0 {
            return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
        }
        let status = open_pointer::open(object, OBJ_KERNEL_HANDLE, 0, access, object_type, 0, slot);
        let handle = guest::read64(slot);
        guest::free_bytes(slot);
        Ok(match status? {
            0 => Ok(handle),
            status => Err(status),
        })
    }

    fn close(handle: u64) -> Result<(), KernelError> {
        invoke_handler("ZwClose", &[handle]).map(|_| ())
    }

    fn map(call: &Call) -> Result<u64, KernelError> {
        let (section, process) = (call.arg(1), call.arg(2));
        let section_handle = match kernel_handle(section, SECTION_ALL_ACCESS, 0)? {
            Ok(handle) => handle,
            Err(status) => return Ok(signed_status(status)),
        };
        let process_handle = match kernel_handle(process, PROCESS_ALL_ACCESS, object_types::process_type().pointer)? {
            Ok(handle) => handle,
            Err(status) => {
                close(section_handle)?;
                return Ok(signed_status(status));
            }
        };
        let status = previous_mode::with_kernel(|| map_view::map(section_handle, process_handle, call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8) as u32, call.arg(9) as u32, call.arg(10) as u32, 0));
        close(process_handle)?;
        close(section_handle)?;
        Ok(signed_status(status??))
    }

    fn unmap(call: &Call) -> Result<u64, KernelError> {
        let process_handle = match kernel_handle(call.arg(1), PROCESS_ALL_ACCESS, object_types::process_type().pointer)? {
            Ok(handle) => handle,
            Err(status) => return Ok(signed_status(status)),
        };
        let status = previous_mode::with_kernel(|| map_view::unmap(process_handle, call.arg(2), 0));
        close(process_handle)?;
        Ok(signed_status(status??))
    }

    pub static GROUP: Group = Group {
        name: "view-of-section",
        names: &["MmMapViewOfSection", "MmUnmapViewOfSection"],
        handlers: &[map, unmap],
        data_exports: &[],
    };
}

pub mod virtual_memory_services {
    //! ZwAllocateVirtualMemory(Ex)/ZwFreeVirtualMemory/ZwProtectVirtualMemory
    //! em KernelMode: o processo alvo vem do handle (o pseudo-handle é o
    //! processo corrente, inclusive anexado) e é retido durante a operação;
    //! o processo de usuário ativo usa os VADs do runtime, os demais as
    //! regiões privadas do próprio espaço (`ps::user::memory::Space`).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ke::irql;
    use crate::ntos::mm::query_virtual;
    use crate::ntos::ps::process;
    use crate::ntos::ps::user::memory::{self, Space};
    use crate::rtl::KernelError;

    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
    const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
    const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
    const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
    const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RESET: u32 = 0x8_0000;
    const MEM_TOP_DOWN: u32 = 0x10_0000;
    const MEM_WRITE_WATCH: u32 = 0x20_0000;
    const MEM_PHYSICAL: u32 = 0x40_0000;
    const MEM_RESET_UNDO: u32 = 0x100_0000;
    const MEM_LARGE_PAGES: u32 = 0x2000_0000;

    /// Executa `body` no espaço do processo do handle, com o processo retido.
    fn with_target(handle: u64, body: impl FnOnce(Space) -> Result<u32, KernelError>) -> Result<u64, KernelError> {
        if irql::get_irql() != 0 {
            return Err(KernelError::new("Zw*VirtualMemory requires PASSIVE_LEVEL"));
        }
        let pointer = match query_virtual::target(handle) {
            Ok((pointer, _)) => pointer,
            Err(status) => return Ok(signed_status(status)),
        };
        let Some(terminated) = process::with_record(pointer, |record| record.terminated) else { return Ok(signed_status(STATUS_INVALID_HANDLE)) };
        if terminated {
            return Ok(signed_status(STATUS_PROCESS_IS_TERMINATING));
        }
        if process::reference(pointer).is_none() {
            return Ok(signed_status(STATUS_INVALID_HANDLE));
        }
        let result = body(Space::of(pointer));
        process::dereference(pointer)?;
        Ok(signed_status(result?))
    }

    /// ZeroBits: até 53 é a quantidade de bits altos zerados; acima disso é
    /// uma máscara do endereço mais alto. 0 = limite padrão do espaço.
    fn highest_from_zero_bits(zero_bits: u64) -> Result<u64, u32> {
        match zero_bits {
            0 => Ok(0),
            1..=53 => Ok(u64::MAX >> zero_bits),
            mask if mask >= 0x1_0000 => Ok(u64::MAX >> mask.leading_zeros()),
            _ => Err(STATUS_INVALID_PARAMETER_3),
        }
    }

    /// Tipos de alocação: COMMIT/RESERVE/TOP_DOWN vão ao alocador; RESET só
    /// valida (o conteúdo pode ser preservado); os demais não existem aqui.
    fn checked_type(allocation_type: u32) -> Result<u32, u32> {
        let known = MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_PHYSICAL | MEM_RESET_UNDO | MEM_LARGE_PAGES;
        if allocation_type & !known != 0 || allocation_type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET | MEM_RESET_UNDO) == 0 {
            return Err(STATUS_INVALID_PARAMETER_5);
        }
        if allocation_type & MEM_LARGE_PAGES != 0 {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        if allocation_type & (MEM_WRITE_WATCH | MEM_PHYSICAL | MEM_RESET_UNDO) != 0 {
            return Err(STATUS_NOT_SUPPORTED);
        }
        Ok(allocation_type)
    }

    /// MEM_RESET: a faixa precisa estar inteira numa região comitada.
    fn reset(space: Space, base_pointer: u64, size_pointer: u64) -> Result<u32, KernelError> {
        memory::validate_committed(space, base_pointer, size_pointer)
    }

    fn allocate(call: &Call) -> Result<u64, KernelError> {
        let (base_pointer, zero_bits, size_pointer, allocation_type, protect) = (call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u32);
        let highest = match highest_from_zero_bits(zero_bits) {
            Ok(highest) => highest,
            Err(status) => return Ok(signed_status(status)),
        };
        let allocation_type = match checked_type(allocation_type) {
            Ok(value) => value,
            Err(status) => return Ok(signed_status(status)),
        };
        with_target(call.arg(1), |space| {
            if allocation_type & MEM_RESET != 0 {
                return reset(space, base_pointer, size_pointer);
            }
            memory::allocate_in(space, base_pointer, size_pointer, allocation_type & (MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN), protect, 0, highest, 0x1_0000)
        })
    }

    fn allocate_ex(call: &Call) -> Result<u64, KernelError> {
        let (base_pointer, size_pointer, allocation_type, protect, parameters, count) = (call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32, call.arg(6), call.arg(7) as u32 as u64);
        let allocation_type = match checked_type(allocation_type) {
            Ok(value) => value,
            Err(status) => return Ok(signed_status(status)),
        };
        with_target(call.arg(1), |space| {
            if allocation_type & MEM_RESET != 0 {
                return reset(space, base_pointer, size_pointer);
            }
            memory::allocate_ex_in(space, base_pointer, size_pointer, allocation_type & (MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN), protect, parameters, count)
        })
    }

    fn free(call: &Call) -> Result<u64, KernelError> {
        let (base_pointer, size_pointer, free_type) = (call.arg(2), call.arg(3), call.arg(4) as u32);
        with_target(call.arg(1), |space| memory::free_in(space, base_pointer, size_pointer, free_type))
    }

    fn protect(call: &Call) -> Result<u64, KernelError> {
        let (base_pointer, size_pointer, new_protect, old_pointer) = (call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5));
        with_target(call.arg(1), |space| memory::protect_in(space, base_pointer, size_pointer, new_protect, old_pointer, false))
    }

    pub static GROUP: Group = Group {
        name: "virtual-memory",
        names: &["ZwAllocateVirtualMemory", "ZwAllocateVirtualMemoryEx", "ZwFreeVirtualMemory", "ZwProtectVirtualMemory"],
        handlers: &[allocate, allocate_ex, free, protect],
        data_exports: &[],
    };
}
