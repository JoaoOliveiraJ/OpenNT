//! Exports Mm* (memória não cacheada, I/O space, MDL, mapeamentos reservados,
//! sondagem de usuário) — `system32/win32/ntoskrnl/mm.js`.

use crate::ntos::init::exports::{Call, Group};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{image_paging, io_space, kernel_data, mdl, paging, small, sysload};
use crate::rtl::KernelError;

fn allocate_non_cached_memory(call: &Call) -> Result<u64, KernelError> {
    Ok(guest::alloc_bytes(call.arg(1)))
}
fn free_non_cached_memory(call: &Call) -> Result<u64, KernelError> {
    guest::free_bytes(call.arg(1));
    Ok(0)
}
fn map_io_space(call: &Call) -> Result<u64, KernelError> {
    Ok(io_space::map(call.arg(1), call.arg(2)))
}
fn unmap_io_space(call: &Call) -> Result<u64, KernelError> {
    io_space::unmap(call.arg(1));
    Ok(0)
}
/// Anda as tabelas de página de verdade.
fn get_physical_address(call: &Call) -> Result<u64, KernelError> {
    Ok(paging::translate(call.arg(1)))
}
fn get_system_address_for_mdl_safe(call: &Call) -> Result<u64, KernelError> {
    Ok(mdl::system_address(call.arg(1)))
}
fn get_system_routine_address(call: &Call) -> Result<u64, KernelError> {
    sysload::system_routine_address(call.arg(1))
}
fn map_locked_pages_specify_cache(call: &Call) -> Result<u64, KernelError> {
    Ok(mdl::map_locked_pages(call.arg(1), call.arg(4)))
}
fn unmap_locked_pages(call: &Call) -> Result<u64, KernelError> {
    mdl::unmap_locked_pages(call.arg(2));
    Ok(0)
}
fn map_io_space_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(io_space::map_ex(call.arg(1)))
}
fn probe_and_lock_pages(call: &Call) -> Result<u64, KernelError> {
    mdl::probe_and_lock_pages(call.arg(1));
    Ok(0)
}
fn unlock_pages(call: &Call) -> Result<u64, KernelError> {
    mdl::unlock_pages(call.arg(1));
    Ok(0)
}
fn build_mdl_for_non_paged_pool(call: &Call) -> Result<u64, KernelError> {
    mdl::build_for_non_paged_pool(call.arg(1));
    Ok(0)
}
fn allocate_mapping_address(call: &Call) -> Result<u64, KernelError> {
    Ok(mdl::allocate_mapping_address(call.arg(1), call.arg(2) as u32))
}
fn free_mapping_address(call: &Call) -> Result<u64, KernelError> {
    mdl::free_mapping_address(call.arg(1));
    Ok(0)
}
fn map_locked_pages_with_reserved_mapping(call: &Call) -> Result<u64, KernelError> {
    Ok(mdl::map_locked_pages_with_reserved_mapping(call.arg(1), call.arg(3)))
}
fn unmap_reserved_mapping(call: &Call) -> Result<u64, KernelError> {
    mdl::unmap_reserved_mapping(call.arg(3));
    Ok(0)
}
fn lock_pagable_data_section(call: &Call) -> Result<u64, KernelError> {
    image_paging::lock(call.arg(1))
}
fn unlock_pagable_image_section(call: &Call) -> Result<u64, KernelError> {
    image_paging::unlock(call.arg(1))
}
fn probe_for_read(call: &Call) -> Result<u64, KernelError> {
    small::probe_user_address(call.arg(1), call.arg(2), call.arg(3) as u32);
    Ok(0)
}
fn probe_for_write(call: &Call) -> Result<u64, KernelError> {
    small::probe_user_address(call.arg(1), call.arg(2), call.arg(3) as u32);
    Ok(0)
}
fn allocate_pages_for_mdl(call: &Call) -> Result<u64, KernelError> {
    Ok(mdl::allocate_pages(call.arg(4)))
}
fn free_pages_from_mdl(call: &Call) -> Result<u64, KernelError> {
    mdl::free_pages(call.arg(1));
    Ok(0)
}

fn section_object_type_address() -> u64 {
    kernel_data::required_address("MmSectionObjectType")
}
fn user_probe_address() -> u64 {
    kernel_data::required_address("MmUserProbeAddress")
}
fn highest_user_address() -> u64 {
    kernel_data::required_address("MmHighestUserAddress")
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
    //! seção e EPROCESS) do Nt/ZwMapViewOfSection; a lógica mora em
    //! `mm/section/map_view`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::section::map_view;
    use crate::rtl::KernelError;

    fn map(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(map_view::map_by_pointer(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8) as u32, call.arg(9) as u32, call.arg(10) as u32)?))
    }

    fn unmap(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(map_view::unmap_by_pointer(call.arg(1), call.arg(2))?))
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
    //! em KernelMode; a lógica mora em `mm/virtual_memory_services`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::virtual_memory_services;
    use crate::rtl::KernelError;

    fn allocate(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(virtual_memory_services::allocate(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u32)?))
    }

    fn allocate_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(virtual_memory_services::allocate_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32, call.arg(6), call.arg(7) as u32)?))
    }

    fn free(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(virtual_memory_services::free(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32)?))
    }

    fn protect(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(virtual_memory_services::protect(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5))?))
    }

    pub static GROUP: Group = Group {
        name: "virtual-memory",
        names: &["ZwAllocateVirtualMemory", "ZwAllocateVirtualMemoryEx", "ZwFreeVirtualMemory", "ZwProtectVirtualMemory"],
        handlers: &[allocate, allocate_ex, free, protect],
        data_exports: &[],
    };
}
