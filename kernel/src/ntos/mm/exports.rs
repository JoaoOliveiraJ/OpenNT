//! Exports Mm* (memória não cacheada, I/O space, MDL, mapeamentos reservados,
//! sondagem de usuário).

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
    Ok(io_space::map_ex(call.arg(1), call.arg(2)))
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
    //! MmIsAddressValid.

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
    //! MmCreateSection. Entrega um
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
    //! MmMapMemoryDumpMdl.

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
    //! Memória física contígua.
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
    //! Paginação de imagens de drivers.

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
    //! MmMapViewInSystemSpace (entrada de três argumentos, no fim da ABI para
    //! preservar os ids).

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::mm::section::map_system_view;
    use crate::rtl::KernelError;

    fn map(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("map-system-view", map_system_view::map_from_start(call.arg(1), call.arg(2), call.arg(3)))? as u64)
    }

    pub static GROUP: Group = Group { name: "map-section-in-system-space", names: &["MmMapViewInSystemSpace"], handlers: &[map], data_exports: &[] };
}

pub mod map_system_view {
    //! MmMapViewInSystemSpaceEx; uma falha
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
    //! MmSizeOfMdl.

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
    //! MmGetPhysicalMemoryRanges.

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
    //! MmProtectMdlSystemAddress.

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
    //! MmUnmapViewInSystemSpace.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::mm::section::unmap_system_view;
    use crate::rtl::KernelError;

    fn unmap(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("unmap-system-view", unmap_system_view::unmap(call.arg(1)))? as u64)
    }

    pub static GROUP: Group = Group { name: "unmap-system-view", names: &["MmUnmapViewInSystemSpace"], handlers: &[unmap], data_exports: &[] };
}

pub mod create_section {
    //! ZwCreateSection; o Zw usa KernelMode
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
    //! ZwOpenSection, em KernelMode.

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
    //! ZwMapViewOfSection, em KernelMode.

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
    //! ZwUnmapViewOfSection, em KernelMode.

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
    //! ZwQueryVirtualMemory; a implementação
    //! e o estado pertencem ao `mm/query_virtual`.

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

pub mod mm_verifier {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::verifier;
    use crate::rtl::KernelError;

    fn is_verifier_enabled(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(verifier::is_enabled(call.arg(1))))
    }

    fn is_driver_verifying(call: &Call) -> Result<u64, KernelError> {
        Ok(verifier::is_driver_verifying(call.arg(1)) as u64)
    }

    fn is_driver_verifying_by_address(call: &Call) -> Result<u64, KernelError> {
        Ok(verifier::is_driver_verifying_by_address(call.arg(1)) as u64)
    }

    fn add_verifier_thunks(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(verifier::add_thunks(call.arg(1), call.arg(2) as u32)))
    }

    fn is_driver_suspect_for_verifier(call: &Call) -> Result<u64, KernelError> {
        Ok(verifier::is_driver_suspect(call.arg(1)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "mm-verifier",
        names: &["MmIsVerifierEnabled", "MmIsDriverVerifying", "MmIsDriverVerifyingByAddress", "MmAddVerifierThunks", "MmIsDriverSuspectForVerifier"],
        handlers: &[is_verifier_enabled, is_driver_verifying, is_driver_verifying_by_address, add_verifier_thunks, is_driver_suspect_for_verifier],
        data_exports: &[],
    };
}

pub mod mm_session_views {
    use crate::ntos::init::exports::{fatal_unless_transfer, signed_status, Call, Group};
    use crate::ntos::mm::section::session_view;
    use crate::rtl::KernelError;

    fn map(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(fatal_unless_transfer("map-session-view", session_view::map(call.arg(1), call.arg(2), call.arg(3)))?))
    }

    fn map_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(fatal_unless_transfer("map-session-view", session_view::map_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5)))?))
    }

    fn unmap(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(fatal_unless_transfer("unmap-session-view", session_view::unmap(call.arg(1)))?))
    }

    fn commit(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(session_view::commit(call.arg(1), call.arg(2))?))
    }

    pub static GROUP: Group = Group {
        name: "mm-session-views",
        names: &["MmMapViewInSessionSpace", "MmMapViewInSessionSpaceEx", "MmUnmapViewInSessionSpace", "MmCommitSessionMappedView"],
        handlers: &[map, map_ex, unmap, commit],
        data_exports: &[],
    };
}

pub mod mm_system_image {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::sysload;
    use crate::rtl::KernelError;

    fn load(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(sysload::load_system_image(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6))?))
    }

    fn unload(call: &Call) -> Result<u64, KernelError> {
        sysload::unload_system_image(call.arg(1))?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "mm-system-image",
        names: &["MmLoadSystemImage", "MmUnloadSystemImage"],
        handlers: &[load, unload],
        data_exports: &[],
    };
}

pub mod mm_mdl_ex {
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::mdl;
    use crate::rtl::KernelError;

    fn allocate_pages_for_mdl_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(mdl::allocate_pages_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, 0, call.arg(6) as u32))
    }

    fn allocate_node_pages_for_mdl_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(mdl::allocate_pages_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u32, call.arg(7) as u32))
    }

    fn create_mdl(call: &Call) -> Result<u64, KernelError> {
        Ok(mdl::create(call.arg(1), call.arg(2), call.arg(3)))
    }

    /// MmMapLockedPagesSpecifyCache(Mdl, AccessMode, MmCached, NULL, TRUE, HighPagePriority).
    fn map_locked_pages(call: &Call) -> Result<u64, KernelError> {
        Ok(mdl::map_locked_pages(call.arg(1), 0))
    }

    fn mdl_page_contents_state(call: &Call) -> Result<u64, KernelError> {
        Ok(mdl::page_contents_state(call.arg(1), call.arg(2) as u32) as u64)
    }

    fn probe_and_lock_process_pages(call: &Call) -> Result<u64, KernelError> {
        mdl::probe_and_lock_process_pages(call.arg(1), call.arg(2), call.arg(3) as u8, call.arg(4) as u32)?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "mm-mdl-ex",
        names: &["MmAllocatePagesForMdlEx", "MmAllocateNodePagesForMdlEx", "MmCreateMdl", "MmMapLockedPages", "MmMdlPageContentsState", "MmProbeAndLockProcessPages"],
        handlers: &[allocate_pages_for_mdl_ex, allocate_node_pages_for_mdl_ex, create_mdl, map_locked_pages, mdl_page_contents_state, probe_and_lock_process_pages],
        data_exports: &[],
    };
}

pub mod mm_secure_memory {
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::secure_memory;
    use crate::rtl::KernelError;

    fn secure(call: &Call) -> Result<u64, KernelError> {
        Ok(secure_memory::secure(call.arg(1), call.arg(2), call.arg(3) as u32))
    }

    fn unsecure(call: &Call) -> Result<u64, KernelError> {
        secure_memory::unsecure(call.arg(1));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "mm-secure-memory",
        names: &["MmSecureVirtualMemory", "MmUnsecureVirtualMemory"],
        handlers: &[secure, unsecure],
        data_exports: &[],
    };
}

pub mod mm_physical_memory {
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::{contiguous_memory, native_pfn_database, physical_layout};
    use crate::rtl::KernelError;

    fn allocate_contiguous_node_memory(call: &Call) -> Result<u64, KernelError> {
        contiguous_memory::allocate_node(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u32)
    }

    fn get_virtual_for_physical(call: &Call) -> Result<u64, KernelError> {
        Ok(native_pfn_database::virtual_for_physical(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "mm-physical-memory",
        names: &["MmAllocateContiguousNodeMemory", "MmGetVirtualForPhysical"],
        handlers: &[allocate_contiguous_node_memory, get_virtual_for_physical],
        data_exports: &[("Mm64BitPhysicalAddress", physical_layout::sixty_four_bit_physical_address_cell)],
    };
}

pub mod mm_system_info {
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::system_info;
    use crate::rtl::KernelError;

    fn is_this_an_nt_as_system(_: &Call) -> Result<u64, KernelError> {
        Ok(system_info::is_this_an_nt_as_system() as u64)
    }

    fn query_system_size(_: &Call) -> Result<u64, KernelError> {
        Ok(system_info::query_system_size() as u64)
    }

    pub static GROUP: Group = Group {
        name: "mm-system-info",
        names: &["MmIsThisAnNtAsSystem", "MmQuerySystemSize"],
        handlers: &[is_this_an_nt_as_system, query_system_size],
        data_exports: &[("MmSystemRangeStart", system_info::system_range_start_cell), ("MmBadPointer", system_info::bad_pointer_cell)],
    };
}

pub mod mm_file_system_support {
    //! MmForceSectionClosed, MmMdlPagesAreZero e MmSetAddressRangeModified:
    //! a lógica mora em `mm/section/object_pointers.rs`, `mm/mdl.rs` e
    //! `mm/modified_pages.rs`.

    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::{Mdl, SectionObjectPointers};
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::section::object_pointers;
    use crate::ntos::mm::{mdl, modified_pages};
    use crate::rtl::KernelError;

    /// MmForceSectionClosed(SectionObjectPointer, DelayClose) -> BOOLEAN.
    fn force_section_closed(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: SECTION_OBJECT_POINTERS do FCB do FS chamador.
        let pointers = unsafe { SectionObjectPointers::at(call.arg(1)) };
        Ok(object_pointers::force_section_closed(pointers, call.arg(2) as u8 != 0) as u64)
    }

    /// MmMdlPagesAreZero(Mdl) -> BOOLEAN.
    fn mdl_pages_are_zero(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: MDL vivo do FS chamador.
        Ok(mdl::pages_are_zero(unsafe { Mdl::at(call.arg(1)) }) as u64)
    }

    /// MmSetAddressRangeModified(Address, Length) -> BOOLEAN.
    fn set_address_range_modified(call: &Call) -> Result<u64, KernelError> {
        Ok(modified_pages::set_address_range_modified(call.arg(1), call.arg(2)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "mm-file-system-support",
        names: &["MmForceSectionClosed", "MmMdlPagesAreZero", "MmSetAddressRangeModified"],
        handlers: &[force_section_closed, mdl_pages_are_zero, set_address_range_modified],
        data_exports: &[],
    };
}

pub mod vf_device_verification {
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::verifier;
    use crate::rtl::KernelError;

    fn is_verification_enabled(call: &Call) -> Result<u64, KernelError> {
        Ok(verifier::is_verification_enabled(call.arg(1) as u32, call.arg(2)) as u64)
    }

    fn fail_device_node(call: &Call) -> Result<u64, KernelError> {
        verifier::fail_device_node(call.arg(1));
        Ok(0)
    }

    fn fail_system_bios(_: &Call) -> Result<u64, KernelError> {
        verifier::fail_system_bios();
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "vf-device-verification",
        names: &["VfFailDeviceNode", "VfFailSystemBIOS", "VfIsVerificationEnabled"],
        handlers: &[fail_device_node, fail_system_bios, is_verification_enabled],
        data_exports: &[],
    };
}
