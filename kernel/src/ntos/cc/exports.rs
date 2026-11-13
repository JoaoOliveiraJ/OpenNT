//! Exports do Cache Manager: adaptadores finos sobre os assuntos de
//! ntos::cc (ARQUITETURA, seção 3.1).

pub mod cc_cache_map {
    //! Shared/private cache maps (adaptadores de `ntos::cc::cache_map`).

    use crate::ntos::cc::{cache_map, status};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn initialize_cache_map(call: &Call) -> Result<u64, KernelError> {
        status::into_export(cache_map::initialize_cache_map(call.arg(1), call.arg(2), call.arg(3) as u8 != 0, call.arg(4), call.arg(5), 0).map(|()| 0))
    }

    fn initialize_cache_map_ex(call: &Call) -> Result<u64, KernelError> {
        status::into_export(cache_map::initialize_cache_map(call.arg(1), call.arg(2), call.arg(3) as u8 != 0, call.arg(4), call.arg(5), call.arg(6) as u32).map(|()| 0))
    }

    fn uninitialize_cache_map(call: &Call) -> Result<u64, KernelError> {
        status::into_export(cache_map::uninitialize_cache_map(call.arg(1), call.arg(2), call.arg(3)).map(u64::from))
    }

    fn set_file_sizes(call: &Call) -> Result<u64, KernelError> {
        status::into_export(cache_map::set_file_sizes(call.arg(1), call.arg(2)).map(|_| 0))
    }

    fn set_file_sizes_ex(call: &Call) -> Result<u64, KernelError> {
        status::into_export(cache_map::set_file_sizes(call.arg(1), call.arg(2)).map(signed_status))
    }

    fn set_additional_cache_attributes(call: &Call) -> Result<u64, KernelError> {
        status::into_export(cache_map::set_additional_cache_attributes(call.arg(1), call.arg(2) as u8 != 0, call.arg(3) as u8 != 0).map(|()| 0))
    }

    fn set_additional_cache_attributes_ex(call: &Call) -> Result<u64, KernelError> {
        status::into_export(cache_map::set_additional_cache_attributes_ex(call.arg(1), call.arg(2) as u32).map(|()| 0))
    }

    fn set_read_ahead_granularity(call: &Call) -> Result<u64, KernelError> {
        cache_map::set_read_ahead_granularity(call.arg(1), call.arg(2) as u32);
        Ok(0)
    }

    fn set_parallel_flush_file(call: &Call) -> Result<u64, KernelError> {
        status::into_export(cache_map::set_parallel_flush_file(call.arg(1), call.arg(2) as u8 != 0).map(|()| 0))
    }

    fn get_file_object_from_section_ptrs(call: &Call) -> Result<u64, KernelError> {
        Ok(cache_map::file_object_from_section_pointers(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "cc-cache-map",
        names: &[
            "CcInitializeCacheMap",
            "CcInitializeCacheMapEx",
            "CcUninitializeCacheMap",
            "CcSetFileSizes",
            "CcSetFileSizesEx",
            "CcSetAdditionalCacheAttributes",
            "CcSetAdditionalCacheAttributesEx",
            "CcSetReadAheadGranularity",
            "CcSetParallelFlushFile",
            "CcGetFileObjectFromSectionPtrs",
        ],
        handlers: &[
            initialize_cache_map,
            initialize_cache_map_ex,
            uninitialize_cache_map,
            set_file_sizes,
            set_file_sizes_ex,
            set_additional_cache_attributes,
            set_additional_cache_attributes_ex,
            set_read_ahead_granularity,
            set_parallel_flush_file,
            get_file_object_from_section_ptrs,
        ],
        data_exports: &[],
    };
}

pub mod cc_copy {
    //! Cópias em cache e controle de escrita (adaptadores de `ntos::cc::copy`).

    use crate::ntos::cc::{copy, status};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn copy_read(call: &Call) -> Result<u64, KernelError> {
        status::into_export(copy::copy_read(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u8 != 0, call.arg(5), call.arg(6)).map(u64::from))
    }

    fn fast_copy_read(call: &Call) -> Result<u64, KernelError> {
        status::into_export(copy::copy_read_at(call.arg(1), call.arg(2) as u32 as u64, call.arg(3) as u32, true, call.arg(5), call.arg(6)).map(|_| 0))
    }

    fn copy_write(call: &Call) -> Result<u64, KernelError> {
        status::into_export(copy::copy_write(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u8 != 0, call.arg(5)).map(u64::from))
    }

    fn fast_copy_write(call: &Call) -> Result<u64, KernelError> {
        status::into_export(copy::copy_write_at(call.arg(1), call.arg(2) as u32 as u64, call.arg(3) as u32, true, call.arg(4)).map(|_| 0))
    }

    fn copy_write_wont_flush(call: &Call) -> Result<u64, KernelError> {
        Ok(copy::copy_write_wont_flush(call.arg(1), call.arg(2), call.arg(3) as u32) as u64)
    }

    fn can_i_write(call: &Call) -> Result<u64, KernelError> {
        status::into_export(copy::can_i_write(call.arg(1), call.arg(2) as u32, call.arg(3) as u8 != 0, call.arg(4) as u8).map(u64::from))
    }

    fn defer_write(call: &Call) -> Result<u64, KernelError> {
        status::into_export(copy::defer_write(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u8 != 0).map(|()| 0))
    }

    pub static GROUP: Group = Group {
        name: "cc-copy",
        names: &[
            "CcCopyRead",
            "CcCopyReadEx",
            "CcAsyncCopyRead",
            "CcFastCopyRead",
            "CcCopyWrite",
            "CcCopyWriteEx",
            "CcFastCopyWrite",
            "CcCopyWriteWontFlush",
            "CcCanIWrite",
            "CcDeferWrite",
        ],
        handlers: &[copy_read, copy_read, copy_read, fast_copy_read, copy_write, copy_write, fast_copy_write, copy_write_wont_flush, can_i_write, defer_write],
        data_exports: &[],
    };
}

pub mod cc_pin {
    //! Mapear e fixar dados do cache (adaptadores de `ntos::cc::pin`).

    use crate::ntos::cc::{pin, status};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn map_data(call: &Call) -> Result<u64, KernelError> {
        status::into_export(pin::map_data(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, call.arg(5), call.arg(6)).map(u64::from))
    }

    fn pin_read(call: &Call) -> Result<u64, KernelError> {
        status::into_export(pin::pin_read(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, call.arg(5), call.arg(6)).map(u64::from))
    }

    fn prepare_pin_write(call: &Call) -> Result<u64, KernelError> {
        status::into_export(pin::prepare_pin_write(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u8 != 0, call.arg(5) as u32, call.arg(6), call.arg(7)).map(u64::from))
    }

    fn pin_mapped_data(call: &Call) -> Result<u64, KernelError> {
        status::into_export(pin::pin_mapped_data(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, call.arg(5)).map(u64::from))
    }

    fn set_dirty_pinned_data(call: &Call) -> Result<u64, KernelError> {
        status::into_export(pin::set_dirty_pinned_data(call.arg(1), call.arg(2)).map(|()| 0))
    }

    fn unpin_data(call: &Call) -> Result<u64, KernelError> {
        status::into_export(pin::unpin_data(call.arg(1)).map(|()| 0))
    }

    fn repin_bcb(call: &Call) -> Result<u64, KernelError> {
        status::into_export(pin::repin_bcb(call.arg(1)).map(|()| 0))
    }

    fn unpin_repinned_bcb(call: &Call) -> Result<u64, KernelError> {
        status::into_export(pin::unpin_repinned_bcb(call.arg(1), call.arg(2) as u8 != 0, call.arg(3)).map(|()| 0))
    }

    fn remap_bcb(call: &Call) -> Result<u64, KernelError> {
        status::into_export(pin::remap_bcb(call.arg(1)))
    }

    fn get_file_object_from_bcb(call: &Call) -> Result<u64, KernelError> {
        Ok(pin::file_object_from_bcb(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "cc-pin",
        names: &[
            "CcMapData",
            "CcPinRead",
            "CcPreparePinWrite",
            "CcPinMappedData",
            "CcSetDirtyPinnedData",
            "CcUnpinData",
            "CcUnpinDataForThread",
            "CcRepinBcb",
            "CcUnpinRepinnedBcb",
            "CcRemapBcb",
            "CcGetFileObjectFromBcb",
        ],
        handlers: &[map_data, pin_read, prepare_pin_write, pin_mapped_data, set_dirty_pinned_data, unpin_data, unpin_data, repin_bcb, unpin_repinned_bcb, remap_bcb, get_file_object_from_bcb],
        data_exports: &[],
    };
}

pub mod cc_flush {
    //! Flush, purge, zeragem e lazy writer (adaptadores de `ntos::cc::flush`).

    use crate::ntos::cc::{flush, status};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn flush_cache(call: &Call) -> Result<u64, KernelError> {
        status::into_export(flush::flush_cache(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4)).map(|()| 0))
    }

    fn flush_cache_to_lsn(call: &Call) -> Result<u64, KernelError> {
        status::into_export(flush::flush_cache_to_lsn(call.arg(1), call.arg(2), call.arg(3)).map(|()| 0))
    }

    fn purge_cache_section(call: &Call) -> Result<u64, KernelError> {
        status::into_export(flush::purge_cache_section(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u32).map(u64::from))
    }

    fn coherency_flush_and_purge_cache(call: &Call) -> Result<u64, KernelError> {
        status::into_export(flush::coherency_flush_and_purge_cache(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32).map(|()| 0))
    }

    fn zero_data(call: &Call) -> Result<u64, KernelError> {
        status::into_export(flush::zero_data(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u8 != 0).map(u64::from))
    }

    fn wait_for_current_lazy_writer_activity(_call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(flush::wait_for_current_lazy_writer_activity()))
    }

    fn unmap_file_offset_from_system_cache(call: &Call) -> Result<u64, KernelError> {
        status::into_export(flush::unmap_file_offset_from_system_cache(call.arg(1), call.arg(2), call.arg(3) as u32).map(u64::from))
    }

    pub static GROUP: Group = Group {
        name: "cc-flush",
        names: &[
            "CcFlushCache",
            "CcFlushCacheToLsn",
            "CcPurgeCacheSection",
            "CcCoherencyFlushAndPurgeCache",
            "CcZeroData",
            "CcWaitForCurrentLazyWriterActivity",
            "CcUnmapFileOffsetFromSystemCache",
        ],
        handlers: &[flush_cache, flush_cache_to_lsn, purge_cache_section, coherency_flush_and_purge_cache, zero_data, wait_for_current_lazy_writer_activity, unmap_file_offset_from_system_cache],
        data_exports: &[],
    };
}

pub mod cc_mdl {
    //! MDLs sobre o cache (adaptadores de `ntos::cc::mdl`).

    use crate::ntos::cc::{mdl, status};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn mdl_read(call: &Call) -> Result<u64, KernelError> {
        status::into_export(mdl::mdl_read(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5)).map(|()| 0))
    }

    fn mdl_read_complete(call: &Call) -> Result<u64, KernelError> {
        mdl::mdl_read_complete(call.arg(1), call.arg(2));
        Ok(0)
    }

    fn prepare_mdl_write(call: &Call) -> Result<u64, KernelError> {
        status::into_export(mdl::prepare_mdl_write(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5)).map(|()| 0))
    }

    fn mdl_write_complete(call: &Call) -> Result<u64, KernelError> {
        status::into_export(mdl::mdl_write_complete(call.arg(1), call.arg(2), call.arg(3)).map(|()| 0))
    }

    fn mdl_write_abort(call: &Call) -> Result<u64, KernelError> {
        mdl::mdl_write_abort(call.arg(1), call.arg(2));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "cc-mdl",
        names: &["CcMdlRead", "CcMdlReadComplete", "CcPrepareMdlWrite", "CcMdlWriteComplete", "CcMdlWriteAbort"],
        handlers: &[mdl_read, mdl_read_complete, prepare_mdl_write, mdl_write_complete, mdl_write_abort],
        data_exports: &[],
    };
}

pub mod cc_log {
    //! Fluxos com log e consultas de sujeira (adaptadores de `ntos::cc::log`).

    use crate::ntos::cc::{log, status};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn set_log_handle_for_file_ex(call: &Call) -> Result<u64, KernelError> {
        status::into_export(log::set_log_handle_for_file(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5)).map(|()| 0))
    }

    fn get_dirty_pages(call: &Call) -> Result<u64, KernelError> {
        Ok(log::get_dirty_pages(call.arg(1), call.arg(2), call.arg(3), call.arg(4)))
    }

    fn is_there_dirty_logged_pages(call: &Call) -> Result<u64, KernelError> {
        Ok(log::is_there_dirty_logged_pages(call.arg(1), call.arg(2)) as u64)
    }

    fn get_cached_dirty_page_count_for_file(call: &Call) -> Result<u64, KernelError> {
        Ok(log::cached_dirty_page_count(call.arg(1)) as u64)
    }

    fn set_logged_data_threshold(call: &Call) -> Result<u64, KernelError> {
        log::set_logged_data_threshold(call.arg(1), call.arg(2) as u32);
        Ok(0)
    }

    fn is_there_dirty_data(call: &Call) -> Result<u64, KernelError> {
        Ok(log::is_there_dirty_data(call.arg(1)) as u64)
    }

    fn error_callback_routine(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(log::error_callback_routine(call.arg(1))))
    }

    fn is_cache_manager_callback_needed(call: &Call) -> Result<u64, KernelError> {
        Ok(log::is_cache_manager_callback_needed(call.arg(1) as u32) as u64)
    }

    pub static GROUP: Group = Group {
        name: "cc-log",
        names: &[
            "CcSetLogHandleForFileEx",
            "CcGetDirtyPages",
            "CcIsThereDirtyLoggedPages",
            "CcGetCachedDirtyPageCountForFile",
            "CcSetLoggedDataThreshold",
            "CcIsThereDirtyData",
            "CcErrorCallbackRoutine",
            "CcIsCacheManagerCallbackNeeded",
        ],
        handlers: &[set_log_handle_for_file_ex, get_dirty_pages, is_there_dirty_logged_pages, get_cached_dirty_page_count_for_file, set_logged_data_threshold, is_there_dirty_data, error_callback_routine, is_cache_manager_callback_needed],
        data_exports: &[],
    };
}
