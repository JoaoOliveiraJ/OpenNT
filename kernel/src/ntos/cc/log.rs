//! Fluxos com log e consultas de páginas sujas — o papel do `cache\logsup.c`
//! do NT (CcSetLogHandleForFile, CcGetDirtyPages, ...), mais as consultas de
//! sujeira por volume e o callback de erro do Cc.
//!
//! O log handle e as rotinas (FlushToLsnRoutine, QueryLogUsageRoutine) ficam
//! no mapa; o bit 24 de SHARED_CACHE_MAP.Flags marca o fluxo com log, como o
//! CcSetLogHandleForFileEx. CcGetDirtyPages entrega, por BCB sujo, os
//! endereços dentro do próprio BCB nativo (FileOffset, OldestLsn, NewestLsn),
//! como o NT. Sem partições do Cc, o CcErrorCallbackRoutine não tem o que
//! drenar.

use alloc::vec::Vec;

use super::cache_map::{self, LogHandle, CACHE};
use super::layout::{self, scm_flags, status, Bcb};
use super::status::CcResult;
use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::Vpb;
use crate::ntos::ob::objects::file as file_objects;

/// CcSetLogHandleForFileEx(FileObject, LogHandle, FlushToLsnRoutine,
/// QueryLogUsageRoutine, RelatedLogHandleFileObject). LogHandle NULL desliga.
pub fn set_log_handle_for_file(file: u64, handle: u64, flush_to_lsn: u64, query_log_usage: u64, related_file: u64) -> CcResult<()> {
    let base = cache_map::require_map(file)?;
    let previous = {
        let mut cache = CACHE.lock();
        let Some(map) = cache.maps.get_mut(&base) else { return Ok(()) };
        let previous = map.log.related_file;
        if handle == 0 {
            map.log = LogHandle::default();
            map.set_flags(0, scm_flags::LOGGED_STREAM);
        } else {
            map.log = LogHandle { handle, flush_to_lsn, query_log_usage, related_file };
            map.set_flags(scm_flags::LOGGED_STREAM, 0);
        }
        // SHARED_CACHE_MAP.V1 (_LOGGED_STREAM_CALLBACK_V1).
        let v1 = &map.native().v1;
        v1.log_handle.set(map.log.handle);
        v1.flush_to_lsn_routine.set(map.log.flush_to_lsn);
        previous
    };
    // O FILE_OBJECT relacionado é referenciado enquanto registrado.
    if related_file != 0 && handle != 0 {
        let _ = file_objects::reference(related_file);
    }
    if previous != 0 {
        let _ = file_objects::dereference(previous);
    }
    Ok(())
}

/// CcGetDirtyPages(LogHandle, DirtyPageRoutine, Context1, Context2): chama
/// DirtyPageRoutine(FileObject, &FileOffset, Length, &OldestLsn, &NewestLsn,
/// Context1, Context2) por BCB sujo dos fluxos do log; devolve o menor
/// OldestLsn (0 sem páginas sujas com log).
pub fn get_dirty_pages(handle: u64, routine: u64, context1: u64, context2: u64) -> u64 {
    let dirty: Vec<(u64, u64, u32, u64)> = {
        let cache = CACHE.lock();
        cache
            .maps
            .values()
            .filter(|map| map.log.handle == handle)
            .flat_map(|map| map.bcbs.iter().filter(|(_, bcb)| bcb.dirty).map(move |(&address, bcb)| (map.file_object, address, bcb.length, bcb.oldest_lsn)))
            .collect()
    };
    let mut oldest = 0u64;
    for (file, address, length, lsn) in dirty {
        if lsn != 0 && (oldest == 0 || lsn < oldest) {
            oldest = lsn;
        }
        if routine != 0 {
            // SAFETY: BCB sujo do mapa (os ponteiros apontam para dentro dele, como no NT).
            let bcb = unsafe { Bcb::at(address) };
            native_call::call(routine, &[file, bcb.file_offset.address(), length as u64, bcb.oldest_lsn.address(), bcb.newest_lsn.address(), context1, context2]);
        }
    }
    oldest
}

/// Dispositivo de volume de um FILE_OBJECT (Vpb->DeviceObject ou DeviceObject).
fn volume_device(file: u64) -> (u64, u64) {
    let file = cache_map::file_object(file);
    let vpb = file.vpb.get();
    // SAFETY: o VPB montado do FILE_OBJECT do mapa.
    (if vpb != 0 { unsafe { Vpb::at(vpb) }.device_object.get() } else { 0 }, file.device_object.get())
}

/// CcIsThereDirtyLoggedPages(DeviceObject, NumberOfDirtyPages): páginas sujas
/// dos fluxos com log do volume.
pub fn is_there_dirty_logged_pages(device: u64, count_pointer: u64) -> bool {
    let count: u32 = CACHE
        .lock()
        .maps
        .values()
        .filter(|map| map.log.handle != 0)
        .filter(|map| {
            let (mounted, own) = volume_device(map.file_object);
            mounted == device || own == device
        })
        .map(|map| map.dirty_pages())
        .sum();
    if count == 0 {
        return false;
    }
    if count_pointer != 0 {
        // SAFETY: PULONG de saída de kernel do file system.
        unsafe { Field::<u32>::at(count_pointer) }.set(count);
    }
    true
}

/// CcGetCachedDirtyPageCountForFile(SectionObjectPointer): DirtyPages do mapa,
/// ou 0xFFFFFFFF sem cache map.
pub fn cached_dirty_page_count(pointers: u64) -> u32 {
    let Some(base) = cache_map::map_of_pointers(pointers) else { return u32::MAX };
    CACHE.lock().maps.get(&base).map_or(u32::MAX, |map| map.dirty_pages())
}

/// CcSetLoggedDataThreshold(LogHandle, NumberOfPages): registrado por log;
/// o limite global do CcCanIWrite continua valendo.
pub fn set_logged_data_threshold(handle: u64, pages: u32) {
    CACHE.lock().logged_thresholds.insert(handle, pages);
}

/// CcIsThereDirtyData(Vpb): algum arquivo do volume (não temporário) com
/// páginas sujas.
pub fn is_there_dirty_data(vpb: u64) -> bool {
    CACHE.lock().maps.values().any(|map| {
        let file = cache_map::file_object(map.file_object);
        file.vpb.get() == vpb && map.dirty_pages() != 0 && file.flags.get() & layout::FO_TEMPORARY_FILE == 0
    })
}

/// CcErrorCallbackRoutine(Context): só STATUS 0xC000A008 pede a drenagem de
/// deleções entre partições; sem partições, nada a drenar. Devolve 0.
pub fn error_callback_routine(_context: u64) -> u32 {
    status::SUCCESS
}

/// CcIsCacheManagerCallbackNeeded(Status).
pub fn is_cache_manager_callback_needed(code: u32) -> bool {
    code == status::CROSS_PARTITION_DRAIN
}
