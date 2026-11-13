//! Escrita, flush, purge e zeragem — o papel do lazy writer do Cache Manager,
//! de CcFlushCache/CcPurgeCacheSection/CcZeroData e da escrita de
//! seção que o Mm faz por baixo no NT.
//!
//! [`write_range`] grava as páginas sujas por corridas contíguas dentro de
//! cada vista, com IRP_MJ_WRITE de paginação ao arquivo. Antes de uma corrida
//! coberta por BCBs com log, o write-ahead logging chama
//! FlushToLsnRoutine(LogHandle, NewestLsn). Uma falha devolve as páginas ao
//! estado sujo e o status sai no IoStatus (CcFlushCache não levanta).
//!
//! Sem thread de lazy writer: os dados sujos saem por CcFlushCache, pelo
//! write-through, pelo último CcUninitializeCacheMap e por
//! [`lazy_write_pass`], que roda (com AcquireForLazyWrite/ReleaseFromLazyWrite
//! sem espera e o TopLevelIrp preservado) quando o CcCanIWrite passa do
//! limite de páginas sujas.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::cache_map::{self, CacheManager, MapState, CACHE};
use super::layout::{self, purge_flags, status, PAGE_SIZE};
use super::section_io::{self, Fill};
use super::status::{CcResult, Failure};
use super::vacb;
use crate::hal::amd64::native_call;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_cc::CacheManagerCallbacks;
use crate::ntos::inc::types::{Ethread, IoStatusBlock, LargeInteger};
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// Páginas sujas de cada vista cobertas por BCBs com log até `limit`.
fn logged_masks(map: &MapState, limit: u64) -> BTreeMap<u64, u64> {
    let mut masks = BTreeMap::new();
    for bcb in map.bcbs.values() {
        if bcb.dirty && bcb.oldest_lsn != 0 && bcb.oldest_lsn <= limit {
            *masks.entry(bcb.view).or_insert(0u64) |= vacb::range_mask(bcb.view, bcb.offset, bcb.offset + bcb.length as u64);
        }
    }
    masks
}

/// Limpa os BCBs cujas páginas já não estão sujas; solta os sem pin.
fn clean_bcbs(map: &mut MapState) {
    let views = &map.views;
    let mut freed = Vec::new();
    for (&address, bcb) in map.bcbs.iter_mut() {
        let still_dirty = views.get(&bcb.view).is_some_and(|view| view.dirty & vacb::range_mask(bcb.view, bcb.offset, bcb.offset + bcb.length as u64) != 0);
        if bcb.dirty && !still_dirty {
            bcb.dirty = false;
            bcb.oldest_lsn = 0;
            bcb.newest_lsn = 0;
            // SAFETY: BCB nativo registrado neste mapa.
            let native = unsafe { layout::Bcb::at(address) };
            native.dirty.set(0);
            native.oldest_lsn.quad_part.set(0);
            native.newest_lsn.quad_part.set(0);
        }
        if !bcb.dirty && bcb.pins == 0 {
            freed.push(address);
        }
    }
    for address in freed {
        map.bcbs.remove(&address);
        cache_map::free_native_bcb(address);
    }
}

/// Grava as páginas sujas de [start, end) (bytes). Com `lsn_limit`, só as
/// páginas de BCBs com OldestLsn <= limite. Devolve (NTSTATUS, bytes gravados).
pub fn write_range(base: u64, start: u64, end: u64, lsn_limit: Option<u64>) -> Result<(u32, u64), KernelError> {
    let mut written = 0u64;
    loop {
        let job = {
            let mut cache = CACHE.lock();
            let Some(map) = cache.maps.get_mut(&base) else { return Ok((status::SUCCESS, written)) };
            let file_size = map.file_size;
            let logged = lsn_limit.map(|limit| logged_masks(map, limit));
            let mut found = None;
            for (&index, view) in map.views.iter_mut() {
                let filter = logged.as_ref().map_or(u64::MAX, |masks| masks.get(&index).copied().unwrap_or(0));
                let candidates = view.dirty & !view.writing & vacb::range_mask(index, start, end) & filter;
                if candidates == 0 {
                    continue;
                }
                // Páginas inteiramente além do fim do arquivo não vão ao disco.
                let beyond = vacb::range_mask(index, file_size.next_multiple_of(PAGE_SIZE), u64::MAX);
                view.dirty &= !(candidates & beyond);
                let candidates = candidates & !beyond;
                if candidates == 0 {
                    continue;
                }
                let (first, count) = vacb::runs(candidates)[0];
                let mask = vacb::page_mask(first, first + count - 1);
                view.writing |= mask;
                view.dirty &= !mask;
                view.refs += 1;
                found = Some((index, first, count, mask, view.base));
                break;
            }
            let Some((index, first, count, mask, view_base)) = found else {
                clean_bcbs(map);
                cache_map::publish(map);
                return Ok((status::SUCCESS, written));
            };
            let offset = vacb::view_offset(index) + first * PAGE_SIZE;
            let run_end = offset + count * PAGE_SIZE;
            let lsn = map.bcbs.values().filter(|bcb| bcb.dirty && bcb.offset < run_end && bcb.offset + bcb.length as u64 > offset).map(|bcb| bcb.newest_lsn).max().unwrap_or(0);
            cache_map::publish(map);
            (index, mask, offset, count * PAGE_SIZE, view_base + first * PAGE_SIZE, map.file_object, lsn, map.log, file_size)
        };
        let (index, mask, offset, length, address, file, lsn, log, file_size) = job;
        // Write-ahead logging: o log precisa estar no disco antes da página.
        if lsn != 0 && log.flush_to_lsn != 0 {
            native_call::call(log.flush_to_lsn, &[log.handle, lsn]);
        }
        let result = section_io::page_io(file, true, offset, address, length);
        let failed = !matches!(result, Ok((code, _)) if code >> 30 != 3);
        {
            let mut cache = CACHE.lock();
            if let Some(map) = cache.maps.get_mut(&base) {
                if let Some(view) = map.views.get_mut(&index) {
                    view.writing &= !mask;
                    if failed {
                        view.dirty |= mask;
                    }
                }
                if !failed {
                    let end_of_run = (offset + length).min(file_size);
                    written += end_of_run.saturating_sub(offset);
                    map.valid_data_length = map.valid_data_length.max(end_of_run);
                    clean_bcbs(map);
                }
                cache_map::publish(map);
            }
        }
        cache_map::release_view(base, index);
        match result {
            Err(error) => return Err(error),
            Ok((code, _)) if code >> 30 == 3 => return Ok((code, written)),
            Ok(_) => {}
        }
    }
}

/// Descarta todos os dados sujos do mapa (escrita adiada perdida).
pub fn discard_dirty(cache: &mut CacheManager, base: u64) {
    if let Some(map) = cache.maps.get_mut(&base) {
        for view in map.views.values_mut() {
            view.dirty = 0;
        }
        clean_bcbs(map);
        cache_map::publish(map);
    }
}

/// Purga [start, end) com o lock preso: falha (FALSE) com vista referenciada
/// ou em I/O; DO_NOT_PURGE_DIRTY_PAGES conserva as páginas sujas (FALSE).
fn purge(cache: &mut CacheManager, base: u64, start: u64, end: u64, flags: u32) -> bool {
    let Some(map) = cache.maps.get_mut(&base) else { return true };
    let busy = map.views.iter().any(|(&index, view)| vacb::range_mask(index, start, end) != 0 && (view.refs != 0 || view.reading != 0 || view.writing != 0));
    if busy {
        return false;
    }
    let keep_dirty = flags & purge_flags::DO_NOT_PURGE_DIRTY_PAGES != 0;
    let mut retained = false;
    for (&index, view) in map.views.iter_mut() {
        let mut discard = vacb::range_mask(index, start, end);
        if keep_dirty {
            retained |= view.dirty & discard != 0;
            discard &= !view.dirty;
        }
        view.valid &= !discard;
        view.dirty &= !discard;
    }
    let doomed: Vec<u64> = map.bcbs.iter().filter(|(_, bcb)| bcb.pins == 0 && bcb.offset >= start && bcb.offset + bcb.length as u64 <= end && !(keep_dirty && bcb.dirty)).map(|(&address, _)| address).collect();
    for address in doomed {
        map.bcbs.remove(&address);
        cache_map::free_native_bcb(address);
    }
    clean_bcbs(map);
    cache_map::publish(map);
    !retained
}

/// O encolhimento de CcSetFileSizes/CcUninitializeCacheMap: descarta as
/// páginas além do novo fim e zera a cauda da última página
/// (CcPurgeAndClearCacheSection). FALSE quando algo além está fixado.
pub fn truncate_cached_data(cache: &mut CacheManager, base: u64, size: u64) -> bool {
    let purged = purge(cache, base, size.next_multiple_of(PAGE_SIZE), u64::MAX, 0);
    if let Some(map) = cache.maps.get_mut(&base) {
        if size % PAGE_SIZE != 0 {
            let index = vacb::view_index(size);
            let page = (size - vacb::view_offset(index)) / PAGE_SIZE;
            if let Some(view) = map.views.get(&index) {
                if view.valid & (1 << page) != 0 {
                    let within = size - vacb::view_offset(index);
                    vacb::zero_bytes(view.base + within, PAGE_SIZE - within % PAGE_SIZE);
                }
            }
        }
    }
    purged
}

/// O IO_STATUS_BLOCK de kernel do file system, se houver.
fn io_status_at(io_status: u64) -> Option<&'static IoStatusBlock> {
    // SAFETY: PIO_STATUS_BLOCK de kernel passado pelo file system.
    (io_status != 0).then(|| unsafe { IoStatusBlock::at(io_status) })
}

fn write_io_status(io_status: u64, code: u32, information: u64) {
    if let Some(block) = io_status_at(io_status) {
        block.status.set(code as i32);
        block.information.set(information);
    }
}

/// Um PLARGE_INTEGER de kernel do file system.
pub fn large_integer(pointer: u64) -> u64 {
    // SAFETY: os offsets do Cc vêm de memória de kernel do file system.
    unsafe { LargeInteger::at(pointer) }.quad_part.get() as u64
}

/// [start, end) de um par (FileOffset*, Length): NULL = arquivo inteiro.
fn byte_range(offset_pointer: u64, length: u32, zero_means_all: bool) -> (u64, u64) {
    if offset_pointer == 0 {
        return (0, u64::MAX);
    }
    let start = large_integer(offset_pointer);
    if length == 0 && zero_means_all {
        return (start, u64::MAX);
    }
    (start, start.saturating_add(length as u64))
}

/// CcFlushCache(SectionObjectPointer, FileOffset, Length, IoStatus).
pub fn flush_cache(pointers: u64, offset_pointer: u64, length: u32, io_status: u64) -> CcResult<()> {
    let Some(base) = cache_map::map_of_pointers(pointers) else {
        write_io_status(io_status, status::SUCCESS, 0);
        return Ok(());
    };
    let (start, end) = byte_range(offset_pointer, length, false);
    let (code, written) = write_range(base, start, end, None)?;
    write_io_status(io_status, code, written);
    super::copy::post_deferred_writes(false);
    Ok(())
}

/// CcFlushCacheToLsn(SectionObjectPointer, LsnToFlushTo, IoStatus): grava as
/// páginas de BCBs com log cujo OldestLsn não passa do LSN pedido.
pub fn flush_cache_to_lsn(pointers: u64, lsn: u64, io_status: u64) -> CcResult<()> {
    let Some(base) = cache_map::map_of_pointers(pointers) else {
        write_io_status(io_status, status::SUCCESS, 0);
        return Ok(());
    };
    let (code, written) = write_range(base, 0, u64::MAX, Some(lsn))?;
    write_io_status(io_status, code, written);
    Ok(())
}

/// CcPurgeCacheSection(SectionObjectPointer, FileOffset, Length, Flags).
/// UNINITIALIZE_CACHE_MAPS solta os mapas privados de todos os FILE_OBJECTs;
/// um mapa que fica sem abertos é gravado (o que restou sujo) e apagado.
pub fn purge_cache_section(pointers: u64, offset_pointer: u64, length: u32, flags: u32) -> CcResult<bool> {
    let Some(base) = cache_map::map_of_pointers(pointers) else { return Ok(true) };
    let (start, end) = byte_range(offset_pointer, length, true);
    let (purged, orphaned) = {
        let mut cache = CACHE.lock();
        if flags & purge_flags::UNINITIALIZE_CACHE_MAPS != 0 {
            if let Some(map) = cache.maps.get_mut(&base) {
                for (file, private) in map.private_maps.clone() {
                    cache_map::release_private_map(map, file, private);
                }
                cache_map::publish(map);
            }
        }
        let purged = purge(&mut cache, base, start, end, flags);
        (purged, cache.maps.get(&base).is_some_and(|map| map.open_count == 0))
    };
    if orphaned {
        let (code, _) = write_range(base, 0, u64::MAX, None)?;
        let deleted = {
            let mut cache = CACHE.lock();
            if code >> 30 == 3 {
                discard_dirty(&mut cache, base);
            }
            if cache.maps.get(&base).is_some_and(|map| map.open_count == 0) { cache_map::delete_if_idle(&mut cache, base) } else { None }
        };
        if let Some(deleted) = deleted {
            deleted.finish();
        }
    }
    Ok(purged)
}

/// CcCoherencyFlushAndPurgeCache: flush; sem CC_FLUSH_AND_PURGE_NO_PURGE e com
/// flush bem-sucedido, purga com DO_NOT_PURGE_DIRTY_PAGES; purga recusada vira
/// STATUS_CACHE_PAGE_LOCKED no IoStatus. (Sem vistas de usuário, o
/// MmTrimSection do NT não tem o que aparar.)
pub fn coherency_flush_and_purge_cache(pointers: u64, offset_pointer: u64, length: u32, io_status: u64, flags: u32) -> CcResult<()> {
    write_io_status(io_status, status::SUCCESS, 0);
    flush_cache(pointers, offset_pointer, length, io_status)?;
    let block = io_status_at(io_status);
    let flushed = block.is_none_or(|block| (block.status.get() as u32) >> 30 != 3);
    if flushed && flags & layout::coherency_flags::NO_PURGE == 0 && !purge_cache_section(pointers, offset_pointer, length, purge_flags::DO_NOT_PURGE_DIRTY_PAGES)? {
        if let Some(block) = block {
            block.status.set(status::CACHE_PAGE_LOCKED as i32);
        }
    }
    Ok(())
}

/// CcZeroData(FileObject, StartOffset, EndOffset, Wait). Arquivo em cache:
/// zera pelo cache (páginas inteiras sem leitura, as parciais lidas) e marca
/// sujo; sem cache: grava zeros direto com escritas de paginação. Sem espera
/// e com I/O necessário: FALSE.
pub fn zero_data(file: u64, start_pointer: u64, end_pointer: u64, wait: bool) -> CcResult<bool> {
    let (start, end) = (large_integer(start_pointer), large_integer(end_pointer));
    if end <= start {
        return Ok(true);
    }
    let Some(base) = cache_map::map_of_file(file) else { return zero_uncached(file, start, end, wait) };
    let Some(held) = section_io::prepare_range(base, start, end, Fill::Overwrite { start, end }, wait)? else { return Ok(false) };
    {
        let mut cache = CACHE.lock();
        if let Some(map) = cache.maps.get_mut(&base) {
            for &(index, view_base) in &held {
                let view_start = vacb::view_offset(index);
                let (low, high) = (start.max(view_start), end.min(view_start + layout::VIEW_SIZE));
                vacb::zero_bytes(view_base + (low - view_start), high - low);
                if let Some(view) = map.views.get_mut(&index) {
                    let mask = vacb::range_mask(index, low, high);
                    view.valid |= mask;
                    view.dirty |= mask;
                }
            }
            map.valid_data_goal = map.valid_data_goal.max(end);
            cache_map::publish(map);
        }
    }
    section_io::release_range(base, &held);
    write_through(file, base, start, end)?;
    Ok(true)
}

fn zero_uncached(file: u64, start: u64, end: u64, wait: bool) -> CcResult<bool> {
    if !wait {
        return Ok(false);
    }
    const CHUNK: u64 = 0x1_0000;
    let buffer = crate::ntos::mm::independent_pages::allocate(CHUNK, 0)?;
    if buffer == 0 {
        return Err(Failure::Raise(status::INSUFFICIENT_RESOURCES));
    }
    vacb::zero_bytes(buffer, CHUNK);
    let mut offset = start;
    let mut failure = None;
    while offset < end {
        let length = (end - offset).min(CHUNK);
        match section_io::page_io(file, true, offset, buffer, length) {
            Ok((code, _)) if code >> 30 != 3 => offset += length,
            Ok((code, _)) => {
                failure = Some(Failure::Raise(code));
                break;
            }
            Err(error) => {
                failure = Some(Failure::Kernel(error));
                break;
            }
        }
    }
    let _ = crate::ntos::mm::independent_pages::free(buffer);
    match failure {
        Some(failure) => Err(failure),
        None => Ok(true),
    }
}

/// FO_WRITE_THROUGH: o intervalo recém-sujo vai ao disco agora; falha levanta.
pub fn write_through(file: u64, base: u64, start: u64, end: u64) -> CcResult<()> {
    if cache_map::file_object(file).flags.get() & layout::FO_WRITE_THROUGH == 0 {
        return Ok(());
    }
    let (code, _) = write_range(base, start, end, None)?;
    if code >> 30 == 3 {
        return Err(super::status::copy_failure(code));
    }
    Ok(())
}

/// Uma passada do lazy writer: cada mapa sujo é gravado sob
/// AcquireForLazyWrite(Context, FALSE)/ReleaseFromLazyWrite, preservando o
/// TopLevelIrp da thread; o FS que recusa a aquisição fica para depois.
pub fn lazy_write_pass() -> Result<(), KernelError> {
    let dirty: Vec<(u64, u64, u64)> = CACHE.lock().maps.values().filter(|map| map.dirty_pages() != 0).map(|map| (map.native, map.callbacks, map.lazy_write_context)).collect();
    // SAFETY: a ETHREAD da thread corrente.
    let top_level = &unsafe { Ethread::at(process::get_current_thread()) }.top_level_irp;
    for (base, callbacks, context) in dirty {
        // O lazy writer do NT entra no FS sem TopLevelIrp (os Acquire*ForLazyWrite
        // conferem e trocam por FSRTL_CACHE_TOP_LEVEL_IRP); o da thread volta depois.
        let saved = top_level.get();
        top_level.set(0);
        let (acquire, release) = if callbacks != 0 {
            // SAFETY: CACHE_MANAGER_CALLBACKS estático do file system (CcInitializeCacheMap).
            let routines = unsafe { CacheManagerCallbacks::at(callbacks) };
            (routines.acquire_for_lazy_write.get(), routines.release_from_lazy_write.get())
        } else {
            (0, 0)
        };
        if acquire != 0 && native_call::call(acquire, &[context, 0]) & 0xFF == 0 {
            top_level.set(saved);
            continue;
        }
        let result = write_range(base, 0, u64::MAX, None);
        if acquire != 0 && release != 0 {
            native_call::call(release, &[context]);
        }
        top_level.set(saved);
        result?;
    }
    Ok(())
}

/// CcWaitForCurrentLazyWriterActivity: nenhuma passada fica pendente neste
/// modelo síncrono; STATUS_SUCCESS.
pub fn wait_for_current_lazy_writer_activity() -> u32 {
    status::SUCCESS
}

/// CcUnmapFileOffsetFromSystemCache(FileObject, FileOffset, Length): retira as
/// vistas sem uso do intervalo. Vistas sujas guardam os dados (aqui não há
/// seção por baixo) e ficam; TRUE quando nenhuma vista do intervalo está ativa.
pub fn unmap_file_offset_from_system_cache(file: u64, offset_pointer: u64, length: u32) -> CcResult<bool> {
    let base = cache_map::require_map(file)?;
    let (start, end) = byte_range(offset_pointer, length, true);
    let (retired, active) = {
        let mut cache = CACHE.lock();
        let Some(map) = cache.maps.get_mut(&base) else { return Ok(true) };
        let mut retired = Vec::new();
        let mut active = false;
        let indices: Vec<u64> = map.views.keys().copied().filter(|&index| vacb::range_mask(index, start, end) != 0).collect();
        for index in indices {
            let idle = map.views.get(&index).is_some_and(|view| view.refs == 0 && view.dirty == 0 && view.reading == 0 && view.writing == 0);
            if idle {
                if let Some(view) = map.views.remove(&index) {
                    retired.push(view);
                }
            } else {
                active |= map.views.get(&index).is_some_and(|view| view.refs != 0);
            }
        }
        cache.view_count = cache.view_count.saturating_sub(retired.len() as u64);
        (retired, active)
    };
    vacb::free_views(retired);
    Ok(!active)
}
