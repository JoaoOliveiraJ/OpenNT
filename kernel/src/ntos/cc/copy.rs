//! Cópias entre o cache e o buffer do chamador e o controle de escrita —
//! o papel do `cache\copysup.c` do NT (CcCopyRead/CcFastCopyRead,
//! CcCopyWrite/CcFastCopyWrite, CcCanIWrite, CcDeferWrite).
//!
//! Leitura: as páginas ausentes vêm do arquivo por paginação e os bytes são
//! copiados da vista. Escrita: páginas parcialmente escritas abaixo de
//! ValidDataGoal são lidas antes, as inteiras e as além dele são zeradas; o
//! intervalo fica sujo e ValidDataGoal avança. FO_WRITE_THROUGH grava na hora.
//! Sem espera e com I/O necessário, as rotinas devolvem FALSE sem copiar.
//!
//! Falhas levantadas como no NT: I/O de página ->
//! FsRtlNormalizeNtstatus(status, STATUS_UNEXPECTED_IO_ERROR); buffer do
//! chamador sem tradução -> STATUS_INVALID_USER_BUFFER.
//!
//! O controle de escrita usa um limite de páginas sujas (metade do orçamento
//! de vistas): acima dele CcCanIWrite sem espera responde FALSE, com espera
//! roda uma passada do lazy writer; CcDeferWrite posta na hora quando pode.

use super::cache_map::{self, DeferredWrite, CACHE};
use super::layout::{self, VIEW_SIZE};
use super::section_io::{self, Fill};
use super::status::{self, CcResult, Failure};
use super::{flush, vacb};
use crate::hal::amd64::native_call;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_cc::PrivateCacheMap;
use crate::ntos::inc::types::IoStatusBlock;

/// Páginas sujas toleradas antes de o CcCanIWrite estrangular.
pub const DIRTY_PAGE_THRESHOLD: u64 = vacb::VIEW_BUDGET * layout::PAGES_PER_VIEW / 2;
/// CcCopyWriteWontFlush recusa escritas a partir de 16 MB.
const WONT_FLUSH_LIMIT: u32 = 0x100_0000;

fn write_io_status(io_status: u64, code: u32, information: u64) {
    if io_status != 0 {
        // SAFETY: PIO_STATUS_BLOCK de kernel do file system.
        let block = unsafe { IoStatusBlock::at(io_status) };
        block.status.set(code as i32);
        block.information.set(information);
    }
}

fn copy_error(failure: Failure) -> Failure {
    match failure {
        Failure::Raise(code) => status::copy_failure(code),
        other => other,
    }
}

/// O pedaço [low, high) do intervalo que cai na vista `index`.
fn slice(index: u64, start: u64, end: u64) -> (u64, u64) {
    let view_start = vacb::view_offset(index);
    (start.max(view_start), end.min(view_start + VIEW_SIZE))
}

/// Histórico de leitura do PRIVATE_CACHE_MAP (FileOffset1/BeyondLastByte1).
fn record_read(file: u64, offset: u64, end: u64) {
    let address = cache_map::file_object(file).private_cache_map.get();
    if address != 0 {
        // SAFETY: o PRIVATE_CACHE_MAP que o CcInitializeCacheMap deu ao FILE_OBJECT.
        let private = unsafe { PrivateCacheMap::at(address) };
        private.file_offset2.quad_part.set(private.file_offset1.quad_part.get());
        private.beyond_last_byte2.quad_part.set(private.beyond_last_byte1.quad_part.get());
        private.file_offset1.quad_part.set(offset as i64);
        private.beyond_last_byte1.quad_part.set(end as i64);
    }
}

/// Leitura em cache em `offset` (CcCopyRead/CcFastCopyRead).
pub fn copy_read_at(file: u64, offset: u64, length: u32, wait: bool, buffer: u64, io_status: u64) -> CcResult<bool> {
    let base = cache_map::require_map(file)?;
    if length == 0 {
        write_io_status(io_status, layout::status::SUCCESS, 0);
        return Ok(true);
    }
    let end = offset + length as u64;
    let Some(held) = section_io::prepare_range(base, offset, end, Fill::Read, wait).map_err(copy_error)? else { return Ok(false) };
    let mut faulted = false;
    for &(index, view_base) in &held {
        let (low, high) = slice(index, offset, end);
        if vacb::copy_to_caller(buffer + (low - offset), view_base + (low - vacb::view_offset(index)), high - low).is_err() {
            faulted = true;
            break;
        }
    }
    section_io::release_range(base, &held);
    if faulted {
        return Err(status::user_buffer_failure());
    }
    record_read(file, offset, end);
    write_io_status(io_status, layout::status::SUCCESS, length as u64);
    Ok(true)
}

/// CcCopyRead/CcCopyReadEx/CcAsyncCopyRead(FileObject, FileOffset, Length, Wait, Buffer, IoStatus, ...).
/// O contexto assíncrono do CcAsyncCopyRead não é usado: o caminho é o síncrono.
pub fn copy_read(file: u64, offset_pointer: u64, length: u32, wait: bool, buffer: u64, io_status: u64) -> CcResult<bool> {
    copy_read_at(file, flush::large_integer(offset_pointer), length, wait, buffer, io_status)
}

/// Escrita em cache em `offset` (CcCopyWrite/CcFastCopyWrite).
pub fn copy_write_at(file: u64, offset: u64, length: u32, wait: bool, buffer: u64) -> CcResult<bool> {
    let base = cache_map::require_map(file)?;
    if length == 0 {
        return Ok(true);
    }
    let end = offset + length as u64;
    let Some(held) = section_io::prepare_range(base, offset, end, Fill::Overwrite { start: offset, end }, wait).map_err(copy_error)? else { return Ok(false) };
    let mut faulted = false;
    for &(index, view_base) in &held {
        let (low, high) = slice(index, offset, end);
        if vacb::copy_from_caller(view_base + (low - vacb::view_offset(index)), buffer + (low - offset), high - low).is_err() {
            faulted = true;
            break;
        }
    }
    {
        let mut cache = CACHE.lock();
        if let Some(map) = cache.maps.get_mut(&base) {
            for &(index, _) in &held {
                let (low, high) = slice(index, offset, end);
                let mask = vacb::range_mask(index, low, high);
                if let Some(view) = map.views.get_mut(&index) {
                    if faulted {
                        // Páginas zeradas para a cópia que não terminou voltam a ser lidas.
                        view.valid &= !(mask & !view.dirty);
                    } else {
                        view.valid |= mask;
                        view.dirty |= mask;
                    }
                }
            }
            if !faulted {
                map.valid_data_goal = map.valid_data_goal.max(end);
            }
            cache_map::publish(map);
        }
    }
    section_io::release_range(base, &held);
    if faulted {
        return Err(status::user_buffer_failure());
    }
    flush::write_through(file, base, offset, end)?;
    Ok(true)
}

/// CcCopyWrite/CcCopyWriteEx(FileObject, FileOffset, Length, Wait, Buffer, ...).
pub fn copy_write(file: u64, offset_pointer: u64, length: u32, wait: bool, buffer: u64) -> CcResult<bool> {
    copy_write_at(file, flush::large_integer(offset_pointer), length, wait, buffer)
}

fn dirty_pages() -> u64 {
    CACHE.lock().maps.values().map(|map| map.dirty_pages() as u64).sum()
}

fn under_threshold(bytes: u32) -> bool {
    dirty_pages() + (bytes as u64).div_ceil(layout::PAGE_SIZE) <= DIRTY_PAGE_THRESHOLD
}

/// CcCopyWriteWontFlush(FileObject, FileOffset, Length): a escrita cabe sem
/// estrangulamento (menos de 16 MB, sem FO_WRITE_THROUGH, abaixo do limite).
pub fn copy_write_wont_flush(file: u64, _offset_pointer: u64, length: u32) -> bool {
    length < WONT_FLUSH_LIMIT && cache_map::file_object(file).flags.get() & layout::FO_WRITE_THROUGH == 0 && under_threshold(length)
}

/// CcCanIWrite(FileObject, BytesToWrite, Wait, Retrying).
pub fn can_i_write(file: u64, bytes: u32, wait: bool, retrying: u8) -> CcResult<bool> {
    if cache_map::file_object(file).flags.get() & layout::FO_WRITE_THROUGH != 0 {
        return Ok(true);
    }
    let queue_empty = CACHE.lock().deferred.is_empty();
    if under_threshold(bytes) && (queue_empty || retrying != 0) {
        return Ok(true);
    }
    if !wait {
        return Ok(false);
    }
    flush::lazy_write_pass()?;
    post_deferred_writes(false);
    Ok(true)
}

/// CcDeferWrite(FileObject, PostRoutine, Context1, Context2, BytesToWrite, Retrying).
pub fn defer_write(file: u64, post_routine: u64, context1: u64, context2: u64, bytes: u32, retrying: bool) -> CcResult<()> {
    let queue_empty = CACHE.lock().deferred.is_empty();
    if queue_empty && under_threshold(bytes) {
        native_call::call(post_routine, &[context1, context2]);
        return Ok(());
    }
    {
        let entry = DeferredWrite { file_object: file, post_routine, context1, context2, bytes };
        let mut cache = CACHE.lock();
        if retrying { cache.deferred.insert(0, entry) } else { cache.deferred.push(entry) }
    }
    // Sem lazy writer para tentar de novo depois, a passada termina postando
    // a fila (o TimeAdded do DEFERRED_WRITE do NT também força o progresso).
    flush::lazy_write_pass()?;
    post_deferred_writes(true);
    Ok(())
}

/// Posta, em ordem, as escritas adiadas que agora cabem (todas com `force`).
pub fn post_deferred_writes(force: bool) {
    loop {
        let next = {
            let mut cache = CACHE.lock();
            let fits = cache.deferred.first().is_some_and(|entry| {
                if force {
                    return true;
                }
                let pages = (entry.bytes as u64).div_ceil(layout::PAGE_SIZE);
                cache.maps.values().map(|map| map.dirty_pages() as u64).sum::<u64>() + pages <= DIRTY_PAGE_THRESHOLD
            });
            if fits { Some(cache.deferred.remove(0)) } else { None }
        };
        let Some(entry) = next else { return };
        native_call::call(entry.post_routine, &[entry.context1, entry.context2]);
    }
}
