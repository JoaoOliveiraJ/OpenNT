//! O writer de páginas mapeadas do ntoskrnl 19041 (MiMappedPageWriter): a
//! thread de sistema que grava as páginas de arquivos de file system que as
//! vistas alteraram e ninguém gravou, para que uma vista que fica aberta não
//! guarde as alterações só na memória até o desmapeamento.
//!
//! No NT as páginas mapeadas chegam à lista de modificadas quando o corte
//! do working set (ou o desmapeamento) colhe o bit Dirty delas, e o
//! MiMappedPageWriter as grava com o arquivo adquirido pelo
//! FsRtlAcquireFileForModWriteEx e o FSRTL_MOD_WRITE_TOP_LEVEL_IRP como IRP de
//! nível de topo. O OpenNT não corta as vistas de seção; a thread acorda a
//! cada [`PERIOD_100NS`] (ou pelo [`wake`]) e cada passada colhe o bit
//! Dirty das vistas que não são do cache (`ps::user::sections`,
//! `write_mapped_pages`) e grava as páginas modificadas, em escritas de
//! paginação de até 16 páginas vizinhas. Um arquivo que o file system não
//! entrega sem espera (STATUS_CANT_WAIT) fica para a passada seguinte. As
//! control areas com NoModifiedWriting ficam de fora, como no NT.
//!
//! A escrita do NT é assíncrona (IoAsynchronousPageWrite); aqui é síncrona,
//! um cluster por vez.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ntos::fsrtl::fs_filter;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Kevent;
use crate::ntos::io::threads::top_level_irp;
use crate::ntos::ke::{dispatcher, wait};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::section::fsd_file;
use crate::rtl::KernelError;

pub const STATUS_CANT_WAIT: u32 = fs_filter::STATUS_CANT_WAIT;
/// FSRTL_MOD_WRITE_TOP_LEVEL_IRP (o 2 é o FSRTL_CACHE_TOP_LEVEL_IRP do lazy
/// writer, que o ntfs.sys trata de outro jeito).
const FSRTL_MOD_WRITE_TOP_LEVEL_IRP: u64 = 3;
const PAGE: u64 = 0x1000;
/// O intervalo entre as passadas (5 s).
const PERIOD_100NS: u64 = 50_000_000;
/// A prioridade da thread do MiMappedPageWriter no 19041 (a mesma do
/// MiModifiedPageWriter).
const WRITER_PRIORITY: u64 = 18;

static STARTED: AtomicBool = AtomicBool::new(false);
/// O evento que acorda a thread (sincronização).
static WAKE_EVENT: AtomicU64 = AtomicU64::new(0);
/// Páginas e escritas do writer, e as passadas terminadas.
static PAGES_WRITTEN: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);
static PASSES: AtomicU64 = AtomicU64::new(0);

/// Páginas gravadas, escritas feitas e passadas terminadas pelo writer.
pub fn statistics() -> (u64, u64, u64) {
    (PAGES_WRITTEN.load(Ordering::Acquire), WRITES.load(Ordering::Acquire), PASSES.load(Ordering::Acquire))
}

/// O evento e a thread do writer, uma vez (com a primeira seção gravável de
/// um arquivo de file system).
pub fn start() {
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let event = guest::alloc_bytes(Kevent::SIZE);
    if event == 0 {
        crate::debug_print!("[mm] evento do writer de paginas mapeadas sem memoria");
        return;
    }
    dispatcher::initialize_event(event, 1, false);
    WAKE_EVENT.store(event, Ordering::Release);
    let entry: extern "win64" fn(u64) = mapped_page_writer;
    let started = crate::ntos::mm::kernel_address::image_address(entry as usize as u64).and_then(|start| crate::ntos::ps::kernel_threads::create_system_thread(0, start, 0, 0x1F_FFFF, 0, None));
    match started {
        Ok(handle) => {
            let _ = crate::ntos::ob::object_manager::close(handle as u32);
        }
        Err(error) => crate::debug_print!("[mm] thread do writer de paginas mapeadas nao criada: {}", error),
    }
}

/// Acorda o writer para uma passada agora.
pub fn wake() {
    let event = WAKE_EVENT.load(Ordering::Acquire);
    if event != 0 {
        dispatcher::set_event(event);
    }
}

extern "win64" fn mapped_page_writer(_context: u64) {
    let _ = crate::ntos::ke::thread_priority::set_priority(crate::ntos::ps::process::get_current_thread(), WRITER_PRIORITY);
    loop {
        dispatcher::wait_for_single_object_reason(WAKE_EVENT.load(Ordering::Acquire), wait::reason::EXECUTIVE, 0, false, Some(PERIOD_100NS));
        crate::ntos::ps::user::sections::write_mapped_pages();
        PASSES.fetch_add(1, Ordering::AcqRel);
    }
}

/// Grava as páginas vizinhas a partir de `first_page` (os frames, na
/// ordem) pelo FILE_OBJECT `file`, em escritas de paginação síncronas. Do
/// writer (`modified_writer`): o arquivo adquirido sem espera pelo
/// FsRtlAcquireFileForModWriteEx até o fim da faixa e o IRP de nível de topo
/// FSRTL_MOD_WRITE_TOP_LEVEL_IRP durante a escrita; STATUS_CANT_WAIT volta
/// como erro com esse status.
pub fn write_run(file: u64, first_page: u64, frames: &[u64], modified_writer: bool) -> Result<(), KernelError> {
    if !modified_writer {
        return fsd_file::write_frames(file, first_page, frames);
    }
    let ending = (first_page + frames.len() as u64) * PAGE;
    let (status, resource) = fs_filter::acquire_for_mod_write(file, ending)?;
    if status & 0x8000_0000 != 0 {
        return Err(KernelError::with_status("arquivo ocupado para o writer de paginas mapeadas", status));
    }
    let previous = top_level_irp::get();
    top_level_irp::set(FSRTL_MOD_WRITE_TOP_LEVEL_IRP);
    let written = fsd_file::write_frames(file, first_page, frames);
    top_level_irp::set(previous);
    fs_filter::release_for_mod_write(file, resource)?;
    if written.is_ok() {
        PAGES_WRITTEN.fetch_add(frames.len() as u64, Ordering::AcqRel);
        WRITES.fetch_add((frames.len() as u64).div_ceil(16), Ordering::AcqRel);
    }
    written
}
