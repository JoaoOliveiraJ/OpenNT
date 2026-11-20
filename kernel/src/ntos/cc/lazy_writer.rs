//! O lazy writer do Cache Manager, como no NT.
//!
//! * [`schedule_scan`] é o CcScheduleLazyWriteScan: sem pressa, arma o
//!   ScanTimer para daqui a CcFirstDelay (3 s) se nenhuma passada está
//!   agendada (ScanActive); com pressa (FastScan, o
//!   CcNotifyWriteBehindInternal), acorda o lazy writer agora. Um mapa que
//!   ganha páginas sujas (`cache_map::publish`) e o último
//!   CcUninitializeCacheMap que deixa o SHARED_CACHE_MAP para o lazy writer
//!   agendam a passada.
//! * A DPC do timer (o CcScanDpc) acorda a thread do lazy writer: uma thread
//!   de sistema do Cc (criada pelo PsCreateSystemThread, na própria pilha),
//!   que espera o evento de passada e roda a passada com a identidade dela
//!   (TopLevelIrp, posse de recursos) e esperas que bloqueiam de verdade.
//! * [`lazy_write_scan`] (o CcLazyWriteScan) percorre os mapas sujos e os
//!   que esperam remoção e, para cada um, faz o CcWriteBehind: adquire o
//!   arquivo pelo AcquireForLazyWrite(Context, Wait=TRUE) dos callbacks do
//!   file system, grava as páginas sujas (escrita de paginação ao arquivo,
//!   com o write-ahead do log), solta pelo ReleaseFromLazyWrite e, se o mapa
//!   não tem mais FILE_OBJECTs (OpenCount 0) nem páginas sujas, apaga o
//!   SHARED_CACHE_MAP — e solta a referência que ele tinha do stream file,
//!   de onde vem o IRP_MJ_CLOSE do file system, depois. No fim, sinaliza
//!   quem espera a passada (CcWaitForCurrentLazyWriterActivity), posta as
//!   escritas adiadas e reagenda por CcIdleDelay (1 s) enquanto houver
//!   trabalho.

use alloc::vec::Vec;

use super::cache_map::{self, CACHE};
use super::layout::scm_flags;
use super::flush;
use crate::hal::amd64::native_call;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_cc::CacheManagerCallbacks;
use crate::ntos::inc::types::{Ethread, Kdpc, Kevent, Ktimer};
use crate::ntos::ke::{dispatcher, dpc, timer};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::{kernel_threads, process};
use crate::rtl::SpinLock;

/// CcFirstDelay e CcIdleDelay (100 ns, relativos).
const FIRST_DELAY: i64 = -30_000_000;
const IDLE_DELAY: i64 = -10_000_000;
/// IoSetTopLevelIrp(FSRTL_CACHE_TOP_LEVEL_IRP).
const FSRTL_CACHE_TOP_LEVEL_IRP: u64 = 2;
/// THREAD_ALL_ACCESS.
const THREAD_ALL_ACCESS: u32 = 0x1F_FFFF;

/// O LAZY_WRITER do Cc.
struct LazyWriter {
    /// Os objetos nativos: o ScanTimer, a ScanDpc e o evento que acorda a
    /// thread do lazy writer.
    timer: u64,
    scan_dpc: u64,
    scan_event: u64,
    /// A thread de sistema do lazy writer.
    worker: u64,
    /// Uma passada agendada ou em curso.
    scan_active: bool,
    /// Trabalho além das páginas sujas (remoções, quem espera).
    other_work: bool,
    /// Pedido de agendamento antes de os objetos existirem.
    pending: bool,
    /// Eventos de quem espera a passada (CcWaitForCurrentLazyWriterActivity).
    waiters: Vec<u64>,
}

static LAZY: SpinLock<LazyWriter> = SpinLock::new(LazyWriter { timer: 0, scan_dpc: 0, scan_event: 0, worker: 0, scan_active: false, other_work: false, pending: false, waiters: Vec::new() });
/// Serializa a criação dos objetos (a primeira CcInitializeCacheMap).
static CREATING: SpinLock<()> = SpinLock::new(());

/// A thread corrente é a do lazy writer.
pub fn on_lazy_writer_thread() -> bool {
    let worker = LAZY.lock().worker;
    worker != 0 && worker == process::get_current_thread()
}

/// Cria os objetos e a thread do lazy writer na primeira vez (fora de
/// qualquer trava do Cc).
pub fn initialize() {
    if LAZY.lock().timer != 0 {
        return;
    }
    let Some(_creating) = CREATING.try_lock() else { return };
    if LAZY.lock().timer != 0 {
        return;
    }
    let timer = guest::alloc_bytes(Ktimer::SIZE);
    let scan_dpc = guest::alloc_bytes(Kdpc::SIZE);
    let scan_event = guest::alloc_bytes(Kevent::SIZE);
    if timer == 0 || scan_dpc == 0 || scan_event == 0 {
        debug_print!("[cc] objetos do lazy writer sem memoria");
        return;
    }
    timer::initialize_timer(timer, 0);
    dpc::initialize_kernel_dpc(scan_dpc, scan_dpc_routine, 0);
    // SynchronizationEvent: cada sinal acorda uma passada.
    dispatcher::initialize_event(scan_event, 1, false);
    let entry: extern "win64" fn(u64) = lazy_writer_thread;
    let start = match crate::ntos::mm::kernel_address::image_address(entry as usize as u64) {
        Ok(start) => start,
        Err(error) => {
            debug_print!("[cc] rotina do lazy writer: {}", error);
            return;
        }
    };
    let worker = match kernel_threads::create_system_thread(0, start, 0, THREAD_ALL_ACCESS, 0, None) {
        Ok(handle) => {
            let pointer = kernel_threads::of_handle(handle).unwrap_or(0);
            let _ = object_manager::close(handle as u32);
            pointer
        }
        Err(error) => {
            debug_print!("[cc] thread do lazy writer nao criada: {}", error);
            return;
        }
    };
    let pending = {
        let mut lazy = LAZY.lock();
        lazy.timer = timer;
        lazy.scan_dpc = scan_dpc;
        lazy.scan_event = scan_event;
        lazy.worker = worker;
        core::mem::take(&mut lazy.pending)
    };
    if pending {
        schedule_scan(false);
    }
}

/// CcScheduleLazyWriteScan(FastScan).
pub fn schedule_scan(fast: bool) {
    let wake = {
        let mut lazy = LAZY.lock();
        if lazy.timer == 0 {
            lazy.pending = true;
            return;
        }
        if fast {
            lazy.scan_active = true;
            timer::cancel_timer(lazy.timer);
            Some(lazy.scan_event)
        } else {
            if !lazy.scan_active {
                lazy.scan_active = true;
                timer::set_timer(lazy.timer, FIRST_DELAY, lazy.scan_dpc, 0);
            }
            None
        }
    };
    if let Some(event) = wake {
        dispatcher::set_event(event);
    }
}

/// Trabalho que não é página suja (um mapa à espera de remoção): a passada
/// vem mesmo sem dados sujos.
pub fn request_other_work(fast: bool) {
    LAZY.lock().other_work = true;
    schedule_scan(fast);
}

/// CcScanDpc: acorda a thread do lazy writer.
fn scan_dpc_routine(_dpc: u64, _context: u64, _first: u64, _second: u64) {
    let event = LAZY.lock().scan_event;
    if event != 0 {
        dispatcher::set_event(event);
    }
}

/// A thread do lazy writer: espera o evento de passada e roda a passada.
extern "win64" fn lazy_writer_thread(_context: u64) {
    loop {
        let event = LAZY.lock().scan_event;
        dispatcher::wait_for_single_object(event, 0, 0, false);
        lazy_write_scan();
    }
}

/// A thread de sistema do lazy writer (0 antes da primeira CcInitializeCacheMap).
pub fn worker_thread() -> u64 {
    LAZY.lock().worker
}

/// Um mapa com trabalho para o lazy writer: páginas sujas que ele grava ou
/// a remoção pendente.
fn has_work(map: &cache_map::MapState) -> bool {
    if map.write_queued || map.delete_pending {
        return false;
    }
    let write_behind = map.dirty_pages() != 0 && (map.flags() & scm_flags::DISABLE_WRITE_BEHIND == 0 || map.open_count == 0);
    write_behind || (map.open_count == 0 && map.lazy_delete)
}

/// CcLazyWriteScan.
pub fn lazy_write_scan() {
    let waiters = {
        let mut lazy = LAZY.lock();
        lazy.other_work = false;
        core::mem::take(&mut lazy.waiters)
    };
    let candidates: Vec<u64> = CACHE.lock().maps.values().filter(|map| has_work(map)).map(|map| map.native).collect();
    for base in candidates {
        write_behind(base);
    }
    super::copy::post_deferred_writes(false);
    for event in waiters {
        dispatcher::set_event(event);
    }
    let more = {
        let cache = CACHE.lock();
        cache.maps.values().any(has_work) || !cache.deferred.is_empty()
    };
    let mut lazy = LAZY.lock();
    lazy.scan_active = false;
    if more || lazy.other_work || !lazy.waiters.is_empty() {
        lazy.scan_active = true;
        let delay = if lazy.waiters.is_empty() { IDLE_DELAY } else { 0 };
        timer::set_timer(lazy.timer, delay, lazy.scan_dpc, 0);
    }
}

/// CcWriteBehind de um mapa.
fn write_behind(base: u64) {
    let job = {
        let mut cache = CACHE.lock();
        let Some(map) = cache.maps.get_mut(&base) else { return };
        if map.write_queued {
            return;
        }
        map.write_queued = true;
        let flags = map.flags();
        map.set_flags(scm_flags::WRITE_QUEUED, 0);
        let writes = map.dirty_pages() != 0 && (flags & scm_flags::DISABLE_WRITE_BEHIND == 0 || map.open_count == 0);
        (writes, map.callbacks, map.lazy_write_context, map.open_count)
    };
    let (writes, callbacks, context, open_count) = job;
    if writes {
        let (acquire, release) = if callbacks != 0 {
            // SAFETY: CACHE_MANAGER_CALLBACKS estático do file system (CcInitializeCacheMap).
            let routines = unsafe { CacheManagerCallbacks::at(callbacks) };
            (routines.acquire_for_lazy_write.get(), routines.release_from_lazy_write.get())
        } else {
            (0, 0)
        };
        // SAFETY: a ETHREAD corrente (a thread do lazy writer).
        let top_level = &unsafe { Ethread::at(process::get_current_thread()) }.top_level_irp;
        let saved = top_level.get();
        top_level.set(0);
        let acquired = acquire == 0 || native_call::call(acquire, &[context, 1]) & 0xFF != 0;
        if acquired {
            // Sem rotina de aquisição, o próprio Cc marca a escrita como sua.
            if top_level.get() == 0 {
                top_level.set(FSRTL_CACHE_TOP_LEVEL_IRP);
            }
            let result = flush::write_range(base, 0, u64::MAX, None);
            top_level.set(0);
            if acquire != 0 && release != 0 {
                native_call::call(release, &[context]);
            }
            let failed = match result {
                Ok((status, _)) => (status >> 30 == 3).then_some(status),
                Err(error) => Some(if error.status != 0 { error.status } else { 0xC000_0001 }),
            };
            // Escrita adiada perdida de um mapa sem FILE_OBJECTs: o NT a
            // registra e descarta os dados.
            if let Some(status) = failed {
                if open_count == 0 {
                    debug_print!("[cc] escrita adiada falhou ({:#x}); dados sujos de {:#x} descartados", status, base);
                    flush::discard_dirty(&mut CACHE.lock(), base);
                }
            }
        }
        top_level.set(saved);
    }
    let deleted = {
        let mut cache = CACHE.lock();
        let Some(map) = cache.maps.get_mut(&base) else { return };
        map.write_queued = false;
        map.set_flags(0, scm_flags::WRITE_QUEUED);
        if map.open_count == 0 && map.lazy_delete && map.dirty_pages() == 0 {
            cache_map::delete_if_idle(&mut cache, base)
        } else {
            None
        }
    };
    if let Some(deleted) = deleted {
        deleted.finish();
    }
}

/// CcWaitForCurrentLazyWriterActivity: agenda uma passada rápida e espera
/// o fim dela.
pub fn wait_for_current_lazy_writer_activity() -> u32 {
    initialize();
    if worker_thread() == 0 {
        // Sem a thread (sem memória na criação), a passada roda aqui.
        lazy_write_scan();
        return super::layout::status::SUCCESS;
    }
    let event = guest::alloc_bytes(Kevent::SIZE);
    if event == 0 {
        return super::layout::status::INSUFFICIENT_RESOURCES;
    }
    dispatcher::initialize_event(event, 0, false);
    {
        let mut lazy = LAZY.lock();
        lazy.waiters.push(event);
        lazy.other_work = true;
    }
    schedule_scan(true);
    dispatcher::wait_for_single_object(event, 0, 0, false);
    guest::free_bytes(event);
    super::layout::status::SUCCESS
}

/// Uma passada está agendada (testes).
pub fn scan_scheduled() -> bool {
    LAZY.lock().scan_active
}
