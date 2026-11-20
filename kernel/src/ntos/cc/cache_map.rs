//! Shared/private cache maps, como no Cache Manager do NT.
//!
//! Um arquivo em cache tem um `SharedCacheMap` nativo (layout do PDB, com
//! FileSize em +8 como o `CcGetFileSizePointer` do ntifs.h) pendurado em
//! `FileObject->SectionObjectPointer->SharedCacheMap`, e cada FILE_OBJECT que
//! inicializou o cache tem o seu `PrivateCacheMap` em
//! `FileObject->PrivateCacheMap` (o primeiro é o embutido no mapa). O estado
//! do motor (vistas, BCBs, log) fica na tabela [`CACHE`], indexada pelo
//! endereço do mapa nativo; os campos nativos são espelhados por [`publish`]
//! (contadores com stores atômicos, Flags com fetch_or/fetch_and).
//!
//! Contrato de lock: [`CACHE`] nunca fica preso durante uma chamada nativa
//! (IRP de paginação, callbacks do FS, dereference de FILE_OBJECT).
//!
//! O último CcUninitializeCacheMap segue o NT: um mapa com páginas sujas,
//! com escrita do lazy writer em curso ou sem PinAccess (e sem evento de
//! desinicialização) fica para o lazy writer (`lazy_writer.rs`), que grava
//! os dados e apaga o mapa depois, soltando então a referência do stream
//! file (devolve FALSE); os demais são apagados na hora (TRUE).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use alloc::sync::Arc;

use super::cache_section::{self, CacheSection};
use super::layout::{self, scm_flags};
use super::status::{CcResult, Failure};
use super::{flush, vacb};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_cc::{CacheUninitializeEvent, CcFileSizes, PrivateCacheMap, SharedCacheMap};
use crate::ntos::inc::types::extra_fsrtl::FsrtlCommonFcbHeader;
use crate::ntos::inc::types::{FileObject, ListEntry, SectionObjectPointers};
use crate::ntos::ex::list_entry;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::file as file_objects;
use crate::rtl::{KernelError, SpinLock};

/// Uma vista de 256 KB do arquivo (o VACB do NT) com o estado por página.
#[derive(Clone, Copy)]
pub struct View {
    /// VA das páginas independentes que guardam os dados.
    pub base: u64,
    /// `Vacb` nativo (CcMapData devolve `vacb | 1`).
    pub vacb: u64,
    pub valid: u64,
    pub dirty: u64,
    pub reading: u64,
    pub writing: u64,
    /// Mapeamentos, pins, MDLs e I/O em andamento.
    pub refs: u32,
    /// Referências de CcMapData/CcRemapBcb (ActiveCount do VACB).
    pub maps: u32,
    pub last_use: u64,
}

/// Estado de um BCB nativo (`layout::Bcb`).
pub struct BcbState {
    pub offset: u64,
    pub length: u32,
    pub pins: u32,
    pub dirty: bool,
    pub oldest_lsn: u64,
    pub newest_lsn: u64,
    pub view: u64,
}

/// Rotinas de log registradas por CcSetLogHandleForFile(Ex).
#[derive(Clone, Copy, Default)]
pub struct LogHandle {
    pub handle: u64,
    pub flush_to_lsn: u64,
    pub query_log_usage: u64,
    pub related_file: u64,
}

/// O estado de um SHARED_CACHE_MAP.
pub struct MapState {
    pub native: u64,
    pub section_pointers: u64,
    /// FILE_OBJECT usado na paginação (referenciado enquanto o mapa vive).
    pub file_object: u64,
    pub referenced: bool,
    pub open_count: u32,
    pub file_size: u64,
    pub valid_data_length: u64,
    pub valid_data_goal: u64,
    pub section_size: u64,
    pub callbacks: u64,
    pub lazy_write_context: u64,
    pub views: BTreeMap<u64, View>,
    pub bcbs: BTreeMap<u64, BcbState>,
    /// (FILE_OBJECT, PRIVATE_CACHE_MAP).
    pub private_maps: Vec<(u64, u64)>,
    pub log: LogHandle,
    /// CACHE_UNINITIALIZE_EVENTs sinalizados quando o mapa for apagado.
    pub events: Vec<u64>,
    pub delete_pending: bool,
    /// O lazy writer está gravando o mapa (WRITE_QUEUED).
    pub write_queued: bool,
    /// O último CcUninitializeCacheMap deixou o mapa para o lazy writer apagar.
    pub lazy_delete: bool,
    /// A seção do cache (`cache_section`); sem ela, vistas de páginas próprias.
    pub section: Option<Arc<CacheSection>>,
}

impl MapState {
    pub fn dirty_pages(&self) -> u32 {
        self.views.values().map(|view| view.dirty.count_ones()).sum()
    }

    /// O `SharedCacheMap` nativo.
    pub fn native(&self) -> &'static SharedCacheMap {
        native_map(self.native)
    }

    pub fn flags(&self) -> u32 {
        self.native().flags.get()
    }

    /// Flags é lido e alterado por outras CPUs: fetch_or/fetch_and.
    pub fn set_flags(&self, set: u32, clear: u32) {
        let flags = self.native().flags.atomic();
        if clear != 0 {
            flags.fetch_and(!clear, Ordering::SeqCst);
        }
        if set != 0 {
            flags.fetch_or(set, Ordering::SeqCst);
        }
    }

    fn referenced_views(&self) -> bool {
        self.views.values().any(|view| view.refs != 0)
    }
}

/// Escrita adiada de CcDeferWrite.
pub struct DeferredWrite {
    pub file_object: u64,
    pub post_routine: u64,
    pub context1: u64,
    pub context2: u64,
    pub bytes: u32,
}

/// Estado global do Cache Manager.
pub struct CacheManager {
    pub maps: BTreeMap<u64, MapState>,
    pub view_count: u64,
    pub tick: u64,
    pub deferred: Vec<DeferredWrite>,
    /// MDL -> (shared cache map, vista) das cadeias de CcMdlRead/CcPrepareMdlWrite.
    pub mdls: BTreeMap<u64, (u64, u64)>,
    /// CcSetLoggedDataThreshold por log handle.
    pub logged_thresholds: BTreeMap<u64, u32>,
    /// Purgas da seção do cache decididas com o lock preso, feitas depois de
    /// soltá-lo (`flush::run_pending_purges`).
    pub pending_purges: Vec<PendingPurge>,
}

/// Um MmPurgeSection a fazer: [start, end) sem as páginas que o Cc
/// conservou (sujas, com DO_NOT_PURGE_DIRTY_PAGES).
pub struct PendingPurge {
    pub section: Arc<CacheSection>,
    pub start: u64,
    pub end: u64,
    pub kept: Vec<u64>,
}

pub static CACHE: SpinLock<CacheManager> = SpinLock::new(CacheManager { maps: BTreeMap::new(), view_count: 0, tick: 0, deferred: Vec::new(), mdls: BTreeMap::new(), logged_thresholds: BTreeMap::new(), pending_purges: Vec::new() });

/// O FILE_OBJECT que o file system passou ao Cc.
pub fn file_object(address: u64) -> &'static FileObject {
    // SAFETY: as rotinas Cc recebem um PFILE_OBJECT vivo do file system, como no NT.
    unsafe { FileObject::at(address) }
}

/// O `SharedCacheMap` nativo de um mapa vivo deste Cc.
pub fn native_map(base: u64) -> &'static SharedCacheMap {
    // SAFETY: `base` é um mapa alocado por `new_native_map` e ainda na tabela.
    unsafe { SharedCacheMap::at(base) }
}

fn pointers_at(address: u64) -> &'static SectionObjectPointers {
    // SAFETY: SECTION_OBJECT_POINTERS do FCB do file system (memória de kernel).
    unsafe { SectionObjectPointers::at(address) }
}

/// `FILE_OBJECT->SectionObjectPointer`.
pub fn section_pointers_of(file: u64) -> u64 {
    if file == 0 { 0 } else { file_object(file).section_object_pointer.get() }
}

/// `SectionObjectPointer->SharedCacheMap` quando ele é um mapa vivo deste Cc.
pub fn map_of_pointers(pointers: u64) -> Option<u64> {
    if pointers == 0 {
        return None;
    }
    let map = pointers_at(pointers).shared_cache_map.get();
    (map != 0 && CACHE.lock().maps.contains_key(&map)).then_some(map)
}

pub fn map_of_file(file: u64) -> Option<u64> {
    map_of_pointers(section_pointers_of(file))
}

/// Mapa vivo ou falha interna: o NT derreferencia o ponteiro sem checar.
pub fn require_map(file: u64) -> CcResult<u64> {
    map_of_file(file).ok_or_else(|| Failure::Kernel(KernelError::new("Cc routine on a file object without an initialized cache map")))
}

/// Espelha os campos nativos lidos pelos drivers e pelas rotinas exportadas.
pub fn publish(map: &MapState) {
    let native = map.native();
    native.open_count.atomic().store(map.open_count, Ordering::SeqCst);
    native.file_size.quad_part.set(map.file_size as i64);
    native.section_size.quad_part.set(map.section_size as i64);
    native.valid_data_length.quad_part.set(map.valid_data_length as i64);
    native.valid_data_goal.quad_part.set(map.valid_data_goal as i64);
    // Um mapa que ganha páginas sujas entra na mira do lazy writer
    // (CcSetDirtyInMask: CcScheduleLazyWriteScan sem passada agendada).
    let dirty = map.dirty_pages();
    if native.dirty_pages.atomic().swap(dirty, Ordering::SeqCst) == 0 && dirty != 0 {
        super::lazy_writer::schedule_scan(false);
    }
    native.num_active_vacb.atomic().store(map.views.values().filter(|view| view.maps != 0).count() as u32, Ordering::SeqCst);
}

/// RemoveEntryList de um elo de estrutura do Cc.
fn remove_entry_list(entry: &ListEntry) {
    let (next, previous) = (entry.flink.get(), entry.blink.get());
    if next == 0 || previous == 0 {
        return;
    }
    // SAFETY: vizinhos são LIST_ENTRYs vivos da mesma lista do Cc.
    unsafe {
        ListEntry::at(previous).flink.set(next);
        ListEntry::at(next).blink.set(previous);
    }
    entry.flink.set(0);
    entry.blink.set(0);
}

/// BCB nativo novo (prefixo PUBLIC_BCB) ligado na BcbList do mapa.
pub fn new_native_bcb(map: &MapState, offset: u64, length: u32, index: u64, buffer: u64) -> u64 {
    let address = guest::alloc_bytes(layout::Bcb::SIZE);
    if address == 0 {
        return 0;
    }
    // SAFETY: alocação zerada de sizeof(BCB).
    let bcb = unsafe { layout::Bcb::at(address) };
    bcb.node_type_code.set(layout::NTC_BCB);
    bcb.byte_length.set(length);
    bcb.file_offset.quad_part.set(offset as i64);
    bcb.beyond_last_byte.quad_part.set((offset + length as u64) as i64);
    bcb.vacb.set(map.views.get(&index).map_or(0, |view| view.vacb));
    bcb.shared_cache_map.set(map.native);
    bcb.base_address.set(buffer);
    list_entry::insert_tail(&map.native().bcb_list, &bcb.bcb_links);
    address
}

/// Desliga o BCB nativo da BcbList e devolve a memória.
pub fn free_native_bcb(address: u64) {
    // SAFETY: BCB alocado por `new_native_bcb`.
    remove_entry_list(&unsafe { layout::Bcb::at(address) }.bcb_links);
    guest::free_bytes(address);
}

fn round_up(value: u64, granularity: u64) -> u64 {
    value.checked_add(granularity - 1).map_or(u64::MAX & !(granularity - 1), |sum| sum & !(granularity - 1))
}

/// CC_FILE_SIZES (AllocationSize, FileSize, ValidDataLength).
pub fn read_file_sizes(sizes: u64) -> (u64, u64, u64) {
    // SAFETY: CC_FILE_SIZES de kernel do file system.
    let sizes = unsafe { CcFileSizes::at(sizes) };
    (sizes.allocation_size.quad_part.get() as u64, sizes.file_size.quad_part.get() as u64, sizes.valid_data_length.quad_part.get() as u64)
}

fn new_native_map(file: u64, pin_access: bool, callbacks: u64, context: u64) -> CcResult<u64> {
    let base = guest::alloc_bytes(SharedCacheMap::SIZE);
    if base == 0 {
        return Err(Failure::Raise(layout::status::INSUFFICIENT_RESOURCES));
    }
    let native = native_map(base);
    native.node_type_code.set(layout::NTC_SHARED_CACHE_MAP);
    native.node_byte_size.set(SharedCacheMap::SIZE as i16);
    list_entry::initialize(&native.bcb_list);
    list_entry::initialize(&native.logged_stream_links);
    list_entry::initialize(&native.shared_cache_map_links);
    list_entry::initialize(&native.private_list);
    // EX_FAST_REF sem referências em cache nos 4 bits baixos.
    native.file_object_fast_ref.object.set(file & !0xF);
    native.callbacks.set(callbacks);
    native.lazy_write_context.set(context);
    native.flags.set(if pin_access { scm_flags::PIN_ACCESS } else { 0 });
    dispatcher::initialize_event(native.event.address(), 0, false);
    Ok(base)
}

/// CcInitializeCacheMap(Ex): cria o SHARED_CACHE_MAP na primeira vez, aumenta
/// SectionSize quando AllocationSize cresce e dá ao FILE_OBJECT o seu
/// PRIVATE_CACHE_MAP (OpenCount conta os mapas privados).
pub fn initialize_cache_map(file: u64, sizes: u64, pin_access: bool, callbacks: u64, context: u64, _flags: u32) -> CcResult<()> {
    let pointers = section_pointers_of(file);
    if pointers == 0 || sizes == 0 {
        return Err(Failure::Kernel(KernelError::new("CcInitializeCacheMap without SectionObjectPointer or file sizes")));
    }
    super::lazy_writer::initialize();
    let (allocation, file_size, valid_data_length) = read_file_sizes(sizes);
    let section_size = round_up(allocation, layout::VIEW_SIZE);
    let shared = &pointers_at(pointers).shared_cache_map;
    // A seção do cache nasce antes do mapa, fora do lock (CcCreateSectionForCache
    // -> MmCreateSection com o FILE_OBJECT); quem perde a corrida a solta.
    let existing = shared.get();
    let mut fresh_section = if existing != 0 && CACHE.lock().maps.contains_key(&existing) { None } else { cache_section::create(file, pointers, file_size) };
    let created = {
        let mut cache = CACHE.lock();
        let existing = shared.get();
        if existing != 0 && cache.maps.contains_key(&existing) {
            None
        } else {
            let base = new_native_map(file, pin_access, callbacks, context)?;
            cache.maps.insert(base, MapState {
                native: base,
                section_pointers: pointers,
                file_object: file,
                referenced: false,
                open_count: 0,
                file_size,
                valid_data_length: valid_data_length.min(file_size),
                valid_data_goal: valid_data_length,
                section_size,
                callbacks,
                lazy_write_context: context,
                views: BTreeMap::new(),
                bcbs: BTreeMap::new(),
                private_maps: Vec::new(),
                log: LogHandle::default(),
                events: Vec::new(),
                delete_pending: false,
                write_queued: false,
                lazy_delete: false,
                section: fresh_section.take(),
            });
            if let Some(section) = cache.maps.get(&base).and_then(|map| map.section.as_ref()) {
                native_map(base).section.set(section.pointer());
            }
            shared.set(base);
            Some(base)
        }
    };
    if let Some(unused) = fresh_section {
        cache_section::release(&unused);
    }
    // O mapa referencia o FILE_OBJECT da paginação (como a control area do NT).
    if let Some(base) = created {
        let referenced = matches!(file_objects::reference(file), Ok(Some(_)));
        if let Some(map) = CACHE.lock().maps.get_mut(&base) {
            map.referenced = referenced;
        }
    }
    let mut cache = CACHE.lock();
    let base = shared.get();
    let Some(map) = cache.maps.get_mut(&base) else {
        return Err(Failure::Kernel(KernelError::new("shared cache map vanished during initialization")));
    };
    if section_size > map.section_size {
        map.section_size = section_size;
    }
    let owner = file_object(file);
    if owner.private_cache_map.get() == 0 {
        let embedded = &map.native().private_cache_map;
        let address = if embedded.node_type_code.get() == 0 { embedded.address() } else { guest::alloc_bytes(PrivateCacheMap::SIZE) };
        if address == 0 {
            return Err(Failure::Raise(layout::status::INSUFFICIENT_RESOURCES));
        }
        guest::write_bytes(address, &[0u8; PrivateCacheMap::SIZE as usize]);
        // SAFETY: o embutido do mapa ou uma alocação de sizeof(PRIVATE_CACHE_MAP), zerados.
        let private = unsafe { PrivateCacheMap::at(address) };
        private.node_type_code.set(layout::NTC_PRIVATE_CACHE_MAP);
        private.read_ahead_mask.set(layout::PAGE_SIZE as u32 - 1);
        private.file_object.set(file);
        list_entry::insert_tail(&map.native().private_list, &private.private_links);
        owner.private_cache_map.set(address);
        map.private_maps.push((file, address));
        map.open_count += 1;
        map.delete_pending = false;
        map.lazy_delete = false;
    }
    publish(map);
    Ok(())
}

/// Solta um PRIVATE_CACHE_MAP (lista nativa, FILE_OBJECT e memória).
pub fn release_private_map(map: &mut MapState, file: u64, address: u64) {
    // SAFETY: mapa privado registrado em `private_maps`.
    let private = unsafe { PrivateCacheMap::at(address) };
    remove_entry_list(&private.private_links);
    if address == map.native().private_cache_map.address() {
        private.node_type_code.set(0);
    } else {
        guest::free_bytes(address);
    }
    let owner = file_object(file);
    if owner.private_cache_map.get() == address {
        owner.private_cache_map.set(0);
    }
    map.private_maps.retain(|&(holder, block)| holder != file || block != address);
    map.open_count = map.open_count.saturating_sub(1);
}

/// O que sobra para fazer fora do lock depois de apagar um mapa.
pub struct Deleted {
    file: u64,
    referenced: bool,
    events: Vec<u64>,
    views: Vec<View>,
    section: Option<Arc<CacheSection>>,
}

/// O KEVENT de um CACHE_UNINITIALIZE_EVENT do file system.
fn signal_uninitialize_event(event: u64) {
    // SAFETY: CACHE_UNINITIALIZE_EVENT de kernel passado ao CcUninitializeCacheMap.
    dispatcher::set_event(unsafe { CacheUninitializeEvent::at(event) }.event.address());
}

impl Deleted {
    /// Libera as vistas, sinaliza os eventos de desinicialização e solta a
    /// referência do FILE_OBJECT.
    pub fn finish(self) {
        vacb::free_views(self.views);
        // A seção do cache sai depois das vistas dela.
        if let Some(section) = &self.section {
            cache_section::release(section);
        }
        for event in self.events {
            signal_uninitialize_event(event);
        }
        if self.referenced {
            let _ = file_objects::dereference(self.file);
        }
    }
}

/// Apaga o mapa se ninguém o usa (OpenCount 0 e nenhuma vista referenciada);
/// senão marca a remoção pendente. Chamar com o lock preso.
pub fn delete_if_idle(cache: &mut CacheManager, base: u64) -> Option<Deleted> {
    let map = cache.maps.get_mut(&base)?;
    if map.open_count != 0 {
        return None;
    }
    if map.referenced_views() {
        map.delete_pending = true;
        return None;
    }
    let map = cache.maps.remove(&base)?;
    cache.view_count = cache.view_count.saturating_sub(map.views.len() as u64);
    let views: Vec<View> = map.views.into_values().collect();
    // O mapa inteiro sai: os BCBs não precisam ser desligados um a um.
    for &bcb in map.bcbs.keys() {
        guest::free_bytes(bcb);
    }
    let shared = &pointers_at(map.section_pointers).shared_cache_map;
    if shared.get() == base {
        shared.set(0);
    }
    cache.mdls.retain(|_, &mut (owner, _)| owner != base);
    guest::free_bytes(base);
    Some(Deleted { file: map.file_object, referenced: map.referenced, events: map.events, views, section: map.section })
}

/// O último FILE_OBJECT saiu do mapa (OpenCount 0): como no
/// CcUninitializeCacheMap do NT, um mapa sem PinAccess (e sem evento de
/// desinicialização), com escrita do lazy writer em curso ou com páginas
/// sujas fica para o lazy writer apagar (TRUE); os demais são apagados já.
pub fn defer_to_lazy_writer(map: &mut MapState, with_event: bool) -> bool {
    let deferred = (map.flags() & scm_flags::PIN_ACCESS == 0 && !with_event) || map.write_queued || map.dirty_pages() != 0;
    if deferred {
        map.lazy_delete = true;
    }
    deferred
}

/// Libera uma referência de vista e conclui uma remoção pendente.
pub fn release_view(base: u64, index: u64) {
    let deleted = {
        let mut cache = CACHE.lock();
        let pending = match cache.maps.get_mut(&base) {
            Some(map) => {
                if let Some(view) = map.views.get_mut(&index) {
                    view.refs = view.refs.saturating_sub(1);
                }
                map.delete_pending
            }
            None => false,
        };
        if pending { delete_if_idle(&mut cache, base) } else { None }
    };
    if let Some(deleted) = deleted {
        deleted.finish();
    }
}

/// CcUninitializeCacheMap (RVA 0x276f30): solta o mapa privado do
/// FILE_OBJECT; TruncateSize encurta o arquivo e descarta o cache além dele.
/// Com outros FILE_OBJECTs no mapa, o evento é sinalizado já (FALSE). No
/// último, o mapa sem PinAccess e sem evento, com escrita do lazy writer em
/// curso ou com páginas sujas fica para o lazy writer (FALSE, o evento vai
/// com o mapa); senão é apagado agora (TRUE). Sem cache, só sinaliza o
/// evento (FALSE).
pub fn uninitialize_cache_map(file: u64, truncate_size: u64, event: u64) -> CcResult<bool> {
    let base = match map_of_file(file) {
        Some(base) => base,
        None => {
            file_object(file).private_cache_map.set(0);
            if event != 0 {
                signal_uninitialize_event(event);
            }
            return Ok(false);
        }
    };
    // SAFETY: PLARGE_INTEGER de kernel do file system.
    let truncate = (truncate_size != 0).then(|| unsafe { crate::ntos::inc::types::LargeInteger::at(truncate_size) }.quad_part.get() as u64);
    {
        let mut cache = CACHE.lock();
        let Some(map) = cache.maps.get_mut(&base) else { return Ok(false) };
        let private = file_object(file).private_cache_map.get();
        if private != 0 && map.private_maps.iter().any(|&(owner, block)| owner == file && block == private) {
            release_private_map(map, file, private);
        }
        if let Some(size) = truncate {
            if map.private_maps.is_empty() {
                map.file_size = size;
                map.valid_data_length = map.valid_data_length.min(size);
                map.valid_data_goal = map.valid_data_goal.min(size);
            }
            flush::truncate_cached_data(&mut cache, base, size);
        }
        let Some(map) = cache.maps.get_mut(&base) else { return Ok(false) };
        publish(map);
        if map.open_count != 0 {
            // Outros FILE_OBJECTs ainda usam o mapa: o evento é sinalizado
            // agora se sobra mapa privado, senão vai com o mapa.
            let signal_now = event != 0 && !map.private_maps.is_empty();
            if event != 0 && !signal_now {
                map.events.push(event);
            }
            drop(cache);
            flush::run_pending_purges();
            if signal_now {
                signal_uninitialize_event(event);
            }
            return Ok(false);
        }
        if event != 0 {
            map.events.push(event);
        }
        if defer_to_lazy_writer(map, event != 0) {
            drop(cache);
            flush::run_pending_purges();
            super::lazy_writer::request_other_work(event != 0);
            return Ok(false);
        }
    }
    flush::run_pending_purges();
    let deleted = {
        let mut cache = CACHE.lock();
        if cache.maps.get(&base).is_some_and(|map| map.open_count != 0) {
            return Ok(false);
        }
        delete_if_idle(&mut cache, base)
    };
    Ok(match deleted {
        Some(deleted) => {
            deleted.finish();
            true
        }
        None => false,
    })
}

/// CcSetFileSizesEx: cresce SectionSize (granularidade de 1 MB), limita
/// ValidDataLength ao novo FileSize, ValidDataGoal = ValidDataLength do FS, e
/// num encolhimento (sem PinAccess) descarta o cache além do novo fim e zera
/// a cauda da última página. Sem cache map: STATUS_SUCCESS.
pub fn set_file_sizes(file: u64, sizes: u64) -> CcResult<u32> {
    let Some(base) = map_of_file(file) else { return Ok(layout::status::SUCCESS) };
    let (allocation, file_size, valid_data_length) = read_file_sizes(sizes);
    let mut cache = CACHE.lock();
    let Some(map) = cache.maps.get_mut(&base) else { return Ok(layout::status::SUCCESS) };
    if allocation > map.section_size {
        map.section_size = round_up(allocation, 0x10_0000);
    }
    if file_size < map.valid_data_length {
        map.valid_data_length = file_size;
    }
    map.valid_data_goal = valid_data_length;
    let shrinking = file_size < map.file_size && map.flags() & scm_flags::PIN_ACCESS == 0;
    let mut status = layout::status::SUCCESS;
    if shrinking && !flush::truncate_cached_data(&mut cache, base, file_size) {
        status = layout::status::PURGE_FAILED;
    }
    if let Some(map) = cache.maps.get_mut(&base) {
        map.file_size = file_size;
        publish(map);
    }
    drop(cache);
    flush::run_pending_purges();
    Ok(status)
}

/// `SharedCacheMap->FileSize = size` de um FILE_OBJECT em cache: o campo que
/// o CcGetFileSizePointer do ntifs.h expõe e que as escritas rápidas do
/// FsRtl (FsRtlCopyWrite, FsRtlPrepareMdlWriteDev) gravam direto depois de
/// estender o arquivo. Aqui o motor guarda o tamanho e espelha o campo.
pub fn set_file_size_field(file: u64, size: u64) {
    let Some(base) = map_of_file(file) else { return };
    let mut cache = CACHE.lock();
    if let Some(map) = cache.maps.get_mut(&base) {
        map.file_size = size;
        publish(map);
    }
}

/// CcSetAdditionalCacheAttributes(FileObject, DisableReadAhead, DisableWriteBehind).
pub fn set_additional_cache_attributes(file: u64, disable_read_ahead: bool, disable_write_behind: bool) -> CcResult<()> {
    let base = require_map(file)?;
    let cache = CACHE.lock();
    let Some(map) = cache.maps.get(&base) else { return Ok(()) };
    let read_ahead = if disable_read_ahead { (scm_flags::DISABLE_READ_AHEAD, 0) } else { (0, scm_flags::DISABLE_READ_AHEAD) };
    let write_behind = if disable_write_behind { (scm_flags::DISABLE_WRITE_BEHIND | scm_flags::MODIFIED_WRITE_DISABLED, 0) } else { (0, scm_flags::DISABLE_WRITE_BEHIND) };
    map.set_flags(read_ahead.0 | write_behind.0, read_ahead.1 | write_behind.1);
    Ok(())
}

/// CcSetAdditionalCacheAttributesEx(FileObject, Flags): bits 1/2 vão para
/// CcSetAdditionalCacheAttributes (salvo com o bit 0x2000), e os demais para
/// os bits de SHARED_CACHE_MAP.Flags vistos na desmontagem.
pub fn set_additional_cache_attributes_ex(file: u64, flags: u32) -> CcResult<()> {
    let base = require_map(file)?;
    let locked = CACHE.lock().maps.get(&base).is_some_and(|map| map.flags() & scm_flags::ATTRIBUTES_LOCKED != 0);
    if !locked {
        set_additional_cache_attributes(file, flags & 2 != 0, flags & 4 != 0)?;
    }
    let cache = CACHE.lock();
    let Some(map) = cache.maps.get(&base) else { return Ok(()) };
    let pick = |bit: u32, on: bool| if on { (1 << bit, 0) } else { (0, 1 << bit) };
    let mut set = 0u32;
    let mut clear = 0u32;
    for (bit, on) in [(0x17, flags & 0x1 != 0), (0x1A, flags & 0x8 != 0), (0x1C, flags & 0x10 != 0), (0x1B, flags & 0x20 != 0), (0x0C, flags & 0x1000_0000 != 0)] {
        let (on_bits, off_bits) = pick(bit, on);
        set |= on_bits;
        clear |= off_bits;
    }
    // Religar o rastreamento de páginas sujas marca o bit 0x11.
    if flags & 0x8 == 0 && map.flags() & (1 << 0x1A) != 0 {
        set |= 1 << 0x11;
    }
    map.set_flags(set, clear);
    Ok(())
}

/// CcSetReadAheadGranularity: PrivateCacheMap->ReadAheadMask = Granularity - 1.
pub fn set_read_ahead_granularity(file: u64, granularity: u32) {
    let private = file_object(file).private_cache_map.get();
    if private != 0 {
        // SAFETY: o PRIVATE_CACHE_MAP que o CcInitializeCacheMap deu ao FILE_OBJECT.
        unsafe { PrivateCacheMap::at(private) }.read_ahead_mask.set(granularity.wrapping_sub(1));
    }
}

/// FSRTL_COMMON_FCB_HEADER.Flags: FSRTL_FLAG_LIMIT_MODIFIED_PAGES.
const FSRTL_FLAG_LIMIT_MODIFIED_PAGES: u8 = 0x04;

/// CcSetDirtyPageThreshold(FileObject, DirtyPageThreshold) (RVA 0x4e9a40):
/// grava o limite em SharedCacheMap->DirtyPageThreshold, quando o arquivo já
/// tem cache map (o SectionObjectPointer é lido sem teste, como no NT), e
/// liga FSRTL_FLAG_LIMIT_MODIFIED_PAGES no cabeçalho do FCB
/// (FileObject->FsContext).
pub fn set_dirty_page_threshold(file: u64, threshold: u32) {
    let object = file_object(file);
    let map = pointers_at(object.section_object_pointer.get()).shared_cache_map.get();
    if map != 0 {
        // SAFETY: o SHARED_CACHE_MAP que o CcInitializeCacheMap pendurou no arquivo.
        unsafe { SharedCacheMap::at(map) }.dirty_page_threshold.set(threshold);
    }
    // SAFETY: o FsContext de um arquivo de file system começa pelo cabeçalho comum do FCB.
    let header = unsafe { FsrtlCommonFcbHeader::at(object.fs_context.get()) };
    let flags = header.flags.get();
    if flags & FSRTL_FLAG_LIMIT_MODIFIED_PAGES == 0 {
        header.flags.set(flags | FSRTL_FLAG_LIMIT_MODIFIED_PAGES);
    }
}

/// CcSetParallelFlushFile: bit 18 de SHARED_CACHE_MAP.Flags.
pub fn set_parallel_flush_file(file: u64, enable: bool) -> CcResult<()> {
    let base = require_map(file)?;
    if let Some(map) = CACHE.lock().maps.get(&base) {
        if enable { map.set_flags(scm_flags::PARALLEL_FLUSH, 0) } else { map.set_flags(0, scm_flags::PARALLEL_FLUSH) }
    }
    Ok(())
}

/// CcGetFileObjectFromSectionPtrs: o FILE_OBJECT do EX_FAST_REF do mapa
/// (marcando o bit 20), ou NULL sem cache map.
pub fn file_object_from_section_pointers(pointers: u64) -> u64 {
    let Some(base) = map_of_pointers(pointers) else { return 0 };
    let cache = CACHE.lock();
    let Some(map) = cache.maps.get(&base) else { return 0 };
    map.set_flags(scm_flags::FILE_OBJECT_QUERIED, 0);
    map.native().file_object_fast_ref.object.get() & !0xF
}

/// CcChangeBackingFileObject(CurrentFileObject, NewFileObject): o mapa do
/// stream (pela SectionObjectPointer do novo arquivo) passa a paginar pelo
/// novo FILE_OBJECT — sem dono atual informado, troca qualquer arquivo; com
/// dono, só se for ele. O mapa referencia o novo e solta o antigo, fora do
/// lock do Cc (o OB do OpenNT pode apagar o objeto de forma síncrona). Sem
/// cache map no stream não há o que trocar: STATUS_SUCCESS sem mudança,
/// como o MmChangeSectionBackingFile sem CONTROL_AREA.
pub fn change_backing_file_object(current: u64, new: u64) -> Result<u32, KernelError> {
    const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
    let pointers = section_pointers_of(new);
    if current != 0 && section_pointers_of(current) != pointers {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    let Some(base) = map_of_pointers(pointers) else { return Ok(0) };
    let referenced_new = matches!(file_objects::reference(new), Ok(Some(_)));
    let released = {
        let mut cache = CACHE.lock();
        match cache.maps.get_mut(&base) {
            Some(map) if current == 0 || map.file_object == current => {
                let previous = (map.file_object, map.referenced, map.section.clone());
                map.native().file_object_fast_ref.object.set(new & !0xF);
                map.file_object = new;
                map.referenced = referenced_new;
                Some(previous)
            }
            _ => None,
        }
    };
    // A seção do cache pagina pelo novo FILE_OBJECT também.
    if let Some((_, _, Some(section))) = &released {
        cache_section::change_file(section, new);
    }
    let released = released.map(|(old, referenced, _)| (old, referenced));
    match released {
        Some((old, true)) => {
            let _ = file_objects::dereference(old);
        }
        None if referenced_new => {
            let _ = file_objects::dereference(new);
        }
        _ => {}
    }
    Ok(0)
}

/// Snapshot de leitura de um mapa (testes e diagnósticos).
pub struct MapInfo {
    pub open_count: u32,
    pub file_size: u64,
    pub valid_data_goal: u64,
    pub dirty_pages: u32,
    pub views: usize,
    pub bcbs: usize,
}

pub fn info(pointers: u64) -> Option<MapInfo> {
    let base = map_of_pointers(pointers)?;
    let cache = CACHE.lock();
    let map = cache.maps.get(&base)?;
    Some(MapInfo { open_count: map.open_count, file_size: map.file_size, valid_data_goal: map.valid_data_goal, dirty_pages: map.dirty_pages(), views: map.views.len(), bcbs: map.bcbs.len() })
}
