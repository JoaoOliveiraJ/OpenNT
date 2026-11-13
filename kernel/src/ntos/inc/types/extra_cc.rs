//! Estruturas do Cache Manager que o gerador não emitiu: os layouts do Cc
//! presentes no ntkrnlmp.pdb 19041 mas fora do conjunto gerado
//! (`_SHARED_CACHE_MAP`, `_PRIVATE_CACHE_MAP`, `_VACB`,
//! `_CACHE_MANAGER_CALLBACKS`, `_CACHE_UNINITIALIZE_EVENT`) e as estruturas
//! públicas do `ntifs.h` que não constam dos símbolos (`PUBLIC_BCB`,
//! `CC_FILE_SIZES`).
//!
//! Mantido à mão no estilo de `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`,
//! ponteiros como `Field<u64>` com o tipo apontado no comentário, uniões em
//! vistas encadeadas por `Deref`, tamanhos e offsets conferidos em compilação
//! (os do PDB: `inspect-pdb.py --type ntkrnlmp.pdb _SHARED_CACHE_MAP` etc.).

use super::*;

/// `_SHARED_CACHE_MAP` (ntkrnlmp.pdb; 0x228 bytes): o mapa compartilhado do
/// arquivo, em `SECTION_OBJECT_POINTERS.SharedCacheMap`. O `ntifs.h` lê
/// `FileSize` por `CcGetFileSizePointer` (`(PLARGE_INTEGER)SharedCacheMap + 1`).
#[repr(C)]
pub struct SharedCacheMap {
    pub node_type_code: Field<i16>,
    pub node_byte_size: Field<i16>,
    pub open_count: Field<u32>,
    pub file_size: LargeInteger,
    pub bcb_list: ListEntry,
    pub section_size: LargeInteger,
    pub valid_data_length: LargeInteger,
    pub valid_data_goal: LargeInteger,
    /// -> `_VACB` [4]
    pub initial_vacbs: [Field<u64>; 4],
    /// -> `_VACB *`
    pub vacbs: Field<u64>,
    pub file_object_fast_ref: ExFastRef,
    pub vacb_lock: ExPushLock,
    pub dirty_pages: Field<u32>,
    _pad_74: Reserved<0x4>,
    pub logged_stream_links: ListEntry,
    pub shared_cache_map_links: ListEntry,
    pub flags: Field<u32>,
    pub status: Field<i32>,
    /// -> `_MBCB`
    pub mbcb: Field<u64>,
    /// -> `void` (seção de dados)
    pub section: Field<u64>,
    /// -> `_KEVENT`
    pub create_event: Field<u64>,
    /// -> `_KEVENT`
    pub wait_on_active_count: Field<u64>,
    pub pages_to_write: Field<u32>,
    _pad_c4: Reserved<0x4>,
    pub beyond_last_flush: Field<i64>,
    /// -> `_CACHE_MANAGER_CALLBACKS`
    pub callbacks: Field<u64>,
    /// -> `void`
    pub lazy_write_context: Field<u64>,
    pub private_list: ListEntry,
    /// União `V1` (`_LOGGED_STREAM_CALLBACK_V1`) / `V2` (`_V2`).
    pub v1: LoggedStreamCallbackV1,
    pub largest_lsn: LargeInteger,
    pub dirty_page_threshold: Field<u32>,
    pub lazy_write_pass_count: Field<u32>,
    /// -> `_CACHE_UNINITIALIZE_EVENT`
    pub uninitialize_event: Field<u64>,
    pub bcb_lock: FastMutex,
    pub last_unmap_behind_offset: LargeInteger,
    pub event: Kevent,
    pub high_water_mapping_offset: LargeInteger,
    pub private_cache_map: PrivateCacheMap,
    /// -> `void`
    pub write_behind_work_queue_entry: Field<u64>,
    /// -> `_VOLUME_CACHE_MAP`
    pub volume_cache_map: Field<u64>,
    pub proc_image_path_hash: Field<u32>,
    pub writes_in_progress: Field<u32>,
    pub async_read_request_count: Field<u32>,
    _pad_20c: Reserved<0x4>,
    /// -> `_PARTITION`
    pub partition: Field<u64>,
    pub internal_ref_count: Field<u32>,
    pub num_mapped_vacb: Field<u32>,
    pub num_active_vacb: Field<u32>,
    _pad_224: Reserved<0x4>,
}

unsafe impl NtStruct for SharedCacheMap {}

const _: () = {
    assert!(core::mem::size_of::<SharedCacheMap>() == 0x228);
    assert!(core::mem::offset_of!(SharedCacheMap, open_count) == 0x4);
    assert!(core::mem::offset_of!(SharedCacheMap, file_size) == 0x8);
    assert!(core::mem::offset_of!(SharedCacheMap, bcb_list) == 0x10);
    assert!(core::mem::offset_of!(SharedCacheMap, section_size) == 0x20);
    assert!(core::mem::offset_of!(SharedCacheMap, valid_data_length) == 0x28);
    assert!(core::mem::offset_of!(SharedCacheMap, valid_data_goal) == 0x30);
    assert!(core::mem::offset_of!(SharedCacheMap, initial_vacbs) == 0x38);
    assert!(core::mem::offset_of!(SharedCacheMap, vacbs) == 0x58);
    assert!(core::mem::offset_of!(SharedCacheMap, file_object_fast_ref) == 0x60);
    assert!(core::mem::offset_of!(SharedCacheMap, vacb_lock) == 0x68);
    assert!(core::mem::offset_of!(SharedCacheMap, dirty_pages) == 0x70);
    assert!(core::mem::offset_of!(SharedCacheMap, logged_stream_links) == 0x78);
    assert!(core::mem::offset_of!(SharedCacheMap, shared_cache_map_links) == 0x88);
    assert!(core::mem::offset_of!(SharedCacheMap, flags) == 0x98);
    assert!(core::mem::offset_of!(SharedCacheMap, status) == 0x9c);
    assert!(core::mem::offset_of!(SharedCacheMap, mbcb) == 0xa0);
    assert!(core::mem::offset_of!(SharedCacheMap, section) == 0xa8);
    assert!(core::mem::offset_of!(SharedCacheMap, create_event) == 0xb0);
    assert!(core::mem::offset_of!(SharedCacheMap, wait_on_active_count) == 0xb8);
    assert!(core::mem::offset_of!(SharedCacheMap, pages_to_write) == 0xc0);
    assert!(core::mem::offset_of!(SharedCacheMap, beyond_last_flush) == 0xc8);
    assert!(core::mem::offset_of!(SharedCacheMap, callbacks) == 0xd0);
    assert!(core::mem::offset_of!(SharedCacheMap, lazy_write_context) == 0xd8);
    assert!(core::mem::offset_of!(SharedCacheMap, private_list) == 0xe0);
    assert!(core::mem::offset_of!(SharedCacheMap, v1) == 0xf0);
    assert!(core::mem::offset_of!(SharedCacheMap, largest_lsn) == 0x100);
    assert!(core::mem::offset_of!(SharedCacheMap, dirty_page_threshold) == 0x108);
    assert!(core::mem::offset_of!(SharedCacheMap, lazy_write_pass_count) == 0x10c);
    assert!(core::mem::offset_of!(SharedCacheMap, uninitialize_event) == 0x110);
    assert!(core::mem::offset_of!(SharedCacheMap, bcb_lock) == 0x118);
    assert!(core::mem::offset_of!(SharedCacheMap, last_unmap_behind_offset) == 0x150);
    assert!(core::mem::offset_of!(SharedCacheMap, event) == 0x158);
    assert!(core::mem::offset_of!(SharedCacheMap, high_water_mapping_offset) == 0x170);
    assert!(core::mem::offset_of!(SharedCacheMap, private_cache_map) == 0x178);
    assert!(core::mem::offset_of!(SharedCacheMap, write_behind_work_queue_entry) == 0x1f0);
    assert!(core::mem::offset_of!(SharedCacheMap, volume_cache_map) == 0x1f8);
    assert!(core::mem::offset_of!(SharedCacheMap, proc_image_path_hash) == 0x200);
    assert!(core::mem::offset_of!(SharedCacheMap, writes_in_progress) == 0x204);
    assert!(core::mem::offset_of!(SharedCacheMap, async_read_request_count) == 0x208);
    assert!(core::mem::offset_of!(SharedCacheMap, partition) == 0x210);
    assert!(core::mem::offset_of!(SharedCacheMap, internal_ref_count) == 0x218);
    assert!(core::mem::offset_of!(SharedCacheMap, num_mapped_vacb) == 0x21c);
    assert!(core::mem::offset_of!(SharedCacheMap, num_active_vacb) == 0x220);
};

/// `_LOGGED_STREAM_CALLBACK_V1` (0x10 bytes); a `_V2` (LogHandleContext)
/// sobrepõe o primeiro ponteiro.
#[repr(C)]
pub struct LoggedStreamCallbackV1 {
    /// -> `void`
    pub log_handle: Field<u64>,
    /// -> `PFLUSH_TO_LSN`
    pub flush_to_lsn_routine: Field<u64>,
}

unsafe impl NtStruct for LoggedStreamCallbackV1 {}

const _: () = {
    assert!(core::mem::size_of::<LoggedStreamCallbackV1>() == 0x10);
    assert!(core::mem::offset_of!(LoggedStreamCallbackV1, flush_to_lsn_routine) == 0x8);
};

/// `_PRIVATE_CACHE_MAP` (ntkrnlmp.pdb; 0x78 bytes): o mapa de cada
/// FILE_OBJECT, em `FILE_OBJECT.PrivateCacheMap`.
///
/// Membros sobrepostos (uniões anônimas do C) ficam na vista
/// `PrivateCacheMapView1`, alcançada por `Deref`.
#[repr(C)]
pub struct PrivateCacheMap {
    pub node_type_code: Field<i16>,
    _pad_2: Reserved<0x2>,
    pub read_ahead_mask: Field<u32>,
    /// -> `_FILE_OBJECT`
    pub file_object: Field<u64>,
    pub file_offset1: LargeInteger,
    pub beyond_last_byte1: LargeInteger,
    pub file_offset2: LargeInteger,
    pub beyond_last_byte2: LargeInteger,
    pub sequential_read_count: Field<u32>,
    pub read_ahead_length: Field<u32>,
    pub read_ahead_offset: LargeInteger,
    pub read_ahead_beyond_last_byte: LargeInteger,
    pub prev_read_ahead_beyond_last_byte: Field<u64>,
    pub read_ahead_spin_lock: Field<u64>,
    pub pipelined_read_ahead_request_size: Field<u32>,
    pub read_ahead_growth: Field<u32>,
    pub private_links: ListEntry,
    /// -> `void`
    pub read_ahead_work_item: Field<u64>,
}

/// Vista 1 de `_PRIVATE_CACHE_MAP`: `Flags` (`_PRIVATE_CACHE_MAP_FLAGS`)
/// sobreposto a `NodeTypeCode`.
#[repr(C)]
pub struct PrivateCacheMapView1 {
    _align: [u64; 0],
    pub flags: Field<u32>,
    _rest: Reserved<0x74>,
}

impl PrivateCacheMapView1 {
    pub const READ_AHEAD_ACTIVE_SHIFT: u32 = 16;
    pub const READ_AHEAD_ENABLED_SHIFT: u32 = 17;
    pub const PAGE_PRIORITY_SHIFT: u32 = 18;
    pub const PAGE_PRIORITY_MASK: u32 = 0x7 << 18;
    pub const PIPELINE_READ_AHEADS_SHIFT: u32 = 21;
}

impl core::ops::Deref for PrivateCacheMap {
    type Target = PrivateCacheMapView1;
    #[inline(always)]
    fn deref(&self) -> &PrivateCacheMapView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PrivateCacheMapView1>() }
    }
}

unsafe impl NtStruct for PrivateCacheMap {}

const _: () = {
    assert!(core::mem::size_of::<PrivateCacheMap>() == 0x78);
    assert!(core::mem::offset_of!(PrivateCacheMap, read_ahead_mask) == 0x4);
    assert!(core::mem::offset_of!(PrivateCacheMap, file_object) == 0x8);
    assert!(core::mem::offset_of!(PrivateCacheMap, file_offset1) == 0x10);
    assert!(core::mem::offset_of!(PrivateCacheMap, beyond_last_byte1) == 0x18);
    assert!(core::mem::offset_of!(PrivateCacheMap, file_offset2) == 0x20);
    assert!(core::mem::offset_of!(PrivateCacheMap, beyond_last_byte2) == 0x28);
    assert!(core::mem::offset_of!(PrivateCacheMap, sequential_read_count) == 0x30);
    assert!(core::mem::offset_of!(PrivateCacheMap, read_ahead_length) == 0x34);
    assert!(core::mem::offset_of!(PrivateCacheMap, read_ahead_offset) == 0x38);
    assert!(core::mem::offset_of!(PrivateCacheMap, read_ahead_beyond_last_byte) == 0x40);
    assert!(core::mem::offset_of!(PrivateCacheMap, prev_read_ahead_beyond_last_byte) == 0x48);
    assert!(core::mem::offset_of!(PrivateCacheMap, read_ahead_spin_lock) == 0x50);
    assert!(core::mem::offset_of!(PrivateCacheMap, pipelined_read_ahead_request_size) == 0x58);
    assert!(core::mem::offset_of!(PrivateCacheMap, read_ahead_growth) == 0x5c);
    assert!(core::mem::offset_of!(PrivateCacheMap, private_links) == 0x60);
    assert!(core::mem::offset_of!(PrivateCacheMap, read_ahead_work_item) == 0x70);
    assert!(core::mem::size_of::<PrivateCacheMapView1>() == 0x78);
    assert!(core::mem::align_of::<PrivateCacheMapView1>() == core::mem::align_of::<PrivateCacheMap>());
};

/// `_VACB` (ntkrnlmp.pdb; 0x28 bytes): uma vista de 256 KB do arquivo no
/// cache do sistema.
#[repr(C)]
pub struct Vacb {
    /// -> `void`
    pub base_address: Field<u64>,
    /// -> `_SHARED_CACHE_MAP`
    pub shared_cache_map: Field<u64>,
    pub overlay: VacbOverlay,
    /// -> `_VACB_ARRAY_HEADER`
    pub array_head: Field<u64>,
}

unsafe impl NtStruct for Vacb {}

const _: () = {
    assert!(core::mem::size_of::<Vacb>() == 0x28);
    assert!(core::mem::offset_of!(Vacb, shared_cache_map) == 0x8);
    assert!(core::mem::offset_of!(Vacb, overlay) == 0x10);
    assert!(core::mem::offset_of!(Vacb, array_head) == 0x20);
};

/// `_VACB::Overlay` (0x10 bytes): `Links`, com `FileOffset` e `ActiveCount`
/// (os 16 bits baixos de `FileOffset`) nas vistas.
#[repr(C)]
pub struct VacbOverlay {
    pub links: ListEntry,
}

/// Vista 1 de `_VACB::Overlay`: `FileOffset`.
#[repr(C)]
pub struct VacbOverlayView1 {
    pub file_offset: LargeInteger,
    _pad_8: Reserved<0x8>,
}

/// Vista 2 de `_VACB::Overlay`: `ActiveCount`.
#[repr(C)]
pub struct VacbOverlayView2 {
    _align: [u64; 0],
    pub active_count: Field<u16>,
    _pad_2: Reserved<0xe>,
}

impl core::ops::Deref for VacbOverlay {
    type Target = VacbOverlayView1;
    #[inline(always)]
    fn deref(&self) -> &VacbOverlayView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<VacbOverlayView1>() }
    }
}

impl core::ops::Deref for VacbOverlayView1 {
    type Target = VacbOverlayView2;
    #[inline(always)]
    fn deref(&self) -> &VacbOverlayView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<VacbOverlayView2>() }
    }
}

unsafe impl NtStruct for VacbOverlay {}

const _: () = {
    assert!(core::mem::size_of::<VacbOverlay>() == 0x10);
    assert!(core::mem::size_of::<VacbOverlayView1>() == 0x10);
    assert!(core::mem::align_of::<VacbOverlayView1>() == core::mem::align_of::<VacbOverlay>());
    assert!(core::mem::size_of::<VacbOverlayView2>() == 0x10);
    assert!(core::mem::align_of::<VacbOverlayView2>() == core::mem::align_of::<VacbOverlay>());
};

/// `_CACHE_MANAGER_CALLBACKS` (ntkrnlmp.pdb / ntifs.h; 0x20 bytes).
#[repr(C)]
pub struct CacheManagerCallbacks {
    /// -> `PACQUIRE_FOR_LAZY_WRITE` (Context, Wait)
    pub acquire_for_lazy_write: Field<u64>,
    /// -> `PRELEASE_FROM_LAZY_WRITE` (Context)
    pub release_from_lazy_write: Field<u64>,
    /// -> `PACQUIRE_FOR_READ_AHEAD` (Context, Wait)
    pub acquire_for_read_ahead: Field<u64>,
    /// -> `PRELEASE_FROM_READ_AHEAD` (Context)
    pub release_from_read_ahead: Field<u64>,
}

unsafe impl NtStruct for CacheManagerCallbacks {}

const _: () = {
    assert!(core::mem::size_of::<CacheManagerCallbacks>() == 0x20);
    assert!(core::mem::offset_of!(CacheManagerCallbacks, release_from_lazy_write) == 0x8);
    assert!(core::mem::offset_of!(CacheManagerCallbacks, acquire_for_read_ahead) == 0x10);
    assert!(core::mem::offset_of!(CacheManagerCallbacks, release_from_read_ahead) == 0x18);
};

/// `_CACHE_UNINITIALIZE_EVENT` (ntkrnlmp.pdb / ntifs.h; 0x20 bytes).
#[repr(C)]
pub struct CacheUninitializeEvent {
    /// -> `_CACHE_UNINITIALIZE_EVENT`
    pub next: Field<u64>,
    pub event: Kevent,
}

unsafe impl NtStruct for CacheUninitializeEvent {}

const _: () = {
    assert!(core::mem::size_of::<CacheUninitializeEvent>() == 0x20);
    assert!(core::mem::offset_of!(CacheUninitializeEvent, event) == 0x8);
};

/// `PUBLIC_BCB` (ntifs.h; 0x10 bytes): o prefixo público de todo BCB que o
/// CcPinRead/CcPreparePinWrite devolve.
#[repr(C)]
pub struct PublicBcb {
    pub node_type_code: Field<i16>,
    pub node_byte_size: Field<i16>,
    pub mapped_length: Field<u32>,
    pub mapped_file_offset: LargeInteger,
}

unsafe impl NtStruct for PublicBcb {}

const _: () = {
    assert!(core::mem::size_of::<PublicBcb>() == 0x10);
    assert!(core::mem::offset_of!(PublicBcb, mapped_length) == 0x4);
    assert!(core::mem::offset_of!(PublicBcb, mapped_file_offset) == 0x8);
};

/// `CC_FILE_SIZES` (ntifs.h; 0x18 bytes).
#[repr(C)]
pub struct CcFileSizes {
    pub allocation_size: LargeInteger,
    pub file_size: LargeInteger,
    pub valid_data_length: LargeInteger,
}

unsafe impl NtStruct for CcFileSizes {}

const _: () = {
    assert!(core::mem::size_of::<CcFileSizes>() == 0x18);
    assert!(core::mem::offset_of!(CcFileSizes, file_size) == 0x8);
    assert!(core::mem::offset_of!(CcFileSizes, valid_data_length) == 0x10);
};
