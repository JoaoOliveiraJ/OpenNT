//! Cc: mapas de cache compartilhado e privado, VACBs e callbacks do Cache Manager.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_SHARED_CACHE_MAP` (0x228 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SharedCacheMapView1`, alcançada por `Deref`.
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
    /// -> `_VACB`
    pub initial_vacbs: [Field<u64>; 4],
    /// -> `_VACB*`
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
    /// -> `void`
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
    /// -> `_CC_PARTITION`
    pub partition: Field<u64>,
    pub internal_ref_count: Field<u32>,
    pub num_mapped_vacb: Field<u32>,
    pub num_active_vacb: Field<u32>,
    _pad_224: Reserved<0x4>,
}

/// Vista 1 de `_SHARED_CACHE_MAP` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SharedCacheMapView1 {
    _pad_0: Reserved<0xf0>,
    pub v2: LoggedStreamCallbackV2,
    _pad_f8: Reserved<0x130>,
}

impl core::ops::Deref for SharedCacheMap {
    type Target = SharedCacheMapView1;
    #[inline(always)]
    fn deref(&self) -> &SharedCacheMapView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SharedCacheMapView1>() }
    }
}

unsafe impl NtStruct for SharedCacheMap {}

const _: () = {
    assert!(core::mem::size_of::<SharedCacheMap>() == 0x228);
    assert!(core::mem::offset_of!(SharedCacheMap, node_type_code) == 0x0);
    assert!(core::mem::offset_of!(SharedCacheMap, node_byte_size) == 0x2);
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
    assert!(core::mem::size_of::<SharedCacheMapView1>() == 0x228);
    assert!(core::mem::align_of::<SharedCacheMapView1>() == core::mem::align_of::<SharedCacheMap>());
    assert!(core::mem::offset_of!(SharedCacheMapView1, v2) == 0xf0);
};

/// `_LOGGED_STREAM_CALLBACK_V1` (0x10 bytes).
#[repr(C)]
pub struct LoggedStreamCallbackV1 {
    /// -> `void`
    pub log_handle: Field<u64>,
    /// -> `fn`
    pub flush_to_lsn_routine: Field<u64>,
}

unsafe impl NtStruct for LoggedStreamCallbackV1 {}

const _: () = {
    assert!(core::mem::size_of::<LoggedStreamCallbackV1>() == 0x10);
    assert!(core::mem::offset_of!(LoggedStreamCallbackV1, log_handle) == 0x0);
    assert!(core::mem::offset_of!(LoggedStreamCallbackV1, flush_to_lsn_routine) == 0x8);
};

/// `_LOGGED_STREAM_CALLBACK_V2` (0x8 bytes).
#[repr(C)]
pub struct LoggedStreamCallbackV2 {
    /// -> `_LOG_HANDLE_CONTEXT`
    pub log_handle_context: Field<u64>,
}

unsafe impl NtStruct for LoggedStreamCallbackV2 {}

const _: () = {
    assert!(core::mem::size_of::<LoggedStreamCallbackV2>() == 0x8);
    assert!(core::mem::offset_of!(LoggedStreamCallbackV2, log_handle_context) == 0x0);
};

/// `_PRIVATE_CACHE_MAP` (0x78 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
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

/// Vista 1 de `_PRIVATE_CACHE_MAP` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PrivateCacheMapView1 {
    _align: [u64; 0],
    pub flags: PrivateCacheMapFlags,
    _pad_4: Reserved<0x74>,
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
    assert!(core::mem::offset_of!(PrivateCacheMap, node_type_code) == 0x0);
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
    assert!(core::mem::offset_of!(PrivateCacheMapView1, flags) == 0x0);
};

/// `_PRIVATE_CACHE_MAP_FLAGS` (0x4 bytes).
#[repr(C)]
pub struct PrivateCacheMapFlags {
    pub bitfield_0: Field<u32>,
}

unsafe impl NtStruct for PrivateCacheMapFlags {}

impl PrivateCacheMapFlags {
    /// `DontUse`: bits 0..=15 de `bitfield_0`.
    pub const DONT_USE_SHIFT: u32 = 0;
    pub const DONT_USE_MASK: u32 = 0xffff;
    #[inline(always)]
    pub fn dont_use(&self) -> u32 {
        self.bitfield_0.bits(0, 16) as u32
    }
    #[inline(always)]
    pub fn set_dont_use(&self, value: u32) {
        self.bitfield_0.set_bits(0, 16, value as u64)
    }
    /// `ReadAheadActive`: bits 16..=16 de `bitfield_0`.
    pub const READ_AHEAD_ACTIVE_SHIFT: u32 = 16;
    pub const READ_AHEAD_ACTIVE_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn read_ahead_active(&self) -> u32 {
        self.bitfield_0.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_read_ahead_active(&self, value: u32) {
        self.bitfield_0.set_bits(16, 1, value as u64)
    }
    /// `ReadAheadEnabled`: bits 17..=17 de `bitfield_0`.
    pub const READ_AHEAD_ENABLED_SHIFT: u32 = 17;
    pub const READ_AHEAD_ENABLED_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn read_ahead_enabled(&self) -> u32 {
        self.bitfield_0.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_read_ahead_enabled(&self, value: u32) {
        self.bitfield_0.set_bits(17, 1, value as u64)
    }
    /// `PagePriority`: bits 18..=20 de `bitfield_0`.
    pub const PAGE_PRIORITY_SHIFT: u32 = 18;
    pub const PAGE_PRIORITY_MASK: u32 = 0x1c0000;
    #[inline(always)]
    pub fn page_priority(&self) -> u32 {
        self.bitfield_0.bits(18, 3) as u32
    }
    #[inline(always)]
    pub fn set_page_priority(&self, value: u32) {
        self.bitfield_0.set_bits(18, 3, value as u64)
    }
    /// `PipelineReadAheads`: bits 21..=21 de `bitfield_0`.
    pub const PIPELINE_READ_AHEADS_SHIFT: u32 = 21;
    pub const PIPELINE_READ_AHEADS_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn pipeline_read_aheads(&self) -> u32 {
        self.bitfield_0.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_pipeline_read_aheads(&self, value: u32) {
        self.bitfield_0.set_bits(21, 1, value as u64)
    }
    /// `Available`: bits 22..=31 de `bitfield_0`.
    pub const AVAILABLE_SHIFT: u32 = 22;
    pub const AVAILABLE_MASK: u32 = 0xffc00000;
    #[inline(always)]
    pub fn available(&self) -> u32 {
        self.bitfield_0.bits(22, 10) as u32
    }
    #[inline(always)]
    pub fn set_available(&self, value: u32) {
        self.bitfield_0.set_bits(22, 10, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<PrivateCacheMapFlags>() == 0x4);
    assert!(core::mem::offset_of!(PrivateCacheMapFlags, bitfield_0) == 0x0);
};

/// `_VACB` (0x28 bytes).
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
    assert!(core::mem::offset_of!(Vacb, base_address) == 0x0);
    assert!(core::mem::offset_of!(Vacb, shared_cache_map) == 0x8);
    assert!(core::mem::offset_of!(Vacb, overlay) == 0x10);
    assert!(core::mem::offset_of!(Vacb, array_head) == 0x20);
};

/// `_VACB::Overlay` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `VacbOverlayView1`..`VacbOverlayView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct VacbOverlay {
    pub file_offset: LargeInteger,
    _pad_8: Reserved<0x8>,
}

/// Vista 1 de `_VACB::Overlay` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct VacbOverlayView1 {
    _align: [u64; 0],
    pub active_count: Field<u16>,
    _pad_2: Reserved<0xe>,
}

/// Vista 2 de `_VACB::Overlay` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct VacbOverlayView2 {
    pub links: ListEntry,
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
    assert!(core::mem::offset_of!(VacbOverlay, file_offset) == 0x0);
    assert!(core::mem::size_of::<VacbOverlayView1>() == 0x10);
    assert!(core::mem::align_of::<VacbOverlayView1>() == core::mem::align_of::<VacbOverlay>());
    assert!(core::mem::offset_of!(VacbOverlayView1, active_count) == 0x0);
    assert!(core::mem::size_of::<VacbOverlayView2>() == 0x10);
    assert!(core::mem::align_of::<VacbOverlayView2>() == core::mem::align_of::<VacbOverlay>());
    assert!(core::mem::offset_of!(VacbOverlayView2, links) == 0x0);
};

/// `_CACHE_MANAGER_CALLBACKS` (0x20 bytes).
#[repr(C)]
pub struct CacheManagerCallbacks {
    /// -> `fn`
    pub acquire_for_lazy_write: Field<u64>,
    /// -> `fn`
    pub release_from_lazy_write: Field<u64>,
    /// -> `fn`
    pub acquire_for_read_ahead: Field<u64>,
    /// -> `fn`
    pub release_from_read_ahead: Field<u64>,
}

unsafe impl NtStruct for CacheManagerCallbacks {}

const _: () = {
    assert!(core::mem::size_of::<CacheManagerCallbacks>() == 0x20);
    assert!(core::mem::offset_of!(CacheManagerCallbacks, acquire_for_lazy_write) == 0x0);
    assert!(core::mem::offset_of!(CacheManagerCallbacks, release_from_lazy_write) == 0x8);
    assert!(core::mem::offset_of!(CacheManagerCallbacks, acquire_for_read_ahead) == 0x10);
    assert!(core::mem::offset_of!(CacheManagerCallbacks, release_from_read_ahead) == 0x18);
};

/// `_CACHE_UNINITIALIZE_EVENT` (0x20 bytes).
#[repr(C)]
pub struct CacheUninitializeEvent {
    /// -> `_CACHE_UNINITIALIZE_EVENT`
    pub next: Field<u64>,
    pub event: Kevent,
}

unsafe impl NtStruct for CacheUninitializeEvent {}

const _: () = {
    assert!(core::mem::size_of::<CacheUninitializeEvent>() == 0x20);
    assert!(core::mem::offset_of!(CacheUninitializeEvent, next) == 0x0);
    assert!(core::mem::offset_of!(CacheUninitializeEvent, event) == 0x8);
};
