//! Ob: cabeçalhos de objeto, tipos, diretórios e tabelas de handles.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_OBJECT_ATTRIBUTES` (0x30 bytes).
#[repr(C)]
pub struct ObjectAttributes {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub root_directory: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub object_name: Field<u64>,
    pub attributes: Field<u32>,
    _pad_1c: Reserved<0x4>,
    /// -> `void`
    pub security_descriptor: Field<u64>,
    /// -> `void`
    pub security_quality_of_service: Field<u64>,
}

unsafe impl NtStruct for ObjectAttributes {}

const _: () = {
    assert!(core::mem::size_of::<ObjectAttributes>() == 0x30);
    assert!(core::mem::offset_of!(ObjectAttributes, length) == 0x0);
    assert!(core::mem::offset_of!(ObjectAttributes, root_directory) == 0x8);
    assert!(core::mem::offset_of!(ObjectAttributes, object_name) == 0x10);
    assert!(core::mem::offset_of!(ObjectAttributes, attributes) == 0x18);
    assert!(core::mem::offset_of!(ObjectAttributes, security_descriptor) == 0x20);
    assert!(core::mem::offset_of!(ObjectAttributes, security_quality_of_service) == 0x28);
};

/// `_OBJECT_HEADER` (0x38 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ObjectHeaderView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ObjectHeader {
    pub pointer_count: Field<i64>,
    pub handle_count: Field<i64>,
    pub lock: ExPushLock,
    pub type_index: Field<u8>,
    pub trace_flags: Field<u8>,
    pub info_mask: Field<u8>,
    pub flags: Field<u8>,
    pub reserved: Field<u32>,
    /// -> `_OBJECT_CREATE_INFORMATION`
    pub object_create_info: Field<u64>,
    /// -> `void`
    pub security_descriptor: Field<u64>,
    pub body: Quad,
}

/// Vista 1 de `_OBJECT_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ObjectHeaderView1 {
    _pad_0: Reserved<0x8>,
    /// -> `void`
    pub next_to_free: Field<u64>,
    _pad_10: Reserved<0x10>,
    /// -> `void`
    pub quota_block_charged: Field<u64>,
    _pad_28: Reserved<0x10>,
}

impl core::ops::Deref for ObjectHeader {
    type Target = ObjectHeaderView1;
    #[inline(always)]
    fn deref(&self) -> &ObjectHeaderView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ObjectHeaderView1>() }
    }
}

unsafe impl NtStruct for ObjectHeader {}

impl ObjectHeader {
    /// `DbgRefTrace`: bits 0..=0 de `trace_flags`.
    pub const DBG_REF_TRACE_SHIFT: u32 = 0;
    pub const DBG_REF_TRACE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn dbg_ref_trace(&self) -> u8 {
        self.trace_flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_dbg_ref_trace(&self, value: u8) {
        self.trace_flags.set_bits(0, 1, value as u64)
    }
    /// `DbgTracePermanent`: bits 1..=1 de `trace_flags`.
    pub const DBG_TRACE_PERMANENT_SHIFT: u32 = 1;
    pub const DBG_TRACE_PERMANENT_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn dbg_trace_permanent(&self) -> u8 {
        self.trace_flags.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_dbg_trace_permanent(&self, value: u8) {
        self.trace_flags.set_bits(1, 1, value as u64)
    }
    /// `NewObject`: bits 0..=0 de `flags`.
    pub const NEW_OBJECT_SHIFT: u32 = 0;
    pub const NEW_OBJECT_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn new_object(&self) -> u8 {
        self.flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_new_object(&self, value: u8) {
        self.flags.set_bits(0, 1, value as u64)
    }
    /// `KernelObject`: bits 1..=1 de `flags`.
    pub const KERNEL_OBJECT_SHIFT: u32 = 1;
    pub const KERNEL_OBJECT_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn kernel_object(&self) -> u8 {
        self.flags.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_kernel_object(&self, value: u8) {
        self.flags.set_bits(1, 1, value as u64)
    }
    /// `KernelOnlyAccess`: bits 2..=2 de `flags`.
    pub const KERNEL_ONLY_ACCESS_SHIFT: u32 = 2;
    pub const KERNEL_ONLY_ACCESS_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn kernel_only_access(&self) -> u8 {
        self.flags.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_kernel_only_access(&self, value: u8) {
        self.flags.set_bits(2, 1, value as u64)
    }
    /// `ExclusiveObject`: bits 3..=3 de `flags`.
    pub const EXCLUSIVE_OBJECT_SHIFT: u32 = 3;
    pub const EXCLUSIVE_OBJECT_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn exclusive_object(&self) -> u8 {
        self.flags.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_exclusive_object(&self, value: u8) {
        self.flags.set_bits(3, 1, value as u64)
    }
    /// `PermanentObject`: bits 4..=4 de `flags`.
    pub const PERMANENT_OBJECT_SHIFT: u32 = 4;
    pub const PERMANENT_OBJECT_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn permanent_object(&self) -> u8 {
        self.flags.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_permanent_object(&self, value: u8) {
        self.flags.set_bits(4, 1, value as u64)
    }
    /// `DefaultSecurityQuota`: bits 5..=5 de `flags`.
    pub const DEFAULT_SECURITY_QUOTA_SHIFT: u32 = 5;
    pub const DEFAULT_SECURITY_QUOTA_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn default_security_quota(&self) -> u8 {
        self.flags.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_default_security_quota(&self, value: u8) {
        self.flags.set_bits(5, 1, value as u64)
    }
    /// `SingleHandleEntry`: bits 6..=6 de `flags`.
    pub const SINGLE_HANDLE_ENTRY_SHIFT: u32 = 6;
    pub const SINGLE_HANDLE_ENTRY_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn single_handle_entry(&self) -> u8 {
        self.flags.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_single_handle_entry(&self, value: u8) {
        self.flags.set_bits(6, 1, value as u64)
    }
    /// `DeletedInline`: bits 7..=7 de `flags`.
    pub const DELETED_INLINE_SHIFT: u32 = 7;
    pub const DELETED_INLINE_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn deleted_inline(&self) -> u8 {
        self.flags.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_deleted_inline(&self, value: u8) {
        self.flags.set_bits(7, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeader>() == 0x38);
    assert!(core::mem::offset_of!(ObjectHeader, pointer_count) == 0x0);
    assert!(core::mem::offset_of!(ObjectHeader, handle_count) == 0x8);
    assert!(core::mem::offset_of!(ObjectHeader, lock) == 0x10);
    assert!(core::mem::offset_of!(ObjectHeader, type_index) == 0x18);
    assert!(core::mem::offset_of!(ObjectHeader, trace_flags) == 0x19);
    assert!(core::mem::offset_of!(ObjectHeader, info_mask) == 0x1a);
    assert!(core::mem::offset_of!(ObjectHeader, flags) == 0x1b);
    assert!(core::mem::offset_of!(ObjectHeader, reserved) == 0x1c);
    assert!(core::mem::offset_of!(ObjectHeader, object_create_info) == 0x20);
    assert!(core::mem::offset_of!(ObjectHeader, security_descriptor) == 0x28);
    assert!(core::mem::offset_of!(ObjectHeader, body) == 0x30);
    assert!(core::mem::size_of::<ObjectHeaderView1>() == 0x38);
    assert!(core::mem::align_of::<ObjectHeaderView1>() == core::mem::align_of::<ObjectHeader>());
    assert!(core::mem::offset_of!(ObjectHeaderView1, next_to_free) == 0x8);
    assert!(core::mem::offset_of!(ObjectHeaderView1, quota_block_charged) == 0x20);
};

/// `_OBJECT_TYPE` (0xd8 bytes).
#[repr(C)]
pub struct ObjectType {
    pub type_list: ListEntry,
    pub name: UnicodeString,
    /// -> `void`
    pub default_object: Field<u64>,
    pub index: Field<u8>,
    _pad_29: Reserved<0x3>,
    pub total_number_of_objects: Field<u32>,
    pub total_number_of_handles: Field<u32>,
    pub high_water_number_of_objects: Field<u32>,
    pub high_water_number_of_handles: Field<u32>,
    _pad_3c: Reserved<0x4>,
    pub type_info: ObjectTypeInitializer,
    pub type_lock: ExPushLock,
    pub key: Field<u32>,
    _pad_c4: Reserved<0x4>,
    pub callback_list: ListEntry,
}

unsafe impl NtStruct for ObjectType {}

const _: () = {
    assert!(core::mem::size_of::<ObjectType>() == 0xd8);
    assert!(core::mem::offset_of!(ObjectType, type_list) == 0x0);
    assert!(core::mem::offset_of!(ObjectType, name) == 0x10);
    assert!(core::mem::offset_of!(ObjectType, default_object) == 0x20);
    assert!(core::mem::offset_of!(ObjectType, index) == 0x28);
    assert!(core::mem::offset_of!(ObjectType, total_number_of_objects) == 0x2c);
    assert!(core::mem::offset_of!(ObjectType, total_number_of_handles) == 0x30);
    assert!(core::mem::offset_of!(ObjectType, high_water_number_of_objects) == 0x34);
    assert!(core::mem::offset_of!(ObjectType, high_water_number_of_handles) == 0x38);
    assert!(core::mem::offset_of!(ObjectType, type_info) == 0x40);
    assert!(core::mem::offset_of!(ObjectType, type_lock) == 0xb8);
    assert!(core::mem::offset_of!(ObjectType, key) == 0xc0);
    assert!(core::mem::offset_of!(ObjectType, callback_list) == 0xc8);
};

/// `_OBJECT_TYPE_INITIALIZER` (0x78 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ObjectTypeInitializerView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ObjectTypeInitializer {
    pub length: Field<u16>,
    pub object_type_flags: Field<u16>,
    pub object_type_code: Field<u32>,
    pub invalid_attributes: Field<u32>,
    pub generic_mapping: GenericMapping,
    pub valid_access_mask: Field<u32>,
    pub retain_access: Field<u32>,
    pub pool_type: Field<PoolType>,
    pub default_paged_pool_charge: Field<u32>,
    pub default_non_paged_pool_charge: Field<u32>,
    /// -> `fn`
    pub dump_procedure: Field<u64>,
    /// -> `fn`
    pub open_procedure: Field<u64>,
    /// -> `fn`
    pub close_procedure: Field<u64>,
    /// -> `fn`
    pub delete_procedure: Field<u64>,
    /// -> `fn`
    pub parse_procedure: Field<u64>,
    /// -> `fn`
    pub security_procedure: Field<u64>,
    /// -> `fn`
    pub query_name_procedure: Field<u64>,
    /// -> `fn`
    pub okay_to_close_procedure: Field<u64>,
    pub wait_object_flag_mask: Field<u32>,
    pub wait_object_flag_offset: Field<u16>,
    pub wait_object_pointer_offset: Field<u16>,
}

/// Vista 1 de `_OBJECT_TYPE_INITIALIZER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ObjectTypeInitializerView1 {
    _pad_0: Reserved<0x2>,
    pub bitfield_2: Field<u8>,
    pub bitfield_3: Field<u8>,
    _pad_4: Reserved<0x4c>,
    /// -> `fn`
    pub parse_procedure_ex: Field<u64>,
    _pad_58: Reserved<0x20>,
}

impl core::ops::Deref for ObjectTypeInitializer {
    type Target = ObjectTypeInitializerView1;
    #[inline(always)]
    fn deref(&self) -> &ObjectTypeInitializerView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ObjectTypeInitializerView1>() }
    }
}

unsafe impl NtStruct for ObjectTypeInitializer {}

impl ObjectTypeInitializer {
    /// `CaseInsensitive`: bits 0..=0 de `bitfield_2`.
    pub const CASE_INSENSITIVE_SHIFT: u32 = 0;
    pub const CASE_INSENSITIVE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn case_insensitive(&self) -> u8 {
        self.bitfield_2.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_case_insensitive(&self, value: u8) {
        self.bitfield_2.set_bits(0, 1, value as u64)
    }
    /// `UnnamedObjectsOnly`: bits 1..=1 de `bitfield_2`.
    pub const UNNAMED_OBJECTS_ONLY_SHIFT: u32 = 1;
    pub const UNNAMED_OBJECTS_ONLY_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn unnamed_objects_only(&self) -> u8 {
        self.bitfield_2.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_unnamed_objects_only(&self, value: u8) {
        self.bitfield_2.set_bits(1, 1, value as u64)
    }
    /// `UseDefaultObject`: bits 2..=2 de `bitfield_2`.
    pub const USE_DEFAULT_OBJECT_SHIFT: u32 = 2;
    pub const USE_DEFAULT_OBJECT_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn use_default_object(&self) -> u8 {
        self.bitfield_2.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_use_default_object(&self, value: u8) {
        self.bitfield_2.set_bits(2, 1, value as u64)
    }
    /// `SecurityRequired`: bits 3..=3 de `bitfield_2`.
    pub const SECURITY_REQUIRED_SHIFT: u32 = 3;
    pub const SECURITY_REQUIRED_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn security_required(&self) -> u8 {
        self.bitfield_2.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_security_required(&self, value: u8) {
        self.bitfield_2.set_bits(3, 1, value as u64)
    }
    /// `MaintainHandleCount`: bits 4..=4 de `bitfield_2`.
    pub const MAINTAIN_HANDLE_COUNT_SHIFT: u32 = 4;
    pub const MAINTAIN_HANDLE_COUNT_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn maintain_handle_count(&self) -> u8 {
        self.bitfield_2.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_maintain_handle_count(&self, value: u8) {
        self.bitfield_2.set_bits(4, 1, value as u64)
    }
    /// `MaintainTypeList`: bits 5..=5 de `bitfield_2`.
    pub const MAINTAIN_TYPE_LIST_SHIFT: u32 = 5;
    pub const MAINTAIN_TYPE_LIST_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn maintain_type_list(&self) -> u8 {
        self.bitfield_2.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_maintain_type_list(&self, value: u8) {
        self.bitfield_2.set_bits(5, 1, value as u64)
    }
    /// `SupportsObjectCallbacks`: bits 6..=6 de `bitfield_2`.
    pub const SUPPORTS_OBJECT_CALLBACKS_SHIFT: u32 = 6;
    pub const SUPPORTS_OBJECT_CALLBACKS_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn supports_object_callbacks(&self) -> u8 {
        self.bitfield_2.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_supports_object_callbacks(&self, value: u8) {
        self.bitfield_2.set_bits(6, 1, value as u64)
    }
    /// `CacheAligned`: bits 7..=7 de `bitfield_2`.
    pub const CACHE_ALIGNED_SHIFT: u32 = 7;
    pub const CACHE_ALIGNED_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn cache_aligned(&self) -> u8 {
        self.bitfield_2.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_cache_aligned(&self, value: u8) {
        self.bitfield_2.set_bits(7, 1, value as u64)
    }
    /// `UseExtendedParameters`: bits 0..=0 de `bitfield_3`.
    pub const USE_EXTENDED_PARAMETERS_SHIFT: u32 = 0;
    pub const USE_EXTENDED_PARAMETERS_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn use_extended_parameters(&self) -> u8 {
        self.bitfield_3.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_use_extended_parameters(&self, value: u8) {
        self.bitfield_3.set_bits(0, 1, value as u64)
    }
    /// `Reserved`: bits 1..=7 de `bitfield_3`.
    pub const RESERVED_SHIFT: u32 = 1;
    pub const RESERVED_MASK: u8 = 0xfe;
    #[inline(always)]
    pub fn reserved(&self) -> u8 {
        self.bitfield_3.bits(1, 7) as u8
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u8) {
        self.bitfield_3.set_bits(1, 7, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ObjectTypeInitializer>() == 0x78);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, length) == 0x0);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, object_type_flags) == 0x2);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, object_type_code) == 0x4);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, invalid_attributes) == 0x8);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, generic_mapping) == 0xc);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, valid_access_mask) == 0x1c);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, retain_access) == 0x20);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, pool_type) == 0x24);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, default_paged_pool_charge) == 0x28);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, default_non_paged_pool_charge) == 0x2c);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, dump_procedure) == 0x30);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, open_procedure) == 0x38);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, close_procedure) == 0x40);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, delete_procedure) == 0x48);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, parse_procedure) == 0x50);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, security_procedure) == 0x58);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, query_name_procedure) == 0x60);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, okay_to_close_procedure) == 0x68);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, wait_object_flag_mask) == 0x70);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, wait_object_flag_offset) == 0x74);
    assert!(core::mem::offset_of!(ObjectTypeInitializer, wait_object_pointer_offset) == 0x76);
    assert!(core::mem::size_of::<ObjectTypeInitializerView1>() == 0x78);
    assert!(core::mem::align_of::<ObjectTypeInitializerView1>() == core::mem::align_of::<ObjectTypeInitializer>());
    assert!(core::mem::offset_of!(ObjectTypeInitializerView1, bitfield_2) == 0x2);
    assert!(core::mem::offset_of!(ObjectTypeInitializerView1, bitfield_3) == 0x3);
    assert!(core::mem::offset_of!(ObjectTypeInitializerView1, parse_procedure_ex) == 0x50);
};

/// `_OBJECT_HEADER_NAME_INFO` (0x20 bytes).
#[repr(C)]
pub struct ObjectHeaderNameInfo {
    /// -> `_OBJECT_DIRECTORY`
    pub directory: Field<u64>,
    pub name: UnicodeString,
    pub reference_count: Field<i32>,
    pub reserved: Field<u32>,
}

unsafe impl NtStruct for ObjectHeaderNameInfo {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeaderNameInfo>() == 0x20);
    assert!(core::mem::offset_of!(ObjectHeaderNameInfo, directory) == 0x0);
    assert!(core::mem::offset_of!(ObjectHeaderNameInfo, name) == 0x8);
    assert!(core::mem::offset_of!(ObjectHeaderNameInfo, reference_count) == 0x18);
    assert!(core::mem::offset_of!(ObjectHeaderNameInfo, reserved) == 0x1c);
};

/// `_OBJECT_DIRECTORY` (0x158 bytes).
#[repr(C)]
pub struct ObjectDirectory {
    /// -> `_OBJECT_DIRECTORY_ENTRY`
    pub hash_buckets: [Field<u64>; 37],
    pub lock: ExPushLock,
    /// -> `_DEVICE_MAP`
    pub device_map: Field<u64>,
    /// -> `_OBJECT_DIRECTORY`
    pub shadow_directory: Field<u64>,
    /// -> `void`
    pub namespace_entry: Field<u64>,
    /// -> `void`
    pub session_object: Field<u64>,
    pub flags: Field<u32>,
    pub session_id: Field<u32>,
}

unsafe impl NtStruct for ObjectDirectory {}

const _: () = {
    assert!(core::mem::size_of::<ObjectDirectory>() == 0x158);
    assert!(core::mem::offset_of!(ObjectDirectory, hash_buckets) == 0x0);
    assert!(core::mem::offset_of!(ObjectDirectory, lock) == 0x128);
    assert!(core::mem::offset_of!(ObjectDirectory, device_map) == 0x130);
    assert!(core::mem::offset_of!(ObjectDirectory, shadow_directory) == 0x138);
    assert!(core::mem::offset_of!(ObjectDirectory, namespace_entry) == 0x140);
    assert!(core::mem::offset_of!(ObjectDirectory, session_object) == 0x148);
    assert!(core::mem::offset_of!(ObjectDirectory, flags) == 0x150);
    assert!(core::mem::offset_of!(ObjectDirectory, session_id) == 0x154);
};

/// `_HANDLE_TABLE` (0x80 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `HandleTableView1`, alcançada por `Deref`.
#[repr(C)]
pub struct HandleTable {
    pub next_handle_needing_pool: Field<u32>,
    pub extra_info_pages: Field<i32>,
    pub table_code: Field<u64>,
    /// -> `_EPROCESS`
    pub quota_process: Field<u64>,
    pub handle_table_list: ListEntry,
    pub unique_process_id: Field<u32>,
    pub flags: Field<u32>,
    pub handle_contention_event: ExPushLock,
    pub handle_table_lock: ExPushLock,
    pub free_lists: [HandleTableFreeList; 1],
}

/// Vista 1 de `_HANDLE_TABLE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct HandleTableView1 {
    _pad_0: Reserved<0x2c>,
    pub bitfield_2c: Field<u8>,
    _pad_2d: Reserved<0x13>,
    pub actual_entry: [Field<u8>; 32],
    /// -> `_HANDLE_TRACE_DEBUG_INFO`
    pub debug_info: Field<u64>,
    _pad_68: Reserved<0x18>,
}

impl core::ops::Deref for HandleTable {
    type Target = HandleTableView1;
    #[inline(always)]
    fn deref(&self) -> &HandleTableView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<HandleTableView1>() }
    }
}

unsafe impl NtStruct for HandleTable {}

impl HandleTable {
    /// `StrictFIFO`: bits 0..=0 de `bitfield_2c`.
    pub const STRICT_FIFO_SHIFT: u32 = 0;
    pub const STRICT_FIFO_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn strict_fifo(&self) -> u8 {
        self.bitfield_2c.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_strict_fifo(&self, value: u8) {
        self.bitfield_2c.set_bits(0, 1, value as u64)
    }
    /// `EnableHandleExceptions`: bits 1..=1 de `bitfield_2c`.
    pub const ENABLE_HANDLE_EXCEPTIONS_SHIFT: u32 = 1;
    pub const ENABLE_HANDLE_EXCEPTIONS_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn enable_handle_exceptions(&self) -> u8 {
        self.bitfield_2c.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_enable_handle_exceptions(&self, value: u8) {
        self.bitfield_2c.set_bits(1, 1, value as u64)
    }
    /// `Rundown`: bits 2..=2 de `bitfield_2c`.
    pub const RUNDOWN_SHIFT: u32 = 2;
    pub const RUNDOWN_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn rundown(&self) -> u8 {
        self.bitfield_2c.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_rundown(&self, value: u8) {
        self.bitfield_2c.set_bits(2, 1, value as u64)
    }
    /// `Duplicated`: bits 3..=3 de `bitfield_2c`.
    pub const DUPLICATED_SHIFT: u32 = 3;
    pub const DUPLICATED_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn duplicated(&self) -> u8 {
        self.bitfield_2c.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_duplicated(&self, value: u8) {
        self.bitfield_2c.set_bits(3, 1, value as u64)
    }
    /// `RaiseUMExceptionOnInvalidHandleClose`: bits 4..=4 de `bitfield_2c`.
    pub const RAISE_UM_EXCEPTION_ON_INVALID_HANDLE_CLOSE_SHIFT: u32 = 4;
    pub const RAISE_UM_EXCEPTION_ON_INVALID_HANDLE_CLOSE_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn raise_um_exception_on_invalid_handle_close(&self) -> u8 {
        self.bitfield_2c.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_raise_um_exception_on_invalid_handle_close(&self, value: u8) {
        self.bitfield_2c.set_bits(4, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<HandleTable>() == 0x80);
    assert!(core::mem::offset_of!(HandleTable, next_handle_needing_pool) == 0x0);
    assert!(core::mem::offset_of!(HandleTable, extra_info_pages) == 0x4);
    assert!(core::mem::offset_of!(HandleTable, table_code) == 0x8);
    assert!(core::mem::offset_of!(HandleTable, quota_process) == 0x10);
    assert!(core::mem::offset_of!(HandleTable, handle_table_list) == 0x18);
    assert!(core::mem::offset_of!(HandleTable, unique_process_id) == 0x28);
    assert!(core::mem::offset_of!(HandleTable, flags) == 0x2c);
    assert!(core::mem::offset_of!(HandleTable, handle_contention_event) == 0x30);
    assert!(core::mem::offset_of!(HandleTable, handle_table_lock) == 0x38);
    assert!(core::mem::offset_of!(HandleTable, free_lists) == 0x40);
    assert!(core::mem::size_of::<HandleTableView1>() == 0x80);
    assert!(core::mem::align_of::<HandleTableView1>() == core::mem::align_of::<HandleTable>());
    assert!(core::mem::offset_of!(HandleTableView1, bitfield_2c) == 0x2c);
    assert!(core::mem::offset_of!(HandleTableView1, actual_entry) == 0x40);
    assert!(core::mem::offset_of!(HandleTableView1, debug_info) == 0x60);
};

/// `_HANDLE_TABLE_FREE_LIST` (0x40 bytes).
#[repr(C)]
pub struct HandleTableFreeList {
    pub free_list_lock: ExPushLock,
    /// -> `_HANDLE_TABLE_ENTRY`
    pub first_free_handle_entry: Field<u64>,
    /// -> `_HANDLE_TABLE_ENTRY`
    pub last_free_handle_entry: Field<u64>,
    pub handle_count: Field<i32>,
    pub high_water_mark: Field<u32>,
    _pad_20: Reserved<0x20>,
}

unsafe impl NtStruct for HandleTableFreeList {}

const _: () = {
    assert!(core::mem::size_of::<HandleTableFreeList>() == 0x40);
    assert!(core::mem::offset_of!(HandleTableFreeList, free_list_lock) == 0x0);
    assert!(core::mem::offset_of!(HandleTableFreeList, first_free_handle_entry) == 0x8);
    assert!(core::mem::offset_of!(HandleTableFreeList, last_free_handle_entry) == 0x10);
    assert!(core::mem::offset_of!(HandleTableFreeList, handle_count) == 0x18);
    assert!(core::mem::offset_of!(HandleTableFreeList, high_water_mark) == 0x1c);
};

/// `_HANDLE_TABLE_ENTRY` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `HandleTableEntryView1`..`HandleTableEntryView3`, alcançadas por `Deref`.
#[repr(C)]
pub struct HandleTableEntry {
    pub volatile_low_value: Field<i64>,
    pub high_value: Field<i64>,
}

/// Vista 1 de `_HANDLE_TABLE_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct HandleTableEntryView1 {
    pub low_value: Field<i64>,
    /// -> `_HANDLE_TABLE_ENTRY`
    pub next_free_handle_entry: Field<u64>,
}

/// Vista 2 de `_HANDLE_TABLE_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct HandleTableEntryView2 {
    /// -> `_HANDLE_TABLE_ENTRY_INFO`
    pub info_table: Field<u64>,
    pub leaf_handle_value: Exhandle,
}

/// Vista 3 de `_HANDLE_TABLE_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct HandleTableEntryView3 {
    pub ref_count_field: Field<i64>,
    pub bitfield_8: Field<u32>,
    pub spare2: Field<u32>,
}

impl core::ops::Deref for HandleTableEntry {
    type Target = HandleTableEntryView1;
    #[inline(always)]
    fn deref(&self) -> &HandleTableEntryView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<HandleTableEntryView1>() }
    }
}

impl core::ops::Deref for HandleTableEntryView1 {
    type Target = HandleTableEntryView2;
    #[inline(always)]
    fn deref(&self) -> &HandleTableEntryView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<HandleTableEntryView2>() }
    }
}

impl core::ops::Deref for HandleTableEntryView2 {
    type Target = HandleTableEntryView3;
    #[inline(always)]
    fn deref(&self) -> &HandleTableEntryView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<HandleTableEntryView3>() }
    }
}

unsafe impl NtStruct for HandleTableEntry {}

impl HandleTableEntry {
    /// `Unlocked`: bits 0..=0 de `volatile_low_value`.
    pub const UNLOCKED_SHIFT: u32 = 0;
    pub const UNLOCKED_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn unlocked(&self) -> u64 {
        self.volatile_low_value.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_unlocked(&self, value: u64) {
        self.volatile_low_value.set_bits(0, 1, value as u64)
    }
    /// `RefCnt`: bits 1..=16 de `volatile_low_value`.
    pub const REF_CNT_SHIFT: u32 = 1;
    pub const REF_CNT_MASK: u64 = 0x1fffe;
    #[inline(always)]
    pub fn ref_cnt(&self) -> u64 {
        self.volatile_low_value.bits(1, 16) as u64
    }
    #[inline(always)]
    pub fn set_ref_cnt(&self, value: u64) {
        self.volatile_low_value.set_bits(1, 16, value as u64)
    }
    /// `Attributes`: bits 17..=19 de `volatile_low_value`.
    pub const ATTRIBUTES_SHIFT: u32 = 17;
    pub const ATTRIBUTES_MASK: u64 = 0xe0000;
    #[inline(always)]
    pub fn attributes(&self) -> u64 {
        self.volatile_low_value.bits(17, 3) as u64
    }
    #[inline(always)]
    pub fn set_attributes(&self, value: u64) {
        self.volatile_low_value.set_bits(17, 3, value as u64)
    }
    /// `ObjectPointerBits`: bits 20..=63 de `volatile_low_value`.
    pub const OBJECT_POINTER_BITS_SHIFT: u32 = 20;
    pub const OBJECT_POINTER_BITS_MASK: u64 = 0xfffffffffff00000;
    #[inline(always)]
    pub fn object_pointer_bits(&self) -> u64 {
        self.volatile_low_value.bits(20, 44) as u64
    }
    #[inline(always)]
    pub fn set_object_pointer_bits(&self, value: u64) {
        self.volatile_low_value.set_bits(20, 44, value as u64)
    }
    /// `GrantedAccessBits`: bits 0..=24 de `bitfield_8`.
    pub const GRANTED_ACCESS_BITS_SHIFT: u32 = 0;
    pub const GRANTED_ACCESS_BITS_MASK: u32 = 0x1ffffff;
    #[inline(always)]
    pub fn granted_access_bits(&self) -> u32 {
        self.bitfield_8.bits(0, 25) as u32
    }
    #[inline(always)]
    pub fn set_granted_access_bits(&self, value: u32) {
        self.bitfield_8.set_bits(0, 25, value as u64)
    }
    /// `NoRightsUpgrade`: bits 25..=25 de `bitfield_8`.
    pub const NO_RIGHTS_UPGRADE_SHIFT: u32 = 25;
    pub const NO_RIGHTS_UPGRADE_MASK: u32 = 0x2000000;
    #[inline(always)]
    pub fn no_rights_upgrade(&self) -> u32 {
        self.bitfield_8.bits(25, 1) as u32
    }
    #[inline(always)]
    pub fn set_no_rights_upgrade(&self, value: u32) {
        self.bitfield_8.set_bits(25, 1, value as u64)
    }
    /// `Spare1`: bits 26..=31 de `bitfield_8`.
    pub const SPARE1_SHIFT: u32 = 26;
    pub const SPARE1_MASK: u32 = 0xfc000000;
    #[inline(always)]
    pub fn spare1(&self) -> u32 {
        self.bitfield_8.bits(26, 6) as u32
    }
    #[inline(always)]
    pub fn set_spare1(&self, value: u32) {
        self.bitfield_8.set_bits(26, 6, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<HandleTableEntry>() == 0x10);
    assert!(core::mem::offset_of!(HandleTableEntry, volatile_low_value) == 0x0);
    assert!(core::mem::offset_of!(HandleTableEntry, high_value) == 0x8);
    assert!(core::mem::size_of::<HandleTableEntryView1>() == 0x10);
    assert!(core::mem::align_of::<HandleTableEntryView1>() == core::mem::align_of::<HandleTableEntry>());
    assert!(core::mem::offset_of!(HandleTableEntryView1, low_value) == 0x0);
    assert!(core::mem::offset_of!(HandleTableEntryView1, next_free_handle_entry) == 0x8);
    assert!(core::mem::size_of::<HandleTableEntryView2>() == 0x10);
    assert!(core::mem::align_of::<HandleTableEntryView2>() == core::mem::align_of::<HandleTableEntry>());
    assert!(core::mem::offset_of!(HandleTableEntryView2, info_table) == 0x0);
    assert!(core::mem::offset_of!(HandleTableEntryView2, leaf_handle_value) == 0x8);
    assert!(core::mem::size_of::<HandleTableEntryView3>() == 0x10);
    assert!(core::mem::align_of::<HandleTableEntryView3>() == core::mem::align_of::<HandleTableEntry>());
    assert!(core::mem::offset_of!(HandleTableEntryView3, ref_count_field) == 0x0);
    assert!(core::mem::offset_of!(HandleTableEntryView3, bitfield_8) == 0x8);
    assert!(core::mem::offset_of!(HandleTableEntryView3, spare2) == 0xc);
};

/// `_OBJECT_HANDLE_INFORMATION` (0x8 bytes).
#[repr(C)]
pub struct ObjectHandleInformation {
    pub handle_attributes: Field<u32>,
    pub granted_access: Field<u32>,
}

unsafe impl NtStruct for ObjectHandleInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHandleInformation>() == 0x8);
    assert!(core::mem::offset_of!(ObjectHandleInformation, handle_attributes) == 0x0);
    assert!(core::mem::offset_of!(ObjectHandleInformation, granted_access) == 0x4);
};

/// `_OBJECT_NAME_INFORMATION` (0x10 bytes).
#[repr(C)]
pub struct ObjectNameInformation {
    pub name: UnicodeString,
}

unsafe impl NtStruct for ObjectNameInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObjectNameInformation>() == 0x10);
    assert!(core::mem::offset_of!(ObjectNameInformation, name) == 0x0);
};

/// `_OBP_SILODRIVERSTATE` (0x2e0 bytes).
#[repr(C)]
pub struct ObpSilodriverstate {
    /// -> `_DEVICE_MAP`
    pub system_device_map: Field<u64>,
    pub system_dos_device_state: ObpSystemDosDeviceState,
    _pad_74: Reserved<0x4>,
    pub device_map_lock: ExPushLock,
    pub private_namespace_lookup_table: ObjectNamespaceLookuptable,
}

unsafe impl NtStruct for ObpSilodriverstate {}

const _: () = {
    assert!(core::mem::size_of::<ObpSilodriverstate>() == 0x2e0);
    assert!(core::mem::offset_of!(ObpSilodriverstate, system_device_map) == 0x0);
    assert!(core::mem::offset_of!(ObpSilodriverstate, system_dos_device_state) == 0x8);
    assert!(core::mem::offset_of!(ObpSilodriverstate, device_map_lock) == 0x78);
    assert!(core::mem::offset_of!(ObpSilodriverstate, private_namespace_lookup_table) == 0x80);
};

/// `_OBP_SYSTEM_DOS_DEVICE_STATE` (0x6c bytes).
#[repr(C)]
pub struct ObpSystemDosDeviceState {
    pub global_device_map: Field<u32>,
    pub local_device_count: [Field<u32>; 26],
}

unsafe impl NtStruct for ObpSystemDosDeviceState {}

const _: () = {
    assert!(core::mem::size_of::<ObpSystemDosDeviceState>() == 0x6c);
    assert!(core::mem::offset_of!(ObpSystemDosDeviceState, global_device_map) == 0x0);
    assert!(core::mem::offset_of!(ObpSystemDosDeviceState, local_device_count) == 0x4);
};

/// `_OBJECT_NAMESPACE_LOOKUPTABLE` (0x260 bytes).
#[repr(C)]
pub struct ObjectNamespaceLookuptable {
    pub hash_buckets: [ListEntry; 37],
    pub lock: ExPushLock,
    pub number_of_private_spaces: Field<u32>,
    _pad_25c: Reserved<0x4>,
}

unsafe impl NtStruct for ObjectNamespaceLookuptable {}

const _: () = {
    assert!(core::mem::size_of::<ObjectNamespaceLookuptable>() == 0x260);
    assert!(core::mem::offset_of!(ObjectNamespaceLookuptable, hash_buckets) == 0x0);
    assert!(core::mem::offset_of!(ObjectNamespaceLookuptable, lock) == 0x250);
    assert!(core::mem::offset_of!(ObjectNamespaceLookuptable, number_of_private_spaces) == 0x258);
};

/// `_OBJECT_HEADER_CREATOR_INFO` (0x20 bytes).
#[repr(C)]
pub struct ObjectHeaderCreatorInfo {
    pub type_list: ListEntry,
    /// -> `void`
    pub creator_unique_process: Field<u64>,
    pub creator_back_trace_index: Field<u16>,
    pub reserved1: Field<u16>,
    pub reserved2: Field<u32>,
}

unsafe impl NtStruct for ObjectHeaderCreatorInfo {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeaderCreatorInfo>() == 0x20);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, type_list) == 0x0);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, creator_unique_process) == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, creator_back_trace_index) == 0x18);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, reserved1) == 0x1a);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, reserved2) == 0x1c);
};

/// `_OBJECT_HANDLE_COUNT_ENTRY` (0x10 bytes).
#[repr(C)]
pub struct ObjectHandleCountEntry {
    /// -> `_EPROCESS`
    pub process: Field<u64>,
    pub bitfield_8: Field<u32>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for ObjectHandleCountEntry {}

impl ObjectHandleCountEntry {
    /// `HandleCount`: bits 0..=23 de `bitfield_8`.
    pub const HANDLE_COUNT_SHIFT: u32 = 0;
    pub const HANDLE_COUNT_MASK: u32 = 0xffffff;
    #[inline(always)]
    pub fn handle_count(&self) -> u32 {
        self.bitfield_8.bits(0, 24) as u32
    }
    #[inline(always)]
    pub fn set_handle_count(&self, value: u32) {
        self.bitfield_8.set_bits(0, 24, value as u64)
    }
    /// `LockCount`: bits 24..=31 de `bitfield_8`.
    pub const LOCK_COUNT_SHIFT: u32 = 24;
    pub const LOCK_COUNT_MASK: u32 = 0xff000000;
    #[inline(always)]
    pub fn lock_count(&self) -> u32 {
        self.bitfield_8.bits(24, 8) as u32
    }
    #[inline(always)]
    pub fn set_lock_count(&self, value: u32) {
        self.bitfield_8.set_bits(24, 8, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ObjectHandleCountEntry>() == 0x10);
    assert!(core::mem::offset_of!(ObjectHandleCountEntry, process) == 0x0);
    assert!(core::mem::offset_of!(ObjectHandleCountEntry, bitfield_8) == 0x8);
};

/// `_OBJECT_HANDLE_COUNT_DATABASE` (0x18 bytes).
#[repr(C)]
pub struct ObjectHandleCountDatabase {
    pub count_entries: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub handle_count_entries: [ObjectHandleCountEntry; 1],
}

unsafe impl NtStruct for ObjectHandleCountDatabase {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHandleCountDatabase>() == 0x18);
    assert!(core::mem::offset_of!(ObjectHandleCountDatabase, count_entries) == 0x0);
    assert!(core::mem::offset_of!(ObjectHandleCountDatabase, handle_count_entries) == 0x8);
};

/// `_OBJECT_HEADER_HANDLE_INFO` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ObjectHeaderHandleInfoView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ObjectHeaderHandleInfo {
    /// -> `_OBJECT_HANDLE_COUNT_DATABASE`
    pub handle_count_data_base: Field<u64>,
    _pad_8: Reserved<0x8>,
}

/// Vista 1 de `_OBJECT_HEADER_HANDLE_INFO` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ObjectHeaderHandleInfoView1 {
    pub single_entry: ObjectHandleCountEntry,
}

impl core::ops::Deref for ObjectHeaderHandleInfo {
    type Target = ObjectHeaderHandleInfoView1;
    #[inline(always)]
    fn deref(&self) -> &ObjectHeaderHandleInfoView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ObjectHeaderHandleInfoView1>() }
    }
}

unsafe impl NtStruct for ObjectHeaderHandleInfo {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeaderHandleInfo>() == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderHandleInfo, handle_count_data_base) == 0x0);
    assert!(core::mem::size_of::<ObjectHeaderHandleInfoView1>() == 0x10);
    assert!(core::mem::align_of::<ObjectHeaderHandleInfoView1>() == core::mem::align_of::<ObjectHeaderHandleInfo>());
    assert!(core::mem::offset_of!(ObjectHeaderHandleInfoView1, single_entry) == 0x0);
};

/// `_OBJECT_HEADER_QUOTA_INFO` (0x20 bytes).
#[repr(C)]
pub struct ObjectHeaderQuotaInfo {
    pub paged_pool_charge: Field<u32>,
    pub non_paged_pool_charge: Field<u32>,
    pub security_descriptor_charge: Field<u32>,
    pub reserved1: Field<u32>,
    /// -> `void`
    pub security_descriptor_quota_block: Field<u64>,
    pub reserved2: Field<u64>,
}

unsafe impl NtStruct for ObjectHeaderQuotaInfo {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeaderQuotaInfo>() == 0x20);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, paged_pool_charge) == 0x0);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, non_paged_pool_charge) == 0x4);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, security_descriptor_charge) == 0x8);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, reserved1) == 0xc);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, security_descriptor_quota_block) == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, reserved2) == 0x18);
};

/// `_OBJECT_HEADER_PROCESS_INFO` (0x10 bytes).
#[repr(C)]
pub struct ObjectHeaderProcessInfo {
    /// -> `_EPROCESS`
    pub exclusive_process: Field<u64>,
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for ObjectHeaderProcessInfo {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeaderProcessInfo>() == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderProcessInfo, exclusive_process) == 0x0);
    assert!(core::mem::offset_of!(ObjectHeaderProcessInfo, reserved) == 0x8);
};

/// `_OBJECT_HEADER_AUDIT_INFO` (0x10 bytes).
#[repr(C)]
pub struct ObjectHeaderAuditInfo {
    /// -> `void`
    pub security_descriptor: Field<u64>,
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for ObjectHeaderAuditInfo {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeaderAuditInfo>() == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderAuditInfo, security_descriptor) == 0x0);
    assert!(core::mem::offset_of!(ObjectHeaderAuditInfo, reserved) == 0x8);
};

/// `_OBJECT_HEADER_EXTENDED_INFO` (0x10 bytes).
#[repr(C)]
pub struct ObjectHeaderExtendedInfo {
    /// -> `_OBJECT_FOOTER`
    pub footer: Field<u64>,
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for ObjectHeaderExtendedInfo {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeaderExtendedInfo>() == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderExtendedInfo, footer) == 0x0);
    assert!(core::mem::offset_of!(ObjectHeaderExtendedInfo, reserved) == 0x8);
};

/// `_OBJECT_HEADER_PADDING_INFO` (0x4 bytes).
#[repr(C)]
pub struct ObjectHeaderPaddingInfo {
    pub padding_amount: Field<u32>,
}

unsafe impl NtStruct for ObjectHeaderPaddingInfo {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeaderPaddingInfo>() == 0x4);
    assert!(core::mem::offset_of!(ObjectHeaderPaddingInfo, padding_amount) == 0x0);
};

/// `_OBJECT_CREATE_INFORMATION` (0x40 bytes).
#[repr(C)]
pub struct ObjectCreateInformation {
    pub attributes: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub root_directory: Field<u64>,
    pub probe_mode: Field<i8>,
    _pad_11: Reserved<0x3>,
    pub paged_pool_charge: Field<u32>,
    pub non_paged_pool_charge: Field<u32>,
    pub security_descriptor_charge: Field<u32>,
    /// -> `void`
    pub security_descriptor: Field<u64>,
    /// -> `_SECURITY_QUALITY_OF_SERVICE`
    pub security_qos: Field<u64>,
    pub security_quality_of_service: SecurityQualityOfService,
    _pad_3c: Reserved<0x4>,
}

unsafe impl NtStruct for ObjectCreateInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObjectCreateInformation>() == 0x40);
    assert!(core::mem::offset_of!(ObjectCreateInformation, attributes) == 0x0);
    assert!(core::mem::offset_of!(ObjectCreateInformation, root_directory) == 0x8);
    assert!(core::mem::offset_of!(ObjectCreateInformation, probe_mode) == 0x10);
    assert!(core::mem::offset_of!(ObjectCreateInformation, paged_pool_charge) == 0x14);
    assert!(core::mem::offset_of!(ObjectCreateInformation, non_paged_pool_charge) == 0x18);
    assert!(core::mem::offset_of!(ObjectCreateInformation, security_descriptor_charge) == 0x1c);
    assert!(core::mem::offset_of!(ObjectCreateInformation, security_descriptor) == 0x20);
    assert!(core::mem::offset_of!(ObjectCreateInformation, security_qos) == 0x28);
    assert!(core::mem::offset_of!(ObjectCreateInformation, security_quality_of_service) == 0x30);
};
