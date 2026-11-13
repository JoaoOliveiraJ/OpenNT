//! Ex: recursos, push locks, rundown, work items e lookasides.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_FAST_MUTEX` (0x38 bytes).
#[repr(C)]
pub struct FastMutex {
    pub count: Field<i32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub owner: Field<u64>,
    pub contention: Field<u32>,
    _pad_14: Reserved<0x4>,
    pub event: Kevent,
    pub old_irql: Field<u32>,
    _pad_34: Reserved<0x4>,
}

unsafe impl NtStruct for FastMutex {}

const _: () = {
    assert!(core::mem::size_of::<FastMutex>() == 0x38);
    assert!(core::mem::offset_of!(FastMutex, count) == 0x0);
    assert!(core::mem::offset_of!(FastMutex, owner) == 0x8);
    assert!(core::mem::offset_of!(FastMutex, contention) == 0x10);
    assert!(core::mem::offset_of!(FastMutex, event) == 0x18);
    assert!(core::mem::offset_of!(FastMutex, old_irql) == 0x30);
};

/// `_WORK_QUEUE_ITEM` (0x20 bytes).
#[repr(C)]
pub struct WorkQueueItem {
    pub list: ListEntry,
    /// -> `fn`
    pub worker_routine: Field<u64>,
    /// -> `void`
    pub parameter: Field<u64>,
}

unsafe impl NtStruct for WorkQueueItem {}

const _: () = {
    assert!(core::mem::size_of::<WorkQueueItem>() == 0x20);
    assert!(core::mem::offset_of!(WorkQueueItem, list) == 0x0);
    assert!(core::mem::offset_of!(WorkQueueItem, worker_routine) == 0x10);
    assert!(core::mem::offset_of!(WorkQueueItem, parameter) == 0x18);
};

/// `_GENERAL_LOOKASIDE` (0x80 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `GeneralLookasideView1`, alcançada por `Deref`.
#[repr(C)]
pub struct GeneralLookaside {
    pub list_head: SlistHeader,
    pub depth: Field<u16>,
    pub maximum_depth: Field<u16>,
    pub total_allocates: Field<u32>,
    pub allocate_misses: Field<u32>,
    pub total_frees: Field<u32>,
    pub free_misses: Field<u32>,
    pub type_: Field<PoolType>,
    pub tag: Field<u32>,
    pub size: Field<u32>,
    /// -> `fn`
    pub allocate_ex: Field<u64>,
    /// -> `fn`
    pub free_ex: Field<u64>,
    pub list_entry: ListEntry,
    pub last_total_allocates: Field<u32>,
    pub last_allocate_misses: Field<u32>,
    pub future: [Field<u32>; 2],
    _pad_60: Reserved<0x20>,
}

/// Vista 1 de `_GENERAL_LOOKASIDE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct GeneralLookasideView1 {
    pub single_list_head: SingleListEntry,
    _pad_8: Reserved<0x10>,
    pub allocate_hits: Field<u32>,
    _pad_1c: Reserved<0x4>,
    pub free_hits: Field<u32>,
    _pad_24: Reserved<0xc>,
    /// -> `fn`
    pub allocate: Field<u64>,
    /// -> `fn`
    pub free: Field<u64>,
    _pad_40: Reserved<0x14>,
    pub last_allocate_hits: Field<u32>,
    _pad_58: Reserved<0x28>,
}

impl core::ops::Deref for GeneralLookaside {
    type Target = GeneralLookasideView1;
    #[inline(always)]
    fn deref(&self) -> &GeneralLookasideView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<GeneralLookasideView1>() }
    }
}

unsafe impl NtStruct for GeneralLookaside {}

const _: () = {
    assert!(core::mem::size_of::<GeneralLookaside>() == 0x80);
    assert!(core::mem::offset_of!(GeneralLookaside, list_head) == 0x0);
    assert!(core::mem::offset_of!(GeneralLookaside, depth) == 0x10);
    assert!(core::mem::offset_of!(GeneralLookaside, maximum_depth) == 0x12);
    assert!(core::mem::offset_of!(GeneralLookaside, total_allocates) == 0x14);
    assert!(core::mem::offset_of!(GeneralLookaside, allocate_misses) == 0x18);
    assert!(core::mem::offset_of!(GeneralLookaside, total_frees) == 0x1c);
    assert!(core::mem::offset_of!(GeneralLookaside, free_misses) == 0x20);
    assert!(core::mem::offset_of!(GeneralLookaside, type_) == 0x24);
    assert!(core::mem::offset_of!(GeneralLookaside, tag) == 0x28);
    assert!(core::mem::offset_of!(GeneralLookaside, size) == 0x2c);
    assert!(core::mem::offset_of!(GeneralLookaside, allocate_ex) == 0x30);
    assert!(core::mem::offset_of!(GeneralLookaside, free_ex) == 0x38);
    assert!(core::mem::offset_of!(GeneralLookaside, list_entry) == 0x40);
    assert!(core::mem::offset_of!(GeneralLookaside, last_total_allocates) == 0x50);
    assert!(core::mem::offset_of!(GeneralLookaside, last_allocate_misses) == 0x54);
    assert!(core::mem::offset_of!(GeneralLookaside, future) == 0x58);
    assert!(core::mem::size_of::<GeneralLookasideView1>() == 0x80);
    assert!(core::mem::align_of::<GeneralLookasideView1>() == core::mem::align_of::<GeneralLookaside>());
    assert!(core::mem::offset_of!(GeneralLookasideView1, single_list_head) == 0x0);
    assert!(core::mem::offset_of!(GeneralLookasideView1, allocate_hits) == 0x18);
    assert!(core::mem::offset_of!(GeneralLookasideView1, free_hits) == 0x20);
    assert!(core::mem::offset_of!(GeneralLookasideView1, allocate) == 0x30);
    assert!(core::mem::offset_of!(GeneralLookasideView1, free) == 0x38);
    assert!(core::mem::offset_of!(GeneralLookasideView1, last_allocate_hits) == 0x54);
};

/// `_POOL_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct PoolType(pub i32);

impl PoolType {
    pub const NON_PAGED_POOL: Self = Self(0);
    pub const NON_PAGED_POOL_EXECUTE: Self = Self(0);
    pub const PAGED_POOL: Self = Self(1);
    pub const NON_PAGED_POOL_MUST_SUCCEED: Self = Self(2);
    pub const DONT_USE_THIS_TYPE: Self = Self(3);
    pub const NON_PAGED_POOL_CACHE_ALIGNED: Self = Self(4);
    pub const PAGED_POOL_CACHE_ALIGNED: Self = Self(5);
    pub const NON_PAGED_POOL_CACHE_ALIGNED_MUST_S: Self = Self(6);
    pub const MAX_POOL_TYPE: Self = Self(7);
    pub const NON_PAGED_POOL_BASE: Self = Self(0);
    pub const NON_PAGED_POOL_BASE_MUST_SUCCEED: Self = Self(2);
    pub const NON_PAGED_POOL_BASE_CACHE_ALIGNED: Self = Self(4);
    pub const NON_PAGED_POOL_BASE_CACHE_ALIGNED_MUST_S: Self = Self(6);
    pub const NON_PAGED_POOL_SESSION: Self = Self(32);
    pub const PAGED_POOL_SESSION: Self = Self(33);
    pub const NON_PAGED_POOL_MUST_SUCCEED_SESSION: Self = Self(34);
    pub const DONT_USE_THIS_TYPE_SESSION: Self = Self(35);
    pub const NON_PAGED_POOL_CACHE_ALIGNED_SESSION: Self = Self(36);
    pub const PAGED_POOL_CACHE_ALIGNED_SESSION: Self = Self(37);
    pub const NON_PAGED_POOL_CACHE_ALIGNED_MUST_S_SESSION: Self = Self(38);
    pub const NON_PAGED_POOL_NX: Self = Self(512);
    pub const NON_PAGED_POOL_NX_CACHE_ALIGNED: Self = Self(516);
    pub const NON_PAGED_POOL_SESSION_NX: Self = Self(544);
}

/// `_EX_RUNDOWN_REF` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ExRundownRefView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ExRundownRef {
    pub count: Field<u64>,
}

/// Vista 1 de `_EX_RUNDOWN_REF` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ExRundownRefView1 {
    /// -> `void`
    pub ptr: Field<u64>,
}

impl core::ops::Deref for ExRundownRef {
    type Target = ExRundownRefView1;
    #[inline(always)]
    fn deref(&self) -> &ExRundownRefView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ExRundownRefView1>() }
    }
}

unsafe impl NtStruct for ExRundownRef {}

const _: () = {
    assert!(core::mem::size_of::<ExRundownRef>() == 0x8);
    assert!(core::mem::offset_of!(ExRundownRef, count) == 0x0);
    assert!(core::mem::size_of::<ExRundownRefView1>() == 0x8);
    assert!(core::mem::align_of::<ExRundownRefView1>() == core::mem::align_of::<ExRundownRef>());
    assert!(core::mem::offset_of!(ExRundownRefView1, ptr) == 0x0);
};

/// `_EX_PUSH_LOCK` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ExPushLockView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ExPushLock {
    pub value: Field<u64>,
}

/// Vista 1 de `_EX_PUSH_LOCK` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ExPushLockView1 {
    /// -> `void`
    pub ptr: Field<u64>,
}

impl core::ops::Deref for ExPushLock {
    type Target = ExPushLockView1;
    #[inline(always)]
    fn deref(&self) -> &ExPushLockView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ExPushLockView1>() }
    }
}

unsafe impl NtStruct for ExPushLock {}

impl ExPushLock {
    /// `Locked`: bits 0..=0 de `value`.
    pub const LOCKED_SHIFT: u32 = 0;
    pub const LOCKED_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn locked(&self) -> u64 {
        self.value.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_locked(&self, value: u64) {
        self.value.set_bits(0, 1, value as u64)
    }
    /// `Waiting`: bits 1..=1 de `value`.
    pub const WAITING_SHIFT: u32 = 1;
    pub const WAITING_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn waiting(&self) -> u64 {
        self.value.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_waiting(&self, value: u64) {
        self.value.set_bits(1, 1, value as u64)
    }
    /// `Waking`: bits 2..=2 de `value`.
    pub const WAKING_SHIFT: u32 = 2;
    pub const WAKING_MASK: u64 = 0x4;
    #[inline(always)]
    pub fn waking(&self) -> u64 {
        self.value.bits(2, 1) as u64
    }
    #[inline(always)]
    pub fn set_waking(&self, value: u64) {
        self.value.set_bits(2, 1, value as u64)
    }
    /// `MultipleShared`: bits 3..=3 de `value`.
    pub const MULTIPLE_SHARED_SHIFT: u32 = 3;
    pub const MULTIPLE_SHARED_MASK: u64 = 0x8;
    #[inline(always)]
    pub fn multiple_shared(&self) -> u64 {
        self.value.bits(3, 1) as u64
    }
    #[inline(always)]
    pub fn set_multiple_shared(&self, value: u64) {
        self.value.set_bits(3, 1, value as u64)
    }
    /// `Shared`: bits 4..=63 de `value`.
    pub const SHARED_SHIFT: u32 = 4;
    pub const SHARED_MASK: u64 = 0xfffffffffffffff0;
    #[inline(always)]
    pub fn shared(&self) -> u64 {
        self.value.bits(4, 60) as u64
    }
    #[inline(always)]
    pub fn set_shared(&self, value: u64) {
        self.value.set_bits(4, 60, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ExPushLock>() == 0x8);
    assert!(core::mem::offset_of!(ExPushLock, value) == 0x0);
    assert!(core::mem::size_of::<ExPushLockView1>() == 0x8);
    assert!(core::mem::align_of::<ExPushLockView1>() == core::mem::align_of::<ExPushLock>());
    assert!(core::mem::offset_of!(ExPushLockView1, ptr) == 0x0);
};

/// `_EX_FAST_REF` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ExFastRefView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ExFastRef {
    /// -> `void`
    pub object: Field<u64>,
}

/// Vista 1 de `_EX_FAST_REF` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ExFastRefView1 {
    pub value: Field<u64>,
}

impl core::ops::Deref for ExFastRef {
    type Target = ExFastRefView1;
    #[inline(always)]
    fn deref(&self) -> &ExFastRefView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ExFastRefView1>() }
    }
}

unsafe impl NtStruct for ExFastRef {}

impl ExFastRef {
    /// `RefCnt`: bits 0..=3 de `value`.
    pub const REF_CNT_SHIFT: u32 = 0;
    pub const REF_CNT_MASK: u64 = 0xf;
    #[inline(always)]
    pub fn ref_cnt(&self) -> u64 {
        self.value.bits(0, 4) as u64
    }
    #[inline(always)]
    pub fn set_ref_cnt(&self, value: u64) {
        self.value.set_bits(0, 4, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ExFastRef>() == 0x8);
    assert!(core::mem::offset_of!(ExFastRef, object) == 0x0);
    assert!(core::mem::size_of::<ExFastRefView1>() == 0x8);
    assert!(core::mem::align_of::<ExFastRefView1>() == core::mem::align_of::<ExFastRef>());
    assert!(core::mem::offset_of!(ExFastRefView1, value) == 0x0);
};

/// `_WNF_STATE_NAME` (0x8 bytes).
#[repr(C)]
pub struct WnfStateName {
    pub data: [Field<u32>; 2],
}

unsafe impl NtStruct for WnfStateName {}

const _: () = {
    assert!(core::mem::size_of::<WnfStateName>() == 0x8);
    assert!(core::mem::offset_of!(WnfStateName, data) == 0x0);
};

/// `_ERESOURCE` (0x68 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `EresourceView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Eresource {
    pub system_resources_list: ListEntry,
    /// -> `_OWNER_ENTRY`
    pub owner_table: Field<u64>,
    pub active_count: Field<i16>,
    pub flag: Field<u16>,
    _pad_1c: Reserved<0x4>,
    /// -> `void`
    pub shared_waiters: Field<u64>,
    /// -> `void`
    pub exclusive_waiters: Field<u64>,
    pub owner_entry: OwnerEntry,
    pub active_entries: Field<u32>,
    pub contention_count: Field<u32>,
    pub number_of_shared_waiters: Field<u32>,
    pub number_of_exclusive_waiters: Field<u32>,
    /// -> `void`
    pub reserved2: Field<u64>,
    /// -> `void`
    pub address: Field<u64>,
    pub spin_lock: Field<u64>,
}

/// Vista 1 de `_ERESOURCE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EresourceView1 {
    _pad_0: Reserved<0x1a>,
    pub reserved_low_flags: Field<u8>,
    pub waiter_priority: Field<u8>,
    _pad_1c: Reserved<0x3c>,
    pub creator_back_trace_index: Field<u64>,
    _pad_60: Reserved<0x8>,
}

impl core::ops::Deref for Eresource {
    type Target = EresourceView1;
    #[inline(always)]
    fn deref(&self) -> &EresourceView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EresourceView1>() }
    }
}

unsafe impl NtStruct for Eresource {}

const _: () = {
    assert!(core::mem::size_of::<Eresource>() == 0x68);
    assert!(core::mem::offset_of!(Eresource, system_resources_list) == 0x0);
    assert!(core::mem::offset_of!(Eresource, owner_table) == 0x10);
    assert!(core::mem::offset_of!(Eresource, active_count) == 0x18);
    assert!(core::mem::offset_of!(Eresource, flag) == 0x1a);
    assert!(core::mem::offset_of!(Eresource, shared_waiters) == 0x20);
    assert!(core::mem::offset_of!(Eresource, exclusive_waiters) == 0x28);
    assert!(core::mem::offset_of!(Eresource, owner_entry) == 0x30);
    assert!(core::mem::offset_of!(Eresource, active_entries) == 0x40);
    assert!(core::mem::offset_of!(Eresource, contention_count) == 0x44);
    assert!(core::mem::offset_of!(Eresource, number_of_shared_waiters) == 0x48);
    assert!(core::mem::offset_of!(Eresource, number_of_exclusive_waiters) == 0x4c);
    assert!(core::mem::offset_of!(Eresource, reserved2) == 0x50);
    assert!(core::mem::offset_of!(Eresource, address) == 0x58);
    assert!(core::mem::offset_of!(Eresource, spin_lock) == 0x60);
    assert!(core::mem::size_of::<EresourceView1>() == 0x68);
    assert!(core::mem::align_of::<EresourceView1>() == core::mem::align_of::<Eresource>());
    assert!(core::mem::offset_of!(EresourceView1, reserved_low_flags) == 0x1a);
    assert!(core::mem::offset_of!(EresourceView1, waiter_priority) == 0x1b);
    assert!(core::mem::offset_of!(EresourceView1, creator_back_trace_index) == 0x58);
};

/// `_OWNER_ENTRY` (0x10 bytes).
#[repr(C)]
pub struct OwnerEntry {
    pub owner_thread: Field<u64>,
    pub table_size: Field<u32>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for OwnerEntry {}

impl OwnerEntry {
    /// `IoPriorityBoosted`: bits 0..=0 de `table_size`.
    pub const IO_PRIORITY_BOOSTED_SHIFT: u32 = 0;
    pub const IO_PRIORITY_BOOSTED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn io_priority_boosted(&self) -> u32 {
        self.table_size.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_io_priority_boosted(&self, value: u32) {
        self.table_size.set_bits(0, 1, value as u64)
    }
    /// `OwnerReferenced`: bits 1..=1 de `table_size`.
    pub const OWNER_REFERENCED_SHIFT: u32 = 1;
    pub const OWNER_REFERENCED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn owner_referenced(&self) -> u32 {
        self.table_size.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_owner_referenced(&self, value: u32) {
        self.table_size.set_bits(1, 1, value as u64)
    }
    /// `IoQoSPriorityBoosted`: bits 2..=2 de `table_size`.
    pub const IO_QO_S_PRIORITY_BOOSTED_SHIFT: u32 = 2;
    pub const IO_QO_S_PRIORITY_BOOSTED_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn io_qo_s_priority_boosted(&self) -> u32 {
        self.table_size.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_io_qo_s_priority_boosted(&self, value: u32) {
        self.table_size.set_bits(2, 1, value as u64)
    }
    /// `OwnerCount`: bits 3..=31 de `table_size`.
    pub const OWNER_COUNT_SHIFT: u32 = 3;
    pub const OWNER_COUNT_MASK: u32 = 0xfffffff8;
    #[inline(always)]
    pub fn owner_count(&self) -> u32 {
        self.table_size.bits(3, 29) as u32
    }
    #[inline(always)]
    pub fn set_owner_count(&self, value: u32) {
        self.table_size.set_bits(3, 29, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<OwnerEntry>() == 0x10);
    assert!(core::mem::offset_of!(OwnerEntry, owner_thread) == 0x0);
    assert!(core::mem::offset_of!(OwnerEntry, table_size) == 0x8);
};

/// `_PP_LOOKASIDE_LIST` (0x10 bytes).
#[repr(C)]
pub struct PpLookasideList {
    /// -> `_GENERAL_LOOKASIDE`
    pub p: Field<u64>,
    /// -> `_GENERAL_LOOKASIDE`
    pub l: Field<u64>,
}

unsafe impl NtStruct for PpLookasideList {}

const _: () = {
    assert!(core::mem::size_of::<PpLookasideList>() == 0x10);
    assert!(core::mem::offset_of!(PpLookasideList, p) == 0x0);
    assert!(core::mem::offset_of!(PpLookasideList, l) == 0x8);
};

/// `_GENERAL_LOOKASIDE_POOL` (0x60 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `GeneralLookasidePoolView1`, alcançada por `Deref`.
#[repr(C)]
pub struct GeneralLookasidePool {
    pub list_head: SlistHeader,
    pub depth: Field<u16>,
    pub maximum_depth: Field<u16>,
    pub total_allocates: Field<u32>,
    pub allocate_misses: Field<u32>,
    pub total_frees: Field<u32>,
    pub free_misses: Field<u32>,
    pub type_: Field<PoolType>,
    pub tag: Field<u32>,
    pub size: Field<u32>,
    /// -> `fn`
    pub allocate_ex: Field<u64>,
    /// -> `fn`
    pub free_ex: Field<u64>,
    pub list_entry: ListEntry,
    pub last_total_allocates: Field<u32>,
    pub last_allocate_misses: Field<u32>,
    pub future: [Field<u32>; 2],
}

/// Vista 1 de `_GENERAL_LOOKASIDE_POOL` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct GeneralLookasidePoolView1 {
    pub single_list_head: SingleListEntry,
    _pad_8: Reserved<0x10>,
    pub allocate_hits: Field<u32>,
    _pad_1c: Reserved<0x4>,
    pub free_hits: Field<u32>,
    _pad_24: Reserved<0xc>,
    /// -> `fn`
    pub allocate: Field<u64>,
    /// -> `fn`
    pub free: Field<u64>,
    _pad_40: Reserved<0x14>,
    pub last_allocate_hits: Field<u32>,
    _pad_58: Reserved<0x8>,
}

impl core::ops::Deref for GeneralLookasidePool {
    type Target = GeneralLookasidePoolView1;
    #[inline(always)]
    fn deref(&self) -> &GeneralLookasidePoolView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<GeneralLookasidePoolView1>() }
    }
}

unsafe impl NtStruct for GeneralLookasidePool {}

const _: () = {
    assert!(core::mem::size_of::<GeneralLookasidePool>() == 0x60);
    assert!(core::mem::offset_of!(GeneralLookasidePool, list_head) == 0x0);
    assert!(core::mem::offset_of!(GeneralLookasidePool, depth) == 0x10);
    assert!(core::mem::offset_of!(GeneralLookasidePool, maximum_depth) == 0x12);
    assert!(core::mem::offset_of!(GeneralLookasidePool, total_allocates) == 0x14);
    assert!(core::mem::offset_of!(GeneralLookasidePool, allocate_misses) == 0x18);
    assert!(core::mem::offset_of!(GeneralLookasidePool, total_frees) == 0x1c);
    assert!(core::mem::offset_of!(GeneralLookasidePool, free_misses) == 0x20);
    assert!(core::mem::offset_of!(GeneralLookasidePool, type_) == 0x24);
    assert!(core::mem::offset_of!(GeneralLookasidePool, tag) == 0x28);
    assert!(core::mem::offset_of!(GeneralLookasidePool, size) == 0x2c);
    assert!(core::mem::offset_of!(GeneralLookasidePool, allocate_ex) == 0x30);
    assert!(core::mem::offset_of!(GeneralLookasidePool, free_ex) == 0x38);
    assert!(core::mem::offset_of!(GeneralLookasidePool, list_entry) == 0x40);
    assert!(core::mem::offset_of!(GeneralLookasidePool, last_total_allocates) == 0x50);
    assert!(core::mem::offset_of!(GeneralLookasidePool, last_allocate_misses) == 0x54);
    assert!(core::mem::offset_of!(GeneralLookasidePool, future) == 0x58);
    assert!(core::mem::size_of::<GeneralLookasidePoolView1>() == 0x60);
    assert!(core::mem::align_of::<GeneralLookasidePoolView1>() == core::mem::align_of::<GeneralLookasidePool>());
    assert!(core::mem::offset_of!(GeneralLookasidePoolView1, single_list_head) == 0x0);
    assert!(core::mem::offset_of!(GeneralLookasidePoolView1, allocate_hits) == 0x18);
    assert!(core::mem::offset_of!(GeneralLookasidePoolView1, free_hits) == 0x20);
    assert!(core::mem::offset_of!(GeneralLookasidePoolView1, allocate) == 0x30);
    assert!(core::mem::offset_of!(GeneralLookasidePoolView1, free) == 0x38);
    assert!(core::mem::offset_of!(GeneralLookasidePoolView1, last_allocate_hits) == 0x54);
};

/// `_NPAGED_LOOKASIDE_LIST` (0x80 bytes).
#[repr(C)]
pub struct NpagedLookasideList {
    pub l: GeneralLookaside,
}

unsafe impl NtStruct for NpagedLookasideList {}

const _: () = {
    assert!(core::mem::size_of::<NpagedLookasideList>() == 0x80);
    assert!(core::mem::offset_of!(NpagedLookasideList, l) == 0x0);
};

/// `_PAGED_LOOKASIDE_LIST` (0x80 bytes).
#[repr(C)]
pub struct PagedLookasideList {
    pub l: GeneralLookaside,
}

unsafe impl NtStruct for PagedLookasideList {}

const _: () = {
    assert!(core::mem::size_of::<PagedLookasideList>() == 0x80);
    assert!(core::mem::offset_of!(PagedLookasideList, l) == 0x0);
};

/// `_LOOKASIDE_LIST_EX` (0x60 bytes).
#[repr(C)]
pub struct LookasideListEx {
    pub l: GeneralLookasidePool,
}

unsafe impl NtStruct for LookasideListEx {}

const _: () = {
    assert!(core::mem::size_of::<LookasideListEx>() == 0x60);
    assert!(core::mem::offset_of!(LookasideListEx, l) == 0x0);
};

/// `_EXHANDLE` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ExhandleView1`..`ExhandleView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct Exhandle {
    _align: [u64; 0],
    pub bitfield_0: Field<u32>,
    _pad_4: Reserved<0x4>,
}

/// Vista 1 de `_EXHANDLE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ExhandleView1 {
    /// -> `void`
    pub generic_handle_overlay: Field<u64>,
}

/// Vista 2 de `_EXHANDLE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ExhandleView2 {
    pub value: Field<u64>,
}

impl core::ops::Deref for Exhandle {
    type Target = ExhandleView1;
    #[inline(always)]
    fn deref(&self) -> &ExhandleView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ExhandleView1>() }
    }
}

impl core::ops::Deref for ExhandleView1 {
    type Target = ExhandleView2;
    #[inline(always)]
    fn deref(&self) -> &ExhandleView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ExhandleView2>() }
    }
}

unsafe impl NtStruct for Exhandle {}

impl Exhandle {
    /// `TagBits`: bits 0..=1 de `bitfield_0`.
    pub const TAG_BITS_SHIFT: u32 = 0;
    pub const TAG_BITS_MASK: u32 = 0x3;
    #[inline(always)]
    pub fn tag_bits(&self) -> u32 {
        self.bitfield_0.bits(0, 2) as u32
    }
    #[inline(always)]
    pub fn set_tag_bits(&self, value: u32) {
        self.bitfield_0.set_bits(0, 2, value as u64)
    }
    /// `Index`: bits 2..=31 de `bitfield_0`.
    pub const INDEX_SHIFT: u32 = 2;
    pub const INDEX_MASK: u32 = 0xfffffffc;
    #[inline(always)]
    pub fn index(&self) -> u32 {
        self.bitfield_0.bits(2, 30) as u32
    }
    #[inline(always)]
    pub fn set_index(&self, value: u32) {
        self.bitfield_0.set_bits(2, 30, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Exhandle>() == 0x8);
    assert!(core::mem::offset_of!(Exhandle, bitfield_0) == 0x0);
    assert!(core::mem::size_of::<ExhandleView1>() == 0x8);
    assert!(core::mem::align_of::<ExhandleView1>() == core::mem::align_of::<Exhandle>());
    assert!(core::mem::offset_of!(ExhandleView1, generic_handle_overlay) == 0x0);
    assert!(core::mem::size_of::<ExhandleView2>() == 0x8);
    assert!(core::mem::align_of::<ExhandleView2>() == core::mem::align_of::<Exhandle>());
    assert!(core::mem::offset_of!(ExhandleView2, value) == 0x0);
};

/// `_WNF_NAME_INSTANCE` (0xa8 bytes).
#[repr(C)]
pub struct WnfNameInstance {
    pub header: WnfNodeHeader,
    _pad_4: Reserved<0x4>,
    pub run_ref: ExRundownRef,
    pub tree_links: RtlBalancedNode,
    pub state_name: WnfStateNameStruct,
    /// -> `_WNF_SCOPE_INSTANCE`
    pub scope_instance: Field<u64>,
    pub state_name_info: WnfStateNameRegistration,
    pub state_data_lock: WnfLock,
    /// -> `_WNF_STATE_DATA`
    pub state_data: Field<u64>,
    pub current_change_stamp: Field<u32>,
    _pad_64: Reserved<0x4>,
    /// -> `void`
    pub permanent_data_store: Field<u64>,
    pub state_subscription_list_lock: WnfLock,
    pub state_subscription_list_head: ListEntry,
    pub temporary_name_list_entry: ListEntry,
    /// -> `_EPROCESS`
    pub creator_process: Field<u64>,
    pub data_subscribers_count: Field<i32>,
    pub current_delivery_count: Field<i32>,
}

unsafe impl NtStruct for WnfNameInstance {}

const _: () = {
    assert!(core::mem::size_of::<WnfNameInstance>() == 0xa8);
    assert!(core::mem::offset_of!(WnfNameInstance, header) == 0x0);
    assert!(core::mem::offset_of!(WnfNameInstance, run_ref) == 0x8);
    assert!(core::mem::offset_of!(WnfNameInstance, tree_links) == 0x10);
    assert!(core::mem::offset_of!(WnfNameInstance, state_name) == 0x28);
    assert!(core::mem::offset_of!(WnfNameInstance, scope_instance) == 0x30);
    assert!(core::mem::offset_of!(WnfNameInstance, state_name_info) == 0x38);
    assert!(core::mem::offset_of!(WnfNameInstance, state_data_lock) == 0x50);
    assert!(core::mem::offset_of!(WnfNameInstance, state_data) == 0x58);
    assert!(core::mem::offset_of!(WnfNameInstance, current_change_stamp) == 0x60);
    assert!(core::mem::offset_of!(WnfNameInstance, permanent_data_store) == 0x68);
    assert!(core::mem::offset_of!(WnfNameInstance, state_subscription_list_lock) == 0x70);
    assert!(core::mem::offset_of!(WnfNameInstance, state_subscription_list_head) == 0x78);
    assert!(core::mem::offset_of!(WnfNameInstance, temporary_name_list_entry) == 0x88);
    assert!(core::mem::offset_of!(WnfNameInstance, creator_process) == 0x98);
    assert!(core::mem::offset_of!(WnfNameInstance, data_subscribers_count) == 0xa0);
    assert!(core::mem::offset_of!(WnfNameInstance, current_delivery_count) == 0xa4);
};

/// `_WNF_NODE_HEADER` (0x4 bytes).
#[repr(C)]
pub struct WnfNodeHeader {
    pub node_type_code: Field<u16>,
    pub node_byte_size: Field<u16>,
}

unsafe impl NtStruct for WnfNodeHeader {}

const _: () = {
    assert!(core::mem::size_of::<WnfNodeHeader>() == 0x4);
    assert!(core::mem::offset_of!(WnfNodeHeader, node_type_code) == 0x0);
    assert!(core::mem::offset_of!(WnfNodeHeader, node_byte_size) == 0x2);
};

/// `_WNF_STATE_NAME_STRUCT` (0x8 bytes).
#[repr(C)]
pub struct WnfStateNameStruct {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for WnfStateNameStruct {}

impl WnfStateNameStruct {
    /// `Version`: bits 0..=3 de `bitfield_0`.
    pub const VERSION_SHIFT: u32 = 0;
    pub const VERSION_MASK: u64 = 0xf;
    #[inline(always)]
    pub fn version(&self) -> u64 {
        self.bitfield_0.bits(0, 4) as u64
    }
    #[inline(always)]
    pub fn set_version(&self, value: u64) {
        self.bitfield_0.set_bits(0, 4, value as u64)
    }
    /// `NameLifetime`: bits 4..=5 de `bitfield_0`.
    pub const NAME_LIFETIME_SHIFT: u32 = 4;
    pub const NAME_LIFETIME_MASK: u64 = 0x30;
    #[inline(always)]
    pub fn name_lifetime(&self) -> u64 {
        self.bitfield_0.bits(4, 2) as u64
    }
    #[inline(always)]
    pub fn set_name_lifetime(&self, value: u64) {
        self.bitfield_0.set_bits(4, 2, value as u64)
    }
    /// `DataScope`: bits 6..=9 de `bitfield_0`.
    pub const DATA_SCOPE_SHIFT: u32 = 6;
    pub const DATA_SCOPE_MASK: u64 = 0x3c0;
    #[inline(always)]
    pub fn data_scope(&self) -> u64 {
        self.bitfield_0.bits(6, 4) as u64
    }
    #[inline(always)]
    pub fn set_data_scope(&self, value: u64) {
        self.bitfield_0.set_bits(6, 4, value as u64)
    }
    /// `PermanentData`: bits 10..=10 de `bitfield_0`.
    pub const PERMANENT_DATA_SHIFT: u32 = 10;
    pub const PERMANENT_DATA_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn permanent_data(&self) -> u64 {
        self.bitfield_0.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_permanent_data(&self, value: u64) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `Sequence`: bits 11..=63 de `bitfield_0`.
    pub const SEQUENCE_SHIFT: u32 = 11;
    pub const SEQUENCE_MASK: u64 = 0xfffffffffffff800;
    #[inline(always)]
    pub fn sequence(&self) -> u64 {
        self.bitfield_0.bits(11, 53) as u64
    }
    #[inline(always)]
    pub fn set_sequence(&self, value: u64) {
        self.bitfield_0.set_bits(11, 53, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WnfStateNameStruct>() == 0x8);
    assert!(core::mem::offset_of!(WnfStateNameStruct, bitfield_0) == 0x0);
};

/// `_WNF_STATE_NAME_REGISTRATION` (0x18 bytes).
#[repr(C)]
pub struct WnfStateNameRegistration {
    pub max_state_size: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `_WNF_TYPE_ID`
    pub type_id: Field<u64>,
    /// -> `_SECURITY_DESCRIPTOR`
    pub security_descriptor: Field<u64>,
}

unsafe impl NtStruct for WnfStateNameRegistration {}

const _: () = {
    assert!(core::mem::size_of::<WnfStateNameRegistration>() == 0x18);
    assert!(core::mem::offset_of!(WnfStateNameRegistration, max_state_size) == 0x0);
    assert!(core::mem::offset_of!(WnfStateNameRegistration, type_id) == 0x8);
    assert!(core::mem::offset_of!(WnfStateNameRegistration, security_descriptor) == 0x10);
};

/// `_WNF_LOCK` (0x8 bytes).
#[repr(C)]
pub struct WnfLock {
    pub push_lock: ExPushLock,
}

unsafe impl NtStruct for WnfLock {}

const _: () = {
    assert!(core::mem::size_of::<WnfLock>() == 0x8);
    assert!(core::mem::offset_of!(WnfLock, push_lock) == 0x0);
};

/// `_WNF_SUBSCRIPTION` (0x88 bytes).
#[repr(C)]
pub struct WnfSubscription {
    pub header: WnfNodeHeader,
    _pad_4: Reserved<0x4>,
    pub run_ref: ExRundownRef,
    pub subscription_id: Field<u64>,
    pub process_subscription_list_entry: ListEntry,
    /// -> `_EPROCESS`
    pub process: Field<u64>,
    /// -> `_WNF_NAME_INSTANCE`
    pub name_instance: Field<u64>,
    pub state_name: WnfStateNameStruct,
    pub state_subscription_list_entry: ListEntry,
    pub callback_routine: Field<u64>,
    /// -> `void`
    pub callback_context: Field<u64>,
    pub current_change_stamp: Field<u32>,
    pub subscribed_event_set: Field<u32>,
    pub pending_subscription_list_entry: ListEntry,
    pub subscription_state: Field<WnfSubscriptionState>,
    pub signaled_event_set: Field<u32>,
    pub in_delivery_event_set: Field<u32>,
    _pad_84: Reserved<0x4>,
}

unsafe impl NtStruct for WnfSubscription {}

const _: () = {
    assert!(core::mem::size_of::<WnfSubscription>() == 0x88);
    assert!(core::mem::offset_of!(WnfSubscription, header) == 0x0);
    assert!(core::mem::offset_of!(WnfSubscription, run_ref) == 0x8);
    assert!(core::mem::offset_of!(WnfSubscription, subscription_id) == 0x10);
    assert!(core::mem::offset_of!(WnfSubscription, process_subscription_list_entry) == 0x18);
    assert!(core::mem::offset_of!(WnfSubscription, process) == 0x28);
    assert!(core::mem::offset_of!(WnfSubscription, name_instance) == 0x30);
    assert!(core::mem::offset_of!(WnfSubscription, state_name) == 0x38);
    assert!(core::mem::offset_of!(WnfSubscription, state_subscription_list_entry) == 0x40);
    assert!(core::mem::offset_of!(WnfSubscription, callback_routine) == 0x50);
    assert!(core::mem::offset_of!(WnfSubscription, callback_context) == 0x58);
    assert!(core::mem::offset_of!(WnfSubscription, current_change_stamp) == 0x60);
    assert!(core::mem::offset_of!(WnfSubscription, subscribed_event_set) == 0x64);
    assert!(core::mem::offset_of!(WnfSubscription, pending_subscription_list_entry) == 0x68);
    assert!(core::mem::offset_of!(WnfSubscription, subscription_state) == 0x78);
    assert!(core::mem::offset_of!(WnfSubscription, signaled_event_set) == 0x7c);
    assert!(core::mem::offset_of!(WnfSubscription, in_delivery_event_set) == 0x80);
};

/// `_WNF_SUBSCRIPTION_STATE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct WnfSubscriptionState(pub i32);

impl WnfSubscriptionState {
    pub const WNF_SUB_STATE_QUIESCENT: Self = Self(0);
    pub const WNF_SUB_STATE_READY_TO_DELIVER: Self = Self(1);
    pub const WNF_SUB_STATE_IN_DELIVERY: Self = Self(2);
    pub const WNF_SUB_STATE_RETRY: Self = Self(3);
}

/// `_WNF_SCOPE_INSTANCE` (0x50 bytes).
#[repr(C)]
pub struct WnfScopeInstance {
    pub header: WnfNodeHeader,
    _pad_4: Reserved<0x4>,
    pub run_ref: ExRundownRef,
    pub data_scope: Field<WnfDataScope>,
    pub instance_id_size: Field<u32>,
    /// -> `void`
    pub instance_id_data: Field<u64>,
    pub resolver_list_entry: ListEntry,
    pub name_set_lock: WnfLock,
    pub name_set: RtlAvlTree,
    /// -> `void`
    pub permanent_data_store: Field<u64>,
    /// -> `void`
    pub volatile_permanent_data_store: Field<u64>,
}

unsafe impl NtStruct for WnfScopeInstance {}

const _: () = {
    assert!(core::mem::size_of::<WnfScopeInstance>() == 0x50);
    assert!(core::mem::offset_of!(WnfScopeInstance, header) == 0x0);
    assert!(core::mem::offset_of!(WnfScopeInstance, run_ref) == 0x8);
    assert!(core::mem::offset_of!(WnfScopeInstance, data_scope) == 0x10);
    assert!(core::mem::offset_of!(WnfScopeInstance, instance_id_size) == 0x14);
    assert!(core::mem::offset_of!(WnfScopeInstance, instance_id_data) == 0x18);
    assert!(core::mem::offset_of!(WnfScopeInstance, resolver_list_entry) == 0x20);
    assert!(core::mem::offset_of!(WnfScopeInstance, name_set_lock) == 0x30);
    assert!(core::mem::offset_of!(WnfScopeInstance, name_set) == 0x38);
    assert!(core::mem::offset_of!(WnfScopeInstance, permanent_data_store) == 0x40);
    assert!(core::mem::offset_of!(WnfScopeInstance, volatile_permanent_data_store) == 0x48);
};

/// `_WNF_DATA_SCOPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct WnfDataScope(pub i32);

impl WnfDataScope {
    pub const WNF_DATA_SCOPE_SYSTEM: Self = Self(0);
    pub const WNF_DATA_SCOPE_SESSION: Self = Self(1);
    pub const WNF_DATA_SCOPE_USER: Self = Self(2);
    pub const WNF_DATA_SCOPE_PROCESS: Self = Self(3);
    pub const WNF_DATA_SCOPE_MACHINE: Self = Self(4);
    pub const WNF_DATA_SCOPE_PHYSICAL_MACHINE: Self = Self(5);
}

/// `_WNF_PROCESS_CONTEXT` (0x88 bytes).
#[repr(C)]
pub struct WnfProcessContext {
    pub header: WnfNodeHeader,
    _pad_4: Reserved<0x4>,
    /// -> `_EPROCESS`
    pub process: Field<u64>,
    pub wnf_processes_list_entry: ListEntry,
    /// -> `void`
    pub implicit_scope_instances: [Field<u64>; 3],
    pub temporary_names_list_lock: WnfLock,
    pub temporary_names_list_head: ListEntry,
    pub process_subscription_list_lock: WnfLock,
    pub process_subscription_list_head: ListEntry,
    pub delivery_pending_list_lock: WnfLock,
    pub delivery_pending_list_head: ListEntry,
    /// -> `_KEVENT`
    pub notification_event: Field<u64>,
}

unsafe impl NtStruct for WnfProcessContext {}

const _: () = {
    assert!(core::mem::size_of::<WnfProcessContext>() == 0x88);
    assert!(core::mem::offset_of!(WnfProcessContext, header) == 0x0);
    assert!(core::mem::offset_of!(WnfProcessContext, process) == 0x8);
    assert!(core::mem::offset_of!(WnfProcessContext, wnf_processes_list_entry) == 0x10);
    assert!(core::mem::offset_of!(WnfProcessContext, implicit_scope_instances) == 0x20);
    assert!(core::mem::offset_of!(WnfProcessContext, temporary_names_list_lock) == 0x38);
    assert!(core::mem::offset_of!(WnfProcessContext, temporary_names_list_head) == 0x40);
    assert!(core::mem::offset_of!(WnfProcessContext, process_subscription_list_lock) == 0x50);
    assert!(core::mem::offset_of!(WnfProcessContext, process_subscription_list_head) == 0x58);
    assert!(core::mem::offset_of!(WnfProcessContext, delivery_pending_list_lock) == 0x68);
    assert!(core::mem::offset_of!(WnfProcessContext, delivery_pending_list_head) == 0x70);
    assert!(core::mem::offset_of!(WnfProcessContext, notification_event) == 0x80);
};

/// `_WNF_SILODRIVERSTATE` (0x38 bytes).
#[repr(C)]
pub struct WnfSilodriverstate {
    /// -> `_WNF_SCOPE_MAP`
    pub scope_map: Field<u64>,
    /// -> `void`
    pub permanent_name_store_root_key: Field<u64>,
    /// -> `void`
    pub persistent_name_store_root_key: Field<u64>,
    pub permanent_name_sequence_number: Field<i64>,
    pub permanent_name_sequence_number_lock: WnfLock,
    pub permanent_name_sequence_number_pool: Field<i64>,
    pub runtime_name_sequence_number: Field<i64>,
}

unsafe impl NtStruct for WnfSilodriverstate {}

const _: () = {
    assert!(core::mem::size_of::<WnfSilodriverstate>() == 0x38);
    assert!(core::mem::offset_of!(WnfSilodriverstate, scope_map) == 0x0);
    assert!(core::mem::offset_of!(WnfSilodriverstate, permanent_name_store_root_key) == 0x8);
    assert!(core::mem::offset_of!(WnfSilodriverstate, persistent_name_store_root_key) == 0x10);
    assert!(core::mem::offset_of!(WnfSilodriverstate, permanent_name_sequence_number) == 0x18);
    assert!(core::mem::offset_of!(WnfSilodriverstate, permanent_name_sequence_number_lock) == 0x20);
    assert!(core::mem::offset_of!(WnfSilodriverstate, permanent_name_sequence_number_pool) == 0x28);
    assert!(core::mem::offset_of!(WnfSilodriverstate, runtime_name_sequence_number) == 0x30);
};

/// `_EXCEPTION_POINTERS` (0x10 bytes).
#[repr(C)]
pub struct ExceptionPointers {
    /// -> `_EXCEPTION_RECORD`
    pub exception_record: Field<u64>,
    /// -> `_CONTEXT`
    pub context_record: Field<u64>,
}

unsafe impl NtStruct for ExceptionPointers {}

const _: () = {
    assert!(core::mem::size_of::<ExceptionPointers>() == 0x10);
    assert!(core::mem::offset_of!(ExceptionPointers, exception_record) == 0x0);
    assert!(core::mem::offset_of!(ExceptionPointers, context_record) == 0x8);
};

/// `_EX_RUNDOWN_REF_CACHE_AWARE` (0x18 bytes).
#[repr(C)]
pub struct ExRundownRefCacheAware {
    /// -> `_EX_RUNDOWN_REF`
    pub run_refs: Field<u64>,
    /// -> `void`
    pub pool_to_free: Field<u64>,
    pub run_ref_size: Field<u32>,
    pub number: Field<u32>,
}

unsafe impl NtStruct for ExRundownRefCacheAware {}

const _: () = {
    assert!(core::mem::size_of::<ExRundownRefCacheAware>() == 0x18);
    assert!(core::mem::offset_of!(ExRundownRefCacheAware, run_refs) == 0x0);
    assert!(core::mem::offset_of!(ExRundownRefCacheAware, pool_to_free) == 0x8);
    assert!(core::mem::offset_of!(ExRundownRefCacheAware, run_ref_size) == 0x10);
    assert!(core::mem::offset_of!(ExRundownRefCacheAware, number) == 0x14);
};

/// `_WNF_STATE_DATA` (0x10 bytes).
#[repr(C)]
pub struct WnfStateData {
    pub header: WnfNodeHeader,
    pub allocated_size: Field<u32>,
    pub data_size: Field<u32>,
    pub change_stamp: Field<u32>,
}

unsafe impl NtStruct for WnfStateData {}

const _: () = {
    assert!(core::mem::size_of::<WnfStateData>() == 0x10);
    assert!(core::mem::offset_of!(WnfStateData, header) == 0x0);
    assert!(core::mem::offset_of!(WnfStateData, allocated_size) == 0x4);
    assert!(core::mem::offset_of!(WnfStateData, data_size) == 0x8);
    assert!(core::mem::offset_of!(WnfStateData, change_stamp) == 0xc);
};

/// `_WNF_SCOPE_MAP` (0xb0 bytes).
#[repr(C)]
pub struct WnfScopeMap {
    pub header: WnfNodeHeader,
    _pad_4: Reserved<0x4>,
    /// -> `_WNF_SCOPE_INSTANCE`
    pub system_scope_instance: Field<u64>,
    /// -> `_WNF_SCOPE_INSTANCE`
    pub machine_scope_instance: Field<u64>,
    /// -> `_WNF_SCOPE_INSTANCE`
    pub physical_machine_scope_instance: Field<u64>,
    pub by_data_scope: [WnfScopeMapEntry; 6],
}

unsafe impl NtStruct for WnfScopeMap {}

const _: () = {
    assert!(core::mem::size_of::<WnfScopeMap>() == 0xb0);
    assert!(core::mem::offset_of!(WnfScopeMap, header) == 0x0);
    assert!(core::mem::offset_of!(WnfScopeMap, system_scope_instance) == 0x8);
    assert!(core::mem::offset_of!(WnfScopeMap, machine_scope_instance) == 0x10);
    assert!(core::mem::offset_of!(WnfScopeMap, physical_machine_scope_instance) == 0x18);
    assert!(core::mem::offset_of!(WnfScopeMap, by_data_scope) == 0x20);
};

/// `_WNF_SCOPE_MAP_ENTRY` (0x18 bytes).
#[repr(C)]
pub struct WnfScopeMapEntry {
    pub map_entry_lock: WnfLock,
    pub map_entry_head: ListEntry,
}

unsafe impl NtStruct for WnfScopeMapEntry {}

const _: () = {
    assert!(core::mem::size_of::<WnfScopeMapEntry>() == 0x18);
    assert!(core::mem::offset_of!(WnfScopeMapEntry, map_entry_lock) == 0x0);
    assert!(core::mem::offset_of!(WnfScopeMapEntry, map_entry_head) == 0x8);
};

/// `_EXT_SET_PARAMETERS_V0` (0x10 bytes).
#[repr(C)]
pub struct ExtSetParametersV0 {
    pub version: Field<u32>,
    pub reserved: Field<u32>,
    pub no_wake_tolerance: Field<i64>,
}

unsafe impl NtStruct for ExtSetParametersV0 {}

const _: () = {
    assert!(core::mem::size_of::<ExtSetParametersV0>() == 0x10);
    assert!(core::mem::offset_of!(ExtSetParametersV0, version) == 0x0);
    assert!(core::mem::offset_of!(ExtSetParametersV0, reserved) == 0x4);
    assert!(core::mem::offset_of!(ExtSetParametersV0, no_wake_tolerance) == 0x8);
};
