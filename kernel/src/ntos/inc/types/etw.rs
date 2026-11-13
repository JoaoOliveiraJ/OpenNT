//! Etw: estruturas de rastreamento.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_TRACE_ENABLE_INFO` (0x20 bytes).
#[repr(C)]
pub struct TraceEnableInfo {
    pub is_enabled: Field<u32>,
    pub level: Field<u8>,
    pub reserved1: Field<u8>,
    pub logger_id: Field<u16>,
    pub enable_property: Field<u32>,
    pub reserved2: Field<u32>,
    pub match_any_keyword: Field<u64>,
    pub match_all_keyword: Field<u64>,
}

unsafe impl NtStruct for TraceEnableInfo {}

const _: () = {
    assert!(core::mem::size_of::<TraceEnableInfo>() == 0x20);
    assert!(core::mem::offset_of!(TraceEnableInfo, is_enabled) == 0x0);
    assert!(core::mem::offset_of!(TraceEnableInfo, level) == 0x4);
    assert!(core::mem::offset_of!(TraceEnableInfo, reserved1) == 0x5);
    assert!(core::mem::offset_of!(TraceEnableInfo, logger_id) == 0x6);
    assert!(core::mem::offset_of!(TraceEnableInfo, enable_property) == 0x8);
    assert!(core::mem::offset_of!(TraceEnableInfo, reserved2) == 0xc);
    assert!(core::mem::offset_of!(TraceEnableInfo, match_any_keyword) == 0x10);
    assert!(core::mem::offset_of!(TraceEnableInfo, match_all_keyword) == 0x18);
};

/// `_ETW_REG_ENTRY` (0x70 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `EtwRegEntryView1`..`EtwRegEntryView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct EtwRegEntry {
    pub reg_list: ListEntry,
    pub group_reg_list: ListEntry,
    /// -> `_ETW_GUID_ENTRY`
    pub guid_entry: Field<u64>,
    /// -> `_ETW_GUID_ENTRY`
    pub group_entry: Field<u64>,
    /// -> `_ETW_REPLY_QUEUE`
    pub reply_queue: Field<u64>,
    pub session_id: Field<u32>,
    _pad_3c: Reserved<0x14>,
    /// -> `_EPROCESS`
    pub process: Field<u64>,
    /// -> `void`
    pub callback: Field<u64>,
    pub index: Field<u16>,
    pub flags: Field<u16>,
    pub enable_mask: Field<u8>,
    pub group_enable_mask: Field<u8>,
    pub host_enable_mask: Field<u8>,
    pub host_group_enable_mask: Field<u8>,
    /// -> `_ETW_PROVIDER_TRAITS`
    pub traits: Field<u64>,
}

/// Vista 1 de `_ETW_REG_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EtwRegEntryView1 {
    _pad_0: Reserved<0x30>,
    /// -> `_ETW_QUEUE_ENTRY`
    pub reply_slot: [Field<u64>; 4],
    /// -> `void`
    pub callback_context: Field<u64>,
    _pad_58: Reserved<0x18>,
}

/// Vista 2 de `_ETW_REG_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EtwRegEntryView2 {
    _pad_0: Reserved<0x30>,
    /// -> `void`
    pub caller: Field<u64>,
    _pad_38: Reserved<0x38>,
}

impl core::ops::Deref for EtwRegEntry {
    type Target = EtwRegEntryView1;
    #[inline(always)]
    fn deref(&self) -> &EtwRegEntryView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EtwRegEntryView1>() }
    }
}

impl core::ops::Deref for EtwRegEntryView1 {
    type Target = EtwRegEntryView2;
    #[inline(always)]
    fn deref(&self) -> &EtwRegEntryView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EtwRegEntryView2>() }
    }
}

unsafe impl NtStruct for EtwRegEntry {}

impl EtwRegEntry {
    /// `DbgKernelRegistration`: bits 0..=0 de `flags`.
    pub const DBG_KERNEL_REGISTRATION_SHIFT: u32 = 0;
    pub const DBG_KERNEL_REGISTRATION_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn dbg_kernel_registration(&self) -> u16 {
        self.flags.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_kernel_registration(&self, value: u16) {
        self.flags.set_bits(0, 1, value as u64)
    }
    /// `DbgUserRegistration`: bits 1..=1 de `flags`.
    pub const DBG_USER_REGISTRATION_SHIFT: u32 = 1;
    pub const DBG_USER_REGISTRATION_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn dbg_user_registration(&self) -> u16 {
        self.flags.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_user_registration(&self, value: u16) {
        self.flags.set_bits(1, 1, value as u64)
    }
    /// `DbgReplyRegistration`: bits 2..=2 de `flags`.
    pub const DBG_REPLY_REGISTRATION_SHIFT: u32 = 2;
    pub const DBG_REPLY_REGISTRATION_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn dbg_reply_registration(&self) -> u16 {
        self.flags.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_reply_registration(&self, value: u16) {
        self.flags.set_bits(2, 1, value as u64)
    }
    /// `DbgClassicRegistration`: bits 3..=3 de `flags`.
    pub const DBG_CLASSIC_REGISTRATION_SHIFT: u32 = 3;
    pub const DBG_CLASSIC_REGISTRATION_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn dbg_classic_registration(&self) -> u16 {
        self.flags.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_classic_registration(&self, value: u16) {
        self.flags.set_bits(3, 1, value as u64)
    }
    /// `DbgSessionSpaceRegistration`: bits 4..=4 de `flags`.
    pub const DBG_SESSION_SPACE_REGISTRATION_SHIFT: u32 = 4;
    pub const DBG_SESSION_SPACE_REGISTRATION_MASK: u16 = 0x10;
    #[inline(always)]
    pub fn dbg_session_space_registration(&self) -> u16 {
        self.flags.bits(4, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_session_space_registration(&self, value: u16) {
        self.flags.set_bits(4, 1, value as u64)
    }
    /// `DbgModernRegistration`: bits 5..=5 de `flags`.
    pub const DBG_MODERN_REGISTRATION_SHIFT: u32 = 5;
    pub const DBG_MODERN_REGISTRATION_MASK: u16 = 0x20;
    #[inline(always)]
    pub fn dbg_modern_registration(&self) -> u16 {
        self.flags.bits(5, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_modern_registration(&self, value: u16) {
        self.flags.set_bits(5, 1, value as u64)
    }
    /// `DbgClosed`: bits 6..=6 de `flags`.
    pub const DBG_CLOSED_SHIFT: u32 = 6;
    pub const DBG_CLOSED_MASK: u16 = 0x40;
    #[inline(always)]
    pub fn dbg_closed(&self) -> u16 {
        self.flags.bits(6, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_closed(&self, value: u16) {
        self.flags.set_bits(6, 1, value as u64)
    }
    /// `DbgInserted`: bits 7..=7 de `flags`.
    pub const DBG_INSERTED_SHIFT: u32 = 7;
    pub const DBG_INSERTED_MASK: u16 = 0x80;
    #[inline(always)]
    pub fn dbg_inserted(&self) -> u16 {
        self.flags.bits(7, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_inserted(&self, value: u16) {
        self.flags.set_bits(7, 1, value as u64)
    }
    /// `DbgWow64`: bits 8..=8 de `flags`.
    pub const DBG_WOW64_SHIFT: u32 = 8;
    pub const DBG_WOW64_MASK: u16 = 0x100;
    #[inline(always)]
    pub fn dbg_wow64(&self) -> u16 {
        self.flags.bits(8, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_wow64(&self, value: u16) {
        self.flags.set_bits(8, 1, value as u64)
    }
    /// `DbgUseDescriptorType`: bits 9..=9 de `flags`.
    pub const DBG_USE_DESCRIPTOR_TYPE_SHIFT: u32 = 9;
    pub const DBG_USE_DESCRIPTOR_TYPE_MASK: u16 = 0x200;
    #[inline(always)]
    pub fn dbg_use_descriptor_type(&self) -> u16 {
        self.flags.bits(9, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_use_descriptor_type(&self, value: u16) {
        self.flags.set_bits(9, 1, value as u64)
    }
    /// `DbgDropProviderTraits`: bits 10..=10 de `flags`.
    pub const DBG_DROP_PROVIDER_TRAITS_SHIFT: u32 = 10;
    pub const DBG_DROP_PROVIDER_TRAITS_MASK: u16 = 0x400;
    #[inline(always)]
    pub fn dbg_drop_provider_traits(&self) -> u16 {
        self.flags.bits(10, 1) as u16
    }
    #[inline(always)]
    pub fn set_dbg_drop_provider_traits(&self, value: u16) {
        self.flags.set_bits(10, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<EtwRegEntry>() == 0x70);
    assert!(core::mem::offset_of!(EtwRegEntry, reg_list) == 0x0);
    assert!(core::mem::offset_of!(EtwRegEntry, group_reg_list) == 0x10);
    assert!(core::mem::offset_of!(EtwRegEntry, guid_entry) == 0x20);
    assert!(core::mem::offset_of!(EtwRegEntry, group_entry) == 0x28);
    assert!(core::mem::offset_of!(EtwRegEntry, reply_queue) == 0x30);
    assert!(core::mem::offset_of!(EtwRegEntry, session_id) == 0x38);
    assert!(core::mem::offset_of!(EtwRegEntry, process) == 0x50);
    assert!(core::mem::offset_of!(EtwRegEntry, callback) == 0x58);
    assert!(core::mem::offset_of!(EtwRegEntry, index) == 0x60);
    assert!(core::mem::offset_of!(EtwRegEntry, flags) == 0x62);
    assert!(core::mem::offset_of!(EtwRegEntry, enable_mask) == 0x64);
    assert!(core::mem::offset_of!(EtwRegEntry, group_enable_mask) == 0x65);
    assert!(core::mem::offset_of!(EtwRegEntry, host_enable_mask) == 0x66);
    assert!(core::mem::offset_of!(EtwRegEntry, host_group_enable_mask) == 0x67);
    assert!(core::mem::offset_of!(EtwRegEntry, traits) == 0x68);
    assert!(core::mem::size_of::<EtwRegEntryView1>() == 0x70);
    assert!(core::mem::align_of::<EtwRegEntryView1>() == core::mem::align_of::<EtwRegEntry>());
    assert!(core::mem::offset_of!(EtwRegEntryView1, reply_slot) == 0x30);
    assert!(core::mem::offset_of!(EtwRegEntryView1, callback_context) == 0x50);
    assert!(core::mem::size_of::<EtwRegEntryView2>() == 0x70);
    assert!(core::mem::align_of::<EtwRegEntryView2>() == core::mem::align_of::<EtwRegEntry>());
    assert!(core::mem::offset_of!(EtwRegEntryView2, caller) == 0x30);
};

/// `_ETW_GUID_ENTRY` (0x1a8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `EtwGuidEntryView1`, alcançada por `Deref`.
#[repr(C)]
pub struct EtwGuidEntry {
    pub guid_list: ListEntry,
    pub silo_guid_list: ListEntry,
    pub ref_count: Field<i64>,
    pub guid: Guid,
    pub reg_list_head: ListEntry,
    /// -> `void`
    pub security_descriptor: Field<u64>,
    pub last_enable: EtwLastEnableInfo,
    pub provider_enable_info: TraceEnableInfo,
    pub enable_info: [TraceEnableInfo; 8],
    /// -> `_ETW_FILTER_HEADER`
    pub filter_data: Field<u64>,
    /// -> `_ETW_SILODRIVERSTATE`
    pub silo_state: Field<u64>,
    /// -> `_ETW_GUID_ENTRY`
    pub host_entry: Field<u64>,
    pub lock: ExPushLock,
    /// -> `_ETHREAD`
    pub lock_owner: Field<u64>,
}

/// Vista 1 de `_ETW_GUID_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EtwGuidEntryView1 {
    _pad_0: Reserved<0x50>,
    pub match_id: Field<u64>,
    _pad_58: Reserved<0x150>,
}

impl core::ops::Deref for EtwGuidEntry {
    type Target = EtwGuidEntryView1;
    #[inline(always)]
    fn deref(&self) -> &EtwGuidEntryView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EtwGuidEntryView1>() }
    }
}

unsafe impl NtStruct for EtwGuidEntry {}

const _: () = {
    assert!(core::mem::size_of::<EtwGuidEntry>() == 0x1a8);
    assert!(core::mem::offset_of!(EtwGuidEntry, guid_list) == 0x0);
    assert!(core::mem::offset_of!(EtwGuidEntry, silo_guid_list) == 0x10);
    assert!(core::mem::offset_of!(EtwGuidEntry, ref_count) == 0x20);
    assert!(core::mem::offset_of!(EtwGuidEntry, guid) == 0x28);
    assert!(core::mem::offset_of!(EtwGuidEntry, reg_list_head) == 0x38);
    assert!(core::mem::offset_of!(EtwGuidEntry, security_descriptor) == 0x48);
    assert!(core::mem::offset_of!(EtwGuidEntry, last_enable) == 0x50);
    assert!(core::mem::offset_of!(EtwGuidEntry, provider_enable_info) == 0x60);
    assert!(core::mem::offset_of!(EtwGuidEntry, enable_info) == 0x80);
    assert!(core::mem::offset_of!(EtwGuidEntry, filter_data) == 0x180);
    assert!(core::mem::offset_of!(EtwGuidEntry, silo_state) == 0x188);
    assert!(core::mem::offset_of!(EtwGuidEntry, host_entry) == 0x190);
    assert!(core::mem::offset_of!(EtwGuidEntry, lock) == 0x198);
    assert!(core::mem::offset_of!(EtwGuidEntry, lock_owner) == 0x1a0);
    assert!(core::mem::size_of::<EtwGuidEntryView1>() == 0x1a8);
    assert!(core::mem::align_of::<EtwGuidEntryView1>() == core::mem::align_of::<EtwGuidEntry>());
    assert!(core::mem::offset_of!(EtwGuidEntryView1, match_id) == 0x50);
};

/// `_ETW_LAST_ENABLE_INFO` (0x10 bytes).
#[repr(C)]
pub struct EtwLastEnableInfo {
    pub enable_flags: LargeInteger,
    pub logger_id: Field<u16>,
    pub level: Field<u8>,
    pub bitfield_b: Field<u8>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for EtwLastEnableInfo {}

impl EtwLastEnableInfo {
    /// `Enabled`: bits 0..=0 de `bitfield_b`.
    pub const ENABLED_SHIFT: u32 = 0;
    pub const ENABLED_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn enabled(&self) -> u8 {
        self.bitfield_b.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_enabled(&self, value: u8) {
        self.bitfield_b.set_bits(0, 1, value as u64)
    }
    /// `InternalFlag`: bits 1..=7 de `bitfield_b`.
    pub const INTERNAL_FLAG_SHIFT: u32 = 1;
    pub const INTERNAL_FLAG_MASK: u8 = 0xfe;
    #[inline(always)]
    pub fn internal_flag(&self) -> u8 {
        self.bitfield_b.bits(1, 7) as u8
    }
    #[inline(always)]
    pub fn set_internal_flag(&self, value: u8) {
        self.bitfield_b.set_bits(1, 7, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<EtwLastEnableInfo>() == 0x10);
    assert!(core::mem::offset_of!(EtwLastEnableInfo, enable_flags) == 0x0);
    assert!(core::mem::offset_of!(EtwLastEnableInfo, logger_id) == 0x8);
    assert!(core::mem::offset_of!(EtwLastEnableInfo, level) == 0xa);
    assert!(core::mem::offset_of!(EtwLastEnableInfo, bitfield_b) == 0xb);
};

/// `_EVENT_DESCRIPTOR` (0x10 bytes).
#[repr(C)]
pub struct EventDescriptor {
    pub id: Field<u16>,
    pub version: Field<u8>,
    pub channel: Field<u8>,
    pub level: Field<u8>,
    pub opcode: Field<u8>,
    pub task: Field<u16>,
    pub keyword: Field<u64>,
}

unsafe impl NtStruct for EventDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<EventDescriptor>() == 0x10);
    assert!(core::mem::offset_of!(EventDescriptor, id) == 0x0);
    assert!(core::mem::offset_of!(EventDescriptor, version) == 0x2);
    assert!(core::mem::offset_of!(EventDescriptor, channel) == 0x3);
    assert!(core::mem::offset_of!(EventDescriptor, level) == 0x4);
    assert!(core::mem::offset_of!(EventDescriptor, opcode) == 0x5);
    assert!(core::mem::offset_of!(EventDescriptor, task) == 0x6);
    assert!(core::mem::offset_of!(EventDescriptor, keyword) == 0x8);
};

/// `_EVENT_DATA_DESCRIPTOR` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `EventDataDescriptorView1`, alcançada por `Deref`.
#[repr(C)]
pub struct EventDataDescriptor {
    pub ptr: Field<u64>,
    pub size: Field<u32>,
    pub reserved: Field<u32>,
}

/// Vista 1 de `_EVENT_DATA_DESCRIPTOR` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EventDataDescriptorView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0xc>,
    pub type_: Field<u8>,
    pub reserved1: Field<u8>,
    pub reserved2: Field<u16>,
}

impl core::ops::Deref for EventDataDescriptor {
    type Target = EventDataDescriptorView1;
    #[inline(always)]
    fn deref(&self) -> &EventDataDescriptorView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EventDataDescriptorView1>() }
    }
}

unsafe impl NtStruct for EventDataDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<EventDataDescriptor>() == 0x10);
    assert!(core::mem::offset_of!(EventDataDescriptor, ptr) == 0x0);
    assert!(core::mem::offset_of!(EventDataDescriptor, size) == 0x8);
    assert!(core::mem::offset_of!(EventDataDescriptor, reserved) == 0xc);
    assert!(core::mem::size_of::<EventDataDescriptorView1>() == 0x10);
    assert!(core::mem::align_of::<EventDataDescriptorView1>() == core::mem::align_of::<EventDataDescriptor>());
    assert!(core::mem::offset_of!(EventDataDescriptorView1, type_) == 0xc);
    assert!(core::mem::offset_of!(EventDataDescriptorView1, reserved1) == 0xd);
    assert!(core::mem::offset_of!(EventDataDescriptorView1, reserved2) == 0xe);
};
