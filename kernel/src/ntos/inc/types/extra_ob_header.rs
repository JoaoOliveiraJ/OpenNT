//! Os cabeçalhos opcionais do OBJECT_HEADER e a informação de criação que
//! o ObCreateObject captura (layouts dos símbolos do ntoskrnl 19041; o
//! gerador não os emite).
//!
//! Mantido à mão, no estilo de `types`: `#[repr(C)]`, folhas `Field<T>`,
//! `size_of`/`offset_of!` conferidos em compilação.

use super::*;

/// `_OBJECT_HEADER_CREATOR_INFO` (0x20 bytes; InfoMask 0x01).
#[repr(C)]
pub struct ObjectHeaderCreatorInfo {
    pub type_list: ListEntry,
    /// -> `void`
    pub creator_unique_process: Field<u64>,
    pub creator_back_trace_index: Field<u16>,
    pub reserved1: Field<u16>,
    pub reserved2: Field<u32>,
}

/// `_OBJECT_HANDLE_COUNT_ENTRY` (0x10 bytes): HandleCount nos bits 0..24 e
/// LockCount nos bits 24..32 de `counts`.
#[repr(C)]
pub struct ObjectHandleCountEntry {
    /// -> `_EPROCESS`
    pub process: Field<u64>,
    pub counts: Field<u32>,
    _pad_c: Reserved<0x4>,
}

impl ObjectHandleCountEntry {
    pub const HANDLE_COUNT_MASK: u32 = 0x00FF_FFFF;
    #[inline(always)]
    pub fn handle_count(&self) -> u32 {
        self.counts.get() & Self::HANDLE_COUNT_MASK
    }
    #[inline(always)]
    pub fn set_handle_count(&self, value: u32) {
        self.counts.set((self.counts.get() & !Self::HANDLE_COUNT_MASK) | (value & Self::HANDLE_COUNT_MASK));
    }
    #[inline(always)]
    pub fn lock_count(&self) -> u32 {
        self.counts.get() >> 24
    }
}

/// `_OBJECT_HANDLE_COUNT_DATABASE` (0x18 bytes com uma entrada).
#[repr(C)]
pub struct ObjectHandleCountDatabase {
    pub count_entries: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub handle_count_entries: ObjectHandleCountEntry,
}

/// `_OBJECT_HEADER_HANDLE_INFO` (0x10 bytes; InfoMask 0x04): a entrada única
/// (SingleHandleEntry no OBJECT_HEADER.Flags) ou o banco de contagens.
#[repr(C)]
pub struct ObjectHeaderHandleInfo {
    /// `SingleEntry` (a união com `HandleCountDataBase`, o ponteiro em +0).
    pub single_entry: ObjectHandleCountEntry,
}

/// `_OBJECT_HEADER_QUOTA_INFO` (0x20 bytes; InfoMask 0x08).
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

/// `_OBJECT_HEADER_PROCESS_INFO` (0x10 bytes; InfoMask 0x10).
#[repr(C)]
pub struct ObjectHeaderProcessInfo {
    /// -> `_EPROCESS`
    pub exclusive_process: Field<u64>,
    pub reserved: Field<u64>,
}

/// `_OBJECT_HEADER_AUDIT_INFO` (0x10 bytes; InfoMask 0x20).
#[repr(C)]
pub struct ObjectHeaderAuditInfo {
    /// -> `void`
    pub security_descriptor: Field<u64>,
    pub reserved: Field<u64>,
}

/// `_OBJECT_HEADER_EXTENDED_INFO` (0x10 bytes; InfoMask 0x40).
#[repr(C)]
pub struct ObjectHeaderExtendedInfo {
    /// -> `_OBJECT_FOOTER`
    pub footer: Field<u64>,
    pub reserved: Field<u64>,
}

/// `_OBJECT_HEADER_PADDING_INFO` (4 bytes; InfoMask 0x80).
#[repr(C)]
pub struct ObjectHeaderPaddingInfo {
    pub padding_amount: Field<u32>,
}

/// `_OBJECT_CREATE_INFORMATION` (0x40 bytes).
#[repr(C)]
pub struct ObjectCreateInformation {
    pub attributes: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub root_directory: Field<u64>,
    pub probe_mode: Field<u8>,
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

unsafe impl NtStruct for ObjectHeaderCreatorInfo {}
unsafe impl NtStruct for ObjectHandleCountEntry {}
unsafe impl NtStruct for ObjectHandleCountDatabase {}
unsafe impl NtStruct for ObjectHeaderHandleInfo {}
unsafe impl NtStruct for ObjectHeaderQuotaInfo {}
unsafe impl NtStruct for ObjectHeaderProcessInfo {}
unsafe impl NtStruct for ObjectHeaderAuditInfo {}
unsafe impl NtStruct for ObjectHeaderExtendedInfo {}
unsafe impl NtStruct for ObjectHeaderPaddingInfo {}
unsafe impl NtStruct for ObjectCreateInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHeaderCreatorInfo>() == 0x20);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, type_list) == 0x0);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, creator_unique_process) == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, creator_back_trace_index) == 0x18);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, reserved1) == 0x1a);
    assert!(core::mem::offset_of!(ObjectHeaderCreatorInfo, reserved2) == 0x1c);
    assert!(core::mem::size_of::<ObjectHandleCountEntry>() == 0x10);
    assert!(core::mem::offset_of!(ObjectHandleCountEntry, process) == 0x0);
    assert!(core::mem::offset_of!(ObjectHandleCountEntry, counts) == 0x8);
    assert!(core::mem::size_of::<ObjectHandleCountDatabase>() == 0x18);
    assert!(core::mem::offset_of!(ObjectHandleCountDatabase, count_entries) == 0x0);
    assert!(core::mem::offset_of!(ObjectHandleCountDatabase, handle_count_entries) == 0x8);
    assert!(core::mem::size_of::<ObjectHeaderHandleInfo>() == 0x10);
    assert!(core::mem::size_of::<ObjectHeaderQuotaInfo>() == 0x20);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, paged_pool_charge) == 0x0);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, non_paged_pool_charge) == 0x4);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, security_descriptor_charge) == 0x8);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, reserved1) == 0xc);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, security_descriptor_quota_block) == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderQuotaInfo, reserved2) == 0x18);
    assert!(core::mem::size_of::<ObjectHeaderProcessInfo>() == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderProcessInfo, exclusive_process) == 0x0);
    assert!(core::mem::size_of::<ObjectHeaderAuditInfo>() == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderAuditInfo, security_descriptor) == 0x0);
    assert!(core::mem::size_of::<ObjectHeaderExtendedInfo>() == 0x10);
    assert!(core::mem::offset_of!(ObjectHeaderExtendedInfo, footer) == 0x0);
    assert!(core::mem::size_of::<ObjectHeaderPaddingInfo>() == 0x4);
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
