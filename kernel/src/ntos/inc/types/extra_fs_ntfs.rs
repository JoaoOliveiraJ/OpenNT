//! Estruturas usadas pelo suporte ao ntfs.sys / exfat.sys que os símbolos
//! do ntoskrnl não têm (nem `wdk.rs`).
//!
//! Mantido à mão no estilo de `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`,
//! ponteiros como `Field<u64>` com o tipo apontado no comentário, layout x64
//! conferido em compilação. Origem de cada uma:
//!
//! - `BaseMcb` — BASE_MCB (ntifs.h), 0x18
//! - `RtlBitmapRun` — RTL_BITMAP_RUN (wdm.h), 0x8
//! - `RtlModuleBasicInfo` / `RtlModuleExtendedInfo` — RTL_MODULE_BASIC_INFO /
//!   RTL_MODULE_EXTENDED_INFO (aux_klib.h), 0x8 / 0x110
//! - `SeSecurityDescriptor` / `SeAccessRequest` / `SeAccessReply` —
//!   SE_SECURITY_DESCRIPTOR / SE_ACCESS_REQUEST / SE_ACCESS_REPLY (ntifs.h), 0x10 / 0x38 / 0x28
//! - `FileFullEaInformation` / `FileQuotaInformation` — FILE_FULL_EA_INFORMATION
//!   (wdm.h) / FILE_QUOTA_INFORMATION (ntifs.h), 0xC / 0x38
//! - `ShareAccess` / `LinkShareAccess` — SHARE_ACCESS / LINK_SHARE_ACCESS (wdm.h), 0x1C / 0xC
//! - `ReparseDataBuffer` (+ vistas) / `ReparseGuidDataBuffer` —
//!   REPARSE_DATA_BUFFER / REPARSE_GUID_DATA_BUFFER (ntifs.h), 0x18 / 0x1C
//!
//! FSRTL_PER_FILE_CONTEXT vem de `extra_fsrtl.rs` e TUNNEL de
//! `extra_fs_fat.rs` (não duplicados aqui). `_EX_PUSH_LOCK_AUTO_EXPAND` e
//! `_IOP_IRP_EXTENSION` constam dos símbolos e são geradas (`types/ex.rs`,
//! `io.rs`); ficam reexportadas aqui.

use super::*;

pub use super::{ExPushLockAutoExpand, IopIrpExtension};

// ---- main ----

/// `_BASE_MCB` (ntifs.h): o mapa VBN -> LBN dos file systems
/// (FsRtl*BaseMcb*). `Mapping` aponta para os pares internos do FsRtl
/// (8 bytes cada; ver `fsrtl::mcb`). O `_LARGE_MCB` público é
/// `{ PKGUARDED_MUTEX GuardedMutex; BASE_MCB BaseMcb; }`.
#[repr(C)]
pub struct BaseMcb {
    pub maximum_pair_count: Field<u32>,
    pub pair_count: Field<u32>,
    pub pool_type: Field<u16>,
    pub flags: Field<u16>,
    _pad_c: Reserved<0x4>,
    /// -> `MAPPING[MaximumPairCount]` (interno do FsRtl)
    pub mapping: Field<u64>,
}

unsafe impl NtStruct for BaseMcb {}

const _: () = {
    assert!(core::mem::size_of::<BaseMcb>() == 0x18);
    assert!(core::mem::offset_of!(BaseMcb, maximum_pair_count) == 0x0);
    assert!(core::mem::offset_of!(BaseMcb, pair_count) == 0x4);
    assert!(core::mem::offset_of!(BaseMcb, pool_type) == 0x8);
    assert!(core::mem::offset_of!(BaseMcb, flags) == 0xa);
    assert!(core::mem::offset_of!(BaseMcb, mapping) == 0x10);
};

// ---- A ----

/// `_RTL_BITMAP_RUN` (wdm.h; 0x8 bytes): elemento do vetor de saída do
/// RtlFindClearRuns.
#[repr(C)]
pub struct RtlBitmapRun {
    pub starting_index: Field<u32>,
    pub number_of_bits: Field<u32>,
}

unsafe impl NtStruct for RtlBitmapRun {}

const _: () = {
    assert!(core::mem::size_of::<RtlBitmapRun>() == 0x8);
    assert!(core::mem::offset_of!(RtlBitmapRun, starting_index) == 0x0);
    assert!(core::mem::offset_of!(RtlBitmapRun, number_of_bits) == 0x4);
};

/// `_RTL_MODULE_BASIC_INFO` (aux_klib.h; 0x8 bytes): elemento do
/// RtlQueryModuleInformation com SizePerModule = 8.
#[repr(C)]
pub struct RtlModuleBasicInfo {
    /// -> `void`
    pub image_base: Field<u64>,
}

unsafe impl NtStruct for RtlModuleBasicInfo {}

const _: () = {
    assert!(core::mem::size_of::<RtlModuleBasicInfo>() == 0x8);
    assert!(core::mem::offset_of!(RtlModuleBasicInfo, image_base) == 0x0);
};

/// `_RTL_MODULE_EXTENDED_INFO` (aux_klib.h; 0x110 bytes): elemento do
/// RtlQueryModuleInformation com SizePerModule = 0x110.
#[repr(C)]
pub struct RtlModuleExtendedInfo {
    pub basic_info: RtlModuleBasicInfo,
    pub image_size: Field<u32>,
    pub file_name_offset: Field<u16>,
    pub full_path_name: [Field<u8>; 256],
    _pad_10e: Reserved<0x2>,
}

unsafe impl NtStruct for RtlModuleExtendedInfo {}

const _: () = {
    assert!(core::mem::size_of::<RtlModuleExtendedInfo>() == 0x110);
    assert!(core::mem::offset_of!(RtlModuleExtendedInfo, basic_info) == 0x0);
    assert!(core::mem::offset_of!(RtlModuleExtendedInfo, image_size) == 0x8);
    assert!(core::mem::offset_of!(RtlModuleExtendedInfo, file_name_offset) == 0xc);
    assert!(core::mem::offset_of!(RtlModuleExtendedInfo, full_path_name) == 0xe);
};

// ---- B ----

/// `_SE_SECURITY_DESCRIPTOR` (ntifs.h; 0x10 bytes).
#[repr(C)]
pub struct SeSecurityDescriptor {
    pub size: Field<u32>,
    /// SE_SECURITY_DESCRIPTOR_FLAG_* (bits 0..2; o hint do access check).
    pub flags: Field<u32>,
    /// -> `void` (SECURITY_DESCRIPTOR)
    pub security_descriptor: Field<u64>,
}

unsafe impl NtStruct for SeSecurityDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<SeSecurityDescriptor>() == 0x10);
    assert!(core::mem::offset_of!(SeSecurityDescriptor, size) == 0x0);
    assert!(core::mem::offset_of!(SeSecurityDescriptor, flags) == 0x4);
    assert!(core::mem::offset_of!(SeSecurityDescriptor, security_descriptor) == 0x8);
};

/// `_SE_ACCESS_REQUEST` (ntifs.h; 0x38 bytes).
#[repr(C)]
pub struct SeAccessRequest {
    pub size: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `_SE_SECURITY_DESCRIPTOR`
    pub se_security_descriptor: Field<u64>,
    pub desired_access: Field<u32>,
    pub previously_granted_access: Field<u32>,
    /// -> `void` (SID)
    pub principal_self_sid: Field<u64>,
    /// -> `_GENERIC_MAPPING`
    pub generic_mapping: Field<u64>,
    pub object_type_list_count: Field<u32>,
    _pad_2c: Reserved<0x4>,
    /// -> `_OBJECT_TYPE_LIST`
    pub object_type_list: Field<u64>,
}

unsafe impl NtStruct for SeAccessRequest {}

const _: () = {
    assert!(core::mem::size_of::<SeAccessRequest>() == 0x38);
    assert!(core::mem::offset_of!(SeAccessRequest, size) == 0x0);
    assert!(core::mem::offset_of!(SeAccessRequest, se_security_descriptor) == 0x8);
    assert!(core::mem::offset_of!(SeAccessRequest, desired_access) == 0x10);
    assert!(core::mem::offset_of!(SeAccessRequest, previously_granted_access) == 0x14);
    assert!(core::mem::offset_of!(SeAccessRequest, principal_self_sid) == 0x18);
    assert!(core::mem::offset_of!(SeAccessRequest, generic_mapping) == 0x20);
    assert!(core::mem::offset_of!(SeAccessRequest, object_type_list_count) == 0x28);
    assert!(core::mem::offset_of!(SeAccessRequest, object_type_list) == 0x30);
};

/// `_SE_ACCESS_REPLY` (ntifs.h; 0x28 bytes).
#[repr(C)]
pub struct SeAccessReply {
    pub size: Field<u32>,
    pub result_list_count: Field<u32>,
    /// -> `u32` (ACCESS_MASK[ResultListCount])
    pub granted_access: Field<u64>,
    /// -> `i32` (NTSTATUS[ResultListCount])
    pub access_status: Field<u64>,
    /// -> `_ACCESS_REASONS`
    pub access_reason: Field<u64>,
    /// -> `_PRIVILEGE_SET *`
    pub privileges: Field<u64>,
}

unsafe impl NtStruct for SeAccessReply {}

const _: () = {
    assert!(core::mem::size_of::<SeAccessReply>() == 0x28);
    assert!(core::mem::offset_of!(SeAccessReply, size) == 0x0);
    assert!(core::mem::offset_of!(SeAccessReply, result_list_count) == 0x4);
    assert!(core::mem::offset_of!(SeAccessReply, granted_access) == 0x8);
    assert!(core::mem::offset_of!(SeAccessReply, access_status) == 0x10);
    assert!(core::mem::offset_of!(SeAccessReply, access_reason) == 0x18);
    assert!(core::mem::offset_of!(SeAccessReply, privileges) == 0x20);
};

// ---- C ----

/// `_FILE_FULL_EA_INFORMATION` (wdm.h): uma entrada da lista de atributos
/// estendidos (NtSetEaFile, IRP_MJ_SET_EA, IoCheckEaBufferValidity).
#[repr(C)]
pub struct FileFullEaInformation {
    pub next_entry_offset: Field<u32>,
    pub flags: Field<u8>,
    pub ea_name_length: Field<u8>,
    pub ea_value_length: Field<u16>,
    /// `CHAR EaName[1]`: EaNameLength bytes, o NUL e depois o valor.
    pub ea_name: [Field<u8>; 1],
    _pad_9: Reserved<0x3>,
}

unsafe impl NtStruct for FileFullEaInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileFullEaInformation>() == 0xC);
    assert!(core::mem::offset_of!(FileFullEaInformation, next_entry_offset) == 0x0);
    assert!(core::mem::offset_of!(FileFullEaInformation, flags) == 0x4);
    assert!(core::mem::offset_of!(FileFullEaInformation, ea_name_length) == 0x5);
    assert!(core::mem::offset_of!(FileFullEaInformation, ea_value_length) == 0x6);
    assert!(core::mem::offset_of!(FileFullEaInformation, ea_name) == 0x8);
};

/// `_FILE_QUOTA_INFORMATION` (ntifs.h): uma entrada de cota por SID
/// (NtSetQuotaInformationFile, IoCheckQuotaBufferValidity).
#[repr(C)]
pub struct FileQuotaInformation {
    pub next_entry_offset: Field<u32>,
    pub sid_length: Field<u32>,
    pub change_time: LargeInteger,
    pub quota_used: LargeInteger,
    pub quota_threshold: LargeInteger,
    pub quota_limit: LargeInteger,
    /// `SID Sid` (SidLength bytes; o SubAuthority[1] declarado continua além).
    pub sid: Sid,
    _pad_34: Reserved<0x4>,
}

unsafe impl NtStruct for FileQuotaInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileQuotaInformation>() == 0x38);
    assert!(core::mem::offset_of!(FileQuotaInformation, sid_length) == 0x4);
    assert!(core::mem::offset_of!(FileQuotaInformation, change_time) == 0x8);
    assert!(core::mem::offset_of!(FileQuotaInformation, quota_limit) == 0x20);
    assert!(core::mem::offset_of!(FileQuotaInformation, sid) == 0x28);
};

/// `_SHARE_ACCESS` (wdm.h): contadores de abertura e de compartilhamento
/// que o file system guarda por arquivo (IoCheckShareAccess & co.).
#[repr(C)]
pub struct ShareAccess {
    pub open_count: Field<u32>,
    pub readers: Field<u32>,
    pub writers: Field<u32>,
    pub deleters: Field<u32>,
    pub shared_read: Field<u32>,
    pub shared_write: Field<u32>,
    pub shared_delete: Field<u32>,
}

unsafe impl NtStruct for ShareAccess {}

const _: () = {
    assert!(core::mem::size_of::<ShareAccess>() == 0x1C);
    assert!(core::mem::offset_of!(ShareAccess, readers) == 0x4);
    assert!(core::mem::offset_of!(ShareAccess, deleters) == 0xC);
    assert!(core::mem::offset_of!(ShareAccess, shared_read) == 0x10);
    assert!(core::mem::offset_of!(ShareAccess, shared_delete) == 0x18);
};

/// `_LINK_SHARE_ACCESS` (ntifs.h): a contagem de exclusão por hard link
/// (IoCheckLinkShareAccess, IoSetLinkShareAccess, Io*LinkShareAccessEx).
#[repr(C)]
pub struct LinkShareAccess {
    pub open_count: Field<u32>,
    pub deleters: Field<u32>,
    pub shared_deleters: Field<u32>,
}

unsafe impl NtStruct for LinkShareAccess {}

const _: () = {
    assert!(core::mem::size_of::<LinkShareAccess>() == 0xC);
    assert!(core::mem::offset_of!(LinkShareAccess, deleters) == 0x4);
    assert!(core::mem::offset_of!(LinkShareAccess, shared_deleters) == 0x8);
};

// ---- D ----

/// `_REPARSE_DATA_BUFFER::SymbolicLinkReparseBuffer` (ntifs.h, 0x10 bytes).
#[repr(C)]
pub struct ReparseDataBufferSymbolicLink {
    pub substitute_name_offset: Field<u16>,
    pub substitute_name_length: Field<u16>,
    pub print_name_offset: Field<u16>,
    pub print_name_length: Field<u16>,
    pub flags: Field<u32>,
    /// `WCHAR PathBuffer[1]`
    pub path_buffer: [Field<u16>; 1],
    _pad_e: Reserved<0x2>,
}

unsafe impl NtStruct for ReparseDataBufferSymbolicLink {}

/// `_REPARSE_DATA_BUFFER::MountPointReparseBuffer` (ntifs.h, 0xa bytes).
#[repr(C)]
pub struct ReparseDataBufferMountPoint {
    pub substitute_name_offset: Field<u16>,
    pub substitute_name_length: Field<u16>,
    pub print_name_offset: Field<u16>,
    pub print_name_length: Field<u16>,
    /// `WCHAR PathBuffer[1]`
    pub path_buffer: [Field<u16>; 1],
}

unsafe impl NtStruct for ReparseDataBufferMountPoint {}

/// `_REPARSE_DATA_BUFFER` (ntifs.h, 0x18 bytes): cabeçalho de 8 bytes e a
/// união SymbolicLink / MountPoint / Generic (vistas por `Deref`).
#[repr(C)]
pub struct ReparseDataBuffer {
    pub reparse_tag: Field<u32>,
    pub reparse_data_length: Field<u16>,
    pub reserved: Field<u16>,
    pub symbolic_link_reparse_buffer: ReparseDataBufferSymbolicLink,
}

/// Vista 1 de `_REPARSE_DATA_BUFFER` (MountPointReparseBuffer).
#[repr(C)]
pub struct ReparseDataBufferView1 {
    _align: [u32; 0],
    _header: Reserved<0x8>,
    pub mount_point_reparse_buffer: ReparseDataBufferMountPoint,
    _pad_12: Reserved<0x6>,
}

/// Vista 2 de `_REPARSE_DATA_BUFFER` (GenericReparseBuffer).
#[repr(C)]
pub struct ReparseDataBufferView2 {
    _align: [u32; 0],
    _header: Reserved<0x8>,
    /// `UCHAR DataBuffer[1]`
    pub data_buffer: [Field<u8>; 1],
    _pad_9: Reserved<0xf>,
}

impl core::ops::Deref for ReparseDataBuffer {
    type Target = ReparseDataBufferView1;
    #[inline(always)]
    fn deref(&self) -> &ReparseDataBufferView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ReparseDataBufferView1>() }
    }
}

impl core::ops::Deref for ReparseDataBufferView1 {
    type Target = ReparseDataBufferView2;
    #[inline(always)]
    fn deref(&self) -> &ReparseDataBufferView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ReparseDataBufferView2>() }
    }
}

unsafe impl NtStruct for ReparseDataBuffer {}

const _: () = {
    assert!(core::mem::size_of::<ReparseDataBufferSymbolicLink>() == 0x10);
    assert!(core::mem::offset_of!(ReparseDataBufferSymbolicLink, flags) == 0x8);
    assert!(core::mem::offset_of!(ReparseDataBufferSymbolicLink, path_buffer) == 0xc);
    assert!(core::mem::size_of::<ReparseDataBufferMountPoint>() == 0xa);
    assert!(core::mem::offset_of!(ReparseDataBufferMountPoint, path_buffer) == 0x8);
    assert!(core::mem::size_of::<ReparseDataBuffer>() == 0x18);
    assert!(core::mem::offset_of!(ReparseDataBuffer, reparse_data_length) == 0x4);
    assert!(core::mem::offset_of!(ReparseDataBuffer, reserved) == 0x6);
    assert!(core::mem::offset_of!(ReparseDataBuffer, symbolic_link_reparse_buffer) == 0x8);
    assert!(core::mem::size_of::<ReparseDataBufferView1>() == 0x18);
    assert!(core::mem::align_of::<ReparseDataBufferView1>() == core::mem::align_of::<ReparseDataBuffer>());
    assert!(core::mem::offset_of!(ReparseDataBufferView1, mount_point_reparse_buffer) == 0x8);
    assert!(core::mem::size_of::<ReparseDataBufferView2>() == 0x18);
    assert!(core::mem::align_of::<ReparseDataBufferView2>() == core::mem::align_of::<ReparseDataBuffer>());
    assert!(core::mem::offset_of!(ReparseDataBufferView2, data_buffer) == 0x8);
};

/// `_REPARSE_GUID_DATA_BUFFER` (ntifs.h, 0x1c bytes).
#[repr(C)]
pub struct ReparseGuidDataBuffer {
    pub reparse_tag: Field<u32>,
    pub reparse_data_length: Field<u16>,
    pub reserved: Field<u16>,
    pub reparse_guid: Guid,
    /// `GenericReparseBuffer.DataBuffer[1]`
    pub data_buffer: [Field<u8>; 1],
    _pad_19: Reserved<0x3>,
}

unsafe impl NtStruct for ReparseGuidDataBuffer {}

const _: () = {
    assert!(core::mem::size_of::<ReparseGuidDataBuffer>() == 0x1c);
    assert!(core::mem::offset_of!(ReparseGuidDataBuffer, reparse_data_length) == 0x4);
    assert!(core::mem::offset_of!(ReparseGuidDataBuffer, reparse_guid) == 0x8);
    assert!(core::mem::offset_of!(ReparseGuidDataBuffer, data_buffer) == 0x18);
};
