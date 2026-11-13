//! Estruturas usadas pelo suporte ao ntfs.sys / exfat.sys que não constam do
//! conjunto gerado de `inc/types` nem de `wdk.rs`.
//!
//! Mantido à mão no estilo de `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`,
//! ponteiros como `Field<u64>` com o tipo apontado no comentário, layout x64
//! conferido em compilação. Origem de cada uma:
//!
//! - `BaseMcb` — BASE_MCB (ntifs.h), 0x18
//! - `ExPushLockAutoExpand` — _EX_PUSH_LOCK_AUTO_EXPAND (ntkrnlmp.pdb, fora do
//!   conjunto gerado), 0x10
//! - `RtlBitmapRun` — RTL_BITMAP_RUN (wdm.h), 0x8
//! - `RtlModuleBasicInfo` / `RtlModuleExtendedInfo` — RTL_MODULE_BASIC_INFO /
//!   RTL_MODULE_EXTENDED_INFO (aux_klib.h), 0x8 / 0x110
//! - `SeSecurityDescriptor` / `SeAccessRequest` / `SeAccessReply` —
//!   SE_SECURITY_DESCRIPTOR / SE_ACCESS_REQUEST / SE_ACCESS_REPLY (ntifs.h), 0x10 / 0x38 / 0x28
//! - `FileFullEaInformation` / `FileQuotaInformation` — FILE_FULL_EA_INFORMATION
//!   (wdm.h) / FILE_QUOTA_INFORMATION (ntifs.h), 0xC / 0x38
//! - `ShareAccess` / `LinkShareAccess` — SHARE_ACCESS / LINK_SHARE_ACCESS (wdm.h), 0x1C / 0xC
//! - `IopIrpExtension` — _IOP_IRP_EXTENSION (ntkrnlmp.pdb, fora do conjunto
//!   gerado), 0x50
//! - `ReparseDataBuffer` (+ vistas) / `ReparseGuidDataBuffer` —
//!   REPARSE_DATA_BUFFER / REPARSE_GUID_DATA_BUFFER (ntifs.h), 0x18 / 0x1C
//!
//! FSRTL_ADVANCED_FCB_HEADER e FSRTL_PER_FILE_CONTEXT vêm de `extra_fsrtl.rs`
//! e TUNNEL de `extra_fs_fat.rs` (não duplicados aqui).
// extra_fs_ntfs: gerado por merge_extra_fs_ntfs.py

use super::*;

// ---- main ----

/// `_BASE_MCB` (ntifs.h): o mapa VBN -> LBN dos file systems
/// (FsRtl*BaseMcb*). `Mapping` aponta para os pares internos do largemcb.c
/// (8 bytes cada; ver `fsrtl::mcb`). O `_LARGE_MCB` público é
/// `{ PKGUARDED_MUTEX GuardedMutex; BASE_MCB BaseMcb; }`.
#[repr(C)]
pub struct BaseMcb {
    pub maximum_pair_count: Field<u32>,
    pub pair_count: Field<u32>,
    pub pool_type: Field<u16>,
    pub flags: Field<u16>,
    _pad_c: Reserved<0x4>,
    /// -> `MAPPING[MaximumPairCount]` (interno do largemcb.c)
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

/// `_EX_PUSH_LOCK_AUTO_EXPAND` (0x10 bytes; consta do ntkrnlmp.pdb mas fora
/// do conjunto gerado). `State` é `_EX_PUSH_LOCK_AUTO_EXPAND_STATE`
/// (Expanded:1, Transitioning:1, Pageable:1, o resto = ponteiro da tabela em
/// leque & ~7).
#[repr(C)]
pub struct ExPushLockAutoExpand {
    pub local_lock: ExPushLock,
    pub state: Field<u32>,
    pub stats: Field<u32>,
}

unsafe impl NtStruct for ExPushLockAutoExpand {}

impl ExPushLockAutoExpand {
    /// `State.Expanded`: bits 0..=0 de `state`.
    pub const EXPANDED_SHIFT: u32 = 0;
    pub const EXPANDED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn expanded(&self) -> u32 {
        self.state.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_expanded(&self, value: u32) {
        self.state.set_bits(0, 1, value as u64)
    }
    /// `State.Transitioning`: bits 1..=1 de `state`.
    pub const TRANSITIONING_SHIFT: u32 = 1;
    pub const TRANSITIONING_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn transitioning(&self) -> u32 {
        self.state.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_transitioning(&self, value: u32) {
        self.state.set_bits(1, 1, value as u64)
    }
    /// `State.Pageable`: bits 2..=2 de `state`.
    pub const PAGEABLE_SHIFT: u32 = 2;
    pub const PAGEABLE_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn pageable(&self) -> u32 {
        self.state.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_pageable(&self, value: u32) {
        self.state.set_bits(2, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ExPushLockAutoExpand>() == 0x10);
    assert!(core::mem::offset_of!(ExPushLockAutoExpand, local_lock) == 0x0);
    assert!(core::mem::offset_of!(ExPushLockAutoExpand, state) == 0x8);
    assert!(core::mem::offset_of!(ExPushLockAutoExpand, stats) == 0xc);
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

/// `_IOP_IRP_EXTENSION` (ntkrnlmp.pdb 19041, tipo privado do I/O Manager que
/// o gerador não emitiu): o bloco apontado por `Irp->IrpExtension`
/// (`extra_io::IrpExtensionField`). `TypesAllocated` é o bitmap dos tipos
/// (1 Timestamp, 2 genérica, 4 ZeroingOffset, 5 FsTrackOffset, 6 atribuição de
/// disco, 7 AdapterCryptoParameters, 8 DriverFlags, 9 CopyInformation).
#[repr(C)]
pub struct IopIrpExtension {
    /// Bits: Allocated (0), PropagateId (1), SpareBits (2..15).
    pub extension_flags: Field<u16>,
    pub types_allocated: Field<u16>,
    pub generic_extension: Field<u32>,
    /// -> `void`
    pub verifier_context: Field<u64>,
    pub disk_io_attribution_handle: Field<u64>,
    pub activity_id: Guid,
    /// União em +0x28: `Timestamp` (LARGE_INTEGER), `ZeroingOffset` (ULONG),
    /// `FsTrackOffsetBlob` (-> `IO_IRP_EXT_TRACK_OFFSET_HEADER`, este campo) e
    /// o início de `AdapterCryptoParameters` (16 bytes).
    pub fs_track_offset_blob: Field<u64>,
    /// `FsTrackedOffset` (LONGLONG), parceiro do blob na mesma união.
    pub fs_tracked_offset: Field<u64>,
    pub driver_flags: Field<u64>,
    /// `_COPY_INFORMATION` (16 bytes).
    pub copy_information: [Field<u64>; 2],
}

unsafe impl NtStruct for IopIrpExtension {}

const _: () = {
    assert!(core::mem::size_of::<IopIrpExtension>() == 0x50);
    assert!(core::mem::offset_of!(IopIrpExtension, types_allocated) == 0x2);
    assert!(core::mem::offset_of!(IopIrpExtension, generic_extension) == 0x4);
    assert!(core::mem::offset_of!(IopIrpExtension, verifier_context) == 0x8);
    assert!(core::mem::offset_of!(IopIrpExtension, activity_id) == 0x18);
    assert!(core::mem::offset_of!(IopIrpExtension, fs_track_offset_blob) == 0x28);
    assert!(core::mem::offset_of!(IopIrpExtension, fs_tracked_offset) == 0x30);
    assert!(core::mem::offset_of!(IopIrpExtension, driver_flags) == 0x38);
    assert!(core::mem::offset_of!(IopIrpExtension, copy_information) == 0x40);
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
