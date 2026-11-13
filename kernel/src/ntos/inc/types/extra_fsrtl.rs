//! Estruturas públicas do FsRtl ausentes do conjunto gerado (`ntifs.h` /
//! `winioctl.h` do WDK; `_ECP_LIST` e `_FSRTL_ADVANCED_FCB_HEADER` conferem
//! com o `ntkrnlmp.pdb` 19041), no estilo de `inc/types`: `#[repr(C)]` de
//! células, tamanhos e offsets conferidos em compilação.
//!
//! - `FsrtlCommonFcbHeader` — FSRTL_COMMON_FCB_HEADER (ntifs.h), 0x30
//! - `FsrtlAdvancedFcbHeader` — FSRTL_ADVANCED_FCB_HEADER (ntifs.h; PDB), 0x68
//! - `FileLockInfo` — FILE_LOCK_INFO (ntifs.h), 0x30
//! - `FileLock` — FILE_LOCK (ntifs.h), 0x60
//! - `EcpList` — _ECP_LIST (PDB; opaco no ntifs.h), 0x18
//! - `FsrtlPerStreamContext` — FSRTL_PER_STREAM_CONTEXT (ntifs.h), 0x28
//! - `FsrtlPerFileContext` — FSRTL_PER_FILE_CONTEXT (ntifs.h), 0x28
//! - `FsrtlPerFileobjectContext` — FSRTL_PER_FILEOBJECT_CONTEXT (ntifs.h), 0x20
//! - `OplockKeyContext` — OPLOCK_KEY_CONTEXT (ntifs.h), 0x28
//! - `RequestOplockInputBuffer` — REQUEST_OPLOCK_INPUT_BUFFER (winioctl.h), 0xC

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{Guid, LargeInteger, ListEntry};

/// FSRTL_COMMON_FCB_HEADER (ntifs.h).
#[repr(C)]
pub struct FsrtlCommonFcbHeader {
    pub node_type_code: Field<i16>,
    pub node_byte_size: Field<i16>,
    pub flags: Field<u8>,
    pub is_fast_io_possible: Field<u8>,
    pub flags2: Field<u8>,
    /// `Reserved : 4`, `Version : 4`.
    pub bitfield_7: Field<u8>,
    /// -> `_ERESOURCE`
    pub resource: Field<u64>,
    /// -> `_ERESOURCE`
    pub paging_io_resource: Field<u64>,
    pub allocation_size: LargeInteger,
    pub file_size: LargeInteger,
    pub valid_data_length: LargeInteger,
}

unsafe impl NtStruct for FsrtlCommonFcbHeader {}

impl FsrtlCommonFcbHeader {
    /// `Version`: bits 4..=7 de `bitfield_7`.
    pub const VERSION_SHIFT: u32 = 4;
    pub const VERSION_MASK: u32 = 0xF0;
    #[inline(always)]
    pub fn version(&self) -> u32 {
        self.bitfield_7.bits(4, 4) as u32
    }
    #[inline(always)]
    pub fn set_version(&self, value: u32) {
        self.bitfield_7.set_bits(4, 4, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<FsrtlCommonFcbHeader>() == 0x30);
    assert!(core::mem::offset_of!(FsrtlCommonFcbHeader, flags2) == 0x6);
    assert!(core::mem::offset_of!(FsrtlCommonFcbHeader, bitfield_7) == 0x7);
    assert!(core::mem::offset_of!(FsrtlCommonFcbHeader, resource) == 0x8);
    assert!(core::mem::offset_of!(FsrtlCommonFcbHeader, allocation_size) == 0x18);
    assert!(core::mem::offset_of!(FsrtlCommonFcbHeader, file_size) == 0x20);
    assert!(core::mem::offset_of!(FsrtlCommonFcbHeader, valid_data_length) == 0x28);
};

/// FSRTL_ADVANCED_FCB_HEADER (ntifs.h): o cabeçalho comum e as extensões de
/// filtros (PDB `_FSRTL_ADVANCED_FCB_HEADER`, 0x68, campos achatados).
#[repr(C)]
pub struct FsrtlAdvancedFcbHeader {
    pub node_type_code: Field<i16>,
    pub node_byte_size: Field<i16>,
    pub flags: Field<u8>,
    pub is_fast_io_possible: Field<u8>,
    pub flags2: Field<u8>,
    /// `Reserved : 4`, `Version : 4`.
    pub bitfield_7: Field<u8>,
    /// -> `_ERESOURCE`
    pub resource: Field<u64>,
    /// -> `_ERESOURCE`
    pub paging_io_resource: Field<u64>,
    pub allocation_size: LargeInteger,
    pub file_size: LargeInteger,
    pub valid_data_length: LargeInteger,
    /// -> `_FAST_MUTEX`
    pub fast_mutex: Field<u64>,
    pub filter_contexts: ListEntry,
    /// EX_PUSH_LOCK (acesso atômico).
    pub push_lock: Field<u64>,
    /// -> `PVOID` (o `PerFileContextPointer`)
    pub file_context_support_pointer: Field<u64>,
    /// `Oplock` / `ReservedForRemote` (união).
    pub oplock: Field<u64>,
    /// -> `void`
    pub reserved_context: Field<u64>,
}

unsafe impl NtStruct for FsrtlAdvancedFcbHeader {}

impl FsrtlAdvancedFcbHeader {
    /// `Version`: bits 4..=7 de `bitfield_7`.
    pub const VERSION_SHIFT: u32 = 4;
    pub const VERSION_MASK: u32 = 0xF0;
    #[inline(always)]
    pub fn version(&self) -> u32 {
        self.bitfield_7.bits(4, 4) as u32
    }
    #[inline(always)]
    pub fn set_version(&self, value: u32) {
        self.bitfield_7.set_bits(4, 4, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<FsrtlAdvancedFcbHeader>() == 0x68);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, flags2) == 0x6);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, bitfield_7) == 0x7);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, file_size) == 0x20);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, fast_mutex) == 0x30);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, filter_contexts) == 0x38);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, push_lock) == 0x48);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, file_context_support_pointer) == 0x50);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, oplock) == 0x58);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, reserved_context) == 0x60);
};

/// FILE_LOCK_INFO (ntifs.h).
#[repr(C)]
pub struct FileLockInfo {
    pub starting_byte: LargeInteger,
    pub length: LargeInteger,
    pub exclusive_lock: Field<u8>,
    _pad_11: Reserved<0x3>,
    pub key: Field<u32>,
    /// -> `_FILE_OBJECT`
    pub file_object: Field<u64>,
    /// -> `void`
    pub process_id: Field<u64>,
    pub ending_byte: LargeInteger,
}

unsafe impl NtStruct for FileLockInfo {}

const _: () = {
    assert!(core::mem::size_of::<FileLockInfo>() == 0x30);
    assert!(core::mem::offset_of!(FileLockInfo, length) == 0x8);
    assert!(core::mem::offset_of!(FileLockInfo, exclusive_lock) == 0x10);
    assert!(core::mem::offset_of!(FileLockInfo, key) == 0x14);
    assert!(core::mem::offset_of!(FileLockInfo, file_object) == 0x18);
    assert!(core::mem::offset_of!(FileLockInfo, process_id) == 0x20);
    assert!(core::mem::offset_of!(FileLockInfo, ending_byte) == 0x28);
};

/// FILE_LOCK (ntifs.h).
#[repr(C)]
pub struct FileLock {
    /// -> `fn` (PCOMPLETE_LOCK_IRP_ROUTINE)
    pub complete_lock_irp_routine: Field<u64>,
    /// -> `fn` (PUNLOCK_ROUTINE)
    pub unlock_routine: Field<u64>,
    pub fast_io_is_questionable: Field<u8>,
    pub spare_c: [Field<u8>; 3],
    _pad_14: Reserved<0x4>,
    /// -> `void` (LOCK_INFO, privado do FsRtl)
    pub lock_information: Field<u64>,
    pub last_returned_lock_info: FileLockInfo,
    /// -> `void`
    pub last_returned_lock: Field<u64>,
    /// `LONG volatile` (acesso atômico).
    pub lock_requests_in_progress: Field<i32>,
    _pad_5c: Reserved<0x4>,
}

unsafe impl NtStruct for FileLock {}

const _: () = {
    assert!(core::mem::size_of::<FileLock>() == 0x60);
    assert!(core::mem::offset_of!(FileLock, unlock_routine) == 0x8);
    assert!(core::mem::offset_of!(FileLock, fast_io_is_questionable) == 0x10);
    assert!(core::mem::offset_of!(FileLock, lock_information) == 0x18);
    assert!(core::mem::offset_of!(FileLock, last_returned_lock_info) == 0x20);
    assert!(core::mem::offset_of!(FileLock, last_returned_lock) == 0x50);
    assert!(core::mem::offset_of!(FileLock, lock_requests_in_progress) == 0x58);
};

/// _ECP_LIST (PDB; o ECP_LIST é opaco no ntifs.h).
#[repr(C)]
pub struct EcpList {
    pub signature: Field<u32>,
    pub flags: Field<u32>,
    pub ecp_list: ListEntry,
}

unsafe impl NtStruct for EcpList {}

const _: () = {
    assert!(core::mem::size_of::<EcpList>() == 0x18);
    assert!(core::mem::offset_of!(EcpList, flags) == 0x4);
    assert!(core::mem::offset_of!(EcpList, ecp_list) == 0x8);
};

/// FSRTL_PER_STREAM_CONTEXT (ntifs.h).
#[repr(C)]
pub struct FsrtlPerStreamContext {
    pub links: ListEntry,
    /// -> `void`
    pub owner_id: Field<u64>,
    /// -> `void`
    pub instance_id: Field<u64>,
    /// -> `fn` (PFREE_FUNCTION)
    pub free_callback: Field<u64>,
}

unsafe impl NtStruct for FsrtlPerStreamContext {}

const _: () = {
    assert!(core::mem::size_of::<FsrtlPerStreamContext>() == 0x28);
    assert!(core::mem::offset_of!(FsrtlPerStreamContext, owner_id) == 0x10);
    assert!(core::mem::offset_of!(FsrtlPerStreamContext, instance_id) == 0x18);
    assert!(core::mem::offset_of!(FsrtlPerStreamContext, free_callback) == 0x20);
};

/// FSRTL_PER_FILE_CONTEXT (ntifs.h).
#[repr(C)]
pub struct FsrtlPerFileContext {
    pub links: ListEntry,
    /// -> `void`
    pub owner_id: Field<u64>,
    /// -> `void`
    pub instance_id: Field<u64>,
    /// -> `fn` (PFREE_FUNCTION)
    pub free_callback: Field<u64>,
}

unsafe impl NtStruct for FsrtlPerFileContext {}

const _: () = {
    assert!(core::mem::size_of::<FsrtlPerFileContext>() == 0x28);
    assert!(core::mem::offset_of!(FsrtlPerFileContext, owner_id) == 0x10);
    assert!(core::mem::offset_of!(FsrtlPerFileContext, free_callback) == 0x20);
};

/// FSRTL_PER_FILEOBJECT_CONTEXT (ntifs.h).
#[repr(C)]
pub struct FsrtlPerFileobjectContext {
    pub links: ListEntry,
    /// -> `void`
    pub owner_id: Field<u64>,
    /// -> `void`
    pub instance_id: Field<u64>,
}

unsafe impl NtStruct for FsrtlPerFileobjectContext {}

const _: () = {
    assert!(core::mem::size_of::<FsrtlPerFileobjectContext>() == 0x20);
    assert!(core::mem::offset_of!(FsrtlPerFileobjectContext, owner_id) == 0x10);
    assert!(core::mem::offset_of!(FsrtlPerFileobjectContext, instance_id) == 0x18);
};

/// OPLOCK_KEY_CONTEXT (ntifs.h).
#[repr(C)]
pub struct OplockKeyContext {
    pub version: Field<u16>,
    /// OPLOCK_KEY_FLAG_PARENT_KEY (1) / OPLOCK_KEY_FLAG_TARGET_KEY (2).
    pub flags: Field<u16>,
    pub parent_oplock_key: Guid,
    pub target_oplock_key: Guid,
    pub reserved: Field<u32>,
}

unsafe impl NtStruct for OplockKeyContext {}

const _: () = {
    assert!(core::mem::size_of::<OplockKeyContext>() == 0x28);
    assert!(core::mem::offset_of!(OplockKeyContext, flags) == 0x2);
    assert!(core::mem::offset_of!(OplockKeyContext, parent_oplock_key) == 0x4);
    assert!(core::mem::offset_of!(OplockKeyContext, target_oplock_key) == 0x14);
    assert!(core::mem::offset_of!(OplockKeyContext, reserved) == 0x24);
};

/// REQUEST_OPLOCK_INPUT_BUFFER (winioctl.h).
#[repr(C)]
pub struct RequestOplockInputBuffer {
    pub structure_version: Field<u16>,
    pub structure_length: Field<u16>,
    pub requested_oplock_level: Field<u32>,
    pub flags: Field<u32>,
}

unsafe impl NtStruct for RequestOplockInputBuffer {}

const _: () = {
    assert!(core::mem::size_of::<RequestOplockInputBuffer>() == 0xC);
    assert!(core::mem::offset_of!(RequestOplockInputBuffer, requested_oplock_level) == 0x4);
    assert!(core::mem::offset_of!(RequestOplockInputBuffer, flags) == 0x8);
};
