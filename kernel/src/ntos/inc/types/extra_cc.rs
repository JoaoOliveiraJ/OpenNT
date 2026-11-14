//! Estruturas públicas do Cache Manager (`ntifs.h`) que os símbolos do
//! ntoskrnl não têm: `PUBLIC_BCB` e `CC_FILE_SIZES`.
//!
//! Mantido à mão no estilo de `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`,
//! ponteiros como `Field<u64>` com o tipo apontado no comentário, tamanhos e
//! offsets conferidos em compilação.
//!
//! Os layouts do Cc que constam dos símbolos (`_SHARED_CACHE_MAP`,
//! `_PRIVATE_CACHE_MAP`, `_VACB`, `_CACHE_MANAGER_CALLBACKS`,
//! `_CACHE_UNINITIALIZE_EVENT`, `_LOGGED_STREAM_CALLBACK_V1`) são gerados
//! (`types/cc.rs`) e ficam reexportados aqui.

use super::*;

pub use super::{
    CacheManagerCallbacks, CacheUninitializeEvent, LoggedStreamCallbackV1, PrivateCacheMap, SharedCacheMap, Vacb,
    VacbOverlay,
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
