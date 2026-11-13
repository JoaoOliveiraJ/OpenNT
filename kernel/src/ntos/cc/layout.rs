//! Constantes do Cache Manager e os corpos nativos privados do Cc.
//!
//! Os layouts que drivers enxergam vêm de `inc::types`: `SectionObjectPointers`,
//! `FileObject`, `Irp`, `Mdl` (gerados) e `extra_cc::{SharedCacheMap,
//! PrivateCacheMap, Vacb, CacheManagerCallbacks, CacheUninitializeEvent,
//! PublicBcb, CcFileSizes}`. Aqui ficam as constantes (códigos de nó, bits de
//! Flags, flags de MAP_/PIN_/purge, NTSTATUS) e os dois corpos internos do
//! Cc que não constam de símbolo algum: o BCB (prefixo PUBLIC_BCB; campos
//! conferidos na desmontagem de CcSetDirtyPinnedData, CcRemapBcb,
//! CcRepinBcb e CcGetFileObjectFromBcb) e o OBCB.

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::extra_cc::PublicBcb;
use crate::ntos::inc::types::{Eresource, LargeInteger, ListEntry};

/// VACB_MAPPING_GRANULARITY: uma vista do cache cobre 256 KB do arquivo.
pub const VIEW_SIZE: u64 = 0x4_0000;
pub const VIEW_SHIFT: u32 = 18;
pub const PAGE_SIZE: u64 = 0x1000;
pub const PAGES_PER_VIEW: u64 = VIEW_SIZE / PAGE_SIZE;

/// Códigos de nó (NodeTypeCode) do Cc.
pub const NTC_OBCB: i16 = 0x2FA;
pub const NTC_BCB: i16 = 0x2FD;
pub const NTC_PRIVATE_CACHE_MAP: i16 = 0x2FE;
pub const NTC_SHARED_CACHE_MAP: i16 = 0x2FF;

/// Bits de SHARED_CACHE_MAP.Flags vistos na desmontagem.
pub mod scm_flags {
    /// CcSetAdditionalCacheAttributes(DisableReadAhead).
    pub const DISABLE_READ_AHEAD: u32 = 0x1;
    /// CcSetAdditionalCacheAttributes(DisableWriteBehind) liga 0x202 e desliga só 0x2.
    pub const DISABLE_WRITE_BEHIND: u32 = 0x2;
    pub const MODIFIED_WRITE_DISABLED: u32 = 0x200;
    /// PinAccess do CcInitializeCacheMap (o encolhimento não purga).
    pub const PIN_ACCESS: u32 = 0x4;
    /// CcGetFileObjectFromSectionPtrs marca o bit 20.
    pub const FILE_OBJECT_QUERIED: u32 = 1 << 20;
    /// CcSetParallelFlushFile.
    pub const PARALLEL_FLUSH: u32 = 1 << 18;
    /// CcSetLogHandleForFileEx: fluxo com log.
    pub const LOGGED_STREAM: u32 = 1 << 24;
    /// CcSetAdditionalCacheAttributesEx: CcSetAdditionalCacheAttributes não é chamada.
    pub const ATTRIBUTES_LOCKED: u32 = 0x2000;
}

/// FILE_OBJECT.Flags usados pelo Cc (wdm.h).
pub const FO_WRITE_THROUGH: u32 = 0x10;
pub const FO_TEMPORARY_FILE: u32 = 0x8000;

/// Flags de CcMapData / CcPinRead / CcPreparePinWrite (ntifs.h).
pub mod pin_flags {
    pub const WAIT: u32 = 0x1;
    pub const EXCLUSIVE: u32 = 0x2;
    pub const NO_READ: u32 = 0x4;
    pub const IF_BCB: u32 = 0x8;
    pub const MAP_NO_READ: u32 = 0x10;
}

/// Flags de CcPurgeCacheSection.
pub mod purge_flags {
    pub const UNINITIALIZE_CACHE_MAPS: u32 = 0x1;
    pub const DO_NOT_RETRY_PURGE: u32 = 0x2;
    pub const DO_NOT_PURGE_DIRTY_PAGES: u32 = 0x4;
}

/// Flags de CcCoherencyFlushAndPurgeCache.
pub mod coherency_flags {
    pub const NO_PURGE: u32 = 0x1;
}

/// IRP.Flags de IoPageReadEx / IoSynchronousPageWriteEx:
/// IRP_PAGING_IO | IRP_NOCACHE | IRP_SYNCHRONOUS_PAGING_IO.
pub const PAGING_IRP_FLAGS: u32 = 0x43;
/// MDL_IO_PAGE_READ (MDL das leituras de página).
pub const MDL_IO_PAGE_READ: i16 = 0x40;
pub const MDL_PAGES_LOCKED: i16 = 0x2;
pub const MDL_SOURCE_IS_NONPAGED_POOL: i16 = 0x4;

/// NTSTATUS usados pelo Cc.
pub mod status {
    pub const SUCCESS: u32 = 0;
    pub const PENDING: u32 = 0x103;
    pub const CACHE_PAGE_LOCKED: u32 = 0x115;
    pub const END_OF_FILE: u32 = 0xC000_0011;
    pub const INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
    pub const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub const INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
    pub const INVALID_USER_BUFFER: u32 = 0xC000_00E8;
    pub const UNEXPECTED_IO_ERROR: u32 = 0xC000_00E9;
    pub const PURGE_FAILED: u32 = 0xC000_0435;
    /// O status que exige CcErrorCallbackRoutine (CcIsCacheManagerCallbackNeeded).
    pub const CROSS_PARTITION_DRAIN: u32 = 0xC000_A008;
}

/// O BCB do Cc (0xC0 bytes; nenhum símbolo o descreve). Os primeiros 0x10
/// bytes são o PUBLIC_BCB do ntifs.h (`NodeByteSize` sobreposto por
/// `Dirty`/`Reserved`); o ERESOURCE ocupa exatamente 0x48..0xB0.
#[repr(C)]
pub struct Bcb {
    pub node_type_code: Field<i16>,
    pub dirty: Field<u8>,
    pub reserved: Field<u8>,
    /// PUBLIC_BCB.MappedLength.
    pub byte_length: Field<u32>,
    /// PUBLIC_BCB.MappedFileOffset.
    pub file_offset: LargeInteger,
    pub bcb_links: ListEntry,
    pub beyond_last_byte: LargeInteger,
    pub oldest_lsn: LargeInteger,
    pub newest_lsn: LargeInteger,
    /// -> `_VACB`
    pub vacb: Field<u64>,
    pub pin_count: Field<u32>,
    _pad_44: Reserved<0x4>,
    pub resource: Eresource,
    /// -> `_SHARED_CACHE_MAP`
    pub shared_cache_map: Field<u64>,
    /// -> `void` (dados fixados na vista)
    pub base_address: Field<u64>,
}

// SAFETY: #[repr(C)] só de células (Field/Reserved/NtStruct).
unsafe impl NtStruct for Bcb {}

impl Bcb {
    /// A vista PUBLIC_BCB do mesmo objeto (o que o file system enxerga).
    pub fn public(&self) -> &PublicBcb {
        // SAFETY: PUBLIC_BCB é o prefixo do BCB (asserções abaixo).
        unsafe { PublicBcb::at(self.address()) }
    }
}

const _: () = {
    assert!(core::mem::size_of::<Bcb>() == 0xC0);
    assert!(core::mem::offset_of!(Bcb, dirty) == 0x2);
    assert!(core::mem::offset_of!(Bcb, byte_length) == 0x4);
    assert!(core::mem::offset_of!(Bcb, file_offset) == 0x8);
    assert!(core::mem::offset_of!(Bcb, bcb_links) == 0x10);
    assert!(core::mem::offset_of!(Bcb, beyond_last_byte) == 0x20);
    assert!(core::mem::offset_of!(Bcb, oldest_lsn) == 0x28);
    assert!(core::mem::offset_of!(Bcb, newest_lsn) == 0x30);
    assert!(core::mem::offset_of!(Bcb, vacb) == 0x38);
    assert!(core::mem::offset_of!(Bcb, pin_count) == 0x40);
    assert!(core::mem::offset_of!(Bcb, resource) == 0x48);
    assert!(core::mem::offset_of!(Bcb, shared_cache_map) == 0xB0);
    assert!(core::mem::offset_of!(Bcb, base_address) == 0xB8);
    assert!(core::mem::offset_of!(PublicBcb, mapped_length) == core::mem::offset_of!(Bcb, byte_length));
    assert!(core::mem::offset_of!(PublicBcb, mapped_file_offset) == core::mem::offset_of!(Bcb, file_offset));
};

/// OBCB (overlap BCB, NodeTypeCode 0x2FA): o vetor de BCBs terminado em NULL
/// a partir de +0x10 que o CcUnpinData percorre (ANYSIZE_ARRAY).
#[repr(C)]
pub struct Obcb {
    pub node_type_code: Field<i16>,
    pub node_byte_size: Field<i16>,
    pub byte_length: Field<u32>,
    pub file_offset: LargeInteger,
    /// -> `_BCB` [ANYSIZE_ARRAY]
    pub bcbs: [Field<u64>; 1],
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for Obcb {}

impl Obcb {
    /// `Bcbs[index]`.
    pub fn bcb(&self, index: u64) -> &Field<u64> {
        // SAFETY: o vetor continua além do tipo até o NULL terminal.
        unsafe { Field::<u64>::at(self.bcbs[0].address() + index * 8) }
    }
}

const _: () = {
    assert!(core::mem::offset_of!(Obcb, bcbs) == 0x10);
};
