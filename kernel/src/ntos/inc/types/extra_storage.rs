//! Estruturas do I/O, do PnP e do WHEA usadas pelo suporte à pilha de
//! armazenamento que os símbolos do ntoskrnl não têm, no estilo de
//! `inc/types`: `#[repr(C)]` de células, tamanhos e offsets conferidos em
//! compilação, cada uma do cabeçalho público citado.
//!
//! - `BusInterfaceStandard` — BUS_INTERFACE_STANDARD (wdm.h), 0x40
//! - `IoReportInterruptActiveStateParameters` —
//!   IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS (wdm.h), 0x10
//! - `IoInterruptMessageInfoEntry` / `IoInterruptMessageInfo` —
//!   IO_INTERRUPT_MESSAGE_INFO_ENTRY / IO_INTERRUPT_MESSAGE_INFO (wdm.h), 0x30 / 0x38
//! - `LoaderPartitionInformationEx` / `BootdiskInformationLite` —
//!   LOADER_PARTITION_INFORMATION_EX / BOOTDISK_INFORMATION_LITE (ntddk.h), 0x1C / 0x20
//! - `WheaErrorSourceConfigurationDeviceDriverV1` / `WheaErrorSourceConfigurationDeviceDriver` —
//!   WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 / _DEVICE_DRIVER (ntddk.h), 0x2C / 0x54
//!
//! As estruturas do WHEA são `#pragma pack(1)` no ntddk.h: os membros de 64 bits
//! fora do alinhamento natural são `UnalignedField`, e os demais estão em
//! offsets naturalmente alinhados (alinhamento do tipo Rust: 4).
//!
//! `_INTERFACE`, `_DEVICE_DESCRIPTION`, `_POP_IRP_DATA` (o bloco do Power
//! Manager no Context da última posição de pilha de um IRP de energia) e
//! `_WHEA_TIMESTAMP`, `_WHEA_ERROR_RECORD_HEADER`, `_WHEA_ERROR_PACKET_V2`,
//! `_WHEA_DEVICE_DRIVER_DESCRIPTOR` e `_WHEA_ERROR_SOURCE_DESCRIPTOR`
//! constam dos símbolos e são geradas (`types/io.rs`, `po.rs`, `hal.rs`);
//! ficam reexportadas aqui.

use crate::ntos::inc::field::{Field, NtStruct, Reserved, UnalignedField};
use crate::ntos::inc::types::Guid;

pub use super::{
    DeviceDescription, Interface, PopIrpData, WheaDeviceDriverDescriptor, WheaErrorPacketV2, WheaErrorRecordHeader,
    WheaErrorSourceDescriptor, WheaTimestamp,
};

/// BUS_INTERFACE_STANDARD (wdm.h).
#[repr(C)]
pub struct BusInterfaceStandard {
    pub interface: Interface,
    /// -> `PTRANSLATE_BUS_ADDRESS`
    pub translate_bus_address: Field<u64>,
    /// -> `PGET_DMA_ADAPTER`
    pub get_dma_adapter: Field<u64>,
    /// -> `PGET_SET_DEVICE_DATA`
    pub set_bus_data: Field<u64>,
    /// -> `PGET_SET_DEVICE_DATA`
    pub get_bus_data: Field<u64>,
}

unsafe impl NtStruct for BusInterfaceStandard {}

const _: () = {
    assert!(core::mem::size_of::<BusInterfaceStandard>() == 0x40);
    assert!(core::mem::offset_of!(BusInterfaceStandard, translate_bus_address) == 0x20);
    assert!(core::mem::offset_of!(BusInterfaceStandard, get_dma_adapter) == 0x28);
    assert!(core::mem::offset_of!(BusInterfaceStandard, set_bus_data) == 0x30);
    assert!(core::mem::offset_of!(BusInterfaceStandard, get_bus_data) == 0x38);
};

/// IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS (wdm.h).
#[repr(C)]
pub struct IoReportInterruptActiveStateParameters {
    /// CONNECT_FULLY_SPECIFIED (1), _LINE_BASED (2), _MESSAGE_BASED (3), _FULLY_SPECIFIED_GROUP (4).
    pub version: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// União ConnectionContext: PKINTERRUPT ou PIO_INTERRUPT_MESSAGE_INFO.
    pub connection_context: Field<u64>,
}

unsafe impl NtStruct for IoReportInterruptActiveStateParameters {}

const _: () = {
    assert!(core::mem::size_of::<IoReportInterruptActiveStateParameters>() == 0x10);
    assert!(core::mem::offset_of!(IoReportInterruptActiveStateParameters, connection_context) == 0x8);
};

/// IO_INTERRUPT_MESSAGE_INFO_ENTRY (wdm.h).
#[repr(C)]
pub struct IoInterruptMessageInfoEntry {
    pub message_address: Field<i64>,
    pub target_processor_set: Field<u64>,
    /// -> `KINTERRUPT`
    pub interrupt_object: Field<u64>,
    pub message_data: Field<u32>,
    pub vector: Field<u32>,
    pub irql: Field<u8>,
    _pad_21: Reserved<0x3>,
    pub mode: Field<u32>,
    pub polarity: Field<u32>,
    _pad_2c: Reserved<0x4>,
}

unsafe impl NtStruct for IoInterruptMessageInfoEntry {}

const _: () = {
    assert!(core::mem::size_of::<IoInterruptMessageInfoEntry>() == 0x30);
    assert!(core::mem::offset_of!(IoInterruptMessageInfoEntry, interrupt_object) == 0x10);
    assert!(core::mem::offset_of!(IoInterruptMessageInfoEntry, message_data) == 0x18);
    assert!(core::mem::offset_of!(IoInterruptMessageInfoEntry, irql) == 0x20);
    assert!(core::mem::offset_of!(IoInterruptMessageInfoEntry, mode) == 0x24);
    assert!(core::mem::offset_of!(IoInterruptMessageInfoEntry, polarity) == 0x28);
};

/// IO_INTERRUPT_MESSAGE_INFO (wdm.h): cabeçalho e o vetor de MessageCount entradas.
#[repr(C)]
pub struct IoInterruptMessageInfo {
    pub unified_irql: Field<u8>,
    _pad_1: Reserved<0x3>,
    pub message_count: Field<u32>,
    pub message_info: [IoInterruptMessageInfoEntry; 1],
}

unsafe impl NtStruct for IoInterruptMessageInfo {}

const _: () = {
    assert!(core::mem::size_of::<IoInterruptMessageInfo>() == 0x38);
    assert!(core::mem::offset_of!(IoInterruptMessageInfo, message_count) == 0x4);
    assert!(core::mem::offset_of!(IoInterruptMessageInfo, message_info) == 0x8);
};

/// LOADER_PARTITION_INFORMATION_EX (ntddk.h).
#[repr(C)]
pub struct LoaderPartitionInformationEx {
    pub partition_style: Field<u32>,
    pub partition_number: Field<u32>,
    /// União { ULONG Signature; GUID DeviceId; }.
    pub device_id: Guid,
    pub flags: Field<u32>,
}

unsafe impl NtStruct for LoaderPartitionInformationEx {}

const _: () = {
    assert!(core::mem::size_of::<LoaderPartitionInformationEx>() == 0x1C);
    assert!(core::mem::offset_of!(LoaderPartitionInformationEx, device_id) == 0x8);
    assert!(core::mem::offset_of!(LoaderPartitionInformationEx, flags) == 0x18);
};

/// BOOTDISK_INFORMATION_LITE (ntddk.h): NumberEntries e o vetor de entradas.
#[repr(C)]
pub struct BootdiskInformationLite {
    pub number_entries: Field<u32>,
    pub entries: [LoaderPartitionInformationEx; 1],
}

unsafe impl NtStruct for BootdiskInformationLite {}

const _: () = {
    assert!(core::mem::size_of::<BootdiskInformationLite>() == 0x20);
    assert!(core::mem::offset_of!(BootdiskInformationLite, entries) == 0x4);
};

/// WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 (ntddk.h), `#pragma pack(1)`.
#[repr(C)]
pub struct WheaErrorSourceConfigurationDeviceDriverV1 {
    pub version: Field<u32>,
    pub source_guid: Guid,
    pub log_tag: Field<u16>,
    _reserved: Reserved<0x6>,
    /// -> `PFN_WHEA_ERROR_SOURCE_INITIALIZE_DEVICE_DRIVER`
    pub initialize: UnalignedField<u64>,
    /// -> `PFN_WHEA_ERROR_SOURCE_UNINITIALIZE_DEVICE_DRIVER`
    pub uninitialize: UnalignedField<u64>,
}

unsafe impl NtStruct for WheaErrorSourceConfigurationDeviceDriverV1 {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorSourceConfigurationDeviceDriverV1>() == 0x2C);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDeviceDriverV1, source_guid) == 0x4);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDeviceDriverV1, log_tag) == 0x14);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDeviceDriverV1, initialize) == 0x1C);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDeviceDriverV1, uninitialize) == 0x24);
};

/// WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER (versão 2; ntddk.h), `#pragma pack(1)`.
#[repr(C)]
pub struct WheaErrorSourceConfigurationDeviceDriver {
    pub v1: WheaErrorSourceConfigurationDeviceDriverV1,
    pub max_section_data_length: Field<u32>,
    pub max_sections_per_report: Field<u32>,
    pub creator_id: Guid,
    pub partition_id: Guid,
}

unsafe impl NtStruct for WheaErrorSourceConfigurationDeviceDriver {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorSourceConfigurationDeviceDriver>() == 0x54);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDeviceDriver, max_section_data_length) == 0x2C);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDeviceDriver, max_sections_per_report) == 0x30);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDeviceDriver, creator_id) == 0x34);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDeviceDriver, partition_id) == 0x44);
};
