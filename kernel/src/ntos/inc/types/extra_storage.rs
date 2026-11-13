//! Estruturas do I/O, do PnP, do Power Manager e do WHEA usadas pelo suporte
//! à pilha de armazenamento e ausentes do conjunto gerado, no estilo de
//! `inc/types`: `#[repr(C)]` de células, tamanhos e offsets conferidos em
//! compilação. As que constam do `ntkrnlmp.pdb` 19041 foram conferidas campo a
//! campo com ele; as demais vêm do cabeçalho público citado. O
//! _IOP_IRP_EXTENSION é o de `extra_fs_ntfs`.
//!
//! - `Interface` — INTERFACE (wdm.h; PDB), 0x20
//! - `BusInterfaceStandard` — BUS_INTERFACE_STANDARD (wdm.h), 0x40
//! - `DeviceDescription` — DEVICE_DESCRIPTION (wdm.h; PDB, versão 3), 0x40
//! - `IoReportInterruptActiveStateParameters` —
//!   IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS (wdm.h), 0x10
//! - `IoInterruptMessageInfoEntry` / `IoInterruptMessageInfo` —
//!   IO_INTERRUPT_MESSAGE_INFO_ENTRY / IO_INTERRUPT_MESSAGE_INFO (wdm.h), 0x30 / 0x38
//! - `LoaderPartitionInformationEx` / `BootdiskInformationLite` —
//!   LOADER_PARTITION_INFORMATION_EX / BOOTDISK_INFORMATION_LITE (ntddk.h), 0x1C / 0x20
//! - `PopIrpData` — _POP_IRP_DATA (PDB; o bloco do Power Manager no Context da
//!   última posição de pilha de um IRP de energia), 0x100
//! - `WheaTimestamp` — WHEA_TIMESTAMP (ntddk.h; PDB), 8
//! - `WheaErrorRecordHeader` — WHEA_ERROR_RECORD_HEADER (ntddk.h; PDB), 0x80
//! - `WheaErrorPacketV2` — WHEA_ERROR_PACKET_V2 (ntddk.h; PDB), 0x50
//! - `WheaDeviceDriverDescriptor` — WHEA_DEVICE_DRIVER_DESCRIPTOR (ntddk.h; PDB), 0x74
//! - `WheaErrorSourceDescriptor` — WHEA_ERROR_SOURCE_DESCRIPTOR (ntddk.h; PDB), 0x3CC
//! - `WheaErrorSourceConfigurationDeviceDriverV1` / `WheaErrorSourceConfigurationDeviceDriver` —
//!   WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 / _DEVICE_DRIVER (ntddk.h), 0x2C / 0x54
//!
//! As estruturas do WHEA são `#pragma pack(1)` no ntddk.h: os membros de 64 bits
//! fora do alinhamento natural são `UnalignedField`, e os demais estão em
//! offsets naturalmente alinhados (alinhamento do tipo Rust: 4).

use crate::ntos::inc::field::{Field, NtStruct, Reserved, UnalignedField};
use crate::ntos::inc::types::{Guid, InterfaceType, ListEntry};

/// INTERFACE (wdm.h).
#[repr(C)]
pub struct Interface {
    pub size: Field<u16>,
    pub version: Field<u16>,
    _pad_4: Reserved<0x4>,
    pub context: Field<u64>,
    /// -> `PINTERFACE_REFERENCE`
    pub interface_reference: Field<u64>,
    /// -> `PINTERFACE_DEREFERENCE`
    pub interface_dereference: Field<u64>,
}

unsafe impl NtStruct for Interface {}

const _: () = {
    assert!(core::mem::size_of::<Interface>() == 0x20);
    assert!(core::mem::offset_of!(Interface, version) == 0x2);
    assert!(core::mem::offset_of!(Interface, context) == 0x8);
    assert!(core::mem::offset_of!(Interface, interface_reference) == 0x10);
    assert!(core::mem::offset_of!(Interface, interface_dereference) == 0x18);
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

/// DEVICE_DESCRIPTION (wdm.h; PDB) — versão 3 (as versões 0..2 usam os
/// primeiros 0x28 bytes).
#[repr(C)]
pub struct DeviceDescription {
    pub version: Field<u32>,
    pub master: Field<u8>,
    pub scatter_gather: Field<u8>,
    pub demand_mode: Field<u8>,
    pub auto_initialize: Field<u8>,
    pub dma32_bit_addresses: Field<u8>,
    pub ignore_count: Field<u8>,
    pub reserved1: Field<u8>,
    pub dma64_bit_addresses: Field<u8>,
    pub bus_number: Field<u32>,
    pub dma_channel: Field<u32>,
    pub interface_type: Field<InterfaceType>,
    pub dma_width: Field<u32>,
    pub dma_speed: Field<u32>,
    pub maximum_length: Field<u32>,
    pub dma_port: Field<u32>,
    pub dma_address_width: Field<u32>,
    pub dma_controller_instance: Field<u32>,
    pub dma_request_line: Field<u32>,
    _pad_34: Reserved<0x4>,
    pub device_address: Field<i64>,
}

unsafe impl NtStruct for DeviceDescription {}

const _: () = {
    assert!(core::mem::size_of::<DeviceDescription>() == 0x40);
    assert!(core::mem::offset_of!(DeviceDescription, master) == 0x4);
    assert!(core::mem::offset_of!(DeviceDescription, dma64_bit_addresses) == 0xB);
    assert!(core::mem::offset_of!(DeviceDescription, bus_number) == 0xC);
    assert!(core::mem::offset_of!(DeviceDescription, interface_type) == 0x14);
    assert!(core::mem::offset_of!(DeviceDescription, dma_port) == 0x24);
    assert!(core::mem::offset_of!(DeviceDescription, dma_address_width) == 0x28);
    assert!(core::mem::offset_of!(DeviceDescription, dma_request_line) == 0x30);
    assert!(core::mem::offset_of!(DeviceDescription, device_address) == 0x38);
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

/// _POP_IRP_DATA (PDB). As uniões `Device`/`System` em +0xD8 aparecem pela
/// forma `Device` (a usada pelo PoGet/SetSystemWake).
#[repr(C)]
pub struct PopIrpData {
    pub link: ListEntry,
    /// -> `_IRP`
    pub irp: Field<u64>,
    pub pdo: Field<u64>,
    pub target_device: Field<u64>,
    pub current_device: Field<u64>,
    pub watchdog_start: Field<u64>,
    /// KTIMER WatchdogTimer.
    _watchdog_timer: Reserved<0x40>,
    /// KDPC WatchdogDpc.
    _watchdog_dpc: Reserved<0x40>,
    pub minor_function: Field<u8>,
    _pad_b9: Reserved<0x3>,
    pub power_state_type: Field<u32>,
    pub power_state: Field<u32>,
    pub watchdog_enabled: Field<u8>,
    _pad_c5: Reserved<0x3>,
    pub fx_device: Field<u64>,
    pub system_transition: Field<u8>,
    pub notify_pep: Field<u8>,
    _pad_d2: Reserved<0x2>,
    pub irp_sequence_id: Field<u32>,
    pub device_caller_completion: Field<u64>,
    pub device_caller_context: Field<u64>,
    pub device_caller_device: Field<u64>,
    pub device_system_wake: Field<u8>,
    _pad_f1: Reserved<0x7>,
    pub dstate_reason: Field<u32>,
    _pad_fc: Reserved<0x4>,
}

unsafe impl NtStruct for PopIrpData {}

const _: () = {
    assert!(core::mem::size_of::<PopIrpData>() == 0x100);
    assert!(core::mem::offset_of!(PopIrpData, watchdog_start) == 0x30);
    assert!(core::mem::offset_of!(PopIrpData, minor_function) == 0xB8);
    assert!(core::mem::offset_of!(PopIrpData, power_state_type) == 0xBC);
    assert!(core::mem::offset_of!(PopIrpData, watchdog_enabled) == 0xC4);
    assert!(core::mem::offset_of!(PopIrpData, fx_device) == 0xC8);
    assert!(core::mem::offset_of!(PopIrpData, irp_sequence_id) == 0xD4);
    assert!(core::mem::offset_of!(PopIrpData, device_caller_completion) == 0xD8);
    assert!(core::mem::offset_of!(PopIrpData, device_system_wake) == 0xF0);
    assert!(core::mem::offset_of!(PopIrpData, dstate_reason) == 0xF8);
};

/// WHEA_TIMESTAMP (ntddk.h): `Seconds:8 Minutes:8 Hours:8 Precise:1 Reserved:7
/// Day:8 Month:8 Year:8 Century:8`, um campo por byte.
#[repr(C)]
pub struct WheaTimestamp {
    pub seconds: Field<u8>,
    pub minutes: Field<u8>,
    pub hours: Field<u8>,
    /// `Precise : 1`, `Reserved : 7`.
    pub precise: Field<u8>,
    pub day: Field<u8>,
    pub month: Field<u8>,
    pub year: Field<u8>,
    pub century: Field<u8>,
}

unsafe impl NtStruct for WheaTimestamp {}

const _: () = {
    assert!(core::mem::size_of::<WheaTimestamp>() == 0x8);
    assert!(core::mem::offset_of!(WheaTimestamp, precise) == 0x3);
    assert!(core::mem::offset_of!(WheaTimestamp, century) == 0x7);
};

/// WHEA_ERROR_RECORD_HEADER (ntddk.h; PDB), `#pragma pack(1)`.
#[repr(C)]
pub struct WheaErrorRecordHeader {
    pub signature: Field<u32>,
    pub revision: Field<u16>,
    pub signature_end: UnalignedField<u32>,
    pub section_count: Field<u16>,
    pub severity: Field<u32>,
    pub valid_bits: Field<u32>,
    pub length: Field<u32>,
    pub timestamp: WheaTimestamp,
    pub platform_id: Guid,
    pub partition_id: Guid,
    pub creator_id: Guid,
    pub notify_type: Guid,
    pub record_id: UnalignedField<u64>,
    pub flags: Field<u32>,
    pub persistence_info: UnalignedField<u64>,
    _reserved: Reserved<0xC>,
}

unsafe impl NtStruct for WheaErrorRecordHeader {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorRecordHeader>() == 0x80);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, revision) == 0x4);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, signature_end) == 0x6);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, section_count) == 0xA);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, severity) == 0xC);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, valid_bits) == 0x10);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, timestamp) == 0x18);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, platform_id) == 0x20);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, creator_id) == 0x40);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, notify_type) == 0x50);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, record_id) == 0x60);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, flags) == 0x68);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, persistence_info) == 0x6C);
};

/// WHEA_ERROR_PACKET_V2 (ntddk.h; PDB), `#pragma pack(1)`.
#[repr(C)]
pub struct WheaErrorPacketV2 {
    pub signature: Field<u32>,
    pub version: Field<u32>,
    pub length: Field<u32>,
    pub flags: Field<u32>,
    pub error_type: Field<u32>,
    pub error_severity: Field<u32>,
    pub error_source_id: Field<u32>,
    pub error_source_type: Field<u32>,
    pub notify_type: Guid,
    pub context: UnalignedField<u64>,
    pub data_format: Field<u32>,
    pub reserved1: Field<u32>,
    pub data_offset: Field<u32>,
    pub data_length: Field<u32>,
    pub pshed_data_offset: Field<u32>,
    pub pshed_data_length: Field<u32>,
}

unsafe impl NtStruct for WheaErrorPacketV2 {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorPacketV2>() == 0x50);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, error_severity) == 0x14);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, error_source_type) == 0x1C);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, notify_type) == 0x20);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, context) == 0x30);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, data_format) == 0x38);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, pshed_data_length) == 0x4C);
};

/// WHEA_DEVICE_DRIVER_DESCRIPTOR (ntddk.h; PDB), `#pragma pack(1)`: o Info de
/// uma fonte WheaErrSrcTypeDeviceDriver.
#[repr(C)]
pub struct WheaDeviceDriverDescriptor {
    pub type_: Field<u16>,
    pub enabled: Field<u8>,
    pub reserved: Field<u8>,
    pub source_guid: Guid,
    pub log_tag: Field<u16>,
    pub reserved2: Field<u16>,
    pub packet_length: Field<u32>,
    pub packet_count: Field<u32>,
    pub packet_buffer: UnalignedField<u64>,
    /// WHEA_ERROR_SOURCE_CONFIGURATION_DD: Initialize, Uninitialize, Correct.
    pub initialize: UnalignedField<u64>,
    pub uninitialize: UnalignedField<u64>,
    pub correct: UnalignedField<u64>,
    pub creator_id: Guid,
    pub partition_id: Guid,
    pub max_section_data_length: Field<u32>,
    pub max_sections_per_record: Field<u32>,
    pub packet_state_buffer: UnalignedField<u64>,
    pub open_handles: Field<u32>,
}

unsafe impl NtStruct for WheaDeviceDriverDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaDeviceDriverDescriptor>() == 0x74);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, source_guid) == 0x4);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, log_tag) == 0x14);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, packet_length) == 0x18);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, packet_buffer) == 0x20);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, initialize) == 0x28);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, correct) == 0x38);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, creator_id) == 0x40);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, partition_id) == 0x50);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, max_section_data_length) == 0x60);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, packet_state_buffer) == 0x68);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, open_handles) == 0x70);
};

/// WHEA_ERROR_SOURCE_DESCRIPTOR (ntddk.h; PDB), `#pragma pack(1)`. O Info
/// (união de 0x3A4 bytes) aparece pela forma DeviceDriver, a única que o
/// OpenNT monta; o resto da união é preenchimento.
#[repr(C)]
pub struct WheaErrorSourceDescriptor {
    pub length: Field<u32>,
    pub version: Field<u32>,
    pub type_: Field<u32>,
    pub state: Field<u32>,
    pub max_raw_data_length: Field<u32>,
    pub num_records_to_preallocate: Field<u32>,
    pub max_sections_per_record: Field<u32>,
    pub error_source_id: Field<u32>,
    pub platform_error_source_id: Field<u32>,
    pub flags: Field<u32>,
    pub device_driver: WheaDeviceDriverDescriptor,
    _info_rest: Reserved<0x330>,
}

unsafe impl NtStruct for WheaErrorSourceDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorSourceDescriptor>() == 0x3CC);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, type_) == 0x8);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, state) == 0xC);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, max_sections_per_record) == 0x18);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, error_source_id) == 0x1C);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, flags) == 0x24);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, device_driver) == 0x28);
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
