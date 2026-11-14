//! IOCTLs do FsRtl — FsRtlIssueDeviceIoControl (RVA 0x6954f0) e os
//! seus clientes FsRtlVolumeDeviceToCorrelationId (RVA 0x695060) e
//! FsRtlGetSectorSizeInformation (RVA 0x6950f0), e o FsRtlBalanceReads (RVA
//! 0x6a5700), do ntoskrnl
//! 10.0.19045.
//!
//! FsRtlIssueDeviceIoControl(DeviceObject, IoCtl, Flags, InputBuffer,
//! InputBufferLength, OutputBuffer, OutputBufferLength, IosbInformation):
//! KeInitializeEvent(Notification, FALSE) + IoBuildDeviceIoControlRequest
//! (não interno) — sem IRP, STATUS_INSUFFICIENT_RESOURCES —, Flags somado ao
//! IO_STACK_LOCATION.Flags do próximo slot, IofCallDriver e, se pendente,
//! KeWaitForSingleObject + Iosb.Status; com sucesso devolve
//! Iosb.Information em *IosbInformation (se dado).
//!
//! FsRtlVolumeDeviceToCorrelationId(VolumeDeviceObject, Guid):
//! IOCTL_MOUNTDEV_QUERY_STABLE_GUID (0x4D0018) com saída de 16 bytes;
//! sucesso copia o GUID. STUB (sinalizado): na falha o NT recorre ao
//! IoVolumeDeviceToGuid (banco do mount manager); o OpenNT não tem mount
//! manager, então devolve o status do IOCTL.

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{DeviceObject, Guid, IoStackLocation, IoStatusBlock, Irp, Kevent};
use crate::ntos::io::io_manager;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;

pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const IOCTL_MOUNTDEV_QUERY_STABLE_GUID: u32 = 0x004D_0018;

const NOTIFICATION_EVENT: u8 = 0;

/// FsRtlIssueDeviceIoControl. `information_out` recebe Iosb.Information no
/// sucesso (o `PULONG_PTR IosbInformation` opcional).
#[allow(clippy::too_many_arguments)]
pub fn issue_device_io_control(device: &DeviceObject, io_control_code: u32, flags: u8, input: u64, input_length: u32, output: u64, output_length: u32, information_out: Option<&Field<u64>>) -> u32 {
    // KEVENT + IO_STATUS_BLOCK (variáveis locais no NT).
    let block = guest::alloc_bytes(Kevent::SIZE + IoStatusBlock::SIZE);
    // SAFETY: bloco recém-alocado: o KEVENT seguido do IO_STATUS_BLOCK.
    let (event, iosb) = unsafe { (Kevent::at(block), IoStatusBlock::at(block + Kevent::SIZE)) };
    dispatcher::initialize_event(event.address(), NOTIFICATION_EVENT, false);
    let irp = io_manager::build_device_io_control_request(io_control_code, device.address(), input, input_length, output, output_length, 0, event.address(), iosb.address(), None);
    let status = if irp == 0 {
        STATUS_INSUFFICIENT_RESOURCES
    } else {
        // SAFETY: IRP recém-montado; o próximo slot fica logo abaixo do corrente.
        let next_stack = unsafe { IoStackLocation::at(Irp::at(irp).tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
        next_stack.flags.set(next_stack.flags.get() | flags);
        let mut status = io_manager::iof_call_driver(device.address(), irp) as u32;
        if status == STATUS_PENDING {
            dispatcher::wait_for_single_object(event.address(), 0, 0, false);
            status = iosb.status.get() as u32;
        }
        if let (true, Some(out)) = ((status as i32) >= 0, information_out) {
            out.set(iosb.information.get());
        }
        status
    };
    guest::free_bytes(block);
    status
}

// ---- FsRtlBalanceReads ---------------------------------------------------------------
//
// ntoskrnl 10.0.19041, RVA 0x6a5700 (cauda fria 0x80ee94): KEVENT de
// notificação na pilha, IoBuildDeviceIoControlRequest(FT_BALANCED_READ_MODE
// 0x66001B, TargetDevice, sem buffers, não interno) — sem IRP,
// STATUS_INSUFFICIENT_RESOURCES —, IofCallDriver e, pendente, a espera e o
// Iosb.Status. Sem flags na stack location (não passa pelo
// FsRtlIssueDeviceIoControl).

/// FT_BALANCED_READ_MODE.
pub const FT_BALANCED_READ_MODE: u32 = 0x0066_001B;

/// FsRtlBalanceReads(TargetDevice) -> NTSTATUS.
pub fn balance_reads(device: &DeviceObject) -> u32 {
    let block = guest::alloc_bytes(Kevent::SIZE + IoStatusBlock::SIZE);
    // SAFETY: bloco recém-alocado: o KEVENT seguido do IO_STATUS_BLOCK.
    let (event, iosb) = unsafe { (Kevent::at(block), IoStatusBlock::at(block + Kevent::SIZE)) };
    dispatcher::initialize_event(event.address(), NOTIFICATION_EVENT, false);
    let irp = io_manager::build_device_io_control_request(FT_BALANCED_READ_MODE, device.address(), 0, 0, 0, 0, 0, event.address(), iosb.address(), None);
    let status = if irp == 0 {
        STATUS_INSUFFICIENT_RESOURCES
    } else {
        let status = io_manager::iof_call_driver(device.address(), irp) as u32;
        if status == STATUS_PENDING {
            dispatcher::wait_for_single_object(event.address(), 0, 0, false);
            iosb.status.get() as u32
        } else {
            status
        }
    };
    guest::free_bytes(block);
    status
}

// ---- FsRtlGetSectorSizeInformation ---------------------------------------------------
//
// ntoskrnl 10.0.19041, RVA 0x6950f0 (caudas frias 0x80a36a..0x80a395). Todas as
// consultas passam pelo FsRtlIssueDeviceIoControl com SL_OVERRIDE_VERIFY_VOLUME:
// 1. IOCTL_DISK_GET_DRIVE_GEOMETRY (0x70000, DISK_GEOMETRY de 0x18): a falha é
//    devolvida; BytesPerSector zero ou não potência de 2 dá
//    STATUS_BAD_DEVICE_TYPE.
// 2. IOCTL_STORAGE_QUERY_PROPERTY StorageAccessAlignmentProperty (6): o
//    STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR vale se Information, Version e Size
//    cobrem 0x1C bytes, BytesPerLogicalSector = BytesPerSector da geometria,
//    BytesPerPhysicalSector potência de 2, múltiplo do lógico, e
//    BytesOffsetForSectorAlignment múltiplo do lógico; senão o físico é o
//    lógico e o deslocamento é desconhecido (0xFFFFFFFF).
// 3. Flags = ALIGNED_DEVICE | PARTITION_ALIGNED_ON_DEVICE; com o deslocamento
//    conhecido, ALIGNED_DEVICE cai se ele não for múltiplo do físico, e
//    IOCTL_DISK_GET_PARTITION_INFO_EX (0x70048) dá
//    ByteOffsetForPartitionAlignment = StartingOffset % físico, derrubando
//    PARTITION_ALIGNED_ON_DEVICE se (físico - resto) % físico difere do
//    deslocamento do setor módulo o físico.
// 4. SeekPenalty (7) sem penalidade -> NO_SEEK_PENALTY; Trim (8) ligado ->
//    TRIM_ENABLED; DeviceAttributes (0x37) com
//    STORAGE_ATTRIBUTE_BYTE_ADDRESSABLE_IO -> BYTE_ADDRESSABLE. Falhas
//    dessas consultas são ignoradas; o resultado é STATUS_SUCCESS.

pub const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x0007_0000;
pub const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048;
pub const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
/// O status do NT para BytesPerSector inválido.
pub const STATUS_BAD_DEVICE_TYPE: u32 = 0xC000_00CB;
const SL_OVERRIDE_VERIFY_VOLUME: u8 = 0x02;
const STORAGE_ACCESS_ALIGNMENT_PROPERTY: u32 = 6;
const STORAGE_DEVICE_SEEK_PENALTY_PROPERTY: u32 = 7;
const STORAGE_DEVICE_TRIM_PROPERTY: u32 = 8;
const STORAGE_DEVICE_ATTRIBUTES_PROPERTY: u32 = 0x37;
const STORAGE_ATTRIBUTE_BYTE_ADDRESSABLE_IO: u64 = 1;
const UNKNOWN_ALIGNMENT: u32 = 0xFFFF_FFFF;
pub const SSINFO_FLAGS_ALIGNED_DEVICE: u32 = 0x01;
pub const SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE: u32 = 0x02;
pub const SSINFO_FLAGS_NO_SEEK_PENALTY: u32 = 0x04;
pub const SSINFO_FLAGS_TRIM_ENABLED: u32 = 0x08;
pub const SSINFO_FLAGS_BYTE_ADDRESSABLE: u32 = 0x10;

/// FILE_FS_SECTOR_SIZE_INFORMATION (ntifs.h).
#[repr(C)]
pub struct FileFsSectorSizeInformation {
    pub logical_bytes_per_sector: Field<u32>,
    pub physical_bytes_per_sector_for_atomicity: Field<u32>,
    pub physical_bytes_per_sector_for_performance: Field<u32>,
    pub file_system_effective_physical_bytes_per_sector_for_atomicity: Field<u32>,
    pub flags: Field<u32>,
    pub byte_offset_for_sector_alignment: Field<u32>,
    pub byte_offset_for_partition_alignment: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for FileFsSectorSizeInformation {}

/// O bloco de trabalho (as variáveis locais do NT): DISK_GEOMETRY,
/// STORAGE_PROPERTY_QUERY, o descritor de saída e a PARTITION_INFORMATION_EX.
#[repr(C)]
struct SectorQueries {
    /// DISK_GEOMETRY: Cylinders, MediaType, TracksPerCylinder,
    /// SectorsPerTrack, BytesPerSector.
    geometry: [Field<u32>; 6],
    /// STORAGE_PROPERTY_QUERY: PropertyId, QueryType, AdditionalParameters.
    query: [Field<u32>; 3],
    _pad_24: Reserved<0x4>,
    /// Saída das consultas de propriedade (até 0x1C bytes).
    descriptor: [Field<u32>; 8],
    /// PARTITION_INFORMATION_EX: PartitionStyle e StartingOffset em +8.
    partition: [Field<u64>; 0x12],
    information: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SectorQueries {}

const _: () = {
    assert!(core::mem::size_of::<FileFsSectorSizeInformation>() == 0x1C);
    assert!(core::mem::offset_of!(SectorQueries, query) == 0x18);
    assert!(core::mem::offset_of!(SectorQueries, descriptor) == 0x28);
    assert!(core::mem::offset_of!(SectorQueries, partition) == 0x48);
    assert!(core::mem::size_of::<[Field<u64>; 0x12]>() == 0x90);
};

impl SectorQueries {
    /// IOCTL_STORAGE_QUERY_PROPERTY (PropertyStandardQuery) com saída de
    /// `output_length` bytes no descritor zerado.
    fn query_property(&self, device: &DeviceObject, property: u32, output_length: u32) -> u32 {
        self.query[0].set(property);
        self.query[1].set(0);
        self.query[2].set(0);
        for cell in &self.descriptor {
            cell.set(0);
        }
        issue_device_io_control(device, IOCTL_STORAGE_QUERY_PROPERTY, SL_OVERRIDE_VERIFY_VOLUME, self.query[0].address(), 0x0C, self.descriptor[0].address(), output_length, Some(&self.information))
    }

    /// Version e Size do descritor cobrem `minimum` e o que o driver devolveu.
    fn descriptor_covers(&self, minimum: u32) -> bool {
        let information = self.information.get();
        information >= minimum as u64 && self.descriptor[0].get() >= minimum && self.descriptor[1].get() as u64 >= information
    }
}

/// FsRtlGetSectorSizeInformation(DeviceObject, SectorSizeInfo) -> NTSTATUS.
pub fn get_sector_size_information(device: &DeviceObject, info: &FileFsSectorSizeInformation) -> u32 {
    let block = guest::alloc_bytes(SectorQueries::SIZE);
    // SAFETY: bloco zerado recém-alocado do tamanho do bloco de trabalho.
    let work = unsafe { SectorQueries::at(block) };
    let status = sector_size_information(device, info, work);
    guest::free_bytes(block);
    status
}

fn sector_size_information(device: &DeviceObject, info: &FileFsSectorSizeInformation, work: &SectorQueries) -> u32 {
    for cell in [&info.logical_bytes_per_sector, &info.physical_bytes_per_sector_for_atomicity, &info.physical_bytes_per_sector_for_performance, &info.file_system_effective_physical_bytes_per_sector_for_atomicity, &info.flags, &info.byte_offset_for_sector_alignment, &info.byte_offset_for_partition_alignment] {
        cell.set(0);
    }
    let status = issue_device_io_control(device, IOCTL_DISK_GET_DRIVE_GEOMETRY, SL_OVERRIDE_VERIFY_VOLUME, 0, 0, work.geometry[0].address(), 0x18, None);
    if (status as i32) < 0 {
        return status;
    }
    let logical = work.geometry[5].get();
    if !logical.is_power_of_two() {
        return STATUS_BAD_DEVICE_TYPE;
    }
    // STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR: Version, Size, BytesPerCacheLine,
    // BytesOffsetForCacheAlignment, BytesPerLogicalSector,
    // BytesPerPhysicalSector, BytesOffsetForSectorAlignment.
    let aligned = (work.query_property(device, STORAGE_ACCESS_ALIGNMENT_PROPERTY, 0x1C) as i32) >= 0 && work.descriptor_covers(0x1C) && {
        let (descriptor_logical, physical, offset) = (work.descriptor[4].get(), work.descriptor[5].get(), work.descriptor[6].get());
        descriptor_logical != 0 && descriptor_logical == logical && physical >= descriptor_logical && physical.is_power_of_two() && physical % descriptor_logical == 0 && offset % descriptor_logical == 0
    };
    let (physical, sector_offset) = if aligned { (work.descriptor[5].get(), work.descriptor[6].get()) } else { (logical, UNKNOWN_ALIGNMENT) };
    info.logical_bytes_per_sector.set(logical);
    info.physical_bytes_per_sector_for_atomicity.set(physical);
    info.physical_bytes_per_sector_for_performance.set(physical);
    info.file_system_effective_physical_bytes_per_sector_for_atomicity.set(logical);
    info.flags.set(SSINFO_FLAGS_ALIGNED_DEVICE | SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE);
    info.byte_offset_for_sector_alignment.set(sector_offset);
    info.byte_offset_for_partition_alignment.set(UNKNOWN_ALIGNMENT);
    if sector_offset != UNKNOWN_ALIGNMENT {
        let remainder = sector_offset % physical;
        if remainder != 0 {
            info.flags.set(SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE);
        }
        for cell in &work.partition {
            cell.set(0);
        }
        if (issue_device_io_control(device, IOCTL_DISK_GET_PARTITION_INFO_EX, SL_OVERRIDE_VERIFY_VOLUME, 0, 0, work.partition[0].address(), 0x90, None) as i32) >= 0 {
            let partition_remainder = ((work.partition[1].get() as i64) % physical as i64) as u32;
            info.byte_offset_for_partition_alignment.set(partition_remainder);
            if physical.wrapping_sub(partition_remainder) % physical != remainder {
                info.flags.set(info.flags.get() & !SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE);
            }
        }
    }
    // DEVICE_SEEK_PENALTY_DESCRIPTOR / DEVICE_TRIM_DESCRIPTOR: Version, Size e o BOOLEAN em +8.
    if (work.query_property(device, STORAGE_DEVICE_SEEK_PENALTY_PROPERTY, 0x0C) as i32) >= 0 && work.descriptor_covers(0x0C) && work.descriptor[2].get() & 0xFF == 0 {
        info.flags.set(info.flags.get() | SSINFO_FLAGS_NO_SEEK_PENALTY);
    }
    if (work.query_property(device, STORAGE_DEVICE_TRIM_PROPERTY, 0x0C) as i32) >= 0 && work.descriptor_covers(0x0C) && work.descriptor[2].get() & 0xFF != 0 {
        info.flags.set(info.flags.get() | SSINFO_FLAGS_TRIM_ENABLED);
    }
    // STORAGE_DEVICE_ATTRIBUTES_DESCRIPTOR: Version, Size e Attributes (64 bits) em +8.
    if (work.query_property(device, STORAGE_DEVICE_ATTRIBUTES_PROPERTY, 0x10) as i32) >= 0 && work.information.get() == 0x10 && (work.descriptor[2].get() as u64 | (work.descriptor[3].get() as u64) << 32) & STORAGE_ATTRIBUTE_BYTE_ADDRESSABLE_IO != 0 {
        info.flags.set(info.flags.get() | SSINFO_FLAGS_BYTE_ADDRESSABLE);
    }
    0
}

/// FsRtlVolumeDeviceToCorrelationId(VolumeDeviceObject, Guid) -> NTSTATUS.
pub fn volume_device_to_correlation_id(device: &DeviceObject, guid: &Guid) -> u32 {
    let output = guest::alloc_bytes(Guid::SIZE);
    let status = issue_device_io_control(device, IOCTL_MOUNTDEV_QUERY_STABLE_GUID, 0, 0, 0, output, Guid::SIZE as u32, None);
    if (status as i32) >= 0 {
        guest::write_bytes(guid.address(), &guest::read_bytes(output, Guid::SIZE as usize));
    }
    guest::free_bytes(output);
    status
}
