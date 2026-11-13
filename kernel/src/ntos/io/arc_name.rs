//! Nomes ARC e informação do disco de boot (NT: io\iomgr\arcsec.c e
//! io\iomgr\ioinit.c).
//!
//! No NT as duas rotinas partem do ARC_DISK_INFORMATION que o winload deixa
//! no LOADER_PARAMETER_BLOCK (KeLoaderBlock->ArcDiskInformation, +0xE8) e da
//! IoArcTableListHead montada a partir dele. O OpenNT sobe sem loader block
//! do NT: a lista de assinaturas de disco do loader é vazia. As rotinas
//! seguem o NT com essa lista vazia.
//!
//! Transcrição do ntoskrnl 19041:
//!   IoCreateArcName               rva 0x780120 -> IopCreateArcName(Device, -1) 0x780138
//!     IOCTL_STORAGE_GET_DEVICE_NUMBER (0x2D1080, saída 0xC),
//!     IOCTL_DISK_GET_DRIVE_GEOMETRY (0x70000, saída 0x18) e
//!     IOCTL_DISK_GET_DRIVE_LAYOUT_EX (0x70050, buffer 0x1000) síncronos;
//!     qualquer falha é devolvida; depois casa a assinatura com as entradas
//!     da IoArcTableListHead e, sem entrada, STATUS_NOT_SUPPORTED (0x7803b8).
//!   IoGetBootDiskInformationLite  rva 0x79d300 -> IopGetBootDiskInformationLite 0xa45940
//!     BOOTDISK_INFORMATION_LITE { ULONG NumberEntries; 3 + n entradas de
//!     0x1C } em NonPagedPoolNx zerado; lista vazia = NumberEntries 0 com as
//!     três entradas reservadas (4 + 3*0x1C = 0x58 bytes), STATUS_SUCCESS.

use crate::ntos::inc::types::extra_storage::{BootdiskInformationLite, LoaderPartitionInformationEx};
use crate::ntos::inc::types::{Field, IoStatusBlock, Kevent, NtStruct};
use crate::ntos::io::io_manager;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x0007_0000;
const IOCTL_DISK_GET_DRIVE_LAYOUT_EX: u32 = 0x0007_0050;
const STORAGE_DEVICE_NUMBER_SIZE: u32 = 0xC;
const DISK_GEOMETRY_SIZE: u32 = 0x18;
const DRIVE_LAYOUT_BUFFER_SIZE: u32 = 0x1000;

/// Entradas que o IopGetBootDiskInformationLite reserva além das do loader.
const BOOT_DISK_LITE_RESERVED_ENTRIES: u64 = 3;

const STATUS_SUCCESS: u32 = 0;
const STATUS_PENDING: u32 = 0x103;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// Entradas da IoArcTableListHead (assinaturas do loader). Vazia no OpenNT:
/// não há ARC_DISK_INFORMATION de um winload.
fn arc_disk_signature_count() -> u64 {
    0
}

/// IOCTL interno síncrono (IoBuildDeviceIoControlRequest + IofCallDriver +
/// espera no evento), como o IopCreateArcName faz para cada consulta.
fn synchronous_device_control(device: u64, code: u32, output: u64, output_length: u32) -> Result<u32, KernelError> {
    let event = guest::alloc_bytes(Kevent::SIZE);
    let io_status = guest::alloc_bytes(IoStatusBlock::SIZE);
    if event == 0 || io_status == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    dispatcher::initialize_event(event, 0, false);
    let packet = io_manager::build_device_io_control_request(code, device, 0, 0, output, output_length, 0, event, io_status, None);
    if packet == 0 {
        guest::free_bytes(event);
        guest::free_bytes(io_status);
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let mut status = io_manager::iof_call_driver(device, packet) as u32;
    if status == STATUS_PENDING {
        dispatcher::wait_for_single_object(event, 0, 0, false);
        // SAFETY: IO_STATUS_BLOCK alocado acima e completado pelo driver.
        status = unsafe { IoStatusBlock::at(io_status) }.status.get() as u32;
    }
    guest::free_bytes(packet);
    guest::free_bytes(event);
    guest::free_bytes(io_status);
    Ok(status)
}

/// IoCreateArcName(DeviceObject): consulta número, geometria e layout do
/// disco e associa o nome ARC da entrada do loader com a mesma assinatura.
/// Sem entradas do loader, nenhum disco tem nome ARC.
pub fn create_arc_name(device: u64) -> Result<u32, KernelError> {
    // Os IRPs vão ao dispositivo dado, montados com o StackSize dele.
    let number = guest::alloc_bytes(STORAGE_DEVICE_NUMBER_SIZE as u64);
    let geometry = guest::alloc_bytes(DISK_GEOMETRY_SIZE as u64);
    if number == 0 || geometry == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let mut status = synchronous_device_control(device, IOCTL_STORAGE_GET_DEVICE_NUMBER, number, STORAGE_DEVICE_NUMBER_SIZE)?;
    if status as i32 >= 0 {
        status = synchronous_device_control(device, IOCTL_DISK_GET_DRIVE_GEOMETRY, geometry, DISK_GEOMETRY_SIZE)?;
    }
    if status as i32 >= 0 {
        // Buffer do layout: 0x1000, dobrando enquanto o disco pedir mais.
        let mut length = DRIVE_LAYOUT_BUFFER_SIZE;
        loop {
            let layout = guest::alloc_bytes(length as u64);
            if layout == 0 {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            status = synchronous_device_control(device, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, layout, length)?;
            guest::free_bytes(layout);
            if status != STATUS_BUFFER_TOO_SMALL || length >= 0x10_0000 {
                break;
            }
            length *= 2;
        }
        if status as i32 >= 0 && arc_disk_signature_count() == 0 {
            status = STATUS_NOT_SUPPORTED;
        }
    }
    guest::free_bytes(number);
    guest::free_bytes(geometry);
    Ok(status)
}

/// IoGetBootDiskInformationLite(BootDiskInformation*): bloco alocado com as
/// entradas dos discos do loader (nenhuma no OpenNT).
pub fn get_boot_disk_information_lite(output: u64) -> u32 {
    let entries = BOOT_DISK_LITE_RESERVED_ENTRIES + arc_disk_signature_count();
    // BOOTDISK_INFORMATION_LITE já traz uma entrada; as demais seguem.
    let size = BootdiskInformationLite::SIZE + (entries - 1) * LoaderPartitionInformationEx::SIZE;
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: bloco recém-alocado (zerado) do tamanho calculado.
    unsafe { BootdiskInformationLite::at(block) }.number_entries.set(0);
    // SAFETY: PBOOTDISK_INFORMATION_LITE* de saída de um chamador de modo kernel.
    unsafe { Field::<u64>::at(output) }.set(block);
    STATUS_SUCCESS
}
