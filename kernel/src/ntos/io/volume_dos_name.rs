//! IoVolumeDeviceToDosName.
//!
//! O nome DOS vem dos drivers donos do volume e dos pontos de montagem do
//! Mount Manager; nenhuma letra é inferida do caminho de um arquivo.

use super::io_manager::{self, RequestContext};
use crate::ntos::ex::pool_allocation;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::kernel_pool;
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{DeviceObject, IoStatusBlock, Irp, MountmgrVolumePaths, NtStruct, UnicodeString};
use crate::ntos::io::device as io;

const MOUNT_MANAGER: &str = "\\Device\\MountPointManager";
const INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const BUFFER_OVERFLOW: u32 = 0x8000_0005;

/// O chamador retém evento, IOSB e buffers até a conclusão; o IRP construído
/// é liberado aqui, inclusive quando o driver rejeita o pedido.
#[allow(clippy::too_many_arguments)]
fn query_device(device: u64, code: u32, input: u64, input_length: u32, output: u64, output_length: u32, scratch: u64) -> u32 {
    let event = scratch;
    let status_block = scratch + 24;
    dispatcher::initialize_event(event, 0, false);
    let request = io_manager::build_device_io_control_request(code, device, input, input_length, output, output_length, 0, event, status_block, Some(RequestContext { thread: process::get_current_thread(), ..Default::default() }));
    if request == 0 {
        return INSUFFICIENT_RESOURCES;
    }
    let mut status = io_manager::iof_call_driver(device, request) as u32;
    if status == 0x103 {
        dispatcher::wait_for_single_object(event, 0, 0, false);
        // SAFETY: IO_STATUS_BLOCK de rascunho dentro de `scratch`.
        status = unsafe { IoStatusBlock::at(status_block) }.status.get() as u32;
    }
    // Rejeição imediata sem IoCompleteRequest deixa o buffer do construtor vivo.
    // SAFETY: IRP construído aqui e ainda não liberado.
    let buffer = unsafe { Irp::at(request) }.associated_irp.system_buffer.get();
    if buffer != 0 {
        guest::free_bytes(buffer);
    }
    guest::free_bytes(request);
    status
}

/// O pool devolvido pertence ao chamador (ExFreePool); em erro o
/// UNICODE_STRING fica intocado.
pub fn volume_device_to_dos_name(device: u64, dos_name: u64) -> Result<u32, KernelError> {
    // SAFETY: DEVICE_OBJECT vivo do chamador.
    let device_type = unsafe { DeviceObject::at(device) }.device_type.get();
    if ![2, 7, 31, 36].contains(&device_type) {
        return Ok(0xC000_000D);
    }
    let scratch = guest::alloc_bytes(656);
    if scratch == 0 {
        return Ok(INSUFFICIENT_RESOURCES);
    }
    let device_name = scratch + 48;
    let path_header = scratch + 40;
    let unicode_name = scratch + 560;
    let name_buffer = scratch + 576;
    let file_output = scratch + 640;
    let device_output = scratch + 648;
    let mut file = 0;
    let mut allocation = 0;
    let result = (|| -> Result<u32, KernelError> {
        let status = query_device(device, 0x4D_0008, 0, 0, device_name, 512, scratch);
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        // A abertura percorre o namespace e envia CREATE ao Mount Manager.
        let units: alloc::vec::Vec<u16> = MOUNT_MANAGER.encode_utf16().collect();
        // SAFETY: UNICODE_STRING de rascunho dentro de `scratch`.
        let name = unsafe { UnicodeString::at(unicode_name) };
        name.length.set(units.len() as u16 * 2);
        name.maximum_length.set((units.len() as u16 + 1) * 2);
        name.buffer.set(name_buffer);
        let text: alloc::vec::Vec<u8> = units.iter().chain(&[0]).flat_map(|unit| unit.to_le_bytes()).collect();
        guest::write_bytes(name_buffer, &text);
        let status = io::get_device_object_pointer(unicode_name, 0x80, file_output, device_output)?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        // SAFETY: células de saída dentro de `scratch`, preenchidas pelo IoGetDeviceObjectPointer.
        let (file_cell, device_cell) = unsafe { (Field::<u64>::at(file_output), Field::<u64>::at(device_output)) };
        file = file_cell.get();
        let manager = device_cell.get();
        // A primeira consulta mede MultiSzLength (BUFFER_OVERFLOW esperado).
        let status = query_device(manager, 0x6D_0030, device_name, 512, path_header, 8, scratch);
        if status & 0x8000_0000 != 0 && status != BUFFER_OVERFLOW {
            return Ok(status);
        }
        // SAFETY: resposta de 8 bytes (MOUNTMGR_VOLUME_PATHS) dentro de `scratch`.
        let size = unsafe { MountmgrVolumePaths::at(path_header) }.multi_sz_length.get().wrapping_add(8);
        if size > 0xFFFF {
            return Ok(0xC000_0206);
        }
        allocation = pool_allocation::allocate_tagged(1, size as u64, 0x2064_3244)?;
        if allocation == 0 {
            return Ok(INSUFFICIENT_RESOURCES);
        }
        let status = query_device(manager, 0x6D_0030, device_name, 512, allocation, size, scratch);
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        // MULTI_SZ sem o cabeçalho e os dois terminadores, com um NUL publicado.
        // SAFETY: MOUNTMGR_VOLUME_PATHS completo devolvido pelo IOCTL.
        let paths = unsafe { MountmgrVolumePaths::at(allocation) };
        let length = (paths.multi_sz_length.get() as u16).wrapping_sub(4);
        // SAFETY: UNICODE_STRING DosName do chamador de modo kernel.
        let dos = unsafe { UnicodeString::at(dos_name) };
        dos.buffer.set(allocation);
        dos.length.set(length);
        dos.maximum_length.set(length.wrapping_add(2));
        // O MultiSz desce sobre o cabeçalho e ganha o terminador.
        let name = guest::read_bytes(paths.multi_sz[0].address(), length as usize);
        guest::write_bytes(allocation, &name);
        guest::write_bytes(allocation + (length & !1) as u64, &[0; 2]);
        // A propriedade passou ao chamador.
        allocation = 0;
        Ok(0)
    })();
    if allocation != 0 {
        let _ = kernel_pool::free(allocation, None);
    }
    if file != 0 {
        file_objects::dereference(file)?;
    }
    guest::free_bytes(scratch);
    result
}

// ---- IoVolumeDeviceToGuidPath / IoVolumeDeviceToGuid ----------------------------
//
// ntoskrnl 10.0.19045: IoVolumeDeviceToGuidPath 0x721540 (tipo de dispositivo
// 2/7/0x1F/0x24, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME com 0x200 bytes e nome
// limitado a 0x1FE) -> IoVolumeDeviceNameToGuidPath 0x7216b0 (MOUNTMGR_MOUNT_POINT
// só com DeviceName, IOCTL_MOUNTMGR_QUERY_POINTS medido e repetido, primeiro
// link "\??\Volume" sem diferenciar maiúsculas, 'D2G ' paginado com NUL);
// IoVolumeDeviceToGuid 0x7214b0 (tira os 10 caracteres e RtlGUIDFromString).

use crate::ntos::inc::types::extra_fs_fat::{MountdevName, MountmgrMountPoint, MountmgrMountPoints};

const MOUNTMGR_QUERY_POINTS: u32 = 0x6D_0008;
const MOUNTDEV_QUERY_DEVICE_NAME: u32 = 0x4D_0008;
const GUID_PATH_TAG: u32 = 0x2047_3244; // 'D2G '
const VOLUME_PREFIX: &str = "\\??\\Volume";

/// Grava uma UNICODE_STRING de kernel sobre `buffer` (Length = MaximumLength - 2).
fn kernel_unicode(string: &UnicodeString, text: &str, buffer: u64) {
    let units: alloc::vec::Vec<u16> = text.encode_utf16().collect();
    guest::write_bytes(buffer, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<alloc::vec::Vec<u8>>());
    string.length.set(units.len() as u16 * 2);
    string.maximum_length.set(units.len() as u16 * 2 + 2);
    string.buffer.set(buffer);
}

/// IoVolumeDeviceNameToGuidPath(DeviceName, GuidPath).
fn device_name_to_guid_path(device_name: &UnicodeString, guid_path: &UnicodeString) -> Result<u32, KernelError> {
    let name_length = device_name.length.get();
    if name_length > 0xF000 {
        return Ok(0xC000_000D);
    }
    let input_length = name_length as u32 + 0x1A;
    let input = pool_allocation::allocate_tagged(1, input_length as u64, GUID_PATH_TAG)?;
    if input == 0 {
        return Ok(INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(input, &alloc::vec![0u8; input_length as usize]);
    // SAFETY: o bloco de entrada acabou de ser alocado com espaço para o nome.
    let point = unsafe { MountmgrMountPoint::at(input) };
    point.device_name_offset.set(MountmgrMountPoint::SIZE as u32);
    point.device_name_length.set(name_length);
    guest::write_bytes(input + MountmgrMountPoint::SIZE, &guest::read_bytes(device_name.buffer.get(), name_length as usize));
    let scratch = guest::alloc_bytes(0x300);
    let mut file = 0;
    let mut points = 0;
    let result = (|| -> Result<u32, KernelError> {
        if scratch == 0 {
            return Ok(INSUFFICIENT_RESOURCES);
        }
        // SAFETY: células de rascunho dentro de `scratch`.
        let (unicode_name, file_output, device_output) = unsafe { (UnicodeString::at(scratch + 0x60), Field::<u64>::at(scratch + 0x40), Field::<u64>::at(scratch + 0x48)) };
        kernel_unicode(unicode_name, MOUNT_MANAGER, scratch + 0x70);
        let header = scratch + 0x100;
        let status = io::get_device_object_pointer(unicode_name.address(), 0x80, file_output.address(), device_output.address())?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        file = file_output.get();
        let manager = device_output.get();
        let status = query_device(manager, MOUNTMGR_QUERY_POINTS, input, input_length, header, 0x20, scratch);
        if status & 0x8000_0000 != 0 && status != BUFFER_OVERFLOW {
            return Ok(status);
        }
        // SAFETY: o cabeçalho MOUNTMGR_MOUNT_POINTS devolvido em `header`.
        let size = unsafe { MountmgrMountPoints::at(header) }.size.get().wrapping_add(0x20);
        if size > 0xFFFF {
            return Ok(0xC000_0206);
        }
        points = pool_allocation::allocate_tagged(1, size as u64, GUID_PATH_TAG)?;
        if points == 0 {
            return Ok(INSUFFICIENT_RESOURCES);
        }
        let status = query_device(manager, MOUNTMGR_QUERY_POINTS, input, input_length, points, size, scratch);
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        // SAFETY: a lista completa devolvida pelo Mount Manager em `points` (size bytes).
        let list = unsafe { MountmgrMountPoints::at(points) };
        let count = list.number_of_mount_points.get() as usize;
        let entries = unsafe { MountmgrMountPoint::array_at(list.mount_points[0].address(), count) };
        let prefix: alloc::vec::Vec<u16> = VOLUME_PREFIX.encode_utf16().collect();
        for entry in entries {
            let link = points + entry.symbolic_link_name_offset.get() as u64;
            let link_length = entry.symbolic_link_name_length.get();
            let head = guest::read_bytes(link, prefix.len() * 2);
            let mut matches = head.len() == prefix.len() * 2;
            for (position, &unit) in prefix.iter().enumerate() {
                let candidate = u16::from_le_bytes([head[position * 2], head[position * 2 + 1]]);
                if !matches || crate::ntos::rtl::unicode_case::upcase_char(candidate)? != crate::ntos::rtl::unicode_case::upcase_char(unit)? {
                    matches = false;
                    break;
                }
            }
            if !matches {
                continue;
            }
            let buffer = pool_allocation::allocate_tagged(1, link_length as u64 + 2, GUID_PATH_TAG)?;
            if buffer == 0 {
                // O NT zera só o Length da GuidPath quando a alocação final falha.
                guid_path.length.set(0);
                return Ok(INSUFFICIENT_RESOURCES);
            }
            guid_path.length.set(link_length);
            guid_path.maximum_length.set(link_length + 2);
            guid_path.buffer.set(buffer);
            let mut bytes = guest::read_bytes(link, link_length as usize);
            bytes.extend_from_slice(&[0, 0]);
            guest::write_bytes(buffer, &bytes);
            return Ok(0);
        }
        Ok(0xC000_0225)
    })();
    let _ = kernel_pool::free(input, None);
    if points != 0 {
        let _ = kernel_pool::free(points, None);
    }
    if file != 0 {
        file_objects::dereference(file)?;
    }
    if scratch != 0 {
        guest::free_bytes(scratch);
    }
    result
}

/// IoVolumeDeviceToGuidPath(VolumeDeviceObject, GuidPath).
pub fn volume_device_to_guid_path(device: &DeviceObject, guid_path: &UnicodeString) -> Result<u32, KernelError> {
    if ![2, 7, 31, 36].contains(&device.device_type.get()) {
        return Ok(0xC000_000D);
    }
    let scratch = guest::alloc_bytes(0x260);
    if scratch == 0 {
        return Ok(INSUFFICIENT_RESOURCES);
    }
    let output = scratch + 0x40;
    let status = query_device(device.address(), MOUNTDEV_QUERY_DEVICE_NAME, 0, 0, output, 0x200, scratch);
    let result = if status & 0x8000_0000 != 0 {
        Ok(status)
    } else {
        // SAFETY: MOUNTDEV_NAME devolvido em `output`; UNICODE_STRING de rascunho em `scratch`.
        let (mountdev, name) = unsafe { (MountdevName::at(output), UnicodeString::at(scratch + 0x30)) };
        let length = mountdev.name_length.get().min(0x1FE);
        name.length.set(length);
        name.maximum_length.set(length);
        name.buffer.set(mountdev.name[0].address());
        device_name_to_guid_path(name, guid_path)
    };
    guest::free_bytes(scratch);
    result
}

/// IoVolumeDeviceToGuid(VolumeDeviceObject, Guid).
pub fn volume_device_to_guid(device: &DeviceObject, guid: u64) -> Result<u32, KernelError> {
    let scratch = guest::alloc_bytes(0x20);
    if scratch == 0 {
        return Ok(INSUFFICIENT_RESOURCES);
    }
    // SAFETY: duas UNICODE_STRINGs de rascunho em `scratch`.
    let (path, braced) = unsafe { (UnicodeString::at(scratch), UnicodeString::at(scratch + 0x10)) };
    let status = volume_device_to_guid_path(device, path)?;
    if status & 0x8000_0000 != 0 {
        guest::free_bytes(scratch);
        return Ok(status);
    }
    let buffer = path.buffer.get();
    braced.length.set(path.length.get().wrapping_sub(0x14));
    braced.maximum_length.set(path.maximum_length.get().wrapping_sub(0x14));
    braced.buffer.set(buffer + 0x14);
    let status = crate::ntos::init::exports::invoke_handler("RtlGUIDFromString", &[braced.address(), guid])? as u32;
    let _ = kernel_pool::free(buffer, None);
    guest::free_bytes(scratch);
    Ok(status)
}
