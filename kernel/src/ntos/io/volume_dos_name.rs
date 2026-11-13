//! IoVolumeDeviceToDosName — `system32/ntos/io/volume-dos-name.js`.
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
use crate::ntos::inc::nt_abi::irp;
use crate::ntos::io::exports as io;

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
        status = guest::read32(status_block);
    }
    // Rejeição imediata sem IoCompleteRequest deixa o buffer do construtor vivo.
    let buffer = guest::read64(request + irp::SYSTEM_BUFFER);
    if buffer != 0 {
        guest::free_bytes(buffer);
    }
    guest::free_bytes(request);
    status
}

/// O pool devolvido pertence ao chamador (ExFreePool); em erro o
/// UNICODE_STRING fica intocado.
pub fn volume_device_to_dos_name(device: u64, dos_name: u64) -> Result<u32, KernelError> {
    let device_type = guest::read32(device + 0x48);
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
        guest::write16(unicode_name, units.len() as u16 * 2);
        guest::write16(unicode_name + 2, (units.len() as u16 + 1) * 2);
        guest::write64(unicode_name + 8, name_buffer);
        for (index, unit) in units.iter().enumerate() {
            guest::write16(name_buffer + index as u64 * 2, *unit);
        }
        guest::write16(name_buffer + units.len() as u64 * 2, 0);
        let status = io::get_device_object_pointer(unicode_name, 0x80, file_output, device_output)? as u32;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        file = guest::read64(file_output);
        let manager = guest::read64(device_output);
        // A primeira consulta mede MultiSzLength (BUFFER_OVERFLOW esperado).
        let status = query_device(manager, 0x6D_0030, device_name, 512, path_header, 8, scratch);
        if status & 0x8000_0000 != 0 && status != BUFFER_OVERFLOW {
            return Ok(status);
        }
        let size = guest::read32(path_header).wrapping_add(8);
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
        let length = guest::read16(allocation).wrapping_sub(4);
        guest::write64(dos_name + 8, allocation);
        guest::write16(dos_name, length);
        guest::write16(dos_name + 2, length.wrapping_add(2));
        for index in 0..length as u64 {
            guest::write8(allocation + index, guest::read8(allocation + 4 + index));
        }
        guest::write16(allocation + (length & !1) as u64, 0);
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
