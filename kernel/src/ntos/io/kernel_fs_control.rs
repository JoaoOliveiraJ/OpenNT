//! FsRtlKernelFsControlFile.
//!
//! Buffers de kernel do chamador e um IRP retido: a rotina de conclusão
//! sinaliza o evento privado e devolve MORE_PROCESSING; só este chamador
//! solta o IRP/MDL, depois da conclusão ou do cancelamento.

use crate::ntos::io::file::information as file_information;
use super::retained_irp;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::paging;
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{io_stack_location as stack_location, irp as packet, mdl as descriptor};
use crate::ntos::io::irp_builder::{self, BuildOptions, DeviceControl};

const RESOURCE: u32 = 0xC000_009A;

/// Cópia com sobreposição (memmove).
pub fn move_bytes(destination: u64, source: u64, length: u64) {
    if destination == source || length == 0 {
        return;
    }
    if destination > source && destination < source + length {
        for index in (0..length).rev() {
            guest::write8(destination + index, guest::read8(source + index));
        }
    } else {
        for index in 0..length {
            guest::write8(destination + index, guest::read8(source + index));
        }
    }
}

/// O contrato do FsRtl exige buffers de kernel residentes durante a chamada:
/// a VA de kernel existente é um mapeamento de sistema válido e os PFNs vêm
/// das tabelas de páginas reais. `Err(status)` = página inválida.
fn resident_mdl(buffer: u64, length: u32, write: bool) -> Result<u64, u32> {
    let start = buffer & !4095;
    let offset = buffer & 4095;
    let pages = (offset + length as u64).div_ceil(4096);
    let size = descriptor::PFN_ARRAY + pages * 8;
    let mdl = guest::alloc_bytes(size);
    if mdl == 0 {
        return Ok(0);
    }
    guest::write16(mdl + descriptor::SIZE, size as u16);
    guest::write64(mdl + descriptor::START_VA, start);
    guest::write32(mdl + descriptor::BYTE_OFFSET, offset as u32);
    guest::write32(mdl + descriptor::BYTE_COUNT, length);
    guest::write64(mdl + descriptor::MAPPED_SYSTEM_VA, buffer);
    for index in 0..pages {
        let page = paging::query_page(start + index * 4096, false);
        let Some(page) = page.filter(|page| !write || page.access & 2 != 0) else {
            guest::free_bytes(mdl);
            return Err(0xC000_0005);
        };
        guest::write64(mdl + descriptor::PFN_ARRAY + index * 8, page.physical_address / 4096);
    }
    guest::write16(mdl + descriptor::MDL_FLAGS, descriptor::FLAG_PAGES_LOCKED | descriptor::FLAG_MAPPED_TO_SYSTEM_VA);
    Ok(mdl)
}

#[allow(clippy::too_many_arguments)]
fn native(file: u64, code: u32, input: u64, input_length: u32, output: u64, output_length: u32, returned: u64, device: u64) -> Result<u32, KernelError> {
    let routine = retained_irp::completion_routine()?;
    if routine == 0 {
        return Ok(RESOURCE);
    }
    // Os argumentos de cancelamento ficam reservados antes do despacho: o
    // cancelamento não pode alocar depois de o pedido ficar pendente.
    let event = guest::alloc_bytes(40);
    if event == 0 {
        return Ok(RESOURCE);
    }
    let mut irp = 0;
    let mut mdl = 0;
    let result = (|| -> Result<u32, KernelError> {
        dispatcher::initialize_event(event, 0, false);
        let count = match guest::read8(device + 0x4C) {
            0 => 1,
            count => count as u32,
        };
        irp = guest::alloc_bytes(irp_builder::size_for(count));
        if irp == 0 {
            return Ok(RESOURCE);
        }
        irp_builder::build(irp, &BuildOptions { major: 13, minor: 4, device_object: device, stack_count: count, file_object: file, buffer_length: output_length, thread: process::get_current_thread(), requestor_mode: 0, ioctl: Some(DeviceControl { code, input_length, type3_buffer: 0 }), ..BuildOptions::default() });
        let stack = irp_builder::first_stack_location(irp, count);
        let method = code & 3;
        let mut system = 0;
        let mut flags = 4u32;
        if method == 0 {
            if input_length != 0 || output_length != 0 {
                system = if input_length >= output_length { input } else { output };
                if input_length < output_length {
                    move_bytes(output, input, input_length as u64);
                }
                flags |= 0x10;
                if output != 0 {
                    flags |= 0x40;
                }
                guest::write64(irp + packet::USER_BUFFER, output);
            }
        } else if method == 3 {
            guest::write64(irp + packet::USER_BUFFER, output);
            guest::write64(stack + stack_location::IOCTL_TYPE3_BUFFER, input);
        } else {
            if input != 0 {
                system = input;
                flags |= 0x10;
            }
            if output != 0 {
                mdl = match resident_mdl(output, output_length, method == 2) {
                    Ok(0) => return Ok(RESOURCE),
                    Ok(mdl) => mdl,
                    Err(status) => return Ok(status),
                };
                guest::write64(irp + packet::MDL_ADDRESS, mdl);
            }
        }
        guest::write64(irp + packet::SYSTEM_BUFFER, system);
        guest::write32(irp + packet::FLAGS, flags);
        if let Some(failure) = retained_irp::dispatch(device, irp, stack, event, routine)? {
            return Ok(failure);
        }
        let status = guest::read32(irp + packet::IO_STATUS);
        let information = guest::read32(irp + packet::IO_STATUS_INFORMATION);
        guest::write32(returned, information);
        if status & 0x8000_0000 == 0 && information != 0 && input_length >= output_length {
            move_bytes(output, input, information.min(output_length) as u64);
        }
        Ok(status)
    })();
    if mdl != 0 {
        guest::free_bytes(mdl);
    }
    if irp != 0 {
        guest::free_bytes(irp);
    }
    guest::free_bytes(event);
    result
}

#[allow(clippy::too_many_arguments)]
pub fn control(file: u64, code: u32, input: u64, input_length: u32, output: u64, output_length: u32, returned: u64) -> Result<u32, KernelError> {
    if guest::read32(file + 0x50) & 0x800 != 0 {
        return Ok(0xC000_0010);
    }
    let device = file_information::related_device(file)?;
    if device != 0 {
        return native(file, code, input, input_length, output, output_length, returned, device);
    }
    let Some((volume, path)) = crate::ntos::io::file::zw::file_backing(file) else { return Ok(0xC000_0010) };
    let bytes: alloc::vec::Vec<u8> = (0..input_length as u64).map(|index| guest::read8(input + index)).collect();
    if code & 3 == 0 && input_length < output_length {
        move_bytes(output, input, input_length as u64);
    }
    let Some(result) = volume.control(&path, code, &bytes, output_length) else { return Ok(0xC000_0010) };
    match result {
        Ok(result) => {
            let destination = if code & 3 == 0 && input_length >= output_length { input } else { output };
            guest::write_bytes(destination, &result.bytes);
            guest::write32(returned, result.information);
            if result.status & 0x8000_0000 == 0 && result.information != 0 && input_length >= output_length {
                move_bytes(output, input, result.information.min(output_length) as u64);
            }
            Ok(result.status)
        }
        Err(error) => {
            guest::write32(returned, 0);
            Ok(if error.status != crate::ntos::inc::status::STATUS_UNSUCCESSFUL { error.status } else { 0xC000_0185 })
        }
    }
}
