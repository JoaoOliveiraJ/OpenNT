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
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{DeviceObject, FileObject, IoStackLocation, Irp, Mdl, NtStruct};
use crate::ntos::io::irp_builder::{self, BuildOptions, DeviceControl};

const RESOURCE: u32 = 0xC000_009A;
/// MDL_PAGES_LOCKED | MDL_MAPPED_TO_SYSTEM_VA.
const MDL_PAGES_LOCKED_AND_MAPPED: i16 = 0x0002 | 0x0001;
/// FILE_OBJECT.Flags: FO_DIRECT_DEVICE_OPEN.
const FO_DIRECT_DEVICE_OPEN: u32 = 0x800;

/// Cópia com sobreposição (memmove): o bloco inteiro é lido antes de ser
/// gravado, então a sobreposição em qualquer sentido preserva a origem.
pub fn move_bytes(destination: u64, source: u64, length: u64) {
    if destination == source || length == 0 {
        return;
    }
    guest::write_bytes(destination, &guest::read_bytes(source, length as usize));
}

/// O contrato do FsRtl exige buffers de kernel residentes durante a chamada:
/// a VA de kernel existente é um mapeamento de sistema válido e os PFNs vêm
/// das tabelas de páginas reais. `Err(status)` = página inválida.
fn resident_mdl(buffer: u64, length: u32, write: bool) -> Result<u64, u32> {
    let start = buffer & !4095;
    let offset = buffer & 4095;
    let pages = (offset + length as u64).div_ceil(4096);
    // O vetor de PFNs (PFN_NUMBER) segue o cabeçalho do MDL.
    let size = Mdl::SIZE + pages * 8;
    let mdl = guest::alloc_bytes(size);
    if mdl == 0 {
        return Ok(0);
    }
    // SAFETY: alocação zerada do MDL com o vetor de PFNs.
    let (header, pfns) = unsafe { (Mdl::at(mdl), Field::<u64>::array_at(mdl + Mdl::SIZE, pages as usize)) };
    header.size.set(size as i16);
    header.start_va.set(start);
    header.byte_offset.set(offset as u32);
    header.byte_count.set(length);
    header.mapped_system_va.set(buffer);
    for (index, pfn) in pfns.iter().enumerate() {
        let page = paging::query_page(start + index as u64 * 4096, false);
        let Some(page) = page.filter(|page| !write || page.access & 2 != 0) else {
            guest::free_bytes(mdl);
            return Err(0xC000_0005);
        };
        pfn.set(page.physical_address / 4096);
    }
    header.mdl_flags.set(MDL_PAGES_LOCKED_AND_MAPPED);
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
        // SAFETY: dispositivo relacionado ao arquivo, vivo durante o pedido.
        let count = match unsafe { DeviceObject::at(device) }.stack_size.get() as u8 {
            0 => 1,
            count => count as u32,
        };
        irp = guest::alloc_bytes(irp_builder::size_for(count));
        if irp == 0 {
            return Ok(RESOURCE);
        }
        irp_builder::build(irp, &BuildOptions { major: 13, minor: 4, device_object: device, stack_count: count, file_object: file, buffer_length: output_length, thread: process::get_current_thread(), requestor_mode: 0, ioctl: Some(DeviceControl { code, input_length, type3_buffer: 0 }), ..BuildOptions::default() });
        let stack = irp_builder::first_stack_location(irp, count);
        // SAFETY: IRP recém-construído e o slot do topo dele.
        let (request, location) = unsafe { (Irp::at(irp), IoStackLocation::at(stack)) };
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
                request.user_buffer.set(output);
            }
        } else if method == 3 {
            request.user_buffer.set(output);
            location.parameters.file_system_control.type3_input_buffer.set(input);
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
                request.mdl_address.set(mdl);
            }
        }
        request.associated_irp.system_buffer.set(system);
        request.flags.set(flags);
        if let Some(failure) = retained_irp::dispatch(device, irp, stack, event, routine)? {
            return Ok(failure);
        }
        let status = request.io_status.status.get() as u32;
        let information = request.io_status.information.get() as u32;
        // SAFETY: PULONG de saída do chamador de modo kernel.
        unsafe { Field::<u32>::at(returned) }.set(information);
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
    // SAFETY: FILE_OBJECT vivo do chamador.
    if unsafe { FileObject::at(file) }.flags.get() & FO_DIRECT_DEVICE_OPEN != 0 {
        return Ok(0xC000_0010);
    }
    let device = file_information::related_device(file)?;
    if device != 0 {
        return native(file, code, input, input_length, output, output_length, returned, device);
    }
    let Some((volume, path)) = crate::ntos::io::file::zw::file_backing(file) else { return Ok(0xC000_0010) };
    let bytes = guest::read_bytes(input, input_length as usize);
    if code & 3 == 0 && input_length < output_length {
        move_bytes(output, input, input_length as u64);
    }
    let Some(result) = volume.control(&path, code, &bytes, output_length) else { return Ok(0xC000_0010) };
    match result {
        Ok(result) => {
            let destination = if code & 3 == 0 && input_length >= output_length { input } else { output };
            guest::write_bytes(destination, &result.bytes);
            // SAFETY: PULONG de saída do chamador de modo kernel.
            unsafe { Field::<u32>::at(returned) }.set(result.information);
            if result.status & 0x8000_0000 == 0 && result.information != 0 && input_length >= output_length {
                move_bytes(output, input, result.information.min(output_length) as u64);
            }
            Ok(result.status)
        }
        Err(error) => {
            // SAFETY: PULONG de saída do chamador de modo kernel.
            unsafe { Field::<u32>::at(returned) }.set(0);
            Ok(if error.status != crate::ntos::inc::status::STATUS_UNSUCCESSFUL { error.status } else { 0xC000_0185 })
        }
    }
}
