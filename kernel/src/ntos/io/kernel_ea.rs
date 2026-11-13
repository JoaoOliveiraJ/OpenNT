//! FsRtlQueryKernelEaFile / FsRtlSetKernelEaFile.
//!
//! Contratos originais de EA do FsRtl: buffers de kernel do chamador, IRPs
//! explícitos de consulta/escrita, status da conclusão e posse retida até o
//! cancelamento.

use alloc::vec::Vec;

use crate::ntos::io::file::information as file_information;
use super::retained_irp;
use crate::drivers::fs::extended_attributes::{QueryOptions, QueryState};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::{data_pool, kernel_pool};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::ntos::inc::status::STATUS_UNSUCCESSFUL;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::irp as packet;
use crate::ntos::io::irp_builder::{self, BuildOptions};

const RESOURCE: u32 = 0xC000_009A;

/// Parâmetros de IRP_MJ_QUERY_EA.
struct Query {
    restart: bool,
    single: bool,
    names: u64,
    names_length: u32,
    index: u64,
    returned: u64,
}

fn native(file: u64, buffer: u64, length: u32, options: Option<&Query>, device: u64) -> Result<u32, KernelError> {
    let routine = retained_irp::completion_routine()?;
    if routine == 0 {
        return Ok(RESOURCE);
    }
    let event = guest::alloc_bytes(40);
    if event == 0 {
        return Ok(RESOURCE);
    }
    let mut irp = 0;
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
        let (major, minor) = if options.is_some() { (7, 0) } else { (8, 4) };
        irp_builder::build(irp, &BuildOptions { major, minor, device_object: device, stack_count: count, file_object: file, buffer_length: length, user_buffer: buffer, requestor_mode: 0, thread: process::get_current_thread(), ..BuildOptions::default() });
        let stack = irp_builder::first_stack_location(irp, count);
        guest::write32(irp + packet::FLAGS, 4);
        if let Some(query) = options {
            guest::write8(stack + 2, query.restart as u8 | (query.single as u8) << 1 | ((query.index != 0) as u8) << 2);
            guest::write64(stack + 16, query.names);
            guest::write32(stack + 24, query.names_length);
            guest::write32(stack + 32, if query.index != 0 { guest::read32(query.index) } else { 0 });
        }
        if let Some(failure) = retained_irp::dispatch(device, irp, stack, event, routine)? {
            return Ok(failure);
        }
        if let Some(query) = options {
            guest::write32(query.returned, guest::read32(irp + packet::IO_STATUS_INFORMATION));
        }
        Ok(guest::read32(irp + packet::IO_STATUS))
    })();
    if irp != 0 {
        // O driver pode anexar MDLs ao pedido: os buffers são do chamador,
        // os descritores pertencem ao IRP concluído e voltam ao dono real.
        let mut mdl = guest::read64(irp + packet::MDL_ADDRESS);
        while mdl != 0 {
            let next = guest::read64(mdl);
            if kernel_pool::owns(mdl) {
                kernel_pool::free(mdl, None)?;
            } else if data_pool::owns(mdl) {
                data_pool::free(mdl)?;
            } else if guest::owns_allocation(mdl) {
                guest::free_bytes(mdl);
            } else {
                return Err(KernelError::new("MDL descriptor has no allocation owner"));
            }
            mdl = next;
        }
        guest::free_bytes(irp);
    }
    guest::free_bytes(event);
    result
}

fn read(pointer: u64, length: u32) -> Vec<u8> {
    (0..length as u64).map(|index| guest::read8(pointer + index)).collect()
}

fn failure_status(error: &KernelError) -> u32 {
    if error.status != STATUS_UNSUCCESSFUL { error.status } else { 0xC000_0185 }
}

#[allow(clippy::too_many_arguments)]
pub fn query(file: u64, buffer: u64, length: u32, single: u8, names: u64, names_length: u32, index: u64, restart: u8, returned: u64) -> Result<u32, KernelError> {
    let (single, restart) = (single != 0, restart != 0);
    if guest::read32(file + 0x50) & 0x800 != 0 {
        return Ok(0xC000_0010);
    }
    let device = file_information::related_device(file)?;
    if device != 0 {
        return native(file, buffer, length, Some(&Query { restart, single, names, names_length, index, returned }), device);
    }
    let backing = crate::ntos::io::file::zw::file_backing(file);
    let (mut status, mut information, mut bytes) = (0xC000_004F, 0, Vec::new());
    if let Some((volume, path)) = backing {
        let options = QueryOptions { single, restart, names: (names != 0 && names_length != 0).then(|| read(names, names_length)), index: (index != 0).then(|| guest::read32(index)) };
        let mut state = QueryState { index: file_objects::ea_index(file)? as usize };
        if let Some(result) = volume.query_ea(&path, length as usize, &options, &mut state) {
            match result {
                Ok(result) => {
                    file_objects::set_ea_index(file, state.index as u32)?;
                    (status, information, bytes) = (result.status, result.information, result.bytes);
                }
                Err(error) => (status, information) = (failure_status(&error), 0),
            }
        }
    }
    guest::write_bytes(buffer, &bytes);
    guest::write32(returned, information);
    Ok(status)
}

pub fn set(file: u64, buffer: u64, length: u32) -> Result<u32, KernelError> {
    if guest::read32(file + 0x50) & 0x800 != 0 {
        return Ok(0xC000_0010);
    }
    let device = file_information::related_device(file)?;
    if device != 0 {
        return native(file, buffer, length, None, device);
    }
    let Some((volume, path)) = crate::ntos::io::file::zw::file_backing(file) else { return Ok(0xC000_004F) };
    match volume.set_ea(&path, &read(buffer, length), true) {
        None => Ok(0xC000_004F),
        Some(Ok(())) => Ok(0),
        Some(Err(error)) => Ok(failure_status(&error)),
    }
}
