//! NtQueryEaFile pelo ZwQueryEaFile: o serviço com o modo anterior
//! KernelMode.
//!
//! ntoskrnl 19041 (NtQueryEaFile 0x67f740, ZwQueryEaFile 0x3fc330 pelo
//! KiServiceInternal com o serviço 0x146). No ramo KernelMode:
//! - EaList com EaListLength vira uma cópia em pool (sem validar a lista);
//!   o EaIndex, quando dado, é lido do ponteiro;
//! - IopReferenceFileObject(handle, FILE_READ_EA): a falha volta sem tocar no
//!   IO_STATUS_BLOCK;
//! - IRP_MJ_QUERY_EA ao IoGetRelatedDeviceObject, com OriginalFileObject,
//!   Thread e RequestorMode KernelMode; a cópia da lista vai em
//!   Tail.Overlay.AuxiliaryBuffer e em Parameters.QueryEa.EaList/
//!   EaListLength; Parameters.QueryEa.Length e EaIndex; os flags da pilha
//!   SL_RESTART_SCAN, SL_RETURN_SINGLE_ENTRY e SL_INDEX_SPECIFIED;
//! - o buffer segue o método do dispositivo: DO_BUFFERED_IO usa um
//!   SystemBuffer zerado (IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER |
//!   IRP_INPUT_OPERATION, copiado para o buffer do chamador na conclusão sem
//!   erro), DO_DIRECT_IO um MDL travado para escrita, e o resto o próprio
//!   UserBuffer;
//! - o IopSynchronousServiceTail espera a conclusão e o IO_STATUS_BLOCK do
//!   chamador recebe Status e Information.
//!
//! Os arquivos dos volumes do próprio kernel (sem DEVICE_OBJECT de file
//! system) respondem pelo mesmo caminho do FsRtlQueryKernelEaFile.
//!
//! NtSetEaFile pelo ZwSetEaFile (NtSetEaFile 0x730f20), no ramo KernelMode:
//! - IopReferenceFileObject(handle, FILE_WRITE_EA): a falha volta sem tocar no
//!   IO_STATUS_BLOCK;
//! - IRP_MJ_SET_EA ao IoGetRelatedDeviceObject, com OriginalFileObject,
//!   Thread, RequestorMode KernelMode, IRP_SYNCHRONOUS_API e
//!   Parameters.SetEa.Length;
//! - DO_BUFFERED_IO: com Length, um SystemBuffer do pool com a cópia da
//!   lista, conferida pelo IoCheckEaBufferValidity antes do IRP — um status
//!   de sinal negativo (o aviso STATUS_EA_LIST_INCONSISTENT inclusive) vai
//!   ao IO_STATUS_BLOCK com o ErrorOffset em Information e volta sem IRP —
//!   e IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER; sem Length, nenhum buffer;
//!   DO_DIRECT_IO: um MDL travado para leitura; nos demais, o próprio
//!   UserBuffer (nesses dois a lista não é conferida pelo I/O Manager);
//! - o IopSynchronousServiceTail espera a conclusão e o IO_STATUS_BLOCK do
//!   chamador recebe Status e Information.
//! Os arquivos dos volumes do próprio kernel gravam pelo FsRtlSetKernelEaFile.

use crate::ntos::inc::types::{DeviceObject, IoStackLocation, Irp, NtStruct};
use crate::ntos::io::file::{information as file_information, query as file_query};
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::io::{buffer_validation, kernel_ea, mdl as io_mdl, retained_irp};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{kernel_pool, mdl as mm_mdl};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
/// IRP_MJ_QUERY_EA e IRP_MJ_SET_EA.
const IRP_MJ_QUERY_EA: u8 = 7;
const IRP_MJ_SET_EA: u8 = 8;
/// IRP.Flags.
const IRP_SYNCHRONOUS_API: u32 = 0x4;
const IRP_BUFFERED_IO: u32 = 0x10;
const IRP_DEALLOCATE_BUFFER: u32 = 0x20;
const IRP_INPUT_OPERATION: u32 = 0x40;
/// DEVICE_OBJECT.Flags.
const DO_BUFFERED_IO: u32 = 0x4;
const DO_DIRECT_IO: u32 = 0x10;
/// IO_STACK_LOCATION.Flags do IRP_MJ_QUERY_EA.
const SL_RESTART_SCAN: u8 = 0x01;
const SL_RETURN_SINGLE_ENTRY: u8 = 0x02;
const SL_INDEX_SPECIFIED: u8 = 0x04;
/// Tag do pool da cópia da lista e do SystemBuffer.
const POOL_TAG: u32 = 0x2020_6F49;

/// Parâmetros do NtQueryEaFile.
pub struct QueryEa {
    pub handle: u64,
    pub io_status: u64,
    pub buffer: u64,
    pub length: u32,
    pub single: bool,
    pub ea_list: u64,
    pub ea_list_length: u32,
    pub ea_index: u64,
    pub restart: bool,
}

fn pool(length: u32) -> u64 {
    kernel_pool::allocate(length as u64, kernel_pool::AllocateOptions { tag: POOL_TAG, ..Default::default() }).unwrap_or(0)
}

fn free_pool(pointer: u64) {
    if pointer != 0 {
        let _ = kernel_pool::free(pointer, None);
    }
}

/// ZwQueryEaFile(FileHandle, IoStatusBlock, Buffer, Length,
/// ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan).
pub fn query_ea_file(request: &QueryEa) -> Result<u32, KernelError> {
    let mut list = 0;
    if request.ea_list != 0 && request.ea_list_length != 0 {
        list = pool(request.ea_list_length);
        if list == 0 {
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        guest::write_bytes(list, &guest::read_bytes(request.ea_list, request.ea_list_length as usize));
    }
    let selected = match file_query::resolve(request.handle, false) {
        Ok(selected) if selected.pointer != 0 => selected,
        Ok(_) => {
            free_pool(list);
            return Ok(STATUS_INVALID_HANDLE);
        }
        Err(status) => {
            free_pool(list);
            return Ok(status);
        }
    };
    let file = selected.pointer;
    if file_objects::reference(file)?.is_none() {
        free_pool(list);
        return Ok(STATUS_INVALID_HANDLE);
    }
    let result = (|| -> Result<(u32, u64), KernelError> {
        let device = file_information::related_device(file)?;
        if device == 0 {
            // Arquivo de volume do kernel: a consulta direta ao volume.
            let returned = guest::alloc_bytes(8);
            if returned == 0 {
                return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
            }
            let status = kernel_ea::query(file, request.buffer, request.length, request.single as u8, list, if list != 0 { request.ea_list_length } else { 0 }, request.ea_index, request.restart as u8, returned)?;
            let information = guest::read32(returned) as u64;
            guest::free_bytes(returned);
            return Ok((status, information));
        }
        send(request, file, device, list)
    })();
    file_objects::dereference(file)?;
    // A cópia da lista pertence ao IRP (AuxiliaryBuffer) até a conclusão.
    free_pool(list);
    let (status, information) = result?;
    if information != u64::MAX {
        guest::write32(request.io_status, status);
        guest::write64(request.io_status + 8, information);
    }
    Ok(status)
}

/// O IRP_MJ_QUERY_EA do NtQueryEaFile ao dispositivo do file system:
/// (status, Information), ou Information = u64::MAX quando o pedido não
/// chegou a ser concluído (o IO_STATUS_BLOCK fica como estava).
fn send(request: &QueryEa, file: u64, device: u64, list: u64) -> Result<(u32, u64), KernelError> {
    let routine = retained_irp::completion_routine()?;
    if routine == 0 {
        return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
    }
    let event = guest::alloc_bytes(40);
    if event == 0 {
        return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
    }
    // SAFETY: dispositivo relacionado ao arquivo, vivo durante o pedido.
    let target = unsafe { DeviceObject::at(device) };
    let count = (target.stack_size.get() as u8).max(1) as u32;
    let irp = guest::alloc_bytes(irp_builder::size_for(count));
    let (mut system_buffer, mut descriptor) = (0u64, 0u64);
    let result = (|| -> Result<(u32, u64), KernelError> {
        if irp == 0 {
            return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
        }
        dispatcher::initialize_event(event, 0, false);
        irp_builder::build(irp, &BuildOptions { major: IRP_MJ_QUERY_EA, device_object: device, stack_count: count, file_object: file, requestor_mode: 0, thread: process::get_current_thread(), ..BuildOptions::default() });
        let stack = irp_builder::first_stack_location(irp, count);
        // SAFETY: IRP recém-construído e o slot do topo dele.
        let (packet, location) = unsafe { (Irp::at(irp), IoStackLocation::at(stack)) };
        packet.flags.set(IRP_SYNCHRONOUS_API);
        packet.tail.overlay.auxiliary_buffer.set(list);
        let parameters = &location.parameters.query_ea;
        parameters.length.set(request.length);
        parameters.ea_list.set(list);
        parameters.ea_list_length.set(if list != 0 { request.ea_list_length } else { 0 });
        parameters.ea_index.set(if request.ea_index != 0 { guest::read32(request.ea_index) } else { 0 });
        let flags = (if request.restart { SL_RESTART_SCAN } else { 0 }) | (if request.single { SL_RETURN_SINGLE_ENTRY } else { 0 }) | (if request.ea_index != 0 { SL_INDEX_SPECIFIED } else { 0 });
        location.flags.set(flags);
        let device_flags = target.flags.get();
        if device_flags & DO_BUFFERED_IO != 0 {
            if request.length != 0 {
                system_buffer = pool(request.length);
                if system_buffer == 0 {
                    return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
                }
                guest::write_bytes(system_buffer, &alloc::vec![0u8; request.length as usize]);
                packet.associated_irp.system_buffer.set(system_buffer);
                packet.flags.set(packet.flags.get() | IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION);
            } else {
                packet.flags.set(packet.flags.get() | IRP_BUFFERED_IO | IRP_INPUT_OPERATION);
            }
            packet.user_buffer.set(request.buffer);
        } else if device_flags & DO_DIRECT_IO != 0 {
            if request.length != 0 {
                descriptor = io_mdl::allocate_mdl(request.buffer, request.length);
                if descriptor == 0 {
                    return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
                }
                // O sistema de arquivos escreve as EAs no buffer (IoWriteAccess).
                mm_mdl::probe_and_lock_pages(descriptor, 1);
                packet.mdl_address.set(descriptor);
            }
        } else {
            packet.user_buffer.set(request.buffer);
        }
        if let Some(failure) = retained_irp::dispatch(device, irp, stack, event, routine)? {
            return Ok((failure, u64::MAX));
        }
        let (status, information) = (packet.io_status.status.get() as u32, packet.io_status.information.get());
        // A cópia de volta do IopCompleteRequest para o IRP_INPUT_OPERATION
        // bufferizado: só sem erro, e só os bytes de Information.
        if system_buffer != 0 && status & 0xC000_0000 != 0xC000_0000 && information != 0 {
            guest::write_bytes(request.buffer, &guest::read_bytes(system_buffer, information.min(request.length as u64) as usize));
        }
        Ok((status, information))
    })();
    if descriptor != 0 {
        mm_mdl::unlock_pages(descriptor);
        io_mdl::free_mdl(descriptor);
    }
    free_pool(system_buffer);
    if irp != 0 {
        guest::free_bytes(irp);
    }
    guest::free_bytes(event);
    result
}

// ---- ZwSetEaFile ---------------------------------------------------------------

/// ZwSetEaFile(FileHandle, IoStatusBlock, Buffer, Length).
pub fn set_ea_file(handle: u64, io_status: u64, buffer: u64, length: u32) -> Result<u32, KernelError> {
    let selected = match file_query::resolve(handle, false) {
        Ok(selected) if selected.pointer != 0 => selected,
        Ok(_) => return Ok(STATUS_INVALID_HANDLE),
        Err(status) => return Ok(status),
    };
    let file = selected.pointer;
    if file_objects::reference(file)?.is_none() {
        return Ok(STATUS_INVALID_HANDLE);
    }
    let result = (|| -> Result<(u32, u64), KernelError> {
        let device = file_information::related_device(file)?;
        if device == 0 {
            // Arquivo de volume do kernel: a gravação direta no volume.
            return Ok((kernel_ea::set(file, buffer, length)?, 0));
        }
        send_set(file, device, buffer, length)
    })();
    file_objects::dereference(file)?;
    let (status, information) = result?;
    if information != u64::MAX {
        guest::write32(io_status, status);
        guest::write64(io_status + 8, information);
    }
    Ok(status)
}

/// O IRP_MJ_SET_EA do NtSetEaFile ao dispositivo do file system: (status,
/// Information), com Information = u64::MAX quando o pedido não chegou a ser
/// concluído (o IO_STATUS_BLOCK fica como estava). Uma lista recusada pelo
/// IoCheckEaBufferValidity volta como (status, ErrorOffset).
fn send_set(file: u64, device: u64, buffer: u64, length: u32) -> Result<(u32, u64), KernelError> {
    let routine = retained_irp::completion_routine()?;
    if routine == 0 {
        return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
    }
    let event = guest::alloc_bytes(40);
    if event == 0 {
        return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
    }
    // SAFETY: dispositivo relacionado ao arquivo, vivo durante o pedido.
    let target = unsafe { DeviceObject::at(device) };
    let count = (target.stack_size.get() as u8).max(1) as u32;
    let irp = guest::alloc_bytes(irp_builder::size_for(count));
    let (mut system_buffer, mut descriptor) = (0u64, 0u64);
    let result = (|| -> Result<(u32, u64), KernelError> {
        if irp == 0 {
            return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
        }
        dispatcher::initialize_event(event, 0, false);
        irp_builder::build(irp, &BuildOptions { major: IRP_MJ_SET_EA, device_object: device, stack_count: count, file_object: file, requestor_mode: 0, thread: process::get_current_thread(), ..BuildOptions::default() });
        let stack = irp_builder::first_stack_location(irp, count);
        // SAFETY: IRP recém-construído e o slot do topo dele.
        let (packet, location) = unsafe { (Irp::at(irp), IoStackLocation::at(stack)) };
        packet.flags.set(IRP_SYNCHRONOUS_API);
        location.parameters.set_ea.length.set(length);
        let device_flags = target.flags.get();
        if device_flags & DO_BUFFERED_IO != 0 {
            if length != 0 {
                system_buffer = pool(length);
                if system_buffer == 0 {
                    return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
                }
                guest::write_bytes(system_buffer, &guest::read_bytes(buffer, length as usize));
                let offset = guest::alloc_bytes(4);
                // SAFETY: célula de rascunho do ErrorOffset.
                let status = buffer_validation::check_ea_buffer_validity(system_buffer, length, unsafe { crate::ntos::inc::field::Field::<u32>::at(offset) });
                let error_offset = guest::read32(offset) as u64;
                guest::free_bytes(offset);
                if status & 0x8000_0000 != 0 {
                    return Ok((status, error_offset));
                }
                packet.associated_irp.system_buffer.set(system_buffer);
                packet.flags.set(packet.flags.get() | IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER);
            }
        } else if device_flags & DO_DIRECT_IO != 0 {
            if length != 0 {
                descriptor = io_mdl::allocate_mdl(buffer, length);
                if descriptor == 0 {
                    return Ok((STATUS_INSUFFICIENT_RESOURCES, u64::MAX));
                }
                // O sistema de arquivos lê as EAs do buffer (IoReadAccess).
                mm_mdl::probe_and_lock_pages(descriptor, 0);
                packet.mdl_address.set(descriptor);
            }
        } else {
            packet.user_buffer.set(buffer);
        }
        if let Some(failure) = retained_irp::dispatch(device, irp, stack, event, routine)? {
            return Ok((failure, u64::MAX));
        }
        Ok((packet.io_status.status.get() as u32, packet.io_status.information.get()))
    })();
    if descriptor != 0 {
        mm_mdl::unlock_pages(descriptor);
        io_mdl::free_mdl(descriptor);
    }
    free_pool(system_buffer);
    if irp != 0 {
        guest::free_bytes(irp);
    }
    guest::free_bytes(event);
    result
}
