//! NtReadFile/ZwReadFile.
//!
//! Argumentos capturados, bytes reais do arquivo de volume (ou da fonte) ou
//! IRP_MJ_READ ao driver (Fast I/O primeiro), e conclusão pela mesma posse
//! das requisições de controle (`file_request`). Os handles de usuário
//! entram com o estado de modo usuário (fase 7).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::io::file::request::{self as file_request, Shared};
use crate::ntos::io::transfer::backed_file_transfer::{self, NtfsFile, TransferSource};
use crate::ntos::io::{cancel, io_manager};
use crate::ntos::io::file::{information as file_information, query as query_file};
use crate::hal::amd64::native_call;
use crate::drivers::fs::volume::FileSystem;
use crate::drivers::fs::ntfs;
use crate::ntos::ke::{dispatcher, irql};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::objects::file::{self as file_objects, FileSource};
use crate::ntos::ps::{previous_mode, process, user_probe};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{DeviceObject, DriverObject, Ethread, FastIoDispatch, FileObject, IoStackLocation, IoStatusBlock, Irp, Kthread, LargeInteger, NtStruct};
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::io::file::zw as zw_files;

const AV: u32 = 0xC000_0005;
const INVALID: u32 = 0xC000_000D;

/// FILE_OBJECT vivo (referenciado pelo handle do pedido).
fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: o pedido mantém a referência do FILE_OBJECT.
    unsafe { FileObject::at(file) }
}

/// DEVICE_OBJECT vivo (o relacionado ao arquivo).
fn device_at(device: u64) -> &'static DeviceObject {
    // SAFETY: dispositivo relacionado a um FILE_OBJECT vivo.
    unsafe { DeviceObject::at(device) }
}

/// Bloco de argumentos do Fast I/O (88 bytes alocados pelo chamador):
/// FileOffset em +64 e o IO_STATUS_BLOCK em +72.
const FAST_OFFSET: u64 = 64;
const FAST_IO_STATUS: u64 = 72;

/// Rotina de Fast I/O do driver do dispositivo, se a tabela a tiver.
fn fast_routine(device: u64, minimum: u32, select: fn(&FastIoDispatch) -> u64) -> u64 {
    let driver = device_at(device).driver_object.get();
    // SAFETY: DeviceObject->DriverObject de um dispositivo vivo.
    let table = if driver != 0 { unsafe { DriverObject::at(driver) }.fast_io_dispatch.get() } else { 0 };
    if table == 0 {
        return 0;
    }
    // SAFETY: DriverObject->FastIoDispatch do driver vivo.
    let dispatch = unsafe { FastIoDispatch::at(table) };
    if dispatch.size_of_fast_io_dispatch.get() >= minimum { select(dispatch) } else { 0 }
}

pub(crate) fn probe(pointer: u64, length: u64, write: bool) -> bool {
    if length == 0 {
        return true;
    }
    pointer > 0 && pointer.checked_add(length).is_some_and(|end| end <= crate::ntos::mm::memory_map::USER_PROBE_ADDRESS) && if write { user_probe::probe_user_write(pointer, length) } else { user_probe::probe_user_read(pointer, length) }
}

/// Bytes de um arquivo de volume.
struct VolumeTransfer {
    volume: &'static dyn FileSystem,
    path: alloc::string::String,
}

impl TransferSource for VolumeTransfer {
    fn read_at(&self, offset: u64, length: u64) -> Result<Option<Vec<u8>>, KernelError> {
        self.volume.read_range(&self.path, offset, length)
    }
}

/// Bytes de uma fonte de imagem.
struct SourceTransfer(Arc<dyn FileSource>);

impl TransferSource for SourceTransfer {
    fn read_at(&self, offset: u64, length: u64) -> Result<Option<Vec<u8>>, KernelError> {
        let available = self.0.size().saturating_sub(offset).min(length);
        self.0.read_at(offset, available as usize).map(Some)
    }
}

/// Arquivo com bytes próprios (volume ou fonte): tamanho, diretório e leitor.
pub(crate) struct Backing {
    pub size: u64,
    pub directory: bool,
    pub source: Box<dyn TransferSource>,
}

pub(crate) fn backing(file: u64) -> Result<Option<Backing>, u32> {
    if let Some((volume, path)) = zw_files::file_backing(file) {
        let stat = volume.stat(&path);
        let Some(size) = volume.size(&path).or_else(|| stat.as_ref().map(|stat| stat.size)) else { return Err(0xC000_0123) };
        let directory = stat.as_ref().is_some_and(|stat| stat.directory || stat.attributes & 0x10 != 0);
        // O caminho físico do volume entra quando ele fornece a capacidade.
        let ntfs_file = ntfs::mounted().filter(|mounted| {
            let mounted_volume: &dyn FileSystem = mounted.as_ref();
            core::ptr::addr_eq(mounted_volume as *const dyn FileSystem, volume as *const dyn FileSystem)
        });
        let source: Box<dyn TransferSource> = match ntfs_file {
            Some(mounted) => Box::new(NtfsFile { volume: mounted, path }),
            None => Box::new(VolumeTransfer { volume, path }),
        };
        return Ok(Some(Backing { size, directory, source }));
    }
    Ok(file_objects::source(file).map(|source| Backing { size: source.size(), directory: source.stat().is_some_and(|stat| stat.directory), source: Box::new(SourceTransfer(source)) }))
}

/// FastIoRead do driver (arquivo síncrono com cache inicializado).
fn fast_read(request: &Shared, device: u64, offset: i64, key: u32) -> Result<bool, KernelError> {
    let (synchronous, file, output, length) = {
        let r = request.lock();
        (r.synchronous, r.file, r.output, r.output_length)
    };
    if !synchronous || file_at(file).private_cache_map.get() == 0 {
        return Ok(false);
    }
    let fast = fast_routine(device, 0x18, |dispatch| dispatch.fast_io_read.get());
    if fast == 0 {
        return Ok(false);
    }
    let arguments = guest::alloc_bytes(88);
    if arguments == 0 {
        return Ok(false);
    }
    // SAFETY: células do bloco de argumentos recém-alocado.
    let (file_offset, iosb) = unsafe { (LargeInteger::at(arguments + FAST_OFFSET), IoStatusBlock::at(arguments + FAST_IO_STATUS)) };
    file_offset.quad_part.set(offset);
    let handled = native_call::call(fast, &[file, file_offset.address(), length as u64, 1, key as u64, output, iosb.address(), device]) & 0xFF != 0;
    let result = if handled {
        let status = iosb.status.get() as u32;
        if status != 0 && status != 0x8000_0005 && status != 0xC000_0011 {
            Ok(false)
        } else {
            {
                let mut r = request.lock();
                r.status = status;
                r.information = iosb.information.get();
                r.done = true;
                r.skip_apc = true;
            }
            file_request::finish(request)?;
            Ok(true)
        }
    } else {
        Ok(false)
    };
    guest::free_bytes(arguments);
    result
}

/// IRP_MJ_READ com o método do dispositivo (buffered, direct ou neither).
fn dispatch(request: &Shared, device: u64, offset: i64, key: u32, flags: u32) -> Result<u32, KernelError> {
    if fast_read(request, device, offset, key)? {
        return Ok(request.lock().status);
    }
    let count = match device_at(device).stack_size.get() as u8 {
        0 => 1,
        count => count as u32,
    };
    let device_flags = device_at(device).flags.get();
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if packet == 0 {
        return Ok(0xC000_009A);
    }
    request.lock().irp = packet;
    let mut irp_flags = 0x900 | if flags & 8 != 0 { 1 } else { 0 };
    let mut user_buffer = 0;
    let (output, length) = {
        let r = request.lock();
        (r.output, r.output_length)
    };
    if device_flags & 4 != 0 {
        request.lock().copy_output = true;
        irp_flags |= if length != 0 { 0x70 } else { 0x50 };
        if length != 0 {
            let Ok(system) = kernel_pool::allocate(length as u64, AllocateOptions { paged: false, tag: 0x6452_6F49, ..Default::default() }) else { return Ok(0xC000_009A) };
            if system == 0 {
                return Ok(0xC000_009A);
            }
            request.lock().system = system;
            user_buffer = output;
        }
    } else if device_flags & 16 != 0 {
        if length != 0 && !file_request::fill_mdl(request, true)? {
            return Ok(0xC000_009A);
        }
    } else {
        user_buffer = output;
    }
    let (system, file, thread, mode, io_status, event, mdl_address, apc_routine, apc_context) = {
        let r = request.lock();
        (r.system, r.file, r.thread, r.mode, r.io_status, r.event.as_ref().map_or(0, |event| event.pointer), r.mdl, r.apc_routine, r.apc_context)
    };
    irp_builder::build(packet, &BuildOptions { major: 3, minor: 0, buffer: system, buffer_length: length, device_object: device, stack_count: count, file_object: file, thread, requestor_mode: mode, byte_offset: offset as u64, user_iosb: io_status, user_buffer, user_event: event, ..Default::default() });
    // SAFETY: IRP recém-construído e o slot do topo dele.
    let (irp, stack) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count))) };
    stack.parameters.read.key.set(key);
    irp.mdl_address.set(mdl_address);
    irp.overlay.asynchronous_parameters.user_apc_routine.set(apc_routine);
    irp.overlay.asynchronous_parameters.user_apc_context.set(apc_context);
    irp.flags.set(irp_flags);
    let completed = request.clone();
    io_manager::manage_completion(packet, Box::new(move |status, information| {
        {
            let mut r = completed.lock();
            r.done = true;
            r.status = status as u32;
            r.information = information;
        }
        let _ = file_request::finish(&completed);
    }));
    file_request::track(request);
    let status = io_manager::iof_call_driver(device, packet) as u32;
    if !request.lock().done && status != 0x103 {
        if status >> 30 != 3 {
            return Err(KernelError::new("driver returned without completing its read IRP"));
        }
        {
            let mut r = request.lock();
            r.done = true;
            r.status = if status == 0xFFFF_FFFD { 0xC000_0010 } else { status };
            r.information = 0;
        }
        file_request::finish(request)?;
    }
    Ok(status)
}

#[allow(clippy::too_many_arguments)]
pub fn read(handle: u64, event: u64, apc_routine: u64, apc_context: u64, io_status: u64, output: u64, length: u32, offset_pointer: u64, key_pointer: u64) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("NtReadFile requires PASSIVE_LEVEL"));
    }
    let thread = process::get_current_thread();
    let mode = previous_mode::get()?;
    // SAFETY: a thread corrente.
    if unsafe { Kthread::at(thread) }.special_apc_disable.get() != 0 {
        return Err(KernelError::new("NtReadFile requires special APCs enabled"));
    }
    let selected = match query_file::resolve(handle & !3, mode != 0) {
        Ok(selected) => selected,
        Err(status) => return Ok(status),
    };
    if mode != 0 && selected.access & 1 == 0 {
        return Ok(0xC000_0022);
    }
    let file = selected.pointer;
    let flags = file_at(file).flags.get();
    let synchronous = flags & 2 != 0;
    if mode != 0 {
        if !probe(io_status, 16, true) || !probe(output, length as u64, true) {
            return Ok(AV);
        }
        if file_at(file).completion_context.get() != 0 && apc_routine & !1 != 0 {
            return Ok(INVALID);
        }
        if offset_pointer != 0 && offset_pointer & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if (offset_pointer != 0 && !probe(offset_pointer, 8, false)) || (key_pointer != 0 && !probe(key_pointer, 4, false)) {
            return Ok(AV);
        }
    }
    let request = file_request::new(file, thread, Some(process::get_current_process()), mode, io_status, output, length, apc_routine, apc_context, synchronous);
    let mut locked = false;
    let result = (|| -> Result<u32, KernelError> {
        // ByteOffset e Key podem ser ponteiros de modo usuário: leitura sondada.
        // (alinhamento de ULONG, como o ProbeForRead do NT).
        let mut offset = if offset_pointer != 0 { guest::try_read::<i64>(offset_pointer)? } else { 0 };
        let key = if key_pointer != 0 { guest::try_read::<u32>(key_pointer)? } else { 0 };
        let device = file_information::related_device(file)?;
        if mode != 0 && flags & 8 != 0 {
            let sector = if device != 0 { device_at(device).sector_size.get() as u32 } else { 512 };
            let alignment = if device != 0 { device_at(device).alignment_requirement.get() as u64 } else { 511 };
            if (sector != 0 && length % sector != 0) || output & alignment != 0 || (offset_pointer != 0 && sector != 0 && (offset as u64) & (sector as u64 - 1) != 0) {
                return Ok(INVALID);
            }
        }
        let prepared = file_request::prepare(&request, event)?;
        if prepared != 0 {
            return Ok(prepared);
        }
        if synchronous {
            file_information::acquire_file(file)?;
            locked = true;
        }
        if synchronous && (offset_pointer == 0 || offset == -2) {
            offset = file_at(file).current_byte_offset.quad_part.get();
        }
        if (!synchronous && offset_pointer == 0 && flags & 0x280 == 0) || offset < 0 {
            return Ok(INVALID);
        }
        dispatcher::clear_event(file_at(file).event.address());
        let start = offset;
        request.lock().on_complete = Some(Box::new(move |status, count| {
            if synchronous && status & 0x8000_0000 == 0 {
                file_at(file).current_byte_offset.quad_part.set((start as u64).wrapping_add(count) as i64);
            }
        }));
        let source = match backing(file) {
            Ok(source) => source,
            Err(status) => return Ok(status),
        };
        let status = if let Some(source) = source {
            if source.directory {
                return Ok(0xC000_00BA);
            }
            let mut transferred = 0;
            let mut status = 0;
            if length != 0 {
                if offset as u64 >= source.size {
                    status = 0xC000_0011;
                } else {
                    transferred = backed_file_transfer::read_into_guest(source.source.as_ref(), offset as u64, output, (length as u64).min(source.size - offset as u64))?;
                }
            }
            {
                let mut r = request.lock();
                r.status = status;
                r.information = transferred;
                r.done = true;
            }
            file_request::finish(&request)?;
            status
        } else {
            if device == 0 {
                return Ok(0xC000_0010);
            }
            dispatch(&request, device, offset, key, flags)?
        };
        if status == 0x103 && synchronous {
            loop {
                file_request::pump();
                if request.lock().finished {
                    break;
                }
                // SAFETY: a thread corrente.
                if unsafe { Ethread::at(thread) }.terminated() != 0 {
                    let irp = request.lock().irp;
                    if irp != 0 {
                        let _ = cancel::irp(irp);
                    }
                }
                dispatcher::pump_kernel();
            }
            return Ok(request.lock().status);
        }
        let r = request.lock();
        Ok(if status == 0x103 && !synchronous { status } else if r.finished { r.status } else { status })
    })();
    if locked {
        file_information::release_file(file)?;
    }
    if !file_request::is_tracked(&request) && !request.lock().finished {
        file_request::cleanup(&request)?;
    }
    match result {
        Err(error) if error.status != 0xC000_0001 => Ok(error.status),
        other => other,
    }
}
