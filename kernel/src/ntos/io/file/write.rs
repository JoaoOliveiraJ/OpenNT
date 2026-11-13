//! NtWriteFile/ZwWriteFile.
//!
//! Escreve no arquivo de volume aberto ou monta IRP_MJ_WRITE (Fast I/O
//! primeiro); a posse do buffer e a conclusão são as mesmas dos demais
//! serviços de arquivo (`file_request`). Fontes de imagem são somente
//! leitura. Os handles de usuário entram com o estado de modo usuário (fase 7).

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::ntos::io::file::request::{self as file_request, Shared};
use crate::ntos::io::file::read::probe;
use crate::ntos::io::{cancel, io_manager};
use crate::ntos::io::file::{information as file_information, query as query_file};
use crate::hal::amd64::native_call;
use crate::ntos::ke::{dispatcher, irql};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::{previous_mode, process};
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{io_stack_location, irp};
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::io::file::zw as zw_files;

const AV: u32 = 0xC000_0005;
const INVALID: u32 = 0xC000_000D;
/// Maior offset+tamanho aceito (Number.MAX_SAFE_INTEGER do original).
const MAX_SAFE: u64 = (1 << 53) - 1;

fn range(pointer: u64, length: u64) -> bool {
    length == 0 || pointer.checked_add(length).is_some_and(|end| end <= 0x7FFF_FFFF_0000)
}

/// FastIoWrite do driver: só aceita STATUS_SUCCESS.
fn fast_write(request: &Shared, device: u64, offset: i64, key: u32, flags: u32) -> Result<bool, KernelError> {
    let (synchronous, file, input, length) = {
        let r = request.lock();
        (r.synchronous, r.file, r.output, r.output_length)
    };
    if !synchronous || guest::read64(file + 0x30) == 0 {
        return Ok(false);
    }
    let driver = guest::read64(device + 8);
    let table = if driver != 0 { guest::read64(driver + 0x50) } else { 0 };
    let fast = if table != 0 && guest::read32(table) >= 0x20 { guest::read64(table + 0x18) } else { 0 };
    if fast == 0 {
        return Ok(false);
    }
    let arguments = guest::alloc_bytes(88);
    if arguments == 0 {
        return Ok(false);
    }
    guest::write64(arguments + 64, offset as u64);
    let handled = native_call::call(fast, &[file, arguments + 64, length as u64, 1, key as u64, input, arguments + 72, device]) & 0xFF != 0;
    let result = if !handled || guest::read32(arguments + 72) != 0 {
        Ok(false)
    } else {
        {
            let mut r = request.lock();
            r.status = 0;
            r.information = guest::read64(arguments + 80);
            r.done = true;
            r.skip_apc = true;
            r.skip_event = flags & 0x0800_0000 != 0;
            r.skip_file_event = true;
        }
        file_request::finish(request).map(|_| true)
    };
    guest::free_bytes(arguments);
    result
}

/// IRP_MJ_WRITE com o método do dispositivo; o buffered copia a entrada
/// para o buffer de sistema antes de chamar o driver.
fn dispatch(request: &Shared, device: u64, offset: i64, key: u32, flags: u32) -> Result<u32, KernelError> {
    if fast_write(request, device, offset, key, flags)? {
        return Ok(0);
    }
    let count = match guest::read8(device + 0x4C) {
        0 => 1,
        count => count as u32,
    };
    let device_flags = guest::read32(device + 0x30);
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if packet == 0 {
        return Ok(0xC000_009A);
    }
    request.lock().irp = packet;
    let mut irp_flags = 0xA00 | if flags & 8 != 0 { 1 } else { 0 };
    let mut user_buffer = 0;
    let (input, length, mode) = {
        let r = request.lock();
        (r.output, r.output_length, r.mode)
    };
    if device_flags & 4 != 0 {
        irp_flags |= if length != 0 { 0x30 } else { 0x10 };
        if length != 0 {
            if mode != 0 && !probe(input, length as u64, false) {
                return Ok(AV);
            }
            let Ok(system) = kernel_pool::allocate(length as u64, AllocateOptions { paged: false, tag: 0x7257_6F49, ..Default::default() }) else { return Ok(0xC000_009A) };
            if system == 0 {
                return Ok(0xC000_009A);
            }
            for offset in 0..length as u64 {
                guest::write8(system + offset, guest::read8(input + offset));
            }
            request.lock().system = system;
        }
    } else if device_flags & 16 != 0 {
        if mode != 0 && !probe(input, length as u64, false) {
            return Ok(AV);
        }
        if length != 0 && !file_request::fill_mdl(request, false)? {
            return Ok(0xC000_009A);
        }
    } else {
        user_buffer = input;
    }
    let (system, file, thread, io_status, event, mdl_address, apc_routine, apc_context) = {
        let r = request.lock();
        (r.system, r.file, r.thread, r.io_status, r.event.as_ref().map_or(0, |event| event.pointer), r.mdl, r.apc_routine, r.apc_context)
    };
    irp_builder::build(packet, &BuildOptions { major: 4, minor: 0, buffer: system, buffer_length: length, device_object: device, stack_count: count, file_object: file, thread, requestor_mode: mode, byte_offset: offset as u64, user_iosb: io_status, user_buffer, user_event: event, ..Default::default() });
    let stack = irp_builder::first_stack_location(packet, count);
    let extension = guest::read64(file + 0xD0);
    // SL_WRITE_THROUGH para FILE_WRITE_THROUGH.
    guest::write8(stack + 2, if flags & 0x10 != 0 { 4 } else { 0 });
    guest::write32(stack + io_stack_location::READ_KEY, key);
    if extension != 0 && guest::read32(extension) & 0x10 != 0 {
        guest::write32(stack + 0x14, guest::read32(io_status + 8));
    }
    guest::write64(packet + irp::MDL_ADDRESS, mdl_address);
    guest::write32(packet + irp::FLAGS, irp_flags);
    guest::write64(packet + 0x58, apc_routine);
    guest::write64(packet + 0x60, apc_context);
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
            return Err(KernelError::new("driver returned without completing its write IRP"));
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

/// Escrita direta no arquivo do volume; offset -1 = fim do arquivo.
fn write_backed(file: u64, synchronous: bool, mode: u8, input: u64, length: u32, offset: &mut i64) -> Result<(u32, u64), KernelError> {
    let Some((volume, path)) = zw_files::file_backing(file) else {
        // Fontes de imagem não aceitam escrita.
        return Ok((0xC000_00A2, 0));
    };
    let stat = volume.stat(&path);
    let Some(size) = volume.size(&path).or_else(|| stat.as_ref().map(|stat| stat.size)) else { return Ok((0xC000_0123, 0)) };
    if stat.as_ref().is_some_and(|stat| stat.directory || stat.attributes & 0x10 != 0) {
        return Ok((0xC000_00BA, 0));
    }
    if *offset == -1 {
        *offset = size as i64;
    }
    if (*offset as u64).saturating_add(length as u64) > MAX_SAFE {
        return Ok((INVALID, 0));
    }
    if mode != 0 && !probe(input, length as u64, false) {
        return Ok((AV, 0));
    }
    let data: Vec<u8> = (0..length as u64).map(|index| guest::read8(input + index)).collect();
    let count = match volume.write_at(&path, *offset as u64, &data) {
        Ok(count) => count,
        Err(error) if error.status != 0xC000_0001 => return Ok((error.status, 0)),
        Err(error) => return Err(error),
    };
    if count > length as u64 {
        return Err(KernelError::new("filesystem returned invalid write length"));
    }
    if synchronous {
        guest::write64(file + 0x68, (*offset as u64).wrapping_add(count));
    }
    Ok((0, count))
}

#[allow(clippy::too_many_arguments)]
pub fn write(handle: u64, event: u64, apc_routine: u64, apc_context: u64, io_status: u64, input: u64, length: u32, offset_pointer: u64, key_pointer: u64) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("NtWriteFile requires PASSIVE_LEVEL"));
    }
    let thread = process::get_current_thread();
    let mode = previous_mode::get()?;
    if guest::read16(thread + 0x1E6) != 0 {
        return Err(KernelError::new("NtWriteFile requires special APCs enabled"));
    }
    let selected = match query_file::resolve(handle & !3, mode != 0) {
        Ok(selected) => selected,
        Err(status) => return Ok(status),
    };
    let file = selected.pointer;
    let flags = guest::read32(file + 0x50);
    // A referência de escrita confere direito de escrita/acréscimo mesmo em
    // KernelMode; pipes nomeados exigem FILE_WRITE_DATA.
    if selected.access & if flags & 0x80 != 0 { 2 } else { 6 } == 0 {
        return Ok(0xC000_0022);
    }
    let extension = guest::read64(file + 0xD0);
    if extension != 0 && guest::read32(extension) & 4 != 0 && process::get_primary_token(process::get_current_process()).and_then(|token| tokens::with(token, |token| token.app_container.is_some())).unwrap_or(false) {
        return Ok(0xC000_0910);
    }
    let synchronous = flags & 2 != 0;
    if mode != 0 {
        if !probe(io_status, 16, true) || !range(input, length as u64) {
            return Ok(AV);
        }
        if guest::read64(file + 0xB0) != 0 && apc_routine & !1 != 0 {
            return Ok(INVALID);
        }
        if offset_pointer != 0 && offset_pointer & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if (offset_pointer != 0 && !probe(offset_pointer, 8, false)) || (key_pointer != 0 && !probe(key_pointer, 4, false)) {
            return Ok(AV);
        }
    }
    let request = file_request::new(file, thread, Some(process::get_current_process()), mode, io_status, input, length, apc_routine, apc_context, synchronous);
    let mut locked = false;
    let result = (|| -> Result<u32, KernelError> {
        let mut offset = if offset_pointer != 0 { guest::read64(offset_pointer) as i64 } else { 0 };
        let key = if key_pointer != 0 { guest::read32(key_pointer) } else { 0 };
        let device = file_information::related_device(file)?;
        if mode != 0 && flags & 8 != 0 {
            let sector = if device != 0 { guest::read16(device + 0x130) as u32 } else { 512 };
            let alignment = if device != 0 { guest::read32(device + 0x98) as u64 } else { 511 };
            if (sector != 0 && length % sector != 0) || input & alignment != 0 || (offset_pointer != 0 && offset != -1 && !(offset == -2 && synchronous) && sector != 0 && (offset as u64) & (sector as u64 - 1) != 0) {
                return Ok(INVALID);
            }
        }
        // Só FILE_APPEND_DATA: toda escrita vai para o fim.
        if selected.access & 6 == 4 {
            offset = -1;
        }
        let prepared = file_request::prepare(&request, event)?;
        if prepared != 0 {
            return Ok(prepared);
        }
        if synchronous {
            file_information::acquire_file(file)?;
            locked = true;
        }
        if synchronous && ((offset_pointer == 0 && offset == 0) || offset == -2) {
            offset = guest::read64(file + 0x68) as i64;
        }
        if (!synchronous && offset_pointer == 0 && flags & 0x280 == 0) || offset < -1 {
            return Ok(INVALID);
        }
        dispatcher::clear_event(file + 0x98);
        let backed = zw_files::file_backing(file).is_some() || file_objects::source(file).is_some();
        let status = if backed {
            let (status, count) = write_backed(file, synchronous, mode, input, length, &mut offset)?;
            {
                let mut r = request.lock();
                r.status = status;
                r.information = count;
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
                if guest::read32(thread + 0x510) & 1 != 0 {
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
