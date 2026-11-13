//! ZwDeviceIoControlFile.
//!
//! Posse real do arquivo, Fast I/O ou IRP_MJ_DEVICE_CONTROL nativo, os
//! quatro métodos de buffer e conclusão no contexto da thread que pediu
//! (`file_request`).

use alloc::boxed::Box;

use crate::ntos::io::file::request::{self as file_request, Shared};
use super::{cancel, io_manager};
use crate::ntos::io::file::{information as file_information, query as query_file};
use crate::hal::amd64::native_call;
use crate::ntos::ke::{apc, dispatcher, irql};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{io_stack_location, irp};
use crate::ntos::io::irp_builder::{self, BuildOptions, DeviceControl};

const TAG: u32 = 0x7443_6F49;

fn dispatch(request: &Shared, device: u64, input: u64, input_length: u32, code: u32, access: u32) -> Result<u32, KernelError> {
    let (file, output, output_length, method) = {
        let r = request.lock();
        (r.file, r.output, r.output_length, r.method)
    };
    // FastIoDeviceControl (FAST_IO_DISPATCH+0x50).
    let driver = guest::read64(device + 8);
    let fast_table = if driver != 0 { guest::read64(driver + 0x50) } else { 0 };
    let fast = if fast_table != 0 && guest::read32(fast_table) >= 0x58 { guest::read64(fast_table + 0x50) } else { 0 };
    if fast != 0 {
        let arguments = guest::alloc_bytes(88);
        if arguments == 0 {
            return Ok(0xC000_009A);
        }
        let handled = native_call::call(fast, &[file, 1, input, input_length as u64, output, output_length as u64, code as u64, arguments + 72, device]) & 0xFF != 0;
        let result = if handled {
            let status = {
                let mut r = request.lock();
                r.status = guest::read32(arguments + 72);
                r.information = guest::read64(arguments + 80);
                r.done = true;
                r.status
            };
            file_request::finish(request).map(|_| Some(status))
        } else {
            Ok(None)
        };
        guest::free_bytes(arguments);
        if let Some(status) = result? {
            return Ok(status);
        }
    }
    let count = match guest::read8(device + 0x4C) {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if packet == 0 {
        return Ok(0xC000_009A);
    }
    request.lock().irp = packet;
    let size = match method {
        0 => input_length.max(output_length),
        3 => 0,
        _ => {
            if input != 0 {
                input_length
            } else {
                0
            }
        }
    };
    if size != 0 {
        let Ok(system) = kernel_pool::allocate(size as u64, AllocateOptions { paged: false, tag: TAG, ..Default::default() }) else { return Ok(0xC000_009A) };
        if system == 0 {
            return Ok(0xC000_009A);
        }
        for index in 0..size as u64 {
            guest::write8(system + index, if input != 0 && index < input_length as u64 { guest::read8(input + index) } else { 0 });
        }
        request.lock().system = system;
    }
    if (method == 1 || method == 2) && output_length != 0 && !file_request::fill_mdl(request, method == 2)? {
        return Ok(0xC000_009A);
    }
    let (system, thread, io_status, event, mdl_address, apc_routine, apc_context) = {
        let r = request.lock();
        (r.system, r.thread, r.io_status, r.event.as_ref().map_or(0, |event| event.pointer), r.mdl, r.apc_routine, r.apc_context)
    };
    irp_builder::build(packet, &BuildOptions {
        major: 14,
        minor: 0,
        buffer: system,
        buffer_length: output_length,
        device_object: device,
        stack_count: count,
        file_object: file,
        thread,
        requestor_mode: 0,
        user_iosb: io_status,
        user_buffer: if method == 1 || method == 2 { 0 } else { output },
        user_event: event,
        ioctl: Some(DeviceControl { code, input_length, type3_buffer: if method == 3 { input } else { 0 } }),
        ..Default::default()
    });
    let stack = irp_builder::first_stack_location(packet, count);
    guest::write8(stack + io_stack_location::FLAGS, ((access & 1) | ((access & 2) << 1)) as u8);
    guest::write64(packet + irp::MDL_ADDRESS, mdl_address);
    guest::write64(packet + 0x58, apc_routine);
    guest::write64(packet + 0x60, apc_context);
    guest::write32(packet + irp::FLAGS, if system != 0 { if method == 0 && output_length != 0 { 0x70 } else { 0x30 } } else { 0 });
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
            return Err(KernelError::new("driver returned without completing its IOCTL IRP"));
        }
        // Sem conclusão do driver: a falha real, sem IOSB inventado.
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
pub fn control(handle: u64, event: u64, apc_routine: u64, apc_context: u64, io_status: u64, code: u32, input: u64, input_length: u32, output: u64, output_length: u32) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("ZwDeviceIoControlFile requires PASSIVE_LEVEL"));
    }
    let thread = process::get_current_thread();
    if guest::read16(thread + 0x1E6) != 0 {
        return Err(KernelError::new("ZwDeviceIoControlFile requires special APCs enabled"));
    }
    let selected = match query_file::resolve(handle & !3, false) {
        Ok(selected) => selected,
        Err(status) => return Ok(status),
    };
    if selected.pointer == 0 {
        return Ok(0xC000_0010);
    }
    let file = selected.pointer;
    if guest::read64(file + 0xB0) != 0 && apc_routine & !1 != 0 {
        return Ok(0xC000_000D);
    }
    let device = file_information::related_device(file)?;
    if device == 0 {
        return Ok(0xC000_0010);
    }
    let request = file_request::new(file, thread, None, 0, io_status, output, output_length, apc_routine, apc_context, false);
    request.lock().method = code & 3;
    let synchronous = guest::read32(file + 0x50) & 2 != 0;
    let mut locked = false;
    let result = (|| -> Result<u32, KernelError> {
        if file_objects::reference(file)?.is_none() {
            return Ok(0xC000_0008);
        }
        process::reference_thread(thread);
        request.lock().retained = true;
        if event != 0 {
            let reference = match file_request::event_reference(event, 0) {
                Ok(reference) => reference,
                Err(status) => return Ok(status),
            };
            dispatcher::clear_event(reference.pointer);
            request.lock().event = Some(reference);
        }
        if synchronous {
            file_information::acquire_file(file)?;
            locked = true;
        }
        dispatcher::clear_event(file + 0x98);
        if apc_routine != 0 {
            let routine = file_request::free_routine()?;
            if routine == 0 {
                return Ok(0xC000_009A);
            }
            let Ok(packet) = kernel_pool::allocate(0x58, AllocateOptions { paged: false, tag: TAG, ..Default::default() }) else { return Ok(0xC000_009A) };
            if packet == 0 {
                return Ok(0xC000_009A);
            }
            apc::initialize(packet, thread, 0, routine, routine, apc_routine, 0, apc_context);
            request.lock().apc = packet;
        }
        let status = dispatch(&request, device, input, input_length, code, selected.access)?;
        let (finished, done) = {
            let r = request.lock();
            (r.finished, r.done)
        };
        if !finished && status != 0x103 && !done {
            return Ok(status);
        }
        if status == 0x103 && synchronous {
            loop {
                file_request::pump();
                if request.lock().finished {
                    break;
                }
                if guest::read32(thread + 0x510) & 1 != 0 {
                    let packet = request.lock().irp;
                    if packet != 0 {
                        let _ = cancel::irp(packet);
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
