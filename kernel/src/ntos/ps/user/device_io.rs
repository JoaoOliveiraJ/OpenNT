//! READ/WRITE bufferizados de dispositivos.
//!
//! IRPs nativos reais, conclusão e posse: a conclusão do driver nunca
//! escreve direto num buffer de usuário não fixado.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::events::{self, EventObject};
use super::files::UserDevice;
use super::state::{self, UserHandle};
use super::threads::{self, UserThread, Wait};
use crate::ntos::io::{cancel, io_manager};
use crate::ntos::ke::dispatcher;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{device_object, irp};
use crate::ntos::io::irp_builder::{self, BuildOptions};

struct RequestState {
    done: bool,
    finished: bool,
    abandoned: bool,
    status: u32,
    count: u64,
}

struct Request {
    entry: Arc<UserHandle>,
    event: Option<Arc<EventObject>>,
    thread: Option<Arc<UserThread>>,
    iosb: u64,
    user_buffer: u64,
    length: u64,
    offset: u64,
    write: bool,
    irp: u64,
    buffer: u64,
    pid: u64,
    state: SpinLock<RequestState>,
}

static PENDING: SpinLock<Vec<Arc<Request>>> = SpinLock::new(Vec::new());

fn device(entry: &UserHandle) -> Option<&UserDevice> {
    entry.downcast::<UserDevice>()
}

fn finish(request: &Arc<Request>) {
    let (mut status, mut count) = {
        let state = request.state.lock();
        if state.finished || !state.done {
            return;
        }
        (state.status, state.count)
    };
    if count > request.length {
        status = 0xC000_0001;
        count = 0;
    }
    let abandoned = request.state.lock().abandoned;
    if !abandoned && request.pid == state::with(|state| state.current_process_id) {
        if !state::probe_user_write(request.iosb, 16) || (!request.write && count != 0 && !state::probe_user_write(request.user_buffer, count)) {
            status = 0xC000_0005;
            count = 0;
        } else {
            if !request.write && count != 0 && status >> 30 != 3 {
                let bytes: Vec<u8> = (0..count).map(|index| guest::read8(request.buffer + index)).collect();
                let _ = state::write_user_bytes(request.user_buffer, &bytes);
            }
            guest::write64(request.iosb, status as u64);
            guest::write64(request.iosb + 8, count);
        }
        if let Some(device) = device(&request.entry).filter(|device| status == 0 && device.options & 0x30 != 0) {
            *device.position.lock() = request.offset + count;
        }
        if let Some(event) = &request.event {
            dispatcher::set_event(event.pointer);
        }
    }
    {
        let mut state = request.state.lock();
        state.status = status;
        state.finished = true;
    }
    PENDING.lock().retain(|candidate| !Arc::ptr_eq(candidate, request));
    io_manager::forget_completion(request.irp);
    guest::free_bytes(request.irp);
    guest::free_bytes(request.buffer);
    if let Some(event) = &request.event {
        events::release(event);
    }
    let _ = state::release_user_handle_reference(&request.entry);
    if let Some(thread) = &request.thread {
        threads::release_thread(thread);
    }
}

pub fn pump() {
    let pending = PENDING.lock().clone();
    for request in pending {
        finish(&request);
    }
}

/// NtReadFile/NtWriteFile de um handle `device`: IRP bufferizado síncrono
/// ou pendente (STATUS_PENDING no assíncrono).
pub fn transfer(entry: &Arc<UserHandle>, event_handle: u64, iosb: u64, user_buffer: u64, length: u64, offset_pointer: u64, write: bool) -> Result<u32, KernelError> {
    if entry.access() & if write { 2 } else { 1 } == 0 {
        return Ok(0xC000_0022);
    }
    if length > 1_048_576 {
        return Ok(0xC000_009A);
    }
    let Some(device) = device(entry) else { return Ok(0xC000_0008) };
    let Some((_, top)) = io_manager::device_route(&device.device_path) else { return Ok(0xC000_0008) };
    if top == 0 || guest::read32(top + device_object::FLAGS) & 4 == 0 {
        return Ok(0xC000_00BB);
    }
    let mut offset = *device.position.lock();
    if offset_pointer != 0 {
        let high = guest::read32(offset_pointer + 4);
        let low = guest::read32(offset_pointer);
        // FILE_USE_FILE_POINTER_POSITION num handle síncrono usa a posição.
        if !(high == 0xFFFF_FFFF && low == 0xFFFF_FFFE && device.options & 0x30 != 0) {
            offset = low as u64 | (high as u64) << 32;
            if offset > (1 << 53) - 1 || high & 0x8000_0000 != 0 {
                return Ok(0xC000_000D);
            }
        }
    }
    let event = if event_handle != 0 {
        match events::reference(event_handle, 2) {
            Ok(event) => Some(event),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let count = match guest::read8(top + device_object::STACK_SIZE) {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    let buffer = guest::alloc_bytes(length.max(1));
    if packet == 0 || buffer == 0 {
        for pointer in [packet, buffer] {
            if pointer != 0 {
                guest::free_bytes(pointer);
            }
        }
        if let Some(event) = &event {
            events::release(event);
        }
        return Ok(0xC000_0017);
    }
    if write {
        for index in 0..length {
            guest::write8(buffer + index, guest::read8(user_buffer + index));
        }
    }
    let thread = threads::current();
    let request = Arc::new(Request { entry: entry.clone(), event: event.clone(), thread: thread.clone(), iosb, user_buffer, length, offset, write, irp: packet, buffer, pid: state::with(|state| state.current_process_id), state: SpinLock::new(RequestState { done: false, finished: false, abandoned: false, status: 0x103, count: 0 }) });
    state::retain_user_handle_reference(entry);
    if let Some(thread) = &thread {
        threads::retain_thread(thread);
    }
    irp_builder::build(packet, &BuildOptions { major: if write { 4 } else { 3 }, minor: 0, buffer, buffer_length: length as u32, byte_offset: offset, device_object: top, stack_count: count, file_object: device.file_object, requestor_mode: 1, thread: thread.as_ref().map_or(0, |thread| thread.pointer()), ..BuildOptions::default() });
    guest::write32(packet + irp::FLAGS, 0x10 | if write { 0 } else { 0x40 }); // BUFFERED_IO, INPUT_OPERATION
    let observer = request.clone();
    io_manager::observe_completion(
        packet,
        Box::new(move |status, information| {
            let abandoned = {
                let mut state = observer.state.lock();
                state.done = true;
                state.status = status as u32;
                state.count = information;
                state.abandoned
            };
            if abandoned {
                finish(&observer);
            }
        }),
    );
    PENDING.lock().push(request.clone());
    if let Some(event) = &event {
        dispatcher::reset_event(event.pointer);
    }
    guest::write64(iosb, 0x103);
    guest::write64(iosb + 8, 0);
    let result = io_manager::iof_call_driver(top, packet) as u32;
    // Rotinas de despacho ausentes falham antes de o driver possuir o IRP.
    {
        let mut state = request.state.lock();
        if !state.done && result >= 0x8000_0000 {
            state.done = true;
            state.status = if result == 0xFFFF_FFFD { 0xC000_0010 } else { result };
        }
    }
    finish(&request);
    let (finished, status) = {
        let state = request.state.lock();
        (state.finished, state.status)
    };
    if finished {
        return Ok(status);
    }
    if device.options & 0x30 == 0 {
        return Ok(0x103);
    }
    let polled = request.clone();
    Ok(threads::wait_custom(
        Wait {
            poll: Some(Box::new(move || {
                finish(&polled);
                let state = polled.state.lock();
                state.finished.then_some(state.status)
            })),
            ..Wait::default()
        },
        0,
        None,
    ))
}

pub fn release_process(pid: u64) {
    let pending = PENDING.lock().clone();
    for request in pending.iter().filter(|request| request.pid == pid) {
        let done = {
            let mut state = request.state.lock();
            state.abandoned = true;
            state.done
        };
        if !done {
            let _ = cancel::irp(request.irp);
        }
        // O cancelamento não concluído retém o IRP, o FILE_OBJECT e o
        // KTHREAD até a conclusão real do driver.
        finish(request);
    }
}

fn same_object(entry: &UserHandle, object: *const UserDevice) -> bool {
    device(entry).is_some_and(|device| core::ptr::eq(device, object))
}

/// Cancela as requisições do objeto (por IOSB alvo e/ou thread chamadora).
pub fn cancel_entry(object: &UserDevice, target: u64, calling_thread_only: bool) -> bool {
    let current = threads::current();
    let process_id = state::with(|state| state.current_process_id);
    let mut found = false;
    let pending = PENDING.lock().clone();
    for request in pending {
        let mine = request.thread.as_ref().zip(current.as_ref()).is_some_and(|(thread, current)| Arc::ptr_eq(thread, current)) || (request.thread.is_none() && current.is_none());
        if request.pid != process_id || !same_object(&request.entry, object) || (target != 0 && request.iosb != target) || (calling_thread_only && !mine) {
            continue;
        }
        if request.state.lock().done {
            finish(&request);
            continue;
        }
        found = true;
        let _ = cancel::irp(request.irp);
        finish(&request);
    }
    found
}

fn cancel_io(handle: u64, target: u64, out: u64, thread_only: bool) -> u32 {
    let Some(entry) = state::get_user_handle(handle).filter(|entry| entry.kind() == "device" || entry.kind() == "file") else { return 0xC000_0008 };
    if !state::probe_user_write(out, 16) {
        return 0xC000_0005;
    }
    let found = device(&entry).is_some_and(|device| cancel_entry(device, target, thread_only));
    let status = if found || thread_only { 0 } else { 0xC000_0225 };
    guest::write64(out, status as u64);
    guest::write64(out + 8, 0);
    status
}

fn nt_cancel_io_file(handle: u64, out: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(cancel_io(handle, 0, out, true))
}

fn nt_cancel_io_file_ex(handle: u64, target: u64, out: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(cancel_io(handle, target, out, false))
}

pub fn init() {
    state::register_handler("NtCancelIoFile", nt_cancel_io_file);
    state::register_handler("NtCancelIoFileEx", nt_cancel_io_file_ex);
    threads::set_pump(threads::pump::DEVICE_IO, pump);
}
