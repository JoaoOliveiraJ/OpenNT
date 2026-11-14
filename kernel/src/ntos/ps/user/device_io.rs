//! READ/WRITE de dispositivos: bufferizados (DO_BUFFERED_IO) e, sem
//! DO_BUFFERED_IO nem DO_DIRECT_IO, "neither" (o IRP leva o buffer de
//! usuário em Irp->UserBuffer, sem SystemBuffer, como o NtReadFile/
//! NtWriteFile do NT; o driver o usa no contexto de quem pediu).
//!
//! IRPs nativos reais, conclusão e posse: no caminho bufferizado a conclusão
//! do driver nunca escreve direto num buffer de usuário não fixado.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::events::{self, EventObject};
use super::files::UserDevice;
use super::process_state;
use super::state::{self, UserHandle};
use super::threads::{self, UserThread, Wait};
use crate::ntos::io::{cancel, io_manager};
use crate::ntos::ke::dispatcher;
use crate::ntos::ps::{process, process_context};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{DeviceObject, Irp, NtStruct};
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
    /// O EPROCESS da requisição: dono do IOSB e do buffer de usuário.
    process: u64,
    state: SpinLock<RequestState>,
}

static PENDING: SpinLock<Vec<Arc<Request>>> = SpinLock::new(Vec::new());

/// DEVICE_OBJECT.Flags.
const DO_BUFFERED_IO: u32 = 0x4;
const DO_DIRECT_IO: u32 = 0x10;
/// IRP.Flags.
const IRP_BUFFERED_IO: u32 = 0x10;
const IRP_INPUT_OPERATION: u32 = 0x40;

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
    // A conclusão roda no contexto de quem a observa (o pump do laço, a
    // espera da thread ou a própria chamada): a cópia para o usuário exige o
    // processo da requisição ainda vivo e roda anexada a ele, como a APC de
    // conclusão do NT roda no contexto da thread que pediu.
    if !abandoned && process_state::by_id(request.pid).is_some() {
        (status, count) = process_context::with_process(request.process, || copy_out(request, status, count)).unwrap_or((0xC000_0005, 0));
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
    if request.buffer != 0 {
        guest::free_bytes(request.buffer);
    }
    if let Some(event) = &request.event {
        events::release(event);
    }
    let _ = state::release_user_handle_reference(&request.entry);
    if let Some(thread) = &request.thread {
        threads::release_thread(thread);
    }
}

/// SystemBuffer e IOSB para o processo da requisição (o corrente): devolve
/// o status e a contagem finais.
fn copy_out(request: &Request, status: u32, count: u64) -> (u32, u64) {
    if !state::probe_user_write(request.iosb, 16) || (!request.write && count != 0 && !state::probe_user_write(request.user_buffer, count)) {
        return (0xC000_0005, 0);
    }
    if !request.write && count != 0 && status >> 30 != 3 && request.buffer != 0 {
        // SystemBuffer (pool do kernel) para o buffer de usuário sondado.
        let bytes = guest::read_bytes(request.buffer, count as usize);
        let _ = state::write_user_bytes(request.user_buffer, &bytes);
    }
    if state::set_user_iosb(request.iosb, status, count).is_err() {
        return (0xC000_0005, 0);
    }
    (status, count)
}

pub fn pump() {
    let pending = PENDING.lock().clone();
    for request in pending {
        finish(&request);
    }
}

/// NtReadFile/NtWriteFile de um handle `device`: IRP bufferizado ou neither,
/// síncrono ou pendente (STATUS_PENDING no assíncrono). DO_DIRECT_IO (MDL
/// fixada) ainda não é suportado.
pub fn transfer(entry: &Arc<UserHandle>, event_handle: u64, iosb: u64, user_buffer: u64, length: u64, offset_pointer: u64, write: bool) -> Result<u32, KernelError> {
    if entry.access() & if write { 2 } else { 1 } == 0 {
        return Ok(0xC000_0022);
    }
    if length > 1_048_576 {
        return Ok(0xC000_009A);
    }
    let Some(device) = device(entry) else { return Ok(0xC000_0008) };
    let Some((_, top)) = io_manager::device_route(&device.device_path) else { return Ok(0xC000_0008) };
    // SAFETY: o topo da rota é um DEVICE_OBJECT vivo do I/O manager.
    let top_device = (top != 0).then(|| unsafe { DeviceObject::at(top) });
    // DO_BUFFERED_IO, ou neither (nem DO_BUFFERED_IO nem DO_DIRECT_IO).
    let Some(top_device) = top_device.filter(|device| device.flags.get() & DO_BUFFERED_IO != 0 || device.flags.get() & DO_DIRECT_IO == 0) else { return Ok(0xC000_00BB) };
    let buffered = top_device.flags.get() & DO_BUFFERED_IO != 0;
    let mut offset = *device.position.lock();
    if offset_pointer != 0 {
        // ByteOffset (LARGE_INTEGER, sondado pelo chamador): uma leitura.
        let Ok(value) = guest::try_read::<u64>(offset_pointer) else { return Ok(0xC000_0005) };
        let (high, low) = ((value >> 32) as u32, value as u32);
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
    // Dados de uma escrita bufferizada, capturados do buffer de usuário (sondado pelo chamador).
    let data = if write && buffered {
        match guest::try_read_bytes(user_buffer, length as usize) {
            Ok(data) => Some(data),
            Err(_) => {
                if let Some(event) = &event {
                    events::release(event);
                }
                return Ok(0xC000_0005);
            }
        }
    } else {
        None
    };
    let count = match top_device.stack_size.get() as u8 {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    let buffer = if buffered { guest::alloc_bytes(length.max(1)) } else { 0 };
    if packet == 0 || (buffered && buffer == 0) {
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
    if let Some(data) = &data {
        guest::write_bytes(buffer, data);
    }
    let thread = threads::current();
    let request = Arc::new(Request { entry: entry.clone(), event: event.clone(), thread: thread.clone(), iosb, user_buffer, length, offset, write, irp: packet, buffer, pid: state::current_process_id(), process: process::get_current_process(), state: SpinLock::new(RequestState { done: false, finished: false, abandoned: false, status: 0x103, count: 0 }) });
    state::retain_user_handle_reference(entry);
    if let Some(thread) = &thread {
        threads::retain_thread(thread);
    }
    irp_builder::build(packet, &BuildOptions { major: if write { 4 } else { 3 }, minor: 0, buffer, buffer_length: length as u32, byte_offset: offset, device_object: top, stack_count: count, file_object: device.file_object, requestor_mode: 1, thread: thread.as_ref().map_or(0, |thread| thread.pointer()), user_buffer: if buffered { 0 } else { user_buffer }, ..BuildOptions::default() });
    if buffered {
        // SAFETY: IRP recém-montado acima.
        unsafe { Irp::at(packet) }.flags.set(IRP_BUFFERED_IO | if write { 0 } else { IRP_INPUT_OPERATION });
    }
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
    // A conclusão volta a gravar o IOSB; uma falha aqui reaparece lá.
    let _ = state::set_user_iosb(iosb, 0x103, 0);
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
    let process_id = state::current_process_id();
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
    if state::set_user_iosb(out, status, 0).is_err() {
        return 0xC000_0005;
    }
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
