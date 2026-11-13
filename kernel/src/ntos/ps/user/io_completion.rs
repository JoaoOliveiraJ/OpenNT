//! Portas de conclusão de modo usuário — `system32/ntos/ps/user/io-completion.js`.
//!
//! Pacotes em FIFO, consumidores em LIFO, contextos nativos de 64 bits,
//! associação de threads e limite de consumidores executáveis.
//! NtRemoveIoCompletionEx usa a retirada em lote de `io/remove-completion`.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::registry::parse_user_object_attributes;
use super::state::{self, probe_user_read, probe_user_write, UserHandle};
use crate::ntos::io::completion::create as create_completion;
use super::threads::{self, Wait};
use crate::ntos::ob::objects::completion::{self as completion_objects, Packet, Port, Waiter};
use crate::ntos::ob::objects::dispatcher::UserDispatcher;
use crate::ntos::ob::object_manager;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Handle de porta com o acesso exigido.
pub fn resolve(handle: u64, access: u32) -> Result<(Arc<UserHandle>, Arc<Port>), u32> {
    let Some(entry) = state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "completion" {
        return Err(0xC000_0024);
    }
    if entry.access() & access != access {
        return Err(0xC000_0022);
    }
    let port = entry.downcast::<UserDispatcher>().and_then(|dispatcher| completion_objects::port_of(dispatcher.pointer)).ok_or(0xC000_0008u32)?;
    Ok((entry, port))
}

/// ULONG_PTR em duas palavras de 32 bits.
pub fn write_words(out: u64, value: u64) {
    guest::write32(out, value as u32);
    guest::write32(out + 4, (value >> 32) as u32);
}

fn words(value: [u32; 2]) -> u64 {
    value[0] as u64 | ((value[1] as u64) << 32)
}

pub fn enqueue(port: &Port, packet: Packet) {
    completion_objects::enqueue(port, packet);
}

/// O frame bruto conserva os ponteiros de 64 bits.
fn nt_create_io_completion(output: u64, access: u64, attributes: u64, concurrency: u64, _rsp: u64) -> Result<u32, KernelError> {
    let raw = state::with(|state| state.service_raw_arguments);
    let output = if raw != 0 { guest::read64(raw + 8) } else { output };
    let attributes = if raw != 0 { guest::read64(raw + 24) } else { attributes };
    create_completion::create(output, access as u32, attributes, concurrency as u32, 1)
}

fn nt_open_io_completion(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(out, 8) || !probe_user_read(attributes, 48) {
        return Ok(0xC000_0005);
    }
    let Some(parsed) = parse_user_object_attributes(attributes) else { return Ok(0xC000_000D) };
    let Some(node) = object_manager::lookup(&parsed.path) else { return Ok(0xC000_0034) };
    let Some(snapshot) = object_manager::node(node).filter(|node| node.type_name == "IoCompletion") else { return Ok(0xC000_0024) };
    let Some(port) = snapshot.data.and_then(|data| completion_objects::port_of(data.native_pointer)) else { return Ok(0xC000_0024) };
    completion_objects::publish(&port, out, access as u32, guest::read32(attributes + 24), 0, false)
}

/// NtSetIoCompletion(handle, key, context, status, information na pilha).
fn nt_set_io_completion(handle: u64, _key: u64, _context: u64, status: u64, rsp: u64) -> Result<u32, KernelError> {
    let port = match resolve(handle, 2) {
        Ok((_, port)) => port,
        Err(status) => return Ok(status),
    };
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(0xC000_0005);
    }
    enqueue(
        &port,
        Packet {
            key: words(state::syscall_arg_words(rsp, 2)),
            context: words(state::syscall_arg_words(rsp, 3)),
            status: status as u32,
            information: words(state::syscall_arg_words(rsp, 5)),
            ..Packet::default()
        },
    );
    Ok(0)
}

/// NtQueryIoCompletion: só a classe básica (Depth de 4 bytes).
fn nt_query_io_completion(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let port = match resolve(handle, 1) {
        Ok((_, port)) => port,
        Err(status) => return Ok(status),
    };
    if class != 0 {
        return Ok(0xC000_0003);
    }
    let returned = state::stack_arg(rsp, 5);
    if returned != 0 && !probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    if returned != 0 {
        guest::write32(returned, 4);
    }
    if length != 4 {
        return Ok(0xC000_0004);
    }
    if !probe_user_write(out, 4) {
        return Ok(0xC000_0005);
    }
    guest::write32(out, port.with(|state| state.packets.len() as u32));
    Ok(0)
}

/// Opções de quem reutiliza a retirada (pacotes de espera, worker factories).
#[derive(Default)]
pub struct RemoveOptions {
    pub entries: Vec<Arc<UserHandle>>,
    pub poll: Option<Box<dyn FnMut() -> Option<u32> + Send>>,
    pub cleanup: Option<Box<dyn FnOnce() + Send>>,
    /// `timeoutMs` explícito; None deriva do ponteiro.
    pub timeout_ms: Option<Option<u64>>,
}

/// Associa a thread corrente à porta, entra na fila LIFO de consumidores e
/// espera um pacote dentro do limite de concorrência.
pub fn remove_entry(entry: Arc<UserHandle>, port: Arc<Port>, timeout: u64, alertable: bool, validate: Arc<dyn Fn() -> bool + Send + Sync>, deliver: Box<dyn FnMut(&mut VecDeque<Packet>) -> Option<Packet> + Send>, options: RemoveOptions) -> u32 {
    if (timeout != 0 && !probe_user_read(timeout, 8)) || !validate() {
        return 0xC000_0005;
    }
    let thread = threads::current().map(|thread| thread.pointer());
    if port.closed() {
        return 0x80;
    }
    if let Some(thread) = thread {
        completion_objects::associate(thread, &port);
    }
    let waiter = Arc::new(Waiter { thread, waiting: None, reserve: None });
    port.with(|state| state.waiters.push(waiter.clone()));
    let RemoveOptions { entries: extra, poll: mut extra_poll, cleanup: extra_cleanup, timeout_ms } = options;
    let mut entries = alloc::vec![entry];
    entries.extend(extra);
    let (poll_port, poll_waiter, mut deliver) = (port.clone(), waiter.clone(), deliver);
    let poll = move || -> Option<u32> {
        if let Some(status) = extra_poll.as_mut().and_then(|poll| poll()) {
            return Some(status);
        }
        if poll_port.closed() {
            return Some(0x80); // STATUS_ABANDONED
        }
        let blocked = poll_port.with(|state| {
            if state.packets.is_empty() || state.active.len() as u32 >= poll_port.concurrency() {
                return true;
            }
            let last = state.waiters.iter().rev().find(|candidate| candidate.thread.is_none_or(completion_objects::thread_eligible));
            !last.is_some_and(|last| Arc::ptr_eq(last, &poll_waiter))
        });
        if blocked {
            return None;
        }
        // Outra thread pode ter desmapeado o buffer de um consumidor.
        if !validate() {
            return Some(0xC000_0005);
        }
        let packet = poll_port.with(|state| deliver(&mut state.packets));
        if let Some(on_dequeue) = packet.and_then(|packet| packet.on_dequeue) {
            on_dequeue();
        }
        if let Some(thread) = poll_waiter.thread {
            poll_port.with(|state| state.active.insert(thread));
        }
        Some(0)
    };
    let cleanup = move |_status: u32| {
        port.with(|state| state.waiters.retain(|candidate| !Arc::ptr_eq(candidate, &waiter)));
        if let Some(cleanup) = extra_cleanup {
            cleanup();
        }
    };
    threads::wait_custom(Wait { entries: Some(entries), alertable: Some(alertable), poll: Some(Box::new(poll)), cleanup: Some(Box::new(cleanup)), ..Wait::default() }, timeout, timeout_ms)
}

/// NtRemoveIoCompletion(handle, key*, context*, iosb*, timeout*).
fn nt_remove_io_completion(handle: u64, key: u64, context: u64, iosb: u64, rsp: u64) -> Result<u32, KernelError> {
    let (entry, port) = match resolve(handle, 2) {
        Ok(resolved) => resolved,
        Err(status) => return Ok(status),
    };
    let validate: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || probe_user_write(key, 8) && probe_user_write(context, 8) && probe_user_write(iosb, 16));
    let deliver = Box::new(move |packets: &mut VecDeque<Packet>| {
        let mut packet = packets.pop_front()?;
        let (packet_key, packet_context, status, information) = packet.values();
        write_words(key, packet_key);
        write_words(context, packet_context);
        guest::write64(iosb, status as u64);
        write_words(iosb + 8, information);
        Some(Packet { on_dequeue: packet.on_dequeue.take(), ..Packet::default() })
    });
    Ok(remove_entry(entry, port, state::stack_arg(rsp, 5), false, validate, deliver, RemoveOptions::default()))
}

/// NtRemoveIoCompletionEx(handle, entries*, count, removed*, timeout*,
/// alertable): o frame bruto conserva os ponteiros de 64 bits.
fn nt_remove_io_completion_ex(handle: u64, out: u64, count: u64, removed: u64, rsp: u64) -> Result<u32, KernelError> {
    let count = count as u32;
    if count == 0 || count > 0x7FF_FFFF {
        return Ok(0xC000_000D);
    }
    if !state::probe_syscall_stack(rsp, 16) {
        return Ok(0xC000_0005);
    }
    let raw = state::with(|state| state.service_raw_arguments);
    let (handle, out, removed) = if raw != 0 { (guest::read64(raw + 8), guest::read64(raw + 16), guest::read64(raw + 32)) } else { (handle, out, removed) };
    let consumer = threads::current().map(|thread| thread.pointer());
    let request = crate::ntos::io::completion::remove::begin(handle, out, count, removed, guest::read64(rsp + 40), guest::read8(rsp + 48) != 0, 1, false, consumer)?;
    let request = Arc::new(crate::rtl::SpinLock::new(request));
    let (polled, cancelled) = (request.clone(), request);
    Ok(threads::wait_custom(Wait { poll: Some(Box::new(move || polled.lock().poll())), cleanup: Some(Box::new(move |_status| cancelled.lock().cancel())), ..Wait::default() }, 0, Some(None)))
}

pub fn init() {
    state::register_handler("NtRemoveIoCompletion", nt_remove_io_completion);
    state::register_handler("NtRemoveIoCompletionEx", nt_remove_io_completion_ex);
    state::register_handler("NtCreateIoCompletion", nt_create_io_completion);
    state::register_handler("NtOpenIoCompletion", nt_open_io_completion);
    state::register_handler("NtSetIoCompletion", nt_set_io_completion);
    state::register_handler("NtQueryIoCompletion", nt_query_io_completion);
}
