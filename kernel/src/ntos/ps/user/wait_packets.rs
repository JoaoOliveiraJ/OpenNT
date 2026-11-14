//! Pacotes de espera.
//!
//! Uma associação de uso único consome um objeto esperável e publica os
//! contextos do chamador numa IOCP. As referências sobrevivem ao fechamento
//! dos handles originais.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::io_completion;
use super::state::{self, probe_user_read, probe_user_write};
use super::threads::{self, pump};
use crate::ntos::ke::dispatcher;
use crate::ntos::ob::objects::completion::{self as completion_objects, Packet};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::objects::work::{self as work_objects, Association, Queued, WaitPacket};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::ObjectAttributes;

/// Associações pendentes, na ordem de inserção.
static PENDING: SpinLock<Vec<Arc<WaitPacket>>> = SpinLock::new(Vec::new());

fn forget(packet: &Arc<WaitPacket>) {
    PENDING.lock().retain(|candidate| !Arc::ptr_eq(candidate, packet));
}

fn resolve(handle: u64) -> Result<Arc<WaitPacket>, u32> {
    let Some(entry) = state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "waitpacket" {
        return Err(0xC000_0024);
    }
    if entry.access() & 1 == 0 {
        return Err(0xC000_0022);
    }
    entry.downcast::<dispatcher_objects::UserDispatcher>().and_then(|dispatcher| work_objects::packet_of(dispatcher.pointer)).ok_or(0xC000_0008u32)
}

fn detach(packet: &Arc<WaitPacket>, remove_queued: bool) -> u32 {
    if let Some(association) = packet.association() {
        packet.set_association(None);
        forget(packet);
        let _ = state::release_user_handle_reference(&association.target);
        let _ = state::release_user_handle_reference(&association.port_entry);
        let _ = dispatcher_objects::dereference(packet.pointer);
        return 0;
    }
    if let Some(queued) = packet.queued() {
        if !remove_queued {
            return 0x103;
        }
        let item = queued.port.with(|state| state.packets.iter().position(|item| item.tag == packet.pointer).and_then(|index| state.packets.remove(index)));
        if let Some(on_dequeue) = item.and_then(|item| item.on_dequeue) {
            on_dequeue();
        }
        return 0;
    }
    0xC000_0120
}

fn nt_create_wait_completion_packet(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(out, 8) || (attributes != 0 && !probe_user_read(attributes, 48)) {
        return Ok(0xC000_0005);
    }
    // Pacotes de espera não têm nome.
    if attributes != 0 {
        match state::user_struct::<ObjectAttributes>(attributes).and_then(|object| object.object_name.probe_get()) {
            Ok(0) => {}
            Ok(_) => return Ok(0xC000_0033),
            Err(error) => return Ok(error.status),
        }
    }
    create(out, access as u32, attributes)
}

/// O núcleo do NtCreateWaitCompletionPacket (e do Zw, em modo kernel): o
/// pacote novo e o handle dele, na tabela do processo corrente, em `out`.
pub fn create(out: u64, access: u32, attributes: u64) -> Result<u32, KernelError> {
    let result = work_objects::packet(attributes, detach).and_then(|packet| work_objects::publish(packet.pointer, out, access, attributes, packet.clone()));
    match result {
        Ok(status) => Ok(status),
        Err(error) if error.status != 0 => Ok(error.status),
        Err(error) => Err(error),
    }
}

fn poll(packet: &Arc<WaitPacket>) -> bool {
    let Some(association) = packet.association() else { return false };
    if association.port.closed() {
        detach(packet, true);
        return false;
    }
    if dispatcher::try_wait_objects(&[association.target_pointer], 1).is_none() {
        return false;
    }
    let pointer = packet.pointer;
    let _ = dispatcher_objects::reference(pointer);
    forget(packet);
    packet.set_association(None);
    let port = association.port.clone();
    let (owner, port_entry) = (packet.clone(), association.port_entry.clone());
    let item = Packet {
        key: packet.key(),
        context: packet.context(),
        status: packet.status(),
        information: packet.information(),
        tag: pointer,
        on_dequeue: Some(Box::new(move || {
            if owner.queued().is_none() {
                return;
            }
            owner.set_queued(None);
            let _ = state::release_user_handle_reference(&port_entry);
            let _ = dispatcher_objects::dereference(owner.pointer);
        })),
        ..Packet::default()
    };
    packet.set_queued(Some(Queued { port: port.clone() }));
    completion_objects::enqueue(&port, item);
    let _ = state::release_user_handle_reference(&association.target);
    let _ = dispatcher_objects::dereference(pointer);
    true
}

/// NtAssociateWaitCompletionPacket(packet, port, target, key, context,
/// status, information, alreadySignaled*).
fn nt_associate_wait_completion_packet(handle: u64, port_handle: u64, target_handle: u64, _key: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 32) {
        return Ok(0xC000_0005);
    }
    let already = state::stack_arg(rsp, 8);
    if already != 0 && !probe_user_write(already, 1) {
        return Ok(0xC000_0005);
    }
    let completion = (state::syscall_arg_words(rsp, 4), state::syscall_arg_words(rsp, 5), state::stack_arg32(rsp, 6), state::syscall_arg_words(rsp, 7));
    let signaled = match associate(handle, port_handle, target_handle, completion) {
        Ok(signaled) => signaled,
        Err(status) => return Ok(status),
    };
    // BOOLEAN *AlreadySignaled (sondado acima).
    if already != 0 && guest::try_write::<u8>(already, signaled as u8).is_err() {
        return Ok(0xC000_0005);
    }
    Ok(0)
}

/// O núcleo do NtAssociateWaitCompletionPacket (e do Zw): associa o pacote
/// ao objeto esperável e à IOCP, com a conclusão (chave, contexto, status e
/// informação) que vai para a fila quando o objeto sinaliza. Devolve se ele
/// já estava sinalizado (o pacote foi para a fila na hora).
pub fn associate(handle: u64, port_handle: u64, target_handle: u64, completion: ([u32; 2], [u32; 2], u32, [u32; 2])) -> Result<bool, u32> {
    let packet = resolve(handle)?;
    if packet.association().is_some() || packet.queued().is_some() {
        return Err(0xC000_000D);
    }
    let (port_entry, port) = io_completion::resolve(port_handle, 2)?;
    let Some(target) = state::get_user_handle(target_handle) else { return Err(0xC000_0008) };
    if !["event", "timer", "semaphore", "thread"].contains(&target.kind()) {
        return Err(0xC000_0024);
    }
    if target.access() & 0x10_0000 == 0 {
        return Err(0xC000_0022);
    }
    packet.set_completion(completion.0, completion.1, completion.2, completion.3);
    let target_pointer = target.object.native_body().map_or(0, |body| body.pointer);
    state::retain_user_handle_reference(&port_entry);
    state::retain_user_handle_reference(&target);
    let _ = dispatcher_objects::reference(packet.pointer);
    packet.set_association(Some(Association { port_entry, port, target, target_pointer }));
    PENDING.lock().push(packet.clone());
    Ok(poll(&packet))
}

/// O núcleo do NtCancelWaitCompletionPacket (e do Zw).
pub fn cancel(handle: u64, remove_signaled: bool) -> u32 {
    match resolve(handle) {
        Ok(packet) => detach(&packet, remove_signaled),
        Err(status) => status,
    }
}

fn nt_cancel_wait_completion_packet(handle: u64, remove: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(cancel(handle, remove & 0xFF != 0))
}

pub fn pump() {
    let pending = PENDING.lock().clone();
    for packet in pending {
        poll(&packet);
    }
}

pub fn init() {
    threads::set_pump(pump::WAIT_PACKETS, pump);
    state::register_handler("NtCreateWaitCompletionPacket", nt_create_wait_completion_packet);
    state::register_handler("NtAssociateWaitCompletionPacket", nt_associate_wait_completion_packet);
    state::register_handler("NtCancelWaitCompletionPacket", nt_cancel_wait_completion_packet);
}
