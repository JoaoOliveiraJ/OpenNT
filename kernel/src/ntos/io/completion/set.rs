//! IoSetIoCompletionEx.
//!
//! Publica um pacote de memória na IOCP dona (chave e informação em 64 bits);
//! a retirada e o fechamento usam a mesma liberação do pacote.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;

use crate::ntos::io::transfer::completion_packets;
use crate::ntos::ke::irql;
use crate::ntos::ob::objects::completion::{self as completion_objects, Packet};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::rtl::{KernelError, SpinLock};

static IN_FLIGHT: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());

pub fn post(port_pointer: u64, key: u64, context: u64, status: u32, information: u64, charge_quota: u64, supplied: u64) -> Result<u32, KernelError> {
    if irql::get_irql() > 2 {
        return Err(KernelError::new("IOCP post above DISPATCH_LEVEL"));
    }
    let live = dispatcher_objects::get(port_pointer).is_some_and(|(kind, _, _)| kind == "completion");
    let Some(port) = completion_objects::port_of(port_pointer).filter(|port| live && !port.closed()) else { return Err(KernelError::new("IOCP post requires a live completion queue")) };
    if supplied != 0 && (IN_FLIGHT.lock().contains(&supplied) || completion_packets::is_cached(supplied)) {
        return Err(KernelError::new("completion packet already belongs to a queue or cache"));
    }
    let pointer = if supplied != 0 { supplied } else { completion_packets::allocate(charge_quota & 0xFF != 0) };
    if pointer == 0 {
        return Ok(0xC000_009A);
    }
    let _ = dispatcher_objects::reference(port_pointer);
    let result = (|| -> Result<u32, KernelError> {
        let packet = completion_packets::packet_at(pointer);
        if ![1, 3, 4].contains(&packet.packet_type.get()) {
            return Err(KernelError::new("invalid supplied completion packet"));
        }
        packet.key_context.set(key);
        packet.apc_context.set(context);
        packet.io_status.set(status as i32);
        packet.io_status_information.set(information);
        IN_FLIGHT.lock().insert(pointer);
        // A fila assume a custódia antes de notificar: um consumidor pode
        // retirar, liberar e republicar o pacote durante esta chamada.
        completion_objects::enqueue(
            &port,
            Packet {
                key: 0,
                context: 0,
                status: 0,
                information: 0,
                native_pointer: pointer,
                on_dequeue: Some(Box::new(move || {
                    if IN_FLIGHT.lock().remove(&pointer) {
                        let _ = completion_packets::release(pointer);
                    }
                })),
                ..Packet::default()
            },
        );
        Ok(0)
    })();
    if result.is_err() && supplied == 0 {
        let _ = completion_packets::release(pointer);
    }
    let _ = dispatcher_objects::dereference(port_pointer);
    result
}

/// Pacotes publicados ainda não retirados.
pub fn pending_count() -> usize {
    IN_FLIGHT.lock().len()
}

/// NtSetIoCompletionEx(IoCompletionHandle, IoCompletionPacketHandle,
/// KeyContext, ApcContext, IoStatus, IoStatusInformation) no modo `mode`
/// (0 para o ZwSetIoCompletionEx): o pacote vai para a IOCP do handle — um
/// handle da tabela do processo corrente (com IO_COMPLETION_MODIFY_STATE)
/// ou da tabela nativa (a IOCP criada em modo kernel; um handle de kernel
/// só em KernelMode). O pacote é o embutido no IoCompletionReserve do
/// NtAllocateReserveObject: a reserva, referenciada no mesmo modo, é tomada
/// (InUse) depois da IOCP e o pacote vai pelo IoSetIoCompletionEx; uma
/// falha devolve a reserva. Em UserMode o handle da reserva é obrigatório
/// (nulo é STATUS_INVALID_HANDLE, como no 19041); o Zw sem reserva publica
/// um pacote comum.
pub fn set_io_completion_ex(handle: u64, reserve: u64, key: u64, context: u64, status: u32, information: u64, mode: u8) -> u32 {
    let port = match resolve_port_with(handle, 2, mode != 0) {
        Ok(port) => port,
        Err(status) => return status,
    };
    if reserve == 0 && mode == 0 {
        completion_objects::enqueue(&port, Packet { key, context, status, information, ..Packet::default() });
        return 0;
    }
    let packet = match crate::ntos::ps::memory_reserve::take_completion_reserve(reserve, mode) {
        Ok(Ok(packet)) => packet,
        Ok(Err(status)) => return status,
        Err(_) => return 0xC000_0001,
    };
    match post(port.pointer, key, context, status, information, 0, packet) {
        Ok(0) => 0,
        result => {
            let _ = crate::ntos::ps::memory_reserve::abandon_completion_reserve(packet);
            result.unwrap_or(0xC000_0001)
        }
    }
}

/// ObReferenceObjectByHandle(handle, `access`, IoCompletionObjectType): o
/// corpo da IOCP com uma referência (solta com
/// `dispatcher::dereference`), da tabela do processo corrente ou da nativa.
pub fn reference_port(handle: u64, access: u32) -> Result<u64, u32> {
    let port = resolve_port_with(handle, access, false)?;
    dispatcher_objects::reference(port.pointer).map_err(|_| 0xC000_0008u32)?;
    Ok(port.pointer)
}

/// A IOCP do handle com `access`: a tabela do processo corrente ou a
/// nativa (sem handles de kernel quando `from_user_mode`).
fn resolve_port_with(handle: u64, access: u32, from_user_mode: bool) -> Result<alloc::sync::Arc<completion_objects::Port>, u32> {
    match crate::ntos::ps::user::io_completion::resolve(handle, access) {
        Ok((_, port)) => Ok(port),
        Err(0xC000_0008) => match crate::ntos::ob::open_pointer::resolve(handle, from_user_mode) {
            Some(Ok(opened)) if opened.item.object_type.name == "IoCompletion" => match completion_objects::port_of(opened.item.pointer) {
                Some(port) if opened.access & access == access => Ok(port),
                Some(_) => Err(0xC000_0022),
                None => Err(0xC000_0008),
            },
            Some(Ok(_)) => Err(0xC000_0024),
            Some(Err(status)) => Err(status),
            None => Err(0xC000_0008),
        },
        Err(status) => Err(status),
    }
}
