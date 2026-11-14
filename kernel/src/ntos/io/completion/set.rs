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

/// ZwSetIoCompletionEx(IoCompletionHandle, IoCompletionPacketHandle,
/// KeyContext, ApcContext, IoStatus, IoStatusInformation): o pacote vai para
/// a IOCP do handle, como o NtSetIoCompletionEx — um handle da tabela do
/// processo corrente (com IO_COMPLETION_MODIFY_STATE) ou da tabela nativa
/// (a IOCP criada em modo kernel). O pacote de reserva (um
/// IoCompletionReserve do NtAllocateReserveObject) ainda não existe no
/// OpenNT: um handle de reserva não nulo dá STATUS_INVALID_HANDLE.
pub fn set_io_completion_ex(handle: u64, reserve: u64, key: u64, context: u64, status: u32, information: u64) -> u32 {
    if reserve != 0 {
        return 0xC000_0008;
    }
    let port = match crate::ntos::ps::user::io_completion::resolve(handle, 2) {
        Ok((_, port)) => port,
        Err(0xC000_0008) => match crate::ntos::ob::open_pointer::resolve(handle, false) {
            Some(Ok(opened)) if opened.item.object_type.name == "IoCompletion" => match completion_objects::port_of(opened.item.pointer) {
                Some(port) if opened.access & 2 != 0 => port,
                Some(_) => return 0xC000_0022,
                None => return 0xC000_0008,
            },
            Some(Ok(_)) => return 0xC000_0024,
            Some(Err(status)) => return status,
            None => return 0xC000_0008,
        },
        Err(status) => return status,
    };
    completion_objects::enqueue(&port, Packet { key, context, status, information, ..Packet::default() });
    0
}
