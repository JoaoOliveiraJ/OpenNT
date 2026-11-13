//! IoSetIoCompletionEx — `system32/ntos/io/set-completion.js`.
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
use crate::ntos::mm::guest_memory as guest;

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
        if ![1, 3, 4].contains(&guest::read8(pointer + 0x10)) {
            return Err(KernelError::new("invalid supplied completion packet"));
        }
        guest::write64(pointer + 0x18, key);
        guest::write64(pointer + 0x20, context);
        guest::write32(pointer + 0x28, status);
        guest::write64(pointer + 0x30, information);
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
