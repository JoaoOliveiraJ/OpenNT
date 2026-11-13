//! Associação da porta ALPC a uma IOCP.
//!
//! A associação conserva a IOCP real. As notificações usam um conjunto
//! limitado de pacotes: a retirada de um libera espaço para a próxima
//! notificação pendente. Estado privado de 16 bytes: limite, pacotes
//! publicados, pendências e retirada.

use alloc::boxed::Box;
use alloc::sync::Arc;

use super::completion_reference::{self, Reference};
use crate::ntos::ob::objects::completion::{self as completion_objects, Packet, Port as CompletionPort};
use crate::ntos::ob::objects::port::{Port, PortCompletion};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const STATE_SIZE: u64 = 16;

#[derive(Default)]
struct Flags {
    draining: bool,
    released: bool,
    storage_released: bool,
}

struct Association {
    queue: Arc<CompletionPort>,
    pointer: u64,
    key: u64,
    flags: SpinLock<Flags>,
    reference: SpinLock<Option<Reference>>,
}

impl Association {
    fn collect(&self) {
        let mut flags = self.flags.lock();
        if !flags.storage_released && !flags.draining && flags.released && guest::read32(self.pointer + 4) == 0 {
            flags.storage_released = true;
            guest::free_bytes(self.pointer);
        }
    }

    fn publish_pending(self: &Arc<Self>) {
        {
            let mut flags = self.flags.lock();
            if flags.draining || flags.storage_released {
                return;
            }
            flags.draining = true;
        }
        let pointer = self.pointer;
        if self.queue.closed() {
            guest::write32(pointer + 8, 0);
        }
        while guest::read32(pointer + 8) != 0 && guest::read32(pointer + 4) < guest::read32(pointer) {
            if self.queue.closed() {
                guest::write32(pointer + 8, 0);
                break;
            }
            guest::write32(pointer + 8, guest::read32(pointer + 8) - 1);
            guest::write32(pointer + 4, guest::read32(pointer + 4) + 1);
            let owner = self.clone();
            completion_objects::enqueue(
                &self.queue,
                Packet {
                    key: self.key,
                    on_dequeue: Some(Box::new(move || {
                        guest::write32(owner.pointer + 4, guest::read32(owner.pointer + 4) - 1);
                        // Uma notificação já produzida sobrevive ao consumo da
                        // mensagem e ao fechamento da ALPC; fechar a IOCP
                        // drena e cancela as restantes.
                        owner.publish_pending();
                        owner.collect();
                    })),
                    ..Packet::default()
                },
            );
        }
        self.flags.lock().draining = false;
        self.collect();
    }
}

struct AssociationHandle(Arc<Association>);

impl PortCompletion for AssociationHandle {
    fn notify(&self) {
        let association = &self.0;
        if association.flags.lock().released || association.queue.closed() {
            return;
        }
        guest::write32(association.pointer + 8, guest::read32(association.pointer + 8) + 1);
        association.publish_pending();
    }
    fn port_pointer(&self) -> u64 {
        self.0.queue.pointer
    }
    fn release(&self) {
        let association = &self.0;
        {
            let mut flags = association.flags.lock();
            if flags.released {
                return;
            }
            flags.released = true;
        }
        guest::write32(association.pointer + 12, 1);
        association.collect();
        if let Some(mut reference) = association.reference.lock().take() {
            let _ = reference.release();
        }
    }
}

pub fn associate(port: &Arc<Port>, handle: u64, key: u64, access_mode: u8) -> Result<u32, KernelError> {
    if handle == 0 {
        return Ok(0xC000_000D);
    }
    if port.with(|state| state.completion.is_some()) {
        return Ok(0xC000_0048);
    }
    let mut reference = match completion_reference::reference(handle, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let queue = reference.port.clone();
    let pointer = guest::alloc_bytes(STATE_SIZE);
    if pointer == 0 {
        let _ = reference.release();
        return Ok(0xC000_009A);
    }
    guest::write32(pointer, queue.concurrency().min(4));
    for offset in (4..STATE_SIZE).step_by(4) {
        guest::write32(pointer + offset, 0);
    }
    let association = Arc::new(Association { queue, pointer, key, flags: SpinLock::new(Flags::default()), reference: SpinLock::new(Some(reference)) });
    let handle: Arc<dyn PortCompletion> = Arc::new(AssociationHandle(association));
    port.set_completion_key(key);
    // A primeira associação também anuncia as respostas que já aguardavam
    // recepção, sem notificar respostas síncronas ou eventos diretos.
    let waiting = port.with(|state| {
        state.completion = Some(handle.clone());
        state.pending.iter().filter(|message| !message.synchronous && !message.direct).count()
    });
    for _ in 0..waiting {
        handle.notify();
    }
    Ok(0)
}
