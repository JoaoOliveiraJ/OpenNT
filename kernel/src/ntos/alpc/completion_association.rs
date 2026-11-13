//! Associação da porta ALPC a uma IOCP.
//!
//! A associação conserva a IOCP real. As notificações usam um conjunto
//! limitado de pacotes: a retirada de um libera espaço para a próxima
//! notificação pendente. Estado privado de 16 bytes: limite, pacotes
//! publicados, pendências e retirada.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::completion_reference::{self, Reference};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::ob::objects::completion::{self as completion_objects, Packet, Port as CompletionPort};
use crate::ntos::ob::objects::port::{Port, PortCompletion};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Estado privado da associação. `pending` cresce no notify e `published`
/// cai na retirada do consumidor, em threads diferentes: os contadores são
/// atômicos.
#[repr(C)]
struct AssociationState {
    limit: Field<u32>,
    published: Field<u32>,
    pending: Field<u32>,
    released: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for AssociationState {}

const _: () = assert!(core::mem::size_of::<AssociationState>() == 0x10);

pub const STATE_SIZE: u64 = AssociationState::SIZE;

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
    fn state(&self) -> &'static AssociationState {
        // SAFETY: estado alocado por `associate`, liberado só por `collect`
        // (com storage_released marcado sob `flags`).
        unsafe { AssociationState::at(self.pointer) }
    }

    fn collect(&self) {
        let mut flags = self.flags.lock();
        if !flags.storage_released && !flags.draining && flags.released && self.state().published.atomic().load(Ordering::SeqCst) == 0 {
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
        let state = self.state();
        let (pending, published) = (state.pending.atomic(), state.published.atomic());
        if self.queue.closed() {
            pending.store(0, Ordering::SeqCst);
        }
        while pending.load(Ordering::SeqCst) != 0 && published.load(Ordering::SeqCst) < state.limit.get() {
            if self.queue.closed() {
                pending.store(0, Ordering::SeqCst);
                break;
            }
            // Só este laço (sob `draining`) consome pendências.
            if pending.try_update(Ordering::SeqCst, Ordering::SeqCst, |count| count.checked_sub(1)).is_err() {
                break;
            }
            published.fetch_add(1, Ordering::SeqCst);
            let owner = self.clone();
            completion_objects::enqueue(
                &self.queue,
                Packet {
                    key: self.key,
                    on_dequeue: Some(Box::new(move || {
                        owner.state().published.atomic().fetch_sub(1, Ordering::SeqCst);
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
        association.state().pending.atomic().fetch_add(1, Ordering::SeqCst);
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
        association.state().released.set(1);
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
    // Alocação zerada: só o limite de pacotes publicados.
    // SAFETY: alocação nova do tamanho do estado.
    unsafe { AssociationState::at(pointer) }.limit.set(queue.concurrency().min(4));
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
