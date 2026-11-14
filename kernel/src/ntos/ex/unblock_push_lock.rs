//! ExfUnblockPushLock.
//!
//! Consome uma cadeia simples de blocos aguardando desbloqueio. Recebe o
//! ponteiro bruto da cadeia, não a palavra marcada de ExAcquirePushLock.

use core::sync::atomic::Ordering::SeqCst;

use super::push_lock::{wait_block, WaitBlock};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::ExPushLock;
use crate::ntos::ke::{dispatcher, irql};
use crate::rtl::KernelError;

/// Troca a cabeça por zero e devolve a cadeia retirada por esta chamada.
fn detach_waiter_chain(pointer: u64) -> u64 {
    // SAFETY: o export recebe o PEX_PUSH_LOCK do chamador (aqui, a cabeça da cadeia).
    unsafe { ExPushLock::at(pointer) }.value.atomic().swap(0, SeqCst)
}

/// Retira o bit de espera ativa e informa se ele estava presente.
fn clear_spinning_flag(block: &WaitBlock) -> bool {
    block.flags.atomic().fetch_and(!2, SeqCst) & 2 != 0
}

/// Operação suspensível que desliga e sinaliza a cadeia. `wait_block`
/// permite aguardar o bloco do chamador quando outro desbloqueador já o
/// retirou.
pub struct UnblockRequest {
    pointer: u64,
    wait_block: u64,
    started: bool,
    parked: bool,
}

pub fn begin(pointer: u64, wait_block: u64) -> UnblockRequest {
    UnblockRequest { pointer, wait_block, started: false, parked: false }
}

impl UnblockRequest {
    /// `None` enquanto o evento do chamador não foi sinalizado. O resultado
    /// só encerra a operação VOID; não representa posse do lock.
    pub fn poll(&mut self) -> Result<Option<()>, KernelError> {
        if !self.started {
            if irql::get_irql() > 2 {
                return Err(KernelError::new("ExfUnblockPushLock above DISPATCH_LEVEL"));
            }
            self.started = true;
            let mut block = detach_waiter_chain(self.pointer);
            let mut found = false;
            // O caminho nativo eleva o IRQL para cadeias com vários blocos,
            // mesmo quando a espera ativa dispensa todos os eventos.
            let previous = (block != 0 && wait_block(block).next.get() != 0).then(|| irql::raise_irql(2));
            while block != 0 {
                let waiter = wait_block(block);
                let next = waiter.next.get();
                if block == self.wait_block {
                    found = true;
                }
                if !clear_spinning_flag(waiter) {
                    dispatcher::set_event(waiter.wake_event.address());
                }
                block = next;
            }
            if let Some(previous) = previous {
                irql::lower_irql(previous as u64);
            }
            // Outro desbloqueador possui este bloco: inicializa o evento antes
            // de retirar a espera ativa, preservando uma sinalização concorrente.
            if self.wait_block != 0 && !found {
                let own = wait_block(self.wait_block);
                own.wake_event.header.type_.set(0);
                own.wake_event.header.signalling.set(0);
                dispatcher::initialize_event(own.wake_event.address(), 0, false);
                self.parked = clear_spinning_flag(own);
                if self.parked && irql::get_irql() > 1 {
                    return Err(KernelError::new("push-lock unblock wait above APC_LEVEL"));
                }
            }
        }
        if self.parked && dispatcher::try_wait_objects(&[self.wait_block], 1).is_none() {
            return Ok(None);
        }
        Ok(Some(()))
    }
}

/// Conduz a operação até concluir: numa syscall a thread bloqueia; fora
/// dela o dispatcher progride entre consultas.
pub fn unblock(pointer: u64, wait_block: u64) -> Result<(), KernelError> {
    let mut request = begin(pointer, wait_block);
    crate::ntos::ke::context_switch::acquire_until(|| request.poll(), dispatcher::pump_kernel)
}
