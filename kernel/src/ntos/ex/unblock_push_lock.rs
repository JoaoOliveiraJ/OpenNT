//! ExfUnblockPushLock.
//!
//! Consome uma cadeia simples de blocos aguardando desbloqueio. Recebe o
//! ponteiro bruto da cadeia, não a palavra marcada de ExAcquirePushLock.

use crate::ntos::ke::{dispatcher, irql};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Próxima ligação e flags de espera no bloco nativo.
const NEXT_BLOCK: u64 = 0x18;
const BLOCK_FLAGS: u64 = 0x34;

/// Troca a cabeça por zero e devolve a cadeia retirada por esta chamada.
fn detach_waiter_chain(pointer: u64) -> Result<u64, KernelError> {
    let mut head = guest::compare_exchange64(pointer, 0, 0)?;
    loop {
        let previous = guest::compare_exchange64(pointer, head, 0)?;
        if previous == head {
            return Ok(head);
        }
        head = previous;
    }
}

/// Retira o bit de espera ativa e informa se ele estava presente.
fn clear_spinning_flag(block: u64) -> Result<bool, KernelError> {
    let address = block + BLOCK_FLAGS;
    let mut flags = guest::read32(address);
    loop {
        let previous = guest::compare_exchange32(address, flags, flags & !2)?;
        if previous == flags {
            return Ok(flags & 2 != 0);
        }
        flags = previous;
    }
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
            let mut block = detach_waiter_chain(self.pointer)?;
            let mut found = false;
            // O caminho nativo eleva o IRQL para cadeias com vários blocos,
            // mesmo quando a espera ativa dispensa todos os eventos.
            let previous = (block != 0 && guest::read64(block + NEXT_BLOCK) != 0).then(|| irql::raise_irql(2));
            let walked = (|| {
                while block != 0 {
                    let next = guest::read64(block + NEXT_BLOCK);
                    if block == self.wait_block {
                        found = true;
                    }
                    if !clear_spinning_flag(block)? {
                        dispatcher::set_event(block);
                    }
                    block = next;
                }
                Ok(())
            })();
            if let Some(previous) = previous {
                irql::lower_irql(previous as u64);
            }
            walked?;
            // Outro desbloqueador possui este bloco: inicializa o evento antes
            // de retirar a espera ativa, preservando uma sinalização concorrente.
            if self.wait_block != 0 && !found {
                guest::write16(self.wait_block, 0);
                dispatcher::initialize_event(self.wait_block, 0, false);
                self.parked = clear_spinning_flag(self.wait_block)?;
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

/// Conduz a operação até concluir, deixando o dispatcher progredir.
pub fn unblock(pointer: u64, wait_block: u64) -> Result<(), KernelError> {
    let mut request = begin(pointer, wait_block);
    while request.poll()?.is_none() {
        dispatcher::pump_kernel();
    }
    Ok(())
}
