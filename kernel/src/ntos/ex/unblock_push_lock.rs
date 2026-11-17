//! ExfUnblockPushLock e as esperas por endereço sobre um push lock
//! (ExBlockOnAddressPushLock e ExUnblockOnAddressPushLockEx).
//!
//! Consome uma cadeia simples de blocos aguardando desbloqueio. Recebe o
//! ponteiro bruto da cadeia, não a palavra marcada de ExAcquirePushLock.
//!
//! ntoskrnl 19041:
//! - ExpUnblockPushLock(PushLock, WaitBlock, Waited) 0x2f4d68: troca a cabeça
//!   por zero e sinaliza cada bloco retirado que já saiu da espera ativa; se
//!   o bloco do chamador ficou com outro desbloqueador, espera por ele (pelo
//!   ExTimedWaitForUnblockPushLock sem prazo, ou, com Waited, direto no
//!   evento já iniciado). ExfUnblockPushLock (0x3f8c30) é o Waited FALSE.
//! - ExBlockPushLock 0x2f4c60: Flags = 2 (espera ativa), Next = cabeça e a
//!   troca atômica da cabeça pelo bloco.
//! - ExTimedWaitForUnblockPushLock 0x2f4c80: inicia o evento de notificação
//!   do bloco e retira o bit de espera ativa; se ninguém o retirou antes,
//!   espera (WrPushLock, KernelMode) com o prazo; vencido, desbloqueia a si
//!   mesmo (Waited TRUE) e devolve o STATUS_TIMEOUT.
//! - ExBlockOnAddressPushLock(PushLock, TargetAddress, CompareAddress,
//!   AddressSize, Timeout) 0x2f4ba0: bloqueia, compara 1, 2, 4 ou 8 bytes e,
//!   iguais, espera; diferentes (ou outro tamanho), desbloqueia e devolve
//!   STATUS_SUCCESS.
//! - ExUnblockOnAddressPushLockEx(PushLock, Flags) 0x3f8be0: Flags fora dos
//!   dois bits baixos é o bugcheck 0x152 (Flags, PushLock); com a cadeia não
//!   vazia, o ExpUnblockPushLock sem bloco próprio.

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
    /// O chamador já esperou no evento do bloco (o Waited TRUE).
    waited: bool,
    started: bool,
    parked: bool,
}

pub fn begin(pointer: u64, wait_block: u64) -> UnblockRequest {
    UnblockRequest { pointer, wait_block, waited: false, started: false, parked: false }
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
            if self.wait_block != 0 && !found && self.waited {
                // O evento foi iniciado pela espera que venceu; o
                // desbloqueador que levou o bloco ainda vai sinalizá-lo.
                self.parked = true;
            } else if self.wait_block != 0 && !found {
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
    drive(begin(pointer, wait_block))
}

fn drive(mut request: UnblockRequest) -> Result<(), KernelError> {
    crate::ntos::ke::context_switch::acquire_signaled(
        || {
            let result = request.poll();
            let watched = (request.parked && request.wait_block != 0).then(|| self::wait_block(request.wait_block).wake_event.address());
            (result, watched)
        },
        crate::ntos::ke::wait::reason::WR_PUSH_LOCK,
        dispatcher::pump_kernel,
    )
}

// ---- Esperas por endereço -------------------------------------------------------

const STATUS_SUCCESS: u32 = 0;
/// Bugcheck do ExUnblockOnAddressPushLockEx com Flags inválidas.
const INVALID_PUSH_LOCK_FLAGS: u32 = 0x152;
const NOTIFICATION_EVENT: u8 = 0;
const KERNEL_MODE: u8 = 0;
/// Flags do bloco: espera ativa.
const SPINNING: u32 = 2;

/// ExBlockPushLock(PushLock, WaitBlock): o bloco entra na cabeça da cadeia.
fn block(pointer: u64, block: &WaitBlock) {
    block.flags.set(SPINNING);
    // SAFETY: o PEX_PUSH_LOCK do chamador (a cabeça da cadeia).
    let head = unsafe { ExPushLock::at(pointer) }.value.atomic();
    let mut current = head.load(SeqCst);
    loop {
        block.next.set(current);
        match head.compare_exchange(current, block.address(), SeqCst, SeqCst) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// ExTimedWaitForUnblockPushLock(PushLock, WaitBlock, Timeout).
fn timed_wait(pointer: u64, own: &WaitBlock, timeout: u64) -> Result<u32, KernelError> {
    dispatcher::initialize_event(own.wake_event.address(), NOTIFICATION_EVENT, false);
    if !clear_spinning_flag(own) {
        // O desbloqueador já retirou o bloco e não vai sinalizar o evento.
        return Ok(STATUS_SUCCESS);
    }
    let event = own.wake_event.address();
    let status = if crate::ntos::ke::context_switch::kernel_thread_can_block() {
        use crate::ntos::ke::wait;
        wait::wait_for_objects(&[event], false, wait::Deadline::after(dispatcher::timeout_to_100ns(timeout)), KERNEL_MODE, false, wait::reason::WR_PUSH_LOCK)
    } else {
        dispatcher::wait_for_single_object(event, timeout, KERNEL_MODE, false)
    };
    if status != STATUS_SUCCESS {
        drive(UnblockRequest { pointer, wait_block: own.address(), waited: true, started: false, parked: false })?;
    }
    Ok(status)
}

/// Os `size` bytes dos dois endereços são iguais (1, 2, 4 ou 8; outro tamanho
/// nunca é igual).
fn same_value(target: u64, compare: u64, size: u64) -> bool {
    use crate::ntos::mm::guest_memory as guest;
    match size {
        1 => guest::read8(target) == guest::read8(compare),
        2 => guest::read16(target) == guest::read16(compare),
        4 => guest::read32(target) == guest::read32(compare),
        8 => guest::read64(target) == guest::read64(compare),
        _ => false,
    }
}

/// ExBlockOnAddressPushLock(PushLock, TargetAddress, CompareAddress,
/// AddressSize, Timeout) -> NTSTATUS. O bloco de 0x40 bytes, que o NT põe
/// na pilha, sai do pool e volta a ele quando nenhum desbloqueador o tem.
pub fn block_on_address(pointer: u64, target: u64, compare: u64, size: u64, timeout: u64) -> Result<u32, KernelError> {
    use crate::ntos::mm::guest_memory as guest;
    let allocation = guest::alloc_bytes(WaitBlock::SIZE);
    if allocation == 0 {
        return Err(KernelError::new("push-lock address wait block allocation failed"));
    }
    guest::write_bytes(allocation, &[0u8; WaitBlock::SIZE as usize]);
    let own = wait_block(allocation);
    block(pointer, own);
    let result = if same_value(target, compare, size) { timed_wait(pointer, own, timeout) } else { drive(begin(pointer, allocation)).map(|()| STATUS_SUCCESS) };
    guest::free_bytes(allocation);
    result
}

/// ExUnblockOnAddressPushLockEx(PushLock, Flags).
pub fn unblock_on_address(pointer: u64, flags: u32) -> Result<(), KernelError> {
    if flags & !3 != 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(INVALID_PUSH_LOCK_FLAGS, flags as u64, pointer, 0, 0);
    }
    core::sync::atomic::fence(SeqCst);
    // SAFETY: o PEX_PUSH_LOCK do chamador.
    if unsafe { ExPushLock::at(pointer) }.value.atomic().load(SeqCst) == 0 {
        return Ok(());
    }
    unblock(pointer, 0)
}
