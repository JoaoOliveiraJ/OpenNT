//! Spin locks do kernel: KSPIN_LOCK, os in-stack queued (KLOCK_QUEUE_HANDLE)
//! e os locks numerados da LockQueue da PRCB.
//!
//! A posse é o bit 0 do KSPIN_LOCK, trocado atomicamente (o
//! InterlockedBitTestAndSet64 do NT), para que dois processadores nunca
//! saiam com o mesmo lock. A aquisição comum sobe a DISPATCH_LEVEL; as
//! variantes ForDpc e RaiseToSynch sobem ao nível pedido sem nunca descer.
//! O KLOCK_QUEUE_HANDLE é { Next, Lock, OldIrql }: a fila fica vazia e o
//! lock é o mesmo bit do KSPIN_LOCK.

use super::{irql, pcr};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// LockQueueIoVpbLock.
const LOCK_QUEUE_IO_VPB_LOCK: u64 = 9;

/// KLOCK_QUEUE_HANDLE.LockQueue.Lock.
const HANDLE_LOCK: u64 = 8;
/// KLOCK_QUEUE_HANDLE.OldIrql.
const HANDLE_OLD_IRQL: u64 = 0x10;

/// KeInitializeSpinLock.
pub fn initialize(lock: u64) {
    guest::write64(lock, 0);
}

/// Uma tentativa de posse do bit 0.
fn try_spin(lock: u64) -> bool {
    let value = guest::read64(lock);
    value & 1 == 0 && guest::compare_exchange64(lock, value, value | 1).unwrap_or_else(|error| panic!("{error}")) == value
}

/// KeAcquireSpinLockAtDpcLevel: gira até a posse, sem mexer no IRQL.
pub fn acquire_at_dpc_level(lock: u64) {
    while !try_spin(lock) {
        core::hint::spin_loop();
    }
}

/// KeTryToAcquireSpinLockAtDpcLevel.
pub fn try_to_acquire_at_dpc_level(lock: u64) -> bool {
    try_spin(lock)
}

/// KeAcquireSpinLockRaiseToDpc / KfAcquireSpinLock: devolve o IRQL antigo.
pub fn acquire(lock: u64) -> u8 {
    let previous = irql::get_irql();
    irql::raise_irql(irql::DISPATCH_LEVEL);
    acquire_at_dpc_level(lock);
    previous
}

/// KeReleaseSpinLock / KfReleaseSpinLock: KIRQL é UCHAR, só o byte baixo do
/// registrador vale.
pub fn release(lock: u64, new_irql: u64) {
    guest::write64(lock, 0);
    irql::lower_irql(new_irql & 0xFF);
}

/// KeReleaseSpinLockFromDpcLevel.
pub fn release_from_dpc_level(lock: u64) {
    guest::write64(lock, 0);
}

/// KeAcquireSpinLockForDpc: sobe a DISPATCH_LEVEL (nunca desce).
pub fn acquire_for_dpc(lock: u64) -> u8 {
    let previous = irql::raise_at_least(irql::DISPATCH_LEVEL);
    acquire_at_dpc_level(lock);
    previous
}

/// KeAcquireSpinLockRaiseToSynch.
pub fn acquire_raise_to_synch(lock: u64) -> u8 {
    let previous = irql::raise_at_least(irql::SYNCH_LEVEL);
    acquire_at_dpc_level(lock);
    previous
}

/// KeTestSpinLock: TRUE quando o lock está livre.
pub fn test(lock: u64) -> bool {
    guest::read64(lock) & 1 == 0
}

// ---- in-stack queued -------------------------------------------------------

/// KeAcquireInStackQueuedSpinLock.
pub fn acquire_in_stack_queued(lock: u64, handle: u64) {
    guest::write64(handle, 0);
    guest::write64(handle + HANDLE_LOCK, lock);
    let previous = acquire(lock);
    guest::write8(handle + HANDLE_OLD_IRQL, previous);
}

/// KeReleaseInStackQueuedSpinLock / KeReleaseInStackQueuedSpinLockForDpc.
pub fn release_in_stack_queued(handle: u64) {
    release(guest::read64(handle + HANDLE_LOCK), guest::read8(handle + HANDLE_OLD_IRQL) as u64);
}

/// KeAcquireInStackQueuedSpinLockAtDpcLevel.
pub fn acquire_in_stack_queued_at_dpc_level(lock: u64, handle: u64) {
    guest::write64(handle, 0);
    guest::write64(handle + HANDLE_LOCK, lock);
    acquire_at_dpc_level(lock);
}

/// KeReleaseInStackQueuedSpinLockFromDpcLevel.
pub fn release_in_stack_queued_from_dpc_level(handle: u64) {
    guest::write64(guest::read64(handle + HANDLE_LOCK), 0);
}

/// KLOCK_QUEUE_HANDLE no nível pedido (nunca desce).
fn acquire_in_stack_at(lock: u64, handle: u64, level: u8) {
    guest::write64(handle, 0);
    guest::write64(handle + HANDLE_LOCK, lock);
    let previous = irql::raise_at_least(level);
    acquire_at_dpc_level(lock);
    guest::write8(handle + HANDLE_OLD_IRQL, previous);
}

/// KeAcquireInStackQueuedSpinLockForDpc: numa DPC comum (DISPATCH_LEVEL) só
/// pega o lock; numa DPC encadeada sobe antes.
pub fn acquire_in_stack_queued_for_dpc(lock: u64, handle: u64) {
    acquire_in_stack_at(lock, handle, irql::DISPATCH_LEVEL);
}

/// KeAcquireInStackQueuedSpinLockRaiseToSynch.
pub fn acquire_in_stack_queued_raise_to_synch(lock: u64, handle: u64) {
    acquire_in_stack_at(lock, handle, irql::SYNCH_LEVEL);
}

// ---- locks numerados (KSPIN_LOCK_QUEUE_NUMBER) -----------------------------

/// O KSPIN_LOCK da entrada `number` da LockQueue da PRCB corrente.
fn queued_lock(number: u64) -> Result<u64, KernelError> {
    let number = number as u32 as u64;
    if number >= pcr::LOCK_QUEUE_MAXIMUM {
        return Err(KernelError::new(alloc::format!("KSPIN_LOCK_QUEUE_NUMBER invalido: {number}")));
    }
    pcr::queued_spin_lock(number).ok_or_else(|| KernelError::new("LockQueue da PRCB sem lock"))
}

/// Uma tentativa em `level`; sem sucesso o IRQL volta e a saída fica intacta.
fn try_acquire_raised(lock: u64, level: u8, old_irql: u64) -> bool {
    let previous = irql::raise_at_least(level);
    if try_spin(lock) {
        guest::write8(old_irql, previous);
        true
    } else {
        irql::lower_irql(previous as u64);
        false
    }
}

/// KeAcquireQueuedSpinLock: devolve o IRQL antigo.
pub fn acquire_queued(number: u64) -> Result<u8, KernelError> {
    Ok(acquire(queued_lock(number)?))
}

/// KeAcquireQueuedSpinLockRaiseToSynch.
pub fn acquire_queued_raise_to_synch(number: u64) -> Result<u8, KernelError> {
    let lock = queued_lock(number)?;
    let previous = irql::raise_at_least(irql::SYNCH_LEVEL);
    acquire_at_dpc_level(lock);
    Ok(previous)
}

/// KeReleaseQueuedSpinLock.
pub fn release_queued(number: u64, new_irql: u64) -> Result<(), KernelError> {
    release(queued_lock(number)?, new_irql);
    Ok(())
}

/// KeTryToAcquireQueuedSpinLock: o IRQL antigo vai para a saída no sucesso.
pub fn try_to_acquire_queued(number: u64, old_irql: u64) -> Result<bool, KernelError> {
    Ok(try_acquire_raised(queued_lock(number)?, irql::DISPATCH_LEVEL, old_irql))
}

/// KeTryToAcquireQueuedSpinLockRaiseToSynch.
pub fn try_to_acquire_queued_raise_to_synch(number: u64, old_irql: u64) -> Result<bool, KernelError> {
    Ok(try_acquire_raised(queued_lock(number)?, irql::SYNCH_LEVEL, old_irql))
}

/// IoAcquireVpbSpinLock: o lock numerado LockQueueIoVpbLock; o IRQL
/// anterior vai para a saída.
pub fn acquire_vpb_spin_lock(old_irql: u64) -> Result<u64, KernelError> {
    let previous = acquire(queued_lock(LOCK_QUEUE_IO_VPB_LOCK)?);
    guest::write8(old_irql, previous);
    Ok(0)
}

/// IoReleaseVpbSpinLock.
pub fn release_vpb_spin_lock(new_irql: u64) -> Result<u64, KernelError> {
    release(queued_lock(LOCK_QUEUE_IO_VPB_LOCK)?, new_irql);
    Ok(0)
}
