//! Operações interlocked sobre a memória do convidado — Interlocked* de 32
//! bits, listas simples (InterlockedPushEntryList/PopEntryList) e listas
//! duplas sob spinlock (ExInterlockedInsertTailList/RemoveHeadList).
//!
//! Cada Interlocked* é uma instrução LOCK sobre a célula do convidado
//! (ponteiro do driver: sonda e alinhamento natural). As listas simples
//! trocam a cabeça por CMPXCHG; as ExInterlocked* tomam o spin lock legado
//! do chamador (`ex::spin_lock`) em DISPATCH_LEVEL e devolvem o IRQL
//! anterior na liberação.

use core::sync::atomic::Ordering;

use crate::ntos::ex::spin_lock;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// InterlockedIncrement: devolve o valor novo.
pub fn increment(address: u64) -> Result<u32, KernelError> {
    Ok(guest::try_atomic_u32(address)?.fetch_add(1, Ordering::SeqCst).wrapping_add(1))
}

/// InterlockedDecrement: devolve o valor novo.
pub fn decrement(address: u64) -> Result<u32, KernelError> {
    Ok(guest::try_atomic_u32(address)?.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1))
}

/// InterlockedExchange: devolve o valor anterior.
pub fn exchange(address: u64, value: u32) -> Result<u32, KernelError> {
    Ok(guest::try_atomic_u32(address)?.swap(value, Ordering::SeqCst))
}

/// InterlockedCompareExchange: troca só se o valor atual for o comparando;
/// devolve o valor anterior.
pub fn compare_exchange(address: u64, exchange: u32, comparand: u32) -> Result<u32, KernelError> {
    guest::compare_exchange32(address, comparand, exchange)
}

/// InterlockedPushEntryList: entry->Next = head->Next; head->Next = entry,
/// publicado por CMPXCHG na cabeça. Devolve o antigo primeiro item.
pub fn push_entry_list(head: u64, entry: u64) -> Result<u64, KernelError> {
    let cell = guest::try_atomic_u64(head)?;
    let mut old = cell.load(Ordering::SeqCst);
    loop {
        guest::try_write64(entry, old)?;
        match cell.compare_exchange(old, entry, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(old),
            Err(observed) => old = observed,
        }
    }
}

/// InterlockedPopEntryList: o primeiro item ou NULL com a lista vazia.
pub fn pop_entry_list(head: u64) -> Result<u64, KernelError> {
    let cell = guest::try_atomic_u64(head)?;
    let mut first = cell.load(Ordering::SeqCst);
    loop {
        if first == 0 {
            return Ok(0);
        }
        let next = guest::try_read64(first)?;
        match cell.compare_exchange(first, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(first),
            Err(observed) => first = observed,
        }
    }
}

/// ExInterlockedInsertTailList: LIST_ENTRY circular sob spinlock; devolve o
/// antigo último item (NULL com a lista vazia).
pub fn insert_tail_list(head: u64, entry: u64, lock: u64) -> u64 {
    let previous = spin_lock::lock_with_raise(lock);
    let last = guest::read64(head + 8);
    guest::write64(entry, head);
    guest::write64(entry + 8, last);
    guest::write64(last, entry);
    guest::write64(head + 8, entry);
    spin_lock::unlock_with_lower(lock, previous);
    if last == head { 0 } else { last }
}

/// ExInterlockedRemoveHeadList: o item removido ou NULL com a lista vazia.
pub fn remove_head_list(head: u64, lock: u64) -> u64 {
    let previous = spin_lock::lock_with_raise(lock);
    let first = guest::read64(head);
    let mut removed = 0;
    if first != head {
        removed = first;
        let next = guest::read64(first);
        guest::write64(head, next);
        guest::write64(next + 8, head);
    }
    spin_lock::unlock_with_lower(lock, previous);
    removed
}
