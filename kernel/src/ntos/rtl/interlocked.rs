//! Operações interlocked sobre a memória do convidado — Interlocked* de 32
//! bits, listas simples (InterlockedPushEntryList/PopEntryList) e listas
//! duplas sob spinlock (ExInterlockedInsertTailList/RemoveHeadList).
//!
//! As ExInterlocked* tomam o spinlock do chamador como test-and-set em
//! DISPATCH_LEVEL; o IRQL anterior volta na liberação.

use crate::ntos::ke::irql;
use crate::ntos::mm::guest_memory as guest;

/// InterlockedIncrement: devolve o valor novo.
pub fn increment(address: u64) -> u32 {
    let value = guest::read32(address).wrapping_add(1);
    guest::write32(address, value);
    value
}

/// InterlockedDecrement: devolve o valor novo.
pub fn decrement(address: u64) -> u32 {
    let value = guest::read32(address).wrapping_sub(1);
    guest::write32(address, value);
    value
}

/// InterlockedExchange: devolve o valor anterior.
pub fn exchange(address: u64, value: u32) -> u32 {
    let previous = guest::read32(address);
    guest::write32(address, value);
    previous
}

/// InterlockedCompareExchange: troca só se o valor atual for o comparando.
pub fn compare_exchange(address: u64, exchange: u32, comparand: u32) -> u32 {
    let previous = guest::read32(address);
    if previous == comparand {
        guest::write32(address, exchange);
    }
    previous
}

/// InterlockedPushEntryList: entry->Next = head->Next; head->Next = entry.
pub fn push_entry_list(head: u64, entry: u64) -> u64 {
    let old = guest::read64(head);
    guest::write64(entry, old);
    guest::write64(head, entry);
    old
}

/// InterlockedPopEntryList: o primeiro item ou NULL com a lista vazia.
pub fn pop_entry_list(head: u64) -> u64 {
    let first = guest::read64(head);
    if first == 0 {
        return 0;
    }
    guest::write64(head, guest::read64(first));
    first
}

/// Spinlock test-and-set em DISPATCH_LEVEL dos ExInterlocked* de lista.
fn spin_lock_acquire(lock: u64) -> u8 {
    let previous = irql::get_irql();
    irql::raise_irql(irql::DISPATCH_LEVEL);
    loop {
        if guest::read32(lock) == 0 {
            guest::write32(lock, 1);
            return previous;
        }
    }
}

fn spin_lock_release(lock: u64, previous: u8) {
    guest::write32(lock, 0);
    irql::lower_irql(previous as u64);
}

/// ExInterlockedInsertTailList: LIST_ENTRY circular sob spinlock; devolve o
/// antigo último item (NULL com a lista vazia).
pub fn insert_tail_list(head: u64, entry: u64, lock: u64) -> u64 {
    let previous = spin_lock_acquire(lock);
    let last = guest::read64(head + 8);
    guest::write64(entry, head);
    guest::write64(entry + 8, last);
    guest::write64(last, entry);
    guest::write64(head + 8, entry);
    spin_lock_release(lock, previous);
    if last == head { 0 } else { last }
}

/// ExInterlockedRemoveHeadList: o item removido ou NULL com a lista vazia.
pub fn remove_head_list(head: u64, lock: u64) -> u64 {
    let previous = spin_lock_acquire(lock);
    let first = guest::read64(head);
    let mut removed = 0;
    if first != head {
        removed = first;
        let next = guest::read64(first);
        guest::write64(head, next);
        guest::write64(next + 8, head);
    }
    spin_lock_release(lock, previous);
    removed
}
