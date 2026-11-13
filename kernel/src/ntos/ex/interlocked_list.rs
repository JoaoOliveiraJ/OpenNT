//! Listas simples protegidas por spin lock (ExInterlockedPushEntryList e
//! ExInterlockedPopEntryList).
//!
//! A cabeça é uma SINGLE_LIST_ENTRY com Depth em +8 e Sequence em +0xA; o
//! spin lock do chamador é o legado de `spin_lock` (sobe a DISPATCH_LEVEL).

use super::spin_lock;
use crate::ntos::mm::guest_memory as guest;

/// SINGLE_LIST com Depth em +8 e Sequence em +0xA (como o original).
fn push_entry(head: u64, entry: u64) -> u64 {
    let previous = guest::read64(head);
    guest::write64(entry, previous);
    guest::write64(head, entry);
    guest::write16(head + 8, guest::read16(head + 8).wrapping_add(1));
    guest::write16(head + 0xA, guest::read16(head + 0xA).wrapping_add(1));
    previous
}

fn pop_entry(head: u64) -> u64 {
    let first = guest::read64(head);
    if first == 0 {
        return 0;
    }
    guest::write64(head, guest::read64(first));
    guest::write16(head + 8, guest::read16(head + 8).wrapping_sub(1));
    first
}

/// ExInterlockedPushEntryList: devolve a entrada que estava no topo.
pub fn push(head: u64, entry: u64, lock: u64) -> u64 {
    let previous_irql = spin_lock::lock_with_raise(lock);
    let previous = push_entry(head, entry);
    spin_lock::unlock_with_lower(lock, previous_irql);
    previous
}

/// ExInterlockedPopEntryList: devolve a entrada removida (0 se vazia).
pub fn pop(head: u64, lock: u64) -> u64 {
    let previous_irql = spin_lock::lock_with_raise(lock);
    let removed = pop_entry(head);
    spin_lock::unlock_with_lower(lock, previous_irql);
    removed
}
