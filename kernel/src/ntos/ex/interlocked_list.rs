//! Listas simples protegidas por spin lock (ExInterlockedPushEntryList e
//! ExInterlockedPopEntryList).
//!
//! A cabeça é uma SINGLE_LIST_ENTRY de 8 bytes (só o ponteiro Next): como no
//! ntoskrnl, só `[ListHead]` e `[Entry]` são tocados — não há Depth nem
//! Sequence, que são do SLIST_HEADER. O spin lock do chamador é o legado de
//! `spin_lock` (sobe a DISPATCH_LEVEL).

use super::spin_lock;
use crate::ntos::mm::guest_memory as guest;

fn push_entry(head: u64, entry: u64) -> u64 {
    let previous = guest::read64(head);
    guest::write64(entry, previous);
    guest::write64(head, entry);
    previous
}

fn pop_entry(head: u64) -> u64 {
    let first = guest::read64(head);
    if first == 0 {
        return 0;
    }
    guest::write64(head, guest::read64(first));
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
