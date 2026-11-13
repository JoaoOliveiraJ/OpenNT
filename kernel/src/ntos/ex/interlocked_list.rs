//! Listas simples protegidas por spin lock (ExInterlockedPushEntryList e
//! ExInterlockedPopEntryList).
//!
//! A cabeça é uma SINGLE_LIST_ENTRY de 8 bytes (só o ponteiro Next): como no
//! ntoskrnl, só `[ListHead]` e `[Entry]` são tocados — não há Depth nem
//! Sequence, que são do SLIST_HEADER. O spin lock do chamador é o legado de
//! `spin_lock` (sobe a DISPATCH_LEVEL).

use super::spin_lock;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::SingleListEntry;

fn entry_at(address: u64) -> &'static SingleListEntry {
    // SAFETY: cabeça e entradas são SINGLE_LIST_ENTRYs do chamador.
    unsafe { SingleListEntry::at(address) }
}

fn push_entry(head: &SingleListEntry, entry: &SingleListEntry) -> u64 {
    let previous = head.next.get();
    entry.next.set(previous);
    head.next.set(entry.address());
    previous
}

fn pop_entry(head: &SingleListEntry) -> u64 {
    let first = head.next.get();
    if first == 0 {
        return 0;
    }
    head.next.set(entry_at(first).next.get());
    first
}

/// ExInterlockedPushEntryList: devolve a entrada que estava no topo.
pub fn push(head: u64, entry: u64, lock: u64) -> u64 {
    let previous_irql = spin_lock::lock_with_raise(lock);
    let previous = push_entry(entry_at(head), entry_at(entry));
    spin_lock::unlock_with_lower(lock, previous_irql);
    previous
}

/// ExInterlockedPopEntryList: devolve a entrada removida (0 se vazia).
pub fn pop(head: u64, lock: u64) -> u64 {
    let previous_irql = spin_lock::lock_with_raise(lock);
    let removed = pop_entry(entry_at(head));
    spin_lock::unlock_with_lower(lock, previous_irql);
    removed
}
