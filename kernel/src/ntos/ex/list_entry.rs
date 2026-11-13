//! LIST_ENTRY duplamente encadeada: InitializeListHead, InsertTailList e
//! RemoveEntryList sobre a memória do próprio objeto.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::ListEntry;

/// A LIST_ENTRY em `address` (um Flink/Blink lido de outra entrada).
pub(super) fn at(address: u64) -> &'static ListEntry {
    // SAFETY: os vínculos de uma lista viva apontam para LIST_ENTRYs vivas.
    unsafe { ListEntry::at(address) }
}

/// InitializeListHead.
pub(super) fn initialize(head: &ListEntry) {
    head.flink.set(head.address());
    head.blink.set(head.address());
}

/// `head->Blink->Flink == head` (a checagem do InsertTailList seguro).
pub(super) fn tail_consistent(head: &ListEntry) -> bool {
    at(head.blink.get()).flink.get() == head.address()
}

/// InsertTailList (sem checagem; ver [`tail_consistent`]).
pub(super) fn insert_tail(head: &ListEntry, entry: &ListEntry) {
    let last = at(head.blink.get());
    entry.flink.set(head.address());
    entry.blink.set(last.address());
    last.flink.set(entry.address());
    head.blink.set(entry.address());
}

/// RemoveEntryList com a checagem dos vizinhos: devolve o Flink antigo, ou
/// `None` (sem tocar em nada) se os vizinhos não apontam de volta.
pub(super) fn remove(entry: &ListEntry) -> Option<u64> {
    let next = at(entry.flink.get());
    let previous = at(entry.blink.get());
    if next.blink.get() != entry.address() || previous.flink.get() != entry.address() {
        return None;
    }
    previous.flink.set(next.address());
    next.blink.set(previous.address());
    Some(next.address())
}
