//! Operações interlocked sobre a memória do convidado — Interlocked* de 32
//! bits, listas simples (InterlockedPushEntryList/PopEntryList) e listas
//! duplas sob spinlock (ExInterlockedInsertTailList/RemoveHeadList).
//!
//! Cada Interlocked* é uma instrução LOCK sobre a célula do convidado
//! (ponteiro do driver: sonda e alinhamento natural). As listas simples
//! trocam a cabeça por CMPXCHG; as ExInterlocked* tomam o KSPIN_LOCK do
//! chamador (um ULONG_PTR: posse no bit 0 por LOCK BTS de 64 bits, o mesmo
//! protocolo do KeAcquireSpinLock em `ke::spin_lock`) em DISPATCH_LEVEL e
//! devolvem o IRQL anterior na liberação.

use core::sync::atomic::Ordering;

use crate::ntos::inc::types::{ListEntry, NtStruct, SingleListEntry};
use crate::ntos::ke::spin_lock;
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
    let cell = guest::try_atomic_u64(SingleListEntry::try_at(head)?.next.address())?;
    let entry_links = SingleListEntry::try_at(entry)?;
    let mut old = cell.load(Ordering::SeqCst);
    loop {
        entry_links.next.probe_set(old)?;
        match cell.compare_exchange(old, entry, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(old),
            Err(observed) => old = observed,
        }
    }
}

/// InterlockedPopEntryList: o primeiro item ou NULL com a lista vazia.
pub fn pop_entry_list(head: u64) -> Result<u64, KernelError> {
    let cell = guest::try_atomic_u64(SingleListEntry::try_at(head)?.next.address())?;
    let mut first = cell.load(Ordering::SeqCst);
    loop {
        if first == 0 {
            return Ok(0);
        }
        let next = SingleListEntry::try_at(first)?.next.probe_get()?;
        match cell.compare_exchange(first, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(first),
            Err(observed) => first = observed,
        }
    }
}

/// LIST_ENTRY do chamador, protegido pelo spin lock dele.
fn links(entry: u64) -> &'static ListEntry {
    // SAFETY: cabeça e entradas vivas e alinhadas da lista do chamador.
    unsafe { ListEntry::at(entry) }
}

/// ExInterlockedInsertTailList: LIST_ENTRY circular sob spinlock; devolve o
/// antigo último item (NULL com a lista vazia).
pub fn insert_tail_list(head: u64, entry: u64, lock: u64) -> u64 {
    let previous = spin_lock::acquire(lock);
    let last = links(head).blink.get();
    links(entry).flink.set(head);
    links(entry).blink.set(last);
    links(last).flink.set(entry);
    links(head).blink.set(entry);
    spin_lock::release(lock, previous as u64);
    if last == head { 0 } else { last }
}

/// ExInterlockedRemoveHeadList: o item removido ou NULL com a lista vazia.
pub fn remove_head_list(head: u64, lock: u64) -> u64 {
    let previous = spin_lock::acquire(lock);
    let first = links(head).flink.get();
    let mut removed = 0;
    if first != head {
        removed = first;
        let next = links(first).flink.get();
        links(head).flink.set(next);
        links(next).blink.set(head);
    }
    spin_lock::release(lock, previous as u64);
    removed
}
