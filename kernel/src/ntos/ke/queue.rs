//! Objetos KQUEUE: KeInitializeQueue, KeInsertQueue, KeInsertHeadQueue,
//! KeRemoveQueue(Ex), KeRundownQueue e KeReadStateQueue.
//!
//! O `Kqueue` (0x40) tem DISPATCHER_HEADER (Type 4, SignalState = entradas),
//! EntryListHead, CurrentCount, MaximumCount e ThreadListHead; a thread
//! associada fica em KTHREAD.Queue e KTHREAD.QueueListEntry. Semântica do
//! ntoskrnl 19041:
//! - inserção com checagem de lista (fast fail 3 -> bugcheck 0x139),
//!   SignalState++ e o SignalState anterior como resultado. No NT um
//!   aguardante recebe a entrada direto; aqui ele a pega da lista na
//!   próxima consulta (mesmo resultado);
//! - a thread já associada retira entradas sem mexer no CurrentCount
//!   enquanto SignalState != 0 e CurrentCount <= MaximumCount; senão libera
//!   a vaga (ou se associa, deixando a fila anterior) e espera SignalState !=
//!   0 e CurrentCount < MaximumCount, ocupando a vaga ao retomar. Cada
//!   entrada retirada fica com Flink = NULL. Uma espera que termina com
//!   status o devolve na primeira posição (STATUS_TIMEOUT; STATUS_ABANDONED
//!   numa fila desmontada, bit Abandoned do cabeçalho);
//! - o rundown zera SignalState, tira a cabeça da lista circular (as
//!   entradas seguem circulares, devolvidas pela primeira), marca a fila
//!   (`lock bts` no bit 8 do cabeçalho) e desassocia as threads
//!   (CurrentCount 0).
//!
//! A espera é a cooperativa do `dispatcher` (o mesmo laço do
//! KeWaitForSingleObject). Limites: alertas e APCs de usuário não encerram
//! a espera; uma thread associada que espera outro objeto não libera a vaga
//! (o KiActivateWaiterQueue do NT depende de ganchos do escalonador);
//! KeWaitForSingleObject direto numa KQUEUE não está no
//! `dispatcher::acquire_status`.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{bugcheck, clock, dispatcher, smp};
use crate::ntos::inc::types::{Kqueue, Kthread, ListEntry, NtStruct};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

/// QueueObject e o Size (0x40 / 4) do KeInitializeQueue.
const QUEUE_OBJECT: u8 = 4;
const QUEUE_SIZE_DWORDS: u8 = 0x10;
const STATUS_ABANDONED: u64 = 0x80;
const STATUS_TIMEOUT: u64 = 0x102;
/// KERNEL_SECURITY_CHECK_FAILURE / FAST_FAIL_CORRUPT_LIST_ENTRY.
const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_CORRUPT_LIST_ENTRY: u64 = 3;

/// Lock do objeto (KiAcquireKobjectLockSafe): nunca retido numa espera.
static OBJECT_LOCK: SpinLock<()> = SpinLock::new(());

fn corrupt_list() -> ! {
    bugcheck::bug_check_ex(KERNEL_SECURITY_CHECK_FAILURE, FAST_FAIL_CORRUPT_LIST_ENTRY, 0, 0, 0)
}

fn link(address: u64) -> &'static ListEntry {
    // SAFETY: vínculos de uma lista viva apontam para LIST_ENTRYs vivas.
    unsafe { ListEntry::at(address) }
}

fn initialize_list(head: &ListEntry) {
    head.flink.set(head.address());
    head.blink.set(head.address());
}

fn is_empty(head: &ListEntry) -> bool {
    head.flink.get() == head.address()
}

/// InsertHeadList/InsertTailList com a checagem do vizinho.
fn insert(head: &ListEntry, entry: &ListEntry, at_head: bool) {
    if at_head {
        let first = link(head.flink.get());
        if first.blink.get() != head.address() {
            corrupt_list();
        }
        entry.flink.set(first.address());
        entry.blink.set(head.address());
        first.blink.set(entry.address());
        head.flink.set(entry.address());
    } else {
        let last = link(head.blink.get());
        if last.flink.get() != head.address() {
            corrupt_list();
        }
        entry.flink.set(head.address());
        entry.blink.set(last.address());
        last.flink.set(entry.address());
        head.blink.set(entry.address());
    }
}

/// RemoveEntryList com a checagem dos vizinhos.
fn remove_link(entry: &ListEntry) {
    let (next, previous) = (link(entry.flink.get()), link(entry.blink.get()));
    if next.blink.get() != entry.address() || previous.flink.get() != entry.address() {
        corrupt_list();
    }
    previous.flink.set(next.address());
    next.blink.set(previous.address());
}

/// Ocupa (+1) ou libera (-1) uma vaga, sem passar de zero.
fn adjust_current(queue: &Kqueue, delta: i32) {
    let _ = queue.current_count.atomic().try_update(Ordering::SeqCst, Ordering::SeqCst, |count| Some((count as i32).saturating_add(delta).max(0) as u32));
}

/// Retira até `count` entradas (Flink = NULL, SignalState--).
fn take(queue: &Kqueue, count: u32) -> Vec<u64> {
    let mut taken = Vec::new();
    while (taken.len() as u32) < count && !is_empty(&queue.entry_list_head) {
        let entry = link(queue.entry_list_head.flink.get());
        remove_link(entry);
        entry.flink.set(0);
        queue.header.signal_state.atomic().fetch_sub(1, Ordering::SeqCst);
        taken.push(entry.address());
    }
    taken
}

/// KeInitializeQueue: MaximumCount = Count, ou os processadores ativos
/// (KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)).
pub fn initialize(queue: &Kqueue, count: u32) {
    queue.header.type_.set(QUEUE_OBJECT);
    queue.header.signalling.set(0);
    queue.header.size.set(QUEUE_SIZE_DWORDS);
    initialize_list(&queue.header.wait_list_head);
    initialize_list(&queue.entry_list_head);
    initialize_list(&queue.thread_list_head);
    queue.header.signal_state.set(0);
    queue.current_count.set(0);
    queue.maximum_count.set(if count != 0 { count } else { smp::online_cpu_count() as u32 });
}

/// KeReadStateQueue: SignalState (LONG).
pub fn read_state(queue: &Kqueue) -> i32 {
    queue.header.signal_state.get()
}

/// KeInsertQueue / KeInsertHeadQueue: o SignalState anterior.
pub fn insert_entry(queue: &Kqueue, entry: &ListEntry, at_head: bool) -> i32 {
    let _lock = OBJECT_LOCK.lock();
    let previous = queue.header.signal_state.atomic().fetch_add(1, Ordering::SeqCst);
    insert(&queue.entry_list_head, entry, at_head);
    previous
}

/// Corpo de KeRemoveQueueEx: as entradas retiradas, ou [status].
pub fn remove_entries(queue: &Kqueue, timeout_pointer: u64, count: u32) -> Result<Vec<u64>, KernelError> {
    let address = process::get_current_thread();
    if address == 0 {
        return Err(KernelError::new("KeRemoveQueue requires a current KTHREAD"));
    }
    // SAFETY: a KTHREAD corrente está viva durante a chamada.
    let thread = unsafe { Kthread::at(address) };
    let count = count.max(1);
    let timeout = dispatcher::timeout_to_100ns(timeout_pointer);
    let deadline = timeout.map(|timeout| clock::uptime_100ns() + timeout);
    let available = |queue: &Kqueue| queue.header.signal_state.get() != 0;
    {
        let _lock = OBJECT_LOCK.lock();
        let associated = thread.queue.get();
        if associated == queue.address() {
            // A thread mantém a vaga do item anterior no caminho rápido.
            if available(queue) && queue.current_count.get() <= queue.maximum_count.get() && queue.header.abandoned() == 0 {
                return Ok(take(queue, count));
            }
            adjust_current(queue, -1);
        } else {
            if associated != 0 {
                // SAFETY: KTHREAD.Queue só aponta para KQUEUEs vivas.
                adjust_current(unsafe { Kqueue::at(associated) }, -1);
                remove_link(&thread.queue_list_entry);
            }
            thread.queue.set(queue.address());
            insert(&queue.thread_list_head, &thread.queue_list_entry, false);
        }
    }
    loop {
        {
            let _lock = OBJECT_LOCK.lock();
            if queue.header.abandoned() != 0 {
                return Ok(alloc::vec![STATUS_ABANDONED]);
            }
            if available(queue) && queue.current_count.get() < queue.maximum_count.get() {
                adjust_current(queue, 1);
                return Ok(take(queue, count));
            }
            if timeout == Some(0) || deadline.is_some_and(|deadline| clock::uptime_100ns() >= deadline) {
                // A thread volta a ficar ativa na fila ao retomar.
                adjust_current(queue, 1);
                return Ok(alloc::vec![STATUS_TIMEOUT]);
            }
        }
        dispatcher::pump_kernel();
    }
}

/// KeRemoveQueue(Queue, WaitMode, Timeout): a entrada, ou o status como
/// ponteiro.
pub fn remove(queue: &Kqueue, timeout_pointer: u64) -> Result<u64, KernelError> {
    Ok(remove_entries(queue, timeout_pointer, 1)?.first().copied().unwrap_or(0))
}

/// KeRemoveQueueEx(Queue, WaitMode, Alertable, Timeout, Array, Count):
/// grava as entradas (ou o status) no vetor e devolve quantas.
pub fn remove_ex(queue: &Kqueue, timeout_pointer: u64, array: u64, count: u32) -> Result<u32, KernelError> {
    let entries = remove_entries(queue, timeout_pointer, count)?;
    // SAFETY: PLIST_ENTRY EntryArray[Count] do chamador (modo kernel); no
    // máximo `count` posições são gravadas.
    let slots = unsafe { crate::ntos::inc::types::Field::<u64>::array_at(array, entries.len()) };
    for (slot, &entry) in slots.iter().zip(&entries) {
        slot.set(entry);
    }
    Ok(entries.len() as u32)
}

/// KeRundownQueue: a primeira entrada restante (NULL se vazia).
pub fn rundown(queue: &Kqueue) -> u64 {
    let _lock = OBJECT_LOCK.lock();
    let head = &queue.entry_list_head;
    let first = if is_empty(head) {
        0
    } else {
        queue.header.signal_state.set(0);
        let (first, last) = (link(head.flink.get()), link(head.blink.get()));
        if first.blink.get() != head.address() || last.flink.get() != head.address() {
            corrupt_list();
        }
        last.flink.set(first.address());
        first.blink.set(last.address());
        initialize_list(head);
        first.address()
    };
    // KeRundownQueueCommon: marca o rundown e desassocia as threads.
    queue.header.lock.atomic().fetch_or(1 << 8, Ordering::SeqCst);
    while !is_empty(&queue.thread_list_head) {
        let entry = link(queue.thread_list_head.flink.get());
        remove_link(entry);
        // SAFETY: as entradas da ThreadListHead são KTHREAD.QueueListEntry vivas.
        let thread = unsafe { Kthread::at(entry.address() - core::mem::offset_of!(Kthread, queue_list_entry) as u64) };
        thread.queue.set(0);
    }
    queue.current_count.set(0);
    first
}
