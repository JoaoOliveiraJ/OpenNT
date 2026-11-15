//! Objetos KQUEUE: KeInitializeQueue, KeInsertQueue, KeInsertHeadQueue,
//! KeRemoveQueue(Ex), KeRundownQueue e KeReadStateQueue.
//!
//! O `Kqueue` (0x40) tem DISPATCHER_HEADER (Type 4, SignalState = entradas),
//! EntryListHead, CurrentCount, MaximumCount e ThreadListHead; a thread
//! associada fica em KTHREAD.Queue e KTHREAD.QueueListEntry. Semântica do
//! ntoskrnl 19041:
//! - inserção com checagem de lista (fast fail 3 -> bugcheck 0x139) e o
//!   SignalState anterior como resultado. Como no KiInsertQueue, com uma
//!   thread parada na fila (o primeiro bloco WaitDequeue da WaitListHead, o
//!   da espera mais recente), vaga livre (CurrentCount < MaximumCount) e
//!   quem insere fora da fila, a entrada não entra na lista: vai direto à
//!   thread pelo KTHREAD.WaitStatus, que sai da espera ocupando a vaga
//!   (CurrentCount++); senão SignalState++ e a entrada entra na lista;
//! - a thread já associada retira entradas sem mexer no CurrentCount
//!   enquanto SignalState != 0 e CurrentCount <= MaximumCount; senão libera
//!   a vaga (ou se associa, deixando a fila anterior) e espera SignalState !=
//!   0 e CurrentCount < MaximumCount, ocupando a vaga ao retomar. Cada
//!   entrada retirada da lista fica com Flink = NULL. Uma espera que termina
//!   com status o devolve na primeira posição (STATUS_TIMEOUT; STATUS_ABANDONED
//!   numa fila desmontada, bit Abandoned do cabeçalho);
//! - o rundown zera SignalState, tira a cabeça da lista circular (as
//!   entradas seguem circulares, devolvidas pela primeira), marca a fila
//!   (`lock bts` no bit 8 do cabeçalho), desassocia as threads
//!   (CurrentCount 0) e tira da espera as paradas nela, com STATUS_ABANDONED.
//!
//! A espera de uma thread de kernel é a do KeRemoveQueueEx (`ke::wait`): o
//! bloco WaitDequeue (WaitKey 0x80, WrQueue) na cabeça da WaitListHead, a
//! vaga liberada logo antes, e a thread fora das prontas até a entrada
//! entregue pelo KeInsertQueue, o prazo, um alerta ou uma APC (a de kernel é
//! entregue e a espera recomeça). A de uma thread de usuário numa syscall
//! bloqueia (o KiSwapContext do OpenNT) e o despachante de usuário sonda a
//! fila no contexto dela; o contexto de boot gira o `pump_kernel` entre
//! tentativas. Como no NT, uma entrada disponível vence o alerta; a espera
//! alertável termina com STATUS_ALERTED (ou STATUS_USER_APC em UserMode) e a
//! thread volta a ocupar a vaga. Limites: uma thread associada que espera
//! outro objeto não libera a vaga (o KiActivateWaiterQueue do NT depende de
//! ganchos do escalonador); KeWaitForSingleObject direto numa KQUEUE não está
//! no `dispatcher::acquire_status`.
//!
//! O estado das filas fica sob o lock do despachante (`wait::lock`), o
//! mesmo das listas de espera: a entrega direta e a espera não se cruzam.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{bugcheck, clock, context_switch, dispatcher, smp, thread_alert, wait};
use crate::ntos::inc::types::{Kqueue, Kthread, ListEntry, NtStruct};
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// QueueObject e o Size (0x40 / 4) do KeInitializeQueue.
const QUEUE_OBJECT: u8 = 4;
const QUEUE_SIZE_DWORDS: u8 = 0x10;
const STATUS_ABANDONED: u32 = 0x80;
const STATUS_TIMEOUT: u32 = 0x102;
/// KERNEL_SECURITY_CHECK_FAILURE / FAST_FAIL_CORRUPT_LIST_ENTRY.
const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_CORRUPT_LIST_ENTRY: u64 = 3;

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

/// KeInsertQueue / KeInsertHeadQueue (o KiInsertQueue): o SignalState
/// anterior. A entrada vai direto à thread parada na fila quando há vaga e
/// quem insere não está associado a ela; senão entra na lista.
pub fn insert_entry(queue: &Kqueue, entry: &ListEntry, at_head: bool) -> i32 {
    let mut lock = wait::lock();
    let previous = queue.header.signal_state.get();
    let caller = process::get_current_thread();
    // SAFETY: a KTHREAD corrente está viva durante a chamada.
    let caller_associated = caller != 0 && unsafe { Kthread::at(caller) }.queue.get() == queue.address();
    if !caller_associated && queue.current_count.get() < queue.maximum_count.get() {
        if let Some(waiter) = lock.first_dequeue_waiter(queue.address()) {
            adjust_current(queue, 1);
            if lock.unwait(waiter, entry.address()) {
                return previous;
            }
            adjust_current(queue, -1);
        }
    }
    queue.header.signal_state.atomic().fetch_add(1, Ordering::SeqCst);
    insert(&queue.entry_list_head, entry, at_head);
    previous
}

/// Corpo de KeRemoveQueueEx: as entradas retiradas, ou [status]. `wait_mode`
/// e `alertable` são os do KeRemoveQueueEx (KeRemoveQueue: não alertável).
pub fn remove_entries(queue: &Kqueue, timeout_pointer: u64, count: u32, wait_mode: u8, alertable: bool) -> Result<Vec<u64>, KernelError> {
    let address = process::get_current_thread();
    if address == 0 {
        return Err(KernelError::new("KeRemoveQueue requires a current KTHREAD"));
    }
    // SAFETY: a KTHREAD corrente está viva durante a chamada.
    let thread = unsafe { Kthread::at(address) };
    let count = count.max(1);
    let timeout = dispatcher::timeout_to_100ns(timeout_pointer);
    let available = |queue: &Kqueue| queue.header.signal_state.get() != 0;
    let blocking = context_switch::kernel_thread_can_block() && context_switch::on_kernel_thread_stack() == Some(address);
    // A thread já associada a esta fila ocupa uma vaga nela; numa thread de
    // kernel ela a libera só ao bloquear.
    let holding;
    {
        let _lock = wait::lock();
        let associated = thread.queue.get();
        holding = associated == queue.address();
        if holding {
            // A thread mantém a vaga do item anterior no caminho rápido.
            if available(queue) && queue.current_count.get() <= queue.maximum_count.get() && queue.header.abandoned() == 0 {
                return Ok(take(queue, count));
            }
            if !blocking {
                adjust_current(queue, -1);
            }
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
    let mut taken = None;
    if blocking {
        // A espera do KeRemoveQueueEx: sob o lock do despachante, a fila
        // desmontada, a entrada com vaga ou o bloqueio com a vaga liberada.
        let holding = core::cell::Cell::new(holding);
        let entries = core::cell::RefCell::new(None);
        let outcome = wait::wait_queue(
            queue.address(),
            wait::Deadline::after(timeout),
            wait_mode,
            alertable,
            || {
                if queue.header.abandoned() != 0 {
                    return Some(STATUS_ABANDONED as u64);
                }
                let (current, maximum) = (queue.current_count.get(), queue.maximum_count.get());
                if available(queue) && (current < maximum || (holding.get() && current <= maximum)) {
                    if !holding.get() {
                        adjust_current(queue, 1);
                        holding.set(true);
                    }
                    *entries.borrow_mut() = Some(take(queue, count));
                    return Some(0);
                }
                None
            },
            || {
                if holding.replace(false) {
                    adjust_current(queue, -1);
                }
            },
            || {
                if queue.header.abandoned() == 0 {
                    adjust_current(queue, 1);
                    holding.set(true);
                }
            },
        );
        return Ok(match outcome {
            wait::QueueWait::Entry(entry) => alloc::vec![entry],
            wait::QueueWait::Attempt(status) => entries.into_inner().unwrap_or_else(|| alloc::vec![status]),
            wait::QueueWait::Status(status) => {
                // Prazo, alerta ou APC de usuário: a thread volta a ocupar a
                // vaga (a fila desmontada já a desassociou).
                if !holding.get() && status != STATUS_ABANDONED {
                    let _lock = wait::lock();
                    adjust_current(queue, 1);
                }
                alloc::vec![status as u64]
            }
        });
    }
    let deadline = timeout.map(|timeout| clock::uptime_100ns() + timeout);
    // Uma tentativa: fila desmontada, entrada com vaga livre (a vaga é
    // ocupada) ou, com `check_timeout`, prazo vencido.
    let mut attempt = |check_timeout: bool| -> Option<u32> {
        let _lock = wait::lock();
        if queue.header.abandoned() != 0 {
            return Some(STATUS_ABANDONED);
        }
        if available(queue) && queue.current_count.get() < queue.maximum_count.get() {
            adjust_current(queue, 1);
            taken = Some(take(queue, count));
            return Some(0);
        }
        let expired = timeout == Some(0) || deadline.is_some_and(|deadline| clock::uptime_100ns() >= deadline);
        (check_timeout && expired).then_some(STATUS_TIMEOUT)
    };
    // Uma entrada disponível vence o alerta; senão a espera do NT: o alerta
    // (na alertável) e então a fila e o prazo.
    let status = match attempt(false) {
        Some(status) => status,
        None => {
            let mut poll = || attempt(true);
            if alertable {
                thread_alert::cooperate(address, wait_mode, true, &mut poll, dispatcher::pump_kernel)
            } else {
                context_switch::wait_until(&mut poll, dispatcher::pump_kernel)
            }
        }
    };
    if let Some(entries) = taken {
        return Ok(entries);
    }
    // Prazo, alerta, APC de usuário ou término: a thread volta a ficar ativa
    // na fila (a desmontada já a desassociou).
    if status != STATUS_ABANDONED {
        let _lock = wait::lock();
        adjust_current(queue, 1);
    }
    Ok(alloc::vec![status as u64])
}

/// KeRemoveQueue(Queue, WaitMode, Timeout): a entrada, ou o status como
/// ponteiro. Não alertável.
pub fn remove(queue: &Kqueue, wait_mode: u8, timeout_pointer: u64) -> Result<u64, KernelError> {
    Ok(remove_entries(queue, timeout_pointer, 1, wait_mode, false)?.first().copied().unwrap_or(0))
}

/// KeRemoveQueueEx(Queue, WaitMode, Alertable, Timeout, Array, Count):
/// grava as entradas (ou o status) no vetor e devolve quantas.
pub fn remove_ex(queue: &Kqueue, wait_mode: u8, alertable: bool, timeout_pointer: u64, array: u64, count: u32) -> Result<u32, KernelError> {
    let entries = remove_entries(queue, timeout_pointer, count, wait_mode, alertable)?;
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
    let mut lock = wait::lock();
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
    // As threads de kernel paradas na fila saem da espera com STATUS_ABANDONED.
    while let Some(waiter) = lock.first_dequeue_waiter(queue.address()) {
        if !lock.unwait(waiter, STATUS_ABANDONED as u64) {
            break;
        }
    }
    first
}
