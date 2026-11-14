//! Filas de dispositivo (KDEVICE_QUEUE): a fila de pedidos de um
//! DEVICE_OBJECT (DeviceObject->DeviceQueue, a do IoStartPacket) e a de
//! espera de um CONTROLLER_OBJECT (DeviceWaitQueue).
//!
//! O layout é o do NT x64: lista em DeviceListHead, KSPIN_LOCK em Lock e, no
//! qword de +0x20, o BOOLEAN Busy no byte baixo e um Hint de 56 bits com
//! sinal nos bits 8..63 — a última entrada que precedeu uma retirada por
//! chave, de onde o KeRemoveByKeyDeviceQueue seguinte retoma a busca. Toda
//! retirada que leva a própria entrada do Hint o zera (mantendo o Busy).
//!
//! As entradas (KDEVICE_QUEUE_ENTRY) têm o elo no início, a SortKey e o
//! BOOLEAN Inserted. Inserção e retirada acontecem com o Lock retido em
//! DISPATCH_LEVEL (o KeAcquireInStackQueuedSpinLockForDpc do NT: sobe ao
//! nível só se estiver abaixo e volta ao anterior na saída), e um elo que
//! não aponta de volta é corrupção de lista (__fastfail 3, o bugcheck 0x139).

use crate::ntos::inc::types::{KdeviceQueue, KdeviceQueueEntry, ListEntry, NtStruct};
use crate::ntos::ke::{bugcheck, spin_lock};

/// DeviceQueueObject (KOBJECTS).
const DEVICE_QUEUE_OBJECT: i16 = 0x14;
/// KERNEL_SECURITY_CHECK_FAILURE / FAST_FAIL_CORRUPT_LIST_ENTRY.
const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_CORRUPT_LIST_ENTRY: u64 = 3;

/// Lock da fila retido; a saída solta e devolve o IRQL anterior.
struct Held<'a> {
    queue: &'a KdeviceQueue,
    previous: u8,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        spin_lock::release(self.queue.lock.address(), self.previous as u64);
    }
}

/// KeAcquireInStackQueuedSpinLockForDpc: sobe a DISPATCH_LEVEL se preciso.
fn lock_for_dpc(queue: &KdeviceQueue) -> Held<'_> {
    Held { queue, previous: spin_lock::acquire_for_dpc(queue.lock.address()) }
}

/// KeAcquireInStackQueuedSpinLock: sobe sempre a DISPATCH_LEVEL.
fn lock_raised(queue: &KdeviceQueue) -> Held<'_> {
    Held { queue, previous: spin_lock::acquire(queue.lock.address()) }
}

fn corrupt_list() -> ! {
    bugcheck::bug_check_ex(KERNEL_SECURITY_CHECK_FAILURE, FAST_FAIL_CORRUPT_LIST_ENTRY, 0, 0, 0)
}

fn link_at(address: u64) -> &'static ListEntry {
    // SAFETY: elo de uma fila viva (a cabeça ou o início de uma entrada).
    unsafe { ListEntry::at(address) }
}

fn entry_at(address: u64) -> &'static KdeviceQueueEntry {
    // SAFETY: o elo é o primeiro campo da KDEVICE_QUEUE_ENTRY.
    unsafe { KdeviceQueueEntry::at(address) }
}

/// O Hint: bits 8..63 do qword de +0x20, com sinal (SAR 8).
fn hint(queue: &KdeviceQueue) -> u64 {
    ((queue.bitfield_20.get() as i64) >> 8) as u64
}

/// Grava o Hint mantendo o Busy do byte baixo.
fn set_hint(queue: &KdeviceQueue, entry: u64) {
    let busy = queue.bitfield_20.get() & 0xFF;
    queue.bitfield_20.set(entry << 8 | busy);
}

/// A entrada que sai era o Hint: zera o Hint, mantém o Busy.
fn forget_hint(queue: &KdeviceQueue, entry: u64) {
    if hint(queue) == entry {
        set_hint(queue, 0);
    }
}

/// Insere `entry` antes de `next` (no fim quando `next` é a cabeça), com a
/// checagem `next->Blink->Flink == next`.
fn link_before(next: &ListEntry, entry: &KdeviceQueueEntry) {
    let previous = link_at(next.blink.get());
    if previous.flink.get() != next.address() {
        corrupt_list();
    }
    let link = &entry.device_list_entry;
    link.flink.set(next.address());
    link.blink.set(previous.address());
    previous.flink.set(link.address());
    next.blink.set(link.address());
}

/// RemoveEntryList com a checagem dos dois vizinhos.
fn unlink(link: &ListEntry) {
    let next = link_at(link.flink.get());
    let previous = link_at(link.blink.get());
    if next.blink.get() != link.address() || previous.flink.get() != link.address() {
        corrupt_list();
    }
    previous.flink.set(next.address());
    next.blink.set(previous.address());
}

/// RemoveHeadList com a checagem `First->Blink == Head` e
/// `First->Flink->Blink == First`.
fn unlink_first(head: &ListEntry) -> &'static KdeviceQueueEntry {
    let first = link_at(head.flink.get());
    let next = link_at(first.flink.get());
    if first.blink.get() != head.address() || next.blink.get() != first.address() {
        corrupt_list();
    }
    head.flink.set(next.address());
    next.blink.set(head.address());
    entry_at(first.address())
}

/// Depois de tirar a entrada: Inserted apagado e o Hint que apontava para
/// ela.
fn taken(queue: &KdeviceQueue, entry: &'static KdeviceQueueEntry) -> &'static KdeviceQueueEntry {
    entry.inserted.set(0);
    forget_hint(queue, entry.address());
    entry
}

/// KeInitializeDeviceQueue: Type/Size, lista vazia, Lock livre, Busy e Hint
/// zerados.
pub fn initialize(queue: &KdeviceQueue) {
    queue.type_.set(DEVICE_QUEUE_OBJECT);
    queue.size.set(KdeviceQueue::SIZE as i16);
    let head = &queue.device_list_head;
    head.blink.set(head.address());
    head.flink.set(head.address());
    queue.lock.set(0);
    queue.busy.set(0);
    queue.bitfield_20.set(0);
}

/// KeInsertDeviceQueue: marca Busy; a fila já estava ocupada põe a entrada
/// no fim e devolve TRUE (Inserted), livre devolve FALSE (o chamador inicia
/// o pedido na hora). A SortKey não muda.
pub fn insert(queue: &KdeviceQueue, entry: &KdeviceQueueEntry) -> bool {
    let _held = lock_for_dpc(queue);
    let was_busy = queue.busy.get();
    queue.busy.set(1);
    let inserted = was_busy == 1;
    if inserted {
        link_before(&queue.device_list_head, entry);
    }
    entry.inserted.set(inserted as u8);
    inserted
}

/// KeInsertByKeyDeviceQueue: grava a SortKey (antes do lock, sempre) e, com
/// a fila ocupada, insere depois de todas as entradas de chave <= `key`
/// (direto no fim quando a última já tem chave <= `key`).
pub fn insert_by_key(queue: &KdeviceQueue, entry: &KdeviceQueueEntry, key: u32) -> bool {
    entry.sort_key.set(key);
    let _held = lock_for_dpc(queue);
    let was_busy = queue.busy.get();
    queue.busy.set(1);
    let inserted = was_busy == 1;
    if inserted {
        let head = &queue.device_list_head;
        let mut next = head;
        if head.flink.get() != head.address() && key < entry_at(head.blink.get()).sort_key.get() {
            next = link_at(head.flink.get());
            while key >= entry_at(next.address()).sort_key.get() {
                next = link_at(next.flink.get());
            }
        }
        link_before(next, entry);
    }
    entry.inserted.set(inserted as u8);
    inserted
}

/// KeRemoveDeviceQueue: a primeira entrada; fila vazia zera o Busy e
/// devolve `None`.
pub fn remove(queue: &KdeviceQueue) -> Option<&'static KdeviceQueueEntry> {
    let _held = lock_for_dpc(queue);
    let head = &queue.device_list_head;
    if head.flink.get() == head.address() {
        queue.busy.set(0);
        return None;
    }
    let first = unlink_first(head);
    Some(taken(queue, first))
}

/// KeRemoveByKeyDeviceQueue: a primeira entrada de chave >= `key` (a
/// primeira da fila quando nenhuma chega a `key`). A busca parte do Hint
/// quando `key` passa da chave dele; o Hint passa a ser a entrada anterior
/// à retirada (zero quando ela era a primeira). Fila vazia zera o Busy.
pub fn remove_by_key(queue: &KdeviceQueue, key: u32) -> Option<&'static KdeviceQueueEntry> {
    let _held = lock_for_dpc(queue);
    let head = &queue.device_list_head;
    let first = head.flink.get();
    if first == head.address() {
        queue.busy.set(0);
        return None;
    }
    let found = if entry_at(head.blink.get()).sort_key.get() < key {
        entry_at(first)
    } else {
        let start = hint(queue);
        let mut candidate = if start != 0 && key > entry_at(start).sort_key.get() { entry_at(start) } else { entry_at(first) };
        while key > candidate.sort_key.get() {
            candidate = entry_at(candidate.device_list_entry.flink.get());
        }
        candidate
    };
    let previous = found.device_list_entry.blink.get();
    set_hint(queue, if previous == head.address() { 0 } else { previous });
    unlink(&found.device_list_entry);
    found.inserted.set(0);
    Some(found)
}

/// KeRemoveByKeyDeviceQueueIfBusy: com a fila ocupada, a primeira entrada
/// de chave >= `key` (ou a primeira da fila); fila vazia zera o Busy. Livre,
/// não mexe em nada e devolve `None`.
pub fn remove_by_key_if_busy(queue: &KdeviceQueue, key: u32) -> Option<&'static KdeviceQueueEntry> {
    let _held = lock_for_dpc(queue);
    if queue.busy.get() == 0 {
        return None;
    }
    let head = &queue.device_list_head;
    let first = head.flink.get();
    if first == head.address() {
        queue.busy.set(0);
        return None;
    }
    let mut link = first;
    while link != head.address() && key > entry_at(link).sort_key.get() {
        link = link_at(link).flink.get();
    }
    let found = if link == head.address() {
        unlink_first(head)
    } else {
        unlink(link_at(link));
        entry_at(link)
    };
    Some(taken(queue, found))
}

/// KeRemoveEntryDeviceQueue: tira `entry` se ela estiver na fila e diz se
/// estava (o Lock sobe sempre a DISPATCH_LEVEL e volta ao IRQL anterior).
pub fn remove_entry(queue: &KdeviceQueue, entry: &'static KdeviceQueueEntry) -> bool {
    let _held = lock_raised(queue);
    let inserted = entry.inserted.get() == 1;
    if inserted {
        entry.inserted.set(0);
        unlink(&entry.device_list_entry);
        forget_hint(queue, entry.address());
    }
    inserted
}

/// Entradas na fila (diagnóstico e testes).
pub fn count(queue: &KdeviceQueue) -> usize {
    let _held = lock_for_dpc(queue);
    let head = queue.device_list_head.address();
    let mut count = 0;
    let mut link = queue.device_list_head.flink.get();
    while link != head && link != 0 {
        count += 1;
        link = link_at(link).flink.get();
    }
    count
}

/// O Hint corrente (testes).
pub fn current_hint(queue: &KdeviceQueue) -> u64 {
    hint(queue)
}
