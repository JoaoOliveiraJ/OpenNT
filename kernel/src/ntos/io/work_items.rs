//! Io Work Items.
//!
//! IoAllocateWorkItem/IoQueueWorkItem/ExQueueWorkItem: o kernel drena a fila
//! em PASSIVE_LEVEL (o papel das worker threads do sistema).
//!
//! O IO_WORKITEM é opaco para os drivers (só IoSizeofWorkItem o dimensiona);
//! o corpo é o do OpenNT, de 0x30 bytes ([`WorkItemBody`]): o WORK_QUEUE_ITEM
//! do NT no início (o mesmo prefixo do item do ExInitializeWorkItem, que a
//! fila trata igual), o dispositivo, o tipo e a marca de enfileirado. O
//! `_IO_WORKITEM` dos símbolos tem 0x58 bytes (Routine/IoObject/Context
//! depois do WORK_QUEUE_ITEM); componentes que embutem work items em blocos
//! próprios contam com os 0x30 do IoSizeofWorkItem.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{NtStruct, WorkQueueItem};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// Corpo do IO_WORKITEM do OpenNT (o tamanho que IoSizeofWorkItem devolve).
#[repr(C)]
struct WorkItemBody {
    /// List, WorkerRoutine (a rotina do driver) e Parameter (o contexto).
    work_item: WorkQueueItem,
    device_object: Field<u64>,
    /// QueueType | 0x8000_0000 na variante Ex.
    kind: Field<u32>,
    queued: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for WorkItemBody {}

const _: () = {
    assert!(core::mem::size_of::<WorkItemBody>() == 0x30);
    assert!(core::mem::offset_of!(WorkItemBody, device_object) == 0x20);
    assert!(core::mem::offset_of!(WorkItemBody, queued) == 0x2C);
};

/// Corpo do item (IO_WORKITEM do OpenNT).
fn body_at(item: u64) -> &'static WorkItemBody {
    // SAFETY: item alocado/inicializado por este módulo e vivo até o IoFreeWorkItem.
    unsafe { WorkItemBody::at(item) }
}

/// WORK_QUEUE_ITEM do item (prefixo comum de IO_WORKITEM e do item Ex).
fn queue_item_at(item: u64) -> &'static WorkQueueItem {
    // SAFETY: item vivo do chamador (driver ou kernel).
    unsafe { WorkQueueItem::at(item) }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Io,
    IoEx,
    Ex,
}

/// Rotina interna do kernel (no lugar de código nativo): (device, contexto).
pub type KernelWorkRoutine = fn(u64, u64);

struct Queue {
    entries: Vec<(u64, Kind)>,
    kernel_routines: BTreeMap<u64, KernelWorkRoutine>,
    readiness: BTreeMap<u64, fn() -> bool>,
}

static QUEUE: SpinLock<Queue> = SpinLock::new(Queue { entries: Vec::new(), kernel_routines: BTreeMap::new(), readiness: BTreeMap::new() });

fn forget_kernel_routine(queue: &mut Queue, item: u64) {
    queue.kernel_routines.remove(&item);
    queue.readiness.remove(&item);
}

/// IoAllocateWorkItem: zera o item e liga ao device dono.
pub fn create_work_item(device: u64, item: u64) {
    forget_kernel_routine(&mut QUEUE.lock(), item);
    let body = body_at(item);
    body.work_item.list.flink.set(0);
    body.work_item.list.blink.set(0);
    body.work_item.worker_routine.set(0);
    body.work_item.parameter.set(0);
    body.device_object.set(device);
    body.kind.set(0);
    body.queued.set(0);
}

/// IoQueueWorkItem(Ex): a rotina Ex recebe (ioObject, context, ioWorkItem).
pub fn queue_work_item_ex(item: u64, routine: u64, queue_type: u32, context: u64, extended: bool) {
    let mut queue = QUEUE.lock();
    if queue.entries.iter().any(|&(queued, _)| queued == item) {
        return;
    }
    forget_kernel_routine(&mut queue, item);
    let body = body_at(item);
    body.work_item.worker_routine.set(routine);
    body.work_item.parameter.set(context);
    body.kind.set(queue_type | if extended { 0x8000_0000 } else { 0 });
    body.queued.set(1);
    queue.entries.push((item, if extended { Kind::IoEx } else { Kind::Io }));
}

pub fn queue_work_item(item: u64, routine: u64, queue_type: u32, context: u64) {
    queue_work_item_ex(item, routine, queue_type, context, false);
}

/// IoAllocateWorkItem: aloca o IO_WORKITEM e o liga ao device dono.
pub fn allocate_work_item(device: u64) -> u64 {
    let item = guest::alloc_bytes(WorkItemBody::SIZE);
    create_work_item(device, item);
    item
}

/// IoFreeWorkItem: tira o item da fila e devolve o armazenamento.
pub fn free_work_item(item: u64) {
    unqueue(item);
    guest::free_bytes(item);
}

/// IoSizeofWorkItem.
pub fn work_item_size() -> u64 {
    WorkItemBody::SIZE
}

/// Variante interna: rotina do kernel em vez de código de driver.
pub fn queue_kernel_work_item(item: u64, routine: KernelWorkRoutine, context: u64, ready: Option<fn() -> bool>) {
    if QUEUE.lock().entries.iter().any(|&(queued, _)| queued == item) {
        return;
    }
    queue_work_item_ex(item, 0, 1, context, false); // DelayedWorkQueue
    let mut queue = QUEUE.lock();
    queue.kernel_routines.insert(item, routine);
    if let Some(ready) = ready {
        queue.readiness.insert(item, ready);
    }
}

/// Cancela um item; a rotina e o predicado internos também são soltos.
pub fn unqueue(item: u64) {
    let mut queue = QUEUE.lock();
    let kind = queue.entries.iter().position(|&(queued, _)| queued == item).map(|index| queue.entries.remove(index).1);
    forget_kernel_routine(&mut queue, item);
    if kind != Some(Kind::Ex) {
        body_at(item).queued.set(0);
    }
}

/// Drena a fila em PASSIVE_LEVEL.
pub fn run_queue() {
    loop {
        let (item, kind, kernel_routine) = {
            let mut queue = QUEUE.lock();
            if queue.entries.is_empty() {
                return;
            }
            let readiness = queue.readiness.clone();
            let Some(index) = queue.entries.iter().position(|(item, _)| readiness.get(item).is_none_or(|ready| ready())) else {
                return;
            };
            let (item, kind) = queue.entries.remove(index);
            let routine = queue.kernel_routines.remove(&item);
            queue.readiness.remove(&item);
            (item, kind, routine)
        };
        if kind != Kind::Ex {
            body_at(item).queued.set(0);
        }
        let queue_item = queue_item_at(item);
        let routine = queue_item.worker_routine.get();
        let device = if kind == Kind::Ex { 0 } else { body_at(item).device_object.get() };
        let context = queue_item.parameter.get();
        match (kernel_routine, kind) {
            (Some(routine), _) => routine(device, context),
            (None, Kind::IoEx) => {
                native_call::call(routine, &[device, context, item, 0]);
            }
            (None, Kind::Ex) => {
                native_call::call(routine, &[context, 0, 0, 0]);
            }
            (None, Kind::Io) => {
                native_call::call(routine, &[device, context, 0, 0]);
            }
        }
    }
}

/// ExInitializeWorkItem: a rotina recebe só o contexto.
pub fn initialize_ex_work_item(item: u64, routine: u64, context: u64) {
    forget_kernel_routine(&mut QUEUE.lock(), item);
    let queue_item = queue_item_at(item);
    queue_item.list.flink.set(0);
    queue_item.list.blink.set(0);
    queue_item.worker_routine.set(routine);
    queue_item.parameter.set(context);
}

/// ExQueueWorkItem.
pub fn queue_ex_work_item(item: u64, _queue_type: u32) {
    let mut queue = QUEUE.lock();
    if queue.entries.iter().any(|&(queued, _)| queued == item) {
        return;
    }
    forget_kernel_routine(&mut queue, item);
    queue.entries.push((item, Kind::Ex));
}

pub fn pending() -> usize {
    QUEUE.lock().entries.len()
}
