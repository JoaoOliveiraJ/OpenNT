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

/// Variante interna do ExQueueWorkItem: um WORK_QUEUE_ITEM do kernel
/// (embutido num bloco próprio) cuja rotina é Rust e recebe o Parameter.
pub fn queue_kernel_ex_work_item(item: u64, routine: KernelWorkRoutine, parameter: u64) {
    let mut queue = QUEUE.lock();
    if queue.entries.iter().any(|&(queued, _)| queued == item) {
        return;
    }
    let queue_item = queue_item_at(item);
    queue_item.list.flink.set(0);
    queue_item.list.blink.set(0);
    queue_item.worker_routine.set(0);
    queue_item.parameter.set(parameter);
    queue.entries.push((item, Kind::Ex));
    queue.kernel_routines.insert(item, routine);
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

/// WORKER_INVALID.
const WORKER_INVALID: u32 = 0xE4;

/// ExpValidateWorkItem: List.Flink nulo (item fora de fila), QueueType
/// fora de 7..=31 e abaixo de 64, WorkerRoutine no espaço de sistema; senão
/// WORKER_INVALID (1, 6 ou 7).
fn validate_ex_work_item(item: u64, queue_type: u32) {
    let queue_item = queue_item_at(item);
    if queue_item.list.flink.get() != 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(WORKER_INVALID, 1, item, queue_type as i32 as i64 as u64, 0);
    }
    if queue_type.wrapping_sub(7) <= 0x18 || queue_type as i32 >= 0x40 {
        crate::ntos::ke::bugcheck::bug_check_ex(WORKER_INVALID, 6, item, queue_type as i32 as i64 as u64, 0);
    }
    if queue_item.worker_routine.get() <= crate::ntos::mm::memory_map::USER_PROBE_ADDRESS {
        crate::ntos::ke::bugcheck::bug_check_ex(WORKER_INVALID, 7, item, 0, 0);
    }
}

/// ExTryQueueWorkItem(WorkItem, QueueType): valida o item como o
/// ExQueueWorkItem e o põe na fila se o pool de workers está pronto,
/// devolvendo TRUE. A fila do OpenNT é drenada pelos pumps do kernel, que
/// sempre a aceitam (o ExpIsPoolReadyForWork nunca recusa).
pub fn try_queue_ex_work_item(item: u64, queue_type: u32) -> bool {
    validate_ex_work_item(item, queue_type);
    queue_ex_work_item(item, queue_type);
    true
}

pub fn pending() -> usize {
    QUEUE.lock().entries.len()
}

/// IoUninitializeWorkItem (ntoskrnl 19041 rva 0x320590): um IO_WORKITEM
/// embutido (IoInitializeWorkItem) só pode ser desfeito fora da fila; ainda
/// enfileirado é KeBugCheckEx(WORKER_INVALID 0xE4, 2, Item, &Item->IoObject, 0).
/// No NT o teste é WorkItem.List.Flink != NULL; no OpenNT a posse da fila é
/// a lista `QUEUE.entries`. Fora da fila, só solta a rotina interna ligada.
pub fn uninitialize_work_item(item: u64) {
    let queued = QUEUE.lock().entries.iter().any(|&(queued, _)| queued == item);
    let body = body_at(item);
    if queued || body.work_item.list.flink.get() != 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(0xE4, 2, item, body.device_object.address(), 0);
    }
    forget_kernel_routine(&mut QUEUE.lock(), item);
}
