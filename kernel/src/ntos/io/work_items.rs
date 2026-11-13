//! Io Work Items — `system32/ntos/io/work-items.js`.
//!
//! IoAllocateWorkItem/IoQueueWorkItem/ExQueueWorkItem: o kernel drena a fila
//! em PASSIVE_LEVEL (o papel das worker threads do sistema). IO_WORKITEM no
//! formato interno do NT: WORK_QUEUE_ITEM { LIST_ENTRY; Function } + Context
//! + DeviceObject + Type.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::io_workitem as layout;

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
    guest::write64(item + layout::LIST_FLINK, 0);
    guest::write64(item + layout::LIST_BLINK, 0);
    guest::write64(item + layout::FUNCTION, 0);
    guest::write64(item + layout::CONTEXT, 0);
    guest::write64(item + layout::DEVICE_OBJECT, device);
    guest::write32(item + layout::TYPE, 0);
    guest::write32(item + layout::QUEUED, 0);
}

/// IoQueueWorkItem(Ex): a rotina Ex recebe (ioObject, context, ioWorkItem).
pub fn queue_work_item_ex(item: u64, routine: u64, queue_type: u32, context: u64, extended: bool) {
    let mut queue = QUEUE.lock();
    if queue.entries.iter().any(|&(queued, _)| queued == item) {
        return;
    }
    forget_kernel_routine(&mut queue, item);
    guest::write64(item + layout::FUNCTION, routine);
    guest::write64(item + layout::CONTEXT, context);
    guest::write32(item + layout::TYPE, queue_type | if extended { 0x8000_0000 } else { 0 });
    guest::write32(item + layout::QUEUED, 1);
    queue.entries.push((item, if extended { Kind::IoEx } else { Kind::Io }));
}

pub fn queue_work_item(item: u64, routine: u64, queue_type: u32, context: u64) {
    queue_work_item_ex(item, routine, queue_type, context, false);
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
        guest::write32(item + layout::QUEUED, 0);
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
            guest::write32(item + layout::QUEUED, 0);
        }
        let routine = guest::read64(item + layout::FUNCTION);
        let device = if kind == Kind::Ex { 0 } else { guest::read64(item + layout::DEVICE_OBJECT) };
        let context = guest::read64(item + layout::CONTEXT);
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
    guest::write64(item + layout::LIST_FLINK, 0);
    guest::write64(item + layout::LIST_BLINK, 0);
    guest::write64(item + layout::FUNCTION, routine);
    guest::write64(item + layout::CONTEXT, context);
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
