//! Io Work Items.
//!
//! IoAllocateWorkItem/IoQueueWorkItem/ExQueueWorkItem: o kernel drena a fila
//! em PASSIVE_LEVEL (o papel das worker threads do sistema) nos pumps de
//! quem espera. No NT cada item roda na sua worker thread, e uma worker que
//! espera não executa outros itens: aqui um item não começa enquanto outro
//! roda na mesma CPU (o pump de dentro de um item não drena a fila), e uma
//! drenagem só roda os itens que já estavam na fila quando ela começou (os
//! que um item enfileira ficam para a próxima). Assim quem espera pelo fim
//! de um item volta a conferir a espera antes de os itens enfileirados por
//! ele rodarem — um deles pode esperar pelo que essa thread retém (o
//! DeviceLock de uma montagem em curso, por exemplo).
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
    /// Ordem de chegada de cada item na fila.
    sequence: BTreeMap<u64, u64>,
    next_sequence: u64,
    kernel_routines: BTreeMap<u64, KernelWorkRoutine>,
    readiness: BTreeMap<u64, fn() -> bool>,
    /// O instante (ms desde o boot) da chegada de cada item.
    arrival: BTreeMap<u64, u64>,
}

static QUEUE: SpinLock<Queue> = SpinLock::new(Queue { entries: Vec::new(), sequence: BTreeMap::new(), next_sequence: 0, kernel_routines: BTreeMap::new(), readiness: BTreeMap::new(), arrival: BTreeMap::new() });
/// Os itens entregues a uma worker dinâmica: (item, tipo, rotina interna).
static HANDOFF: SpinLock<Vec<(u64, Kind, Option<KernelWorkRoutine>)>> = SpinLock::new(Vec::new());
/// Quanto um item espera, com a worker desta CPU bloqueada, até ganhar uma
/// worker dinâmica (o intervalo do ExpWorkerThreadBalanceManager).
const BALANCE_INTERVAL_MS: u64 = 1000;
/// As CPUs (pela KPCR) com um item em execução na pilha.
static RUNNING_ON: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// Entra na fila com a ordem de chegada.
fn push(queue: &mut Queue, item: u64, kind: Kind) {
    let sequence = queue.next_sequence;
    queue.next_sequence += 1;
    queue.sequence.insert(item, sequence);
    queue.arrival.insert(item, crate::ntos::ke::clock::uptime_ms());
    queue.entries.push((item, kind));
}

/// Um item roda na pilha desta CPU (o pump corrente está dentro dele).
pub fn nested() -> bool {
    let processor = crate::ntos::ke::pcr::current_address();
    RUNNING_ON.lock().contains(&processor)
}

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
    push(&mut queue, item, if extended { Kind::IoEx } else { Kind::Io });
}

/// IoQueueWorkItemToNode(IoWorkItem, WorkerRoutine, QueueType, Context,
/// NodeNumber) (RVA 0x506e00): o IoQueueWorkItemEx num nó NUMA. O
/// ExpQueueWorkItem troca um nó fora de KeNumberNodes pelo da CPU corrente
/// e só recusa (FALSE, com o IoObject desreferenciado) quando o pool de
/// workers do nó não está pronto; o OpenNT tem um nó, cuja fila sempre
/// aceita: o item entra como o do IoQueueWorkItemEx e o resultado é TRUE.
pub fn queue_work_item_to_node(item: u64, routine: u64, queue_type: u32, context: u64, _node: u32) -> bool {
    queue_work_item_ex(item, routine, queue_type, context, true);
    true
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
    push(&mut queue, item, Kind::Ex);
    queue.kernel_routines.insert(item, routine);
}

/// Cancela um item; a rotina e o predicado internos também são soltos.
pub fn unqueue(item: u64) {
    let mut queue = QUEUE.lock();
    let kind = queue.entries.iter().position(|&(queued, _)| queued == item).map(|index| queue.entries.remove(index).1);
    queue.sequence.remove(&item);
    queue.arrival.remove(&item);
    forget_kernel_routine(&mut queue, item);
    if kind != Some(Kind::Ex) {
        body_at(item).queued.set(0);
    }
}

/// Drena em PASSIVE_LEVEL os itens que já estavam na fila. Um item com
/// predicado de prontidão decide por ele; os demais não começam dentro de
/// outro item desta CPU.
pub fn run_queue() {
    let snapshot = QUEUE.lock().next_sequence;
    let processor = crate::ntos::ke::pcr::current_address();
    loop {
        let (item, kind, kernel_routine) = {
            let mut queue = QUEUE.lock();
            if queue.entries.is_empty() {
                return;
            }
            let readiness = queue.readiness.clone();
            let free = !RUNNING_ON.lock().contains(&processor);
            let sequence = &queue.sequence;
            let Some(index) = queue.entries.iter().position(|(item, _)| sequence.get(item).is_some_and(|&arrival| arrival < snapshot) && readiness.get(item).map_or(free, |ready| ready())) else {
                let stalled = if free { None } else { take_stalled(&mut queue, snapshot) };
                drop(queue);
                if let Some(stalled) = stalled {
                    start_dynamic_worker(stalled);
                }
                return;
            };
            let (item, kind) = queue.entries.remove(index);
            queue.sequence.remove(&item);
            queue.arrival.remove(&item);
            let routine = queue.kernel_routines.remove(&item);
            queue.readiness.remove(&item);
            (item, kind, routine)
        };
        let outermost = {
            let mut running = RUNNING_ON.lock();
            let outermost = !running.contains(&processor);
            if outermost {
                running.push(processor);
            }
            outermost
        };
        run_item(item, kind, kernel_routine);
        if outermost {
            RUNNING_ON.lock().retain(|&entry| entry != processor);
        }
    }
}

/// O ExpWorkerThreadBalanceManager: com a worker desta CPU bloqueada numa
/// espera dentro de um item, o item comum que já espera há um intervalo
/// inteiro ganha uma worker dinâmica (uma thread de sistema que o executa
/// e termina), como as threads que o NT cria quando as workers de uma fila
/// estão todas bloqueadas. Assim o item que a worker bloqueada espera (o
/// work item que outro driver enfileirou no caminho do pedido dela) anda
/// sem rodar aninhado na pilha dela.
fn take_stalled(queue: &mut Queue, snapshot: u64) -> Option<(u64, Kind, Option<KernelWorkRoutine>)> {
    if crate::ntos::ps::process::get_system_process() == 0 {
        return None;
    }
    let now = crate::ntos::ke::clock::uptime_ms();
    let (sequence, arrival, readiness) = (&queue.sequence, &queue.arrival, &queue.readiness);
    let index = queue.entries.iter().position(|(item, _)| sequence.get(item).is_some_and(|&order| order < snapshot) && !readiness.contains_key(item) && arrival.get(item).is_some_and(|&time| now.saturating_sub(time) >= BALANCE_INTERVAL_MS))?;
    let (item, kind) = queue.entries.remove(index);
    queue.sequence.remove(&item);
    queue.arrival.remove(&item);
    let routine = queue.kernel_routines.remove(&item);
    Some((item, kind, routine))
}

/// Cria a worker dinâmica do item (fora da trava da fila); sem a thread, o
/// item volta à fila.
fn start_dynamic_worker((item, kind, routine): (u64, Kind, Option<KernelWorkRoutine>)) {
    HANDOFF.lock().push((item, kind, routine));
    let entry: extern "win64" fn(u64) = dynamic_worker;
    let started = crate::ntos::mm::kernel_address::image_address(entry as usize as u64).ok().and_then(|start| crate::ntos::ps::kernel_threads::create_system_thread(0, start, item, 0x1F_FFFF, 0, None).ok());
    match started {
        Some(handle) => {
            let _ = crate::ntos::ob::object_manager::close(handle as u32);
        }
        None => {
            HANDOFF.lock().retain(|&(handed, _, _)| handed != item);
            let mut queue = QUEUE.lock();
            push(&mut queue, item, kind);
            if let Some(routine) = routine {
                queue.kernel_routines.insert(item, routine);
            }
        }
    }
}

/// A rotina da worker dinâmica: executa o item entregue e termina.
extern "win64" fn dynamic_worker(item: u64) {
    let handed = {
        let mut handoff = HANDOFF.lock();
        handoff.iter().position(|&(handed, _, _)| handed == item).map(|index| handoff.remove(index))
    };
    if let Some((item, kind, routine)) = handed {
        run_item(item, kind, routine);
    }
}

/// Executa um item retirado da fila.
fn run_item(item: u64, kind: Kind, kernel_routine: Option<KernelWorkRoutine>) {
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
    push(&mut queue, item, Kind::Ex);
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
