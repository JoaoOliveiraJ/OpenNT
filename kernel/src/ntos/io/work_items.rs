//! Io Work Items e as worker threads do sistema.
//!
//! IoAllocateWorkItem/IoQueueWorkItem/ExQueueWorkItem põem o item na fila do
//! sistema, e as worker threads (o ExpWorkerThread do NT) o executam em
//! PASSIVE_LEVEL, cada item na pilha de uma delas. O ExpWorkerInitialization
//! da fase 1 ([`initialize_workers`], chamado logo depois dos exports, como
//! o ExInitSystem antes do IoInitSystem) cria as workers mínimas no
//! processo System; antes disso a fila só guarda os itens, como no NT, e
//! eles rodam quando as workers nascem. Uma worker sem item espera o evento
//! da fila (de sincronização); o item que entra acorda uma, e a worker que
//! tira um item com outros prontos atrás acorda a seguinte. Cada item roda na
//! prioridade do seu tipo de fila (o ExpTypeToPriority do ntoskrnl 19041 e a
//! tabela ExpBuiltinPriorities: Critical 13, Delayed 12, HyperCritical 15,
//! Normal 8, Background 7, RealTime 18, SuperCritical 14; um QueueType de 32
//! em diante é a prioridade QueueType - 32).
//!
//! Uma worker que espera dentro de um item não roda outro. Como o
//! gerenciador das filas do NT (ExpWorkQueueManagerThread), quando nenhuma
//! worker está livre e o item pronto mais antigo espera há um intervalo
//! inteiro, o pool ganha mais uma worker, no máximo uma por intervalo
//! ([`balance`], que os pumps do despachante chamam): o item que uma worker
//! bloqueada espera anda sem rodar aninhado na pilha dela, e um item que
//! espera para sempre (o FsRtlWaitForSmssEvent sem smss, o WorkerThread do
//! mountmgr.sys à espera do `\Device\VolumesSafeForWriteAccess`) só prende a
//! própria worker.
//!
//! Nenhum item roda no contexto de boot nem na pilha de quem espera.
//! [`run_queue`] não executa nada: espera que os itens já enfileirados
//! terminem ou que as workers deles parem numa espera (KTHREAD.State
//! Waiting).
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
use crate::ntos::inc::types::{Kevent, NtStruct, WorkQueueItem};
use crate::ntos::ke::{context_switch, dispatcher, irql, thread_dispatch, thread_priority};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::{kernel_threads, process};
use crate::rtl::{KernelError, SpinLock};

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

/// DelayedWorkQueue.
const DELAYED_WORK_QUEUE: u32 = 1;
/// SynchronizationEvent.
const SYNCHRONIZATION_EVENT: u8 = 1;
/// As workers que o ExpWorkerInitialization cria.
const MINIMUM_WORKER_THREADS: usize = 4;
/// O teto do pool (o gerenciador não passa dele).
const MAXIMUM_WORKER_THREADS: usize = 64;
/// O intervalo do gerenciador das filas: quanto o item pronto mais antigo
/// espera, sem worker livre, até o pool ganhar uma worker, e o mínimo entre
/// duas criações.
pub const BALANCE_INTERVAL_MS: u64 = 1000;

/// Um item em execução numa worker: a thread e a ordem de chegada dele.
struct Running {
    thread: u64,
    sequence: u64,
}

struct Queue {
    entries: Vec<(u64, Kind)>,
    /// Ordem de chegada de cada item na fila.
    sequence: BTreeMap<u64, u64>,
    next_sequence: u64,
    kernel_routines: BTreeMap<u64, KernelWorkRoutine>,
    readiness: BTreeMap<u64, fn() -> bool>,
    /// O instante (ms desde o boot) da chegada de cada item.
    arrival: BTreeMap<u64, u64>,
    /// O QueueType de cada item (a prioridade da worker que o roda).
    queue_types: BTreeMap<u64, u32>,
    /// Os itens que as workers executam agora.
    running: Vec<Running>,
    /// As ETHREAD das workers.
    workers: Vec<u64>,
    /// Workers sem item (a esperar o evento ou ainda por começar).
    available: usize,
    /// O KEVENT de sincronização que acorda as workers (0 antes do
    /// ExpWorkerInitialization).
    wake: u64,
    /// O instante da última worker criada pelo gerenciador.
    last_growth: u64,
}

static QUEUE: SpinLock<Queue> = SpinLock::new(Queue {
    entries: Vec::new(),
    sequence: BTreeMap::new(),
    next_sequence: 0,
    kernel_routines: BTreeMap::new(),
    readiness: BTreeMap::new(),
    arrival: BTreeMap::new(),
    queue_types: BTreeMap::new(),
    running: Vec::new(),
    workers: Vec::new(),
    available: 0,
    wake: 0,
    last_growth: 0,
});

/// O item pode começar agora (o predicado de prontidão, se houver).
fn ready(queue: &Queue, item: u64) -> bool {
    queue.readiness.get(&item).is_none_or(|ready| ready())
}

/// Entra na fila com a ordem de chegada, o tipo de fila e a rotina interna.
/// Devolve o evento das workers a sinalizar (fora da trava).
fn enqueue(queue: &mut Queue, item: u64, kind: Kind, queue_type: u32, routine: Option<KernelWorkRoutine>, ready: Option<fn() -> bool>) -> u64 {
    let sequence = queue.next_sequence;
    queue.next_sequence += 1;
    queue.sequence.insert(item, sequence);
    queue.arrival.insert(item, crate::ntos::ke::clock::uptime_ms());
    queue.queue_types.insert(item, queue_type);
    match routine {
        Some(routine) => queue.kernel_routines.insert(item, routine),
        None => queue.kernel_routines.remove(&item),
    };
    match ready {
        Some(ready) => queue.readiness.insert(item, ready),
        None => queue.readiness.remove(&item),
    };
    queue.entries.push((item, kind));
    queue.wake
}

/// Acorda uma worker (o evento de sincronização entrega o sinal a uma só).
fn signal(wake: u64) {
    if wake != 0 {
        dispatcher::set_event(wake);
    }
}

fn is_queued(queue: &Queue, item: u64) -> bool {
    queue.entries.iter().any(|&(queued, _)| queued == item)
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

/// O IO_WORKITEM na fila: rotina, contexto e tipo gravados no corpo.
fn queue_io_item(item: u64, routine: u64, queue_type: u32, context: u64, extended: bool, kernel_routine: Option<KernelWorkRoutine>, ready: Option<fn() -> bool>) {
    let wake = {
        let mut queue = QUEUE.lock();
        if is_queued(&queue, item) {
            return;
        }
        let body = body_at(item);
        body.work_item.worker_routine.set(routine);
        body.work_item.parameter.set(context);
        body.kind.set(queue_type | if extended { 0x8000_0000 } else { 0 });
        body.queued.set(1);
        enqueue(&mut queue, item, if extended { Kind::IoEx } else { Kind::Io }, queue_type, kernel_routine, ready)
    };
    signal(wake);
}

/// IoQueueWorkItem(Ex): a rotina Ex recebe (ioObject, context, ioWorkItem).
pub fn queue_work_item_ex(item: u64, routine: u64, queue_type: u32, context: u64, extended: bool) {
    queue_io_item(item, routine, queue_type, context, extended, None, None);
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

/// Variante interna: rotina do kernel em vez de código de driver, na
/// DelayedWorkQueue; `ready` adia o item até o predicado valer.
pub fn queue_kernel_work_item(item: u64, routine: KernelWorkRoutine, context: u64, ready: Option<fn() -> bool>) {
    queue_io_item(item, 0, DELAYED_WORK_QUEUE, context, false, Some(routine), ready);
}

/// Variante interna do ExQueueWorkItem: um WORK_QUEUE_ITEM do kernel
/// (embutido num bloco próprio) cuja rotina é Rust e recebe o Parameter.
pub fn queue_kernel_ex_work_item(item: u64, routine: KernelWorkRoutine, parameter: u64) {
    let wake = {
        let mut queue = QUEUE.lock();
        if is_queued(&queue, item) {
            return;
        }
        let queue_item = queue_item_at(item);
        queue_item.list.flink.set(0);
        queue_item.list.blink.set(0);
        queue_item.worker_routine.set(0);
        queue_item.parameter.set(parameter);
        enqueue(&mut queue, item, Kind::Ex, DELAYED_WORK_QUEUE, Some(routine), None)
    };
    signal(wake);
}

/// Cancela um item; a rotina e o predicado internos também são soltos.
pub fn unqueue(item: u64) {
    let mut queue = QUEUE.lock();
    let kind = queue.entries.iter().position(|&(queued, _)| queued == item).map(|index| queue.entries.remove(index).1);
    queue.sequence.remove(&item);
    queue.arrival.remove(&item);
    queue.queue_types.remove(&item);
    forget_kernel_routine(&mut queue, item);
    if kind != Some(Kind::Ex) {
        body_at(item).queued.set(0);
    }
}

/// Um item retirado da fila por uma worker.
struct Job {
    item: u64,
    kind: Kind,
    routine: Option<KernelWorkRoutine>,
    queue_type: u32,
}

/// A worker `thread` tira o primeiro item pronto (na ordem de chegada) e
/// deixa de estar livre.
fn take(queue: &mut Queue, thread: u64) -> Option<Job> {
    let index = queue.entries.iter().position(|&(item, _)| ready(queue, item))?;
    let (item, kind) = queue.entries.remove(index);
    let sequence = queue.sequence.remove(&item).unwrap_or(0);
    queue.arrival.remove(&item);
    queue.readiness.remove(&item);
    let routine = queue.kernel_routines.remove(&item);
    let queue_type = queue.queue_types.remove(&item).unwrap_or(DELAYED_WORK_QUEUE);
    queue.running.push(Running { thread, sequence });
    queue.available = queue.available.saturating_sub(1);
    Some(Job { item, kind, routine, queue_type })
}

/// ExpTypeToPriority: a prioridade da worker para o tipo de fila.
pub fn queue_type_priority(queue_type: u32) -> i32 {
    const BUILTIN: [i32; 7] = [13, 12, 15, 8, 7, 18, 14];
    match BUILTIN.get(queue_type as usize) {
        Some(&priority) => priority,
        None => queue_type as i32 - 0x20,
    }
}

/// O ExpWorkerThread: tira itens da fila e os executa na própria pilha, na
/// prioridade do tipo de fila; sem item pronto, espera o evento das workers.
extern "win64" fn worker_thread(_context: u64) {
    let thread = process::get_current_thread();
    loop {
        let (job, wake, more) = {
            let mut queue = QUEUE.lock();
            let job = take(&mut queue, thread);
            let more = job.is_some() && queue.available > 0 && queue.entries.iter().any(|&(item, _)| ready(&queue, item));
            (job, queue.wake, more)
        };
        let Some(job) = job else {
            dispatcher::wait_for_single_object(wake, 0, 0, false);
            continue;
        };
        if more {
            signal(wake);
        }
        let priority = queue_type_priority(job.queue_type);
        if (0..32).contains(&priority) && thread_priority::query_priority(thread) != priority {
            let _ = thread_priority::set_priority(thread, priority as u64);
        }
        run_item(job.item, job.kind, job.routine);
        let mut queue = QUEUE.lock();
        queue.running.retain(|running| running.thread != thread);
        queue.available += 1;
    }
}

/// Cria uma worker no processo System. A vaga conta como livre desde já: a
/// thread nova pode rodar antes de esta função voltar.
fn create_worker() -> Result<(), KernelError> {
    QUEUE.lock().available += 1;
    let entry: extern "win64" fn(u64) = worker_thread;
    let created = crate::ntos::mm::kernel_address::image_address(entry as usize as u64).and_then(|start| kernel_threads::create_system_thread(0, start, 0, 0x1F_FFFF, 0, None));
    match created {
        Ok(handle) => {
            let thread = kernel_threads::of_handle(handle).unwrap_or(0);
            let _ = crate::ntos::ob::object_manager::close(handle as u32);
            QUEUE.lock().workers.push(thread);
            Ok(())
        }
        Err(error) => {
            let mut queue = QUEUE.lock();
            queue.available = queue.available.saturating_sub(1);
            Err(error)
        }
    }
}

/// ExpWorkerInitialization: o evento das workers e as workers mínimas. Os
/// itens enfileirados antes delas rodam agora.
pub fn initialize_workers() -> Result<(), KernelError> {
    if QUEUE.lock().wake != 0 {
        return Ok(());
    }
    let wake = guest::alloc_bytes(Kevent::SIZE);
    if wake == 0 {
        return Err(KernelError::new("evento das worker threads"));
    }
    dispatcher::initialize_event(wake, SYNCHRONIZATION_EVENT, false);
    QUEUE.lock().wake = wake;
    for _ in 0..MINIMUM_WORKER_THREADS {
        create_worker()?;
    }
    signal(wake);
    Ok(())
}

/// As workers do pool e quantas estão sem item.
pub fn worker_counts() -> (usize, usize) {
    let queue = QUEUE.lock();
    (queue.workers.len(), queue.available)
}

/// A worker `thread` é uma worker thread do sistema.
pub fn is_worker_thread(thread: u64) -> bool {
    thread != 0 && QUEUE.lock().workers.contains(&thread)
}

/// O gerenciador das filas, nos pumps do despachante: um item pronto com
/// worker livre a acorda; sem worker livre, o item pronto mais antigo que
/// espera há um intervalo inteiro dá ao pool mais uma worker (no máximo uma
/// por intervalo, até o teto).
pub fn balance() {
    let now = crate::ntos::ke::clock::uptime_ms();
    let (wake, grow) = {
        let mut queue = QUEUE.lock();
        if queue.wake == 0 {
            return;
        }
        let oldest = queue.entries.iter().filter(|&&(item, _)| ready(&queue, item)).filter_map(|(item, _)| queue.arrival.get(item).copied()).min();
        let Some(oldest) = oldest else { return };
        let grow = queue.available == 0 && now.saturating_sub(oldest) >= BALANCE_INTERVAL_MS && now.saturating_sub(queue.last_growth) >= BALANCE_INTERVAL_MS && queue.workers.len() < MAXIMUM_WORKER_THREADS;
        if grow {
            queue.last_growth = now;
        }
        ((queue.available > 0).then_some(queue.wake), grow)
    };
    if let Some(wake) = wake {
        signal(wake);
    }
    if grow {
        if let Err(error) = create_worker() {
            debug_print!("[work] worker nova nao criada: {}", error);
        }
    }
}

/// Ainda há trabalho dos itens anteriores a `snapshot`: um pronto na fila,
/// ou um em execução numa worker (outra que não `current`) que não está
/// parada numa espera.
fn queued_work_pending(snapshot: u64, current: u64) -> bool {
    let queue = QUEUE.lock();
    let queued = queue.entries.iter().any(|&(item, _)| queue.sequence.get(&item).is_some_and(|&order| order < snapshot) && ready(&queue, item));
    queued || queue.running.iter().any(|running| running.sequence < snapshot && running.thread != current && thread_dispatch::thread_state(running.thread) != thread_dispatch::state::WAITING)
}

/// Espera, sem executar nada, que os itens já enfileirados terminem ou que
/// as workers deles parem numa espera: uma thread sai das prontas com a
/// condição sondada pelo despachante, o contexto de boot gira o despachante.
/// Antes das workers (a fila só guarda) e onde não se pode esperar, volta.
pub fn run_queue() {
    if QUEUE.lock().wake == 0 || irql::get_irql() >= irql::DISPATCH_LEVEL || (context_switch::in_kernel_thread() && !context_switch::kernel_thread_can_block()) {
        return;
    }
    let snapshot = QUEUE.lock().next_sequence;
    let current = process::get_current_thread();
    let mut poll = || (!queued_work_pending(snapshot, current)).then_some(0);
    let _ = context_switch::wait_until(&mut poll, dispatcher::pump_kernel);
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
pub fn queue_ex_work_item(item: u64, queue_type: u32) {
    let wake = {
        let mut queue = QUEUE.lock();
        if is_queued(&queue, item) {
            return;
        }
        enqueue(&mut queue, item, Kind::Ex, queue_type, None, None)
    };
    signal(wake);
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
/// devolvendo TRUE. A fila do OpenNT sempre aceita (o ExpIsPoolReadyForWork
/// nunca recusa: antes das workers ela guarda o item).
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
    let queued = is_queued(&QUEUE.lock(), item);
    let body = body_at(item);
    if queued || body.work_item.list.flink.get() != 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(0xE4, 2, item, body.device_object.address(), 0);
    }
    forget_kernel_routine(&mut QUEUE.lock(), item);
}
