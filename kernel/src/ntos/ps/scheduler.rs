//! Despacho de contextos de kernel por prioridade — `system32/ntos/ps/scheduler.js`.
//!
//! No original um processo era uma função geradora: cada `yield` devolvia o
//! controle ao kernel. Em Rust o processo é um `Future`: cada
//! `yield_now().await` devolve `Pending` e o escalonador o retoma depois. O
//! valor do `yield` (espera com continuação de prontidão, manter o quantum)
//! é publicado pelo future como sinal de passo antes de devolver `Pending`.
//! Estados: ready -> running -> waiting/done/killed (recolhidos pelo kernel).
//!
//! Cada processo tem um EPROCESS + KTHREAD reais (`ps/process`); o tick
//! ajusta a thread corrente (o gs:[0x188] do NT) durante o passo de cada um
//! e a seleção segue as filas de prioridade do `ke/thread-dispatch`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use super::process;
use crate::ntos::ke::{clock, thread_dispatch};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

pub type ProcessFuture = Pin<Box<dyn Future<Output = u32> + Send>>;
/// Continuação de prontidão: consumida no contexto do dono; `true` = pronta.
pub type PrepareDispatch = Box<dyn FnMut() -> bool + Send>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
    Waiting,
    Done,
    Killed,
}

impl ProcessState {
    pub fn as_str(self) -> &'static str {
        match self {
            ProcessState::Ready => "ready",
            ProcessState::Running => "running",
            ProcessState::Waiting => "waiting",
            ProcessState::Done => "done",
            ProcessState::Killed => "killed",
        }
    }
}

struct Process {
    pid: u32,
    name: String,
    /// `None` enquanto o processo está sendo executado (fora do lock).
    future: Option<ProcessFuture>,
    state: ProcessState,
    exit_status: Option<u32>,
    process_pointer: u64,
    thread_pointer: u64,
    owns_process: bool,
    on_reap: Option<Box<dyn FnOnce() + Send>>,
    prepare_dispatch: Option<PrepareDispatch>,
}

struct SchedulerState {
    processes: Vec<Process>,
    next_pid: u32,
    system_thread: u64,
}

static STATE: SpinLock<SchedulerState> = SpinLock::new(SchedulerState { processes: Vec::new(), next_pid: 8, system_thread: 0 }); // 0-7 reservados (4 = System)

/// O valor do `yield` do passo corrente.
enum StepSignal {
    Waiting(PrepareDispatch),
    RetainQuantum,
}

static STEP: SpinLock<Option<StepSignal>> = SpinLock::new(None);

/// Resumo público de um processo (`Scheduler.list()`).
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub state: ProcessState,
    pub exit_status: Option<u32>,
    pub process_pointer: u64,
    pub thread_pointer: u64,
}

fn push(state: &mut SchedulerState, name: &str, future: ProcessFuture, process_pointer: u64, thread_pointer: u64, owns_process: bool, on_reap: Option<Box<dyn FnOnce() + Send>>) -> u32 {
    let pid = state.next_pid;
    state.next_pid += 1;
    state.processes.push(Process {
        pid,
        name: String::from(name),
        future: Some(future),
        state: ProcessState::Ready,
        exit_status: None,
        process_pointer,
        thread_pointer,
        owns_process,
        on_reap,
        prepare_dispatch: None,
    });
    pid
}

/// Cria um processo de kernel (EPROCESS + KTHREAD) e devolve o pid.
pub fn spawn(name: &str, body: impl Future<Output = u32> + Send + 'static) -> u32 {
    try_spawn(name, Box::pin(body)).unwrap_or_else(|error| panic!("spawn {name}: {error}"))
}

pub fn try_spawn(name: &str, future: ProcessFuture) -> Result<u32, KernelError> {
    let pid = STATE.lock().next_pid;
    let process_pointer = process::create_process(pid as u64, name, 0, None)?;
    let thread_pointer = process::create_kernel_thread(process_pointer, pid as u64 * 4, false, 0, None)?;
    let pid = push(&mut STATE.lock(), name, future, process_pointer, thread_pointer, true, None);
    process::describe_thread(thread_pointer, Some(pid), false);
    thread_dispatch::register(thread_pointer, pid as u64)?;
    Ok(pid)
}

/// Thread de kernel dentro de um processo existente (System para drivers,
/// como o NT): sem EPROCESS novo; o KTHREAD já foi criado pelo chamador.
pub fn spawn_into_process(name: &str, process_pointer: u64, thread_pointer: u64, future: ProcessFuture, on_reap: Option<Box<dyn FnOnce() + Send>>) -> Result<u32, KernelError> {
    process::add_thread(process_pointer);
    let pid = push(&mut STATE.lock(), name, future, process_pointer, thread_pointer, false, on_reap);
    process::describe_thread(thread_pointer, Some(pid), false);
    thread_dispatch::register(thread_pointer, pid as u64)?;
    Ok(pid)
}

pub fn kill(pid: u32, exit_status: u32) -> bool {
    let suspend = {
        let mut state = STATE.lock();
        let Some(process) = state.processes.iter_mut().find(|process| process.pid == pid) else {
            return false;
        };
        let mut suspend = None;
        if process.state != ProcessState::Killed && process.state != ProcessState::Done {
            if process.state != ProcessState::Running {
                suspend = Some(process.thread_pointer);
            }
            process.state = ProcessState::Killed;
            process.exit_status = Some(exit_status);
        }
        suspend
    };
    if let Some(thread) = suspend {
        let _ = thread_dispatch::suspend(thread, thread_dispatch::state::TERMINATED);
    }
    true
}

/// ZwTerminateProcess: marca no escalonador preservando o status. Devolve
/// o NTSTATUS (STATUS_INVALID_HANDLE para pid desconhecido).
pub fn terminate_by_handle(handle: u64, exit_status: u32) -> u32 {
    let pid = process::process_id_from_handle(handle);
    if kill(pid as u32, exit_status) { 0 } else { 0xC000_0008 }
}

/// Recolhe processos terminados. Descartar o `Future` encerra o processo
/// (o `gen.return()` do original).
fn reap() {
    loop {
        let finished = {
            let mut state = STATE.lock();
            // Um processo em execução (sem future) é recolhido depois.
            let index = state.processes.iter().rposition(|process| matches!(process.state, ProcessState::Done | ProcessState::Killed) && process.future.is_some());
            match index {
                Some(index) => state.processes.remove(index),
                None => return,
            }
        };
        if let Err(error) = finish(finished) {
            debug_print!("[sched] recolhimento falhou: {}", error);
        }
    }
}

fn finish(process: Process) -> Result<(), KernelError> {
    // Retira vínculos nativos antes de qualquer callback que destrua a ETHREAD.
    thread_dispatch::unregister(process.thread_pointer)?;
    process::describe_thread(process.thread_pointer, process::thread_record(process.thread_pointer).and_then(|record| record.runtime), true);
    // Os destrutores do future rodam fora do lock: podem chamar o escalonador.
    drop(process.future);
    if process.owns_process {
        let previous = process::get_current_thread();
        process::set_current_thread(process.thread_pointer);
        let result = process::terminate_process(process.process_pointer, process.exit_status.unwrap_or(0));
        process::set_current_thread(previous);
        result?;
        process::release_thread(process.thread_pointer)
    } else {
        process::remove_thread(process.process_pointer);
        match process.on_reap {
            Some(on_reap) => {
                on_reap();
                Ok(())
            }
            None => process::release_thread(process.thread_pointer),
        }
    }
}

/// Sondar uma espera não executa o contexto. A conclusão é consumida uma
/// vez, no contexto do dono, e só então a thread volta à fila.
fn refresh_waiting_threads() -> Result<(), KernelError> {
    let mut waiting: Vec<(u32, u64)> = STATE.lock().processes.iter().filter(|process| process.state == ProcessState::Waiting).map(|process| (process.pid, process.thread_pointer)).collect();
    waiting.sort_by_key(|&(_, thread)| core::cmp::Reverse(thread_dispatch::priority(thread)));
    for (pid, thread) in waiting {
        let prepare = STATE.lock().processes.iter_mut().find(|process| process.pid == pid && process.state == ProcessState::Waiting).map(|process| process.prepare_dispatch.take());
        let Some(prepare) = prepare else { continue };
        let Some(mut prepare) = prepare else {
            return Err(KernelError::new("waiting kernel thread has no readiness continuation"));
        };
        let previous = process::get_current_thread();
        process::set_current_thread(thread);
        let ready = prepare();
        process::set_current_thread(previous);
        let mut state = STATE.lock();
        let Some(process) = state.processes.iter_mut().find(|process| process.pid == pid) else { continue };
        if ready && process.state == ProcessState::Waiting {
            process.state = ProcessState::Ready;
            drop(state);
            thread_dispatch::make_ready(thread)?;
        } else {
            process.prepare_dispatch = Some(prepare);
        }
    }
    Ok(())
}

/// Um passo do contexto selecionado.
fn run_step(pid: u32, thread: u64) -> Result<(), KernelError> {
    let future = {
        let mut state = STATE.lock();
        let Some(process) = state.processes.iter_mut().find(|process| process.pid == pid) else {
            return Err(KernelError::new("ready thread has no scheduler context"));
        };
        process.state = ProcessState::Running;
        process.future.take()
    };
    let Some(mut future) = future else {
        return Err(KernelError::new("selected context is already running"));
    };
    let previous = process::get_current_thread();
    process::set_current_thread(thread);
    process::dispatch_thread(thread);
    thread_dispatch::begin_execution(thread)?;
    let started = clock::uptime_100ns();
    let saved_signal = STEP.lock().take();
    let mut context = Context::from_waker(Waker::noop());
    let step = future.as_mut().poll(&mut context);
    let signal = core::mem::replace(&mut *STEP.lock(), saved_signal);
    let new_state = {
        let mut state = STATE.lock();
        let Some(process) = state.processes.iter_mut().find(|process| process.pid == pid) else {
            return Err(KernelError::new("running context disappeared"));
        };
        process.future = Some(future);
        let mut retain = false;
        match step {
            Poll::Ready(exit_status) => {
                if process.state != ProcessState::Killed {
                    process.state = ProcessState::Done;
                    process.exit_status = Some(exit_status);
                }
            }
            Poll::Pending => {
                match signal {
                    Some(StepSignal::Waiting(prepare)) => {
                        process.prepare_dispatch = Some(prepare);
                        if process.state != ProcessState::Killed {
                            process.state = ProcessState::Waiting;
                        }
                    }
                    Some(StepSignal::RetainQuantum) => retain = true,
                    None => {}
                }
                if process.state == ProcessState::Running {
                    process.state = ProcessState::Ready;
                }
            }
        }
        let state_now = process.state;
        drop(state);
        if state_now == ProcessState::Ready && !retain {
            thread_dispatch::request_yield(thread)?;
        }
        match state_now {
            ProcessState::Ready => thread_dispatch::state::READY,
            ProcessState::Waiting => thread_dispatch::state::WAITING,
            _ => thread_dispatch::state::TERMINATED,
        }
    };
    process::account_thread(thread, true, clock::uptime_100ns() - started);
    let result = thread_dispatch::end_execution(thread, new_state);
    process::set_current_thread(previous);
    result
}

/// Um tick tem orçamento limitado de passos; cada seleção consulta as filas
/// vivas. Uma thread de prioridade menor não ganha CPU só porque a maior já
/// rodou neste tick.
pub fn tick(minimum_priority: i32) {
    reap();
    let budget = STATE.lock().processes.len();
    for _ in 0..budget {
        let selected = refresh_waiting_threads().and_then(|_| thread_dispatch::peek());
        let (thread, owner) = match selected {
            Ok(Some(selected)) => selected,
            Ok(None) => break,
            Err(error) => {
                debug_print!("[sched] seleção falhou: {}", error);
                break;
            }
        };
        if owner.runtime & thread_dispatch::USER_RUNTIME != 0 || thread_dispatch::priority(thread) as i32 <= minimum_priority {
            break;
        }
        let pid = owner.runtime as u32;
        if let Err(error) = run_step(pid, thread) {
            debug_print!("[sched] processo {} morreu: {}", pid, error);
            let mut state = STATE.lock();
            if let Some(process) = state.processes.iter_mut().find(|process| process.pid == pid) {
                if process.state != ProcessState::Killed {
                    process.state = ProcessState::Done;
                    process.exit_status = Some(if error.status != 0 { error.status } else { 0xC000_0001 });
                }
            }
        }
    }
    reap();
}

/// No contexto síncrono de boot, o próprio chamador aguarda as concorrentes
/// mais prioritárias quando uma prioridade muda.
fn priority_changed() {
    let caller = process::get_current_thread();
    if caller == 0 || thread_dispatch::owner(caller).is_some() {
        return;
    }
    let caller_priority = thread_dispatch::priority(caller);
    loop {
        match thread_dispatch::peek() {
            Ok(Some((selected, owner))) if owner.runtime & thread_dispatch::USER_RUNTIME == 0 && thread_dispatch::priority(selected) > caller_priority => tick(caller_priority as i32),
            _ => return,
        }
    }
}

pub fn init() -> Result<(), KernelError> {
    process::init()?;
    // A "thread do System" (contexto de boot/drivers): gs:[0x188] inicial.
    let system_thread = process::create_kernel_thread(process::get_system_process(), 4, false, 0, None)?;
    process::set_current_thread(system_thread);
    STATE.lock().system_thread = system_thread;
    // O contexto de boot está executando; não representa o processo Idle.
    thread_dispatch::initialize_queues();
    thread_dispatch::begin_execution(system_thread)?;
    thread_dispatch::register_priority_change_observer(priority_changed)
}

pub fn system_thread() -> u64 {
    STATE.lock().system_thread
}

pub fn list() -> Vec<ProcessInfo> {
    STATE
        .lock()
        .processes
        .iter()
        .map(|process| ProcessInfo {
            pid: process.pid,
            name: process.name.clone(),
            state: process.state,
            exit_status: process.exit_status,
            process_pointer: process.process_pointer,
            thread_pointer: process.thread_pointer,
        })
        .collect()
}

pub fn count() -> usize {
    STATE.lock().processes.len()
}

/// Pid do processo da thread corrente (KTHREAD.Cid.UniqueProcess).
pub fn current_pid() -> u32 {
    let thread = process::get_current_thread();
    if thread == 0 {
        return 0;
    }
    guest::read64(thread + kthread::CID_UNIQUE_PROCESS) as u32
}

/// Devolve o controle ao escalonador uma vez — o `yield` dos geradores.
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false, signal: None }
}

/// `yield { retainQuantum: true }`: devolve o controle sem pedir troca.
pub fn yield_retaining_quantum() -> YieldNow {
    YieldNow { yielded: false, signal: Some(StepSignalKind::RetainQuantum) }
}

/// `yield { waiting: true, prepareDispatch }`: a thread espera até que a
/// continuação, sondada pelo escalonador no contexto do dono, a libere.
pub fn wait_until(prepare: impl FnMut() -> bool + Send + 'static) -> YieldNow {
    YieldNow { yielded: false, signal: Some(StepSignalKind::Waiting(Box::new(prepare))) }
}

enum StepSignalKind {
    RetainQuantum,
    Waiting(PrepareDispatch),
}

pub struct YieldNow {
    yielded: bool,
    signal: Option<StepSignalKind>,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        *STEP.lock() = match self.signal.take() {
            Some(StepSignalKind::RetainQuantum) => Some(StepSignal::RetainQuantum),
            Some(StepSignalKind::Waiting(prepare)) => Some(StepSignal::Waiting(prepare)),
            None => None,
        };
        Poll::Pending
    }
}
