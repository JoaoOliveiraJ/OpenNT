//! Despacho das threads de kernel por prioridade.
//!
//! Cada entrada do escalonador é uma thread de kernel com EPROCESS/KTHREAD
//! reais (`ps/process`) e pilha de kernel própria: um processo de kernel
//! ([`spawn`], um `Future` sondado na pilha da própria thread, que devolve
//! a CPU a cada `yield_now().await`) ou uma thread de outro processo
//! ([`spawn_into_process`], com o corpo dado: as threads de sistema dos
//! drivers e as requisições do kernel no System). O tick ([`tick`]) roda no
//! despachante da CPU — o contexto de boot, nunca a pilha de uma thread de
//! kernel —, escolhe pelas filas de prioridade do `ke/thread_dispatch` e
//! entra na thread por uma troca de contexto (`context_switch::resume`): ela
//! roda até ceder a vez, esperar ou terminar, e devolve a CPU por outra
//! troca. Uma espera tira a thread das prontas: a de um objeto do
//! despachante ou de uma fila (`ke::wait`) até o sinal aprontá-la, e a de
//! uma condição sondada ([`block_polled`], [`wait_until`]) até o despachante
//! achar a condição satisfeita. Estados: ready -> running -> waiting/done
//! (recolhidos pelo kernel).
//!
//! As threads de usuário estão nas mesmas filas: quando a mais prioritária
//! é uma delas, o tick dá intervalos pelo despachante de todos os processos
//! (`ps::user::threads::dispatch_one`), de qualquer processo, até
//! [`USER_SLICES_PER_TICK`] — se a CPU pode despachar usuário (o BSP, em
//! PASSIVE_LEVEL, sem trava retida, fora de outro despacho). Assim os
//! processos de usuário andam mesmo sem ninguém esperá-los, e o timer, que
//! encerra o intervalo de quem não cede a CPU, alterna entre eles.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use super::{cid, process};
use super::user::threads::{self as user_threads, Dispatched};
use crate::ntos::ke::context_switch::{self, SwitchReason};
use crate::ntos::ke::{clock, thread_dispatch, wait};
use crate::ntos::mm::kernel_stack;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Ethread;

pub type ProcessFuture = Pin<Box<dyn Future<Output = u32> + Send>>;
/// Continuação de prontidão: consumida no contexto do dono; `true` = pronta.
pub type PrepareDispatch = Box<dyn FnMut() -> bool + Send>;
/// O corpo de uma thread de kernel: roda na pilha dela e devolve o status
/// de saída.
pub type ThreadBody = Box<dyn FnOnce() -> u32 + Send>;

/// STATUS_UNSUCCESSFUL: o status de uma thread sem corpo.
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

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
    /// O corpo, até a thread começar (ela o leva para a própria pilha).
    body: Option<ThreadBody>,
    state: ProcessState,
    exit_status: Option<u32>,
    process_pointer: u64,
    thread_pointer: u64,
    owns_process: bool,
    on_reap: Option<Box<dyn FnOnce() + Send>>,
    prepare_dispatch: Option<PrepareDispatch>,
    /// Terminação pedida (`kill`): a thread sai no próximo ponto de cessão.
    kill_requested: bool,
    /// A thread fez a última troca: a pilha já pode ser recolhida.
    exited: bool,
}

struct SchedulerState {
    processes: Vec<Process>,
    next_pid: u32,
    system_thread: u64,
}

static STATE: SpinLock<SchedulerState> = SpinLock::new(SchedulerState { processes: Vec::new(), next_pid: 8, system_thread: 0 }); // 0-7 reservados (4 = System)

/// Resumo público de um processo (`list()`).
#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub state: ProcessState,
    pub exit_status: Option<u32>,
    pub process_pointer: u64,
    pub thread_pointer: u64,
}

fn push(state: &mut SchedulerState, name: &str, make_body: impl FnOnce(u32) -> ThreadBody, process_pointer: u64, thread_pointer: u64, owns_process: bool, on_reap: Option<Box<dyn FnOnce() + Send>>) -> u32 {
    let pid = state.next_pid;
    state.next_pid += 1;
    state.processes.push(Process {
        pid,
        name: String::from(name),
        body: Some(make_body(pid)),
        state: ProcessState::Ready,
        exit_status: None,
        process_pointer,
        thread_pointer,
        owns_process,
        on_reap,
        prepare_dispatch: None,
        kill_requested: false,
        exited: false,
    });
    pid
}

/// A entrada de toda thread do escalonador, na pilha dela: leva o corpo
/// para a pilha, roda e sai pela última troca.
extern "C" fn thread_entry(pid: u64) -> ! {
    context_switch::begin_kernel_thread();
    let pid = pid as u32;
    let body = STATE.lock().processes.iter_mut().find(|process| process.pid == pid).and_then(|process| process.body.take());
    let status = match body {
        Some(body) => body(),
        None => STATUS_UNSUCCESSFUL,
    };
    exit_current_thread(status)
}

/// A thread do escalonador corrente termina com `status`: a última troca,
/// de onde quer que ela esteja (o PsTerminateSystemThread sai de dentro do
/// serviço). O despachante recolhe a pilha depois, fora dela.
pub fn exit_current_thread(status: u32) -> ! {
    let thread = context_switch::on_kernel_thread_stack().expect("fim de thread do escalonador fora da pilha dela");
    let pid = thread_dispatch::owner(thread).map(|owner| owner.runtime as u32);
    {
        let mut state = STATE.lock();
        if let Some(process) = state.processes.iter_mut().find(|process| Some(process.pid) == pid) {
            if !process.kill_requested || process.exit_status.is_none() {
                process.exit_status = Some(status);
            }
            process.exited = true;
        }
    }
    context_switch::exit_kernel_thread()
}

fn kill_requested(pid: u32) -> bool {
    STATE.lock().processes.iter().any(|process| process.pid == pid && process.kill_requested)
}

/// O corpo de um processo de kernel: sonda o `Future` na pilha da thread; a
/// cada `Pending` (um `yield_now().await`) a thread cede a vez e volta a
/// sondar quando retomada. Uma terminação pedida descarta o `Future` no
/// ponto de cessão seguinte, na própria pilha.
fn future_body(pid: u32, mut future: ProcessFuture) -> u32 {
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if kill_requested(pid) {
            return 0;
        }
        if let Poll::Ready(status) = future.as_mut().poll(&mut context) {
            return status;
        }
        context_switch::yield_kernel_thread(false);
    }
}

/// Cria um processo de kernel (EPROCESS + KTHREAD) e devolve o pid.
pub fn spawn(name: &str, body: impl Future<Output = u32> + Send + 'static) -> u32 {
    try_spawn(name, Box::pin(body)).unwrap_or_else(|error| panic!("spawn {name}: {error}"))
}

pub fn try_spawn(name: &str, future: ProcessFuture) -> Result<u32, KernelError> {
    // PID e TID do EPROCESS/KTHREAD vêm da tabela de ids de cliente; o pid
    // do escalonador é outra numeração.
    let process_pointer = process::create_process(cid::ALLOCATE, name, 0, None)?;
    let stack = kernel_stack::create_for_kernel_thread()?;
    let thread_pointer = process::create_kernel_thread(process_pointer, cid::ALLOCATE, false, 0, Some(stack))?;
    let pid = push(&mut STATE.lock(), name, move |pid| Box::new(move || future_body(pid, future)), process_pointer, thread_pointer, true, None);
    start(pid, thread_pointer)?;
    Ok(pid)
}

/// Thread de kernel dentro de um processo existente (System para drivers,
/// como o NT): sem EPROCESS novo; o KTHREAD, com pilha própria, já foi
/// criado pelo chamador. `body` roda na pilha dele.
pub fn spawn_into_process(name: &str, process_pointer: u64, thread_pointer: u64, body: ThreadBody, on_reap: Option<Box<dyn FnOnce() + Send>>) -> Result<u32, KernelError> {
    process::add_thread(process_pointer);
    let pid = push(&mut STATE.lock(), name, move |_| body, process_pointer, thread_pointer, false, on_reap);
    start(pid, thread_pointer)?;
    Ok(pid)
}

/// O quadro inicial na pilha da thread e a entrada nas filas.
fn start(pid: u32, thread_pointer: u64) -> Result<(), KernelError> {
    process::describe_thread(thread_pointer, Some(pid), false);
    context_switch::initialize_kernel_thread(thread_pointer, thread_entry, pid as u64);
    thread_dispatch::register(thread_pointer, pid as u64)
}

/// Pede a terminação de um processo de kernel: a thread sai no próximo
/// ponto de cessão do corpo dela (um processo de kernel descarta o `Future`
/// ali), com `exit_status`. Uma thread parada numa espera sai quando ela
/// conclui, como uma thread de sistema do NT, que só termina por si.
pub fn kill(pid: u32, exit_status: u32) -> bool {
    let mut state = STATE.lock();
    let Some(process) = state.processes.iter_mut().find(|process| process.pid == pid) else {
        return false;
    };
    if !process.exited && !process.kill_requested {
        process.kill_requested = true;
        process.exit_status = Some(exit_status);
    }
    true
}

/// ZwTerminateProcess: marca no escalonador preservando o status. Devolve
/// o NTSTATUS (STATUS_INVALID_HANDLE para pid desconhecido).
pub fn terminate_by_handle(handle: u64, exit_status: u32) -> u32 {
    let pid = process::process_id_from_handle(handle);
    if kill(pid as u32, exit_status) { 0 } else { 0xC000_0008 }
}

/// Recolhe as threads que fizeram a última troca: a pilha delas já não está
/// em uso.
fn reap() {
    loop {
        let finished = {
            let mut state = STATE.lock();
            let index = state.processes.iter().rposition(|process| process.exited);
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
    // Um corpo que nunca rodou é descartado fora do lock.
    drop(process.body);
    if process.owns_process {
        let previous = process::get_current_thread();
        process::set_current_thread(process.thread_pointer);
        let result = process::terminate_process(process.process_pointer, process.exit_status.unwrap_or(0));
        process::set_current_thread(previous);
        result?;
        // O ceifador: a pilha própria volta ao Mm, fora dela.
        process::release_kernel_stack(process.thread_pointer);
        process::release_thread(process.thread_pointer)
    } else {
        process::remove_thread(process.process_pointer);
        match process.on_reap {
            Some(on_reap) => {
                on_reap();
                Ok(())
            }
            None => {
                process::release_kernel_stack(process.thread_pointer);
                process::release_thread(process.thread_pointer)
            }
        }
    }
}

/// Sondar uma espera não executa o contexto. A conclusão é consumida uma
/// vez, no contexto do dono, e só então a thread volta à fila.
fn refresh_waiting_threads() -> Result<(), KernelError> {
    let mut waiting: Vec<(u32, u64)> = STATE.lock().processes.iter().filter(|process| process.state == ProcessState::Waiting && process.prepare_dispatch.is_some()).map(|process| (process.pid, process.thread_pointer)).collect();
    waiting.sort_by_key(|&(_, thread)| core::cmp::Reverse(thread_dispatch::priority(thread)));
    for (pid, thread) in waiting {
        let prepare = STATE.lock().processes.iter_mut().find(|process| process.pid == pid && process.state == ProcessState::Waiting).and_then(|process| process.prepare_dispatch.take());
        let Some(mut prepare) = prepare else { continue };
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

/// A sondagem de uma thread de kernel parada, emprestada ao despachante:
/// vive na pilha da thread, que só volta a executar depois que o despachante
/// a consome.
struct BorrowedPoll {
    poll: *mut (dyn FnMut() -> Option<u32> + 'static),
    result: *const Cell<Option<u32>>,
}

// SAFETY: a sondagem só é chamada pelo despachante, na CPU da thread parada,
// enquanto ela não executa.
unsafe impl Send for BorrowedPoll {}

impl BorrowedPoll {
    fn call(&mut self) -> bool {
        // SAFETY: o quadro da thread parada continua vivo até ela ser
        // retomada, e a continuação é descartada antes disso.
        unsafe {
            match (*self.poll)() {
                Some(status) => {
                    (*self.result).set(Some(status));
                    true
                }
                None => false,
            }
        }
    }
}

/// A thread de kernel corrente sai das prontas até `poll` concluir, e
/// devolve o status: o despachante sonda a condição no contexto dela a cada
/// passo, sem a thread gastar CPU. Para as esperas sem objeto do despachante
/// a sinalizar (as que são de um objeto ou de uma fila passam por `ke::wait`,
/// prontas pelo sinal).
pub fn block_polled(poll: &mut dyn FnMut() -> Option<u32>) -> u32 {
    let thread = context_switch::on_kernel_thread_stack().expect("espera sondada fora de uma thread de kernel");
    let pid = thread_dispatch::owner(thread).map(|owner| owner.runtime as u32).expect("thread de kernel sem dono no escalonador");
    let raw: *mut (dyn FnMut() -> Option<u32> + '_) = poll;
    // SAFETY: só o tempo de vida do objeto muda; a continuação que guarda o
    // ponteiro é consumida antes de este quadro voltar a rodar.
    let raw: *mut (dyn FnMut() -> Option<u32> + 'static) = unsafe { core::mem::transmute(raw) };
    let result = Cell::new(None);
    loop {
        let mut borrowed = BorrowedPoll { poll: raw, result: &result };
        if let Some(process) = STATE.lock().processes.iter_mut().find(|process| process.pid == pid) {
            process.prepare_dispatch = Some(Box::new(move || borrowed.call()));
        }
        context_switch::switch_out(SwitchReason::Wait);
        if let Some(status) = result.get() {
            return status;
        }
        // SAFETY: a sondagem é da própria thread, que voltou a executar.
        if let Some(status) = unsafe { (*raw)() } {
            return status;
        }
    }
}

/// Um passo da thread selecionada: a troca de contexto para ela, até ela
/// devolver a CPU.
fn run_step(pid: u32, thread: u64) -> Result<(), KernelError> {
    {
        let mut state = STATE.lock();
        let Some(process) = state.processes.iter_mut().find(|process| process.pid == pid) else {
            return Err(KernelError::new("ready thread has no scheduler context"));
        };
        if process.exited || process.state == ProcessState::Running {
            return Err(KernelError::new("selected context is already running"));
        }
        process.state = ProcessState::Running;
    }
    let previous = process::get_current_thread();
    process::set_current_thread(thread);
    process::dispatch_thread(thread);
    thread_dispatch::begin_execution(thread)?;
    let started = clock::uptime_100ns();
    let reason = context_switch::resume(thread);
    process::set_current_thread(previous);
    let (new_state, yield_requested) = {
        let mut state = STATE.lock();
        let Some(process) = state.processes.iter_mut().find(|process| process.pid == pid) else {
            return Err(KernelError::new("running context disappeared"));
        };
        match reason {
            SwitchReason::Exit => {
                process.state = ProcessState::Done;
                (thread_dispatch::state::TERMINATED, false)
            }
            SwitchReason::Yield { retain } => {
                process.state = ProcessState::Ready;
                (thread_dispatch::state::READY, !retain)
            }
            SwitchReason::Wait => {
                // Uma espera sondada fica com o despachante; a de um objeto
                // (ke::wait) é confirmada aqui, e a já satisfeita entre a
                // saída da thread e este ponto volta direto à fila.
                if process.prepare_dispatch.is_some() || wait::commit(thread) {
                    process.state = ProcessState::Waiting;
                    (thread_dispatch::state::WAITING, false)
                } else {
                    process.state = ProcessState::Ready;
                    (thread_dispatch::state::READY, false)
                }
            }
        }
    };
    if yield_requested {
        thread_dispatch::request_yield(thread)?;
    }
    process::account_thread(thread, true, clock::uptime_100ns() - started);
    thread_dispatch::end_execution(thread, new_state)
}

/// Uma thread de kernel parada numa espera de objeto foi aprontada pelo
/// sinal (`ke::wait`): o escalonador a vê pronta.
pub fn thread_readied(thread: u64) {
    let pid = thread_dispatch::owner(thread).map(|owner| owner.runtime);
    let Some(pid) = pid.filter(|&runtime| runtime & thread_dispatch::USER_RUNTIME == 0) else { return };
    if let Some(process) = STATE.lock().processes.iter_mut().find(|process| process.pid as u64 == pid) {
        if process.state == ProcessState::Waiting {
            process.state = ProcessState::Ready;
        }
    }
}

/// Intervalos de usuário que um tick dá, no máximo.
pub const USER_SLICES_PER_TICK: usize = 16;

/// Um tick tem orçamento limitado de passos; cada seleção consulta as filas
/// vivas. Uma thread de prioridade menor não ganha CPU só porque a maior já
/// rodou neste tick. Uma thread de usuário selecionada ganha um intervalo
/// pelo despachante de todos os processos (só no tick comum, sem piso de
/// prioridade, e quando a CPU pode despachar usuário). O tick só roda no
/// despachante: pedido de dentro de uma thread de kernel, ela cede a vez.
pub fn tick(minimum_priority: i32) {
    if context_switch::on_kernel_thread_stack().is_some() {
        if context_switch::kernel_thread_can_block() {
            context_switch::yield_kernel_thread(false);
        }
        return;
    }
    reap();
    // Como a interrupção de relógio do NT, cada tick vence os timers devidos
    // (inclusive o prazo das esperas, no KTHREAD.Timer de cada thread) antes
    // da seleção: as threads que eles aprontam já entram nela.
    crate::ntos::ke::timer::check_timers();
    let budget = STATE.lock().processes.len();
    let (mut steps, mut slices) = (0, 0);
    let user_slices = |slices: usize| minimum_priority < 0 && slices < USER_SLICES_PER_TICK && user_threads::can_dispatch();
    // As threads de usuário paradas cuja espera já concluiu entram na fila
    // antes da seleção, mesmo quando nenhuma delas está pronta.
    if minimum_priority < 0 {
        user_threads::refresh_waiting();
    }
    while steps < budget || user_slices(slices) {
        let selected = refresh_waiting_threads().and_then(|_| thread_dispatch::peek());
        let (thread, owner) = match selected {
            Ok(Some(selected)) => selected,
            Ok(None) => break,
            Err(error) => {
                debug_print!("[sched] seleção falhou: {}", error);
                break;
            }
        };
        if owner.runtime & thread_dispatch::USER_RUNTIME != 0 {
            if !user_slices(slices) {
                break;
            }
            slices += 1;
            match user_threads::dispatch_one() {
                Ok(Dispatched::Ran { .. }) => continue,
                Ok(Dispatched::Idle) => break,
                Err(error) => {
                    debug_print!("[sched] despacho de usuario falhou: {}", error);
                    break;
                }
            }
        }
        if steps >= budget || thread_dispatch::priority(thread) as i32 <= minimum_priority {
            break;
        }
        steps += 1;
        let pid = owner.runtime as u32;
        if let Err(error) = run_step(pid, thread) {
            debug_print!("[sched] processo {} morreu: {}", pid, error);
        }
    }
    reap();
}

/// No contexto síncrono de boot, o próprio chamador aguarda as concorrentes
/// mais prioritárias quando uma prioridade muda.
fn priority_changed() {
    let caller = process::get_current_thread();
    if caller == 0 || thread_dispatch::owner(caller).is_some() || context_switch::on_kernel_thread_stack().is_some() {
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
    let system_thread = process::create_kernel_thread(process::get_system_process(), cid::ALLOCATE, false, 0, None)?;
    process::set_current_thread(system_thread);
    STATE.lock().system_thread = system_thread;
    // O contexto de boot está executando; não representa o processo Idle.
    thread_dispatch::initialize_queues();
    thread_dispatch::begin_execution(system_thread)?;
    crate::rtl::sync::set_contention_yield(contention_yield);
    thread_dispatch::register_priority_change_observer(priority_changed)
}

/// A volta de quem espera um SharedLock com dono: a thread de kernel cede a
/// vez; o contexto de boot roda um tick.
fn contention_yield() {
    if crate::ntos::ke::irql::get_irql() >= crate::ntos::ke::irql::DISPATCH_LEVEL || crate::rtl::sync::spin_locks_held() != 0 {
        core::hint::spin_loop();
        return;
    }
    tick(-1);
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
            state: if process.kill_requested { ProcessState::Killed } else { process.state },
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
    // SAFETY: a thread corrente do Process Manager.
    unsafe { Ethread::at(thread) }.cid.unique_process.get() as u32
}

/// Devolve o controle ao escalonador uma vez (a thread cede a vez).
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        Poll::Pending
    }
}
