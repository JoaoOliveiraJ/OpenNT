//! Threads de usuário.
//!
//! As threads executam código nativo em anel 3; a HAL salva CONTEXTs x64
//! completos nas saídas de syscall/timer e este módulo cuida do
//! escalonamento e do ciclo de vida. Cada processo tem a lista das próprias
//! threads (`ProcessState.threads`) e a entrada no despachante (`started`);
//! `THREADS` é o índice global (despachante, APCs e busca por id de
//! cliente), onde a thread fica até ser liberada, mesmo depois do término do
//! processo dela. O fim de um processo libera as threads dele, e só as dele
//! ([`release_process`]). A execução do contexto (`exec_user_context`) é
//! instalada pela HAL de modo usuário; os pumps de ALPC, `device_io`, worker
//! factories, timers e pacotes de espera ocupam slots fixos do despachante.
//!
//! Um despachante só serve as threads de todos os processos vivos
//! ([`dispatch_one`]): cada chamada sonda as esperas de todas, roda os pumps
//! e dá um intervalo à thread pronta mais prioritária, de qualquer processo,
//! com a raiz dela carregada pela troca de thread corrente. Um processo
//! entra no despachante por [`start`] e anda com os outros, esperado ou não:
//! quem precisa do fim dele bloqueia em [`wait_for_process`], que despacha
//! todos enquanto espera, e o `scheduler::tick` do kernel também despacha
//! intervalos de usuário (o timer encerra o intervalo de quem não cede a
//! CPU, então um processo não segura os outros). No M0 só o BSP despacha
//! usuário (assert).
//!
//! O fim de um processo, pedido de qualquer contexto (o NtTerminateProcess
//! dele mesmo, o de outro processo por handle, uma exceção fatal), passa por
//! `ps::create::exit_process`: as threads dele morrem na hora
//! ([`begin_exit`]) e o término propriamente dito (notificações, recursos,
//! estado) roda quando nenhuma delas tem mais serviço suspenso no kernel —
//! as bloqueadas são retomadas para desfazer o serviço antes, e o
//! despachante conclui o término adiado depois do intervalo
//! ([`finish_pending_exits`]).
//!
//! Uma thread também pode bloquear dentro de uma syscall
//! (`ke::context_switch::block_current`): o serviço fica suspenso na pilha de
//! kernel dela ([`KernelState::Blocked`]), o intervalo termina e o
//! despachante roda as outras. A espera dela é sondada como as demais;
//! quando conclui, o despachante a retoma na própria pilha em vez de entrar
//! no anel 3, e o serviço termina o intervalo como qualquer syscall.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use super::memory;
use super::process_state;
use super::state::{self, probe_user_read, probe_user_write, NativeBody, Region, UserHandle, UserObject};
use crate::hal::amd64::context_switch::EXIT_BLOCKED;
use crate::ntos::ke::{apc, clock, context_switch, dispatcher, irql, smp, thread_alert, thread_dispatch, thread_priority};
use crate::ntos::ob::objects::completion as completion_objects;
use crate::ntos::ps::{alert_thread, cid, process, query_thread, set_thread_information, system_process_information};
use crate::ntos::se::token::thread as thread_tokens;
use crate::rtl::{sync, KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{kernel_stack, peb_teb};
use crate::ntos::inc::types::{ClientId, Context, Eprocess, Ethread, ImageDosHeader, ImageNtHeaders64, Kthread, NtStruct, ObjectAttributes, Peb, PsAttribute, PsAttributeList, Teb, ThreadBasicInformation};
use core::mem::offset_of;

pub const CONTEXT_SIZE: u64 = Context::SIZE;
const PENDING: u32 = 0x103;
const NOT_SUPPORTED: u32 = 0xC000_00BB;
const THREAD_IS_TERMINATING: u32 = 0xC000_004B;

/// Slots dos pumps do laço, em ordem fixa.
pub mod pump {
    pub const ALPC: usize = 0;
    pub const DEVICE_IO: usize = 1;
    pub const WORKER_FACTORY: usize = 2;
    pub const TIMERS: usize = 3;
    pub const WAIT_PACKETS: usize = 4;
}

/// Espera de uma thread: objetos, atraso, alerta por id ou personalizada.
#[derive(Default)]
pub struct Wait {
    pub entries: Option<Vec<Arc<UserHandle>>>,
    /// Ponteiros dos objetos de `entries`.
    pub objects: Vec<u64>,
    pub wait_type: u32,
    pub alertable: Option<bool>,
    pub delay: bool,
    /// NtWaitForAlertByThreadId: a thread cujo alerta encerra a espera.
    pub alert: Option<Arc<UserThread>>,
    pub deadline: Option<u64>,
    pub alerts: Option<thread_alert::AlertWait>,
    pub poll: Option<Box<dyn FnMut() -> Option<u32> + Send>>,
    pub cleanup: Option<Box<dyn FnOnce(u32) + Send>>,
    /// Espera de trabalho de uma worker factory (o corpo da fábrica).
    pub worker_factory: u64,
}

/// Onde está o fluxo de kernel da thread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KernelState {
    /// Nenhum serviço suspenso: o próximo intervalo retoma o CONTEXT de
    /// usuário.
    #[default]
    User,
    /// Bloqueada dentro de um serviço, com o quadro de troca salvo em
    /// KTHREAD.KernelStack; `status` é o resultado da espera, publicado
    /// quando ela conclui (a thread fica pronta para ser retomada).
    Blocked { status: Option<u32> },
}

pub struct ThreadMut {
    pub thread_pointer: u64,
    pub process_pointer: u64,
    pub teb_va: u64,
    pub context: u64,
    pub regions: Option<Vec<Region>>,
    pub handles: u32,
    pub dead: bool,
    pub exit_status: u32,
    pub suspend_count: u32,
    pub hidden: bool,
    pub start: u64,
    pub alerted: bool,
    pub scheduling_registered: bool,
    pub pending_exception: bool,
    /// Worker factory dona da thread (corpo), pronta depois do
    /// NtWorkerFactoryWorkerReady.
    pub worker_factory: u64,
    pub worker_ready: bool,
    pub priority: u32,
    pub base_priority: u32,
    /// Instantâneo diagnóstico da pilha de usuário quando esta thread
    /// encerrou o processo (NtTerminateProcess ou exceção sem tratamento).
    pub termination_rsp: u64,
    wait: Option<Wait>,
    /// Há uma espera instalada (mesmo enquanto é sondada fora da trava).
    waiting: bool,
    /// Serviço suspenso na pilha de kernel da thread.
    kernel: KernelState,
}

pub struct UserThread {
    pub thread_id: u64,
    m: SpinLock<ThreadMut>,
}

impl UserThread {
    /// Thread publicada pelo processo (a principal) ou pela criação.
    pub fn new(thread_id: u64, thread_pointer: u64, teb_va: u64, start: u64) -> Arc<Self> {
        // KTHREAD.Teb acompanha a TEB da thread (PsGetThreadTeb).
        if thread_pointer != 0 {
            kernel_thread(thread_pointer).teb.set(teb_va);
        }
        Arc::new(Self {
            thread_id,
            m: SpinLock::new(ThreadMut {
                thread_pointer,
                process_pointer: 0,
                teb_va,
                context: 0,
                regions: None,
                handles: 0,
                dead: false,
                exit_status: PENDING,
                suspend_count: 0,
                hidden: false,
                start,
                alerted: false,
                scheduling_registered: false,
                pending_exception: false,
                worker_factory: 0,
                worker_ready: false,
                priority: 0,
                base_priority: 0,
                termination_rsp: 0,
                wait: None,
                waiting: false,
                kernel: KernelState::User,
            }),
        })
    }

    pub fn with<R>(&self, body: impl FnOnce(&mut ThreadMut) -> R) -> R {
        body(&mut self.m.lock())
    }

    pub fn pointer(&self) -> u64 {
        self.m.lock().thread_pointer
    }

    pub fn dead(&self) -> bool {
        self.m.lock().dead
    }

    pub fn waiting(&self) -> bool {
        self.m.lock().waiting
    }

    /// Onde está o fluxo de kernel da thread.
    pub fn kernel_state(&self) -> KernelState {
        self.m.lock().kernel
    }

    /// A thread tem um serviço suspenso na própria pilha de kernel.
    pub fn blocked_in_kernel(&self) -> bool {
        matches!(self.m.lock().kernel, KernelState::Blocked { .. })
    }

    /// Fábrica marcada na espera instalada (0 sem espera de worker).
    pub fn wait_worker_factory(&self) -> u64 {
        self.m.lock().wait.as_ref().map_or(0, |wait| wait.worker_factory)
    }

    /// Marca a espera instalada como espera de trabalho da fábrica.
    pub fn mark_wait_worker_factory(&self, factory: u64) {
        if let Some(wait) = self.m.lock().wait.as_mut() {
            wait.worker_factory = factory;
        }
    }

    fn take_wait(&self) -> Option<Wait> {
        self.m.lock().wait.take()
    }

    fn restore_wait(&self, wait: Wait) {
        self.m.lock().wait = Some(wait);
    }
}

static THREADS: SpinLock<Vec<Arc<UserThread>>> = SpinLock::new(Vec::new());
/// O despachante está ativo no BSP (um [`dispatch_one`] em curso, ou a
/// simulação dos autotestes): nenhum despacho aninhado.
static RUNNING: AtomicBool = AtomicBool::new(false);
static CURRENT: SpinLock<Option<Arc<UserThread>>> = SpinLock::new(None);
/// Processos com o fim pedido ([`begin_exit`]) cujo término espera os
/// serviços suspensos das threads deles serem desfeitos.
static EXITING: SpinLock<Vec<PendingExit>> = SpinLock::new(Vec::new());
static APC_PUMP_REGISTERED: AtomicBool = AtomicBool::new(false);
static DRAINING_APCS: AtomicBool = AtomicBool::new(false);
/// `exec_user_context(context, teb)` da HAL de modo usuário.
static EXECUTOR: SpinLock<Option<fn(u64, u64) -> u32>> = SpinLock::new(None);
/// `call_capture::consume` + `exceptions::hardware`/`pending`: devolve o status
/// fatal ou 0 para continuar.
static EXIT_HANDLER: SpinLock<Option<fn(&Arc<UserThread>, u32, u32) -> u32>> = SpinLock::new(None);
static PUMPS: SpinLock<[Option<fn()>; 5]> = SpinLock::new([None; 5]);

pub fn set_executor(executor: fn(u64, u64) -> u32) {
    *EXECUTOR.lock() = Some(executor);
}

pub fn set_exit_handler(handler: fn(&Arc<UserThread>, u32, u32) -> u32) {
    *EXIT_HANDLER.lock() = Some(handler);
}

pub fn set_pump(slot: usize, routine: fn()) {
    PUMPS.lock()[slot] = Some(routine);
}

/// O índice global: as threads de todos os processos ainda não liberadas.
pub fn all() -> Vec<Arc<UserThread>> {
    THREADS.lock().clone()
}

/// As threads do processo `process`: a lista do `ProcessState` enquanto ele
/// vive; depois do término, as que ainda estão no índice.
pub fn of_process(process: u64) -> Vec<Arc<UserThread>> {
    match process_state::get(process) {
        Some(state) => state.threads.lock().clone(),
        None => THREADS.lock().iter().filter(|thread| thread.with(|thread| thread.process_pointer) == process).cloned().collect(),
    }
}

/// Publica a thread no processo dono (o do KTHREAD, ou o corrente) e no
/// índice global.
pub fn push(thread: Arc<UserThread>) {
    let owner = thread.with(|thread| {
        if thread.process_pointer == 0 {
            thread.process_pointer = if thread.thread_pointer != 0 { kernel_thread(thread.thread_pointer).process.get() } else { process::get_current_process() };
        }
        thread.process_pointer
    });
    if let Some(state) = process_state::get(owner) {
        state.threads.lock().push(thread.clone());
    }
    THREADS.lock().push(thread);
}

/// Retira a thread do índice e da lista do processo dono, sem liberar nada.
pub fn remove(thread: &Arc<UserThread>) {
    THREADS.lock().retain(|candidate| !Arc::ptr_eq(candidate, thread));
    let owner = thread.with(|thread| thread.process_pointer);
    if let Some(state) = process_state::get(owner) {
        state.threads.lock().retain(|candidate| !Arc::ptr_eq(candidate, thread));
    }
}

/// O processo corrente já entrou no despachante (aceita threads novas).
fn current_process_started() -> bool {
    process_state::current().is_some_and(|state| state.started.load(Ordering::Acquire))
}

/// O processo `process` está vivo e entrou no despachante.
fn process_started(process: u64) -> bool {
    process_state::get(process).is_some_and(|state| state.started.load(Ordering::Acquire))
}

pub fn find_by_id(id: u64) -> Option<Arc<UserThread>> {
    THREADS.lock().iter().find(|thread| thread.thread_id == id).cloned()
}

pub fn find_by_pointer(pointer: u64) -> Option<Arc<UserThread>> {
    THREADS.lock().iter().find(|thread| pointer != 0 && thread.pointer() == pointer).cloned()
}

pub fn current() -> Option<Arc<UserThread>> {
    CURRENT.lock().clone()
}

pub fn active() -> bool {
    RUNNING.load(Ordering::Acquire) && CURRENT.lock().is_some()
}

/// Estado do despachante (`running`) e a entrada do processo corrente nele;
/// os autotestes o simulam.
pub fn set_running(running: bool, current: Option<Arc<UserThread>>) {
    if let Some(state) = process_state::current() {
        state.started.store(running, Ordering::Release);
    }
    set_dispatching(running, current);
}

fn set_dispatching(running: bool, current: Option<Arc<UserThread>>) {
    RUNNING.store(running, Ordering::Release);
    *CURRENT.lock() = current;
}

/// APCs de kernel podem rodar com a thread suspensa ou esperando: nada de
/// anel 3 é agendado, mas o contexto salvo e a identidade estão vivos.
pub fn drain_kernel_apcs() {
    let caller_irql = irql::get_irql();
    if DRAINING_APCS.load(Ordering::Acquire) || caller_irql > 1 {
        return;
    }
    let previous = process::get_current_thread();
    DRAINING_APCS.store(true, Ordering::Release);
    for thread in all() {
        let (dead, context, pointer, blocked) = thread.with(|thread| (thread.dead, thread.context, thread.thread_pointer, matches!(thread.kernel, KernelState::Blocked { .. })));
        if dead || context == 0 || !apc::has_pending(pointer) {
            continue;
        }
        // Bloqueada no kernel acima de PASSIVE_LEVEL (um fast mutex em
        // APC_LEVEL): as APCs de kernel esperam a retomada.
        if blocked && kernel_thread(pointer).wait_irql.get() != irql::PASSIVE_LEVEL {
            continue;
        }
        // Quem espera em APC_LEVEL não suprime as APCs especiais de outro
        // contexto salvo, que retoma em PASSIVE_LEVEL.
        if pointer == previous && caller_irql != 0 {
            continue;
        }
        process::set_current_thread(pointer);
        if caller_irql != 0 {
            irql::lower_irql(0);
        }
        let _ = apc::deliver_all_queued();
        if caller_irql != 0 {
            irql::raise_irql(caller_irql);
        }
        process::set_current_thread(previous);
    }
    process::set_current_thread(previous);
    DRAINING_APCS.store(false, Ordering::Release);
}

/// O KTHREAD de uma thread de usuário.
fn kernel_thread(pointer: u64) -> &'static Kthread {
    // SAFETY: KTHREAD vivo, retido pela thread de usuário.
    unsafe { Kthread::at(pointer) }
}

/// CONTEXT inicial de usuário (memória do kernel ou região do processo
/// recém-comprometida, antes de a thread rodar).
pub fn initialize_context(context: u64, rip: u64, rsp: u64, rcx: u64, rdx: u64) {
    guest::write_bytes(context, &[0; CONTEXT_SIZE as usize]);
    // SAFETY: o CONTEXT acabou de ser zerado e pertence ao chamador.
    let initial = unsafe { Context::at(context) };
    initial.context_flags.set(0x10_000B);
    initial.mx_csr.set(0x1F80);
    initial.seg_cs.set(0x33);
    initial.seg_ss.set(0x2B);
    initial.e_flags.set(0x202);
    initial.rcx.set(rcx);
    initial.rdx.set(rdx);
    initial.rsp.set(rsp);
    initial.rip.set(rip);
    initial.flt_save.control_word.set(0x37F);
    initial.flt_save.mx_csr.set(0x1F80);
}

fn prepare_main(thread: &Arc<UserThread>, rip: u64, rsp: u64, argument: u64, ntdll_base: u64) -> Result<(), KernelError> {
    let (pointer, start) = thread.with(|thread| (thread.thread_pointer, thread.start));
    process::describe_thread(pointer, None, false);
    process::set_thread_start(pointer, if start != 0 { start } else { rip });
    let context = guest::alloc_bytes(CONTEXT_SIZE);
    if context == 0 {
        return Err(KernelError::new("No memory for user CONTEXT"));
    }
    initialize_context(context, rip, rsp, argument, ntdll_base);
    let process_pointer = process::get_current_process();
    // A suspensão da criação (THREAD_CREATE_FLAGS_CREATE_SUSPENDED) fica: o
    // registro no despacho a respeita.
    thread.with(|thread| {
        thread.context = context;
        thread.exit_status = PENDING;
        thread.dead = false;
        thread.wait = None;
        thread.waiting = false;
        thread.handles = 0;
        thread.process_pointer = process_pointer;
    });
    // O cabeçalho do KTHREAD é um objeto de notificação do tipo Thread.
    dispatcher::initialize_event(pointer, 6, false);
    attach_scheduling(thread)
}

/// Registra a thread no despacho (USER_RUNTIME | TID), suspensa se o
/// `suspend_count` pede. Prioridades são vistas dos campos nativos (sem
/// cópia divergente).
pub fn attach_scheduling(thread: &Arc<UserThread>) -> Result<(), KernelError> {
    let pointer = thread.pointer();
    thread_dispatch::register(pointer, thread_dispatch::USER_RUNTIME | thread.thread_id)?;
    let suspended = thread.with(|thread| {
        thread.scheduling_registered = true;
        thread.suspend_count != 0
    });
    if suspended {
        thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING)?;
    }
    Ok(())
}

/// Sonda as esperas das threads de usuário de todos os processos que
/// entraram no despachante e põe na fila as prontas. Uma thread bloqueada no
/// kernel é sondada mesmo suspensa ou terminada (inclusive depois do término
/// do processo dela): o serviço precisa concluir (a suspensão vale na volta
/// ao anel 3; a terminada é retomada por [`resume_terminated`]). A sondagem
/// roda no contexto da thread (thread corrente e raiz dela); quem chama
/// restaura a dele.
fn refresh_ready_user_threads() {
    let mut candidates: Vec<Arc<UserThread>> = all()
        .into_iter()
        .filter(|thread| {
            let (runnable, blocked, process) = thread.with(|thread| (!thread.dead && thread.suspend_count == 0, matches!(thread.kernel, KernelState::Blocked { .. }), thread.process_pointer));
            blocked || (runnable && process_started(process))
        })
        .collect();
    candidates.sort_by_key(|thread| core::cmp::Reverse(thread_priority::query_priority(thread.pointer())));
    for candidate in candidates {
        let pointer = candidate.pointer();
        if let Some(mut wait) = candidate.take_wait() {
            process::set_current_thread(pointer);
            match poll_wait(&mut wait) {
                None => {
                    candidate.restore_wait(wait);
                    continue;
                }
                Some(status) => finish_wait(&candidate, wait, status),
            }
        } else if candidate.waiting() {
            continue;
        }
        let _ = thread_dispatch::make_ready(pointer);
    }
}

/// Um intervalo de [`dispatch_one`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dispatched {
    /// Nenhuma thread de usuário pronta (ou o despacho não cabe aqui: um
    /// despacho já em curso, uma thread de kernel mais prioritária).
    Idle,
    /// A thread `thread` (KTHREAD) teve um intervalo, encerrado com o tipo
    /// de saída `exit_kind` da HAL.
    Ran { thread: u64, exit_kind: u32 },
}

/// Voltas do despachante que um fim de processo adiado espera os serviços
/// suspensos das threads dele serem desfeitos.
const UNWIND_ROUNDS: usize = 64;
/// Quantas vezes, por chamada, o despachante descarta uma thread da fila de
/// prontas que não pode rodar (terminada, de processo que não entrou no
/// despachante, ou fora do índice).
const DISCARD_LIMIT: usize = 64;

/// O despacho de usuário cabe neste ponto: o executor está instalado, a CPU
/// é o BSP (no M0 só ele despacha usuário), a IRQL é PASSIVE_LEVEL, nenhuma
/// trava está retida, e nada de usuário está em curso nesta CPU (outro
/// despacho, um intervalo cru dos autotestes, APCs de kernel drenadas em nome
/// de uma thread). O `scheduler::tick` consulta isto antes de [`dispatch_one`].
pub fn can_dispatch() -> bool {
    // A trava do executor é solta antes da contagem de travas retidas.
    let installed = EXECUTOR.lock().is_some();
    installed
        && context_switch::processor() == 0
        && irql::get_irql() == irql::PASSIVE_LEVEL
        && sync::spin_locks_held() == 0
        && sync::shared_locks_held() == 0
        && !RUNNING.load(Ordering::Acquire)
        && !DRAINING_APCS.load(Ordering::Acquire)
        && !crate::hal::amd64::usermode::executing()
}

/// Põe a thread principal de um processo no despachante: o CONTEXT inicial
/// (`rip`, `rsp`, o argumento em rcx e a base da ntdll em rdx), o registro no
/// despacho e a entrada do processo (`started`). Daí em diante o processo
/// anda com os outros, esperado ou não. Roda com a thread corrente no
/// processo (o PID e o processo dono saem dela).
pub fn start(thread: &Arc<UserThread>, rip: u64, rsp: u64, argument: u64, ntdll_base: u64) -> Result<(), KernelError> {
    if EXECUTOR.lock().is_none() {
        return Err(KernelError::new("user-mode execution unavailable"));
    }
    prepare_main(thread, rip, rsp, argument, ntdll_base)?;
    if !APC_PUMP_REGISTERED.swap(true, Ordering::AcqRel) {
        dispatcher::register_completion_pump(drain_kernel_apcs);
    }
    let process_pointer = thread.with(|thread| thread.process_pointer);
    if let Some(state) = process_state::get(process_pointer) {
        state.started.store(true, Ordering::Release);
    }
    // O diagnóstico de falha (post-mortem) começa limpo para o processo novo.
    crate::hal::amd64::usermode::reset_fault_state();
    Ok(())
}

/// Põe a thread principal no despachante e espera o fim do processo dela
/// ([`start`] e [`wait_for_process`]); devolve o status de saída.
pub fn run(thread: &Arc<UserThread>, rip: u64, rsp: u64, argument: u64, ntdll_base: u64) -> Result<u32, KernelError> {
    start(thread, rip, rsp, argument, ntdll_base)?;
    wait_for_process(thread.with(|thread| thread.process_pointer))
}

/// Um intervalo de usuário de qualquer processo: sonda as esperas de todas
/// as threads, roda os pumps do kernel e dos objetos de usuário, retoma as
/// terminadas que precisam desfazer um serviço bloqueado, conclui os fins de
/// processo adiados e dá um intervalo à thread de usuário pronta mais
/// prioritária, com a raiz do processo dela carregada pela troca de thread
/// corrente. Depois do intervalo trata a saída (o fim do processo pedido
/// pelo NtTerminateProcess dele, uma exceção fatal) e recolhe as threads
/// mortas do processo. Só no BSP (assert); um despacho aninhado (de um pump
/// dentro deste) devolve `Idle`. A thread corrente de quem chama volta
/// intacta.
pub fn dispatch_one() -> Result<Dispatched, KernelError> {
    let Some(executor) = *EXECUTOR.lock() else { return Ok(Dispatched::Idle) };
    assert!(context_switch::processor() == 0, "despacho de usuario fora do processador de boot");
    if RUNNING.swap(true, Ordering::AcqRel) {
        return Ok(Dispatched::Idle);
    }
    let caller = process::get_current_thread();
    let result = dispatch_from(executor, caller);
    process::set_current_thread(caller);
    *CURRENT.lock() = None;
    RUNNING.store(false, Ordering::Release);
    result
}

/// Sonda as esperas das threads de usuário paradas e põe na fila de
/// despacho as que concluíram, sem dar intervalo a ninguém. O tick chama a
/// cada volta: quando todas as threads de usuário esperam, nenhuma está na
/// fila para o [`dispatch_one`] sondar as outras, e a condição que uma delas
/// espera pode ter sido produzida por quem acabou de parar (um pedido ALPC
/// posto na IOCP do servidor por um cliente que em seguida espera a
/// resposta). Mesmas condições do despacho; um despacho em curso já sonda.
pub fn refresh_waiting() {
    if !can_dispatch() || RUNNING.swap(true, Ordering::AcqRel) {
        return;
    }
    let caller = process::get_current_thread();
    refresh_ready_user_threads();
    process::set_current_thread(caller);
    RUNNING.store(false, Ordering::Release);
}

/// O corpo de [`dispatch_one`], com o despacho já marcado como em curso.
fn dispatch_from(executor: fn(u64, u64) -> u32, caller: u64) -> Result<Dispatched, KernelError> {
    refresh_ready_user_threads();
    process::set_current_thread(caller);
    dispatcher::pump_kernel();
    let pumps = *PUMPS.lock();
    for routine in pumps.into_iter().flatten() {
        routine();
    }
    refresh_ready_user_threads();
    process::set_current_thread(caller);
    resume_terminated(executor, caller)?;
    finish_pending_exits(true);
    for _ in 0..DISCARD_LIMIT {
        let Some((pointer, owner)) = thread_dispatch::peek()? else { return Ok(Dispatched::Idle) };
        // Uma thread de kernel mais prioritária é entregue no próximo pump.
        if owner.runtime & thread_dispatch::USER_RUNTIME == 0 {
            return Ok(Dispatched::Idle);
        }
        let Some(next) = find_by_pointer(pointer) else {
            thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING)?;
            continue;
        };
        let (dead, process) = next.with(|thread| (thread.dead, thread.process_pointer));
        let kernel = next.kernel_state();
        // Bloqueada no kernel com a espera ainda pendente (um alerta a
        // pôs na fila antes da sondagem): volta a esperar.
        if kernel == (KernelState::Blocked { status: None }) {
            thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING)?;
            continue;
        }
        if kernel == KernelState::User {
            // Terminada, ou de um processo que não entrou no despachante
            // (ou já saiu dele): sai da fila de prontas sem rodar.
            if dead {
                thread_dispatch::suspend(pointer, thread_dispatch::state::TERMINATED)?;
                continue;
            }
            if !process_started(process) {
                thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING)?;
                continue;
            }
        }
        return Ok(run_slice(&next, process, kernel, executor, caller));
    }
    Ok(Dispatched::Idle)
}

/// O status de saída de um processo cujo despacho falhou.
fn dispatch_failure(error: &KernelError) -> u32 {
    if error.status != 0 { error.status } else { 0xC000_0001 }
}

/// O intervalo de `next` (do processo `process`), escolhido por
/// [`dispatch_from`], e o que vem depois dele.
fn run_slice(next: &Arc<UserThread>, process: u64, kernel: KernelState, executor: fn(u64, u64) -> u32, caller: u64) -> Dispatched {
    let pointer = next.pointer();
    *CURRENT.lock() = Some(next.clone());
    process::set_current_thread(pointer);
    process::dispatch_thread(pointer);
    // Retorno ao modo usuário (o KiInitiateUserApc do
    // KiSystemServiceExit/KiExceptionExit): com UserApcPending ou
    // SpecialUserApcPending, o frame do KiUserApcDispatcher é montado antes
    // de retomar o CONTEXT salvo. Uma thread retomada no kernel ainda está
    // no serviço: as APCs de usuário esperam a volta ao anel 3.
    let mut exit = None;
    let mut kind = 0;
    if kernel == KernelState::User {
        let undeliverable = super::user_apc::deliver(next);
        if undeliverable != 0 {
            exit = Some(undeliverable);
        }
    }
    if exit.is_none() {
        match execute(next, executor) {
            Ok((status, exit_kind)) => {
                kind = exit_kind;
                if exit_kind == 0 {
                    // NtTerminateProcess do próprio processo (ou uma exceção
                    // de segunda chance): o intervalo acabou de vez.
                    exit = Some(status);
                } else if exit_kind != EXIT_BLOCKED {
                    // Captura de chamada e exceções (#DB próprio do usuário
                    // ou pendente); um bloqueio não é saída do serviço. Roda
                    // no contexto da thread: a entrega escreve na pilha dela.
                    let handler = *EXIT_HANDLER.lock();
                    let failed = match handler {
                        Some(handler) => handler(next, exit_kind, status),
                        None if exit_kind == 3 => status,
                        None => 0,
                    };
                    if failed != 0 {
                        exit = Some(failed);
                    }
                }
            }
            Err(error) => {
                crate::debug_print!("[thread] tid={} despacho falhou: {}", next.thread_id, error);
                exit = Some(dispatch_failure(&error));
            }
        }
    }
    // Daqui em diante a thread do intervalo não é mais a corrente: o
    // término e a liberação a recolhem.
    process::set_current_thread(caller);
    if let Some(status) = exit {
        crate::ntos::ps::create::exit_process(process, status);
    }
    finish_pending_exits(false);
    release_finished(process);
    // Fora de qualquer pilha de thread: as liberações adiadas.
    kernel_stack::reap();
    Dispatched::Ran { thread: pointer, exit_kind: kind }
}

/// Recolhe as threads mortas de `process` que não têm mais serviço suspenso
/// no kernel (a pilha de uma bloqueada só volta depois que o serviço dela é
/// desfeito) e, se o processo já terminou (a última thread saiu dentro do
/// intervalo, pelo NtTerminateThread), o que restou dele.
fn release_finished(process: u64) {
    for finished in of_process(process) {
        if finished.dead() && !finished.blocked_in_kernel() {
            release_execution_resources(&finished);
        }
    }
    if process::with_record(process, |record| record.terminated) == Some(true) && !exit_pending(process) {
        release_process(process);
    }
}

/// Bloqueia quem chama até o processo `process` acabar e devolve
/// EPROCESS.ExitStatus. Enquanto espera, despacha as threads de todos os
/// processos ([`dispatch_one`]), não só as dele. O processo acabou quando o
/// término dele concluiu (sem fim adiado nem thread ainda bloqueada no
/// kernel; uma que não desfaz o serviço em [`UNWIND_ROUNDS`] voltas fica
/// para trás, com o aviso) ou, num processo que não terminou (o de teste com
/// uma thread de kernel própria), quando todas as threads de usuário dele
/// morreram e desfizeram os serviços.
pub fn wait_for_process(process: u64) -> Result<u32, KernelError> {
    if RUNNING.load(Ordering::Acquire) {
        return Err(KernelError::new("espera de processo dentro do despachante"));
    }
    if process::reference(process).is_none() {
        return Err(KernelError::new("espera de processo desconhecido"));
    }
    // Voltas com o processo já terminado e uma thread dele ainda bloqueada
    // no kernel; depois de `UNWIND_ROUNDS`, a espera acaba com o aviso.
    let mut unwinding = 0;
    let result = loop {
        let done = match progress(process) {
            Progress::Done => true,
            Progress::Running => false,
            Progress::Unwinding => {
                unwinding += 1;
                let given_up = unwinding > UNWIND_ROUNDS;
                if given_up {
                    crate::debug_print!("[thread] processo {:#x} terminado com thread ainda bloqueada no kernel", process);
                }
                given_up
            }
        };
        if done {
            // SAFETY: o EPROCESS é referenciado durante a espera.
            break Ok(unsafe { Eprocess::at(process) }.exit_status.get() as u32);
        }
        if let Err(error) = dispatch_one() {
            break Err(error);
        }
    };
    let _ = process::dereference(process);
    result
}

/// Onde está o fim de um processo esperado (ver [`wait_for_process`]).
enum Progress {
    /// Ainda roda, ou o fim pedido não concluiu.
    Running,
    /// Terminou, mas uma thread dele ainda desfaz um serviço no kernel.
    Unwinding,
    /// Acabou.
    Done,
}

fn progress(process: u64) -> Progress {
    if exit_pending(process) {
        return Progress::Running;
    }
    let threads = of_process(process);
    let blocked = threads.iter().any(|thread| thread.blocked_in_kernel());
    match process::with_record(process, |record| record.terminated) {
        Some(false) if blocked || threads.is_empty() || !threads.iter().all(|thread| thread.dead()) => Progress::Running,
        Some(true) if blocked => Progress::Unwinding,
        _ => Progress::Done,
    }
}

/// Um intervalo da thread corrente `thread`: entra no anel 3 pelo CONTEXT
/// salvo ou, se ela está bloqueada no kernel com a espera concluída, retoma o
/// serviço na pilha dela (`context_switch::switch_to`). Devolve o resultado
/// e o tipo da saída.
fn execute(thread: &Arc<UserThread>, executor: fn(u64, u64) -> u32) -> Result<(u32, u32), KernelError> {
    let pointer = thread.pointer();
    let kernel_before = process::thread_kernel_time(pointer);
    let started = clock::uptime_ms();
    thread_dispatch::begin_execution(pointer)?;
    let status = if thread.blocked_in_kernel() {
        context_switch::switch_to(thread)
    } else {
        let (context, teb) = thread.with(|thread| (thread.context, thread.teb_va));
        executor(context, teb)
    };
    let new_state = thread.with(|thread| {
        if thread.dead {
            thread_dispatch::state::TERMINATED
        } else if thread.waiting || thread.suspend_count != 0 {
            thread_dispatch::state::WAITING
        } else {
            thread_dispatch::state::READY
        }
    });
    thread_dispatch::end_execution(pointer, new_state)?;
    let elapsed = (clock::uptime_ms() - started) * 10_000;
    let kernel = process::thread_kernel_time(pointer).saturating_sub(kernel_before);
    process::account_thread(pointer, false, elapsed.saturating_sub(kernel));
    Ok((status, crate::hal::amd64::usermode::block().exit_kind.get()))
}

/// Threads de qualquer processo terminadas enquanto bloqueadas no kernel,
/// com a espera concluída (o término a conclui com THREAD_IS_TERMINATING):
/// voltam à própria pilha para desfazer o serviço, fora da fila de prontas,
/// e são recolhidas quando o deixam. Um serviço desfeito que termina o
/// processo (saída tipo 0) pede o fim dele.
fn resume_terminated(executor: fn(u64, u64) -> u32, caller: u64) -> Result<(), KernelError> {
    for thread in all() {
        if !thread.with(|thread| thread.dead && matches!(thread.kernel, KernelState::Blocked { status: Some(_) })) {
            continue;
        }
        *CURRENT.lock() = Some(thread.clone());
        process::set_current_thread(thread.pointer());
        let outcome = execute(&thread, executor);
        process::set_current_thread(caller);
        let (status, kind) = outcome?;
        let process = thread.with(|thread| thread.process_pointer);
        if kind == 0 {
            crate::ntos::ps::create::exit_process(process, status);
        }
        if !thread.blocked_in_kernel() {
            release_execution_resources(&thread);
        }
    }
    Ok(())
}

/// Um fim de processo pedido e ainda não concluído.
struct PendingExit {
    process: u64,
    status: u32,
    /// Voltas do despachante desde o pedido.
    rounds: usize,
    /// O término já está rodando: um despacho aninhado nele (uma espera do
    /// término que gira o pump) não o recomeça.
    finishing: bool,
}

/// O fim de `process` foi pedido e ainda não concluiu.
pub fn exit_pending(process: u64) -> bool {
    EXITING.lock().iter().any(|pending| pending.process == process)
}

/// Quem vai rodar o término de `process` o reivindica: devolve o status do
/// fim pedido, ou `None` se não há fim pedido ou o término já roda.
pub fn claim_exit(process: u64) -> Option<u32> {
    let mut exiting = EXITING.lock();
    let pending = exiting.iter_mut().find(|pending| pending.process == process && !pending.finishing)?;
    pending.finishing = true;
    Some(pending.status)
}

/// O lado das threads do fim de um processo (o PspExitProcess antes do
/// término): o pedido fica registrado com o status (o primeiro vence) e
/// retém o EPROCESS; cada thread de usuário de `process` morre com o
/// status, a espera instalada conclui com THREAD_IS_TERMINATING (a de uma
/// bloqueada no kernel vira o status com que o serviço é desfeito) e as que
/// não estão em execução saem da fila de prontas. Devolve `false` se o fim
/// já tinha sido pedido ou o processo já terminou.
pub fn begin_exit(process: u64, status: u32) -> bool {
    if process::with_record(process, |record| record.terminated || record.exiting) != Some(false) {
        return false;
    }
    {
        let mut exiting = EXITING.lock();
        if exiting.iter().any(|pending| pending.process == process) {
            return false;
        }
        exiting.push(PendingExit { process, status, rounds: 0, finishing: false });
    }
    process::reference(process);
    for thread in of_process(process) {
        if let Some(wait) = thread.take_wait() {
            finish_wait(&thread, wait, THREAD_IS_TERMINATING);
        }
        let (pointer, registered) = thread.with(|thread| {
            thread.dead = true;
            if thread.exit_status == PENDING {
                thread.exit_status = status;
            }
            (thread.thread_pointer, thread.scheduling_registered)
        });
        if registered && pointer != 0 && thread_dispatch::thread_state(pointer) != thread_dispatch::state::RUNNING {
            let _ = thread_dispatch::suspend(pointer, thread_dispatch::state::TERMINATED);
        }
    }
    true
}

/// O término de um processo com o fim pedido já pode rodar: nenhuma thread
/// dele tem serviço suspenso no kernel e o intervalo em curso nesta CPU, se
/// houver, não é de uma delas.
pub fn exit_ready(process: u64) -> bool {
    let in_slice = crate::hal::amd64::usermode::in_service() && current().is_some_and(|thread| thread.with(|thread| thread.process_pointer) == process);
    !in_slice && !of_process(process).iter().any(|thread| thread.blocked_in_kernel())
}

/// O fim pedido de `process` concluiu: sai do registro e solta o EPROCESS.
pub fn end_exit(process: u64) {
    let removed = {
        let mut exiting = EXITING.lock();
        let before = exiting.len();
        exiting.retain(|pending| pending.process != process);
        exiting.len() != before
    };
    if removed {
        let _ = process::dereference(process);
    }
}

/// Conclui os fins de processo adiados que já podem rodar. Um que espera há
/// mais de [`UNWIND_ROUNDS`] voltas do despachante (`count_round`: esta
/// chamada é a de uma volta) — um serviço que nunca deixa o kernel —
/// conclui mesmo assim, com o aviso: a thread presa fica no índice.
fn finish_pending_exits(count_round: bool) {
    if crate::hal::amd64::usermode::in_service() {
        return;
    }
    let due: Vec<u64> = {
        let mut exiting = EXITING.lock();
        if count_round {
            exiting.iter_mut().for_each(|pending| pending.rounds += 1);
        }
        exiting.iter().filter(|pending| !pending.finishing && pending.rounds > UNWIND_ROUNDS).map(|pending| pending.process).collect()
    };
    for process in due.iter().copied() {
        let left = of_process(process).iter().filter(|thread| thread.blocked_in_kernel()).count();
        if left != 0 {
            crate::debug_print!("[thread] {} thread(s) ainda bloqueada(s) no kernel no fim do processo {:#x}", left, process);
        }
        crate::ntos::ps::create::finish_exit(process);
    }
    let pending: Vec<u64> = EXITING.lock().iter().filter(|pending| !pending.finishing).map(|pending| pending.process).collect();
    for process in pending {
        if exit_ready(process) {
            crate::ntos::ps::create::finish_exit(process);
        }
    }
}

fn finish_wait(thread: &UserThread, mut wait: Wait, status: u32) {
    if let Some(alerts) = wait.alerts.as_mut() {
        let _ = alerts.finish(status);
    }
    if let Some(cleanup) = wait.cleanup.take() {
        cleanup(status);
    }
    for entry in wait.entries.iter().flatten() {
        let _ = state::release_user_handle_reference(entry);
    }
    let (pointer, context, blocked) = thread.with(|thread| {
        thread.wait = None;
        thread.waiting = false;
        // Um serviço bloqueado recebe o status na retomada; o CONTEXT de
        // usuário recebe o resultado da syscall quando ela termina.
        let blocked = matches!(thread.kernel, KernelState::Blocked { .. });
        if blocked {
            thread.kernel = KernelState::Blocked { status: Some(status) };
        }
        (thread.thread_pointer, thread.context, blocked)
    });
    completion_objects::activate(pointer);
    if context != 0 && !blocked {
        // SAFETY: CONTEXT salvo da thread (memória do kernel).
        unsafe { Context::at(context) }.rax.set(status as u64);
    }
}

fn poll_wait(wait: &mut Wait) -> Option<u32> {
    if wait.alert.is_none() && (wait.entries.is_some() || wait.delay || wait.alertable.is_some()) {
        if wait.alerts.is_none() {
            wait.alerts = thread_alert::wait(process::get_current_thread(), 1, wait.alertable.unwrap_or(false), false).ok();
        }
        if let Some(interrupted) = wait.alerts.as_ref().and_then(|alerts| alerts.pending()) {
            return Some(interrupted);
        }
    }
    if let Some(target) = wait.alert.as_ref() {
        if target.with(|thread| core::mem::replace(&mut thread.alerted, false)) {
            return Some(0x101);
        }
    }
    if wait.delay {
        return (clock::uptime_ms() >= wait.deadline.unwrap_or(0)).then_some(0);
    }
    let result = if let Some(poll) = wait.poll.as_mut() {
        poll()
    } else if wait.alert.is_some() {
        None
    } else {
        dispatcher::try_wait_objects(&wait.objects, wait.wait_type)
    };
    if result.is_some() {
        return result;
    }
    match wait.deadline {
        Some(deadline) if clock::uptime_ms() >= deadline => Some(0x102),
        _ => None,
    }
}

fn block_current(mut wait: Wait) {
    if let Some(alerts) = wait.alerts.as_mut() {
        let _ = alerts.arm();
    }
    let Some(current) = current() else { return };
    completion_objects::deactivate(current.pointer());
    current.with(|thread| {
        thread.wait = Some(wait);
        thread.waiting = true;
    });
}

/// Bloqueio dentro de uma syscall (`ke::context_switch::block_current`):
/// instala a espera da thread corrente `thread` e a marca bloqueada no
/// kernel. O laço a sonda como as demais e, quando ela conclui, publica o
/// status e retoma o serviço na pilha da thread.
pub fn block_in_kernel(thread: &UserThread, wait: Wait) {
    thread.with(|thread| thread.kernel = KernelState::Blocked { status: None });
    block_current(wait);
}

/// O despacho dos intervalos de um callback de modo usuário (o
/// KeUserModeCallback de `ke/user_callback.rs`): a thread corrente
/// `thread`, dentro de um serviço, roda aninhado nele o CONTEXT `context`
/// (`usermode::exec_user_callback`) até `returned()` valer (o
/// NtCallbackReturn dela). Enquanto isso o CONTEXT do callback é o da
/// thread: a espera de um serviço aninhado conclui nele, e as APCs de
/// usuário e as exceções são entregues nele. Cada saída é tratada como o
/// despachante trataria: syscall e timer seguem; a espera PENDING de um
/// serviço aninhado é sondada no lugar, girando os pumps (dentro do
/// callback a thread não deixa a CPU, como `context_switch::can_block`
/// garante); exceções e capturas passam pelo tratador de saída. Uma thread
/// terminada (por outra, ou o fim do processo pedido de dentro do callback,
/// que fica com o despachante) encerra o laço com STATUS_THREAD_IS_TERMINATING.
/// Devolve 0 quando o callback retornou.
pub fn run_callback(thread: &Arc<UserThread>, context: u64, returned: &dyn Fn() -> bool) -> u32 {
    let (outer, teb, process_pointer) = thread.with(|thread| (core::mem::replace(&mut thread.context, context), thread.teb_va, thread.process_pointer));
    let status = loop {
        if thread.dead() {
            break THREAD_IS_TERMINATING;
        }
        if let Some(mut wait) = thread.take_wait() {
            let status = loop {
                if let Some(status) = poll_wait(&mut wait) {
                    break status;
                }
                dispatcher::pump_kernel();
                let pumps = *PUMPS.lock();
                for routine in pumps.into_iter().flatten() {
                    routine();
                }
            };
            finish_wait(thread, wait, status);
            continue;
        }
        let undeliverable = super::user_apc::deliver(thread);
        if undeliverable != 0 {
            crate::ntos::ps::create::exit_process(process_pointer, undeliverable);
            continue;
        }
        let (status, exit_kind) = crate::hal::amd64::usermode::exec_user_callback(context, teb);
        let failed = match exit_kind {
            // NtTerminateProcess de dentro do callback: o fim do processo.
            0 => Some(status),
            1 | 2 => None,
            _ => {
                let handler = *EXIT_HANDLER.lock();
                match handler {
                    Some(handler) => Some(handler(thread, exit_kind, status)).filter(|&failed| failed != 0),
                    None if exit_kind == 3 => Some(status),
                    None => None,
                }
            }
        };
        if let Some(failed) = failed {
            crate::ntos::ps::create::exit_process(process_pointer, failed);
            continue;
        }
        if returned() {
            break 0;
        }
    };
    thread.with(|thread| thread.context = outer);
    status
}

/// O status da espera de uma thread que o laço retomou no kernel; o
/// serviço deixa de estar suspenso.
pub fn take_kernel_wait_status(thread: &UserThread) -> u32 {
    let state = thread.with(|thread| core::mem::take(&mut thread.kernel));
    match state {
        KernelState::Blocked { status: Some(status) } => status,
        other => panic!("thread retomada no kernel sem espera concluida ({:?})", other),
    }
}

fn conclude(wait: &mut Wait, status: u32) {
    if let Some(alerts) = wait.alerts.as_mut() {
        let _ = alerts.finish(status);
    }
    if let Some(cleanup) = wait.cleanup.take() {
        cleanup(status);
    }
}

/// Espera personalizada: `timeout_ms` None deriva o prazo do ponteiro;
/// `Some(None)` é infinito. Fora do laço, a espera que bloquearia recusa
/// com 0xC00000BB; o pendente interno (0x103) é trocado antes da retomada.
pub fn wait_custom(mut wait: Wait, timeout: u64, timeout_ms: Option<Option<u64>>) -> u32 {
    let ms = timeout_ms.unwrap_or_else(|| dispatcher::timeout_pointer_to_ms(timeout));
    wait.deadline = ms.map(|ms| clock::uptime_ms() + ms);
    if let Some(immediate) = poll_wait(&mut wait) {
        conclude(&mut wait, immediate);
        return immediate;
    }
    if !active() {
        conclude(&mut wait, NOT_SUPPORTED);
        return NOT_SUPPORTED;
    }
    for entry in wait.entries.iter().flatten() {
        state::retain_user_handle_reference(entry);
    }
    block_current(wait);
    PENDING
}

pub fn wait_objects(entries: Vec<Arc<UserHandle>>, objects: Vec<u64>, wait_type: u32, timeout: u64, alertable: bool) -> u32 {
    let ms = dispatcher::timeout_pointer_to_ms(timeout);
    let mut wait = Wait { entries: Some(entries), objects, wait_type, alertable: Some(alertable), deadline: ms.map(|ms| clock::uptime_ms() + ms), ..Wait::default() };
    if let Some(immediate) = poll_wait(&mut wait) {
        if let Some(alerts) = wait.alerts.as_mut() {
            let _ = alerts.finish(immediate);
        }
        return immediate;
    }
    for entry in wait.entries.iter().flatten() {
        state::retain_user_handle_reference(entry);
    }
    block_current(wait);
    PENDING
}

/// Fim do processo `process`: as threads dele (e só as dele) morrem, as
/// esperas acabam com THREAD_IS_TERMINATING e os recursos de execução, o
/// registro no escalonador e o KTHREAD voltam. A thread do intervalo em curso
/// (o processo terminou de dentro de um serviço dela) só morre: o resto fica
/// para depois do intervalo, e o KTHREAD da thread corrente fica para quando
/// ela deixar de ser a corrente (como o NT, que só recolhe uma thread
/// terminada depois da troca). Chamar de novo conclui o que ficou.
pub fn release_process(process: u64) {
    let in_slice = crate::hal::amd64::usermode::block().context.get();
    let owned: Vec<Arc<UserThread>> = all().into_iter().filter(|thread| thread.with(|thread| thread.process_pointer) == process).collect();
    for thread in owned {
        if let Some(wait) = thread.take_wait() {
            finish_wait(&thread, wait, THREAD_IS_TERMINATING);
        }
        // A do intervalo em curso e as bloqueadas no kernel (a espera acabou
        // de concluir com THREAD_IS_TERMINATING) ainda têm o serviço na
        // pilha: só morrem, e o laço as desfaz antes da próxima liberação.
        if (in_slice != 0 && thread.with(|thread| thread.context) == in_slice) || thread.blocked_in_kernel() {
            thread.with(|thread| thread.dead = true);
            continue;
        }
        let (pointer, registered) = thread.with(|thread| {
            thread.dead = true;
            (thread.thread_pointer, core::mem::replace(&mut thread.scheduling_registered, false))
        });
        if registered {
            let _ = thread_dispatch::unregister(pointer);
        }
        if pointer != 0 {
            let _ = thread_tokens::release(pointer);
            completion_objects::dissociate(pointer);
        }
        release_execution_resources(&thread);
        let context = thread.with(|thread| core::mem::replace(&mut thread.context, 0));
        if context != 0 {
            guest::free_bytes(context);
        }
        destroy_thread_if_unused(&thread);
    }
}

/// APCs de conclusão retêm a ETHREAD, não o CONTEXT: são canceladas com a
/// identidade e a memória de execução ainda vivas.
pub fn release_execution_resources(thread: &Arc<UserThread>) {
    rundown_apcs(thread);
    // O ceifador devolve a pilha de kernel da thread morta (adiada se a CPU
    // ainda está nela).
    let pointer = thread.pointer();
    if pointer != 0 {
        process::release_kernel_stack(pointer);
    }
    // A pilha e a TEB da thread principal são do VAD do processo e voltam no
    // término dele.
    let Some(regions) = thread.with(|thread| thread.regions.take()) else { return };
    system_process_information::sample();
    for region in &regions {
        memory::release_private_region(region);
    }
    let context = thread.with(|thread| {
        thread.teb_va = 0;
        if thread.thread_pointer != 0 {
            kernel_thread(thread.thread_pointer).teb.set(0);
        }
        core::mem::replace(&mut thread.context, 0)
    });
    if context != 0 {
        guest::free_bytes(context);
    }
    destroy_thread_if_unused(thread);
}

fn rundown_apcs(thread: &UserThread) {
    let pointer = thread.pointer();
    if pointer == 0 {
        return;
    }
    let previous = process::get_current_thread();
    process::set_current_thread(pointer);
    let _ = apc::rundown(pointer);
    process::set_current_thread(previous);
}

/// Uma thread morta, sem handles nem regiões, sai do índice e do processo e
/// solta o KTHREAD, exceto o da thread corrente (fica para a próxima
/// liberação, quando ela já não for a corrente).
fn destroy_thread_if_unused(thread: &Arc<UserThread>) {
    let current = process::get_current_thread();
    let Some((pointer, registered)) = thread.with(|thread| {
        if !thread.dead || thread.handles != 0 || thread.regions.is_some() || (thread.thread_pointer != 0 && thread.thread_pointer == current) {
            return None;
        }
        Some((core::mem::replace(&mut thread.thread_pointer, 0), core::mem::replace(&mut thread.scheduling_registered, false)))
    }) else {
        return;
    };
    remove(thread);
    if registered {
        let _ = thread_dispatch::unregister(pointer);
    }
    if pointer != 0 {
        let _ = process::release_thread(pointer);
    }
}

fn allocate_private(size: u64, highest: u64) -> Result<(u64, Region), u32> {
    let scratch = guest::alloc_bytes(16);
    if scratch == 0 {
        return Err(0xC000_0017);
    }
    guest::write64(scratch, 0);
    guest::write64(scratch + 8, size);
    // `highest` 0 = o topo das alocações de usuário.
    let status = match memory::do_user_allocate(scratch, scratch + 8, 0x3000, 4, 0, highest, crate::ntos::mm::memory_map::ALLOCATION_GRANULARITY) {
        Ok(status) => status,
        Err(error) => if error.status != 0 { error.status } else { 0xC000_0017 },
    };
    let base = if status != 0 { 0 } else { guest::read64(scratch) };
    guest::free_bytes(scratch);
    if status != 0 {
        return Err(status);
    }
    memory::find_region(base).map(|region| (base, region)).ok_or(0xC000_0017)
}

/// Objeto de handle de thread: a ETHREAD real, contada em `handles`.
pub struct ThreadHandleObject {
    pub thread: Arc<UserThread>,
    pub pointer: u64,
}

impl UserObject for ThreadHandleObject {
    fn kind(&self) -> &'static str {
        "thread"
    }
    fn native_body(&self) -> Option<NativeBody> {
        let pointer = self.pointer;
        Some(NativeBody {
            pointer,
            type_name: String::from("Thread"),
            record: pointer,
            reference: Arc::new(move || {
                process::reference_thread(pointer);
            }),
            dereference: Arc::new(move || {
                let _ = process::dereference_thread(pointer);
            }),
        })
    }
    fn on_each_handle_open(&self) -> Result<bool, KernelError> {
        process::account_thread_handle(1)?;
        Ok(true)
    }
    fn on_each_handle_close(&self) {
        let _ = process::account_thread_handle(-1);
    }
    fn wait_pointer(&self) -> Option<u64> {
        Some(self.pointer)
    }
    fn release(&self) {
        self.thread.with(|thread| thread.handles = thread.handles.saturating_sub(1));
        destroy_thread_if_unused(&self.thread);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn thread_handle(thread: &Arc<UserThread>, access: u32, attributes: u32) -> Result<u64, KernelError> {
    let pointer = thread.pointer();
    thread.with(|thread| thread.handles += 1);
    match state::alloc_user_handle(Arc::new(ThreadHandleObject { thread: thread.clone(), pointer }), access, attributes) {
        Ok(handle) => Ok(handle as u64),
        Err(error) => {
            thread.with(|thread| thread.handles -= 1);
            destroy_thread_if_unused(thread);
            Err(error)
        }
    }
}

pub fn resolve(handle: u64, access: u32) -> Result<Arc<UserThread>, u32> {
    if handle as i64 == -2 {
        if let Some(current) = current() {
            return Ok(current);
        }
    }
    let Some(entry) = state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "thread" {
        return Err(0xC000_0024);
    }
    if entry.access() & access != access {
        return Err(0xC000_0022);
    }
    entry.downcast::<ThreadHandleObject>().map(|object| object.thread.clone()).ok_or(0xC000_0008u32)
}

pub struct CreateRequest {
    pub start: u64,
    pub argument_words: [u32; 2],
    pub flags: u32,
    pub zero_bits: u64,
    pub commit: u64,
    pub reserve: u64,
}

/// NtCreateThreadEx(out, access, oa, process, start, argument, flags,
/// zeroBits, commit, reserve, attributeList).
fn nt_create_thread_ex(out: u64, access: u64, attributes: u64, process_handle: u64, rsp: u64) -> Result<u32, KernelError> {
    if process_handle as i64 != -1 {
        return Ok(0xC000_0008);
    }
    if !probe_user_write(out, 8) || !state::probe_syscall_stack(rsp, 56) || (attributes != 0 && !probe_user_read(attributes, 48)) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| create_thread_ex(out, access, attributes, rsp))
}

fn create_thread_ex(out: u64, access: u64, attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    let start = state::stack_arg(rsp, 5);
    let flags = state::stack_arg32(rsp, 7);
    let zero_bits = state::stack_arg(rsp, 8);
    let commit = state::stack_arg(rsp, 9);
    let reserve = state::stack_arg(rsp, 10);
    let list = state::stack_arg(rsp, 11);
    if !current_process_started() || !probe_user_read(start, 1) {
        return Ok(0xC000_0005);
    }
    if flags & !0x77 != 0 || zero_bits > 32 {
        return Ok(0xC000_000D);
    }
    // Objetos de thread não têm nome.
    if attributes != 0 && state::user_struct::<ObjectAttributes>(attributes)?.object_name.probe_get()? != 0 {
        return Ok(0xC000_0033);
    }
    let mut outputs: Vec<(u64, u64, u64, u64)> = Vec::new();
    if list != 0 {
        if !probe_user_read(list, 8) {
            return Ok(0xC000_0005);
        }
        let attribute_list = state::user_struct::<PsAttributeList>(list)?;
        let bytes = attribute_list.total_length.probe_get()?;
        let header = offset_of!(PsAttributeList, attributes) as u64;
        if !(header..=header + 128 * PsAttribute::SIZE).contains(&bytes) || (bytes - header) % PsAttribute::SIZE != 0 {
            return Ok(0xC000_000D);
        }
        if !probe_user_read(list, bytes) {
            return Ok(0xC000_0005);
        }
        let mut seen: Vec<u64> = Vec::new();
        let mut at = list + header;
        while at < list + bytes {
            let entry = state::user_struct::<PsAttribute>(at)?;
            let attribute = entry.attribute.probe_get()?;
            let size = entry.size.probe_get()?;
            let target = entry.value_ptr.probe_get()?;
            let returned = entry.return_length.probe_get()?;
            let need = match attribute {
                0x10003 => 16,
                0x10004 => 8,
                _ => 0,
            };
            if need == 0 || seen.contains(&attribute) || size != need {
                return Ok(0xC000_000D);
            }
            if !probe_user_write(target, need) || (returned != 0 && !probe_user_write(returned, 8)) {
                return Ok(0xC000_0005);
            }
            seen.push(attribute);
            outputs.push((attribute, target, returned, size));
            at += PsAttribute::SIZE;
        }
    }
    let thread = match create_user_thread(&CreateRequest { start, argument_words: state::syscall_arg_words(rsp, 6), flags, zero_bits, commit, reserve }) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    // PHANDLE de saída e os atributos de saída, todos sondados acima.
    guest::try_write::<u64>(out, thread_handle(&thread, access as u32, 0)?)?;
    let (process_id, teb) = (state::current_process_id(), thread.with(|thread| thread.teb_va));
    for (attribute, target, returned, size) in outputs {
        if attribute == 0x10003 {
            // PS_ATTRIBUTE_CLIENT_ID.
            let client = state::user_struct::<ClientId>(target)?;
            client.unique_process.probe_set(process_id)?;
            client.unique_thread.probe_set(thread.thread_id)?;
        } else {
            // PS_ATTRIBUTE_TEB_ADDRESS.
            guest::try_write::<u64>(target, teb)?;
        }
        if returned != 0 {
            guest::try_write::<u64>(returned, size)?;
        }
    }
    Ok(0)
}

/// Pilha com compromisso antecipado (política deste kernel: todas as
/// páginas reservadas têm PFN); qualquer falha desfaz a thread inteira.
pub fn create_user_thread(request: &CreateRequest) -> Result<Arc<UserThread>, u32> {
    if !current_process_started() || !probe_user_read(request.start, 1) {
        return Err(0xC000_0005);
    }
    // A PEB e o PID são do processo corrente (o EPROCESS).
    let (peb, process_id) = (state::current_peb(), state::current_process_id());
    let (exports, ntdll_base) = state::with(|state| {
        let exports = state.ntdll_exports.as_ref().map(|exports| (exports.get("RtlUserThreadStart").copied().unwrap_or(0), exports.get("LdrInitializeThunk").copied().unwrap_or(0)));
        (exports.unwrap_or((0, 0)), state.ntdll_image_base)
    });
    // SizeOfStackReserve da imagem: a PEB e os cabeçalhos estão em memória
    // de usuário, então cada passo é sondado.
    let reserve = (|| -> Result<u64, KernelError> {
        let image_base = &state::user_struct::<Peb>(peb)?.image_base_address;
        if !probe_user_read(image_base.address(), 8) {
            return Err(guest::address_fault(peb));
        }
        let image_base = image_base.probe_get()?;
        if !probe_user_read(image_base, ImageDosHeader::SIZE) {
            return Err(guest::address_fault(image_base));
        }
        let headers = image_base + state::user_struct::<ImageDosHeader>(image_base)?.e_lfanew.probe_get()? as u32 as u64;
        if !probe_user_read(headers, ImageNtHeaders64::SIZE) {
            return Err(guest::address_fault(headers));
        }
        state::user_struct::<ImageNtHeaders64>(headers)?.optional_header.size_of_stack_reserve.probe_get()
    })();
    let default_reserve = match reserve {
        Ok(0) => 0x10_0000,
        Ok(value) => value,
        Err(error) => return Err(error.status),
    };
    let wanted = (if request.reserve != 0 { request.reserve } else { default_reserve }).max(if request.commit != 0 { request.commit } else { 0x1000 }) as u128;
    let stack_size = wanted.div_ceil(0x10000) * 0x10000;
    if stack_size == 0 || stack_size > 0x7FFF_FFFF {
        return Err(0xC000_000D);
    }
    let stack_size = stack_size as u64;
    let mut regions: Vec<Region> = Vec::new();
    let mut context = 0u64;
    let mut thread_pointer = 0u64;
    let result = (|| -> Result<Arc<UserThread>, u32> {
        let (stack, region) = allocate_private(stack_size, if request.zero_bits != 0 { (1u64 << (64 - request.zero_bits)) - 0x1000 } else { 0 })?;
        regions.push(region);
        let (teb, region) = allocate_private(0x2000, 0)?;
        regions.push(region);
        let (startup, region) = allocate_private(0x1000, 0)?;
        regions.push(region);
        context = guest::alloc_bytes(CONTEXT_SIZE);
        if context == 0 {
            return Err(0xC000_0017);
        }
        let process_pointer = process::get_current_process();
        // O TID sai da tabela de ids de cliente, a mesma dos PIDs; a pilha de
        // kernel própria vai com a KTHREAD (que a libera nas falhas).
        let own_stack = kernel_stack::create(false).map_err(|error| if error.status != 0 { error.status } else { 0xC000_0017 })?;
        thread_pointer = process::create_kernel_thread(process_pointer, cid::ALLOCATE, true, 1, Some(own_stack)).map_err(|_| 0xC000_0017u32)?;
        if thread_pointer == 0 {
            return Err(0xC000_0017);
        }
        // SAFETY: ETHREAD recém-criado acima.
        let id = unsafe { Ethread::at(thread_pointer) }.cid.unique_thread.get();
        dispatcher::initialize_event(thread_pointer, 6, false);
        let thread = UserThread::new(id, thread_pointer, teb, request.start);
        thread.with(|thread| {
            thread.process_pointer = process_pointer;
            thread.context = context;
            thread.regions = Some(core::mem::take(&mut regions));
            thread.suspend_count = request.flags & 1;
            thread.hidden = request.flags & 4 != 0;
        });
        // O MmCreateTeb sobre a TEB recém-comprometida.
        peb_teb::initialize_teb(teb, &peb_teb::TebDescription { process_id, thread_id: id, peb, stack_base: stack + stack_size, stack_limit: stack });
        // SAFETY: TEB recém-comprometida; a thread ainda não roda.
        let block = unsafe { Teb::at(teb) };
        // SameTebFlags: SkipThreadAttach, LoaderWorker e SkipLoaderInit.
        block.same_teb_flags.set((if request.flags & 2 != 0 { 8 } else { 0 }) | (if request.flags & 0x10 != 0 { 0x2000 } else { 0 }) | (if request.flags & 0x20 != 0 { 0x4000 } else { 0 }));
        initialize_context(startup, exports.0, stack + stack_size - 8, request.start, 0);
        // O argumento é um ULONG_PTR opaco: preserva os 64 bits.
        // SAFETY: o CONTEXT de partida acabou de ser montado.
        unsafe { Context::at(startup) }.rdx.set(request.argument_words[0] as u64 | (request.argument_words[1] as u64) << 32);
        initialize_context(context, exports.1, stack + stack_size - 8, startup, ntdll_base);
        process::add_thread(process_pointer);
        process::describe_thread(thread_pointer, None, false);
        process::set_thread_start(thread_pointer, request.start);
        push(thread.clone());
        if attach_scheduling(&thread).is_err() {
            remove(&thread);
            process::remove_thread(process_pointer);
            regions = thread.with(|thread| thread.regions.take().unwrap_or_default());
            return Err(0xC000_0017);
        }
        let _ = process::notify_thread_created(thread_pointer);
        crate::debug_print!("[thread] created tid={} start={:#x} flags={:#x} teb={:#x}", id, request.start, request.flags, teb);
        Ok(thread)
    })();
    if result.is_err() {
        for region in &regions {
            memory::release_private_region(region);
        }
        if context != 0 {
            guest::free_bytes(context);
        }
        if thread_pointer != 0 {
            let _ = process::release_thread(thread_pointer);
        }
    }
    result
}

fn change_suspend(handle: u64, out: u64, delta: i32) -> u32 {
    let thread = match resolve(handle, 2) {
        Ok(thread) => thread,
        Err(status) => return status,
    };
    if out != 0 && !probe_user_write(out, 4) {
        return 0xC000_0005;
    }
    let (previous, dead) = thread.with(|thread| (thread.suspend_count, thread.dead));
    if dead {
        return THREAD_IS_TERMINATING;
    }
    if delta > 0 && previous == 127 {
        return 0xC000_004A;
    }
    // ULONG *PreviousSuspendCount (sondado acima).
    if out != 0 && guest::try_write::<u32>(out, previous).is_err() {
        return 0xC000_0005;
    }
    adjust_suspend_count(&thread, delta);
    0
}

/// Soma `delta` à contagem de suspensão (o par KeSuspendThread/
/// KeResumeThread) e devolve a anterior: a thread que deixa de estar
/// suspensa volta à fila de prontas; a que passa a estar sai dela.
fn adjust_suspend_count(thread: &UserThread, delta: i32) -> u32 {
    let (previous, pointer, registered, suspended, waiting) = thread.with(|thread| {
        let previous = thread.suspend_count;
        thread.suspend_count = (previous as i32 + delta).max(0) as u32;
        (previous, thread.thread_pointer, thread.scheduling_registered, thread.suspend_count != 0, thread.waiting)
    });
    if registered && thread_dispatch::thread_state(pointer) != thread_dispatch::state::RUNNING {
        let _ = if suspended || waiting { thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING) } else { thread_dispatch::make_ready(pointer) };
    }
    previous
}

/// KeResumeThread(Thread): uma retomada na thread de usuário (a contagem de
/// suspensão desce uma unidade, se não for zero); devolve a contagem
/// anterior. Threads de sistema não têm contagem e devolvem 0.
pub fn resume_thread(pointer: u64) -> u32 {
    let Some(thread) = find_by_pointer(pointer) else { return 0 };
    if thread.with(|thread| thread.suspend_count) == 0 {
        return 0;
    }
    adjust_suspend_count(&thread, -1)
}

fn nt_suspend_thread(handle: u64, previous: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(change_suspend(handle, previous, 1))
}

fn nt_resume_thread(handle: u64, previous: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(change_suspend(handle, previous, -1))
}

fn nt_terminate_thread(handle: u64, status: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let thread = match resolve(if handle == 0 { (-2i64) as u64 } else { handle }, 1) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    if thread.dead() {
        return Ok(THREAD_IS_TERMINATING);
    }
    terminate_thread(&thread, status as u32)?;
    Ok(0)
}

/// NtTerminateProcess(NULL, status), o primeiro passo do RtlExitUserProcess:
/// as outras threads do processo corrente terminam com `status` (as
/// bloqueadas no kernel desfazem o serviço quando o despachante as retoma) e
/// quem chamou segue. Devolve o NTSTATUS.
pub fn terminate_other_threads(status: u32) -> Result<u32, KernelError> {
    let caller = process::get_current_thread();
    let current = current();
    for thread in of_process(process::get_current_process()) {
        let caller_thread = thread.pointer() == caller || current.as_ref().is_some_and(|current| Arc::ptr_eq(current, &thread));
        if caller_thread || thread.dead() {
            continue;
        }
        terminate_thread(&thread, status)?;
    }
    Ok(0)
}

/// O término de uma thread viva (PspTerminateThreadByPointer): a espera
/// conclui com THREAD_IS_TERMINATING, a thread morre com `status`, sai do
/// escalonador, passa pela saída nativa (notificações, APCs, token,
/// conclusões, mutantes) e deixa de contar no EPROCESS; a última thread
/// encerra o processo.
fn terminate_thread(thread: &Arc<UserThread>, status: u32) -> Result<(), KernelError> {
    if let Some(wait) = thread.take_wait() {
        finish_wait(thread, wait, THREAD_IS_TERMINATING);
    }
    let (pointer, registered, process_pointer) = thread.with(|thread| {
        thread.dead = true;
        thread.exit_status = status;
        (thread.thread_pointer, thread.scheduling_registered, thread.process_pointer)
    });
    process::describe_thread(pointer, None, true);
    if registered && thread_dispatch::thread_state(pointer) != thread_dispatch::state::RUNNING {
        thread_dispatch::suspend(pointer, thread_dispatch::state::TERMINATED)?;
    }
    process::exit_thread(pointer, status)?;
    rundown_apcs(thread);
    let _ = thread_tokens::release(pointer);
    completion_objects::dissociate(pointer);
    dispatcher::set_event(pointer);
    super::mutants::release_thread(pointer);
    process::remove_thread(process_pointer);
    // Notifica antes que a última ETHREAD possa ser recolhida.
    // SAFETY: o EPROCESS da thread, referenciado por ela.
    if unsafe { Eprocess::at(process_pointer) }.active_threads.get() == 0 {
        let previous = process::get_current_thread();
        process::set_current_thread(pointer);
        let terminated = process::terminate_process(process_pointer, status);
        process::set_current_thread(previous);
        terminated?;
    }
    crate::debug_print!("[thread] exit tid={} status={:#x}", thread.thread_id, status);
    Ok(())
}

/// O PID do CLIENT_ID da thread (ETHREAD.Cid); uma thread já recolhida
/// pertencia ao processo corrente, dono do handle por onde foi achada.
pub fn owner_process_id(thread: &UserThread) -> u64 {
    match thread.pointer() {
        0 => state::current_process_id(),
        // SAFETY: ETHREAD vivo, retido pela thread de usuário.
        pointer => unsafe { Ethread::at(pointer) }.cid.unique_process.get(),
    }
}

/// A classe 24 tem validação nativa própria sobre a mesma ETHREAD.
fn requested_class(class: u64) -> u32 {
    let raw = state::service_raw_arguments();
    if raw != 0 {
        guest::read32(raw + 16)
    } else {
        class as u32
    }
}

fn nt_query_information_thread(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    if requested_class(class) == 24 {
        return query_thread::query_user(rsp);
    }
    let thread = match resolve(handle, 0x40) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    let returned = state::stack_arg(rsp, 5);
    let need = match class {
        0 => 48,
        9 => 8,
        17 => 1,
        12 => 4,
        _ => return Ok(0xC000_0003),
    };
    if returned != 0 && !probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        if returned != 0 {
            guest::try_write::<u32>(returned, need as u32)?;
        }
        if length != need {
            return Ok(0xC000_0004);
        }
        if !probe_user_write(out, need) {
            return Ok(0xC000_0005);
        }
        let (pointer, exit_status, dead, teb, start, hidden) = thread.with(|thread| (thread.thread_pointer, thread.exit_status, thread.dead, thread.teb_va, thread.start, thread.hidden));
        match class {
            0 => {
                guest::try_write_bytes(out, &[0; ThreadBasicInformation::SIZE as usize])?;
                let information = state::user_struct::<ThreadBasicInformation>(out)?;
                information.exit_status.probe_set(exit_status as i32)?;
                information.teb_base_address.probe_set(if dead { 0 } else { teb })?;
                information.client_id.unique_process.probe_set(owner_process_id(&thread))?;
                information.client_id.unique_thread.probe_set(thread.thread_id)?;
                information.affinity_mask.probe_set((1u64 << smp::online_cpu_count()) - 1)?;
                information.priority.probe_set(thread_priority::query_priority(pointer) as i32)?;
                information.base_priority.probe_set(thread_priority::query_base_priority(pointer) as i32)?;
            }
            // ThreadQuerySetWin32StartAddress (PVOID).
            9 => guest::try_write::<u64>(out, start)?,
            // ThreadHideFromDebugger (BOOLEAN).
            17 => guest::try_write::<u8>(out, hidden as u8)?,
            // ThreadAmILastThread (ULONG): as threads do processo corrente.
            _ => guest::try_write::<u32>(out, (of_process(process::get_current_process()).iter().filter(|thread| !thread.dead()).count() == 1) as u32)?,
        }
        Ok(0)
    })
}

fn nt_delay_execution(alertable: u64, timeout: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_read(timeout, 8) {
        return Ok(0xC000_0005);
    }
    Ok(wait_custom(Wait { delay: true, alertable: Some(alertable & 0xFF != 0), ..Wait::default() }, timeout, None))
}

fn nt_alert_thread(handle: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let raw = state::service_raw_arguments();
    alert_thread::alert(if raw != 0 { guest::read64(raw + 8) } else { handle }, 1)
}

fn nt_yield_execution(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let Some(current) = current() else { return Ok(0x4000_0024) };
    Ok(if thread_dispatch::request_yield(current.pointer())? { 0 } else { 0x4000_0024 })
}

fn nt_wait_for_alert_by_thread_id(_address: u64, timeout: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if timeout != 0 && !probe_user_read(timeout, 8) {
        return Ok(0xC000_0005);
    }
    let Some(current) = current() else { return Ok(NOT_SUPPORTED) };
    if current.with(|thread| core::mem::replace(&mut thread.alerted, false)) {
        return Ok(0x101);
    }
    let ms = dispatcher::timeout_pointer_to_ms(timeout);
    if ms == Some(0) {
        return Ok(0x102);
    }
    block_current(Wait { alert: Some(current), deadline: ms.map(|ms| clock::uptime_ms() + ms), ..Wait::default() });
    Ok(PENDING)
}

fn nt_alert_thread_by_thread_id(id: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let Some(thread) = all().into_iter().find(|thread| thread.thread_id == id && !thread.dead()) else { return Ok(0xC000_000B) };
    thread.with(|thread| thread.alerted = true);
    Ok(0)
}

fn nt_set_information_thread(handle: u64, class: u64, input: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    // A classe 24 tem ordem própria e aceita alterar uma ETHREAD retida.
    if requested_class(class) == 24 {
        return set_thread_information::set_user(rsp);
    }
    let thread = match resolve(handle, 0x20) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    if thread.dead() {
        return Ok(THREAD_IS_TERMINATING);
    }
    match class {
        // ThreadZeroTlsCell: TlsFree zera o índice em toda TEB viva.
        10 => {
            if length != 4 {
                return Ok(0xC000_0004);
            }
            if !probe_user_read(input, 4) {
                return Ok(0xC000_0005);
            }
            // ULONG: o índice TLS (sondado acima).
            let index = match guest::try_read::<u32>(input) {
                Ok(index) => index as u64,
                Err(error) => return Ok(error.status),
            };
            if index >= 1088 {
                return Ok(0xC000_000D);
            }
            let mut slots = Vec::new();
            for target in of_process(process::get_current_process()) {
                let (dead, teb) = target.with(|thread| (thread.dead, thread.teb_va));
                if dead || teb == 0 {
                    continue;
                }
                // TEB de usuário: TlsSlots[64] e o vetor TlsExpansionSlots.
                let Ok(block) = state::user_struct::<Teb>(teb) else { return Ok(0xC000_0005) };
                let expansion = if index >= 64 {
                    if !probe_user_read(block.tls_expansion_slots.address(), 8) {
                        return Ok(0xC000_0005);
                    }
                    match block.tls_expansion_slots.probe_get() {
                        Ok(expansion) => expansion,
                        Err(error) => return Ok(error.status),
                    }
                } else {
                    0
                };
                if index >= 64 && expansion == 0 {
                    continue;
                }
                let slot = if index < 64 { block.tls_slots[index as usize].address() } else { expansion + (index - 64) * 8 };
                if !probe_user_write(slot, 8) {
                    return Ok(0xC000_0005);
                }
                slots.push(slot);
            }
            for slot in slots {
                if guest::try_write::<u64>(slot, 0).is_err() {
                    return Ok(0xC000_0005);
                }
            }
            Ok(0)
        }
        17 => {
            if length != 0 {
                return Ok(0xC000_0004);
            }
            thread.with(|thread| thread.hidden = true);
            Ok(0)
        }
        1 | 2 => {
            if length != 4 {
                return Ok(0xC000_0004);
            }
            if !probe_user_read(input, 4) {
                return Ok(0xC000_0005);
            }
            // LONG: a prioridade pedida (sondada acima).
            let priority = match guest::try_read::<i32>(input) {
                Ok(priority) => priority,
                Err(error) => return Ok(error.status),
            };
            let pointer = thread.pointer();
            if class == 1 {
                if !(1..=31).contains(&priority) {
                    return Ok(0xC000_000D);
                }
                thread_priority::set_priority(pointer, priority as u64)?;
            } else {
                if !(-16..=15).contains(&priority) {
                    return Ok(0xC000_000D);
                }
                kernel_thread(pointer).base_priority.set((8 + priority).clamp(1, 15) as i8);
                thread_priority::set_priority(pointer, thread_priority::query_base_priority(pointer) as u64)?;
            }
            Ok(0)
        }
        _ => {
            crate::debug_print!("[thread] NtSetInformationThread class={}", class);
            Ok(0xC000_0003)
        }
    }
}

pub fn retain_thread(thread: &UserThread) {
    thread.with(|thread| thread.handles += 1);
}

pub fn release_thread(thread: &Arc<UserThread>) {
    thread.with(|thread| thread.handles = thread.handles.saturating_sub(1));
    destroy_thread_if_unused(thread);
}

/// Consumidor elegível de uma porta de conclusão: viva e não suspensa.
fn eligible(pointer: u64) -> bool {
    find_by_pointer(pointer).is_none_or(|thread| thread.with(|thread| !thread.dead && thread.suspend_count == 0))
}

pub fn init() {
    completion_objects::set_thread_eligibility(eligible);
    set_pump(pump::TIMERS, super::timer_objects::pump);
    state::register_handler("NtCreateThreadEx", nt_create_thread_ex);
    state::register_handler("NtSuspendThread", nt_suspend_thread);
    state::register_handler("NtResumeThread", nt_resume_thread);
    state::register_handler("NtTerminateThread", nt_terminate_thread);
    state::register_handler("NtQueryInformationThread", nt_query_information_thread);
    state::register_handler("NtDelayExecution", nt_delay_execution);
    state::register_handler("NtAlertThread", nt_alert_thread);
    state::register_handler("NtYieldExecution", nt_yield_execution);
    state::register_handler("NtWaitForAlertByThreadId", nt_wait_for_alert_by_thread_id);
    state::register_handler("NtAlertThreadByThreadId", nt_alert_thread_by_thread_id);
    state::register_handler("NtSetInformationThread", nt_set_information_thread);
    state::register_handler("NtGetContextThread", super::set_thread_context::nt_get_context_thread);
    state::register_handler("NtSetContextThread", super::set_thread_context::nt_set_context_thread);
}
