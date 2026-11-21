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
//! factories e pacotes de espera ocupam slots fixos do despachante.
//!
//! Um despachante só serve as threads de todos os processos vivos
//! ([`dispatch_one`]): cada chamada sonda as esperas de todas, roda os pumps
//! e dá um intervalo à thread pronta mais prioritária, de qualquer processo,
//! com a raiz dela carregada pela troca de thread corrente. Um processo
//! entra no despachante por [`start`] e anda com os outros, esperado ou não:
//! quem precisa do fim dele bloqueia em [`wait_for_process`], que despacha
//! todos enquanto espera, e o `scheduler::tick` do kernel também despacha
//! intervalos de usuário (o timer encerra o intervalo de quem não cede a
//! CPU, então um processo não segura os outros). Com o despacho em várias
//! CPUs, cada AP também dá intervalos ([`dispatch_on_processor`]): escolhe a
//! pronta de usuário mais prioritária da fila comum e a roda, sem os pumps,
//! as sondagens e os fins de processo, que continuam no BSP (o AP lhe passa
//! o que o intervalo pediu, [`EXIT_REQUESTS`]). Uma thread é de uma CPU só
//! por vez (`thread_dispatch`: Running, Standby ou emprestada); a sondagem e
//! as APCs de kernel de uma thread fora da CPU passam por um empréstimo, e o
//! término ou a suspensão pedidos para uma thread que outra CPU executa
//! valem no fim do intervalo dela, decididos sob o PrcbLock.
//!
//! O fim de um processo, pedido de qualquer contexto (o NtTerminateProcess
//! dele mesmo, o de outro processo por handle, uma exceção fatal), passa por
//! `ps::create::exit_process`: as threads dele sem estado do win32k morrem na
//! hora ([`begin_exit`]) e o término propriamente dito (notificações,
//! recursos, estado) roda quando nenhuma delas tem mais serviço suspenso no
//! kernel — as bloqueadas são retomadas para desfazer o serviço antes, e o
//! despachante conclui o término adiado depois do intervalo
//! ([`finish_pending_exits`]).
//!
//! Uma thread com estado do win32k (KTHREAD.Win32Thread) termina como no
//! 19041: o término dela, pedido pelo NtTerminateThread, pelo
//! NtTerminateProcess ou pelo fim do processo, só a marca
//! ([`request_termination`], o KeRequestTerminationThread com a APC de
//! término); o serviço em curso se desfaz (as esperas de UserMode saem com
//! STATUS_USER_APC) e, na volta ao modo usuário, ela roda o próprio
//! PspExitThread no contexto dela ([`exit_current`]): o callout de saída de
//! thread do win32k vê a thread corrente com o Win32Thread publicado. A
//! última a sair conclui o fim do processo, com o callout de processo.
//!
//! Uma thread também pode bloquear dentro de uma syscall
//! (`ke::context_switch::block_registered`, `block_current`): o serviço fica
//! suspenso na pilha de kernel dela ([`KernelState::Blocked`]), o intervalo
//! termina e o despachante roda as outras. Quando a espera conclui, o
//! despachante a retoma na própria pilha em vez de entrar no anel 3, e o
//! serviço termina o intervalo como qualquer syscall.
//!
//! As esperas de objeto, de prazo e de alerta das threads de usuário são
//! registradas no despachante ([`Registered`], `ke::wait`), como as das
//! threads de kernel: o sinal apronta a thread (o KiUnwaitThread) e o
//! despachante só leva o status ao CONTEXT ou à retomada do serviço, sem
//! sondar. As acordadas (o alerta por id, a porta de conclusão, o
//! transporte ALPC) voltam à fila pelo sinal da fila ou pelo `wake` de quem
//! muda a condição, e a sondagem delas roda só então (e, sem nada, a cada
//! [`WOKEN_BACKSTOP_MS`]). As demais (E/S de dispositivo, notificação de
//! registro e as condições próprias de um serviço) seguem sondadas a cada
//! volta do despachante.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::memory;
use super::process_state;
use super::state::{self, probe_user_read, probe_user_write, NativeBody, Region, UserHandle, UserObject};
use crate::hal::amd64::context_switch::{EXIT_BLOCKED, EXIT_THREAD_EXITED};
use crate::ntos::ke::user_callback::CalloutStacks;
use crate::ntos::ke::{apc, clock, context_switch, dispatcher, irql, smp, thread_alert, thread_dispatch, thread_lock, thread_priority};
use crate::ntos::ob::objects::completion as completion_objects;
use crate::ntos::ps::{alert_thread, cid, dispatch_perf, process, query_thread, set_thread_information};
use crate::ntos::se::token::thread as thread_tokens;
use crate::rtl::{sync, KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{kernel_stack, peb_teb};
use crate::ntos::mm::memory_map::MAX_CPUS;
use crate::ntos::inc::types::{ClientId, Context, Eprocess, Ethread, ImageDosHeader, ImageNtHeaders64, Kthread, KwaitBlock, NtStruct, ObjectAttributes, Peb, PsAttribute, PsAttributeList, Teb, ThreadBasicInformation};
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
    /// Livre: os timers do NtCreateTimer2 vencem no pump dos timers do Ke
    /// (`ke/timer2.rs`), antes destes.
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
    /// Espera de um serviço bloqueado no kernel (`context_switch::block_current`):
    /// o término da thread não a conclui de fora — a sondagem decide, como
    /// numa espera do NT (a de UserMode sai pela APC de término, a de
    /// KernelMode alertável pelo alerta, a não alertável de KernelMode
    /// continua). As demais são esperas adiadas de serviços de UserMode.
    pub kernel: bool,
    /// O KWAIT_REASON publicado na KTHREAD; `None` deriva da forma da
    /// espera ([`wait_reason`]).
    pub reason: Option<u8>,
    /// A espera registrada no despachante ([`Registered`]): sem sondagem a
    /// cada volta; o sinal a conclui.
    pub registered: Option<Registered>,
}

/// A espera de uma thread de usuário registrada no despachante (`ke::wait`),
/// como a de uma thread de kernel: os KWAIT_BLOCKs da KTHREAD ligados aos
/// objetos e o timer do prazo. O sinal de um objeto, o prazo, um alerta ou
/// uma APC de usuário a desfazem dentro do próprio sinal e põem a thread na
/// fila (o KiUnwaitThread -> KiReadyThread do 19041); o status fica em
/// KTHREAD.WaitStatus e o despachante só o leva ao CONTEXT ao escolher a
/// thread, sem sondar nada. Numa espera acordada (`woken`) os blocos são de
/// notificação (ou nenhum, com o `ke::wait::wake` de quem muda a condição):
/// a saída só faz a sondagem da espera (`Wait.poll`) rodar de novo, no
/// contexto da thread, e sem conclusão a espera volta a ser registrada.
pub struct Registered {
    /// A KTHREAD que espera.
    pub thread: u64,
    pub objects: Vec<u64>,
    /// O WAIT_TYPE dos blocos (WaitAny 1, WaitAll 0) numa espera de objetos.
    pub kind: u8,
    pub deadline: crate::ntos::ke::wait::Deadline,
    /// O status do prazo vencido (STATUS_TIMEOUT; STATUS_SUCCESS num atraso).
    pub timeout_status: u32,
    pub alertable: bool,
    pub woken: bool,
    /// Numa acordada, o instante (uptime em ms) em que a sondagem quer rodar
    /// de novo mesmo sem sinal (a ociosidade de um worker): o timer da espera
    /// vence no menor entre ele e o prazo, e o vencimento antes do prazo só
    /// faz a sondagem rodar.
    pub poll_deadline: Option<Arc<AtomicU64>>,
    /// O número da espera ligada (0 = nenhuma).
    serial: u64,
    /// Uptime (ms) da última sondagem de uma acordada.
    polled_at: u64,
    /// A contagem de pulsos quando o serviço instalou a espera
    /// (`dispatcher::pulse_clock`): os blocos só são ligados quando a thread
    /// deixa a CPU, e o pulso (ou o sinal seguido do reset) que outra CPU der
    /// nesse meio a satisfaz na ligação, como satisfaria a espera do 19041,
    /// ligada dentro do serviço.
    since: Option<u64>,
}

impl Registered {
    /// Uma espera de objetos de UserMode (o NtWaitForSingleObject, o
    /// NtWaitForMultipleObjects): `kind` WaitAny ou WaitAll.
    pub fn objects(thread: u64, objects: Vec<u64>, kind: u8, deadline: crate::ntos::ke::wait::Deadline, alertable: bool) -> Self {
        Registered { thread, objects, kind, deadline, timeout_status: crate::ntos::ke::wait::STATUS_TIMEOUT, alertable, woken: false, poll_deadline: None, serial: 0, polled_at: 0, since: Some(dispatcher::pulse_clock()) }
    }

    /// Só o timer da thread (o KeDelayExecutionThread): STATUS_SUCCESS no
    /// vencimento.
    pub fn delay(thread: u64, deadline: crate::ntos::ke::wait::Deadline, alertable: bool) -> Self {
        Registered { thread, objects: Vec::new(), kind: crate::ntos::ke::wait::wait_type::ANY, deadline, timeout_status: 0, alertable, woken: false, poll_deadline: None, serial: 0, polled_at: 0, since: None }
    }

    /// Uma espera acordada: o sinal de `watch` (blocos de notificação, que
    /// não consomem), um `ke::wait::wake` ou o prazo devolvem a thread à
    /// fila, e a sondagem da espera decide.
    pub fn woken(thread: u64, watch: Vec<u64>, deadline: crate::ntos::ke::wait::Deadline, alertable: bool) -> Self {
        Registered { thread, objects: watch, kind: crate::ntos::ke::wait::wait_type::NOTIFICATION, deadline, timeout_status: crate::ntos::ke::wait::STATUS_TIMEOUT, alertable, woken: true, poll_deadline: None, serial: 0, polled_at: clock::uptime_ms(), since: None }
    }

    /// A espera de kernel dentro de um serviço (o KeWaitFor*, o
    /// KeDelayExecutionThread, a aquisição de um lock do Ex), já ligada pelo
    /// laço do `ke::wait` com o número `serial`: o despachante só leva o
    /// desfecho à retomada; o laço decide o resto (a APC de kernel, a espera
    /// de novo).
    fn linked(thread: u64, serial: u64) -> Self {
        Registered { thread, objects: Vec::new(), kind: crate::ntos::ke::wait::wait_type::ANY, deadline: crate::ntos::ke::wait::Deadline::Infinite, timeout_status: crate::ntos::ke::wait::STATUS_TIMEOUT, alertable: false, woken: false, poll_deadline: None, serial, polled_at: 0, since: None }
    }

    fn spec(&self, reason: u8) -> crate::ntos::ke::wait::WaitSpec {
        use crate::ntos::ke::wait::{wait_type, WaitSpec};
        let kind = if self.woken { wait_type::NOTIFICATION } else { self.kind };
        WaitSpec { timeout_key: self.timeout_status, explicit: self.woken, deferred: true, ..WaitSpec::new(kind, None, 1, self.alertable, reason) }
    }

    /// O prazo do timer da espera: o dela ou, se vem antes, o da sondagem
    /// (nunca menos de 1 ms à frente).
    fn wake_deadline(&self) -> crate::ntos::ke::wait::Deadline {
        use crate::ntos::ke::wait::Deadline;
        let Some(poll) = self.poll_deadline.as_ref() else { return self.deadline };
        // Um prazo da sondagem já vencido vale daqui a 1 ms: o registro nunca
        // conclui por ele, e a sondagem roda no vencimento.
        let now = clock::uptime_100ns();
        let at = poll.load(Ordering::Acquire).saturating_mul(10_000).max(now + 10_000);
        let poll_remaining = at - now;
        match self.deadline.remaining() {
            Some(remaining) if remaining <= poll_remaining => self.deadline,
            _ => Deadline::Uptime(at),
        }
    }

    /// Liga os blocos (a tentativa dos objetos e o prazo primeiro):
    /// `Some(status)` quando concluiu ali mesmo.
    fn link(&mut self, reason: u8) -> Option<u32> {
        use crate::ntos::ke::wait::{begin_user_wait, wait_type, UserWaitStart};
        // O pulso entre a instalação e a ligação (só a primeira: depois os
        // blocos já estavam ligados).
        if let Some(since) = self.since.take().filter(|_| !self.woken && self.kind == wait_type::ANY && !self.objects.is_empty()) {
            if let Some(index) = dispatcher::pulsed_since(&self.objects, wait_type::ANY as u32, since) {
                return Some(index);
            }
        }
        let deadline = self.wake_deadline();
        match begin_user_wait(self.thread, &self.objects, deadline, self.spec(reason)) {
            Ok(UserWaitStart::Done(status)) => Some(status),
            Ok(UserWaitStart::Linked(serial)) => {
                self.serial = serial;
                None
            }
            Err(status) => Some(status),
        }
    }

    /// O status da espera ligada, quando ela já saiu.
    fn outcome(&self) -> Option<u32> {
        if self.serial == 0 {
            return None;
        }
        crate::ntos::ke::wait::user_wait_outcome(self.thread, self.serial)
    }
}

impl Drop for Registered {
    /// Uma espera descartada sem conclusão não deixa blocos ligados em
    /// objetos que sobrevivem à KTHREAD.
    fn drop(&mut self) {
        if self.serial != 0 {
            crate::ntos::ke::wait::withdraw_user_wait(self.thread, self.serial);
        }
    }
}

/// O KWAIT_REASON de uma espera de usuário, como o 19041 passa ao
/// KeWait*: WrAlertByThreadId no NtWaitForAlertByThreadId, DelayExecution
/// no NtDelayExecution, WrQueue na espera de trabalho da worker factory,
/// UserRequest nas esperas de objeto (ObWaitForMultipleObjects,
/// NtWaitForSingleObject) e Executive nas demais.
fn wait_reason(wait: &Wait) -> u8 {
    use crate::ntos::ke::wait::reason;
    if let Some(reason) = wait.reason {
        reason
    } else if wait.alert.is_some() {
        reason::WR_ALERT_BY_THREAD_ID
    } else if wait.delay {
        reason::DELAY_EXECUTION
    } else if wait.worker_factory != 0 {
        reason::WR_QUEUE
    } else if wait.entries.is_some() {
        reason::USER_REQUEST
    } else {
        reason::EXECUTIVE
    }
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
    /// O término foi pedido e a thread roda o próprio PspExitThread na
    /// próxima volta ao modo usuário ([`request_termination`]); `dead` só
    /// vale quando ela sai.
    pub termination_requested: bool,
    /// O PspExitThread dela já roda (a APC de término foi entregue).
    exit_running: bool,
    pub alerted: bool,
    pub scheduling_registered: bool,
    pub pending_exception: bool,
    /// Worker factory dona da thread (corpo), pronta depois do
    /// NtWorkerFactoryWorkerReady.
    pub worker_factory: u64,
    pub worker_ready: bool,
    /// Instantâneo diagnóstico da pilha de usuário quando esta thread
    /// encerrou o processo (NtTerminateProcess ou exceção sem tratamento).
    pub termination_rsp: u64,
    /// A última exceção entregue ao KiUserExceptionDispatcher, para o
    /// diagnóstico de falhas (`crash_report`).
    pub last_exception: Option<super::crash_report::Fault>,
    wait: Option<Wait>,
    /// Há uma espera instalada (mesmo enquanto é sondada fora da trava).
    waiting: bool,
    /// Serviço suspenso na pilha de kernel da thread.
    kernel: KernelState,
    /// Um término pedido enquanto outra CPU era dona da thread, que não pôde
    /// concluir a espera dela de fora: `Some(true)` (a thread morreu) conclui
    /// qualquer espera instalada com STATUS_THREAD_IS_TERMINATING, `Some(false)`
    /// (o pedido de término do 19041) só a de UserMode. A dona aplica no fim
    /// do intervalo, ou a sondagem que a tomar emprestada
    /// ([`apply_deferred_termination`]).
    deferred_termination: Option<bool>,
}

pub struct UserThread {
    pub thread_id: u64,
    m: SpinLock<ThreadMut>,
}

impl UserThread {
    /// Thread publicada pelo processo (a principal) ou pela criação.
    pub fn new(thread_id: u64, thread_pointer: u64, teb_va: u64, start: u64) -> Arc<Self> {
        // KTHREAD.Teb acompanha a TEB da thread (PsGetThreadTeb); a área de
        // XSAVE e o NpxState passam aos de uma thread de usuário.
        if thread_pointer != 0 {
            kernel_thread(thread_pointer).teb.set(teb_va);
            crate::ntos::ke::xstate::initialize_user_thread(thread_pointer);
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
                termination_requested: false,
                exit_running: false,
                alerted: false,
                scheduling_registered: false,
                pending_exception: false,
                worker_factory: 0,
                worker_ready: false,
                termination_rsp: 0,
                last_exception: None,
                wait: None,
                waiting: false,
                kernel: KernelState::User,
                deferred_termination: None,
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

    /// O término desta thread foi pedido e ela ainda não saiu: o
    /// PspExitThread dela roda na próxima volta ao modo usuário.
    pub fn termination_pending(&self) -> bool {
        let thread = self.m.lock();
        thread.termination_requested && !thread.dead
    }

    /// A APC de término está pendente: o término foi pedido e o
    /// PspExitThread ainda não começou. A próxima volta ao modo usuário o
    /// roda.
    fn termination_deliverable(&self) -> bool {
        let thread = self.m.lock();
        thread.termination_requested && !thread.dead && !thread.exit_running
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

    /// Põe (ou tira) a espera instalada sem passar por um serviço: os
    /// autotestes que montam o estado de uma thread parada (um worker numa
    /// espera de outro objeto ou na fila da fábrica).
    pub fn set_wait_for_test(&self, wait: Option<Wait>) {
        let mut thread = self.m.lock();
        thread.waiting = wait.is_some();
        thread.wait = wait;
    }

    fn take_wait(&self) -> Option<Wait> {
        self.m.lock().wait.take()
    }

    fn restore_wait(&self, wait: Wait) {
        self.m.lock().wait = Some(wait);
    }
}

static THREADS: SpinLock<Vec<Arc<UserThread>>> = SpinLock::new(Vec::new());
/// O mesmo índice pela KTHREAD ([`find_by_pointer`], consultado a cada
/// despacho): sem percorrer a lista tomando a trava de cada thread.
static BY_POINTER: SpinLock<crate::rtl::PtrMap<Arc<UserThread>>> = SpinLock::new(crate::rtl::PtrMap::new());
/// O despachante está ativo em cada CPU (um [`dispatch_one`] ou um
/// [`dispatch_on_processor`] em curso, ou a simulação dos autotestes):
/// nenhum despacho aninhado.
static DISPATCHING: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
/// A thread de usuário do intervalo em curso em cada CPU.
static CURRENT: [SpinLock<Option<Arc<UserThread>>>; MAX_CPUS] = [const { SpinLock::new(None) }; MAX_CPUS];
/// O que o intervalo de um AP pede ao BSP, que roda os fins de processo e
/// recolhe as threads: o processo da thread e, no fim do processo pedido no
/// intervalo (o NtTerminateProcess dele, uma exceção fatal), o status.
static EXIT_REQUESTS: SpinLock<Vec<(u64, Option<u32>)>> = SpinLock::new(Vec::new());
/// Processos com o fim pedido ([`begin_exit`]) cujo término espera os
/// serviços suspensos das threads deles serem desfeitos.
static EXITING: SpinLock<Vec<PendingExit>> = SpinLock::new(Vec::new());
static APC_PUMP_REGISTERED: AtomicBool = AtomicBool::new(false);
static DRAINING_APCS: AtomicBool = AtomicBool::new(false);
/// O diagnóstico da primeira conclusão de E/S adiada drenada por
/// [`drain_kernel_apcs`] já foi impresso.
static DEFERRED_COMPLETION_REPORTED: AtomicBool = AtomicBool::new(false);
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
    let pointer = thread.pointer();
    if pointer != 0 {
        BY_POINTER.lock().insert(pointer, thread.clone());
    }
    THREADS.lock().push(thread);
}

/// Retira a thread do índice e da lista do processo dono, sem liberar nada.
pub fn remove(thread: &Arc<UserThread>) {
    THREADS.lock().retain(|candidate| !Arc::ptr_eq(candidate, thread));
    // A liberação zera o ponteiro antes de tirar a thread do índice: sem
    // ele, a entrada sai pela identidade.
    let pointer = thread.pointer();
    {
        let mut index = BY_POINTER.lock();
        if pointer != 0 && index.get(&pointer).is_some_and(|candidate| Arc::ptr_eq(candidate, thread)) {
            index.remove(&pointer);
        } else if pointer == 0 {
            index.retain(|_, candidate| !Arc::ptr_eq(candidate, thread));
        }
    }
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

/// PspInsertThread 0x6c1f1d..0x6c2043: com ProcessDelete (PspTerminateProcess
/// 0x707544) ou ProcessSelfDelete (NtTerminateProcess 0x707473) uma thread de
/// usuário nova não entra no processo: STATUS_PROCESS_IS_TERMINATING. Aqui:
/// o fim pedido (EXITING) ou o registro já saindo ou terminado.
fn process_terminating(process: u64) -> bool {
    use crate::ntos::inc::types::Eprocess;
    // SAFETY: o EPROCESS do processo corrente, vivo durante a criação.
    let flags = unsafe { Eprocess::at(process) }.flags.get();
    flags & (Eprocess::PROCESS_DELETE_MASK | Eprocess::PROCESS_SELF_DELETE_MASK) != 0 || exit_pending(process) || process::with_record(process, |record| record.exiting || record.terminated) == Some(true)
}

pub fn find_by_id(id: u64) -> Option<Arc<UserThread>> {
    THREADS.lock().iter().find(|thread| thread.thread_id == id).cloned()
}

pub fn find_by_pointer(pointer: u64) -> Option<Arc<UserThread>> {
    if pointer == 0 {
        return None;
    }
    // A entrada de uma thread cuja KTHREAD a liberação já soltou (o ponteiro
    // zerado, ainda no índice) não vale.
    let thread = BY_POINTER.lock().get(&pointer).cloned()?;
    (thread.pointer() == pointer).then_some(thread)
}

/// O número desta CPU.
fn cpu() -> usize {
    context_switch::processor()
}

pub fn current() -> Option<Arc<UserThread>> {
    CURRENT[cpu()].lock().clone()
}

pub fn active() -> bool {
    let cpu = cpu();
    DISPATCHING[cpu].load(Ordering::Acquire) && CURRENT[cpu].lock().is_some()
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
    let cpu = cpu();
    DISPATCHING[cpu].store(running, Ordering::Release);
    *CURRENT[cpu].lock() = current;
}

/// APCs de kernel podem rodar com a thread suspensa ou esperando: nada de
/// anel 3 é agendado, mas o contexto salvo e a identidade estão vivos.
///
/// Entram também as conclusões de E/S que só o contexto da thread termina
/// (o IopCompleteRequest, uma APC especial de kernel no NT, entregue com a
/// thread parada numa espera em PASSIVE_LEVEL): um ZwReadFile assíncrono que
/// uma thread de usuário fez dentro de um serviço (o RIMStartDeviceRead do
/// RIT do win32k, com a thread depois parada no KeWaitForMultipleObjects) é
/// concluído pelo driver num DPC; a conclusão grava o IO_STATUS_BLOCK e
/// enfileira a APC da ApcRoutine do pedido, que roda logo depois.
pub fn drain_kernel_apcs() {
    let caller_irql = irql::get_irql();
    if DRAINING_APCS.load(Ordering::Acquire) || caller_irql > 1 {
        return;
    }
    let previous = process::get_current_thread();
    DRAINING_APCS.store(true, Ordering::Release);
    for thread in all() {
        let (dead, context, pointer, blocked) = thread.with(|thread| (thread.dead, thread.context, thread.thread_pointer, matches!(thread.kernel, KernelState::Blocked { .. })));
        if dead || context == 0 || !crate::ntos::ke::thread_apcs_pending(pointer) {
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
        // A thread que outra CPU executa entrega as próprias APCs: a dona
        // as entrega antes do intervalo seguinte, e o IPI de quem as
        // enfileirou encerra o intervalo em curso.
        let Some(borrow) = thread_dispatch::try_borrow(pointer) else { continue };
        process::set_current_thread(pointer);
        if caller_irql != 0 {
            irql::lower_irql(0);
        }
        // As conclusões primeiro: elas enfileiram as APCs de conclusão.
        if crate::ntos::io::file::request::has_completions_for(pointer) && !DEFERRED_COMPLETION_REPORTED.swap(true, Ordering::AcqRel) {
            debug_print!("[apc] primeira conclusao de E/S adiada drenada no contexto da thread de usuario tid={} (pid {})", process::get_current_thread_id(), process::get_current_process_id());
        }
        crate::ntos::io::file::request::pump();
        let _ = apc::deliver_all_queued();
        if caller_irql != 0 {
            irql::raise_irql(caller_irql);
        }
        process::set_current_thread(previous);
        thread_dispatch::release_borrow(borrow);
    }
    process::set_current_thread(previous);
    DRAINING_APCS.store(false, Ordering::Release);
}

/// Num AP, a espera que gira dentro de um serviço (o `wait_until` de quem não
/// pode deixar a CPU, com uma trava retida) entrega as conclusões de E/S e as
/// APCs de kernel da própria thread, como o [`drain_kernel_apcs`] do pump do
/// BSP faz com a thread corrente dele: a conclusão de um pedido de arquivo só
/// termina no contexto de quem pediu, e a espera do pedido não acaba sem
/// ela. O resto do pump (IRQs, DPCs, timers) é do BSP.
pub fn drain_own_kernel_apcs() {
    if irql::get_irql() != irql::PASSIVE_LEVEL {
        return;
    }
    let pointer = process::get_current_thread();
    if pointer == 0 || current().is_none_or(|thread| thread.pointer() != pointer) {
        return;
    }
    if !crate::ntos::ke::thread_apcs_pending(pointer) && !crate::ntos::io::file::request::has_completions_for(pointer) {
        return;
    }
    crate::ntos::io::file::request::pump();
    let _ = apc::deliver_all_queued();
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
    // O processo é dado como iniciado antes de a thread entrar na fila: um
    // AP ocioso a escolhe logo, e o `admit` dele devolve à espera a thread
    // de um processo ainda não iniciado, que só a sondagem do BSP aprontaria.
    if let Some(state) = process_state::get(process_pointer) {
        state.started.store(true, Ordering::Release);
    }
    attach_scheduling(thread)
}

/// A CPU que executa, reservou ou tomou emprestada a thread, se não é a
/// corrente. O ponteiro da KTHREAD é lido sob a trava da thread e a posse
/// sob o PrcbLock antes de soltá-la: a liberação da thread morta
/// (`destroy_thread_if_unused`) zera o ponteiro sob a mesma trava antes de
/// soltar a KTHREAD, então a consulta nunca lê uma KTHREAD já solta, e a
/// thread sem KTHREAD não é de ninguém.
fn owned_elsewhere(thread: &UserThread) -> Option<usize> {
    if !thread_dispatch::concurrent() {
        return None;
    }
    thread_dispatch::with_queues(|queues| thread.with(|thread| (thread.thread_pointer != 0).then(|| queues.owner_elsewhere(thread.thread_pointer)).flatten()))
}

/// Diagnóstico de parada (a linha `[perf] ... aps:` com o sistema parado por
/// 15 s): uma linha `[parada]` por thread de usuário viva, com o estado de
/// despacho, a CPU dona, a contagem de suspensão e a espera.
pub fn report_stalled_threads() {
    let threads: Vec<Arc<UserThread>> = THREADS.lock().clone();
    crate::debug_print!("[parada] sistema parado ha 15 s: {} threads de usuario", threads.len());
    for thread in threads {
        let snapshot = thread.with(|thread| {
            let wait = thread.wait.as_ref().map(|wait| {
                let objects = wait.registered.as_ref().map_or_else(|| wait.objects.clone(), |registered| registered.objects.clone());
                let shape = if wait.registered.is_some() { "registrada" } else if wait.poll.is_some() { "sondada" } else { "simples" };
                (objects, shape, wait.kernel, wait_reason(wait), wait.deadline)
            });
            (thread.thread_pointer, thread.process_pointer, thread.suspend_count, thread.waiting, thread.dead, thread.termination_requested, thread.kernel, thread.deferred_termination, wait)
        });
        let (pointer, process_pointer, suspend_count, waiting, dead, termination, kernel, deferred, wait) = snapshot;
        if pointer == 0 || dead {
            continue;
        }
        let (dispatch_state, owner, queued) = thread_dispatch::describe(pointer);
        // SAFETY: EPROCESS do processo dono da thread viva.
        let (pid, name) = if process_pointer != 0 {
            let eprocess = unsafe { Eprocess::at(process_pointer) };
            let bytes: Vec<u8> = eprocess.image_file_name.iter().map(|byte| byte.get()).take_while(|&byte| byte != 0).collect();
            (eprocess.unique_process_id.get(), String::from_utf8_lossy(&bytes).into_owned())
        } else {
            (0, String::new())
        };
        let mut line = alloc::format!("[parada] {} {}:{} estado {} dona {:?} na fila {} suspensa {} espera {} {:?}", name, pid, thread.thread_id, dispatch_state, owner, queued, suspend_count, waiting, kernel);
        if termination || deferred.is_some() {
            line.push_str(&alloc::format!(" termino pedido {} adiado {:?}", termination, deferred));
        }
        let kthread = kernel_thread(pointer);
        line.push_str(&alloc::format!(" servico {:#x}", kthread.system_call_number.get()));
        // Bloqueada no kernel: a pilha do serviço pelo quadro de troca salvo
        // em KTHREAD.KernelStack (o RBP em +0xF0, o retorno em +0xF8) e a
        // cadeia de RBP a partir dele.
        if matches!(kernel, KernelState::Blocked { .. }) {
            let present = |address: u64| address >= 0xFFFF_8000_0000_0000 && address & 7 == 0 && crate::ntos::mm::paging::translate(address & !0xFFF) != 0 && crate::ntos::mm::paging::translate((address + 8) & !0xFFF) != 0;
            let saved = kthread.kernel_stack.get();
            if present(saved + 0xF0) {
                line.push_str(" | pilha:");
                // Os retornos fora do kernel do OpenNT (os drivers e o win32k)
                // saem como módulo+deslocamento.
                let push_return = |line: &mut String, ret: u64| {
                    if (0xFFFF_F800_4000_0000..0xFFFF_F800_4200_0000).contains(&ret) {
                        line.push_str(&alloc::format!(" {:#x}", ret));
                    } else {
                        line.push(' ');
                        crate::ntos::ke::bugcheck_trace::describe(line, ret, 0x4000);
                    }
                };
                let mut frame = guest::read64(saved + 0xF0);
                push_return(&mut line, guest::read64(saved + 0xF8));
                for _ in 0..14 {
                    if !present(frame) {
                        break;
                    }
                    let (next, ret) = (guest::read64(frame), guest::read64(frame + 8));
                    push_return(&mut line, ret);
                    if next <= frame {
                        break;
                    }
                    frame = next;
                }
            }
        }
        if let Some((objects, shape, kernel_wait, reason, deadline)) = wait {
            line.push_str(&alloc::format!(" | {} motivo {} kernel {} prazo {:?}:", shape, reason, kernel_wait, deadline));
            for object in objects {
                // SAFETY: objeto retido pela espera instalada.
                let header = unsafe { crate::ntos::inc::types::DispatcherHeader::at(object) };
                line.push_str(&alloc::format!(" {:#x} (tipo {} sinal {})", object, header.type_.get() & 0x7F, header.signal_state.get()));
            }
        }
        // A espera ligada no despachante (`ke::wait`): os objetos dela.
        if let Some((objects, explicit)) = crate::ntos::ke::wait::describe_waiting(pointer) {
            line.push_str(&alloc::format!(" | ke::wait{}:", if explicit { " explicita" } else { "" }));
            for (object, kind, signal) in objects {
                line.push_str(&alloc::format!(" {:#x} (tipo {} sinal {})", object, kind, signal));
            }
        }
        // Os KWAIT_BLOCKs ligados da KTHREAD (a espera de kernel dentro de um
        // serviço não guarda os objetos no registro).
        let list = kthread.wait_block_list.get();
        let count = kthread.wait_block_count.get().min(8) as u64;
        if list != 0 && count != 0 && kthread.wait_reason.get() == crate::ntos::ke::wait::reason::WR_RESOURCE {
            // SAFETY: o primeiro bloco ligado da espera WrResource.
            let event = unsafe { KwaitBlock::at(list) }.object.get();
            if let Some((resource, owner, active)) = crate::ntos::ex::resource::describe_wait_event(event) {
                let owner_tid = if owner != 0 { crate::ntos::ps::thread_accessors::id(owner) } else { 0 };
                line.push_str(&alloc::format!(" | ERESOURCE {:#x} dono exclusivo tid {} ({:#x}), {} entradas ativas", resource, owner_tid, owner, active));
            }
        }
        if list != 0 && count != 0 {
            line.push_str(&alloc::format!(" | KTHREAD motivo {} blocos:", kthread.wait_reason.get()));
            for index in 0..count {
                // SAFETY: a lista de blocos da espera ligada da thread (a
                // KTHREAD ou o vetor do chamador, vivo enquanto ela espera).
                let block = unsafe { KwaitBlock::at(list + index * core::mem::size_of::<KwaitBlock>() as u64) };
                let object = block.object.get();
                if object == 0 || object < 0xFFFF_8000_0000_0000 {
                    continue;
                }
                // SAFETY: o objeto do bloco ligado.
                let header = unsafe { crate::ntos::inc::types::DispatcherHeader::at(object) };
                line.push_str(&alloc::format!(" {:#x} (tipo {} sinal {} estado {})", object, header.type_.get() & 0x7F, header.signal_state.get(), block.block_state.get()));
            }
        }
        crate::debug_print!("{}", line);
    }
    super::alpc::report_stalled_ports();
    crate::ntos::alpc::server::report_stalled_servers();
}

/// Registra a thread no despacho (USER_RUNTIME | TID), suspensa se o
/// `suspend_count` pede. Prioridades são vistas dos campos nativos (sem
/// cópia divergente).
pub fn attach_scheduling(thread: &Arc<UserThread>) -> Result<(), KernelError> {
    let pointer = thread.pointer();
    thread_dispatch::register_owner(pointer, thread_dispatch::USER_RUNTIME | thread.thread_id)?;
    // A decisão sai da contagem de suspensão sob o PrcbLock, como a da
    // retomada (`adjust_suspend_count`): a criada suspensa vai direto à
    // espera, sem passar pela fila. Pronta antes e suspensa depois, um AP
    // ocioso acordado pela prontidão a escolhia no meio e executava o
    // começo dela no anel 3 antes da retomada (no 19041 a thread criada
    // suspensa só entrega a APC de suspensão e espera).
    thread_dispatch::with_queues(|queues| {
        let suspended = thread.with(|thread| {
            thread.scheduling_registered = true;
            thread.suspend_count != 0
        });
        if suspended {
            queues.suspend(pointer, thread_dispatch::state::WAITING)
        } else {
            queues.make_ready(pointer)
        }
    })
}

/// Sonda as esperas das threads de usuário de todos os processos que
/// entraram no despachante e põe na fila as prontas. Uma thread bloqueada no
/// kernel é sondada mesmo suspensa ou terminada (inclusive depois do término
/// do processo dela): o serviço precisa concluir (a suspensão vale na volta
/// ao anel 3; a terminada é retomada por [`resume_terminated`]). A sondagem
/// roda no contexto da thread (thread corrente e raiz dela); quem chama
/// restaura a dele.
fn refresh_ready_user_threads() {
    if !poll_due() {
        dispatch_perf::POLLS_SKIPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let started = crate::hal::cpu::rdtsc();
    let loads = dispatch_perf::CR3_LOADS.load(Ordering::Relaxed);
    poll_user_waits();
    dispatch_perf::SWITCHES.fetch_add(dispatch_perf::CR3_LOADS.load(Ordering::Relaxed).wrapping_sub(loads), Ordering::Relaxed);
    dispatch_perf::REFRESH.add_since(started);
}

/// O corpo de [`refresh_ready_user_threads`].
fn poll_user_waits() {
    // A época antes da sondagem: o que despertar durante ou depois dela faz a
    // próxima saída de serviço passar pelo despachante.
    POLLED_EPOCH.store(dispatcher::wake_epoch(), Ordering::Release);
    POLLED_TICK.store(crate::nano::interrupts::tick_count(), Ordering::Relaxed);
    let mut candidates: Vec<Arc<UserThread>> = all()
        .into_iter()
        .filter(|thread| {
            let (runnable, blocked, process) = thread.with(|thread| (!thread.dead && thread.suspend_count == 0, matches!(thread.kernel, KernelState::Blocked { .. }), thread.process_pointer));
            blocked || (runnable && process_started(process))
        })
        .collect();
    // Pela prioridade e, entre as de mesma prioridade, pelo processo: as
    // sondagens seguidas do mesmo processo não recarregam o CR3 (sem PCID nem
    // páginas globais, cada carga esvazia o TLB, também o do kernel).
    candidates.sort_by_cached_key(|thread| (core::cmp::Reverse(thread_priority::query_priority(thread.pointer())), thread.with(|thread| thread.process_pointer)));
    for candidate in candidates {
        let pointer = candidate.pointer();
        // A thread que outra CPU executa, reservou ou sonda fica para a
        // próxima sondagem: só a dona mexe na espera dela.
        let Some(borrow) = thread_dispatch::try_borrow(pointer) else {
            dispatch_perf::BORROWS_REFUSED.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        apply_deferred_termination(&candidate);
        match poll_installed(&candidate) {
            Polled::Waiting => {}
            // A registrada concluída volta à fila direto.
            Polled::Settled => {
                let _ = thread_dispatch::make_ready(pointer);
            }
            Polled::Free => {
                // O despacho de usuário só roda fora de qualquer intervalo: uma
                // thread de usuário Running que não está numa CPU é um estado
                // restaurado por engano, e o `make_ready` a pularia para sempre.
                if thread_dispatch::thread_state(pointer) == thread_dispatch::state::RUNNING && !thread_dispatch::on_processor(pointer) {
                    crate::debug_print!("[thread] tid={} pronta com KTHREAD.State Running fora da CPU; volta a Waiting para entrar na fila", candidate.thread_id);
                    let _ = thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING);
                }
                let _ = thread_dispatch::make_ready(pointer);
            }
        }
        thread_dispatch::release_borrow(borrow);
    }
}

/// O término pedido enquanto outra CPU era dona da thread
/// (`deferred_termination`), aplicado por quem agora é dono dela (a CPU no
/// fim do intervalo, ou a sondagem com a thread emprestada): a espera
/// instalada conclui com STATUS_THREAD_IS_TERMINATING, como o término teria
/// feito na hora com a thread fora da CPU. `true` se uma espera concluiu.
fn apply_deferred_termination(thread: &UserThread) -> bool {
    let Some(any_wait) = thread.with(|thread| thread.deferred_termination.take()) else { return false };
    let Some(wait) = thread.take_wait() else { return false };
    if any_wait || !wait.kernel {
        finish_wait(thread, wait, THREAD_IS_TERMINATING);
        true
    } else {
        thread.restore_wait(wait);
        false
    }
}

/// O desfecho de [`poll_installed`].
enum Polled {
    /// A espera continua instalada.
    Waiting,
    /// A espera registrada concluiu (ou a acordada sondou e concluiu).
    Settled,
    /// A thread ficou sem espera: concluída pela sondagem, ou sem espera.
    Free,
}

/// Sonda a espera instalada de `candidate` (com ela como thread corrente
/// quando a sondagem precisa do contexto dela; quem chama restaura a dele) e
/// a conclui se terminou. A registrada não é sondada: só o desfecho, e a
/// conclusão (ou a sondagem de uma acordada) no contexto da thread.
fn poll_installed(candidate: &Arc<UserThread>) -> Polled {
    let pointer = candidate.pointer();
    let Some(mut wait) = candidate.take_wait() else {
        return if candidate.waiting() { Polled::Waiting } else { Polled::Free };
    };
    if wait.registered.is_some() {
        if !registered_done(&wait) {
            // Uma acordada sem saída há WOKEN_BACKSTOP_MS sonda mesmo
            // assim: uma mudança que não acordou ninguém espera no máximo
            // isso.
            if !woken_backstop_due(&wait) {
                candidate.restore_wait(wait);
                return Polled::Waiting;
            }
            process::set_current_thread(pointer);
            return match woken_backstop(&mut wait) {
                Some(status) => {
                    finish_wait(candidate, wait, status);
                    Polled::Settled
                }
                None => {
                    candidate.restore_wait(wait);
                    Polled::Waiting
                }
            };
        }
        process::set_current_thread(pointer);
        return match settle_registered(&mut wait, true) {
            Some(status) => {
                finish_wait(candidate, wait, status);
                Polled::Settled
            }
            None => {
                candidate.restore_wait(wait);
                Polled::Waiting
            }
        };
    }
    dispatch_perf::POLLS.fetch_add(1, Ordering::Relaxed);
    let outcome = match poll_delay(&wait) {
        Some(outcome) => outcome,
        None => {
            process::set_current_thread(pointer);
            poll_wait(&mut wait)
        }
    };
    match outcome {
        None => {
            candidate.restore_wait(wait);
            Polled::Waiting
        }
        Some(status) => {
            process::set_current_thread(pointer);
            finish_wait(candidate, wait, status);
            Polled::Free
        }
    }
}

/// [`poll_installed`] de uma thread só (a sondagem do refresh): `true` se a
/// thread ficou sem espera.
pub fn poll_installed_wait(candidate: &Arc<UserThread>) -> bool {
    !matches!(poll_installed(candidate), Polled::Waiting)
}

/// Uma thread de usuário pronta que não pode voltar ao anel 3: com a espera
/// de usuário ainda instalada (o KeAlertThread a pôs na fila) ou suspensa.
/// No 19041 o KiUnwaitThread termina a espera e a APC de suspensão roda
/// antes do anel 3 (KeAlertThread 0x35be90), então ela nunca volta ao modo
/// usuário com a espera pela metade. Volta a Waiting e `true`; a sondagem
/// seguinte termina a espera.
pub fn hold_before_ring3(thread: &UserThread) -> Result<bool, KernelError> {
    let (pointer, held) = thread.with(|thread| (thread.thread_pointer, thread.waiting || thread.suspend_count != 0));
    if held {
        thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING)?;
    }
    Ok(held)
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
        && !context_switch::in_kernel_thread()
        && irql::get_irql() == irql::PASSIVE_LEVEL
        && sync::spin_locks_held() == 0
        && sync::shared_locks_held() == 0
        && !DISPATCHING[0].load(Ordering::Acquire)
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
    if !APC_PUMP_REGISTERED.swap(true, Ordering::AcqRel) {
        dispatcher::register_completion_pump(drain_kernel_apcs);
    }
    // O diagnóstico de falha (post-mortem) começa limpo para o processo novo,
    // antes de a thread poder rodar (num AP, assim que entra na fila).
    crate::hal::amd64::usermode::reset_fault_state();
    // A thread entra na fila no fim, com o processo já dado como iniciado.
    prepare_main(thread, rip, rsp, argument, ntdll_base)
}

/// Põe a thread principal no despachante e espera o fim do processo dela
/// ([`start`] e [`wait_for_process`]); devolve o status de saída.
pub fn run(thread: &Arc<UserThread>, rip: u64, rsp: u64, argument: u64, ntdll_base: u64) -> Result<u32, KernelError> {
    start(thread, rip, rsp, argument, ntdll_base)?;
    wait_for_process(thread.with(|thread| thread.process_pointer))
}

/// Um intervalo de usuário de qualquer processo: roda os pumps do kernel e
/// dos objetos de usuário, sonda as esperas de todas as threads, retoma as
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
    // O despacho de usuário é do despachante da CPU, nunca da pilha de uma
    // thread de kernel.
    if context_switch::in_kernel_thread() {
        return Ok(Dispatched::Idle);
    }
    if DISPATCHING[0].swap(true, Ordering::AcqRel) {
        return Ok(Dispatched::Idle);
    }
    let started = crate::hal::cpu::rdtsc();
    let caller = process::get_current_thread();
    let result = dispatch_from(executor, caller);
    process::set_current_thread(caller);
    *CURRENT[0].lock() = None;
    DISPATCHING[0].store(false, Ordering::Release);
    dispatch_perf::DISPATCH.add_since(started);
    result
}

/// Sonda as esperas das threads de usuário paradas e põe na fila de
/// despacho as que concluíram, sem dar intervalo a ninguém. O tick chama a
/// cada volta: quando todas as threads de usuário esperam, nenhuma está na
/// fila para o [`dispatch_one`] sondar as outras, e a condição que uma delas
/// espera pode ter sido produzida por quem acabou de parar (um pedido ALPC
/// posto na IOCP do servidor por um cliente que em seguida espera a
/// resposta). Mesmas condições do despacho; um despacho em curso já sonda.
/// Uma espera que gira no BSP dentro do despacho (o fim de um processo que,
/// no callout do win32k, disputa a trava do user): com o despacho em várias
/// CPUs, as esperas das threads de usuário são sondadas mesmo assim. A dona
/// da trava pode estar parada numa espera que só a sondagem do BSP conclui,
/// e pronta ela roda num AP; sem a sondagem, o BSP girava para sempre (a
/// guarda do despacho em curso barra o `refresh_waiting`).
pub fn poll_while_spinning() {
    static POLLING: AtomicBool = AtomicBool::new(false);
    if !thread_dispatch::concurrent() || cpu() != 0 || !DISPATCHING[0].load(Ordering::Acquire) || POLLING.swap(true, Ordering::AcqRel) {
        return;
    }
    let caller = process::get_current_thread();
    poll_user_waits();
    process::set_current_thread(caller);
    POLLING.store(false, Ordering::Release);
}

pub fn refresh_waiting() {
    if !can_dispatch() || DISPATCHING[0].swap(true, Ordering::AcqRel) {
        return;
    }
    let caller = process::get_current_thread();
    serve_exit_requests(caller);
    refresh_ready_user_threads();
    process::set_current_thread(caller);
    DISPATCHING[0].store(false, Ordering::Release);
}

/// O corpo de [`dispatch_one`], com o despacho já marcado como em curso.
fn dispatch_from(executor: fn(u64, u64) -> u32, caller: u64) -> Result<Dispatched, KernelError> {
    // Os pumps sem o tick do escalonador: o despacho roda dentro do tick,
    // que já alterna as threads de kernel e as de usuário pela prioridade.
    let started = crate::hal::cpu::rdtsc();
    serve_exit_requests(caller);
    dispatcher::pump_kernel_work();
    let pumps = *PUMPS.lock();
    for routine in pumps.into_iter().flatten() {
        routine();
    }
    dispatch_perf::PUMPS.add_since(started);
    // Uma sondagem só, depois dos pumps e antes da escolha: o tique sondou
    // no começo dele e depois de cada intervalo que deixou a fila vazia, e o
    // que os pumps concluírem entra nela também.
    refresh_ready_user_threads();
    process::set_current_thread(caller);
    let started = crate::hal::cpu::rdtsc();
    resume_terminated(executor, caller)?;
    finish_pending_exits(true);
    dispatch_perf::EXITS.add_since(started);
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
        let Some((process, kernel)) = admit(&next, pointer, caller)? else { continue };
        dispatch_perf::slice_begin(next.thread_id, process);
        let started = crate::hal::cpu::rdtsc();
        let dispatched = run_slice(&next, process, kernel, executor, caller);
        dispatch_perf::SLICE.add_since(started);
        dispatch_perf::slice_end(next.thread_id, started);
        return Ok(dispatched);
    }
    Ok(Dispatched::Idle)
}

/// As conferências da thread escolhida e reservada nesta CPU, antes do
/// intervalo: o processo dela e onde está o fluxo de kernel, ou `None`
/// quando ela não roda agora (voltou a esperar, terminou, está suspensa).
fn admit(next: &Arc<UserThread>, pointer: u64, caller: u64) -> Result<Option<(u64, KernelState)>, KernelError> {
    // Na fila com a espera ainda instalada: a registrada que o sinal
    // satisfez conclui aqui, no contexto da thread (o status vai ao
    // CONTEXT, ou à retomada do serviço bloqueado); a que segue (uma
    // acordada sem conclusão, ou a thread aprontada por fora da espera)
    // volta a esperar.
    if next.waiting() {
        process::set_current_thread(pointer);
        let settled = settle(next);
        process::set_current_thread(caller);
        if !settled {
            thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING)?;
            return Ok(None);
        }
    }
    let (dead, process) = next.with(|thread| (thread.dead, thread.process_pointer));
    let kernel = next.kernel_state();
    // Bloqueada no kernel com a espera ainda pendente (um alerta a
    // pôs na fila antes da sondagem): volta a esperar.
    if kernel == (KernelState::Blocked { status: None }) {
        thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING)?;
        return Ok(None);
    }
    if kernel == KernelState::User {
        // Terminada, ou de um processo que não entrou no despachante
        // (ou já saiu dele): sai da fila de prontas sem rodar.
        if dead {
            thread_dispatch::suspend(pointer, thread_dispatch::state::TERMINATED)?;
            return Ok(None);
        }
        // Suspensa (o sinal de uma espera registrada apronta mesmo a
        // suspensa) ou com a espera instalada: a retomada (ou a
        // sondagem) a põe na fila de novo.
        if hold_before_ring3(next)? {
            return Ok(None);
        }
        if !process_started(process) {
            thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING)?;
            return Ok(None);
        }
    }
    Ok(Some((process, kernel)))
}

/// O despacho de usuário de um AP (o KiIdleLoop dele, com a escolha do
/// KiSelectNextThread 0x2568ec): a pronta de usuário mais prioritária que
/// esta CPU pode rodar (`thread_dispatch::peek_for`) ganha um intervalo. Os
/// pumps, as sondagens das esperas, os fins de processo e o recolhimento das
/// threads continuam no BSP: o que o intervalo pede a ele vai a
/// [`EXIT_REQUESTS`], e ele é acordado. `Idle` sem nenhuma pronta.
pub fn dispatch_on_processor() -> Result<Dispatched, KernelError> {
    let Some(executor) = *EXECUTOR.lock() else { return Ok(Dispatched::Idle) };
    let cpu = cpu();
    if cpu == 0 || DISPATCHING[cpu].swap(true, Ordering::AcqRel) {
        return Ok(Dispatched::Idle);
    }
    thread_dispatch::clear_kick();
    let caller = process::get_current_thread();
    let result = dispatch_processor_from(cpu, executor, caller);
    process::set_current_thread(caller);
    *CURRENT[cpu].lock() = None;
    DISPATCHING[cpu].store(false, Ordering::Release);
    result
}

/// O corpo de [`dispatch_on_processor`].
fn dispatch_processor_from(cpu: usize, executor: fn(u64, u64) -> u32, caller: u64) -> Result<Dispatched, KernelError> {
    for _ in 0..DISCARD_LIMIT {
        let Some((pointer, owner)) = thread_dispatch::peek_for(cpu, true)? else { return Ok(Dispatched::Idle) };
        if owner.runtime & thread_dispatch::USER_RUNTIME == 0 {
            thread_dispatch::unreserve(pointer);
            return Ok(Dispatched::Idle);
        }
        let Some(next) = find_by_pointer(pointer) else {
            thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING)?;
            continue;
        };
        let Some((process, kernel)) = admit(&next, pointer, caller)? else { continue };
        deliver_owned_apcs(&next, pointer, kernel, caller);
        let started = crate::hal::cpu::rdtsc();
        let dispatched = run_slice_on_processor(&next, process, kernel, executor, caller);
        dispatch_perf::PROCESSOR_SLICES.add_since(started);
        return Ok(dispatched);
    }
    Ok(Dispatched::Idle)
}

/// As APCs de kernel da thread escolhida por um AP, entregues por ele, dono
/// dela, no contexto dela antes do intervalo (o KiSignalThreadForApc 0x3436d0
/// manda o processador da thread entregá-las): as conclusões de E/S que só o
/// contexto dela termina e as APCs da fila de kernel, como o
/// [`drain_kernel_apcs`] do BSP faz com as threads fora da CPU.
fn deliver_owned_apcs(thread: &UserThread, pointer: u64, kernel: KernelState, caller: u64) {
    if !crate::ntos::ke::thread_apcs_pending(pointer) && !crate::ntos::io::file::request::has_completions_for(pointer) {
        return;
    }
    // Bloqueada no kernel acima de PASSIVE_LEVEL: as APCs esperam a retomada.
    if kernel != KernelState::User && kernel_thread(pointer).wait_irql.get() != irql::PASSIVE_LEVEL {
        return;
    }
    if thread.dead() || irql::get_irql() != irql::PASSIVE_LEVEL {
        return;
    }
    process::set_current_thread(pointer);
    crate::ntos::io::file::request::pump();
    let _ = apc::deliver_all_queued();
    process::set_current_thread(caller);
}

/// O status de saída de um processo cujo despacho falhou.
fn dispatch_failure(error: &KernelError) -> u32 {
    if error.status != 0 { error.status } else { 0xC000_0001 }
}

/// O intervalo de `next` (do processo `process`), escolhido por
/// [`dispatch_from`], e o que vem depois dele.
fn run_slice(next: &Arc<UserThread>, process: u64, kernel: KernelState, executor: fn(u64, u64) -> u32, caller: u64) -> Dispatched {
    let pointer = next.pointer();
    let (exit, kind) = run_interval(next, kernel, executor);
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

/// O intervalo de `next` escolhido por um AP ([`dispatch_on_processor`]):
/// como [`run_slice`], mas o fim do processo pedido no intervalo, os fins
/// adiados e o recolhimento das threads mortas vão ao BSP
/// ([`EXIT_REQUESTS`]), que é acordado.
fn run_slice_on_processor(next: &Arc<UserThread>, process: u64, kernel: KernelState, executor: fn(u64, u64) -> u32, caller: u64) -> Dispatched {
    let pointer = next.pointer();
    let (exit, kind) = run_interval(next, kernel, executor);
    process::set_current_thread(caller);
    let finished = next.dead() || exit_pending(process) || process::with_record(process, |record| record.terminated || record.exiting) == Some(true);
    if exit.is_some() || finished {
        EXIT_REQUESTS.lock().push((process, exit));
        thread_dispatch::wake_processor(0);
    }
    kernel_stack::reap();
    Dispatched::Ran { thread: pointer, exit_kind: kind }
}

/// O intervalo da thread escolhida nesta CPU, que quem chama já conferiu
/// ([`admit`]): a entrega das APCs de usuário, a execução e o tratamento da
/// saída. Devolve o status do fim do processo, quando o intervalo o pediu, e
/// o tipo de saída.
fn run_interval(next: &Arc<UserThread>, kernel: KernelState, executor: fn(u64, u64) -> u32) -> (Option<u32>, u32) {
    let pointer = next.pointer();
    *CURRENT[cpu()].lock() = Some(next.clone());
    process::set_current_thread(pointer);
    process::dispatch_thread(pointer);
    // Retorno ao modo usuário (o KiInitiateUserApc do
    // KiSystemServiceExit/KiExceptionExit): com UserApcPending ou
    // SpecialUserApcPending, o frame do KiUserApcDispatcher é montado antes
    // de retomar o CONTEXT salvo. Uma thread retomada no kernel ainda está
    // no serviço: as APCs de usuário esperam a volta ao anel 3. A APC de
    // término vem antes de todas e não volta ao anel 3 (`execute`).
    let mut exit = None;
    let mut kind = 0;
    if kernel == KernelState::User && !next.termination_deliverable() {
        let undeliverable = super::user_apc::deliver(next);
        if undeliverable != 0 {
            exit = Some(undeliverable);
        }
    }
    if exit.is_none() {
        match execute(next, executor) {
            Ok((status, exit_kind, failed)) => {
                kind = exit_kind;
                if exit_kind == 0 {
                    // NtTerminateProcess do próprio processo (ou uma exceção
                    // de segunda chance): o intervalo acabou de vez.
                    exit = Some(status);
                } else if failed != 0 {
                    exit = Some(failed);
                }
            }
            Err(error) => {
                crate::debug_print!("[thread] tid={} despacho falhou: {}", next.thread_id, error);
                exit = Some(dispatch_failure(&error));
            }
        }
    }
    (exit, kind)
}

/// Os pedidos dos intervalos dos APs ([`EXIT_REQUESTS`]), no BSP: o fim do
/// processo que o intervalo pediu, os fins adiados e o recolhimento das
/// threads mortas, como o [`run_slice`] faz depois de um intervalo dele.
fn serve_exit_requests(caller: u64) {
    let requests = core::mem::take(&mut *EXIT_REQUESTS.lock());
    if requests.is_empty() {
        return;
    }
    for &(process, status) in &requests {
        if let Some(status) = status {
            // O fim já começou no AP (`execute`): só a conclusão, quando as
            // threads permitem.
            if !crate::ntos::ps::create::exit_process(process, status) && exit_ready(process) {
                crate::ntos::ps::create::finish_exit(process);
            }
        }
    }
    finish_pending_exits(false);
    let mut released: Vec<u64> = Vec::new();
    for &(process, _) in &requests {
        if !released.contains(&process) {
            released.push(process);
            release_finished(process);
        }
    }
    process::set_current_thread(caller);
    kernel_stack::reap();
}

/// Recolhe as threads mortas de `process` que não têm mais serviço suspenso
/// no kernel (a pilha de uma bloqueada só volta depois que o serviço dela é
/// desfeito) e, se o processo já terminou (a última thread saiu dentro do
/// intervalo, pelo NtTerminateThread), o que restou dele.
fn release_finished(process: u64) {
    for finished in of_process(process) {
        if finished.dead() && !finished.blocked_in_kernel() && owned_elsewhere(&finished).is_none() {
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
    if DISPATCHING[cpu()].load(Ordering::Acquire) {
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
        // Uma thread de kernel não despacha usuário na própria pilha: sai das
        // prontas até o fim do processo, e o despachante da CPU roda as
        // threads dele.
        if context_switch::in_kernel_thread() {
            context_switch::wait_until(&mut || matches!(progress(process), Progress::Done).then_some(0), dispatcher::pump_kernel);
            continue;
        }
        if let Err(error) = dispatch_round() {
            break Err(error);
        }
    };
    let _ = process::dereference(process);
    result
}

/// Uma volta do despachante para quem espera fora do tick (o contexto de
/// boot em [`wait_for_process`], os autotestes): um despacho de usuário
/// ([`dispatch_one`]) e os passos das threads de kernel prontas que o tick
/// daria (`scheduler::tick(0)`, sem intervalo de usuário), já que o despacho
/// não aninha o tick.
pub fn dispatch_round() -> Result<Dispatched, KernelError> {
    let dispatched = dispatch_one()?;
    crate::ntos::ps::scheduler::tick(0);
    Ok(dispatched)
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
/// serviço na pilha dela (`context_switch::switch_to`). Com o término pedido
/// ela não volta ao anel 3: a APC de término é entregue nesta volta ao modo
/// usuário e o PspExitThread roda na pilha de kernel dela
/// (`usermode::exec_kernel_routine`, o KiSchedulerApcTerminate). Devolve o
/// resultado e o tipo da saída.
fn execute(thread: &Arc<UserThread>, executor: fn(u64, u64) -> u32) -> Result<(u32, u32, u32), KernelError> {
    let pointer = thread.pointer();
    let cpu = cpu();
    let kernel_before = process::thread_kernel_time(pointer);
    let started = clock::uptime_ms();
    thread_dispatch::begin_execution(pointer)?;
    // O intervalo do despachante em curso: só as saídas de serviço dele podem
    // voltar direto ao anel 3 (`may_return_to_user`), até o próximo tique do
    // timer desta CPU.
    let mark_slice = || {
        SLICE_TICK[cpu].store(crate::nano::interrupts::processor_tick_count(), Ordering::Relaxed);
        SLICE_THREAD[cpu].store(pointer, Ordering::Release);
    };
    let status = if thread.blocked_in_kernel() {
        mark_slice();
        context_switch::switch_to(thread)
    } else if thread.termination_deliverable() {
        let (context, teb) = thread.with(|thread| (thread.context, thread.teb_va));
        crate::hal::amd64::usermode::exec_kernel_routine(context, teb, termination_entry, 0)
    } else {
        let (context, teb) = thread.with(|thread| (thread.context, thread.teb_va));
        mark_slice();
        executor(context, teb)
    };
    SLICE_THREAD[cpu].store(0, Ordering::Release);
    let exit_kind = crate::hal::amd64::usermode::block().exit_kind.get();
    // A captura de chamada e as exceções do intervalo (#DB próprio do usuário
    // ou pendente, a falta de página), tratadas com a thread ainda Running
    // nesta CPU, como o KiDispatchException do 19041 roda no contexto da
    // thread antes de qualquer troca: a entrega escreve na pilha e no CONTEXT
    // dela, que outra CPU não pode tomar no meio. Um bloqueio não é saída do
    // serviço. Devolve o status fatal, se a entrega falhou.
    let failed = if exit_kind != 0 && exit_kind != EXIT_BLOCKED && exit_kind != EXIT_THREAD_EXITED {
        let handler = *EXIT_HANDLER.lock();
        match handler {
            Some(handler) => handler(thread, exit_kind, status),
            None if exit_kind == 3 => status,
            None => 0,
        }
    } else {
        0
    };
    // O fim do processo pedido no intervalo de um AP (o NtTerminateProcess
    // da própria thread, ou a exceção fatal) é feito pelo BSP
    // (EXIT_REQUESTS), mas o pedido vale já, antes de a thread deixar a CPU:
    // senão ela voltava à fila, outra CPU a escolhia e ela seguia no anel 3
    // depois de um NtTerminateProcess que não volta no 19041 (o int3 do smss
    // depois do fim dele). As threads do processo recebem o término aqui; o
    // BSP só conclui o fim.
    if cpu != 0 {
        let fatal = if exit_kind == 0 { Some(status) } else { (failed != 0).then_some(failed) };
        if let Some(fatal) = fatal {
            let process = thread.with(|thread| thread.process_pointer);
            crate::ntos::ps::create::begin_termination(process, fatal);
            begin_exit(process, fatal);
        }
    }
    // Um término pedido por outra CPU durante o intervalo: a espera que ele
    // concluiria conclui agora, pela dona.
    apply_deferred_termination(thread);
    // A espera adiada que o serviço instalou liga os blocos agora, com o
    // serviço concluído e a thread ainda corrente (a sondagem de uma acordada
    // roda no contexto dela): concluída ali mesmo, a thread volta à fila.
    if let Some(mut wait) = thread.take_wait() {
        if wait.registered.as_ref().is_some_and(|registered| registered.serial == 0) {
            match settle_registered(&mut wait, false) {
                Some(status) => finish_wait(thread, wait, status),
                None => thread.restore_wait(wait),
            }
        } else {
            thread.restore_wait(wait);
        }
    }
    // O estado novo sai do que a thread pede (morta, esperando, suspensa)
    // lido sob o PrcbLock, no mesmo trecho em que ela deixa de estar Running:
    // uma retomada ou uma conclusão de outra CPU antes disso é vista aqui, e
    // uma depois encontra a thread fora da CPU e a põe na fila.
    let mut observed = (false, false, false, false);
    thread_dispatch::end_execution_with(pointer, || {
        observed = thread.with(|thread| (thread.dead, thread.waiting, thread.suspend_count != 0, thread.wait.as_ref().is_some_and(|wait| wait.registered.is_some())));
        let (dead, waiting, suspended, _) = observed;
        if dead {
            thread_dispatch::state::TERMINATED
        } else if waiting || suspended {
            thread_dispatch::state::WAITING
        } else {
            thread_dispatch::state::READY
        }
    })?;
    let (dead, waiting, suspended, registered) = observed;
    // O término pedido entre a primeira conferência e a decisão: a espera
    // conclui agora, com a thread já fora da CPU, e uma viva volta à fila.
    if thread.with(|thread| thread.deferred_termination.is_some()) && apply_deferred_termination(thread) && !dead {
        thread_dispatch::make_ready(pointer)?;
    }
    // O KiCommitThreadWait, com a thread já Waiting e fora da CPU (como o
    // `scheduler::run_step` das threads de kernel): a espera registrada passa
    // a WaitCommitted e o sinal seguinte a apronta. A que já saiu antes
    // (WaitAborted: satisfeita dentro do próprio intervalo, ou um alerta
    // pendente) volta à fila aqui, e o despachante leva o status ao CONTEXT
    // ao escolhê-la.
    if !dead && waiting && registered && !crate::ntos::ke::wait::commit_user_wait(pointer) && !suspended {
        thread_dispatch::make_ready(pointer)?;
    }
    let elapsed = (clock::uptime_ms() - started) * 10_000;
    let kernel = process::thread_kernel_time(pointer).saturating_sub(kernel_before);
    process::account_thread(pointer, false, elapsed.saturating_sub(kernel));
    Ok((status, exit_kind, failed))
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
        if owned_elsewhere(&thread).is_some() {
            continue;
        }
        *CURRENT[cpu()].lock() = Some(thread.clone());
        process::set_current_thread(thread.pointer());
        let outcome = execute(&thread, executor);
        process::set_current_thread(caller);
        let (status, kind, _) = outcome?;
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

/// Quanto um fim de processo adiado espera as threads que rodam o próprio
/// PspExitThread (as com estado do win32k) antes do aviso. O término não
/// roda antes delas: o PspExitThread da última thread do 19041
/// (0x6c3af1..0x6c3c83) espera, sem prazo, o objeto de cada outra thread
/// antes do próprio callout de thread e do callout de processo.
const UNWIND_TIMEOUT_MS: u64 = 10_000;

/// Um fim de processo pedido e ainda não concluído.
struct PendingExit {
    process: u64,
    status: u32,
    /// Voltas do despachante desde o pedido.
    rounds: usize,
    /// Uptime (ms) do pedido.
    since: u64,
    /// O término já está rodando: um despacho aninhado nele (uma espera do
    /// término que gira o pump) não o recomeça.
    finishing: bool,
    /// O aviso de término demorado já saiu.
    warned: bool,
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

/// O lado das threads do fim de um processo (o PspTerminateAllThreads antes
/// do término): o pedido fica registrado com o status (o primeiro vence) e
/// retém o EPROCESS. Uma thread com estado do win32k recebe o pedido de
/// término do 19041 ([`request_termination`]) e sai sozinha, no contexto
/// dela; a última a sair conclui o fim do processo. As demais morrem com o
/// status: a espera instalada conclui com THREAD_IS_TERMINATING (a de uma
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
        exiting.push(PendingExit { process, status, rounds: 0, since: clock::uptime_ms(), finishing: false, warned: false });
    }
    dispatcher::note_wake();
    process::reference(process);
    for thread in of_process(process) {
        if exits_in_own_context(&thread) {
            request_termination(&thread, status);
            continue;
        }
        // A thread que outra CPU executa (ou sonda) só morre aqui: a dona
        // conclui a espera dela e a tira da fila no fim do intervalo.
        let borrow = thread_dispatch::try_borrow(thread.pointer());
        if borrow.is_some() {
            if let Some(wait) = thread.take_wait() {
                finish_wait(&thread, wait, THREAD_IS_TERMINATING);
            }
        }
        let (pointer, registered) = thread.with(|thread| {
            thread.dead = true;
            if thread.exit_status == PENDING {
                thread.exit_status = status;
            }
            if borrow.is_none() {
                thread.deferred_termination = Some(true);
            }
            (thread.thread_pointer, thread.scheduling_registered)
        });
        match borrow {
            Some(borrow) => {
                if registered && pointer != 0 && thread_dispatch::thread_state(pointer) != thread_dispatch::state::RUNNING {
                    let _ = thread_dispatch::suspend(pointer, thread_dispatch::state::TERMINATED);
                }
                thread_dispatch::release_borrow(borrow);
            }
            None => {
                if let Some(owner) = thread_dispatch::owned_elsewhere(pointer) {
                    thread_dispatch::kick_processor(owner);
                }
            }
        }
    }
    true
}

/// O término de um processo com o fim pedido já pode rodar: nenhuma thread
/// dele tem serviço suspenso no kernel nem o próprio término por rodar, e o
/// intervalo em curso nesta CPU, se houver, não é de uma delas.
pub fn exit_ready(process: u64) -> bool {
    let in_slice = crate::hal::amd64::usermode::in_service() && current().is_some_and(|thread| thread.with(|thread| thread.process_pointer) == process);
    !in_slice && !of_process(process).iter().any(|thread| thread.blocked_in_kernel() || thread.termination_pending() || owned_elsewhere(thread).is_some())
}

/// O aviso de um término que segura o fim do processo: onde a thread está,
/// a última espera publicada na KTHREAD (WaitMode, Alertable, WaitReason e o
/// objeto do primeiro KWAIT_BLOCK com o DISPATCHER_HEADER.Type; numa espera
/// só por sondagem esses campos são de uma espera anterior) e, se ela deixou
/// a CPU dentro de um export chamado por código nativo (o win32k no callout
/// de saída), o export, quem o chamou e os quadros nativos.
fn describe_unfinished_exit(thread: &UserThread, process: u64) {
    let (exit_running, kernel) = thread.with(|thread| (thread.exit_running, thread.kernel));
    let pointer = thread.pointer();
    if pointer == 0 {
        crate::debug_print!("[thread] processo {:#x}: tid={} ainda sem o proprio termino (sem KTHREAD); o termino espera", process, thread.thread_id);
        return;
    }
    let tcb = kernel_thread(pointer);
    let block = tcb.wait_block_list.get();
    // SAFETY: a KWAIT_BLOCK da última espera publicada na KTHREAD viva.
    let object = if block != 0 { unsafe { KwaitBlock::at(block) }.object.get() } else { 0 };
    let kind = if object != 0 { guest::read8(object) } else { 0xFF };
    crate::debug_print!(
        "[thread] processo {:#x}: tid={} ainda sem o proprio termino (PspExitThread em curso={}, servico={:?}, estado={}, WaitMode={}, Alertable={}, WaitReason={}, objeto={:#x} tipo={}); o termino espera",
        process,
        thread.thread_id,
        exit_running,
        kernel,
        thread_dispatch::thread_state(pointer),
        tcb.wait_mode.get(),
        tcb.alertable(),
        tcb.wait_reason.get(),
        object,
        kind
    );
    if matches!(kernel, KernelState::Blocked { .. }) {
        if let Some(context) = crate::ntos::rtl::native_context::context_on_stack(tcb.kernel_stack.get()) {
            crate::ntos::ke::bugcheck_trace::describe_native_call(&alloc::format!("[thread] tid={}", thread.thread_id), context);
        }
    }
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
/// chamada é a de uma volta) só com threads mortas presas num serviço que
/// nunca deixa o kernel conclui mesmo assim, com o aviso: a thread presa fica
/// no índice. Enquanto uma thread dele ainda tem o próprio término por
/// rodar, o término espera, sem prazo, como o PspExitThread do 19041
/// (0x6c3c61); passado [`UNWIND_TIMEOUT_MS`] sai um aviso, uma vez.
fn finish_pending_exits(count_round: bool) {
    if crate::hal::amd64::usermode::in_service() {
        return;
    }
    let due: Vec<(u64, u64, bool)> = {
        let mut exiting = EXITING.lock();
        if count_round {
            exiting.iter_mut().for_each(|pending| pending.rounds += 1);
        }
        exiting.iter().filter(|pending| !pending.finishing && pending.rounds > UNWIND_ROUNDS).map(|pending| (pending.process, pending.since, pending.warned)).collect()
    };
    let now = clock::uptime_ms();
    for (process, since, warned) in due.iter().copied() {
        let threads = of_process(process);
        // Uma thread que roda ou vai rodar o próprio PspExitThread segura o
        // término: o callout de processo do win32k (o DestroyProcessInfo solta
        // o ppi->rpwinsta) não pode vir antes do callout de thread dela.
        let exiting_alone: Vec<&Arc<UserThread>> = threads.iter().filter(|thread| thread.termination_pending()).collect();
        if !exiting_alone.is_empty() {
            if !warned && now.saturating_sub(since) >= UNWIND_TIMEOUT_MS {
                if let Some(pending) = EXITING.lock().iter_mut().find(|pending| pending.process == process) {
                    pending.warned = true;
                }
                for thread in exiting_alone {
                    describe_unfinished_exit(thread, process);
                }
            }
            continue;
        }
        let left = threads.iter().filter(|thread| thread.blocked_in_kernel()).count();
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
    // Uma espera registrada ainda ligada (concluída de fora: o término, o fim
    // do processo) sai dos objetos com o status.
    if let Some(registered) = wait.registered.as_mut() {
        if registered.serial != 0 {
            crate::ntos::ke::wait::cancel_user_wait(registered.thread, registered.serial, status);
            registered.serial = 0;
        }
    }
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

/// A sondagem de um NtDelayExecution que já foi sondado uma vez (os alertas
/// armados para a thread dele): o mesmo que [`poll_wait`] faz nele, mas sem o
/// contexto da thread, porque nada ali lê a memória do processo (o alerta e
/// as APCs são conferidos pelo ponteiro da thread). `None` = a espera não é
/// dessas e precisa do contexto.
fn poll_delay(wait: &Wait) -> Option<Option<u32>> {
    if !wait.delay || wait.alert.is_some() {
        return None;
    }
    let alerts = wait.alerts.as_ref()?;
    if let Some(interrupted) = alerts.pending() {
        return Some(Some(interrupted));
    }
    Some((clock::uptime_ms() >= wait.deadline.unwrap_or(0)).then_some(0))
}

fn poll_wait(wait: &mut Wait) -> Option<u32> {
    // A registrada da thread corrente, ainda na CPU (o laço de um callback):
    // o desfecho, e numa acordada que não concluiu, os blocos de novo (a
    // thread deixa a CPU em seguida e a saída do intervalo confirma).
    if wait.registered.is_some() {
        return settle_registered(wait, false);
    }
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
    // A registrada tem os alertas e as APCs pelo despachante (`ke::wait`).
    let registered = wait.registered.is_some();
    if !registered {
        if let Some(alerts) = wait.alerts.as_mut() {
            let _ = alerts.arm();
        }
    }
    let Some(current) = current() else { return };
    completion_objects::deactivate(current.pointer());
    // A espera de kernel dentro de um serviço (`block_in_kernel`) já gravou
    // os campos dela no KeWait*; a adiada registrada os grava aqui e de novo
    // ao ligar os blocos, na saída da CPU.
    if !current.blocked_in_kernel() {
        crate::ntos::ke::wait::publish_user_wait(current.pointer(), wait_reason(&wait), wait.alertable.unwrap_or(false));
    }
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

/// Bloqueio dentro de uma syscall numa espera já registrada no despachante
/// (`ke::wait`, a espera número `serial` da thread corrente `thread`): o
/// sinal a apronta, e o despachante publica o status (KTHREAD.WaitStatus) e
/// retoma o serviço na pilha da thread, sem sondá-la.
pub fn block_in_registered_wait(thread: &UserThread, serial: u64) {
    let pointer = thread.pointer();
    block_in_kernel(thread, Wait { registered: Some(Registered::linked(pointer, serial)), kernel: true, ..Wait::default() });
}

/// O despacho dos intervalos de um callback de modo usuário (o
/// KeUserModeCallback de `ke/user_callback.rs`): a thread corrente
/// `thread`, dentro de um serviço, roda aninhado nele o CONTEXT `context`
/// (`usermode::exec_user_callback`) até `returned()` valer (o
/// NtCallbackReturn dela). Enquanto isso o CONTEXT do callback é o da
/// thread: a espera de um serviço aninhado conclui nele, e as APCs de
/// usuário e as exceções são entregues nele. Cada saída é tratada como o
/// despachante trataria: syscalls seguem; exceções e capturas passam pelo
/// tratador de saída. Uma thread terminada (por outra, ou o fim do processo
/// pedido de dentro do callback, que fica com o despachante) encerra o laço
/// com STATUS_THREAD_IS_TERMINATING. Devolve 0 quando o callback retornou.
///
/// Uma thread com o término pedido ([`request_termination`]) recebe a APC de
/// término na volta ao anel 3 do callback, como no KiCallUserMode do NT: o
/// PspExitThread dela roda aqui ([`exit_current`]), na pilha deste nível, e
/// ela não volta ao serviço que chamou o KeUserModeCallback; os níveis de
/// fora acabam também, cada um no fim do intervalo aninhado dele
/// (EXIT_THREAD_EXITED). O que os KeUserModeCallback abandonados alocaram
/// volta pelo ceifador (`ke::user_callback::release_abandoned`).
///
/// Dentro do callback a thread deixa a CPU como qualquer outra (no NT ela
/// continua escalonável durante o KeUserModeCallback). Os intervalos
/// aninhados terminam neste laço, não no despachante, então é ele que
/// repassa a troca: este nível bloqueia o serviço de fora, na pilha de fora
/// (`stacks`, o `ke::user_callback::CalloutStacks`), e o despachante roda
/// as outras threads até a espera concluir. Três casos:
///
/// - um serviço aninhado bloqueou no kernel (uma espera do win32k, um
///   KeWaitFor*): o intervalo aninhado saiu com EXIT_BLOCKED, a espera dele
///   está instalada e o quadro de troca dele está em KTHREAD.KernelStack.
///   O laço guarda o quadro, bloqueia e, retomado, volta ao serviço
///   aninhado (`usermode::resume_user_callback`), que recebe o status;
/// - uma syscall aninhada voltou PENDING com a espera adiada instalada (as
///   esperas de objeto, de alerta por id, das seções críticas): o laço a
///   sonda uma vez, bloqueia e, retomado, põe o status no RAX do CONTEXT do
///   callback;
/// - o timer encerrou o intervalo aninhado (o fim do quantum): a thread
///   cede a vez com uma espera que conclui na primeira sondagem, como uma
///   thread fora de callback no fim do intervalo.
///
/// Com callbacks aninhados cada nível repassa ao de fora, até o
/// despachante, e a retomada desce nível a nível. Se a troca não couber
/// (só com o estado do serviço de fora impróprio, o que o bloqueio do
/// aninhado já excluiu), a espera é sondada aqui, girando os pumps.
pub fn run_callback(thread: &Arc<UserThread>, context: u64, returned: &dyn Fn() -> bool, stacks: &CalloutStacks) -> u32 {
    let (outer, teb, process_pointer) = thread.with(|thread| (core::mem::replace(&mut thread.context, context), thread.teb_va, thread.process_pointer));
    // O quadro de troca do serviço aninhado que bloqueou, a retomar.
    let mut suspended: Option<u64> = None;
    let status = loop {
        let exit = if let Some(saved) = suspended.take() {
            // O serviço aninhado é retomado mesmo numa thread terminada: ele
            // recebe THREAD_IS_TERMINATING e se desfaz.
            leave_cpu_in_callback(thread, stacks, false);
            crate::hal::amd64::usermode::resume_user_callback(saved, teb)
        } else {
            if thread.dead() {
                break THREAD_IS_TERMINATING;
            }
            if thread.termination_deliverable() {
                thread.with(|thread| thread.context = outer);
                stacks.abandon_callback();
                exit_current(thread);
            }
            if let Some(mut wait) = thread.take_wait() {
                if let Some(status) = poll_wait(&mut wait) {
                    finish_wait(thread, wait, status);
                    continue;
                }
                thread.restore_wait(wait);
                thread.with(|thread| thread.kernel = KernelState::Blocked { status: None });
                leave_cpu_in_callback(thread, stacks, true);
                let status = take_kernel_wait_status(thread);
                // O resultado da syscall aninhada que deixou a espera.
                // SAFETY: o CONTEXT do callback (memória do kernel).
                unsafe { Context::at(context) }.rax.set(status as u64);
                continue;
            }
            let undeliverable = super::user_apc::deliver(thread);
            if undeliverable != 0 {
                crate::ntos::ps::create::exit_process(process_pointer, undeliverable);
                continue;
            }
            crate::hal::amd64::usermode::exec_user_callback(context, teb)
        };
        let (status, exit_kind) = exit;
        let failed = match exit_kind {
            // NtTerminateProcess de dentro do callback: o fim do processo.
            0 => Some(status),
            1 => None,
            2 => {
                // O pop de SList interrompido recomeça (KiCheckForSListAddress).
                // SAFETY: o CONTEXT do callback (memória do kernel).
                crate::ntos::ke::user_slist::check_for_slist_address(unsafe { Context::at(context) });
                yield_in_callback(thread, stacks);
                None
            }
            EXIT_BLOCKED => {
                suspended = Some(kernel_thread(thread.pointer()).kernel_stack.get());
                continue;
            }
            // A thread saiu de vez num nível de callback mais interno: este
            // acaba também, sem voltar ao serviço que o chamou.
            EXIT_THREAD_EXITED => {
                thread.with(|thread| thread.context = outer);
                stacks.abandon_callback();
                crate::hal::amd64::usermode::end_thread_interval(status);
            }
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

/// O laço de um callback deixa a CPU pela espera instalada na thread (com o
/// serviço marcado bloqueado) e volta quando ela conclui; o status fica no
/// estado de kernel da thread. Sem a troca, a espera é sondada no lugar.
fn leave_cpu_in_callback(thread: &UserThread, stacks: &CalloutStacks, record_irql: bool) {
    if stacks.block_outer_service(record_irql) {
        return;
    }
    while thread.kernel_state() == (KernelState::Blocked { status: None }) {
        if let Some(mut wait) = thread.take_wait() {
            match poll_wait(&mut wait) {
                Some(status) => {
                    finish_wait(thread, wait, status);
                    break;
                }
                None => thread.restore_wait(wait),
            }
        }
        // Os pumps são do BSP; num AP a espera só entrega o que é da própria
        // thread e gira.
        if cpu() != 0 {
            drain_own_kernel_apcs();
            crate::hal::cpu::pause();
            continue;
        }
        dispatcher::pump_kernel();
        let pumps = *PUMPS.lock();
        for routine in pumps.into_iter().flatten() {
            routine();
        }
    }
}

/// O fim do quantum dentro de um callback: a thread cede a vez com uma
/// espera que conclui na primeira sondagem do despachante, que põe na fila
/// as prontas e escolhe a mais prioritária.
fn yield_in_callback(thread: &UserThread, stacks: &CalloutStacks) {
    // Uma thread terminada (ou com a APC de término pendente) só segue até o
    // laço a encerrar.
    if thread.dead() || thread.termination_deliverable() {
        return;
    }
    thread.with(|thread| {
        thread.wait = Some(Wait { poll: Some(Box::new(|| Some(0))), kernel: true, ..Wait::default() });
        thread.waiting = true;
        thread.kernel = KernelState::Blocked { status: None };
    });
    if stacks.block_outer_service(true) {
        let _ = take_kernel_wait_status(thread);
        return;
    }
    // Sem a troca, o intervalo só segue.
    thread.with(|thread| {
        thread.wait = None;
        thread.waiting = false;
        thread.kernel = KernelState::User;
    });
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

/// A espera instalada de `thread`, que o despachante achou na fila (a thread
/// fora da CPU, no contexto dela, que quem chama carregou): a registrada que
/// já saiu conclui, e `true`; a que ainda espera, ou uma sondada (a thread
/// foi aprontada por fora da espera), `false`.
fn settle(thread: &UserThread) -> bool {
    let Some(mut wait) = thread.take_wait() else { return !thread.waiting() };
    if !registered_done(&wait) {
        thread.restore_wait(wait);
        return false;
    }
    match settle_registered(&mut wait, true) {
        Some(status) => {
            finish_wait(thread, wait, status);
            true
        }
        None => {
            thread.restore_wait(wait);
            false
        }
    }
}

/// Quanto uma espera acordada fica sem sondar (sem sinal, `ke::wait::wake`
/// nem prazo) antes de o despachante a sondar mesmo assim.
const WOKEN_BACKSTOP_MS: u64 = 50;

/// A espera acordada de `wait`, ainda ligada, não é sondada há
/// [`WOKEN_BACKSTOP_MS`].
fn woken_backstop_due(wait: &Wait) -> bool {
    wait.registered.as_ref().is_some_and(|registered| registered.woken && registered.serial != 0 && clock::uptime_ms().saturating_sub(registered.polled_at) >= WOKEN_BACKSTOP_MS)
}

/// A sondagem de uma espera acordada ainda ligada, no contexto da thread
/// (que quem chama carregou): concluída, a espera sai dos objetos com o
/// status (`finish_wait`).
fn woken_backstop(wait: &mut Wait) -> Option<u32> {
    if let Some(registered) = wait.registered.as_mut() {
        registered.polled_at = clock::uptime_ms();
    }
    dispatch_perf::POLLS.fetch_add(1, Ordering::Relaxed);
    wait.poll.as_mut().and_then(|poll| poll())
}

/// A espera registrada de `wait` já saiu (o desfecho dela está pronto), ou
/// ainda não foi ligada: a conclusão (ou o registro) roda no contexto da
/// thread.
fn registered_done(wait: &Wait) -> bool {
    wait.registered.as_ref().is_some_and(|registered| registered.serial == 0 || registered.outcome().is_some())
}

/// O desfecho de uma espera registrada ([`Registered`]): `None` enquanto ela
/// espera. Numa acordada que saiu, a sondagem roda (no contexto da thread,
/// que quem chama já carregou): concluída, o status dela; o prazo, um alerta
/// ou uma APC de usuário sem conclusão, o status da saída; senão os blocos
/// são ligados de novo. `off_cpu`: a thread está fora da CPU (o despachante)
/// e a espera nova é confirmada aqui, com a thread de volta a Waiting; senão
/// (a thread corrente, no laço de um callback) a saída do intervalo confirma.
fn settle_registered(wait: &mut Wait, off_cpu: bool) -> Option<u32> {
    use crate::ntos::ke::wait::{STATUS_ALERTED, STATUS_TIMEOUT, STATUS_USER_APC};
    let reason = wait_reason(wait);
    // A espera adiada de um serviço só liga os blocos quando a thread deixa
    // a CPU, depois de todo o código do serviço: o que ele ainda faz depois
    // de instalar a espera (soltar referências, um lock do Ex, um
    // KeWaitFor*) não pode encontrar os blocos embutidos da KTHREAD já
    // ligados. A tentativa sob o lock vem junto, e numa acordada a sondagem
    // depois do registro (um `wake` entre as duas não se perde).
    if wait.registered.as_ref()?.serial == 0 {
        let registered = wait.registered.as_mut()?;
        if let Some(done) = registered.link(reason) {
            return Some(done);
        }
        if registered.woken {
            registered.polled_at = clock::uptime_ms();
            if let Some(done) = wait.poll.as_mut().and_then(|poll| poll()) {
                if let Some(registered) = wait.registered.as_mut() {
                    crate::ntos::ke::wait::withdraw_user_wait(registered.thread, registered.serial);
                    registered.serial = 0;
                }
                return Some(done);
            }
        }
        if !off_cpu {
            return None;
        }
        let thread = wait.registered.as_ref()?.thread;
        let _ = thread_dispatch::suspend(thread, thread_dispatch::state::WAITING);
        if crate::ntos::ke::wait::commit_user_wait(thread) {
            return None;
        }
        let _ = thread_dispatch::make_ready(thread);
    }
    loop {
        let registered = wait.registered.as_mut()?;
        let status = registered.outcome()?;
        registered.serial = 0;
        if !registered.woken {
            return Some(status);
        }
        registered.polled_at = clock::uptime_ms();
        if let Some(done) = wait.poll.as_mut().and_then(|poll| poll()) {
            return Some(done);
        }
        let registered = wait.registered.as_mut()?;
        let expired = status == STATUS_TIMEOUT && registered.deadline.remaining() == Some(0);
        if expired || status == STATUS_ALERTED || status == STATUS_USER_APC {
            return Some(status);
        }
        if let Some(done) = registered.link(reason) {
            return Some(done);
        }
        if !off_cpu {
            return None;
        }
        // A thread (pronta pela saída) volta a Waiting e a espera nova é
        // confirmada; a que já saiu de novo antes disso é sondada outra vez.
        let thread = registered.thread;
        let _ = thread_dispatch::suspend(thread, thread_dispatch::state::WAITING);
        if crate::ntos::ke::wait::commit_user_wait(thread) {
            return None;
        }
        let _ = thread_dispatch::make_ready(thread);
    }
}

/// Uma espera de serviço de UserMode registrada no despachante
/// ([`Registered`]), como o KeWaitForMultipleObjects do 19041: a tentativa
/// (os objetos, ou a sondagem numa espera acordada), os alertas e a APC de
/// usuário pendente (o KiCheckAlertability) e o prazo zero. Sem conclusão,
/// STATUS_PENDING com a espera instalada; os blocos são ligados quando a
/// thread deixa a CPU ([`execute`], `settle_registered`), e então o sinal a
/// apronta e o despachante grava o status no CONTEXT quando a escolhe.
fn wait_registered(mut wait: Wait) -> u32 {
    let Some((thread, woken, alertable)) = wait.registered.as_ref().map(|registered| (registered.thread, registered.woken, registered.alertable)) else {
        conclude(&mut wait, NOT_SUPPORTED);
        return NOT_SUPPORTED;
    };
    let mut immediate = if woken {
        wait.poll.as_mut().and_then(|poll| poll())
    } else {
        wait.registered.as_ref().filter(|registered| !registered.objects.is_empty()).and_then(|registered| dispatcher::try_wait_objects_for(&registered.objects, registered.kind as u32, thread))
    };
    // Fora do despachante (sem thread de usuário corrente) a espera que
    // bloquearia é recusada, como na sondada; com o prazo já vencido, ela
    // volta o status do prazo.
    if immediate.is_none() && (thread == 0 || !active()) {
        let expired = wait.registered.as_ref().filter(|registered| registered.deadline.remaining() == Some(0)).map(|registered| registered.timeout_status);
        immediate = Some(expired.unwrap_or(NOT_SUPPORTED));
    }
    if immediate.is_none() {
        immediate = thread_alert::consume(thread, 1, alertable);
    }
    // O prazo zero (ou já vencido) volta aqui, sem instalar nada: a consulta
    // de um objeto não passa pelo despachante.
    if immediate.is_none() {
        immediate = wait.registered.as_ref().filter(|registered| registered.deadline.remaining() == Some(0)).map(|registered| registered.timeout_status);
    }
    if let Some(status) = immediate {
        conclude(&mut wait, status);
        return status;
    }
    for entry in wait.entries.iter().flatten() {
        state::retain_user_handle_reference(entry);
    }
    block_current(wait);
    PENDING
}

/// Uma espera de serviço do transporte ALPC/LPC (a recepção de uma mensagem,
/// a resposta de um pedido síncrono, a decisão de uma conexão), com o prazo
/// apontado por `timeout` (0 = sem prazo): uma espera acordada
/// ([`Registered`]) pelo `alpc::kernel_entry::notify_waiters` de toda mudança
/// do transporte, como as de kernel, e a sondagem da operação só roda então.
pub fn wait_transport(mut wait: Wait, timeout: u64) -> u32 {
    let thread = current_pointer();
    let deadline = crate::ntos::ke::wait::Deadline::after(dispatcher::timeout_pointer_to_ms(timeout).map(|ms| ms.saturating_mul(10_000)));
    let alertable = wait.alertable.unwrap_or(false);
    crate::ntos::alpc::kernel_entry::watch(thread);
    let previous = wait.cleanup.take();
    wait.cleanup = Some(Box::new(move |status| {
        crate::ntos::alpc::kernel_entry::unwatch(thread);
        if let Some(previous) = previous {
            previous(status);
        }
    }));
    wait.registered = Some(Registered::woken(thread, Vec::new(), deadline, alertable));
    wait_registered(wait)
}

/// Uma espera de serviço já montada com a [`Registered`] (a retirada de uma
/// porta de conclusão): [`wait_registered`] para quem a monta fora daqui.
pub fn wait_registered_service(wait: Wait) -> u32 {
    wait_registered(wait)
}

/// O prazo de uma espera de serviço (o LARGE_INTEGER capturado; `None` sem
/// prazo), em ms inteiros arredondados para cima, como as esperas sondadas:
/// um prazo não nulo nunca vence antes do próximo ms.
fn service_deadline(timeout: Option<i64>) -> crate::ntos::ke::wait::Deadline {
    crate::ntos::ke::wait::Deadline::after(dispatcher::timeout_value_to_ms(timeout).map(|ms| ms.saturating_mul(10_000)))
}

/// A KTHREAD da thread de usuário corrente (0 fora do despachante).
fn current_pointer() -> u64 {
    current().map_or(0, |thread| thread.pointer())
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

/// A espera de um serviço de modo usuário nos objetos capturados por
/// `ob/wait::reference_objects` (WaitAny devolve o primeiro índice
/// satisfeito, WaitAll o status conjunto), com o prazo capturado (`None` =
/// sem prazo): o ObWaitForMultipleObjects de UserMode, registrada no
/// despachante ([`Registered`], UserRequest). As referências da captura
/// ficam com a espera e saem quando ela conclui.
pub fn wait_referenced(set: crate::ntos::ob::wait::WaitObjects, wait_type: u32, timeout: Option<i64>, alertable: bool) -> u32 {
    let objects = set.objects.clone();
    let registered = Registered::objects(current_pointer(), objects.clone(), wait_type as u8, service_deadline(timeout), alertable);
    // O alarme das esperas satisfeitas em processos (`ob::wait`), com os
    // objetos ainda retidos; só observa.
    let waiter = crate::ntos::ob::wait::Waiter::current();
    let cleanup = move |status: u32| {
        crate::ntos::ob::wait::check_satisfied(&waiter, &set.handles, &set.objects, wait_type, status);
        set.release();
    };
    let wait = Wait { objects, wait_type, alertable: Some(alertable), cleanup: Some(Box::new(cleanup)), reason: Some(crate::ntos::ke::wait::reason::USER_REQUEST), registered: Some(registered), ..Wait::default() };
    wait_registered(wait)
}

/// A espera de modo usuário nos `objects` (os handles de `entries` retidos
/// até ela concluir), com o prazo apontado por `timeout` (0 = sem prazo),
/// registrada no despachante.
pub fn wait_objects(entries: Vec<Arc<UserHandle>>, objects: Vec<u64>, wait_type: u32, timeout: u64, alertable: bool) -> u32 {
    let deadline = crate::ntos::ke::wait::Deadline::after(dispatcher::timeout_pointer_to_ms(timeout).map(|ms| ms.saturating_mul(10_000)));
    let registered = Registered::objects(current_pointer(), objects.clone(), wait_type as u8, deadline, alertable);
    wait_registered(Wait { entries: Some(entries), objects, wait_type, alertable: Some(alertable), registered: Some(registered), ..Wait::default() })
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
        // A thread que outra CPU executa, reservou ou sonda só morre: ela é
        // recolhida numa chamada seguinte, já fora da CPU.
        if owned_elsewhere(&thread).is_some() {
            thread.with(|thread| {
                thread.dead = true;
                thread.deferred_termination = Some(true);
            });
            continue;
        }
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
    // ainda está nela) e o que os callbacks de modo usuário de que ela saiu
    // sem voltar alocaram.
    let pointer = thread.pointer();
    if pointer != 0 {
        crate::ntos::ke::user_callback::release_abandoned(pointer);
        process::release_kernel_stack(pointer);
    }
    // A pilha e a TEB da thread principal são do VAD do processo e voltam no
    // término dele.
    let Some(regions) = thread.with(|thread| thread.regions.take()) else { return };
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
        state::note_denial("handle", "thread", access, entry.access());
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

/// PROCESS_CREATE_THREAD.
const PROCESS_CREATE_THREAD: u32 = 0x2;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;

/// NtCreateThreadEx(out, access, oa, process, start, argument, flags,
/// zeroBits, commit, reserve, attributeList).
fn nt_create_thread_ex(out: u64, access: u64, attributes: u64, process_handle: u64, rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(out, 8) || !state::probe_syscall_stack(rsp, 56) || (attributes != 0 && !probe_user_read(attributes, 48)) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| create_thread_ex(out, access, attributes, process_handle, rsp))
}

/// O processo de um handle que não é o NtCurrentProcess, como o
/// PspCreateThread o pega (19041 rva 0x6c1a0c): o ObReferenceObjectByHandle
/// com PROCESS_CREATE_THREAD na tabela de quem chama (sem o direito,
/// STATUS_ACCESS_DENIED; o NtCurrentThread ou outro tipo,
/// STATUS_OBJECT_TYPE_MISMATCH; um valor fora da tabela,
/// STATUS_INVALID_HANDLE) e a proteção de rundown do alvo (um processo que
/// sai, STATUS_PROCESS_IS_TERMINATING). O EPROCESS volta referenciado.
fn remote_target(handle: u64) -> Result<u64, u32> {
    if handle as i64 == -2 {
        return Err(0xC000_0024);
    }
    if handle > 0x7FFF_FFFF && handle != 0xFFFF_FFFF {
        return Err(0xC000_0008);
    }
    let pointer = super::handles::process_pointer(handle, PROCESS_CREATE_THREAD)?;
    if process::with_record(pointer, |record| record.exiting || record.terminated) != Some(false) || process::reference(pointer).is_none() {
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    Ok(pointer)
}

fn create_thread_ex(out: u64, access: u64, attributes: u64, process_handle: u64, rsp: u64) -> Result<u32, KernelError> {
    let start = state::stack_arg(rsp, 5);
    let flags = state::stack_arg32(rsp, 7);
    let zero_bits = state::stack_arg(rsp, 8);
    let commit = state::stack_arg(rsp, 9);
    let reserve = state::stack_arg(rsp, 10);
    let list = state::stack_arg(rsp, 11);
    let local = process_handle as i64 == -1;
    // A rotina inicial de outro processo é conferida no espaço dele, anexado.
    if local && (!current_process_started() || !probe_user_read(start, 1)) {
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
    let request = CreateRequest { start, argument_words: state::syscall_arg_words(rsp, 6), flags, zero_bits, commit, reserve };
    // Num processo alheio, a TEB, a pilha e a ETHREAD nascem com a thread
    // anexada a ele (o MmCreateTeb do PspAllocateThread); o PID do
    // CLIENT_ID é o dele.
    let created = if local {
        Ok(create_user_thread(&request).map(|thread| (thread, state::current_process_id())))
    } else {
        let target = match remote_target(process_handle) {
            Ok(target) => target,
            Err(status) => return Ok(status),
        };
        let created = crate::ntos::ps::process_context::with_process(target, || create_user_thread(&request).map(|thread| (thread, state::current_process_id())));
        process::dereference(target)?;
        created
    };
    let (thread, process_id) = match created {
        Ok(Ok(created)) => created,
        Ok(Err(status)) => return Ok(status),
        // A raiz do alvo já não carrega: ele está saindo.
        Err(_) => return Ok(STATUS_PROCESS_IS_TERMINATING),
    };
    // PHANDLE de saída (na tabela de quem chama) e os atributos de saída,
    // todos sondados acima.
    guest::try_write::<u64>(out, thread_handle(&thread, access as u32, 0)?)?;
    let teb = thread.with(|thread| thread.teb_va);
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

/// A pilha sai do `memory::create_user_stack` (o RtlCreateUserStack do
/// PspSetupUserStack: o commit no topo da reserva e a guarda embaixo);
/// qualquer falha desfaz a thread inteira.
pub fn create_user_thread(request: &CreateRequest) -> Result<Arc<UserThread>, u32> {
    if !current_process_started() || !probe_user_read(request.start, 1) {
        return Err(0xC000_0005);
    }
    if process_terminating(process::get_current_process()) {
        return Err(0xC000_010A);
    }
    // A PEB e o PID são do processo corrente (o EPROCESS).
    let (peb, process_id) = (state::current_peb(), state::current_process_id());
    let (exports, ntdll_base) = state::with(|state| {
        let exports = state.ntdll_exports.as_ref().map(|exports| (exports.get("RtlUserThreadStart").copied().unwrap_or(0), exports.get("LdrInitializeThunk").copied().unwrap_or(0)));
        (exports.unwrap_or((0, 0)), state.ntdll_image_base)
    });
    // Um tamanho zero sai da imagem (o SizeOfStackCommit e o
    // SizeOfStackReserve dos cabeçalhos do ImageBaseAddress da PEB, como no
    // RtlCreateUserStack): a PEB e os cabeçalhos estão em memória de
    // usuário, então cada passo é sondado.
    let (commit, reserve) = if request.commit != 0 && request.reserve != 0 {
        (request.commit, request.reserve)
    } else {
        let image = (|| -> Result<(u64, u64), KernelError> {
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
            let optional = &state::user_struct::<ImageNtHeaders64>(headers)?.optional_header;
            Ok((optional.size_of_stack_commit.probe_get()?, optional.size_of_stack_reserve.probe_get()?))
        })();
        match image {
            Ok((image_commit, image_reserve)) => (if request.commit != 0 { request.commit } else { image_commit }, if request.reserve != 0 { request.reserve } else { image_reserve }),
            Err(error) => return Err(error.status),
        }
    };
    if commit.max(reserve) > 0x7FFF_FFFF {
        return Err(0xC000_000D);
    }
    let mut regions: Vec<Region> = Vec::new();
    let mut context = 0u64;
    let mut thread_pointer = 0u64;
    let result = (|| -> Result<Arc<UserThread>, u32> {
        let stack = memory::create_user_stack(commit, reserve, if request.zero_bits != 0 { (1u64 << (64 - request.zero_bits)) - 0x1000 } else { 0 }, true)?;
        regions.push(stack.region.clone());
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
        peb_teb::initialize_teb(teb, &peb_teb::TebDescription { process_id, thread_id: id, peb, stack_base: stack.base, stack_limit: stack.limit, deallocation_stack: stack.allocation_base, current_locale: crate::ntos::ps::locale::thread_locale_of(process_pointer) });
        // SAFETY: TEB recém-comprometida; a thread ainda não roda.
        let block = unsafe { Teb::at(teb) };
        // SameTebFlags: SkipThreadAttach, LoaderWorker e SkipLoaderInit.
        block.same_teb_flags.set((if request.flags & 2 != 0 { 8 } else { 0 }) | (if request.flags & 0x10 != 0 { 0x2000 } else { 0 }) | (if request.flags & 0x20 != 0 { 0x4000 } else { 0 }));
        initialize_context(startup, exports.0, stack.base - 8, request.start, 0);
        // O argumento é um ULONG_PTR opaco: preserva os 64 bits.
        // SAFETY: o CONTEXT de partida acabou de ser montado.
        unsafe { Context::at(startup) }.rdx.set(request.argument_words[0] as u64 | (request.argument_words[1] as u64) << 32);
        initialize_context(context, exports.1, stack.base - 8, startup, ntdll_base);
        process::add_thread(process_pointer);
        process::describe_thread(thread_pointer, None, false);
        process::set_thread_start(thread_pointer, request.start);
        push(thread.clone());
        // O begin_exit registra o EXITING antes de percorrer as threads: um
        // pedido de fim que chega entre a primeira checagem e o push aparece
        // aqui (o lugar da trava do processo do PspInsertThread, para SMP).
        let terminating = process_terminating(process_pointer);
        if terminating || attach_scheduling(&thread).is_err() {
            remove(&thread);
            process::remove_thread(process_pointer);
            regions = thread.with(|thread| thread.regions.take().unwrap_or_default());
            return Err(if terminating { 0xC000_010A } else { 0xC000_0017 });
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
    // Uma thread com o término pedido (CrossThreadFlags.Terminated) também
    // recusa a suspensão, como o PsSuspendThread: ela precisa rodar para sair.
    let (previous, dead, terminating) = thread.with(|thread| (thread.suspend_count, thread.dead, thread.termination_requested));
    if dead || (delta > 0 && terminating) {
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
    if delta < 0 {
        dispatcher::note_wake();
    }
    let pointer = thread.pointer();
    // A contagem muda e a decisão sai dela sob o PrcbLock: a thread que outra
    // CPU executa ou reservou decide no fim do intervalo, no mesmo trecho
    // (`execute`), e nenhuma retomada se perde entre a leitura e a fila.
    let (previous, owner) = thread_dispatch::with_queues(|queues| {
        let (previous, registered, suspended, waiting) = thread.with(|thread| {
            let previous = thread.suspend_count;
            thread.suspend_count = (previous as i32 + delta).max(0) as u32;
            (previous, thread.scheduling_registered, thread.suspend_count != 0, thread.waiting)
        });
        if !registered || pointer == 0 {
            return (previous, None);
        }
        if let Some(owner) = queues.running_elsewhere(pointer) {
            return (previous, Some(owner));
        }
        if queues.state(pointer) != thread_dispatch::state::RUNNING {
            let _ = if suspended || waiting { queues.suspend(pointer, thread_dispatch::state::WAITING) } else { queues.make_ready(pointer) };
        }
        (previous, None)
    });
    // A suspensão de uma thread em execução em outra CPU vale quando ela
    // deixa a CPU: o IPI encerra o intervalo no anel 3.
    if let (Some(owner), true) = (owner, delta > 0) {
        thread_dispatch::kick_processor(owner);
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

/// PsSuspendThread(Thread, NULL) na thread de usuário: uma suspensão
/// (KeSuspendThread), menos numa thread que já sai
/// (STATUS_THREAD_IS_TERMINATING) ou com a contagem no limite de 127
/// (STATUS_SUSPEND_COUNT_EXCEEDED). Threads de sistema não têm contagem.
pub fn suspend_thread(pointer: u64) -> u32 {
    let Some(thread) = find_by_pointer(pointer) else { return 0 };
    let (previous, dead) = thread.with(|thread| (thread.suspend_count, thread.dead || thread.termination_requested));
    if dead {
        return THREAD_IS_TERMINATING;
    }
    if previous == 127 {
        return 0xC000_004A;
    }
    adjust_suspend_count(&thread, 1);
    0
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
/// como no 19041, EPROCESS.Flags.ProcessSelfDelete é ligado e o
/// PspTerminateAllThreads confere o processo crítico (`ps/critical.rs`:
/// CRITICAL_PROCESS_DIED); depois as outras threads do processo corrente
/// terminam com `status` (as bloqueadas no kernel desfazem o serviço quando
/// o despachante as retoma; com ProcessSelfDelete, uma thread crítica não
/// para a máquina) e quem chamou segue. Devolve o NTSTATUS.
pub fn terminate_other_threads(status: u32) -> Result<u32, KernelError> {
    let caller = process::get_current_thread();
    let current = current();
    let process_pointer = process::get_current_process();
    // SAFETY: o EPROCESS do processo corrente.
    unsafe { Eprocess::at(process_pointer) }.flags.atomic().fetch_or(Eprocess::PROCESS_SELF_DELETE_MASK, Ordering::SeqCst);
    crate::ntos::ps::critical::terminating_process(process_pointer, status);
    for thread in of_process(process_pointer) {
        let caller_thread = thread.pointer() == caller || current.as_ref().is_some_and(|current| Arc::ptr_eq(current, &thread));
        if caller_thread || thread.dead() {
            continue;
        }
        terminate_thread(&thread, status)?;
    }
    Ok(0)
}

/// O término de uma thread viva (PspTerminateThreadByPointer): uma thread
/// crítica de um processo sem fim pedido para a máquina antes de tudo
/// (`ps/critical.rs`). Uma thread com estado do win32k recebe o pedido de
/// término do 19041 ([`request_termination`]) e sai sozinha, no contexto
/// dela — a corrente, no fim deste mesmo serviço. As demais: a espera
/// conclui com THREAD_IS_TERMINATING, a thread morre com `status`, sai do
/// escalonador, passa pela saída nativa (notificações, APCs, token,
/// conclusões, mutantes) e deixa de contar no EPROCESS; a última thread
/// encerra o processo, e a de um processo crítico para a máquina antes (o
/// PspExitThread).
fn terminate_thread(thread: &Arc<UserThread>, status: u32) -> Result<(), KernelError> {
    crate::ntos::ps::critical::terminating_thread(thread.pointer(), status);
    if exits_in_own_context(thread) {
        request_termination(thread, status);
        return Ok(());
    }
    // Uma thread que outra CPU executa termina no próprio contexto, como no
    // 19041 toda thread termina (o KeRequestTerminationThread 0x35bd28): o
    // pedido de término e o IPI à dona. As demais terminam aqui, emprestadas
    // durante todo o término.
    let Some(borrow) = thread_dispatch::try_borrow(thread.pointer()) else {
        request_termination(thread, status);
        return Ok(());
    };
    let result = terminate_borrowed(thread, status);
    thread_dispatch::release_borrow(borrow);
    result
}

/// O corpo de [`terminate_thread`] com a thread fora de qualquer outra CPU.
fn terminate_borrowed(thread: &Arc<UserThread>, status: u32) -> Result<(), KernelError> {
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
    // SAFETY: o EPROCESS da thread, referenciado por ela.
    let last_thread = unsafe { Eprocess::at(process_pointer) }.active_threads.get() == 0;
    crate::ntos::ps::critical::exiting_thread(pointer, last_thread, status);
    // Notifica antes que a última ETHREAD possa ser recolhida.
    if last_thread {
        let previous = process::get_current_thread();
        process::set_current_thread(pointer);
        let terminated = process::terminate_process(process_pointer, status);
        process::set_current_thread(previous);
        terminated?;
    }
    crate::debug_print!("[thread] exit tid={} status={:#x}", thread.thread_id, status);
    object_census_on_exit(process_pointer);
    Ok(())
}

/// Threads de usuário que já saíram, para o censo de objetos.
static EXITED_THREADS: AtomicU32 = AtomicU32::new(0);

/// O censo de objetos do `--heap-census`, a cada 256 threads de usuário que
/// saem: o heap do kernel, as threads do índice (mortas, mortas com handles
/// abertos e os handles delas, mortas com regiões), as ETHREADs registradas
/// (soltas pelo dono e ainda referenciadas, já saídas), os corpos de
/// despacho por tipo (quantos/sem handle/referências), as cópias divididas
/// de descritores (`ob/shared_policy.rs`), os pacotes de espera por fase e
/// os handles do processo da thread por tipo.
fn object_census_on_exit(process_pointer: u64) {
    if !crate::ntos::init::boot_config::heap_census() || EXITED_THREADS.fetch_add(1, Ordering::Relaxed) % 256 != 255 {
        return;
    }
    let (mut total, mut dead, mut dead_with_handles, mut open_handles, mut dead_with_regions) = (0u32, 0u32, 0u32, 0u32, 0u32);
    for thread in all() {
        thread.with(|thread| {
            total += 1;
            if thread.dead {
                dead += 1;
                dead_with_handles += (thread.handles != 0) as u32;
                open_handles += thread.handles;
                dead_with_regions += thread.regions.is_some() as u32;
            }
        });
    }
    let (records, released, exiting) = process::thread_census();
    let (_, heap_used) = crate::hal::kmalloc::info();
    let mut bodies = String::new();
    for (kind, count, unhandled, refs) in crate::ntos::ob::objects::dispatcher::census() {
        bodies.push_str(&alloc::format!(" {kind}={count}/{unhandled}/{refs}"));
    }
    let packets = crate::ntos::ob::objects::work::packet_census();
    let mut handles = String::new();
    if let Some(table) = process_state::get(process_pointer) {
        for (kind, count) in state::user_handle_census(&table) {
            handles.push_str(&alloc::format!(" {kind}={count}"));
        }
    }
    crate::debug_print!(
        "[heap-census] objetos apos {} saidas: heap {} KB; threads {} (mortas {}, com handles {} [{} handles], com regioes {}); ETHREADs {} (soltas {}, saidas {}); corpos{}; descritores divididos {}; pacotes ociosos/associados/enfileirados/fechados {}/{}/{}/{}; handles do processo{}",
        EXITED_THREADS.load(Ordering::Relaxed),
        heap_used / 1024,
        total,
        dead,
        dead_with_handles,
        open_handles,
        dead_with_regions,
        records,
        released,
        exiting,
        bodies,
        crate::ntos::ob::shared_policy::live(),
        packets[0],
        packets[1],
        packets[2],
        packets[3],
        handles
    );
}

/// A thread termina como no 19041, rodando o próprio PspExitThread no
/// contexto dela: tem estado do win32k (KTHREAD.Win32Thread, que o callout
/// de saída de thread do win32k lê pela thread corrente), um CONTEXT, o
/// registro no despacho, pilha de kernel própria e o processo no
/// despachante, que a roda até ela sair.
fn exits_in_own_context(thread: &UserThread) -> bool {
    let (pointer, context, registered, dead, process_pointer) = thread.with(|thread| (thread.thread_pointer, thread.context, thread.scheduling_registered, thread.dead, thread.process_pointer));
    if pointer == 0 || context == 0 || !registered || dead || !process_started(process_pointer) || EXECUTOR.lock().is_none() {
        return false;
    }
    let tcb = kernel_thread(pointer);
    tcb.win32_thread.get() != 0 && crate::ntos::mm::memory_map::is_kernel_stack(tcb.initial_stack.get())
}

/// O pedido de término de uma thread que sai no próprio contexto
/// ([`exits_in_own_context`]), como o PspTerminateThreadByPointer sem
/// DirectTerminate e o KeRequestTerminationThread do 19041 (0x7079e0,
/// 0x35bd28):
///
/// - CrossThreadFlags.Terminated (LOCK BTS) e, no primeiro pedido,
///   ETHREAD.ExitStatus; o status de saída da thread é o do primeiro pedido;
/// - KTHREAD.ThreadFlags.TerminationApcRequest e a APC de término: no NT a
///   SchedulerApc (APC normal de kernel, KiSchedulerApc) se reenfileira como
///   APC de usuário com o KiSchedulerApcTerminate, que o KiInsertQueueApc
///   põe na cabeça da fila de usuário com UserApcPending. Aqui o efeito é o
///   mesmo: UserApcPending publicado; qualquer espera de UserMode sai com
///   STATUS_USER_APC (o KiCheckAlertability) e a próxima volta ao modo
///   usuário roda o PspExitThread ([`exit_current`]);
/// - o KeAlertThread(Thread, KernelMode): uma espera alertável sai com
///   STATUS_ALERTED; uma não alertável de KernelMode continua até concluir,
///   como no NT;
/// - o KeForceResumeThread: a contagem de suspensão vai a zero.
///
/// A espera adiada de um serviço (a thread está fora do kernel, ou no laço de
/// um callback) é de UserMode e conclui aqui. A thread não morre neste
/// ponto: o serviço em curso se desfaz e ela sai na volta ao modo usuário,
/// com o Win32Thread ainda publicado.
fn request_termination(thread: &Arc<UserThread>, status: u32) {
    let pointer = thread.pointer();
    let first = thread.with(|thread| {
        if thread.dead || thread.termination_requested {
            return false;
        }
        thread.termination_requested = true;
        dispatcher::note_wake();
        if thread.exit_status == PENDING {
            thread.exit_status = status;
        }
        true
    });
    if !first || pointer == 0 {
        return;
    }
    // SAFETY: ETHREAD vivo, retido pela thread de usuário.
    let ethread = unsafe { Ethread::at(pointer) };
    if ethread.cross_thread_flags.atomic().fetch_or(Ethread::TERMINATED_MASK, Ordering::SeqCst) & Ethread::TERMINATED_MASK == 0 {
        ethread.exit_status.set(status as i32);
    }
    let tcb = kernel_thread(pointer);
    tcb.thread_flags.atomic().fetch_or(Kthread::TERMINATION_APC_REQUEST_MASK as i32, Ordering::SeqCst);
    thread_lock::with_lock(pointer, || tcb.apc_state.set_user_apc_pending(1));
    // A espera de uma thread que outra CPU executa (ou sonda) conclui pela
    // dona, no fim do intervalo, ou pela sondagem seguinte.
    match thread_dispatch::try_borrow(pointer) {
        Some(borrow) => {
            if let Some(wait) = thread.take_wait() {
                if wait.kernel {
                    thread.restore_wait(wait);
                } else {
                    finish_wait(thread, wait, THREAD_IS_TERMINATING);
                }
            }
            thread_dispatch::release_borrow(borrow);
        }
        None => thread.with(|thread| {
            if thread.deferred_termination.is_none() {
                thread.deferred_termination = Some(false);
            }
        }),
    }
    // A espera registrada de UserMode de um serviço bloqueado sai com
    // STATUS_USER_APC, como a sondada pelo KiCheckAlertability.
    crate::ntos::ke::wait::user_apc_published(pointer);
    // A thread que pede o próprio término sai no fim deste serviço: nada a
    // alertar nem retomar.
    if pointer == process::get_current_thread() {
        return;
    }
    let _ = thread_alert::alert(pointer, 0);
    let suspended = thread.with(|thread| thread.suspend_count);
    if suspended != 0 {
        adjust_suspend_count(thread, -(suspended as i32));
    }
    // A dona em outra CPU: no anel 3 o IPI encerra o intervalo, e num
    // serviço a saída dele vê o término.
    if let Some(owner) = thread_dispatch::owned_elsewhere(pointer) {
        thread_dispatch::kick_processor(owner);
    }
}

/// O PspExitThread (0x6c35f8) de uma thread de usuário com o término pedido,
/// rodando nela mesma: a thread corrente, na própria pilha de kernel, num
/// intervalo de serviço (pode bloquear) em PASSIVE_LEVEL — no fim de um
/// serviço ([`service_exit_termination`]), na volta ao anel 3 de um callback
/// (`run_callback`) ou num intervalo sem anel 3 ([`termination_entry`]). Na
/// ordem do 19041: as notificações e o callout de saída de thread do win32k
/// (PsW32ThreadCalloutExit, com KTHREAD.Win32Thread ainda publicado e esta
/// thread corrente) antes do IoCancelThreadIo, do ExTimerRundown, do
/// CmNotifyRunDown e do KiRundownMutants (`ps::process::exit_thread`); o
/// rundown das APCs, o token, as conclusões, a contagem no EPROCESS e o
/// objeto thread sinalizado (KeTerminateThread). A última thread viva do
/// processo encerra o processo aqui, no contexto dela, com o callout de
/// saída de processo do win32k ([`end_process_from_last_thread`]). O
/// intervalo acaba de vez (EXIT_THREAD_EXITED); o despachante recolhe a
/// pilha depois.
fn exit_current(thread: &Arc<UserThread>) -> ! {
    let (pointer, process_pointer, status) = thread.with(|thread| {
        thread.exit_running = true;
        (thread.thread_pointer, thread.process_pointer, thread.exit_status)
    });
    assert!(pointer != 0 && pointer == process::get_current_thread(), "PspExitThread fora da thread que sai");
    // A entrega da APC de término (o KiDeliverApc de UserMode limpa
    // UserApcPending antes da rotina de kernel): as esperas de UserMode da
    // saída (os callouts do win32k) esperam de verdade.
    let tcb = kernel_thread(pointer);
    thread_lock::with_lock(pointer, || tcb.apc_state.set_user_apc_pending(0));
    process::describe_thread(pointer, None, true);
    if let Err(error) = process::exit_thread(pointer, status) {
        crate::debug_print!("[thread] saida da thread tid={}: {}", thread.thread_id, error);
    }
    rundown_apcs(thread);
    let _ = thread_tokens::release(pointer);
    completion_objects::dissociate(pointer);
    super::mutants::release_thread(pointer);
    process::remove_thread(process_pointer);
    // A verificação do PspExitThread: a última thread de um processo
    // crítico para a máquina.
    // SAFETY: o EPROCESS da thread, referenciado por ela.
    let last_thread = unsafe { Eprocess::at(process_pointer) }.active_threads.get() == 0;
    crate::ntos::ps::critical::exiting_thread(pointer, last_thread, status);
    thread.with(|thread| thread.dead = true);
    dispatcher::set_event(pointer);
    crate::debug_print!("[thread] exit tid={} status={:#x} (no proprio contexto)", thread.thread_id, status);
    object_census_on_exit(process_pointer);
    end_process_from_last_thread(thread, process_pointer, status);
    crate::hal::amd64::usermode::end_thread_interval(status)
}

/// O fim do processo pela última thread que sai no próprio contexto, como o
/// PspExitThread com LastThread: com o fim do processo pedido e nenhuma
/// outra thread viva (nem desfazendo um serviço), o término roda aqui
/// (`ps::create::finish_exit`); senão o despachante o conclui quando as
/// outras acabarem. Sem fim pedido (a thread saiu por NtTerminateThread), a
/// última thread contada no EPROCESS encerra o processo com o status dela.
fn end_process_from_last_thread(thread: &Arc<UserThread>, process_pointer: u64, status: u32) {
    if exit_pending(process_pointer) {
        let others = of_process(process_pointer).iter().any(|other| !Arc::ptr_eq(other, thread) && (!other.dead() || other.blocked_in_kernel()));
        if !others {
            crate::ntos::ps::create::finish_exit(process_pointer);
        }
        return;
    }
    // SAFETY: o EPROCESS da thread, referenciado por ela.
    if unsafe { Eprocess::at(process_pointer) }.active_threads.get() == 0 {
        if let Err(error) = process::terminate_process(process_pointer, status) {
            crate::debug_print!("[thread] termino do processo {:#x} pela ultima thread: {}", process_pointer, error);
        }
    }
}

/// O intervalo de uma thread com o término pedido que estava fora do kernel
/// (no anel 3, ou ainda sem rodar): a APC de término é entregue na volta ao
/// modo usuário, antes de qualquer outra, e a rotina de kernel dela (o
/// KiSchedulerApcTerminate) chama o PspExitThread sem voltar ao anel 3.
extern "C" fn termination_entry(_argument: u64) -> ! {
    let thread = current().expect("APC de termino sem thread de usuario corrente");
    exit_current(&thread)
}

/// O fim de um serviço da thread corrente, antes de voltar ao anel 3 (o
/// KiServiceExit, que entrega as APCs de usuário pendentes): com o término
/// pedido, o PspExitThread roda aqui e o intervalo acaba sem voltar. Um
/// serviço aninhado num callback volta ao laço do callback, que entrega a APC
/// na volta ao anel 3 dele. Chamado pela HAL no fim de toda syscall.
pub fn service_exit_termination() {
    let pointer = process::get_current_thread();
    // O teste barato primeiro: o pedido de término marca a KTHREAD.
    if pointer == 0 || kernel_thread(pointer).termination_apc_request() == 0 {
        return;
    }
    let Some(thread) = current().filter(|thread| thread.pointer() == pointer) else { return };
    if !thread.termination_deliverable() || kernel_thread(pointer).callback_nesting_level.get() != 0 || irql::get_irql() != irql::PASSIVE_LEVEL || !crate::hal::amd64::usermode::in_service() {
        return;
    }
    exit_current(&thread)
}

/// A época de despertar que a última sondagem das esperas de usuário cobriu
/// (`u64::MAX` antes da primeira: nada volta direto).
static POLLED_EPOCH: AtomicU64 = AtomicU64::new(u64::MAX);
/// O tique do relógio (vetor 0x40) da última sondagem das esperas de usuário
/// (`u32::MAX` antes da primeira).
static POLLED_TICK: AtomicU32 = AtomicU32::new(u32::MAX);

/// A sondagem das esperas de usuário tem o que achar: desde a anterior, a
/// época de despertar andou (um sinal, um pulso, uma entrega ALPC, uma APC,
/// um alerta, um IRP concluído, um término) ou passou um tique do relógio. O
/// tique é o limite do que nenhuma época cobre: o prazo de uma espera
/// sondada (a sondagem compara o uptime), a sondagem de garantia das esperas
/// acordadas (`WOKEN_BACKSTOP_MS`) e uma condição que muda sem sinal; no
/// pior caso, um tique (10 ms) de atraso, nunca uma espera perdida. As
/// esperas registradas não dependem da sondagem: o sinal as apronta.
fn poll_due() -> bool {
    dispatcher::wake_epoch() != POLLED_EPOCH.load(Ordering::Acquire) || crate::nano::interrupts::tick_count() != POLLED_TICK.load(Ordering::Relaxed)
}

/// O intervalo despachado em curso em cada CPU ([`execute`]): a KTHREAD e o
/// tique do timer da CPU no começo dele.
static SLICE_THREAD: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static SLICE_TICK: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// A volta direta ligada sem a opção de boot (os autotestes dela).
static FAST_EXIT_FORCED: AtomicBool = AtomicBool::new(false);

/// Liga ou desliga a volta direta ao anel 3 independentemente da opção
/// `SLOWSERVICEEXIT` (autoteste `multiprocess/service_exit`).
pub fn force_fast_exit(on: bool) {
    FAST_EXIT_FORCED.store(on, Ordering::Relaxed);
}

/// O KiSystemServiceExit do 19041 (0x411510): depois de um serviço que não
/// bloqueou, a thread corrente volta ao anel 3 no mesmo intervalo. O 19041
/// só testa ali as APCs de usuário (UserApcPendingAll, 0x41155d), os
/// registradores de depuração e o SetContext: a troca de thread, quando era
/// preciso, já aconteceu dentro do serviço (a espera, a cessão, a pronta de
/// prioridade maior no KiExitDispatcher, o fim de quantum, as DPCs). Aqui,
/// sem preempção dentro do serviço, a saída pergunta, e o intervalo acaba
/// (pelo CONTEXT e pelo despachante) quando: o intervalo não é do
/// despachante; a thread está num callback de modo usuário, fora de
/// PASSIVE_LEVEL, anexada a outro processo ou com uma trava retida;
/// instalou uma espera, está bloqueada, morta, suspensa, terminando ou com
/// uma exceção pendente; tem APC de usuário (a de término inclusive), APC
/// de kernel ou conclusão de E/S pendente; pediu para ceder a CPU; outra
/// thread deve tomá-la (uma reserva ou uma pronta estritamente acima); um
/// tique do relógio passou desde o começo do intervalo (o quantum e a
/// varredura anti-inanição são do tique); há DPC ou IRQ de dispositivo por
/// atender; algo pode ter concluído uma espera sondada desde a última
/// sondagem (a época de despertar); a raiz carregada não é a do processo;
/// ou o depurador armou um passo. `Err` dá o motivo (`dispatch_perf::slow`).
pub fn may_return_to_user() -> Result<(), usize> {
    use crate::ntos::ps::dispatch_perf::slow as why;
    if !crate::ntos::init::boot_config::fast_service_exit() && !FAST_EXIT_FORCED.load(Ordering::Relaxed) {
        return Err(why::DISABLED);
    }
    let pointer = process::get_current_thread();
    let cpu = cpu();
    if pointer == 0 || SLICE_THREAD[cpu].load(Ordering::Acquire) != pointer {
        return Err(why::NOT_DISPATCHED);
    }
    let tcb = kernel_thread(pointer);
    if tcb.callback_nesting_level.get() != 0 {
        return Err(why::CALLBACK);
    }
    // 0x41153b..0x41154d: IRQL e ApcStateIndex zerados, nenhuma trava.
    if irql::get_irql() != irql::PASSIVE_LEVEL || crate::ntos::ke::process_attachment::is_attached() || sync::spin_locks_held() != 0 || sync::shared_locks_held() != 0 {
        return Err(why::STATE);
    }
    let Some(thread) = current().filter(|thread| thread.pointer() == pointer) else { return Err(why::NOT_DISPATCHED) };
    let (stopped, context, process_pointer) = thread.with(|thread| (thread.waiting || thread.wait.is_some() || thread.kernel != KernelState::User || thread.dead || thread.suspend_count != 0 || thread.termination_requested || thread.pending_exception, thread.context, thread.process_pointer));
    if stopped {
        return Err(why::THREAD);
    }
    // 0x41155d: UserApcPendingAll -> KiInitiateUserApc (a de término inclusive).
    let user_queue = &tcb.apc_state.apc_list_head[1];
    if apc::user_apc_pending_all(pointer) != 0 || tcb.termination_apc_request() != 0 || user_queue.flink.get() != user_queue.address() {
        return Err(why::USER_APC);
    }
    if tcb.apc_state.kernel_apc_pending.get() != 0 || crate::ntos::io::file::request::has_completions_for(pointer) {
        return Err(why::KERNEL_APC);
    }
    if thread_dispatch::yield_pending(pointer) {
        return Err(why::YIELD);
    }
    if thread_dispatch::preemption_pending(pointer) {
        return Err(why::PREEMPT);
    }
    if crate::nano::interrupts::processor_tick_count() != SLICE_TICK[cpu].load(Ordering::Relaxed) {
        return Err(why::TICK);
    }
    // As DPCs, as IRQs de dispositivo e as sondagens são do BSP: num AP o
    // intervalo segue, e o BSP ocioso é acordado para sondar.
    if cpu == 0 {
        if crate::ntos::ke::dpc::pending() != 0 || crate::nano::interrupts::has_pending_devices() {
            return Err(why::INTERRUPT);
        }
        if dispatcher::wake_epoch() != POLLED_EPOCH.load(Ordering::Acquire) {
            return Err(why::WAKE);
        }
    } else if dispatcher::wake_epoch() != POLLED_EPOCH.load(Ordering::Acquire) {
        thread_dispatch::wake_processor(0);
    }
    if context_switch::require_loadable(process_pointer).ok() != Some(context_switch::loaded_root()) {
        return Err(why::STATE);
    }
    if crate::ntos::kd::user_debug::step_armed(context) {
        return Err(why::DEBUG);
    }
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

/// As classes 24 e 18 têm validação nativa própria sobre a mesma ETHREAD.
fn requested_class(class: u64) -> u32 {
    let raw = state::service_raw_arguments();
    if raw != 0 {
        guest::read32(raw + 16)
    } else {
        class as u32
    }
}

fn nt_query_information_thread(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    // ThreadBreakOnTermination, ThreadIoPriority, ThreadCycleTime,
    // ThreadPagePriority e ThreadNameInformation (`ps/query_thread`).
    if matches!(requested_class(class), query_thread::THREAD_BREAK_ON_TERMINATION | 22 | 23 | 24 | 38) {
        return query_thread::query_user(rsp);
    }
    let class = class as u32;
    let length = length as u32 as u64;
    let returned = state::stack_arg(rsp, 5);
    // O ProbeForWrite do buffer (alinhamento 4) e do ReturnLength vem antes
    // de tudo (0x5fba0d..0x5fba4e).
    if length != 0 && out & 3 != 0 {
        return Ok(0x8000_0002);
    }
    if (length != 0 && !probe_user_write(out, length)) || (returned != 0 && !probe_user_write(returned, 4)) {
        return Ok(0xC000_0005);
    }
    // O tamanho exato da classe (STATUS_INFO_LENGTH_MISMATCH) antes do
    // handle, e o acesso de cada classe (o switch de 0x5fc1ac): Basic,
    // Times, PriorityBoost, IsTerminated e ActualBasePriority com
    // THREAD_QUERY_LIMITED_INFORMATION
    // (0x800); Win32StartAddress, IsIoPending e HideFromDebugger com
    // THREAD_QUERY_INFORMATION (0x40). AmILastThread não usa o handle.
    let (need, access) = match class {
        0 => (48, 0x800),
        // ThreadTimes: o KERNEL_USER_TIMES.
        1 => (32, 0x800),
        9 => (8, 0x40),
        12 => (4, 0),
        14 => (4, 0x800),
        16 => (4, 0x40),
        17 => (1, 0x40),
        // ThreadIsTerminated (ULONG).
        20 => (4, 0x800),
        // ThreadActualBasePriority (LONG): o ramo próprio da classe 25
        // (0x5fbbbf), com THREAD_QUERY_LIMITED_INFORMATION.
        25 => (4, 0x800),
        _ => {
            crate::debug_print!("[usermode] NtQueryInformationThread classe {}", class);
            return Ok(0xC000_0003);
        }
    };
    if length != need {
        return Ok(0xC000_0004);
    }
    // ThreadAmILastThread (ULONG): EPROCESS.ActiveThreads == 1 do processo
    // corrente (0x5fbf79), sem referenciar o handle.
    if class == 12 {
        return state::guarded(|| {
            guest::try_write::<u32>(out, (of_process(process::get_current_process()).iter().filter(|thread| !thread.dead()).count() == 1) as u32)?;
            if returned != 0 {
                guest::try_write::<u32>(returned, need as u32)?;
            }
            Ok(0)
        });
    }
    let thread = match resolve(handle, access) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    state::guarded(|| {
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
                // O incremento do KeQueryBasePriorityThread, não a base
                // absoluta (o NtQueryInformationThread do 19041).
                information.base_priority.probe_set(thread_priority::query_base_priority_increment(pointer))?;
            }
            // ThreadTimes: CreateTime e ExitTime da ETHREAD (ExitTime zero
            // enquanto a thread vive) e os tempos de kernel e de usuário em
            // 100 ns.
            1 => {
                // SAFETY: a ETHREAD retida pelo handle resolvido.
                let object = unsafe { crate::ntos::inc::types::Ethread::at(pointer) };
                let quad = |time: &crate::ntos::inc::types::LargeInteger| (time.high_part.get() as u32 as u64) << 32 | time.low_part.get() as u64;
                let (kernel, user) = process::thread_record(pointer).map_or((0, 0), |record| (record.kernel_time, record.user_time));
                let times = [quad(&object.create_time), if dead { quad(&object.exit_time) } else { 0 }, kernel, user];
                for (index, value) in times.iter().enumerate() {
                    guest::try_write::<u64>(out + index as u64 * 8, *value)?;
                }
            }
            // ThreadQuerySetWin32StartAddress (PVOID).
            9 => guest::try_write::<u64>(out, start)?,
            // ThreadPriorityBoost (ULONG): KTHREAD.ThreadFlags.DisableBoost
            // (0x7f0c4e).
            14 => guest::try_write::<u32>(out, kernel_thread(pointer).disable_boost())?,
            // ThreadIsIoPending (ULONG): a IrpList da ETHREAD não vazia
            // (0x5fc0fa). O CRpcThread::WorkerLoop do combase mantém o
            // worker vivo enquanto ele tem IRPs pendentes.
            16 => {
                // SAFETY: a ETHREAD retida pelo handle resolvido.
                let irps = &unsafe { crate::ntos::inc::types::Ethread::at(pointer) }.irp_list;
                let first = irps.flink.get();
                guest::try_write::<u32>(out, (first != 0 && first != irps.address()) as u32)?;
            }
            // ThreadHideFromDebugger (BOOLEAN).
            17 => guest::try_write::<u8>(out, hidden as u8)?,
            // ThreadActualBasePriority: a KTHREAD.BasePriority absoluta, com
            // sinal (0x5fbbfc). O AutoCpuPriority::GetCurrent do
            // StateRepository lê a prioridade por ela antes de cada
            // transação do banco.
            25 => guest::try_write::<i32>(out, thread_priority::query_base_priority(pointer))?,
            // ThreadIsTerminated: o PsIsThreadTerminating (o bit Terminated
            // do CrossThreadFlags, ligado quando o fim é pedido).
            _ => {
                // SAFETY: a ETHREAD retida pelo handle resolvido.
                let flags = unsafe { crate::ntos::inc::types::Ethread::at(pointer) }.cross_thread_flags.get();
                guest::try_write::<u32>(out, (dead || flags & crate::ntos::inc::types::Ethread::TERMINATED_MASK != 0) as u32)?;
            }
        }
        // O ReturnLength só depois dos dados, no sucesso.
        if returned != 0 {
            guest::try_write::<u32>(returned, need as u32)?;
        }
        Ok(0)
    })
}

/// NtDelayExecution(Alertable, DelayInterval*), como o
/// KeDelayExecutionThread 19041: o intervalo é capturado; zero, sem
/// Alertable e sem UserApcPending, é só a troca de thread do
/// NtYieldExecution (STATUS_SUCCESS se outra thread pronta assumiu,
/// STATUS_NO_YIELD_PERFORMED se não); senão a espera do timer da thread:
/// STATUS_SUCCESS no vencimento (um intervalo não nulo nunca vence antes do
/// próximo tick, nem abaixo de 1 ms), STATUS_ALERTED ou STATUS_USER_APC.
fn nt_delay_execution(alertable: u64, interval: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let interval = match state::capture_large_integer(interval) {
        Ok(interval) => interval,
        Err(status) => return Ok(status),
    };
    let alertable = state::boolean(alertable);
    if interval == 0 && !alertable {
        // A UserApcPending já publicada encerra a espera não alertável de
        // UserMode antes da troca (KiBeginThreadWait).
        if let Some(status) = thread_alert::consume(process::get_current_thread(), 1, false) {
            return Ok(status);
        }
        return nt_yield_execution(0, 0, 0, 0, 0);
    }
    let registered = Registered::delay(current_pointer(), service_deadline(Some(interval)), alertable);
    Ok(wait_registered(Wait { delay: true, alertable: Some(alertable), registered: Some(registered), ..Wait::default() }))
}

fn nt_alert_thread(handle: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let raw = state::service_raw_arguments();
    alert_thread::alert(if raw != 0 { guest::read64(raw + 8) } else { handle }, 1)
}

fn nt_yield_execution(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let Some(current) = current() else { return Ok(0x4000_0024) };
    // KeYieldExecution(0): qualquer pronta de prioridade a partir de 1.
    Ok(if thread_dispatch::request_yield_execution(current.pointer())? { 0 } else { 0x4000_0024 })
}

fn nt_wait_for_alert_by_thread_id(_address: u64, timeout: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let timeout = match state::capture_timeout(timeout) {
        Ok(timeout) => timeout,
        Err(status) => return Ok(status),
    };
    let Some(current) = current() else { return Ok(NOT_SUPPORTED) };
    if current.with(|thread| core::mem::replace(&mut thread.alerted, false)) {
        return Ok(0x101);
    }
    if dispatcher::timeout_value_to_ms(timeout) == Some(0) {
        return Ok(0x102);
    }
    // Uma espera acordada sem objetos: o NtAlertThreadByThreadId a acorda
    // (`ke::wait::wake`), e a sondagem consome o alerta.
    let target = current.clone();
    let poll = move || target.with(|thread| core::mem::replace(&mut thread.alerted, false)).then_some(0x101);
    let registered = Registered::woken(current.pointer(), Vec::new(), service_deadline(timeout), false);
    Ok(wait_registered(Wait { alert: Some(current), poll: Some(Box::new(poll)), registered: Some(registered), ..Wait::default() }))
}

/// NtAlertThreadByThreadId(ThreadId), como no 19041: um id desconhecido dá
/// STATUS_INVALID_CID (o PsLookupThreadByThreadId); uma thread de outro
/// processo dá STATUS_ACCESS_DENIED sem alerta; senão o alerta fica
/// pendente na thread (um só, não acumula) até o próximo
/// NtWaitForAlertByThreadId dela.
fn nt_alert_thread_by_thread_id(id: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let Some(thread) = all().into_iter().find(|thread| thread.thread_id == id && !thread.dead()) else { return Ok(0xC000_000B) };
    // O KTHREAD.Process (Tcb.Process) do alvo contra o da thread corrente.
    let owner = |pointer: u64| if pointer != 0 { kernel_thread(pointer).process.get() } else { 0 };
    if owner(thread.pointer()) != owner(process::get_current_thread()) {
        return Ok(0xC000_0022);
    }
    thread.with(|thread| thread.alerted = true);
    // A espera acordada do NtWaitForAlertByThreadId volta à fila e consome o
    // alerta (o KeAlertThreadByThreadId do 19041 apronta a thread ali, com
    // o incremento 1 de 0x25c312).
    crate::ntos::ke::wait::wake_with_increment(thread.pointer(), 1);
    Ok(0)
}

/// THREADINFOCLASS.ThreadPriority e ThreadBasePriority.
const THREAD_PRIORITY: u64 = 2;
const THREAD_BASE_PRIORITY: u64 = 3;
/// THREAD_SET_LIMITED_INFORMATION, o direito das duas classes de prioridade.
const THREAD_SET_LIMITED_INFORMATION: u32 = 0x400;
/// SeIncreaseBasePriorityPrivilege.
const SE_INCREASE_BASE_PRIORITY_PRIVILEGE: u64 = 14;
/// PROCESS_PRIORITY_CLASS_REALTIME e JOB_OBJECT_LIMIT_PRIORITY_CLASS.
const PRIORITY_CLASS_REALTIME: u8 = 4;
const JOB_OBJECT_LIMIT_PRIORITY_CLASS: u32 = 0x20;

/// ThreadPriority (2) e ThreadBasePriority (3) do NtSetInformationThread
/// 19041, na ordem dele: o tamanho (4 bytes, STATUS_INFO_LENGTH_MISMATCH),
/// o valor e as checagens dele, e só então o handle, referenciado com
/// THREAD_SET_LIMITED_INFORMATION.
///
/// - ThreadPriority: KPRIORITY de 1 a 31 (STATUS_INVALID_PARAMETER); 16 ou
///   mais exige SeIncreaseBasePriorityPrivilege; KeSetPriorityThread.
/// - ThreadBasePriority: o incremento sobre a base do processo vale de -2 a
///   2 ou ±16 (a saturação); outro valor só num processo da classe de tempo
///   real (ou o processo da porta de erros padrão do silo, que o OpenNT
///   ainda não registra), senão STATUS_INVALID_PARAMETER. Num processo de um
///   job com JOB_OBJECT_LIMIT_PRIORITY_CLASS, fora do tempo real, um
///   incremento positivo é aceito sem efeito; os demais vão ao
///   KeSetBasePriorityThread. O csrss.exe pede o incremento 2
///   (THREAD_PRIORITY_HIGHEST) para as threads do winsrv.
fn set_priority_class(handle: u64, class: u64, input: u64, length: u64) -> Result<u32, KernelError> {
    if length != 4 {
        return Ok(0xC000_0004);
    }
    if !probe_user_read(input, 4) {
        return Ok(0xC000_0005);
    }
    // LONG: a prioridade ou o incremento (sondado acima).
    let value = match guest::try_read::<i32>(input) {
        Ok(value) => value,
        Err(error) => return Ok(error.status),
    };
    if class == THREAD_PRIORITY {
        if !(1..=31).contains(&value) {
            return Ok(0xC000_000D);
        }
        if value >= 16 && !crate::ntos::se::privilege::single_privilege_check(SE_INCREASE_BASE_PRIORITY_PRIVILEGE, 1) {
            return Ok(0xC000_0061);
        }
    }
    // Numa thread que já terminou também: o NtSetInformationThread 19041
    // não tem STATUS_THREAD_IS_TERMINATING, e o KeSetPriorityThread só
    // grava os campos da KTHREAD terminada.
    let thread = match resolve(handle, THREAD_SET_LIMITED_INFORMATION) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    let pointer = thread.pointer();
    if class == THREAD_PRIORITY {
        thread_priority::set_priority(pointer, value as u64)?;
        return Ok(0);
    }
    set_base_priority_increment(pointer, value)
}

/// A ThreadBasePriority depois do handle: o incremento `value` sobre a base
/// do processo na KTHREAD `pointer`, com as checagens de tempo real e de job
/// descritas em [`set_priority_class`]. A worker factory aplica assim o
/// incremento da classe 11 a cada worker novo.
pub fn set_base_priority_increment(pointer: u64, value: i32) -> Result<u32, KernelError> {
    // SAFETY: o EPROCESS dono de uma thread viva.
    let owner = unsafe { crate::ntos::inc::types::Eprocess::at(kernel_thread(pointer).process.get()) };
    let realtime = owner.priority_class.get() == PRIORITY_CLASS_REALTIME;
    if !matches!(value, -16 | -2..=2 | 16) && !realtime {
        return Ok(0xC000_000D);
    }
    let job = owner.job.get();
    // SAFETY: o EJOB do processo, retido pela participação dele.
    if job != 0 && unsafe { crate::ntos::inc::types::Ejob::at(job) }.effective_limit_flags.get() & JOB_OBJECT_LIMIT_PRIORITY_CLASS != 0 && !realtime && value > 0 {
        return Ok(0);
    }
    thread_priority::set_base_priority(pointer, value as i64 as u64)?;
    Ok(0)
}

/// ThreadActualBasePriority.
const THREAD_ACTUAL_BASE_PRIORITY: u64 = 25;

/// ThreadActualBasePriority (25) do NtSetInformationThread 19041: o
/// tamanho (4 bytes, STATUS_INFO_LENGTH_MISMATCH), a base absoluta de 1 a
/// 31 (STATUS_INVALID_PARAMETER) e o handle com
/// THREAD_SET_LIMITED_INFORMATION; só depois do handle, uma base de 16 ou
/// mais fora de um processo da classe de tempo real exige
/// SeIncreaseBasePriorityPrivilege (STATUS_PRIVILEGE_NOT_HELD). A base vai
/// ao KeSetActualBasePriorityThread. O AppXSvc pede a classe para a thread
/// de cada implantação (o ThreadPriority do prioritypolicy.cpp).
fn set_actual_base_priority(handle: u64, input: u64, length: u64) -> Result<u32, KernelError> {
    if length != 4 {
        return Ok(0xC000_0004);
    }
    if !probe_user_read(input, 4) {
        return Ok(0xC000_0005);
    }
    // LONG: a base absoluta (sondada acima).
    let value = match guest::try_read::<i32>(input) {
        Ok(value) => value,
        Err(error) => return Ok(error.status),
    };
    if !(1..=31).contains(&value) {
        return Ok(0xC000_000D);
    }
    let thread = match resolve(handle, THREAD_SET_LIMITED_INFORMATION) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    let pointer = thread.pointer();
    if value >= 16 {
        // SAFETY: o EPROCESS dono de uma thread viva.
        let owner = unsafe { crate::ntos::inc::types::Eprocess::at(kernel_thread(pointer).process.get()) };
        if owner.priority_class.get() != PRIORITY_CLASS_REALTIME && !crate::ntos::se::privilege::single_privilege_check(SE_INCREASE_BASE_PRIORITY_PRIVILEGE, 1) {
            return Ok(0xC000_0061);
        }
    }
    thread_priority::set_actual_base_priority(pointer, value as i64 as u64)?;
    Ok(0)
}

/// ThreadImpersonationToken.
const THREAD_IMPERSONATION_TOKEN: u64 = 5;
/// THREAD_SET_THREAD_TOKEN e TOKEN_IMPERSONATE.
const THREAD_SET_THREAD_TOKEN: u32 = 0x80;
const TOKEN_IMPERSONATE: u32 = 4;

/// ThreadImpersonationToken: o HANDLE do token (8 bytes, senão
/// STATUS_INFO_LENGTH_MISMATCH), a thread com THREAD_SET_THREAD_TOKEN e o
/// PsAssignImpersonationToken: NULL encerra a impersonação (o RevertToSelf);
/// senão o token, com TOKEN_IMPERSONATE, precisa ser de impersonação
/// (STATUS_BAD_TOKEN_TYPE) e a thread passa a impersoná-lo no nível dele
/// (PsImpersonateClient, sem CopyOnOpen nem EffectiveOnly).
fn set_impersonation_token(handle: u64, input: u64, length: u64) -> Result<u32, KernelError> {
    if length != 8 {
        return Ok(0xC000_0004);
    }
    if !probe_user_read(input, 8) {
        return Ok(0xC000_0005);
    }
    // HANDLE do token (sondado acima).
    let token_handle = match guest::try_read::<u64>(input) {
        Ok(value) => value,
        Err(error) => return Ok(error.status),
    };
    let thread = match resolve(handle, THREAD_SET_THREAD_TOKEN) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    let pointer = thread.pointer();
    if token_handle == 0 {
        crate::ntos::ps::security::impersonate_client(pointer, 0, false, false, 2)?;
        return Ok(0);
    }
    let token = match super::tokens::lookup(token_handle, TOKEN_IMPERSONATE) {
        Ok(token) => token,
        Err(status) => return Ok(status),
    };
    let Some((kind, level)) = crate::ntos::se::token::tokens::with(token, |record| (record.kind, record.impersonation_level)) else { return Ok(0xC000_0008) };
    if kind != 2 {
        return Ok(0xC000_00A8);
    }
    crate::ntos::ps::security::impersonate_client(pointer, token, false, false, level)
}

fn nt_set_information_thread(handle: u64, class: u64, input: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    // As classes 18, 22, 24 e 38 têm ordem própria
    // (`ps/set_thread_information`) e aceitam alterar uma ETHREAD retida.
    if matches!(requested_class(class), 18 | 22 | 24 | 38) {
        return set_thread_information::set_user(rsp);
    }
    if matches!(class, THREAD_PRIORITY | THREAD_BASE_PRIORITY) {
        return set_priority_class(handle, class, input, length);
    }
    if class == THREAD_IMPERSONATION_TOKEN {
        return set_impersonation_token(handle, input, length);
    }
    if class == THREAD_ACTUAL_BASE_PRIORITY {
        return set_actual_base_priority(handle, input, length);
    }
    // Cada classe confere o tamanho e captura o valor antes do handle (a
    // tabela de 0x64b5f4); uma classe desconhecida nem referencia o handle.
    // Não há STATUS_THREAD_IS_TERMINATING: uma thread que já terminou ainda
    // aceita as classes.
    let (need, access) = match class {
        // ThreadZeroTlsCell e ThreadHideFromDebugger: THREAD_SET_INFORMATION.
        10 => (4, 0x20),
        17 => (0, 0x20),
        // ThreadPriorityBoost: THREAD_SET_LIMITED_INFORMATION.
        14 => (4, THREAD_SET_LIMITED_INFORMATION),
        _ => {
            crate::debug_print!("[thread] NtSetInformationThread class={}", class);
            return Ok(0xC000_0003);
        }
    };
    if length != need {
        return Ok(0xC000_0004);
    }
    if need != 0 && !probe_user_read(input, need) {
        return Ok(0xC000_0005);
    }
    // ULONG da classe (sondado acima).
    let value = if need == 4 {
        match guest::try_read::<u32>(input) {
            Ok(value) => value,
            Err(error) => return Ok(error.status),
        }
    } else {
        0
    };
    let thread = match resolve(handle, access) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    match class {
        // ThreadPriorityBoost: o KeSetDisableBoostThread (0x77275c), o bit
        // DisableBoost da KTHREAD.ThreadFlags ligado para um valor não nulo.
        14 => {
            let flags = kernel_thread(thread.pointer()).thread_flags.atomic();
            let mask = crate::ntos::inc::types::Kthread::DISABLE_BOOST_MASK as i32;
            if value != 0 {
                flags.fetch_or(mask, core::sync::atomic::Ordering::SeqCst);
            } else {
                flags.fetch_and(!mask, core::sync::atomic::Ordering::SeqCst);
            }
            Ok(0)
        }
        // ThreadZeroTlsCell: TlsFree zera o índice em toda TEB viva.
        10 => {
            let index = value as u64;
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
        // ThreadHideFromDebugger.
        _ => {
            thread.with(|thread| thread.hidden = true);
            Ok(0)
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
