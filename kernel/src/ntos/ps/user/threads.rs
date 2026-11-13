//! Threads de usuário.
//!
//! As threads executam código nativo em anel 3; a HAL salva CONTEXTs x64
//! completos nas saídas de syscall/timer e este módulo cuida do
//! escalonamento e do ciclo de vida. As threads vivem em `THREADS`.
//! A execução do contexto (`exec_user_context`) é instalada pela HAL de modo
//! usuário; os pumps de ALPC, `device_io`, worker factories, timers e pacotes
//! de espera ocupam slots fixos do laço.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};

use super::memory;
use super::state::{self, probe_user_read, probe_user_write, NativeBody, Region, UserHandle, UserObject};
use crate::ntos::ke::{apc, clock, dispatcher, irql, smp, thread_alert, thread_dispatch, thread_priority};
use crate::ntos::ob::objects::completion as completion_objects;
use crate::ntos::ps::{alert_thread, process, query_thread, set_thread_information, system_process_information};
use crate::ntos::se::token::thread as thread_tokens;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{eprocess, kthread};

pub const CONTEXT_SIZE: u64 = 0x4D0;
const PENDING: u32 = 0x103;
const NOT_SUPPORTED: u32 = 0xC000_00BB;
const THREAD_IS_TERMINATING: u32 = 0xC000_004B;
/// Células da HAL de modo usuário: tipo da saída e estado zerado por execução.
const EXIT_KIND_CELL: u64 = 0x8_F1B0;
const RESET_CELLS: [u64; 5] = [0x8_F090, 0x8_F098, 0x8_F138, 0x8_F140, 0x8_F148];

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
    wait: Option<Wait>,
    /// Há uma espera instalada (mesmo enquanto é sondada fora da trava).
    waiting: bool,
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
            guest::write64(thread_pointer + crate::ntos::inc::nt_abi::kthread::TEB, teb_va);
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
                wait: None,
                waiting: false,
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
static RUNNING: AtomicBool = AtomicBool::new(false);
static CURRENT: SpinLock<Option<Arc<UserThread>>> = SpinLock::new(None);
static APC_PUMP_REGISTERED: AtomicBool = AtomicBool::new(false);
static DRAINING_APCS: AtomicBool = AtomicBool::new(false);
/// `exec_user_context(context, teb)` da HAL de modo usuário.
static EXECUTOR: SpinLock<Option<fn(u64, u64) -> u32>> = SpinLock::new(None);
/// `call_capture::consume` + `exceptions::hardware`/`pending`: devolve o status
/// fatal ou 0 para continuar.
static EXIT_HANDLER: SpinLock<Option<fn(&Arc<UserThread>, u32, u32) -> u32>> = SpinLock::new(None);
/// `win32k::release_thread(pid, tid)`.
static WIN32K_RELEASE: SpinLock<Option<fn(u64, u64)>> = SpinLock::new(None);
static PUMPS: SpinLock<[Option<fn()>; 5]> = SpinLock::new([None; 5]);

pub fn set_executor(executor: fn(u64, u64) -> u32) {
    *EXECUTOR.lock() = Some(executor);
}

pub fn set_exit_handler(handler: fn(&Arc<UserThread>, u32, u32) -> u32) {
    *EXIT_HANDLER.lock() = Some(handler);
}

pub fn set_win32k_release(release: fn(u64, u64)) {
    *WIN32K_RELEASE.lock() = Some(release);
}

pub fn set_pump(slot: usize, routine: fn()) {
    PUMPS.lock()[slot] = Some(routine);
}

pub fn all() -> Vec<Arc<UserThread>> {
    THREADS.lock().clone()
}

pub fn push(thread: Arc<UserThread>) {
    THREADS.lock().push(thread);
}

/// Esvazia a lista de threads de usuário.
pub fn clear() {
    THREADS.lock().clear();
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

/// Estado do laço de execução (`running`); os autotestes o simulam.
pub fn set_running(running: bool, current: Option<Arc<UserThread>>) {
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
        let (dead, context, pointer) = thread.with(|thread| (thread.dead, thread.context, thread.thread_pointer));
        if dead || context == 0 || !apc::has_pending(pointer) {
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

pub fn initialize_context(context: u64, rip: u64, rsp: u64, rcx: u64, rdx: u64) {
    for offset in (0..CONTEXT_SIZE).step_by(4) {
        guest::write32(context + offset, 0);
    }
    guest::write32(context + 0x30, 0x10_000B);
    guest::write32(context + 0x34, 0x1F80);
    guest::write16(context + 0x38, 0x33);
    guest::write16(context + 0x42, 0x2B);
    guest::write32(context + 0x44, 0x202);
    guest::write64(context + 0x80, rcx);
    guest::write64(context + 0x88, rdx);
    guest::write64(context + 0x98, rsp);
    guest::write64(context + 0xF8, rip);
    guest::write16(context + 0x100, 0x37F);
    guest::write32(context + 0x118, 0x1F80);
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
    thread.with(|thread| {
        thread.context = context;
        thread.suspend_count = 0;
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

/// Prioridades são vistas dos campos nativos (sem cópia divergente).
fn attach_scheduling(thread: &Arc<UserThread>) -> Result<(), KernelError> {
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

fn refresh_ready_user_threads() {
    let mut candidates: Vec<Arc<UserThread>> = all().into_iter().filter(|thread| thread.with(|thread| !thread.dead && thread.suspend_count == 0)).collect();
    candidates.sort_by_key(|thread| core::cmp::Reverse(thread_priority::query_priority(thread.pointer())));
    for candidate in candidates {
        let pointer = candidate.pointer();
        process::set_current_thread(pointer);
        if let Some(mut wait) = candidate.take_wait() {
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

/// Laço do processo de usuário: prepara a principal, executa as threads
/// prontas e devolve o status de saída do processo.
pub fn run(thread: &Arc<UserThread>, rip: u64, rsp: u64, argument: u64, ntdll_base: u64) -> Result<u32, KernelError> {
    let Some(executor) = *EXECUTOR.lock() else { return Err(KernelError::new("user-mode execution unavailable")) };
    prepare_main(thread, rip, rsp, argument, ntdll_base)?;
    if !APC_PUMP_REGISTERED.swap(true, Ordering::AcqRel) {
        dispatcher::register_completion_pump(drain_kernel_apcs);
    }
    let process_pointer = thread.with(|thread| thread.process_pointer);
    let caller = process::get_current_thread();
    process::reference(process_pointer);
    set_running(true, None);
    for cell in RESET_CELLS {
        guest::write64(cell, 0);
    }
    let result = (|| -> Result<u32, KernelError> {
        loop {
            refresh_ready_user_threads();
            process::set_current_thread(caller);
            dispatcher::pump_kernel();
            let pumps = *PUMPS.lock();
            for routine in pumps.into_iter().flatten() {
                routine();
            }
            refresh_ready_user_threads();
            let Some((pointer, owner)) = thread_dispatch::peek()? else {
                if all().iter().all(|thread| thread.dead()) {
                    return Ok(guest::read32(process_pointer + eprocess::EXIT_STATUS));
                }
                continue;
            };
            // Uma thread de kernel mais prioritária é entregue no próximo pump.
            if owner.runtime & thread_dispatch::USER_RUNTIME == 0 {
                continue;
            }
            let Some(next) = find_by_pointer(pointer) else { continue };
            *CURRENT.lock() = Some(next.clone());
            process::set_current_thread(pointer);
            process::dispatch_thread(pointer);
            let kernel_before = process::thread_kernel_time(pointer);
            let started = clock::uptime_ms();
            thread_dispatch::begin_execution(pointer)?;
            let (context, teb) = next.with(|thread| (thread.context, thread.teb_va));
            let status = executor(context, teb);
            let new_state = next.with(|thread| {
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
            let kind = guest::read32(EXIT_KIND_CELL);
            if kind == 0 {
                return Ok(status);
            }
            // Captura de chamada e exceções (#DB próprio do usuário ou pendente).
            let handler = *EXIT_HANDLER.lock();
            let failed = match handler {
                Some(handler) => handler(&next, kind, status),
                None if kind == 3 => status,
                None => 0,
            };
            if failed != 0 {
                return Ok(failed);
            }
            for finished in all() {
                if finished.dead() {
                    release_execution_resources(&finished);
                }
            }
        }
    })();
    set_running(false, None);
    process::set_current_thread(caller);
    let _ = process::dereference(process_pointer);
    result
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
    let (pointer, context) = thread.with(|thread| {
        thread.wait = None;
        thread.waiting = false;
        (thread.thread_pointer, thread.context)
    });
    completion_objects::activate(pointer);
    if context != 0 {
        guest::write64(context + 0x78, status as u64);
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

pub fn release_process() {
    for thread in all() {
        if let Some(wait) = thread.take_wait() {
            finish_wait(&thread, wait, THREAD_IS_TERMINATING);
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
    // A TEB principal divide a região com a PEB do processo.
    let Some(regions) = thread.with(|thread| thread.regions.take()) else { return };
    system_process_information::sample();
    if let Some(release) = *WIN32K_RELEASE.lock() {
        release(state::with(|state| state.current_process_id), thread.thread_id);
    }
    for region in &regions {
        memory::release_private_region(region);
    }
    let context = thread.with(|thread| {
        thread.teb_va = 0;
        if thread.thread_pointer != 0 {
            guest::write64(thread.thread_pointer + crate::ntos::inc::nt_abi::kthread::TEB, 0);
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

fn destroy_thread_if_unused(thread: &UserThread) {
    let Some((pointer, registered)) = thread.with(|thread| {
        if !thread.dead || thread.handles != 0 || thread.regions.is_some() || thread.thread_pointer == 0 {
            return None;
        }
        Some((core::mem::replace(&mut thread.thread_pointer, 0), core::mem::replace(&mut thread.scheduling_registered, false)))
    }) else {
        return;
    };
    if registered {
        let _ = thread_dispatch::unregister(pointer);
    }
    let _ = process::release_thread(pointer);
}

fn allocate_private(size: u64, highest: u64) -> Result<(u64, Region), u32> {
    let scratch = guest::alloc_bytes(16);
    if scratch == 0 {
        return Err(0xC000_0017);
    }
    guest::write64(scratch, 0);
    guest::write64(scratch + 8, size);
    let status = match memory::do_user_allocate(scratch, scratch + 8, 0x3000, 4, 0x10000, if highest != 0 { highest } else { 0x7FFF_FFFF_F000 }, 0x10000) {
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
    let start = state::stack_arg(rsp, 5);
    let flags = state::stack_arg32(rsp, 7);
    let zero_bits = state::stack_arg(rsp, 8);
    let commit = state::stack_arg(rsp, 9);
    let reserve = state::stack_arg(rsp, 10);
    let list = state::stack_arg(rsp, 11);
    if !RUNNING.load(Ordering::Acquire) || !probe_user_read(start, 1) {
        return Ok(0xC000_0005);
    }
    if flags & !0x77 != 0 || zero_bits > 32 {
        return Ok(0xC000_000D);
    }
    // Objetos de thread não têm nome.
    if attributes != 0 && guest::read64(attributes + 16) != 0 {
        return Ok(0xC000_0033);
    }
    let mut outputs: Vec<(u64, u64, u64, u64)> = Vec::new();
    if list != 0 {
        if !probe_user_read(list, 8) {
            return Ok(0xC000_0005);
        }
        let bytes = guest::read64(list);
        if !(8..=0x1008).contains(&bytes) || (bytes - 8) % 32 != 0 {
            return Ok(0xC000_000D);
        }
        if !probe_user_read(list, bytes) {
            return Ok(0xC000_0005);
        }
        let mut seen: Vec<u64> = Vec::new();
        let mut at = list + 8;
        while at < list + bytes {
            let attribute = guest::read64(at);
            let size = guest::read64(at + 8);
            let target = guest::read64(at + 16);
            let returned = guest::read64(at + 24);
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
            at += 32;
        }
    }
    let thread = match create_user_thread(&CreateRequest { start, argument_words: state::syscall_arg_words(rsp, 6), flags, zero_bits, commit, reserve }) {
        Ok(thread) => thread,
        Err(status) => return Ok(status),
    };
    guest::write64(out, thread_handle(&thread, access as u32, 0)?);
    let (process_id, teb) = (state::with(|state| state.current_process_id), thread.with(|thread| thread.teb_va));
    for (attribute, target, returned, size) in outputs {
        if attribute == 0x10003 {
            guest::write64(target, process_id);
            guest::write64(target + 8, thread.thread_id);
        } else {
            guest::write64(target, teb);
        }
        if returned != 0 {
            guest::write64(returned, size);
        }
    }
    Ok(0)
}

/// Pilha com compromisso antecipado (política deste kernel: todas as
/// páginas reservadas têm PFN); qualquer falha desfaz a thread inteira.
pub fn create_user_thread(request: &CreateRequest) -> Result<Arc<UserThread>, u32> {
    if !RUNNING.load(Ordering::Acquire) || !probe_user_read(request.start, 1) {
        return Err(0xC000_0005);
    }
    let (peb, stack_top, process_id, exports, ntdll_base) = state::with(|state| {
        let exports = state.ntdll_exports.as_ref().map(|exports| (exports.get("RtlUserThreadStart").copied().unwrap_or(0), exports.get("LdrInitializeThunk").copied().unwrap_or(0)));
        (state.current_peb_va, state.syscall_stack_top, state.current_process_id, exports.unwrap_or((0, 0)), state.ntdll_image_base)
    });
    let image_base = guest::read64(peb + 0x10);
    let optional = image_base + guest::read32(image_base + 0x3C) as u64 + 24;
    let default_reserve = match guest::read64(optional + 72) {
        0 => 0x10_0000,
        value => value,
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
        let id = state::with(|state| {
            let id = state.next_process_id;
            state.next_process_id += 4;
            id
        });
        thread_pointer = process::create_kernel_thread(process_pointer, id, true, 1, Some(stack_top).filter(|&top| top != 0)).map_err(|_| 0xC000_0017u32)?;
        if thread_pointer == 0 {
            return Err(0xC000_0017);
        }
        dispatcher::initialize_event(thread_pointer, 6, false);
        let thread = UserThread::new(id, thread_pointer, teb, request.start);
        thread.with(|thread| {
            thread.process_pointer = process_pointer;
            thread.context = context;
            thread.regions = Some(core::mem::take(&mut regions));
            thread.suspend_count = request.flags & 1;
            thread.hidden = request.flags & 4 != 0;
        });
        guest::write64(teb + 8, stack + stack_size);
        guest::write64(teb + 0x10, stack);
        guest::write64(teb + 0x30, teb);
        guest::write64(teb + 0x40, process_id);
        guest::write64(teb + 0x48, id);
        guest::write64(teb + 0x60, peb);
        guest::write64(teb + 0x1478, stack);
        guest::write16(teb + 0x17EE, (if request.flags & 2 != 0 { 8 } else { 0 }) | (if request.flags & 0x10 != 0 { 0x2000 } else { 0 }) | (if request.flags & 0x20 != 0 { 0x4000 } else { 0 }));
        initialize_context(startup, exports.0, stack + stack_size - 8, request.start, 0);
        // O argumento é um ULONG_PTR opaco: preserva os 64 bits.
        guest::write32(startup + 0x88, request.argument_words[0]);
        guest::write32(startup + 0x8C, request.argument_words[1]);
        initialize_context(context, exports.1, stack + stack_size - 8, startup, ntdll_base);
        process::add_thread(process_pointer);
        process::describe_thread(thread_pointer, None, false);
        process::set_thread_start(thread_pointer, request.start);
        push(thread.clone());
        if attach_scheduling(&thread).is_err() {
            THREADS.lock().retain(|candidate| !Arc::ptr_eq(candidate, &thread));
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

fn nt_open_thread(out: u64, access: u64, attributes: u64, cid: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(out, 8) || !probe_user_read(cid, 16) || (attributes != 0 && !probe_user_read(attributes, 48)) {
        return Ok(0xC000_0005);
    }
    let (pid, tid) = (guest::read64(cid), guest::read64(cid + 8));
    let thread = all().into_iter().find(|thread| thread.thread_id == tid && thread.with(|thread| !thread.dead || thread.handles != 0));
    let Some(thread) = thread.filter(|_| pid == 0 || pid == state::with(|state| state.current_process_id)) else { return Ok(0xC000_000B) };
    guest::write64(out, thread_handle(&thread, access as u32, 0)?);
    Ok(0)
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
    if out != 0 {
        guest::write32(out, previous);
    }
    let (pointer, registered, suspended, waiting) = thread.with(|thread| {
        thread.suspend_count = (previous as i32 + delta).max(0) as u32;
        (thread.thread_pointer, thread.scheduling_registered, thread.suspend_count != 0, thread.waiting)
    });
    if registered && thread_dispatch::thread_state(pointer) != thread_dispatch::state::RUNNING {
        let _ = if suspended || waiting { thread_dispatch::suspend(pointer, thread_dispatch::state::WAITING) } else { thread_dispatch::make_ready(pointer) };
    }
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
    if let Some(wait) = thread.take_wait() {
        finish_wait(&thread, wait, THREAD_IS_TERMINATING);
    }
    let status = status as u32;
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
    rundown_apcs(&thread);
    let _ = thread_tokens::release(pointer);
    completion_objects::dissociate(pointer);
    dispatcher::set_event(pointer);
    super::mutants::release_thread(pointer);
    process::remove_thread(process_pointer);
    // Notifica antes que a última ETHREAD possa ser recolhida.
    if guest::read32(process_pointer + eprocess::ACTIVE_THREADS) == 0 {
        let previous = process::get_current_thread();
        process::set_current_thread(pointer);
        let terminated = process::terminate_process(process_pointer, status);
        process::set_current_thread(previous);
        terminated?;
    }
    crate::debug_print!("[thread] exit tid={} status={:#x}", thread.thread_id, status);
    Ok(0)
}

/// A classe 24 tem validação nativa própria sobre a mesma ETHREAD.
fn requested_class(class: u64) -> u32 {
    let raw = state::with(|state| state.service_raw_arguments);
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
    if returned != 0 {
        guest::write32(returned, need as u32);
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
            for offset in (0..need).step_by(4) {
                guest::write32(out + offset, 0);
            }
            guest::write32(out, exit_status);
            guest::write64(out + 8, if dead { 0 } else { teb });
            guest::write64(out + 16, state::with(|state| state.current_process_id));
            guest::write64(out + 24, thread.thread_id);
            guest::write64(out + 32, (1u64 << smp::online_cpu_count()) - 1);
            guest::write32(out + 40, thread_priority::query_priority(pointer) as u32);
            guest::write32(out + 44, thread_priority::query_base_priority(pointer) as u32);
        }
        9 => guest::write64(out, start),
        17 => guest::write8(out, hidden as u8),
        _ => guest::write32(out, (all().iter().filter(|thread| !thread.dead()).count() == 1) as u32),
    }
    Ok(0)
}

fn nt_delay_execution(alertable: u64, timeout: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_read(timeout, 8) {
        return Ok(0xC000_0005);
    }
    Ok(wait_custom(Wait { delay: true, alertable: Some(alertable & 0xFF != 0), ..Wait::default() }, timeout, None))
}

fn nt_alert_thread(handle: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let raw = state::with(|state| state.service_raw_arguments);
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
            let index = guest::read32(input) as u64;
            if index >= 1088 {
                return Ok(0xC000_000D);
            }
            let mut slots = Vec::new();
            for target in all() {
                let (dead, teb) = target.with(|thread| (thread.dead, thread.teb_va));
                if dead || teb == 0 {
                    continue;
                }
                let expansion = if index >= 64 { guest::read64(teb + 0x1780) } else { 0 };
                if index >= 64 && expansion == 0 {
                    continue;
                }
                let slot = if index < 64 { teb + 0x1480 + index * 8 } else { expansion + (index - 64) * 8 };
                if !probe_user_write(slot, 8) {
                    return Ok(0xC000_0005);
                }
                slots.push(slot);
            }
            for slot in slots {
                guest::write64(slot, 0);
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
            let priority = guest::read32(input) as i32;
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
                guest::write8(pointer + kthread::BASE_PRIORITY, (8 + priority).clamp(1, 15) as u8);
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

pub fn release_thread(thread: &UserThread) {
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
    state::register_handler("NtOpenThread", nt_open_thread);
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
}
