//! Threads de sistema nativas.
//!
//! Cada thread preserva pilha e contexto de CPU/FX próprios; o gateway cede
//! antes de despachar cada API nativa e nenhum frame Rust fica suspenso. As
//! esperas interceptadas (despachante, mutexes, recursos, remoção de
//! callbacks…) viram requisições sondadas pelo escalonador; uma requisição
//! pode pedir callbacks nativos, que rodam na pilha da própria thread abaixo
//! do chamador suspenso, com contexto separado (podem chamar APIs, esperar e
//! aninhar outros callbacks). Ficam para os módulos que ainda faltam as
//! interceptações de ALPC (ZwAlpcConnectPort[Ex]/ZwAlpcSendWaitReceivePort),
//! ZwRemoveIoCompletionEx, Ps[p]SetContextThread[Internal] e
//! PsEnumProcessThreads: até lá essas APIs seguem pelo despacho comum.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::Ordering;

use super::{cid, enum_process_threads, lookup_thread, process, scheduler};
use crate::ntos::ps::notify::{image as image_notify, process as process_notify, thread as thread_notify};
use crate::hal::amd64::win32_thunk;
use crate::ntos::cm::callbacks as registry_callbacks;
use crate::ntos::ex::{callbacks as executive_callbacks, enum_handles, push_lock, resource, rundown, unblock_push_lock};
use crate::ntos::ke::thread_alert::{self, AlertWait};
use crate::ntos::ke::{apc, clock, dispatcher, fast_mutex, irql};
use crate::ntos::ob::callbacks as object_callbacks;
use crate::ntos::ob::object_manager::{self, NodeId, ObjectData, ObjectHooks};
use crate::ntos::rtl::native_context;
use crate::ntos::rtl::run_once;
use crate::ntos::se::token::thread as thread_tokens;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ClientId, Ethread, ObjectAttributes};
use crate::ntos::init::export_names as abi_names;
use crate::ntos::io::file::zw as zw_files;

const CONTEXT_SIZE: u64 = 0x400;
const RAW: u64 = 0x300;
const ARGUMENT_REGISTERS: [u64; 4] = [8, 16, 0x40, 0x48];
/// KOBJECTS: ThreadObject.
const THREAD_OBJECT: u8 = 6;

fn ethread(pointer: u64) -> &'static Ethread {
    // SAFETY: ETHREAD de uma thread de sistema criada por este módulo.
    unsafe { Ethread::at(pointer) }
}

/// Resultado de uma sondagem de espera.
pub enum WaitPoll {
    Pending,
    /// Valor final de RAX.
    Done(u64),
    /// Executar `routine(arguments…)` e devolver o RAX por `resume`.
    Callback { routine: u64, arguments: Vec<u64> },
}

/// Requisição suspensível de uma thread de sistema.
pub trait KernelWait: Send {
    fn poll(&mut self) -> Result<WaitPoll, KernelError>;
    fn resume(&mut self, _value: u64) -> Result<(), KernelError> {
        Ok(())
    }
    /// O callback pedido não pôde começar (sem pilha ou sem contexto).
    fn callback_failed(&mut self) {
        let _ = self.resume(0);
    }
    fn cancel(&mut self) {}
}

pub type Wait = Box<dyn KernelWait>;

/// Continuação suspensa por um callback nativo.
struct Frame {
    context: u64,
    wait: Wait,
}

struct Thread {
    id: u64,
    pointer: u64,
    /// StackLimit da pilha de kernel própria (a KTHREAD é dona dela).
    stack: u64,
    node: NodeId,
    context: u64,
    handle: u32,
    terminated: bool,
    reaped: bool,
    exit_status: u32,
    irql: u8,
    initial_request: Option<Wait>,
    wait: Option<Wait>,
    callbacks: Vec<Frame>,
    /// Falha de uma sondagem feita pelo escalonador (`prepare_dispatch`).
    failure: Option<KernelError>,
}

type Shared = Arc<SpinLock<Thread>>;

static BY_POINTER: SpinLock<BTreeMap<u64, Shared>> = SpinLock::new(BTreeMap::new());
static CURRENT: SpinLock<Option<Shared>> = SpinLock::new(None);

fn lookup(pointer: u64) -> Option<Shared> {
    BY_POINTER.lock().get(&pointer).cloned()
}

fn collect(pointer: u64) {
    let Some(thread) = lookup(pointer) else { return };
    let (reaped, node) = {
        let thread = thread.lock();
        (thread.reaped, thread.node)
    };
    let refs = object_manager::node(node).map_or(0, |node| node.refs);
    if !reaped || refs != 0 || process::thread_reference_count(pointer).unwrap_or(0) != 0 {
        return;
    }
    BY_POINTER.lock().remove(&pointer);
    let _ = process::release_thread(pointer);
}

pub fn reference(pointer: u64) -> bool {
    if lookup(pointer).is_none() {
        return false;
    }
    process::reference_thread(pointer);
    true
}

pub fn dereference(pointer: u64) -> Result<Option<u32>, KernelError> {
    if lookup(pointer).is_none() {
        return Ok(None);
    }
    let count = process::dereference_thread(pointer)?;
    collect(pointer);
    Ok(count)
}

/// KTHREAD de uma thread de sistema pelo handle.
pub fn of_handle(handle: u64) -> Option<u64> {
    let node = object_manager::get_object((handle & 0x7FFF_FFFC) as u32)?;
    let node = object_manager::node(node)?;
    if node.type_name != "Thread" {
        return None;
    }
    let pointer = node.data.as_ref()?.native_pointer;
    lookup(pointer).map(|_| pointer)
}

/// Espera do despachante (KeWait*, KeDelayExecutionThread,
/// ZwWaitForSingleObject) com alertas e prazo.
struct DispatcherWait {
    objects: Vec<u64>,
    wait_type: u32,
    deadline: Option<u64>,
    delay: bool,
    alerts: Option<AlertWait>,
}

impl KernelWait for DispatcherWait {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        if let Some(interrupted) = self.alerts.as_ref().and_then(|alerts| alerts.pending()) {
            if let Some(alerts) = self.alerts.as_mut() {
                alerts.finish(interrupted)?;
            }
            return Ok(WaitPoll::Done(interrupted as u64));
        }
        if !self.delay {
            if let Some(status) = dispatcher::try_wait_objects(&self.objects, self.wait_type) {
                if let Some(alerts) = self.alerts.as_mut() {
                    alerts.finish(status)?;
                }
                return Ok(WaitPoll::Done(status as u64));
            }
        }
        if self.deadline.is_some_and(|deadline| clock::uptime_ms() >= deadline) {
            let status = if self.delay { 0 } else { 0x102 };
            if let Some(alerts) = self.alerts.as_mut() {
                alerts.finish(status)?;
            }
            return Ok(WaitPoll::Done(status as u64));
        }
        if let Some(alerts) = self.alerts.as_mut() {
            alerts.arm()?;
        }
        Ok(WaitPoll::Pending)
    }

    fn cancel(&mut self) {
        if let Some(alerts) = self.alerts.as_mut() {
            let _ = alerts.finish(0xC000_0120);
        }
    }
}

/// Resultado imediato (argumentos recusados antes da espera).
struct Immediate(u64);

impl KernelWait for Immediate {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(WaitPoll::Done(self.0))
    }
}

fn done<T>(value: Option<T>, result: impl FnOnce(T) -> u64) -> WaitPoll {
    value.map_or(WaitPoll::Pending, |value| WaitPoll::Done(result(value)))
}

impl KernelWait for fast_mutex::Request {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(fast_mutex::Request::poll(self)?, |status| status as u64))
    }
}

impl KernelWait for resource::Request {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(resource::Request::poll(self)?, |value| value))
    }
}

impl KernelWait for push_lock::PushLockRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(push_lock::PushLockRequest::poll(self)?, |_| 0))
    }
}

impl KernelWait for unblock_push_lock::UnblockRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(unblock_push_lock::UnblockRequest::poll(self)?, |_| 0))
    }
}

impl KernelWait for rundown::RundownRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(if rundown::RundownRequest::poll(self) { WaitPoll::Done(0) } else { WaitPoll::Pending })
    }
}

impl KernelWait for lookup_thread::LookupRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(lookup_thread::LookupRequest::poll(self)?, |status| status as u64))
    }
}

impl KernelWait for enum_process_threads::NextRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(enum_process_threads::NextRequest::poll(self)?, |thread| thread))
    }
    fn cancel(&mut self) {
        enum_process_threads::NextRequest::cancel(self);
    }
}

impl KernelWait for registry_callbacks::Removal {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(registry_callbacks::Removal::poll(self), |status| status as u64))
    }
}

impl KernelWait for object_callbacks::RemoveRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(object_callbacks::RemoveRequest::poll(self)?, |status| status as u64))
    }
}

impl KernelWait for image_notify::RemoveRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(image_notify::RemoveRequest::poll(self), |status| status as u64))
    }
    fn cancel(&mut self) {
        image_notify::RemoveRequest::cancel(self);
    }
}

impl KernelWait for thread_notify::RemoveRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(thread_notify::RemoveRequest::poll(self)?, |status| status as u64))
    }
}

impl KernelWait for process_notify::RemoveRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(process_notify::RemoveRequest::poll(self)?, |status| status as u64))
    }
}

impl KernelWait for executive_callbacks::UnregisterRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(executive_callbacks::UnregisterRequest::poll(self)?, |status| status as u64))
    }
    fn cancel(&mut self) {
        executive_callbacks::UnregisterRequest::cancel(self);
    }
}

impl KernelWait for executive_callbacks::NotifyRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(match executive_callbacks::NotifyRequest::poll(self)? {
            Some(call) => WaitPoll::Callback { routine: call.callback, arguments: call.arguments.to_vec() },
            None => WaitPoll::Done(0),
        })
    }
    fn resume(&mut self, _value: u64) -> Result<(), KernelError> {
        executive_callbacks::NotifyRequest::resume(self)
    }
    fn cancel(&mut self) {
        let _ = executive_callbacks::NotifyRequest::cancel(self);
    }
}

impl KernelWait for enum_handles::EnumRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(match enum_handles::EnumRequest::poll(self)? {
            enum_handles::Step::Busy => WaitPoll::Pending,
            enum_handles::Step::Callback { callback, arguments } => WaitPoll::Callback { routine: callback, arguments: arguments.to_vec() },
            enum_handles::Step::Done(value) => WaitPoll::Done(value as u64),
        })
    }
    fn resume(&mut self, value: u64) -> Result<(), KernelError> {
        enum_handles::EnumRequest::resume(self, value)
    }
    fn callback_failed(&mut self) {
        enum_handles::EnumRequest::callback_failed(self);
    }
    fn cancel(&mut self) {
        enum_handles::EnumRequest::cancel(self);
    }
}

impl KernelWait for run_once::BeginRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(done(run_once::BeginRequest::poll(self)?, |status| status as u64))
    }
}

impl KernelWait for run_once::ExecutionRequest {
    fn poll(&mut self) -> Result<WaitPoll, KernelError> {
        Ok(match run_once::ExecutionRequest::poll(self)? {
            None => WaitPoll::Pending,
            Some(run_once::ExecutionStep::Done(status)) => WaitPoll::Done(status as u64),
            Some(run_once::ExecutionStep::Callback { routine, arguments }) => WaitPoll::Callback { routine, arguments: arguments.to_vec() },
        })
    }
    fn resume(&mut self, value: u64) -> Result<(), KernelError> {
        run_once::ExecutionRequest::resume(self, value)
    }
}

/// Modo e região crítica das aquisições de ERESOURCE interceptadas.
fn resource_mode(name: &str) -> Option<(resource::Mode, bool)> {
    Some(match name {
        "ExAcquireResourceExclusiveLite" => (resource::Mode::Exclusive, false),
        "ExAcquireResourceSharedLite" => (resource::Mode::Shared, false),
        "ExAcquireSharedStarveExclusive" => (resource::Mode::Starve, false),
        "ExAcquireSharedWaitForExclusive" => (resource::Mode::WaitExclusive, false),
        "ExEnterCriticalRegionAndAcquireResourceExclusive" => (resource::Mode::Exclusive, true),
        "ExEnterCriticalRegionAndAcquireResourceShared" => (resource::Mode::Shared, true),
        _ => return None,
    })
}

/// Requisição suspensível para as APIs interceptadas; `None` = despacho comum.
fn begin_wait(name: &str, args: &[u64; 14]) -> Result<Option<Wait>, KernelError> {
    let boxed = |wait: Box<dyn KernelWait>| Ok(Some(wait));
    match name {
        "PsGetNextProcessThread" => return boxed(Box::new(enum_process_threads::begin_next(args[0], args[1])?)),
        "CmUnRegisterCallback" => return boxed(Box::new(registry_callbacks::begin_remove(args[0])?)),
        "PsLookupThreadByThreadId" => return boxed(Box::new(lookup_thread::begin(args[0], args[1])?)),
        "ExfUnblockPushLock" => return boxed(Box::new(unblock_push_lock::begin(args[0], args[1]))),
        "ExEnumHandleTable" => return boxed(Box::new(enum_handles::begin(args[0], args[1], args[2], args[3])?)),
        "ObUnRegisterCallbacks" => return boxed(Box::new(object_callbacks::begin_remove(args[0])?)),
        "PsRemoveLoadImageNotifyRoutine" => return boxed(Box::new(image_notify::begin_remove(args[0])?)),
        "PsRemoveCreateThreadNotifyRoutine" => return boxed(Box::new(thread_notify::begin_remove(args[0])?)),
        "ExNotifyCallback" => return boxed(Box::new(executive_callbacks::begin_notify(args[0], args[1], args[2])?)),
        "ExUnregisterCallback" => return boxed(Box::new(executive_callbacks::begin_unregister(args[0])?)),
        "ExAcquireFastMutex" | "ExAcquireFastMutexUnsafe" | "KeAcquireGuardedMutex" | "KeAcquireGuardedMutexUnsafe" => {
            return boxed(Box::new(fast_mutex::begin(args[0], name.ends_with("Unsafe"), name.starts_with("Ke"))?));
        }
        "ExWaitForRundownProtectionRelease" | "ExWaitForRundownProtectionReleaseCacheAware" => {
            return boxed(Box::new(rundown::begin(args[0], name == "ExWaitForRundownProtectionReleaseCacheAware")?));
        }
        "RtlRunOnceExecuteOnce" => return boxed(Box::new(run_once::execute_request(args[0], args[1], args[2], args[3])?)),
        "RtlRunOnceBeginInitialize" => return boxed(Box::new(run_once::begin(args[0], args[1] as u32, args[2])?)),
        "ExAcquirePushLockExclusiveEx" | "ExAcquirePushLockSharedEx" => {
            return boxed(Box::new(push_lock::begin(args[0], name == "ExAcquirePushLockSharedEx", args[1] as u32)?));
        }
        _ => {}
    }
    if ((name == "PsSetCreateProcessNotifyRoutineEx" || name == "PsSetCreateProcessNotifyRoutine") && args[1] & 255 != 0) || name == "PsRemoveCreateProcessNotifyRoutine" {
        let flags = if name == "PsSetCreateProcessNotifyRoutineEx" { process_notify::NOTIFY_EXTENDED } else { 0 };
        return boxed(Box::new(process_notify::begin_remove(args[0], flags)?));
    }
    if name == "PsSetCreateProcessNotifyRoutineEx2" && args[0] as u32 == 0 && args[2] & 255 != 0 {
        return boxed(Box::new(process_notify::begin_remove(args[1], process_notify::NOTIFY_EXTENDED | process_notify::NOTIFY_SUBSYSTEMS)?));
    }
    if let Some((mode, enter_critical)) = resource_mode(name) {
        // As variantes com região crítica têm um só argumento e sempre esperam
        // (sem ler o RDX residual como Wait).
        let wait = enter_critical || args[1] & 0xFF != 0;
        return boxed(Box::new(resource::begin(args[0], mode, wait, enter_critical)?));
    }
    let (objects, wait_type, timeout, delay, wait_mode, alertable) = match name {
        "KeWaitForSingleObject" => (alloc::vec![args[0]], 1, args[4], false, args[2], args[3]),
        "KeWaitForMultipleObjects" => {
            let count = args[0] as u32;
            let wait_type = args[2] as u32;
            if count == 0 || count > 64 || wait_type > 1 {
                return boxed(Box::new(Immediate(0xC000_000D)));
            }
            // SAFETY: PVOID Object[Count] do chamador de kernel.
            let objects: Vec<u64> = unsafe { Field::<u64>::array_at(args[1], count as usize) }.iter().map(Field::get).collect();
            let mut unique = objects.clone();
            unique.sort_unstable();
            unique.dedup();
            if unique.len() != objects.len() {
                return boxed(Box::new(Immediate(0xC000_000D)));
            }
            (objects, wait_type, args[6], false, args[4], args[5])
        }
        "KeDelayExecutionThread" => {
            if args[2] == 0 {
                return boxed(Box::new(Immediate(0xC000_000D)));
            }
            (Vec::new(), 1, args[2], true, args[0], args[1])
        }
        "ZwWaitForSingleObject" => {
            let pointer = of_handle(args[0]).unwrap_or_else(|| zw_files::wait_object_of_handle(args[0]));
            if pointer == 0 {
                return boxed(Box::new(Immediate(0xC000_0008)));
            }
            (alloc::vec![pointer], 1, args[2], false, 0, args[1])
        }
        _ => return Ok(None),
    };
    let deadline = dispatcher::timeout_pointer_to_ms(timeout).map(|milliseconds| clock::uptime_ms() + milliseconds);
    let alerts = thread_alert::wait(process::get_current_thread(), wait_mode as u8, alertable & 255 != 0, false)?;
    boxed(Box::new(DispatcherWait { objects, wait_type, deadline, delay, alerts: Some(alerts) }))
}

/// Grava o frame bruto (id, 14 argumentos, RIP, RSP anterior) e devolve os
/// argumentos; o RSP salvo está depois do `ret` da API (arg 5 em RSP+32).
fn read_request(context: u64, id: u64) -> [u64; 14] {
    let raw = context + RAW;
    guest::write64(raw, id - 32);
    let resume_rsp = guest::read64(context + 0x20);
    let mut args = [0u64; 14];
    for (index, slot) in args.iter_mut().enumerate() {
        let value = guest::read64(if index < 4 { context + ARGUMENT_REGISTERS[index] } else { resume_rsp + 32 + (index as u64 - 4) * 8 });
        guest::write64(raw + (index as u64 + 1) * 8, value);
        *slot = value;
    }
    guest::write64(raw + 15 * 8, guest::read64(context + 0x80));
    guest::write64(raw + 16 * 8, resume_rsp - 8);
    args
}

fn swap_irql(target: u8) {
    let current = irql::get_irql();
    if target > current {
        irql::raise_irql(target);
    } else if target < current {
        irql::lower_irql(target as u64);
    }
}

/// Entra no contexto da thread (corrente + IRQL próprio); devolve o estado
/// anterior para `leave`.
fn enter(thread: &Shared) -> (Option<Shared>, u8) {
    let previous = CURRENT.lock().replace(thread.clone());
    let previous_irql = irql::get_irql();
    swap_irql(thread.lock().irql);
    (previous, previous_irql)
}

fn leave(thread: &Shared, (previous, previous_irql): (Option<Shared>, u8)) {
    thread.lock().irql = irql::get_irql();
    swap_irql(previous_irql);
    *CURRENT.lock() = previous;
}

/// Sonda a espera pendente: conclui (RAX), segue pendente ou monta o
/// contexto de um callback nativo na pilha da thread.
fn advance_wait(thread: &Shared) -> Result<(), KernelError> {
    let Some(mut wait) = thread.lock().wait.take() else { return Ok(()) };
    let polled = match wait.poll() {
        Ok(polled) => polled,
        Err(error) => {
            thread.lock().wait = Some(wait);
            return Err(error);
        }
    };
    match polled {
        WaitPoll::Pending => {
            thread.lock().wait = Some(wait);
        }
        WaitPoll::Done(value) => {
            let context = thread.lock().context;
            guest::write64(context, value);
        }
        WaitPoll::Callback { routine, arguments } => {
            let (parent, stack) = {
                let thread = thread.lock();
                (thread.context, thread.stack)
            };
            let rsp = (guest::read64(parent + 0x20) & !15).wrapping_sub(40);
            let prepared = (|| -> Result<u64, KernelError> {
                if rsp < stack + 0x100 {
                    return Err(KernelError::new("native callback stack overflow"));
                }
                if arguments.len() > 4 {
                    return Err(KernelError::new("native callback register argument limit"));
                }
                let context = guest::alloc_bytes(CONTEXT_SIZE);
                if context == 0 {
                    return Err(KernelError::new("native callback context allocation failed"));
                }
                for offset in (0..RAW).step_by(8) {
                    guest::write64(context + offset, guest::read64(parent + offset));
                }
                for (index, register) in ARGUMENT_REGISTERS.iter().enumerate() {
                    guest::write64(context + register, arguments.get(index).copied().unwrap_or(0));
                }
                guest::write64(context + 0x20, rsp);
                guest::write64(context + 0x80, routine);
                guest::write64(rsp, win32_thunk::kernel_thread_return());
                Ok(context)
            })();
            match prepared {
                Ok(context) => {
                    let mut thread = thread.lock();
                    thread.callbacks.push(Frame { context: parent, wait });
                    thread.context = context;
                }
                Err(error) => {
                    wait.callback_failed();
                    thread.lock().wait = Some(wait);
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}

/// Um passo nativo: entrega APCs, avança a espera ou roda o contexto até a
/// próxima saída. `Ok(true)` = a thread terminou o laço.
fn step(thread: &Shared) -> Result<bool, KernelError> {
    apc::deliver_all_queued()?;
    if thread.lock().wait.is_some() {
        advance_wait(thread)?;
    }
    if thread.lock().wait.is_some() {
        return Ok(false);
    }
    let context = thread.lock().context;
    let id = win32_thunk::run_kernel_context(context) as u64;
    if id == 0xFFFF_FFFF {
        let parent = {
            let mut thread = thread.lock();
            thread.callbacks.pop()
        };
        let Some(parent) = parent else {
            thread.lock().exit_status = 0;
            return Ok(true);
        };
        let value = guest::read64(context + 0x50);
        guest::free_bytes(context);
        let mut wait = parent.wait;
        let resumed = wait.resume(value);
        {
            let mut thread = thread.lock();
            thread.context = parent.context;
            thread.wait = Some(wait);
        }
        resumed?;
        // Uma continuação pronta não conta como espera em DISPATCH_LEVEL.
        advance_wait(thread)?;
        return Ok(false);
    }
    let provider = native_context::provider().ok_or_else(|| KernelError::new("native kernel dispatcher unavailable"))?;
    let name = id.checked_sub(32).and_then(|index| abi_names::EXPORT_NAMES.get(index as usize).copied());
    if id < 32 || (name.is_none() && !(provider.valid)(id)) {
        return Err(KernelError::new(format!("invalid native thread API {id}")));
    }
    let args = read_request(context, id);
    let wait = match name {
        Some(name) => begin_wait(name, &args)?,
        None => None,
    };
    if let Some(wait) = wait {
        thread.lock().wait = Some(wait);
        advance_wait(thread)?;
        return Ok(false);
    }
    native_context::dispatch_cpu(context, id, provider)?;
    // Nunca retoma depois de PsTerminateSystemThread.
    Ok(thread.lock().terminated)
}

/// O escalonador sonda a espera no contexto da thread antes
/// da seleção por prioridade; o resultado fica no contexto salvo.
fn prepare_dispatch(thread: &Shared) -> bool {
    let saved = enter(thread);
    let result = (|| -> Result<bool, KernelError> {
        apc::deliver_all_queued()?;
        if thread.lock().wait.is_some() {
            advance_wait(thread)?;
        }
        let thread = thread.lock();
        Ok(thread.terminated || thread.wait.is_none())
    })();
    leave(thread, saved);
    match result {
        Ok(ready) => ready,
        Err(error) => {
            thread.lock().failure = Some(error);
            true
        }
    }
}

/// Encerramento: cancela esperas e callbacks, libera o token, marca
/// Terminated, sai da thread no IRQL dela e sinaliza o objeto.
fn finish_thread(thread: &Shared) {
    let (pointer, wait, irql_level) = {
        let mut thread = thread.lock();
        thread.terminated = true;
        (thread.pointer, thread.wait.take(), thread.irql)
    };
    if let Some(mut wait) = wait {
        wait.cancel();
    }
    let _ = thread_tokens::release(pointer);
    ethread(pointer).cross_thread_flags.atomic().fetch_or(Ethread::TERMINATED_MASK, Ordering::SeqCst);
    loop {
        let parent = thread.lock().callbacks.pop();
        let Some(mut parent) = parent else { break };
        let context = thread.lock().context;
        guest::free_bytes(context);
        parent.wait.cancel();
        thread.lock().context = parent.context;
    }
    let caller_irql = irql::get_irql();
    swap_irql(irql_level);
    let exit_status = thread.lock().exit_status;
    if let Err(error) = process::exit_thread(pointer, exit_status) {
        debug_print!("[kernel-threads] exit failed: {}", error);
    }
    if let Err(error) = apc::rundown(pointer) {
        debug_print!("[kernel-threads] APC rundown failed: {}", error);
    }
    swap_irql(caller_irql);
    ethread(pointer).tcb.header.signal_state.set(1);
}

async fn thread_proc(thread: Shared) -> u32 {
    {
        let mut thread = thread.lock();
        thread.wait = thread.initial_request.take();
    }
    let outcome: Result<(), KernelError> = async {
        while !thread.lock().terminated {
            let saved = enter(&thread);
            let stepped = step(&thread);
            leave(&thread, saved);
            if stepped? {
                break;
            }
            if let Some(error) = thread.lock().failure.take() {
                return Err(error);
            }
            let (waiting, level) = {
                let thread = thread.lock();
                (thread.wait.is_some(), thread.irql)
            };
            if !waiting && level >= irql::DISPATCH_LEVEL {
                continue;
            }
            if waiting && level >= irql::DISPATCH_LEVEL {
                return Err(KernelError::new("native thread blocked at DISPATCH_LEVEL"));
            }
            if waiting {
                let polled = thread.clone();
                scheduler::wait_until(move || prepare_dispatch(&polled)).await;
            } else {
                scheduler::yield_retaining_quantum().await;
            }
            if let Some(error) = thread.lock().failure.take() {
                return Err(error);
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = &outcome {
        let id = thread.lock().id;
        debug_print!("[kernel-threads] thread {:#x} failed: {}", id, error);
        thread.lock().exit_status = if error.status == 0 { 0xC000_0001 } else { error.status };
    }
    finish_thread(&thread);
    let status = thread.lock().exit_status;
    status
}

/// Ganchos do objeto Thread: contagem de handles e coleta.
struct ThreadHooks {
    pointer: u64,
}

impl ObjectHooks for ThreadHooks {
    fn on_handle_open(&self) -> Result<(), KernelError> {
        process::account_thread_handle(1)
    }
    fn on_handle_close(&self) {
        let _ = process::account_thread_handle(-1);
        collect(self.pointer);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Opções do handle publicado: dono e atributos OBJ_* do chamador.
#[derive(Clone, Copy, Default)]
pub struct HandleOptions {
    pub owner_process: Option<u64>,
    pub attributes: u32,
}

/// PsCreateSystemThread: KTHREAD do System com pilha de kernel própria
/// (`mm/kernel_stack`, com guarda, devolvida pelo ceifador), contexto com a
/// rotina inicial e a continuação de retorno; devolve o handle publicado.
pub fn create_system_thread(output_handle: u64, start_routine: u64, context_pointer: u64, access: u32, client_id: u64, handle_options: Option<HandleOptions>) -> Result<u64, KernelError> {
    // O TID é reservado na tabela de ids de cliente antes do KTHREAD, que o
    // recebe na criação.
    let id = cid::allocate(cid::Kind::Thread)?;
    let mut allocated: Vec<u64> = Vec::new();
    let mut registered = 0u64;
    let mut handle = 0u32;
    let result = (|| -> Result<u64, KernelError> {
        let context = guest::alloc_bytes(CONTEXT_SIZE);
        if context == 0 {
            return Err(KernelError::new("no thread context"));
        }
        allocated.push(context);
        // A pilha própria vai com a KTHREAD: o ceifador a devolve.
        let stack = kernel_stack::create(false)?;
        let system = process::get_system_process();
        let pointer = process::create_kernel_thread(system, id, true, 0, Some(stack))?;
        if pointer == 0 {
            return Err(KernelError::new("no thread object"));
        }
        allocated.push(pointer);
        let rsp = stack.initial - 40;
        guest::write64(context + 8, context_pointer);
        guest::write64(context + 0x20, rsp);
        guest::write64(context + 0x80, start_routine);
        guest::write64(context + 0x88, 0x202);
        win32_thunk::init_kernel_context_fx(context);
        guest::write64(rsp, win32_thunk::kernel_thread_return());
        // ThreadObject: não sinalizado até o término.
        let object = ethread(pointer);
        object.tcb.header.type_.set(THREAD_OBJECT);
        object.tcb.header.signal_state.set(0);
        object.tcb.kernel_apc_disable.set(-1);
        let attributes = handle_options.map_or(0, |options| options.attributes);
        // Requisições internas ficam com handles da tabela do System;
        // PsCreateSystemThread repassa os atributos OBJ_* do chamador.
        let node = object_manager::new_node(&format!("thread-{id}"), "Thread", Some(ObjectData {
            native_pointer: pointer,
            access: Some(access),
            owner_process: Some(handle_options.and_then(|options| options.owner_process).unwrap_or(system)),
            open_attributes: Some(attributes),
            attributes: attributes & 2,
            hooks: Some(Arc::new(ThreadHooks { pointer })),
            ..Default::default()
        }));
        let thread = Arc::new(SpinLock::new(Thread {
            id,
            pointer,
            stack: stack.limit,
            node,
            context,
            handle: 0,
            terminated: false,
            reaped: false,
            exit_status: 0,
            irql: 0,
            initial_request: None,
            wait: None,
            callbacks: Vec::new(),
            failure: None,
        }));
        BY_POINTER.lock().insert(pointer, thread.clone());
        registered = pointer;
        handle = object_manager::open_object(node, None)?;
        thread.lock().handle = handle;
        let published = if attributes & 0x200 != 0 { 0xFFFF_FFFF_8000_0000 | handle as u64 } else { handle as u64 };
        if output_handle != 0 {
            // SAFETY: PHANDLE de saída do chamador de kernel.
            unsafe { Field::<u64>::at(output_handle) }.set(published);
        }
        if client_id != 0 {
            // SAFETY: PCLIENT_ID de saída do chamador de kernel.
            let output = unsafe { ClientId::at(client_id) };
            output.unique_process.set(object.cid.unique_process.get());
            output.unique_thread.set(id);
        }
        process::set_thread_start(pointer, start_routine);
        process::notify_thread_created(pointer)?;
        let reaped = thread.clone();
        scheduler::spawn_into_process(&format!("kt-{id}"), system, pointer, Box::pin(thread_proc(thread)), Some(Box::new(move || {
            let context = {
                let mut thread = reaped.lock();
                thread.terminated = true;
                thread.reaped = true;
                thread.context
            };
            ethread(pointer).tcb.header.signal_state.set(1);
            // O ceifador roda no escalonador, fora da pilha da thread.
            process::release_kernel_stack(pointer);
            guest::free_bytes(context);
            collect(pointer);
        })))?;
        Ok(published)
    })();
    if result.is_err() {
        // Uma reserva que não chegou ao KTHREAD volta à tabela.
        cid::release(id, 0);
        if registered != 0 {
            BY_POINTER.lock().remove(&registered);
            let _ = process::forget_thread(registered);
        }
        if handle != 0 {
            let _ = object_manager::close(handle);
        }
        for pointer in allocated.into_iter().rev() {
            guest::free_bytes(pointer);
        }
    }
    result
}

/// PsCreateSystemThread(handle*, access, oa, process, clientId*, start,
/// context) pelos OBJECT_ATTRIBUTES do chamador: OBJ_KERNEL_HANDLE escolhe a
/// tabela do System; senão, a do processo corrente.
pub fn create_system_thread_with_attributes(output_handle: u64, access: u32, object_attributes: u64, client_id: u64, start_routine: u64, context_pointer: u64) -> Result<u64, KernelError> {
    // SAFETY: OBJECT_ATTRIBUTES do chamador de kernel (opcional).
    let flags = if object_attributes != 0 { unsafe { ObjectAttributes::at(object_attributes) }.attributes.get() } else { 0 };
    let owner = if flags & 0x200 != 0 { process::get_system_process() } else { process::get_current_process() };
    create_system_thread(output_handle, start_routine, context_pointer, access, client_id, Some(HandleOptions { owner_process: Some(owner), attributes: flags }))
}

/// PsTerminateSystemThread: a thread corrente não retoma o código nativo.
pub fn terminate_current_thread(status: u32) -> Result<u32, KernelError> {
    let current = CURRENT.lock().clone().ok_or_else(|| KernelError::new("PsTerminateSystemThread outside a scheduled native thread"))?;
    let pointer = {
        let mut thread = current.lock();
        thread.exit_status = status;
        thread.terminated = true;
        thread.pointer
    };
    ethread(pointer).cross_thread_flags.atomic().fetch_or(Ethread::TERMINATED_MASK, Ordering::SeqCst);
    Ok(0)
}

/// Requisição do kernel com thread/pilha do System próprias: pode emitir
/// vários callbacks nativos e retoma a continuação de retorno no fim.
pub fn create_system_request(request: Wait) -> Result<u64, KernelError> {
    let handle = create_system_thread(0, win32_thunk::kernel_thread_return(), 0, 0x1F_FFFF, 0, None)?;
    let pointer = of_handle(handle).ok_or_else(|| KernelError::new("system request thread vanished"))?;
    if let Some(thread) = lookup(pointer) {
        thread.lock().initial_request = Some(request);
    }
    object_manager::close(handle as u32)?;
    Ok(pointer)
}

/// Handle da thread de sistema corrente (0 fora delas).
pub fn get_current_thread_handle() -> u32 {
    CURRENT.lock().as_ref().map_or(0, |thread| thread.lock().handle)
}

/// A thread de sistema terminou de executar (objeto sinalizado).
pub fn is_terminated(pointer: u64) -> bool {
    lookup(pointer).is_none_or(|thread| thread.lock().terminated)
}
