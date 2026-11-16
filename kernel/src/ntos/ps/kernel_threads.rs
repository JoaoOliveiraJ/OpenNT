//! Threads de sistema nativas.
//!
//! Cada thread criada pelo PsCreateSystemThread é uma thread de kernel do
//! escalonador: KTHREAD do System com pilha de kernel própria (`mm/kernel_stack`,
//! com guarda, devolvida pelo ceifador), em que a rotina inicial roda inteira
//! pelo caminho síncrono dos exports, o mesmo do DriverEntry: cada API que o
//! código nativo chama é servida na pilha da própria thread, e uma espera
//! (KeWaitForSingleObject/Multiple, KeDelayExecutionThread, KeRemoveQueue,
//! os locks do Ex, a retirada de uma porta de conclusão, as esperas do ALPC)
//! tira a thread das prontas e troca de contexto (`ke::wait`,
//! `ke::context_switch`) até o sinal aprontá-la. Na entrada de cada API,
//! uma thread que gastou o quantum cede a vez, e as APCs de kernel pendentes
//! são entregues. A rotina que retorna termina a thread com STATUS_SUCCESS;
//! o PsTerminateSystemThread termina de dentro do serviço, pela última troca
//! de contexto (os quadros de cima da pilha não voltam, como no NT).
//!
//! As requisições do kernel com thread própria ([`create_system_request`])
//! rodam na pilha da thread uma requisição suspensível ([`KernelWait`]), que
//! pode pedir callbacks nativos (chamados ali mesmo) e esperar (a thread sai
//! das prontas, com a requisição sondada pelo despachante).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::Ordering;

use super::{cid, process, scheduler};
use crate::hal::amd64::{native_call, win32_thunk};
use crate::ntos::ke::{apc, context_switch, irql, wait};
use crate::ntos::ob::object_manager::{self, NodeId, ObjectData, ObjectHooks};
use crate::ntos::rtl::{native_context, run_once};
use crate::ntos::se::token::thread as thread_tokens;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::kernel_stack;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ClientId, Ethread, ObjectAttributes};

/// KOBJECTS: ThreadObject.
const THREAD_OBJECT: u8 = 6;

fn ethread(pointer: u64) -> &'static Ethread {
    // SAFETY: ETHREAD de uma thread de sistema criada por este módulo.
    unsafe { Ethread::at(pointer) }
}

/// Resultado de uma sondagem de requisição.
pub enum WaitPoll {
    Pending,
    /// Valor final.
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
}

pub type Wait = Box<dyn KernelWait>;

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

struct Thread {
    pointer: u64,
    node: NodeId,
    handle: u32,
    terminated: bool,
    reaped: bool,
    exit_status: u32,
    start_routine: u64,
    start_context: u64,
    initial_request: Option<Wait>,
}

type Shared = Arc<SpinLock<Thread>>;

static BY_POINTER: SpinLock<BTreeMap<u64, Shared>> = SpinLock::new(BTreeMap::new());

fn lookup(pointer: u64) -> Option<Shared> {
    BY_POINTER.lock().get(&pointer).cloned()
}

/// A thread de sistema em cuja pilha a CPU está.
fn current() -> Option<Shared> {
    context_switch::on_kernel_thread_stack().and_then(lookup)
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

/// O ThreadObject sinalizado, com as esperas nele satisfeitas.
fn signal_object(pointer: u64) {
    ethread(pointer).tcb.header.signal_state.set(1);
    wait::signal(pointer);
}

/// Encerramento, na pilha da thread: libera o token, marca Terminated, sai
/// da thread (as rotinas de saída e o rundown das APCs) e sinaliza o objeto.
fn finish_thread(thread: &Shared) {
    let pointer = {
        let mut thread = thread.lock();
        thread.terminated = true;
        thread.pointer
    };
    let _ = thread_tokens::release(pointer);
    ethread(pointer).cross_thread_flags.atomic().fetch_or(Ethread::TERMINATED_MASK, Ordering::SeqCst);
    let exit_status = thread.lock().exit_status;
    if let Err(error) = process::exit_thread(pointer, exit_status) {
        debug_print!("[kernel-threads] exit failed: {}", error);
    }
    if let Err(error) = apc::rundown(pointer) {
        debug_print!("[kernel-threads] APC rundown failed: {}", error);
    }
    signal_object(pointer);
}

/// A thread sai de vez: o encerramento e a última troca de contexto.
fn exit(thread: &Shared) -> ! {
    finish_thread(thread);
    let status = thread.lock().exit_status;
    // As chamadas em curso na pilha desta thread não voltam mais.
    native_context::forget_current_stack();
    irql::swap_irql(irql::PASSIVE_LEVEL);
    scheduler::exit_current_thread(status)
}

/// Uma requisição do kernel na pilha da thread: os callbacks pedidos rodam
/// ali mesmo, e uma espera tira a thread das prontas com a requisição
/// sondada pelo despachante.
fn run_request(mut request: Wait) {
    let mut polled = request.poll();
    loop {
        match polled {
            Ok(WaitPoll::Done(_)) => return,
            Ok(WaitPoll::Callback { routine, arguments }) => {
                if arguments.len() > native_call::MAX_NATIVE_ARGUMENTS {
                    debug_print!("[kernel-threads] callback com argumentos demais");
                    return;
                }
                let value = native_call::call(routine, &arguments);
                if let Err(error) = request.resume(value) {
                    debug_print!("[kernel-threads] requisicao falhou: {}", error);
                    return;
                }
                polled = request.poll();
            }
            Ok(WaitPoll::Pending) => {
                let mut next = None;
                context_switch::wait_until(
                    &mut || match request.poll() {
                        Ok(WaitPoll::Pending) => None,
                        other => {
                            next = Some(other);
                            Some(0)
                        }
                    },
                    crate::ntos::ke::dispatcher::pump_kernel,
                );
                polled = next.unwrap_or(Ok(WaitPoll::Pending));
            }
            Err(error) => {
                debug_print!("[kernel-threads] requisicao falhou: {}", error);
                return;
            }
        }
    }
}

/// O corpo da thread, na pilha dela: a requisição do kernel ou a rotina
/// inicial nativa (PKSTART_ROUTINE(StartContext)), e o fim da thread.
fn thread_body(thread: Shared) -> u32 {
    let (request, routine, context) = {
        let mut thread = thread.lock();
        (thread.initial_request.take(), thread.start_routine, thread.start_context)
    };
    match request {
        Some(request) => run_request(request),
        None => {
            native_call::call(routine, &[context]);
        }
    }
    exit(&thread)
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

/// Opções do handle publicado (dono e atributos OBJ_* do chamador) e o
/// processo da thread (o System quando None).
#[derive(Clone, Copy, Default)]
pub struct HandleOptions {
    pub owner_process: Option<u64>,
    pub attributes: u32,
    pub thread_process: Option<u64>,
}

/// PsCreateSystemThread: KTHREAD com pilha de kernel própria e a rotina
/// inicial, posta no escalonador; devolve o handle publicado. A thread é do
/// System, ou do processo de `HandleOptions::thread_process`.
pub fn create_system_thread(output_handle: u64, start_routine: u64, context_pointer: u64, access: u32, client_id: u64, handle_options: Option<HandleOptions>) -> Result<u64, KernelError> {
    create_thread(output_handle, start_routine, context_pointer, access, client_id, handle_options, None)
}

fn create_thread(output_handle: u64, start_routine: u64, context_pointer: u64, access: u32, client_id: u64, handle_options: Option<HandleOptions>, request: Option<Wait>) -> Result<u64, KernelError> {
    // O TID é reservado na tabela de ids de cliente antes do KTHREAD, que o
    // recebe na criação.
    let id = cid::allocate(cid::Kind::Thread)?;
    let mut registered = 0u64;
    let mut handle = 0u32;
    let mut request = request;
    let result = (|| -> Result<u64, KernelError> {
        // A pilha própria vai com a KTHREAD: o ceifador a devolve.
        let stack = kernel_stack::create_for_kernel_thread()?;
        let system = process::get_system_process();
        // O processo da thread: o System, ou o do ProcessHandle do
        // PsCreateSystemThread (uma thread de modo kernel no espaço de
        // endereçamento dele, que vê a sessão dele).
        let owner = handle_options.and_then(|options| options.thread_process).unwrap_or(system);
        let pointer = process::create_kernel_thread(owner, id, true, 0, Some(stack))?;
        if pointer == 0 {
            return Err(KernelError::new("no thread object"));
        }
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
            pointer,
            node,
            handle: 0,
            terminated: false,
            reaped: false,
            exit_status: 0,
            start_routine,
            start_context: context_pointer,
            initial_request: request.take(),
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
        let body = thread.clone();
        scheduler::spawn_into_process(&format!("kt-{id}"), owner, pointer, Box::new(move || thread_body(body)), Some(Box::new(move || {
            {
                let mut thread = reaped.lock();
                thread.terminated = true;
                thread.reaped = true;
            }
            if ethread(pointer).tcb.header.signal_state.get() == 0 {
                signal_object(pointer);
            }
            // O ceifador roda no despachante, fora da pilha da thread.
            process::release_kernel_stack(pointer);
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
    }
    result
}

/// OBJ_KERNEL_HANDLE.
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// PROCESS_CREATE_THREAD.
const PROCESS_CREATE_THREAD: u32 = 0x2;

/// PsCreateSystemThread(handle*, access, oa, process, clientId*, start,
/// context), como o PsCreateSystemThreadEx do ntoskrnl 19041 (rva
/// 0x6fd980): o handle é sempre de kernel (os atributos do chamador com
/// OBJ_KERNEL_HANDLE ligado, ou só OBJ_KERNEL_HANDLE sem OBJECT_ATTRIBUTES).
/// Sem ProcessHandle a thread é do System; com ele, o
/// ObReferenceObjectByHandle(PROCESS_CREATE_THREAD, PsProcessType,
/// KernelMode) escolhe o processo da thread (o cdd.dll cria assim a thread
/// de apresentação no csrss da sessão, que vê o espaço de sessão), e a
/// recusa dele é o status devolvido. Devolve o NTSTATUS.
pub fn create_system_thread_with_attributes(output_handle: u64, access: u32, object_attributes: u64, process_handle: u64, client_id: u64, start_routine: u64, context_pointer: u64) -> Result<u32, KernelError> {
    // SAFETY: OBJECT_ATTRIBUTES do chamador de kernel (opcional).
    let flags = if object_attributes != 0 { unsafe { ObjectAttributes::at(object_attributes) }.attributes.get() } else { 0 } | OBJ_KERNEL_HANDLE;
    let target = if process_handle != 0 {
        match super::query_process::reference_process(process_handle, PROCESS_CREATE_THREAD)? {
            Ok(target) => Some(target),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let options = HandleOptions { owner_process: Some(process::get_system_process()), attributes: flags, thread_process: target };
    let result = create_system_thread(output_handle, start_routine, context_pointer, access, client_id, Some(options));
    if let Some(target) = target {
        super::query_process::release_process(target)?;
    }
    result.map(|_| 0)
}

/// PsTerminateSystemThread: a thread de sistema corrente termina de dentro
/// do serviço e não retoma o código nativo.
pub fn terminate_current_thread(status: u32) -> Result<u32, KernelError> {
    let current = current().ok_or_else(|| KernelError::new("PsTerminateSystemThread outside a scheduled native thread"))?;
    current.lock().exit_status = status;
    exit(&current)
}

/// Requisição do kernel com thread/pilha do System próprias: pode emitir
/// vários callbacks nativos e termina quando a requisição conclui.
pub fn create_system_request(request: Wait) -> Result<u64, KernelError> {
    let handle = create_thread(0, win32_thunk::kernel_thread_return(), 0, 0x1F_FFFF, 0, None, Some(request))?;
    let pointer = of_handle(handle).ok_or_else(|| KernelError::new("system request thread vanished"))?;
    object_manager::close(handle as u32)?;
    Ok(pointer)
}

/// Handle da thread de sistema corrente (0 fora delas).
pub fn get_current_thread_handle() -> u32 {
    current().map_or(0, |thread| thread.lock().handle)
}

/// A thread de sistema terminou de executar (objeto sinalizado).
pub fn is_terminated(pointer: u64) -> bool {
    lookup(pointer).is_none_or(|thread| thread.lock().terminated)
}
