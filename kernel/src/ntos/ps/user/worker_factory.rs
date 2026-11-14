//! Workers nativos gerenciados pelo kernel.
//!
//! A NTDLL de modo usuário possui as filas de callbacks; este objeto possui
//! a criação de workers, as esperas de conclusão e a vida dos workers.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use super::io_completion::{self, RemoveOptions};
use super::state::{self, UserHandle};
use super::threads::{self, CreateRequest, UserThread};
use crate::ntos::ke::clock;
use crate::ntos::ob::objects::completion::Packet;
use crate::ntos::ob::objects::dispatcher::UserDispatcher;
use crate::ntos::ob::objects::work::{self as work_objects, Factory, FactoryInitial};
use crate::ntos::ps::{process, process_context};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::extra_ps_user::WorkerFactoryDeferredWork;
use crate::ntos::inc::types::{FileIoCompletionInformation, NtStruct, ObjectAttributes, WorkerFactoryBasicInformation};

static FACTORIES: SpinLock<Vec<Arc<Factory>>> = SpinLock::new(Vec::new());

/// Uma fila compartilhada conserva a referência das fábricas até a
/// reavaliação; o timer curto tem precedência, como no gerenciador do Windows.
struct Deferred {
    factories: Vec<Arc<Factory>>,
    deadline: Option<u64>,
    priority: u32,
}

static DEFERRED: SpinLock<Deferred> = SpinLock::new(Deferred { factories: Vec::new(), deadline: None, priority: 0 });

fn reference(factory: &Factory) {
    let _ = crate::ntos::ob::objects::dispatcher::reference(factory.pointer);
}

fn dereference(factory: &Factory) {
    let _ = crate::ntos::ob::objects::dispatcher::dereference(factory.pointer);
}

fn is_deferred(factory: &Arc<Factory>) -> bool {
    DEFERRED.lock().factories.iter().any(|candidate| Arc::ptr_eq(candidate, factory))
}

fn defer_worker_creation(factory: &Arc<Factory>, priority: u32) {
    let mut deferred = DEFERRED.lock();
    if !deferred.factories.iter().any(|candidate| Arc::ptr_eq(candidate, factory)) {
        reference(factory);
        deferred.factories.push(factory.clone());
    }
    if priority > deferred.priority {
        deferred.priority = priority;
        deferred.deadline = Some(clock::uptime_ms() + if priority == 3 { 30 } else { 120 });
    }
}

fn cancel_deferred_creation(factory: &Arc<Factory>) {
    factory.set_soft_creation_phase(0);
    let removed = {
        let mut deferred = DEFERRED.lock();
        let before = deferred.factories.len();
        deferred.factories.retain(|candidate| !Arc::ptr_eq(candidate, factory));
        let removed = deferred.factories.len() != before;
        if deferred.factories.is_empty() {
            deferred.deadline = None;
            deferred.priority = 0;
        }
        removed
    };
    if removed {
        dereference(factory);
    }
}

fn resolve(handle: u64, access: u32) -> Result<(Arc<UserHandle>, Arc<Factory>), u32> {
    let Some(entry) = state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "workerfactory" {
        return Err(0xC000_0024);
    }
    if entry.access() & access != access {
        return Err(0xC000_0022);
    }
    let factory = entry.downcast::<UserDispatcher>().and_then(|dispatcher| work_objects::factory_of(dispatcher.pointer)).ok_or(0xC000_0008u32)?;
    Ok((entry, factory))
}

fn live(factory: &Factory) -> Vec<Arc<UserThread>> {
    factory.workers().into_iter().filter(|thread| !thread.dead()).collect()
}

fn remove_worker(factory: &Factory, thread: &Arc<UserThread>) {
    if !factory.remove_worker(thread) {
        return;
    }
    thread.with(|thread| thread.worker_factory = 0);
    dereference(factory);
}

fn usable(process_pointer: u64) -> bool {
    process::with_record(process_pointer, |record| !record.exiting && !record.terminated).unwrap_or(false)
}

fn create_workers(factory: &Arc<Factory>, desired: u32) -> Result<u32, KernelError> {
    if factory.port.closed() {
        shutdown(factory);
        return Ok(0xC000_010A);
    }
    if factory.shutdown() || factory.paused() || factory.creating() {
        return Ok(0);
    }
    reference(factory);
    factory.set_creating(true);
    let result = (|| -> Result<u32, KernelError> {
        let desired = desired.max(factory.minimum()).min(factory.maximum());
        while !factory.shutdown() && !factory.paused() && (live(factory).len() as u32) < desired {
            if !usable(factory.process_pointer()) {
                shutdown(factory);
                factory.set_last_status(0xC000_010A);
                return Ok(0xC000_010A);
            }
            // O runtime atual possui um espaço de usuário: a criação usa o
            // EPROCESS real da fábrica e o seu runtime de usuário.
            let parameter = factory.parameter();
            let request = CreateRequest {
                start: factory.start(),
                argument_words: [parameter as u32, (parameter >> 32) as u32],
                // A classe 13 marca os próximos workers para o carregador da
                // NTDLL; a criação materializa LoaderWorker no TEB real.
                flags: if factory.loader_worker() { 0x10 } else { 0 },
                zero_bits: 0,
                commit: factory.commit(),
                reserve: factory.reserve(),
            };
            // Só um processo de usuário vivo recebe workers.
            let created = if !state::is_user_process_id(factory.process_id()) { Err(0xC000_00BB) } else { process_context::with_process(factory.process_pointer(), || threads::create_user_thread(&request))? };
            let thread = match created {
                Ok(thread) => {
                    factory.set_last_status(0);
                    thread
                }
                Err(status) => {
                    factory.set_last_status(status);
                    factory.set_retry_at(clock::uptime_ms() as i64 - factory.retry_timeout() / 10_000);
                    return Ok(status);
                }
            };
            let pointer = thread.pointer();
            if thread.dead() || (pointer != 0 && process::thread_record(pointer).is_some_and(|record| record.exiting)) {
                factory.set_last_status(0xC000_010A);
                return Ok(0xC000_010A);
            }
            // Os callbacks de criação podem fechar todos os handles: a
            // referência da operação retém a fábrica até o worker ter a sua.
            reference(factory);
            let priority = factory.priority();
            thread.with(|thread| {
                thread.worker_factory = factory.pointer;
                thread.worker_ready = false;
                thread.priority = priority;
                thread.base_priority = priority;
            });
            factory.add_worker(thread);
        }
        Ok(0)
    })();
    factory.set_creating(false);
    dereference(factory);
    result
}

fn shutdown(factory: &Arc<Factory>) {
    factory.set_shutdown(true);
    factory.set_minimum(0);
    if let Some(listener) = factory.on_queued.lock().clone() {
        factory.port.listeners.lock().retain(|candidate| !Arc::ptr_eq(candidate, &listener));
    }
    cancel_deferred_creation(factory);
}

/// O limite flexível adia a expansão automática: a demanda real da fila
/// passa por duas reavaliações (30 e 120 ms) antes de criar acima dele.
fn request_queued_worker(factory: &Arc<Factory>, from_deferred_timer: bool) -> Result<u32, KernelError> {
    if factory.port.closed() {
        shutdown(factory);
        return Ok(0xC000_010A);
    }
    if factory.shutdown() || factory.paused() || factory.creating() {
        // O timer já retirou a entrada: uma pausa não deixa fase pendente
        // sem timer, o que bloquearia a expansão depois da retomada.
        if from_deferred_timer {
            factory.set_soft_creation_phase(0);
        }
        return Ok(0);
    }
    let workers = live(factory);
    let ready: Vec<&Arc<UserThread>> = workers.iter().filter(|thread| thread.with(|thread| thread.worker_ready)).collect();
    let busy = ready.iter().filter(|thread| !thread.waiting()).count() as u32;
    let desired = (busy + 1).max(factory.minimum()).min(factory.maximum());
    if factory.port.with(|state| state.packets.is_empty()) || workers.len() as u32 >= desired {
        factory.set_soft_creation_phase(0);
        return Ok(0);
    }
    if factory.soft_maximum() != 0 && ready.len() as u32 > factory.soft_maximum() {
        if factory.soft_creation_phase() == 0 {
            factory.set_soft_creation_phase(1);
            defer_worker_creation(factory, 3);
            return Ok(0);
        }
        if !from_deferred_timer {
            return Ok(0);
        }
        if factory.soft_creation_phase() == 1 {
            factory.set_soft_creation_phase(2);
            defer_worker_creation(factory, 2);
            return Ok(0);
        }
    }
    factory.set_soft_creation_phase(0);
    create_workers(factory, desired)
}

fn process_deferred_creations() {
    let pending = {
        let mut deferred = DEFERRED.lock();
        if deferred.deadline.is_none_or(|deadline| clock::uptime_ms() < deadline) {
            return;
        }
        deferred.deadline = None;
        deferred.priority = 0;
        core::mem::take(&mut deferred.factories)
    };
    for factory in pending {
        // A fila pode ter sido consumida, o limite alterado ou o objeto
        // encerrado: reavaliar impede threads desnecessárias.
        if let Err(error) = request_queued_worker(&factory, true) {
            crate::debug_print!("[workerfactory] {}", error);
        }
        dereference(&factory);
    }
}

/// Windows 19045: comprimento e captura antes do handle. Só o bit zero
/// altera LoaderWorker; os demais são ignorados.
fn set_worker_flags(handle: u64, input: u64, length: u32) -> u32 {
    if length != 4 {
        return 0xC000_0004;
    }
    if !state::probe_user_read(input, 4) {
        return 0xC000_0005;
    }
    // ULONG de entrada, sondado acima.
    let value = match guest::try_read::<u32>(input) {
        Ok(value) => value,
        Err(error) => return error.status,
    };
    let factory = match resolve(handle, 4) {
        Ok((_, factory)) => factory,
        Err(status) => return status,
    };
    // Aceita também uma fábrica encerrada; vale para as próximas criações.
    factory.set_loader_worker(value & 1 != 0);
    0
}

/// A captura precede a validação do handle; zero desativa o adiamento.
fn set_thread_soft_maximum(handle: u64, input: u64, length: u32) -> u32 {
    if length != 4 {
        return 0xC000_0004;
    }
    if !state::probe_user_read(input, 4) {
        return 0xC000_0005;
    }
    // ULONG de entrada, sondado acima.
    let value = match guest::try_read::<u32>(input) {
        Ok(value) => value,
        Err(error) => return error.status,
    };
    let factory = match resolve(handle, 4) {
        Ok((_, factory)) => factory,
        Err(status) => return status,
    };
    if factory.shutdown() {
        return 0x80; // STATUS_ABANDONED, medido no Windows.
    }
    factory.set_soft_maximum(if value != 0 { value.max(factory.minimum()).min(factory.maximum()) } else { 0 });
    0
}

fn dispose(factory: &Arc<Factory>) {
    if let Some(listener) = factory.on_queued.lock().take() {
        factory.port.listeners.lock().retain(|candidate| !Arc::ptr_eq(candidate, &listener));
    }
    FACTORIES.lock().retain(|candidate| !Arc::ptr_eq(candidate, factory));
    let _ = state::release_user_handle_reference(&factory.port_entry);
    let _ = process::dereference(factory.process_pointer());
}

fn last_handle_close(factory: &Arc<Factory>) {
    factory.set_closed(true);
    shutdown(factory);
}

fn nt_create_worker_factory(out: u64, access: u64, attributes: u64, port_handle: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) || !state::probe_syscall_stack(rsp, 48) || (attributes != 0 && !state::probe_user_read(attributes, 48)) {
        return Ok(0xC000_0005);
    }
    // Objetos sem nome.
    if attributes != 0 {
        match state::user_struct::<ObjectAttributes>(attributes).and_then(|object| object.object_name.probe_get()) {
            Ok(0) => {}
            Ok(_) => return Ok(0xC000_0033),
            Err(error) => return Ok(error.status),
        }
    }
    // ProcessHandle (quinto argumento): só o processo corrente.
    if state::stack_arg(rsp, 5) != u64::MAX {
        return Ok(0xC000_0008);
    }
    let process_pointer = process::get_current_process();
    if !usable(process_pointer) {
        return Ok(0xC000_010A);
    }
    let (entry, port) = match io_completion::resolve(port_handle, 2) {
        Ok(resolved) => resolved,
        Err(status) => return Ok(status),
    };
    let start = state::stack_arg(rsp, 6);
    let maximum = state::stack_arg32(rsp, 8);
    let reserve = state::stack_arg(rsp, 9);
    let commit = state::stack_arg(rsp, 10);
    if !state::probe_user_read(start, 1) {
        return Ok(0xC000_0005);
    }
    const SAFE: u64 = (1 << 53) - 1;
    if maximum == 0 || maximum > 0xFFFF || reserve > SAFE || commit > SAFE {
        return Ok(0xC000_000D);
    }
    let initial = FactoryInitial { port_entry: entry.clone(), port: port.clone(), start, parameter: state::stack_arg(rsp, 7), process_pointer, process_id: process::get_current_process_id(), maximum, reserve, commit };
    let factory = match work_objects::factory(initial, attributes, dispose, last_handle_close) {
        Ok(factory) => factory,
        Err(error) if error.status != 0 => return Ok(error.status),
        Err(error) => return Err(error),
    };
    state::retain_user_handle_reference(&entry);
    process::reference(process_pointer);
    let weak: Weak<Factory> = Arc::downgrade(&factory);
    let listener: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        if let Some(factory) = weak.upgrade() {
            if let Err(error) = request_queued_worker(&factory, false) {
                crate::debug_print!("[workerfactory] {}", error);
            }
        }
    });
    *factory.on_queued.lock() = Some(listener.clone());
    port.listeners.lock().push(listener);
    FACTORIES.lock().push(factory.clone());
    match work_objects::publish(factory.pointer, out, access as u32, attributes, factory.clone()) {
        Ok(status) => Ok(status),
        Err(error) => {
            crate::ntos::ob::objects::dispatcher::collect(factory.pointer);
            if error.status != 0 { Ok(error.status) } else { Err(error) }
        }
    }
}

fn nt_release_worker_factory_worker(handle: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    let factory = match resolve(handle, 1) {
        Ok((_, factory)) => factory,
        Err(status) => return Ok(status),
    };
    if factory.port.closed() {
        shutdown(&factory);
    }
    if factory.shutdown() {
        return Ok(0xC000_010A);
    }
    // TppProcessIoCompletion da NTDLL reconhece KeyContext nulo como pedido
    // para drenar a fila de trabalho de usuário (19041, RVA 4e2e7/4e412).
    reference(&factory);
    io_completion::enqueue(&factory.port, Packet::default());
    factory.add_release_count();
    let result = request_queued_worker(&factory, false);
    dereference(&factory);
    result
}

fn nt_worker_factory_worker_ready(handle: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    let factory = match resolve(handle, 0x10) {
        Ok((_, factory)) => factory,
        Err(status) => return Ok(status),
    };
    let Some(thread) = threads::current().filter(|thread| thread.with(|thread| thread.worker_factory) == factory.pointer) else { return Ok(0xC000_000D) };
    thread.with(|thread| thread.worker_ready = true);
    Ok(if factory.shutdown() { 0xC000_010A } else { 0 })
}

fn nt_set_information_worker_factory(handle: u64, class: u64, input: u64, length: u64, _rsp: u64) -> Result<u32, KernelError> {
    let (class, length) = (class as u32, length as u32);
    if class == 13 {
        return Ok(set_worker_flags(handle, input, length));
    }
    if class == 14 {
        return Ok(set_thread_soft_maximum(handle, input, length));
    }
    let factory = match resolve(handle, 4) {
        Ok((_, factory)) => factory,
        Err(status) => return Ok(status),
    };
    if factory.shutdown() {
        return Ok(0xC000_010A);
    }
    if ![2, 3, 4, 5, 6, 8, 11].contains(&class) {
        crate::debug_print!("[workerfactory] information class={} unsupported", class);
        return Ok(0xC000_0003);
    }
    let size = if class == 2 { 8 } else if class == 6 && length == 1 { 1 } else { 4 };
    if length != size {
        return Ok(0xC000_0004);
    }
    if !state::probe_user_read(input, size as u64) {
        return Ok(0xC000_0005);
    }
    // BOOLEAN, ULONG ou LARGE_INTEGER de entrada, sondado acima.
    let value = match if size == 1 { guest::try_read::<u8>(input).map(u32::from) } else { guest::try_read::<u32>(input) } {
        Ok(value) => value,
        Err(error) => return Ok(error.status),
    };
    match class {
        2 => {
            let signed = match guest::try_read::<i64>(input) {
                Ok(signed) => signed,
                Err(error) => return Ok(error.status),
            };
            if signed >= 0 {
                return Ok(0xC000_000D);
            }
            factory.set_idle_timeout(signed);
            Ok(0)
        }
        3 => {
            // A contagem de vínculos é um delta com sinal, não absoluta.
            let count = factory.binding_count() as i64 + value as i32 as i64;
            if count < 0 {
                return Ok(0xC000_000D);
            }
            factory.set_binding_count(count as u32);
            Ok(0)
        }
        4 => {
            if value > factory.maximum() {
                return Ok(0xC000_000D);
            }
            factory.set_minimum(value);
            create_workers(&factory, value)
        }
        5 => {
            if value == 0 || value > 0xFFFF || value < factory.minimum() {
                return Ok(0xC000_000D);
            }
            factory.set_maximum(value);
            Ok(0)
        }
        6 => {
            if value > 1 {
                return Ok(0xC000_000D);
            }
            factory.set_paused(value != 0);
            create_workers(&factory, factory.minimum())
        }
        8 => create_workers(&factory, value),
        _ => {
            if !(1..=31).contains(&value) {
                return Ok(0xC000_000D);
            }
            factory.set_priority(value);
            for thread in live(&factory) {
                thread.with(|thread| {
                    thread.priority = value;
                    thread.base_priority = value;
                });
            }
            Ok(0)
        }
    }
}

fn nt_query_information_worker_factory(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let factory = match resolve(handle, 8) {
        Ok((_, factory)) => factory,
        Err(status) => return Ok(status),
    };
    if class as u32 != 7 {
        return Ok(0xC000_0003);
    }
    let returned = state::stack_arg(rsp, 5);
    if returned != 0 && !state::probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        if returned != 0 {
            guest::try_write::<u32>(returned, WorkerFactoryBasicInformation::SIZE as u32)?;
        }
        if length != WorkerFactoryBasicInformation::SIZE {
            return Ok(0xC000_0004);
        }
        if !state::probe_user_write(out, WorkerFactoryBasicInformation::SIZE) {
            return Ok(0xC000_0005);
        }
        let workers = live(&factory);
        guest::try_write_bytes(out, &[0; WorkerFactoryBasicInformation::SIZE as usize])?;
        let information = state::user_struct::<WorkerFactoryBasicInformation>(out)?;
        information.timeout.quad_part.probe_set(factory.timeout())?;
        information.retry_timeout.quad_part.probe_set(factory.retry_timeout())?;
        information.idle_timeout.quad_part.probe_set(factory.idle_timeout())?;
        information.paused.probe_set(factory.paused() as u8)?;
        information.queued_to_ex_worker.probe_set(is_deferred(&factory) as u8)?;
        information.may_create.probe_set((!factory.shutdown() && (workers.len() as u32) < factory.maximum()) as u8)?;
        information.shutdown.probe_set(factory.shutdown() as u8)?;
        information.binding_count.probe_set(factory.binding_count())?;
        information.thread_minimum.probe_set(factory.minimum())?;
        information.thread_maximum.probe_set(factory.maximum())?;
        information.pending_worker_count.probe_set(workers.iter().filter(|thread| !thread.with(|thread| thread.worker_ready)).count() as u32)?;
        information.waiting_worker_count.probe_set(workers.iter().filter(|thread| thread.wait_worker_factory() == factory.pointer).count() as u32)?;
        information.total_worker_count.probe_set(workers.len() as u32)?;
        information.release_count.probe_set(factory.release_count())?;
        information.infinite_wait_goal.probe_set(factory.minimum() as i64)?;
        information.start_routine.probe_set(factory.start())?;
        information.start_parameter.probe_set(factory.parameter())?;
        information.process_id.probe_set(factory.process_id())?;
        information.stack_reserve.probe_set(factory.reserve())?;
        information.stack_commit.probe_set(factory.commit())?;
        information.last_thread_creation_status.probe_set(factory.last_status() as i32)?;
        Ok(0)
    })
}

fn nt_wait_for_work_via_worker_factory(handle: u64, out: u64, count: u64, returned: u64, rsp: u64) -> Result<u32, KernelError> {
    let (entry, factory) = match resolve(handle, 2) {
        Ok(resolved) => resolved,
        Err(status) => return Ok(status),
    };
    let Some(thread) = threads::current().filter(|thread| thread.with(|thread| thread.worker_factory) == factory.pointer) else { return Ok(0xC000_000D) };
    let deferred = state::stack_arg(rsp, 5);
    if deferred != 0 && !state::probe_user_read(deferred, 24) {
        return Ok(0xC000_0005);
    }
    // Envios ALPC adiados exigem a implementação assíncrona do ALPC.
    if deferred != 0 {
        let work = state::user_struct::<WorkerFactoryDeferredWork>(deferred).and_then(|work| Ok((work.alpc_send_message.probe_get()?, work.alpc_send_message_port.probe_get()?)));
        match work {
            Ok((0, 0)) => {}
            Ok(_) => return Ok(0xC000_00BB),
            Err(error) => return Ok(error.status),
        }
    }
    let count = count as u32;
    if count == 0 || count > 0x7FFF_FFFF / 32 {
        return Ok(0xC000_000D);
    }
    let validate: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || state::probe_user_write(out, count as u64 * 32) && state::probe_user_write(returned, 4));
    // Os pacotes retirados são escritos sob a trava da porta; as
    // notificações de retirada rodam depois, fora dela.
    let deliver = Box::new(move |packets: &mut VecDeque<Packet>| {
        let size = (count as usize).min(packets.len());
        let mut dequeued: Vec<Box<dyn FnOnce() + Send>> = Vec::new();
        for index in 0..size {
            let Some(mut packet) = packets.pop_front() else { break };
            let at = out + index as u64 * FileIoCompletionInformation::SIZE;
            let (key, context, status, information) = packet.values();
            // Saídas sondadas pelo `validate` logo antes; uma página desmapeada
            // nesse meio tempo perde só a cópia do pacote.
            let _ = state::user_struct::<FileIoCompletionInformation>(at).and_then(|entry| {
                entry.key_context.probe_set(key)?;
                entry.apc_context.probe_set(context)?;
                state::set_user_iosb(entry.io_status_block.address(), status as u32, information)
            });
            if let Some(on_dequeue) = packet.on_dequeue.take() {
                dequeued.push(on_dequeue);
            }
        }
        let _ = guest::try_write::<u32>(returned, size as u32);
        let on_dequeue: Option<Box<dyn FnOnce() + Send>> = if dequeued.is_empty() {
            None
        } else {
            Some(Box::new(move || {
                for notify in dequeued {
                    notify();
                }
            }))
        };
        Some(Packet { on_dequeue, ..Packet::default() })
    });
    let idle = live(&factory).len() as u32 > factory.minimum();
    let timeout_ms = if idle { Some((-factory.idle_timeout() / 10_000) as u64) } else { None };
    let watched = factory.clone();
    let options = RemoveOptions { entries: alloc::vec![entry], poll: Some(Box::new(move || watched.shutdown().then_some(0x80))), cleanup: None, timeout_ms: Some(timeout_ms) };
    let status = io_completion::remove_entry(factory.port_entry.clone(), factory.port.clone(), 0, false, validate, deliver, options);
    thread.mark_wait_worker_factory(factory.pointer);
    Ok(status)
}

fn nt_shutdown_worker_factory(handle: u64, pending_count: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    let factory = match resolve(handle, 0x20) {
        Ok((_, factory)) => factory,
        Err(status) => return Ok(status),
    };
    if !state::probe_user_write(pending_count, 4) {
        return Ok(0xC000_0005);
    }
    if !factory.shutdown() {
        // Workers que ainda não entraram na NTDLL não tomam a referência
        // normal do pool: as pendentes são transferidas no encerramento.
        let pending = live(&factory).iter().filter(|thread| !thread.with(|thread| thread.worker_ready)).count() as u32;
        // `volatile LONG *PendingWorkerCount`: os workers de modo usuário o
        // alteram ao mesmo tempo; a soma é uma única instrução interlocked.
        match guest::try_atomic_u32(pending_count) {
            Ok(counter) => {
                counter.fetch_add(pending, core::sync::atomic::Ordering::SeqCst);
            }
            Err(error) => return Ok(error.status),
        }
    }
    shutdown(&factory);
    Ok(0)
}

/// As fábricas do processo `process_id`, que saiu.
pub fn release_process(process_id: u64) {
    let factories = FACTORIES.lock().clone();
    for factory in factories.iter().filter(|factory| factory.process_id() == process_id) {
        shutdown(factory);
    }
}

pub fn pump() {
    let factories = FACTORIES.lock().clone();
    for factory in factories {
        if !FACTORIES.lock().iter().any(|candidate| Arc::ptr_eq(candidate, &factory)) {
            continue;
        }
        reference(&factory);
        let result = (|| -> Result<(), KernelError> {
            if factory.port.closed() {
                shutdown(&factory);
            }
            for thread in factory.workers() {
                if thread.dead() {
                    remove_worker(&factory, &thread);
                }
            }
            if factory.shutdown() || factory.paused() || (factory.last_status() != 0 && (clock::uptime_ms() as i64) < factory.retry_at()) {
                return Ok(());
            }
            // Mantém o mínimo depois da saída de workers; uma criação falha
            // é repetida após o intervalo de nova tentativa.
            create_workers(&factory, factory.minimum())?;
            request_queued_worker(&factory, false)?;
            Ok(())
        })();
        if let Err(error) = result {
            crate::debug_print!("[workerfactory] {}", error);
        }
        dereference(&factory);
    }
    process_deferred_creations();
}

fn thread_exit(pointer: u64) {
    let factories = FACTORIES.lock().clone();
    for factory in factories {
        if !usable(factory.process_pointer()) {
            shutdown(&factory);
        }
        for thread in factory.workers() {
            if thread.pointer() == pointer {
                remove_worker(&factory, &thread);
            }
        }
    }
}

pub fn init() {
    process::register_thread_exit_routine(thread_exit);
    state::register_handler("NtCreateWorkerFactory", nt_create_worker_factory);
    state::register_handler("NtReleaseWorkerFactoryWorker", nt_release_worker_factory_worker);
    state::register_handler("NtWorkerFactoryWorkerReady", nt_worker_factory_worker_ready);
    state::register_handler("NtSetInformationWorkerFactory", nt_set_information_worker_factory);
    state::register_handler("NtQueryInformationWorkerFactory", nt_query_information_worker_factory);
    state::register_handler("NtWaitForWorkViaWorkerFactory", nt_wait_for_work_via_worker_factory);
    state::register_handler("NtShutdownWorkerFactory", nt_shutdown_worker_factory);
    threads::set_pump(threads::pump::WORKER_FACTORY, pump);
}
