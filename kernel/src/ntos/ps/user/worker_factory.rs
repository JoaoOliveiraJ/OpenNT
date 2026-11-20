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
use crate::ntos::ke::{clock, processor_group, smp};
use crate::ntos::ob::objects::completion::Packet;
use crate::ntos::ob::objects::dispatcher::UserDispatcher;
use crate::ntos::ob::objects::work::{self as work_objects, Factory, FactoryInitial};
use crate::ntos::ps::{process, process_context};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::extra_ps_user::WorkerFactoryDeferredWork;
use crate::ntos::inc::types::{Ethread, FileIoCompletionInformation, NtStruct, ObjectAttributes, WorkerFactoryBasicInformation};

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
    if thread.with(|thread| thread.worker_ready) {
        let _ = factory.update_ready_workers(|count| count.checked_sub(1));
    }
    thread.with(|thread| thread.worker_factory = 0);
    dereference(factory);
}

/// A fábrica só cria threads num processo sem fim pedido: senão o
/// PspInsertThread recusa (STATUS_PROCESS_IS_TERMINATING) e a fábrica para
/// com esse LastThreadCreationStatus.
fn usable(process_pointer: u64) -> bool {
    process::with_record(process_pointer, |record| !record.exiting && !record.terminated).unwrap_or(false) && !threads::exit_pending(process_pointer)
}

/// CREATE_SUSPENDED e LoaderWorker do RtlpCreateUserThreadEx.
const CREATE_SUSPENDED: u32 = 1;
const CREATE_LOADER_WORKER: u32 = 0x10;

/// Um worker, como o ExpWorkerFactoryCreateThread do 19041: a thread nasce
/// sempre suspensa (CREATE_SUSPENDED, mais LoaderWorker pela classe 13),
/// entra na fábrica e só então é retomada. Assim o TppWorkerThread, em
/// qualquer CPU, já se acha worker desta fábrica no primeiro
/// NtWorkerFactoryWorkerReady e na primeira espera. Devolve o status da
/// criação, guardado também no LastThreadCreationStatus.
fn create_thread(factory: &Arc<Factory>) -> Result<u32, KernelError> {
    if factory.shutdown() {
        return Ok(0x80);
    }
    if !usable(factory.process_pointer()) {
        shutdown(factory);
        factory.set_last_status(0xC000_010A);
        return Ok(0xC000_010A);
    }
    // O runtime atual possui um espaço de usuário: a criação usa o EPROCESS
    // real da fábrica e o seu runtime de usuário.
    let parameter = factory.parameter();
    let request = CreateRequest {
        start: factory.start(),
        argument_words: [parameter as u32, (parameter >> 32) as u32],
        // A classe 13 marca os próximos workers para o carregador da NTDLL;
        // a criação materializa LoaderWorker no TEB real.
        flags: CREATE_SUSPENDED | if factory.loader_worker() { CREATE_LOADER_WORKER } else { 0 },
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
    // Os callbacks de criação podem fechar todos os handles: a referência
    // do worker retém a fábrica até ele sair dela.
    reference(factory);
    thread.with(|thread| {
        thread.worker_factory = factory.pointer;
        thread.worker_ready = false;
    });
    factory.add_worker(thread);
    factory.add_flags(work_objects::FACTORY_THREAD_CREATED);
    // O incremento da classe 11 vai pela ThreadBasePriority antes de a
    // thread rodar; uma recusa (incremento fora de -2..2 e ±16 fora do tempo
    // real) deixa a prioridade do processo, como no 19041.
    let increment = factory.priority() as i32;
    if increment != 0 {
        let _ = threads::set_base_priority_increment(pointer, increment);
    }
    threads::resume_thread(pointer);
    Ok(0)
}

/// Cria workers um a um enquanto `done` for falso, como a única criação em
/// andamento da fábrica; devolve a primeira falha.
fn create_until(factory: &Arc<Factory>, mut done: impl FnMut(&Factory) -> bool) -> Result<u32, KernelError> {
    if factory.port.closed() {
        shutdown(factory);
        return Ok(0xC000_010A);
    }
    if factory.shutdown() || factory.creating() {
        return Ok(0);
    }
    reference(factory);
    factory.set_creating(true);
    let result = (|| -> Result<u32, KernelError> {
        while !factory.shutdown() && !done(factory) {
            let status = create_thread(factory)?;
            if status != 0 {
                return Ok(status);
            }
        }
        Ok(0)
    })();
    factory.set_creating(false);
    dereference(factory);
    result
}

fn create_workers(factory: &Arc<Factory>, desired: u32) -> Result<u32, KernelError> {
    let desired = desired.max(factory.minimum()).min(factory.maximum());
    create_until(factory, |factory| live(factory).len() as u32 >= desired)
}

fn shutdown(factory: &Arc<Factory>) {
    factory.set_shutdown(true);
    factory.set_minimum(0);
    if let Some(listener) = factory.on_queued.lock().clone() {
        factory.port.listeners.lock().retain(|candidate| !Arc::ptr_eq(candidate, &listener));
    }
    cancel_deferred_creation(factory);
}

/// A criação pela fila, como o fim do NtWaitForWorkViaWorkerFactory do 19041
/// (0x2040fd..0x204176): com trabalho na fila e nenhum worker esperando nela,
/// um worker novo (o ExpWorkerFactoryCheckCreate). Um worker pronto parado
/// em outra espera (um evento, uma chamada ALPC, um lock) não atende a fila:
/// conta como ocupado, como o que roda. O limite flexível adia a expansão
/// automática: a demanda real da fila passa por duas reavaliações (30 e 120
/// ms) antes de criar acima dele.
fn request_queued_worker(factory: &Arc<Factory>, from_deferred_timer: bool) -> Result<u32, KernelError> {
    if factory.port.closed() {
        shutdown(factory);
        return Ok(0xC000_010A);
    }
    if factory.shutdown() || factory.creating() {
        // O timer já retirou a entrada: uma criação em andamento não deixa
        // fase pendente sem timer, o que bloquearia a expansão depois.
        if from_deferred_timer {
            factory.set_soft_creation_phase(0);
        }
        return Ok(0);
    }
    let workers = live(factory);
    let ready: Vec<&Arc<UserThread>> = workers.iter().filter(|thread| thread.with(|thread| thread.worker_ready)).collect();
    let busy = ready.iter().filter(|thread| !(thread.waiting() && thread.wait_worker_factory() == factory.pointer)).count() as u32;
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

/// Workers criados que ainda não passaram pelo NtWorkerFactoryWorkerReady
/// (o PendingWorkerCount).
fn pending(factory: &Factory) -> u32 {
    live(factory).iter().filter(|thread| !thread.with(|thread| thread.worker_ready)).count() as u32
}

/// Workers que passaram pelo NtWorkerFactoryWorkerReady e ainda contam na
/// fábrica (o TotalWorkerCount).
fn total(factory: &Factory) -> u32 {
    live(factory).iter().filter(|thread| thread.with(|thread| thread.worker_ready)).count() as u32
}

/// O pedido de worker das classes 5 e 9: numa fábrica encerrada,
/// STATUS_ABANDONED; com os workers prontos no máximo,
/// STATUS_TOO_MANY_THREADS; senão um worker novo, se nenhum está sendo
/// criado e os prontos mais os pendentes ainda cabem no máximo. Devolve o
/// status da criação.
fn request_worker(factory: &Arc<Factory>) -> Result<u32, KernelError> {
    if factory.shutdown() {
        return Ok(0x80);
    }
    let count = factory.ready_workers();
    if count >= factory.maximum() {
        return Ok(0xC000_0129);
    }
    if factory.creating() || count + pending(factory) >= factory.maximum() {
        return Ok(0);
    }
    let mut first = true;
    create_until(factory, |_| !core::mem::replace(&mut first, false))
}

/// WorkerFactoryIdleTimeout (2): um LARGE_INTEGER relativo (negativo, senão
/// STATUS_INVALID_PARAMETER), limitado a [-600 s, -1 s]; vale para as
/// próximas esperas dos workers.
fn set_idle_timeout(factory: &Factory, value: i64) -> u32 {
    if factory.shutdown() {
        return 0x80;
    }
    if value >= 0 {
        return 0xC000_000D;
    }
    factory.set_idle_timeout(value.clamp(-6_000_000_000, -10_000_000));
    0
}

/// WorkerFactoryBindingCount (3, o TpAdjustBindingCount): um delta com
/// sinal, sem falha e sem olhar o encerramento. O positivo satura em
/// 0xFFFFFFFF (como no 19041, o delta zero também cai na saturação) e o
/// negativo em zero. A primeira ligação (de zero para não zero) pede um
/// worker se já há trabalho na fila.
fn adjust_binding_count(factory: &Arc<Factory>, delta: i32) -> Result<u32, KernelError> {
    let old = factory.binding_count();
    let new = if delta >= 0 {
        let sum = old.wrapping_add(delta as u32);
        if old < sum { sum } else { u32::MAX }
    } else {
        old.saturating_sub(delta.unsigned_abs())
    };
    factory.set_binding_count(new);
    if old == 0 && new != 0 {
        request_queued_worker(factory, false)?;
    }
    Ok(0)
}

/// WorkerFactoryThreadMinimum (4): o mínimo novo, e o máximo sobe junto se
/// ficar abaixo dele (sem erro). Se o mínimo cresceu, os workers que faltam
/// (prontos mais pendentes abaixo do mínimo) são criados agora, um a um; a
/// primeira falha de criação volta.
fn set_thread_minimum(factory: &Arc<Factory>, value: u32) -> Result<u32, KernelError> {
    if factory.shutdown() {
        return Ok(0x80);
    }
    let grew = value > factory.minimum();
    factory.set_minimum(value);
    if factory.maximum() < value {
        factory.set_maximum(value);
    }
    if !grew {
        return Ok(0);
    }
    create_until(factory, |factory| factory.ready_workers() + pending(factory) >= factory.minimum())
}

/// WorkerFactoryThreadMaximum (5): qualquer valor, zero inclusive; o mínimo
/// desce junto se ficar acima dele. Com máximo não nulo e trabalho na fila
/// (as liberações pendentes também são pacotes da fila), um worker é
/// pedido; o resultado do pedido não volta.
fn set_thread_maximum(factory: &Arc<Factory>, value: u32) -> Result<u32, KernelError> {
    if factory.shutdown() {
        return Ok(0x80);
    }
    let work = value != 0 && factory.port.with(|state| !state.packets.is_empty());
    factory.set_maximum(value);
    if value < factory.minimum() {
        factory.set_minimum(value);
    }
    if work {
        request_worker(factory)?;
    }
    Ok(0)
}

/// WorkerFactoryCallbackType (9, rva 0x2dc2c7 do 19041): um ULONG que a
/// ntdll manda em volta de um callback longo. 1 é o TpCallbackMayRunLong e
/// 2 o TpCallbackIndependent; 0 desfaz no TppCallbackEpilog e 3 vem da
/// saída do worker (TppWorkerThread). 0 sobe a contagem dos workers prontos
/// (STATUS_UNSUCCESSFUL se ela já é o total); 2 e 3 a descem
/// (STATUS_UNSUCCESSFUL em zero) e, quando ela zera, pedem um worker como o
/// 1; o 3 também tira o worker que chama do total, então a saída da thread
/// não desconta de novo. Outro valor é STATUS_INVALID_PARAMETER. O servidor
/// LRPC do rpcrt4 recusa o bind com ERROR_MAX_THRDS_REACHED se o
/// TpCallbackMayRunLong falha.
fn set_callback_type(factory: &Arc<Factory>, value: u32) -> Result<u32, KernelError> {
    let grow = match value {
        0 => {
            let total = total(factory);
            if factory.update_ready_workers(|count| (count != total).then(|| count + 1)).is_err() {
                return Ok(0xC000_0001);
            }
            false
        }
        1 => true,
        2 | 3 => {
            let Ok(count) = factory.update_ready_workers(|count| count.checked_sub(1)) else { return Ok(0xC000_0001) };
            if value == 3 {
                if let Some(thread) = threads::current().filter(|thread| thread.with(|thread| thread.worker_factory) == factory.pointer) {
                    thread.with(|thread| thread.worker_ready = false);
                    remove_worker(factory, &thread);
                }
            }
            count == 1
        }
        _ => return Ok(0xC000_000D),
    };
    if !grow {
        return Ok(0);
    }
    request_worker(factory)
}

/// WorkerFactoryStackInformation (10): o TP_POOL_STACK_INFORMATION
/// {StackReserve, StackCommit} das próximas threads, sem validação. O
/// TppPoolpReferenceGlobalPool da ntdll trata a falha como fatal, e todo
/// Tp* do pool global falharia.
fn set_stack_information(factory: &Factory, reserve: u64, commit: u64) -> u32 {
    if factory.shutdown() {
        return 0x80;
    }
    factory.set_reserve(reserve);
    factory.set_commit(commit);
    0
}

/// WorkerFactoryThreadSoftMaximum (14): zero desliga o limite flexível;
/// outro valor fica entre o mínimo e o máximo.
fn set_thread_soft_maximum(factory: &Factory, value: u32) -> u32 {
    if factory.shutdown() {
        return 0x80;
    }
    factory.set_soft_maximum(if value != 0 { value.max(factory.minimum()).min(factory.maximum()) } else { 0 });
    0
}

/// O status do KiValidateCpuSetMasks para máscaras fora dos processadores
/// ativos.
const STATUS_INVALID_CPU_SET_MASKS: u32 = 0xC000_01AF;

/// WorkerFactoryThreadCpuSets (15): as máscaras de CPU sets por grupo.
/// Depois do primeiro worker criado, STATUS_INVALID_STATE_TRANSITION. As
/// máscaras passam pela validação do KiValidateCpuSetMasks (no máximo uma
/// por grupo, cada uma dentro dos processadores ativos do grupo) e
/// substituem as anteriores. O kernel ainda não aplica CPU sets a threads:
/// elas ficam guardadas na fábrica.
fn set_thread_cpu_sets(factory: &Factory, captured: &[u8]) -> u32 {
    if factory.shutdown() {
        return 0x80;
    }
    if factory.flags() & work_objects::FACTORY_THREAD_CREATED != 0 {
        return 0xC000_A003;
    }
    let masks: Vec<u64> = captured.chunks_exact(8).map(|bytes| u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]])).collect();
    if masks.len() as u64 > processor_group::group_count() {
        return STATUS_INVALID_CPU_SET_MASKS;
    }
    if masks.iter().enumerate().any(|(group, mask)| mask & !processor_group::group_affinity(group as u16) != 0) {
        return STATUS_INVALID_CPU_SET_MASKS;
    }
    factory.set_cpu_sets(&masks);
    factory.add_flags(work_objects::FACTORY_CPU_SETS);
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

/// NtReleaseWorkerFactoryWorker (19041 rva 0x2424e0): uma conclusão de
/// chave nula na IOCP e a reavaliação da criação; numa fábrica encerrada,
/// STATUS_ABANDONED sem enfileirar. O resultado da reavaliação não volta.
fn nt_release_worker_factory_worker(handle: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    let factory = match resolve(handle, 1) {
        Ok((_, factory)) => factory,
        Err(status) => return Ok(status),
    };
    if factory.port.closed() {
        shutdown(&factory);
    }
    if factory.shutdown() {
        return Ok(0x80);
    }
    // TppProcessIoCompletion da NTDLL reconhece KeyContext nulo como pedido
    // para drenar a fila de trabalho de usuário (19041, RVA 4e2e7/4e412).
    reference(&factory);
    io_completion::enqueue(&factory.port, Packet::default());
    factory.add_release_count();
    let result = request_queued_worker(&factory, false);
    dereference(&factory);
    result.map(|_| 0)
}

/// NtWorkerFactoryWorkerReady (19041 rva 0x3110a0): o worker criado pela
/// fábrica passa a contar entre os prontos e no total, uma vez; outra
/// chamada (ou de uma thread que não é worker pendente desta fábrica) é
/// STATUS_UNSUCCESSFUL, como sem criação em andamento. Depois do
/// encerramento, que entregou os pendentes ao contador do
/// NtShutdownWorkerFactory, o worker pendente recebe
/// STATUS_PROCESS_IS_TERMINATING e a ntdll o encerra.
fn nt_worker_factory_worker_ready(handle: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    let factory = match resolve(handle, 0x10) {
        Ok((_, factory)) => factory,
        Err(status) => return Ok(status),
    };
    let Some(thread) = threads::current().filter(|thread| thread.with(|thread| thread.worker_factory == factory.pointer && !thread.worker_ready)) else { return Ok(0xC000_0001) };
    if factory.shutdown() {
        return Ok(0xC000_010A);
    }
    if thread.with(|thread| !core::mem::replace(&mut thread.worker_ready, true)) {
        let _ = factory.update_ready_workers(|count| count.checked_add(1));
    }
    Ok(0)
}

/// O maior buffer da classe 15 (as máscaras de todos os grupos).
const CPU_SETS_SIZE: u32 = (work_objects::CPU_SET_GROUPS * 8) as u32;

/// NtSetInformationWorkerFactory(handle, class, buffer, length) na ordem do
/// 19041 (rva 0x2dbae0): a classe (2 a 15, senão STATUS_INVALID_INFO_CLASS;
/// a 7 só de consulta), o tamanho dela (STATUS_INFO_LENGTH_MISMATCH; a 6,
/// WorkerFactoryPaused, é STATUS_NOT_IMPLEMENTED), a captura do buffer de
/// usuário (alinhado em 4 nas classes 2, 9, 10 e 15; a 12 é de entrada e
/// saída) e só então o handle, com WORKER_FACTORY_SET_INFORMATION. Numa
/// fábrica encerrada as classes 2, 4, 5, 10, 11, 14 e 15 voltam 0x80
/// (STATUS_ABANDONED).
fn nt_set_information_worker_factory(handle: u64, class: u64, input: u64, length: u64, _rsp: u64) -> Result<u32, KernelError> {
    let (class, length) = (class as u32, length as u32);
    let size = match class {
        2 => 8,
        3 | 4 | 5 | 8 | 9 | 11 | 12 | 13 | 14 => 4,
        6 => return Ok(0xC000_0002),
        10 => 16,
        // Um múltiplo de 8 até 0xA0 bytes.
        15 => {
            if length >= CPU_SETS_SIZE {
                CPU_SETS_SIZE
            } else {
                length + (length & 7)
            }
        }
        _ => {
            crate::debug_print!("[workerfactory] information class={} unsupported", class);
            return Ok(0xC000_0003);
        }
    };
    if length != size {
        return Ok(0xC000_0004);
    }
    if size != 0 && matches!(class, 2 | 9 | 10 | 15) && input & 3 != 0 {
        return Ok(0x8000_0002);
    }
    // A 12 devolve o resultado no próprio buffer: sondado para gravação.
    let probed = if class == 12 { state::probe_user_write(input, 4) } else { size == 0 || state::probe_user_read(input, size as u64) };
    if !probed {
        return Ok(0xC000_0005);
    }
    // O buffer de entrada, sondado acima, capturado de uma vez.
    let captured = if size == 0 {
        Vec::new()
    } else {
        match guest::try_read_bytes(input, size as usize) {
            Ok(bytes) => bytes,
            Err(error) => return Ok(error.status),
        }
    };
    let word = |offset: usize| captured.get(offset..offset + 8).map_or(0, |bytes| u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]));
    let value = captured.get(..4).map_or(0, |bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    let factory = match resolve(handle, 4) {
        Ok((_, factory)) => factory,
        Err(status) => return Ok(status),
    };
    match class {
        2 => Ok(set_idle_timeout(&factory, word(0) as i64)),
        3 => adjust_binding_count(&factory, value as i32),
        4 => set_thread_minimum(&factory, value),
        5 => set_thread_maximum(&factory, value),
        // WorkerFactoryAdjustThreadGoal: só a concorrência da IOCP (o
        // KQUEUE.MaximumCount), o valor ou, com zero, o número de
        // processadores; sem olhar o encerramento e sem criar workers.
        8 => {
            factory.port.set_concurrency(if value != 0 { value } else { smp::online_cpu_count() as u32 });
            Ok(0)
        }
        9 => set_callback_type(&factory, value),
        10 => Ok(set_stack_information(&factory, word(0), word(8))),
        // WorkerFactoryThreadBasePriority: o incremento de prioridade de
        // base (a ntdll manda de -16 a 16) que cada worker novo recebe antes
        // de rodar; sem validação, gravado mesmo numa fábrica encerrada.
        11 => {
            factory.set_priority(value);
            Ok(if factory.shutdown() { 0x80 } else { 0 })
        }
        12 => Ok(timeout_waiters(&factory, input)),
        // WorkerFactoryFlags: só o bit 0 (LoaderWorker) conta, também numa
        // fábrica encerrada; vale para as próximas criações.
        13 => {
            factory.set_loader_worker(value & 1 != 0);
            Ok(0)
        }
        14 => Ok(set_thread_soft_maximum(&factory, value)),
        _ => Ok(set_thread_cpu_sets(&factory, &captured)),
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

/// WORKER_FACTORY_DEFERRED_WORK.Flags: há resposta a enviar.
const DEFERRED_SEND: u32 = 1;
/// ALPC_MSGFLG_SYNC_REQUEST: o envio antes da espera não acontece.
const ALPC_SYNC_REQUEST: u32 = 0x2_0000;

/// O envio ALPC adiado capturado do WORKER_FACTORY_DEFERRED_WORK.
#[derive(Clone, Copy)]
struct DeferredSend {
    message: u64,
    port: u64,
    flags: u32,
}

impl DeferredSend {
    /// A mensagem sem atributos nem recepção (`alpc::deferred_send`); a
    /// falha só fica no log, com o cabeçalho PORT_MESSAGE da mensagem
    /// recusada (DataLength, TotalLength, Type, DataInfoOffset e MessageId).
    fn send(self, flags: u32) -> Result<(), KernelError> {
        let status = crate::ntos::ps::user::alpc::deferred_send(self.port, flags, self.message)?;
        if status & 0x8000_0000 != 0 {
            let header = guest::try_read_bytes(self.message, 0x28).unwrap_or_default();
            let word = |offset: usize| header.get(offset..offset + 2).map_or(0, |bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
            let id = header.get(0x18..0x1C).map_or(0, |bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
            crate::debug_print!("[workerfactory] envio adiado na porta {:#x} (flags {:#x}) falhou: {:#x} (DataLength {:#x} TotalLength {:#x} Type {:#x} DataInfoOffset {:#x} MessageId {:#x})", self.port, flags, status, word(0), word(2), word(4), word(6), id);
        }
        Ok(())
    }
}

/// Workers com a espera de trabalho desta fábrica instalada (o
/// WaitingWorkerCount).
fn waiting(factory: &Factory) -> u32 {
    live(factory).iter().filter(|thread| thread.wait_worker_factory() == factory.pointer).count() as u32
}

/// O worker `thread` sai da fábrica pela espera (STATUS_TIMEOUT): deixa os
/// prontos e o total agora, como a retirada do 19041, e a ntdll encerra a
/// thread sem mandar a classe 9 (3).
fn retire(factory: &Factory, thread: &Arc<UserThread>) {
    if thread.with(|thread| thread.worker_factory) == factory.pointer {
        remove_worker(factory, thread);
    }
}

/// Um worker cuja espera terminou por tempo fica na fábrica se há trabalho
/// na fila (que um worker novo pegaria), se os prontos não passam do
/// mínimo ou se a thread ainda tem IRPs pendentes (a IrpList do ETHREAD).
fn should_stay(factory: &Factory, thread: &UserThread) -> bool {
    if !factory.port.with(|state| state.packets.is_empty()) || factory.ready_workers() <= factory.minimum() {
        return true;
    }
    let pointer = thread.pointer();
    // SAFETY: o ETHREAD da thread que espera, vivo durante a espera.
    let irps = &unsafe { Ethread::at(pointer) }.irp_list;
    pointer != 0 && irps.flink.get() != irps.address()
}

/// WorkerFactoryTimeoutWaiters (12, o TpTrimPools): sem criação em
/// andamento e com mais workers prontos que o mínimo, até o excesso dos
/// workers que esperam trabalho tem a espera terminada com STATUS_TIMEOUT
/// (o KeTimeOutQueueWaiters); cada um ainda confere se deve ficar. O número
/// volta no próprio buffer (de entrada e saída). Sem olhar o encerramento.
fn timeout_waiters(factory: &Factory, buffer: u64) -> u32 {
    let mut count = 0;
    let (ready, minimum) = (factory.ready_workers(), factory.minimum());
    if !factory.creating() && ready > minimum {
        count = (ready - minimum).min(waiting(factory));
        factory.add_timeout_requests(count);
    }
    match guest::try_write::<u32>(buffer, count) {
        Ok(()) => 0,
        Err(error) => error.status,
    }
}

/// NtWaitForWorkViaWorkerFactory(handle, MiniPackets, Count,
/// PacketsReturned, DeferredWork), como o 19041 (rva 0x203110): Count de 1
/// a 0x7FFFFFF antes de tudo; em modo usuário, a saída dos pacotes
/// alinhada em 8 e gravável, PacketsReturned gravável e o
/// WORKER_FACTORY_DEFERRED_WORK alinhado em 8 e sempre capturado. A resposta
/// adiada (bit 0 de Flags) sai uma vez: antes da espera, ou na saída quando
/// a espera nem começou (handle inválido, fábrica encerrada, worker em
/// excesso).
fn nt_wait_for_work_via_worker_factory(handle: u64, out: u64, count: u64, returned: u64, rsp: u64) -> Result<u32, KernelError> {
    let count = count as u32;
    if count.wrapping_sub(1) > 0x7FF_FFFE {
        return Ok(0xC000_000D);
    }
    let deferred = state::stack_arg(rsp, 5);
    if out & 7 != 0 {
        return Ok(0x8000_0002);
    }
    if !state::probe_user_write(out, count as u64 * FileIoCompletionInformation::SIZE) || !state::probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    if deferred & 7 != 0 {
        return Ok(0x8000_0002);
    }
    if !state::probe_user_read(deferred, WorkerFactoryDeferredWork::SIZE) {
        return Ok(0xC000_0005);
    }
    let captured = state::user_struct::<WorkerFactoryDeferredWork>(deferred).and_then(|work| Ok((work.alpc_send_message.probe_get()?, work.alpc_send_message_port.probe_get()?, work.alpc_send_message_flags.probe_get()?, work.flags.probe_get()?)));
    let mut send = match captured {
        Ok((message, port, flags, work_flags)) => (work_flags & DEFERRED_SEND != 0).then_some(DeferredSend { message, port, flags }),
        Err(error) => return Ok(error.status),
    };
    let status = wait_for_work(handle, out, count, returned, &mut send)?;
    // A espera não começou: a resposta vai como no NtAlpcSendWaitReceivePort
    // com as flags capturadas inteiras e sem recepção.
    if let Some(send) = send {
        send.send(send.flags)?;
    }
    Ok(status)
}

/// O corpo do NtWaitForWorkViaWorkerFactory depois das capturas: `send` é
/// consumido quando a resposta sai antes da espera.
fn wait_for_work(handle: u64, out: u64, count: u32, returned: u64, send: &mut Option<DeferredSend>) -> Result<u32, KernelError> {
    let (entry, factory) = match resolve(handle, 2) {
        Ok(resolved) => resolved,
        Err(status) => return Ok(status),
    };
    if factory.port.closed() {
        shutdown(&factory);
    }
    if factory.shutdown() {
        return Ok(0x80);
    }
    let thread = threads::current();
    // O máximo desceu abaixo dos prontos: o excesso sai sem esperar.
    if factory.ready_workers() > factory.maximum() {
        if let Some(thread) = thread.as_ref() {
            retire(&factory, thread);
        }
        return Ok(0x102);
    }
    // Só as flags altas; com ALPC_MSGFLG_SYNC_REQUEST o envio não
    // acontece. Uma falha do envio não muda nada: a espera segue.
    if let Some(send) = send.take() {
        let flags = send.flags & 0xFFFF_0000;
        if flags & ALPC_SYNC_REQUEST == 0 {
            send.send(flags)?;
        }
    }
    let validate: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || state::probe_user_write(out, count as u64 * FileIoCompletionInformation::SIZE) && state::probe_user_write(returned, 4));
    // Os pacotes retirados são escritos sob a trava da porta; as
    // notificações de retirada rodam depois, fora dela. PacketsReturned só
    // é gravado quando há pacotes (status 0).
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
    // A espera em si é infinita e alertável (uma APC de usuário volta com
    // STATUS_USER_APC). A ociosidade é contada por worker: depois de
    // IdleTimeout sem trabalho, ou quando a classe 12 pede, a espera termina
    // com STATUS_TIMEOUT se o worker não deve ficar; senão o prazo recomeça.
    let idle_ms = ((-factory.idle_timeout()) / 10_000).max(1) as u64;
    let mut deadline = clock::uptime_ms() + idle_ms;
    let (watched, waiter) = (factory.clone(), thread.clone());
    let poll = move || -> Option<u32> {
        if watched.shutdown() {
            return Some(0x80);
        }
        let now = clock::uptime_ms();
        if !watched.take_timeout_request() && now < deadline {
            return None;
        }
        deadline = now + idle_ms;
        let waiter = waiter.as_ref()?;
        if should_stay(&watched, waiter) {
            return None;
        }
        retire(&watched, waiter);
        Some(0x102)
    };
    let options = RemoveOptions { entries: alloc::vec![entry], poll: Some(Box::new(poll)), cleanup: None, timeout_ms: Some(None) };
    let status = io_completion::remove_entry(factory.port_entry.clone(), factory.port.clone(), 0, true, validate, deliver, options);
    if let Some(thread) = thread {
        thread.mark_wait_worker_factory(factory.pointer);
    }
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
            if factory.shutdown() || (factory.last_status() != 0 && (clock::uptime_ms() as i64) < factory.retry_at()) {
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
