//! Espera por handle (ZwWaitForSingleObject, ZwWaitForMultipleObjects,
//! ObWaitForSingleObject, ObWaitForMultipleObjects, o export
//! NtWaitForSingleObject no modo anterior do chamador, a captura dos
//! objetos de espera que os serviços de modo usuário usam e o sinal do
//! NtSignalAndWaitForSingleObject).
//!
//! O handle é resolvido na ordem: a tabela nativa (abertos por ponteiro),
//! threads de sistema, os eventos abertos pelo núcleo de handles de kernel do
//! I/O e a tabela de handles de usuário do processo corrente; a espera em si
//! é a do dispatcher do Ke.
//!
//! O objeto de espera é o DefaultObject do tipo, como no ObpGetWaitObject:
//! o próprio corpo nos tipos que começam no DISPATCHER_HEADER, o
//! FILE_OBJECT.Event num arquivo, a KQUEUE do IoCompletion e, nos demais
//! tipos, o objeto padrão (ObpDefaultObject: um evento de notificação
//! sinalizado desde a criação, então a espera nele conclui de imediato).

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{FileObject, Kevent};
use crate::ntos::init::exports::signed_status;
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::ke::dispatcher;
use crate::ntos::ob::open_pointer;
use crate::ntos::ps::kernel_threads;
use crate::ntos::ps::user::state;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// ZwWaitForSingleObject: eventos, timers, semáforos, mutants e processos da
/// tabela nativa (os corpos que começam no DISPATCHER_HEADER; o KPROCESS só
/// fica sinalizado no fim do término, depois da saída da última thread),
/// threads de sistema e os eventos abertos pelo zw. Devolve o valor nativo
/// do export: a falha da resolução e a espera numa thread de sistema saem
/// estendidas com zeros; os demais NTSTATUS, com sinal.
pub fn wait_for_single_object(handle: u64, alertable: bool, timeout: u64) -> u64 {
    match open_pointer::resolve(handle, false) {
        Some(Err(status)) => return status as u64,
        Some(Ok(opened)) if matches!(opened.item.object_type.name.as_str(), "Event" | "Timer" | "Semaphore" | "Mutant" | "Process") => {
            // O último fechamento durante a espera não libera o corpo em uso.
            opened.item.reference();
            let status = dispatcher::wait_for_single_object(opened.item.pointer, timeout, 0, alertable);
            opened.item.dereference();
            return signed_status(status);
        }
        _ => {}
    }
    if let Some(thread) = kernel_threads::of_handle(handle) {
        return dispatcher::wait_for_single_object(thread, timeout, 0, alertable) as u64;
    }
    let pointer = zw_files::wait_object_of_handle(handle);
    if pointer == 0 {
        return signed_status(STATUS_INVALID_HANDLE);
    }
    signed_status(dispatcher::wait_for_single_object(pointer, timeout, 0, alertable))
}

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INVALID_PARAMETER_MIX: u32 = 0xC000_0030;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// O direito que o ObReferenceObjectByHandle das esperas pede.
const SYNCHRONIZE: u32 = 0x10_0000;
/// MAXIMUM_WAIT_OBJECTS.
pub const MAXIMUM_WAIT_OBJECTS: u32 = 64;
/// WAIT_TYPE: WaitAll e WaitAny.
pub const WAIT_ALL: u32 = 0;
pub const WAIT_ANY: u32 = 1;
/// Tipos cujo corpo começa no DISPATCHER_HEADER (DefaultObject = deslocamento
/// 0); o IRTimer começa no KTIMER2 e o EJOB no KEVENT do fim do prazo do job.
const DISPATCHER_TYPES: [&str; 8] = ["Event", "Semaphore", "Mutant", "Timer", "IRTimer", "Process", "Thread", "Job"];

/// ObpGetWaitObject: o objeto de despacho de uma espera no corpo `pointer`
/// do tipo `type_name` (o pacote de espera de um IoCompletion espera nele):
/// o FILE_OBJECT.Event de um arquivo, o próprio corpo dos
/// [`DISPATCHER_TYPES`], a KQUEUE do IoCompletion e, numa porta ALPC, o
/// objeto do DefaultObject indireto (o semáforo de uma porta esperável, que
/// cada mensagem na fila libera, ou o AlpcpDummyEvent sinalizado: o
/// registrador do CoreMessaging e os clientes dele esperam as portas assim),
/// ou `None` para os tipos que esperam no ObpDefaultObject.
pub fn wait_object_of(pointer: u64, type_name: &str) -> Option<u64> {
    if type_name == "File" {
        // SAFETY: FILE_OBJECT vivo, retido pelo chamador.
        return Some(unsafe { FileObject::at(pointer) }.event.address());
    }
    if type_name == "ALPC Port" {
        return crate::ntos::ob::objects::port::port_of(pointer).map(|port| port.wait_target()).filter(|&target| target != 0);
    }
    (DISPATCHER_TYPES.contains(&type_name) || type_name == "IoCompletion").then_some(pointer)
}

/// ObpDefaultObject: o KEVENT de notificação sinalizado em que esperam os
/// tipos sem objeto de espera próprio (criado na primeira espera).
static DEFAULT_OBJECT: AtomicU64 = AtomicU64::new(0);

/// O endereço do ObpDefaultObject (0 sem memória para criá-lo).
pub fn default_object() -> u64 {
    let current = DEFAULT_OBJECT.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let event = guest::alloc_bytes(Kevent::SIZE);
    if event == 0 {
        return 0;
    }
    dispatcher::initialize_event(event, 0, true);
    match DEFAULT_OBJECT.compare_exchange(0, event, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => event,
        Err(winner) => {
            guest::free_bytes(event);
            winner
        }
    }
}

/// O objeto de espera de um corpo, pelo DefaultObject do tipo.
enum WaitTarget {
    /// Um DISPATCHER_HEADER (o corpo ou o evento dentro dele).
    Header(u64),
    /// A KQUEUE do IoCompletion (o WaitAll a recusa).
    Queue(u64),
    /// O ObpDefaultObject.
    Default,
}

fn target_of(type_name: &str, pointer: u64) -> WaitTarget {
    match type_name {
        // SAFETY: FILE_OBJECT vivo, retido por quem resolveu o handle.
        "File" => WaitTarget::Header(unsafe { FileObject::at(pointer) }.event.address()),
        "IoCompletion" => WaitTarget::Queue(pointer),
        // DefaultObject indireto (0xF9): o KSEMAPHORE de uma porta esperável
        // (NtCreateWaitablePort, WAITABLE_PORT); nas outras portas o
        // AlpcpDummyEvent, sinalizado.
        "ALPC Port" => match crate::ntos::ob::objects::port::port_of(pointer).map(|port| port.wait_target()) {
            Some(target) if target != 0 => WaitTarget::Header(target),
            _ => WaitTarget::Default,
        },
        name if DISPATCHER_TYPES.contains(&name) => WaitTarget::Header(pointer),
        _ => WaitTarget::Default,
    }
}

/// A referência que retém um objeto de espera resolvido durante a espera.
enum Held {
    Native(open_pointer::Described),
    User(alloc::sync::Arc<state::UserHandle>),
    Plain,
}

impl Held {
    fn release(self) {
        match self {
            Held::Native(item) => item.dereference(),
            Held::User(entry) => {
                let _ = state::release_user_handle_reference(&entry);
            }
            Held::Plain => {}
        }
    }
}

/// O objeto de espera de `handle` (o ObReferenceObjectByHandle com
/// SYNCHRONIZE): em UserMode o handle precisa conceder SYNCHRONIZE.
fn wait_object(handle: u64, previous_mode: u8) -> Result<(WaitTarget, Held), u32> {
    match open_pointer::resolve(handle, previous_mode != 0) {
        Some(Err(status)) => return Err(status),
        Some(Ok(opened)) => {
            if previous_mode != 0 && opened.access & SYNCHRONIZE == 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
            opened.item.reference();
            let target = target_of(&opened.item.object_type.name, opened.item.pointer);
            return Ok((target, Held::Native(opened.item)));
        }
        None => {}
    }
    if let Some(thread) = kernel_threads::of_handle(handle) {
        return Ok((WaitTarget::Header(thread), Held::Plain));
    }
    let pointer = zw_files::wait_object_of_handle(handle);
    if pointer != 0 {
        return Ok((WaitTarget::Header(pointer), Held::Plain));
    }
    let Some(entry) = state::get_user_handle(handle) else { return Err(STATUS_INVALID_HANDLE) };
    if previous_mode != 0 && entry.access() & SYNCHRONIZE == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    // O corpo nativo do handle diz o tipo; um objeto só do runtime expõe o
    // ponteiro de espera dele (ou nenhum: o objeto padrão).
    let target = match entry.object.native_body() {
        Some(body) => target_of(&body.type_name, body.pointer),
        None => entry.object.wait_pointer().map_or(WaitTarget::Default, WaitTarget::Header),
    };
    state::retain_user_handle_reference(&entry);
    Ok((target, Held::User(entry)))
}

/// Os objetos de espera de um vetor de handles, retidos até `release`.
pub struct WaitObjects {
    /// Os ponteiros na ordem dos handles (o vetor do KeWaitForMultipleObjects).
    pub objects: Vec<u64>,
    /// Os valores dos handles, na mesma ordem (o alarme de
    /// [`check_satisfied`]).
    pub handles: Vec<u64>,
    held: Vec<Held>,
}

impl WaitObjects {
    /// Solta as referências tomadas na captura.
    pub fn release(self) {
        self.held.into_iter().for_each(Held::release);
    }
}

/// A resolução de handles do ObWaitForMultipleObjects 19041: cada handle é
/// referenciado (em UserMode com SYNCHRONIZE, senão STATUS_ACCESS_DENIED);
/// no WaitAll um IoCompletion dá STATUS_INVALID_HANDLE; o objeto de espera é
/// o DefaultObject do tipo (o objeto padrão, sempre sinalizado, para os tipos
/// sem um); no WaitAll com mais de um handle, dois objetos de espera iguais
/// dão STATUS_INVALID_PARAMETER_MIX. No WaitAny um objeto repetido é aceito
/// (o KeWaitForMultipleObjects devolve o primeiro índice satisfeito). Count e
/// WaitType ficam com quem chama.
pub fn reference_objects(handles: &[u64], previous_mode: u8, wait_type: u32) -> Result<WaitObjects, u32> {
    let mut set = WaitObjects { objects: Vec::with_capacity(handles.len()), handles: handles.to_vec(), held: Vec::with_capacity(handles.len()) };
    for &handle in handles {
        let (target, held) = match wait_object(handle, previous_mode) {
            Ok(resolved) => resolved,
            Err(status) => {
                set.release();
                return Err(status);
            }
        };
        set.held.push(held);
        let object = match target {
            WaitTarget::Header(pointer) => pointer,
            WaitTarget::Queue(_) if wait_type == WAIT_ALL => 0,
            WaitTarget::Queue(pointer) => pointer,
            WaitTarget::Default => default_object(),
        };
        if object == 0 {
            set.release();
            return Err(if matches!(target, WaitTarget::Queue(_)) { STATUS_INVALID_HANDLE } else { STATUS_INSUFFICIENT_RESOURCES });
        }
        set.objects.push(object);
    }
    if wait_type == WAIT_ALL && set.objects.len() > 1 && set.objects.iter().collect::<BTreeSet<_>>().len() != set.objects.len() {
        set.release();
        return Err(STATUS_INVALID_PARAMETER_MIX);
    }
    Ok(set)
}

/// EVENT_MODIFY_STATE e SEMAPHORE_MODIFY_STATE.
const EVENT_MODIFY_STATE: u32 = 2;
const SEMAPHORE_MODIFY_STATE: u32 = 2;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;

/// O objeto a sinalizar do NtSignalAndWaitForSingleObject, retido até o
/// sinal.
pub struct SignalObject {
    type_name: alloc::string::String,
    pointer: u64,
    access: u32,
    held: Held,
}

/// O ObReferenceObjectByHandle(SignalHandle, 0, NULL) do
/// NtSignalAndWaitForSingleObject: qualquer tipo, sem direito exigido na
/// referência (o direito depende do tipo, no sinal).
pub fn reference_signal_object(handle: u64, previous_mode: u8) -> Result<SignalObject, u32> {
    match open_pointer::resolve(handle, previous_mode != 0) {
        Some(Err(status)) => return Err(status),
        Some(Ok(opened)) => {
            opened.item.reference();
            let (type_name, pointer) = (opened.item.object_type.name.clone(), opened.item.pointer);
            return Ok(SignalObject { type_name, pointer, access: opened.access, held: Held::Native(opened.item) });
        }
        None => {}
    }
    let Some(entry) = state::get_user_handle(handle) else { return Err(STATUS_INVALID_HANDLE) };
    let (type_name, pointer) = entry.object.native_body().map(|body| (body.type_name, body.pointer)).unwrap_or_default();
    let access = entry.access();
    state::retain_user_handle_reference(&entry);
    Ok(SignalObject { type_name, pointer, access, held: Held::User(entry) })
}

impl SignalObject {
    /// O sinal do NtSignalAndWaitForSingleObject 19041 pelo tipo do objeto:
    /// evento (em UserMode com EVENT_MODIFY_STATE, senão
    /// STATUS_ACCESS_DENIED) pelo KeSetEvent; mutant pelo KeReleaseMutant
    /// (STATUS_MUTANT_NOT_OWNED sem a posse); semáforo (em UserMode com
    /// SEMAPHORE_MODIFY_STATE) pelo KeReleaseSemaphore de 1
    /// (STATUS_SEMAPHORE_LIMIT_EXCEEDED no limite); outro tipo,
    /// STATUS_OBJECT_TYPE_MISMATCH. Solta a referência.
    pub fn signal(self, previous_mode: u8) -> u32 {
        let user = previous_mode != 0;
        let status = match self.type_name.as_str() {
            "Event" if user && self.access & EVENT_MODIFY_STATE == 0 => STATUS_ACCESS_DENIED,
            "Event" => {
                dispatcher::set_event_with_increment(self.pointer, dispatcher::SYNCHRONIZATION_INCREMENT);
                0
            }
            "Mutant" => dispatcher::release_mutant_with_increment(self.pointer, false, dispatcher::SYNCHRONIZATION_INCREMENT).map_or_else(|status| status, |_| 0),
            "Semaphore" if user && self.access & SEMAPHORE_MODIFY_STATE == 0 => STATUS_ACCESS_DENIED,
            "Semaphore" => dispatcher::release_semaphore_with_increment(self.pointer, 1, dispatcher::SYNCHRONIZATION_INCREMENT).map_or_else(|status| status, |_| 0),
            _ => STATUS_OBJECT_TYPE_MISMATCH,
        };
        self.held.release();
        status
    }

    /// Solta a referência sem sinalizar.
    pub fn release(self) {
        self.held.release();
    }
}

/// O KeWaitForMultipleObjects (UserRequest) sobre objetos já capturados, com
/// o prazo apontado por `timeout`; solta as referências no fim.
pub fn wait_referenced(set: WaitObjects, wait_type: u32, wait_mode: u8, alertable: bool, timeout: u64) -> u32 {
    let status = match set.objects.as_slice() {
        [single] => dispatcher::wait_for_single_object(*single, timeout, wait_mode, alertable),
        objects => {
            let array = guest::alloc_bytes(objects.len() as u64 * 8);
            if array == 0 {
                set.release();
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            for (index, &pointer) in objects.iter().enumerate() {
                guest::write64(array + index as u64 * 8, pointer);
            }
            let status = dispatcher::wait_for_multiple_objects(objects.len() as u32, array, wait_type, timeout, wait_mode, alertable);
            guest::free_bytes(array);
            status
        }
    };
    set.release();
    status
}

/// ObWaitForSingleObject(Handle, PreviousMode, WaitMode, Alertable,
/// Timeout): o KeWaitForSingleObject (UserRequest) no objeto do handle.
pub fn ob_wait_for_single_object(handle: u64, previous_mode: u8, wait_mode: u8, alertable: bool, timeout: u64) -> u32 {
    match reference_objects(&[handle], previous_mode, WAIT_ANY) {
        Ok(set) => wait_referenced(set, WAIT_ANY, wait_mode, alertable, timeout),
        Err(status) => status,
    }
}

/// NtWaitForSingleObject(Handle, Alertable, Timeout) chamado por código de
/// kernel (o export Nt*): o modo anterior da thread é o PreviousMode e o
/// WaitMode do ObWaitForSingleObject. Em UserMode o LARGE_INTEGER do prazo
/// é capturado antes (sondado; um endereço do kernel falha como no
/// ProbeForRead) e a espera usa a cópia.
pub fn nt_wait_for_single_object(handle: u64, alertable: bool, timeout: u64) -> Result<u32, KernelError> {
    let previous_mode = crate::ntos::ps::previous_mode::get()?;
    if timeout == 0 || previous_mode == 0 {
        return Ok(ob_wait_for_single_object(handle, previous_mode, previous_mode, alertable, timeout));
    }
    let limit = crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
    let source = if timeout >= limit { limit } else { timeout };
    let Ok(value) = guest::try_read::<u64>(source) else { return Ok(STATUS_ACCESS_VIOLATION) };
    let captured = guest::alloc_bytes(8);
    if captured == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(captured, value);
    let status = ob_wait_for_single_object(handle, previous_mode, previous_mode, alertable, captured);
    guest::free_bytes(captured);
    Ok(status)
}

/// ObWaitForMultipleObjects(Count, Handles, PreviousMode, WaitType,
/// WaitMode, Alertable, Timeout): os objetos dos handles (até
/// MAXIMUM_WAIT_OBJECTS) no KeWaitForMultipleObjects.
pub fn ob_wait_for_multiple_objects(count: u32, handles: u64, previous_mode: u8, wait_type: u32, wait_mode: u8, alertable: bool, timeout: u64) -> Result<u32, KernelError> {
    if count == 0 || count > MAXIMUM_WAIT_OBJECTS || wait_type > WAIT_ANY {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let handles: Vec<u64> = (0..count as u64).map(|index| guest::read64(handles + index * 8)).collect();
    Ok(match reference_objects(&handles, previous_mode, wait_type) {
        Ok(set) => wait_referenced(set, wait_type, wait_mode, alertable, timeout),
        Err(status) => status,
    })
}

/// ZwWaitForMultipleObjects(Count, Handles, WaitType, Alertable, Timeout): o
/// NtWaitForMultipleObjects em KernelMode. Count fora de 1..=64 dá
/// STATUS_INVALID_PARAMETER_1 e WaitType além de WaitAny
/// STATUS_INVALID_PARAMETER_3 antes de olhar os handles; depois o
/// ObWaitForMultipleObjects. Devolve o valor nativo do export (NTSTATUS com
/// sinal ou o índice do WaitAny).
pub fn wait_for_multiple_objects(count: u32, handles: u64, wait_type: u32, alertable: bool, timeout: u64) -> Result<u64, KernelError> {
    if let Err(status) = check_multiple_wait(count, wait_type) {
        return Ok(signed_status(status));
    }
    Ok(signed_status(ob_wait_for_multiple_objects(count, handles, 0, wait_type, 0, alertable, timeout)?))
}

/// As checagens do NtWaitForMultipleObjects antes da captura: Count fora de
/// 1..=MAXIMUM_WAIT_OBJECTS dá STATUS_INVALID_PARAMETER_1 e WaitType além de
/// WaitAny, STATUS_INVALID_PARAMETER_3.
pub fn check_multiple_wait(count: u32, wait_type: u32) -> Result<(), u32> {
    if count == 0 || count > MAXIMUM_WAIT_OBJECTS {
        return Err(STATUS_INVALID_PARAMETER_1);
    }
    if wait_type > WAIT_ANY {
        return Err(STATUS_INVALID_PARAMETER_3);
    }
    Ok(())
}

// ---- alarme das esperas satisfeitas em processos ---------------------------

/// Um handle de processo que um processo recebeu do NtCreateUserProcess
/// ([`track_process_handle`]): o EPROCESS e o pid do alvo, o pid do dono (um
/// EPROCESS reaproveitado não herda o registro) e quem fechou o valor.
#[derive(Clone, Copy)]
struct TrackedHandle {
    owner_pid: u64,
    target: u64,
    target_pid: u64,
    /// (pid, tid, de modo kernel) do NtClose que fechou o valor.
    closed_by: Option<(u64, u64, bool)>,
}

/// Os handles de processo vigiados, por (EPROCESS do dono, valor do handle).
static TRACKED: crate::rtl::SpinLock<alloc::collections::BTreeMap<(u64, u64), TrackedHandle>> = crate::rtl::SpinLock::new(alloc::collections::BTreeMap::new());
/// Registros no máximo; além disso sai o de menor chave.
const TRACKED_MAX: usize = 1024;

/// O DISPATCHER_HEADER.Type de um KPROCESS (ProcessObject).
const PROCESS_OBJECT: u8 = 3;

/// Quem esperou (capturado no começo da espera: a conclusão pode rodar no
/// contexto de outra thread).
pub struct Waiter {
    pub process: u64,
    pub pid: u64,
    pub tid: u64,
}

impl Waiter {
    /// A thread corrente.
    pub fn current() -> Self {
        let process = crate::ntos::ps::process::get_current_process();
        Self { process, pid: crate::ntos::ps::process::get_current_process_id(), tid: crate::ntos::ps::process::get_current_thread_id() }
    }
}

/// O processo `pointer` ainda não começou a terminar (o fim pedido marca o
/// registro antes de o KPROCESS ficar sinalizado).
fn process_alive(pointer: u64) -> bool {
    crate::ntos::ps::process::with_record(pointer, |record| !record.terminated && !record.exiting).unwrap_or(false)
}

/// O tipo e, num processo, o pid e as threads ativas do objeto de espera
/// `object`, para a linha do alarme.
fn describe_wait_object(object: u64) -> alloc::string::String {
    // SAFETY: um objeto de espera retido pela espera que acabou de concluir.
    let header_type = unsafe { crate::ntos::inc::types::DispatcherHeader::at(object) }.type_.get() & 0x7F;
    let name = open_pointer::describe(object).map_or_else(|| alloc::format!("tipo de despacho {header_type}"), |described| described.object_type.name.clone());
    if header_type == PROCESS_OBJECT && crate::ntos::ps::process::is_process(object) {
        // SAFETY: EPROCESS vivo (registrado no Process Manager).
        let eprocess = unsafe { crate::ntos::inc::types::Eprocess::at(object) };
        let state = if process_alive(object) { "sem fim pedido" } else { "terminando ou terminado" };
        return alloc::format!("{name} {object:#x} (pid {}, {} threads ativas, {state})", eprocess.unique_process_id.get(), eprocess.active_threads.get());
    }
    alloc::format!("{name} {object:#x}")
}

/// O NtCreateUserProcess publicou em `owner` o handle `handle` do processo
/// novo `target`: as esperas satisfeitas nesse valor passam a ser conferidas
/// ([`check_satisfied`]). Só observa.
pub fn track_process_handle(owner: u64, handle: u64, target: u64) {
    // SAFETY: EPROCESS do dono (o corrente) e do processo recém-criado.
    let (owner_pid, target_pid) = unsafe { (crate::ntos::inc::types::Eprocess::at(owner).unique_process_id.get(), crate::ntos::inc::types::Eprocess::at(target).unique_process_id.get()) };
    let mut tracked = TRACKED.lock();
    if tracked.len() >= TRACKED_MAX {
        if let Some(&oldest) = tracked.keys().next() {
            tracked.remove(&oldest);
        }
    }
    tracked.insert((owner, handle & !3), TrackedHandle { owner_pid, target, target_pid, closed_by: None });
}

/// O NtClose do valor `handle` na tabela de `owner` (`ob/close.rs`): o
/// registro vigiado anota quem fechou. Só observa.
pub fn note_handle_closed(owner: u64, handle: u64, from_user_mode: bool) {
    let mut tracked = TRACKED.lock();
    if tracked.is_empty() {
        return;
    }
    if let Some(record) = tracked.get_mut(&(owner, handle & !3)) {
        record.closed_by.get_or_insert((crate::ntos::ps::process::get_current_process_id(), crate::ntos::ps::process::get_current_thread_id(), !from_user_mode));
    }
}

/// O alarme de uma espera de modo usuário que concluiu com `status` nos
/// `handles` (com os objetos de espera `objects`, na mesma ordem): uma linha
/// `[diag] espera satisfeita` quando o objeto satisfeito é um processo que
/// não começou a terminar, ou quando o valor era de um handle de processo
/// vigiado e hoje resolve para outro objeto sem que o dono o tenha fechado
/// em modo usuário (o valor fechado por outro caminho e reaproveitado). Só
/// observa: a espera e o resultado não mudam.
pub fn check_satisfied(waiter: &Waiter, handles: &[u64], objects: &[u64], wait_type: u32, status: u32) {
    let satisfied = match status {
        0 if wait_type == WAIT_ALL => 0..objects.len(),
        index if (index as usize) < objects.len() => index as usize..index as usize + 1,
        abandoned if (0x80..0xC0).contains(&abandoned) && ((abandoned - 0x80) as usize) < objects.len() => (abandoned - 0x80) as usize..(abandoned - 0x80) as usize + 1,
        _ => return,
    };
    for index in satisfied {
        let (Some(&handle), Some(&object)) = (handles.get(index), objects.get(index)) else { continue };
        // SAFETY: um objeto de espera retido pela espera que acabou de concluir.
        let header_type = unsafe { crate::ntos::inc::types::DispatcherHeader::at(object) }.type_.get() & 0x7F;
        if header_type == PROCESS_OBJECT && crate::ntos::ps::process::is_process(object) && process_alive(object) {
            crate::debug_print!("[diag] espera satisfeita num processo vivo: espera de {}:{} no handle {:#x} -> {}", waiter.pid, waiter.tid, handle, describe_wait_object(object));
        }
        let tracked = {
            let tracked = TRACKED.lock();
            if tracked.is_empty() {
                continue;
            }
            tracked.get(&(waiter.process, handle & !3)).copied()
        };
        let Some(record) = tracked else { continue };
        if record.owner_pid != waiter.pid {
            TRACKED.lock().remove(&(waiter.process, handle & !3));
            continue;
        }
        let closed_by_owner = record.closed_by.is_some_and(|(pid, _, kernel)| pid == record.owner_pid && !kernel);
        if record.target != object && !closed_by_owner {
            let closed = record.closed_by.map_or_else(|| alloc::string::String::from("nunca fechado pelo NtClose"), |(pid, tid, kernel)| alloc::format!("fechado por {pid}:{tid} em modo {}", if kernel { "kernel" } else { "usuário" }));
            crate::debug_print!("[diag] espera satisfeita num handle de processo reaproveitado: espera de {}:{} no handle {:#x}, criado para o pid {} (Process {:#x}), {}; agora -> {}", waiter.pid, waiter.tid, handle, record.target_pid, record.target, closed, describe_wait_object(object));
        }
    }
}

/// O alarme do pacote de espera (`ps/user/wait_packets.rs`, o
/// RtlRegisterWait e as esperas do threadpool) que vai para a IOCP pelo
/// objeto `object`: a mesma linha quando ele é um processo que não começou
/// a terminar. Só observa.
pub fn check_packet_delivery(object: u64) {
    // SAFETY: o objeto de espera retido pela associação que acabou de concluir.
    let header_type = unsafe { crate::ntos::inc::types::DispatcherHeader::at(object) }.type_.get() & 0x7F;
    if header_type == PROCESS_OBJECT && crate::ntos::ps::process::is_process(object) && process_alive(object) {
        crate::debug_print!("[diag] espera satisfeita num processo vivo: pacote de espera entregue à IOCP -> {}", describe_wait_object(object));
    }
}
