//! Espera por handle (ZwWaitForSingleObject, ZwWaitForMultipleObjects,
//! ObWaitForSingleObject, ObWaitForMultipleObjects, o export
//! NtWaitForSingleObject no modo anterior do chamador e a captura dos
//! objetos de espera que os serviços de modo usuário usam).
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

/// ZwWaitForSingleObject: eventos, timers, semáforos e mutants da tabela
/// nativa (os corpos que começam no DISPATCHER_HEADER), threads de sistema e
/// os eventos abertos pelo zw. Devolve o valor nativo do export: a falha da
/// resolução e a espera numa thread de sistema saem estendidas com zeros; os
/// demais NTSTATUS, com sinal.
pub fn wait_for_single_object(handle: u64, alertable: bool, timeout: u64) -> u64 {
    match open_pointer::resolve(handle, false) {
        Some(Err(status)) => return status as u64,
        Some(Ok(opened)) if matches!(opened.item.object_type.name.as_str(), "Event" | "Timer" | "Semaphore" | "Mutant") => {
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
    let mut set = WaitObjects { objects: Vec::with_capacity(handles.len()), held: Vec::with_capacity(handles.len()) };
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
