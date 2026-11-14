//! Espera por handle em modo kernel (ZwWaitForSingleObject,
//! ObWaitForSingleObject e ObWaitForMultipleObjects).
//!
//! O handle é resolvido na ordem: a tabela nativa (abertos por ponteiro),
//! threads de sistema, os eventos abertos pelo núcleo de handles de kernel do
//! I/O e, para os Ob*, a tabela de handles de usuário do processo corrente;
//! a espera em si é a do dispatcher do Ke.

use alloc::vec::Vec;

use crate::ntos::init::exports::signed_status;
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::ke::dispatcher;
use crate::ntos::ob::open_pointer;
use crate::ntos::ps::kernel_threads;
use crate::ntos::ps::user::state;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// ZwWaitForSingleObject: eventos da tabela nativa (abertos por ponteiro),
/// threads de sistema e os eventos abertos pelo zw. Devolve o valor nativo
/// do export: a falha da resolução e a espera numa thread de sistema saem
/// estendidas com zeros; os demais NTSTATUS, com sinal.
pub fn wait_for_single_object(handle: u64, alertable: bool, timeout: u64) -> u64 {
    match open_pointer::resolve(handle, false) {
        Some(Err(status)) => return status as u64,
        Some(Ok(opened)) if opened.item.object_type.name == "Event" => {
            // O último fechamento durante a espera não libera o KEVENT em uso.
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
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// O direito que o ObReferenceObjectByHandle das esperas pede.
const SYNCHRONIZE: u32 = 0x10_0000;
/// MAXIMUM_WAIT_OBJECTS.
const MAXIMUM_WAIT_OBJECTS: u32 = 64;
/// Tipos cujo corpo começa no DISPATCHER_HEADER (os demais esperam no
/// objeto padrão do tipo, sempre sinalizado no NT).
const DISPATCHER_TYPES: [&str; 6] = ["Event", "Semaphore", "Mutant", "Timer", "Process", "Thread"];

/// Um objeto de espera resolvido e a referência que o retém durante a
/// espera.
enum Held {
    Native(open_pointer::Resolved),
    User(alloc::sync::Arc<state::UserHandle>),
    Plain,
}

impl Held {
    fn release(self) {
        match self {
            Held::Native(opened) => opened.item.dereference(),
            Held::User(entry) => {
                let _ = state::release_user_handle_reference(&entry);
            }
            Held::Plain => {}
        }
    }
}

/// O objeto de espera de `handle` (o ObReferenceObjectByHandle com
/// SYNCHRONIZE): em UserMode um handle de usuário precisa conceder
/// SYNCHRONIZE. Um objeto sem DISPATCHER_HEADER dá `None` no ponteiro: ele
/// espera no objeto padrão, sempre sinalizado.
fn wait_object(handle: u64, previous_mode: u8) -> Result<(Option<u64>, Held), u32> {
    match open_pointer::resolve(handle, previous_mode != 0) {
        Some(Err(status)) => return Err(status),
        Some(Ok(opened)) => {
            if previous_mode != 0 && opened.access & SYNCHRONIZE == 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
            opened.item.reference();
            let pointer = DISPATCHER_TYPES.contains(&opened.item.object_type.name.as_str()).then_some(opened.item.pointer);
            return Ok((pointer, Held::Native(opened)));
        }
        None => {}
    }
    if let Some(thread) = kernel_threads::of_handle(handle) {
        return Ok((Some(thread), Held::Plain));
    }
    let pointer = zw_files::wait_object_of_handle(handle);
    if pointer != 0 {
        return Ok((Some(pointer), Held::Plain));
    }
    let Some(entry) = state::get_user_handle(handle) else { return Err(STATUS_INVALID_HANDLE) };
    if previous_mode != 0 && entry.access() & SYNCHRONIZE == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    let pointer = entry.object.wait_pointer();
    state::retain_user_handle_reference(&entry);
    Ok((pointer, Held::User(entry)))
}

/// ObWaitForSingleObject(Handle, PreviousMode, WaitMode, Alertable,
/// Timeout): o KeWaitForSingleObject (UserRequest) no objeto do handle.
pub fn ob_wait_for_single_object(handle: u64, previous_mode: u8, wait_mode: u8, alertable: bool, timeout: u64) -> u32 {
    let (pointer, held) = match wait_object(handle, previous_mode) {
        Ok(resolved) => resolved,
        Err(status) => return status,
    };
    let status = match pointer {
        Some(pointer) => dispatcher::wait_for_single_object(pointer, timeout, wait_mode, alertable),
        None => 0,
    };
    held.release();
    status
}

/// ObWaitForMultipleObjects(Count, Handles, PreviousMode, WaitType,
/// WaitMode, Alertable, Timeout): os objetos dos handles (até
/// MAXIMUM_WAIT_OBJECTS) no KeWaitForMultipleObjects; os sem
/// DISPATCHER_HEADER contam como sinalizados.
pub fn ob_wait_for_multiple_objects(count: u32, handles: u64, previous_mode: u8, wait_type: u32, wait_mode: u8, alertable: bool, timeout: u64) -> Result<u32, KernelError> {
    if count == 0 || count > MAXIMUM_WAIT_OBJECTS || wait_type > 1 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let mut held = Vec::new();
    let mut objects = Vec::new();
    for index in 0..count as u64 {
        let handle = guest::read64(handles + index * 8);
        match wait_object(handle, previous_mode) {
            Ok((pointer, reference)) => {
                held.push(reference);
                objects.push(pointer);
            }
            Err(status) => {
                held.into_iter().for_each(Held::release);
                return Ok(status);
            }
        }
    }
    // Um objeto padrão (sempre sinalizado) satisfaz WaitAny no índice dele;
    // em WaitAll só os de verdade contam.
    let default = objects.iter().position(Option::is_none);
    let status = match (default, wait_type) {
        (Some(index), 1) => index as u32,
        _ => {
            let pointers: Vec<u64> = objects.iter().flatten().copied().collect();
            let array = guest::alloc_bytes(pointers.len().max(1) as u64 * 8);
            for (index, &pointer) in pointers.iter().enumerate() {
                guest::write64(array + index as u64 * 8, pointer);
            }
            let status = if pointers.is_empty() { 0 } else { dispatcher::wait_for_multiple_objects(pointers.len() as u32, array, wait_type, timeout, wait_mode, alertable) };
            guest::free_bytes(array);
            status
        }
    };
    held.into_iter().for_each(Held::release);
    Ok(status)
}

