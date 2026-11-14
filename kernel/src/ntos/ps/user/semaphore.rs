//! Semáforos de usuário.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use super::registry::{parse_user_object_attributes, user_object_attributes};
use super::state;
use crate::ntos::ke::dispatcher;
use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks, UserDispatcher};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Ksemaphore, NtStruct, SemaphoreBasicInformation};

/// KSEMAPHORE de 0x20 bytes com o nome publicado.
pub struct SemaphoreObject {
    pub pointer: u64,
    pub name: String,
    node: SpinLock<Option<NodeId>>,
}

static SEMAPHORES: SpinLock<BTreeMap<u64, Arc<SemaphoreObject>>> = SpinLock::new(BTreeMap::new());

fn dispose(pointer: u64) {
    let object = SEMAPHORES.lock().remove(&pointer);
    if let Some(node) = object.and_then(|object| object.node.lock().take()) {
        object_manager::remove_named(node);
    }
    guest::free_bytes(pointer);
}

/// `creating`: o handle de quem cria um objeto novo recebe o acesso pedido
/// sem a checagem da DACL (o ObInsertObject do NT); abrir confere a DACL.
fn publish(object: &Arc<SemaphoreObject>, out: u64, access: u32, attributes: u64, success: u32, creating: bool) -> Result<u32, KernelError> {
    state::guarded(|| {
        let flags = user_object_attributes(attributes)?;
        dispatcher_objects::publish(object.pointer, out, access, flags, success, creating, Some(object.clone()))
    })
}

fn semaphore_of_node(node: NodeId) -> Option<Arc<SemaphoreObject>> {
    let pointer = object_manager::node(node)?.data?.native_pointer;
    SEMAPHORES.lock().get(&pointer).cloned()
}

/// Ponteiro do semáforo de um handle `semaphore` com o acesso pedido.
fn semaphore_of_handle(handle: u64, access: u32) -> Result<u64, u32> {
    let Some(entry) = state::get_user_handle(handle).filter(|entry| entry.kind() == "semaphore") else { return Err(0xC000_0008) };
    if entry.access() & access == 0 {
        return Err(0xC000_0022);
    }
    entry.downcast::<UserDispatcher>().map(|dispatcher| dispatcher.pointer).ok_or(0xC000_0008)
}

/// NtCreateSemaphore(out, access, oa, initial, maximum).
fn nt_create_semaphore(out: u64, access: u64, attributes: u64, initial: u64, rsp: u64) -> Result<u32, KernelError> {
    let initial = initial as u32 as i32;
    let maximum = state::stack_arg32(rsp, 5) as i32;
    if maximum <= 0 || initial < 0 || initial > maximum {
        return Ok(0xC000_000D);
    }
    if !state::probe_user_write(out, 8) {
        return Ok(0xC000_0005);
    }
    let name = if attributes != 0 {
        match parse_user_object_attributes(attributes) {
            Some(parsed) => parsed.path,
            None => return Ok(0xC000_000D),
        }
    } else {
        String::new()
    };
    let cut = name.rfind('\\').unwrap_or(0);
    let parent = if cut == 0 { String::from("\\") } else { String::from(&name[..cut]) };
    if !name.is_empty() {
        if let Some(existing) = object_manager::lookup(&name) {
            if object_manager::node(existing).is_none_or(|node| node.type_name != "Semaphore") {
                return Ok(0xC000_0024);
            }
            // OBJ_OPENIF.
            match user_object_attributes(attributes) {
                Ok(flags) if flags & 0x80 != 0 => {}
                Ok(_) => return Ok(0xC000_0035),
                Err(error) => return Ok(error.status),
            }
            let Some(object) = semaphore_of_node(existing) else { return Ok(0xC000_0024) };
            return publish(&object, out, access as u32, attributes, 0x4000_0000, false);
        }
        if object_manager::lookup(&parent).and_then(object_manager::node).is_none_or(|node| node.type_name != "Directory") {
            return Ok(0xC000_003A);
        }
    }
    let pointer = guest::alloc_bytes(0x20);
    if pointer == 0 {
        return Ok(0xC000_0017);
    }
    dispatcher::initialize_semaphore(pointer, initial as u32, maximum as u32);
    let object = Arc::new(SemaphoreObject { pointer, name: name.clone(), node: SpinLock::new(None) });
    if let Err(error) = dispatcher_objects::create(pointer, "semaphore", dispose, None, attributes, true, DispatcherHooks::default()) {
        guest::free_bytes(pointer);
        return if error.status != 0 { Ok(error.status) } else { Err(error) };
    }
    SEMAPHORES.lock().insert(pointer, object.clone());
    if !name.is_empty() {
        match object_manager::create_object(&parent, &name[cut + 1..], "Semaphore", Some(dispatcher_objects::data(pointer))) {
            Ok(node) => *object.node.lock() = Some(node),
            Err(error) => {
                dispatcher_objects::collect(pointer);
                return if error.status != 0 { Ok(error.status) } else { Err(error) };
            }
        }
    }
    publish(&object, out, access as u32, attributes, 0, true)
}

fn nt_open_semaphore(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) {
        return Ok(0xC000_0005);
    }
    let Some(parsed) = parse_user_object_attributes(attributes) else { return Ok(0xC000_000D) };
    let Some(node) = object_manager::lookup(&parsed.path) else { return Ok(0xC000_0034) };
    if object_manager::node(node).is_none_or(|node| node.type_name != "Semaphore") {
        return Ok(0xC000_0024);
    }
    let Some(object) = semaphore_of_node(node) else { return Ok(0xC000_0024) };
    publish(&object, out, access as u32, attributes, 0, false)
}

/// NtReleaseSemaphore(handle, count, previous*) com SEMAPHORE_MODIFY_STATE.
fn nt_release_semaphore(handle: u64, count: u64, previous: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let pointer = match semaphore_of_handle(handle, 2) {
        Ok(pointer) => pointer,
        Err(status) => return Ok(status),
    };
    if previous != 0 && !state::probe_user_write(previous, 4) {
        return Ok(0xC000_0005);
    }
    Ok(match dispatcher::release_semaphore(pointer, count as u32 as i32 as i64) {
        Ok(old) => {
            // LONG *PreviousCount, sondado acima.
            if previous != 0 && guest::try_write::<u32>(previous, old).is_err() { 0xC000_0005 } else { 0 }
        }
        Err(status) => status,
    })
}

/// NtQuerySemaphore(SemaphoreBasicInformation): contagem e limite.
fn nt_query_semaphore(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let pointer = match semaphore_of_handle(handle, 1) {
        Ok(pointer) => pointer,
        Err(status) => return Ok(status),
    };
    if class != 0 {
        return Ok(0xC000_0003);
    }
    let returned = state::stack_arg(rsp, 5);
    if returned != 0 && !state::probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        if returned != 0 {
            guest::try_write::<u32>(returned, SemaphoreBasicInformation::SIZE as u32)?;
        }
        if length < SemaphoreBasicInformation::SIZE {
            return Ok(0xC000_0004);
        }
        if !state::probe_user_write(out, SemaphoreBasicInformation::SIZE) {
            return Ok(0xC000_0005);
        }
        // SAFETY: KSEMAPHORE vivo, retido pelo handle.
        let semaphore = unsafe { Ksemaphore::at(pointer) };
        let information = state::user_struct::<SemaphoreBasicInformation>(out)?;
        information.current_count.probe_set(dispatcher::read_state(pointer) as i32)?;
        information.maximum_count.probe_set(semaphore.limit.get())?;
        Ok(0)
    })
}

pub fn init() {
    state::register_handler("NtCreateSemaphore", nt_create_semaphore);
    state::register_handler("NtOpenSemaphore", nt_open_semaphore);
    state::register_handler("NtReleaseSemaphore", nt_release_semaphore);
    state::register_handler("NtQuerySemaphore", nt_query_semaphore);
}
