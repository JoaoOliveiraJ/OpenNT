//! Eventos de usuário — `system32/ntos/ps/user/events.js`.
//!
//! KEVENTs têm vidas independentes de handle e de referência de kernel: um
//! driver pode manter um evento referenciado depois de o handle de usuário
//! que o criou fechar.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use super::registry::parse_user_object_attributes;
use super::state;
use crate::ntos::ke::dispatcher;
use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks, UserDispatcher};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// O objeto evento do dono: KEVENT de 0x18 bytes, tipo e nome.
pub struct EventObject {
    pub pointer: u64,
    pub event_type: u32,
    pub name: String,
    node: SpinLock<Option<NodeId>>,
}

static EVENTS: SpinLock<BTreeMap<u64, Arc<EventObject>>> = SpinLock::new(BTreeMap::new());

fn dispose(pointer: u64) {
    let object = EVENTS.lock().remove(&pointer);
    if let Some(node) = object.and_then(|object| object.node.lock().take()) {
        object_manager::remove_named(node);
    }
    guest::free_bytes(pointer);
}

fn split_name(name: &str) -> (String, String) {
    let cut = name.rfind('\\').unwrap_or(0);
    let parent = if cut == 0 { String::from("\\") } else { String::from(&name[..cut]) };
    (parent, String::from(&name[cut + 1..]))
}

/// Inicializa o KEVENT, registra o corpo e publica o nome.
pub fn create(pointer: u64, name: &str, event_type: u32, signaled: bool, attributes: u64, user: bool) -> Result<Arc<EventObject>, KernelError> {
    dispatcher::initialize_event(pointer, event_type as u8, signaled);
    let object = Arc::new(EventObject { pointer, event_type, name: String::from(name), node: SpinLock::new(None) });
    if let Err(error) = dispatcher_objects::create(pointer, "event", dispose, None, attributes, user, DispatcherHooks::default()) {
        guest::free_bytes(pointer);
        return Err(error);
    }
    EVENTS.lock().insert(pointer, object.clone());
    if !name.is_empty() {
        let (parent, leaf) = split_name(name);
        match object_manager::create_object(&parent, &leaf, "Event", Some(dispatcher_objects::data(pointer))) {
            Ok(node) => *object.node.lock() = Some(node),
            Err(error) => {
                dispatcher_objects::collect(pointer);
                return Err(error);
            }
        }
    }
    Ok(object)
}

fn publish(object: &Arc<EventObject>, out: u64, access: u32, attributes: u64, success: u32) -> Result<u32, KernelError> {
    let flags = if attributes != 0 { guest::read32(attributes + 24) } else { 0 };
    dispatcher_objects::publish(object.pointer, out, access, flags, success, false, Some(object.clone()))
}

/// Evento de um handle `event` do processo, com o corpo retido.
pub fn reference(handle: u64, access: u32) -> Result<Arc<EventObject>, u32> {
    let Some(entry) = state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "event" {
        return Err(0xC000_0024);
    }
    if entry.access() & access != access {
        return Err(0xC000_0022);
    }
    let object = entry.downcast::<UserDispatcher>().and_then(|dispatcher| dispatcher.payload.clone()).and_then(|payload| payload.downcast::<EventObject>().ok()).ok_or(0xC000_0024u32)?;
    let _ = dispatcher_objects::reference(object.pointer);
    Ok(object)
}

pub fn release(object: &EventObject) {
    let _ = dispatcher_objects::dereference(object.pointer);
}

fn event_of_node(node: NodeId) -> Option<Arc<EventObject>> {
    let pointer = object_manager::node(node)?.data?.native_pointer;
    EVENTS.lock().get(&pointer).cloned()
}

/// NtCreateEvent(out, access, oa, type, initialState).
fn nt_create_event(out: u64, access: u64, attributes: u64, event_type: u64, rsp: u64) -> Result<u32, KernelError> {
    let event_type = event_type as u32;
    if event_type > 1 {
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
    if !name.is_empty() {
        if let Some(existing) = object_manager::lookup(&name) {
            if object_manager::node(existing).is_none_or(|node| node.type_name != "Event") {
                return Ok(0xC000_0024);
            }
            if guest::read32(attributes + 0x18) & 0x80 == 0 {
                return Ok(0xC000_0035);
            }
            let Some(object) = event_of_node(existing) else { return Ok(0xC000_0024) };
            return publish(&object, out, access as u32, attributes, 0x4000_0000);
        }
        let (parent, _) = split_name(&name);
        if object_manager::lookup(&parent).and_then(object_manager::node).is_none_or(|node| node.type_name != "Directory") {
            return Ok(0xC000_003A);
        }
    }
    let pointer = guest::alloc_bytes(0x18);
    if pointer == 0 {
        return Ok(0xC000_0017);
    }
    let signaled = state::stack_arg32(rsp, 5) & 255 != 0;
    match create(pointer, &name, event_type, signaled, attributes, true) {
        Ok(object) => publish(&object, out, access as u32, attributes, 0),
        Err(error) if error.status != 0 => Ok(error.status),
        Err(error) => Err(error),
    }
}

/// NtOpenEvent(out, access, oa).
fn nt_open_event(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) {
        return Ok(0xC000_0005);
    }
    let Some(parsed) = parse_user_object_attributes(attributes) else { return Ok(0xC000_000D) };
    let Some(node) = object_manager::lookup(&parsed.path) else { return Ok(0xC000_0034) };
    if object_manager::node(node).is_none_or(|node| node.type_name != "Event") {
        return Ok(0xC000_0024);
    }
    let Some(object) = event_of_node(node) else { return Ok(0xC000_0024) };
    publish(&object, out, access as u32, attributes, 0)
}

/// Set/Reset/Clear com EVENT_MODIFY_STATE; o estado anterior é opcional.
fn modify(handle: u64, previous: u64, operation: fn(u64) -> u32) -> u32 {
    if previous != 0 && !state::probe_user_write(previous, 4) {
        return 0xC000_0005;
    }
    let object = match reference(handle, 2) {
        Ok(object) => object,
        Err(status) => return status,
    };
    let value = operation(object.pointer);
    if previous != 0 {
        guest::write32(previous, value);
    }
    release(&object);
    0
}

fn nt_set_event(handle: u64, previous: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(modify(handle, previous, dispatcher::set_event))
}

fn nt_reset_event(handle: u64, previous: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(modify(handle, previous, dispatcher::reset_event))
}

fn nt_clear_event(handle: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(modify(handle, 0, dispatcher::reset_event))
}

/// NtQueryEvent(EventBasicInformation): tipo e estado.
fn nt_query_event(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let object = match reference(handle, 1) {
        Ok(object) => object,
        Err(status) => return Ok(status),
    };
    let status = (|| {
        if class != 0 {
            return 0xC000_0003;
        }
        let returned = state::stack_arg(rsp, 5);
        if returned != 0 && !state::probe_user_write(returned, 4) {
            return 0xC000_0005;
        }
        if returned != 0 {
            guest::write32(returned, 8);
        }
        if length < 8 {
            return 0xC000_0004;
        }
        if !state::probe_user_write(out, 8) {
            return 0xC000_0005;
        }
        guest::write32(out, object.event_type);
        guest::write32(out + 4, dispatcher::read_state(object.pointer));
        0
    })();
    release(&object);
    Ok(status)
}

/// Evento nomeado do kernel (`\KernelObjects\...`), retido pelo chamador.
pub fn create_kernel_event(name: &str, event_type: u32, signaled: bool) -> Result<Arc<EventObject>, KernelError> {
    if event_type > 1 {
        return Err(KernelError::new("Invalid event type"));
    }
    if object_manager::lookup(name).is_some() {
        return Err(KernelError::new(alloc::format!("Event already exists: {name}")));
    }
    let pointer = guest::alloc_bytes(0x18);
    if pointer == 0 {
        return Err(KernelError::new("Cannot allocate kernel event"));
    }
    let object = create(pointer, name, event_type, signaled, 0, false)?;
    let _ = dispatcher_objects::reference(pointer);
    Ok(object)
}

pub fn init() {
    state::register_handler("NtCreateEvent", nt_create_event);
    state::register_handler("NtOpenEvent", nt_open_event);
    state::register_handler("NtSetEvent", nt_set_event);
    state::register_handler("NtResetEvent", nt_reset_event);
    state::register_handler("NtClearEvent", nt_clear_event);
    state::register_handler("NtQueryEvent", nt_query_event);
}
