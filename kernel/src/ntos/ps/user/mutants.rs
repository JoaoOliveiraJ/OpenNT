//! Mutantes de usuário — `system32/ntos/ps/user/mutants.js`.
//!
//! KMUTANT de 0x38 bytes: o corpo não é coletado enquanto houver dono
//! (`busy`); a saída de uma thread abandona os mutantes que ela possui.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::registry::parse_user_object_attributes;
use super::state;
use crate::ntos::ke::dispatcher;
use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks, UserDispatcher};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// MUTANT_OWNER (KMUTANT.OwnerThread) e Abandoned.
const OWNER: u64 = 0x28;
const ABANDONED: u64 = 0x30;

pub struct MutantObject {
    pub pointer: u64,
    pub name: String,
    node: SpinLock<Option<NodeId>>,
}

static MUTANTS: SpinLock<BTreeMap<u64, Arc<MutantObject>>> = SpinLock::new(BTreeMap::new());

fn dispose(pointer: u64) {
    let object = MUTANTS.lock().remove(&pointer);
    if let Some(node) = object.and_then(|object| object.node.lock().take()) {
        object_manager::remove_named(node);
    }
    guest::free_bytes(pointer);
}

fn busy(pointer: u64) -> bool {
    guest::read64(pointer + OWNER) != 0
}

fn publish(object: &Arc<MutantObject>, out: u64, access: u32, attributes: u64, success: u32) -> Result<u32, KernelError> {
    let flags = if attributes != 0 { guest::read32(attributes + 24) } else { 0 };
    dispatcher_objects::publish(object.pointer, out, access, flags, success, false, Some(object.clone()))
}

fn mutant_of_node(node: NodeId) -> Option<Arc<MutantObject>> {
    let pointer = object_manager::node(node)?.data?.native_pointer;
    MUTANTS.lock().get(&pointer).cloned()
}

/// Mutante de um handle `mutant` (sem checagem de acesso, como o original
/// para NtReleaseMutant).
fn mutant_of_handle(handle: u64) -> Result<(Arc<state::UserHandle>, u64), u32> {
    let Some(entry) = state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "mutant" {
        return Err(0xC000_0024);
    }
    let pointer = entry.downcast::<UserDispatcher>().map(|dispatcher| dispatcher.pointer).ok_or(0xC000_0024u32)?;
    Ok((entry, pointer))
}

/// NtCreateMutant(out, access, oa, initialOwner).
fn nt_create_mutant(out: u64, access: u64, attributes: u64, initial_owner: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) || (attributes != 0 && !state::probe_user_read(attributes, 48)) {
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
        if let Some(node) = object_manager::lookup(&name) {
            if object_manager::node(node).is_none_or(|node| node.type_name != "Mutant") {
                return Ok(0xC000_0024);
            }
            if guest::read32(attributes + 0x18) & 0x80 == 0 {
                return Ok(0xC000_0035);
            }
            let Some(object) = mutant_of_node(node) else { return Ok(0xC000_0024) };
            return publish(&object, out, access as u32, attributes, 0x4000_0000);
        }
        if object_manager::lookup(&parent).and_then(object_manager::node).is_none_or(|node| node.type_name != "Directory") {
            debug_print!("[usermode] NtCreateMutant missing directory: {}", name);
            return Ok(0xC000_003A);
        }
    }
    let pointer = guest::alloc_bytes(0x38);
    if pointer == 0 {
        return Ok(0xC000_0017);
    }
    dispatcher::initialize_mutant(pointer, initial_owner & 255 != 0);
    let object = Arc::new(MutantObject { pointer, name: name.clone(), node: SpinLock::new(None) });
    if let Err(error) = dispatcher_objects::create(pointer, "mutant", dispose, Some(busy), attributes, true, DispatcherHooks::default()) {
        guest::free_bytes(pointer);
        return if error.status != 0 { Ok(error.status) } else { Err(error) };
    }
    MUTANTS.lock().insert(pointer, object.clone());
    // Desfaz: um mutante possuído sem handles nem referências é abandonado
    // antes da coleta.
    let rollback = |pointer: u64| {
        if dispatcher_objects::get(pointer).is_some_and(|(_, refs, handles)| refs == 0 && handles == 0) && busy(pointer) {
            let _ = dispatcher::release_mutant(pointer, true);
        }
        dispatcher_objects::collect(pointer);
    };
    if !name.is_empty() {
        match object_manager::create_object(&parent, &name[cut + 1..], "Mutant", Some(dispatcher_objects::data(pointer))) {
            Ok(node) => *object.node.lock() = Some(node),
            Err(error) => {
                rollback(pointer);
                return if error.status != 0 { Ok(error.status) } else { Err(error) };
            }
        }
    }
    let status = publish(&object, out, access as u32, attributes, 0)?;
    if status != 0 {
        rollback(pointer);
    }
    Ok(status)
}

fn nt_open_mutant(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) || !state::probe_user_read(attributes, 48) {
        return Ok(0xC000_0005);
    }
    let Some(parsed) = parse_user_object_attributes(attributes) else { return Ok(0xC000_000D) };
    let Some(node) = object_manager::lookup(&parsed.path) else { return Ok(0xC000_0034) };
    if object_manager::node(node).is_none_or(|node| node.type_name != "Mutant") {
        return Ok(0xC000_0024);
    }
    let Some(object) = mutant_of_node(node) else { return Ok(0xC000_0024) };
    publish(&object, out, access as u32, attributes, 0)
}

/// NtReleaseMutant: exige a posse; devolve o estado anterior.
fn nt_release_mutant(handle: u64, previous: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if previous != 0 && !state::probe_user_write(previous, 4) {
        return Ok(0xC000_0005);
    }
    let pointer = match mutant_of_handle(handle) {
        Ok((_, pointer)) => pointer,
        Err(status) => return Ok(status),
    };
    Ok(match dispatcher::release_mutant(pointer, false) {
        Ok(old) => {
            if previous != 0 {
                guest::write32(previous, old as u32);
            }
            0
        }
        Err(status) => status,
    })
}

/// NtQueryMutant: básica (estado, posse pela thread corrente, abandono) e
/// dono (CLIENT_ID do ETHREAD).
fn nt_query_mutant(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let (entry, pointer) = match mutant_of_handle(handle) {
        Ok(found) => found,
        Err(status) => return Ok(status),
    };
    if entry.access() & 1 == 0 {
        return Ok(0xC000_0022);
    }
    if class != 0 && class != 1 {
        return Ok(0xC000_0003);
    }
    let size = if class == 0 { 8 } else { 16 };
    let returned = state::stack_arg(rsp, 5);
    if returned != 0 && !state::probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    if returned != 0 {
        guest::write32(returned, size as u32);
    }
    if length < size {
        return Ok(0xC000_0004);
    }
    if !state::probe_user_write(out, size) {
        return Ok(0xC000_0005);
    }
    let owner = guest::read64(pointer + OWNER);
    if class == 0 {
        guest::write32(out, dispatcher::read_state(pointer));
        guest::write8(out + 4, (owner != 0 && owner == process::get_current_thread()) as u8);
        guest::write8(out + 5, guest::read8(pointer + ABANDONED) & 1);
        guest::write16(out + 6, 0);
    } else {
        // ETHREAD.Cid, compartilhado com as threads reais do gerenciador.
        guest::write64(out, if owner != 0 { guest::read64(owner + 0x478) } else { 0 });
        guest::write64(out + 8, if owner != 0 { guest::read64(owner + 0x480) } else { 0 });
    }
    Ok(0)
}

/// Saída de thread: abandona os mutantes que ela possui e coleta os sem uso.
pub fn release_thread(thread: u64) {
    let owned: Vec<u64> = MUTANTS.lock().keys().copied().filter(|&pointer| guest::read64(pointer + OWNER) == thread).collect();
    for pointer in owned {
        let _ = dispatcher::release_mutant(pointer, true);
        dispatcher_objects::collect(pointer);
    }
}

/// Abandona os mutantes de todas as threads do processo.
pub fn release_process() {
    for thread in super::threads::all() {
        release_thread(thread.pointer());
    }
}

pub fn init() {
    state::register_handler("NtCreateMutant", nt_create_mutant);
    state::register_handler("NtOpenMutant", nt_open_mutant);
    state::register_handler("NtReleaseMutant", nt_release_mutant);
    state::register_handler("NtQueryMutant", nt_query_mutant);
    process::register_thread_exit_routine(release_thread);
}
