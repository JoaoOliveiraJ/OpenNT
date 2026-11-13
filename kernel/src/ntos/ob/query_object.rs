//! ZwQueryObject.
//!
//! Consulta objetos dos provedores reais e dos tipos registrados: nome,
//! referências e segurança vêm da identidade viva do dono, retida durante a
//! coleta. A serialização das classes 0–4 é `query_object_format`.
//!
//! ObQueryNameString também mora aqui (como no `obquery.c` do NT): o caminho
//! completo pelo corpo nativo, ou o nome próprio de um callback do Ex.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::object_manager;
use super::object_reference::native_pointer_of_node;
use super::object_types::{self, ObjectType};
use super::open_pointer;
use super::query_object_format::{self, ObjectInformation};
use crate::ntos::cm::registry;
use crate::ntos::ex::callbacks;
use crate::ntos::ke::irql;
use crate::ntos::mm::{kernel_pool, paging};
use crate::ntos::ps::process;
use crate::ntos::ps::user::state::{self, UserHandle};
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::model::SecurityPolicy;
use crate::ntos::se::token::handles as token_handles;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// Informação coletada e a liberação da referência de consulta.
pub struct Collected {
    pub information: ObjectInformation,
    release: Option<Box<dyn FnOnce()>>,
}

impl Collected {
    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

fn information(object_type: ObjectType, name: String, attributes: u32, access: u32, handles: u32, references: u32) -> ObjectInformation {
    ObjectInformation { attributes: attributes & 7, object_flags: 0, access, handles, references, paged_charge: 0, nonpaged_charge: 0, name: Some(name).filter(|name| !name.is_empty()), object_type, security_length: 0, creation_time: 0 }
}

/// Ponteiro nativo de um handle de usuário (corpo, objeto esperável).
fn user_pointer(entry: &UserHandle) -> u64 {
    entry.object.native_body().map(|body| body.pointer).or_else(|| entry.object.wait_pointer()).unwrap_or(0)
}

/// Handles vivos do mesmo corpo nas descrições de kernel e de usuário.
fn handle_count(pointer: u64) -> u32 {
    let kernel = object_manager::handle_entries().into_iter().filter(|(_, node)| object_manager::node(*node).and_then(|node| node.data).is_some_and(|data| data.native_pointer == pointer)).count();
    let user = state::user_handle_values().into_iter().filter_map(|value| state::get_user_handle(value as u64)).filter(|entry| user_pointer(entry) == pointer).count();
    (kernel + user) as u32
}

/// Carga do descritor disponível quando o handle concede READ_CONTROL.
fn security_length(policy: &SecurityPolicy, access: u32) -> u32 {
    if access & 0x2_0000 == 0 {
        return 0;
    }
    let dacl = policy.dacl.as_ref().map_or(0, |entries| 8 + entries.iter().map(|ace| ace.raw.as_ref().map_or(8 + ace.sid.as_ref().map_or(0, |sid| sid.len()), |raw| raw.len())).sum::<usize>());
    (20 + policy.owner.len() + policy.group.as_ref().map_or(0, |group| group.len()) + dacl) as u32
}

/// Retém o corpo enquanto coleta os metadados do dono.
fn from_body(pointer: u64, attributes: u32, access: u32) -> Result<Collected, u32> {
    let Some(item) = open_pointer::describe(pointer) else {
        let found = object_manager::namespace_entries().into_iter().find(|(node, _)| object_manager::node(*node).and_then(|node| node.data).is_some_and(|data| data.native_pointer == pointer));
        let (Some((node, path)), Some(object_type)) = (found, object_types::bound(pointer)) else { return Err(STATUS_INVALID_HANDLE) };
        let refs = object_manager::node(node).map_or(0, |node| node.refs);
        return Ok(Collected { information: information(object_type, path, attributes, access, refs, refs + 1), release: None });
    };
    item.reference();
    let record = item.owner.query_record(pointer);
    let allocation = kernel_pool::info(pointer);
    let exclusive = item.owner.exclusive_process(pointer) != 0;
    let mut collected = information(item.object_type.clone(), record.name, attributes, access, record.handles.unwrap_or_else(|| handle_count(pointer)), record.references);
    collected.object_flags = (if record.permanent { 0x10 } else { 0 }) | (if exclusive { 0x20 } else { 0 });
    collected.security_length = security_length(&item.owner.security(pointer), access);
    if let Some(allocation) = allocation {
        if allocation.paged {
            collected.paged_charge = allocation.bytes as u32;
        } else {
            collected.nonpaged_charge = allocation.bytes as u32;
        }
    }
    Ok(Collected { information: collected, release: Some(Box::new(move || item.dereference())) })
}

/// Pseudo-handle, handle por ponteiro, callback/token de kernel, tabela de
/// usuário do processo ou registro Zw — com a posse verificada.
pub fn resolve(handle: u64) -> Result<Collected, u32> {
    match handle as i64 {
        -1 => return from_body(process::get_current_process(), 0, object_types::process_type().valid_access),
        -2 => return from_body(process::get_current_thread(), 0, object_types::thread_type().valid_access),
        _ => {}
    }
    let kernel_handle = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if !kernel_handle && handle > 0x7FFF_FFFF {
        return Err(STATUS_INVALID_HANDLE);
    }
    let handle = handle & !3;
    match open_pointer::resolve(handle, false) {
        Some(Err(status)) => return Err(status),
        Some(Ok(resolved)) => return from_body(resolved.item.pointer, resolved.attributes, resolved.access),
        None => {}
    }
    if kernel_handle {
        if let Some(data) = callbacks::resolve_handle(handle, false) {
            return from_body(data.native_pointer, data.attributes, data.access.unwrap_or(0));
        }
        return match token_handles::resolve_native(handle) {
            Some(data) => from_body(data.native_pointer, data.attributes, data.access.unwrap_or(0)),
            None => Err(STATUS_INVALID_HANDLE),
        };
    }
    let current = process::get_current_process();
    if current != process::get_system_process() && state::with(|state| state.current_process_id) == guest::read64(current + 0x440) {
        if let Some(entry) = state::get_user_handle(handle) {
            return resolve_user(entry);
        }
    }
    resolve_kernel_record(handle as u32, current)
}

fn resolve_user(entry: Arc<UserHandle>) -> Result<Collected, u32> {
    let pointer = user_pointer(&entry);
    if pointer != 0 {
        return from_body(pointer, entry.attributes(), entry.access());
    }
    let Some(object_type) = object_types::user_type(entry.kind()) else { return Err(0xC000_00BB) };
    // A identidade é o objeto compartilhado pelas duplicações do handle.
    let same: Vec<Arc<UserHandle>> = state::user_handle_values().into_iter().filter_map(|value| state::get_user_handle(value as u64)).filter(|candidate| Arc::ptr_eq(&candidate.object, &entry.object)).collect();
    let name = entry.object.object_path().unwrap_or_default();
    state::retain_user_handle_reference(&entry);
    let references = same.len() as u32 + same.iter().map(|candidate| candidate.wait_references()).sum::<u32>();
    let mut collected = information(object_type, name, entry.attributes(), entry.access(), same.len() as u32, references);
    collected.security_length = entry.object.security().map_or(0, |policy| security_length(&policy, entry.access()));
    Ok(Collected { information: collected, release: Some(Box::new(move || {
        let _ = state::release_user_handle_reference(&entry);
    })) })
}

/// Registro Zw do handle: nó do Object Manager ou chave do registro.
fn resolve_kernel_record(handle: u32, current: u64) -> Result<Collected, u32> {
    if let Some((_, node)) = object_manager::handle_entries().into_iter().find(|(identifier, _)| *identifier == handle) {
        let Some(snapshot) = object_manager::node(node) else { return Err(STATUS_INVALID_HANDLE) };
        let data = snapshot.data.clone().unwrap_or_default();
        let kernel = data.attributes & 0x200 != 0;
        if !kernel && data.owner_process.is_some_and(|owner| owner != current) {
            return Err(STATUS_INVALID_HANDLE);
        }
        if data.native_pointer != 0 {
            return from_body(data.native_pointer, data.attributes, data.access.unwrap_or(0));
        }
        let Some(object_type) = object_types::by_name(&snapshot.type_name) else { return Err(0xC000_00BB) };
        let path = object_manager::path_of(node).unwrap_or_default();
        return Ok(Collected { information: information(object_type, path, data.attributes, data.access.unwrap_or(0), snapshot.refs, snapshot.refs + 1), release: None });
    }
    let entries = registry::handle_entries();
    let Some((_, opened)) = entries.iter().find(|(identifier, _)| *identifier == handle) else { return Err(STATUS_INVALID_HANDLE) };
    let Some(record) = crate::ntos::cm::key::services::close_record(handle) else { return Err(STATUS_INVALID_HANDLE) };
    if !record.kernel_handle && record.owner_process != current {
        return Err(STATUS_INVALID_HANDLE);
    }
    let count = entries.iter().filter(|(_, entry)| entry.node == opened.node).count() as u32;
    Ok(Collected { information: information(object_types::key_type(), opened.path.clone(), record.attributes, record.access, count, count + 1), release: None })
}

/// Contribuição anterior dos objetos de usuário sem contagem própria.
static USER_CONTRIBUTIONS: SpinLock<BTreeMap<String, (u32, u32)>> = SpinLock::new(BTreeMap::new());

fn publish_statistics(object_type: &ObjectType, objects: u32, handles: u32, peak_objects: u32, peak_handles: u32) {
    let Some((current_objects, current_handles, _, _)) = object_types::statistics(&object_type.name) else { return };
    let _ = object_types::account(&object_type.name, objects as i64 - current_objects as i64, handles as i64 - current_handles as i64);
    object_types::raise_peaks(&object_type.name, peak_objects, peak_handles);
}

/// Contadores dos tipos com as contribuições do namespace, do registro e
/// dos objetos de usuário ainda não contados pelos próprios provedores.
pub fn types() -> Vec<ObjectType> {
    for object_type in [object_types::directory_type(), object_types::symbolic_link_type()] {
        let statistics = object_manager::type_stats(&object_type.name);
        publish_statistics(&object_type, statistics.objects, statistics.handles, statistics.peak_objects, statistics.peak_handles);
    }
    let keys = registry::object_stats();
    publish_statistics(&object_types::key_type(), keys.objects as u32, keys.handles as u32, keys.peak_objects as u32, keys.peak_handles as u32);
    let mut current: BTreeMap<String, (Vec<usize>, u32)> = BTreeMap::new();
    for value in state::user_handle_values() {
        let Some(entry) = state::get_user_handle(value as u64) else { continue };
        let Some(object_type) = object_types::user_type(entry.kind()) else { continue };
        // Estes provedores já contam seus corpos e handles.
        if entry.object.opened_natively() || entry.object.native_body().is_some() || user_pointer(&entry) != 0 || ["process", "thread", "key", "section", "directory", "symlink"].contains(&entry.kind()) {
            continue;
        }
        let identity = Arc::as_ptr(&entry.object) as *const () as usize;
        let slot = current.entry(object_type.name.clone()).or_insert_with(|| (Vec::new(), 0));
        if !slot.0.contains(&identity) {
            slot.0.push(identity);
        }
        slot.1 += 1;
    }
    let mut contributions = USER_CONTRIBUTIONS.lock();
    let names: Vec<String> = current.keys().chain(contributions.keys()).cloned().collect();
    for name in names {
        let before = contributions.get(&name).copied().unwrap_or((0, 0));
        let after = current.get(&name).map_or((0, 0), |(objects, handles)| (objects.len() as u32, *handles));
        if before == after {
            continue;
        }
        let _ = object_types::account(&name, after.0 as i64 - before.0 as i64, after.1 as i64 - before.1 as i64);
        contributions.insert(name, after);
    }
    object_types::all()
}

/// Limites canônicos e todas as páginas que receberão bytes de saída.
fn writable_range(pointer: u64, length: u64) -> bool {
    if length == 0 {
        return true;
    }
    let Some(end) = pointer.checked_add(length) else { return false };
    if pointer == 0 || (pointer < 0xFFFF_8000_0000_0000 && end > 0x8000_0000_0000) {
        return false;
    }
    let mut page = pointer;
    while page < end {
        if paging::access_flags(page) & 3 != 3 {
            return false;
        }
        page = (page & !0xFFF) + 0x1000;
    }
    true
}

/// Resolve a identidade, mede as regiões efetivamente escritas e serializa
/// a classe; a referência de consulta é liberada em todos os caminhos.
pub fn query(handle: u64, class: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("ZwQueryObject requires PASSIVE_LEVEL"));
    }
    let list = types();
    let mut collected = if class == 3 {
        None
    } else {
        match resolve(handle) {
            Ok(collected) => Some(collected),
            Err(status) => return Ok(status),
        }
    };
    let result = (|| -> u32 {
        // O caminho nativo valida classe e tamanho antes de sondar memória.
        if class > 4 {
            return 0xC000_0003;
        }
        if class == 0 && length != 56 {
            return 0xC000_0004;
        }
        let information = collected.as_ref().map(|collected| &collected.information);
        let required = match class {
            0 => 56,
            1 => information.and_then(|information| information.name.as_ref()).map_or(16, |name| 18 + name.encode_utf16().count() as u32 * 2),
            2 => information.map_or(0, |information| query_object_format::type_size(&information.object_type)),
            4 => 2,
            _ => 8 + list.iter().map(query_object_format::type_size).sum::<u32>(),
        };
        let mut written = if length < required { 0 } else { required };
        if class == 3 {
            written = if length < 4 { 0 } else { 4 };
            let mut offset = 8;
            for object_type in &list {
                let size = query_object_format::type_size(object_type);
                if length >= offset + size {
                    written = offset + 106 + object_type.name.encode_utf16().count() as u32 * 2;
                }
                offset += size;
            }
        } else if class == 2 && written != 0 {
            written = 106 + information.map_or(0, |information| information.object_type.name.encode_utf16().count() as u32 * 2);
        }
        if written != 0 && !writable_range(output, written as u64) {
            return STATUS_ACCESS_VIOLATION;
        }
        let empty = information.cloned().unwrap_or_else(|| self::information(object_types::directory_type(), String::new(), 0, 0, 0, 0));
        let formatted = query_object_format::format(&empty, class, output, length, &list);
        if returned != 0 {
            if let Some(needed) = formatted.needed {
                if !writable_range(returned, 4) {
                    return STATUS_ACCESS_VIOLATION;
                }
                guest::write32(returned, needed);
            }
        }
        formatted.status
    })();
    if let Some(collected) = collected.as_mut() {
        collected.release();
    }
    Ok(result)
}

/// Caminho completo pelo corpo nativo (\Device, \Driver e \KernelObjects).
fn find_path_by_native_pointer(pointer: u64) -> Option<String> {
    for root in ["\\Device", "\\Driver", "\\KernelObjects"] {
        let Some(children) = object_manager::lookup(root).and_then(object_manager::node).and_then(|node| node.children) else { continue };
        for &child in children.values() {
            let Some(node) = object_manager::node(child) else { continue };
            let Some(data) = node.data.as_ref() else { continue };
            if native_pointer_of_node(Some(child)) == pointer || (node.type_name == "Event" && data.native_pointer == pointer) {
                return Some(alloc::format!("{root}\\{}", node.name));
            }
        }
    }
    None
}

/// ObQueryNameString: o caminho completo do objeto (callbacks pelo nome
/// próprio, com o UNICODE_STRING montado no buffer).
pub fn query_name_string(pointer: u64, output: u64, size: u32, returned: u64) -> u32 {
    if callbacks::exists(pointer) {
        let name = callbacks::name(pointer);
        let units = name.as_ref().map_or(0, |name| name.encode_utf16().count() as u32);
        let needed = 16 + if name.is_some() { units * 2 + 2 } else { 0 };
        if returned != 0 {
            guest::write32(returned, needed);
        }
        if size < needed {
            return 0xC000_0004;
        }
        for offset in 0..16 {
            guest::write8(output + offset, 0);
        }
        if let Some(name) = name {
            guest::write16(output, units as u16 * 2);
            guest::write16(output + 2, units as u16 * 2 + 2);
            guest::write64(output + 8, output + 16);
            guest_strings::write_wide_string(output + 16, &name);
        }
        return 0;
    }
    let Some(path) = find_path_by_native_pointer(pointer) else {
        if returned != 0 {
            guest::write32(returned, 0);
        }
        return 0xC000_000D;
    };
    let units = path.encode_utf16().count() as u32;
    let needed = units * 2 + 2;
    if returned != 0 {
        guest::write32(returned, needed);
    }
    if size < needed {
        return 0xC000_0004;
    }
    guest_strings::write_wide_string(guest::read64(output + 8), &path);
    guest::write16(output, units as u16 * 2);
    guest::write16(output + 2, units as u16 * 2 + 2);
    0
}
