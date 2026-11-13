//! Handles de diretórios e links do namespace — `system32/ntos/ob/namespace-handles.js`.
//!
//! NtOpen/NtCreateDirectoryObject, NtOpenSymbolicLinkObject,
//! NtQuerySymbolicLinkObject, NtQueryDirectoryObject e NtMakeTemporaryObject.
//! Os handles de usuário do processo corrente entram com a fase 7.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::namespace as namespace_objects;
use crate::ntos::ob::open_pointer;
use crate::ntos::ex::callback_security;
use crate::ntos::ps::user_probe;
use crate::ntos::mm::guest_memory as guest;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// Handle resolvido para um corpo de diretório ou link.
pub struct Opened {
    pub body: u64,
    pub node: NodeId,
    pub directory: bool,
    pub access: u32,
}

/// Exige um corpo Directory ou SymbolicLink registrado no namespace.
pub fn resolve(handle: u64, from_user_mode: bool) -> Result<Opened, u32> {
    let resolved = match open_pointer::resolve(handle, from_user_mode) {
        Some(Err(status)) => return Err(status),
        Some(Ok(resolved)) => resolved,
        None => return Err(STATUS_INVALID_HANDLE),
    };
    let Some((node, directory)) = namespace_objects::get(resolved.item.pointer) else {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    };
    Ok(Opened { body: resolved.item.pointer, node, directory, access: resolved.access })
}

struct Captured {
    name: String,
    start: NodeId,
    flags: u32,
    case_insensitive: bool,
    attributes: u64,
}

fn readable(pointer: u64, length: u64, from_user_mode: bool) -> bool {
    !from_user_mode || user_probe::probe_user_read(pointer, length)
}

/// Lê OBJECT_ATTRIBUTES e o UNICODE_STRING com as sondas de usuário;
/// RootDirectory define o início de nomes relativos.
fn capture(attributes: u64, from_user_mode: bool) -> Result<Captured, u32> {
    if attributes == 0 {
        return Err(0xC000_000D);
    }
    if !readable(attributes, 48, from_user_mode) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if guest::read32(attributes) != 48 {
        return Err(0xC000_000D);
    }
    let flags = guest::read32(attributes + 24);
    let root = guest::read64(attributes + 8);
    let unicode = guest::read64(attributes + 16);
    if from_user_mode && flags & 0x200 != 0 {
        return Err(STATUS_INVALID_HANDLE);
    }
    if unicode == 0 {
        return Err(0xC000_0033);
    }
    if !readable(unicode, 16, from_user_mode) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let length = guest::read16(unicode);
    let buffer = guest::read64(unicode + 8);
    if length & 1 != 0 || length > guest::read16(unicode + 2) {
        return Err(0xC000_0033);
    }
    if length != 0 && (buffer == 0 || !readable(buffer, length as u64, from_user_mode)) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let units: Vec<u16> = (0..length as u64 / 2).map(|index| guest::read16(buffer + index * 2)).collect();
    let name = String::from_utf16_lossy(&units);
    let mut start = object_manager::ROOT;
    if root != 0 {
        let opened = resolve(root, from_user_mode)?;
        if !opened.directory {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if name.starts_with('\\') {
            return Err(0xC000_003B);
        }
        start = opened.node;
    } else if !name.starts_with('\\') {
        return Err(0xC000_003B);
    }
    Ok(Captured { name, start, flags, case_insensitive: flags & 0x40 != 0, attributes })
}

/// Abre ou cria (`create`) o objeto, valida o tipo e publica o handle pelo
/// corpo nativo; uma criação incompleta remove o nó inserido.
pub fn open(output_handle: u64, access: u32, attributes: u64, kind: &str, from_user_mode: bool, create: bool) -> u32 {
    if from_user_mode && !user_probe::probe_user_write(output_handle, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut created: Option<NodeId> = None;
    let status = open_inner(output_handle, access, attributes, kind, from_user_mode, create, &mut created);
    if let Some(node) = created {
        object_manager::remove_named(node);
    }
    status
}

#[allow(clippy::too_many_arguments)]
fn open_inner(output_handle: u64, access: u32, attributes: u64, kind: &str, from_user_mode: bool, create: bool, created: &mut Option<NodeId>) -> u32 {
    let input = match capture(attributes, from_user_mode) {
        Ok(input) => input,
        Err(status) => return status,
    };
    let (found, rest) = object_manager::resolve_from(&input.name, 0, input.case_insensitive, kind == "SymbolicLink", input.start);
    if rest.is_some_and(|rest| !rest.is_empty()) {
        return 0xC000_003A;
    }
    let mut node = found;
    if create {
        if node.is_some() && input.flags & 0x80 == 0 {
            return 0xC000_0035;
        }
        if node.is_none() {
            let mut parts: Vec<&str> = input.name.split('\\').filter(|part| !part.is_empty()).collect();
            let Some(name) = parts.pop() else { return 0xC000_0033 };
            let (parent, parent_rest) = object_manager::resolve_from(&parts.join("\\"), 0, input.case_insensitive, false, input.start);
            let parent = parent.filter(|&parent| object_manager::node(parent).is_some_and(|node| node.type_name == "Directory") && parent_rest.is_none());
            let Some(parent) = parent else { return 0xC000_003A };
            let Some(inserted) = object_manager::insert_named(parent, name, "Directory", None, input.case_insensitive) else {
                return 0xC000_0035;
            };
            *created = Some(inserted);
            object_manager::update_node(inserted, |node| node.permanent = Some(input.flags & 0x10 != 0));
            node = Some(inserted);
        }
    }
    let Some(node) = node else { return 0xC000_0034 };
    if object_manager::node(node).is_none_or(|snapshot| snapshot.type_name != kind) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    let body = match namespace_objects::ensure(node) {
        Ok(Some(body)) => body,
        Ok(None) => return STATUS_OBJECT_TYPE_MISMATCH,
        Err(error) => return if error.status != 0 { error.status } else { 0xC000_0001 },
    };
    if created.is_some() {
        let descriptor = guest::read64(input.attributes + 32);
        if descriptor != 0 {
            match callback_security::capture(descriptor) {
                Ok(policy) => namespace_objects::set_security(body, policy),
                Err(status) => return status,
            }
        }
    }
    let object_type = open_pointer::describe(body).map_or(0, |item| item.object_type.pointer);
    let status = match open_pointer::open(body, input.flags, 0, access, object_type, from_user_mode as u8, output_handle) {
        Ok(status) => status,
        Err(error) => return if error.status != 0 { error.status } else { 0xC000_0001 },
    };
    if status == 0 {
        *created = None;
        // STATUS_OBJECT_NAME_EXISTS: OBJ_OPENIF abriu um nome que já existia.
        return if create && found.is_some() { 0x4000_0000 } else { 0 };
    }
    status
}

/// NtQuerySymbolicLinkObject: copia o destino respeitando a capacidade.
pub fn query_link(handle: u64, output_buffer: u64, output_length: u64, from_user_mode: bool) -> u32 {
    let item = match resolve(handle, from_user_mode) {
        Ok(item) => item,
        Err(status) => return status,
    };
    if item.directory {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if from_user_mode && item.access & 1 == 0 {
        return STATUS_ACCESS_DENIED;
    }
    if from_user_mode && (!user_probe::probe_user_read(output_buffer, 16) || !user_probe::probe_user_write(output_buffer, 2) || (output_length != 0 && !user_probe::probe_user_write(output_length, 4))) {
        return STATUS_ACCESS_VIOLATION;
    }
    let maximum = guest::read16(output_buffer + 2) as u32;
    let buffer = guest::read64(output_buffer + 8);
    let units: Vec<u16> = namespace_objects::target(item.body).unwrap_or_default().encode_utf16().collect();
    let length = units.len() as u32 * 2;
    if output_length != 0 {
        guest::write32(output_length, length);
    }
    if maximum < length {
        return 0xC000_0023;
    }
    if length != 0 && (buffer == 0 || (from_user_mode && !user_probe::probe_user_write(buffer, length as u64))) {
        return STATUS_ACCESS_VIOLATION;
    }
    for (index, &unit) in units.iter().enumerate() {
        guest::write16(buffer + index as u64 * 2, unit);
    }
    guest::write16(output_buffer, length as u16);
    0
}

/// NtMakeTemporaryObject: o nome sai no último fechamento. `None` quando o
/// handle não é de namespace.
pub fn make_temporary(handle: u64) -> Option<u32> {
    match resolve(handle, false) {
        Ok(item) => {
            namespace_objects::set_permanent(item.body, false);
            Some(0)
        }
        Err(STATUS_OBJECT_TYPE_MISMATCH) => None,
        Err(status) => Some(status),
    }
}

/// NtQueryDirectoryObject: descritores nome/tipo, um terminador vazio e os
/// textos UTF-16 no mesmo buffer, a partir do índice do contexto.
#[allow(clippy::too_many_arguments)]
pub fn query_directory(handle: u64, output_buffer: u64, length: u32, single_entry: bool, restart_scan: bool, context: u64, output_length: u64) -> u32 {
    let item = match resolve(handle, false) {
        Ok(item) => item,
        Err(status) => return status,
    };
    if !item.directory {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if context == 0 {
        return STATUS_ACCESS_VIOLATION;
    }
    // Ordem de inserção: os ids da arena são alocados na inserção.
    let mut children: Vec<(NodeId, String, String)> = object_manager::node(item.node)
        .and_then(|node| node.children)
        .map(|children| children.values().filter_map(|&child| object_manager::node(child).map(|node| (child, node.name, node.type_name))).collect())
        .unwrap_or_default();
    children.sort_by_key(|(id, _, _)| *id);
    let start = if restart_scan { 0 } else { guest::read32(context) as usize };
    if start >= children.len() {
        if output_length != 0 {
            guest::write32(output_length, 0);
        }
        return 0x8000_001A;
    }
    let mut rows = Vec::new();
    let mut required = 32u32;
    for child in &children[start..] {
        let entry = 32 + (child.1.encode_utf16().count() + child.2.encode_utf16().count() + 2) as u32 * 2;
        if required + entry > length {
            if rows.is_empty() {
                if output_length != 0 {
                    guest::write32(output_length, required + entry);
                }
                return 0xC000_0023;
            }
            break;
        }
        rows.push(child);
        required += entry;
        if single_entry {
            break;
        }
    }
    let mut strings = output_buffer + (rows.len() as u64 + 1) * 32;
    for offset in (0..(rows.len() as u64 + 1) * 32).step_by(8) {
        guest::write64(output_buffer + offset, 0);
    }
    for (index, row) in rows.iter().enumerate() {
        for (offset, text) in [(0u64, &row.1), (16, &row.2)] {
            let unicode = output_buffer + index as u64 * 32 + offset;
            let units: Vec<u16> = text.encode_utf16().collect();
            let bytes = units.len() as u64 * 2;
            guest::write16(unicode, bytes as u16);
            guest::write16(unicode + 2, bytes as u16 + 2);
            guest::write64(unicode + 8, strings);
            for (position, &unit) in units.iter().enumerate() {
                guest::write16(strings + position as u64 * 2, unit);
            }
            guest::write16(strings + bytes, 0);
            strings += bytes + 2;
        }
    }
    guest::write32(context, (start + rows.len()) as u32);
    if output_length != 0 {
        guest::write32(output_length, required);
    }
    if !single_entry && start + rows.len() < children.len() { 0x105 } else { 0 }
}
