//! Handles de diretórios e links do namespace.
//!
//! NtOpen/NtCreateDirectoryObject, NtOpenSymbolicLinkObject,
//! NtQuerySymbolicLinkObject, NtQueryDirectoryObject e NtMakeTemporaryObject.
//! Os handles de usuário do processo corrente entram com a fase 7.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::namespace as namespace_objects;
use crate::ntos::ob::open_pointer;
use crate::ntos::ex::callback_security;
use crate::ntos::ex::callbacks as executive_callbacks;
use crate::ntos::ps::user_probe;
use crate::ntos::inc::types::{NtStruct, ObjectAttributes, ObjectDirectoryInformation, UnicodeString};
use crate::ntos::mm::guest_memory::{self as guest, GuestScalar};
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// Campo de uma estrutura do chamador (de modo usuário ou não): sonda e um
/// acesso da largura do campo, o `__try` do NT. Sem exigir o alinhamento da
/// estrutura inteira, como a captura original.
fn read_field<T: GuestScalar>(base: u64, offset: usize) -> Result<T, u32> {
    guest::try_read(base + offset as u64).map_err(|_| STATUS_ACCESS_VIOLATION)
}

fn write_field<T: GuestScalar>(base: u64, offset: usize, value: T) -> Result<(), u32> {
    guest::try_write(base + offset as u64, value).map_err(|_| STATUS_ACCESS_VIOLATION)
}

fn write_text(address: u64, bytes: &[u8]) -> Result<(), u32> {
    guest::try_write_bytes(address, bytes).map_err(|_| STATUS_ACCESS_VIOLATION)
}

fn utf16_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

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
    /// OBJECT_ATTRIBUTES.SecurityDescriptor capturado uma única vez.
    security_descriptor: u64,
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
    if !readable(attributes, ObjectAttributes::SIZE, from_user_mode) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if read_field::<u32>(attributes, offset_of!(ObjectAttributes, length))? != ObjectAttributes::SIZE as u32 {
        return Err(0xC000_000D);
    }
    let flags = read_field::<u32>(attributes, offset_of!(ObjectAttributes, attributes))?;
    let root = read_field::<u64>(attributes, offset_of!(ObjectAttributes, root_directory))?;
    let unicode = read_field::<u64>(attributes, offset_of!(ObjectAttributes, object_name))?;
    let security_descriptor = read_field::<u64>(attributes, offset_of!(ObjectAttributes, security_descriptor))?;
    if from_user_mode && flags & 0x200 != 0 {
        return Err(STATUS_INVALID_HANDLE);
    }
    if unicode == 0 {
        return Err(0xC000_0033);
    }
    if !readable(unicode, UnicodeString::SIZE, from_user_mode) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let length = read_field::<u16>(unicode, offset_of!(UnicodeString, length))?;
    let buffer = read_field::<u64>(unicode, offset_of!(UnicodeString, buffer))?;
    if length & 1 != 0 || length > read_field::<u16>(unicode, offset_of!(UnicodeString, maximum_length))? {
        return Err(0xC000_0033);
    }
    if length != 0 && (buffer == 0 || !readable(buffer, length as u64, from_user_mode)) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let bytes = if length != 0 { guest::try_read_bytes(buffer, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)? } else { Vec::new() };
    let units: Vec<u16> = bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
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
    Ok(Captured { name, start, flags, case_insensitive: flags & 0x40 != 0, security_descriptor })
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
        let descriptor = input.security_descriptor;
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
    match query_link_into(&item, output_buffer, output_length, from_user_mode) {
        Ok(status) | Err(status) => status,
    }
}

/// LinkTarget (UNICODE_STRING do chamador) e ReturnedLength, sondados.
fn query_link_into(item: &Opened, output_buffer: u64, output_length: u64, from_user_mode: bool) -> Result<u32, u32> {
    let maximum = read_field::<u16>(output_buffer, offset_of!(UnicodeString, maximum_length))? as u32;
    let buffer = read_field::<u64>(output_buffer, offset_of!(UnicodeString, buffer))?;
    let units: Vec<u16> = namespace_objects::target(item.body).unwrap_or_default().encode_utf16().collect();
    let length = units.len() as u32 * 2;
    if output_length != 0 {
        write_field::<u32>(output_length, 0, length)?;
    }
    if maximum < length {
        return Ok(0xC000_0023);
    }
    if length != 0 && (buffer == 0 || (from_user_mode && !user_probe::probe_user_write(buffer, length as u64))) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    write_text(buffer, &utf16_bytes(&units))?;
    write_field::<u16>(output_buffer, offset_of!(UnicodeString, length), length as u16)?;
    Ok(0)
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

/// ZwMakeTemporaryObject: os objetos de callback do Executive primeiro,
/// depois os nós do namespace; outro handle = STATUS_INVALID_HANDLE.
pub fn make_temporary_object(handle: u64) -> Result<u32, KernelError> {
    if let Some(status) = executive_callbacks::make_temporary(handle)? {
        return Ok(status);
    }
    Ok(make_temporary(handle).unwrap_or(STATUS_INVALID_HANDLE))
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
    match query_directory_into(&item, output_buffer, length, single_entry, restart_scan, context, output_length) {
        Ok(status) | Err(status) => status,
    }
}

/// Descritores OBJECT_DIRECTORY_INFORMATION, terminador e textos no buffer
/// do chamador; Context e ReturnLength sondados.
#[allow(clippy::too_many_arguments)]
fn query_directory_into(item: &Opened, output_buffer: u64, length: u32, single_entry: bool, restart_scan: bool, context: u64, output_length: u64) -> Result<u32, u32> {
    let entry_size = ObjectDirectoryInformation::SIZE;
    // Ordem de inserção: os ids da arena são alocados na inserção.
    let mut children: Vec<(NodeId, String, String)> = object_manager::node(item.node)
        .and_then(|node| node.children)
        .map(|children| children.values().filter_map(|&child| object_manager::node(child).map(|node| (child, node.name, node.type_name))).collect())
        .unwrap_or_default();
    children.sort_by_key(|(id, _, _)| *id);
    let start = if restart_scan { 0 } else { read_field::<u32>(context, 0)? as usize };
    if start >= children.len() {
        if output_length != 0 {
            write_field::<u32>(output_length, 0, 0)?;
        }
        return Ok(0x8000_001A);
    }
    let mut rows = Vec::new();
    let mut required = entry_size as u32;
    for child in &children[start..] {
        let entry = entry_size as u32 + (child.1.encode_utf16().count() + child.2.encode_utf16().count() + 2) as u32 * 2;
        if required + entry > length {
            if rows.is_empty() {
                if output_length != 0 {
                    write_field::<u32>(output_length, 0, required + entry)?;
                }
                return Ok(0xC000_0023);
            }
            break;
        }
        rows.push(child);
        required += entry;
        if single_entry {
            break;
        }
    }
    let mut strings = output_buffer + (rows.len() as u64 + 1) * entry_size;
    // Descritores e terminador zerados numa cópia.
    write_text(output_buffer, &vec![0u8; ((rows.len() as u64 + 1) * entry_size) as usize])?;
    for (index, row) in rows.iter().enumerate() {
        let descriptor = output_buffer + index as u64 * entry_size;
        for (offset, text) in [(offset_of!(ObjectDirectoryInformation, name), &row.1), (offset_of!(ObjectDirectoryInformation, type_name), &row.2)] {
            let unicode = descriptor + offset as u64;
            let mut bytes = utf16_bytes(&text.encode_utf16().collect::<Vec<u16>>());
            let text_length = bytes.len() as u64;
            write_field::<u16>(unicode, offset_of!(UnicodeString, length), text_length as u16)?;
            write_field::<u16>(unicode, offset_of!(UnicodeString, maximum_length), text_length as u16 + 2)?;
            write_field::<u64>(unicode, offset_of!(UnicodeString, buffer), strings)?;
            bytes.extend_from_slice(&[0, 0]);
            write_text(strings, &bytes)?;
            strings += text_length + 2;
        }
    }
    write_field::<u32>(context, 0, (start + rows.len()) as u32)?;
    if output_length != 0 {
        write_field::<u32>(output_length, 0, required)?;
    }
    Ok(if !single_entry && start + rows.len() < children.len() { 0x105 } else { 0 })
}
