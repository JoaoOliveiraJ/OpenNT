//! Argumentos próprios de uma conexão.
//!
//! Nenhuma destas operações publica handles ou fabrica respostas do servidor.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::alpc::transport::{self, Listener};
use crate::ntos::mm::section::create as create_section;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ob::{object_access, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::se::descriptor;
use crate::ntos::se::token::tokens;
use crate::ntos::mm::guest_memory as guest;

/// UNICODE_STRING.Length é o comprimento consumido; MaximumLength não
/// limita esta captura NT. O nome do endpoint é sensível a caixa.
pub fn unicode(pointer: u64, mode: u8, allow_empty: bool) -> Result<String, u32> {
    if !message_buffer::accessible(pointer, 16, mode, false) {
        return Err(0xC000_0005);
    }
    let length = guest::read16(pointer) as u64;
    let buffer = guest::read64(pointer + 8);
    if length & 1 != 0 || (!allow_empty && length == 0) {
        return Err(0xC000_0033);
    }
    if length != 0 && !message_buffer::accessible(buffer, length, mode, false) {
        return Err(0xC000_0005);
    }
    let units: Vec<u16> = (0..length).step_by(2).map(|offset| guest::read16(buffer + offset)).collect();
    let name: String = units.iter().map(|&unit| char::from_u32(unit as u32).unwrap_or('\u{FFFD}')).collect();
    if name.contains('\0') || name.ends_with('\\') || name.contains("\\\\") {
        return Err(0xC000_0033);
    }
    Ok(name)
}

/// SeCaptureSid copia o SID antes da busca do endpoint; o SID exigido é
/// comparado com o token primário real do servidor.
pub fn identifier(pointer: u64, mode: u8) -> Result<Option<Vec<u8>>, u32> {
    if pointer == 0 {
        return Ok(None);
    }
    if !message_buffer::accessible(pointer, 8, mode, false) {
        return Err(0xC000_0005);
    }
    let count = guest::read8(pointer + 1) as u64;
    if guest::read8(pointer) != 1 || count > 15 {
        return Err(0xC000_0078);
    }
    let length = 8 + 4 * count;
    if !message_buffer::accessible(pointer, length, mode, false) {
        return Err(0xC000_0005);
    }
    Ok(Some((0..length).map(|offset| guest::read8(pointer + offset)).collect()))
}

/// Endpoint resolvido: nó, registro do servidor e caminho.
#[derive(Clone)]
pub struct Target {
    pub node: NodeId,
    pub server: Arc<Listener>,
    pub path: String,
}

pub fn listener(name_pointer: u64, required: Option<&[u8]>, mode: u8) -> Result<Target, u32> {
    let name = unicode(name_pointer, mode, false)?;
    if !name.starts_with('\\') {
        return Err(0xC000_003B);
    }
    let (node, _) = object_manager::resolve_from(&name, 0, false, false, object_manager::ROOT);
    resolve_listener(node, &name, required, mode, false)
}

/// As duas variantes compartilham tipo, proprietário vivo e direito CONNECT.
pub fn resolve_listener(node: Option<NodeId>, path: &str, required: Option<&[u8]>, mode: u8, force_access_check: bool) -> Result<Target, u32> {
    let Some(node) = node else { return Err(0xC000_0034) };
    if object_manager::node(node).is_none_or(|record| record.type_name != "AlpcPort") {
        return Err(0xC000_0024);
    }
    let Some(server) = transport::listener_of(node) else { return Err(0xC000_0042) };
    let alive = process::with_record(server.process, |record| !record.exiting && !record.terminated).unwrap_or(false);
    if !alive {
        return Err(0xC000_0037);
    }
    let object_type = object_types::user_type("alpc").ok_or(0xC000_0024u32)?;
    object_access::check(&server.security, object_access::subject(), 1, &object_type, mode == 0 && !force_access_check)?;
    if let Some(required) = required {
        let token = process::get_primary_token(server.process).and_then(tokens::get);
        let matches = token.is_some_and(|token| token.app_container.is_none() && token.user.as_slice() == required);
        if !matches {
            return Err(0xC000_02A0);
        }
    }
    Ok(Target { node, server, path: String::from(path) })
}

/// OBJECT_ATTRIBUTES capturado para a nova porta cliente.
#[derive(Clone, Default)]
pub struct Creation {
    pub flags: u32,
    pub pointer: u64,
    pub name: Option<String>,
    pub parent: Option<NodeId>,
    pub leaf: String,
    pub insensitive: bool,
}

/// O OBJECT_ATTRIBUTES pertence à nova porta cliente. Nome e política são
/// capturados antes de inserir o handle; exclusividade não altera o listener.
pub fn object_attributes(pointer: u64, mode: u8) -> Result<Creation, u32> {
    if pointer == 0 {
        return Ok(Creation::default());
    }
    if mode != 0 && pointer & 7 != 0 {
        return Err(0x8000_0002);
    }
    if !message_buffer::accessible(pointer, 48, mode, false) {
        return Err(0xC000_0005);
    }
    if guest::read32(pointer) != 48 {
        return Err(0xC000_000D);
    }
    let mut flags = guest::read32(pointer + 24);
    if flags & !0x1_1F72 != 0 {
        return Err(0xC000_000D);
    }
    if mode != 0 {
        flags &= !0x200;
    }
    if mode != 0 && flags & 0x10 != 0 {
        let privileged = object_access::subject().and_then(|token| tokens::with(token, |token| token.privileges.iter().any(|privilege| privilege.id == 16 && privilege.attributes & 2 != 0))).unwrap_or(false);
        if !privileged {
            return Err(0xC000_0061);
        }
    }
    let security = guest::read64(pointer + 32);
    if security != 0 {
        if mode != 0 && security & 3 != 0 {
            return Err(0x8000_0002);
        }
        if mode != 0 && !create_section::descriptor_probe(security) {
            return Err(0xC000_0005);
        }
        if guest::read8(security) != 1 {
            return Err(0xC000_0058);
        }
        if !descriptor::valid(security) {
            return Err(0xC000_0079);
        }
    }
    let root = guest::read64(pointer + 8);
    let name_pointer = guest::read64(pointer + 16);
    let unnamed = Creation { flags, pointer, ..Creation::default() };
    if name_pointer == 0 {
        return if root != 0 { Err(0xC000_0033) } else { Ok(unnamed) };
    }
    if mode != 0 && name_pointer & 7 != 0 {
        return Err(0x8000_0002);
    }
    let mut name = unicode(name_pointer, mode, true)?;
    if name.is_empty() {
        return Ok(unnamed);
    }
    if root != 0 {
        if name.starts_with('\\') {
            return Err(0xC000_003B);
        }
        let native = match open_pointer::resolve(root, mode != 0) {
            Some(Err(status)) => return Err(status),
            Some(Ok(resolved)) => resolved.data.native_open.and_then(|open| open.node),
            None => None,
        };
        let directory = native.or_else(|| if root <= 0x7FFF_FFFF { namespace_handles::resolve(root, mode != 0).ok().map(|opened| opened.node) } else { None });
        let Some(directory) = directory else { return Err(0xC000_0008) };
        if object_manager::node(directory).is_none_or(|record| record.type_name != "Directory") {
            return Err(0xC000_0024);
        }
        let Some(parent_path) = object_manager::path_of(directory) else { return Err(0xC000_003A) };
        name = alloc::format!("{}\\{}", if parent_path == "\\" { "" } else { parent_path.as_str() }, name);
    } else if !name.starts_with('\\') {
        return Err(0xC000_003B);
    }
    let insensitive = flags & 0x40 != 0;
    let separator = name.rfind('\\').unwrap_or(0);
    let parent_path = if separator == 0 { "\\" } else { &name[..separator] };
    let (parent, _) = object_manager::resolve_from(parent_path, 0, insensitive, false, object_manager::ROOT);
    let Some(parent) = parent else { return Err(0xC000_003A) };
    if object_manager::node(parent).is_none_or(|record| record.type_name != "Directory" || record.mount.is_some()) {
        return Err(0xC000_0024);
    }
    if object_manager::resolve_from(&name, 0, insensitive, false, object_manager::ROOT).0.is_some() {
        return Err(0xC000_0035);
    }
    let leaf = String::from(&name[separator + 1..]);
    Ok(Creation { flags, pointer, name: Some(name), parent: Some(parent), leaf, insensitive })
}

/// ConnectionMessage capturado: carga e tipo LPC_CONNECTION_REQUEST.
pub struct ConnectionMessage {
    pub data: Vec<u8>,
    pub message_type: u16,
}

/// Em UserMode, Type e DataInfoOffset são ignorados, mas o comprimento
/// deve ser coerente; a carga é copiada antes de chegar ao servidor.
pub fn message(pointer: u64, maximum: u32, mode: u8) -> Result<ConnectionMessage, u32> {
    if pointer == 0 {
        return Ok(ConnectionMessage { data: Vec::new(), message_type: 0x200A });
    }
    let header = message_buffer::probe_header(pointer, mode);
    if header != 0 {
        return Err(header);
    }
    if !message_buffer::accessible(pointer, 40, mode, false) {
        return Err(0xC000_0005);
    }
    let data_length = guest::read16(pointer) as u32;
    let total_length = guest::read16(pointer + 2) as u32;
    if data_length + 40 != total_length {
        return Err(0xC000_000D);
    }
    if total_length > maximum {
        return Err(0xC000_002F);
    }
    if !message_buffer::accessible(pointer, total_length as u64, mode, false) {
        return Err(0xC000_0005);
    }
    let data = (0..data_length as u64).map(|offset| guest::read8(pointer + 40 + offset)).collect();
    Ok(ConnectionMessage { data, message_type: 0x200A | if mode == 0 { guest::read16(pointer + 4) & 0x8000 } else { 0 } })
}
