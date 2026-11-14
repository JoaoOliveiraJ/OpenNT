//! NtOpenSection.
//!
//! Abre a SECTION existente conservando a identidade nativa e o backing. A
//! ordem de validação segue o NtOpenSection/Ob do NT de referência; as
//! entradas de `\KnownDlls` são provisionadas do volume na primeira busca,
//! exceto no boot do processo inicial real (`--initial-process=smss`), em que
//! o smss cria o diretório e as seções.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::ex::callback_security;
use crate::ntos::ke::irql;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::namespace as namespace_objects;
use crate::ntos::ob::{object_access, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::ps::user::state;
use crate::ntos::se::object_security;
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;
use core::mem::offset_of;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::section::create::{caller_read, caller_units};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ObjectAttributes, SecurityDescriptor, SecurityQualityOfService, UnicodeString};

fn readable(pointer: u64, length: u64) -> bool {
    state::probe_user_read(pointer, length)
}

/// OBJECT_ATTRIBUTES capturados para a abertura.
#[derive(Clone, Debug)]
pub struct Captured {
    pub flags: u32,
    pub root: u64,
    pub name: String,
}

/// Captura na ordem do Ob: alinhamentos, QoS, descritor (validado, mas sem
/// substituir a segurança do objeto existente) e o nome por Length bytes.
pub fn capture(pointer: u64, mode: u8) -> Result<Captured, u32> {
    if pointer == 0 {
        return Err(0xC000_000D);
    }
    if mode != 0 && pointer & 7 != 0 {
        return Err(0x8000_0002);
    }
    if mode != 0 && !readable(pointer, 48) {
        return Err(0xC000_0005);
    }
    if caller_read::<u32>(pointer + offset_of!(ObjectAttributes, length) as u64, mode)? != ObjectAttributes::SIZE as u32 {
        return Err(0xC000_000D);
    }
    let mut flags: u32 = caller_read(pointer + offset_of!(ObjectAttributes, attributes) as u64, mode)?;
    if mode != 0 {
        // O Ob limpa OBJ_KERNEL_HANDLE para chamadores de usuário.
        flags &= !0x200;
    }
    if flags & !0x1_1FF2 != 0 {
        return Err(0xC000_000D);
    }
    let root: u64 = caller_read(pointer + offset_of!(ObjectAttributes, root_directory) as u64, mode)?;
    let unicode: u64 = caller_read(pointer + offset_of!(ObjectAttributes, object_name) as u64, mode)?;
    let descriptor: u64 = caller_read(pointer + offset_of!(ObjectAttributes, security_descriptor) as u64, mode)?;
    let qos: u64 = caller_read(pointer + offset_of!(ObjectAttributes, security_quality_of_service) as u64, mode)?;
    if qos != 0 {
        if mode != 0 && qos & 3 != 0 {
            return Err(0x8000_0002);
        }
        if mode != 0 && !readable(qos, 12) {
            return Err(0xC000_0005);
        }
    }
    if descriptor != 0 {
        if mode != 0 && descriptor & 3 != 0 {
            return Err(0x8000_0002);
        }
        if mode != 0 && !crate::ntos::mm::section::create::descriptor_probe(descriptor) {
            return Err(0xC000_0005);
        }
        if caller_read::<u8>(descriptor + offset_of!(SecurityDescriptor, revision) as u64, mode)? != 1 {
            return Err(0xC000_0058);
        }
        callback_security::capture(descriptor)?;
    }
    if qos != 0 {
        if caller_read::<u8>(qos + offset_of!(SecurityQualityOfService, context_tracking_mode) as u64, mode)? > 1 {
            return Err(0xC000_000D);
        }
        if caller_read::<u32>(qos + offset_of!(SecurityQualityOfService, impersonation_level) as u64, mode)? > 3 {
            return Err(0xC000_00A5);
        }
    }
    if unicode == 0 {
        return Err(if root != 0 { 0xC000_0033 } else { 0xC000_003B });
    }
    if mode != 0 && !readable(unicode, 16) {
        return Err(0xC000_0005);
    }
    let length = caller_read::<u16>(unicode + offset_of!(UnicodeString, length) as u64, mode)? as u64;
    let buffer: u64 = caller_read(unicode + offset_of!(UnicodeString, buffer) as u64, mode)?;
    // O Ob captura Length bytes; MaximumLength não é entrada de validação.
    if mode != 0 && length != 0 && buffer & 1 != 0 {
        return Err(0x8000_0002);
    }
    if mode != 0 && length != 0 && buffer.saturating_add(length) > crate::ntos::mm::memory_map::USER_PROBE_ADDRESS {
        return Err(0xC000_0005);
    }
    if length & 1 != 0 || length == 0xFFFE {
        return Err(0xC000_0033);
    }
    if mode != 0 && length != 0 && !readable(buffer, length) {
        return Err(0xC000_0005);
    }
    let units: Vec<u16> = caller_units(buffer, length, mode)?;
    Ok(Captured { flags, root, name: String::from_utf16_lossy(&units) })
}

/// Diretório raiz por handle de kernel, do Object Manager ou do processo.
fn root_directory(handle: u64, mode: u8) -> Result<NodeId, u32> {
    let kernel = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if (kernel && mode != 0) || (!kernel && handle > 0x7FFF_FFFF) {
        return Err(0xC000_0008);
    }
    let current = process::get_current_process();
    if !kernel && current != process::get_system_process() {
        let entry = if state::is_user_process(current) { state::get_user_handle(handle) } else { None };
        let Some(entry) = entry else { return Err(0xC000_0008) };
        if entry.kind() != "directory" {
            return Err(0xC000_0024);
        }
        return entry.object.namespace_node().ok_or(0xC000_0008);
    }
    let identifier = (handle & 0x7FFF_FFFF) as u32;
    let Some(record) = object_manager::handle_record(identifier) else { return Err(0xC000_0008) };
    if kernel && record.options.open_attributes.unwrap_or(0) & 0x200 == 0 {
        return Err(0xC000_0008);
    }
    if record.options.owner_process.is_some_and(|owner| owner != 0 && owner != current) && !kernel {
        return Err(0xC000_0008);
    }
    match object_manager::node(record.node) {
        Some(node) if node.type_name == "Directory" => Ok(record.node),
        _ => Err(0xC000_0024),
    }
}

/// Resultado da busca: nó encontrado ou status com o pai e a folha da falha.
pub struct Found {
    pub node: Option<NodeId>,
    pub status: u32,
    pub parent: Option<NodeId>,
    pub leaf: String,
}

fn failure(status: u32) -> Found {
    Found { node: None, status, parent: None, leaf: String::new() }
}

fn symlink_target(node: &object_manager::Node) -> String {
    if node.native_namespace != 0 {
        namespace_objects::target(node.native_namespace).unwrap_or_default()
    } else {
        node.data.as_ref().and_then(|data| data.symlink_target.clone()).unwrap_or_default()
    }
}

/// Percorre o namespace com a checagem de travessia (dispensada por
/// SeChangeNotify), links simbólicos (OBJ_OPENLINK e OBJ_DONT_REPARSE) e
/// a profundidade máxima de 32.
pub fn lookup(info: &Captured, mode: u8) -> Found {
    let start = if info.root != 0 {
        if info.name.starts_with('\\') {
            return failure(0xC000_003B);
        }
        match root_directory(info.root, mode) {
            Ok(node) => node,
            Err(status) => return failure(status),
        }
    } else {
        if !info.name.starts_with('\\') {
            return failure(0xC000_003B);
        }
        object_manager::ROOT
    };
    let subject = object_access::subject();
    let enforce = mode != 0 || info.flags & 0x400 != 0;
    let bypass = subject.and_then(|token| tokens::with(token, |token| token.privileges.iter().any(|privilege| privilege.id == 23 && privilege.attributes & 2 != 0))).unwrap_or(false);
    let insensitive = info.flags & 0x40 != 0;
    fn walk(info: &Captured, node: NodeId, name: &str, depth: u32, enforce: bool, bypass: bool, subject: Option<u64>, insensitive: bool) -> Found {
        if depth > 32 {
            return failure(0xC000_003A);
        }
        let parts: Vec<&str> = name.split('\\').collect();
        let mut node = node;
        for (index, part) in parts.iter().enumerate() {
            let Some(current) = object_manager::node(node) else { return failure(0xC000_0024) };
            if current.type_name != "Directory" || current.mount.is_some() {
                return failure(0xC000_0024);
            }
            if part.is_empty() {
                return failure(0xC000_0033);
            }
            if enforce && !bypass {
                let Some(subject) = subject else { return failure(0xC000_007C) };
                if let Err(status) = object_security::access(&object_security::directory(node), subject, 2) {
                    return failure(status);
                }
            }
            let next = current.children.as_ref().and_then(|children| {
                children.values().copied().find(|&child| object_manager::node(child).is_some_and(|child| if insensitive { child.name.to_lowercase() == part.to_lowercase() } else { child.name == *part }))
            });
            let Some(next) = next else {
                return Found { node: None, status: if index == parts.len() - 1 { 0xC000_0034 } else { 0xC000_003A }, parent: Some(node), leaf: String::from(*part) };
            };
            let Some(next_node) = object_manager::node(next) else { return failure(0xC000_003A) };
            if next_node.type_name == "SymbolicLink" {
                if info.flags & 0x1000 != 0 {
                    return failure(0xC000_050B);
                }
                if info.flags & 0x100 != 0 {
                    return Found { node: Some(next), status: 0, parent: None, leaf: String::new() };
                }
                let mut target = symlink_target(&next_node);
                if index + 1 < parts.len() {
                    target.push('\\');
                    target.push_str(&parts[index + 1..].join("\\"));
                }
                return if let Some(rest) = target.strip_prefix('\\') {
                    walk(info, object_manager::ROOT, rest, depth + 1, enforce, bypass, subject, insensitive)
                } else {
                    walk(info, node, &target, depth + 1, enforce, bypass, subject, insensitive)
                };
            }
            node = next;
        }
        Found { node: Some(node), status: 0, parent: None, leaf: String::new() }
    }
    let name = if info.root != 0 { info.name.as_str() } else { &info.name[1..] };
    if name.is_empty() {
        return Found { node: Some(start), status: 0, parent: None, leaf: String::new() };
    }
    walk(info, start, name, 0, enforce, bypass, subject, insensitive)
}

/// NtOpenSection: grava o temporário do Ob na saída em sucesso e em falha.
pub fn open(output: u64, desired: u32, attributes: u64, mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("ZwOpenSection requires PASSIVE_LEVEL"));
    }
    if mode != 0 && !state::probe_user_write(output, 8) {
        return Ok(0xC000_0005);
    }
    let mut handle = 0u64;
    let mut created: Option<alloc::sync::Arc<crate::ntos::ps::user::sections::Section>> = None;
    let result = (|| -> Result<u32, KernelError> {
        let info = match capture(attributes, mode) {
            Ok(info) => info,
            Err(status) => return Ok(status),
        };
        let mut found = lookup(&info, mode);
        // Política de KnownDlls: provisiona o PE real do volume na primeira
        // busca e segue pelas mesmas permissões e caminho de handle do Ob.
        if !crate::ntos::init::boot_config::SMSS_BOOT && found.status == 0xC000_0034 && found.parent.and_then(object_manager::path_of).is_some_and(|path| path.to_lowercase() == "\\knowndlls") {
            if let Some(file) = crate::drivers::fs::volume_files::lookup_volume_file(&found.leaf) {
                let image: alloc::sync::Arc<dyn crate::ntos::ps::user::sections::SectionFile> = file;
                let section = match crate::ntos::ps::user::sections::create_image(image, Some(alloc::format!("\\KnownDlls\\{}", found.leaf)), 0x40, false)? {
                    Ok(section) => section,
                    Err(status) => return Ok(status),
                };
                let node = section.name().and_then(|name| object_manager::lookup(&name));
                created = Some(section);
                found = Found { node, status: 0, parent: None, leaf: String::new() };
            }
        }
        if found.status != 0 {
            return Ok(found.status);
        }
        if info.flags & 0x100 != 0 {
            // A Section recusa OBJ_OPENLINK.
            return Ok(0xC000_000D);
        }
        let Some(node) = found.node.and_then(object_manager::node).filter(|node| node.type_name == "Section") else { return Ok(0xC000_0024) };
        if (mode != 0 || info.flags & 0x400 != 0) && desired == 0 {
            return Ok(0xC000_0022);
        }
        let scratch = guest::alloc_bytes(8);
        if scratch == 0 {
            return Ok(0xC000_009A);
        }
        let pointer = node.data.as_ref().map_or(0, |data| data.native_pointer);
        let status = open_pointer::open(pointer, info.flags & !0x1_0090, 0, desired, object_types::section_type().pointer, mode, scratch);
        // SAFETY: a célula de 8 bytes alocada acima.
        let opened = unsafe { Field::<u64>::at(scratch) }.get();
        guest::free_bytes(scratch);
        let status = status?;
        if status != 0 {
            return Ok(status);
        }
        handle = opened;
        Ok(0)
    })();
    let result = match result {
        Err(error) if error.status != 0 => Ok(error.status),
        other => other,
    };
    let written = guest::try_write64(output, handle);
    if written.is_err() && handle != 0 {
        open_pointer::close(handle);
    }
    if let Some(section) = created {
        crate::ntos::ob::objects::section::collect(section.pointer())?;
    }
    written?;
    result
}
