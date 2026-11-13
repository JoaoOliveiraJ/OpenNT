//! Criação de portas de conclusão.
//!
//! A criação concede a máscara válida pedida; OPENIF verifica a política já
//! pertencente ao objeto sem mudar concorrência, segurança ou pacotes. A
//! publicação usa um temporário para preservar a saída em qualquer falha.

use alloc::string::String;
use alloc::sync::Arc;

use crate::ntos::ex::callback_security;
use crate::ntos::ke::smp;
use crate::ntos::mm::section::create as create_section;
use crate::ntos::ob::objects::completion::{self as completion_objects, Port};
use crate::ntos::ob::object_manager::{self, NodeId, ROOT};
use crate::ntos::ob::objects::{dispatcher as dispatcher_objects, namespace as namespace_objects};
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ob::{object_access, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::ps::user::state;
use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{NtStruct, ObjectAttributes, SecurityDescriptor, SecurityQualityOfService, UnicodeString};
use crate::rtl::KernelError as ProbeError;

const ACCESS_VIOLATION: u32 = 0xC000_0005;
const INVALID_PARAMETER: u32 = 0xC000_000D;
const MISALIGNMENT: u32 = 0x8000_0002;
const ACCESS_DENIED: u32 = 0xC000_0022;

/// Status NT de uma sonda que falhou (ACCESS_VIOLATION ou o da sonda).
fn probe_status(error: ProbeError) -> u32 {
    if error.status != 0 { error.status } else { ACCESS_VIOLATION }
}

/// Leitura sondada de um campo de estrutura do chamador (modo usuário ou
/// kernel): o `__try { ... }` da captura do NT.
fn probe<T: guest::GuestScalar + Copy>(field: &Field<T>) -> Result<T, u32> {
    field.probe_get().map_err(probe_status)
}

struct Captured {
    flags: u32,
    policy: SecurityPolicy,
    name: String,
    parent: Option<NodeId>,
    leaf: String,
    node: Option<NodeId>,
}

/// OBJECT_ATTRIBUTES alinhados a 8 (a saída aceita qualquer byte); OBJ_PERMANENT
/// e OBJ_OPENLINK recusados; QoS e descritor validados; nome contado.
fn capture_attributes(attributes: u64, mode: u8) -> Result<Captured, u32> {
    let (mut flags, mut root, mut name_pointer, mut security, mut quality) = (0u32, 0u64, 0u64, 0u64, 0u64);
    if attributes != 0 {
        if mode != 0 && attributes & 7 != 0 {
            return Err(MISALIGNMENT);
        }
        if mode != 0 && !state::probe_user_read(attributes, 48) {
            return Err(ACCESS_VIOLATION);
        }
        let object_attributes = ObjectAttributes::try_at(attributes).map_err(probe_status)?;
        if probe(&object_attributes.length)? != ObjectAttributes::SIZE as u32 {
            return Err(INVALID_PARAMETER);
        }
        flags = probe(&object_attributes.attributes)?;
        if flags & !0x1EE2 != 0 {
            return Err(INVALID_PARAMETER);
        }
        if mode != 0 {
            flags &= !0x200;
        }
        root = probe(&object_attributes.root_directory)?;
        name_pointer = probe(&object_attributes.object_name)?;
        security = probe(&object_attributes.security_descriptor)?;
        quality = probe(&object_attributes.security_quality_of_service)?;
    }
    if quality != 0 {
        if mode != 0 && quality & 3 != 0 {
            return Err(MISALIGNMENT);
        }
        if mode != 0 && !state::probe_user_read(quality, 12) {
            return Err(ACCESS_VIOLATION);
        }
        let service = SecurityQualityOfService::try_at(quality).map_err(probe_status)?;
        if probe(&service.context_tracking_mode)? > 1 {
            return Err(INVALID_PARAMETER);
        }
        if probe(&service.impersonation_level)?.0 as u32 > 3 {
            return Err(0xC000_00A5);
        }
    }
    if security != 0 {
        if mode != 0 && security & 3 != 0 {
            return Err(MISALIGNMENT);
        }
        if mode != 0 && !create_section::descriptor_probe(security) {
            return Err(ACCESS_VIOLATION);
        }
        // SECURITY_DESCRIPTOR.Revision (o primeiro byte, comum às formas
        // absoluta e relativa).
        if guest::try_read::<u8>(security + core::mem::offset_of!(SecurityDescriptor, revision) as u64).map_err(probe_status)? != 1 {
            return Err(0xC000_0058);
        }
    }
    let policy = if security != 0 { callback_security::capture(security)? } else { object_access::capture(object_access::subject()) };
    let mut captured = Captured { flags, policy, name: String::new(), parent: None, leaf: String::new(), node: None };
    if name_pointer == 0 {
        return if root != 0 { Err(0xC000_0033) } else { Ok(captured) };
    }
    if mode != 0 && !state::probe_user_read(name_pointer, 16) {
        return Err(ACCESS_VIOLATION);
    }
    let name = UnicodeString::try_at(name_pointer).map_err(probe_status)?;
    let length = probe(&name.length)? as u64;
    let buffer = probe(&name.buffer)?;
    if length & 1 != 0 {
        return Err(0xC000_0033);
    }
    if length == 0 {
        return Ok(captured);
    }
    if mode != 0 && buffer & 1 != 0 {
        return Err(MISALIGNMENT);
    }
    if buffer == 0 || (mode != 0 && !state::probe_user_read(buffer, length)) {
        return Err(ACCESS_VIOLATION);
    }
    let bytes = guest::try_read_bytes(buffer, length as usize).map_err(probe_status)?;
    let units: alloc::vec::Vec<u16> = bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
    captured.name = String::from_utf16_lossy(&units);
    let mut start = ROOT;
    if root != 0 {
        if captured.name.starts_with('\\') {
            return Err(0xC000_003B);
        }
        let directory = namespace_handles::resolve(root, mode != 0)?;
        if !directory.directory {
            return Err(0xC000_0024);
        }
        start = directory.node;
    } else if !captured.name.starts_with('\\') {
        return Err(0xC000_003B);
    }
    let (node, rest) = object_manager::resolve_from(&captured.name, 0, true, false, start);
    if rest.is_some_and(|rest| !rest.is_empty()) {
        return Err(0xC000_003A);
    }
    if node.is_some() {
        captured.node = node;
        return Ok(captured);
    }
    let separator = captured.name.rfind('\\');
    let parent_name = separator.map_or(String::new(), |index| String::from(&captured.name[..index]));
    let leaf = String::from(&captured.name[separator.map_or(0, |index| index + 1)..]);
    if leaf.is_empty() || parent_name.ends_with('\\') || parent_name.contains("\\\\") {
        return Err(0xC000_003A);
    }
    let (parent, parent_rest) = object_manager::resolve_from(if parent_name.is_empty() { "\\" } else { &parent_name }, 0, true, false, start);
    let Some(parent) = parent.filter(|&parent| parent_rest.is_none() && object_manager::node(parent).is_some_and(|node| node.type_name == "Directory")) else { return Err(0xC000_003A) };
    let Some(path) = object_manager::path_of(parent) else { return Err(0xC000_003A) };
    captured.name = alloc::format!("{}\\{}", if path == "\\" { "" } else { &path }, leaf);
    captured.parent = Some(parent);
    captured.leaf = leaf;
    Ok(captured)
}

/// NtCreateIoCompletion/ZwCreateIoCompletion.
pub fn create(output: u64, desired: u32, attributes: u64, concurrency: u32, mode: u8) -> Result<u32, KernelError> {
    if mode != 0 && !state::probe_user_write(output, 8) {
        return Ok(ACCESS_VIOLATION);
    }
    let input = match capture_attributes(attributes, mode) {
        Ok(input) => input,
        Err(status) => return Ok(status),
    };
    let object_type = object_types::user_type("completion").ok_or_else(|| KernelError::new("IoCompletion type missing"))?;
    let mut desired = desired;
    let mut created: Option<Arc<Port>> = None;
    let port: Arc<Port> = match input.node {
        Some(node) => {
            let Some(existing) = object_manager::node(node) else { return Ok(0xC000_0024) };
            if existing.type_name != "IoCompletion" {
                return Ok(0xC000_0024);
            }
            if input.flags & 0x80 == 0 {
                return Ok(0xC000_0035);
            }
            let Some(port) = existing.data.and_then(|data| completion_objects::port_of(data.native_pointer)) else { return Ok(0xC000_0024) };
            let exclusive = port.exclusive_process.load(core::sync::atomic::Ordering::Acquire);
            if (exclusive != 0 && (input.flags & 0x20 == 0 || exclusive != process::get_current_process())) || (input.flags & 0x20 != 0 && exclusive == 0) {
                return Ok(ACCESS_DENIED);
            }
            if (mode != 0 || input.flags & 0x400 != 0) && desired == 0 {
                return Ok(ACCESS_DENIED);
            }
            port
        }
        None => {
            if let Some(parent) = input.parent {
                let body = namespace_objects::ensure(parent)?;
                let policy = body.and_then(namespace_objects::security).unwrap_or_default();
                if let Err(status) = object_access::check(&policy, object_access::subject(), 2, &object_types::directory_type(), mode == 0 && input.flags & 0x400 == 0) {
                    return Ok(status);
                }
            }
            let concurrency = if concurrency != 0 { concurrency } else { smp::online_cpu_count() as u32 };
            let port = match completion_objects::create("", concurrency, 0, false) {
                Ok(port) => port,
                Err(error) if error.status != 0 => return Ok(error.status),
                Err(error) => return Err(error),
            };
            created = Some(port.clone());
            dispatcher_objects::set_security(port.pointer, input.policy.clone());
            port.exclusive_process.store(if input.flags & 0x20 != 0 { process::get_current_process() } else { 0 }, core::sync::atomic::Ordering::Release);
            if !input.name.is_empty() {
                let Some(node) = input.parent.and_then(|parent| object_manager::insert_named(parent, &input.leaf, "IoCompletion", Some(dispatcher_objects::data(port.pointer)), true)) else {
                    dispatcher_objects::collect(port.pointer);
                    return Ok(0xC000_0035);
                };
                *port.node.lock() = Some(node);
                *port.name.lock() = input.name.clone();
            }
            let mapped =object_access::map_generic_access(desired, &object_type);
            desired = (mapped & (object_type.valid_access | 0x0100_0000)) | if mapped & 0x0200_0000 != 0 { object_type.valid_access } else { 0 };
            port
        }
    };
    let temporary = guest::alloc_bytes(8);
    if temporary == 0 {
        if let Some(port) = created {
            dispatcher_objects::collect(port.pointer);
        }
        return Ok(0xC000_009A);
    }
    let success = if created.is_some() { 0 } else { 0x4000_0000 };
    let published = if mode != 0 {
        completion_objects::publish(&port, temporary, desired, input.flags, success, created.is_some())
    } else {
        open_pointer::open(port.pointer, if created.is_some() { input.flags & !0x400 } else { input.flags }, 0, desired, object_type.pointer, 0, temporary)
    };
    let result = match published {
        Ok(status) if status & 0x8000_0000 != 0 => Ok(status),
        Ok(_) => {
            // O handle já foi publicado: no Nt original uma falha tardia de
            // cópia preserva o status e o handle (o fim do processo o recolhe).
            // SAFETY: célula HANDLE recém-alocada (temporary).
            let handle = unsafe { Field::<u64>::at(temporary) }.get();
            created = None;
            if mode == 0 {
                guest::try_write64(output, handle)?;
            } else if state::probe_user_write(output, 8) {
                let _ = guest::try_write64(output, handle);
            }
            Ok(success)
        }
        Err(error) if error.status != 0 => Ok(error.status),
        Err(error) => Err(error),
    };
    guest::free_bytes(temporary);
    if let Some(port) = created {
        dispatcher_objects::collect(port.pointer);
    }
    result
}
