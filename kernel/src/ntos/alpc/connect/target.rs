//! Busca e requisito de segurança de Nt/ZwAlpcConnectPortEx.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::alpc::connect::capture::{self as connect_capture, Target};
use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::ex::callback_security;
use crate::ntos::mm::section::create as create_section;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ob::{object_access, object_types};
use crate::ntos::ps::process;
use crate::ntos::se::model::SecurityPolicy;
use core::mem::offset_of;

use crate::ntos::alpc::message::buffer::read_field;
use crate::ntos::inc::types::{NtStruct, ObjectAttributes, SecurityDescriptor, SecurityDescriptorRelative, SecurityQualityOfService};

/// A política explícita não herda owner/DACL do chamador: descreve quais
/// identidades de servidor o cliente aceita, sem alterar a porta.
fn descriptor(pointer: u64, mode: u8) -> Result<Option<SecurityPolicy>, u32> {
    if pointer == 0 {
        return Ok(None);
    }
    if mode != 0 && pointer & 3 != 0 {
        return Err(0x8000_0002);
    }
    if !message_buffer::accessible(pointer, 4, mode, false) {
        return Err(0xC000_0005);
    }
    if read_field::<u8>(pointer, offset_of!(SecurityDescriptor, revision))? != 1 {
        return Err(0xC000_0058);
    }
    if mode != 0 && !create_section::descriptor_probe(pointer) {
        return Err(0xC000_0005);
    }
    let mut policy = callback_security::capture(pointer)?;
    let control = read_field::<u16>(pointer, offset_of!(SecurityDescriptor, control))?;
    // SE_SELF_RELATIVE: Owner é um deslocamento ULONG; senão, um PSID.
    let owner = if control & 0x8000 != 0 { read_field::<u32>(pointer, offset_of!(SecurityDescriptorRelative, owner))? as u64 } else { read_field::<u64>(pointer, offset_of!(SecurityDescriptor, owner))? };
    if owner == 0 {
        policy.owner = Vec::new();
    }
    if control & 4 == 0 {
        policy.dacl = None;
    }
    Ok(Some(policy))
}

/// AlpcpConnectPort só captura o descritor em UserMode; a entrada Zw passa
/// o ponteiro ao SeAccessCheck em KernelMode, que concede o acesso.
pub fn required_security(pointer: u64, mode: u8) -> Result<Option<SecurityPolicy>, u32> {
    if mode != 0 { descriptor(pointer, mode) } else { Ok(None) }
}

fn quality(pointer: u64, mode: u8) -> u32 {
    if pointer == 0 {
        return 0;
    }
    if mode != 0 && pointer & 3 != 0 {
        return 0x8000_0002;
    }
    if !message_buffer::accessible(pointer, SecurityQualityOfService::SIZE, mode, false) {
        return 0xC000_0005;
    }
    // ObCaptureObjectCreateInformation consome os campos, mas ignora Length.
    let tracking = match read_field::<u8>(pointer, offset_of!(SecurityQualityOfService, context_tracking_mode)) {
        Ok(tracking) => tracking,
        Err(status) => return status,
    };
    if tracking > 1 {
        return 0xC000_000D;
    }
    match read_field::<u32>(pointer, offset_of!(SecurityQualityOfService, impersonation_level)) {
        Ok(level) if level > 3 => 0xC000_00A5,
        Ok(_) => 0,
        Err(status) => status,
    }
}

pub fn listener(attributes: u64, required: Option<&SecurityPolicy>, mode: u8) -> Result<Target, u32> {
    if attributes == 0 {
        return Err(0xC000_0033);
    }
    if mode != 0 && attributes & 7 != 0 {
        return Err(0x8000_0002);
    }
    if !message_buffer::accessible(attributes, ObjectAttributes::SIZE, mode, false) {
        return Err(0xC000_0005);
    }
    if read_field::<u32>(attributes, offset_of!(ObjectAttributes, length))? != ObjectAttributes::SIZE as u32 {
        return Err(0xC000_000D);
    }
    let flags = read_field::<u32>(attributes, offset_of!(ObjectAttributes, attributes))?;
    if flags & !0x1_1F72 != 0 {
        return Err(0xC000_000D);
    }
    descriptor(read_field::<u64>(attributes, offset_of!(ObjectAttributes, security_descriptor))?, mode)?;
    let quality_status = quality(read_field::<u64>(attributes, offset_of!(ObjectAttributes, security_quality_of_service))?, mode);
    if quality_status != 0 {
        return Err(quality_status);
    }
    let root = read_field::<u64>(attributes, offset_of!(ObjectAttributes, root_directory))?;
    let name_pointer = read_field::<u64>(attributes, offset_of!(ObjectAttributes, object_name))?;
    if name_pointer == 0 {
        return Err(if root != 0 { 0xC000_0033 } else { 0xC000_003B });
    }
    let path: String = connect_capture::unicode(name_pointer, mode, true)?;
    if path.is_empty() {
        return Err(if root != 0 { 0xC000_0033 } else { 0xC000_003B });
    }
    let mut start = object_manager::ROOT;
    if root != 0 {
        if path.starts_with('\\') {
            return Err(0xC000_003B);
        }
        start = namespace_handles::resolve(root, mode != 0)?.node;
        if object_manager::node(start).is_none_or(|record| record.type_name != "Directory") {
            return Err(0xC000_0024);
        }
    } else if !path.starts_with('\\') {
        return Err(0xC000_003B);
    }
    // Diferencia falha num componente intermediário da ausência do nome final.
    let insensitive = flags & 0x40 != 0;
    let parent = match path.rfind('\\') {
        Some(separator) if separator > 0 => object_manager::resolve_from(&path[..separator], 0, insensitive, false, start).0,
        _ => Some(start),
    };
    let Some(parent) = parent else { return Err(0xC000_003A) };
    if object_manager::node(parent).is_none_or(|record| record.children.is_none() || record.mount.is_some()) {
        return Err(0xC000_0024);
    }
    let (node, _) = object_manager::resolve_from(&path, 0, insensitive, flags & 0x100 != 0, start);
    let shown = node.and_then(object_manager::path_of).unwrap_or_else(|| path.clone());
    let target = connect_capture::resolve_listener(node, &shown, None, mode, flags & 0x400 != 0)?;
    let Some(required) = required else { return Ok(target) };
    let Some(server_token) = process::get_primary_token(target.server.process) else { return Err(0xC000_02A0) };
    let object_type = object_types::user_type("alpc").ok_or(0xC000_0024u32)?;
    // Pede MAXIMUM_ALLOWED e exige PORT_CONNECT na máscara concedida.
    match object_access::check(required, Some(server_token), 0x0200_0000, &object_type, mode == 0) {
        Ok(access) if access & 1 != 0 => Ok(target),
        _ => Err(0xC000_02A0),
    }
}
