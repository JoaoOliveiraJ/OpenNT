//! Registro pelo Rtl — RtlQueryRegistryValues[Ex], RtlWriteRegistryValue,
//! RtlCreateRegistryKey, RtlDeleteRegistryValue e RtlFormatCurrentUserKeyPath.
//!
//! Os caminhos relativos (RTL_REGISTRY_*) viram absolutos; as chaves e os
//! valores passam pelo serviço de chaves do Cm (com as notificações de
//! filtro). Os status do Cm voltam como vieram.

use alloc::string::String;

use crate::hal::amd64::native_call;
use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::registry as cm_registry;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// Prefixos RTL_REGISTRY_* por código de raiz.
fn registry_prefix(relative_to: u32) -> Option<&'static str> {
    Some(match relative_to {
        1 => "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\",
        2 => "\\Registry\\Machine\\System\\Control\\",
        3 => "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\",
        4 => "\\Registry\\Machine\\Hardware\\DeviceMap\\",
        5 => "\\Registry\\User\\.CurrentUser\\",
        _ => return None,
    })
}

/// Caminho absoluto (RTL_REGISTRY_ABSOLUTE mantém o texto).
pub fn resolve_registry_path(relative_to: u32, raw: &str) -> String {
    if relative_to == 0 {
        return String::from(raw);
    }
    match registry_prefix(relative_to) {
        Some(prefix) => alloc::format!("{prefix}{}", raw.trim_start_matches('\\')),
        None => String::from(raw),
    }
}

/// Caminho absoluto de um RelativeTo do convidado: os bits altos
/// (RTL_REGISTRY_OPTIONAL/HANDLE) ficam fora do código de raiz.
fn guest_registry_path(relative_to: u32, path: u64) -> String {
    resolve_registry_path(relative_to & 0xFFFF, &guest_strings::read_wide_string(path))
}

/// Flags da RTL_QUERY_REGISTRY_TABLE (wdm.h).
const QUERY_REGISTRY_REQUIRED: u32 = 0x04;
const QUERY_REGISTRY_DIRECT: u32 = 0x20;

/// RtlQueryRegistryValues[Ex]: cada entrada é processada mesmo com a chave
/// ausente (o driver recebe o default); DIRECT escreve em EntryContext; com
/// QueryRoutine a rotina do driver é chamada; REQUIRED sem valor nem
/// default = OBJECT_NAME_NOT_FOUND. Devolve o valor de retorno do export.
pub fn query_registry_values(_relative_to: u32, path: u64, table: u64, context: u64, _environment: u64) -> Result<u64, KernelError> {
    let key_path = guest_strings::read_wide_string(path);
    debug_print!("[rtl] QueryRegistry path=\"{}\" table=0x{:x}", key_path, table);
    let (open_status, key_handle) = key_services::open_path(&key_path, false)?;
    if open_status != 0 && open_status != 0xC000_0034 {
        return Ok(open_status as u64);
    }
    let mut cursor = table;
    let mut status = 0u64;
    for index in 0..=64 {
        let routine = guest::read64(cursor);
        let flags = guest::read32(cursor + 8);
        let name_pointer = guest::read64(cursor + 0x10);
        let entry_context = guest::read64(cursor + 0x18);
        let default_type = guest::read32(cursor + 0x20);
        let default_data = guest::read64(cursor + 0x28);
        let default_length = guest::read32(cursor + 0x30);
        if routine == 0 && name_pointer == 0 {
            break;
        }
        cursor += 0x38;
        let value_name = if name_pointer != 0 { guest_strings::read_wide_string(name_pointer) } else { String::new() };
        let queried = if key_handle != 0 && !value_name.is_empty() { Some(key_services::named_value(key_services::Kind::QueryValue, key_handle, &value_name, 0, &[])?) } else { None };
        if let Some((query_status, _)) = &queried {
            if *query_status != 0 && *query_status != 0xC000_0034 {
                status = *query_status as u64;
                break;
            }
        }
        let entry = queried.and_then(|(_, value)| value);
        let (value_type, value_bytes) = match &entry {
            Some(value) => (value.value_type, Some(value.data.clone())),
            None if default_type != 0 => (default_type, Some(guest::read_bytes(default_data, default_length as usize))),
            None => (0, None),
        };
        debug_print!("[rtl]   [{}] \"{}\" flags=0x{:x} routine=0x{:x} -> {}", index, value_name, flags, routine, if entry.is_some() { "valor" } else if value_bytes.is_some() { "default" } else { "ausente" });
        let Some(bytes) = value_bytes else {
            if flags & QUERY_REGISTRY_REQUIRED != 0 {
                status = 0xC000_0034u32 as i32 as i64 as u64;
                break;
            }
            continue;
        };
        if flags & QUERY_REGISTRY_DIRECT != 0 {
            guest::write_bytes(entry_context, &bytes);
            continue;
        }
        if routine != 0 {
            // QueryRoutine(valueName, valueType, valueData, valueLength, context, entryContext).
            let data = guest::alloc_bytes(bytes.len().max(1) as u64);
            guest::write_bytes(data, &bytes);
            let routine_status = native_call::call(routine, &[name_pointer, value_type as u64, data, bytes.len() as u64, context, entry_context]) as i32;
            guest::free_bytes(data);
            if routine_status < 0 {
                status = routine_status as i64 as u64;
                break;
            }
        }
    }
    if key_handle != 0 {
        cm_registry::close_handle(key_handle as u32);
    }
    Ok(status)
}

/// RtlWriteRegistryValue pelo serviço de chaves (com as notificações de filtro).
pub fn write_value(relative_to: u32, path: u64, value_name: u64, value_type: u32, data: u64, length: u32) -> Result<u32, KernelError> {
    let path = guest_registry_path(relative_to, path);
    let (status, handle) = key_services::open_path(&path, true)?;
    if status != 0 {
        return Ok(status);
    }
    let data = guest::read_bytes(data, length as usize);
    let result = key_services::named_value(key_services::Kind::Set, handle, &guest_strings::read_wide_string(value_name), value_type, &data);
    cm_registry::close_handle(handle as u32);
    Ok(result?.0)
}

/// RtlCreateRegistryKey: abre criando e fecha o handle.
pub fn create_key(relative_to: u32, path: u64) -> Result<u32, KernelError> {
    let path = guest_registry_path(relative_to, path);
    let (status, handle) = key_services::open_path(&path, true)?;
    if handle != 0 {
        cm_registry::close_handle(handle as u32);
    }
    Ok(status)
}

/// RtlDeleteRegistryValue.
pub fn delete_value(relative_to: u32, path: u64, value_name: u64) -> Result<u32, KernelError> {
    let path = guest_registry_path(relative_to, path);
    let (status, handle) = key_services::open_path(&path, false)?;
    if status != 0 {
        return Ok(status);
    }
    let result = key_services::named_value(key_services::Kind::DeleteValue, handle, &guest_strings::read_wide_string(value_name), 0, &[]);
    cm_registry::close_handle(handle as u32);
    Ok(result?.0)
}

/// RtlFormatCurrentUserKeyPath(PUNICODE_STRING): monta "\REGISTRY\USER\<SID>"
/// do token corrente. Sem usuário interativo o kernel roda como SYSTEM.
pub fn format_current_user_key_path(output: u64) {
    let text = "\\REGISTRY\\USER\\S-1-5-18";
    let bytes = text.encode_utf16().count() as u64 * 2;
    let buffer = guest::alloc_bytes(bytes + 2);
    guest_strings::write_wide_string(buffer, text);
    guest::write16(output, bytes as u16);
    guest::write16(output + 2, (bytes + 2) as u16);
    guest::write64(output + 8, buffer);
}
