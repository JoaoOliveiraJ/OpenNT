//! Os serviços de hive: NtLoadKey/NtLoadKey2/NtLoadKeyEx,
//! NtUnloadKey/NtUnloadKey2/NtUnloadKeyEx, NtSaveKey/NtSaveKeyEx,
//! NtRestoreKey, NtFlushKey, NtCompressKey e NtCompactKeys (e os Zw*
//! exportados, com PreviousMode de kernel).
//!
//! Captura dos parâmetros, privilégios e códigos como no ntoskrnl 19041:
//! - NtLoadKeyEx (CmLoadDifferencingKey, rva 0x6e729c): Flags com algum bit
//!   de 0xFFFF000B é STATUS_INVALID_PARAMETER_3; sem REG_APP_HIVE exige
//!   SeRestorePrivilege (SeSinglePrivilegeCheck pelo PreviousMode; sem ele,
//!   STATUS_PRIVILEGE_NOT_HELD); sem REG_APP_HIVE nem
//!   REG_LOAD_HIVE_OPEN_HANDLE, RootHandle não nulo é
//!   STATUS_INVALID_PARAMETER_7 e Event não nulo
//!   STATUS_INVALID_PARAMETER_5. NtLoadKey é o Ex com zeros; NtLoadKey2, o
//!   Ex com Flags;
//! - NtUnloadKey(2/Ex) (CmUnloadKey, rva 0x66c6bc): SeRestorePrivilege;
//!   Flags além de REG_FORCE_UNLOAD é STATUS_INVALID_PARAMETER; a chave
//!   ausente também (o STATUS_OBJECT_NAME_NOT_FOUND vira
//!   STATUS_INVALID_PARAMETER); o Ex com handles abertos e um evento
//!   devolve STATUS_PENDING e descarrega quando o último handle fecha,
//!   sinalizando o evento;
//! - NtSaveKeyEx (rva 0x729730): SeBackupPrivilege; Format 1
//!   (REG_STANDARD_FORMAT), 2 (REG_LATEST_FORMAT) ou 4
//!   (REG_NO_COMPRESSION), senão STATUS_INVALID_PARAMETER; o handle de
//!   arquivo de usuário precisa de FILE_WRITE_DATA. NtSaveKey é o Ex com 1;
//! - NtRestoreKey (rva 0x8694a0): SeRestorePrivilege; o arquivo de usuário
//!   precisa de FILE_READ_DATA; REG_REFRESH_HIVE com outro bit é
//!   STATUS_INVALID_PARAMETER;
//! - NtFlushKey (rva 0x696c00): qualquer acesso no handle;
//! - NtCompressKey (rva 0x868250): SeBackupPrivilege, KEY_WRITE no handle,
//!   o modo nos dois bits baixos do handle e a chave precisa ser a raiz da
//!   hive (STATUS_INVALID_PARAMETER);
//! - NtCompactKeys (rva 0x867f70): SeBackupPrivilege; Count 0 é sucesso,
//!   Count >= 0x1FFFFFFF é STATUS_INVALID_PARAMETER; KEY_WRITE em cada
//!   handle; as chaves precisam estar na mesma hive e nenhuma pode ser raiz
//!   de hive; o NT valida e devolve sucesso sem mudar a hive.
//!
//! Ainda não existem a hive de aplicativo (REG_APP_HIVE, o \REGISTRY\A do
//! RegLoadAppKey), o handle da raiz na carga (REG_LOAD_HIVE_OPEN_HANDLE) e
//! as restaurações REG_WHOLE_HIVE_VOLATILE e REG_REFRESH_HIVE: esses
//! pedidos devolvem STATUS_NOT_SUPPORTED. As notificações de filtro
//! RegNtPre/PostLoadKey, UnLoadKey, SaveKey, RestoreKey e FlushKey ainda
//! não são enviadas.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::hive_file::HiveFile;
use crate::ntos::cm::hive_list::{self, LATEST_MINOR, STANDARD_MINOR};
use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::inc::types::{NtStruct, ObjectAttributes};
use crate::ntos::io::file::{request as file_request, zw as zw_files};
use crate::ntos::ps::user::{registry as user_registry, state as user_state};
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::privilege;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
const STATUS_INVALID_PARAMETER_7: u32 = 0xC000_00F5;

/// SeBackupPrivilege e SeRestorePrivilege (LUIDs 17 e 18).
const SE_BACKUP_PRIVILEGE: u64 = 17;
const SE_RESTORE_PRIVILEGE: u64 = 18;

const REG_APP_HIVE: u32 = 0x10;
const REG_LOAD_HIVE_OPEN_HANDLE: u32 = 0x800;
const REG_WHOLE_HIVE_VOLATILE: u32 = 1;
const REG_REFRESH_HIVE: u32 = 2;
/// KEY_WRITE, FILE_READ_DATA e FILE_WRITE_DATA.
const KEY_WRITE: u32 = 0x2_0006;
const FILE_READ_DATA: u32 = 1;
const FILE_WRITE_DATA: u32 = 2;

fn privileged(privilege_value: u64, previous_mode: bool) -> bool {
    privilege::single_privilege_check(privilege_value, previous_mode as u32)
}

fn is_registry_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower == "\\registry" || lower.starts_with("\\registry\\")
}

/// O nome de chave de um OBJECT_ATTRIBUTES (CmpNameFromAttributes): o
/// caminho da raiz (handle de chave) mais o nome, ou o nome absoluto.
fn key_path(attributes: u64, previous_mode: bool) -> Result<String, u32> {
    let path = if previous_mode {
        user_registry::parse_user_object_attributes(attributes).ok_or(STATUS_ACCESS_VIOLATION)?.path
    } else {
        if attributes == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // SAFETY: POBJECT_ATTRIBUTES de um chamador de modo kernel.
        let object = unsafe { ObjectAttributes::at(attributes) };
        if object.length.get() != ObjectAttributes::SIZE as u32 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let name_pointer = object.object_name.get();
        let name = if name_pointer != 0 { guest_strings::read_unicode_string(name_pointer) } else { String::new() };
        match object.root_directory.get() {
            0 => name,
            root => {
                let (_, root_path) = key_services::reference_key(root, false, 0)?;
                if name.is_empty() { root_path } else { format!("{root_path}\\{name}") }
            }
        }
    };
    if is_registry_path(&path) { Ok(path) } else { Err(STATUS_OBJECT_PATH_SYNTAX_BAD) }
}

/// O nome NT de arquivo de um OBJECT_ATTRIBUTES.
fn file_path(attributes: u64, previous_mode: bool) -> Result<String, u32> {
    if previous_mode {
        let parsed = user_registry::parse_user_object_attributes(attributes).ok_or(STATUS_ACCESS_VIOLATION)?;
        if parsed.path.is_empty() { Err(STATUS_OBJECT_NAME_NOT_FOUND) } else { Ok(parsed.path) }
    } else {
        zw_files::file_path_from_object_attributes(attributes)
    }
}

/// NtLoadKeyEx(TargetKey, SourceFile, Flags, TrustClassKey, Event,
/// DesiredAccess, RootHandle, Reserved).
#[allow(clippy::too_many_arguments)]
pub fn load_key(target: u64, source: u64, flags: u32, _trust_class_key: u64, event: u64, _desired_access: u32, root_handle: u64, previous_mode: bool) -> u32 {
    if flags & 0xFFFF_000B != 0 {
        return STATUS_INVALID_PARAMETER_3;
    }
    if flags & REG_APP_HIVE == 0 && !privileged(SE_RESTORE_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if flags & (REG_APP_HIVE | REG_LOAD_HIVE_OPEN_HANDLE) != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    if root_handle != 0 {
        return STATUS_INVALID_PARAMETER_7;
    }
    if event != 0 {
        return STATUS_INVALID_PARAMETER_5;
    }
    let target = match key_path(target, previous_mode) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let source = match file_path(source, previous_mode) {
        Ok(path) => path,
        Err(status) => return status,
    };
    hive_list::load(&target, &source, flags)
}

/// NtUnloadKey2/NtUnloadKeyEx(TargetKey, Flags, Event).
pub fn unload_key(target: u64, flags: u32, event: u64, previous_mode: bool) -> u32 {
    if !privileged(SE_RESTORE_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if flags & !hive_list::REG_FORCE_UNLOAD != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let path = match key_path(target, previous_mode) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let Some(node) = registry::node_by_path(&path) else { return STATUS_INVALID_PARAMETER };
    if event != 0 {
        let event = match file_request::event_reference(event, previous_mode as u8) {
            Ok(event) => event,
            Err(status) => return status,
        };
        crate::ntos::ke::dispatcher::reset_event(event.pointer);
        return hive_list::unload_or_defer(node, flags, event);
    }
    hive_list::unload(node, flags)
}

/// NtSaveKeyEx(KeyHandle, FileHandle, Format).
pub fn save_key(key: u64, file: u64, format: u32, previous_mode: bool) -> u32 {
    if !privileged(SE_BACKUP_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if format.wrapping_sub(1) & !3 != 0 || format == 3 {
        return STATUS_INVALID_PARAMETER;
    }
    let file = match HiveFile::from_handle(file, previous_mode, FILE_WRITE_DATA) {
        Ok(file) => file,
        Err(status) => return status,
    };
    let (node, _) = match key_services::reference_key(key, previous_mode, 0) {
        Ok(resolved) => resolved,
        Err(status) => return status,
    };
    hive_list::save(node, &file, if format == 1 { STANDARD_MINOR } else { LATEST_MINOR })
}

/// NtRestoreKey(KeyHandle, FileHandle, Flags).
pub fn restore_key(key: u64, file: u64, flags: u32, previous_mode: bool) -> u32 {
    if !privileged(SE_RESTORE_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    let file = match HiveFile::from_handle(file, previous_mode, FILE_READ_DATA) {
        Ok(file) => file,
        Err(status) => return status,
    };
    let (node, _) = match key_services::reference_key(key, previous_mode, 0) {
        Ok(resolved) => resolved,
        Err(status) => return status,
    };
    if flags & REG_REFRESH_HIVE != 0 && flags & !REG_REFRESH_HIVE != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if flags & (REG_WHOLE_HIVE_VOLATILE | REG_REFRESH_HIVE) != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    hive_list::restore(node, &file, flags)
}

/// NtFlushKey(KeyHandle).
pub fn flush_key(key: u64, previous_mode: bool) -> u32 {
    match key_services::reference_key(key, previous_mode, 0) {
        Ok((node, _)) => hive_list::flush(node),
        Err(status) => status,
    }
}

/// NtCompressKey(Key): o modo vem dos dois bits baixos do handle.
pub fn compress_key(key: u64, previous_mode: bool) -> u32 {
    if !privileged(SE_BACKUP_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    let mode = (key & 3) as u32;
    match key_services::reference_key(key & !3, previous_mode, KEY_WRITE) {
        Ok((node, _)) => hive_list::compress(node, mode),
        Err(status) => status,
    }
}

/// NtCompactKeys(Count, KeyArray).
pub fn compact_keys(count: u32, array: u64, previous_mode: bool) -> u32 {
    if !privileged(SE_BACKUP_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if count == 0 {
        return 0;
    }
    if count >= 0x1FFF_FFFF {
        return STATUS_INVALID_PARAMETER;
    }
    if previous_mode && !user_state::probe_user_read(array, count as u64 * 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let Ok(handles) = crate::ntos::mm::guest_memory::try_read_bytes(array, count as usize * 8) else { return STATUS_ACCESS_VIOLATION };
    let mut nodes: Vec<NodeId> = Vec::with_capacity(count as usize);
    for handle in handles.chunks_exact(8) {
        let handle = u64::from_le_bytes([handle[0], handle[1], handle[2], handle[3], handle[4], handle[5], handle[6], handle[7]]);
        match key_services::reference_key(handle, previous_mode, KEY_WRITE) {
            Ok((node, _)) => nodes.push(node),
            Err(status) => return status,
        }
    }
    if hive_list::same_hive(&nodes) { 0 } else { STATUS_INVALID_PARAMETER }
}
