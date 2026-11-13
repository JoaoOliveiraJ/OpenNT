//! Chaves de Registro do driver — IoOpenDriverRegistryKey (ntoskrnl 19041
//! 0x7c4e70) com PiCreateDriverRedirectedStateKey 0x7c5164 e
//! PiGetStateRootPath 0x78111c.
//!
//! IoOpenDriverRegistryKey(DriverObject, RegKeyType, DesiredAccess, Flags,
//! DriverRegKey):
//! - DriverObject NULL, sem DriverExtension, ServiceKeyName com Buffer NULL
//!   ou Length 0, Flags != 0 ou saída NULL: STATUS_INVALID_PARAMETER;
//! - abre Services\<ServiceKeyName> (PipOpenServiceEnumKeys); erro volta;
//! - o valor Type precisa existir (ausente = STATUS_INVALID_PARAMETER), ser
//!   REG_DWORD de 4 bytes (senão STATUS_REGISTRY_CORRUPT) e ter um dos bits
//!   0xB (kernel driver, FS driver, adapter); senão STATUS_INVALID_PARAMETER;
//! - DriverRegKeyParameters (0): MAXIMUM_ALLOWED vira KEY_READ; qualquer bit
//!   fora de 0x80020019 (leitura) = STATUS_ACCESS_DENIED; abre
//!   Services\<nome>\Parameters (OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE);
//! - DriverRegKeyPersistentState (1): a raiz é a chave redirecionada do
//!   RedirectionMap (valor padrão de ...\RedirectionMap\Keys\DriverStatePath
//!   + "\<nome>", criada se faltar) ou, sem redirecionamento
//!   (STATUS_OBJECT_NAME_NOT_FOUND), a própria chave de serviço; abre a
//!   subchave State com o acesso pedido e a cria se não existir;
//! - outro tipo: STATUS_INVALID_PARAMETER.
//! Divergências honestas: a State criada não recebe o descritor de
//! PiAuGetServiceStateSecurityObject (SID do serviço) nem a marca de
//! IopApplyMutableTagToRegistryKey — o Registro do OpenNT não tem esses dois
//! mecanismos.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::persisted_state;
use crate::ntos::cm::registry;
use crate::ntos::inc::types::{DriverExtension, DriverObject, Field, NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_REGISTRY_CORRUPT: u32 = 0xC000_014C;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const KEY_READ: u32 = 0x2_0019;
const KEY_CREATE_SUB_KEY: u32 = 4;
/// Bits proibidos na chave Parameters (tudo fora de leitura).
const PARAMETERS_FORBIDDEN_ACCESS: u32 = 0x7FFD_FFE6;
/// SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_ADAPTER.
const DRIVER_SERVICE_TYPES: u32 = 0xB;
const OBJ_CASE_INSENSITIVE_KERNEL_HANDLE: u32 = 0x240;
const SERVICES: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";

pub const DRIVER_REG_KEY_PARAMETERS: u32 = 0;
pub const DRIVER_REG_KEY_PERSISTENT_STATE: u32 = 1;

/// ZwOpenKey/ZwCreateKey internos com OBJECT_ATTRIBUTES temporários de
/// handle de kernel (nome absoluto, sem RootDirectory); devolve (status, handle).
fn open_key(path: &str, desired_access: u32, create: bool) -> Result<(u32, u64), KernelError> {
    let name_bytes: Vec<u8> = path.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    let name = guest::alloc_bytes(name_bytes.len() as u64 + 2);
    guest::write_bytes(name, &name_bytes);
    let string_address = guest::alloc_bytes(UnicodeString::SIZE);
    let attributes_address = guest::alloc_bytes(ObjectAttributes::SIZE);
    let output = guest::alloc_bytes(8);
    // SAFETY: blocos recém-alocados (zerados) do tamanho de cada estrutura.
    let (string, attributes, handle) = unsafe { (UnicodeString::at(string_address), ObjectAttributes::at(attributes_address), Field::<u64>::at(output)) };
    string.length.set(name_bytes.len() as u16);
    string.maximum_length.set(name_bytes.len() as u16 + 2);
    string.buffer.set(name);
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.object_name.set(string_address);
    attributes.attributes.set(OBJ_CASE_INSENSITIVE_KERNEL_HANDLE);
    let status = if create {
        key_services::create(output, desired_access, attributes_address, 0, 0, 0, 0, false)
    } else {
        key_services::open(output, desired_access, attributes_address, false, 0)
    };
    let opened = handle.get();
    for pointer in [output, attributes_address, string_address, name] {
        guest::free_bytes(pointer);
    }
    let status = status?;
    Ok((status, if status == 0 { opened } else { 0 }))
}

fn close(handle: u64) {
    if handle != 0 {
        registry::close_handle(handle as u32);
    }
}

/// Valor Type da chave de serviço já aberta.
fn check_service_type(service: u64) -> Result<u32, KernelError> {
    let (status, value) = key_services::named_value(key_services::Kind::QueryValue, service, "Type", 0, &[])?;
    if status == STATUS_OBJECT_NAME_NOT_FOUND {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if status != 0 {
        return Ok(status);
    }
    let Some(value) = value else { return Ok(STATUS_INVALID_PARAMETER) };
    if value.value_type != REG_DWORD || value.data.len() != 4 {
        return Ok(STATUS_REGISTRY_CORRUPT);
    }
    let service_type = u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]);
    Ok(if service_type & DRIVER_SERVICE_TYPES == 0 { STATUS_INVALID_PARAMETER } else { 0 })
}

/// RtlGetPersistedStateLocation("DriverStatePath", NULL, NULL, chave): raiz
/// redirecionada do estado dos drivers, se o mapa a define.
fn redirected_state_root() -> Option<String> {
    let map = format!("{}Keys\\DriverStatePath", persisted_state::ROOT);
    let value = registry::read_value_by_path(&map, "")?;
    if value.value_type != REG_SZ {
        return None;
    }
    let units: Vec<u16> = value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// ServiceKeyName do DriverExtension, se o driver tem uma utilizável.
fn service_key_name(driver: &DriverObject) -> Option<&'static UnicodeString> {
    let extension = driver.driver_extension.get();
    if extension == 0 {
        return None;
    }
    // SAFETY: DriverObject->DriverExtension aponta para o DRIVER_EXTENSION vivo.
    let name = &unsafe { DriverExtension::at(extension) }.service_key_name;
    (name.buffer.get() != 0 && name.length.get() != 0).then_some(name)
}

/// IoOpenDriverRegistryKey; o handle vai para `output` só em sucesso.
/// `driver` e `output` já convertidos pelo adaptador (None = NULL).
pub fn open_driver_registry_key(driver: Option<&DriverObject>, key_type: u32, desired_access: u32, flags: u32, output: Option<&Field<u64>>) -> Result<u32, KernelError> {
    let Some(driver) = driver else { return Ok(STATUS_INVALID_PARAMETER) };
    let Some(name) = service_key_name(driver) else { return Ok(STATUS_INVALID_PARAMETER) };
    let Some(output) = output.filter(|_| flags == 0) else { return Ok(STATUS_INVALID_PARAMETER) };
    let name = guest_strings::read_unicode_string(name.address());
    let service_path = format!("{SERVICES}{name}");
    let (status, service) = open_key(&service_path, KEY_READ | KEY_CREATE_SUB_KEY, false)?;
    if status != 0 {
        return Ok(status);
    }
    let status = check_service_type(service)?;
    if status != 0 {
        close(service);
        return Ok(status);
    }
    let (status, handle) = match key_type {
        DRIVER_REG_KEY_PARAMETERS => {
            let access = if desired_access & MAXIMUM_ALLOWED != 0 { (desired_access & !MAXIMUM_ALLOWED) | KEY_READ } else { desired_access };
            if access & PARAMETERS_FORBIDDEN_ACCESS != 0 {
                (STATUS_ACCESS_DENIED, 0)
            } else {
                open_key(&format!("{service_path}\\Parameters"), access, false)?
            }
        }
        DRIVER_REG_KEY_PERSISTENT_STATE => {
            let parent = match redirected_state_root() {
                Some(root) => format!("{root}\\{name}"),
                None => service_path.clone(),
            };
            let state = format!("{parent}\\State");
            match open_key(&state, desired_access, false)? {
                (STATUS_OBJECT_NAME_NOT_FOUND, _) => open_key(&state, desired_access, true)?,
                opened => opened,
            }
        }
        _ => (STATUS_INVALID_PARAMETER, 0),
    };
    close(service);
    if status == 0 {
        output.set(handle);
    }
    Ok(status)
}
