//! Carga de drivers pela chave do serviço: o nome do DRIVER_OBJECT.
//!
//! ntoskrnl 10.0.19041, IopGetDriverNameFromKeyNode (rva 0x73ecc0), chamado
//! pelo IopLoadDriver e pelo IopUnloadDriver com o handle da chave:
//! - o valor `ObjectName`, quando existe, é o nome: REG_SZ com mais de 2
//!   bytes (o nome são os DataLength - 2 primeiros bytes, sem o NUL final);
//!   outro tipo ou só o terminador dá STATUS_ILL_FORMED_SERVICE_ENTRY;
//! - sem ele, o valor `Type` (o primeiro ULONG dos dados; ausente ou vazio,
//!   STATUS_ILL_FORMED_SERVICE_ENTRY) escolhe o diretório: `\FileSystem\`
//!   para SERVICE_FILE_SYSTEM_DRIVER (2) e SERVICE_RECOGNIZER_DRIVER (8),
//!   `\Driver\` para os outros, seguido do nome da chave como está na hive
//!   (o Name do KEY_BASIC_INFORMATION).
//!
//! O services.exe confere o estado de um driver pelo mesmo nome
//! (CDriverRecord::GetObjectName e o NtQueryDirectoryObject do diretório).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::registry;

/// A raiz das chaves de serviço.
pub const SERVICES_ROOT: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services";

const STATUS_ILL_FORMED_SERVICE_ENTRY: u32 = 0xC000_0160;
const REG_SZ: u32 = 1;
const SERVICE_FILE_SYSTEM_DRIVER: u32 = 2;
const SERVICE_RECOGNIZER_DRIVER: u32 = 8;

/// IopGetDriverNameFromKeyNode(KeyHandle, DriverName): o nome do objeto do
/// driver da chave aberta em `handle`.
pub fn driver_name_from_key(handle: u32) -> Result<String, u32> {
    if let Some(value) = registry::get_value(handle, "ObjectName") {
        if value.value_type != REG_SZ || value.data.len() <= 2 {
            return Err(STATUS_ILL_FORMED_SERVICE_ENTRY);
        }
        let name = &value.data[..value.data.len() - 2];
        let units: Vec<u16> = name.chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)])).collect();
        return Ok(String::from_utf16_lossy(&units));
    }
    let Some(value) = registry::get_value(handle, "Type").filter(|value| !value.data.is_empty()) else { return Err(STATUS_ILL_FORMED_SERVICE_ENTRY) };
    let mut bytes = [0u8; 4];
    let count = value.data.len().min(4);
    bytes[..count].copy_from_slice(&value.data[..count]);
    let directory = match u32::from_le_bytes(bytes) {
        SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER => "\\FileSystem\\",
        _ => "\\Driver\\",
    };
    let key_name = registry::get_node(handle).and_then(|node| registry::with_node(node, |key| key.name.clone())).ok_or(STATUS_ILL_FORMED_SERVICE_ENTRY)?;
    Ok(format!("{directory}{key_name}"))
}

/// O nome do objeto do driver do serviço `name` pela chave dele; sem a chave
/// (um driver sem serviço) ou com ela malformada, `\Driver\<name>`.
pub fn service_driver_name(name: &str) -> String {
    let handle = registry::open(&format!("{SERVICES_ROOT}\\{name}")).unwrap_or(0);
    if handle == 0 {
        return format!("\\Driver\\{name}");
    }
    let result = driver_name_from_key(handle);
    registry::close_handle(handle);
    result.unwrap_or_else(|_| format!("\\Driver\\{name}"))
}
