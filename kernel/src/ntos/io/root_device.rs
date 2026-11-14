//! Dispositivos enumerados pela raiz relatados por um driver
//! (IoReportRootDevice).
//!
//! Como no ntoskrnl 19041: o nome do serviço vem de
//! DriverObject->DriverExtension->ServiceKeyName; a instância é
//! `ROOT\<serviço>\0000` (formato "%04u" com o índice 0) e o HardwareID é
//! `ROOT\<serviço>`. Um nome que não cabe no buffer de 0x190 bytes do NT dá
//! STATUS_OBJECT_NAME_INVALID. O _CmCreateDevice cria a chave da instância
//! sob `Enum`; quando ela é nova, recebe HardwareID (REG_MULTI_SZ),
//! ConfigFlags = CONFIGFLAG_FINISH_INSTALL (0x20) e Service (REG_SZ); uma
//! falha nessas gravações apaga a instância (_CmDeleteDevice). Uma instância
//! que já existia não muda. A propriedade DEVPKEY_Device_Reported vai para o
//! armazenamento de propriedades do PnP, que o OpenNT não tem.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::registry;
use crate::ntos::inc::types::{DriverExtension, DriverObject, NtStruct};
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
/// Raiz das instâncias de dispositivo.
pub const ENUM_PATH: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Enum";
/// O buffer UNICODE_STRING de 0x190 bytes do IoReportRootDevice.
const NAME_BUFFER_BYTES: usize = 0x190;
const CONFIGFLAG_FINISH_INSTALL: u32 = 0x20;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;

fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect()
}

/// Caminho da instância `ROOT\<serviço>\0000` relativo a `Enum`.
pub fn instance_path(service: &str) -> String {
    format!("ROOT\\{service}\\0000")
}

/// IoReportRootDevice(DriverObject): devolve o NTSTATUS.
pub fn report_root_device(driver_object: u64) -> Result<u32, KernelError> {
    // SAFETY: PDRIVER_OBJECT de um chamador de modo kernel e a sua extensão.
    let extension = unsafe { DriverExtension::at(DriverObject::at(driver_object).driver_extension.get()) };
    let service = guest_strings::read_unicode_string(extension.service_key_name.address());
    let hardware_id = format!("ROOT\\{service}");
    // "ROOT\" + serviço precisa caber com o NUL no buffer de 0x190 bytes.
    if (hardware_id.encode_utf16().count() + 1) * 2 > NAME_BUFFER_BYTES {
        return Ok(STATUS_OBJECT_NAME_INVALID);
    }
    let path = format!("{ENUM_PATH}\\{}", instance_path(&service));
    if registry::node_by_path(&path).is_some() {
        return Ok(0);
    }
    let handle = registry::open_or_create(&path, None)?;
    let mut multi = wide(&hardware_id);
    multi.extend([0, 0, 0, 0]);
    let mut service_value = wide(&service);
    service_value.extend([0, 0]);
    let written = registry::set_value(handle, "HardwareID", REG_MULTI_SZ, multi)
        && registry::set_value(handle, "ConfigFlags", REG_DWORD, CONFIGFLAG_FINISH_INSTALL.to_le_bytes().to_vec())
        && registry::set_value(handle, "Service", REG_SZ, service_value);
    if !written {
        registry::delete_key(handle);
        registry::close_handle(handle);
        return Ok(0xC000_0001);
    }
    registry::close_handle(handle);
    Ok(0)
}
