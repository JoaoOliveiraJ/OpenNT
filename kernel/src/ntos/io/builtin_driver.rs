//! Drivers embutidos (IoCreateDriver) — DRIVER_OBJECT criado pelo próprio
//! kernel para um componente sem imagem de serviço (win32k.sys/win32kbase.sys).
//!
//! Comportamento conferido contra o ntoskrnl 19041, IoCreateDriver rva 0x7a5250:
//!   * DriverName NULL -> "\Driver\%08u" (formato em rva 0x7d7ab0) com
//!     InterlockedIncrement de IopUniqueDriverObjectNumber: o primeiro é 00000001.
//!   * ObCreateObjectEx(IoDriverObjectType, OBJ_PERMANENT|OBJ_CASE_INSENSITIVE|
//!     OBJ_KERNEL_HANDLE) de 0x1A0 bytes; DriverExtension logo depois do
//!     DRIVER_OBJECT, Flags = DRVO_BUILTIN_DRIVER (4), MajorFunction[*] =
//!     IopInvalidDeviceRequest, DriverInit = rotina.
//!   * DriverStart = DllBase do módulo de PsLoadedModuleList que contém a
//!     rotina (DriverSize não é escrito).
//!   * DriverExtension->ServiceKeyName = cópia do nome completo (NUL final).
//!   * InitializationFunction(DriverObject, NULL); falha -> objeto temporário e
//!     desreferenciado; devolve o status da rotina.
//!
//! Reuso: `lifecycle::begin_driver` cria o DRIVER_OBJECT/extensão e publica
//! `\Driver\<nome>` (o caminho dos .sys carregados), `loaded_images::find` acha
//! o DllBase e `lifecycle::dispose_driver` desfaz na falha.
//! Adaptações do OpenNT: o namespace de drivers nativos é só `\Driver`, então
//! outro diretório (ex.: `\FileSystem\X`) publica `\Driver\X`; MajorFunction
//! fica nulo, que o IofCallDriver do OpenNT já recusa como o
//! IopInvalidDeviceRequest; DriverName segue a convenção do lifecycle.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{DriverExtension, DriverObject, NtStruct};
use crate::ntos::io::lifecycle;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::loaded_images;
use crate::ntos::ob::object_manager;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const DRVO_BUILTIN_DRIVER: u32 = 0x04;

/// IopUniqueDriverObjectNumber.
static UNIQUE_DRIVER_OBJECT_NUMBER: AtomicU32 = AtomicU32::new(0);

/// IoCreateDriver(DriverName, InitializationFunction): devolve o NTSTATUS.
pub fn create(name_pointer: u64, initialize: u64) -> Result<u32, KernelError> {
    let full = if name_pointer != 0 {
        guest_strings::read_unicode_string(name_pointer)
    } else {
        let number = UNIQUE_DRIVER_OBJECT_NUMBER.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        format!("\\Driver\\{number:08}")
    };
    let short = match full.get(..8) {
        Some(prefix) if prefix.eq_ignore_ascii_case("\\Driver\\") => String::from(&full[8..]),
        _ => String::from(full.rsplit('\\').next().unwrap_or("")),
    };
    if short.is_empty() {
        return Ok(STATUS_OBJECT_NAME_INVALID);
    }
    if short.contains('\\') {
        return Ok(STATUS_OBJECT_PATH_NOT_FOUND);
    }
    if object_manager::lookup(&format!("\\Driver\\{short}")).is_some() {
        return Ok(STATUS_OBJECT_NAME_COLLISION);
    }
    let units: Vec<u16> = full.encode_utf16().collect();
    let service_buffer = guest::alloc_bytes(units.len() as u64 * 2 + 2);
    if service_buffer == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let image_base = loaded_images::find(initialize).map_or(0, |image| image.image_base);
    let previous = lifecycle::current_driver();
    let driver = match lifecycle::begin_driver(&short, image_base, 0, initialize) {
        Ok(driver) => driver,
        Err(error) => {
            lifecycle::set_current_driver(previous);
            guest::free_bytes(service_buffer);
            return Err(error);
        }
    };
    guest_strings::write_wide_string(service_buffer, &full);
    // SAFETY: DRIVER_OBJECT recém-criado pelo begin_driver e a extensão dele.
    let object = unsafe { DriverObject::at(driver) };
    let extension = unsafe { DriverExtension::at(object.driver_extension.get()) };
    let service_key = &extension.service_key_name;
    service_key.length.set(units.len() as u16 * 2);
    service_key.maximum_length.set(units.len() as u16 * 2 + 2);
    service_key.buffer.set(service_buffer);
    object.flags.set(object.flags.get() | DRVO_BUILTIN_DRIVER);
    let status = native_call::call(initialize, &[driver, 0]) as u32;
    lifecycle::set_current_driver(previous);
    if status & 0x8000_0000 != 0 {
        lifecycle::dispose_driver(driver);
        guest::free_bytes(service_buffer);
    }
    Ok(status)
}
