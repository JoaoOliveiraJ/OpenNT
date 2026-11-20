//! Carga e descarga de drivers pela chave do serviço: NtLoadDriver,
//! NtUnloadDriver e o nome do DRIVER_OBJECT.
//!
//! ntoskrnl 10.0.19041:
//! - NtLoadDriver (rva 0x780620) é o IopLoadDriverImage (0x399778): um
//!   DriverServiceName nulo dá STATUS_INVALID_PARAMETER; em UserMode, o
//!   SeSinglePrivilegeCheck(SeLoadDriverPrivilege) do token efetivo
//!   (STATUS_PRIVILEGE_NOT_HELD), uma thread num server silo volta sucesso
//!   sem carregar nada, e a captura do UNICODE_STRING (Length 0 é
//!   STATUS_INVALID_PARAMETER, Buffer ímpar STATUS_DATATYPE_MISALIGNMENT, a
//!   sonda do buffer STATUS_ACCESS_VIOLATION) copia o nome para o pool. O
//!   LOAD_PACKET (WORK_QUEUE_ITEM, KEVENT de notificação, DriverObject,
//!   DriverServiceName e FinalStatus) vai ao IopLoadUnloadDriver direto
//!   quando quem chama já é o processo System; senão a uma worker do
//!   sistema (ExQueueWorkItem, DelayedWorkQueue), e quem chama espera o
//!   evento. O resultado é o FinalStatus.
//! - IopLoadUnloadDriver (0x780640): com DriverObject, chama o DriverUnload;
//!   senão abre a chave (IopOpenRegistryKey, KEY_READ: a falha volta como
//!   está), chama o IopLoadDriver, troca STATUS_FAILED_DRIVER_ENTRY pelo
//!   status do DriverEntry e STATUS_DRIVER_FAILED_PRIOR_UNLOAD por
//!   STATUS_OBJECT_NAME_NOT_FOUND, roda as rotinas de reinicialização dos
//!   drivers (IopCallDriverReinitializationRoutines) e sinaliza o evento.
//! - IopLoadDriver (0x73cc28): o caminho da imagem (IopBuildFullDriverPath:
//!   o ImagePath com pelo menos um caractere, como está quando começa com
//!   `\`, senão sob `\SystemRoot\`; sem ele,
//!   `\SystemRoot\System32\Drivers\<chave>.SYS`), o nome do objeto
//!   (IopGetDriverNameFromKeyNode), o MmLoadSystemImage e o DRIVER_OBJECT;
//!   um objeto que já existe com o nome dá STATUS_IMAGE_ALREADY_LOADED. O
//!   RegistryPath do DriverEntry é o nome da chave aberta. O kernel não
//!   inicia o DependOnService: quem pede a carga (o services.exe) o faz.
//! - NtUnloadDriver (0x89b1f0) é o IopUnloadDriver (0x768cd8) com
//!   InvalidateFlag FALSE: em UserMode o privilégio e a mesma captura (sem a
//!   verificação do ponteiro nulo), e a reentrada pelo ZwUnloadDriver. Em
//!   KernelMode, um server silo dá STATUS_PRIVILEGE_NOT_HELD; a chave e o
//!   nome do objeto como na carga; o ObOpenObjectByName do DRIVER_OBJECT
//!   (ausente: STATUS_OBJECT_NAME_NOT_FOUND); sem DriverUnload, sem
//!   DriverSection (um driver do IoCreateDriver) ou com AddDevice (um driver
//!   PnP, o PnpIsLegacyDriver falso), STATUS_INVALID_DEVICE_REQUEST; o
//!   DriverUnload roda no processo System, pelo mesmo LOAD_PACKET.
//! - IopGetDriverNameFromKeyNode (0x73ecc0): o valor `ObjectName`, quando
//!   existe, é o nome: REG_SZ com mais de 2 bytes (o nome são os
//!   DataLength - 2 primeiros bytes, sem o NUL final); outro tipo ou só o
//!   terminador dá STATUS_ILL_FORMED_SERVICE_ENTRY. Sem ele, o valor `Type`
//!   (o primeiro ULONG dos dados; ausente ou vazio,
//!   STATUS_ILL_FORMED_SERVICE_ENTRY) escolhe o diretório: `\FileSystem\`
//!   para SERVICE_FILE_SYSTEM_DRIVER (2) e SERVICE_RECOGNIZER_DRIVER (8),
//!   `\Driver\` para os outros, seguido do nome da chave como está na hive
//!   (o Name do KEY_BASIC_INFORMATION).
//!
//! O services.exe confere o estado de um driver pelo mesmo nome
//! (CDriverRecord::GetObjectName e o NtQueryDirectoryObject do diretório).
//!
//! O OpenNT ainda não adia a descarga de um driver com referências vivas (o
//! DRVO_UNLOAD_INVOKED do IopCheckUnloadDriver): o pedido é recusado com
//! STATUS_INVALID_DEVICE_REQUEST e o driver fica carregado.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::registry;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{DriverExtension, DriverObject, Kevent, UnicodeString, WorkQueueItem};
use crate::ntos::io::{lifecycle, work_items};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
use crate::ntos::mm::pe_loader::LoadOptions;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::process;
use crate::ntos::ps::silo::query as silo_query;
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::privilege;

/// A raiz das chaves de serviço.
pub const SERVICES_ROOT: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services";

const STATUS_SUCCESS: u32 = 0;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_IMAGE_ALREADY_LOADED: u32 = 0xC000_010E;
const STATUS_ILL_FORMED_SERVICE_ENTRY: u32 = 0xC000_0160;
/// SeLoadDriverPrivilege.
const SE_LOAD_DRIVER_PRIVILEGE: u64 = 10;
/// NotificationEvent.
const NOTIFICATION_EVENT: u8 = 0;
const REG_SZ: u32 = 1;
const SERVICE_FILE_SYSTEM_DRIVER: u32 = 2;
const SERVICE_RECOGNIZER_DRIVER: u32 = 8;

/// O LOAD_PACKET do IopLoadDriverImage e do IopUnloadDriver (o bloco de
/// 0x50 bytes que eles montam na pilha).
#[repr(C)]
struct LoadPacket {
    work_queue_item: WorkQueueItem,
    event: Kevent,
    /// O driver a descarregar (nulo numa carga).
    driver_object: Field<u64>,
    /// -> `_UNICODE_STRING` com o nome da chave (numa carga).
    driver_service_name: Field<u64>,
    final_status: Field<u32>,
    _pad_4c: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for LoadPacket {}

const _: () = {
    assert!(core::mem::size_of::<LoadPacket>() == 0x50);
    assert!(core::mem::offset_of!(LoadPacket, event) == 0x20);
    assert!(core::mem::offset_of!(LoadPacket, driver_object) == 0x38);
    assert!(core::mem::offset_of!(LoadPacket, driver_service_name) == 0x40);
    assert!(core::mem::offset_of!(LoadPacket, final_status) == 0x48);
};

/// Um UNICODE_STRING capturado: Length, MaximumLength, Buffer e a cópia de
/// pool que o capturador libera (0 sem cópia).
#[derive(Clone, Copy)]
struct CapturedName {
    length: u16,
    maximum_length: u16,
    buffer: u64,
    pool: u64,
}

impl CapturedName {
    fn release(self) {
        if self.pool != 0 {
            guest::free_bytes(self.pool);
        }
    }
}

/// A captura de modo usuário do IopLoadDriverImage e do IopUnloadDriver: o
/// ProbeForRead do UNICODE_STRING (um ponteiro acima de MmUserProbeAddress
/// lê o próprio limite), Length diferente de zero, Buffer alinhado em WCHAR
/// e dentro do espaço de usuário, e a cópia do texto para o pool.
fn capture_user_name(pointer: u64) -> Result<CapturedName, u32> {
    let address = pointer.min(USER_PROBE_ADDRESS);
    let lengths = guest::try_read::<u32>(address).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let buffer = guest::try_read::<u64>(address + 8).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let (length, maximum_length) = (lengths as u16, (lengths >> 16) as u16);
    if length == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if buffer & 1 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    let end = buffer.wrapping_add(length as u64);
    if end > USER_PROBE_ADDRESS || end < buffer {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let text = guest::try_read_bytes(buffer, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let pool = guest::alloc_bytes(length as u64);
    if pool == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(pool, &text);
    Ok(CapturedName { length, maximum_length, buffer: pool, pool })
}

/// O UNICODE_STRING de um chamador de modo kernel, como está.
fn kernel_name(pointer: u64) -> Result<CapturedName, u32> {
    let lengths = guest::try_read::<u32>(pointer).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let buffer = guest::try_read::<u64>(pointer + 8).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    Ok(CapturedName { length: lengths as u16, maximum_length: (lengths >> 16) as u16, buffer, pool: 0 })
}

/// NtLoadDriver/ZwLoadDriver(DriverServiceName) de `previous_mode` (0
/// KernelMode, 1 UserMode): o IopLoadDriverImage.
pub fn load_driver_image(service_name: u64, previous_mode: u8) -> u32 {
    if service_name == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let captured = if previous_mode != 0 {
        if !privilege::single_privilege_check(SE_LOAD_DRIVER_PRIVILEGE, 1) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        if silo_query::is_current_thread_in_server_silo() {
            return STATUS_SUCCESS;
        }
        capture_user_name(service_name)
    } else {
        kernel_name(service_name)
    };
    let captured = match captured {
        Ok(captured) => captured,
        Err(status) => return status,
    };
    let status = run_packet(0, Some(captured));
    captured.release();
    status
}

/// NtUnloadDriver/ZwUnloadDriver(DriverServiceName) de `previous_mode`: o
/// IopUnloadDriver com InvalidateFlag FALSE.
pub fn unload_driver_image(service_name: u64, previous_mode: u8) -> u32 {
    if previous_mode != 0 {
        if !privilege::single_privilege_check(SE_LOAD_DRIVER_PRIVILEGE, 1) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        let captured = match capture_user_name(service_name) {
            Ok(captured) => captured,
            Err(status) => return status,
        };
        // A reentrada pelo ZwUnloadDriver: o resto em KernelMode.
        let status = unload_kernel(captured);
        captured.release();
        return status;
    }
    match kernel_name(service_name) {
        Ok(captured) => unload_kernel(captured),
        Err(status) => status,
    }
}

/// O texto de um nome capturado.
fn name_text(name: CapturedName) -> String {
    let bytes = guest::read_bytes(name.buffer, name.length as usize & !1);
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// O ramo de KernelMode do IopUnloadDriver.
fn unload_kernel(name: CapturedName) -> u32 {
    if silo_query::is_current_thread_in_server_silo() {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    let handle = match open_key(&name_text(name)) {
        Ok(handle) => handle,
        Err(status) => return status,
    };
    let object_name = driver_name_from_key(handle);
    registry::close_handle(handle);
    let object_name = match object_name {
        Ok(object_name) => object_name,
        Err(status) => return status,
    };
    let Some(node) = object_manager::lookup(&object_name) else { return STATUS_OBJECT_NAME_NOT_FOUND };
    let Some(entry) = object_manager::node(node).filter(|entry| entry.type_name == "Driver") else { return STATUS_OBJECT_TYPE_MISMATCH };
    let driver = entry.data.map_or(0, |data| data.native_pointer);
    if driver == 0 {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    // SAFETY: DRIVER_OBJECT nativo publicado no namespace e a extensão dele.
    let object = unsafe { DriverObject::at(driver) };
    let extension = object.driver_extension.get();
    // SAFETY: DriverExtension de um DRIVER_OBJECT vivo.
    let add_device = if extension != 0 { unsafe { DriverExtension::at(extension) }.add_device.get() } else { 0 };
    if object.driver_unload.get() == 0 || !lifecycle::has_image(driver) || add_device != 0 {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    run_packet(driver, None)
}

/// Monta o LOAD_PACKET e o entrega ao IopLoadUnloadDriver: direto no
/// processo System, senão numa worker do sistema, com quem chama à espera
/// do evento. Devolve o FinalStatus.
fn run_packet(driver_object: u64, name: Option<CapturedName>) -> u32 {
    let block = guest::alloc_bytes(LoadPacket::SIZE + UnicodeString::SIZE);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: bloco recém-alocado e zerado: o pacote e o UNICODE_STRING.
    let (packet, service_name) = unsafe { (LoadPacket::at(block), UnicodeString::at(block + LoadPacket::SIZE)) };
    dispatcher::initialize_event(packet.event.address(), NOTIFICATION_EVENT, false);
    packet.driver_object.set(driver_object);
    if let Some(name) = name {
        service_name.length.set(name.length);
        service_name.maximum_length.set(name.maximum_length);
        service_name.buffer.set(name.buffer);
        packet.driver_service_name.set(service_name.address());
    }
    if process::get_current_process() == process::get_system_process() {
        load_unload_driver(0, block);
    } else {
        work_items::queue_kernel_ex_work_item(packet.work_queue_item.address(), load_unload_driver, block);
        dispatcher::wait_for_single_object(packet.event.address(), 0, 0, false);
    }
    let status = packet.final_status.get();
    guest::free_bytes(block);
    status
}

/// IopLoadUnloadDriver(LoadPacket).
fn load_unload_driver(_device: u64, block: u64) {
    // SAFETY: o LOAD_PACKET de `run_packet`, vivo até o evento.
    let packet = unsafe { LoadPacket::at(block) };
    let driver = packet.driver_object.get();
    let status = if driver != 0 {
        if lifecycle::unload_driver_object(driver) { STATUS_SUCCESS } else { STATUS_INVALID_DEVICE_REQUEST }
    } else {
        match open_key(&guest_strings::read_unicode_string(packet.driver_service_name.get())) {
            Err(status) => status,
            Ok(handle) => {
                let status = load_driver(handle);
                lifecycle::run_reinitialization_routines();
                status
            }
        }
    };
    packet.final_status.set(status);
    dispatcher::set_event(packet.event.address());
}

/// IopOpenRegistryKey(Handle, NULL, KeyName, KEY_READ, FALSE): o handle de
/// kernel da chave, ou o status da abertura.
fn open_key(path: &str) -> Result<u32, u32> {
    match key_services::open_path(path, false) {
        Ok((0, handle)) => Ok(handle as u32),
        Ok((status, _)) => Err(status),
        Err(error) if error.status != 0 => Err(error.status),
        Err(_) => Err(STATUS_UNSUCCESSFUL),
    }
}

/// O texto de um valor de cadeia com o terminador (Length = DataLength - 2).
fn terminated_text(data: &[u8]) -> String {
    let text = &data[..data.len().saturating_sub(2)];
    let units: Vec<u16> = text.chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)])).collect();
    String::from_utf16_lossy(&units)
}

/// O nome da chave como está na hive (o Name do KEY_BASIC_INFORMATION).
fn key_name(handle: u32) -> Option<String> {
    registry::get_node(handle).and_then(|node| registry::with_node(node, |key| key.name()))
}

/// IopBuildFullDriverPath: o caminho NT da imagem do driver.
fn full_driver_path(handle: u32, key_name: &str) -> String {
    match registry::get_value(handle, "ImagePath").filter(|value| value.data.len() >= 2) {
        Some(value) => {
            let image = terminated_text(&value.data);
            if image.starts_with('\\') {
                image
            } else {
                format!("\\SystemRoot\\{image}")
            }
        }
        None => format!("\\SystemRoot\\System32\\Drivers\\{key_name}.SYS"),
    }
}

/// IopLoadDriver(KeyHandle, ...) sem modo de segurança nem banco de drivers
/// bloqueados; fecha a chave e devolve o status final (o do DriverEntry,
/// quando ele falha).
fn load_driver(handle: u32) -> u32 {
    let prepared = (|| -> Result<(String, String, String, String), u32> {
        let key_name = key_name(handle).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let image_name = full_driver_path(handle, &key_name);
        let object_name = driver_name_from_key(handle)?;
        // O RegistryPath do DriverEntry: o nome da chave aberta.
        let registry_path = registry::get_path(handle).unwrap_or_else(|| format!("{SERVICES_ROOT}\\{key_name}"));
        Ok((key_name, image_name, object_name, registry_path))
    })();
    registry::close_handle(handle);
    let (key_name, image_name, object_name, registry_path) = match prepared {
        Ok(prepared) => prepared,
        Err(status) => return status,
    };
    if object_manager::lookup(&object_name).is_some() {
        return STATUS_IMAGE_ALREADY_LOADED;
    }
    let file_path = match image_volume_path(&image_name) {
        Ok(file_path) => file_path,
        Err((3, _)) => return STATUS_OBJECT_PATH_NOT_FOUND,
        Err(_) => return STATUS_OBJECT_NAME_INVALID,
    };
    let options = lifecycle::DriverOptions { service_name: Some(key_name), registry_path: Some(registry_path), load: Some(LoadOptions { image_name: Some(image_name), ..Default::default() }), object_name: Some(object_name) };
    match lifecycle::load_driver(&file_path, &options) {
        Ok(_) => STATUS_SUCCESS,
        // O status da imagem ou o do DriverEntry (STATUS_FAILED_DRIVER_ENTRY
        // trocado pelo do DriverEntry, como no IopLoadUnloadDriver).
        Err(error) => error.ntstatus.unwrap_or(match error.win32_error {
            2 => STATUS_OBJECT_NAME_NOT_FOUND,
            1056 => STATUS_IMAGE_ALREADY_LOADED,
            _ => STATUS_UNSUCCESSFUL,
        }),
    }
}

/// IopGetDriverNameFromKeyNode(KeyHandle, DriverName): o nome do objeto do
/// driver da chave aberta em `handle`.
pub fn driver_name_from_key(handle: u32) -> Result<String, u32> {
    if let Some(value) = registry::get_value(handle, "ObjectName") {
        if value.value_type != REG_SZ || value.data.len() <= 2 {
            return Err(STATUS_ILL_FORMED_SERVICE_ENTRY);
        }
        return Ok(terminated_text(&value.data));
    }
    let Some(value) = registry::get_value(handle, "Type").filter(|value| !value.data.is_empty()) else { return Err(STATUS_ILL_FORMED_SERVICE_ENTRY) };
    let mut bytes = [0u8; 4];
    let count = value.data.len().min(4);
    bytes[..count].copy_from_slice(&value.data[..count]);
    let directory = match u32::from_le_bytes(bytes) {
        SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER => "\\FileSystem\\",
        _ => "\\Driver\\",
    };
    let key_name = key_name(handle).ok_or(STATUS_ILL_FORMED_SERVICE_ENTRY)?;
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

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    if text.len() >= prefix.len() && text.is_char_boundary(prefix.len()) && text[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&text[prefix.len()..])
    } else {
        None
    }
}

/// O caminho de uma imagem de driver no volume de boot do convidado: o
/// System32\Drivers da instalação fica na raiz do volume e o resto do
/// `\SystemRoot` sob `\Windows`. Recusa unidades indisponíveis (3),
/// componentes vazios, travessia e caracteres não admitidos (123).
pub fn image_volume_path(image_path: &str) -> Result<String, (u32, &'static str)> {
    let mut path = image_path;
    if path.len() >= 2 && path.starts_with('"') && path.ends_with('"') {
        path = &path[1..path.len() - 1];
    }
    let mut path = path.replace('/', "\\");
    for prefix in ["\\??\\", "\\\\?\\"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            path = String::from(rest);
            break;
        }
    }
    if let Some(rest) = strip_prefix_ci(&path, "%SystemRoot%\\") {
        path = format!("\\SystemRoot\\{rest}");
    }
    // ImagePath relativo é relativo a \SystemRoot, como no IopLoadDriver.
    if strip_prefix_ci(&path, "System32\\").is_some() {
        path = format!("\\SystemRoot\\{path}");
    }
    // Drivers de System32\Drivers ficam na raiz do volume do convidado.
    let relative = if let Some(rest) = strip_prefix_ci(&path, "\\SystemRoot\\System32\\Drivers\\") {
        String::from(rest)
    } else if let Some(rest) = strip_prefix_ci(&path, "C:\\Windows\\System32\\Drivers\\") {
        String::from(rest)
    } else if let Some(rest) = strip_prefix_ci(&path, "\\SystemRoot\\") {
        // O resto da instalação (o repositório de drivers em
        // System32\DriverStore) fica onde o \SystemRoot aponta: \Device\KernelVolume1\Windows.
        format!("Windows\\{rest}")
    } else if let Some(rest) = strip_prefix_ci(&path, "C:\\") {
        String::from(rest)
    } else if (path.len() >= 2 && path.as_bytes()[0].is_ascii_alphabetic() && path.as_bytes()[1] == b':') || path.starts_with('\\') {
        return Err((3, "driver volume/path unavailable"));
    } else {
        path
    };
    let components: Vec<&str> = relative.split('\\').collect();
    if components.iter().any(|component| component.is_empty() || *component == "." || *component == ".." || component.contains([':', '"', '\0'])) {
        return Err((123, "invalid driver path"));
    }
    Ok(format!("/{}", components.join("/")))
}
