//! Propriedades e chave de registro de um dispositivo — IoGetDeviceProperty
//! (as propriedades do devnode num PDO da árvore do PnP; nos outros,
//! PhysicalDeviceObjectName e HardwareID do PDO PCI), IoGetDevicePropertyData
//! e IoOpenDeviceRegistryKey (as chaves de hardware e de driver do devnode;
//! nos outros, a chave de serviço do driver dono).

use alloc::format;
use alloc::string::String;

use crate::drivers::bus::pci;
use crate::ntos::cm::key::services as key_services;
use crate::ntos::init::exports::signed_status;
use crate::ntos::io::{device, io_manager};
use crate::ntos::ob::object_manager;
use crate::rtl::KernelError;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{Devpropkey, NtStruct};
use crate::ntos::mm::guest_memory as guest;

/// Texto UTF-16 (sem terminador) no buffer do chamador, numa cópia.
fn write_wide(output: u64, text: &str) {
    let bytes: alloc::vec::Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(output, &bytes);
}

/// PULONG ResultLength do chamador de modo kernel.
fn result_length(returned: u64) -> &'static Field<u32> {
    // SAFETY: ponteiro de saída de um chamador de modo kernel.
    unsafe { Field::<u32>::at(returned) }
}

/// Propriedade de um devnode da árvore do PnP, em bytes (None = ausente).
/// DEVICE_REGISTRY_PROPERTY (wdm.h): textos com o NUL final, listas com o
/// NUL duplo, números de 32 bits, GUIDs de 16 bytes e listas de recursos.
fn devnode_property(node: &crate::ntos::io::pnp::devnode::DeviceNode, property: u32) -> Option<alloc::vec::Vec<u8>> {
    use crate::ntos::io::pnp::{devnode::capability, install};
    let key = format!("{}\\Enum\\{}", install::CONTROL_SET, node.instance_path);
    let text = |value: &str| -> alloc::vec::Vec<u8> {
        let mut bytes: alloc::vec::Vec<u8> = value.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0, 0]);
        bytes
    };
    // "@inf,%chave%;texto": o texto depois do ';'.
    let display = |value: String| -> String { if value.starts_with('@') { value.rsplit_once(';').map(|(_, text)| String::from(text)).unwrap_or(value) } else { value } };
    let resource_bytes = |list: u64| -> Option<alloc::vec::Vec<u8>> {
        let parsed = crate::ntos::io::pnp::resources::CmList::read(list)?;
        Some(guest::read_bytes(list, 20 + parsed.resources.len() * 20))
    };
    let number = |value: u32| Some(value.to_le_bytes().to_vec());
    match property {
        0x0 => install::read_text(&key, "DeviceDesc").map(display).or_else(|| node.description.clone()).map(|value| text(&value)),
        0x1 => (!node.hardware_ids.is_empty()).then(|| install::multi_sz_owned(&node.hardware_ids)),
        0x2 => (!node.compatible_ids.is_empty()).then(|| install::multi_sz_owned(&node.compatible_ids)),
        0x3 => resource_bytes(node.boot_resources),
        0x4 => resource_bytes(node.boot_resources),
        0x5 => install::read_text(&key, "Class").map(|value| text(&value)),
        0x6 => install::read_text(&key, "ClassGUID").map(|value| text(&value)),
        0x7 => install::read_text(&key, "Driver").map(|value| text(&value)),
        0x8 => install::read_text(&key, "Mfg").map(display).map(|value| text(&value)),
        0x9 => install::read_text(&key, "FriendlyName").map(|value| text(&value)),
        0xA => node.location.as_deref().map(text),
        0xB => {
            let name = crate::ntos::io::device::find_device_node_by_pointer(node.pdo).and_then(object_manager::path_of)?;
            Some(text(&name))
        }
        0xC => node.bus_information.map(|(guid, _, _)| guid.to_vec()),
        0xD => node.bus_information.and_then(|(_, legacy, _)| number(legacy as u32)),
        0xE => node.bus_information.and_then(|(_, _, bus)| number(bus)),
        0xF => node.instance_path.split('\\').next().map(text),
        0x10 => Some(node.capability_word(capability::ADDRESS)).filter(|&value| value != 0xFFFF_FFFF).and_then(number),
        0x11 => Some(node.capability_word(capability::UI_NUMBER)).filter(|&value| value != 0xFFFF_FFFF).and_then(number),
        // InstallStateInstalled (0) com serviço; InstallStateFailedInstall (2) sem.
        0x12 => number(if node.service.is_some() || node.internal_driver { 0 } else { 2 }),
        // RemovalPolicyExpectSurpriseRemoval (3) se Removable; senão ExpectNoRemoval (1).
        0x13 => number(if node.capability_bit(capability::REMOVABLE) { 3 } else { 1 }),
        0x15 => resource_bytes(node.resources_translated),
        _ => None,
    }
}

/// IoGetDeviceProperty(dev, property, bufferLength, buffer, resultLength):
/// para um PDO da árvore do PnP, as propriedades do devnode; nos demais,
/// PhysicalDeviceObjectName (0xB) e HardwareID (1) do PDO PCI.
pub fn get_device_property(device: u64, property: u32, size: u32, output: u64, returned: u64) -> u32 {
    if let Some(node) = crate::ntos::io::pnp::devnode::of_device(device) {
        let Some(bytes) = devnode_property(&node, property) else {
            result_length(returned).set(0);
            return 0xC000_0034;
        };
        result_length(returned).set(bytes.len() as u32);
        if (size as usize) < bytes.len() {
            return 0xC000_0023;
        }
        guest::write_bytes(output, &bytes);
        return 0;
    }
    let (text, needed) = if property == 0xB {
        let Some(node) = device::walk_physical(device, device::find_device_node_by_pointer) else { return 0xC000_0034 };
        let name = format!("\\Device\\{}", device::device_name(node));
        let needed = (name.encode_utf16().count() as u32 + 1) * 2;
        (name, needed)
    } else if property == 1 {
        let pci_function = device::walk_physical(device, |candidate| {
            pci::devices().into_iter().find(|function| object_manager::lookup(&format!("\\Device\\{}", function.pdo_name)).and_then(io_manager::device).is_some_and(|entry| entry.native_device == candidate))
        });
        let Some(function) = pci_function else { return 0xC000_0034 };
        let id = pci::hardware_id_of(&function);
        let needed = (id.encode_utf16().count() as u32 + 2) * 2;
        (id, needed)
    } else {
        return 0xC000_000D;
    };
    if size < needed {
        result_length(returned).set(needed);
        return 0xC000_0023;
    }
    write_wide(output, &text);
    if property == 0xB {
        guest::write_bytes(output + text.encode_utf16().count() as u64 * 2, &[0; 2]);
    }
    result_length(returned).set(needed);
    0
}

/// IoOpenDeviceRegistryKey(Device, DevInstKeyType, DesiredAccess, Key*).
/// Num PDO da árvore do PnP: PLUGPLAY_REGKEY_DEVICE (1) é
/// `Enum\<instância>\Device Parameters`, PLUGPLAY_REGKEY_DRIVER (2) é
/// `Control\Class\<valor Driver>`, e PLUGPLAY_REGKEY_CURRENT_HWPROFILE (4)
/// põe a chave sob `Hardware Profiles\Current\System\CurrentControlSet`;
/// as chaves são criadas se ainda não existem. Nos demais dispositivos, a
/// chave de serviço do driver dono. Devolve o valor do export: dispositivo
/// desconhecido com sinal, o status da abertura da chave sem sinal.
pub fn open_device_registry_key(device: u64, key_type: u32, output: u64) -> Result<u64, KernelError> {
    use crate::ntos::io::pnp::{devnode, install};
    if let Some(node) = devnode::get(device) {
        let base = if key_type & 4 != 0 { format!("{}\\Hardware Profiles\\Current\\System\\CurrentControlSet", install::CONTROL_SET) } else { String::from(install::CONTROL_SET) };
        let path = match key_type & 3 {
            1 => format!("{base}\\Enum\\{}\\Device Parameters", node.instance_path),
            2 => {
                let Some(driver) = install::read_text(&format!("{}\\Enum\\{}", install::CONTROL_SET, node.instance_path), "Driver") else { return Ok(signed_status(0xC000_0034)) };
                format!("{base}\\Control\\Class\\{driver}")
            }
            _ => return Ok(signed_status(0xC000_000D)),
        };
        let (status, handle) = key_services::open_path(&path, true)?;
        if status != 0 {
            return Ok(status as u64);
        }
        // SAFETY: PHANDLE do chamador de modo kernel.
        unsafe { Field::<u64>::at(output) }.set(handle);
        return Ok(0);
    }
    let driver_node = io_manager::devices().into_iter().filter(|(_, entry)| entry.native_device == device).filter_map(|(_, entry)| entry.driver).last();
    let Some(driver_node) = driver_node else { return Ok(signed_status(0xC000_0034)) };
    let name = object_manager::node(driver_node).map(|node| node.name).unwrap_or_default();
    let (status, handle) = key_services::open_path(&format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{name}"), false)?;
    if status != 0 {
        return Ok(status as u64);
    }
    // SAFETY: PHANDLE do chamador de modo kernel.
    unsafe { Field::<u64>::at(output) }.set(handle);
    Ok(0)
}

// ---- Propriedades DEVPROPKEY (IoSet/IoGetDevicePropertyData, interfaces) -------
//
// Propriedades unificadas de dispositivo e de interface (DEVPROPKEY), o
// armazenamento que o PnP mantém por devnode e por interface (NT:
// PnP Manager, sobre o PiPnpRtl*ObjectProperty).
//
// Comportamento conferido contra o ntoskrnl 19041:
//   IoSetDevicePropertyData rva 0x743140 -> PnpSetDevicePropertyData 0x742f9c
//     PDO NULL ou sem devnode: KeBugCheckEx(PNP_DETECTED_FATAL_ERROR 0xCA, 2, ...);
//     devnode sem instância: STATUS_INVALID_DEVICE_REQUEST; Lcid != 0 passa por
//     RtlLCIDToCultureName (falha = STATUS_UNSUCCESSFUL); Data NULL zera Type e
//     Size (DEVPROP_TYPE_EMPTY apaga a propriedade); STATUS_NOT_FOUND do
//     armazenamento vira STATUS_OBJECT_NAME_NOT_FOUND.
//   IoSetDeviceInterfacePropertyData rva 0x77dc80 -> PnpSetDeviceInterfacePropertyData
//     0x77dcc8: SymbolicLinkName NULL/vazio = STATUS_INVALID_PARAMETER; mesma
//     regra de Lcid, Type/Size e NOT_FOUND -> OBJECT_NAME_NOT_FOUND (interface
//     inexistente).
//   IoGetDevicePropertyData rva 0x6b2e90 -> PnpGetDevicePropertyData 0x6b2ef8:
//     ausente = STATUS_OBJECT_NAME_NOT_FOUND; buffer pequeno =
//     STATUS_BUFFER_TOO_SMALL com RequiredSize e Type preenchidos.
//
// O armazenamento do OpenNT é volátil (o PiPnpRtl do NT persiste no
// registro só com PLUGPLAY_PERSISTENT; o OpenNT não tem a árvore
// Enum de devnodes). Diferenças honestas: um DEVICE_OBJECT que não é PDO do
// PnP do OpenNT recebe STATUS_INVALID_DEVICE_REQUEST em vez do bugcheck
// (o OpenNT não distingue "sem devnode" de "devnode sem instância"), e o
// LCID não é validado (não há tabela LCID -> nome de cultura).

const PROPERTY_STATUS_SUCCESS: u32 = 0;
const PROPERTY_STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const PROPERTY_STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const PROPERTY_STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const PROPERTY_STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const PROPERTY_DEVPROP_TYPE_EMPTY: u32 = 0;

/// Dono de uma propriedade: o PDO ou o link simbólico da interface.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Owner {
    Device(u64),
    Interface(alloc::string::String),
}

/// DEVPROPKEY (fmtid + pid) e LCID.
type PropertyKey = (Owner, [u8; 16], u32, u32);

static PROPERTIES: crate::rtl::SpinLock<alloc::collections::BTreeMap<PropertyKey, (u32, alloc::vec::Vec<u8>)>> = crate::rtl::SpinLock::new(alloc::collections::BTreeMap::new());

fn read_key(owner: Owner, key: &Devpropkey, lcid: u32) -> PropertyKey {
    let mut fmtid = [0u8; 16];
    fmtid.copy_from_slice(&guest::read_bytes(key.fmtid.address(), 16));
    (owner, fmtid, key.pid.get(), lcid)
}

/// PDO do PnP do OpenNT: devnode da árvore, filho enumerado, PDO de
/// barramento ou relatado.
fn is_pnp_device(pdo: u64) -> bool {
    crate::ntos::io::pnp::devnode::exists(pdo) || io_manager::devices().into_iter().any(|(_, entry)| entry.native_device == pdo && (entry.pdo || entry.extra.is_some()))
}

fn store(key: PropertyKey, property_type: u32, size: u32, data: u64) -> u32 {
    let (property_type, size) = if data == 0 { (PROPERTY_DEVPROP_TYPE_EMPTY, 0) } else { (property_type, size) };
    let mut properties = PROPERTIES.lock();
    if property_type == PROPERTY_DEVPROP_TYPE_EMPTY {
        properties.remove(&key);
        return PROPERTY_STATUS_SUCCESS;
    }
    properties.insert(key, (property_type, guest::read_bytes(data, size as usize)));
    PROPERTY_STATUS_SUCCESS
}

/// O valor de uma propriedade DEVPROPKEY do PDO (LCID neutro): tipo e bytes.
pub fn device_property_value(pdo: u64, fmtid: [u8; 16], pid: u32) -> Option<(u32, alloc::vec::Vec<u8>)> {
    PROPERTIES.lock().get(&(Owner::Device(pdo), fmtid, pid, 0)).cloned()
}

/// Grava uma propriedade DEVPROPKEY do PDO (LCID neutro) pelo próprio PnP
/// (o _PnpSetObjectProperty interno, sem as validações do export);
/// DEVPROP_TYPE_EMPTY apaga.
pub fn store_device_property(pdo: u64, fmtid: [u8; 16], pid: u32, property_type: u32, bytes: &[u8]) {
    let key = (Owner::Device(pdo), fmtid, pid, 0);
    let mut properties = PROPERTIES.lock();
    if property_type == PROPERTY_DEVPROP_TYPE_EMPTY {
        properties.remove(&key);
    } else {
        properties.insert(key, (property_type, bytes.to_vec()));
    }
}

/// IoSetDevicePropertyData(Pdo, PropertyKey, Lcid, Flags, Type, Size, Data).
pub fn set_device_property(pdo: u64, key: &Devpropkey, lcid: u32, _flags: u32, property_type: u32, size: u32, data: u64) -> u32 {
    if pdo == 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(0xCA, 2, 0, 0, key.address());
    }
    if !is_pnp_device(pdo) {
        return PROPERTY_STATUS_INVALID_DEVICE_REQUEST;
    }
    store(read_key(Owner::Device(pdo), key, lcid), property_type, size, data)
}

/// IoSetDeviceInterfacePropertyData(SymbolicLinkName, PropertyKey, Lcid,
/// Flags, Type, Size, Data).
pub fn set_interface_property(link: u64, key: &Devpropkey, lcid: u32, _flags: u32, property_type: u32, size: u32, data: u64) -> u32 {
    if link == 0 {
        return PROPERTY_STATUS_INVALID_PARAMETER;
    }
    // SAFETY: PUNICODE_STRING de um chamador de modo kernel.
    let string = unsafe { crate::ntos::inc::types::UnicodeString::at(link) };
    if string.buffer.get() == 0 || string.length.get() == 0 {
        return PROPERTY_STATUS_INVALID_PARAMETER;
    }
    let name = crate::ntos::rtl::guest_strings::read_unicode_string(link);
    if crate::ntos::io::device_interface::interface_enabled(&name).is_none() {
        return PROPERTY_STATUS_OBJECT_NAME_NOT_FOUND;
    }
    store(read_key(Owner::Interface(name), key, lcid), property_type, size, data)
}

/// DEVPKEY_Device_* {a45c254e-df1c-4efd-8020-67d146a850e0} (devpkey.h).
const DEVPKEY_DEVICE: [u8; 16] = [0x4E, 0x25, 0x5C, 0xA4, 0x1C, 0xDF, 0xFD, 0x4E, 0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0];
/// DEVPROP_TYPE_STRING, DEVPROP_TYPE_STRING_LIST e DEVPROP_TYPE_GUID.
const DEVPROP_TYPE_STRING: u32 = 0x12;
const DEVPROP_TYPE_STRING_LIST: u32 = 0x2012;
const DEVPROP_TYPE_GUID: u32 = 0x0D;

/// GUID binário de um texto "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}".
fn parse_guid(text: &str) -> Option<[u8; 16]> {
    let hex: alloc::vec::Vec<u8> = text.chars().filter(|character| character.is_ascii_hexdigit()).map(|character| character.to_digit(16).unwrap_or(0) as u8).collect();
    if hex.len() != 32 {
        return None;
    }
    let byte = |index: usize| hex[index * 2] << 4 | hex[index * 2 + 1];
    let mut guid = [0u8; 16];
    // Data1, Data2 e Data3 little-endian; Data4 na ordem do texto.
    for (target, source) in [(0, 3), (1, 2), (2, 1), (3, 0), (4, 5), (5, 4), (6, 7), (7, 6)] {
        guid[target] = byte(source);
    }
    for index in 8..16 {
        guid[index] = byte(index);
    }
    Some(guid)
}

/// As propriedades DEVPKEY_Device_* que o PnP manager guarda no devnode e
/// na chave da instância: DeviceDesc (2), HardwareIds (3), CompatibleIds
/// (4), Service (6), Class (9), ClassGuid (10), Driver (11), Manufacturer
/// (13), LocationInfo (15) e PDOName (16).
fn standard_device_property(node: &crate::ntos::io::pnp::devnode::DeviceNode, fmtid: &[u8; 16], pid: u32) -> Option<(u32, alloc::vec::Vec<u8>)> {
    use crate::ntos::io::pnp::install;
    if *fmtid != DEVPKEY_DEVICE {
        return None;
    }
    let instance = format!("{}\\Enum\\{}", install::CONTROL_SET, node.instance_path);
    let text = |value: String| -> (u32, alloc::vec::Vec<u8>) { (DEVPROP_TYPE_STRING, crate::ntos::cm::registry::encode_wide(&value)) };
    let display = |value: String| -> String { if value.starts_with('@') { value.rsplit_once(';').map(|(_, text)| String::from(text)).unwrap_or(value) } else { value } };
    match pid {
        2 => install::read_text(&instance, "DeviceDesc").map(display).map(text),
        3 => (!node.hardware_ids.is_empty()).then(|| (DEVPROP_TYPE_STRING_LIST, install::multi_sz_owned(&node.hardware_ids))),
        4 => (!node.compatible_ids.is_empty()).then(|| (DEVPROP_TYPE_STRING_LIST, install::multi_sz_owned(&node.compatible_ids))),
        6 => node.service.clone().map(text),
        9 => install::read_text(&instance, "Class").map(text),
        10 => install::read_text(&instance, "ClassGUID").and_then(|guid| parse_guid(&guid)).map(|guid| (DEVPROP_TYPE_GUID, guid.to_vec())),
        11 => install::read_text(&instance, "Driver").map(text),
        13 => install::read_text(&instance, "Mfg").map(display).map(text),
        15 => node.location.clone().map(text),
        16 => device::find_device_node_by_pointer(node.pdo).and_then(object_manager::path_of).map(text),
        _ => None,
    }
}

/// IoGetDevicePropertyData(Pdo, PropertyKey, Lcid, Flags, Size, Data,
/// RequiredSize*, Type*).
#[allow(clippy::too_many_arguments)]
pub fn query_device_property_data(pdo: u64, key: &Devpropkey, lcid: u32, _flags: u32, size: u32, data: u64, required: &Field<u32>, type_output: &Field<u32>) -> u32 {
    if pdo == 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(0xCA, 2, 0, 0, key.address());
    }
    if !is_pnp_device(pdo) {
        return PROPERTY_STATUS_INVALID_DEVICE_REQUEST;
    }
    let property_key = read_key(Owner::Device(pdo), key, lcid);
    let stored = PROPERTIES.lock().get(&property_key).cloned();
    let found = stored.or_else(|| crate::ntos::io::pnp::devnode::get(pdo).and_then(|node| standard_device_property(&node, &property_key.1, property_key.2)));
    answer_property(found, size, data, required, type_output)
}

/// Um objeto do PnP pelo nome, como o PiCMGetObjectProperty o entrega ao
/// _PnpGetObjectProperty: o caminho de instância de um dispositivo ou o
/// link simbólico de uma interface.
pub enum NamedObject<'a> {
    Device(&'a str),
    Interface(&'a str),
}

/// A propriedade DEVPROPKEY (LCID neutro) de um objeto nomeado:
/// `Ok((tipo, bytes))`, ou STATUS_NOT_FOUND (propriedade ou interface
/// ausente, o status do armazenamento antes da troca que o
/// IoGet*PropertyData faz) e STATUS_NO_SUCH_DEVICE (instância sem devnode).
pub fn named_object_property(object: NamedObject, fmtid: [u8; 16], pid: u32) -> Result<(u32, alloc::vec::Vec<u8>), u32> {
    const STATUS_NOT_FOUND: u32 = 0xC000_0225;
    const STATUS_NO_SUCH_DEVICE: u32 = 0xC000_000E;
    match object {
        NamedObject::Device(instance) => {
            let Some(node) = crate::ntos::io::pnp::devnode::by_instance_path(instance).and_then(crate::ntos::io::pnp::devnode::get) else { return Err(STATUS_NO_SUCH_DEVICE) };
            let stored = PROPERTIES.lock().get(&(Owner::Device(node.pdo), fmtid, pid, 0)).cloned();
            stored.or_else(|| standard_device_property(&node, &fmtid, pid)).ok_or(STATUS_NOT_FOUND)
        }
        NamedObject::Interface(link) => {
            if crate::ntos::io::device_interface::interface_enabled(link).is_none() {
                return Err(STATUS_NOT_FOUND);
            }
            PROPERTIES.lock().get(&(Owner::Interface(String::from(link)), fmtid, pid, 0)).cloned().ok_or(STATUS_NOT_FOUND)
        }
    }
}

/// Leitura do armazenamento: a propriedade guardada pela chave.
fn read_property(key: &PropertyKey, size: u32, data: u64, required: &Field<u32>, type_output: &Field<u32>) -> u32 {
    let found = PROPERTIES.lock().get(key).cloned();
    answer_property(found, size, data, required, type_output)
}

/// Resposta comum: ausente = STATUS_OBJECT_NAME_NOT_FOUND; buffer pequeno =
/// STATUS_BUFFER_TOO_SMALL com RequiredSize e Type preenchidos.
fn answer_property(found: Option<(u32, alloc::vec::Vec<u8>)>, size: u32, data: u64, required: &Field<u32>, type_output: &Field<u32>) -> u32 {
    let Some((property_type, bytes)) = found else { return PROPERTY_STATUS_OBJECT_NAME_NOT_FOUND };
    required.set(bytes.len() as u32);
    type_output.set(property_type);
    if (size as usize) < bytes.len() {
        return PROPERTY_STATUS_BUFFER_TOO_SMALL;
    }
    guest::write_bytes(data, &bytes);
    PROPERTY_STATUS_SUCCESS
}

/// IoGetDeviceInterfacePropertyData(SymbolicLinkName, PropertyKey, Lcid,
/// Flags, Size, Data, RequiredSize*, Type*): no ntoskrnl 19041 (0x89e320 ->
/// PnpGetDeviceInterfacePropertyData 0x8a28d0) o link NULL, sem buffer ou
/// vazio dá STATUS_INVALID_PARAMETER antes de tudo, Flags não é lido e o
/// STATUS_NOT_FOUND do armazenamento (interface ou propriedade ausente) vira
/// STATUS_OBJECT_NAME_NOT_FOUND; o resto é a leitura comum.
#[allow(clippy::too_many_arguments)]
pub fn query_interface_property_data(link: u64, key: &Devpropkey, lcid: u32, _flags: u32, size: u32, data: u64, required: &Field<u32>, type_output: &Field<u32>) -> u32 {
    if link == 0 {
        return PROPERTY_STATUS_INVALID_PARAMETER;
    }
    // SAFETY: PUNICODE_STRING de um chamador de modo kernel.
    let string = unsafe { crate::ntos::inc::types::UnicodeString::at(link) };
    if string.buffer.get() == 0 || string.length.get() == 0 {
        return PROPERTY_STATUS_INVALID_PARAMETER;
    }
    let name = crate::ntos::rtl::guest_strings::read_unicode_string(link);
    if crate::ntos::io::device_interface::interface_enabled(&name).is_none() {
        return PROPERTY_STATUS_OBJECT_NAME_NOT_FOUND;
    }
    read_property(&read_key(Owner::Interface(name), key, lcid), size, data, required, type_output)
}
