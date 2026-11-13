//! Propriedades e chave de registro de um dispositivo — IoGetDeviceProperty
//! (PhysicalDeviceObjectName e HardwareID do PDO PCI), IoGetDevicePropertyData
//! e IoOpenDeviceRegistryKey (a chave de serviço do driver dono).

use alloc::format;

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

/// IoGetDeviceProperty(dev, property, bufferLength, buffer, resultLength):
/// PhysicalDeviceObjectName (0xB) e HardwareID (1) do PDO PCI.
pub fn get_device_property(device: u64, property: u32, size: u32, output: u64, returned: u64) -> u32 {
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

/// IoOpenDeviceRegistryKey: a chave de serviço do driver dono. Devolve o
/// valor do export: dispositivo desconhecido com sinal, o status da
/// abertura da chave sem sinal.
pub fn open_device_registry_key(device: u64, output: u64) -> Result<u64, KernelError> {
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
// io\pnpmgr\pnpprop.c sobre o PiPnpRtl*ObjectProperty).
//
// Transcrição do ntoskrnl 19041:
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

/// PDO do PnP do OpenNT: filho enumerado, PDO de barramento ou relatado.
fn is_pnp_device(pdo: u64) -> bool {
    io_manager::devices().into_iter().any(|(_, entry)| entry.native_device == pdo && (entry.pdo || entry.extra.is_some()))
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
    let found = PROPERTIES.lock().get(&read_key(Owner::Device(pdo), key, lcid)).cloned();
    let Some((property_type, bytes)) = found else { return PROPERTY_STATUS_OBJECT_NAME_NOT_FOUND };
    required.set(bytes.len() as u32);
    type_output.set(property_type);
    if (size as usize) < bytes.len() {
        return PROPERTY_STATUS_BUFFER_TOO_SMALL;
    }
    guest::write_bytes(data, &bytes);
    PROPERTY_STATUS_SUCCESS
}
