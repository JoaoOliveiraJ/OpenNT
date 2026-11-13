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
use crate::ntos::mm::guest_memory as guest;

fn write_wide(output: u64, text: &str) {
    for (index, unit) in text.encode_utf16().enumerate() {
        guest::write16(output + index as u64 * 2, unit);
    }
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
        guest::write32(returned, needed);
        return 0xC000_0023;
    }
    write_wide(output, &text);
    if property == 0xB {
        guest::write16(output + text.encode_utf16().count() as u64 * 2, 0);
    }
    guest::write32(returned, needed);
    0
}

/// IoGetDevicePropertyData: propriedade desconhecida = STATUS_NOT_FOUND.
pub fn get_device_property_data(pdo: u64, key: u64) -> u32 {
    debug_print!("[io] DevicePropertyData: pdo 0x{:x} key fmtid {:x}-{:x}-{:x} pid {}", pdo, guest::read32(key), guest::read16(key + 4), guest::read16(key + 6), guest::read32(key + 16));
    0xC000_0225
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
    guest::write64(output, handle);
    Ok(0)
}
