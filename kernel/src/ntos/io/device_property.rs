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

/// IoGetDevicePropertyData: propriedade desconhecida = STATUS_NOT_FOUND.
pub fn get_device_property_data(pdo: u64, key: u64) -> u32 {
    // SAFETY: DEVPROPKEY do chamador de modo kernel.
    let property = unsafe { Devpropkey::at(key) };
    debug_print!("[io] DevicePropertyData: pdo 0x{:x} key fmtid {:x}-{:x}-{:x} pid {}", pdo, property.fmtid.data1.get(), property.fmtid.data2.get(), property.fmtid.data3.get(), property.pid.get());
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
    // SAFETY: PHANDLE do chamador de modo kernel.
    unsafe { Field::<u64>::at(output) }.set(handle);
    Ok(0)
}
