//! Interfaces de dispositivo — IoRegisterDeviceInterface e
//! IoSetDeviceInterfaceState.
//!
//! Cada interface é um link `\DosDevices\#{guid}` para o dispositivo,
//! registrada desabilitada; habilitar ou desabilitar dispara as
//! notificações PnP da classe (`pnp_notify`).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::io::{device, io_manager, pnp_notify};
use crate::ntos::ob::object_manager;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Guid, NtStruct, UnicodeString};
use crate::ntos::rtl::guest_strings;

/// Interface de dispositivo: estado e GUID da classe.
struct DeviceInterface {
    enabled: bool,
    class: [u8; 16],
}

static DEVICE_INTERFACES: SpinLock<BTreeMap<String, DeviceInterface>> = SpinLock::new(BTreeMap::new());

/// Texto do GUID no formato do RtlStringFromGUID, em minúsculas (como os
/// links de interface do NT).
fn guid_string(bytes: &[u8]) -> String {
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let tail: String = bytes[10..16].iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{{{data1:08x}-{data2:04x}-{data3:04x}-{:02x}{:02x}-{tail}}}", bytes[8], bytes[9])
}

/// IoRegisterDeviceInterface(PDO, Guid, ReferenceString, SymbolicLinkName).
/// Num PDO da árvore do PnP o link é o do NT,
/// `\??\<instância com '\' trocado por '#'>#{guid}[\referência]`, apontando
/// para o nome do PDO; nos demais, `\DosDevices\#{guid}`. Registrada
/// desabilitada.
pub fn register_device_interface(physical: u64, guid: u64, reference: u64, output: u64) -> Result<u32, KernelError> {
    let guid_bytes = guest::read_bytes(guid, Guid::SIZE as usize);
    let (link, target) = match crate::ntos::io::pnp::devnode::get(physical) {
        Some(node) => {
            let Some(target) = device::find_device_node_by_pointer(physical).and_then(object_manager::path_of) else { return Ok(0xC000_0010) };
            let suffix = if reference != 0 { guest_strings::read_unicode_string(reference) } else { String::new() };
            let mut link = format!("\\??\\{}#{}", node.instance_path.replace('\\', "#"), guid_string(&guid_bytes));
            if !suffix.is_empty() {
                link = format!("{link}\\{suffix}");
            }
            (link, target)
        }
        None => {
            let guid_text: String = guid_bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
            let device = io_manager::devices().into_iter().filter(|(node, entry)| entry.native_device == physical && object_manager::path_of(*node).is_some_and(|path| path.matches('\\').count() == 2)).map(|(node, _)| device::device_name(node)).last().unwrap_or_else(|| String::from("PDO0"));
            (format!("\\DosDevices\\#{{{guid_text}}}"), format!("\\Device\\{device}"))
        }
    };
    // Um link já registrado (o mesmo PDO pedindo a mesma interface) é reusado.
    let known = DEVICE_INTERFACES.lock().contains_key(&link);
    if !known {
        if let Err(error) = object_manager::create_symlink(&link, &target) {
            return device::kernel_status(error);
        }
    }
    let mut class = [0u8; 16];
    class.copy_from_slice(&guid_bytes);
    DEVICE_INTERFACES.lock().entry(link.clone()).or_insert(DeviceInterface { enabled: false, class });
    let length = link.encode_utf16().count() as u64 * 2;
    let buffer = guest::alloc_bytes(length + 2);
    guest_strings::write_wide_string(buffer, &link);
    // SAFETY: PUNICODE_STRING SymbolicLinkName de saída do chamador de modo kernel.
    let link_name = unsafe { UnicodeString::at(output) };
    link_name.length.set(length as u16);
    link_name.maximum_length.set(length as u16 + 2);
    link_name.buffer.set(buffer);
    Ok(0)
}

/// IoSetDeviceInterfaceState: habilitar dispara as notificações PnP.
pub fn set_device_interface_state(link_pointer: u64, enabled: bool) -> u32 {
    let link = guest_strings::read_unicode_string(link_pointer);
    let (changed, class) = {
        let mut interfaces = DEVICE_INTERFACES.lock();
        let Some(entry) = interfaces.get_mut(&link) else { return 0xC000_0034 };
        let changed = entry.enabled != enabled;
        entry.enabled = enabled;
        (changed, entry.class)
    };
    // Chegada ou remoção só na transição, para os registros da classe.
    if changed {
        pnp_notify::notify_interface_change(enabled, &class, &link);
    }
    0
}

/// Links das interfaces habilitadas de uma classe.
pub fn enabled_links(class: &[u8; 16]) -> Vec<String> {
    DEVICE_INTERFACES.lock().iter().filter(|(_, entry)| entry.enabled && entry.class == *class).map(|(link, _)| link.clone()).collect()
}

/// Interface de dispositivo habilitada.
pub fn interface_enabled(link: &str) -> Option<bool> {
    DEVICE_INTERFACES.lock().get(link).map(|entry| entry.enabled)
}

/// Links das interfaces de uma classe — o filtro do IopGetDeviceInterfaces
/// (ntoskrnl 19041 rva 0x6b32e8): só as habilitadas, ou todas com
/// DEVICE_INTERFACE_INCLUDE_NONACTIVE (`include_inactive`).
pub fn class_links(class: &[u8; 16], include_inactive: bool) -> Vec<String> {
    DEVICE_INTERFACES.lock().iter().filter(|(_, entry)| entry.class == *class && (include_inactive || entry.enabled)).map(|(link, _)| link.clone()).collect()
}
