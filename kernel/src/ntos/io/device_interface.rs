//! Interfaces de dispositivo — IoRegisterDeviceInterface,
//! IoSetDeviceInterfaceState, IoOpenDeviceInterfaceRegistryKey e
//! IoGetDeviceInterfaceAlias.
//!
//! Cada interface é um link `\DosDevices\#{guid}` para o dispositivo,
//! registrada desabilitada; habilitar ou desabilitar dispara as
//! notificações PnP da classe (`pnp_notify`). As interfaces de um PDO do PnP
//! têm as chaves do NT em `Control\DeviceClasses` (a da interface com
//! DeviceInstance e a da referência, "#" + referência, com SymbolicLink),
//! onde o IoOpenDeviceInterfaceRegistryKey abre `Device Parameters`.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::registry as cm_registry;
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

/// O nome do link de interface sem a referência (`...#{guid}`).
fn symbolic_link_base(link: &str) -> &str {
    match link.find("}\\") {
        Some(end) => &link[..=end],
        None => link,
    }
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
    if let Some(node) = crate::ntos::io::pnp::devnode::get(physical) {
        let units: Vec<u16> = link.encode_utf16().collect();
        if let Ok((class, subkey)) = interface_subkey(&units) {
            let interface = subkey.split('\\').next().unwrap_or_default();
            write_text_value(&format!("{DEVICE_CLASSES}\\{class}\\{interface}"), "DeviceInstance", &node.instance_path)?;
            write_text_value(&format!("{DEVICE_CLASSES}\\{class}\\{subkey}"), "SymbolicLink", &format!("\\\\?\\{}", &link[4..]))?;
        }
    }
    // O link simbólico do Object Manager tem o nome sem a referência: quem
    // abre `<link>\<referência>` chega ao PDO com a referência como resto do
    // nome (o FileName do IRP_MJ_CREATE), como no NT. Um link já registrado
    // (o mesmo PDO pedindo a mesma interface, com qualquer referência) é
    // reusado.
    let base = symbolic_link_base(&link);
    let known = DEVICE_INTERFACES.lock().keys().any(|registered| symbolic_link_base(registered) == base);
    if !known {
        // Os links de interface ficam no \GLOBAL?? (o \?? é o mapa de quem chama).
        let global = base.strip_prefix("\\??\\").or_else(|| base.strip_prefix("\\DosDevices\\")).map_or_else(|| String::from(base), |rest| format!("\\GLOBAL??\\{rest}"));
        if let Err(error) = object_manager::create_symlink(&global, &target) {
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
        if enabled {
            crate::drivers::video::display_stack::interface_enabled(&class, &link);
        }
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

// ---- IoOpenDeviceInterfaceRegistryKey (ntoskrnl 19041 0x7ccc50) --------------
//
// IoOpenDeviceInterfaceRegistryKey(SymbolicLinkName, DesiredAccess,
// DeviceInterfaceKey*): UNICODE_STRING NULL, sem Buffer ou vazia =
// STATUS_INVALID_PARAMETER; sob o PnpRegistryDeviceResource, o
// _CmOpenDeviceInterfaceRegKey (tipo 0x32, criando) abre
// `Control\DeviceClasses\<GUID>\##?#<nome>\#<referência>\Device Parameters`.
// O nome é validado como no _CmValidateDeviceInterfaceName: ao menos 49
// caracteres, prefixo "\??\" ou "\\?\" (com caixa), no máximo uma barra
// depois do prefixo, ao menos 48 caracteres antes dela e o GUID nos 38
// caracteres finais dessa parte (senão STATUS_OBJECT_NAME_INVALID); a chave
// da referência precisa existir (interface registrada, senão
// STATUS_OBJECT_NAME_NOT_FOUND) e `Device Parameters` é criada nela.

const DEVICE_CLASSES: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\DeviceClasses";
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;

/// "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}", o formato do RtlGUIDFromString.
fn guid_text(units: &[u16]) -> bool {
    units.len() == 38
        && units.iter().enumerate().all(|(index, &unit)| match index {
            0 => unit == b'{' as u16,
            37 => unit == b'}' as u16,
            9 | 14 | 19 | 24 => unit == b'-' as u16,
            _ => unit < 0x80 && (unit as u8).is_ascii_hexdigit(),
        })
}

/// O GUID da classe e o caminho da chave da referência
/// (`##?#<nome>\#<referência>`) de um link de interface.
fn interface_subkey(units: &[u16]) -> Result<(String, String), u32> {
    let prefixed = |prefix: &str| units.len() >= 4 && prefix.encode_utf16().eq(units[..4].iter().copied());
    if (units.len() * 2) & 0xFFFE < 0x62 || !(prefixed("\\??\\") || prefixed("\\\\?\\")) {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let slashes: Vec<usize> = units.iter().enumerate().skip(4).filter(|&(_, &unit)| unit == b'\\' as u16).map(|(index, _)| index).collect();
    if slashes.len() > 1 {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let end = slashes.first().copied().unwrap_or(units.len());
    if end < 0x30 || !guid_text(&units[end - 38..end]) {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let text = |slice: &[u16]| String::from_utf16_lossy(slice);
    let reference = if end < units.len() { text(&units[end + 1..]) } else { String::new() };
    Ok((text(&units[end - 38..end]), format!("##?#{}\\#{reference}", text(&units[4..end]))))
}

/// Cria a árvore de chaves abaixo de `Control` nível a nível (o
/// PnpCtxRegCreateTree) e devolve o handle da última.
fn create_key_tree(path: &str) -> Result<(u32, u64), KernelError> {
    const CONTROL: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control";
    let Some(rest) = path.strip_prefix(CONTROL) else { return key_services::open_path(path, true) };
    let mut current = String::from(CONTROL);
    let mut opened = (0xC000_0034, 0);
    for component in rest.split('\\').filter(|component| !component.is_empty()) {
        if opened.1 != 0 {
            cm_registry::close_handle(opened.1 as u32);
        }
        current.push('\\');
        current.push_str(component);
        opened = key_services::open_path(&current, true)?;
        if opened.0 != 0 {
            return Ok(opened);
        }
    }
    Ok(opened)
}

/// Cria a chave (e as de cima) e grava um REG_SZ.
fn write_text_value(path: &str, name: &str, text: &str) -> Result<(), KernelError> {
    let (status, handle) = create_key_tree(path)?;
    if status != 0 {
        return Ok(());
    }
    let mut bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes.extend_from_slice(&[0, 0]);
    let result = key_services::named_value(key_services::Kind::Set, handle, name, 1, &bytes);
    cm_registry::close_handle(handle as u32);
    result.map(|_| ())
}

/// IoOpenDeviceInterfaceRegistryKey: devolve o NTSTATUS.
pub fn open_interface_registry_key(link_pointer: u64, output: u64) -> Result<u32, KernelError> {
    if link_pointer == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: PUNICODE_STRING do chamador de modo kernel.
    let link = unsafe { UnicodeString::at(link_pointer) };
    if link.buffer.get() == 0 || link.length.get() == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let units = guest_strings::try_read_unicode_units(link_pointer)?;
    let (class, subkey) = match interface_subkey(&units) {
        Ok(found) => found,
        Err(status) => return Ok(status),
    };
    let instance = format!("{DEVICE_CLASSES}\\{class}\\{subkey}");
    let (status, handle) = key_services::open_path(&instance, false)?;
    if status != 0 {
        return Ok(status);
    }
    cm_registry::close_handle(handle as u32);
    let (status, handle) = key_services::open_path(&format!("{instance}\\Device Parameters"), true)?;
    if status != 0 {
        return Ok(status);
    }
    // SAFETY: PHANDLE de saída do chamador de modo kernel.
    unsafe { crate::ntos::inc::types::Field::<u64>::at(output) }.set(handle);
    Ok(0)
}

// ---- IoGetDeviceInterfaceAlias (ntoskrnl 19041 0x72bdf0) ---------------------
//
// IoGetDeviceInterfaceAlias(SymbolicLinkName, AliasInterfaceClassGuid,
// AliasSymbolicLinkName): UNICODE_STRING NULL, sem Buffer ou vazia, ou nome
// que o _CmValidateDeviceInterfaceName recusa = STATUS_INVALID_PARAMETER (o
// filtro obrigatório do PiPnpRtl deixa o chamador de kernel ver toda
// interface). Sob o PnpRegistryDeviceResource: a instância do dispositivo
// dono (DEVPKEY_Device_InstanceId da interface, o DeviceInstance da chave
// da interface em DeviceClasses; tipo que não é DEVPROP_TYPE_STRING =
// STATUS_INVALID_PARAMETER_1), a referência (o que vem depois da barra do
// nome) e o prefixo do link ("\??\" ou "\\?\", o CmGetDeviceInterfacePathFormat)
// montam o nome da interface irmã pelo _CmGetDeviceInterfaceName: prefixo +
// instância + "#" + GUID da classe pedida (em minúsculas), com '\' e '/'
// depois do prefixo trocados por '#', e "\" + referência (referência com
// barra = STATUS_OBJECT_NAME_INVALID, mais de 0x102 caracteres =
// STATUS_INVALID_PARAMETER). A interface irmã precisa estar registrada (a
// chave da referência, o _CmOpenDeviceInterfaceRegKey tipo 0x30); senão o
// buffer devolvido é liberado (RtlFreeAnsiString zera o UNICODE_STRING) e o
// status da abertura volta. Em sucesso o nome fica num buffer do PagedPool
// ('Pp  ') que o chamador libera.

const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NAME_TOO_LONG: u32 = 0xC000_0106;
const REG_SZ: u32 = 1;
/// 'Pp  '.
const TAG_PNP: u32 = 0x2020_7050;
const PAGED_POOL: u32 = 1;
/// Referência mais longa que o _CmGetDeviceInterfaceName aceita.
const MAXIMUM_REFERENCE: usize = 0x102;

/// IoGetDeviceInterfaceAlias: devolve o NTSTATUS.
pub fn interface_alias(link_pointer: u64, alias_class: u64, output: u64) -> Result<u32, KernelError> {
    if link_pointer == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: PUNICODE_STRING do chamador de modo kernel.
    let link = unsafe { UnicodeString::at(link_pointer) };
    if link.buffer.get() == 0 || link.length.get() == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let units = guest_strings::try_read_unicode_units(link_pointer)?;
    let Ok((class, subkey)) = interface_subkey(&units) else { return Ok(STATUS_INVALID_PARAMETER) };
    let interface = subkey.split('\\').next().unwrap_or_default();
    let Some(instance) = cm_registry::read_value_by_path(&format!("{DEVICE_CLASSES}\\{class}\\{interface}"), "DeviceInstance") else { return Ok(0xC000_0034) };
    if instance.value_type != REG_SZ {
        return Ok(STATUS_INVALID_PARAMETER_1);
    }
    let instance: String = String::from_utf16_lossy(&instance.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect::<Vec<u16>>());
    let slash = units.iter().skip(4).position(|&unit| unit == b'\\' as u16).map(|index| index + 4);
    let reference = slash.map(|index| String::from_utf16_lossy(&units[index + 1..]));
    let prefix = String::from_utf16_lossy(&units[..4]);
    let alias_guid = guid_string(&guest::read_bytes(alias_class, Guid::SIZE as usize));
    if let Some(reference) = &reference {
        if reference.encode_utf16().count() > MAXIMUM_REFERENCE {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if reference.contains(['\\', '/']) {
            return Ok(STATUS_OBJECT_NAME_INVALID);
        }
    }
    let body: String = format!("{instance}#{alias_guid}").chars().map(|character| if character == '\\' || character == '/' { '#' } else { character }).collect();
    let mut alias = format!("{prefix}{body}");
    if let Some(reference) = &reference {
        alias = format!("{alias}\\{reference}");
    }
    let alias_units: Vec<u16> = alias.encode_utf16().collect();
    let length = alias_units.len() as u64 * 2;
    if length > 0xFFFC {
        return Ok(STATUS_NAME_TOO_LONG);
    }
    let buffer = crate::ntos::ex::pool_allocation::allocate_tagged(PAGED_POOL, (length + 2).max(0x400), TAG_PNP)?;
    if buffer == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest_strings::write_wide_string(buffer, &alias);
    // SAFETY: PUNICODE_STRING AliasSymbolicLinkName de saída do chamador de modo kernel.
    let output_string = unsafe { UnicodeString::at(output) };
    output_string.length.set(length as u16);
    output_string.maximum_length.set(length as u16 + 2);
    output_string.buffer.set(buffer);
    let opened = match interface_subkey(&alias_units) {
        Ok((alias_class_text, alias_subkey)) => {
            let (status, handle) = key_services::open_path(&format!("{DEVICE_CLASSES}\\{alias_class_text}\\{alias_subkey}"), false)?;
            if status == 0 {
                cm_registry::close_handle(handle as u32);
            }
            status
        }
        Err(status) => status,
    };
    if opened != 0 {
        crate::ntos::ex::pool_allocation::free(buffer, 0)?;
        output_string.length.set(0);
        output_string.maximum_length.set(0);
        output_string.buffer.set(0);
    }
    Ok(opened)
}
