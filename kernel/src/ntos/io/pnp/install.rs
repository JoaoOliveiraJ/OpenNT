//! Instalação de dispositivos pelos INFs da caixa (o papel do banco de
//! drivers e do instalador de dispositivos do NT).
//!
//! `DRIVERS` transcreve as linhas de modelo dos INFs do Windows desta
//! máquina que atendem o hardware emulado (mshdc.inf, disk.inf, volume.inf,
//! volmgr.inf), com o que cada seção de instalação grava: o serviço
//! (`[*.Services]`/`AddService`), a classe (`[Version]` e o INF da classe:
//! c_hdc.inf, c_diskdrive.inf, c_volume.inf, a classe System), os valores
//! da chave do driver (`AddReg` de `[DDInstall]`, HKR = Control\Class\
//! {guid}\NNNN) e os da chave de hardware (`[DDInstall.HW]`, HKR =
//! Enum\<instância>\Device Parameters).
//!
//! A escolha segue a ordem do instalador: os HardwareIDs, na ordem, antes
//! dos CompatibleIDs; o primeiro id que casa com uma linha de modelo dá o
//! driver de melhor posto. Instalar grava na chave da instância os valores
//! que o instalador grava (Service, ClassGUID, Class, Driver, DeviceDesc,
//! Mfg, ConfigFlags), cria a chave do driver e a do hardware e acrescenta a
//! instância em Services\<serviço>\Enum.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::registry;
use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput};
use crate::rtl::KernelError;

pub const CONTROL_SET: &str = "\\Registry\\Machine\\System\\CurrentControlSet";

/// Tipos de valor do Registro.
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;

/// Um valor de AddReg: subchave relativa a HKR, nome e dado.
#[derive(Clone, Copy)]
pub struct RegValue {
    pub subkey: &'static str,
    pub name: &'static str,
    pub data: RegData,
}

#[derive(Clone, Copy)]
pub enum RegData {
    Dword(u32),
    Text(&'static str),
    MultiText(&'static [&'static str]),
}

/// Serviço de `AddService` (o `[*_Service_Inst]` do INF).
pub struct ServiceSpec {
    pub name: &'static str,
    pub display_name: Option<&'static str>,
    pub start: u32,
    pub error_control: u32,
    pub binary: &'static str,
    pub group: Option<&'static str>,
    pub owner: &'static str,
}

/// Classe de dispositivo (o `[ClassInstall32]` do INF da classe).
pub struct ClassSpec {
    pub guid: &'static str,
    pub name: &'static str,
    pub upper_filters: &'static [&'static str],
    pub lower_filters: &'static [&'static str],
}

/// Uma linha de modelo de um INF e a sua seção de instalação.
pub struct InfDriver {
    pub inf: &'static str,
    pub section: &'static str,
    /// Id da linha de modelo.
    pub id: &'static str,
    /// Chave da descrição em [Strings] e o texto.
    pub description_key: &'static str,
    pub description: &'static str,
    pub manufacturer_key: &'static str,
    pub manufacturer: &'static str,
    pub provider: &'static str,
    pub driver_version: &'static str,
    pub service: Option<&'static ServiceSpec>,
    pub class: &'static ClassSpec,
    pub driver_values: &'static [RegValue],
    pub device_values: &'static [RegValue],
}

pub const CLASS_HDC: ClassSpec = ClassSpec { guid: "{4d36e96a-e325-11ce-bfc1-08002be10318}", name: "hdc", upper_filters: &[], lower_filters: &[] };
/// c_diskdrive.inf: `HKR,,UpperFilters,%REG_MULTI_SZ_APPEND%,"partmgr"`.
pub const CLASS_DISK_DRIVE: ClassSpec = ClassSpec { guid: "{4d36e967-e325-11ce-bfc1-08002be10318}", name: "DiskDrive", upper_filters: &["partmgr"], lower_filters: &[] };
pub const CLASS_VOLUME: ClassSpec = ClassSpec { guid: "{71a27cdd-812a-11d0-bec7-08002be2092f}", name: "Volume", upper_filters: &[], lower_filters: &[] };
pub const CLASS_SYSTEM: ClassSpec = ClassSpec { guid: "{4d36e97d-e325-11ce-bfc1-08002be10318}", name: "System", upper_filters: &[], lower_filters: &[] };

/// mshdc.inf `[intelide_Service_Inst]`.
const SERVICE_INTELIDE: ServiceSpec = ServiceSpec { name: "intelide", display_name: None, start: 0, error_control: 3, binary: "intelide.sys", group: Some("System Bus Extender"), owner: "mshdc.inf" };
/// mshdc.inf `[pciide_Service_Inst]`.
const SERVICE_PCIIDE: ServiceSpec = ServiceSpec { name: "pciide", display_name: None, start: 0, error_control: 3, binary: "pciide.sys", group: Some("System Bus Extender"), owner: "mshdc.inf" };
/// mshdc.inf `[atapi_Service_Inst]`.
const SERVICE_ATAPI: ServiceSpec = ServiceSpec { name: "atapi", display_name: Some("@mshdc.inf,%idechannel.DeviceDesc%;IDE Channel"), start: 0, error_control: 3, binary: "atapi.sys", group: Some("SCSI Miniport"), owner: "mshdc.inf" };
/// disk.inf `[disk_ServiceInstallSection]`.
const SERVICE_DISK: ServiceSpec = ServiceSpec { name: "disk", display_name: Some("@disk.inf,%disk_ServiceDesc%;Disk Driver"), start: 0, error_control: 1, binary: "disk.sys", group: None, owner: "disk.inf" };
/// volume.inf `[volume_ServiceInstallSection]`.
const SERVICE_VOLUME: ServiceSpec = ServiceSpec { name: "volume", display_name: Some("@volume.inf,%VolumeServiceDesc%;Volume driver"), start: 0, error_control: 3, binary: "volume.sys", group: None, owner: "volume.inf" };
/// volmgr.inf `[Volmgr_Service]`.
const SERVICE_VOLMGR: ServiceSpec = ServiceSpec { name: "volmgr", display_name: Some("@volmgr.inf,%volmgr_svcdesc%;Volume Manager Driver"), start: 0, error_control: 3, binary: "volmgr.sys", group: Some("System Bus Extender"), owner: "volmgr.inf" };

/// mshdc.inf `[intelChannelEnableCheck_AddReg.HW]`, referenciado pelo
/// `AddReg` de `[intelide_Inst]` (HKR = chave do driver).
const INTEL_CHANNEL_ENABLE_CHECK: &[RegValue] = &[
    RegValue { subkey: "Channel0", name: "ChannelStateMask", data: RegData::Dword(0x80) },
    RegValue { subkey: "Channel0", name: "ChannelStateOffset", data: RegData::Dword(0x41) },
    RegValue { subkey: "Channel1", name: "ChannelStateMask", data: RegData::Dword(0x80) },
    RegValue { subkey: "Channel1", name: "ChannelStateOffset", data: RegData::Dword(0x43) },
];

/// mshdc.inf `[atapi_property_provider_AddReg]` (HKR = chave do driver).
const ATAPI_PROPERTY_PROVIDER: &[RegValue] = &[RegValue { subkey: "", name: "EnumPropPages32", data: RegData::Text("storprop.dll,AtaPropPageProvider") }];
/// mshdc.inf `[atapi_interrupt_priority_AddReg]` e `[atapi_busdevicedesc_AddReg]`
/// (`[atapi_Inst.HW]`, HKR = Device Parameters).
const ATAPI_HARDWARE: &[RegValue] = &[
    RegValue { subkey: "Interrupt Management\\Affinity Policy", name: "DevicePriority", data: RegData::Dword(3) },
    RegValue { subkey: "", name: "UseBusDeviceDesc", data: RegData::Dword(1) },
];

/// As linhas de modelo, na ordem dos INFs.
pub const DRIVERS: &[InfDriver] = &[
    InfDriver {
        inf: "mshdc.inf",
        section: "intelide_Inst",
        id: "PCI\\VEN_8086&DEV_7010",
        description_key: "PCI\\VEN_8086&DEV_7010.DeviceDesc",
        description: "Intel(R) 82371SB PCI Bus Master IDE Controller",
        manufacturer_key: "INTEL",
        manufacturer: "Intel",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_INTELIDE),
        class: &CLASS_HDC,
        driver_values: INTEL_CHANNEL_ENABLE_CHECK,
        device_values: &[],
    },
    InfDriver {
        inf: "mshdc.inf",
        section: "pciide_Inst",
        id: "PCI\\CC_0101",
        description_key: "PCI\\CC_0101.DeviceDesc",
        description: "Standard Dual Channel PCI IDE Controller",
        manufacturer_key: "MS-Drivers",
        manufacturer: "(Standard IDE ATA/ATAPI controllers)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_PCIIDE),
        class: &CLASS_HDC,
        driver_values: &[],
        device_values: &[],
    },
    InfDriver {
        inf: "mshdc.inf",
        section: "atapi_Inst",
        id: "Internal_IDE_Channel",
        description_key: "idechannel.DeviceDesc",
        description: "IDE Channel",
        manufacturer_key: "MS-Drivers",
        manufacturer: "(Standard IDE ATA/ATAPI controllers)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_ATAPI),
        class: &CLASS_HDC,
        driver_values: ATAPI_PROPERTY_PROVIDER,
        device_values: ATAPI_HARDWARE,
    },
    InfDriver {
        inf: "mshdc.inf",
        section: "atapi_Inst",
        id: "Primary_IDE_Channel",
        description_key: "idechannel.DeviceDesc",
        description: "IDE Channel",
        manufacturer_key: "MS-Drivers",
        manufacturer: "(Standard IDE ATA/ATAPI controllers)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_ATAPI),
        class: &CLASS_HDC,
        driver_values: ATAPI_PROPERTY_PROVIDER,
        device_values: ATAPI_HARDWARE,
    },
    InfDriver {
        inf: "mshdc.inf",
        section: "atapi_Inst",
        id: "Secondary_IDE_Channel",
        description_key: "idechannel.DeviceDesc",
        description: "IDE Channel",
        manufacturer_key: "MS-Drivers",
        manufacturer: "(Standard IDE ATA/ATAPI controllers)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_ATAPI),
        class: &CLASS_HDC,
        driver_values: ATAPI_PROPERTY_PROVIDER,
        device_values: ATAPI_HARDWARE,
    },
    InfDriver {
        inf: "disk.inf",
        section: "disk_install.NT",
        id: "GenDisk",
        description_key: "disk_devdesc",
        description: "Disk drive",
        manufacturer_key: "GenManufacturer",
        manufacturer: "(Standard disk drives)",
        provider: "Microsoft",
        driver_version: "10.0.19041.4597",
        service: Some(&SERVICE_DISK),
        class: &CLASS_DISK_DRIVE,
        driver_values: &[],
        device_values: &[],
    },
    InfDriver {
        inf: "volume.inf",
        section: "volume_install.NT",
        id: "STORAGE\\Volume",
        description_key: "VolumeDeviceDesc",
        description: "Volume",
        manufacturer_key: "Msft",
        manufacturer: "Microsoft",
        provider: "Microsoft",
        driver_version: "10.0.19041.1",
        service: Some(&SERVICE_VOLUME),
        class: &CLASS_VOLUME,
        driver_values: &[],
        device_values: &[],
    },
    InfDriver {
        inf: "volmgr.inf",
        section: "Volmgr",
        id: "Root\\VOLMGR",
        description_key: "Volmgr.DeviceDesc",
        description: "Volume Manager",
        manufacturer_key: "MSFT",
        manufacturer: "Microsoft",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_VOLMGR),
        class: &CLASS_SYSTEM,
        driver_values: &[],
        device_values: &[],
    },
];

/// O driver de melhor posto para os ids: HardwareIDs na ordem, depois os
/// CompatibleIDs (sem diferenciar maiúsculas).
pub fn select_driver(hardware_ids: &[String], compatible_ids: &[String]) -> Option<&'static InfDriver> {
    hardware_ids.iter().chain(compatible_ids.iter()).find_map(|id| DRIVERS.iter().find(|driver| driver.id.eq_ignore_ascii_case(id)))
}

fn multi_sz(items: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for item in items {
        bytes.extend(registry::encode_wide(item));
    }
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

/// MULTI_SZ de strings próprias.
pub fn multi_sz_owned(items: &[String]) -> Vec<u8> {
    let borrowed: Vec<&str> = items.iter().map(String::as_str).collect();
    multi_sz(&borrowed)
}

/// Grava um valor numa chave (criada se preciso).
pub fn write_value(path: &str, name: &str, value_type: u32, data: Vec<u8>) -> Result<(), KernelError> {
    let handle = registry::open_or_create(path, None)?;
    registry::set_value(handle, name, value_type, data);
    registry::close_handle(handle);
    Ok(())
}

pub fn write_text(path: &str, name: &str, text: &str) -> Result<(), KernelError> {
    write_value(path, name, REG_SZ, registry::encode_wide(text))
}

pub fn write_dword(path: &str, name: &str, value: u32) -> Result<(), KernelError> {
    write_value(path, name, REG_DWORD, value.to_le_bytes().to_vec())
}

pub fn write_multi(path: &str, name: &str, items: &[String]) -> Result<(), KernelError> {
    write_value(path, name, REG_MULTI_SZ, multi_sz_owned(items))
}

/// Os valores de um AddReg sob a chave `root` (o HKR da seção).
fn apply_values(root: &str, values: &[RegValue]) -> Result<(), KernelError> {
    for value in values {
        let path = if value.subkey.is_empty() { String::from(root) } else { format!("{root}\\{}", value.subkey) };
        match value.data {
            RegData::Dword(number) => write_dword(&path, value.name, number)?,
            RegData::Text(text) => write_text(&path, value.name, text)?,
            RegData::MultiText(items) => write_value(&path, value.name, REG_MULTI_SZ, multi_sz(items))?,
        }
    }
    Ok(())
}

/// Chave do serviço como o AddService a cria: Type, Start, ErrorControl,
/// ImagePath (relativo a \SystemRoot, como o instalador grava), Group,
/// DisplayName e Owners. Um serviço já presente fica como está.
pub fn install_service(service: &ServiceSpec) -> Result<(), KernelError> {
    let input = ConfigurationInput {
        name: String::from(service.name),
        display_name: service.display_name.map(String::from),
        service_type: Some(1),
        start: Some(service.start),
        error_control: Some(service.error_control),
        image_path: Some(format!("System32\\drivers\\{}", service.binary)),
        ..ConfigurationInput::default()
    };
    match service_database::install(&input, true) {
        Ok(_) => {}
        Err(service_database::ServiceError::Win32(code, message)) => return Err(KernelError::new(format!("{}: {message} ({code})", service.name))),
        Err(service_database::ServiceError::Kernel(error)) => return Err(error),
    }
    let key = format!("{CONTROL_SET}\\Services\\{}", service.name);
    if let Some(group) = service.group {
        write_text(&key, "Group", group)?;
    }
    if service.owner.is_empty() {
        return Ok(());
    }
    write_value(&key, "Owners", REG_MULTI_SZ, multi_sz(&[service.owner]))
}

/// Chave da classe como o INF da classe a cria (Class e os filtros).
pub fn install_class(class: &ClassSpec) -> Result<(), KernelError> {
    let key = format!("{CONTROL_SET}\\Control\\Class\\{}", class.guid);
    write_text(&key, "Class", class.name)?;
    if !class.upper_filters.is_empty() {
        write_value(&key, "UpperFilters", REG_MULTI_SZ, multi_sz(class.upper_filters))?;
    }
    if !class.lower_filters.is_empty() {
        write_value(&key, "LowerFilters", REG_MULTI_SZ, multi_sz(class.lower_filters))?;
    }
    Ok(())
}

/// Próxima subchave livre NNNN da classe (a chave do driver).
fn next_driver_key(class_guid: &str) -> String {
    let existing = registry::list_keys(&format!("{CONTROL_SET}\\Control\\Class\\{class_guid}"));
    let mut index = 0;
    while existing.iter().any(|name| name == &format!("{index:04}")) {
        index += 1;
    }
    format!("{class_guid}\\{index:04}")
}

/// Instala `driver` na instância: chave da instância, chave do driver,
/// Device Parameters e Services\<serviço>\Enum. Devolve o serviço.
pub fn install_device(instance_path: &str, driver: &InfDriver, matching_id: &str) -> Result<Option<String>, KernelError> {
    let instance = format!("{CONTROL_SET}\\Enum\\{instance_path}");
    install_class(driver.class)?;
    if let Some(service) = driver.service {
        install_service(service)?;
    }
    let driver_key = next_driver_key(driver.class.guid);
    let software = format!("{CONTROL_SET}\\Control\\Class\\{driver_key}");
    write_text(&software, "DriverDesc", driver.description)?;
    write_text(&software, "ProviderName", driver.provider)?;
    write_text(&software, "DriverVersion", driver.driver_version)?;
    write_text(&software, "InfPath", driver.inf)?;
    write_text(&software, "InfSection", driver.section)?;
    write_text(&software, "MatchingDeviceId", &matching_id.to_lowercase())?;
    apply_values(&software, driver.driver_values)?;
    let lower_key = driver.description_key.to_lowercase();
    write_text(&instance, "DeviceDesc", &format!("@{},%{lower_key}%;{}", driver.inf, driver.description))?;
    write_text(&instance, "Mfg", &format!("@{},%{}%;{}", driver.inf, driver.manufacturer_key.to_lowercase(), driver.manufacturer))?;
    write_text(&instance, "ClassGUID", driver.class.guid)?;
    write_text(&instance, "Class", driver.class.name)?;
    write_text(&instance, "Driver", &driver_key)?;
    write_dword(&instance, "ConfigFlags", 0)?;
    apply_values(&format!("{instance}\\Device Parameters"), driver.device_values)?;
    let Some(service) = driver.service else { return Ok(None) };
    write_text(&instance, "Service", service.name)?;
    register_service_instance(service.name, instance_path)?;
    Ok(Some(String::from(service.name)))
}

/// Services\<serviço>\Enum: "N" = instância, Count e NextInstance.
pub fn register_service_instance(service: &str, instance_path: &str) -> Result<(), KernelError> {
    let key = format!("{CONTROL_SET}\\Services\\{service}\\Enum");
    let count = registry::read_value_by_path(&key, "Count").filter(|value| value.data.len() >= 4).map_or(0, |value| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]));
    write_text(&key, &format!("{count}"), instance_path)?;
    write_dword(&key, "Count", count + 1)?;
    write_dword(&key, "NextInstance", count + 1)
}

/// Valor REG_SZ/REG_EXPAND_SZ de uma chave, sem o terminador.
pub fn read_text(path: &str, name: &str) -> Option<String> {
    let value = registry::read_value_by_path(path, name)?;
    if value.value_type != REG_SZ && value.value_type != REG_EXPAND_SZ {
        return None;
    }
    let units: Vec<u16> = value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// Valor REG_MULTI_SZ de uma chave.
pub fn read_multi(path: &str, name: &str) -> Vec<String> {
    let Some(value) = registry::read_value_by_path(path, name) else { return Vec::new() };
    let units: Vec<u16> = value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    units.split(|&unit| unit == 0).filter(|item| !item.is_empty()).map(String::from_utf16_lossy).collect()
}

/// Valor REG_DWORD de uma chave.
pub fn read_dword(path: &str, name: &str) -> Option<u32> {
    let value = registry::read_value_by_path(path, name)?;
    (value.value_type == REG_DWORD && value.data.len() >= 4).then(|| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
}
