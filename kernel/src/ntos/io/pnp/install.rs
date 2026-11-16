//! Instalação de dispositivos pelos INFs da caixa (o papel do banco de
//! drivers e do instalador de dispositivos do NT).
//!
//! `DRIVERS` transcreve as linhas de modelo dos INFs do Windows desta
//! máquina que atendem o hardware emulado (mshdc.inf, o stornvme.inf, que dá
//! o stornvme.sys a todo controlador NVMe, PCI\CC_010802, disk.inf,
//! volume.inf, volmgr.inf, o display.inf, que dá o BasicDisplay.sys a todo adaptador de
//! classe VGA, PCI\CC_0300, e o machine.inf, que dá o msisadrv.sys, um
//! driver KMDF, às pontes PCI-ISA, PCI\CC_0601, e o driver nulo das seções
//! NO_DRV às pontes de host, PCI\CC_0600, e, com a raiz ACPI, ao HPET, ao
//! relógio CMOS, aos barramentos de recursos, ao contêiner dos processadores
//! e ao botão de função fixa), com o que cada seção de instalação grava: o serviço
//! (`[*.Services]`/`AddService`), a classe (`[Version]` e o INF da classe:
//! c_hdc.inf, c_scsiadapter.inf, c_diskdrive.inf, c_volume.inf, a classe
//! System), os valores
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
const REG_BINARY: u32 = 3;
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
    /// REG_BINARY (FLG_ADDREG_BINVALUETYPE).
    Binary(&'static [u8]),
    /// Só a chave, sem valor (FLG_ADDREG_KEYONLY).
    KeyOnly,
}

/// Serviço de `AddService` (o `[*_Service_Inst]` do INF).
pub struct ServiceSpec {
    pub name: &'static str,
    pub display_name: Option<&'static str>,
    pub start: u32,
    pub error_control: u32,
    /// `ServiceBinary`: o arquivo em `%12%` (System32\drivers), gravado como
    /// ImagePath relativo; ou o caminho NT inteiro de um driver que fica no
    /// repositório de drivers (`%13%`), que o instalador grava como está.
    pub binary: &'static str,
    pub group: Option<&'static str>,
    pub owner: &'static str,
    /// AddReg do `[*_Service_Inst]` (HKR = a chave do serviço: Tag,
    /// Parameters...).
    pub values: &'static [RegValue],
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
    /// `ExcludeID` da seção: um dispositivo com um desses HardwareIDs ou
    /// CompatibleIDs não instala por esta linha.
    pub exclude_ids: &'static [&'static str],
}

pub const CLASS_HDC: ClassSpec = ClassSpec { guid: "{4d36e96a-e325-11ce-bfc1-08002be10318}", name: "hdc", upper_filters: &[], lower_filters: &[] };
/// c_diskdrive.inf: `HKR,,UpperFilters,%REG_MULTI_SZ_APPEND%,"partmgr"`.
pub const CLASS_DISK_DRIVE: ClassSpec = ClassSpec { guid: "{4d36e967-e325-11ce-bfc1-08002be10318}", name: "DiskDrive", upper_filters: &["partmgr"], lower_filters: &[] };
pub const CLASS_VOLUME: ClassSpec = ClassSpec { guid: "{71a27cdd-812a-11d0-bec7-08002be2092f}", name: "Volume", upper_filters: &[], lower_filters: &[] };
pub const CLASS_SYSTEM: ClassSpec = ClassSpec { guid: "{4d36e97d-e325-11ce-bfc1-08002be10318}", name: "System", upper_filters: &[], lower_filters: &[] };
/// display.inf `[Version]` (a classe Display do c_display.inf).
pub const CLASS_DISPLAY: ClassSpec = ClassSpec { guid: "{4d36e968-e325-11ce-bfc1-08002be10318}", name: "Display", upper_filters: &[], lower_filters: &[] };
/// stornvme.inf `[Version]` (a classe SCSIAdapter do c_scsiadapter.inf).
pub const CLASS_SCSI_ADAPTER: ClassSpec = ClassSpec { guid: "{4d36e97b-e325-11ce-bfc1-08002be10318}", name: "SCSIAdapter", upper_filters: &[], lower_filters: &[] };

/// mshdc.inf `[intelide_Service_Inst]`.
const SERVICE_INTELIDE: ServiceSpec = ServiceSpec { name: "intelide", display_name: None, start: 0, error_control: 3, binary: "intelide.sys", group: Some("System Bus Extender"), owner: "mshdc.inf", values: &[] };
/// mshdc.inf `[pciide_Service_Inst]`.
const SERVICE_PCIIDE: ServiceSpec = ServiceSpec { name: "pciide", display_name: None, start: 0, error_control: 3, binary: "pciide.sys", group: Some("System Bus Extender"), owner: "mshdc.inf", values: &[] };
/// mshdc.inf `[atapi_Service_Inst]`.
const SERVICE_ATAPI: ServiceSpec = ServiceSpec { name: "atapi", display_name: Some("@mshdc.inf,%idechannel.DeviceDesc%;IDE Channel"), start: 0, error_control: 3, binary: "atapi.sys", group: Some("SCSI Miniport"), owner: "mshdc.inf", values: &[] };
/// disk.inf `[disk_ServiceInstallSection]`.
const SERVICE_DISK: ServiceSpec = ServiceSpec { name: "disk", display_name: Some("@disk.inf,%disk_ServiceDesc%;Disk Driver"), start: 0, error_control: 1, binary: "disk.sys", group: None, owner: "disk.inf", values: &[] };
/// volume.inf `[volume_ServiceInstallSection]`.
const SERVICE_VOLUME: ServiceSpec = ServiceSpec { name: "volume", display_name: Some("@volume.inf,%VolumeServiceDesc%;Volume driver"), start: 0, error_control: 3, binary: "volume.sys", group: None, owner: "volume.inf", values: &[] };
/// volmgr.inf `[Volmgr_Service]`.
const SERVICE_VOLMGR: ServiceSpec = ServiceSpec { name: "volmgr", display_name: Some("@volmgr.inf,%volmgr_svcdesc%;Volume Manager Driver"), start: 0, error_control: 3, binary: "volmgr.sys", group: Some("System Bus Extender"), owner: "volmgr.inf", values: &[] };
/// machine.inf `[msisadrv_ServiceInstallSection]` (StartType
/// SERVICE_BOOT_START, ErrorControl SERVICE_ERROR_CRITICAL; o AddReg grava o
/// Tag 2).
const SERVICE_MSISADRV: ServiceSpec = ServiceSpec { name: "msisadrv", display_name: None, start: 0, error_control: 3, binary: "msisadrv.sys", group: Some("Boot Bus Extender"), owner: "machine.inf", values: &[] };
/// basicdisplay.inf `[MSBDD_Fallback_Generic_Service_Inst]`, que o
/// `[MSBDA.Services]` do display.inf inclui (`include=basicdisplay.inf`,
/// `needs=MSBDD_Fallback.Services`): ServiceBinary `%13%\BasicDisplay.sys`,
/// no repositório de drivers.
const SERVICE_BASIC_DISPLAY: ServiceSpec = ServiceSpec {
    name: "BasicDisplay",
    display_name: None,
    start: 1,
    error_control: 0,
    binary: "\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicdisplay.inf_amd64_19e58b6267591a82\\BasicDisplay.sys",
    group: Some("Video"),
    owner: "display.inf",
    values: &[],
};

/// stornvme.inf `[Stornvme_Service_Inst]` com o `[nvme_registry_values]` e
/// o `[nvme_registry_device_specific_values]` (HKR = a chave do serviço):
/// a interface de barramento PCIBus (5) no PnpInterface, o BusType NVMe
/// (0x11), o tempo limite de I/O de 10 s, o DMAR só para dispositivos
/// externos e o alinhamento de faixa dos controladores da Intel.
const SERVICE_STORNVME: ServiceSpec = ServiceSpec {
    name: "stornvme",
    display_name: Some("@stornvme.inf,%StorNVMe_ServiceDesc%;Microsoft Standard NVM Express Driver"),
    start: 0,
    error_control: 3,
    binary: "stornvme.sys",
    group: Some("SCSI Miniport"),
    owner: "stornvme.inf",
    values: &[
        RegValue { subkey: "Parameters\\PnpInterface", name: "5", data: RegData::Dword(1) },
        RegValue { subkey: "Parameters", name: "BusType", data: RegData::Dword(0x11) },
        RegValue { subkey: "Parameters", name: "IoTimeoutValue", data: RegData::Dword(0xA) },
        RegValue { subkey: "Parameters", name: "DmaRemappingCompatible", data: RegData::Dword(2) },
        RegValue {
            subkey: "Parameters\\Device",
            name: "IoStripeAlignment",
            data: RegData::MultiText(&["VEN_8086&DEV_0953&REV_?? 128", "VEN_8086&DEV_0984&REV_?? 128", "VEN_8086&DEV_0A53&REV_?? 128", "VEN_8086&DEV_0A54&REV_?? 128", "VEN_8086&DEV_0A55&REV_?? 128"]),
        },
    ],
};

/// stornvme.inf `[Stornvme_Inst_HW_AddReg]` (`[Stornvme_Inst.HW]`, HKR =
/// Device Parameters): as propriedades de interrupção do controlador.
const STORNVME_HARDWARE: &[RegValue] = &[
    RegValue { subkey: "Interrupt Management\\MessageSignaledInterruptProperties", name: "MSISupported", data: RegData::Dword(1) },
    RegValue { subkey: "Interrupt Management\\MessageSignaledInterruptProperties", name: "MessageNumberLimit", data: RegData::Dword(65) },
    RegValue { subkey: "Interrupt Management\\Affinity Policy", name: "DevicePolicy", data: RegData::Dword(5) },
    RegValue { subkey: "Interrupt Management\\Affinity Policy", name: "DevicePriority", data: RegData::Dword(3) },
    RegValue { subkey: "Interrupt Management\\Affinity Policy", name: "GroupPolicy", data: RegData::Dword(1) },
];

/// acpi.inf `[ACPI_Service_Inst]` com o `[acpi_ServiceInstallSection_AddReg]`
/// (Tag 2, Group "Core").
const SERVICE_ACPI: ServiceSpec = ServiceSpec {
    name: "ACPI",
    display_name: Some("@acpi.inf,%ACPI.SvcDesc%;Microsoft ACPI Driver"),
    start: 0,
    error_control: 3,
    binary: "ACPI.sys",
    group: Some("Core"),
    owner: "acpi.inf",
    values: &[RegValue { subkey: "", name: "Tag", data: RegData::Dword(2) }],
};
/// pci.inf `[pci_ServiceInstallSection]` com o
/// `[pci_ServiceInstallSection_AddReg]` (Tag 3 e
/// Parameters\DmaRemappingCompatible = 1).
const SERVICE_PCI: ServiceSpec = ServiceSpec {
    name: "pci",
    display_name: Some("@pci.inf,%pci_svcdesc%;PCI Bus Driver"),
    start: 0,
    error_control: 3,
    binary: "pci.sys",
    group: Some("Boot Bus Extender"),
    owner: "pci.inf",
    values: &[
        RegValue { subkey: "", name: "Tag", data: RegData::Dword(3) },
        RegValue { subkey: "Parameters", name: "DmaRemappingCompatible", data: RegData::Dword(1) },
    ],
};

/// acpi.inf `[RP_REG_MUTE_IRQ]` (HKR = chave do driver).
const ACPI_RESOURCE_PICKER: &[RegValue] = &[RegValue { subkey: "", name: "ResourcePickerExceptions", data: RegData::Text("IRQ:HAL") }];
/// pci.inf `[PCI_ROOT_REG]` (HKR = chave do driver).
const PCI_ROOT_RESOURCE_PICKER: &[RegValue] = &[
    RegValue { subkey: "", name: "ResourcePickerExceptions", data: RegData::Text("IO:HAL,MBRES;MEM:HAL,MBRES") },
    RegValue { subkey: "", name: "ResourcePickerTags", data: RegData::Text("MBRES") },
];
/// pci.inf `[PCI_BRIDGE_HW.AddReg]` (`[PCI_ROOT.HW]`, HKR = Device Parameters).
const PCI_ROOT_HARDWARE: &[RegValue] = &[RegValue { subkey: "", name: "UINumberDescFormat", data: RegData::Text("PCI Slot %1!u!") }];

/// keyboard.inf `[Version]` (a classe Keyboard; c_keyboard.inf põe o
/// kbdclass como filtro superior da classe).
pub const CLASS_KEYBOARD: ClassSpec = ClassSpec { guid: "{4D36E96B-E325-11CE-BFC1-08002BE10318}", name: "Keyboard", upper_filters: &["kbdclass"], lower_filters: &[] };
/// msmouse.inf `[Version]` (a classe Mouse, com o mouclass).
pub const CLASS_MOUSE: ClassSpec = ClassSpec { guid: "{4D36E96F-E325-11CE-BFC1-08002BE10318}", name: "Mouse", upper_filters: &["mouclass"], lower_filters: &[] };
/// keyboard.inf `[STANDARD_i8042prt_Service_Inst]` com o
/// `[STANDARD_i8042prt_Service_AddReg]`.
const SERVICE_I8042PRT: ServiceSpec = ServiceSpec {
    name: "i8042prt",
    display_name: Some("@keyboard.inf,%i8042prt.SvcDesc%;i8042 Keyboard and PS/2 Mouse Port Driver"),
    start: 3,
    error_control: 1,
    binary: "i8042prt.sys",
    group: Some("Keyboard Port"),
    owner: "keyboard.inf",
    values: &[
        RegValue { subkey: "Parameters", name: "LayerDriver JPN", data: RegData::Text("kbd101.dll") },
        RegValue { subkey: "Parameters", name: "LayerDriver KOR", data: RegData::Text("kbd101a.dll") },
    ],
};
/// keyboard.inf `[STANDARD_AddReg]` (HKR = chave do driver).
const KEYBOARD_DRIVER: &[RegValue] = &[RegValue { subkey: "", name: "LocationInformationOverride", data: RegData::Text("plugged into keyboard port") }];
/// keyboard.inf `[KbdClass_HW_AddReg]` (HKR = Device Parameters).
const KEYBOARD_HARDWARE: &[RegValue] = &[RegValue { subkey: "", name: "KeyboardDataQueueSize", data: RegData::Dword(100) }, RegValue { subkey: "", name: "PollStatusIterations", data: RegData::Dword(1) }];
/// msmouse.inf `[PS2_Inst.AddReg]`.
const MOUSE_DRIVER: &[RegValue] = &[RegValue { subkey: "", name: "LocationInformationOverride", data: RegData::Text("plugged into PS/2 mouse port") }];
/// msmouse.inf `[PS2_Inst.HW.AddReg]`.
const MOUSE_HARDWARE: &[RegValue] = &[
    RegValue { subkey: "", name: "EnableWheelDetection", data: RegData::Dword(2) },
    RegValue { subkey: "", name: "MouseDataQueueSize", data: RegData::Dword(100) },
    RegValue { subkey: "", name: "MouseResolution", data: RegData::Dword(3) },
    RegValue { subkey: "", name: "MouseSynchIn100ns", data: RegData::Dword(20_000_000) },
    RegValue { subkey: "", name: "SampleRate", data: RegData::Dword(100) },
    RegValue { subkey: "", name: "WheelDetectionTimeout", data: RegData::Dword(1500) },
    RegValue { subkey: "", name: "MouseInitializePolled", data: RegData::Dword(0) },
];

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

/// machine.inf `[NO_DRV_X_REG]` e `[NO_DRV_X_PNP_REG]` (HKR = chave do driver).
const NO_DRV_X_VALUES: &[RegValue] = &[
    RegValue { subkey: "", name: "ResourcePickerExceptions", data: RegData::Text("IO@0-0xFF:*;IO:HAL,MBRES;IRQ:HAL,*") },
    RegValue { subkey: "", name: "ResourcePickerTags", data: RegData::Text("MBRES") },
];
/// machine.inf `[NO_DRV_HPET_REG]`.
const NO_DRV_HPET_VALUES: &[RegValue] = &[
    RegValue { subkey: "", name: "ResourcePickerExceptions", data: RegData::Text("MEM:HAL,MBRES,*;IRQ:HAL,MBRES,*") },
    RegValue { subkey: "", name: "ResourcePickerTags", data: RegData::Text("MBRES") },
];

/// Uma linha do `[GENDEV_SYS.NTamd64]` do machine.inf com uma seção de
/// driver nulo (`AddService = , %SPSVCINST_ASSOCSERVICE%`): o dispositivo
/// fica instalado, sem serviço.
const fn machine_no_driver(section: &'static str, id: &'static str, description_key: &'static str, description: &'static str, driver_values: &'static [RegValue]) -> InfDriver {
    InfDriver {
        inf: "machine.inf",
        section,
        id,
        description_key,
        description,
        manufacturer_key: "GENDEV_MFG",
        manufacturer: "(Standard system devices)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: None,
        class: &CLASS_SYSTEM,
        driver_values,
        device_values: &[],
        exclude_ids: &[],
    }
}

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
        exclude_ids: &[],
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
        exclude_ids: &[],
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
        exclude_ids: &[],
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
        exclude_ids: &[],
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
        exclude_ids: &[],
    },
    InfDriver {
        inf: "stornvme.inf",
        section: "Stornvme_Inst",
        id: "PCI\\CC_010802",
        description_key: "PCI\\CC_010802.DeviceDesc",
        description: "Standard NVM Express Controller",
        manufacturer_key: "MS-NVME",
        manufacturer: "Standard NVM Express Controller",
        provider: "Microsoft",
        driver_version: "10.0.19041.4355",
        service: Some(&SERVICE_STORNVME),
        class: &CLASS_SCSI_ADAPTER,
        driver_values: &[],
        device_values: STORNVME_HARDWARE,
        exclude_ids: &[],
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
        exclude_ids: &[],
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
        exclude_ids: &[],
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
        exclude_ids: &[],
    },
    InfDriver {
        inf: "display.inf",
        section: "MSBDA",
        id: "PCI\\CC_0300",
        description_key: "MSBDAName",
        description: "Microsoft Basic Display Adapter",
        manufacturer_key: "Std",
        manufacturer: "(Standard display types)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_BASIC_DISPLAY),
        class: &CLASS_DISPLAY,
        driver_values: &[],
        device_values: &[],
        exclude_ids: &["PCI\\VEN_1414&DEV_5353"],
    },
    InfDriver {
        inf: "display.inf",
        section: "MSBDA",
        id: "PCI\\CC_0301",
        description_key: "MSBDAName",
        description: "Microsoft Basic Display Adapter",
        manufacturer_key: "Std",
        manufacturer: "(Standard display types)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_BASIC_DISPLAY),
        class: &CLASS_DISPLAY,
        driver_values: &[],
        device_values: &[],
        exclude_ids: &["PCI\\VEN_1414&DEV_5353"],
    },
    machine_no_driver("NO_DRV", "PCI\\CC_0600", "PCI\\CC_0600_Desc", "PCI standard host CPU bridge", &[]),
    InfDriver {
        inf: "machine.inf",
        section: "MSISADRV",
        id: "PCI\\CC_0601",
        description_key: "PCI\\CC_0601_Desc",
        description: "PCI standard ISA bridge",
        manufacturer_key: "GENDEV_MFG",
        manufacturer: "(Standard system devices)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_MSISADRV),
        class: &CLASS_SYSTEM,
        driver_values: &[],
        device_values: &[],
        exclude_ids: &[],
    },
    InfDriver {
        inf: "machine.inf",
        section: "MSISADRV",
        id: "PCI\\CC_0602",
        description_key: "PCI\\CC_0602_Desc",
        description: "PCI standard EISA bridge",
        manufacturer_key: "GENDEV_MFG",
        manufacturer: "(Standard system devices)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_MSISADRV),
        class: &CLASS_SYSTEM,
        driver_values: &[],
        device_values: &[],
        exclude_ids: &[],
    },
];

/// As linhas de modelo do acpi.inf (`*pnp0c08` e `pnp0c08`, seção ACPI_Inst),
/// do pci.inf (`*PNP0A03` e `*PNP0A08`, seção PCI_ROOT), do keyboard.inf
/// (`*PNP0303`) e do msmouse.inf (`*PNP0F13`), que só a árvore
/// com a raiz ACPI (`--pnp-root=acpi`) usa: o acpi.sys no dispositivo ACPI da
/// HAL e o pci.sys no barramento PCI que ele enumera.
pub const ACPI_ROOT_DRIVERS: &[InfDriver] = &[
    InfDriver {
        inf: "acpi.inf",
        section: "ACPI_Inst",
        id: "*pnp0c08",
        description_key: "*pnp0c08.DeviceDesc",
        description: "Microsoft ACPI-Compliant System",
        manufacturer_key: "MSFT",
        manufacturer: "Microsoft",
        provider: "Microsoft",
        driver_version: "10.0.19041.6456",
        service: Some(&SERVICE_ACPI),
        class: &CLASS_SYSTEM,
        driver_values: ACPI_RESOURCE_PICKER,
        device_values: &[],
        exclude_ids: &[],
    },
    InfDriver {
        inf: "acpi.inf",
        section: "ACPI_Inst",
        id: "pnp0c08",
        description_key: "*pnp0c08.DeviceDesc",
        description: "Microsoft ACPI-Compliant System",
        manufacturer_key: "MSFT",
        manufacturer: "Microsoft",
        provider: "Microsoft",
        driver_version: "10.0.19041.6456",
        service: Some(&SERVICE_ACPI),
        class: &CLASS_SYSTEM,
        driver_values: ACPI_RESOURCE_PICKER,
        device_values: &[],
        exclude_ids: &[],
    },
    InfDriver {
        inf: "pci.inf",
        section: "PCI_ROOT",
        id: "*PNP0A03",
        description_key: "*pnp0a03.DeviceDesc",
        description: "PCI Bus",
        manufacturer_key: "GENDEV_MFG",
        manufacturer: "(Standard system devices)",
        provider: "Microsoft",
        driver_version: "10.0.19041.6456",
        service: Some(&SERVICE_PCI),
        class: &CLASS_SYSTEM,
        driver_values: PCI_ROOT_RESOURCE_PICKER,
        device_values: PCI_ROOT_HARDWARE,
        exclude_ids: &[],
    },
    InfDriver {
        inf: "pci.inf",
        section: "PCI_ROOT",
        id: "*PNP0A08",
        description_key: "*pnp0a08.DeviceDesc",
        description: "PCI Express Root Complex",
        manufacturer_key: "GENDEV_MFG",
        manufacturer: "(Standard system devices)",
        provider: "Microsoft",
        driver_version: "10.0.19041.6456",
        service: Some(&SERVICE_PCI),
        class: &CLASS_SYSTEM,
        driver_values: PCI_ROOT_RESOURCE_PICKER,
        device_values: PCI_ROOT_HARDWARE,
        exclude_ids: &[],
    },
    // Os dispositivos do namespace que o machine.inf instala com o driver
    // nulo: o HPET, o relógio CMOS, os barramentos de recursos (PNP0A06), o
    // contêiner dos processadores e o botão de função fixa.
    machine_no_driver("NO_DRV_HPET", "*PNP0103", "*PNP0103_Desc", "High precision event timer", NO_DRV_HPET_VALUES),
    machine_no_driver("NO_DRV_X", "*PNP0B00", "*PNP0B00_Desc", "System CMOS/real time clock", NO_DRV_X_VALUES),
    machine_no_driver("NO_DRV_X_PNP", "*PNP0A06", "*PNP0A06_Desc", "Extended IO Bus", NO_DRV_X_VALUES),
    machine_no_driver("NO_DRV_X_PNP", "*ACPI0010", "ACPI0010_Desc", "ACPI Processor Container Device", NO_DRV_X_VALUES),
    machine_no_driver("NO_DRV", "ACPI\\FixedButton", "ACPI\\FixedButton_Desc", "ACPI Fixed Feature Button", &[]),
    // O teclado e o mouse PS/2 que o acpi.sys relata sob a ponte PCI-ISA:
    // keyboard.inf `*PNP0303` (STANDARD_Inst) e msmouse.inf `*PNP0F13`
    // (PS2_Inst), os dois com o i8042prt e os filtros de classe.
    InfDriver {
        inf: "keyboard.inf",
        section: "STANDARD_Inst",
        id: "*PNP0303",
        description_key: "*PNP0303.DeviceDesc",
        description: "Standard PS/2 Keyboard",
        manufacturer_key: "Std-Keyboards",
        manufacturer: "(Standard keyboards)",
        provider: "Microsoft",
        driver_version: "10.0.19041.1",
        service: Some(&SERVICE_I8042PRT),
        class: &CLASS_KEYBOARD,
        driver_values: KEYBOARD_DRIVER,
        device_values: KEYBOARD_HARDWARE,
        exclude_ids: &[],
    },
    InfDriver {
        inf: "msmouse.inf",
        section: "PS2_Inst",
        id: "*PNP0F13",
        description_key: "*pnp0f13.DeviceDesc",
        description: "PS/2 Compatible Mouse",
        manufacturer_key: "StdMfg",
        manufacturer: "(Standard mouse types)",
        provider: "Microsoft",
        driver_version: "10.0.19041.1",
        service: Some(&SERVICE_I8042PRT),
        class: &CLASS_MOUSE,
        driver_values: MOUSE_DRIVER,
        device_values: MOUSE_HARDWARE,
        exclude_ids: &[],
    },
];

/// As linhas que o instalador considera neste boot: as dos INFs da caixa
/// (com as da pilha USB e HID, `install_usb`) e, com a raiz ACPI, as do
/// acpi.inf e do pci.inf.
fn candidates() -> impl Iterator<Item = &'static InfDriver> {
    let acpi: &'static [InfDriver] = if crate::drivers::bus::acpi_stack::enabled() { ACPI_ROOT_DRIVERS } else { &[] };
    DRIVERS.iter().chain(super::install_usb::USB_DRIVERS.iter()).chain(acpi.iter())}

/// O driver de melhor posto para os ids: HardwareIDs na ordem, depois os
/// CompatibleIDs (sem diferenciar maiúsculas).
pub fn select_driver(hardware_ids: &[String], compatible_ids: &[String]) -> Option<&'static InfDriver> {
    let ids = || hardware_ids.iter().chain(compatible_ids.iter());
    let excluded = |driver: &InfDriver| driver.exclude_ids.iter().any(|exclude| ids().any(|id| id.eq_ignore_ascii_case(exclude)));
    ids().find_map(|id| candidates().find(|driver| driver.id.eq_ignore_ascii_case(id) && !excluded(driver)))
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
            RegData::Binary(bytes) => write_value(&path, value.name, REG_BINARY, bytes.to_vec())?,
            RegData::KeyOnly => {
                registry::close_handle(registry::open_or_create(&path, None)?);
            }
        }
    }
    Ok(())
}

/// O ImagePath que o AddService grava: relativo a \SystemRoot para um
/// binário de `%12%`, o caminho NT inteiro para um do repositório de drivers.
pub fn service_image_path(service: &ServiceSpec) -> String {
    if service.binary.starts_with('\\') {
        String::from(service.binary)
    } else {
        format!("System32\\drivers\\{}", service.binary)
    }
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
        image_path: Some(service_image_path(service)),
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
    apply_values(&key, service.values)?;
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
