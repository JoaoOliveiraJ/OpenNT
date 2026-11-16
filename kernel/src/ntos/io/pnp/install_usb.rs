//! As linhas de modelo dos INFs da caixa da pilha USB 3 e HID, com o que
//! cada seção de instalação grava (o formato de `install`):
//! - usbxhci.inf `[Generic.Install]` (PCI\CC_0C0330): o serviço USBXHCI, a
//!   classe USB e, na chave de hardware (`[Generic_AddReg.HW]`), o
//!   `Interrupt Management\MessageSignaledInterruptProperties\MSISupported`
//!   que pede ao barramento PCI as interrupções por mensagem, mais o
//!   `D3ColdSupported` do `[PciD3ColdSupported.HW]` do pci.inf;
//! - usbhub3.inf `[Generic.Install]` (USB\ROOT_HUB30, USB\USB30_HUB e
//!   USB\USB20_HUB): o serviço USBHUB3;
//! - input.inf `[HID_Inst]` (os CompatibleIDs USB\Class_03&SubClass_01 e
//!   USB\Class_03 da linha GENERIC_HID_DEVICE): o minidriver HidUsb, na
//!   classe HIDClass, com os valores de hardware do `[HID_Inst.AddReg.NT.HW]`;
//! - keyboard.inf `[HID_Keyboard_Inst]` (HID_DEVICE_SYSTEM_KEYBOARD): o
//!   kbdhid, na classe Keyboard (o kbdclass é o filtro superior da classe);
//! - msmouse.inf `[HID_Mouse_Inst]` (HID_DEVICE_SYSTEM_MOUSE): o mouhid, na
//!   classe Mouse (com o mouclass).

use super::install::{ClassSpec, InfDriver, RegData, RegValue, ServiceSpec, CLASS_KEYBOARD, CLASS_MOUSE};

/// c_usb.inf `[Version]`.
pub const CLASS_USB: ClassSpec = ClassSpec { guid: "{36fc9e60-c465-11cf-8056-444553540000}", name: "USB", upper_filters: &[], lower_filters: &[] };
/// c_hidclass.inf `[Version]`.
pub const CLASS_HID: ClassSpec = ClassSpec { guid: "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}", name: "HIDClass", upper_filters: &[], lower_filters: &[] };

/// usbxhci.inf `[Generic.AddService]` com o `[USBXHCI.AddReg]`.
const SERVICE_USBXHCI: ServiceSpec = ServiceSpec {
    name: "USBXHCI",
    display_name: Some("@usbxhci.inf,%PCI\\CC_0C0330.DeviceDesc%;USB xHCI Compliant Host Controller"),
    start: 3,
    error_control: 1,
    binary: "USBXHCI.SYS",
    group: None,
    owner: "usbxhci.inf",
    values: &[
        RegValue { subkey: "", name: "BootFlags", data: RegData::Dword(16) },
        RegValue { subkey: "Parameters", name: "DmaRemappingCompatibleSelfhost", data: RegData::Dword(1) },
        RegValue { subkey: "Parameters", name: "DmaRemappingCompatible", data: RegData::Dword(2) },
    ],
};

/// usbxhci.inf `[Generic_AddReg.HW]` e pci.inf `[PciD3ColdSupported.RegHW]`
/// (HKR = Device Parameters).
const USBXHCI_HARDWARE: &[RegValue] = &[
    RegValue { subkey: "Interrupt Management", name: "", data: RegData::KeyOnly },
    RegValue { subkey: "Interrupt Management\\MessageSignaledInterruptProperties", name: "", data: RegData::KeyOnly },
    RegValue { subkey: "Interrupt Management\\MessageSignaledInterruptProperties", name: "MSISupported", data: RegData::Dword(1) },
    RegValue { subkey: "e5b3b5ac-9725-4f78-963f-03dfb1d828c7", name: "D3ColdSupported", data: RegData::Dword(1) },
];

/// usbhub3.inf `[Generic.AddService]` com o `[Service_AddReg]`.
const SERVICE_USBHUB3: ServiceSpec = ServiceSpec {
    name: "USBHUB3",
    display_name: Some("@usbhub3.inf,%UsbHub3.SVCDESC%;SuperSpeed Hub"),
    start: 3,
    error_control: 1,
    binary: "UsbHub3.sys",
    group: Some("Base"),
    owner: "usbhub3.inf",
    values: &[
        RegValue { subkey: "", name: "BootFlags", data: RegData::Dword(16) },
        RegValue { subkey: "Parameters\\Wdf", name: "LogPages", data: RegData::Dword(3) },
        RegValue { subkey: "Parameters", name: "LogPages", data: RegData::Dword(3) },
    ],
};

/// input.inf `[HID_Service_Inst]`.
const SERVICE_HIDUSB: ServiceSpec = ServiceSpec {
    name: "HidUsb",
    display_name: Some("@input.inf,%HID.SvcDesc%;Microsoft HID Class Driver"),
    start: 3,
    error_control: 0,
    binary: "hidusb.sys",
    group: Some("extended base"),
    owner: "input.inf",
    values: &[],
};

/// input.inf `[HID_Inst.AddReg.NT.HW]` (o SelectiveSuspendEnabled é
/// REG_BINARY, flag 1).
const HID_HARDWARE: &[RegValue] = &[
    RegValue { subkey: "", name: "SelectiveSuspendEnabled", data: RegData::Binary(&[0]) },
    RegValue { subkey: "", name: "EnhancedPowerManagementEnabled", data: RegData::Dword(1) },
    RegValue { subkey: "", name: "AllowIdleIrpInD3", data: RegData::Dword(1) },
    RegValue { subkey: "", name: "LegacyTouchScaling", data: RegData::Dword(0) },
    RegValue { subkey: "", name: "WriteReportExSupported", data: RegData::Dword(1) },
    RegValue { subkey: "", name: "DeviceResetNotificationEnabled", data: RegData::Dword(1) },
];

/// keyboard.inf `[KbdHid_Service_Inst]` com o `[KbdHid_Service_Inst_AddReg]`.
const SERVICE_KBDHID: ServiceSpec = ServiceSpec {
    name: "kbdhid",
    display_name: Some("@keyboard.inf,%KBDHID.SvcDesc%;Keyboard HID Driver"),
    start: 3,
    error_control: 0,
    binary: "kbdhid.sys",
    group: None,
    owner: "keyboard.inf",
    values: &[RegValue { subkey: "Parameters", name: "WorkNicely", data: RegData::Dword(0) }],
};

/// msmouse.inf `[MouHid_Service_Inst]` com o `[MouHid_Service_Inst_AddReg]`.
const SERVICE_MOUHID: ServiceSpec = ServiceSpec {
    name: "mouhid",
    display_name: Some("@msmouse.inf,%MOUHID.SvcDesc%;Mouse HID Driver"),
    start: 3,
    error_control: 0,
    binary: "mouhid.sys",
    group: None,
    owner: "msmouse.inf",
    values: &[
        RegValue { subkey: "Parameters", name: "UseOnlyMice", data: RegData::Dword(0) },
        RegValue { subkey: "Parameters", name: "TreatAbsoluteAsRelative", data: RegData::Dword(0) },
        RegValue { subkey: "Parameters", name: "TreatAbsolutePointerAsAbsolute", data: RegData::Dword(0) },
    ],
};

/// msmouse.inf `[HID_Mouse_Inst.AddReg.NT]` (HKR = Device Parameters).
const HID_MOUSE_HARDWARE: &[RegValue] = &[
    RegValue { subkey: "", name: "FlipFlopWheel", data: RegData::Dword(0) },
    RegValue { subkey: "", name: "ForceAbsolute", data: RegData::Dword(0) },
    RegValue { subkey: "", name: "HScrollPageOverride", data: RegData::Dword(0) },
    RegValue { subkey: "", name: "HScrollUsageOverride", data: RegData::Dword(0) },
    RegValue { subkey: "", name: "HScrollHighResolutionDisable", data: RegData::Dword(0) },
    RegValue { subkey: "", name: "VScrollPageOverride", data: RegData::Dword(0) },
    RegValue { subkey: "", name: "VScrollUsageOverride", data: RegData::Dword(0) },
    RegValue { subkey: "", name: "VScrollHighResolutionDisable", data: RegData::Dword(0) },
    RegValue { subkey: "", name: "FlipFlopHScroll", data: RegData::Dword(0) },
];

/// Uma linha do usbhub3.inf (a mesma seção para os três ids).
const fn usbhub3(id: &'static str, description_key: &'static str, description: &'static str) -> InfDriver {
    InfDriver {
        inf: "usbhub3.inf",
        section: "Generic.Install",
        id,
        description_key,
        description,
        manufacturer_key: "Generic.Mfg",
        manufacturer: "(Standard USB HUBs)",
        provider: "Microsoft",
        driver_version: "10.0.19041.6456",
        service: Some(&SERVICE_USBHUB3),
        class: &CLASS_USB,
        driver_values: &[],
        device_values: &[],
        exclude_ids: &[],
    }
}

/// A linha GENERIC_HID_DEVICE do input.inf, por um dos CompatibleIDs dela.
const fn hid_usb(id: &'static str) -> InfDriver {
    InfDriver {
        inf: "input.inf",
        section: "HID_Inst",
        id,
        description_key: "HID.DeviceDesc",
        description: "USB Input Device",
        manufacturer_key: "StdMfg",
        manufacturer: "(Standard system devices)",
        provider: "Microsoft",
        driver_version: "10.0.19041.3636",
        service: Some(&SERVICE_HIDUSB),
        class: &CLASS_HID,
        driver_values: &[],
        device_values: HID_HARDWARE,
        exclude_ids: &[],
    }
}

/// As linhas, na ordem dos INFs.
pub const USB_DRIVERS: &[InfDriver] = &[
    InfDriver {
        inf: "usbxhci.inf",
        section: "Generic.Install",
        id: "PCI\\CC_0C0330",
        description_key: "PCI\\CC_0C0330.DeviceDesc",
        description: "USB xHCI Compliant Host Controller",
        manufacturer_key: "Generic.Mfg",
        manufacturer: "Generic USB xHCI Host Controller",
        provider: "Microsoft",
        driver_version: "10.0.19041.5794",
        service: Some(&SERVICE_USBXHCI),
        class: &CLASS_USB,
        driver_values: &[],
        device_values: USBXHCI_HARDWARE,
        exclude_ids: &["PCI\\VEN_1B73&DEV_1000&CC_0C0330", "PCI\\VEN_1B73&DEV_1400&CC_0C0330", "PCI\\VEN_1B73&DEV_1009&REV_00"],
    },
    usbhub3("USB\\ROOT_HUB30", "UsbHub3.RootHubDeviceDesc", "USB Root Hub (USB 3.0)"),
    usbhub3("USB\\USB30_HUB", "UsbHub3.Usb30HubDesc", "Generic SuperSpeed USB Hub"),
    usbhub3("USB\\USB20_HUB", "UsbHub3.Usb20HubDesc", "Generic USB Hub"),
    hid_usb("USB\\Class_03&SubClass_01"),
    hid_usb("USB\\Class_03"),
    InfDriver {
        inf: "keyboard.inf",
        section: "HID_Keyboard_Inst",
        id: "HID_DEVICE_SYSTEM_KEYBOARD",
        description_key: "HID.KeyboardDevice",
        description: "HID Keyboard Device",
        manufacturer_key: "Std-Keyboards",
        manufacturer: "(Standard keyboards)",
        provider: "Microsoft",
        driver_version: "10.0.19041.1",
        service: Some(&SERVICE_KBDHID),
        class: &CLASS_KEYBOARD,
        driver_values: &[],
        device_values: &[],
        exclude_ids: &[],
    },
    InfDriver {
        inf: "msmouse.inf",
        section: "HID_Mouse_Inst",
        id: "HID_DEVICE_SYSTEM_MOUSE",
        description_key: "HID.MouseDevice",
        description: "HID-compliant mouse",
        manufacturer_key: "StdMfg",
        manufacturer: "(Standard mouse types)",
        provider: "Microsoft",
        driver_version: "10.0.19041.1",
        service: Some(&SERVICE_MOUHID),
        class: &CLASS_MOUSE,
        driver_values: &[],
        device_values: HID_MOUSE_HARDWARE,
        exclude_ids: &[],
    },
];
