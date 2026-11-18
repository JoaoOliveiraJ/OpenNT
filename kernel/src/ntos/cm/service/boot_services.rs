//! Chaves de serviço dos drivers .sys que o boot instala (como
//! `\System\CurrentControlSet\Services` no NT): a pilha de teclado e mouse
//! sob demanda, a de armazenamento no boot (port -> class -> Mount Manager)
//! e o vgk e o watchdog sob demanda; os parâmetros do i8042prt e do kbdclass e as classes
//! de teclado e mouse com os filtros superiores. Os file systems de pipes
//! nomeados e mailslots entram em todo boot com as chaves da instalação
//! (`inbox_drivers.rs`).
//!
//! Dados puros da hive SYSTEM (veja `cm/seed.rs`): cada serviço com os
//! valores que o banco de serviços grava numa instalação (Type, Start,
//! ErrorControl, ImagePath em `\SystemRoot\System32\Drivers`, DisplayName =
//! o nome e DependOnService vazio). Nenhuma leva ObjectName: num driver ele é
//! o nome do DRIVER_OBJECT (o IopGetDriverNameFromKeyNode o usa no lugar de
//! `\Driver\<serviço>` ou `\FileSystem\<serviço>`), e as chaves de driver da
//! instalação não o têm. Os drivers de integração da suíte de testes,
//! compilados em C, ficam fora.

use alloc::format;
use alloc::vec::Vec;

use super::super::seed::{SeedKey, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ};

const SERVICES: &str = "CurrentControlSet\\Services";
const CONTROL_CLASS: &str = "CurrentControlSet\\Control\\Class";
const SERVICE_KERNEL_DRIVER: u32 = 1;

/// (serviço, arquivo em System32\Drivers, Start, Type).
const DRIVERS: &[(&str, &str, u32, u32)] = &[
    // i8042prt: demand, inicializado pela pilha de teclado; lê os padrões
    // da subchave Parameters no DriverEntry.
    ("i8042prt", "i8042prt.sys", 3, SERVICE_KERNEL_DRIVER),
    // kbdclass/mouclass: filtros de classe carregados quando o PnP casa um
    // devnode da classe Keyboard/Mouse.
    ("kbdclass", "kbdclass.sys", 3, SERVICE_KERNEL_DRIVER),
    ("mouclass", "mouclass.sys", 3, SERVICE_KERNEL_DRIVER),
    // Armazenamento na ordem de boot do NT: miniport IDE (o ataport carrega
    // como dependência de import), classe de disco e Mount Manager.
    ("atapi", "atapi.sys", 0, SERVICE_KERNEL_DRIVER),
    ("disk", "disk.sys", 0, SERVICE_KERNEL_DRIVER),
    ("mountmgr", "mountmgr.sys", 0, SERVICE_KERNEL_DRIVER),
    // vgk: binário real no volume (D:\VGK.SYS); o cng.sys carrega como
    // módulo de import. Iniciado pelo SCM ou por `--start-driver=vgk`.
    ("vgk", "vgk.sys", 3, SERVICE_KERNEL_DRIVER),
    // watchdog.sys: dependência do stack de vídeo (dxgkrnl/BasicDisplay).
    ("watchdog", "watchdog.sys", 3, SERVICE_KERNEL_DRIVER),
];

/// Os parâmetros do i8042prt que o INF criaria, com o CrashOnCtrlScroll
/// ligado: o despejo manual pelo teclado da documentação do Windows (Ctrl
/// direito pressionado e Scroll Lock duas vezes), em que o próprio
/// i8042prt.sys chama KeBugCheckEx(MANUALLY_INITIATED_CRASH).
const I8042PRT_PARAMETERS: &[(&str, u32)] = &[
    ("KeyboardDataQueueSize", 0x64),
    ("MouseDataQueueSize", 0x64),
    ("PollStatusIterations", 0x2000),
    ("PollingIterations", 0x1900),
    ("ResendIterations", 3),
    ("OverrideKeyboardType", 0),
    ("CrashOnCtrlScroll", 1),
];

/// `Services\kbdclass\Parameters` como uma instalação do Windows a deixa,
/// lida no DriverEntry do kbdclass. Com ConnectMultiplePorts = 0 cada porta
/// de teclado (o i8042prt, o kbdhid de cada teclado HID) recebe o próprio FDO
/// com nome, `\Device\KeyboardClassN`; sem a chave o kbdclass cai no modo
/// "grand master", com um só dispositivo nomeado e os FDOs das portas sem
/// nome.
const KBDCLASS_PARAMETERS: &[(&str, u32)] = &[("ConnectMultiplePorts", 0), ("KeyboardDataQueueSize", 100), ("MaximumPortsServiced", 3), ("SendOutputToAllPorts", 1)];
const KBDCLASS_DEVICE_BASE_NAME: &str = "KeyboardClass";

/// Uma chave de classe de dispositivo em `Control\Class\{guid}`, com os
/// valores que o `[ClassInstall32]` do INF da classe grava numa instalação
/// do Windows 10 19041 (c_keyboard.inf, msmouse.inf).
struct DeviceClass {
    guid: &'static str,
    class: &'static str,
    description: &'static str,
    upper_filters: &'static [&'static str],
    icon_path: &'static str,
    /// `Default Service` da classe Mouse (o i8042prt).
    default_service: Option<&'static str>,
}

/// As classes Keyboard e Mouse, com os UpperFilters que o PnP anexa sobre o
/// FDO do port driver (o kbdclass e o mouclass).
const DEVICE_CLASSES: &[DeviceClass] = &[
    DeviceClass { guid: "{4D36E96B-E325-11CE-BFC1-08002BE10318}", class: "Keyboard", description: "@%SystemRoot%\\System32\\SysClass.Dll,-3002", upper_filters: &["kbdclass"], icon_path: "%SystemRoot%\\System32\\setupapi.dll,-3", default_service: None },
    DeviceClass { guid: "{4D36E96F-E325-11CE-BFC1-08002BE10318}", class: "Mouse", description: "@%SystemRoot%\\System32\\SysClass.Dll,-3004", upper_filters: &["mouclass"], icon_path: "%SystemRoot%\\System32\\setupapi.dll,-2", default_service: Some("i8042prt") },
];

/// A chave de um serviço de driver como o banco de serviços a instala (sem
/// ObjectName).
pub fn service_key(name: &str, service_type: u32, start: u32, error_control: u32, image_path: &str, display_name: &str) -> SeedKey {
    let mut key = SeedKey::new(&format!("{SERVICES}\\{name}"));
    key.dword("Type", service_type).dword("Start", start).dword("ErrorControl", error_control).text("ImagePath", REG_EXPAND_SZ, image_path).text("DisplayName", REG_SZ, display_name).value("DependOnService", REG_MULTI_SZ, alloc::vec![0, 0, 0, 0]);
    key
}

fn driver_list(drivers: &[(&str, &str, u32, u32)]) -> Vec<SeedKey> {
    drivers.iter().map(|&(name, file, start, service_type)| service_key(name, service_type, start, 1, &format!("\\SystemRoot\\System32\\Drivers\\{file}"), name)).collect()
}

pub fn driver_keys() -> Vec<SeedKey> {
    driver_list(DRIVERS)
}

pub fn parameter_keys() -> Vec<SeedKey> {
    let mut keys = Vec::new();
    let mut parameters = SeedKey::new(&format!("{SERVICES}\\i8042prt\\Parameters"));
    for &(name, value) in I8042PRT_PARAMETERS {
        parameters.dword(name, value);
    }
    keys.push(parameters);
    let mut kbdclass = SeedKey::new(&format!("{SERVICES}\\kbdclass\\Parameters"));
    for &(name, value) in KBDCLASS_PARAMETERS {
        kbdclass.dword(name, value);
    }
    kbdclass.text("KeyboardDeviceBaseName", REG_SZ, KBDCLASS_DEVICE_BASE_NAME);
    keys.push(kbdclass);
    // No conjunto de controle, como as demais chaves de classe
    // (`ControlSet001\Control\Class`, pelo link `CurrentControlSet`).
    for class in DEVICE_CLASSES {
        let mut key = SeedKey::new(&format!("{CONTROL_CLASS}\\{}", class.guid));
        key.text("Class", REG_SZ, class.class).text("ClassDesc", REG_SZ, class.description).strings("UpperFilters", class.upper_filters).strings("IconPath", &[class.icon_path]);
        if let Some(service) = class.default_service {
            key.text("Default Service", REG_SZ, service);
        }
        key.text("NoInstallClass", REG_SZ, "1");
        keys.push(key);
    }
    keys
}
