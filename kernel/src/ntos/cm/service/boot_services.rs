//! Chaves de serviço dos drivers .sys que o boot instala (como
//! `\System\CurrentControlSet\Services` no NT): a pilha de teclado e mouse
//! sob demanda, a de armazenamento no boot (port -> class -> Mount Manager),
//! o vgk e o watchdog sob demanda e, no boot do processo inicial real, os
//! file systems de pipes nomeados e mailslots; os parâmetros do i8042prt e
//! as classes de teclado e mouse com os filtros superiores.
//!
//! Dados puros da hive SYSTEM (veja `cm/seed.rs`): cada serviço com os
//! valores que o banco de serviços grava numa instalação (Type, Start,
//! ErrorControl, ImagePath em `\SystemRoot\System32\Drivers`, DisplayName =
//! o nome, ObjectName = LocalSystem e DependOnService vazio). Os drivers de
//! integração da suíte de testes, compilados em C, ficam fora.

use alloc::format;
use alloc::vec::Vec;

use super::super::seed::{SeedKey, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ};

const SERVICES: &str = "CurrentControlSet\\Services";
const SERVICE_KERNEL_DRIVER: u32 = 1;
const SERVICE_FILE_SYSTEM_DRIVER: u32 = 2;

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

/// Os file systems de pipes nomeados e mailslots (SYSTEM_START), que o smss
/// abre para criar os prefixos protegidos.
const SMSS_DRIVERS: &[(&str, &str, u32, u32)] = &[("Npfs", "npfs.sys", 1, SERVICE_FILE_SYSTEM_DRIVER), ("Msfs", "msfs.sys", 1, SERVICE_FILE_SYSTEM_DRIVER)];

/// Os parâmetros do i8042prt que o INF criaria.
const I8042PRT_PARAMETERS: &[(&str, u32)] = &[
    ("KeyboardDataQueueSize", 0x64),
    ("MouseDataQueueSize", 0x64),
    ("PollStatusIterations", 0x2000),
    ("PollingIterations", 0x1900),
    ("ResendIterations", 3),
    ("OverrideKeyboardType", 0),
    ("CrashOnCtrlScroll", 0),
];

/// Classes de dispositivo com os UpperFilters que o PnP anexa sobre o FDO.
const DEVICE_CLASSES: &[(&str, &[&str])] = &[("{4D36E96B-E325-11CE-BFC1-08002BE10318}", &["kbdclass"]), ("{4D36E96F-E325-11CE-BFC1-08002BE10318}", &["mouclass"])];

/// A chave de um serviço como o banco de serviços a instala.
pub fn service_key(name: &str, service_type: u32, start: u32, error_control: u32, image_path: &str, display_name: &str) -> SeedKey {
    let mut key = SeedKey::new(&format!("{SERVICES}\\{name}"));
    key.dword("Type", service_type).dword("Start", start).dword("ErrorControl", error_control).text("ImagePath", REG_EXPAND_SZ, image_path).text("DisplayName", REG_SZ, display_name).text("ObjectName", REG_SZ, "LocalSystem").value("DependOnService", REG_MULTI_SZ, alloc::vec![0, 0, 0, 0]);
    key
}

fn driver_list(drivers: &[(&str, &str, u32, u32)]) -> Vec<SeedKey> {
    drivers.iter().map(|&(name, file, start, service_type)| service_key(name, service_type, start, 1, &format!("\\SystemRoot\\System32\\Drivers\\{file}"), name)).collect()
}

pub fn driver_keys() -> Vec<SeedKey> {
    driver_list(DRIVERS)
}

pub fn smss_driver_keys() -> Vec<SeedKey> {
    driver_list(SMSS_DRIVERS)
}

pub fn parameter_keys() -> Vec<SeedKey> {
    let mut keys = Vec::new();
    let mut parameters = SeedKey::new(&format!("{SERVICES}\\i8042prt\\Parameters"));
    for &(name, value) in I8042PRT_PARAMETERS {
        parameters.dword(name, value);
    }
    keys.push(parameters);
    for &(class, filters) in DEVICE_CLASSES {
        let mut key = SeedKey::new(&format!("Control\\Class\\{class}"));
        key.strings("UpperFilters", filters);
        keys.push(key);
    }
    keys
}
