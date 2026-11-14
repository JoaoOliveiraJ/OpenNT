//! Chaves de serviço de drivers inbox do Windows que o OpenNT inicia sob
//! demanda (`--start-driver` ou `sc start`): o provedor dos contadores de
//! desempenho (pcw), o console (condrv), o driver de segurança do kernel
//! (KSecDD) e o pacote de segurança dele (KSecPkg), a pilha de rede (NDIS,
//! Tcpip, AFD), o núcleo gráfico (DXGKrnl, de sistema (1) na instalação),
//! o \Device\Null (Null), o \Device\Beep (Beep) e os reconhecedores de
//! file system (Fs_Rec).
//!
//! Os valores são os da instalação do Windows 10 19041 (Type, ErrorControl,
//! Group, ImagePath, Tag, DisplayName e as versões de NDIS do Tcpip), com
//! uma diferença: Start = 3 (SERVICE_DEMAND_START). Na instalação pcw,
//! KSecDD, KSecPkg, NDIS, Tcpip e Fs_Rec são de boot (0) e AFD, Null e Beep
//! de sistema (1); aqui eles
//! ainda não fazem parte do boot e sobem quando pedidos (o DriverEntry do
//! pcw.sys ainda não completa). Com o pcw fora do boot, o
//! ExpPcwDisabledStatus lê Start != 0 e os Pcw* sem extensão devolvem
//! sucesso com handle nulo, como num Windows com o pcw desligado. As
//! subchaves com dados da máquina (Parameters, Linkage, interfaces) não são
//! copiadas. O NetIO não tem chave: ele carrega como dependência de import
//! do NDIS e do Tcpip.
//!
//! Os file systems Ntfs e fastfat entram com a chave como está na
//! instalação: Type 2 (SERVICE_FILE_SYSTEM_DRIVER), Start 3, ErrorControl 1
//! e Group "Boot File System", sem ImagePath (o padrão do I/O Manager,
//! `\SystemRoot\System32\Drivers\<serviço>.sys`).
//!
//! O KMDF também fica sob demanda: o runtime Wdf01000 (Start 0 na
//! instalação), que a WdfLdr.sys carrega pela chave no primeiro
//! WdfVersionBind de um cliente, e o msisadrv (Start 0), um cliente KMDF.
//! Ficam os valores que a
//! instalação grava para o framework: a versão do KMDF com que o cliente foi
//! compilado (Parameters\Wdf) e o serviço da biblioteca da versão maior 1
//! (Control\Wdf\Kmdf\KmdfLibrary\Versions\1), que a WdfLdr procura antes do
//! nome padrão. O Parameters do Wdf01000 o próprio runtime grava no
//! DriverEntry; a WdfLdr e a SleepStudyHelper não têm chave.
//!
//! Null, Beep e Fs_Rec não têm ImagePath na instalação
//! (o I/O Manager usa \SystemRoot\System32\Drivers\<serviço>.sys), e o
//! Fs_Rec é do tipo SERVICE_RECOGNIZER_DRIVER (8): as chaves deles são
//! gravadas valor a valor, sem ImagePath, como na instalação.

use crate::ntos::cm::registry;
use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput, ServiceError};
use crate::rtl::KernelError;

const SERVICE_KERNEL_DRIVER: u32 = 1;
const SERVICE_FILE_SYSTEM_DRIVER: u32 = 2;
/// Os file systems da instalação (chaves sem ImagePath).
const FILE_SYSTEMS: &[&str] = &["Ntfs", "fastfat"];
const SERVICE_RECOGNIZER_DRIVER: u32 = 8;
const SERVICE_DEMAND_START: u32 = 3;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

/// Uma chave de serviço de driver da instalação.
struct InboxDriver {
    name: &'static str,
    display_name: Option<&'static str>,
    service_type: u32,
    /// None: a chave da instalação não tem ImagePath.
    image_path: Option<&'static str>,
    start: u32,
    error_control: u32,
    group: &'static str,
    tag: Option<u32>,
    /// Outros DWORDs da chave (nome, valor).
    dwords: &'static [(&'static str, u32)],
}

const DRIVERS: &[InboxDriver] = &[
    InboxDriver { name: "pcw", display_name: Some("Performance Counters for Windows Driver"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\drivers\\pcw.sys"), start: SERVICE_DEMAND_START, error_control: 1, group: "System Reserved", tag: None, dwords: &[] },
    InboxDriver { name: "condrv", display_name: Some("Console Driver"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\drivers\\condrv.sys"), start: SERVICE_DEMAND_START, error_control: 1, group: "Base", tag: None, dwords: &[] },
    InboxDriver { name: "KSecDD", display_name: None, service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\Drivers\\ksecdd.sys"), start: SERVICE_DEMAND_START, error_control: 3, group: "Base", tag: Some(1), dwords: &[] },
    InboxDriver { name: "NDIS", display_name: Some("@%SystemRoot%\\system32\\drivers\\ndis.sys,-200"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("system32\\drivers\\ndis.sys"), start: SERVICE_DEMAND_START, error_control: 3, group: "NDIS Wrapper", tag: None, dwords: &[] },
    InboxDriver {
        name: "Tcpip",
        display_name: Some("@%SystemRoot%\\system32\\drivers\\tcpip.sys,-10001"),
        service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\drivers\\tcpip.sys"),
        start: SERVICE_DEMAND_START,
        error_control: 1,
        group: "PNP_TDI",
        tag: Some(3),
        dwords: &[("BootFlags", 1), ("NdisMajorVersion", 6), ("NdisMinorVersion", 40), ("DriverMajorVersion", 0), ("DriverMinorVersion", 0)],
    },
    InboxDriver { name: "DXGKrnl", display_name: Some("LDDM Graphics Subsystem"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys"), start: SERVICE_DEMAND_START, error_control: 0, group: "Video Init", tag: Some(1), dwords: &[] },
    InboxDriver { name: "KSecPkg", display_name: None, service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\Drivers\\ksecpkg.sys"), start: SERVICE_DEMAND_START, error_control: 3, group: "Cryptography", tag: Some(2), dwords: &[] },
    InboxDriver { name: "Null", display_name: None, service_type: SERVICE_KERNEL_DRIVER, image_path: None, start: SERVICE_DEMAND_START, error_control: 1, group: "Base", tag: Some(1), dwords: &[] },
    InboxDriver { name: "Beep", display_name: Some("Beep"), service_type: SERVICE_KERNEL_DRIVER, image_path: None, start: SERVICE_DEMAND_START, error_control: 1, group: "Base", tag: Some(2), dwords: &[] },
    InboxDriver { name: "Fs_Rec", display_name: None, service_type: SERVICE_RECOGNIZER_DRIVER, image_path: None, start: SERVICE_DEMAND_START, error_control: 0, group: "File System", tag: None, dwords: &[] },
    InboxDriver { name: "AFD", display_name: Some("@%systemroot%\\system32\\drivers\\afd.sys,-1000"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("\\SystemRoot\\system32\\drivers\\afd.sys"), start: SERVICE_DEMAND_START, error_control: 1, group: "PNP_TDI", tag: None, dwords: &[("BootFlags", 1)] },
    InboxDriver { name: "Wdf01000", display_name: Some("@%SystemRoot%\\system32\\drivers\\Wdf01000.sys,-1000"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("system32\\drivers\\Wdf01000.sys"), start: SERVICE_DEMAND_START, error_control: 1, group: "WdfLoadGroup", tag: None, dwords: &[] },
    InboxDriver { name: "msisadrv", display_name: None, service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\drivers\\msisadrv.sys"), start: SERVICE_DEMAND_START, error_control: 3, group: "Boot Bus Extender", tag: Some(2), dwords: &[] },
];

/// Dado de um valor que a instalação grava fora da chave do serviço.
enum Installed {
    Dword(u32),
    String(&'static str),
}

/// (chave abaixo de \Registry\Machine\System\CurrentControlSet, valor, dado).
const INSTALLED_VALUES: &[(&str, &str, Installed)] = &[
    ("Services\\msisadrv\\Parameters\\Wdf", "WdfMajorVersion", Installed::Dword(1)),
    ("Services\\msisadrv\\Parameters\\Wdf", "WdfMinorVersion", Installed::Dword(0xF)),
    ("Control\\Wdf\\Kmdf\\KmdfLibrary\\Versions\\1", "Service", Installed::String("Wdf01000")),
];

/// Instala as chaves (uma chave já instalada fica como está).
pub fn seed() -> Result<(), KernelError> {
    for driver in DRIVERS {
        let path = alloc::format!("{}\\{}", service_database::ROOT, driver.name);
        if let Some(image_path) = driver.image_path {
            let input = ConfigurationInput {
                name: alloc::string::String::from(driver.name),
                display_name: driver.display_name.map(alloc::string::String::from),
                image_path: Some(alloc::string::String::from(image_path)),
                service_type: Some(driver.service_type),
                start: Some(driver.start),
                error_control: Some(driver.error_control),
                ..ConfigurationInput::default()
            };
            match service_database::install(&input, true) {
                Ok(_) => {}
                Err(ServiceError::Win32(code, message)) => return Err(KernelError::new(alloc::format!("{}: {message} ({code})", driver.name))),
                Err(ServiceError::Kernel(error)) => return Err(error),
            }
        } else {
            // Sem ImagePath: os valores da chave, um a um (uma chave já
            // instalada fica como está).
            let existing = registry::open(&path)?;
            if existing != 0 {
                registry::close_handle(existing);
                continue;
            }
            let handle = registry::open_or_create(&path, None)?;
            for (name, value) in [("Type", driver.service_type), ("Start", driver.start), ("ErrorControl", driver.error_control)] {
                registry::set_value(handle, name, REG_DWORD, value.to_le_bytes().to_vec());
            }
            if let Some(display_name) = driver.display_name {
                registry::set_value(handle, "DisplayName", REG_SZ, registry::encode_wide(display_name));
            }
            registry::close_handle(handle);
        }
        let handle = registry::open_or_create(&path, None)?;
        registry::set_value(handle, "Group", REG_SZ, registry::encode_wide(driver.group));
        if let Some(tag) = driver.tag {
            registry::set_value(handle, "Tag", REG_DWORD, tag.to_le_bytes().to_vec());
        }
        for &(name, value) in driver.dwords {
            registry::set_value(handle, name, REG_DWORD, value.to_le_bytes().to_vec());
        }
        registry::close_handle(handle);
    }
    for name in FILE_SYSTEMS {
        let handle = registry::open_or_create(&alloc::format!("{}\\{}", service_database::ROOT, name), None)?;
        for (value_name, value) in [("Type", SERVICE_FILE_SYSTEM_DRIVER), ("Start", SERVICE_DEMAND_START), ("ErrorControl", 1)] {
            registry::set_value(handle, value_name, REG_DWORD, value.to_le_bytes().to_vec());
        }
        registry::set_value(handle, "Group", REG_SZ, registry::encode_wide("Boot File System"));
        registry::close_handle(handle);
    }
    for (key, name, data) in INSTALLED_VALUES {
        let handle = registry::open_or_create(&alloc::format!("\\Registry\\Machine\\System\\CurrentControlSet\\{key}"), None)?;
        match data {
            Installed::Dword(value) => registry::set_value(handle, name, REG_DWORD, value.to_le_bytes().to_vec()),
            Installed::String(text) => registry::set_value(handle, name, REG_SZ, registry::encode_wide(text)),
        };
        registry::close_handle(handle);
    }
    Ok(())
}
