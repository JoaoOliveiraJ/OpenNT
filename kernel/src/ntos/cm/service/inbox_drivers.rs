//! Chaves de serviço de drivers inbox do Windows que o OpenNT inicia sob
//! demanda (`--start-driver` ou `sc start`): o provedor dos contadores de
//! desempenho (pcw), o console (condrv), o driver de segurança do kernel
//! (KSecDD), a pilha de rede (NDIS, Tcpip, AFD) e o núcleo gráfico (DXGKrnl,
//! de sistema (1) na instalação).
//!
//! Os valores são os da instalação do Windows 10 19041 (Type, ErrorControl,
//! Group, ImagePath, Tag, DisplayName e as versões de NDIS do Tcpip), com
//! uma diferença: Start = 3 (SERVICE_DEMAND_START). Na instalação pcw,
//! KSecDD, NDIS e Tcpip são de boot (0) e o AFD de sistema (1); aqui eles
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

use crate::ntos::cm::registry;
use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput, ServiceError};
use crate::rtl::KernelError;

const SERVICE_KERNEL_DRIVER: u32 = 1;
const SERVICE_FILE_SYSTEM_DRIVER: u32 = 2;
/// Os file systems da instalação (chaves sem ImagePath).
const FILE_SYSTEMS: &[&str] = &["Ntfs", "fastfat"];
const SERVICE_DEMAND_START: u32 = 3;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

/// Uma chave de serviço de driver da instalação.
struct InboxDriver {
    name: &'static str,
    display_name: Option<&'static str>,
    image_path: &'static str,
    start: u32,
    error_control: u32,
    group: &'static str,
    tag: Option<u32>,
    /// Outros DWORDs da chave (nome, valor).
    dwords: &'static [(&'static str, u32)],
}

const DRIVERS: &[InboxDriver] = &[
    InboxDriver { name: "pcw", display_name: Some("Performance Counters for Windows Driver"), image_path: "System32\\drivers\\pcw.sys", start: SERVICE_DEMAND_START, error_control: 1, group: "System Reserved", tag: None, dwords: &[] },
    InboxDriver { name: "condrv", display_name: Some("Console Driver"), image_path: "System32\\drivers\\condrv.sys", start: SERVICE_DEMAND_START, error_control: 1, group: "Base", tag: None, dwords: &[] },
    InboxDriver { name: "KSecDD", display_name: None, image_path: "System32\\Drivers\\ksecdd.sys", start: SERVICE_DEMAND_START, error_control: 3, group: "Base", tag: Some(1), dwords: &[] },
    InboxDriver { name: "NDIS", display_name: Some("@%SystemRoot%\\system32\\drivers\\ndis.sys,-200"), image_path: "system32\\drivers\\ndis.sys", start: SERVICE_DEMAND_START, error_control: 3, group: "NDIS Wrapper", tag: None, dwords: &[] },
    InboxDriver {
        name: "Tcpip",
        display_name: Some("@%SystemRoot%\\system32\\drivers\\tcpip.sys,-10001"),
        image_path: "System32\\drivers\\tcpip.sys",
        start: SERVICE_DEMAND_START,
        error_control: 1,
        group: "PNP_TDI",
        tag: Some(3),
        dwords: &[("BootFlags", 1), ("NdisMajorVersion", 6), ("NdisMinorVersion", 40), ("DriverMajorVersion", 0), ("DriverMinorVersion", 0)],
    },
    InboxDriver { name: "DXGKrnl", display_name: Some("LDDM Graphics Subsystem"), image_path: "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", start: SERVICE_DEMAND_START, error_control: 0, group: "Video Init", tag: Some(1), dwords: &[] },
    InboxDriver { name: "AFD", display_name: Some("@%systemroot%\\system32\\drivers\\afd.sys,-1000"), image_path: "\\SystemRoot\\system32\\drivers\\afd.sys", start: SERVICE_DEMAND_START, error_control: 1, group: "PNP_TDI", tag: None, dwords: &[("BootFlags", 1)] },
];

/// Instala as chaves (uma chave já instalada fica como está).
pub fn seed() -> Result<(), KernelError> {
    for driver in DRIVERS {
        let input = ConfigurationInput {
            name: alloc::string::String::from(driver.name),
            display_name: driver.display_name.map(alloc::string::String::from),
            image_path: Some(alloc::string::String::from(driver.image_path)),
            service_type: Some(SERVICE_KERNEL_DRIVER),
            start: Some(driver.start),
            error_control: Some(driver.error_control),
            ..ConfigurationInput::default()
        };
        match service_database::install(&input, true) {
            Ok(_) => {}
            Err(ServiceError::Win32(code, message)) => return Err(KernelError::new(alloc::format!("{}: {message} ({code})", driver.name))),
            Err(ServiceError::Kernel(error)) => return Err(error),
        }
        let handle = registry::open_or_create(&alloc::format!("{}\\{}", service_database::ROOT, driver.name), None)?;
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
    Ok(())
}
