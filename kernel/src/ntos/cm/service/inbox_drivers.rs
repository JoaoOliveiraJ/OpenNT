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
//! sucesso com handle nulo, como num Windows com o pcw desligado. No boot
//! do processo inicial real (`--initial-process=smss`) o DXGKrnl volta ao
//! Start 1 da instalação: o boot o carrega com os drivers de sistema, antes
//! de o smss carregar o win32k.sys, que se conecta a \Device\DxgKrnl. As
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
//! DriverEntry; a WdfLdr e a SleepStudyHelper não têm chave. A extensão de
//! classe UCX dos drivers de controladora USB (Ucx01000, Start 3 e Group
//! "Boot Bus Extender" na instalação, com BootFlags 16) entra igual, com a
//! chave da versão 1.1 da classe Ucx (Control\Wdf\Kmdf\Ucx\Versions\1\1),
//! pela qual o WdfVersionBindClass do usbxhci.sys acha o serviço.
//!
//! Null, Beep e Fs_Rec não têm ImagePath na instalação
//! (o I/O Manager usa \SystemRoot\System32\Drivers\<serviço>.sys), e o
//! Fs_Rec é do tipo SERVICE_RECOGNIZER_DRIVER (8): as chaves deles levam
//! Type, Start, ErrorControl e DisplayName (quando há), sem ImagePath, como
//! na instalação.
//!
//! O driver de vídeo básico (BasicDisplay, Start 1 e Group "Video" na
//! instalação) também fica sob demanda: o PnP o carrega quando instala o
//! adaptador VGA pelo display.inf (`--display=basic`). A chave tem o
//! ImagePath da instalação, no repositório de drivers
//! (System32\DriverStore\FileRepository\basicdisplay.inf_amd64_...), os
//! Owners (display.inf e basicdisplay.inf) e o Parameters\SingleDeviceInstall
//! que o AddReg do basicdisplay.inf grava.
//!
//! O dispositivo de exibição desconectado do win32k (`\Device\Disc`, o da
//! sessão sem console, como a sessão 0 dos serviços) aponta, pelo
//! HARDWARE\DEVICEMAP\VIDEO que o próprio win32k grava, para
//! `Services\TSDDD\Device0`; a instalação traz essa chave sem driver, só
//! com InstalledDisplayDrivers = TSDDD e VgaCompatible = 0, e o win32k a
//! abre ao criar o dispositivo (DrvSetDisconnectedGraphicsDevice).
//!
//! O CLFS (clfs.sys, Start 0 e Group "Filter" na instalação) fica sob
//! demanda como os outros: ele sobe como dependência de import do ntfs.sys,
//! e o DriverEntry dele lê Parameters (EventLogLevel, FlushThreshold e
//! MasterFilePath) pelo RtlQueryRegistryValuesEx, que falha sem a chave.
//!
//! Os file systems de pipes nomeados (Npfs) e de mailslots (Msfs) também
//! entram como na instalação, sem diferença: Type 2, Start 1
//! (SERVICE_SYSTEM_START, carregados pelo boot com os outros drivers de
//! sistema), ErrorControl 1, Group "File system" e sem ImagePath; o Npfs
//! leva a subchave Aliases, que o npfs.sys lê no DriverEntry.
//!
//! Os drivers de software sem hardware também ficam sob demanda, com os
//! valores da instalação: o cache de compatibilidade de aplicativos
//! (ahcache, Start 1 e sem Group na instalação: a chave fica sem Group), o
//! IFS do Winsock 2 (ws2ifsl, Start 4), o navegador de rede (bowser, Type 2,
//! Group Network, Tag 5) e os sockets AF_UNIX (afunix, Start 1). A subchave
//! Parameters\Winsock do afunix (do modo usuário) não é copiada.
//!
//! Dados puros da hive SYSTEM (veja `cm/seed.rs`): cada driver com os
//! valores que o banco de serviços grava numa instalação seguidos de Group,
//! Tag e os DWORDs próprios.

use alloc::format;
use alloc::vec::Vec;

use super::super::seed::{SeedKey, REG_SZ};
use super::boot_services::service_key;

const SERVICE_KERNEL_DRIVER: u32 = 1;
const SERVICE_FILE_SYSTEM_DRIVER: u32 = 2;
/// Os file systems da instalação (chaves sem ImagePath).
const FILE_SYSTEMS: &[&str] = &["Ntfs", "fastfat"];
const SERVICE_RECOGNIZER_DRIVER: u32 = 8;
/// `Npfs\Aliases`: (pipe, aliases) como REG_MULTI_SZ.
const NPFS_ALIASES: &[(&str, &[&str])] = &[("lsass", &["protected_storage", "netlogon", "lsarpc", "samr"]), ("ntsvcs", &["svcctl"])];
const SERVICE_SYSTEM_START: u32 = 1;
const SERVICE_DEMAND_START: u32 = 3;

/// Uma chave de serviço de driver da instalação.
struct InboxDriver {
    name: &'static str,
    display_name: Option<&'static str>,
    service_type: u32,
    /// None: a chave da instalação não tem ImagePath.
    image_path: Option<&'static str>,
    start: u32,
    /// Start no boot do processo inicial real (`--initial-process=smss`),
    /// quando ele segue o da instalação e não o sob demanda.
    smss_start: Option<u32>,
    error_control: u32,
    group: &'static str,
    tag: Option<u32>,
    /// Outros DWORDs da chave (nome, valor).
    dwords: &'static [(&'static str, u32)],
}

const DRIVERS: &[InboxDriver] = &[
    InboxDriver { name: "pcw", display_name: Some("Performance Counters for Windows Driver"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\drivers\\pcw.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "System Reserved", tag: None, dwords: &[] },
    InboxDriver { name: "condrv", display_name: Some("Console Driver"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\drivers\\condrv.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "Base", tag: None, dwords: &[] },
    InboxDriver { name: "KSecDD", display_name: None, service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\Drivers\\ksecdd.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 3, group: "Base", tag: Some(1), dwords: &[] },
    InboxDriver { name: "NDIS", display_name: Some("@%SystemRoot%\\system32\\drivers\\ndis.sys,-200"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("system32\\drivers\\ndis.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 3, group: "NDIS Wrapper", tag: None, dwords: &[] },
    InboxDriver {
        name: "Tcpip",
        display_name: Some("@%SystemRoot%\\system32\\drivers\\tcpip.sys,-10001"),
        service_type: SERVICE_KERNEL_DRIVER,
        image_path: Some("System32\\drivers\\tcpip.sys"),
        start: SERVICE_DEMAND_START,
        smss_start: None,
        error_control: 1,
        group: "PNP_TDI",
        tag: Some(3),
        dwords: &[("BootFlags", 1), ("NdisMajorVersion", 6), ("NdisMinorVersion", 40), ("DriverMajorVersion", 0), ("DriverMinorVersion", 0)],
    },
    InboxDriver { name: "DXGKrnl", display_name: Some("LDDM Graphics Subsystem"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys"), start: SERVICE_DEMAND_START, smss_start: Some(SERVICE_SYSTEM_START), error_control: 0, group: "Video Init", tag: Some(1), dwords: &[] },
    InboxDriver { name: "KSecPkg", display_name: None, service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\Drivers\\ksecpkg.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 3, group: "Cryptography", tag: Some(2), dwords: &[] },
    InboxDriver { name: "Null", display_name: None, service_type: SERVICE_KERNEL_DRIVER, image_path: None, start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "Base", tag: Some(1), dwords: &[] },
    InboxDriver { name: "Beep", display_name: Some("Beep"), service_type: SERVICE_KERNEL_DRIVER, image_path: None, start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "Base", tag: Some(2), dwords: &[] },
    InboxDriver { name: "Fs_Rec", display_name: None, service_type: SERVICE_RECOGNIZER_DRIVER, image_path: None, start: SERVICE_DEMAND_START, smss_start: None, error_control: 0, group: "File System", tag: None, dwords: &[] },
    InboxDriver { name: "CLFS", display_name: Some("@%SystemRoot%\\system32\\drivers\\clfs.sys,-100"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\drivers\\CLFS.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 3, group: "Filter", tag: Some(1), dwords: &[] },
    InboxDriver { name: "Npfs", display_name: None, service_type: SERVICE_FILE_SYSTEM_DRIVER, image_path: None, start: SERVICE_SYSTEM_START, smss_start: None, error_control: 1, group: "File system", tag: None, dwords: &[] },
    InboxDriver { name: "Msfs", display_name: None, service_type: SERVICE_FILE_SYSTEM_DRIVER, image_path: None, start: SERVICE_SYSTEM_START, smss_start: None, error_control: 1, group: "File system", tag: None, dwords: &[] },
    InboxDriver { name: "AFD", display_name: Some("@%systemroot%\\system32\\drivers\\afd.sys,-1000"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("\\SystemRoot\\system32\\drivers\\afd.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "PNP_TDI", tag: None, dwords: &[("BootFlags", 1)] },
    InboxDriver { name: "Wdf01000", display_name: Some("@%SystemRoot%\\system32\\drivers\\Wdf01000.sys,-1000"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("system32\\drivers\\Wdf01000.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "WdfLoadGroup", tag: None, dwords: &[] },
    InboxDriver { name: "Ucx01000", display_name: Some("USB Host Support Library"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("system32\\drivers\\ucx01000.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "Boot Bus Extender", tag: None, dwords: &[("BootFlags", 16)] },
    InboxDriver { name: "msisadrv", display_name: None, service_type: SERVICE_KERNEL_DRIVER, image_path: Some("System32\\drivers\\msisadrv.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 3, group: "Boot Bus Extender", tag: Some(2), dwords: &[] },
    InboxDriver {
        name: "BasicDisplay",
        display_name: None,
        service_type: SERVICE_KERNEL_DRIVER,
        image_path: Some("\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicdisplay.inf_amd64_19e58b6267591a82\\BasicDisplay.sys"),
        start: SERVICE_DEMAND_START,
        smss_start: None,
        error_control: 0,
        group: "Video",
        tag: Some(1),
        dwords: &[],
    },
    // Drivers de software sem hardware (Group "": a chave da instalação não tem Group).
    InboxDriver { name: "ahcache", display_name: Some("@%systemroot%\\system32\\drivers\\ahcache.sys,-102"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("system32\\DRIVERS\\ahcache.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "", tag: None, dwords: &[] },
    InboxDriver { name: "ws2ifsl", display_name: Some("@%systemroot%\\System32\\drivers\\ws2ifsl.sys,-1000"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("\\SystemRoot\\system32\\drivers\\ws2ifsl.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "PNP_TDI", tag: None, dwords: &[] },
    InboxDriver { name: "bowser", display_name: Some("@%systemroot%\\system32\\wkssvc.dll,-2001"), service_type: SERVICE_FILE_SYSTEM_DRIVER, image_path: Some("system32\\DRIVERS\\bowser.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "Network", tag: Some(5), dwords: &[] },
    InboxDriver { name: "afunix", display_name: Some("afunix"), service_type: SERVICE_KERNEL_DRIVER, image_path: Some("\\SystemRoot\\system32\\drivers\\afunix.sys"), start: SERVICE_DEMAND_START, smss_start: None, error_control: 1, group: "PNP_TDI", tag: None, dwords: &[] },
];

/// Dado de um valor que a instalação grava fora da chave do serviço.
enum Installed {
    Dword(u32),
    String(&'static str),
    Strings(&'static [&'static str]),
}

/// (chave abaixo de CurrentControlSet, valor, dado).
const INSTALLED_VALUES: &[(&str, &str, Installed)] = &[
    ("Services\\msisadrv\\Parameters\\Wdf", "WdfMajorVersion", Installed::Dword(1)),
    ("Services\\msisadrv\\Parameters\\Wdf", "WdfMinorVersion", Installed::Dword(0xF)),
    ("Control\\Wdf\\Kmdf\\KmdfLibrary\\Versions\\1", "Service", Installed::String("Wdf01000")),
    ("Control\\Wdf\\Kmdf\\Ucx\\Versions\\1\\1", "Service", Installed::String("ucx01000")),
    ("Services\\Ucx01000\\Parameters\\Wdf", "WdfMajorVersion", Installed::Dword(1)),
    ("Services\\Ucx01000\\Parameters\\Wdf", "WdfMinorVersion", Installed::Dword(0xF)),
    ("Services\\CLFS\\Parameters", "EventLogLevel", Installed::Dword(2)),
    ("Services\\CLFS\\Parameters", "FlushThreshold", Installed::Dword(0x9C40)),
    ("Services\\CLFS\\Parameters", "MasterFilePath", Installed::String("\\SystemRoot\\System32\\config")),
    ("Services\\BasicDisplay", "Owners", Installed::Strings(&["display.inf", "basicdisplay.inf"])),
    ("Services\\BasicDisplay\\Parameters", "SingleDeviceInstall", Installed::Dword(1)),
    ("Services\\TSDDD\\Device0", "InstalledDisplayDrivers", Installed::Strings(&["TSDDD"])),
    ("Services\\TSDDD\\Device0", "VgaCompatible", Installed::Dword(0)),
];

/// As chaves dos drivers inbox, dos file systems e os valores do KMDF.
/// `smss_boot`: o boot do processo inicial real (`--initial-process=smss`).
pub fn seed_keys(smss_boot: bool) -> Vec<SeedKey> {
    let mut keys = Vec::new();
    for driver in DRIVERS {
        let start = match driver.smss_start {
            Some(start) if smss_boot => start,
            _ => driver.start,
        };
        let mut key = match driver.image_path {
            Some(image_path) => service_key(driver.name, driver.service_type, start, driver.error_control, image_path, driver.display_name.unwrap_or(driver.name)),
            None => {
                let mut key = SeedKey::new(&format!("CurrentControlSet\\Services\\{}", driver.name));
                key.dword("Type", driver.service_type).dword("Start", start).dword("ErrorControl", driver.error_control);
                if let Some(display_name) = driver.display_name {
                    key.text("DisplayName", REG_SZ, display_name);
                }
                key
            }
        };
        if !driver.group.is_empty() {
            key.text("Group", REG_SZ, driver.group);
        }
        if let Some(tag) = driver.tag {
            key.dword("Tag", tag);
        }
        for &(name, value) in driver.dwords {
            key.dword(name, value);
        }
        keys.push(key);
    }
    for name in FILE_SYSTEMS {
        let mut key = SeedKey::new(&format!("CurrentControlSet\\Services\\{name}"));
        key.dword("Type", SERVICE_FILE_SYSTEM_DRIVER).dword("Start", SERVICE_DEMAND_START).dword("ErrorControl", 1).text("Group", REG_SZ, "Boot File System");
        keys.push(key);
    }
    for (path, name, data) in INSTALLED_VALUES {
        let mut key = SeedKey::new(&format!("CurrentControlSet\\{path}"));
        match data {
            Installed::Dword(value) => key.dword(name, *value),
            Installed::String(text) => key.text(name, REG_SZ, text),
            Installed::Strings(strings) => key.strings(name, strings),
        };
        keys.push(key);
    }
    let mut aliases = SeedKey::new("CurrentControlSet\\Services\\Npfs\\Aliases");
    for &(pipe, names) in NPFS_ALIASES {
        aliases.strings(pipe, names);
    }
    keys.push(aliases);
    keys
}
