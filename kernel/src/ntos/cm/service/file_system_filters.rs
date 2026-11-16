//! Chaves de serviço do Filter Manager (FltMgr) e dos minifiltros de file
//! system da Microsoft que o OpenNT hospeda: FileInfo, Wof, storqosflt,
//! bindflt, wcifs, luafv e CldFlt.
//!
//! Os valores são os que a instalação do Windows 10 19041 grava (Type 2,
//! ErrorControl, Group, ImagePath quando há, DependOnService, DisplayName,
//! Description, SupportedFeatures e Tag), com a mesma diferença dos outros
//! drivers inbox (`inbox_drivers.rs`): Start = 3 (SERVICE_DEMAND_START).
//! Na instalação o FltMgr, o FileInfo e o Wof são de boot (0) e os outros
//! de início automático (2); aqui eles sobem quando pedidos
//! (`--start-driver`), e o DependOnService (FltMgr) faz o gerenciador de
//! serviços iniciar o FltMgr antes do primeiro minifiltro.
//!
//! O que faz um minifiltro se anexar a um volume é a subchave `Instances`:
//! o FltRegisterFilter lê `DefaultInstance` e, para cada instância, a
//! `Altitude` (a posição na pilha de filtros: quanto maior, mais perto do
//! topo) e as `Flags` (0: anexação automática a cada volume novo e aos já
//! montados no FltStartFiltering). As altitudes são as atribuídas pela
//! Microsoft a cada filtro.
//!
//! Dados puros da hive SYSTEM (veja `cm/seed.rs`).

use alloc::format;
use alloc::vec::Vec;

use super::super::seed::{SeedKey, REG_EXPAND_SZ, REG_SZ};

const SERVICE_FILE_SYSTEM_DRIVER: u32 = 2;
const SERVICE_DEMAND_START: u32 = 3;

/// Uma instância de minifiltro: (nome, altitude, flags).
type Instance = (&'static str, &'static str, u32);

/// A chave de serviço de um filtro de file system da instalação.
struct FilterService {
    name: &'static str,
    /// None: a chave da instalação não tem ImagePath (o padrão do I/O
    /// Manager, `\SystemRoot\System32\Drivers\<serviço>.sys`).
    image_path: Option<&'static str>,
    display_name: &'static str,
    description: Option<&'static str>,
    error_control: u32,
    group: &'static str,
    depend_on: &'static [&'static str],
    tag: Option<u32>,
    /// Outros DWORDs da chave (nome, valor).
    dwords: &'static [(&'static str, u32)],
    /// `Instances\DefaultInstance` e as instâncias (vazio: não é minifiltro).
    default_instance: &'static str,
    instances: &'static [Instance],
}

const FILTERS: &[FilterService] = &[
    FilterService {
        name: "FltMgr",
        image_path: Some("system32\\drivers\\fltmgr.sys"),
        display_name: "@%SystemRoot%\\system32\\drivers\\fltmgr.sys,-10001",
        description: Some("@%SystemRoot%\\system32\\drivers\\fltmgr.sys,-10000"),
        error_control: 3,
        group: "FSFilter Infrastructure",
        depend_on: &[],
        tag: Some(1),
        dwords: &[("AttachWhenLoaded", 1)],
        default_instance: "",
        instances: &[],
    },
    FilterService {
        name: "FileInfo",
        image_path: Some("System32\\drivers\\fileinfo.sys"),
        display_name: "@%SystemRoot%\\system32\\drivers\\fileinfo.sys,-100",
        description: Some("@%SystemRoot%\\system32\\drivers\\fileinfo.sys,-101"),
        error_control: 1,
        group: "FSFilter Bottom",
        depend_on: &["fltmgr"],
        tag: None,
        dwords: &[("SupportedFeatures", 7)],
        default_instance: "FileInfo",
        instances: &[("FileInfo", "40500", 0)],
    },
    FilterService {
        name: "Wof",
        image_path: None,
        display_name: "Windows Overlay File System Filter Driver",
        description: None,
        error_control: 1,
        group: "FSFilter Compression",
        depend_on: &["FltMgr"],
        tag: None,
        dwords: &[("SupportedFeatures", 7)],
        default_instance: "Wof Instance",
        instances: &[("Wof Instance", "40700", 0)],
    },
    FilterService {
        name: "storqosflt",
        image_path: Some("system32\\drivers\\storqosflt.sys"),
        display_name: "@%SystemRoot%\\System32\\drivers\\storqosflt.sys,-101",
        description: Some("@%SystemRoot%\\System32\\drivers\\storqosflt.sys,-102"),
        error_control: 1,
        group: "FSFilter Quota Management",
        depend_on: &["FltMgr"],
        tag: None,
        dwords: &[("SupportedFeatures", 3)],
        default_instance: "storqosflt",
        instances: &[("storqosflt", "244000", 0)],
    },
    FilterService {
        name: "bindflt",
        image_path: Some("\\SystemRoot\\system32\\drivers\\bindflt.sys"),
        display_name: "@%systemroot%\\system32\\drivers\\bindflt.sys,-100",
        description: Some("@%systemroot%\\system32\\drivers\\bindflt.sys,-101"),
        error_control: 1,
        group: "FSFilter Top",
        depend_on: &["FltMgr"],
        tag: None,
        dwords: &[("SupportedFeatures", 7)],
        default_instance: "bindflt Instance",
        instances: &[("bindflt Instance", "409800", 0)],
    },
    FilterService {
        name: "wcifs",
        image_path: Some("\\SystemRoot\\system32\\drivers\\wcifs.sys"),
        display_name: "@%systemroot%\\system32\\drivers\\wcifs.sys,-100",
        description: Some("@%systemroot%\\system32\\drivers\\wcifs.sys,-101"),
        error_control: 1,
        group: "FSFilter Virtualization",
        depend_on: &["FltMgr"],
        tag: None,
        dwords: &[("SupportedFeatures", 7)],
        default_instance: "wcifs Instance",
        instances: &[("wcifs Instance", "189900", 0), ("wcifs Outer Instance", "189899", 0)],
    },
    FilterService {
        name: "luafv",
        image_path: Some("\\SystemRoot\\system32\\drivers\\luafv.sys"),
        display_name: "@%systemroot%\\system32\\drivers\\luafv.sys,-100",
        description: Some("@%systemroot%\\system32\\drivers\\luafv.sys,-101"),
        error_control: 1,
        group: "FSFilter Virtualization",
        depend_on: &["FltMgr"],
        tag: None,
        dwords: &[("SupportedFeatures", 7)],
        default_instance: "luafv",
        instances: &[("luafv", "135000", 0)],
    },
    FilterService {
        name: "CldFlt",
        image_path: Some("system32\\drivers\\cldflt.sys"),
        display_name: "Windows Cloud Files Filter Driver",
        description: None,
        error_control: 1,
        group: "FSFilter HSM",
        depend_on: &["FltMgr"],
        tag: Some(1),
        dwords: &[("SupportedFeatures", 7)],
        default_instance: "CldFlt",
        instances: &[("CldFlt", "180451", 0)],
    },
];

/// Dado de um valor do `Parameters` de um filtro.
enum Parameter {
    Dword(u32),
    Text(&'static str),
}

/// A subchave `Parameters` que a instalação cria para cada filtro, com os
/// seus valores: (serviço, [(valor, dado)]). A do Wof existe vazia; o GUID
/// de rastreamento WPP do bindflt e do wcifs é o que o WppRecorder lê.
const PARAMETERS: &[(&str, &[(&str, Parameter)])] = &[
    ("Wof", &[]),
    ("bindflt", &[("DebugOptions", Parameter::Dword(0)), ("WppRecorder_TraceGuid", Parameter::Text("{1fd216eb-201e-4b4d-93ca-41f33d5a04ec}"))]),
    ("wcifs", &[("DebugOptions", Parameter::Dword(0xC)), ("WppRecorder_TraceGuid", Parameter::Text("{803cb23a-e32b-4200-bd82-d8a15919ac1b}"))]),
    ("luafv", &[("ProgramData", Parameter::Text("C:\\ProgramData"))]),
    ("CldFlt", &[("USMsgTimeoutMillis", Parameter::Dword(1000))]),
];

/// A chave dos parâmetros do prefetcher, que o DriverEntry do FileInfo abre
/// (sem ela, STATUS_OBJECT_NAME_NOT_FOUND) para ler os seus valores
/// opcionais: a instalação a cria com EnablePrefetcher = 3. Os demais
/// valores (BaseTime, BootId) o prefetcher grava em execução.
const PREFETCH_PARAMETERS: &str = "CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters";
const ENABLE_PREFETCHER: u32 = 3;

/// As chaves do FltMgr e dos minifiltros, com as `Instances`.
pub fn seed_keys() -> Vec<SeedKey> {
    let mut keys = Vec::new();
    for filter in FILTERS {
        let mut key = SeedKey::new(&format!("CurrentControlSet\\Services\\{}", filter.name));
        key.dword("Type", SERVICE_FILE_SYSTEM_DRIVER).dword("Start", SERVICE_DEMAND_START).dword("ErrorControl", filter.error_control);
        if let Some(image_path) = filter.image_path {
            key.text("ImagePath", REG_EXPAND_SZ, image_path);
        }
        key.text("DisplayName", REG_SZ, filter.display_name);
        if let Some(description) = filter.description {
            key.text("Description", REG_SZ, description);
        }
        key.text("Group", REG_SZ, filter.group);
        if !filter.depend_on.is_empty() {
            key.strings("DependOnService", filter.depend_on);
        }
        if let Some(tag) = filter.tag {
            key.dword("Tag", tag);
        }
        for &(name, value) in filter.dwords {
            key.dword(name, value);
        }
        keys.push(key);
        if filter.instances.is_empty() {
            continue;
        }
        let mut instances = SeedKey::new(&format!("CurrentControlSet\\Services\\{}\\Instances", filter.name));
        instances.text("DefaultInstance", REG_SZ, filter.default_instance);
        keys.push(instances);
        for &(instance, altitude, flags) in filter.instances {
            let mut key = SeedKey::new(&format!("CurrentControlSet\\Services\\{}\\Instances\\{}", filter.name, instance));
            key.text("Altitude", REG_SZ, altitude).dword("Flags", flags);
            keys.push(key);
        }
    }
    for (service, values) in PARAMETERS {
        let mut key = SeedKey::new(&format!("CurrentControlSet\\Services\\{service}\\Parameters"));
        for (name, data) in values.iter() {
            match data {
                Parameter::Dword(value) => key.dword(name, *value),
                Parameter::Text(text) => key.text(name, REG_SZ, text),
            };
        }
        keys.push(key);
    }
    let mut prefetch = SeedKey::new(PREFETCH_PARAMETERS);
    prefetch.dword("EnablePrefetcher", ENABLE_PREFETCHER);
    keys.push(prefetch);
    keys
}

/// O serviço é o FltMgr ou um dos minifiltros da tabela.
pub fn is_filter(name: &str) -> bool {
    FILTERS.iter().any(|filter| filter.name.eq_ignore_ascii_case(name))
}

/// Os minifiltros (serviços com `Instances`), na ordem da tabela.
pub fn minifilters() -> impl Iterator<Item = (&'static str, &'static [Instance])> {
    FILTERS.iter().filter(|filter| !filter.instances.is_empty()).map(|filter| (filter.name, filter.instances))
}
