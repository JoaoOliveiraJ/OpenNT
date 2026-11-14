//! Árvore de dispositivos do PnP manager (os DEVICE_NODEs do NT).
//!
//! Um nó por PDO, com o que o PnP descobriu dele: os ids (QUERY_ID), o
//! caminho da instância em `Enum`, as capacidades, o barramento, a
//! configuração de boot, os requisitos e os recursos atribuídos (brutos e
//! traduzidos), o serviço e o estado do ciclo (inicializado, drivers
//! adicionados, recursos atribuídos, iniciado) ou o problema que o parou,
//! com os códigos CM_PROB_* do NT. O nó raiz é `HTREE\ROOT\0`, sobre o PDO
//! do `\Driver\PnpManager`. O registro é do OpenNT: os drivers nunca leem o
//! DEVICE_NODE, só os serviços do kernel que perguntam pelo PDO.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::ob::objects::device as device_objects;
use crate::rtl::SpinLock;

/// CM_PROB_* (cfg.h) usados pelo PnP.
pub mod problem {
    pub const NOT_CONFIGURED: u32 = 0x01;
    pub const FAILED_START: u32 = 0x0A;
    pub const NORMAL_CONFLICT: u32 = 0x0C;
    pub const FAILED_INSTALL: u32 = 0x1C;
    pub const FAILED_ADD: u32 = 0x1F;
    pub const FAILED_DRIVER_ENTRY: u32 = 0x25;
    pub const DRIVER_FAILED_LOAD: u32 = 0x27;
}

/// Estado do nó (PNP_DEVNODE_STATE, a parte que o OpenNT percorre).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    Uninitialized,
    Initialized,
    DriversAdded,
    ResourcesAssigned,
    Started,
    /// Parado com um CM_PROB_* em `problem`.
    Failed,
}

/// Um DEVICE_NODE.
#[derive(Clone, Debug)]
pub struct DeviceNode {
    pub pdo: u64,
    /// PDO do nó pai (0 só na raiz).
    pub parent: u64,
    pub children: Vec<u64>,
    pub level: u32,
    pub state: State,
    pub problem: u32,
    /// `Enum\<instance_path>` (ex.: `PCI\VEN_8086&DEV_7010&...\1&...&0&09`).
    pub instance_path: String,
    pub device_id: String,
    pub instance_id: String,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    /// DEVICE_CAPABILITIES do QUERY_CAPABILITIES (0x40 bytes).
    pub capabilities: Vec<u8>,
    /// PNP_BUS_INFORMATION: GUID, INTERFACE_TYPE e número do barramento.
    pub bus_information: Option<([u8; 16], i32, u32)>,
    /// CM_RESOURCE_LIST da configuração de boot (pool do kernel; 0 = nenhuma).
    pub boot_resources: u64,
    /// IO_RESOURCE_REQUIREMENTS_LIST corrente (pool; 0 = sem requisitos).
    pub requirements: u64,
    /// Listas do START_DEVICE (pool; 0 = sem recursos).
    pub resources_raw: u64,
    pub resources_translated: u64,
    /// Serviço do driver funcional (valor `Service` da chave da instância).
    pub service: Option<String>,
    /// FDO do driver funcional (o primeiro DEVICE_OBJECT acima do PDO que não
    /// é filtro inferior), depois dos AddDevice.
    pub function_device: u64,
    /// Nó cujo driver é o próprio kernel (barramento interno): sem AddDevice.
    pub internal_driver: bool,
}

impl DeviceNode {
    pub fn new(pdo: u64, parent: u64, level: u32) -> Self {
        DeviceNode {
            pdo,
            parent,
            children: Vec::new(),
            level,
            state: State::Uninitialized,
            problem: 0,
            instance_path: String::new(),
            device_id: String::new(),
            instance_id: String::new(),
            hardware_ids: Vec::new(),
            compatible_ids: Vec::new(),
            description: None,
            location: None,
            capabilities: Vec::new(),
            bus_information: None,
            boot_resources: 0,
            requirements: 0,
            resources_raw: 0,
            resources_translated: 0,
            service: None,
            function_device: 0,
            internal_driver: false,
        }
    }

    /// Bit de DEVICE_CAPABILITIES (deslocamento em bitfield_4, +4).
    pub fn capability_bit(&self, shift: u32) -> bool {
        self.capabilities.len() >= 8 && u32::from_le_bytes([self.capabilities[4], self.capabilities[5], self.capabilities[6], self.capabilities[7]]) >> shift & 1 != 0
    }

    /// DEVICE_CAPABILITIES.Address (+8) e UINumber (+0xC); 0xFFFFFFFF = ausente.
    pub fn capability_word(&self, offset: usize) -> u32 {
        if self.capabilities.len() < offset + 4 {
            return 0xFFFF_FFFF;
        }
        u32::from_le_bytes([self.capabilities[offset], self.capabilities[offset + 1], self.capabilities[offset + 2], self.capabilities[offset + 3]])
    }
}

/// Bits de DEVICE_CAPABILITIES (wdm.h).
pub mod capability {
    pub const REMOVABLE: u32 = 4;
    pub const UNIQUE_ID: u32 = 6;
    pub const SILENT_INSTALL: u32 = 7;
    pub const RAW_DEVICE_OK: u32 = 8;
    pub const SURPRISE_REMOVAL_OK: u32 = 9;
    pub const HARDWARE_DISABLED: u32 = 14;
    pub const NO_DISPLAY_IN_UI: u32 = 17;
    pub const ADDRESS: usize = 8;
    pub const UI_NUMBER: usize = 0xC;
}

static TREE: SpinLock<BTreeMap<u64, DeviceNode>> = SpinLock::new(BTreeMap::new());
/// PDO do nó raiz (HTREE\ROOT\0).
static ROOT: SpinLock<u64> = SpinLock::new(0);

pub fn insert(node: DeviceNode) {
    let pdo = node.pdo;
    let parent = node.parent;
    let mut tree = TREE.lock();
    tree.insert(pdo, node);
    if let Some(parent) = tree.get_mut(&parent) {
        if !parent.children.contains(&pdo) {
            parent.children.push(pdo);
        }
    }
}

pub fn set_root(pdo: u64) {
    *ROOT.lock() = pdo;
}

pub fn root() -> u64 {
    *ROOT.lock()
}

pub fn get(pdo: u64) -> Option<DeviceNode> {
    TREE.lock().get(&pdo).cloned()
}

pub fn exists(pdo: u64) -> bool {
    pdo != 0 && TREE.lock().contains_key(&pdo)
}

pub fn update<T>(pdo: u64, change: impl FnOnce(&mut DeviceNode) -> T) -> Option<T> {
    TREE.lock().get_mut(&pdo).map(change)
}

/// O nó de qualquer DEVICE_OBJECT da pilha (o PDO é a base dela).
pub fn of_device(device: u64) -> Option<DeviceNode> {
    if device == 0 || !device_objects::is_device(device) {
        return None;
    }
    get(device_objects::base(device))
}

/// PDO do nó com este caminho de instância (sem diferenciar maiúsculas).
pub fn by_instance_path(path: &str) -> Option<u64> {
    TREE.lock().values().find(|node| node.instance_path.eq_ignore_ascii_case(path)).map(|node| node.pdo)
}

/// Retira um nó (e o tira da lista do pai).
pub fn remove(pdo: u64) -> Option<DeviceNode> {
    let mut tree = TREE.lock();
    let node = tree.remove(&pdo)?;
    if let Some(parent) = tree.get_mut(&node.parent) {
        parent.children.retain(|&child| child != pdo);
    }
    Some(node)
}

/// Todos os nós (para os autotestes e a listagem).
pub fn all() -> Vec<DeviceNode> {
    TREE.lock().values().cloned().collect()
}
