//! Orquestrador PnP.
//!
//! Liga um driver funcional num PDO (AddDevice real), monta os filtros de
//! classe, inicia a pilha (START_DEVICE com a CM_RESOURCE_LIST do PDO) e
//! enumera os filhos (QUERY_DEVICE_RELATIONS/BusRelations), recursivamente.
//! A associação driver↔dispositivo vem dos ids de hardware, como o NT faz
//! pelo INF.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::io_manager::{self, irp_mn, IoParams, IoRequest};
use super::work_items;
use crate::ntos::cm::registry;
use crate::ntos::cm::service::system_drivers as services;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{DeviceObject, DeviceRelations, NtStruct};
use crate::ntos::io::{device, lifecycle};

/// hardwareId → serviço do driver funcional (o "INF estático").
pub const FUNCTION_DRIVER_BY_ID: &[(&str, &str)] = &[
    // Controlador PS/2 e mouse PS/2 → port driver.
    ("PNP0303", "i8042prt"),
    ("PNP0F13", "i8042prt"),
    // Controlador IDE do i440fx (PIIX3), casado pelo id exato da VM.
    ("PCI\\VEN_8086&DEV_7010", "atapi"),
];

/// Casamento por prefixo (o "IDE\Disk*" dos INFs).
const FUNCTION_DRIVER_BY_PREFIX: &[(&str, &str)] = &[("IDE\\Disk", "disk"), ("IDE\\CdRom", "cdrom")];

/// hardwareId → GUID da classe (para os UpperFilters).
pub const CLASS_GUID_BY_ID: &[(&str, &str)] = &[("PNP0303", "{4D36E96B-E325-11CE-BFC1-08002BE10318}"), ("PNP0F13", "{4D36E96F-E325-11CE-BFC1-08002BE10318}")];

/// Filhos enumerados: DEVICE_OBJECT → nó `\Device\<pai>_PDOn`.
static CREATED_CHILD_NODES: SpinLock<BTreeMap<u64, NodeId>> = SpinLock::new(BTreeMap::new());
static NEXT_CHILD_PDO_INDEX: SpinLock<u32> = SpinLock::new(0);

fn name_of(node: NodeId) -> String {
    object_manager::node(node).map(|node| node.name).unwrap_or_default()
}

/// Serviço do driver funcional: id exato primeiro, prefixo depois (como o
/// PnP tenta HardwareIDs antes de CompatibleIDs).
pub fn find_function_driver(hardware_ids: &[String]) -> Option<&'static str> {
    if let Some(exact) = hardware_ids.iter().find_map(|id| FUNCTION_DRIVER_BY_ID.iter().find(|(known, _)| known == id).map(|(_, service)| *service)) {
        return Some(exact);
    }
    hardware_ids.iter().find_map(|id| FUNCTION_DRIVER_BY_PREFIX.iter().find(|(prefix, _)| id.starts_with(prefix)).map(|(_, service)| *service))
}

/// AddDevice do driver funcional sobre o PDO; devolve o FDO novo, que herda
/// os recursos do PDO para o START_DEVICE.
pub fn attach_function_driver(pdo: NodeId, driver_name: &str) -> Option<NodeId> {
    let Some(driver_node) = object_manager::lookup(&format!("\\Driver\\{driver_name}")) else {
        debug_print!("[pnp] driver {} nao carregado", driver_name);
        return None;
    };
    let before = io_manager::driver_devices(driver_node);
    let pdo_entry = io_manager::device(pdo).unwrap_or_default();
    let status = lifecycle::call_add_device(driver_name, pdo_entry.native_device) as u32;
    if status != 0 {
        debug_print!("[pnp] AddDevice de {} falhou: 0x{:x}", driver_name, status);
        return None;
    }
    let fdo = io_manager::driver_devices(driver_node).into_iter().find(|device| !before.contains(device))?;
    io_manager::update_device(fdo, |entry| {
        entry.resources = pdo_entry.resources;
        entry.pdo_node = Some(pdo);
    });
    debug_print!("[pnp] {} anexado: FDO \\Device\\{} sobre PDO \\Device\\{}", driver_name, name_of(fdo), name_of(pdo));
    Some(fdo)
}

/// UpperFilters (REG_MULTI_SZ UTF-16LE) da classe de dispositivo.
pub fn read_class_upper_filters(class_guid: &str) -> Vec<String> {
    let Some(entry) = registry::read_value_by_path(&format!("\\Registry\\Machine\\System\\Control\\Class\\{class_guid}"), "UpperFilters") else { return Vec::new() };
    let mut names = Vec::new();
    let mut current = String::new();
    let mut index = 0;
    while index + 1 < entry.data.len() {
        let code = entry.data[index] as u16 | (entry.data[index + 1] as u16) << 8;
        if code == 0 {
            if current.is_empty() {
                break;
            }
            names.push(core::mem::take(&mut current));
        } else {
            current.push(char::from_u32(code as u32).unwrap_or('\u{FFFD}'));
        }
        index += 2;
    }
    names
}

/// Filtros de classe sobre o FDO (cada um recebe o AddDevice com o PDO) e
/// o topo da pilha nativa, para onde vão os IRPs PnP.
pub fn attach_upper_filters(pdo: NodeId, fdo: NodeId, hardware_ids: &[String]) {
    let Some(class_guid) = hardware_ids.iter().find_map(|id| CLASS_GUID_BY_ID.iter().find(|(known, _)| known == id).map(|(_, guid)| *guid)) else { return };
    let physical = io_manager::device(pdo).map_or(0, |entry| entry.native_device);
    for filter in read_class_upper_filters(class_guid) {
        if !services::load_service_driver(&filter) {
            debug_print!("[pnp] filtro {} indisponivel", filter);
            continue;
        }
        let status = lifecycle::call_add_device(&filter, physical) as u32;
        debug_print!("[pnp] AddDevice do filtro {} -> 0x{:x}", filter, status);
    }
    let mut top = io_manager::device(fdo).map_or(0, |entry| entry.native_device);
    for _ in 0..16 {
        // SAFETY: DEVICE_OBJECT vivo da pilha montada.
        let above = unsafe { DeviceObject::at(top) }.attached_device.get();
        if above == 0 {
            break;
        }
        top = above;
    }
    io_manager::update_device(fdo, |entry| entry.stack_top = top);
}

/// O PnP manager do NT despacha os IRPs de PnP com a árvore de devnodes
/// travada (PpDevNodeLockTree: KeEnterCriticalRegion + o ERESOURCE da
/// árvore): os drivers recebem START e QUERY_* com as APCs normais
/// desligadas e podem usar ExAcquireFastMutexUnsafe direto (o i8042prt
/// real faz isso no START). Sem KTHREAD corrente, segue sem a região.
pub fn with_device_tree_lock<T>(body: impl FnOnce() -> T) -> T {
    let entered = crate::ntos::ke::critical_region::enter_critical().is_ok();
    let result = body();
    if entered {
        let _ = crate::ntos::ke::critical_region::leave_critical();
    }
    result
}

fn send_pnp_minor(fdo: NodeId, minor: u8, params: IoParams) -> IoRequest {
    let mut request = io_manager::make_io_request(io_manager::irp_mj::PNP, IoParams { minor, ..params });
    let _ = with_device_tree_lock(|| io_manager::call_driver(&format!("\\Device\\{}", name_of(fdo)), &mut request));
    request
}

/// A sequência do PnP antes do START (capabilities, requisitos e filtro dos
/// requisitos) e o START_DEVICE.
pub fn start_device_stack(fdo: NodeId) -> i32 {
    // QUERY_CAPABILITIES leva o DEVICE_CAPABILITIES já alocado.
    let capabilities = guest::alloc_bytes(0x40);
    send_pnp_minor(fdo, irp_mn::QUERY_CAPABILITIES, IoParams { pnp_slot_pointer: capabilities, ..Default::default() });
    let requirements = send_pnp_minor(fdo, irp_mn::QUERY_RESOURCE_REQUIREMENTS, IoParams::default());
    if requirements.status == 0 && requirements.info != 0 {
        send_pnp_minor(fdo, irp_mn::FILTER_RESOURCE_REQUIREMENTS, IoParams { pnp_slot_pointer: requirements.info, ..Default::default() });
    }
    let status = io_manager::pnp_start_device(fdo).unwrap_or(-1);
    debug_print!("[pnp] START_DEVICE \\Device\\{} -> 0x{:x}", name_of(fdo), status as u32);
    status
}

/// QUERY_DEVICE_RELATIONS(BusRelations): DEVICE_RELATIONS (Count + PDOs).
/// Os ponteiros são lidos com 64 bits.
pub fn query_bus_relations(fdo: NodeId) -> Vec<u64> {
    let request = send_pnp_minor(fdo, irp_mn::QUERY_DEVICE_RELATIONS, IoParams { relations_type: Some(0), ..Default::default() });
    if request.status != 0 || request.info == 0 {
        return Vec::new();
    }
    // SAFETY: DEVICE_RELATIONS devolvido pelo driver em IoStatus.Information.
    let relations = unsafe { DeviceRelations::at(request.info) };
    let count = relations.count.get() as usize;
    // SAFETY: Objects[Count] segue o cabeçalho na mesma alocação.
    let objects = unsafe { Field::<u64>::array_at(relations.objects[0].address(), count) };
    let children = objects.iter().map(Field::get).collect();
    guest::free_bytes(request.info);
    children
}

/// Ids de hardware de um filho já registrado.
pub fn query_hardware_ids(device: u64) -> Vec<String> {
    let node = CREATED_CHILD_NODES.lock().get(&device).copied();
    node.and_then(io_manager::device).and_then(|entry| entry.hardware_ids).unwrap_or_default()
}

/// O filho vira `\Device\<pai>_PDOn` e responde QUERY_ID(HardwareIDs) pelo
/// despacho nativo do barramento.
pub fn register_child_pdo(parent_fdo: NodeId, child: u64) -> Option<NodeId> {
    let index = {
        let mut next = NEXT_CHILD_PDO_INDEX.lock();
        let index = *next;
        *next += 1;
        index
    };
    let name = format!("{}_PDO{index}", name_of(parent_fdo));
    let node = object_manager::create_object("\\Device", &name, "Device", Some(object_manager::ObjectData::pointer(child))).ok()?;
    io_manager::register_device(node, io_manager::DeviceEntry { native_device: child, pdo: true, child_of: Some(parent_fdo), ..Default::default() });
    CREATED_CHILD_NODES.lock().insert(child, node);
    let mut request = io_manager::make_io_request(io_manager::irp_mj::PNP, IoParams { minor: irp_mn::QUERY_ID, relations_type: Some(1), ..Default::default() });
    let _ = io_manager::call_driver(&format!("\\Device\\{name}"), &mut request);
    if request.status == 0 && request.info != 0 {
        // A leitura vai até o primeiro NUL: o primeiro id da lista.
        let ids = guest_strings::read_wide_string(request.info);
        let ids: Vec<String> = ids.split('\0').filter(|id| !id.is_empty()).map(String::from).collect();
        io_manager::update_device(node, |entry| entry.hardware_ids = Some(ids));
    }
    Some(node)
}

/// Sobe a pilha inteira de um PDO: driver funcional (carregado sob demanda),
/// filtros, START e enumeração recursiva dos filhos.
pub fn enumerate_pdo_stack(pdo: NodeId) -> Option<NodeId> {
    let entry = io_manager::device(pdo)?;
    if entry.stack_enumerated {
        return entry.function_stack;
    }
    let fdo = add_pdo_stack(pdo)?;
    start_pdo_stack(fdo);
    Some(fdo)
}

/// Irmãos de um mesmo barramento como o PnP manager do NT os processa:
/// primeiro o AddDevice (driver funcional e filtros) de todos, depois o
/// START de cada um. Port drivers que atendem vários irmãos (o i8042prt com
/// teclado e mouse) contam os AddDevice para saber quando inicializar o
/// controlador. Devolve o FDO de cada PDO, na ordem recebida.
pub fn enumerate_sibling_stacks(pdos: &[NodeId]) -> Vec<Option<NodeId>> {
    let added: Vec<(Option<NodeId>, bool)> = pdos
        .iter()
        .map(|&pdo| match io_manager::device(pdo) {
            Some(entry) if entry.stack_enumerated => (entry.function_stack, false),
            Some(_) => (add_pdo_stack(pdo), true),
            None => (None, false),
        })
        .collect();
    for &(fdo, fresh) in &added {
        if let (Some(fdo), true) = (fdo, fresh) {
            start_pdo_stack(fdo);
        }
    }
    added.into_iter().map(|(fdo, _)| fdo).collect()
}

/// Fase de AddDevice: ids, driver funcional e filtros de classe.
fn add_pdo_stack(pdo: NodeId) -> Option<NodeId> {
    let entry = io_manager::device(pdo)?;
    io_manager::update_device(pdo, |entry| entry.stack_enumerated = true);
    let mut ids = entry.hardware_ids.unwrap_or_default();
    // PDO sem ids preenchidos (PCI): pergunta ao barramento pelo QUERY_ID.
    if ids.is_empty() {
        if let Ok(Some(reported)) = io_manager::query_device_id(&format!("\\Device\\{}", name_of(pdo)), 0) {
            ids = alloc::vec![reported];
            let stored = ids.clone();
            io_manager::update_device(pdo, |entry| entry.hardware_ids = Some(stored));
        }
    }
    let Some(driver_name) = find_function_driver(&ids) else {
        debug_print!("[pnp] sem driver p/ {}", ids.first().cloned().unwrap_or_else(|| name_of(pdo)));
        return None;
    };
    // Serviço com Start=3: carrega agora, como o SCM ao instalar o devnode.
    if object_manager::lookup(&format!("\\Driver\\{driver_name}")).is_none() && !services::load_service_driver(driver_name) {
        debug_print!("[pnp] servico {} indisponivel", driver_name);
        return None;
    }
    let fdo = attach_function_driver(pdo, driver_name)?;
    io_manager::update_device(pdo, |entry| entry.function_stack = Some(fdo));
    // Filtros de classe antes do START: a pilha inteira recebe o START no topo.
    attach_upper_filters(pdo, fdo, &ids);
    Some(fdo)
}

/// Fase de START: a pilha recebe o START no topo e os filhos do barramento
/// são enumerados.
fn start_pdo_stack(fdo: NodeId) {
    if start_device_stack(fdo) != 0 {
        return;
    }
    // A inicialização de hardware dos port drivers roda em work item
    // deferido: drena a fila antes de enumerar os filhos.
    for _ in 0..4 {
        let _ = work_items::run_queue();
    }
    let children = query_bus_relations(fdo);
    debug_print!("[pnp] \\Device\\{}: {} filho(s) no bus", name_of(fdo), children.len());
    for child in children {
        let Some(child_node) = register_child_pdo(fdo, child) else { continue };
        let child_ids = io_manager::device(child_node).and_then(|entry| entry.hardware_ids).unwrap_or_default();
        if find_function_driver(&child_ids).is_some() {
            debug_print!("[pnp] filho \\Device\\{} ({}): montando pilha", name_of(child_node), child_ids.first().map(String::as_str).unwrap_or("?"));
            enumerate_pdo_stack(child_node);
        }
    }
}

/// Dispositivos invalidados por IoInvalidateDeviceState.
static INVALIDATED_DEVICES: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());

/// IoInvalidateDeviceState.
pub fn invalidate_device_state(device: u64) {
    INVALIDATED_DEVICES.lock().insert(device);
}

/// Dispositivos com estado invalidado (consultados pelo fluxo PnP).
pub fn invalidated(device: u64) -> bool {
    INVALIDATED_DEVICES.lock().contains(&device)
}

/// IoInvalidateDeviceRelations: reenumera as BusRelations do FDO pai.
pub fn invalidate_device_relations(device: u64, relation_type: u32) {
    let node = device::find_device_node_by_pointer(device);
    debug_print!("[pnp] relacoes invalidadas ({}) p/ \\Device\\{}", relation_type, node.map(device::device_name).unwrap_or_else(|| String::from("?")));
    let Some(node) = node else { return };
    let parent = io_manager::device(node).and_then(|entry| entry.child_of).unwrap_or(node);
    for child in query_bus_relations(parent) {
        let Some(child_node) = register_child_pdo(parent, child) else { continue };
        if io_manager::device(child_node).and_then(|entry| entry.hardware_ids).is_some_and(|ids| !ids.is_empty()) {
            enumerate_pdo_stack(child_node);
        }
    }
}

// ---- Nó NUMA do devnode (IoGetDeviceNumaNode, ntoskrnl 19041 0x7734f0) -------
//
// Pdo NULL, DEVICE_OBJECT sem devnode (DeviceObjectExtension->DeviceNode
// NULL) ou devnode com DNF 0x20000: STATUS_INVALID_PARAMETER. Com
// DeviceNode->NumaNodeIndex conhecido (<= 0xFFFFFFFD) grava esse USHORT; com
// o índice desconhecido (sem _PXM) devolve o nó 0 se a máquina tiver um só
// nó (KeQueryHighestNodeNumber() == 0), senão STATUS_NOT_FOUND. O OpenNT não
// lê _PXM (todo devnode tem índice desconhecido) e é de um nó só (o
// KeQueryHighestNodeNumber dele devolve 0); devnode = PDO do PnP do OpenNT.

const NUMA_STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// KeQueryHighestNodeNumber do OpenNT (máquina de um nó).
const HIGHEST_NODE_NUMBER: u16 = 0;

/// DEVICE_OBJECT com devnode: filho enumerado, PDO de barramento ou relatado.
fn has_device_node(pdo: u64) -> bool {
    pdo != 0 && io_manager::devices().into_iter().any(|(_, entry)| entry.native_device == pdo && (entry.pdo || entry.extra.is_some()))
}

/// IoGetDeviceNumaNode(Pdo, NodeNumber): `node` é o PUSHORT do chamador.
pub fn device_numa_node(pdo: u64, node: &crate::ntos::inc::types::Field<u16>) -> u32 {
    if !has_device_node(pdo) {
        return NUMA_STATUS_INVALID_PARAMETER;
    }
    // NumaNodeIndex desconhecido: só uma máquina de um nó responde nó 0.
    if HIGHEST_NODE_NUMBER != 0 {
        return 0xC000_0225;
    }
    node.set(0);
    0
}
