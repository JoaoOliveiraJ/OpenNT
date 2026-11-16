//! O processamento da árvore de dispositivos (PipProcessDevNodeTree).
//!
//! Para cada nó novo que um barramento relata, na ordem do NT:
//! 1. PiProcessNewDeviceNode: QUERY_ID (DeviceID), QUERY_CAPABILITIES,
//!    QUERY_ID (InstanceID; sem UniqueID o PnP prefixa o ParentIdPrefix do
//!    pai, o PipMakeGloballyUniqueId), HardwareIDs, CompatibleIDs,
//!    QUERY_DEVICE_TEXT (descrição e local), QUERY_BUS_INFORMATION,
//!    QUERY_RESOURCES (configuração de boot) e QUERY_RESOURCE_REQUIREMENTS,
//!    tudo ao PDO; a chave `Enum\<instância>` recebe HardwareID,
//!    CompatibleIDs, Capabilities, UINumber, LocationInformation e
//!    ParentIdPrefix.
//! 2. Instalação, se a instância ainda não tem Service (`install`).
//! 3. PipCallDriverAddDevice: carrega e chama o AddDevice, com o PDO, dos
//!    LowerFilters da instância e da classe, do serviço e dos UpperFilters
//!    da instância e da classe, nessa ordem.
//! 4. Atribuição: FILTER_RESOURCE_REQUIREMENTS à pilha inteira com a lista
//!    do nó, arbitragem e tradução pelos árbitros e tradutores dos drivers
//!    de barramento acima do nó ou pelos da raiz (`arbiter`, `resources`).
//! 5. START_DEVICE com as listas bruta e traduzida; depois
//!    QUERY_CAPABILITIES e QUERY_PNP_DEVICE_STATE à pilha.
//! 6. PipEnumerateDevice: QUERY_DEVICE_RELATIONS(BusRelations) à pilha; os
//!    PDOs novos voltam ao passo 1.
//! IoInvalidateDeviceRelations de um nó desta árvore enfileira o pedido (o
//! PnpRequestDeviceAction): `process` drena a fila até ela esvaziar, com os
//! work items rodando entre os pedidos; fora dele, o pedido põe na fila de
//! trabalho atrasada o PnpDeviceActionWorker, que a drena (o volume que o
//! volmgr.sys relata quando o partmgr.sys lhe entrega uma partição, de um
//! work item, depois de a árvore já ter sido processada).

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::devnode::{self, capability, problem, DeviceNode, State};
use super::install;
use super::irp;
use super::resources::{CmList, Requirements};
use super::arbiter;
use crate::ntos::cm::service::system_drivers as services;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::{BusQueryIdType, DeviceObject, DeviceRelationType, DeviceTextType, NtStruct, WorkQueueItem};
use crate::ntos::io::{lifecycle, work_items};
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::device as device_objects;
use crate::rtl::{KernelError, SpinLock};

/// DEVICE_OBJECT.Flags de um PDO relatado por um barramento.
const DO_BUS_ENUMERATED_DEVICE: u32 = 0x1000;

/// Nós com BusRelations a reenumerar (IoInvalidateDeviceRelations).
static PENDING: SpinLock<VecDeque<u64>> = SpinLock::new(VecDeque::new());

/// O PnpDeviceActionWorker: o WORK_QUEUE_ITEM (do pool, na primeira vez),
/// se está na fila e se a fila de pedidos já está sendo drenada (pelo
/// worker ou por `process`).
struct ActionWorker {
    item: u64,
    queued: bool,
    active: bool,
}

static WORKER: SpinLock<ActionWorker> = SpinLock::new(ActionWorker { item: 0, queued: false, active: false });

/// Chave `Enum\<instância>`.
fn enum_key(instance_path: &str) -> String {
    format!("{}\\Enum\\{instance_path}", install::CONTROL_SET)
}

/// Monta a raiz (HTREE\ROOT\0) se ainda não existe.
pub fn initialize() -> Result<u64, KernelError> {
    let root_pdo = super::root::initialize()?;
    if !devnode::exists(root_pdo) {
        let mut root = DeviceNode::new(root_pdo, 0, 0);
        root.instance_path = String::from("HTREE\\ROOT\\0");
        root.device_id = String::from("HTREE\\ROOT");
        root.instance_id = String::from("0");
        root.state = State::Started;
        root.internal_driver = true;
        devnode::insert(root);
        devnode::set_root(root_pdo);
    }
    Ok(root_pdo)
}

/// Marca o PDO de um barramento interno: o próprio kernel é o driver dele
/// (sem serviço nem AddDevice).
pub fn mark_internal(pdo: u64) {
    let mut internal = INTERNAL.lock();
    if !internal.contains(&pdo) {
        internal.push(pdo);
    }
}

static INTERNAL: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// Ids de função cujo driver é o próprio kernel neste boot, para os PDOs
/// que um driver de barramento real (o pci.sys) relata.
static INTERNAL_IDS: SpinLock<Option<fn(&[String], &[String]) -> bool>> = SpinLock::new(None);

/// Registra o reconhecimento por ids dos nós do kernel.
pub fn set_internal_ids(predicate: fn(&[String], &[String]) -> bool) {
    *INTERNAL_IDS.lock() = Some(predicate);
}

fn is_internal(pdo: u64) -> bool {
    INTERNAL.lock().contains(&pdo)
}

fn is_internal_by_ids(hardware_ids: &[String], compatible_ids: &[String]) -> bool {
    let predicate = *INTERNAL_IDS.lock();
    predicate.is_some_and(|predicate| predicate(hardware_ids, compatible_ids))
}

/// PipProcessDevNodeTree a partir da raiz, até a fila de reenumeração
/// esvaziar. Entre um pedido e outro rodam os work items, como as threads de
/// trabalho do sistema rodam entre as ações de dispositivo do NT. Um pedido
/// que chega depois fica com o worker.
pub fn process() -> Result<(), KernelError> {
    let root = initialize()?;
    let nested = core::mem::replace(&mut WORKER.lock().active, true);
    let result = enumerate_device(root).and_then(|_| drain());
    if !nested {
        WORKER.lock().active = false;
    }
    if !PENDING.lock().is_empty() {
        request_worker();
    }
    result
}

/// Quantos pedidos de reenumeração esperam na fila.
pub fn pending_requests() -> usize {
    PENDING.lock().len()
}

/// Os pedidos de reenumeração na ordem de chegada.
fn drain() -> Result<(), KernelError> {
    for _ in 0..64 {
        work_items::run_queue();
        let next = PENDING.lock().pop_front();
        let Some(node) = next else { break };
        enumerate_device(node)?;
    }
    Ok(())
}

/// Põe o PnpDeviceActionWorker na DelayedWorkQueue, se ele ainda não está
/// na fila nem drenando os pedidos.
fn request_worker() {
    let mut worker = WORKER.lock();
    if worker.queued || worker.active {
        return;
    }
    if worker.item == 0 {
        worker.item = pool_allocation::allocate_tagged(0, WorkQueueItem::SIZE, u32::from_le_bytes(*b"PnPw")).unwrap_or(0);
        if worker.item == 0 {
            return;
        }
    }
    worker.queued = true;
    let item = worker.item;
    drop(worker);
    work_items::queue_kernel_ex_work_item(item, device_action_worker, 0);
}

/// PnpDeviceActionWorker: drena os pedidos em PASSIVE_LEVEL.
fn device_action_worker(_item: u64, _parameter: u64) {
    {
        let mut worker = WORKER.lock();
        worker.queued = false;
        if worker.active {
            return;
        }
        worker.active = true;
    }
    let result = drain();
    WORKER.lock().active = false;
    if let Err(error) = result {
        debug_print!("[pnp] acao de dispositivo: {}", error);
    }
    if !PENDING.lock().is_empty() {
        request_worker();
    }
}

/// IoInvalidateDeviceRelations de um dispositivo desta árvore. Devolve
/// false se o dispositivo não tem nó (o chamador segue o caminho antigo).
/// Como no ntoskrnl 19041 (rva 0x36f560), BusRelations (a ação 9 do
/// PnpRequestDeviceAction, a subárvore) e SingleBusRelations (a ação 8, só o
/// dispositivo; o volmgr.sys relata assim cada volume novo) pedem a
/// reenumeração do nó.
pub fn invalidate_relations(device: u64, relation: u32) -> bool {
    let Some(node) = devnode::of_device(device) else { return false };
    if relation == DeviceRelationType::BUS_RELATIONS.0 as u32 || relation == DeviceRelationType::SINGLE_BUS_RELATIONS.0 as u32 {
        {
            let mut pending = PENDING.lock();
            if !pending.contains(&node.pdo) {
                pending.push_back(node.pdo);
            }
        }
        request_worker();
    }
    debug_print!("[pnp] relacoes {} invalidadas: {}", relation, node.instance_path);
    true
}

/// PipEnumerateDevice: BusRelations à pilha do nó e os filhos novos.
fn enumerate_device(pdo: u64) -> Result<(), KernelError> {
    let Some(node) = devnode::get(pdo) else { return Ok(()) };
    if node.state != State::Started {
        return Ok(());
    }
    let Some(children) = irp::query_device_relations(pdo, DeviceRelationType::BUS_RELATIONS)? else { return Ok(()) };
    let fresh: Vec<u64> = children.iter().copied().filter(|child| !devnode::exists(*child)).collect();
    if !children.is_empty() {
        debug_print!("[pnp] {}: {} filho(s), {} novo(s)", node.instance_path, children.len(), fresh.len());
    }
    // O driver referenciou cada objeto da DEVICE_RELATIONS; os já conhecidos
    // devolvem a referência.
    for child in children.iter().filter(|child| !fresh.contains(child)) {
        device_objects::dereference(*child)?;
    }
    for &child in &fresh {
        // O PnP marca cada PDO que um barramento relata (PipEnumerateCompleted).
        // SAFETY: DEVICE_OBJECT relatado (e referenciado) pelo barramento.
        let flags = &unsafe { DeviceObject::at(child) }.flags;
        flags.set(flags.get() | DO_BUS_ENUMERATED_DEVICE);
        devnode::insert(DeviceNode::new(child, pdo, node.level + 1));
        if let Err(error) = process_new_device_node(child) {
            debug_print!("[pnp] nó novo falhou: {}", error);
            continue;
        }
    }
    // AddDevice dos irmãos antes do START de cada um, como o NT.
    for &child in &fresh {
        if devnode::get(child).is_some_and(|node| node.state == State::Initialized) {
            add_drivers(child)?;
        }
    }
    for &child in &fresh {
        if devnode::get(child).is_some_and(|node| node.state == State::DriversAdded) {
            start_device_node(child)?;
            enumerate_device(child)?;
        }
    }
    Ok(())
}

/// O hash do caminho do pai no PipMakeGloballyUniqueId (ntoskrnl 19041 rva
/// 0x76baec): RtlUpcaseUnicodeString do caminho, h = h * 37 + c em 32 bits,
/// o produto por 314159269 como inteiro de 32 bits com sinal, o valor
/// absoluto de 32 bits (cdq/xor/sub) e o resto do idiv por 1000000007.
pub fn parent_id_hash(path: &str) -> u32 {
    let mut hash: u32 = 0;
    for unit in path.to_uppercase().encode_utf16() {
        hash = hash.wrapping_mul(37).wrapping_add(unit as u32);
    }
    let product = hash.wrapping_mul(314_159_269) as i32;
    (product.wrapping_abs() % 1_000_000_007) as u32
}

/// Texto de prefixo pai (`%x&%x&%x`: nível do pai, hash do caminho do pai
/// e o contador NextParentID), gravado como ParentIdPrefix na chave do pai.
fn parent_id_prefix(parent: &DeviceNode) -> Result<String, KernelError> {
    let parent_key = enum_key(&parent.instance_path);
    if let Some(prefix) = install::read_text(&parent_key, "ParentIdPrefix") {
        return Ok(prefix);
    }
    let scrambled = parent_id_hash(&parent.instance_path);
    let counter_key = format!("{}\\Control\\Enum", install::CONTROL_SET);
    let counter_name = format!("NextParentID.{scrambled:x}.{:x}", parent.level);
    let next = install::read_dword(&counter_key, &counter_name).unwrap_or(0);
    install::write_dword(&counter_key, &counter_name, next + 1)?;
    let prefix = format!("{:x}&{scrambled:x}&{next:x}", parent.level);
    install::write_text(&parent_key, "ParentIdPrefix", &prefix)?;
    Ok(prefix)
}

/// PiProcessNewDeviceNode: ids, capacidades, textos, barramento e recursos
/// do PDO; chave da instância; instalação.
fn process_new_device_node(pdo: u64) -> Result<(), KernelError> {
    let node = devnode::get(pdo).ok_or_else(|| KernelError::new("nó sem registro"))?;
    let parent = devnode::get(node.parent).ok_or_else(|| KernelError::new("nó sem pai"))?;
    let device_id = irp::query_id(pdo, BusQueryIdType::BUS_QUERY_DEVICE_ID)?.into_iter().next().unwrap_or_default();
    if device_id.is_empty() {
        devnode::update(pdo, |node| {
            node.state = State::Failed;
            node.problem = problem::NOT_CONFIGURED;
        });
        return Err(KernelError::new("PDO sem DeviceID"));
    }
    let capabilities = irp::query_capabilities(pdo)?.unwrap_or_default();
    devnode::update(pdo, |node| node.capabilities = capabilities.clone());
    let node = devnode::get(pdo).unwrap_or(node);
    let instance_id = irp::query_id(pdo, BusQueryIdType::BUS_QUERY_INSTANCE_ID)?.into_iter().next().unwrap_or_default();
    let unique_instance = if node.capability_bit(capability::UNIQUE_ID) {
        instance_id.clone()
    } else {
        let prefix = parent_id_prefix(&parent)?;
        if instance_id.is_empty() { prefix } else { format!("{prefix}&{instance_id}") }
    };
    let instance_path = format!("{device_id}\\{unique_instance}");
    let hardware_ids = irp::query_id(pdo, BusQueryIdType::BUS_QUERY_HARDWARE_I_DS)?;
    let compatible_ids = irp::query_id(pdo, BusQueryIdType::BUS_QUERY_COMPATIBLE_I_DS)?;
    let description = irp::query_device_text(pdo, DeviceTextType::DEVICE_TEXT_DESCRIPTION)?;
    let location = irp::query_device_text(pdo, DeviceTextType::DEVICE_TEXT_LOCATION_INFORMATION)?;
    let bus_information = irp::query_bus_information(pdo)?;
    let boot_resources = irp::query_resources(pdo)?;
    let requirements = irp::query_resource_requirements(pdo)?;
    debug_print!("[pnp] nó {} (hw {:?}, compat {:?})", instance_path, hardware_ids, compatible_ids);
    let key = enum_key(&instance_path);
    if !hardware_ids.is_empty() {
        install::write_multi(&key, "HardwareID", &hardware_ids)?;
    }
    if !compatible_ids.is_empty() {
        install::write_multi(&key, "CompatibleIDs", &compatible_ids)?;
    }
    if capabilities.len() >= 8 {
        install::write_dword(&key, "Capabilities", u32::from_le_bytes([capabilities[4], capabilities[5], capabilities[6], capabilities[7]]) & 0x3FF)?;
    }
    let ui_number = node.capability_word(capability::UI_NUMBER);
    if ui_number != 0xFFFF_FFFF {
        install::write_dword(&key, "UINumber", ui_number)?;
    }
    if let Some(location) = &location {
        install::write_text(&key, "LocationInformation", location)?;
    }
    let mut service = install::read_text(&key, "Service");
    let internal = is_internal(pdo) || is_internal_by_ids(&hardware_ids, &compatible_ids);
    // Uma instância com classe e sem serviço foi instalada com o driver nulo
    // (as seções NO_DRV do machine.inf).
    let mut installed = service.is_some() || install::read_text(&key, "ClassGUID").is_some();
    if !installed && !internal {
        match install::select_driver(&hardware_ids, &compatible_ids) {
            Some(driver) => {
                let matching = hardware_ids.iter().chain(compatible_ids.iter()).find(|id| id.eq_ignore_ascii_case(driver.id)).cloned().unwrap_or_default();
                service = install::install_device(&instance_path, driver, &matching)?;
                installed = true;
                debug_print!("[pnp] {}: instalado por {} [{}] -> {}", instance_path, driver.inf, driver.section, service.as_deref().unwrap_or("sem driver funcional"));
            }
            None => debug_print!("[pnp] {}: sem driver nos INFs", instance_path),
        }
    } else if let Some(service) = &service {
        install::register_service_instance(service, &instance_path)?;
    }
    devnode::update(pdo, |node| {
        node.device_id = device_id;
        node.instance_id = unique_instance;
        node.instance_path = instance_path;
        node.hardware_ids = hardware_ids;
        node.compatible_ids = compatible_ids;
        node.description = description;
        node.location = location;
        node.bus_information = bus_information;
        node.boot_resources = boot_resources;
        node.requirements = requirements;
        node.internal_driver = internal;
        node.service = service.clone();
        if installed || internal {
            node.state = State::Initialized;
        } else {
            node.state = State::Failed;
            node.problem = problem::FAILED_INSTALL;
        }
    });
    Ok(())
}

/// Filtros (REG_MULTI_SZ) de uma chave.
fn filters(key: &str, name: &str) -> Vec<String> {
    install::read_multi(key, name)
}

/// Carrega o serviço (se preciso) e chama o AddDevice dele com o PDO.
fn call_add_device(service: &str, pdo: u64) -> Result<(), u32> {
    if object_manager::lookup(&format!("\\Driver\\{service}")).is_none() && !services::load_service_driver(service) {
        debug_print!("[pnp] servico {} nao carregou", service);
        return Err(problem::DRIVER_FAILED_LOAD);
    }
    let status = lifecycle::call_add_device(service, pdo) as u32;
    debug_print!("[pnp] AddDevice de {} -> {:#x}", service, status);
    if status as i32 >= 0 {
        Ok(())
    } else {
        Err(problem::FAILED_ADD)
    }
}

/// PipCallDriverAddDevice: filtros inferiores, serviço, filtros superiores.
fn add_drivers(pdo: u64) -> Result<(), KernelError> {
    let node = devnode::get(pdo).ok_or_else(|| KernelError::new("nó sem registro"))?;
    if node.internal_driver {
        devnode::update(pdo, |node| node.state = State::DriversAdded);
        return Ok(());
    }
    let Some(service) = node.service.clone() else {
        // Sem driver funcional (PipCallDriverAddDevice, serviço não
        // encontrado): o dispositivo que o barramento declara RawDeviceOK
        // inicia cru, só com o PDO; os demais ficam sem iniciar, sem
        // problema.
        if node.capability_bit(capability::RAW_DEVICE_OK) {
            debug_print!("[pnp] {}: sem driver funcional, inicia cru (RawDeviceOK)", node.instance_path);
            devnode::update(pdo, |node| node.state = State::DriversAdded);
        } else {
            debug_print!("[pnp] {}: sem driver funcional e sem RawDeviceOK, fica sem iniciar", node.instance_path);
        }
        return Ok(());
    };
    let key = enum_key(&node.instance_path);
    let class_key = install::read_text(&key, "ClassGUID").map(|guid| format!("{}\\Control\\Class\\{guid}", install::CONTROL_SET));
    let class_filters = |name: &str| class_key.as_deref().map(|class| filters(class, name)).unwrap_or_default();
    let mut order: Vec<(String, bool)> = Vec::new();
    order.extend(filters(&key, "LowerFilters").into_iter().map(|name| (name, false)));
    order.extend(class_filters("LowerFilters").into_iter().map(|name| (name, false)));
    order.push((service.clone(), true));
    order.extend(filters(&key, "UpperFilters").into_iter().map(|name| (name, false)));
    order.extend(class_filters("UpperFilters").into_iter().map(|name| (name, false)));
    for (driver, function) in order {
        let before = device_objects::top(pdo);
        if let Err(code) = call_add_device(&driver, pdo) {
            devnode::update(pdo, |node| {
                node.state = State::Failed;
                node.problem = code;
            });
            return Ok(());
        }
        if function {
            let fdo = device_objects::top(pdo);
            devnode::update(pdo, |node| node.function_device = if fdo != before { fdo } else { 0 });
        }
    }
    devnode::update(pdo, |node| node.state = State::DriversAdded);
    Ok(())
}

/// Atribuição de recursos, START_DEVICE e as consultas depois dele.
fn start_device_node(pdo: u64) -> Result<(), KernelError> {
    let node = devnode::get(pdo).ok_or_else(|| KernelError::new("nó sem registro"))?;
    let mut requirements_list = node.requirements;
    let (raw, translated) = if requirements_list != 0 || !node.internal_driver {
        if requirements_list != 0 {
            requirements_list = irp::filter_resource_requirements(pdo, requirements_list)?;
        }
        match Requirements::read(requirements_list) {
            Some(requirements) if requirements.alternatives.iter().any(|alternative| !alternative.is_empty()) => match arbiter::allocate(pdo, &requirements)? {
                Some((raw, translated)) => (Some(raw), Some(translated)),
                None => {
                    debug_print!("[pnp] {}: conflito de recursos", node.instance_path);
                    devnode::update(pdo, |node| {
                        node.state = State::Failed;
                        node.problem = problem::NORMAL_CONFLICT;
                    });
                    return Ok(());
                }
            },
            _ => (None, None),
        }
    } else {
        (None, None)
    };
    let raw_list = raw.as_ref().map_or(0, CmList::write);
    let translated_list = translated.as_ref().map_or(0, CmList::write);
    devnode::update(pdo, |node| {
        node.requirements = requirements_list;
        node.resources_raw = raw_list;
        node.resources_translated = translated_list;
        node.state = State::ResourcesAssigned;
    });
    if let (Some(raw), Some(translated)) = (&raw, &translated) {
        debug_print!("[pnp] {}: recursos {:x?}", node.instance_path, raw.resources.iter().map(|resource| (resource.resource_type, resource.start, resource.length)).collect::<Vec<_>>());
        if translated.resources != raw.resources {
            debug_print!("[pnp] {}: traduzidos {:x?}", node.instance_path, translated.resources.iter().map(|resource| (resource.resource_type, resource.start, resource.length)).collect::<Vec<_>>());
        }
    }
    let status = irp::start_device(pdo, raw_list, translated_list)?;
    debug_print!("[pnp] START_DEVICE {} -> {:#x}", node.instance_path, status as u32);
    if status < 0 {
        arbiter::release(pdo);
        devnode::update(pdo, |node| {
            node.state = State::Failed;
            node.problem = problem::FAILED_START;
        });
        return Ok(());
    }
    devnode::update(pdo, |node| node.state = State::Started);
    if let Some(capabilities) = irp::query_capabilities(pdo)? {
        devnode::update(pdo, |node| node.capabilities = capabilities);
    }
    let _ = irp::query_pnp_device_state(pdo)?;
    Ok(())
}

/// Lista dos nós (instância, estado, problema, serviço) para o log.
pub fn summary() -> Vec<(String, State, u32, Option<String>)> {
    devnode::all().into_iter().map(|node| (node.instance_path, node.state, node.problem, node.service)).collect()
}
