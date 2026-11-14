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

/// PnPBootDriversInitialized. O boot daqui roda os drivers de boot e a
/// enumeração dos dispositivos do sistema de uma vez (`init::phase1`): a
/// marca cobre também o fim da enumeração (o evento
/// PnpSystemDeviceEnumerationComplete do NT).
static BOOT_DRIVERS_INITIALIZED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Os drivers de boot rodaram e os dispositivos do sistema foram enumerados.
pub fn mark_boot_drivers_initialized() {
    BOOT_DRIVERS_INITIALIZED.store(true, core::sync::atomic::Ordering::Release);
}

/// NtSerializeBoot: só de modo usuário (senão STATUS_ACCESS_DENIED), com
/// SeTcbPrivilege (senão STATUS_PRIVILEGE_NOT_HELD); o PnpSerializeBoot
/// devolve STATUS_UNSUCCESSFUL antes dos drivers de boot e, depois, espera o
/// fim da enumeração dos dispositivos do sistema, que aqui já terminou com
/// eles.
pub fn serialize_boot(previous_mode: u8) -> u32 {
    if previous_mode != 1 {
        return 0xC000_0022;
    }
    // SeTcbPrivilege.
    if !crate::ntos::se::privilege::single_privilege_check(7, previous_mode as u32) {
        return 0xC000_0061;
    }
    if !BOOT_DRIVERS_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return 0xC000_0001;
    }
    0
}
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

// ---- IoGetRelatedTargetDevice -----------------------------------------------------
//
// ntoskrnl 19041: IoGetRelatedTargetDevice 0x71b7cc -> PnpGetRelatedTargetDevice
// 0x360f2c: IoGetRelatedDeviceObject(FileObject) (NULL ->
// STATUS_NO_SUCH_DEVICE); IRP_MJ_PNP/IRP_MN_QUERY_DEVICE_RELATIONS
// (TargetDeviceRelation) síncrono a esse device, com o FILE_OBJECT na stack
// location (PnpSendIrp); falha devolve o status; sem DEVICE_RELATIONS ou com
// Count != 1, STATUS_NO_SUCH_DEVICE; a lista é liberada e o PDO precisa de
// devnode (PDO->DeviceObjectExtension->DeviceNode), senão
// STATUS_NO_SUCH_DEVICE. O PDO sai com a referência que a relação deu, e
// quem chama a solta com ObDereferenceObject. O devnode do OpenNT é o PDO do
// seu PnP (`has_device_node`), e o PDO devolvido é o DeviceNode->PhysicalDeviceObject.

const PNP_STATUS_NO_SUCH_DEVICE_TARGET: u32 = 0xC000_000E;

/// IoGetRelatedTargetDevice(FileObject, &DeviceObject): (NTSTATUS, PDO referenciado).
pub fn related_target_device(file_object: u64) -> Result<(u32, u64), crate::rtl::KernelError> {
    use crate::ntos::inc::types::{IoStackLocation, IoStatusBlock, Irp, Kevent};
    let related = crate::ntos::init::exports::invoke_handler("IoGetRelatedDeviceObject", &[file_object])?;
    if related == 0 {
        return Ok((PNP_STATUS_NO_SUCH_DEVICE_TARGET, 0));
    }
    let event = guest::alloc_bytes(Kevent::SIZE);
    let io_status = guest::alloc_bytes(IoStatusBlock::SIZE);
    crate::ntos::ke::dispatcher::initialize_event(event, 0, false);
    let packet = io_manager::build_synchronous_fsd_request(io_manager::irp_mj::PNP, related, 0, 0, 0, event, io_status);
    let (status, information) = if packet == 0 {
        (PNP_STATUS_INSUFFICIENT_RESOURCES, 0)
    } else {
        // SAFETY: IRP recém-montado pelo I/O Manager.
        let irp = unsafe { Irp::at(packet) };
        // SAFETY: o slot do primeiro driver, logo abaixo de CurrentStackLocation.
        let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
        irp.io_status.status.set(PNP_STATUS_NOT_SUPPORTED as i32);
        location.minor_function.set(irp_mn::QUERY_DEVICE_RELATIONS);
        location.parameters.query_device_relations.type_.set(crate::ntos::inc::types::DeviceRelationType::TARGET_DEVICE_RELATION);
        location.file_object.set(file_object);
        let mut status = io_manager::iof_call_driver(related, packet) as u32;
        let mut information = irp.io_status.information.get();
        if status == PNP_STATUS_PENDING {
            crate::ntos::ke::dispatcher::wait_for_single_object(event, 0, 0, false);
            // SAFETY: IO_STATUS_BLOCK alocado acima.
            let block = unsafe { IoStatusBlock::at(io_status) };
            status = block.status.get() as u32;
            information = block.information.get();
        }
        guest::free_bytes(packet);
        (status, information)
    };
    guest::free_bytes(event);
    guest::free_bytes(io_status);
    if (status as i32) < 0 {
        return Ok((status, 0));
    }
    if information == 0 {
        return Ok((PNP_STATUS_NO_SUCH_DEVICE_TARGET, 0));
    }
    // SAFETY: DEVICE_RELATIONS devolvido pelo driver em IoStatus.Information.
    let relations = unsafe { DeviceRelations::at(information) };
    let pdo = if relations.count.get() == 1 { relations.objects[0].get() } else { 0 };
    guest::free_bytes(information);
    if pdo == 0 || !has_device_node(pdo) {
        return Ok((PNP_STATUS_NO_SUCH_DEVICE_TARGET, 0));
    }
    Ok((status, pdo))
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

// ---- PnpQueryInterface, IoGetDmaAdapter e IoReportDetectedDevice -------------
//
// ntoskrnl 19041:
//   PnpQueryInterface rva 0x7652c4 (Device, Guid, Version, Size, SpecificData,
//     Interface): Size < 0x20 recusa; zera a INTERFACE, grava Size/Version;
//     IRP_MJ_PNP/IRP_MN_QUERY_INTERFACE síncrono ao topo da pilha
//     (IoGetAttachedDeviceReference) com IoStatus = STATUS_NOT_SUPPORTED e
//     Parameters.QueryInterface { InterfaceType, Size, Version, Interface,
//     InterfaceSpecificData }; STATUS_PENDING espera o evento.
//   IoGetDmaAdapter rva 0x7642e0: PDO NULL devolve NULL; InterfaceType
//     InterfaceTypeUndefined (-1) ou PNPBus (15) troca pela
//     DevicePropertyLegacyBusType do PDO (Isa se a consulta falhar), numa
//     cópia da DEVICE_DESCRIPTION (0x28 bytes até a versão 2, 0x40 na 3);
//     depois PiGetDmaAdapterFromBusInterface rva 0x7643d8: QUERY_INTERFACE
//     GUID_BUS_INTERFACE_STANDARD (versão 1, 0x40 bytes), GetDmaAdapter com
//     Context e InterfaceDereference. Sem a interface do barramento, NULL. O NT
//     não cai em HalGetAdapter aqui: o adaptador DMA vem sempre do bus driver.
//   IoReportDetectedDevice rva 0x7aec70 / IopCreateRootEnumeratedDeviceObject
//     rva 0x7c8af8 / IopPnPDispatch rva 0x74ee60: instância
//     "ROOT\<serviço>\%04u", PDO do \Driver\PnpManager criado com
//     IoCreateDevice(ext 4, FILE_DEVICE_CONTROLLER, FILE_AUTOGENERATED_DEVICE_NAME),
//     DO_BUS_ENUMERATED_DEVICE, recursos gravados no devnode, devnode já
//     DeviceNodeStarted (0x307): o PnP não manda START_DEVICE para essa pilha;
//     *DeviceObject recebe o PDO. *DeviceObject != NULL na entrada reaproveita o
//     PDO já relatado (STATUS_NO_SUCH_DEVICE 0xC00000F6 se não houver devnode).
//
// O PnpManager do OpenNT não tem DRIVER_OBJECT nativo: os PDOs relatados ficam
// com DriverObject = NULL e o despacho do IopPnPDispatch é o respondedor de PDO
// do I/O Manager (o mesmo caminho dos PDOs do barramento PCI).

const PNP_STATUS_SUCCESS: u32 = 0;
const PNP_STATUS_PENDING: u32 = 0x103;
const PNP_STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const PNP_STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const PNP_STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const PNP_STATUS_NO_SUCH_DEVICE: u32 = 0xC000_00F6;
const PNP_STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;

/// GUID_BUS_INTERFACE_STANDARD {496B8280-6F25-11D0-BEAF-08002BE2092F}.
const GUID_BUS_INTERFACE_STANDARD: [u8; 16] = [0x80, 0x82, 0x6B, 0x49, 0x25, 0x6F, 0xD0, 0x11, 0xBE, 0xAF, 0x08, 0x00, 0x2B, 0xE2, 0x09, 0x2F];
const BUS_INTERFACE_STANDARD_VERSION: u16 = 1;
/// DEVICE_DESCRIPTION até a versão 2 (a 3 usa a struct inteira).
const DEVICE_DESCRIPTION_V2_SIZE: usize = 0x28;
const DEVICE_PROPERTY_LEGACY_BUS_TYPE: u32 = 13;
/// INTERFACE: o menor tamanho que o PnpQueryInterface aceita.
const MINIMUM_INTERFACE_SIZE: u16 = 0x20;

/// PDO do PnpManager: FILE_DEVICE_CONTROLLER, FILE_AUTOGENERATED_DEVICE_NAME,
/// DO_BUS_ENUMERATED_DEVICE, extensão de 4 bytes zerada.
const FILE_DEVICE_CONTROLLER: u32 = 4;
const FILE_AUTOGENERATED_DEVICE_NAME: u32 = 0x80;
const DO_BUS_ENUMERATED_DEVICE: u32 = 0x1000;
const REPORTED_PDO_EXTENSION: u64 = 4;
const IO_TYPE_DEVICE: i16 = 3;
/// DEVICE_CAPABILITIES gravado pelo IopPnPDispatch: Size 0x40, Version 1.
const CAPABILITIES_SIZE: u16 = 0x40;
const CAPABILITIES_VERSION: u16 = 1;
/// IRP_MN_SURPRISE_REMOVAL.
const IRP_MN_SURPRISE_REMOVAL: u8 = 0x17;

/// Dispositivo relatado: PDO, serviço e índice da instância ROOT\<serviço>\NNNN.
#[derive(Clone)]
struct ReportedDevice {
    pdo: u64,
    driver: u64,
    service: String,
    instance: u32,
    node: NodeId,
}

static REPORTED_DEVICES: SpinLock<Vec<ReportedDevice>> = SpinLock::new(Vec::new());
static REPORTED_ANSWERER_INSTALLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// IopUniqueDeviceObjectNumber dos nomes \Device\%08x autogerados.
static AUTOGENERATED_DEVICE_NUMBER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// PnpQueryInterface: QUERY_INTERFACE síncrono ao topo da pilha do dispositivo.
pub fn query_interface(device: u64, guid: u64, version: u16, size: u16, specific_data: u64, interface: u64) -> Result<u32, crate::rtl::KernelError> {
    use crate::ntos::inc::types::{IoStackLocation, IoStatusBlock, Irp, Kevent};
    use crate::ntos::inc::types::extra_storage::Interface;
    if size < MINIMUM_INTERFACE_SIZE {
        return Ok(PNP_STATUS_INVALID_PARAMETER);
    }
    guest::write_bytes(interface, &alloc::vec![0u8; size as usize]);
    // SAFETY: buffer INTERFACE do chamador com pelo menos `size` bytes.
    let header = unsafe { Interface::at(interface) };
    header.size.set(size);
    header.version.set(version);
    let top = crate::ntos::ob::objects::device::attached_reference(device, false)?;
    let event = guest::alloc_bytes(Kevent::SIZE);
    let io_status = guest::alloc_bytes(IoStatusBlock::SIZE);
    crate::ntos::ke::dispatcher::initialize_event(event, 0, false);
    let packet = io_manager::build_synchronous_fsd_request(io_manager::irp_mj::PNP, top, 0, 0, 0, event, io_status);
    let status = if packet == 0 {
        PNP_STATUS_INSUFFICIENT_RESOURCES
    } else {
        // SAFETY: IRP recém-montado pelo I/O Manager.
        let irp = unsafe { Irp::at(packet) };
        // O slot do primeiro driver fica logo abaixo de CurrentStackLocation.
        // SAFETY: posição de pilha dentro do IRP.
        let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
        irp.requestor_mode.set(0);
        irp.io_status.status.set(PNP_STATUS_NOT_SUPPORTED as i32);
        location.minor_function.set(irp_mn::QUERY_INTERFACE);
        let parameters = &location.parameters.query_interface;
        parameters.interface_type.set(guid);
        parameters.size.set(size);
        parameters.version.set(version);
        parameters.interface.set(interface);
        parameters.interface_specific_data.set(specific_data);
        let mut status = io_manager::iof_call_driver(top, packet) as u32;
        if status == PNP_STATUS_PENDING {
            crate::ntos::ke::dispatcher::wait_for_single_object(event, 0, 0, false);
            // SAFETY: IO_STATUS_BLOCK alocado acima.
            status = unsafe { IoStatusBlock::at(io_status) }.status.get() as u32;
        }
        guest::free_bytes(packet);
        status
    };
    guest::free_bytes(event);
    guest::free_bytes(io_status);
    crate::ntos::ob::objects::device::dereference(top)?;
    Ok(status)
}

/// IoGetDmaAdapter(PhysicalDeviceObject, DeviceDescription, NumberOfMapRegisters*).
pub fn get_dma_adapter(pdo: u64, description: u64, map_registers: u64) -> Result<u64, crate::rtl::KernelError> {
    use crate::ntos::inc::types::InterfaceType;
    use crate::ntos::inc::types::extra_storage::{BusInterfaceStandard, DeviceDescription};
    if pdo == 0 {
        return Ok(0);
    }
    // SAFETY: DEVICE_DESCRIPTION do driver chamador.
    let original = unsafe { DeviceDescription::at(description) };
    let copy_address = guest::alloc_bytes(DeviceDescription::SIZE);
    let length = match original.version.get() {
        0..=2 => DEVICE_DESCRIPTION_V2_SIZE,
        3 => DeviceDescription::SIZE as usize,
        _ => 0,
    };
    guest::write_bytes(copy_address, &guest::read_bytes(description, length));
    // SAFETY: cópia local recém-alocada.
    let copy = unsafe { DeviceDescription::at(copy_address) };
    let interface_type = original.interface_type.get();
    let effective = if interface_type == InterfaceType::INTERFACE_TYPE_UNDEFINED || interface_type == InterfaceType::PNP_BUS {
        let returned = guest::alloc_bytes(4);
        let status = crate::ntos::io::device_property::get_device_property(pdo, DEVICE_PROPERTY_LEGACY_BUS_TYPE, 4, copy.interface_type.address(), returned);
        guest::free_bytes(returned);
        if (status as i32) < 0 {
            copy.interface_type.set(InterfaceType::ISA);
        }
        copy_address
    } else {
        description
    };
    let interface_address = guest::alloc_bytes(BusInterfaceStandard::SIZE);
    let guid = guest::alloc_bytes(16);
    guest::write_bytes(guid, &GUID_BUS_INTERFACE_STANDARD);
    let mut adapter = 0;
    if query_interface(pdo, guid, BUS_INTERFACE_STANDARD_VERSION, BusInterfaceStandard::SIZE as u16, 0, interface_address)? as i32 >= 0 {
        // SAFETY: interface preenchida pelo bus driver no buffer acima.
        let interface = unsafe { BusInterfaceStandard::at(interface_address) };
        let context = interface.interface.context.get();
        let get_dma_adapter = interface.get_dma_adapter.get();
        if get_dma_adapter != 0 {
            adapter = crate::hal::amd64::native_call::call(get_dma_adapter, &[context, effective, map_registers]);
        }
        let dereference = interface.interface.interface_dereference.get();
        if dereference != 0 {
            crate::hal::amd64::native_call::call(dereference, &[context]);
        }
    }
    guest::free_bytes(guid);
    guest::free_bytes(interface_address);
    guest::free_bytes(copy_address);
    Ok(adapter)
}

/// Serviço do driver: DriverExtension->ServiceKeyName, ou o nome do
/// \Driver\<nome> do OpenNT quando o loader não o preencheu.
fn reported_service_name(driver_address: u64) -> String {
    use crate::ntos::inc::types::{DriverExtension, DriverObject};
    // SAFETY: PDRIVER_OBJECT do driver chamador.
    let extension = unsafe { DriverObject::at(driver_address) }.driver_extension.get();
    if extension != 0 {
        // SAFETY: DriverObject->DriverExtension de um driver carregado.
        let name = &unsafe { DriverExtension::at(extension) }.service_key_name;
        if name.length.get() != 0 {
            return guest_strings::read_unicode_string(name.address());
        }
    }
    lifecycle::node_by_driver_object(driver_address).and_then(object_manager::node).map(|node| node.name).unwrap_or_default()
}

/// Tamanho de uma CM_RESOURCE_LIST: os FULL descriptors e as suas parciais.
fn resource_list_size(list: u64) -> u64 {
    use crate::ntos::inc::types::{CmFullResourceDescriptor, CmPartialResourceDescriptor, CmResourceList};
    // SAFETY: CM_RESOURCE_LIST do driver chamador.
    let header = unsafe { CmResourceList::at(list) };
    // Cabeçalho (Count) antes do primeiro FULL descriptor.
    let mut cursor = header.list[0].address();
    let full_header = CmFullResourceDescriptor::SIZE - CmPartialResourceDescriptor::SIZE;
    for _ in 0..header.count.get() {
        // SAFETY: descritor dentro da lista declarada pelo chamador.
        let partials = unsafe { CmFullResourceDescriptor::at(cursor) }.partial_resource_list.count.get() as u64;
        cursor += full_header + partials * CmPartialResourceDescriptor::SIZE;
    }
    cursor - list
}

fn free_reported_pdo(pointer: u64) {
    guest::free_bytes(pointer);
}

/// IoReportDetectedDevice(DriverObject, LegacyBusType, BusNumber, SlotNumber,
/// ResourceList, ResourceRequirements, ResourceAssigned, DeviceObject*).
#[allow(clippy::too_many_arguments)]
pub fn report_detected_device(driver: u64, _bus_type: u32, _bus_number: u32, _slot: u32, resources: u64, _requirements: u64, _assigned: bool, output: &Field<u64>) -> Result<u32, crate::rtl::KernelError> {
    let existing = output.get();
    if existing != 0 {
        // PDO já relatado: o devnode precisa existir.
        let known = REPORTED_DEVICES.lock().iter().any(|device| device.pdo == existing);
        return Ok(if known { PNP_STATUS_SUCCESS } else { PNP_STATUS_NO_SUCH_DEVICE });
    }
    if !REPORTED_ANSWERER_INSTALLED.swap(true, core::sync::atomic::Ordering::AcqRel) {
        io_manager::register_pdo_native_answerer(answer_reported_pdo_irp);
    }
    let service = reported_service_name(driver);
    let instance = REPORTED_DEVICES.lock().iter().filter(|device| device.service.eq_ignore_ascii_case(&service)).count() as u32;
    // IopCreateRootEnumeratedDeviceObject: DEVICE_OBJECT + extensão de 4 bytes.
    let pdo = guest::alloc_bytes(DeviceObject::SIZE + REPORTED_PDO_EXTENSION);
    if pdo == 0 {
        return Ok(PNP_STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: bloco recém-alocado e zerado do tamanho do DEVICE_OBJECT.
    let device = unsafe { DeviceObject::at(pdo) };
    device.type_.set(IO_TYPE_DEVICE);
    device.size.set(DeviceObject::SIZE as u16);
    device.reference_count.set(1);
    device.device_type.set(FILE_DEVICE_CONTROLLER);
    device.characteristics.set(FILE_AUTOGENERATED_DEVICE_NAME);
    device.flags.set(DO_BUS_ENUMERATED_DEVICE);
    device.stack_size.set(1);
    device.device_extension.set(pdo + DeviceObject::SIZE);
    crate::ntos::ob::objects::device::register(pdo, Some(free_reported_pdo), None)?;
    let number = AUTOGENERATED_DEVICE_NUMBER.fetch_add(1, core::sync::atomic::Ordering::AcqRel) + 1;
    let node = object_manager::create_object("\\Device", &format!("{number:08x}"), "Device", Some(object_manager::ObjectData::pointer(pdo)))?;
    // Recursos já atribuídos: cópia da lista vira os recursos do devnode.
    let mut list = 0;
    if resources != 0 {
        let size = resource_list_size(resources);
        list = guest::alloc_bytes(size);
        guest::write_bytes(list, &guest::read_bytes(resources, size as usize));
        crate::ntos::io::device_resources::register_device_resources(pdo, list);
    }
    let device_id = format!("ROOT\\{}", service.to_uppercase());
    io_manager::register_device(node, io_manager::DeviceEntry { native_device: pdo, resources: list, pdo: true, hardware_ids: Some(alloc::vec![device_id]), stack_enumerated: true, pnp_started: true, ..Default::default() });
    REPORTED_DEVICES.lock().push(ReportedDevice { pdo, driver, service, instance, node });
    output.set(pdo);
    Ok(PNP_STATUS_SUCCESS)
}

/// String UTF-16 com NUL duplo em pool (resposta de QUERY_ID).
fn pool_id_string(text: &str) -> u64 {
    let mut bytes: Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    let buffer = guest::alloc_bytes(bytes.len() as u64);
    guest::write_bytes(buffer, &bytes);
    buffer
}

/// IopPnPDispatch para os PDOs relatados que chegam ao fundo da pilha.
fn answer_reported_pdo_irp(device: u64, packet: u64) -> Option<i32> {
    use crate::ntos::inc::types::{BusQueryIdType, DeviceCapabilities, DevicePowerState, DeviceRelationType, IoStackLocation, Irp};
    let reported = REPORTED_DEVICES.lock().iter().find(|reported| reported.pdo == device).cloned()?;
    // SAFETY: IRP entregue pelo IofCallDriver ao PDO.
    let irp = unsafe { Irp::at(packet) };
    // SAFETY: posição de pilha corrente do IRP.
    let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    let major = location.major_function.get();
    let mut status = irp.io_status.status.get() as u32;
    let mut information = irp.io_status.information.get();
    if major == io_manager::irp_mj::POWER {
        status = PNP_STATUS_SUCCESS;
    } else if major != io_manager::irp_mj::PNP {
        status = PNP_STATUS_INVALID_DEVICE_REQUEST;
        information = 0;
    } else {
        match location.minor_function.get() {
            // START, QUERY_REMOVE, REMOVE, CANCEL_REMOVE, STOP, QUERY_STOP,
            // CANCEL_STOP e SURPRISE_REMOVAL: aceitos pelo PnpManager.
            0..=6 | IRP_MN_SURPRISE_REMOVAL => status = PNP_STATUS_SUCCESS,
            irp_mn::QUERY_DEVICE_RELATIONS if location.parameters.query_device_relations.type_.get() == DeviceRelationType::TARGET_DEVICE_RELATION => {
                let relations_address = guest::alloc_bytes(DeviceRelations::SIZE);
                // SAFETY: DEVICE_RELATIONS recém-alocada com uma entrada.
                let relations = unsafe { DeviceRelations::at(relations_address) };
                relations.count.set(1);
                relations.objects[0].set(device);
                let _ = crate::ntos::ob::objects::device::reference(device);
                information = relations_address;
                status = PNP_STATUS_SUCCESS;
            }
            irp_mn::QUERY_CAPABILITIES => {
                // SAFETY: DEVICE_CAPABILITIES do IRP (alocado por quem pergunta).
                let capabilities = unsafe { DeviceCapabilities::at(location.parameters.device_capabilities.capabilities.get()) };
                capabilities.size.set(CAPABILITIES_SIZE);
                capabilities.version.set(CAPABILITIES_VERSION);
                capabilities.device_state[0].set(DevicePowerState::POWER_DEVICE_UNSPECIFIED);
                capabilities.device_state[1].set(DevicePowerState::POWER_DEVICE_D0);
                for state in &capabilities.device_state[2..] {
                    state.set(DevicePowerState::POWER_DEVICE_D3);
                }
                status = PNP_STATUS_SUCCESS;
            }
            irp_mn::QUERY_ID => {
                let id_type = location.parameters.query_id.id_type.get();
                if id_type == BusQueryIdType::BUS_QUERY_DEVICE_ID {
                    information = pool_id_string(&format!("ROOT\\{}", reported.service.to_uppercase()));
                    status = PNP_STATUS_SUCCESS;
                } else if id_type == BusQueryIdType::BUS_QUERY_INSTANCE_ID {
                    information = pool_id_string(&format!("{:04}", reported.instance));
                    status = PNP_STATUS_SUCCESS;
                }
            }
            _ => {}
        }
    }
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(information);
    io_manager::iof_complete_request(packet);
    Some(status as i32)
}

/// PDO relatado de um driver (para o orquestrador montar a pilha dele).
pub fn reported_device_nodes(driver: u64) -> Vec<NodeId> {
    REPORTED_DEVICES.lock().iter().filter(|device| device.driver == driver).map(|device| device.node).collect()
}
