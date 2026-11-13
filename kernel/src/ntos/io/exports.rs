//! Exports Io* do ntoskrnl — `system32/win32/ntoskrnl/io.js`.
//!
//! Os dispositivos vivem no namespace do Object Manager e encadeados na
//! lista do driver (DeviceObject->NextDevice); as pilhas, IRPs, work items,
//! timers, interrupções, controladores e StartIo usam os módulos do I/O
//! Manager. As extensões de IRP, interfaces de dispositivo, notificações PnP
//! e listas de desligamento/prioridade ficam aqui, como no original.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::io::{irp_builder, lifecycle};
use crate::ntos::io::file::zw as zw_files;
use crate::drivers::bus::pci;
use crate::hal::amd64::native_call;
use crate::ntos::cm::hw_description;
use crate::ntos::cm::key::services as key_services;
use crate::ntos::io::controller::{controller, start_io};
use crate::ntos::io::small::{delete_device, thread_io};
use crate::ntos::io::threads::{io_timer, thread_activity};
use crate::ntos::io::{cancel, device_resources, io_manager, pnp, work_items};
use crate::ntos::io::file::information as file_information;
use crate::ntos::ke::{dispatcher, interrupt_object};
use crate::ntos::mm::{kernel_data, paging};
use crate::ntos::ob::objects::{device as device_objects, file as file_objects};
use crate::ntos::ob::object_manager;
use crate::ntos::po::power_manager;
use crate::ntos::ps::{kernel_threads, process};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::nt_abi::{device_object, driver_object, io_stack_location, io_workitem, irp, mdl};

/// IO_REMOVE_LOCK (bloco comum do wdm.h): Removed @0, IoCount @4, WaitEvent @0x10.
const REMOVE_LOCK_REMOVED: u64 = 0;
const REMOVE_LOCK_IO_COUNT: u64 = 4;
const REMOVE_LOCK_WAIT_EVENT: u64 = 0x10;

/// Extensão de um IRP criada sob demanda (activity id zerado).
#[derive(Clone, Copy, Default)]
struct RequestExtension {
    generic: u64,
    propagate: u32,
    activity_id_pointer: u64,
    activity_id_present: bool,
    hard_error_device: u64,
}

/// Interface de dispositivo: estado e GUID da classe.
struct DeviceInterface {
    enabled: bool,
    class: [u8; 16],
}

/// Registro de notificação PnP (o handle é o registro nativo).
#[derive(Clone, Copy)]
struct PlugPlayRegistration {
    category: u32,
    /// GUID da classe de interface (EventCategoryDeviceInterfaceChange).
    class: [u8; 16],
    callback: u64,
    context: u64,
    record: u64,
}

const EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE: u32 = 2;
const EVENT_CATEGORY_TARGET_DEVICE_CHANGE: u32 = 3;
/// GUID_DEVICE_INTERFACE_ARRIVAL / _REMOVAL (wdmguid.h).
const INTERFACE_ARRIVAL: [u8; 16] = [0x04, 0x40, 0x3A, 0xCB, 0xF0, 0x46, 0xD0, 0x11, 0xB0, 0x8F, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3F];
const INTERFACE_REMOVAL: [u8; 16] = [0x05, 0x40, 0x3A, 0xCB, 0xF0, 0x46, 0xD0, 0x11, 0xB0, 0x8F, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3F];

/// DEVICE_INTERFACE_CHANGE_NOTIFICATION (Version, Size, Event,
/// InterfaceClassGuid, SymbolicLinkName) entregue a callback(estrutura,
/// contexto) de cada registro da classe.
fn notify_interface(registrations: &[PlugPlayRegistration], event: &[u8; 16], class: &[u8; 16], link: &str) {
    for registration in registrations.iter().filter(|registration| registration.category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE && registration.class == *class) {
        let units = link.encode_utf16().count() as u64;
        let notification = guest::alloc_bytes(0x30 + 16 + (units + 1) * 2);
        if notification == 0 {
            continue;
        }
        let string = notification + 0x30;
        let buffer = string + 16;
        guest::write16(notification, 1);
        guest::write16(notification + 2, 0x30);
        guest::write_bytes(notification + 4, event);
        guest::write_bytes(notification + 20, class);
        guest::write32(notification + 36, 0);
        guest::write64(notification + 40, string);
        guest_strings::write_wide_string(buffer, link);
        guest::write16(string, units as u16 * 2);
        guest::write16(string + 2, units as u16 * 2 + 2);
        guest::write64(string + 8, buffer);
        native_call::call(registration.callback, &[notification, registration.context]);
        guest::free_bytes(notification);
    }
}

/// Extensões de driver object: (DRIVER_OBJECT, tag) → bloco.
static DRIVER_EXTENSIONS: SpinLock<BTreeMap<(u64, u64), u64>> = SpinLock::new(BTreeMap::new());
/// FDO → PDO registrado no attach (IoGetDeviceProperty acha o PDO de hardware).
static PHYSICAL_BY_ATTACHED: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());
/// Dispositivos invalidados por IoInvalidateDeviceState.
static INVALIDATED_DEVICES: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());
static DEVICE_INTERFACES: SpinLock<BTreeMap<String, DeviceInterface>> = SpinLock::new(BTreeMap::new());
static PLUG_PLAY_REGISTRATIONS: SpinLock<Vec<PlugPlayRegistration>> = SpinLock::new(Vec::new());
/// Dispositivos com classes WMI registradas.
static WMI_DEVICES: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());
/// CONFIGURATION_INFORMATION global (drivers incrementam as contagens).
static CONFIGURATION_INFORMATION: AtomicU64 = AtomicU64::new(0);
static REQUEST_EXTENSIONS: SpinLock<BTreeMap<u64, RequestExtension>> = SpinLock::new(BTreeMap::new());
/// Dispositivos que recebem IRP_MJ_SHUTDOWN no desligamento.
static SHUTDOWN_DEVICES: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
static PRIORITY_CALLBACKS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
static UNNAMED_DEVICES: SpinLock<u32> = SpinLock::new(0);
/// Mudanças de dispositivo agendadas: work item → (GUID, contexto, callback).
static TARGET_CHANGES: SpinLock<BTreeMap<u64, (u64, u64, u64)>> = SpinLock::new(BTreeMap::new());

fn configuration_information() -> u64 {
    let current = CONFIGURATION_INFORMATION.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let pointer = guest::alloc_bytes(0x40);
    match CONFIGURATION_INFORMATION.compare_exchange(0, pointer, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => pointer,
        Err(existing) => {
            guest::free_bytes(pointer);
            existing
        }
    }
}

fn request_extension(packet: u64) -> RequestExtension {
    let mut extensions = REQUEST_EXTENSIONS.lock();
    *extensions.entry(packet).or_insert_with(|| RequestExtension { activity_id_pointer: guest::alloc_bytes(16), ..Default::default() })
}

fn update_extension(packet: u64, change: impl FnOnce(&mut RequestExtension)) {
    request_extension(packet);
    if let Some(extension) = REQUEST_EXTENSIONS.lock().get_mut(&packet) {
        change(extension);
    }
}

/// Nome relativo a `\Device` (subdiretórios incluídos, como `Ide\IdePort0`).
fn device_name(node: object_manager::NodeId) -> String {
    let path = object_manager::path_of(node).unwrap_or_default();
    match path.get(..8) {
        Some(prefix) if prefix.eq_ignore_ascii_case("\\Device\\") => String::from(&path[8..]),
        _ => object_manager::node(node).map(|node| node.name).unwrap_or_default(),
    }
}

/// Nó `\Device` dono de um DEVICE_OBJECT.
fn find_device_node_by_pointer(device: u64) -> Option<object_manager::NodeId> {
    if device == 0 {
        return None;
    }
    io_manager::devices().into_iter().find(|(_, entry)| entry.native_device == device).map(|(node, _)| node)
}

fn kernel_status(error: KernelError) -> Result<u64, KernelError> {
    if error.status != 0 && error.status != 0xC000_0001 {
        Ok(signed_status(error.status))
    } else {
        Err(error)
    }
}

/// IoCreateDevice: DEVICE_OBJECT real com a extensão logo depois, no
/// namespace e na cabeça da lista do driver dono. Dispositivos sem nome
/// recebem um nome interno único.
fn create_device(driver: u64, extension_size: u32, name: Option<String>, device_type: u32, characteristics: u32, output: u64) -> Result<u64, KernelError> {
    let short_name = match name {
        Some(name) => match name.get(..8) {
            Some(prefix) if prefix.eq_ignore_ascii_case("\\Device\\") => String::from(&name[8..]),
            _ => name,
        },
        None => {
            let mut next = UNNAMED_DEVICES.lock();
            let name = format!("Unnamed{}", *next);
            *next += 1;
            name
        }
    };
    let page = guest::alloc_bytes(device_object::STRUCT_SIZE + extension_size as u64);
    if page == 0 {
        return Ok(signed_status(0xC000_009A));
    }
    guest::write16(page + device_object::TYPE, device_object::IO_TYPE);
    guest::write16(page + device_object::SIZE, device_object::STRUCT_SIZE as u16);
    guest::write32(page + device_object::REFERENCE_COUNT, 1);
    guest::write64(page + device_object::DRIVER_OBJECT, driver);
    guest::write32(page + device_object::DEVICE_TYPE, device_type);
    guest::write32(page + device_object::CHARACTERISTICS, characteristics);
    guest::write8(page + device_object::STACK_SIZE, 1);
    guest::write64(page + device_object::DEVICE_EXTENSION, if extension_size != 0 { page + device_object::STRUCT_SIZE } else { 0 });
    device_objects::register(page, Some(destroy_device), Some(unlink_device))?;
    device_objects::with_lock(|| {
        let head = driver + driver_object::DEVICE_OBJECT;
        guest::write64(page + device_object::NEXT_DEVICE, guest::read64(head));
        guest::write64(head, page);
        Ok(())
    })?;
    // O dispositivo pertence ao DRIVER_OBJECT do argumento (cargas aninhadas
    // de drivers); nomes com subdiretório criam os diretórios intermediários.
    let driver_node = lifecycle::node_by_driver_object(driver).or_else(|| lifecycle::current_driver().and_then(lifecycle::node_by_driver_object));
    if let Some(driver_node) = driver_node {
        let parts: Vec<&str> = short_name.split('\\').collect();
        let created = if parts.len() == 1 {
            object_manager::create_object("\\Device", &short_name, "Device", Some(object_manager::ObjectData::pointer(page)))
        } else {
            let directory = format!("\\Device\\{}", parts[..parts.len() - 1].join("\\"));
            object_manager::create_directory(&directory).and_then(|_| object_manager::create_object(&directory, parts[parts.len() - 1], "Device", Some(object_manager::ObjectData::pointer(page))))
        };
        let node = match created {
            Ok(node) => node,
            Err(error) => return kernel_status(error),
        };
        io_manager::register_device(node, io_manager::DeviceEntry { driver: Some(driver_node), native_device: page, ..Default::default() });
        io_manager::attach_device_to_driver(driver_node, node);
    }
    guest::write64(output, page);
    Ok(0)
}

/// Retira o dispositivo da coleção do driver e da lista nativa.
fn unlink_device(device: u64) {
    let driver = guest::read64(device + 8);
    if let Some(driver_node) = lifecycle::node_by_driver_object(driver) {
        for node in io_manager::driver_devices(driver_node) {
            if io_manager::device(node).is_some_and(|entry| entry.native_device == device) {
                io_manager::detach_device_from_driver(driver_node, node);
            }
        }
    }
    let _ = device_objects::with_lock(|| {
        let mut link = driver + 8;
        loop {
            let current = guest::read64(link);
            if current == 0 {
                break;
            }
            if current == device {
                guest::write64(link, guest::read64(device + 0x10));
                break;
            }
            link = current + 0x10;
        }
        Ok(())
    });
}

/// Devolve o armazenamento depois que o dono autoriza a destruição.
fn destroy_device(device: u64) {
    if let Some(node) = find_device_node_by_pointer(device) {
        object_manager::unlink(&format!("\\Device\\{}", device_name(node)));
        io_manager::unregister_device(node);
    }
    PHYSICAL_BY_ATTACHED.lock().remove(&device);
    guest::free_bytes(device);
    power_manager::forget_device(device);
    io_timer::forget_device(device);
}

/// A rota de despacho de cada `\Device` nomeado segue o topo da pilha.
fn refresh_stack_routes() {
    for (node, entry) in io_manager::devices() {
        if entry.native_device != 0 && device_objects::is_device(entry.native_device) {
            let top = device_objects::top(entry.native_device);
            io_manager::update_device(node, |entry| entry.stack_top = top);
        }
    }
}

/// Anexa a origem ao topo do destino (saída opcional do dispositivo abaixo)
/// e publica as novas rotas de despacho.
pub fn attach_device_to_device_stack(source: u64, target: u64, output: u64) -> Result<u64, KernelError> {
    let lower = device_objects::attach(source, target, output)?;
    if lower != 0 {
        PHYSICAL_BY_ATTACHED.lock().insert(source, device_objects::base(source));
    }
    refresh_stack_routes();
    Ok(lower)
}

fn detach_device(target: u64) -> Result<u64, KernelError> {
    let detached = device_objects::detach(target)?;
    if detached != 0 {
        PHYSICAL_BY_ATTACHED.lock().remove(&detached);
    }
    refresh_stack_routes();
    Ok(0)
}

/// IoGetDeviceObjectPointer: topo da pilha e um FILE_OBJECT real retido.
fn get_device_object_pointer_export(call: &Call) -> Result<u64, KernelError> {
    get_device_object_pointer(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4))
}

/// IoGetDeviceObjectPointer(name, access, outFileObject, outDeviceObject).
pub fn get_device_object_pointer(name_pointer: u64, _access: u32, file_output: u64, device_output: u64) -> Result<u64, KernelError> {
    let name = guest_strings::read_unicode_string(name_pointer);
    let node = object_manager::lookup(&name).filter(|&node| object_manager::node(node).is_some_and(|node| node.type_name == "Device"));
    let Some(node) = node else { return Ok(signed_status(0xC000_0034)) };
    let entry = io_manager::device(node).unwrap_or_default();
    let device = if entry.stack_top != 0 { entry.stack_top } else { entry.native_device };
    let opened = io_manager::open_device(&name, false)?;
    if opened.status != 0 {
        return Ok(opened.status as i64 as u64);
    }
    file_objects::reference(opened.file_object)?;
    io_manager::close_device(opened.handle)?;
    guest::write64(file_output, opened.file_object);
    guest::write64(device_output, device);
    Ok(0)
}

fn io_create_device(call: &Call) -> Result<u64, KernelError> {
    let name = if call.arg(3) != 0 { Some(guest_strings::read_unicode_string(call.arg(3))) } else { None };
    create_device(call.arg(1), call.arg(2) as u32, name, call.arg(4) as u32, call.arg(5) as u32, call.arg(7))
}
fn io_create_symbolic_link(call: &Call) -> Result<u64, KernelError> {
    match object_manager::create_symlink(&guest_strings::read_unicode_string(call.arg(1)), &guest_strings::read_unicode_string(call.arg(2))) {
        Ok(_) => Ok(0),
        Err(error) => kernel_status(error),
    }
}
fn io_delete_device(call: &Call) -> Result<u64, KernelError> {
    Ok(delete_device::delete_device(call.arg(1))? as u64)
}
fn io_delete_symbolic_link(call: &Call) -> Result<u64, KernelError> {
    Ok(if object_manager::unlink(&guest_strings::read_unicode_string(call.arg(1))) { 0 } else { 0xC000_0009 })
}
/// IoAllocateIrp: IRP zerado posicionado acima do topo da pilha.
fn io_allocate_irp(call: &Call) -> Result<u64, KernelError> {
    let count = (call.arg(1) as u8 as i8).max(1) as u64;
    let size = irp::STRUCT_SIZE + count * irp::STACK_LOCATION_SIZE;
    let address = guest::alloc_bytes(size);
    if address == 0 {
        return Ok(0);
    }
    guest::write16(address + irp::TYPE, irp::IO_TYPE);
    guest::write16(address + irp::SIZE_FIELD, size as u16);
    guest::write8(address + irp::STACK_COUNT, count as u8);
    guest::write8(address + irp::CURRENT_LOCATION, count as u8 + 1);
    guest::write64(address + irp::CURRENT_STACK_LOCATION, address + irp::STRUCT_SIZE + count * irp::STACK_LOCATION_SIZE);
    Ok(address)
}
/// IoFreeIrp: a extensão pertence ao IRP e não sobrevive ao reuso.
fn io_free_irp(call: &Call) -> Result<u64, KernelError> {
    if let Some(extension) = REQUEST_EXTENSIONS.lock().remove(&call.arg(1)) {
        guest::free_bytes(extension.activity_id_pointer);
    }
    guest::free_bytes(call.arg(1));
    Ok(0)
}
fn io_complete_request(call: &Call) -> Result<u64, KernelError> {
    Ok(io_manager::iof_complete_request(call.arg(1)) as i64 as u64)
}
fn io_allocate_work_item(call: &Call) -> Result<u64, KernelError> {
    let item = guest::alloc_bytes(io_workitem::SIZE);
    work_items::create_work_item(call.arg(1), item);
    Ok(item)
}
fn io_queue_work_item(call: &Call) -> Result<u64, KernelError> {
    work_items::queue_work_item(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4));
    Ok(0)
}
fn io_free_work_item(call: &Call) -> Result<u64, KernelError> {
    work_items::unqueue(call.arg(1));
    guest::free_bytes(call.arg(1));
    Ok(0)
}
fn io_call_driver(call: &Call) -> Result<u64, KernelError> {
    Ok(io_manager::iof_call_driver(call.arg(1), call.arg(2)) as i64 as u64)
}
fn io_attach_device_to_device_stack(call: &Call) -> Result<u64, KernelError> {
    attach_device_to_device_stack(call.arg(1), call.arg(2), 0)
}
fn io_detach_device(call: &Call) -> Result<u64, KernelError> {
    detach_device(call.arg(1))
}
fn io_build_synchronous_fsd_request(call: &Call) -> Result<u64, KernelError> {
    Ok(io_manager::build_synchronous_fsd_request(call.arg(1) as u8, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6), call.arg(7)))
}
fn io_build_device_io_control_request(call: &Call) -> Result<u64, KernelError> {
    Ok(io_manager::build_device_io_control_request(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32, call.arg(7), call.arg(8), call.arg(9), None))
}
fn io_initialize_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(io_timer::initialize_timer(call.arg(1), call.arg(2), call.arg(3)) as u64)
}
fn io_start_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(io_timer::start_timer(call.arg(1)) as u64)
}
fn io_stop_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(io_timer::stop_timer(call.arg(1)) as u64)
}
/// IoQueueWorkItemEx: a rotina recebe (ioObject, context, ioWorkItem).
fn io_queue_work_item_ex(call: &Call) -> Result<u64, KernelError> {
    work_items::queue_work_item_ex(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), true);
    Ok(0)
}
/// IoAllocateMdl: MDL do wdm.h com os PFNs reais das tabelas de página.
fn io_allocate_mdl(call: &Call) -> Result<u64, KernelError> {
    let (virtual_address, length) = (call.arg(1), call.arg(2) as u32);
    let start = virtual_address & !0xFFF;
    let byte_offset = virtual_address & 0xFFF;
    let pages = (byte_offset + length as u64).div_ceil(0x1000);
    let size = mdl::PFN_ARRAY + pages * 8;
    let descriptor = guest::alloc_bytes(size);
    if descriptor == 0 {
        return Ok(0);
    }
    guest::write64(descriptor + mdl::NEXT, 0);
    guest::write16(descriptor + mdl::SIZE, size as u16);
    guest::write16(descriptor + mdl::MDL_FLAGS, mdl::FLAG_MAPPED_TO_SYSTEM_VA | mdl::FLAG_SOURCE_NONPAGED);
    // O mapeamento deste caminho é por identidade.
    guest::write64(descriptor + mdl::MAPPED_SYSTEM_VA, virtual_address);
    guest::write64(descriptor + mdl::START_VA, start);
    guest::write32(descriptor + mdl::BYTE_COUNT, length);
    guest::write32(descriptor + mdl::BYTE_OFFSET, byte_offset as u32);
    for page in 0..pages {
        guest::write64(descriptor + mdl::PFN_ARRAY + page * 8, paging::translate(start + page * 0x1000) / 0x1000);
    }
    Ok(descriptor)
}
fn io_free_mdl(call: &Call) -> Result<u64, KernelError> {
    guest::free_bytes(call.arg(1));
    Ok(0)
}
fn io_get_current_thread(_: &Call) -> Result<u64, KernelError> {
    Ok(kernel_threads::get_current_thread_handle() as u64)
}
/// IoSetCancelRoutine: devolve a rotina anterior.
fn io_set_cancel_routine(call: &Call) -> Result<u64, KernelError> {
    let previous = guest::read64(call.arg(1) + irp::CANCEL_ROUTINE);
    guest::write64(call.arg(1) + irp::CANCEL_ROUTINE, call.arg(2));
    Ok(previous)
}
fn io_cancel_irp(call: &Call) -> Result<u64, KernelError> {
    Ok(cancel::irp(call.arg(1))? as u64)
}
fn io_allocate_driver_object_extension(call: &Call) -> Result<u64, KernelError> {
    let key = (call.arg(1), call.arg(2));
    let mut extensions = DRIVER_EXTENSIONS.lock();
    if extensions.contains_key(&key) {
        return Ok(signed_status(0xC000_0035));
    }
    let extension = guest::alloc_bytes(call.arg(3) as u32 as u64);
    extensions.insert(key, extension);
    guest::write64(call.arg(4), extension);
    Ok(0)
}
fn io_get_driver_object_extension(call: &Call) -> Result<u64, KernelError> {
    Ok(DRIVER_EXTENSIONS.lock().get(&(call.arg(1), call.arg(2))).copied().unwrap_or(0))
}
fn io_get_current_process(_: &Call) -> Result<u64, KernelError> {
    Ok(process::get_current_process())
}
/// IoCreateFile/IoCreateFileEx: a abertura completa do ZwCreateFile.
fn io_create_file(call: &Call) -> Result<u64, KernelError> {
    Ok(zw_files::create_kernel_file(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(7) as u32, call.arg(8) as u32, call.arg(9) as u32)? as u64)
}
fn io_get_related_device_object(call: &Call) -> Result<u64, KernelError> {
    file_information::related_device(call.arg(1))
}
fn write_wide(output: u64, text: &str) {
    for (index, unit) in text.encode_utf16().enumerate() {
        guest::write16(output + index as u64 * 2, unit);
    }
}
/// PDO de hardware: segue a cadeia de attach até achar o primeiro que
/// satisfaz `found`.
fn walk_physical<T>(device: u64, found: impl Fn(u64) -> Option<T>) -> Option<T> {
    let mut candidate = device;
    let mut result = found(candidate);
    while result.is_none() {
        let Some(next) = PHYSICAL_BY_ATTACHED.lock().get(&candidate).copied() else { break };
        candidate = next;
        result = found(candidate);
    }
    result
}
/// IoGetDeviceProperty(dev, property, bufferLength, buffer, resultLength):
/// PhysicalDeviceObjectName (0xB) e HardwareID (1) do PDO PCI.
fn io_get_device_property(call: &Call) -> Result<u64, KernelError> {
    let (device, property, size, output, returned) = (call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5));
    let (text, needed) = if property == 0xB {
        let Some(node) = walk_physical(device, find_device_node_by_pointer) else { return Ok(signed_status(0xC000_0034)) };
        let name = format!("\\Device\\{}", device_name(node));
        let needed = (name.encode_utf16().count() as u32 + 1) * 2;
        (name, needed)
    } else if property == 1 {
        let pci_function = walk_physical(device, |candidate| {
            pci::devices().into_iter().find(|function| object_manager::lookup(&format!("\\Device\\{}", function.pdo_name)).and_then(io_manager::device).is_some_and(|entry| entry.native_device == candidate))
        });
        let Some(function) = pci_function else { return Ok(signed_status(0xC000_0034)) };
        let id = pci::hardware_id_of(&function);
        let needed = (id.encode_utf16().count() as u32 + 2) * 2;
        (id, needed)
    } else {
        return Ok(signed_status(0xC000_000D));
    };
    if size < needed {
        guest::write32(returned, needed);
        return Ok(signed_status(0xC000_0023));
    }
    write_wide(output, &text);
    if property == 0xB {
        guest::write16(output + text.encode_utf16().count() as u64 * 2, 0);
    }
    guest::write32(returned, needed);
    Ok(0)
}
/// Limites da pilha do kernel do mapa de memória do boot.
fn io_get_stack_limits(call: &Call) -> Result<u64, KernelError> {
    guest::write64(call.arg(1), 0x20_0000);
    guest::write64(call.arg(2), 0x30_0000);
    Ok(0)
}
fn io_initialize_remove_lock(call: &Call) -> Result<u64, KernelError> {
    let lock = call.arg(1);
    guest::write8(lock + REMOVE_LOCK_REMOVED, 0);
    guest::write32(lock + REMOVE_LOCK_IO_COUNT, 0);
    dispatcher::initialize_event(lock + REMOVE_LOCK_WAIT_EVENT, 0, false);
    Ok(0)
}
fn io_acquire_remove_lock(call: &Call) -> Result<u64, KernelError> {
    let lock = call.arg(1);
    if guest::read8(lock + REMOVE_LOCK_REMOVED) != 0 {
        return Ok(signed_status(0xC000_0056));
    }
    guest::write32(lock + REMOVE_LOCK_IO_COUNT, guest::read32(lock + REMOVE_LOCK_IO_COUNT).wrapping_add(1));
    Ok(0)
}
fn io_release_remove_lock(call: &Call) -> Result<u64, KernelError> {
    let lock = call.arg(1);
    let remaining = guest::read32(lock + REMOVE_LOCK_IO_COUNT).wrapping_sub(1);
    guest::write32(lock + REMOVE_LOCK_IO_COUNT, remaining);
    if remaining == 0 && guest::read8(lock + REMOVE_LOCK_REMOVED) != 0 {
        dispatcher::set_event(lock + REMOVE_LOCK_WAIT_EVENT);
    }
    Ok(0)
}
/// Marca removido, solta a referência do chamador e espera as pendentes.
fn io_release_remove_lock_and_wait(call: &Call) -> Result<u64, KernelError> {
    let lock = call.arg(1);
    guest::write8(lock + REMOVE_LOCK_REMOVED, 1);
    let remaining = guest::read32(lock + REMOVE_LOCK_IO_COUNT).wrapping_sub(1);
    guest::write32(lock + REMOVE_LOCK_IO_COUNT, remaining);
    if remaining as i32 > 0 {
        dispatcher::wait_for_single_object(lock + REMOVE_LOCK_WAIT_EVENT, 0, 0, false);
    }
    Ok(0)
}
fn io_allocate_error_log_entry(call: &Call) -> Result<u64, KernelError> {
    Ok(guest::alloc_bytes(call.arg(2) as u8 as u64))
}
/// IoWriteErrorLogEntry: o código vai para o log do sistema (serial).
fn io_write_error_log_entry(call: &Call) -> Result<u64, KernelError> {
    debug_print!("[errorlog] codigo=0x{:x}", guest::read32(call.arg(1) + 4));
    guest::free_bytes(call.arg(1));
    Ok(0)
}
fn io_acquire_cancel_spin_lock(call: &Call) -> Result<u64, KernelError> {
    guest::write8(call.arg(1), cancel::acquire()?);
    Ok(0)
}
fn io_release_cancel_spin_lock(call: &Call) -> Result<u64, KernelError> {
    cancel::release(call.arg(1) as u8)?;
    Ok(0)
}
/// IoRegisterDeviceInterface: `\DosDevices\#{guid}` → dispositivo, desabilitada.
fn io_register_device_interface(call: &Call) -> Result<u64, KernelError> {
    let (physical, guid, output) = (call.arg(1), call.arg(2), call.arg(4));
    let guid_text: String = (0..16).map(|index| format!("{:02x}", guest::read8(guid + index))).collect();
    let device = io_manager::devices().into_iter().filter(|(node, entry)| entry.native_device == physical && object_manager::path_of(*node).is_some_and(|path| path.matches('\\').count() == 2)).map(|(node, _)| device_name(node)).last().unwrap_or_else(|| String::from("PDO0"));
    let link = format!("\\DosDevices\\#{{{guid_text}}}");
    if let Err(error) = object_manager::create_symlink(&link, &format!("\\Device\\{device}")) {
        return kernel_status(error);
    }
    let mut class = [0u8; 16];
    class.copy_from_slice(&guest::read_bytes(guid, 16));
    DEVICE_INTERFACES.lock().insert(link.clone(), DeviceInterface { enabled: false, class });
    let length = link.encode_utf16().count() as u64 * 2;
    let buffer = guest::alloc_bytes(length + 2);
    guest_strings::write_wide_string(buffer, &link);
    guest::write16(output, length as u16);
    guest::write16(output + 2, length as u16 + 2);
    guest::write64(output + 8, buffer);
    Ok(0)
}
/// IoSetDeviceInterfaceState: habilitar dispara as notificações PnP.
fn io_set_device_interface_state(call: &Call) -> Result<u64, KernelError> {
    let link = guest_strings::read_unicode_string(call.arg(1));
    let enabled = call.arg(2) & 0xFF != 0;
    let (changed, class) = {
        let mut interfaces = DEVICE_INTERFACES.lock();
        let Some(entry) = interfaces.get_mut(&link) else { return Ok(signed_status(0xC000_0034)) };
        let changed = entry.enabled != enabled;
        entry.enabled = enabled;
        (changed, entry.class)
    };
    // Chegada ou remoção só na transição, para os registros da classe.
    if changed {
        let registrations = PLUG_PLAY_REGISTRATIONS.lock().clone();
        notify_interface(&registrations, if enabled { &INTERFACE_ARRIVAL } else { &INTERFACE_REMOVAL }, &class, &link);
    }
    Ok(0)
}
/// IoRegisterPlugPlayNotification(EventCategory, EventCategoryFlags,
/// EventCategoryData, DriverObject, CallbackRoutine, Context,
/// NotificationEntry): assinatura do WDK; o handle é o registro.
/// PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES entrega as
/// interfaces já habilitadas da classe.
fn io_register_plug_play_notification(call: &Call) -> Result<u64, KernelError> {
    let (category, flags, data, callback, context, output) = (call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(5), call.arg(6), call.arg(7));
    if callback == 0 || output == 0 {
        return Ok(signed_status(0xC000_000D));
    }
    let mut class = [0u8; 16];
    if category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE {
        if data == 0 {
            return Ok(signed_status(0xC000_000D));
        }
        class.copy_from_slice(&guest::read_bytes(data, 16));
    }
    let record = guest::alloc_bytes(0x20);
    guest::write64(record, callback);
    guest::write64(record + 8, context);
    let registration = PlugPlayRegistration { category, class, callback, context, record };
    PLUG_PLAY_REGISTRATIONS.lock().push(registration);
    guest::write64(output, record);
    if category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE && flags & 1 != 0 {
        let existing: Vec<String> = DEVICE_INTERFACES.lock().iter().filter(|(_, entry)| entry.enabled && entry.class == class).map(|(link, _)| link.clone()).collect();
        for link in existing {
            notify_interface(&[registration], &INTERFACE_ARRIVAL, &class, &link);
        }
    }
    Ok(0)
}
fn io_unregister_plug_play_notification(call: &Call) -> Result<u64, KernelError> {
    let removed = {
        let mut registrations = PLUG_PLAY_REGISTRATIONS.lock();
        let Some(index) = registrations.iter().position(|registration| registration.record == call.arg(1)) else { return Ok(signed_status(0xC000_0034)) };
        registrations.remove(index)
    };
    guest::free_bytes(removed.record);
    Ok(0)
}
fn io_register_driver_reinitialization(call: &Call) -> Result<u64, KernelError> {
    lifecycle::register_reinitialization(call.arg(2), call.arg(3));
    Ok(0)
}
/// IoOpenDeviceRegistryKey: a chave de serviço do driver dono.
fn io_open_device_registry_key(call: &Call) -> Result<u64, KernelError> {
    let device = call.arg(1);
    let driver_node = io_manager::devices().into_iter().filter(|(_, entry)| entry.native_device == device).filter_map(|(_, entry)| entry.driver).last();
    let Some(driver_node) = driver_node else { return Ok(signed_status(0xC000_0034)) };
    let name = object_manager::node(driver_node).map(|node| node.name).unwrap_or_default();
    let (status, handle) = key_services::open_path(&format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{name}"), false)?;
    if status != 0 {
        return Ok(status as u64);
    }
    guest::write64(call.arg(3), handle);
    Ok(0)
}
fn io_wmi_registration_control(call: &Call) -> Result<u64, KernelError> {
    if call.arg(2) as u32 == 0 {
        WMI_DEVICES.lock().insert(call.arg(1));
    } else {
        WMI_DEVICES.lock().remove(&call.arg(1));
    }
    Ok(0)
}
fn io_connect_interrupt(call: &Call) -> Result<u64, KernelError> {
    Ok(interrupt_object::io_connect_interrupt(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u8, call.arg(7) as u8, call.arg(8) as u32, call.arg(9) & 0xFF != 0)? as u64)
}
fn io_disconnect_interrupt(call: &Call) -> Result<u64, KernelError> {
    interrupt_object::io_disconnect_interrupt(call.arg(1));
    Ok(0)
}
fn io_create_controller(call: &Call) -> Result<u64, KernelError> {
    Ok(controller::create(call.arg(1) as u32))
}
fn io_delete_controller(call: &Call) -> Result<u64, KernelError> {
    controller::delete(call.arg(1));
    Ok(0)
}
fn io_allocate_controller(call: &Call) -> Result<u64, KernelError> {
    controller::allocate(call.arg(1), call.arg(2), call.arg(3), call.arg(4));
    Ok(0)
}
fn io_free_controller(call: &Call) -> Result<u64, KernelError> {
    controller::free(call.arg(1));
    Ok(0)
}
fn io_start_packet(call: &Call) -> Result<u64, KernelError> {
    start_io::start_packet(call.arg(1), call.arg(2), call.arg(3), call.arg(4));
    Ok(0)
}
fn io_start_next_packet(call: &Call) -> Result<u64, KernelError> {
    start_io::start_next_packet(call.arg(1), call.arg(2) & 0xFF != 0);
    Ok(0)
}
fn io_set_start_io_attributes(call: &Call) -> Result<u64, KernelError> {
    start_io::set_start_io_attributes(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3) & 0xFF != 0);
    Ok(0)
}
/// Retém o topo pela posse do OB, não pela contagem de arquivos abertos.
fn io_get_attached_device_reference(call: &Call) -> Result<u64, KernelError> {
    device_objects::attached_reference(call.arg(1), false)
}
fn io_invalidate_device_state(call: &Call) -> Result<u64, KernelError> {
    INVALIDATED_DEVICES.lock().insert(call.arg(1));
    Ok(0)
}
fn io_query_device_description(call: &Call) -> Result<u64, KernelError> {
    Ok(hw_description::query_device_description(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8)) as u64)
}
/// IoConnectInterruptEx: LINE_BASED (2) pelo recurso do PDO; FULLY_SPECIFIED
/// (1/4) pelos campos; MESSAGE_BASED (MSI) sem suporte. O KINTERRUPT vai
/// para *(params+0x10).
fn io_connect_interrupt_ex(call: &Call) -> Result<u64, KernelError> {
    let parameters = call.arg(1);
    let version = guest::read32(parameters);
    let service_routine = guest::read64(parameters + 0x18);
    let service_context = guest::read64(parameters + 0x20);
    let spin_lock = guest::read64(parameters + 0x28);
    let output = guest::read64(parameters + 0x10);
    if version == 2 {
        let physical = guest::read64(parameters + 8);
        let Some(resource) = device_resources::consume_next_interrupt(physical) else {
            debug_print!("[io] IoConnectInterruptEx LINE_BASED: PDO 0x{:x} sem IRQ restante", physical);
            return Ok(signed_status(0xC000_009A));
        };
        // O modo vem do recurso (LEVEL_SENSITIVE), como a HAL faz.
        let mode = if resource.flags & 2 != 0 { 1 } else { 0 };
        let status = interrupt_object::io_connect_interrupt(output, service_routine, service_context, spin_lock, resource.vector, resource.level as u8, resource.level as u8, mode, false)?;
        debug_print!("[io] interrupt LINE_BASED: vetor 0x{:x} -> ISR 0x{:x}", resource.vector, service_routine);
        return Ok(status as u64);
    }
    if version == 1 || version == 4 {
        let synchronize = guest::read8(parameters + 0x30);
        let share = guest::read8(parameters + 0x32);
        let vector = guest::read32(parameters + 0x34);
        let level = guest::read8(parameters + 0x38);
        let mode = guest::read32(parameters + 0x3C);
        debug_print!("[io] interrupt FULLY_SPECIFIED: vetor 0x{:x} irql {} -> ISR 0x{:x}", vector, level, service_routine);
        return Ok(interrupt_object::io_connect_interrupt(output, service_routine, service_context, spin_lock, vector, level, synchronize, mode, share != 0)? as u64);
    }
    debug_print!("[io] IoConnectInterruptEx: version {} (MESSAGE_BASED) sem suporte — MSI nao configurado", version);
    Ok(signed_status(0xC000_00BB))
}
fn io_disconnect_interrupt_ex(call: &Call) -> Result<u64, KernelError> {
    let object = guest::read64(call.arg(1) + 8);
    if object == 0 {
        return Ok(signed_status(0xC000_000D));
    }
    interrupt_object::io_disconnect_interrupt(object);
    Ok(0)
}
/// IoReadPartitionTableEx: IOCTL_DISK_GET_DRIVE_LAYOUT_EX ao dispositivo e
/// o buffer devolvido ao chamador.
fn io_read_partition_table_ex(call: &Call) -> Result<u64, KernelError> {
    const IOCTL_DISK_GET_DRIVE_LAYOUT_EX: u32 = 0x0007_0050;
    let buffer = guest::alloc_bytes(0x1000);
    let event = guest::alloc_bytes(0x18);
    dispatcher::initialize_event(event, 0, false);
    let Some(node) = find_device_node_by_pointer(call.arg(1)) else { return Ok(signed_status(0xC000_000D)) };
    let mut request = io_manager::make_io_request(io_manager::irp_mj::DEVICE_CONTROL, io_manager::IoParams { control_code: IOCTL_DISK_GET_DRIVE_LAYOUT_EX, binary: true, buffer_length: Some(0x1000), user_event: event, ..Default::default() });
    io_manager::call_driver(&format!("\\Device\\{}", device_name(node)), &mut request)?;
    if request.status != 0 {
        return Ok(request.status as i64 as u64);
    }
    if let io_manager::IoResult::Bytes(bytes) = &request.result {
        guest::write_bytes(buffer, &bytes[..bytes.len().min(0x1000)]);
    }
    guest::write64(call.arg(2), buffer);
    Ok(0)
}
fn io_get_configuration_information(_: &Call) -> Result<u64, KernelError> {
    Ok(configuration_information())
}
/// IoInvalidateDeviceRelations: reenumera as BusRelations do FDO pai.
fn io_invalidate_device_relations(call: &Call) -> Result<u64, KernelError> {
    let node = find_device_node_by_pointer(call.arg(1));
    debug_print!("[pnp] relacoes invalidadas ({}) p/ \\Device\\{}", call.arg(2) as u32, node.map(device_name).unwrap_or_else(|| String::from("?")));
    let Some(node) = node else { return Ok(0) };
    let parent = io_manager::device(node).and_then(|entry| entry.child_of).unwrap_or(node);
    for child in pnp::query_bus_relations(parent) {
        let Some(child_node) = pnp::register_child_pdo(parent, child) else { continue };
        if io_manager::device(child_node).and_then(|entry| entry.hardware_ids).is_some_and(|ids| !ids.is_empty()) {
            pnp::enumerate_pdo_stack(child_node);
        }
    }
    Ok(0)
}
fn io_get_generic_irp_extension(call: &Call) -> Result<u64, KernelError> {
    Ok(request_extension(call.arg(1)).generic)
}
fn io_set_generic_irp_extension(call: &Call) -> Result<u64, KernelError> {
    let (generic, propagate) = (call.arg(2), (call.arg(3) & 0xFF != 0) as u32);
    update_extension(call.arg(1), |extension| {
        extension.generic = generic;
        extension.propagate = propagate;
    });
    Ok(0)
}
/// Copia a extensão propagável para o IRP associado.
fn io_propagate_irp_extension(call: &Call) -> Result<u64, KernelError> {
    let source = request_extension(call.arg(1));
    if source.generic == 0 {
        return Ok(signed_status(0xC000_0225));
    }
    update_extension(call.arg(2), |target| {
        target.generic = source.generic;
        target.propagate = source.propagate;
    });
    Ok(0)
}
fn io_get_activity_id_irp(call: &Call) -> Result<u64, KernelError> {
    let extension = REQUEST_EXTENSIONS.lock().get(&call.arg(1)).copied();
    let Some(extension) = extension.filter(|extension| extension.activity_id_present) else { return Ok(0xC000_0225) };
    guest::write_bytes(call.arg(2), &guest::read_bytes(extension.activity_id_pointer, 16));
    Ok(0)
}
fn io_set_activity_id_irp(call: &Call) -> Result<u64, KernelError> {
    let extension = request_extension(call.arg(1));
    guest::write_bytes(extension.activity_id_pointer, &guest::read_bytes(call.arg(2), 16));
    update_extension(call.arg(1), |extension| extension.activity_id_present = true);
    Ok(0)
}
/// Devolve o LPCGUID da thread (não copia para um buffer).
fn io_get_activity_id_thread(_: &Call) -> Result<u64, KernelError> {
    Ok(thread_activity::get())
}
fn io_clear_activity_id_thread(call: &Call) -> Result<u64, KernelError> {
    thread_activity::clear(call.arg(1));
    Ok(0)
}
fn io_propagate_activity_id_to_thread(call: &Call) -> Result<u64, KernelError> {
    let extension = REQUEST_EXTENSIONS.lock().get(&call.arg(1)).copied();
    let source = extension.filter(|extension| extension.activity_id_present).map_or(0, |extension| extension.activity_id_pointer);
    Ok(thread_activity::propagate(source, call.arg(2), call.arg(3)) as u64)
}
/// Nenhuma sessão de trace ETW ativa.
fn zero(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
/// IoReuseIrp: reinicializa mantendo o tamanho e a pilha alocados.
fn io_reuse_irp(call: &Call) -> Result<u64, KernelError> {
    let packet = call.arg(1);
    let count = guest::read8(packet + irp::STACK_COUNT);
    guest::write32(packet + irp::FLAGS, 0);
    guest::write64(packet + irp::MDL_ADDRESS, 0);
    guest::write64(packet + irp::SYSTEM_BUFFER, 0);
    guest::write32(packet + irp::IO_STATUS, call.arg(2) as u32);
    guest::write64(packet + irp::IO_STATUS_INFORMATION, 0);
    guest::write8(packet + irp::CURRENT_LOCATION, count.wrapping_add(1));
    guest::write8(packet + irp::CANCEL, 0);
    guest::write64(packet + irp::USER_EVENT, 0);
    guest::write64(packet + irp::CURRENT_STACK_LOCATION, irp_builder::first_stack_location(packet, count as u32) + io_stack_location::SIZE);
    Ok(0)
}
/// IoInitializeIrp: a forma do IopAllocateIrp, sem a alocação.
fn io_initialize_irp(call: &Call) -> Result<u64, KernelError> {
    let (packet, size, count) = (call.arg(1), call.arg(2) as u16, call.arg(3) as u8);
    for offset in (0..size as u64).step_by(4) {
        guest::write32(packet + offset, 0);
    }
    guest::write16(packet + irp::TYPE, irp::IO_TYPE);
    guest::write16(packet + irp::SIZE_FIELD, size);
    guest::write8(packet + irp::STACK_COUNT, count);
    guest::write8(packet + irp::CURRENT_LOCATION, count.wrapping_add(1));
    guest::write64(packet + irp::CURRENT_STACK_LOCATION, irp_builder::first_stack_location(packet, count as u32) + io_stack_location::SIZE);
    Ok(0)
}
fn io_set_master_irp_status(call: &Call) -> Result<u64, KernelError> {
    guest::write32(call.arg(1) + irp::IO_STATUS, call.arg(2) as u32);
    Ok(call.arg(2))
}
/// IoBuildPartialMdl: a janela do alvo dentro da origem, marcada MDL_PARTIAL.
fn io_build_partial_mdl(call: &Call) -> Result<u64, KernelError> {
    let (source, target, virtual_address, length) = (call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32);
    let source_start = guest::read64(source + mdl::START_VA);
    let aligned = virtual_address & !0xFFF;
    guest::write64(target + mdl::START_VA, aligned);
    guest::write32(target + mdl::BYTE_OFFSET, (virtual_address & 0xFFF) as u32);
    guest::write32(target + mdl::BYTE_COUNT, length);
    guest::write16(target + mdl::MDL_FLAGS, guest::read16(target + mdl::MDL_FLAGS) | 0x10);
    let offset = aligned.wrapping_sub(source_start) / 0x1000;
    let pages = ((virtual_address & 0xFFF) + length as u64).div_ceil(0x1000);
    for page in 0..pages {
        guest::write64(target + mdl::PFN_ARRAY + page * 8, guest::read64(source + mdl::PFN_ARRAY + (offset + page) * 8));
    }
    Ok(0)
}
fn io_sizeof_work_item(_: &Call) -> Result<u64, KernelError> {
    Ok(io_workitem::SIZE)
}
/// Storage QoS sem política configurada: identificador nulo.
fn io_allocate_sfio_stream_identifier(call: &Call) -> Result<u64, KernelError> {
    if call.arg(2) != 0 {
        guest::write64(call.arg(2), 0);
    }
    Ok(0)
}
/// Os IRPs nascem de código de kernel: o dono é o System.
fn io_get_requestor_process(_: &Call) -> Result<u64, KernelError> {
    Ok(process::get_system_process())
}
fn io_get_device_attachment_base_ref(call: &Call) -> Result<u64, KernelError> {
    device_objects::attached_reference(call.arg(1), true)
}
/// IoGetDevicePropertyData: propriedade desconhecida = STATUS_NOT_FOUND.
fn io_get_device_property_data(call: &Call) -> Result<u64, KernelError> {
    let key = call.arg(3);
    debug_print!("[io] DevicePropertyData: pdo 0x{:x} key fmtid {:x}-{:x}-{:x} pid {}", call.arg(1), guest::read32(key), guest::read16(key + 4), guest::read16(key + 6), guest::read32(key + 16));
    Ok(signed_status(0xC000_0225))
}
fn io_set_hard_error_or_verify_device(call: &Call) -> Result<u64, KernelError> {
    let device = call.arg(2);
    update_extension(call.arg(1), |extension| extension.hard_error_device = device);
    Ok(0)
}
fn io_set_thread_hard_error_mode(call: &Call) -> Result<u64, KernelError> {
    Ok(thread_io::set_hard_error_mode(call.arg(1) as u8)? as u64)
}
fn io_register_shutdown_notification(call: &Call) -> Result<u64, KernelError> {
    SHUTDOWN_DEVICES.lock().push(call.arg(1));
    Ok(0)
}
fn io_unregister_shutdown_notification(call: &Call) -> Result<u64, KernelError> {
    let mut devices = SHUTDOWN_DEVICES.lock();
    if let Some(index) = devices.iter().position(|&device| device == call.arg(1)) {
        devices.remove(index);
    }
    Ok(0)
}
/// Work item do IoReportTargetDeviceChangeAsynchronous: entrega a estrutura
/// aos registros de EventCategoryTargetDeviceChange e chama o callback de
/// conclusão do chamador.
fn deliver_target_change(_device: u64, item: u64) {
    let Some((notification, callback, context)) = TARGET_CHANGES.lock().remove(&item) else { return };
    let registrations = PLUG_PLAY_REGISTRATIONS.lock().clone();
    for registration in registrations.iter().filter(|registration| registration.category == EVENT_CATEGORY_TARGET_DEVICE_CHANGE) {
        native_call::call(registration.callback, &[notification, registration.context]);
    }
    if callback != 0 {
        native_call::call(callback, &[context, 0]);
    }
}
/// IoReportTargetDeviceChangeAsynchronous(PhysicalDeviceObject,
/// NotificationStructure, Callback, Context).
fn io_report_target_device_change_asynchronous(call: &Call) -> Result<u64, KernelError> {
    let item = guest::alloc_bytes(io_workitem::SIZE);
    TARGET_CHANGES.lock().insert(item, (call.arg(2), call.arg(3), call.arg(4)));
    work_items::queue_kernel_work_item(item, deliver_target_change, item, None);
    Ok(0)
}
fn io_register_priority_callback(call: &Call) -> Result<u64, KernelError> {
    PRIORITY_CALLBACKS.lock().push(call.arg(1));
    Ok(0)
}
fn io_unregister_priority_callback(call: &Call) -> Result<u64, KernelError> {
    let mut callbacks = PRIORITY_CALLBACKS.lock();
    if let Some(index) = callbacks.iter().position(|&callback| callback == call.arg(1)) {
        callbacks.remove(index);
    }
    Ok(0)
}
/// Um ponteiro único e estável serve de id do provedor WMI.
fn io_wmi_device_object_to_provider_id(call: &Call) -> Result<u64, KernelError> {
    Ok(call.arg(1) as u32 as u64)
}
fn io_initialize_work_item(call: &Call) -> Result<u64, KernelError> {
    work_items::create_work_item(call.arg(1), call.arg(2));
    Ok(0)
}
fn io_query_file_information(call: &Call) -> Result<u64, KernelError> {
    Ok(zw_files::query_file_information_by_object(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5))? as u64)
}

fn io_driver_object_type() -> u64 {
    kernel_data::address("IoDriverObjectType").unwrap_or_else(|error| panic!("IoDriverObjectType: {error}"))
}
fn io_file_object_type() -> u64 {
    kernel_data::address("IoFileObjectType").unwrap_or_else(|error| panic!("IoFileObjectType: {error}"))
}

/// Chamado no desligamento: IRP_MJ_SHUTDOWN a cada dispositivo registrado.
pub fn run_shutdown_notifications() {
    let devices = SHUTDOWN_DEVICES.lock().clone();
    for device in devices {
        let Some(node) = find_device_node_by_pointer(device) else { continue };
        let mut request = io_manager::make_io_request(io_manager::irp_mj::SHUTDOWN, io_manager::IoParams::default());
        let _ = io_manager::call_driver(&format!("\\Device\\{}", device_name(node)), &mut request);
    }
}

/// Dispositivos com estado invalidado (consultados pelo fluxo PnP).
pub fn invalidated(device: u64) -> bool {
    INVALIDATED_DEVICES.lock().contains(&device)
}

/// Interface de dispositivo habilitada.
pub fn interface_enabled(link: &str) -> Option<bool> {
    DEVICE_INTERFACES.lock().get(link).map(|entry| entry.enabled)
}

pub static GROUP: Group = Group {
    name: "io",
    names: &[
        "IoCreateDevice", "IoCreateSymbolicLink", "IoDeleteDevice", "IoDeleteSymbolicLink", "IoAllocateIrp", "IoFreeIrp", "IoCompleteRequest", "IofCompleteRequest", "IoAllocateWorkItem", "IoQueueWorkItem", "IoFreeWorkItem", "IoCallDriver", "IofCallDriver", "IoAttachDeviceToDeviceStack", "IoDetachDevice", "IoGetDeviceObjectPointer", "IoBuildSynchronousFsdRequest", "IoBuildDeviceIoControlRequest", "IoInitializeTimer", "IoStartTimer", "IoStopTimer", "IoQueueWorkItemEx", "IoAllocateMdl", "IoFreeMdl", "IoGetCurrentThread", "IoSetCancelRoutine", "IoCancelIrp", "IoAllocateDriverObjectExtension", "IoGetDriverObjectExtension", "IoGetCurrentProcess", "IoCreateFile", "IoGetRelatedDeviceObject", "IoGetDeviceProperty", "IoGetStackLimits", "IoInitializeRemoveLockEx", "IoAcquireRemoveLockEx", "IoReleaseRemoveLockEx", "IoReleaseRemoveLockAndWaitEx", "IoAllocateErrorLogEntry", "IoWriteErrorLogEntry", "IoAcquireCancelSpinLock", "IoReleaseCancelSpinLock", "IoRegisterDeviceInterface", "IoSetDeviceInterfaceState", "IoRegisterPlugPlayNotification", "IoUnregisterPlugPlayNotification", "IoRegisterDriverReinitialization", "IoOpenDeviceRegistryKey", "IoWMIRegistrationControl", "IoConnectInterrupt", "IoDisconnectInterrupt", "IoCreateController", "IoDeleteController", "IoAllocateController", "IoFreeController", "IoStartPacket", "IoStartNextPacket", "IoSetStartIoAttributes", "IoGetAttachedDeviceReference", "IoInvalidateDeviceState", "IoQueryDeviceDescription", "IoConnectInterruptEx", "IoDisconnectInterruptEx", "IoReadPartitionTableEx", "IoGetConfigurationInformation", "IoInvalidateDeviceRelations", "IoGetGenericIrpExtension", "IoSetGenericIrpExtension", "IoPropagateIrpExtensionEx", "IoGetActivityIdIrp", "IoSetActivityIdIrp", "IoGetActivityIdThread", "IoClearActivityIdThread", "IoPropagateActivityIdToThread", "IoIsActivityTracingEnabled", "IoReuseIrp", "IoInitializeIrp", "IoSetMasterIrpStatus", "IoBuildPartialMdl", "IoSizeofWorkItem", "IoAllocateSfioStreamIdentifier", "IoGetSfioStreamIdentifier", "IoFreeSfioStreamIdentifier", "IoGetIoAttributionHandle", "IoRecordIoAttribution", "IoGetIoPriorityHint", "IoGetPagingIoPriority", "IoGetRequestorProcess", "IoIs32bitProcess", "IoGetDeviceAttachmentBaseRef", "IoGetDevicePropertyData", "IoSetHardErrorOrVerifyDevice", "IoSetThreadHardErrorMode", "IoRegisterShutdownNotification", "IoUnregisterShutdownNotification", "IoReportTargetDeviceChangeAsynchronous", "IoRegisterPriorityCallback", "IoUnregisterPriorityCallback", "IoWMIDeviceObjectToProviderId", "IoWMIWriteEvent", "IoCreateFileEx", "IoInitializeWorkItem", "IoQueryFileInformation", "IoUnregisterPlugPlayNotificationEx",
    ],
    handlers: &[
        io_create_device, io_create_symbolic_link, io_delete_device, io_delete_symbolic_link, io_allocate_irp, io_free_irp, io_complete_request, io_complete_request, io_allocate_work_item, io_queue_work_item, io_free_work_item, io_call_driver, io_call_driver, io_attach_device_to_device_stack, io_detach_device, get_device_object_pointer_export, io_build_synchronous_fsd_request, io_build_device_io_control_request, io_initialize_timer, io_start_timer, io_stop_timer, io_queue_work_item_ex, io_allocate_mdl, io_free_mdl, io_get_current_thread, io_set_cancel_routine, io_cancel_irp, io_allocate_driver_object_extension, io_get_driver_object_extension, io_get_current_process, io_create_file, io_get_related_device_object, io_get_device_property, io_get_stack_limits, io_initialize_remove_lock, io_acquire_remove_lock, io_release_remove_lock, io_release_remove_lock_and_wait, io_allocate_error_log_entry, io_write_error_log_entry, io_acquire_cancel_spin_lock, io_release_cancel_spin_lock, io_register_device_interface, io_set_device_interface_state, io_register_plug_play_notification, io_unregister_plug_play_notification, io_register_driver_reinitialization, io_open_device_registry_key, io_wmi_registration_control, io_connect_interrupt, io_disconnect_interrupt, io_create_controller, io_delete_controller, io_allocate_controller, io_free_controller, io_start_packet, io_start_next_packet, io_set_start_io_attributes, io_get_attached_device_reference, io_invalidate_device_state, io_query_device_description, io_connect_interrupt_ex, io_disconnect_interrupt_ex, io_read_partition_table_ex, io_get_configuration_information, io_invalidate_device_relations, io_get_generic_irp_extension, io_set_generic_irp_extension, io_propagate_irp_extension, io_get_activity_id_irp, io_set_activity_id_irp, io_get_activity_id_thread, io_clear_activity_id_thread, io_propagate_activity_id_to_thread, zero, io_reuse_irp, io_initialize_irp, io_set_master_irp_status, io_build_partial_mdl, io_sizeof_work_item, io_allocate_sfio_stream_identifier, zero, zero, zero, zero, zero, zero, io_get_requestor_process, zero, io_get_device_attachment_base_ref, io_get_device_property_data, io_set_hard_error_or_verify_device, io_set_thread_hard_error_mode, io_register_shutdown_notification, io_unregister_shutdown_notification, io_report_target_device_change_asynchronous, io_register_priority_callback, io_unregister_priority_callback, io_wmi_device_object_to_provider_id, zero, io_create_file, io_initialize_work_item, io_query_file_information, io_unregister_plug_play_notification,
    ],
    data_exports: &[("IoDriverObjectType", io_driver_object_type), ("IoFileObjectType", io_file_object_type)],
};

pub mod attach_device_safe {
    //! IoAttachDeviceToDeviceStackSafe — o encadeamento do grupo `io`; a ausência
    //! de dispositivo vira STATUS_NO_SUCH_DEVICE.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::exports as io;
    use crate::rtl::KernelError;

    fn attach(call: &Call) -> Result<u64, KernelError> {
        Ok(if io::attach_device_to_device_stack(call.arg(1), call.arg(2), call.arg(3))? != 0 { 0 } else { signed_status(0xC000_000E) })
    }

    pub static GROUP: Group = Group { name: "attach-device-safe", names: &["IoAttachDeviceToDeviceStackSafe"], handlers: &[attach], data_exports: &[] };
}

pub mod attached_device {
    //! IoGetAttachedDevice — `system32/win32/ntoskrnl/attached-device.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::objects::device as device_objects;

    fn get_attached_device(call: &Call) -> Result<u64, KernelError> {
        Ok(device_objects::top(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "attached-device",
        names: &["IoGetAttachedDevice"],
        handlers: &[get_attached_device],
        data_exports: &[],
    };
}

pub mod convert_file_handle {
    //! IoConvertFileHandleToKernelHandle — `ntos/io/convert-file-handle`; falha
    //! interna interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::init::exports::fatal_unless_transfer;
    use crate::ntos::io::file::convert_handle as convert_file_handle;
    use crate::rtl::KernelError;

    fn convert(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("convert-file-handle", convert_file_handle::convert(call.arg(1), call.arg(2) as u8, call.arg(3) as u32, call.arg(4) & 0xFF != 0, call.arg(5))).map(|status| status as u64)
    }

    pub static GROUP: Group = Group { name: "convert-file-handle", names: &["IoConvertFileHandleToKernelHandle"], handlers: &[convert], data_exports: &[] };
}

fn acquire_vpb_spin_lock(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::ke::exports::acquire_vpb_spin_lock(call.arg(1))
}
fn release_vpb_spin_lock(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::ke::exports::release_vpb_spin_lock(call.arg(1))
}

/// IoGetAffinityInterrupt: o processador que recebe a interrupção (o
/// Number do KINTERRUPT), no grupo 0.
fn get_affinity_interrupt(call: &Call) -> Result<u64, KernelError> {
    let (object, affinity) = (call.arg(1), call.arg(2));
    if object == 0 || affinity == 0 {
        return Ok(signed_status(0xC000_000D));
    }
    let processor = guest::read32(object + crate::ntos::inc::nt_abi::kinterrupt::NUMBER) & 63;
    guest::write_bytes(affinity, &[0; 16]);
    guest::write64(affinity, 1u64 << processor);
    Ok(0)
}

pub static INTERRUPT_AFFINITY_GROUP: Group = Group {
    name: "interrupt-affinity",
    names: &["IoGetAffinityInterrupt"],
    handlers: &[get_affinity_interrupt],
    data_exports: &[],
};

pub static VPB_SPIN_LOCK_GROUP: Group = Group {
    name: "vpb-spin-lock",
    names: &["IoAcquireVpbSpinLock", "IoReleaseVpbSpinLock"],
    handlers: &[acquire_vpb_spin_lock, release_vpb_spin_lock],
    data_exports: &[],
};

pub mod disk_device {
    //! IoGetDiskDeviceObject — `ntos/io/volume-parameters`; falha interna
    //! interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::init::exports::fatal_unless_transfer;
    use crate::ntos::io::volume_parameters;
    use crate::rtl::KernelError;

    fn get_disk_device(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("disk-device", volume_parameters::get_disk_device(call.arg(1), call.arg(2))).map(|status| status as u64)
    }

    pub static GROUP: Group = Group { name: "disk-device", names: &["IoGetDiskDeviceObject"], handlers: &[get_disk_device], data_exports: &[] };
}

pub mod enumerate_devices {
    //! IoEnumerateDeviceObjectList — `system32/win32/ntoskrnl/enumerate-devices.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::objects::device as device_objects;

    fn enumerate_device_object_list(call: &Call) -> Result<u64, KernelError> {
        Ok(device_objects::enumerate(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "enumerate-devices",
        names: &["IoEnumerateDeviceObjectList"],
        handlers: &[enumerate_device_object_list],
        data_exports: &[],
    };
}

pub mod initial_stack {
    //! IoGetInitialStack — `ntos/io/initial-stack`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::small::initial_stack;
    use crate::rtl::KernelError;

    fn get(_: &Call) -> Result<u64, KernelError> {
        Ok(initial_stack::get())
    }

    pub static GROUP: Group = Group { name: "initial-stack", names: &["IoGetInitialStack"], handlers: &[get], data_exports: &[] };
}

pub mod lower_device {
    //! IoGetLowerDeviceObject — `system32/win32/ntoskrnl/lower-device.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::objects::device as device_objects;

    fn get_lower_device_object(call: &Call) -> Result<u64, KernelError> {
        device_objects::get_lower(call.arg(1))
    }

    pub static GROUP: Group = Group {
        name: "lower-device",
        names: &["IoGetLowerDeviceObject"],
        handlers: &[get_lower_device_object],
        data_exports: &[],
    };
}

pub mod set_completion {
    //! IoSetIoCompletionEx — `win32/ntoskrnl/set-completion.js`: publica na fila
    //! real e interrompe usos inválidos de ponteiros de kernel.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::io::completion::set as set_completion;
    use crate::rtl::KernelError;

    fn post(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("set-completion", set_completion::post(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6), call.arg(7)))? as u64)
    }

    pub static GROUP: Group = Group { name: "set-completion", names: &["IoSetIoCompletionEx"], handlers: &[post], data_exports: &[] };
}

pub mod thread_activity_exports {
    //! IoSetActivityIdThread — `ntos/io/thread-activity`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::threads::thread_activity;
    use crate::rtl::KernelError;

    fn set(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_activity::set(call.arg(1)))
    }

    pub static GROUP: Group = Group { name: "thread-activity", names: &["IoSetActivityIdThread"], handlers: &[set], data_exports: &[] };
}

pub mod volume_dos_name {
    //! IoVolumeDeviceToDosName — `ntos/io/volume-dos-name`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::volume_dos_name;
    use crate::rtl::KernelError;

    fn volume_device_to_dos_name(call: &Call) -> Result<u64, KernelError> {
        Ok(volume_dos_name::volume_device_to_dos_name(call.arg(1), call.arg(2))? as u64)
    }

    pub static GROUP: Group = Group { name: "volume-dos-name", names: &["IoVolumeDeviceToDosName"], handlers: &[volume_device_to_dos_name], data_exports: &[] };
}

pub mod create_completion {
    //! ZwCreateIoCompletion — `win32/ntoskrnl/create-completion.js`: KernelMode,
    //! handles de kernel quando pedidos e a ABI de 64 bits.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::io::completion::create as create_completion;
    use crate::rtl::KernelError;

    fn create(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("create-completion", create_completion::create(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, 0))? as u64)
    }

    pub static GROUP: Group = Group { name: "create-completion", names: &["ZwCreateIoCompletion"], handlers: &[create], data_exports: &[] };
}

pub mod remove_completion {
    //! ZwRemoveIoCompletionEx — `win32/ntoskrnl/remove-completion.js`: entrada
    //! Zw de seis argumentos, com espera cooperativa sem contexto suspenso.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::completion::remove as remove_completion;
    use crate::ntos::ke::dispatcher;
    use crate::ntos::rtl::native_context;
    use crate::rtl::KernelError;

    fn remove(call: &Call) -> Result<u64, KernelError> {
        let result = (|| -> Result<u32, KernelError> {
            let mut request = remove_completion::begin(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6) & 0xFF != 0, 0, true, None)?;
            loop {
                if let Some(status) = request.poll() {
                    return Ok(status);
                }
                dispatcher::pump_kernel();
            }
        })();
        match result {
            Ok(status) => Ok(signed_status(status)),
            Err(error) if native_context::is_transfer(&error) => Err(error),
            Err(error) => panic!("[remove-completion] fatal kernel failure: {error}"),
        }
    }

    pub static GROUP: Group = Group { name: "remove-completion", names: &["ZwRemoveIoCompletionEx"], handlers: &[remove], data_exports: &[] };
}

pub mod read_file {
    //! NtReadFile — adaptador da ABI nativa de `ntos/io/read-file`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::file::read as read_file;
    use crate::rtl::KernelError;

    fn read(call: &Call) -> Result<u64, KernelError> {
        Ok(read_file::read(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7) as u32, call.arg(8), call.arg(9))? as u64)
    }

    pub static GROUP: Group = Group { name: "read-file", names: &["NtReadFile"], handlers: &[read], data_exports: &[] };
}

pub mod write_file {
    //! NtWriteFile — adaptador da ABI nativa de `ntos/io/write-file`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::file::write as write_file;
    use crate::rtl::KernelError;

    fn write(call: &Call) -> Result<u64, KernelError> {
        Ok(write_file::write(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7) as u32, call.arg(8), call.arg(9))? as u64)
    }

    pub static GROUP: Group = Group { name: "write-file", names: &["NtWriteFile"], handlers: &[write], data_exports: &[] };
}

pub mod query_file {
    //! NtQueryInformationFile — adaptador da ABI nativa de `ntos/io/query-file`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::file::query as query_file;
    use crate::rtl::KernelError;

    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(query_file::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32)? as u64)
    }

    pub static GROUP: Group = Group { name: "query-file", names: &["NtQueryInformationFile"], handlers: &[query], data_exports: &[] };
}

pub mod delete_file {
    //! ZwDeleteFile — `ntos/io/delete-file`; o Zw força KernelMode durante todo o
    //! serviço e conserva o PreviousMode anterior.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::file::delete as delete_file;
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn remove(call: &Call) -> Result<u64, KernelError> {
        Ok(previous_mode::with_kernel(|| delete_file::remove(call.arg(1)))?? as u64)
    }

    pub static GROUP: Group = Group { name: "delete-file", names: &["ZwDeleteFile"], handlers: &[remove], data_exports: &[] };
}

pub mod device_control {
    //! ZwDeviceIoControlFile — `ntos/io/device-control`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::device_control;
    use crate::rtl::KernelError;

    fn control(call: &Call) -> Result<u64, KernelError> {
        Ok(device_control::control(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6) as u32, call.arg(7), call.arg(8) as u32, call.arg(9), call.arg(10) as u32)? as u64)
    }

    pub static GROUP: Group = Group { name: "device-control", names: &["ZwDeviceIoControlFile"], handlers: &[control], data_exports: &[] };
}

pub mod driver_helpers {
    //! Auxiliares que vários drivers reais importam e que o OpenNT atende com
    //! a semântica real do ntoskrnl: referência segura/adiada de objetos, o
    //! mapeamento genérico do FILE_OBJECT e consultas de energia/boot que não
    //! se aplicam a esta plataforma.

    use core::sync::atomic::{AtomicU64, Ordering};

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ob::exports::{dereference_with_tag, reference_with_tag};
    use crate::ntos::ob::reference_trace::DEFAULT_TAG;
    use crate::rtl::KernelError;

    /// ObReferenceObjectSafe: TRUE se a referência foi adquirida (objeto vivo).
    fn reference_object_safe(call: &Call) -> Result<u64, KernelError> {
        Ok(reference_with_tag(call.arg(1), DEFAULT_TAG, true).is_ok() as u64)
    }
    fn reference_object_safe_with_tag(call: &Call) -> Result<u64, KernelError> {
        Ok(reference_with_tag(call.arg(1), call.arg(2) as u32, true).is_ok() as u64)
    }
    /// ObDereferenceObjectDeferDelete: a coleta do OpenNT já é feita fora da
    /// linha do chamador, então o "defer" não muda nada.
    fn dereference_object_defer_delete(call: &Call) -> Result<u64, KernelError> {
        dereference_with_tag(call.arg(1), DEFAULT_TAG, true)?;
        Ok(0)
    }
    fn dereference_object_defer_delete_with_tag(call: &Call) -> Result<u64, KernelError> {
        dereference_with_tag(call.arg(1), call.arg(2) as u32, true)?;
        Ok(0)
    }

    /// IoGetFileObjectGenericMapping: &IopFileMapping (os quatro valores reais).
    static FILE_MAPPING: AtomicU64 = AtomicU64::new(0);
    fn get_file_object_generic_mapping(_: &Call) -> Result<u64, KernelError> {
        let mut pointer = FILE_MAPPING.load(Ordering::Acquire);
        if pointer == 0 {
            pointer = guest::alloc_bytes(16);
            guest::write32(pointer, 0x0012_0089);
            guest::write32(pointer + 4, 0x0012_0116);
            guest::write32(pointer + 8, 0x0012_00A0);
            guest::write32(pointer + 12, 0x001F_01FF);
            FILE_MAPPING.store(pointer, Ordering::Release);
        }
        Ok(pointer)
    }

    /// Sem estimador de energia, sem soft boot e sem Windows-To-Go aqui.
    fn energy_estimation_enabled(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    fn update_component_power(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    fn is_soft_boot(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    fn check_portable_operating_system(call: &Call) -> Result<u64, KernelError> {
        if call.arg(1) != 0 {
            guest::write8(call.arg(1), 0);
        }
        Ok(0)
    }
    /// ZwFlushKey: o Registry do OpenNT é em memória; nada a descarregar.
    fn flush_key(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(0))
    }

    pub static GROUP: Group = Group {
        name: "driver-helpers",
        names: &[
            "ObReferenceObjectSafe", "ObReferenceObjectSafeWithTag", "ObDereferenceObjectDeferDelete",
            "ObDereferenceObjectDeferDeleteWithTag", "IoGetFileObjectGenericMapping", "PoEnergyEstimationEnabled",
            "PsUpdateComponentPower", "ExIsSoftBoot", "RtlCheckPortableOperatingSystem", "ZwFlushKey",
        ],
        handlers: &[
            reference_object_safe, reference_object_safe_with_tag, dereference_object_defer_delete,
            dereference_object_defer_delete_with_tag, get_file_object_generic_mapping, energy_estimation_enabled,
            update_component_power, is_soft_boot, check_portable_operating_system, flush_key,
        ],
        data_exports: &[],
    };
}

pub mod watchdog_support {
    //! Exports que o `watchdog.sys` real (e, abaixo dele, todo o stack de
    //! vídeo) importa do ntoskrnl e que o OpenNT ainda não oferecia: captura de
    //! contexto, consultas de console/WMI e os Zw que o watchdog usa no início.
    //! São atendidos com a semântica do NT; onde o subsistema não existe nesta
    //! plataforma (WMI, hard-error de usuário, depuração de kernel) devolvem o
    //! status que a inicialização do watchdog tolera, como o próprio Windows.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::file::zw as zw_files;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::rtl::native_context;
    use crate::rtl::KernelError;

    /// Tamanho do CONTEXT x64 do Windows e ContextFlags de CONTEXT_FULL.
    const CONTEXT_SIZE: u64 = 0x4D0;
    const CONTEXT_FULL: u32 = 0x0010_000B;
    const STATUS_WMI_GUID_NOT_FOUND: u32 = 0xC000_0295;
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

    /// IoRaiseInformationalHardError: sem porta de hard-error de usuário neste
    /// host; o uso do watchdog é não-fatal, então nenhum popup sobe (FALSE).
    fn raise_informational_hard_error(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// IoWMIOpenBlock / IoWMIQueryAllData: sem provedor WMI, o GUID não existe
    /// — a inicialização de WMI do watchdog segue mesmo com essa falha.
    fn wmi_open_block(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_WMI_GUID_NOT_FOUND))
    }
    fn wmi_query_all_data(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_WMI_GUID_NOT_FOUND))
    }

    /// RtlCaptureContext: copia o CONTEXT nativo ativo (o estado do chamador no
    /// gateway, isto é, logo após o `call` ao export) para o buffer do
    /// convidado e fixa ContextFlags = CONTEXT_FULL, como o ntoskrnl.
    fn capture_context(call: &Call) -> Result<u64, KernelError> {
        let target = call.arg(1);
        if target != 0 {
            if let Ok(source) = native_context::current() {
                native_context::copy(target, source, CONTEXT_SIZE);
            }
            guest::write32(target + 0x30, CONTEXT_FULL);
        }
        Ok(0)
    }

    /// RtlGetActiveConsoleId: a sessão de console ativa é a 0.
    fn get_active_console_id(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// ZwFlushBuffersFileEx: as escritas do OpenNT já são síncronas; valida o
    /// handle e escreve o IO_STATUS_BLOCK como o ZwFlushBuffersFile (o
    /// IO_STATUS_BLOCK é o 5º argumento no NtFlushBuffersFileEx).
    fn flush_buffers_file_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(zw_files::flush_buffers_file(call.arg(1), call.arg(5))))
    }

    /// ZwSystemDebugControl: depuração de kernel não é suportada neste host.
    fn system_debug_control(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_NOT_IMPLEMENTED))
    }

    pub static GROUP: Group = Group {
        name: "watchdog-support",
        names: &[
            "IoRaiseInformationalHardError", "IoWMIOpenBlock", "IoWMIQueryAllData",
            "RtlCaptureContext", "RtlGetActiveConsoleId", "ZwFlushBuffersFileEx", "ZwSystemDebugControl",
        ],
        handlers: &[
            raise_informational_hard_error, wmi_open_block, wmi_query_all_data,
            capture_context, get_active_console_id, flush_buffers_file_ex, system_debug_control,
        ],
        data_exports: &[],
    };
}

pub mod basicdisplay_support {
    //! Exports que o BasicDisplay.sys real (Microsoft Basic Display, driver de
    //! vídeo display-only) importa e que faltavam: o bit-scan e a comparação da
    //! CRT, o bloqueio de sono do Po e os x86Bios. Não há emulador de VBIOS de
    //! 16 bits aqui — o OpenNT faz o scanout pelo framebuffer DISPI, então a
    //! chamada de BIOS falha de modo tolerado (como numa máquina sem VGA BIOS
    //! legado), e o BasicDisplay segue pelo caminho do framebuffer.

    use core::sync::atomic::{AtomicU64, Ordering};

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::rtl::KernelError;

    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

    /// RtlFindLeastSignificantBit: índice do bit 1 mais baixo, -1 se a máscara
    /// for zero (devolvido como CCHAR, 0xFF).
    fn find_least_significant_bit(call: &Call) -> Result<u64, KernelError> {
        let mask = call.arg(1);
        Ok(if mask == 0 { u64::MAX } else { mask.trailing_zeros() as u64 })
    }

    /// _strnicmp: compara até `count` bytes sem diferenciar maiúsculas/minúsculas.
    fn strnicmp(call: &Call) -> Result<u64, KernelError> {
        let (mut first, mut second, count) = (call.arg(1), call.arg(2), call.arg(3));
        for _ in 0..count {
            let left = guest::read8(first).to_ascii_lowercase();
            let right = guest::read8(second).to_ascii_lowercase();
            if left != right {
                return Ok(if left < right { u64::MAX } else { 1 });
            }
            if left == 0 {
                break;
            }
            first += 1;
            second += 1;
        }
        Ok(0)
    }

    /// PoDisableSleepStates: o OpenNT não entra em estados de sono; devolve um
    /// identificador opaco não-nulo (um buffer em cache) que o driver guarda e
    /// repassa a PoReenableSleepStates, que é um no-op.
    static SLEEP_HANDLE: AtomicU64 = AtomicU64::new(0);
    fn disable_sleep_states(_: &Call) -> Result<u64, KernelError> {
        let mut handle = SLEEP_HANDLE.load(Ordering::Acquire);
        if handle == 0 {
            handle = guest::alloc_bytes(16);
            SLEEP_HANDLE.store(handle, Ordering::Release);
        }
        Ok(handle)
    }
    fn reenable_sleep_states(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// x86BiosCall: sem VBIOS emulado, devolve FALSE; o BasicDisplay tolera.
    fn x86_bios_call(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    /// x86BiosFreeBuffer: nada a liberar — STATUS_SUCCESS.
    fn x86_bios_free_buffer(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }
    /// x86BiosAllocateBuffer/ReadMemory/WriteMemory: recurso de VBIOS ausente.
    fn x86_bios_not_implemented(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_NOT_IMPLEMENTED))
    }

    pub static GROUP: Group = Group {
        name: "basicdisplay-support",
        names: &[
            "RtlFindLeastSignificantBit", "_strnicmp", "PoDisableSleepStates", "PoReenableSleepStates",
            "x86BiosAllocateBuffer", "x86BiosCall", "x86BiosFreeBuffer", "x86BiosReadMemory", "x86BiosWriteMemory",
        ],
        handlers: &[
            find_least_significant_bit, strnicmp, disable_sleep_states, reenable_sleep_states,
            x86_bios_not_implemented, x86_bios_call, x86_bios_free_buffer, x86_bios_not_implemented, x86_bios_not_implemented,
        ],
        data_exports: &[],
    };
}
