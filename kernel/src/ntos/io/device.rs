//! Objetos de dispositivo do I/O Manager — IoCreateDevice, a retirada do
//! dispositivo, as pilhas de attach (IoAttachDeviceToDeviceStack[Safe],
//! IoDetachDevice), IoGetDeviceObjectPointer e os links simbólicos.
//!
//! Os dispositivos vivem no namespace do Object Manager e encadeados na
//! lista do driver (DeviceObject->NextDevice); a rota de despacho de cada
//! `\Device` nomeado segue o topo da pilha. O FDO lembra o PDO registrado no
//! attach, para as consultas de propriedade do hardware.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::io::{io_manager, lifecycle};
use crate::ntos::io::threads::io_timer;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::{device as device_objects, file as file_objects};
use crate::ntos::po::power_manager;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{DeviceObject, DevobjExtension, DriverObject, NtStruct};

const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;

/// FDO → PDO registrado no attach (IoGetDeviceProperty acha o PDO de hardware).
/// IO_TYPE_DEVICE e IO_TYPE_DEVICE_OBJECT_EXTENSION.
const IO_TYPE_DEVICE: i16 = 3;
const IO_TYPE_DEVICE_OBJECT_EXTENSION: i16 = 0x0D;

fn device_at(device: u64) -> &'static DeviceObject {
    // SAFETY: DEVICE_OBJECT vivo (registrado em `device_objects`).
    unsafe { DeviceObject::at(device) }
}

fn driver_at(driver: u64) -> &'static DriverObject {
    // SAFETY: DRIVER_OBJECT vivo dono do dispositivo.
    unsafe { DriverObject::at(driver) }
}

static PHYSICAL_BY_ATTACHED: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());
static UNNAMED_DEVICES: SpinLock<u32> = SpinLock::new(0);

/// FILE_DEVICE_CD_ROM (2), FILE_DEVICE_DISK (7), FILE_DEVICE_TAPE (0x1F) e
/// FILE_DEVICE_VIRTUAL_DISK (0x24): a máscara 0x1080000084 do IoCreateDevice.
const MOUNTABLE_DEVICE_TYPES: u64 = 0x10_8000_0084;

/// SectorSize inicial do IoCreateDevice: 0x800 para o file system de CD-ROM,
/// 0x200 para disco, file system de disco e disco virtual, 0 nos demais.
fn default_sector_size(device_type: u32) -> u16 {
    match device_type {
        0x03 => 0x800,
        0x07 | 0x08 | 0x24 => 0x200,
        _ => 0,
    }
}

/// Nome relativo a `\Device` (subdiretórios incluídos, como `Ide\IdePort0`).
pub fn device_name(node: object_manager::NodeId) -> String {
    let path = object_manager::path_of(node).unwrap_or_default();
    match path.get(..8) {
        Some(prefix) if prefix.eq_ignore_ascii_case("\\Device\\") => String::from(&path[8..]),
        _ => object_manager::node(node).map(|node| node.name).unwrap_or_default(),
    }
}

/// Nó `\Device` dono de um DEVICE_OBJECT.
pub fn find_device_node_by_pointer(device: u64) -> Option<object_manager::NodeId> {
    if device == 0 {
        return None;
    }
    io_manager::devices().into_iter().find(|(_, entry)| entry.native_device == device).map(|(node, _)| node)
}

/// Falha do Object Manager com status próprio vira esse NTSTATUS; as
/// demais continuam como falha interna.
pub fn kernel_status(error: KernelError) -> Result<u32, KernelError> {
    if error.status != 0 && error.status != 0xC000_0001 {
        Ok(error.status)
    } else {
        Err(error)
    }
}

/// IoCreateDevice: DEVICE_OBJECT real com a extensão logo depois, no
/// namespace e na cabeça da lista do driver dono. Dispositivos sem nome
/// (`name_pointer` nulo) recebem um nome interno único.
pub fn create_device(driver: u64, extension_size: u32, name_pointer: u64, device_type: u32, characteristics: u32, output: u64) -> Result<u32, KernelError> {
    let name = if name_pointer != 0 { Some(guest_strings::read_unicode_string(name_pointer)) } else { None };
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
    // Como o IoCreateDevice: DEVICE_OBJECT, extensão do driver (arredondada
    // a 8) e a DEVOBJ_EXTENSION no fim do mesmo bloco.
    let extension_bytes = (extension_size as u64 + 7) & !7;
    let page = guest::alloc_bytes(DeviceObject::SIZE + extension_bytes + DevobjExtension::SIZE);
    if page == 0 {
        return Ok(0xC000_009A);
    }
    let device = device_at(page);
    device.type_.set(IO_TYPE_DEVICE);
    device.size.set(DeviceObject::SIZE as u16);
    device.reference_count.set(1);
    device.driver_object.set(driver);
    device.device_type.set(device_type);
    device.characteristics.set(characteristics);
    device.stack_size.set(1);
    device.device_extension.set(if extension_size != 0 { page + DeviceObject::SIZE } else { 0 });
    let extension_address = page + DeviceObject::SIZE + extension_bytes;
    // SAFETY: a DEVOBJ_EXTENSION ocupa o fim do bloco recém-alocado.
    let object_extension = unsafe { DevobjExtension::at(extension_address) };
    object_extension.type_.set(IO_TYPE_DEVICE_OBJECT_EXTENSION);
    object_extension.size.set(DevobjExtension::SIZE as u16);
    object_extension.device_object.set(page);
    device.device_object_extension.set(extension_address);
    device.sector_size.set(default_sector_size(device_type));
    // Dispositivos montáveis (disco, CD-ROM, fita, disco virtual) nascem com
    // VPB e com o DeviceLock (evento de sincronização sinalizado) que o
    // IopMountVolume e o IoVerifyVolume esperam, como no IoCreateDevice.
    if device_type <= 0x24 && (MOUNTABLE_DEVICE_TYPES >> device_type) & 1 != 0 {
        let status = super::file_system::create_vpb(device)?;
        if status != 0 {
            guest::free_bytes(page);
            return Ok(status);
        }
        crate::ntos::ke::dispatcher::initialize_event(device.device_lock.address(), 1, true);
    }
    super::controller::start_io::queue_initialize(page);
    device_objects::register(page, Some(destroy_device), Some(unlink_device))?;
    device_objects::with_lock(|| {
        let head = &driver_at(driver).device_object;
        device.next_device.set(head.get());
        head.set(page);
        Ok(())
    })?;
    // O dispositivo pertence ao DRIVER_OBJECT do argumento (cargas aninhadas
    // de drivers); nomes com subdiretório criam os diretórios intermediários.
    let driver_node = lifecycle::node_by_driver_object(driver).or_else(|| lifecycle::current_driver().and_then(lifecycle::node_by_driver_object));
    if let Some(driver_node) = driver_node {
        let parts: Vec<&str> = short_name.split('\\').collect();
        let created = if let Some(rest) = short_name.strip_prefix('\\') {
            // Caminho absoluto fora de \Device (os reconhecedores em
            // \FileSystem): o diretório pai precisa existir, como no
            // ObInsertObject do IoCreateDevice.
            let (directory, leaf) = match rest.rfind('\\') {
                Some(split) => (format!("\\{}", &rest[..split]), &rest[split + 1..]),
                None => (String::from("\\"), rest),
            };
            if leaf.is_empty() {
                Err(KernelError::with_status("device name without a leaf", STATUS_OBJECT_NAME_INVALID))
            } else if object_manager::lookup(&directory).is_none() {
                Err(KernelError::with_status("device directory absent", STATUS_OBJECT_PATH_NOT_FOUND))
            } else {
                object_manager::create_object(&directory, leaf, "Device", Some(object_manager::ObjectData::pointer(page)))
            }
        } else if parts.len() == 1 {
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
    // SAFETY: PDEVICE_OBJECT* do chamador de modo kernel.
    unsafe { Field::<u64>::at(output) }.set(page);
    Ok(0)
}

/// Retira o dispositivo da coleção do driver e da lista nativa.
fn unlink_device(device: u64) {
    let driver = device_at(device).driver_object.get();
    if let Some(driver_node) = lifecycle::node_by_driver_object(driver) {
        for node in io_manager::driver_devices(driver_node) {
            if io_manager::device(node).is_some_and(|entry| entry.native_device == device) {
                io_manager::detach_device_from_driver(driver_node, node);
            }
        }
    }
    let _ = device_objects::with_lock(|| {
        // DriverObject->DeviceObject e depois cada DeviceObject->NextDevice.
        let mut link: &Field<u64> = &driver_at(driver).device_object;
        loop {
            let current = link.get();
            if current == 0 {
                break;
            }
            if current == device {
                link.set(device_at(device).next_device.get());
                break;
            }
            link = &device_at(current).next_device;
        }
        Ok(())
    });
}

/// Devolve o armazenamento depois que o dono autoriza a destruição.
fn destroy_device(device: u64) {
    if let Some(node) = find_device_node_by_pointer(device) {
        if let Some(path) = object_manager::path_of(node) {
            object_manager::unlink(&path);
        }
        io_manager::unregister_device(node);
    }
    PHYSICAL_BY_ATTACHED.lock().remove(&device);
    super::file_system::free_unreferenced_vpb(device_at(device));
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

/// IoAttachDeviceToDeviceStackSafe — o mesmo encadeamento; a ausência de
/// dispositivo vira STATUS_NO_SUCH_DEVICE.
pub fn attach_device_to_device_stack_safe(source: u64, target: u64, output: u64) -> Result<u32, KernelError> {
    Ok(if attach_device_to_device_stack(source, target, output)? != 0 { 0 } else { 0xC000_000E })
}

/// IoDetachDevice: desfaz o attach e publica as novas rotas de despacho.
pub fn detach_device(target: u64) -> Result<(), KernelError> {
    let detached = device_objects::detach(target)?;
    if detached != 0 {
        PHYSICAL_BY_ATTACHED.lock().remove(&detached);
    }
    refresh_stack_routes();
    Ok(())
}

/// PDO de hardware: segue a cadeia de attach até achar o primeiro que
/// satisfaz `found`.
pub fn walk_physical<T>(device: u64, found: impl Fn(u64) -> Option<T>) -> Option<T> {
    let mut candidate = device;
    let mut result = found(candidate);
    while result.is_none() {
        let Some(next) = PHYSICAL_BY_ATTACHED.lock().get(&candidate).copied() else { break };
        candidate = next;
        result = found(candidate);
    }
    result
}

/// IoGetDeviceObjectPointer(name, access, outFileObject, outDeviceObject):
/// topo da pilha e um FILE_OBJECT real retido.
pub fn get_device_object_pointer(name_pointer: u64, _access: u32, file_output: u64, device_output: u64) -> Result<u32, KernelError> {
    let name = guest_strings::read_unicode_string(name_pointer);
    let node = object_manager::lookup(&name).filter(|&node| object_manager::node(node).is_some_and(|node| node.type_name == "Device"));
    let Some(node) = node else { return Ok(0xC000_0034) };
    let entry = io_manager::device(node).unwrap_or_default();
    let device = if entry.stack_top != 0 { entry.stack_top } else { entry.native_device };
    let opened = io_manager::open_device(&name, false)?;
    if opened.status != 0 {
        return Ok(opened.status as u32);
    }
    file_objects::reference(opened.file_object)?;
    io_manager::close_device(opened.handle)?;
    // SAFETY: PFILE_OBJECT* e PDEVICE_OBJECT* do chamador de modo kernel.
    unsafe {
        Field::<u64>::at(file_output).set(opened.file_object);
        Field::<u64>::at(device_output).set(device);
    }
    Ok(0)
}

/// IoCreateSymbolicLink(SymbolicLinkName, DeviceName).
pub fn create_symbolic_link(link_pointer: u64, target_pointer: u64) -> Result<u32, KernelError> {
    match object_manager::create_symlink(&guest_strings::read_unicode_string(link_pointer), &guest_strings::read_unicode_string(target_pointer)) {
        Ok(_) => Ok(0),
        Err(error) => kernel_status(error),
    }
}

/// IoDeleteSymbolicLink: falha quando o link não existe.
pub fn delete_symbolic_link(link_pointer: u64) -> u32 {
    if object_manager::unlink(&guest_strings::read_unicode_string(link_pointer)) { 0 } else { 0xC000_0009 }
}
