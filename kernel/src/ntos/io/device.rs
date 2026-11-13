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
use crate::ntos::inc::nt_abi::{device_object, driver_object};

/// FDO → PDO registrado no attach (IoGetDeviceProperty acha o PDO de hardware).
static PHYSICAL_BY_ATTACHED: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());
static UNNAMED_DEVICES: SpinLock<u32> = SpinLock::new(0);

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
    let page = guest::alloc_bytes(device_object::STRUCT_SIZE + extension_size as u64);
    if page == 0 {
        return Ok(0xC000_009A);
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
    guest::write64(file_output, opened.file_object);
    guest::write64(device_output, device);
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
