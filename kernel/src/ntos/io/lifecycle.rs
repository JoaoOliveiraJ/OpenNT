//! Ciclo de vida dos drivers `.sys` — `system32/win32/ntoskrnl/lifecycle.js`.
//!
//! DRIVER_OBJECT real do NT (Type, Size, DriverStart/Size, DriverName,
//! DriverInit, MajorFunction zerado, DriverUnload lido do offset real) e a
//! DRIVER_EXTENSION para o AddDevice do PnP. O dispositivo é ligado ao
//! DRIVER_OBJECT passado ao IoCreateDevice (não a um estado ambiente), o que
//! suporta carga aninhada de drivers.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::io::io_manager;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::{device as device_objects, driver as driver_objects};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::mm::sysload::kernel_image_source;
use crate::ntos::inc::nt_abi::{device_object, driver_extension, driver_object};
use crate::ntos::mm::pe_loader::{self, LoadOptions, PeImage};

/// Estado de um driver nativo (o `node.data` do original).
struct NativeDriver {
    name: String,
    node: NodeId,
    name_buffer: u64,
    initialized: bool,
    exports: BTreeMap<String, u64>,
    image: Option<PeImage>,
    registry_allocation: Vec<u64>,
    import_references: u32,
    kernel_library_pinned: bool,
}

static DRIVERS: SpinLock<BTreeMap<u64, NativeDriver>> = SpinLock::new(BTreeMap::new());
/// Driver em inicialização (entre begin_driver e end_driver) ou em AddDevice.
static CURRENT: SpinLock<Option<u64>> = SpinLock::new(None);
/// IoRegisterDriverReinitialization: rodam depois dos drivers de boot.
static REINITIALIZATION: SpinLock<Vec<(u64, u64)>> = SpinLock::new(Vec::new());

/// Erro de carga com o código Win32 do original (1056 já carregado, 2 não
/// encontrado, 31 DriverEntry falhou).
#[derive(Debug)]
pub struct LoadError {
    pub error: KernelError,
    pub win32_error: u32,
    pub ntstatus: Option<u32>,
}

impl From<KernelError> for LoadError {
    fn from(error: KernelError) -> Self {
        Self { error, win32_error: 0, ntstatus: None }
    }
}

/// Opções de carga (as do loader mais o nome de serviço e o caminho de
/// registro passados ao DriverEntry).
#[derive(Clone, Default)]
pub struct DriverOptions {
    pub service_name: Option<String>,
    pub registry_path: Option<String>,
    pub load: Option<LoadOptions>,
}

/// DRIVER_OBJECT do driver em contexto ativo.
pub fn current_driver() -> Option<u64> {
    *CURRENT.lock()
}

/// Contexto ativo fora do DriverEntry (o PnP chama AddDevice).
pub fn set_current_driver(driver: Option<u64>) {
    *CURRENT.lock() = driver;
}

/// Nó do namespace de um DRIVER_OBJECT nativo.
pub fn node_by_driver_object(driver: u64) -> Option<NodeId> {
    DRIVERS.lock().get(&driver).map(|entry| entry.node)
}

pub fn register_reinitialization(routine: u64, context: u64) {
    REINITIALIZATION.lock().push((routine, context));
}

/// Chamado pelo Service Control ao fim da carga dos drivers de boot.
pub fn run_reinitialization_routines() {
    loop {
        let entry = {
            let mut routines = REINITIALIZATION.lock();
            if routines.is_empty() {
                return;
            }
            routines.remove(0)
        };
        native_call::call(entry.0, &[0, entry.1]);
    }
}

/// Liberação final, quando o provedor remove a última referência do objeto.
fn destroy_driver(driver: u64) {
    let entry = DRIVERS.lock().remove(&driver);
    let Some(mut entry) = entry else { return };
    if let Some(image) = entry.image.as_mut() {
        if let Err(error) = image.release() {
            debug_print!("[lifecycle] liberacao da imagem de {}: {}", entry.name, error);
        }
    }
    guest::free_bytes(entry.name_buffer);
    guest::free_bytes(driver);
}

/// Cria o DRIVER_OBJECT, sua extensão e o nome UTF-16 e os publica.
pub fn begin_driver(name: &str, image_base: u64, image_size: u64, entry_point: u64) -> Result<u64, KernelError> {
    let driver = guest::alloc_bytes(driver_object::STRUCT_SIZE + 0x400);
    let name_units: Vec<u16> = name.encode_utf16().collect();
    let name_buffer = guest::alloc_bytes(name_units.len() as u64 * 2 + 2);
    // A extensão ocupa a região adicional da mesma alocação.
    let extension = driver + driver_object::STRUCT_SIZE;
    guest_strings::write_wide_string(name_buffer, name);
    guest::write16(driver + driver_object::TYPE, driver_object::IO_TYPE);
    guest::write16(driver + driver_object::SIZE, driver_object::STRUCT_SIZE as u16);
    guest::write32(driver + driver_object::DEVICE_OBJECT, 0);
    // DriverStart é PVOID: a VA inteira da imagem.
    guest::write64(driver + driver_object::DRIVER_START, image_base);
    guest::write32(driver + driver_object::DRIVER_SIZE, image_size as u32);
    guest::write16(driver + driver_object::DRIVER_NAME, name_units.len() as u16 * 2);
    guest::write16(driver + driver_object::DRIVER_NAME + 2, name_units.len() as u16 * 2 + 2);
    guest::write64(driver + driver_object::DRIVER_NAME + 8, name_buffer);
    guest::write64(driver + driver_object::DRIVER_INIT, entry_point);
    guest::write64(driver + driver_object::DRIVER_UNLOAD, 0);
    // DRIVER_EXTENSION real: o driver registra AddDevice aqui.
    guest::write64(driver + driver_object::DRIVER_EXTENSION, extension);
    guest::write64(extension + driver_extension::DRIVER_OBJECT, driver);
    guest::write64(extension + driver_extension::ADD_DEVICE, 0);
    let node = match io_manager::create_native_driver(name, driver) {
        Ok(node) => node,
        Err(error) => {
            guest::free_bytes(name_buffer);
            guest::free_bytes(driver);
            return Err(error);
        }
    };
    DRIVERS.lock().insert(driver, NativeDriver { name: name.to_string(), node, name_buffer, initialized: false, exports: BTreeMap::new(), image: None, registry_allocation: Vec::new(), import_references: 0, kernel_library_pinned: false });
    *CURRENT.lock() = Some(driver);
    // A imagem e as alocações só são liberadas quando o provedor remove a
    // última referência, inclusive depois de um unload já concluído.
    if let Err(error) = driver_objects::register(node, destroy_driver) {
        object_manager::unlink(&format!("\\Driver\\{name}"));
        io_manager::forget_driver(node);
        DRIVERS.lock().remove(&driver);
        guest::free_bytes(name_buffer);
        guest::free_bytes(driver);
        return Err(error);
    }
    Ok(driver)
}

/// Encerra o contexto ambiente.
pub fn end_driver() {
    *CURRENT.lock() = None;
}

/// Endereço absoluto de um export do driver (diretório de exports real).
pub fn get_driver_export(driver_name: &str, export_name: &str) -> u64 {
    let Some(node) = object_manager::lookup(&format!("\\Driver\\{driver_name}")) else { return 0 };
    DRIVERS.lock().values().find(|entry| entry.node == node).and_then(|entry| entry.exports.get(export_name).copied()).unwrap_or(0)
}

fn service_name(file_path: &str, options: &DriverOptions) -> String {
    options.service_name.clone().unwrap_or_else(|| {
        let file = file_path.rsplit('/').next().unwrap_or(file_path);
        let lower = file.to_lowercase();
        if lower.ends_with(".sys") {
            file[..file.len() - 4].to_string()
        } else {
            file.to_string()
        }
    })
}

/// Carrega um `.sys`: loader PE e DriverEntry nativo com o caminho de
/// registro do serviço. Fonte: disco em memória (bundle) ou volume NTFS.
pub fn load_driver(file_path: &str, options: &DriverOptions) -> Result<bool, LoadError> {
    let previous = *CURRENT.lock();
    let name = service_name(file_path, options);
    if object_manager::lookup(&format!("\\Driver\\{name}")).is_some() {
        return Err(LoadError { error: KernelError::new(format!("driver already loaded: {name}")), win32_error: 1056, ntstatus: None });
    }
    let result = load_driver_inner(file_path, &name, options);
    if let Err(error) = &result {
        let pending = DRIVERS.lock().iter().find(|(_, entry)| entry.name == name && !entry.initialized).map(|(&driver, _)| driver);
        if let Some(driver) = pending {
            dispose_driver(driver);
        }
        debug_print!("[lifecycle] {} falhou: {}", file_path, error.error);
    }
    *CURRENT.lock() = previous;
    result
}

fn load_driver_inner(file_path: &str, name: &str, options: &DriverOptions) -> Result<bool, LoadError> {
    let Some((source, from_ntfs)) = kernel_image_source::source_for_path(file_path)? else {
        return Err(LoadError { error: KernelError::new(format!("driver nao encontrado: {file_path}")), win32_error: 2, ntstatus: None });
    };
    // Drivers de serviço do NTFS carregam na base preferida, como o NT.
    let mut load = options.load.clone().unwrap_or(LoadOptions { allow_preferred_va: from_ntfs, ..Default::default() });
    load.image_name = Some(source.name().to_string());
    let image = pe_loader::load_from_source(source, &load)?;
    let (image_base, size_of_image, entry_point) = (image.image_base, image.size_of_image, image.entry_point);
    let exports = image.exports.exports.clone();
    let driver = match begin_driver(name, image_base, size_of_image, entry_point) {
        Ok(driver) => driver,
        Err(error) => {
            let mut image = image;
            let _ = image.release();
            return Err(error.into());
        }
    };
    {
        let mut drivers = DRIVERS.lock();
        let entry = drivers.get_mut(&driver).unwrap();
        entry.image = Some(image);
        entry.exports = exports;
    }
    // UNICODE_STRING com o caminho do serviço.
    let registry_path = options.registry_path.clone().unwrap_or_else(|| format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{name}"));
    let units = registry_path.encode_utf16().count() as u64;
    let path_buffer = guest::alloc_bytes(units * 2 + 2);
    guest_strings::write_wide_string(path_buffer, &registry_path);
    let descriptor = guest::alloc_bytes(16);
    guest::write16(descriptor, (units * 2) as u16);
    guest::write16(descriptor + 2, (units * 2 + 2) as u16);
    guest::write64(descriptor + 8, path_buffer);
    if let Some(entry) = DRIVERS.lock().get_mut(&driver) {
        entry.registry_allocation = alloc::vec![descriptor, path_buffer];
    }
    let status = native_call::call(entry_point, &[driver, descriptor]) as u32;
    end_driver();
    let allocations = DRIVERS.lock().get_mut(&driver).map(|entry| core::mem::take(&mut entry.registry_allocation)).unwrap_or_default();
    for pointer in allocations {
        guest::free_bytes(pointer);
    }
    if status >= 0x8000_0000 {
        return Err(LoadError { error: KernelError::with_status(format!("DriverEntry de {name} retornou {status:#x}"), status), win32_error: 31, ntstatus: Some(status) });
    }
    if let Some(entry) = DRIVERS.lock().get_mut(&driver) {
        entry.initialized = true;
    }
    Ok(true)
}

/// Retira dispositivos e nome, libera o caminho temporário do registro e
/// entrega o DRIVER_OBJECT ao provedor que controla as referências.
fn dispose_driver(driver: u64) {
    let (name, node, allocations) = {
        let mut drivers = DRIVERS.lock();
        let Some(entry) = drivers.get_mut(&driver) else { return };
        (entry.name.clone(), entry.node, core::mem::take(&mut entry.registry_allocation))
    };
    for device in io_manager::driver_devices(node) {
        if let Some(native) = io_manager::device(device).map(|entry| entry.native_device).filter(|&native| native != 0) {
            match device_objects::retire(native) {
                Ok(true) => {}
                Ok(false) => debug_print!("[lifecycle] unregistered device deletion"),
                Err(error) => debug_print!("[lifecycle] remocao de dispositivo: {}", error),
            }
        }
    }
    object_manager::unlink(&format!("\\Driver\\{name}"));
    io_manager::forget_driver(node);
    for pointer in allocations {
        guest::free_bytes(pointer);
    }
    if let Err(error) = driver_objects::retire(driver) {
        debug_print!("[lifecycle] retirada do driver {}: {}", name, error);
    }
}

/// Recusa o unload com consumidores da imagem ou referências de
/// dispositivos; senão envia REMOVE_DEVICE, chama DriverUnload e retira o
/// driver de serviço.
pub fn unload_driver(driver_name: &str) -> bool {
    let Some(node) = object_manager::lookup(&format!("\\Driver\\{driver_name}")) else { return false };
    let found = DRIVERS.lock().iter().find(|(_, entry)| entry.node == node).map(|(&driver, entry)| (driver, entry.import_references, entry.kernel_library_pinned));
    let Some((driver, import_references, pinned)) = found else { return false };
    if import_references != 0 || pinned {
        return false;
    }
    let devices = io_manager::driver_devices(node);
    for &device in &devices {
        let native = io_manager::device(device).map_or(0, |entry| entry.native_device);
        if native == 0 {
            continue;
        }
        // ReferenceCount conta usos por arquivos; as referências do gerenciador
        // de objetos são contabilizadas pelo provedor.
        let file_references = guest::read32(native + device_object::REFERENCE_COUNT) as i32;
        let object_references = device_objects::reference_count(native).unwrap_or(0);
        if file_references > 1 || object_references > 1 || guest::read64(native + device_object::ATTACHED_DEVICE) != 0 {
            let device_name = object_manager::node(device).map(|node| node.name).unwrap_or_default();
            debug_print!("[ntoskrnl] unload de {} RECUSADO: \\Device\\{} tem referencias de arquivo/objeto vivas", driver_name, device_name);
            return false;
        }
    }
    let unload_routine = guest::read64(driver + driver_object::DRIVER_UNLOAD);
    // PnP primeiro: REMOVE_DEVICE para cada dispositivo, como o NT.
    for device in devices {
        if let Err(error) = io_manager::pnp_remove_device(device) {
            debug_print!("[lifecycle] REMOVE_DEVICE: {}", error);
        }
    }
    if unload_routine != 0 {
        native_call::call(unload_routine, &[driver, 0]);
    }
    dispose_driver(driver);
    true
}

/// AddDevice registrado em DriverExtension->AddDevice (o caminho real do
/// PnP manager para instanciar um FDO sobre um PDO).
pub fn call_add_device(driver_name: &str, physical_device: u64) -> u64 {
    let Some(node) = object_manager::lookup(&format!("\\Driver\\{driver_name}")) else { return 0xFFFF_FFFF_C000_0034 };
    let Some(driver) = DRIVERS.lock().iter().find(|(_, entry)| entry.node == node).map(|(&driver, _)| driver) else { return 0xFFFF_FFFF_C000_0034 };
    let extension = guest::read64(driver + driver_object::DRIVER_EXTENSION);
    let routine = guest::read64(extension + driver_extension::ADD_DEVICE);
    if routine == 0 {
        return 0xFFFF_FFFF_C000_0034;
    }
    set_current_driver(Some(driver));
    let status = native_call::call(routine, &[driver, physical_device]);
    end_driver();
    status as i32 as i64 as u64
}

/// DRIVER_OBJECT de `\Driver\<nome>` cuja inicialização terminou.
/// Exports do driver carregado (diretório de exports real), para os
/// importadores do `kernel-libraries`.
pub fn driver_exports(driver_name: &str) -> Option<BTreeMap<String, u64>> {
    DRIVERS.lock().values().find(|entry| entry.name.eq_ignore_ascii_case(driver_name)).map(|entry| entry.exports.clone())
}

pub fn initialized_driver(driver_name: &str) -> Option<u64> {
    let node = object_manager::lookup(&format!("\\Driver\\{driver_name}"))?;
    DRIVERS.lock().iter().find(|(_, entry)| entry.node == node && entry.initialized).map(|(&driver, _)| driver)
}

/// Referências de módulos que importam do driver (impedem o unload).
pub fn add_import_reference(driver: u64, delta: i32) {
    if let Some(entry) = DRIVERS.lock().get_mut(&driver) {
        entry.import_references = (entry.import_references as i64 + delta as i64).max(0) as u32;
    }
}

/// Biblioteca de kernel fixada (não descarrega).
pub fn pin_kernel_library(driver: u64) {
    if let Some(entry) = DRIVERS.lock().get_mut(&driver) {
        entry.kernel_library_pinned = true;
    }
}
