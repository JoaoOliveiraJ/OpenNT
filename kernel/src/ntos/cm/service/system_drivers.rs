//! Drivers de boot/sistema e carga sob demanda.
//!
//! Usa a base comum de serviços (`service_database`/`driver_services`) e
//! encaminha o início de dispositivos ao I/O Manager.

use alloc::format;
use alloc::string::String;

use crate::ntos::cm::service::{driver as driver_services, database as service_database};
use crate::ntos::cm::registry;
use crate::drivers::bus::pci;
use crate::hal::amd64::native_call;
use crate::ntos::io::{io_manager, small::boot_drivers_state};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{driver_extension, driver_object};
use crate::ntos::io::lifecycle;

/// Raiz das chaves instaladas.
pub const SERVICES_PATH: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services";

/// Primeiros quatro bytes little-endian do valor; ausente ou curto = None.
fn read_service_integer_value(service: &str, value: &str) -> Option<i32> {
    let entry = registry::read_value_by_path(&format!("{SERVICES_PATH}\\{service}"), value)?;
    if entry.data.len() < 4 {
        return None;
    }
    Some(i32::from_le_bytes([entry.data[0], entry.data[1], entry.data[2], entry.data[3]]))
}

/// String legada de bytes (HardwareId) até o primeiro NUL.
fn read_service_byte_string(service: &str, value: &str) -> Option<String> {
    let entry = registry::read_value_by_path(&format!("{SERVICES_PATH}\\{service}"), value)?;
    Some(entry.data.iter().take_while(|&&byte| byte != 0).map(|&byte| byte as char).collect())
}

/// Compara o HardwareId configurado com os ids dos PDOs PCI, chama o
/// AddDevice quando presente e encaminha START_DEVICE depois do sucesso.
fn match_plug_and_play_device(service: &str, driver_node: NodeId) {
    let Some(hardware_id) = read_service_byte_string(service, "HardwareId") else { return };
    if hardware_id.is_empty() {
        return;
    }
    let matched = pci::devices().into_iter().find(|candidate| io_manager::query_device_id(&format!("\\Device\\{}", candidate.pdo_name), 0).ok().flatten().as_deref() == Some(hardware_id.as_str()));
    let Some(matched) = matched else {
        debug_print!("[pnp] {}: hardware {} ausente no barramento", service, hardware_id);
        return;
    };
    let Some(pdo_node) = object_manager::lookup(&format!("\\Device\\{}", matched.pdo_name)) else { return };
    let driver = object_manager::node(driver_node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
    let extension = guest::read64(driver + driver_object::DRIVER_EXTENSION);
    let add_device = guest::read64(extension + driver_extension::ADD_DEVICE);
    if add_device == 0 {
        return;
    }
    debug_print!("[pnp] {} -> AddDevice({}, {})", service, matched.pdo_name, hardware_id);
    // O driver corrente fica publicado durante o AddDevice.
    lifecycle::set_current_driver(Some(driver));
    let pdo = io_manager::device(pdo_node).map_or(0, |entry| entry.native_device);
    let status = native_call::call(add_device, &[driver, pdo]) as i32;
    lifecycle::end_driver();
    if status == 0 {
        let _ = io_manager::pnp_start_device(pdo_node);
    } else {
        debug_print!("[pnp] AddDevice de {} falhou: {}", service, status);
    }
}

/// Percorre os serviços na ordem da hive e carrega os que têm Start até 1;
/// falhas são informadas individualmente. Conta só os drivers carregados.
pub fn start_boot_drivers() -> usize {
    let mut loaded = 0;
    for service in registry::list_keys(SERVICES_PATH) {
        let start = read_service_integer_value(&service, "Start");
        let image_path = service_database::read(&service).ok().flatten().map(|configuration| configuration.image_path).unwrap_or_default();
        if start.is_none_or(|start| start > 1) || image_path.is_empty() {
            continue;
        }
        debug_print!("[services] {} -> {}", service, image_path);
        match driver_services::start(&service) {
            Ok(_) => {
                loaded += 1;
                if let Some(driver_node) = object_manager::lookup(&format!("\\Driver\\{service}")) {
                    // Inicia os dispositivos já criados e tenta associar o
                    // driver ao dispositivo do HardwareId.
                    for device in io_manager::driver_devices(driver_node) {
                        let _ = io_manager::pnp_start_device(device);
                    }
                    match_plug_and_play_device(&service, driver_node);
                }
            }
            Err(error) => debug_print!("[services] FALHOU {}: {}", service, error.message),
        }
    }
    boot_drivers_state::complete();
    loaded
}

/// Carga sob demanda idempotente: reutiliza RUNNING ou tenta iniciar; diz
/// se o objeto entrou de fato nesse estado.
pub fn load_service_driver(service: &str) -> bool {
    let running = |service: &str| service_database::status(service).is_ok_and(|status| status.current_state == 4);
    if service_database::read(service).ok().flatten().is_some() && running(service) {
        return true;
    }
    if let Err(error) = driver_services::start(service) {
        debug_print!("[services] FALHOU {}: {}", service, error.message);
        return false;
    }
    running(service)
}
