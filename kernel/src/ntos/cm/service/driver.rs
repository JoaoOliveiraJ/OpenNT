//! Serviços de drivers — `system32/ntos/cm/driver-services.js`.
//!
//! Usa a mesma base de configuração dos serviços de usuário. RUNNING exige um
//! DRIVER_OBJECT inicializado: lançar a carga não equivale a concluir o
//! DriverEntry. Também atende ZwLoadDriver/ZwUnloadDriver pelo caminho
//! completo da chave do serviço.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::service::database::{self as service_database, Configuration, ServiceError, ServiceStatus};
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::driver_object;
use crate::ntos::io::lifecycle::{self, DriverOptions};
use crate::ntos::mm::pe_loader::LoadOptions;

/// Falha com o código Win32 preservado (e o NTSTATUS já produzido, se houver).
#[derive(Debug)]
pub struct DriverServiceError {
    pub win32: u32,
    pub ntstatus: Option<u32>,
    pub message: String,
}

impl From<ServiceError> for DriverServiceError {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::Win32(code, message) => Self { win32: code, ntstatus: None, message },
            ServiceError::Kernel(error) => Self { win32: 0, ntstatus: None, message: error.message },
        }
    }
}

fn fail<T>(code: u32, message: &str) -> Result<T, DriverServiceError> {
    Err(DriverServiceError { win32: code, ntstatus: None, message: String::from(message) })
}

/// Uma transição ou o erro da tentativa anterior por nome normalizado; o
/// estado do driver continua vindo do namespace.
#[derive(Clone, Copy)]
struct Operation {
    pending: u32,
    error: u32,
}

static OPERATIONS: SpinLock<BTreeMap<String, Operation>> = SpinLock::new(BTreeMap::new());

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    if text.len() >= prefix.len() && text.is_char_boundary(prefix.len()) && text[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&text[prefix.len()..])
    } else {
        None
    }
}

/// Normaliza o caminho instalado para o volume de boot; recusa unidades
/// indisponíveis, componentes vazios, travessia e caracteres não admitidos.
pub fn image_path(configuration: &Configuration) -> Result<String, DriverServiceError> {
    let mut path = configuration.image_path.as_str();
    if path.len() >= 2 && path.starts_with('"') && path.ends_with('"') {
        path = &path[1..path.len() - 1];
    }
    let mut path = path.replace('/', "\\");
    for prefix in ["\\??\\", "\\\\?\\"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            path = String::from(rest);
            break;
        }
    }
    if let Some(rest) = strip_prefix_ci(&path, "%SystemRoot%\\") {
        path = format!("\\SystemRoot\\{rest}");
    }
    // Drivers de System32\Drivers ficam na raiz do volume do convidado.
    let relative = if let Some(rest) = strip_prefix_ci(&path, "\\SystemRoot\\System32\\Drivers\\") {
        String::from(rest)
    } else if let Some(rest) = strip_prefix_ci(&path, "C:\\Windows\\System32\\Drivers\\") {
        String::from(rest)
    } else if let Some(rest) = strip_prefix_ci(&path, "C:\\") {
        String::from(rest)
    } else if (path.len() >= 2 && path.as_bytes()[0].is_ascii_alphabetic() && path.as_bytes()[1] == b':') || path.starts_with('\\') {
        return fail(3, "driver volume/path unavailable");
    } else {
        path
    };
    let components: Vec<&str> = relative.split('\\').collect();
    if components.iter().any(|component| component.is_empty() || *component == "." || *component == ".." || component.contains([':', '"', '\0'])) {
        return fail(123, "invalid driver path");
    }
    Ok(format!("/{}", components.join("/")))
}

/// Só um DRIVER_OBJECT cuja inicialização terminou.
fn initialized_driver(configuration: &Configuration) -> Option<u64> {
    lifecycle::initialized_driver(&configuration.name)
}

/// Transições pendentes ou o estado do objeto real; aceitar STOP depende do
/// DriverUnload; falhas anteriores ficam no registro da operação.
pub fn status(configuration: &Configuration, status: &mut ServiceStatus) {
    let operation = OPERATIONS.lock().get(&configuration.name.to_lowercase()).copied();
    if let Some(operation) = operation.filter(|operation| operation.pending != 0) {
        status.current_state = operation.pending;
        status.controls_accepted = 0;
        status.checkpoint = 0;
        status.wait_hint = 2000;
        status.process_id = 0;
        return;
    }
    let driver = initialized_driver(configuration);
    status.current_state = if driver.is_some() { 4 } else { 1 };
    status.process_id = 0;
    status.controls_accepted = driver.is_some_and(|driver| guest::read64(driver + driver_object::DRIVER_UNLOAD) != 0) as u32;
    status.win32_exit_code = if driver.is_some() { 0 } else { operation.map_or(0, |operation| operation.error) };
    status.service_specific_exit_code = 0;
    status.checkpoint = 0;
    status.wait_hint = 0;
}

fn current_status(configuration: &Configuration) -> ServiceStatus {
    let mut result = ServiceStatus { service_type: configuration.service_type, current_state: 1, ..Default::default() };
    status(configuration, &mut result);
    result
}

/// Serviço instalado do tipo kernel driver ou file-system driver.
fn require_driver_configuration(name: &str) -> Result<Configuration, DriverServiceError> {
    let Some(configuration) = service_database::read(name)? else { return fail(1060, "driver service absent") };
    if ![1, 2].contains(&configuration.service_type) {
        return fail(50, "service is not a kernel driver");
    }
    Ok(configuration)
}

/// Verifica estado, configuração e dependências recursivas; publica
/// START_PENDING, carrega o binário e só conclui com o objeto inicializado.
pub fn start(name: &str) -> Result<u32, DriverServiceError> {
    start_with_chain(name, &mut BTreeSet::new())
}

fn start_with_chain(name: &str, chain: &mut BTreeSet<String>) -> Result<u32, DriverServiceError> {
    let configuration = require_driver_configuration(name)?;
    let key = name.to_lowercase();
    if chain.contains(&key) {
        return fail(1059, "circular driver dependency");
    }
    if current_status(&configuration).current_state != 1 {
        return fail(1056, "driver already active");
    }
    if configuration.start == 4 {
        return fail(1058, "driver disabled");
    }
    let driver_path = image_path(&configuration)?;
    chain.insert(key.clone());
    let result = (|| -> Result<u32, DriverServiceError> {
        for dependency in &configuration.dependencies {
            if service_database::read(dependency)?.is_none() {
                return fail(1075, "driver dependency absent");
            }
            if service_database::status(dependency)?.current_state == 4 {
                continue;
            }
            if let Err(error) = start_with_chain(dependency, chain) {
                return fail(if error.win32 == 1075 { 1075 } else { 1068 }, "driver dependency failed");
            }
        }
        // Publica a transição antes de executar código do driver.
        OPERATIONS.lock().insert(key.clone(), Operation { pending: 2, error: 0 });
        let options = DriverOptions { service_name: Some(configuration.name.clone()), registry_path: Some(format!("{}\\{}", service_database::ROOT, configuration.name)), load: Some(LoadOptions { allow_preferred_va: true, ..Default::default() }) };
        lifecycle::load_driver(&driver_path, &options).map_err(|error| DriverServiceError { win32: error.win32_error, ntstatus: error.ntstatus, message: error.error.message })?;
        if initialized_driver(&configuration).is_none() {
            return fail(31, "driver initialization did not publish an initialized object");
        }
        OPERATIONS.lock().remove(&key);
        Ok(0)
    })();
    chain.remove(&key);
    result.map_err(|mut error| {
        if error.win32 == 0 {
            error.win32 = 31;
        }
        OPERATIONS.lock().insert(key, Operation { pending: 0, error: error.win32 });
        error
    })
}

/// Recusa parada em transição, sem DriverUnload ou com dependentes ativos;
/// só notifica a base de serviços depois da descarga efetiva.
pub fn stop(name: &str) -> Result<u32, DriverServiceError> {
    let configuration = require_driver_configuration(name)?;
    let key = name.to_lowercase();
    let current = current_status(&configuration);
    if current.current_state == 1 {
        return fail(1062, "driver not active");
    }
    if [2, 3].contains(&current.current_state) {
        return fail(1061, "driver transition pending");
    }
    if current.controls_accepted & 1 == 0 {
        return fail(1052, "driver has no unload routine");
    }
    for other in service_database::list() {
        let Some(dependency) = service_database::read(&other)? else { continue };
        if dependency.dependencies.iter().any(|name| name.to_lowercase() == key) && service_database::status(&other)?.current_state != 1 {
            return fail(1051, "active dependent service");
        }
    }
    OPERATIONS.lock().insert(key.clone(), Operation { pending: 3, error: 0 });
    let unloaded = lifecycle::unload_driver(&configuration.name);
    OPERATIONS.lock().remove(&key);
    if !unloaded {
        return fail(1052, "driver has live references");
    }
    service_database::driver_stopped(name);
    Ok(0)
}

/// Integra a consulta real de drivers à base de serviços.
pub fn init() {
    service_database::set_driver_status_provider(Some(status));
}

/// NtLoadDriver/NtUnloadDriver pelo caminho completo da chave; preserva um
/// NTSTATUS já produzido e converte as falhas Win32 conhecidas.
pub fn nt_request(driver_path: &str, unload: bool) -> u32 {
    let prefix = format!("{}\\", service_database::ROOT);
    let Some(service) = strip_prefix_ci(driver_path, &prefix) else { return 0xC000_003A };
    if service.is_empty() || service.contains(['\\', '/', '\0']) {
        return 0xC000_0033;
    }
    let result = if unload { stop(service) } else { start(service) };
    match result {
        Ok(status) => status,
        Err(error) => error.ntstatus.unwrap_or(match error.win32 {
            2 => 0xC000_0034,
            3 => 0xC000_003A,
            5 => 0xC000_0022,
            50 => 0xC000_000D,
            123 => 0xC000_0033,
            1051 => 0xC000_009E,
            1052 => 0xC000_036B,
            1056 => 0xC000_010E,
            1058 => 0xC000_036C,
            1060 => 0xC000_0034,
            1062 => 0xC000_0034,
            1068 => 0xC000_0365,
            1075 => 0xC000_0034,
            _ => 0xC000_0001,
        }),
    }
}
