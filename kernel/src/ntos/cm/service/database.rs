//! Banco de serviços.
//!
//! Configuração dos serviços na hive e ciclo dos processos de serviço. Um
//! processo lançado fica START_PENDING até relatar SERVICE_RUNNING pelo
//! transporte autenticado; ter configuração não significa estar executando.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::cm::registry::{self, Value};
use crate::rtl::{KernelError, SpinLock};

pub const ROOT: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services";
pub const STOPPED: u32 = 1;
pub const START_PENDING: u32 = 2;
pub const RUNNING: u32 = 4;

/// Falha com o código Win32 do gerenciador, ou erro do kernel.
#[derive(Debug)]
pub enum ServiceError {
    Win32(u32, String),
    Kernel(KernelError),
}

impl ServiceError {
    pub fn win32(&self) -> Option<u32> {
        match self {
            ServiceError::Win32(code, _) => Some(*code),
            ServiceError::Kernel(_) => None,
        }
    }
}

impl From<KernelError> for ServiceError {
    fn from(error: KernelError) -> Self {
        ServiceError::Kernel(error)
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;

fn fail<T>(code: u32, text: &str) -> ServiceResult<T> {
    Err(ServiceError::Win32(code, String::from("SCM: ") + text))
}

/// Configuração validada de um serviço.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub name: String,
    pub display_name: String,
    pub image_path: String,
    pub service_type: u32,
    pub start: u32,
    pub error_control: u32,
    pub object_name: String,
    pub dependencies: Vec<String>,
}

/// Configuração parcial: instalação (com padrões) ou alterações.
#[derive(Clone, Debug, Default)]
pub struct ConfigurationInput {
    pub name: String,
    pub display_name: Option<String>,
    pub image_path: Option<String>,
    pub service_type: Option<u32>,
    pub start: Option<u32>,
    pub error_control: Option<u32>,
    pub object_name: Option<String>,
    pub dependencies: Option<Vec<String>>,
}

/// SERVICE_STATUS com o processo anexado.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceStatus {
    pub service_type: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub checkpoint: u32,
    pub wait_hint: u32,
    pub process_id: u64,
    pub process_exit_code: Option<u32>,
}

/// Campos relatados pelo processo do serviço.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReportedStatus {
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub checkpoint: u32,
    pub wait_hint: u32,
}

/// Linha de comando separada em executável e argumentos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandLine {
    pub path: String,
    pub arguments: String,
}

pub type StoppedListener = Arc<dyn Fn(&str) + Send + Sync>;
pub type StatusListener = Arc<dyn Fn(&str, u64, &ServiceStatus) + Send + Sync>;
/// Ciclo dos objetos de driver reais aplicado ao status de um driver.
pub type DriverStatusProvider = fn(&Configuration, &mut ServiceStatus);

struct Database {
    states: BTreeMap<String, ServiceStatus>,
    stopped: Vec<StoppedListener>,
    status: Vec<StatusListener>,
    driver_status: Option<DriverStatusProvider>,
}

static DATABASE: SpinLock<Database> = SpinLock::new(Database { states: BTreeMap::new(), stopped: Vec::new(), status: Vec::new(), driver_status: None });

/// Nome de 1 a 256 caracteres sem barras nem NUL, como caminho em Services.
fn service_key_path(name: &str) -> ServiceResult<String> {
    if name.is_empty() || name.encode_utf16().count() > 256 || name.contains(['\\', '/', '\0']) {
        return fail(123, "invalid service name");
    }
    Ok(alloc::format!("{ROOT}\\{name}"))
}

/// UTF-16 com terminador; REG_MULTI_SZ recebe o terminador extra.
fn encode_wide_string(text: &str, multi: bool) -> Vec<u8> {
    let mut bytes = registry::encode_wide(text);
    if multi && !text.ends_with('\0') {
        bytes.extend_from_slice(&[0, 0]);
    }
    bytes
}

/// REG_SZ/EXPAND_SZ/MULTI_SZ com bytes pares; retira só os NUL finais.
fn decode_string_value(value: Option<&Value>) -> ServiceResult<String> {
    let Some(value) = value.filter(|value| [1, 2, 7].contains(&value.value_type) && value.data.len() % 2 == 0) else { return fail(13, "invalid string value") };
    let units: Vec<u16> = value.data.chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    Ok(String::from_utf16_lossy(&units).trim_end_matches('\0').to_string())
}

fn decode_integer_value(value: Option<&Value>) -> ServiceResult<u32> {
    let Some(value) = value.filter(|value| value.value_type == 4 && value.data.len() == 4) else { return fail(13, "invalid DWORD value") };
    Ok(u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
}

/// Tipo, início, controle de erro, caminho, nome e dependências; só a conta
/// LocalSystem é admitida.
fn validate(configuration: Configuration) -> ServiceResult<Configuration> {
    service_key_path(&configuration.name)?;
    if ![1, 2, 16, 32].contains(&configuration.service_type) || configuration.start > 4 || configuration.error_control > 3 || (configuration.service_type >= 16 && configuration.start < 2) {
        return fail(87, "invalid service configuration");
    }
    if configuration.image_path.is_empty() || configuration.image_path.contains('\0') || configuration.display_name.encode_utf16().count() > 256 || configuration.display_name.contains('\0') {
        return fail(87, "invalid image path/display name");
    }
    // Sem autenticação fictícia para contas de serviço não implementadas.
    if configuration.object_name != "LocalSystem" {
        return fail(50, "service account logon is not implemented");
    }
    for dependency in &configuration.dependencies {
        service_key_path(dependency)?;
        if dependency.to_lowercase() == configuration.name.to_lowercase() {
            return fail(1059, "circular dependency");
        }
    }
    let mut lowered: Vec<String> = configuration.dependencies.iter().map(|dependency| dependency.to_lowercase()).collect();
    lowered.sort();
    lowered.dedup();
    if lowered.len() != configuration.dependencies.len() {
        return fail(87, "duplicate dependency");
    }
    Ok(configuration)
}

/// Decodifica e valida a configuração da hive; `None` se a chave não existe.
pub fn read(name: &str) -> ServiceResult<Option<Configuration>> {
    let handle = registry::open(&service_key_path(name)?)?;
    if handle == 0 {
        return Ok(None);
    }
    let value = |value_name: &str| registry::get_value(handle, value_name);
    let result = (|| {
        let display = value("DisplayName");
        let object = value("ObjectName");
        let dependencies = value("DependOnService");
        let dependency_text = match &dependencies {
            Some(_) => decode_string_value(dependencies.as_ref())?,
            None => String::new(),
        };
        validate(Configuration {
            name: name.to_string(),
            display_name: if display.is_some() { decode_string_value(display.as_ref())? } else { name.to_string() },
            image_path: decode_string_value(value("ImagePath").as_ref())?,
            service_type: decode_integer_value(value("Type").as_ref())?,
            start: decode_integer_value(value("Start").as_ref())?,
            error_control: decode_integer_value(value("ErrorControl").as_ref())?,
            object_name: if object.is_some() { decode_string_value(object.as_ref())? } else { String::from("LocalSystem") },
            dependencies: if dependency_text.is_empty() { Vec::new() } else { dependency_text.split('\0').map(String::from).collect() },
        })
    })();
    registry::close_handle(handle);
    result.map(Some)
}

/// Completa os padrões do gerenciador e valida antes de armazenar.
fn normalize(input: &ConfigurationInput) -> ServiceResult<Configuration> {
    validate(Configuration {
        name: input.name.clone(),
        display_name: input.display_name.clone().filter(|name| !name.is_empty()).unwrap_or_else(|| input.name.clone()),
        image_path: input.image_path.clone().unwrap_or_default(),
        service_type: input.service_type.unwrap_or(16),
        start: input.start.unwrap_or(3),
        error_control: input.error_control.unwrap_or(1),
        object_name: input.object_name.clone().filter(|name| !name.is_empty()).unwrap_or_else(|| String::from("LocalSystem")),
        dependencies: input.dependencies.clone().unwrap_or_default(),
    })
}

/// REG_DWORD, REG_EXPAND_SZ, REG_SZ e REG_MULTI_SZ.
fn write_configuration(configuration: &Configuration) -> ServiceResult<()> {
    let handle = registry::open_or_create(&service_key_path(&configuration.name)?, None)?;
    for (name, value) in [("Type", configuration.service_type), ("Start", configuration.start), ("ErrorControl", configuration.error_control)] {
        registry::set_value(handle, name, 4, value.to_le_bytes().to_vec());
    }
    registry::set_value(handle, "ImagePath", 2, encode_wide_string(&configuration.image_path, false));
    registry::set_value(handle, "DisplayName", 1, encode_wide_string(&configuration.display_name, false));
    registry::set_value(handle, "ObjectName", 1, encode_wide_string(&configuration.object_name, false));
    registry::set_value(handle, "DependOnService", 7, encode_wide_string(&configuration.dependencies.join("\0"), true));
    registry::close_handle(handle);
    Ok(())
}

/// Dependência ausente na instalação é admitida; ciclo entre configurações
/// presentes é recusado. A configuração nova participa antes de existir.
fn check_dependency_cycles(configuration: &Configuration) -> ServiceResult<()> {
    fn visit(name: &str, configuration: &Configuration, active: &mut Vec<String>, visited: &mut Vec<String>) -> ServiceResult<()> {
        let key = name.to_lowercase();
        if active.contains(&key) {
            return fail(1059, "circular dependency");
        }
        if visited.contains(&key) {
            return Ok(());
        }
        let dependency = if key == configuration.name.to_lowercase() { Some(configuration.clone()) } else { read(name)? };
        let Some(dependency) = dependency else { return Ok(()) };
        active.push(key.clone());
        for next in &dependency.dependencies {
            visit(next, configuration, active, visited)?;
        }
        active.retain(|candidate| *candidate != key);
        visited.push(key);
        Ok(())
    }
    visit(&configuration.name, configuration, &mut Vec::new(), &mut Vec::new())
}

/// Instala; duplicação é recusada, salvo quando o chamador pede para
/// preservar a existente.
pub fn install(input: &ConfigurationInput, preserve_existing: bool) -> ServiceResult<Configuration> {
    let configuration = normalize(input)?;
    if let Some(existing) = read(&configuration.name)? {
        if preserve_existing {
            return Ok(existing);
        }
        return fail(1073, "service already exists");
    }
    check_dependency_cycles(&configuration)?;
    write_configuration(&configuration)?;
    read(&configuration.name)?.ok_or_else(|| ServiceError::Win32(1060, String::from("SCM: service does not exist")))
}

/// Mescla alterações numa configuração existente.
pub fn configure(name: &str, changes: &ConfigurationInput) -> ServiceResult<Configuration> {
    let Some(existing) = read(name)? else { return fail(1060, "service does not exist") };
    let merged = ConfigurationInput {
        name: name.to_string(),
        display_name: Some(changes.display_name.clone().unwrap_or(existing.display_name)),
        image_path: Some(changes.image_path.clone().unwrap_or(existing.image_path)),
        service_type: Some(changes.service_type.unwrap_or(existing.service_type)),
        start: Some(changes.start.unwrap_or(existing.start)),
        error_control: Some(changes.error_control.unwrap_or(existing.error_control)),
        object_name: Some(changes.object_name.clone().unwrap_or(existing.object_name)),
        dependencies: Some(changes.dependencies.clone().unwrap_or(existing.dependencies)),
    };
    let configuration = normalize(&merged)?;
    check_dependency_cycles(&configuration)?;
    write_configuration(&configuration)?;
    read(name)?.ok_or_else(|| ServiceError::Win32(1060, String::from("SCM: service does not exist")))
}

/// Estado parado por padrão, o estado do processo e, para drivers, o ciclo
/// do objeto nativo.
pub fn status(name: &str) -> ServiceResult<ServiceStatus> {
    let Some(configuration) = read(name)? else { return fail(1060, "service does not exist") };
    let (state, provider) = {
        let database = DATABASE.lock();
        (database.states.get(&name.to_lowercase()).copied(), database.driver_status)
    };
    let mut status = state.unwrap_or(ServiceStatus { service_type: configuration.service_type, current_state: STOPPED, ..Default::default() });
    if configuration.service_type < 16 {
        if let Some(provider) = provider {
            provider(&configuration, &mut status);
        }
    }
    Ok(status)
}

/// Exige o serviço parado e exclui a chave só sem subchaves.
pub fn remove(name: &str) -> ServiceResult<()> {
    if status(name)?.current_state != STOPPED {
        return fail(1061, "service process is active");
    }
    let handle = registry::open(&service_key_path(name)?)?;
    let deleted = registry::delete_key(handle);
    registry::close_handle(handle);
    if !deleted {
        return fail(5, "service has child configuration keys");
    }
    DATABASE.lock().states.remove(&name.to_lowercase());
    Ok(())
}

/// Executável e argumentos, respeitando aspas iniciais.
pub fn parse_command_line(command_line: &str) -> ServiceResult<CommandLine> {
    if let Some(rest) = command_line.strip_prefix('"') {
        let Some(closing) = rest.find('"').filter(|&index| index > 0) else { return fail(123, "unclosed image path") };
        return Ok(CommandLine { path: rest[..closing].to_string(), arguments: rest[closing + 1..].trim().to_string() });
    }
    Ok(match command_line.find(char::is_whitespace) {
        None => CommandLine { path: command_line.to_string(), arguments: String::new() },
        Some(index) => CommandLine { path: command_line[..index].to_string(), arguments: command_line[index..].trim().to_string() },
    })
}

fn update_state(name: &str, body: impl FnOnce(&mut ServiceStatus)) {
    if let Some(state) = DATABASE.lock().states.get_mut(&name.to_lowercase()) {
        body(state);
    }
}

fn notify_stopped(name: &str) {
    let listeners = DATABASE.lock().stopped.clone();
    for listener in listeners {
        listener(name);
    }
}

/// Exige serviço de processo próprio com dependências em RUNNING, resolve a
/// imagem (`Some((imagem, é_diretório))`) e executa o processo em
/// START_PENDING; toda saída publica STOPPED e avisa os ouvintes. O
/// executor recebe o anexador do identificador do processo criado.
pub fn launch<I>(name: &str, resolve_image: impl FnOnce(&str) -> Option<(I, bool)>, run_process: impl FnOnce(I, &CommandLine, &dyn Fn(u64) -> ServiceResult<()>) -> ServiceResult<u32>) -> ServiceResult<u32> {
    let Some(configuration) = read(name)? else { return fail(1060, "service does not exist") };
    if status(name)?.current_state != STOPPED {
        return fail(1056, "service is already active");
    }
    if configuration.start == 4 {
        return fail(1058, "service disabled");
    }
    if configuration.service_type != 16 {
        return fail(50, "this launcher requires an own-process service");
    }
    for dependency in &configuration.dependencies {
        if read(dependency)?.is_none() || status(dependency)?.current_state != RUNNING {
            return Err(ServiceError::Win32(1068, alloc::format!("SCM: dependency is not running: {dependency}")));
        }
    }
    let command_line = parse_command_line(&configuration.image_path)?;
    let image = match resolve_image(&command_line.path) {
        Some((image, false)) => image,
        _ => return Err(ServiceError::Win32(2, alloc::format!("SCM: service image absent: {}", command_line.path))),
    };
    DATABASE.lock().states.insert(name.to_lowercase(), ServiceStatus { service_type: configuration.service_type, current_state: START_PENDING, wait_hint: 30000, ..Default::default() });
    // O anexo vale uma única vez; sem ele o transporte não autentica relatos.
    let attach = |process_id: u64| -> ServiceResult<()> {
        let mut database = DATABASE.lock();
        let state = database.states.get_mut(&name.to_lowercase());
        match state {
            Some(state) if process_id > 0 && state.process_id == 0 => {
                state.process_id = process_id;
                Ok(())
            }
            _ => fail(87, "invalid process attachment"),
        }
    };
    let result = run_process(image, &command_line, &attach);
    match &result {
        Ok(exit_code) => update_state(name, |state| {
            state.process_exit_code = Some(*exit_code);
            if state.current_state != STOPPED {
                state.win32_exit_code = if *exit_code != 0 { 1067 } else { 0 };
            }
        }),
        Err(error) => {
            let code = error.win32().unwrap_or(1067);
            update_state(name, |state| state.win32_exit_code = code);
        }
    }
    update_state(name, |state| {
        state.current_state = STOPPED;
        state.controls_accepted = 0;
        state.process_id = 0;
        state.checkpoint = 0;
        state.wait_hint = 0;
    });
    notify_stopped(name);
    result
}

/// Valida que o relato vem do processo anexado e publica o SERVICE_STATUS.
pub fn report_status(name: &str, process_id: u64, reported: &ReportedStatus) -> ServiceResult<()> {
    let snapshot = {
        let mut database = DATABASE.lock();
        let Some(state) = database.states.get_mut(&name.to_lowercase()).filter(|state| state.process_id != 0 && state.process_id == process_id) else {
            return fail(6, "invalid service process");
        };
        if !(1..=7).contains(&reported.current_state) || reported.controls_accepted & !0x1FFF != 0 {
            return fail(13, "invalid service status");
        }
        // Conserva os campos relatados, inclusive checkpoint e controles
        // antigos em STOPPED; o despacho consulta o estado primeiro.
        state.current_state = reported.current_state;
        state.controls_accepted = reported.controls_accepted;
        state.win32_exit_code = reported.win32_exit_code;
        state.service_specific_exit_code = reported.service_specific_exit_code;
        state.checkpoint = reported.checkpoint;
        state.wait_hint = reported.wait_hint;
        (*state, database.status.clone())
    };
    for listener in snapshot.1 {
        listener(name, process_id, &snapshot.0);
    }
    Ok(())
}

/// Subchaves de Services com Type; configurações auxiliares (Tcpip) não
/// contam como serviço instalado.
pub fn list() -> Vec<String> {
    registry::list_keys(ROOT).into_iter().filter(|name| service_key_path(name).is_ok_and(|path| registry::read_value_by_path(&path, "Type").is_some())).collect()
}

pub fn set_driver_status_provider(provider: Option<DriverStatusProvider>) {
    DATABASE.lock().driver_status = provider;
}

pub fn driver_stopped(name: &str) {
    notify_stopped(name);
}

/// Serviços ativos anexados ao processo (autorizam o dispatcher).
pub fn active_for_process(process_id: u64) -> Vec<Configuration> {
    let names: Vec<String> = DATABASE.lock().states.iter().filter(|(_, state)| state.process_id == process_id && state.current_state != STOPPED).map(|(name, _)| name.clone()).collect();
    names.iter().filter_map(|name| read(name).ok().flatten()).collect()
}

/// Serviços em execução que dependem do nome consultado.
pub fn active_dependents(name: &str) -> Vec<String> {
    let lower = name.to_lowercase();
    list()
        .into_iter()
        .filter(|other| status(other).is_ok_and(|status| status.current_state != STOPPED) && read(other).ok().flatten().is_some_and(|configuration| configuration.dependencies.iter().any(|dependency| dependency.to_lowercase() == lower)))
        .collect()
}

pub fn on_status_change(listener: StatusListener) {
    DATABASE.lock().status.push(listener);
}

pub fn on_stopped(listener: StoppedListener) {
    DATABASE.lock().stopped.push(listener);
}
