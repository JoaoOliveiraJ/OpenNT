//! Comando `sc` do shell.
//!
//! Consulta a mesma hive e usa o ciclo real de serviços e drivers; o texto
//! é separado aqui para preservar aspas e caminhos.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::service::driver::{self as driver_services, DriverServiceError};
use crate::ntos::cm::service::channel::{self as service_channel, Control, Failure};
use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput, ServiceError};
use crate::ntos::ke::clock;
use crate::ntos::ps::user::process as user_process;
use crate::ntos::inc::status::STATUS_UNSUCCESSFUL;

/// Nomes publicados pelo SCM para os valores da configuração e do status.
const SERVICE_TYPES: &[(&str, u32)] = &[("kernel", 1), ("filesys", 2), ("own", 16), ("share", 32)];
const START_TYPES: &[(&str, u32)] = &[("boot", 0), ("system", 1), ("auto", 2), ("demand", 3), ("disabled", 4)];
const ERROR_TYPES: &[(&str, u32)] = &[("ignore", 0), ("normal", 1), ("severe", 2), ("critical", 3)];
const STATE_NAMES: &[&str] = &["", "STOPPED", "START_PENDING", "STOP_PENDING", "RUNNING", "CONTINUE_PENDING", "PAUSE_PENDING", "PAUSED"];
const CONTROL_CODES: &[(&str, u32)] = &[("stop", 1), ("pause", 2), ("continue", 3), ("interrogate", 4)];
const HELP: &[&str] = &[
    "sc query [nome] [type= service|driver|all] [state= active|inactive|all]",
    "sc queryex [nome]     status, PID e codigo de saida do processo",
    "sc qc <nome>          configuracao registrada",
    "sc start <nome>       inicia o driver ou processo de servico real",
    "sc stop|pause|continue|interrogate <nome>",
    "sc control <nome> <codigo>   envia um controle aceito pelo servico",
    "sc create <nome> binPath= <caminho> [type= kernel|filesys|own|share]",
    "sc config <nome> <opcao= valor> ...",
    "  opcoes: binPath, type, start, error, displayName, obj, depend",
    "  start= boot|system|auto|demand|disabled; depend= nome1/nome2",
    "sc delete <nome>      exclui a configuracao de um servico parado",
    "sc enumdepend <nome>  lista servicos que dependem dele",
    "sc getdisplayname <nome> | sc getkeyname <nome de exibicao>",
    "Use aspas duplas em valores com espacos; \\\" preserva uma aspa no valor.",
    "Sem nome, query usa type= service state= active.",
    "Processos de usuario usam o carregador sincrono: o shell aguarda sua saida.",
    "Argumentos de inicio, processos compartilhados e SCM remoto nao sao suportados.",
];

/// Saída do comando (o console do shell ou a captura de um teste).
pub type Output = fn(&str);

/// Erro com o código Win32 (o shell não o confunde com uma resposta vazia)
/// e o NTSTATUS de uma falha nativa.
pub struct ScError {
    pub win32: u32,
    pub message: String,
    pub ntstatus: Option<u32>,
}

fn fail<T>(win32: u32, message: &str) -> Result<T, ScError> {
    Err(ScError { win32, message: String::from(message), ntstatus: None })
}

impl From<ServiceError> for ScError {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::Win32(win32, message) => ScError { win32, message, ntstatus: None },
            ServiceError::Kernel(error) => ScError { win32: 31, ntstatus: (error.status != STATUS_UNSUCCESSFUL).then_some(error.status), message: error.message },
        }
    }
}

impl From<DriverServiceError> for ScError {
    fn from(error: DriverServiceError) -> Self {
        ScError { win32: error.win32, message: error.message, ntstatus: error.ntstatus }
    }
}

impl From<Failure> for ScError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Win32(code) => ScError { win32: code, message: format!("Service channel {code}"), ntstatus: None },
            Failure::Rpc(status) => ScError { win32: 31, message: format!("Service channel RPC {status}"), ntstatus: None },
        }
    }
}

/// Palavras separadas por espaço com aspas duplas; barras antes de aspas
/// seguem a regra 2n/2n+1 e as demais ficam literais (caminhos NT).
pub fn tokenize(command_line: &str) -> Result<Vec<String>, ScError> {
    let characters: Vec<char> = command_line.chars().collect();
    let mut arguments = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut started = false;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if character == '\\' {
            let mut slashes = 1;
            while characters.get(index + slashes) == Some(&'\\') {
                slashes += 1;
            }
            index += slashes - 1;
            if characters.get(index + 1) == Some(&'"') {
                token.extend(core::iter::repeat_n('\\', slashes / 2));
                if slashes % 2 == 1 {
                    token.push('"');
                } else {
                    quoted = !quoted;
                }
                index += 1;
            } else {
                token.extend(core::iter::repeat_n('\\', slashes));
            }
            started = true;
        } else if character == '"' {
            quoted = !quoted;
            started = true;
        } else if character.is_whitespace() && !quoted {
            if started {
                arguments.push(core::mem::take(&mut token));
            }
            token.clear();
            started = false;
        } else {
            token.push(character);
            started = true;
        }
        index += 1;
    }
    if quoted {
        return fail(87, "Aspas duplas sem fechamento.");
    }
    if started {
        arguments.push(token);
    }
    Ok(arguments)
}

fn option_name(argument: &str) -> Option<(String, String)> {
    let (name, value) = argument.split_once('=')?;
    (!name.is_empty() && name.chars().all(|character| character.is_ascii_alphabetic())).then(|| (name.to_ascii_lowercase(), String::from(value)))
}

/// Lê todas as opções antes de alterar a hive; desconhecidas e repetidas
/// são erros.
fn parse_options(arguments: &[String], allowed: &[&str]) -> Result<Vec<(String, String)>, ScError> {
    let mut options: Vec<(String, String)> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let Some((name, mut value)) = option_name(&arguments[index]) else { return fail(87, &format!("Esperado opcao= valor: {}", arguments[index])) };
        if !allowed.contains(&name.as_str()) {
            return fail(87, &format!("Opcao nao suportada: {name}"));
        }
        if options.iter().any(|(existing, _)| *existing == name) {
            return fail(87, &format!("Opcao repetida: {name}"));
        }
        if value.is_empty() {
            index += 1;
            if index >= arguments.len() || option_name(&arguments[index]).is_some() {
                return fail(87, &format!("Falta o valor de {name}."));
            }
            value = arguments[index].clone();
        }
        options.push((name, value));
        index += 1;
    }
    Ok(options)
}

fn option<'a>(options: &'a [(String, String)], name: &str) -> Option<&'a str> {
    options.iter().find(|(candidate, _)| candidate == name).map(|(_, value)| value.as_str())
}

/// Só valores documentados; nunca grava um tipo inventado.
fn option_number(values: &[(&str, u32)], value: &str, name: &str) -> Result<u32, ScError> {
    let lower = value.to_ascii_lowercase();
    match values.iter().find(|(candidate, _)| *candidate == lower) {
        Some(&(_, number)) => Ok(number),
        None => fail(87, &format!("Valor invalido de {name}: {value}")),
    }
}

/// Alteração parcial: os campos omitidos ficam com a base de serviços.
fn configuration_changes(arguments: &[String]) -> Result<ConfigurationInput, ScError> {
    let options = parse_options(arguments, &["binpath", "type", "start", "error", "displayname", "obj", "depend"])?;
    let mut changes = ConfigurationInput::default();
    changes.image_path = option(&options, "binpath").map(String::from);
    changes.display_name = option(&options, "displayname").map(String::from);
    changes.object_name = option(&options, "obj").map(String::from);
    if let Some(value) = option(&options, "type") {
        changes.service_type = Some(option_number(SERVICE_TYPES, value, "type")?);
    }
    if let Some(value) = option(&options, "start") {
        changes.start = Some(option_number(START_TYPES, value, "start")?);
    }
    if let Some(value) = option(&options, "error") {
        changes.error_control = Some(option_number(ERROR_TYPES, value, "error")?);
    }
    if let Some(value) = option(&options, "depend") {
        if value.split('/').any(|dependency| dependency.starts_with('+')) {
            return fail(50, "Dependencias de grupos ainda nao sao suportadas.");
        }
        changes.dependencies = Some(if value.is_empty() { Vec::new() } else { value.split('/').map(String::from).collect() });
    }
    Ok(changes)
}

fn require_configuration(name: &str) -> Result<service_database::Configuration, ScError> {
    match service_database::read(name)? {
        Some(configuration) => Ok(configuration),
        None => fail(1060, &format!("Servico nao instalado: {name}")),
    }
}

fn type_name(service_type: u32) -> &'static str {
    match service_type {
        1 => "KERNEL_DRIVER",
        2 => "FILE_SYSTEM_DRIVER",
        16 => "WIN32_OWN_PROCESS",
        32 => "WIN32_SHARE_PROCESS",
        _ => "",
    }
}

/// Valores reais do SCM, com os tipos em hexadecimal como o sc do Windows.
fn print_status(name: &str, extended: bool, write: Output) -> Result<(), ScError> {
    let status = service_database::status(name)?;
    write(&format!("SERVICE_NAME: {name}"));
    write(&format!("        TYPE               : {:x}  {}", status.service_type, type_name(status.service_type)));
    write(&format!("        STATE              : {}  {}", status.current_state, STATE_NAMES.get(status.current_state as usize).copied().unwrap_or("")));
    write(&format!("        CONTROLS_ACCEPTED  : 0x{:x}", status.controls_accepted));
    write(&format!("        WIN32_EXIT_CODE    : {}", status.win32_exit_code));
    write(&format!("        SERVICE_EXIT_CODE  : {}", status.service_specific_exit_code));
    write(&format!("        CHECKPOINT         : {}", status.checkpoint));
    write(&format!("        WAIT_HINT          : {}", status.wait_hint));
    if extended {
        write(&format!("        PID                : {}", status.process_id));
        if let Some(code) = status.process_exit_code {
            write(&format!("        PROCESS_EXIT_CODE  : 0x{code:x}"));
        }
    }
    Ok(())
}

/// Enumeração pela hive e o status atual; parados só no filtro adequado.
fn query_services(arguments: &[String], extended: bool, write: Output) -> Result<(), ScError> {
    if let Some(first) = arguments.first().filter(|first| !first.contains('=')) {
        if arguments.len() != 1 {
            return fail(87, "Use o nome sozinho ou os filtros de enumeracao.");
        }
        return print_status(&require_configuration(first)?.name, extended, write);
    }
    let options = parse_options(arguments, &["type", "state"])?;
    let type_filter = option(&options, "type").unwrap_or("service").to_ascii_lowercase();
    let state_filter = option(&options, "state").unwrap_or("active").to_ascii_lowercase();
    let types: &[u32] = match type_filter.as_str() {
        "all" => &[1, 2, 16, 32],
        "driver" => &[1, 2],
        "service" => &[16, 32],
        "kernel" => &[1],
        "filesys" => &[2],
        "own" => &[16],
        "share" => &[32],
        _ => return fail(87, "Filtro de tipo ou estado invalido."),
    };
    if !matches!(state_filter.as_str(), "all" | "active" | "inactive") {
        return fail(87, "Filtro de tipo ou estado invalido.");
    }
    for name in service_database::list() {
        let status = service_database::status(&name)?;
        if !types.contains(&status.service_type) {
            continue;
        }
        if (state_filter == "active" && status.current_state == 1) || (state_filter == "inactive" && status.current_state != 1) {
            continue;
        }
        print_status(&name, extended, write)?;
    }
    Ok(())
}

/// Operação ainda em andamento: `Ok(None)` pendente, `Ok(Some(código))` concluída.
pub trait ScPending: Send {
    fn poll(&mut self) -> Result<Option<u32>, ScError>;
}

/// O canal entrega o controle ao handler; o shell cede a CPU enquanto espera
/// e tempo esgotado ou rejeição não alteram o estado artificialmente.
struct ControlWait {
    control: Control,
    name: String,
    deadline: u64,
    write: Output,
}

impl ScPending for ControlWait {
    fn poll(&mut self) -> Result<Option<u32>, ScError> {
        let (finished, error) = {
            let control = self.control.lock();
            (control.finished, control.error.unwrap_or(0))
        };
        if !finished {
            if clock::uptime_ms() >= self.deadline {
                return fail(1053, "Tempo esgotado aguardando o handler.");
            }
            return Ok(None);
        }
        if error != 0 {
            return fail(error, "O handler rejeitou o controle.");
        }
        print_status(&self.name, false, self.write)?;
        Ok(Some(0))
    }
}

fn control_service(name: &str, code: u32, write: Output) -> Result<Option<Box<dyn ScPending>>, ScError> {
    let accepted = match code {
        1 => 1,
        2 | 3 => 2,
        6 => 8,
        7..=10 => 16,
        _ => 0,
    };
    let supported = matches!(code, 1 | 2 | 3 | 4 | 6 | 7 | 8 | 9 | 10) || (128..=255).contains(&code);
    let status = service_database::status(name)?;
    if !supported {
        return fail(87, "Codigo de controle invalido.");
    }
    if status.current_state == 1 {
        return fail(1062, "Servico parado.");
    }
    if status.current_state == 2 || status.current_state == 3 {
        return fail(1061, "Servico em transicao.");
    }
    if accepted != 0 && status.controls_accepted & accepted == 0 {
        return fail(1052, "Controle nao aceito pelo servico.");
    }
    if code == 1 && !service_database::active_dependents(name).is_empty() {
        return fail(1051, "Existem dependentes ativos.");
    }
    if status.service_type < 16 {
        if code == 1 {
            driver_services::stop(name)?;
        } else if code != 4 {
            return fail(1052, "Controle nao suportado por drivers.");
        }
        print_status(name, false, write)?;
        return Ok(None);
    }
    let control = service_channel::control(name, code)?;
    Ok(Some(Box::new(ControlWait { control, name: String::from(name), deadline: clock::uptime_ms() + 30000, write })))
}

fn parse_control_code(text: &str) -> Option<u32> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return (!hex.is_empty() && hex.chars().all(|character| character.is_ascii_hexdigit())).then(|| u32::from_str_radix(hex, 16).ok()).flatten();
    }
    (!text.is_empty() && text.chars().all(|character| character.is_ascii_digit())).then(|| text.parse().ok()).flatten()
}

/// Uma operação já separada; escrita só publica sucesso depois de a base
/// aceitar, e start/controles mostram o status observado.
fn dispatch(mut arguments: Vec<String>, write: Output) -> Result<Option<Box<dyn ScPending>>, ScError> {
    let operation = if arguments.is_empty() { String::from("help") } else { arguments.remove(0).to_lowercase() };
    if matches!(operation.as_str(), "help" | "/?" | "-h" | "--help") {
        HELP.iter().for_each(|line| write(line));
        return Ok(None);
    }
    if operation.starts_with("\\\\") {
        return fail(50, "SCM remoto nao suportado.");
    }
    const OPERATIONS: &[&str] = &["query", "queryex", "qc", "start", "stop", "pause", "continue", "interrogate", "control", "create", "config", "delete", "enumdepend", "getdisplayname", "getkeyname"];
    if !OPERATIONS.contains(&operation.as_str()) {
        return fail(87, &format!("Comando sc desconhecido: {operation}"));
    }
    if operation == "query" || operation == "queryex" {
        query_services(&arguments, operation == "queryex", write)?;
        return Ok(None);
    }
    if arguments.is_empty() {
        return fail(87, "Informe o nome do servico; use sc help.");
    }
    let name = arguments.remove(0);
    if name.is_empty() {
        return fail(87, "Informe o nome do servico; use sc help.");
    }
    if operation == "create" || operation == "config" {
        if arguments.is_empty() {
            return fail(87, "Informe as opcoes de configuracao.");
        }
        let changes = configuration_changes(&arguments)?;
        if operation == "create" {
            service_database::install(&ConfigurationInput { name: name.clone(), ..changes }, false)?;
        } else {
            service_database::configure(&name, &changes)?;
        }
        write(&format!("[SC] {} SUCCESS", if operation == "create" { "CreateService" } else { "ChangeServiceConfig" }));
        return Ok(None);
    }
    if operation == "control" {
        let code = if arguments.len() == 1 { parse_control_code(&arguments[0]) } else { None };
        let Some(code) = code else { return fail(87, "Use sc control <nome> <codigo>.") };
        return control_service(&name, code, write);
    }
    if operation == "start" && !arguments.is_empty() {
        return fail(50, "Argumentos de inicio ainda nao sao suportados.");
    }
    if !arguments.is_empty() {
        return fail(87, &format!("Argumentos extras para {operation}."));
    }
    if operation == "getkeyname" {
        let lower = name.to_lowercase();
        let found = service_database::list().into_iter().filter_map(|candidate| service_database::read(&candidate).ok().flatten()).find(|configuration| configuration.display_name.to_lowercase() == lower);
        let Some(found) = found else { return fail(1060, "Nome de exibicao nao encontrado.") };
        write(&format!("NAME = {}", found.name));
        return Ok(None);
    }
    let configuration = require_configuration(&name)?;
    if operation == "start" {
        if configuration.service_type < 16 {
            driver_services::start(&name)?;
        } else {
            write("[SC] Iniciando processo; o shell aguarda o encerramento do servico.");
            user_process::run_service(&name, None)?;
        }
        print_status(&configuration.name, true, write)?;
        let status = service_database::status(&name)?;
        if status.win32_exit_code != 0 {
            return fail(status.win32_exit_code, "O servico terminou com erro.");
        }
    } else if let Some(&(_, code)) = CONTROL_CODES.iter().find(|(control, _)| *control == operation) {
        return control_service(&name, code, write);
    } else if operation == "qc" {
        let start_name = START_TYPES.iter().find(|(_, value)| *value == configuration.start).map_or(String::new(), |(name, _)| name.to_uppercase());
        write(&format!("SERVICE_NAME: {}", configuration.name));
        write(&format!("        TYPE               : {:x}  {}", configuration.service_type, type_name(configuration.service_type)));
        write(&format!("        START_TYPE         : {}  {}", configuration.start, start_name));
        write(&format!("        ERROR_CONTROL      : {}", configuration.error_control));
        write(&format!("        BINARY_PATH_NAME   : {}", configuration.image_path));
        write(&format!("        DISPLAY_NAME       : {}", configuration.display_name));
        write(&format!("        DEPENDENCIES       : {}", configuration.dependencies.join("/")));
        write(&format!("        SERVICE_START_NAME : {}", configuration.object_name));
    } else if operation == "delete" {
        service_database::remove(&name)?;
        write("[SC] DeleteService SUCCESS");
    } else if operation == "getdisplayname" {
        write(&format!("NAME = {}", configuration.display_name));
    } else if operation == "enumdepend" {
        let lower = name.to_lowercase();
        for dependent in service_database::list() {
            if service_database::read(&dependent)?.is_some_and(|configuration| configuration.dependencies.iter().any(|dependency| dependency.to_lowercase() == lower)) {
                print_status(&dependent, false, write)?;
            }
        }
    } else {
        return fail(87, &format!("Comando sc desconhecido: {operation}"));
    }
    Ok(None)
}

fn report(error: &ScError, write: Output) -> u32 {
    let code = if error.win32 != 0 { error.win32 } else { 31 };
    write(&format!("[SC] FAILED {code}: {}", error.message));
    if let Some(status) = error.ntstatus {
        write(&format!("NTSTATUS: 0x{status:08x}"));
    }
    code
}

/// Resultado do comando: o código de saída ou a espera de um controle.
pub enum Execution {
    Done(u32),
    Pending(Box<Waiting>),
}

/// Espera de um controle; a resposta é impressa uma vez.
pub struct Waiting {
    pending: Box<dyn ScPending>,
    completed: Option<u32>,
    write: Output,
}

impl Waiting {
    pub fn poll(&mut self) -> Option<u32> {
        if self.completed.is_none() {
            self.completed = match self.pending.poll() {
                Ok(result) => result,
                Err(error) => Some(report(&error, self.write)),
            };
        }
        self.completed
    }
}

/// Mantém o código de saída para os testes e o shell; falhas nativas
/// conservam o NTSTATUS.
pub fn execute(command_line: &str, write: Output) -> Execution {
    match tokenize(command_line).and_then(|arguments| dispatch(arguments, write)) {
        Ok(None) => Execution::Done(0),
        Ok(Some(pending)) => Execution::Pending(Box::new(Waiting { pending, completed: None, write })),
        Err(error) => Execution::Done(report(&error, write)),
    }
}
