//! SCMR sobre o endpoint ALPC local — `system32/ntos/cm/service-rpc.js`.
//!
//! Operações NDR32 do gerenciador de serviços: os contextos RPC têm dono e
//! máscara de direitos próprios; códigos de operação e campos do protocolo
//! seguem o cliente instalado.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ntos::cm::service::driver::{self as driver_services, DriverServiceError};
use crate::ntos::cm::service::channel::{self as service_channel, Control, Failure};
use crate::ntos::cm::service::database::{self as service_database, ConfigurationInput, ReportedStatus, ServiceError, ServiceStatus};
use crate::ntos::alpc::transport;
use crate::ntos::io::lrpc::{self, Body, Interface, Pending, RpcContext};
use crate::ntos::io::ndr::{self, Reader, Writer};
use crate::ntos::ke::clock;
use crate::ntos::ps::user::{events, index};
use crate::ntos::se::token::tokens;
use crate::rtl::{KernelError, SpinLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Manager,
    Service,
}

struct Entry {
    owner: u64,
    kind: Kind,
    name: String,
    access: u32,
}

/// A tabela é a autoridade da posse dos contextos; as exclusões adiadas
/// esperam o fim dos usuários e do serviço ativo.
static CONTEXTS: SpinLock<BTreeMap<String, Entry>> = SpinLock::new(BTreeMap::new());
static PENDING_DELETIONS: SpinLock<BTreeSet<String>> = SpinLock::new(BTreeSet::new());
static NEXT_CONTEXT: AtomicU32 = AtomicU32::new(1);
static STARTED: AtomicBool = AtomicBool::new(false);

/// Erro Win32 (serializado) ou RPC fault (levado ao transporte).
enum Fail {
    Win32(u32),
    Rpc(u32),
}

impl From<ServiceError> for Fail {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::Win32(code, _) => Fail::Win32(code),
            ServiceError::Kernel(_) => Fail::Rpc(1726),
        }
    }
}

impl From<DriverServiceError> for Fail {
    fn from(error: DriverServiceError) -> Self {
        Fail::Win32(error.win32)
    }
}

impl From<Failure> for Fail {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Win32(code) => Fail::Win32(code),
            Failure::Rpc(status) => Fail::Rpc(status),
        }
    }
}

/// Os 20 bytes do contexto em hexadecimal, sem perder zeros.
fn identity(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| alloc::format!("{byte:02x}")).collect()
}

/// Exige o SID de LocalSystem e resolve as máscaras genéricas para o
/// gerenciador ou o serviço; o endpoint não avalia DACLs de outros usuários.
fn resolve_granted_access(context: &RpcContext, desired: u32, service: bool) -> Result<u32, Fail> {
    const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let caller = tokens::with(context.token, |token| token.user.clone());
    if caller.is_none_or(|user| user.as_slice() != SYSTEM) {
        return Err(Fail::Win32(5));
    }
    let mut mask = desired;
    let all = if service { 0xF_01FF } else { 0xF_003F };
    if mask & 0x8000_0000 != 0 {
        mask |= if service { 0x2_008D } else { 0x2_0014 };
    }
    if mask & 0x4000_0000 != 0 {
        mask |= if service { 0x2_0002 } else { 0x2_0022 };
    }
    if mask & 0x2000_0000 != 0 {
        mask |= if service { 0x2_0170 } else { 0x2_0009 };
    }
    if mask & 0x1200_0000 != 0 {
        mask |= all;
    }
    mask &= 0x0DFF_FFFF;
    if mask & !(all | if service { 0x8000 } else { 0 }) != 0 {
        return Err(Fail::Win32(5));
    }
    Ok(mask)
}

/// Contexto com sequência, processo, assinatura e versão.
fn allocate(context: &RpcContext, kind: Kind, name: &str, access: u32) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 20];
    bytes[4..8].copy_from_slice(&NEXT_CONTEXT.fetch_add(1, Ordering::AcqRel).to_le_bytes());
    bytes[8..12].copy_from_slice(&(context.process_id as u32).to_le_bytes());
    bytes[12..16].copy_from_slice(&0x5343_4D52u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    CONTEXTS.lock().insert(identity(&bytes), Entry { owner: context.process_id, kind, name: String::from(name), access });
    bytes
}

/// Dono, tipo e direitos: contexto ausente (6) e direito insuficiente (5).
fn lookup(context: &RpcContext, bytes: &[u8], kind: Option<Kind>, access: u32) -> Result<(Kind, String, u32), Fail> {
    let contexts = CONTEXTS.lock();
    let Some(entry) = contexts.get(&identity(bytes)).filter(|entry| entry.owner == context.process_id && kind.is_none_or(|kind| entry.kind == kind)) else { return Err(Fail::Win32(6)) };
    if entry.access & access != access {
        return Err(Fail::Win32(5));
    }
    Ok((entry.kind, entry.name.clone(), entry.access))
}

/// Exclusão marcada só depois do último contexto do serviço e da parada.
fn complete_pending_deletion(name: &str) {
    let lower = name.to_lowercase();
    if !PENDING_DELETIONS.lock().contains(&lower) {
        return;
    }
    if CONTEXTS.lock().values().any(|entry| entry.kind == Kind::Service && entry.name.to_lowercase() == lower) {
        return;
    }
    if !service_database::status(name).is_ok_and(|status| status.current_state == 1) {
        return;
    }
    let _ = service_database::remove(name);
    PENDING_DELETIONS.lock().remove(&lower);
}

/// Os sete campos do SERVICE_STATUS, zerados sem estado.
fn write_status(writer: &mut Writer, status: Option<&ServiceStatus>) {
    let fields = status.map_or([0; 7], |status| [status.service_type, status.current_state, status.controls_accepted, status.win32_exit_code, status.service_specific_exit_code, status.checkpoint, status.wait_hint]);
    for field in fields {
        writer.u32(field);
    }
}

/// Separa o erro Win32 (resultado da operação) do fault RPC.
fn captured<T>(result: Result<T, Fail>) -> Result<Result<T, u32>, u32> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(Fail::Win32(code)) => Ok(Err(code)),
        Err(Fail::Rpc(status)) => Err(status),
    }
}

fn pending_deletion(name: &str) -> bool {
    PENDING_DELETIONS.lock().contains(&name.to_lowercase())
}

/// O ControlService de um serviço de usuário espera até 30 s de uptime pela
/// confirmação, sem bloquear o transporte.
struct ControlWait {
    control: Control,
    name: String,
    deadline: u64,
}

impl Pending for ControlWait {
    fn poll(&mut self) -> Result<Option<Vec<u8>>, u32> {
        let (finished, error) = {
            let control = self.control.lock();
            (control.finished, control.error.unwrap_or(0))
        };
        if !finished && clock::uptime_ms() < self.deadline {
            return Ok(None);
        }
        let mut writer = Writer::new();
        write_status(&mut writer, service_database::status(&self.name).ok().as_ref());
        Ok(Some(writer.u32(if finished { error } else { 1053 }).finish()))
    }
}

fn string(reader: &mut Reader, unique: bool, limit: u32) -> Result<Option<String>, u32> {
    reader.string(unique, limit)
}

/// Decodifica a operação, valida os argumentos e autoriza o contexto antes
/// de alterar serviços; operações sem implementação viram RPC fault.
pub fn call(context: &RpcContext, operation: u32, bytes: &[u8]) -> Result<Body, u32> {
    let mut reader = Reader::new(bytes);
    let mut writer = Writer::new();
    let mut error = 0u32;
    match operation {
        15 | 64 => {
            let machine = if operation == 15 { string(&mut reader, true, 256)? } else { None };
            let database = string(&mut reader, true, 256)?;
            let access = reader.u32()?;
            reader.end()?;
            // Os nomes de máquina aceitos apontam ao próprio convidado; a base
            // disponível é ServicesActive.
            let handle = captured((|| {
                if let Some(machine) = &machine {
                    if !matches!(machine.to_lowercase().as_str(), "." | "localhost" | "opennt" | "\\\\opennt") {
                        return Err(Fail::Win32(53));
                    }
                }
                if let Some(database) = &database {
                    let lower = database.to_lowercase();
                    if lower != "servicesactive" {
                        return Err(Fail::Win32(if lower == "servicesfailed" { 1065 } else { 123 }));
                    }
                }
                Ok(allocate(context, Kind::Manager, "", resolve_granted_access(context, access, false)?))
            })())?;
            let handle = handle.map_err(|code| error = code).ok();
            writer.context(handle.as_deref());
        }
        16 => {
            let manager = reader.context()?;
            let name = string(&mut reader, false, 257)?.unwrap_or_default();
            let access = reader.u32()?;
            reader.end()?;
            crate::debug_print!("[scmr] open service={} access=0x{:x}", name, access);
            let handle = captured((|| {
                lookup(context, &manager, Some(Kind::Manager), 1)?;
                if pending_deletion(&name) {
                    return Err(Fail::Win32(1072));
                }
                if service_database::read(&name)?.is_none() {
                    return Err(Fail::Win32(1060));
                }
                let granted = resolve_granted_access(context, access, true)?;
                if granted & 0x8000 != 0 && service_database::status(&name)?.process_id != context.process_id {
                    return Err(Fail::Win32(5));
                }
                Ok(allocate(context, Kind::Service, &name, granted))
            })())?;
            let handle = handle.map_err(|code| error = code).ok();
            writer.context(handle.as_deref());
        }
        // I_ScOpenServiceStatusHandle (MIDL da sechost): contexto de relatório
        // para o START já entregue ao processo.
        54 => {
            let manager = reader.context()?;
            let name = string(&mut reader, false, 257)?.unwrap_or_default();
            let control_id = reader.u64()?;
            reader.end()?;
            let handle = captured((|| {
                lookup(context, &manager, Some(Kind::Manager), 1)?;
                let granted = resolve_granted_access(context, 0x8000, true)?;
                if service_database::read(&name)?.is_none() {
                    return Err(Fail::Win32(1060));
                }
                let control = service_channel::authorize_status_handle(context, &name, control_id)?;
                if control.lock().status_handle.is_some() {
                    return Err(Fail::Win32(1056));
                }
                let handle = allocate(context, Kind::Service, &name, granted);
                control.lock().status_handle = Some(handle.clone());
                Ok(handle)
            })())?;
            let handle = handle.map_err(|code| error = code).ok();
            writer.context(handle.as_deref());
        }
        0 => {
            let handle = reader.context()?;
            reader.end()?;
            let closed = captured((|| {
                let (kind, name, _) = lookup(context, &handle, None, 0)?;
                CONTEXTS.lock().remove(&identity(&handle));
                if kind == Kind::Service {
                    complete_pending_deletion(&name);
                }
                Ok(())
            })())?;
            if let Err(code) = closed {
                error = code;
            }
            writer.context(if error != 0 { Some(&handle) } else { None });
        }
        1 => {
            let handle = reader.context()?;
            let code = reader.u32()?;
            reader.end()?;
            let mut information: Option<ServiceStatus> = None;
            let mut pending: Option<(Control, String)> = None;
            let result = captured((|| {
                // Cada controle exige um direito no handle e o bit
                // SERVICE_ACCEPT_* do serviço; desconhecidos são recusados.
                let policy = match code {
                    1 => (0x20, 1),
                    2 | 3 => (0x40, 2),
                    4 => (0x80, 0),
                    6 => (0x40, 8),
                    7..=10 => (0x40, 16),
                    128..=255 => (0x100, 0),
                    _ => return Err(Fail::Win32(87)),
                };
                let (_, name, _) = lookup(context, &handle, Some(Kind::Service), policy.0)?;
                let status = service_database::status(&name)?;
                information = Some(status);
                if status.current_state == 1 {
                    return Err(Fail::Win32(1062));
                }
                if status.current_state == 2 || status.current_state == 3 {
                    return Err(Fail::Win32(1061));
                }
                if policy.1 != 0 && status.controls_accepted & policy.1 == 0 {
                    return Err(Fail::Win32(1052));
                }
                if code == 1 && !service_database::active_dependents(&name).is_empty() {
                    return Err(Fail::Win32(1051));
                }
                if status.service_type < 16 {
                    if code == 1 {
                        driver_services::stop(&name)?;
                    } else if code != 4 {
                        return Err(Fail::Win32(1052));
                    }
                    information = Some(service_database::status(&name)?);
                } else {
                    pending = Some((service_channel::control(&name, code)?, name.clone()));
                }
                Ok(())
            })())?;
            if let Err(code) = result {
                error = code;
            }
            if let Some((control, name)) = pending {
                return Ok(Body::Later(Box::new(ControlWait { control, name, deadline: clock::uptime_ms() + 30000 })));
            }
            write_status(&mut writer, information.as_ref());
        }
        2 => {
            let handle = reader.context()?;
            reader.end()?;
            let result = captured((|| {
                let (_, name, _) = lookup(context, &handle, Some(Kind::Service), 0x1_0000)?;
                if pending_deletion(&name) {
                    return Err(Fail::Win32(1072));
                }
                PENDING_DELETIONS.lock().insert(name.to_lowercase());
                Ok(())
            })())?;
            if let Err(code) = result {
                error = code;
            }
        }
        6 | 40 => {
            let handle = reader.context()?;
            let level = if operation == 40 { reader.u32()? } else { 0 };
            let requested = if operation == 40 { reader.u32()? } else { 28 };
            reader.end()?;
            // O buffer de status aceito pelo protocolo é limitado antes da resposta.
            if requested > 8192 {
                return Err(ndr::FAULT);
            }
            let mut required = 0;
            let result = captured((|| {
                let (_, name, _) = lookup(context, &handle, Some(Kind::Service), 4)?;
                if level != 0 {
                    return Err(Fail::Win32(124));
                }
                required = if operation == 40 { 36 } else { 28 };
                if requested < required {
                    return Err(Fail::Win32(122));
                }
                Ok(service_database::status(&name)?)
            })())?;
            let information = result.map_err(|code| error = code).ok();
            if operation == 6 {
                write_status(&mut writer, information.as_ref());
            } else {
                let mut status = Writer::new();
                if let Some(information) = &information {
                    write_status(&mut status, Some(information));
                    status.u32(information.process_id as u32).u32(0);
                }
                let encoded = status.finish();
                let mut bytes = alloc::vec![0u8; requested as usize];
                let copied = encoded.len().min(bytes.len());
                bytes[..copied].copy_from_slice(&encoded[..copied]);
                writer.u32(requested).raw(&bytes).u32(required);
            }
        }
        7 => {
            let handle = reader.context()?;
            let mut fields = [0u32; 7];
            for field in fields.iter_mut() {
                *field = reader.u32()?;
            }
            reader.end()?;
            crate::debug_print!("[scmr] status pid={} serviceType={} currentState={} controlsAccepted={} win32ExitCode={} serviceSpecificExitCode={} checkpoint={} waitHint={}", context.process_id, fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]);
            let result = captured((|| {
                let (_, name, access) = lookup(context, &handle, Some(Kind::Service), 0)?;
                if access & 0x8000 == 0 {
                    return Err(Fail::Win32(6));
                }
                let Some(configuration) = service_database::read(&name)? else { return Err(Fail::Rpc(1726)) };
                if configuration.service_type != fields[0] {
                    return Err(Fail::Win32(13));
                }
                service_database::report_status(&name, context.process_id, &ReportedStatus { current_state: fields[1], controls_accepted: fields[2], win32_exit_code: fields[3], service_specific_exit_code: fields[4], checkpoint: fields[5], wait_hint: fields[6] })?;
                Ok(())
            })())?;
            if let Err(code) = result {
                error = code;
            }
        }
        19 => {
            let handle = reader.context()?;
            let count = reader.u32()?;
            let array = reader.u32()?;
            if count > 1024 {
                return Err(ndr::FAULT);
            }
            // Ponteiros e strings capturados e validados pelo NDR; o início de
            // drivers não repassa argumentos de serviço de usuário.
            let mut valid = count == 0;
            if array != 0 {
                let pointers = reader.u32()?;
                if pointers != count {
                    return Err(ndr::FAULT);
                }
                let mut identifiers = Vec::new();
                for _ in 0..pointers {
                    identifiers.push(reader.u32()?);
                }
                for &identifier in &identifiers {
                    if identifier != 0 {
                        string(&mut reader, false, 32769)?;
                    }
                }
                valid = identifiers.iter().all(|&identifier| identifier != 0);
            }
            reader.end()?;
            let result = captured((|| {
                let (_, name, _) = lookup(context, &handle, Some(Kind::Service), 0x10)?;
                if pending_deletion(&name) {
                    return Err(Fail::Win32(1072));
                }
                if !valid {
                    return Err(Fail::Win32(87));
                }
                driver_services::start(&name)?;
                Ok(())
            })())?;
            if let Err(code) = result {
                error = code;
            }
        }
        17 => {
            let handle = reader.context()?;
            let requested = reader.u32()?;
            reader.end()?;
            if requested > 8192 {
                return Err(ndr::FAULT);
            }
            let mut required = 0u32;
            let result = captured((|| {
                let (_, name, _) = lookup(context, &handle, Some(Kind::Service), 1)?;
                let Some(configuration) = service_database::read(&name)? else { return Err(Fail::Rpc(1726)) };
                // Cabeçalho e cinco strings, a lista de dependências com o
                // terminador adicional.
                let mut dependencies = configuration.dependencies.join("\0");
                dependencies.push('\0');
                let strings = [configuration.image_path.clone(), String::new(), dependencies, configuration.object_name.clone(), configuration.display_name.clone()];
                required = 64 + strings.iter().map(|text| (text.encode_utf16().count() as u32 + 1) * 2).sum::<u32>();
                if requested < required {
                    return Err(Fail::Win32(122));
                }
                Ok((configuration, strings))
            })())?;
            let information = result.map_err(|code| error = code).ok();
            let present = information.is_some();
            let (service_type, start, error_control) = information.as_ref().map_or((0, 0, 0), |(configuration, _)| (configuration.service_type, configuration.start, configuration.error_control));
            writer.u32(service_type).u32(start).u32(error_control);
            writer.pointer(present).pointer(present).u32(0).pointer(present).pointer(present).pointer(present);
            if let Some((_, strings)) = &information {
                for text in strings {
                    writer.string(Some(text), false);
                }
            }
            writer.u32(required);
        }
        12 => {
            let manager = reader.context()?;
            let name = string(&mut reader, false, 257)?.unwrap_or_default();
            let display = string(&mut reader, true, 257)?;
            let access = reader.u32()?;
            let service_type = reader.u32()?;
            let start = reader.u32()?;
            let error_control = reader.u32()?;
            let image_path = string(&mut reader, false, 32769)?.unwrap_or_default();
            let group = string(&mut reader, true, 257)?;
            let tag = reader.u32()?;
            if tag != 0 {
                reader.u32()?;
            }
            let dependency_pointer = reader.u32()?;
            let dependency_bytes = if dependency_pointer != 0 {
                let length = reader.u32()?;
                reader.raw(length as usize)?
            } else {
                Vec::new()
            };
            let dependency_length = reader.u32()?;
            let object_name = string(&mut reader, true, 257)?;
            let password_pointer = reader.u32()?;
            let password_bytes = if password_pointer != 0 {
                let length = reader.u32()?;
                reader.raw(length as usize)?
            } else {
                Vec::new()
            };
            let password_length = reader.u32()?;
            reader.end()?;
            if dependency_bytes.len() as u32 != dependency_length || password_bytes.len() as u32 != password_length || dependency_length > 8192 || dependency_length % 2 != 0 {
                return Err(ndr::FAULT);
            }
            let handle = captured((|| {
                lookup(context, &manager, Some(Kind::Manager), 2)?;
                if pending_deletion(&name) {
                    return Err(Fail::Win32(1072));
                }
                // Grupo, tag e senha não são implementados: a operação recusa
                // em vez de registrar configuração que não cumpre.
                if group.is_some() || tag != 0 || password_length != 0 {
                    return Err(Fail::Win32(50));
                }
                let units: Vec<u16> = dependency_bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
                let text = String::from_utf16_lossy(&units);
                if !text.is_empty() && !text.ends_with("\0\0") {
                    return Err(Fail::Win32(87));
                }
                let granted = resolve_granted_access(context, access, true)?;
                if granted & 0x8000 != 0 {
                    return Err(Fail::Win32(5));
                }
                let dependencies: Vec<String> = text.trim_end_matches('\0').split('\0').filter(|part| !part.is_empty()).map(String::from).collect();
                service_database::install(&ConfigurationInput { name: name.clone(), display_name: Some(display.clone().filter(|display| !display.is_empty()).unwrap_or_else(|| name.clone())), image_path: Some(image_path.clone()), service_type: Some(service_type), start: Some(start), error_control: Some(error_control), object_name: Some(object_name.clone().filter(|object| !object.is_empty()).unwrap_or_else(|| String::from("LocalSystem"))), dependencies: Some(dependencies) }, false)?;
                Ok(allocate(context, Kind::Service, &name, granted))
            })())?;
            let handle = handle.map_err(|code| error = code).ok();
            writer.pointer(tag != 0);
            if tag != 0 {
                writer.u32(0);
            }
            writer.context(handle.as_deref());
        }
        _ => return Err(1745),
    }
    crate::debug_print!("[scmr] op={} pid={} error={}", operation, context.process_id, error);
    Ok(Body::Now(writer.u32(error).finish()))
}

/// Fecha os canais e os contextos do processo terminado; depois reavalia
/// as exclusões pendentes dos serviços afetados.
pub fn release_process(process_id: u64) {
    service_channel::release_process(process_id);
    let mut affected = BTreeSet::new();
    CONTEXTS.lock().retain(|_, entry| {
        if entry.owner != process_id {
            return true;
        }
        if entry.kind == Kind::Service {
            affected.insert(entry.name.clone());
        }
        false
    });
    for name in affected {
        complete_pending_deletion(&name);
    }
}

struct Scmr;

impl Interface for Scmr {
    fn call(&self, context: &RpcContext, operation: u32, arguments: &[u8]) -> Result<Body, u32> {
        call(context, operation, arguments)
    }
}

struct Channel;

impl Interface for Channel {
    fn call(&self, context: &RpcContext, operation: u32, arguments: &[u8]) -> Result<Body, u32> {
        service_channel::call(context, operation, arguments)
    }
}

/// A interface SCMR (81bb7a36-…:2) servida pelo ntsvcs.
pub fn scmr() -> Arc<dyn Interface> {
    Arc::new(Scmr)
}

/// Registra as duas interfaces do ntsvcs e cria o evento de disponibilidade
/// do gerenciador.
pub fn initialize() -> Result<(), KernelError> {
    if STARTED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    service_channel::init();
    // O fim do serviço tenta concluir exclusões adiadas pelo estado ativo.
    service_database::on_stopped(Arc::new(complete_pending_deletion));
    let interfaces: BTreeMap<String, Arc<dyn Interface>> = [(String::from("81bb7a364498f135ad3298f038001003:2"), Arc::new(Scmr) as Arc<dyn Interface>), (String::from("7c5fc4a2327dad4696f5adafb486be74:1"), Arc::new(Channel) as Arc<dyn Interface>)].into_iter().collect();
    transport::register("\\RPC Control\\ntsvcs", Arc::new(lrpc::Endpoint::new(interfaces)))?;
    events::create_kernel_event("\\BaseNamedObjects\\SvcctrlStartEvent_A3752DX", 0, true)?;
    crate::debug_print!("[scmr] ntsvcs registrado; gerenciador disponivel");
    Ok(())
}

pub fn init() {
    index::set_late_initializer(index::late::SERVICE_RPC, initialize);
}
