//! Canal local do dispatcher de serviços.
//!
//! Usado pela sechost.dll instalada: o protocolo distingue abrir, trocar
//! controle e fechar; cada canal pertence ao processo realmente lançado pela
//! base de serviços.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::ntos::cm::service::database::{self as service_database, ReportedStatus, ServiceError, ServiceStatus};
use crate::ntos::io::lrpc::{Body, Pending, RpcContext};
use crate::ntos::io::ndr::{self, Reader, Writer};
use crate::rtl::SpinLock;

/// Controle entregue ao dispatcher do processo: o chamador acompanha a
/// conclusão, o erro e os dados devolvidos.
#[derive(Debug, Default)]
pub struct ControlRecord {
    pub service: String,
    pub code: u32,
    pub id: u64,
    pub finished: bool,
    pub error: Option<u32>,
    pub data: Vec<u8>,
    /// Contexto de relatório de status ligado a este START (`service-rpc`).
    pub status_handle: Option<Vec<u8>>,
}

pub type Control = Arc<SpinLock<ControlRecord>>;

struct Channel {
    handle: Vec<u8>,
    pid: u64,
    queue: VecDeque<Control>,
    current: Option<Control>,
    waiting: bool,
    closed: bool,
}

type Shared = Arc<SpinLock<Channel>>;

/// Os contextos RPC são indexados pelos bytes em hexadecimal (não são
/// handles NT); contadores separados identificam canais e controles.
static CHANNELS: SpinLock<BTreeMap<String, Shared>> = SpinLock::new(BTreeMap::new());
static NEXT_CHANNEL: AtomicU32 = AtomicU32::new(1);
static NEXT_CONTROL: AtomicU64 = AtomicU64::new(1);
static LISTENING: AtomicBool = AtomicBool::new(false);

/// Erro de contrato (Win32, serializado na resposta) ou RPC fault.
pub enum Failure {
    Win32(u32),
    Rpc(u32),
}

/// Dois dígitos por byte: sequências com zeros iniciais não colidem.
fn identity(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| alloc::format!("{byte:02x}")).collect()
}

fn channels() -> Vec<Shared> {
    CHANNELS.lock().values().cloned().collect()
}

/// Identidade do contexto, processo dono e estado aberto.
fn lookup(context: &RpcContext, handle: &[u8]) -> Result<Shared, Failure> {
    let channel = CHANNELS.lock().get(&identity(handle)).cloned();
    match channel {
        Some(channel) if { let state = channel.lock(); state.pid == context.process_id && !state.closed } => Ok(channel),
        _ => Err(Failure::Win32(6)),
    }
}

/// Fecha o canal e conclui os controles enfileirados ou em andamento com
/// erro de término de processo.
fn close(channel: &Shared) {
    let handle = {
        let mut state = channel.lock();
        state.closed = true;
        for control in state.queue.drain(..) {
            let mut control = control.lock();
            control.error = Some(1067);
            control.finished = true;
        }
        if let Some(current) = &state.current {
            let mut current = current.lock();
            if !current.finished {
                // No START, o erro vem de dispatchError; nos demais, também o
                // retorno do handler.
                current.error = Some(1067);
                current.finished = true;
            }
        }
        state.handle.clone()
    };
    CHANNELS.lock().remove(&identity(&handle));
}

fn enqueue(channel: &Shared, service: &str, code: u32) -> Control {
    let control = Arc::new(SpinLock::new(ControlRecord { service: String::from(service), code, id: NEXT_CONTROL.fetch_add(1, Ordering::AcqRel), finished: false, error: None, data: Vec::new(), status_handle: None }));
    channel.lock().queue.push_back(control.clone());
    control
}

/// Retira o próximo controle (ou responde o erro), escreve os campos NDR na
/// ordem esperada e lembra qual controle deve ser confirmado.
fn response(channel: Option<&mut Channel>, error: u32) -> Vec<u8> {
    let mut writer = Writer::new();
    let mut channel = channel;
    let control = if error != 0 { None } else { channel.as_mut().and_then(|channel| channel.queue.pop_front()) };
    let (service, code, id) = control.as_ref().map_or((String::new(), 0, 0), |control| {
        let control = control.lock();
        (control.service.clone(), control.code, control.id)
    });
    writer.string(Some(&service), true);
    writer.align(8);
    writer.u32(code).u64(id);
    // Flags, tag de subprocesso, timeout, motivo e a união de argumentos e
    // dados: este lançamento não leva argumentos nem dados de evento externo.
    writer.u32(0).u32(0).u32(30000).u32(0).u32(1).u32(1).pointer(false);
    if let Some(channel) = channel {
        channel.current = control;
    }
    writer.u32(error).finish()
}

struct Exchange {
    channel: Shared,
}

impl Pending for Exchange {
    fn poll(&mut self) -> Result<Option<Vec<u8>>, u32> {
        let mut state = self.channel.lock();
        Ok(if state.closed {
            Some(response(Some(&mut state), 1067))
        } else if !state.queue.is_empty() {
            Some(response(Some(&mut state), 0))
        } else {
            None
        })
    }

    fn cleanup(&mut self) {
        self.channel.lock().waiting = false;
    }
}

fn ndr(result: Result<(), u32>) -> Result<(), Failure> {
    result.map_err(Failure::Rpc)
}

/// Abrir (0), trocar (1) ou fechar (2). A troca confirma o controle
/// anterior e pode devolver uma operação pendente.
pub fn call(context: &RpcContext, operation: u32, bytes: &[u8]) -> Result<Body, u32> {
    ensure_listener();
    let mut reader = Reader::new(bytes);
    let mut handle: Option<Vec<u8>> = None;
    let outcome = (|| -> Result<Option<Body>, Failure> {
        match operation {
            0 => {
                let ansi = reader.u8().map_err(Failure::Rpc)?;
                ndr(reader.end())?;
                if ansi > 1 {
                    return Err(Failure::Win32(87));
                }
                let services = service_database::active_for_process(context.process_id);
                if services.is_empty() {
                    return Err(Failure::Win32(1063));
                }
                if channels().iter().any(|channel| channel.lock().pid == context.process_id) {
                    return Err(Failure::Win32(1056));
                }
                // Contexto de 20 bytes: sequência, processo, assinatura e versão;
                // a tabela local continua a autoridade da posse.
                let created = Writer::new().u32(0).u32(NEXT_CHANNEL.fetch_add(1, Ordering::AcqRel)).u32(context.process_id as u32).u32(0x5343_484E).u32(1).finish();
                let channel = Arc::new(SpinLock::new(Channel { handle: created.clone(), pid: context.process_id, queue: VecDeque::new(), current: None, waiting: false, closed: false }));
                CHANNELS.lock().insert(identity(&created), channel.clone());
                for service in &services {
                    enqueue(&channel, &service.name, 0x51);
                }
                crate::debug_print!("[scm-channel] dispatcher connected pid={}", context.process_id);
                handle = Some(created);
                Ok(None)
            }
            2 => {
                let given = reader.context().map_err(Failure::Rpc)?;
                handle = Some(given.clone());
                ndr(reader.end())?;
                close(&lookup(context, &given)?);
                handle = None;
                Ok(None)
            }
            1 => {
                let channel = lookup(context, &reader.context().map_err(Failure::Rpc)?)?;
                reader.align(8);
                let dispatch_error = reader.u32().map_err(Failure::Rpc)?;
                let control_id = reader.u64().map_err(Failure::Rpc)?;
                let control_error = reader.u32().map_err(Failure::Rpc)?;
                let count = reader.u32().map_err(Failure::Rpc)?;
                let data_pointer = reader.u32().map_err(Failure::Rpc)?;
                let actual = if data_pointer != 0 { reader.u32().map_err(Failure::Rpc)? } else { 0 };
                // A contagem declarada e a conformante do NDR antes de capturar
                // o array de palavras de 32 bits.
                if count != actual || count > 32768 {
                    return Err(Failure::Rpc(ndr::FAULT));
                }
                let data = reader.raw(count as usize * 4).map_err(Failure::Rpc)?;
                ndr(reader.end())?;
                let mut state = channel.lock();
                if state.waiting {
                    return Err(Failure::Win32(170));
                }
                if let Some(current) = state.current.clone() {
                    let (service, code, error) = {
                        let mut control = current.lock();
                        if control.id != control_id {
                            return Err(Failure::Win32(87));
                        }
                        let error = if control.code == 0x51 || dispatch_error != 0 { dispatch_error } else { control_error };
                        control.error = Some(error);
                        control.data = data;
                        control.finished = true;
                        (control.service.clone(), control.code, error)
                    };
                    if code == 0x51 && error != 0 {
                        drop(state);
                        let _ = service_database::report_status(&service, context.process_id, &ReportedStatus { current_state: 1, controls_accepted: 0, win32_exit_code: error, service_specific_exit_code: 0, checkpoint: 0, wait_hint: 0 });
                        state = channel.lock();
                    }
                    state.current = None;
                } else if control_id != 0 {
                    return Err(Failure::Win32(87));
                }
                if !state.queue.is_empty() {
                    return Ok(Some(Body::Now(response(Some(&mut state), 0))));
                }
                // Só uma troca pendente por canal: a consulta não inventa
                // resposta com a fila vazia e o cleanup tira a marca.
                state.waiting = true;
                drop(state);
                Ok(Some(Body::Later(Box::new(Exchange { channel }))))
            }
            _ => Err(Failure::Rpc(1745)),
        }
    })();
    match outcome {
        Ok(Some(body)) => Ok(body),
        Ok(None) => Ok(Body::Now(Writer::new().context(handle.as_deref()).u32(0).finish())),
        Err(Failure::Rpc(status)) => Err(status),
        Err(Failure::Win32(code)) if operation == 1 => Ok(Body::Now(response(None, code))),
        Err(Failure::Win32(code)) => Ok(Body::Now(Writer::new().context(handle.as_deref()).u32(code).finish())),
    }
}

/// Exige serviço fora de parado ou transição e o canal vivo do seu processo.
pub fn control(service: &str, code: u32) -> Result<Control, Failure> {
    ensure_listener();
    let status = service_database::status(service).map_err(|error| match error {
        ServiceError::Win32(code, _) => Failure::Win32(code),
        ServiceError::Kernel(_) => Failure::Rpc(1726),
    })?;
    if status.current_state == 1 {
        return Err(Failure::Win32(1062));
    }
    if status.current_state == 2 || status.current_state == 3 {
        return Err(Failure::Win32(1061));
    }
    let channel = channels().into_iter().find(|channel| {
        let state = channel.lock();
        state.pid == status.process_id && !state.closed
    });
    let Some(channel) = channel else { return Err(Failure::Win32(1061)) };
    Ok(enqueue(&channel, service, code))
}

/// Fecha os canais do processo terminado.
pub fn release_process(process_id: u64) {
    for channel in channels() {
        if channel.lock().pid == process_id {
            close(&channel);
        }
    }
}

/// O handle de relatório de status fica preso ao START entregue, ao nome do
/// serviço, ao id do controle e ao processo autorizado.
pub fn authorize_status_handle(context: &RpcContext, service: &str, control_id: u64) -> Result<Control, Failure> {
    let channel = channels().into_iter().find(|channel| {
        let state = channel.lock();
        state.pid == context.process_id && !state.closed
    });
    let control = channel.and_then(|channel| channel.lock().current.clone());
    let authorized = control.as_ref().is_some_and(|control| {
        let record = control.lock();
        record.code == 0x51 && record.id == control_id && record.service.to_lowercase() == service.to_lowercase()
    }) && service_database::status(service).is_ok_and(|status| status.process_id == context.process_id);
    match control {
        Some(control) if authorized => Ok(control),
        _ => Err(Failure::Win32(5)),
    }
}

/// O último serviço do processo em STOPPED enfileira o encerramento do
/// dispatcher.
fn on_status_change(_service: &str, process_id: u64, status: &ServiceStatus) {
    if status.current_state != 1 || !service_database::active_for_process(process_id).is_empty() {
        return;
    }
    let channel = channels().into_iter().find(|channel| {
        let state = channel.lock();
        state.pid == process_id && !state.closed
    });
    if let Some(channel) = channel {
        enqueue(&channel, "", 0x20);
    }
}

/// O original registra o ouvinte ao carregar o módulo.
fn ensure_listener() {
    if !LISTENING.swap(true, Ordering::AcqRel) {
        service_database::on_status_change(Arc::new(on_status_change));
    }
}

pub fn init() {
    ensure_listener();
}
