//! Portas ALPC/LPC de modo usuário.
//!
//! O transporte de mensagens: respostas e notificações na fila da porta,
//! pedidos entregues aos serviços hospedados no kernel, cancelamento,
//! desconexão e o pump dos trabalhos pendentes. As entradas Nt capturam os
//! argumentos com 64 bits; os provedores conservam as sondagens de UserMode.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::threads::{self, Wait};
use super::{events, state};
use crate::ntos::alpc::cancel_message::{self, Selection};
use crate::ntos::alpc::kernel_entry::{self, Completed, Pending};
use crate::ntos::alpc::message::buffer::{self as message_buffer, Buffer};
use crate::ntos::alpc::message::identity::{self as message_identity, Identity};
use crate::ntos::alpc::small::{context_attribute, direct_event, wake_policy};
use crate::ntos::alpc::transport::{JobResult, Message, Reply, Request, RequestState, Sender};
use crate::ntos::alpc::{kernel_wait, legacy_service, port_reference};
use crate::ntos::alpc::message::{handles as message_handles, security as message_security, view as message_view};
use crate::ntos::alpc::resource::{reserves as resource_reserves, services as services};
use crate::ntos::ke::dispatcher;
use crate::ntos::ob::objects::port::{self as port_objects, Port, PortState, Role};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{AlpcDirectAttr, AlpcMessageAttributes, AlpcPortAttributes, AlpcSecurityAttr, AlpcWorkOnBehalfTicket, NtStruct, ObjectAttributes, PortMessage, UnicodeString};

pub use crate::ntos::alpc::transport::register;

const AV: u32 = 0xC000_0005;
const INVALID: u32 = 0xC000_000D;
/// ALPC_PORFLG_WAITABLE_PORT.
const WAITABLE_PORT: u32 = 0x4_0000;

/// Conexões com trabalho de transporte.
static PORTS: SpinLock<Vec<Arc<Port>>> = SpinLock::new(Vec::new());
/// O fallback LPC registra NtAlpcSendWaitReceivePort antes desta camada.
static LPC_SEND_RECEIVE: SpinLock<Option<state::SyscallHandler>> = SpinLock::new(None);

pub(crate) fn add_port(port: &Arc<Port>) {
    let mut ports = PORTS.lock();
    if !ports.iter().any(|candidate| Arc::ptr_eq(candidate, port)) {
        ports.push(port.clone());
    }
}

fn has_port(port: &Arc<Port>) -> bool {
    PORTS.lock().iter().any(|candidate| Arc::ptr_eq(candidate, port))
}

fn remove_port(port: &Arc<Port>) {
    PORTS.lock().retain(|candidate| !Arc::ptr_eq(candidate, port));
}

pub(crate) fn current_sender() -> Sender {
    Sender { process: process::get_current_process_id(), thread: process::get_current_thread_id(), thread_pointer: 0 }
}

/// Uma mensagem entrou na fila da porta: o pacote da IOCP associada ou, sem
/// ela, a liberação do semáforo de uma porta esperável (como no
/// AlpcpCompleteDispatchMessage).
fn notify_completion(port: &Arc<Port>) {
    match port.with(|state| state.completion.clone()) {
        Some(completion) => completion.notify(),
        None => port.signal_waitable(),
    }
}

/// PORT_MESSAGE de resposta: o CID é o do remetente informado ou o atual.
pub fn reply(data: &[u8], message_type: u16, identity: &Identity, sender: Option<Sender>) -> Vec<u8> {
    let mut result = alloc::vec![0u8; 40 + data.len()];
    let total = result.len() as u16;
    result[0..2].copy_from_slice(&(data.len() as u16).to_le_bytes());
    result[2..4].copy_from_slice(&total.to_le_bytes());
    result[4..6].copy_from_slice(&message_type.to_le_bytes());
    let sender = sender.unwrap_or_else(current_sender);
    result[8..16].copy_from_slice(&sender.process.to_le_bytes());
    result[16..24].copy_from_slice(&sender.thread.to_le_bytes());
    result[24..28].copy_from_slice(&identity.identifier.to_le_bytes());
    result[32..36].copy_from_slice(&identity.callback.to_le_bytes());
    result[40..].copy_from_slice(data);
    result
}

fn queue_reply(port: &Arc<Port>, request: &Arc<Request>, result: &JobResult) -> Result<u32, KernelError> {
    let (reserve, legacy_synchronous, synchronous, context) = {
        let state = request.state.lock();
        // O servidor recebeu um datagrama: não existe associação a responder.
        if state.datagram {
            return Ok(0xC000_0702);
        }
        if state.server_disconnected {
            return Ok(0xC000_0037);
        }
        // Um pedido síncrono cancelado não aceita resposta nem notificação tardia.
        if state.canceled {
            return Ok(0xC000_0703);
        }
        // NtReplyPort de um servidor LPC só responde ao vínculo síncrono.
        if state.legacy && !state.synchronous {
            return Ok(0xC000_0022);
        }
        (state.reserve.clone(), state.legacy_synchronous, state.synchronous, state.context)
    };
    if let Some(reserve) = reserve.as_ref().filter(|_| result.status == 0) {
        let status = resource_reserves::ensure_payload(reserve, result.data.len() as u64)?;
        if status != 0 {
            return Ok(status);
        }
    }
    // A resposta substitui os atributos do pedido; os do emissor anterior
    // não são herdados.
    let identity = &request.identity;
    message_identity::clear_attributes(identity);
    // Uma resposta sem RELEASE_MESSAGE é também um pedido: chega como
    // LPC_REQUEST com LPC_CONTINUATION_REQUIRED e o cliente pode respondê-la
    // pelo MessageId dela.
    let continuation = identity.with(|state| {
        state.replied = true;
        core::mem::take(&mut state.continuation)
    }) && result.status == 0;
    let reply_type = if continuation { 0x2001 } else { 2 };
    // O CLIENT_ID da resposta é o de quem respondeu (o servidor), quando o
    // serviço o informa.
    let buffer = if result.status != 0 { None } else { Some(reply(&result.data, reply_type, identity, result.sender)) };
    if let (Some(reserve), Some(buffer)) = (&reserve, &buffer) {
        if buffer.len() as u64 <= resource_reserves::storage_length(reserve) {
            resource_reserves::write(reserve, buffer, 0)?;
        }
    }
    let (direct, release_direct) = {
        let mut state = request.state.lock();
        (state.direct.take(), state.release_direct.take())
    };
    let sequence = if legacy_synchronous { 0 } else { next_port_sequence(port) };
    let message = Message { bytes: buffer, context, reserve, id: request.id, identity: identity.clone(), sequence, status: result.status, sender: Some(current_sender()), synchronous, direct: direct.is_some() };
    identity.with(|state| {
        state.queued = true;
        state.direct = message.direct;
    });
    // Um MessageId reaproveitado por outra mensagem deixa de nomear a resposta
    // antiga.
    port.with(|state| {
        if continuation {
            state.answerable.insert(identity.identifier, identity.callback);
        } else {
            state.answerable.remove(&identity.identifier);
        }
        state.pending.push(message)
    });
    crate::ntos::alpc::kernel_entry::notify_waiters();
    if let Some(event) = direct {
        dispatcher::set_event(event);
        if let Some(release) = release_direct {
            release();
        }
    } else if !synchronous {
        notify_completion(port);
    }
    Ok(0)
}

fn cleanup_job(request: &Request, delivery_status: Option<u32>) {
    let job = {
        let mut state = request.state.lock();
        if state.cleaned {
            return;
        }
        state.cleaned = true;
        state.delivery_status = delivery_status;
        state.job.take()
    };
    if let Some(mut job) = job {
        job.cleanup(delivery_status.unwrap_or(0));
    }
}

fn release_request(port: &Arc<Port>, request: &Arc<Request>, queued: bool) -> Result<(), KernelError> {
    // Uma notificação de cancelamento pode conservar a identidade depois do job.
    let queued = queued || request.state.lock().cancellation_queued;
    cleanup_job(request, None);
    let (direct, release_direct, retained) = {
        let mut state = request.state.lock();
        (state.direct.take(), state.release_direct.take(), core::mem::replace(&mut state.retained, false))
    };
    if direct.is_some() {
        if let Some(release) = release_direct {
            release();
        }
    }
    let result = if queued { Ok(()) } else { message_identity::release(&request.identity) };
    if retained {
        let _ = dispatcher_objects::dereference(port.pointer);
    }
    result
}

/// Converte a mensagem em LPC_CANCELED, mantendo identidade e reserva; as
/// esperas síncronas recebem o status correspondente.
fn cancel_request(port: &Arc<Port>, request: &Arc<Request>) {
    let synchronous = {
        let mut state = request.state.lock();
        if state.disconnected || state.datagram || state.canceled {
            return;
        }
        state.canceled = true;
        state.disconnected = true;
        state.synchronous
    };
    request.identity.with(|state| state.disconnected = true);
    // LPC_CANCELED conserva a identidade, mas libera os atributos: o
    // contexto deixa de ficar DELETE_PENDING.
    message_identity::clear_attributes(&request.identity);
    if !synchronous {
        queue_cancellation(port, request);
    }
}

/// A notificação conserva CID, contexto, reserva e identidade; o job
/// continua do servidor até concluir ou até o fechamento da porta.
fn queue_cancellation(port: &Arc<Port>, request: &Arc<Request>) {
    let identity = &request.identity;
    let (message, direct, release_direct) = {
        let mut state = request.state.lock();
        if state.cancellation_queued {
            return;
        }
        let sequence = next_port_sequence(port);
        let message = Message { bytes: Some(reply(&[], 12, identity, Some(state.sender))), context: state.context, reserve: state.reserve.clone(), id: request.id, identity: identity.clone(), sequence, status: 0, sender: None, synchronous: false, direct: state.direct.is_some() };
        state.cancellation_queued = true;
        (message, state.direct.take(), state.release_direct.take())
    };
    identity.with(|state| {
        state.queued = true;
        state.direct = message.direct;
    });
    port.with(|state| state.pending.push(message));
    crate::ntos::alpc::kernel_entry::notify_waiters();
    if let Some(event) = direct {
        dispatcher::set_event(event);
        if let Some(release) = release_direct {
            release();
        }
    } else {
        notify_completion(port);
    }
}

pub(crate) fn cancel_exchange(port: &Arc<Port>, request: &Arc<Request>, requesting: &Arc<Port>, flags: u32) -> Result<u32, KernelError> {
    let identity = &request.identity;
    let client_side = Arc::ptr_eq(requesting, port) || requesting.with(|state| state.role) == Role::Client;
    let (replied, queued) = identity.with(|state| (state.replied, state.queued));
    let outgoing = if replied { !client_side } else { client_side };
    let status = if outgoing { if queued { 0 } else { 0x4000_002E } } else { 0x103 };
    // TRY_CANCEL só altera um envio ainda na fila ou uma recepção entregue.
    if flags & 1 != 0 && !(if outgoing { queued } else { !queued }) {
        return Ok(status);
    }
    identity.with(|state| state.canceled = true);
    request.state.lock().canceled = true;
    message_identity::clear_attributes(identity);
    // O Windows libera o atributo direto sem sinalizar o evento; nesse caso
    // não publica LPC_CANCELED, e uma resposta enfileirada mantém a sua.
    let (direct, release_direct, synchronous) = {
        let mut state = request.state.lock();
        (state.direct.take(), state.release_direct.take(), state.synchronous)
    };
    let direct_pending = direct.is_some();
    if direct_pending {
        if let Some(release) = release_direct {
            release();
        }
    }
    if replied {
        let found = port.with(|state| {
            let Some(message) = state.pending.iter_mut().find(|candidate| Arc::ptr_eq(&candidate.identity, identity)) else { return false };
            message.bytes = Some(reply(&[], 12, identity, message.sender));
            message.status = 0;
            true
        });
        if !found {
            return Err(KernelError::new("ALPC queued reply lost its cancellation owner"));
        }
    } else if synchronous {
        request.state.lock().cancel_status = Some(0xC000_0701);
    } else if !direct_pending && (!outgoing || flags & 2 != 0) {
        queue_cancellation(port, request);
    }
    Ok(status)
}

fn install_cancellation(port: &Arc<Port>, request: &Arc<Request>) {
    let (port, owner) = (port.clone(), request.clone());
    request.identity.with(|state| state.cancel_requested_by = Some(Arc::new(move |requesting: &Arc<Port>, flags: u32| cancel_exchange(&port, &owner, requesting, flags))));
}

/// A seleção usa a associação real e o token de geração rejeita callbacks
/// antigos; a retenção permite que liberar atributos chame outros provedores.
pub fn cancel_message(port: &Arc<Port>, selection: Selection, flags: u32) -> Result<u32, KernelError> {
    if selection.identifier & 0x8000_0000 != 0 {
        return cancel_resource_reserve(port, selection, flags);
    }
    let resolved = match message_identity::resolve(port, selection.identifier, selection.callback) {
        Ok(resolved) => resolved,
        Err(status) => return Ok(status),
    };
    let identity = message_identity::reference(&resolved)?;
    let result = cancel_selected_message(port, &identity, selection.message_context, flags);
    let _ = message_identity::dereference(&identity, true);
    result
}

fn cancel_selected_message(port: &Arc<Port>, identity: &Arc<Identity>, message_context: u64, flags: u32) -> Result<u32, KernelError> {
    let client_side = Arc::ptr_eq(port, &identity.port) || port.with(|state| state.role) == Role::Client;
    let (client_context, server_context, canceled, disconnected, operation) = identity.with(|state| (state.client_context, state.server_context, state.canceled, state.disconnected, state.cancel_requested_by.clone()));
    // O bit 8 ativa a comparação do contexto opaco; PortContext e Sequence
    // não participam da decisão.
    if flags & 8 != 0 && message_context != if client_side { client_context } else { server_context } {
        return Ok(0xC000_0719);
    }
    if canceled || disconnected {
        return Ok(0xC000_0703);
    }
    let Some(operation) = operation else { return Err(KernelError::new("ALPC live message has no cancellation operation")) };
    identity.port.run(|| operation(port, flags))
}

/// O identificador com bit alto seleciona a reserva: a aquisição
/// materializa uma geração no slot reservado, ocupada até o cliente receber
/// a notificação, mesmo depois de excluir o handle.
fn cancel_resource_reserve(port: &Arc<Port>, selection: Selection, flags: u32) -> Result<u32, KernelError> {
    let Some(reserve) = resource_reserves::find(port, selection.identifier) else { return Ok(0xC000_02F0) };
    if reserve.state.lock().busy {
        return Ok(0xC000_0708);
    }
    let Some(identity) = message_identity::activate(port, Some(reserve.slot.clone()))? else { return Ok(0xC000_009A) };
    // Uma reserva nunca enviada ainda não tem ClientId de emissor.
    let request = Arc::new(Request { id: identity.identifier, identity: identity.clone(), state: SpinLock::new(RequestState { reserve: Some(reserve), ..RequestState::default() }) });
    install_cancellation(port, &request);
    let result = cancel_selected_message(port, &identity, selection.message_context, flags);
    if !request.state.lock().cancellation_queued {
        message_identity::release(&identity)?;
    }
    result
}

/// Os serviços internos representam pedidos já entregues; o vínculo da
/// comunicação observa o fechamento de um endpoint par.
pub fn disconnect_transport(connection: &Arc<Port>, endpoint: &Arc<Port>, closing: bool) {
    let jobs = connection.with(|state| state.jobs.clone());
    if Arc::ptr_eq(endpoint, connection) {
        for request in &jobs {
            cancel_request(connection, request);
        }
        return;
    }
    let to_connection = connection.with(|state| {
        state.peer_disconnected = true;
        state.connection_port.as_ref().is_some_and(|connection_port| Arc::ptr_eq(connection_port, endpoint))
    });
    if to_connection {
        return;
    }
    for request in &jobs {
        request.state.lock().server_disconnected = true;
    }
    // As respostas na fila foram emitidas pelo endpoint desconectado; o
    // cancelamento preserva o CID original.
    connection.with(|state| {
        for message in state.pending.iter_mut() {
            if message.identity.with(|identity| core::mem::replace(&mut identity.disconnected, true)) {
                continue;
            }
            message.bytes = Some(reply(&[], 12, &message.identity, message.sender));
            message.status = 0;
        }
    });
    if !closing {
        return;
    }
    let skip = endpoint.with(|state| state.skip_pending_flush);
    for request in &jobs {
        // SKIP_PENDING_FLUSH conserva pedidos entregues.
        let delivered = request.state.lock().delivered;
        if !skip || !delivered {
            cancel_request(connection, request);
        }
        request.state.lock().peer_unavailable = true;
    }
}

/// A conexão (inclusive LPC) possui todas as mensagens e libera o
/// transporte ao fechar.
pub fn cleanup_transport(connection: &Arc<Port>) {
    remove_port(connection);
    let pending = connection.with(|state| core::mem::take(&mut state.pending));
    for message in pending {
        let _ = message_identity::release(&message.identity);
    }
    let requests = connection.with(|state| core::mem::take(&mut state.jobs));
    for request in requests {
        let _ = release_request(connection, &request, false);
    }
    let _ = resource_reserves::close_owner(connection);
    connection.with(|state| state.received_views.clear());
}

fn pump_port(port: &Arc<Port>) -> Result<(), KernelError> {
    for request in port.with(|state| state.jobs.clone()) {
        if port.with(|state| state.closing) {
            break;
        }
        let job = {
            let mut state = request.state.lock();
            if state.peer_unavailable || state.polling {
                continue;
            }
            state.polling = true;
            state.job.take()
        };
        let live = port.with(|state| state.jobs.iter().any(|candidate| Arc::ptr_eq(candidate, &request)));
        let Some(mut job) = job.filter(|_| live) else {
            request.state.lock().polling = false;
            continue;
        };
        let result = job.poll();
        {
            let mut state = request.state.lock();
            state.polling = false;
            if !state.cleaned {
                state.job = Some(job);
            }
        }
        if port.with(|state| state.closing) {
            break;
        }
        let Some(result) = result else { continue };
        port.with(|state| state.jobs.retain(|candidate| !Arc::ptr_eq(candidate, &request)));
        let mut queued = false;
        let mut awaiting_peer_close = false;
        if !port.with(|state| state.closing) {
            let delivery = queue_reply(port, &request, &result)?;
            queued = delivery == 0;
            cleanup_job(&request, Some(delivery));
            if delivery == 0xC000_0037 && request.state.lock().server_disconnected {
                // O envio rejeitado não apaga o pedido ainda pendente no par.
                request.state.lock().peer_unavailable = true;
                port.with(|state| state.jobs.push(request.clone()));
                crate::ntos::alpc::kernel_entry::notify_waiters();
                awaiting_peer_close = true;
            }
        }
        if !awaiting_peer_close {
            release_request(port, &request, queued)?;
        }
    }
    Ok(())
}

pub fn pump() {
    crate::ntos::alpc::connect::port::pump();
    let ports = PORTS.lock().clone();
    for port in ports {
        if let Err(error) = port.run(|| pump_port(&port)) {
            crate::debug_print!("[alpc] pump: {}", error);
        }
    }
}

/// Endereço de um atributo no buffer, pelo tamanho de cada atributo alocado
/// (AlpcGetHeaderSize da ntdll, com o slot reservado de 24 bytes).
pub fn attribute_address(pointer: u64, requested: u32) -> u64 {
    // ALPC_MESSAGE_ATTRIBUTES (de usuário ou de kernel, conforme o modo):
    // uma falha de sonda não designa atributo algum.
    let Ok(allocated) = message_attributes(pointer).and_then(|attributes| attributes.allocated_attributes.probe_get()) else { return 0 };
    let mut at = pointer + AlpcMessageAttributes::SIZE;
    for (flag, size) in [(0x8000_0000u32, 24u64), (0x4000_0000, 32), (0x2000_0000, 32), (0x1000_0000, 24), (0x0800_0000, 24), (0x0400_0000, 8), (0x0200_0000, 8)] {
        if flag == requested {
            return at;
        }
        if allocated & flag != 0 {
            at += size;
        }
    }
    0
}

fn context_attribute(pointer: u64) -> u64 {
    attribute_address(pointer, 0x2000_0000)
}

/// O cabeçalho ALPC_MESSAGE_ATTRIBUTES; os acessos são sondados porque o
/// buffer pode ser de usuário.
fn message_attributes(pointer: u64) -> Result<&'static AlpcMessageAttributes, KernelError> {
    state::user_struct::<AlpcMessageAttributes>(pointer)
}

pub fn attributes(pointer: u64, input: bool, mode: u8) -> u32 {
    if pointer == 0 {
        return 0;
    }
    if !(if input { message_buffer::accessible(pointer, 8, mode, false) } else { message_buffer::writable(pointer, 8, mode) }) {
        return AV;
    }
    let header = message_attributes(pointer).and_then(|header| Ok((header.allocated_attributes.probe_get()?, header.valid_attributes.probe_get()?)));
    let Ok((allocated, valid)) = header else { return AV };
    if input && valid & !allocated != 0 {
        return INVALID;
    }
    if input && valid & !0xF600_0000 != 0 {
        crate::debug_print!("[alpc] send attributes=0x{:x}", valid);
        return 0xC000_00BB;
    }
    if input && valid & 0x8000_0000 != 0 {
        let at = attribute_address(pointer, 0x8000_0000);
        if !message_buffer::accessible(at, 24, mode, false) {
            return AV;
        }
        let Ok(quality) = state::user_struct::<AlpcSecurityAttr>(at).and_then(|security| security.p_qos.probe_get()) else { return AV };
        if quality != 0 && !message_buffer::accessible(quality, 12, mode, false) {
            return AV;
        }
    }
    if input && valid & 0x0400_0000 != 0 && !message_buffer::accessible(attribute_address(pointer, 0x0400_0000), 8, mode, false) {
        return AV;
    }
    if input && valid & message_view::VIEW_ATTRIBUTE != 0 && !message_buffer::accessible(attribute_address(pointer, message_view::VIEW_ATTRIBUTE), 32, mode, false) {
        return AV;
    }
    if (if input { valid } else { allocated }) & 0x2000_0000 != 0 {
        let at = context_attribute(pointer);
        if !(if input { message_buffer::accessible(at, 32, mode, false) } else { message_buffer::writable(at, 32, mode) }) {
            return AV;
        }
    }
    // O bit de envio 0x02000000 pede a captura da thread de kernel atual;
    // o Ticket do chamador não é entrada e, sem trabalho delegado, nenhum
    // atributo de recepção é publicado.
    if input && valid & 0x0200_0000 != 0 && !message_buffer::accessible(attribute_address(pointer, 0x0200_0000), 8, mode, false) {
        return AV;
    }
    0
}

/// A próxima sequência de entrega da porta: lida, incrementada e gravada
/// sob a mesma trava (dois emissores nunca recebem o mesmo número).
fn next_port_sequence(port: &Port) -> u32 {
    port.with(|state| {
        let sequence = message_identity::next_sequence(state.message_sequence);
        state.message_sequence = sequence;
        port.set_sequence(sequence);
        sequence
    })
}

/// A mensagem nova que um servidor de modo usuário manda à porta de um
/// cliente (o callback, `alpc/server.rs`): uma identidade na porta do
/// cliente dá o MessageId e o CallbackId, `register` recebe o MessageId
/// antes de a mensagem entrar na fila (a resposta do cliente pode vir logo),
/// e a mensagem fica entre as pendentes, com a sequência da porta do cliente,
/// a IOCP dele avisada. Devolve o MessageId, ou
/// STATUS_INSUFFICIENT_RESOURCES sem identidade.
pub(crate) fn post_server_message(port: &Arc<Port>, message_type: u16, data: &[u8], sender: Sender, register: impl FnOnce(u32)) -> Result<Result<u32, u32>, KernelError> {
    let Some(identity) = message_identity::activate(port, None)? else { return Ok(Err(0xC000_009A)) };
    let identifier = identity.identifier;
    register(identifier);
    let sequence = next_port_sequence(port);
    let message = Message { bytes: Some(reply(data, message_type, &identity, Some(sender))), context: 0, reserve: None, id: identifier, identity: identity.clone(), sequence, status: 0, sender: Some(sender), synchronous: false, direct: false };
    identity.with(|state| state.queued = true);
    port.with(|state| state.pending.push(message));
    crate::ntos::alpc::kernel_entry::notify_waiters();
    notify_completion(port);
    Ok(Ok(identifier))
}

/// Publica o ALPC_CONTEXT_ATTR e o ValidAttributes da recepção; uma falha
/// de sonda devolve ACCESS_VIOLATION.
pub fn try_publish_attributes(pointer: u64, port: &Port, context: u64, sequence: u32, identity: &Identity) -> Result<(), u32> {
    if pointer == 0 {
        return Ok(());
    }
    let header = message_attributes(pointer).map_err(|error| error.status)?;
    let allocated = header.allocated_attributes.probe_get().map_err(|error| error.status)? & 0x2000_0000;
    let port_context = port.with(|state| state.port_context);
    if allocated != 0 {
        context_attribute::try_write(context_attribute(pointer), port_context, context, sequence, identity.identifier, identity.callback)?;
    }
    header.valid_attributes.probe_set(if port_context != 0 { allocated } else { 0 }).map_err(|error| error.status)
}

/// Como [`try_publish_attributes`], para quem já validou o buffer: uma falha
/// de sonda só perde a publicação.
pub fn publish_attributes(pointer: u64, port: &Port, context: u64, sequence: u32, identity: &Identity) {
    let _ = try_publish_attributes(pointer, port, context, sequence, identity);
}

fn capture(address: u64, maximum: u32) -> Result<Vec<u8>, u32> {
    if !state::probe_user_read(address, PortMessage::SIZE) {
        return Err(AV);
    }
    let header = state::user_struct::<PortMessage>(address).and_then(|message| Ok((message.u1.s1.total_length.probe_get()? as u16 as u32, message.u1.s1.data_length.probe_get()? as u16 as u32, message.u2.s2.data_info_offset.probe_get()?)));
    let (size, data_size, data_info_offset) = header.map_err(|error| error.status)?;
    let header_size = PortMessage::SIZE as u32;
    if size < header_size || size > maximum || data_size != size - header_size || data_info_offset != 0 {
        return Err(0xC000_0021);
    }
    if !state::probe_user_read(address, size as u64) {
        return Err(AV);
    }
    // A carga depois do cabeçalho, numa cópia sondada.
    guest::try_read_bytes(address + PortMessage::SIZE, data_size as usize).map_err(|error| error.status)
}

/// O AlpcpCheckConnectionSecurity da conexão de modo usuário: o
/// RequiredServerSid do NtAlpcConnectPort (capturado como no SeCaptureSid) ou
/// o ServerSecurityRequirements do NtAlpcConnectPortEx (capturado como no
/// SeCaptureSecurityDescriptor), conferidos com o token primário do processo
/// dono da porta de conexão (o System, nos serviços hospedados no kernel).
fn check_server_security(pointer: u64, required_sid: bool, server_process: u64) -> u32 {
    if pointer == 0 {
        return 0;
    }
    let checked = if required_sid {
        crate::ntos::alpc::connect::capture::identifier(pointer, 1).and_then(|sid| match sid {
            Some(sid) => crate::ntos::alpc::connect::capture::check_server_sid(server_process, &sid),
            None => Ok(()),
        })
    } else {
        crate::ntos::ob::object_security::capture_descriptor(pointer, true).and_then(|descriptor| match descriptor {
            Some(descriptor) => crate::ntos::alpc::connect::capture::check_server_descriptor(server_process, &descriptor),
            None => Ok(()),
        })
    };
    checked.err().unwrap_or(0)
}

fn nt_alpc_connect_port(out: u64, name: u64, oa: u64, port_attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    state::guarded(|| connect_port(out, name, oa, port_attributes, rsp, true))
}

/// NtAlpcConnectPortEx(PortHandle*, ConnectionPortObjectAttributes,
/// ClientPortObjectAttributes, PortAttributes, Flags,
/// ServerSecurityRequirements, ConnectionMessage, BufferLength,
/// OutMessageAttributes, InMessageAttributes, Timeout): a mesma conexão do
/// NtAlpcConnectPort, com o nome da porta no OBJECT_ATTRIBUTES (sem
/// RootDirectory) e, no lugar do SID exigido, o SECURITY_DESCRIPTOR que o
/// token do processo dono da porta deve satisfazer.
fn nt_alpc_connect_port_ex(out: u64, connection: u64, oa: u64, port_attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    state::guarded(|| {
        if !state::probe_user_read(connection, ObjectAttributes::SIZE) {
            return Ok(AV);
        }
        let attributes = state::user_struct::<ObjectAttributes>(connection)?;
        if attributes.root_directory.probe_get()? != 0 {
            return Ok(INVALID);
        }
        let name = attributes.object_name.probe_get()?;
        if name == 0 {
            return Ok(0xC000_0033);
        }
        connect_port(out, name, oa, port_attributes, rsp, false)
    })
}

fn connect_port(out: u64, name: u64, oa: u64, port_attributes: u64, rsp: u64, required_sid: bool) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) || !state::probe_user_read(name, UnicodeString::SIZE) || !state::probe_syscall_stack(rsp, 56) || (oa != 0 && !state::probe_user_read(oa, ObjectAttributes::SIZE)) || (port_attributes != 0 && !state::probe_user_read(port_attributes, AlpcPortAttributes::SIZE)) {
        return Ok(AV);
    }
    let port_name = state::user_struct::<UnicodeString>(name)?;
    let name_length = port_name.length.probe_get()? as u64;
    let name_buffer = port_name.buffer.probe_get()?;
    if name_length == 0 || name_length % 2 != 0 || name_length > 1024 {
        return Ok(INVALID);
    }
    if !state::probe_user_read(name_buffer, name_length) {
        return Ok(AV);
    }
    let path = state::try_read_user_wide_string(name_buffer, name_length / 2)?;
    let Some(node) = object_manager::lookup(&path) else { return Ok(0xC000_0034) };
    if object_manager::node(node).is_none_or(|record| record.type_name != "AlpcPort") {
        return Ok(0xC000_0024);
    }
    let Some(listener) = crate::ntos::alpc::transport::listener_of(node) else { return Ok(0xC000_0042) };
    if let Err(status) = crate::ntos::alpc::server::check_connect_access(node, &path) {
        return Ok(status);
    }
    let flags = state::stack_arg32(rsp, 5);
    let message = state::stack_arg(rsp, 7);
    let length = state::stack_arg(rsp, 8);
    let send_attributes = state::stack_arg(rsp, 9);
    let receive_attributes = state::stack_arg(rsp, 10);
    if flags & !0x2_0000 != 0 {
        return Ok(0xC000_00BB);
    }
    let mut status = check_server_security(state::stack_arg(rsp, 6), required_sid, listener.process);
    if status == 0 {
        status = attributes(send_attributes, true, 1);
    }
    if status == 0 {
        status = attributes(receive_attributes, false, 1);
    }
    if status != 0 {
        return Ok(status);
    }
    if message != 0 && (length == 0 || !state::probe_user_write(length, 8)) {
        return Ok(AV);
    }
    let service = listener.service.clone();
    // AlpcpValidateAndSetPortAttributes de uma porta de cliente: o
    // MaxMessageLength pedido (de 0x28 a 0xFFFF, senão
    // STATUS_INVALID_PARAMETER) limitado ao da porta de conexão; sem
    // ALPC_PORT_ATTRIBUTES, 0x200, também limitado. É o máximo das
    // mensagens da porta, a de conexão inclusive (o TerminalServerRequestThread
    // do csrss pede 0x4070 à \SmSsWinStationApiPort do lsm.dll, que tem
    // 0x4070).
    let listener_maximum = service.max_message_length();
    let maximum = if port_attributes != 0 {
        let requested = state::user_struct::<AlpcPortAttributes>(port_attributes)?.max_message_length.probe_get()?;
        if !(0x28..=0xFFFF).contains(&requested) {
            return Ok(INVALID);
        }
        (requested as u32).min(listener_maximum)
    } else {
        listener_maximum.min(0x200)
    };
    let data = if message != 0 {
        match capture(message, maximum) {
            Ok(data) => data,
            Err(status) => return Ok(status),
        }
    } else {
        Vec::new()
    };
    // SIZE_T *BufferLength (entrada e saída, sondado acima).
    let capacity = if message != 0 { guest::try_read::<u64>(length)? } else { 0 };
    if capacity > 0x1_0000 {
        return Ok(INVALID);
    }
    if message != 0 && !state::probe_user_write(message, capacity) {
        return Ok(AV);
    }
    // ALPC_PORT_ATTRIBUTES opcional: Flags, SecurityQos, MaxViewSize e
    // DupObjectTypes capturados uma vez. Sem ele, os atributos padrão do
    // AlpcpValidateAndSetPortAttributes de uma porta de cliente:
    // ALLOW_IMPERSONATION e o QOS anônimo, dinâmico e só efetivo.
    let (port_flags, duplicate_object_types, maximum_view_size, quality) = if port_attributes != 0 {
        let attributes = state::user_struct::<AlpcPortAttributes>(port_attributes)?;
        let qos = &attributes.security_qos;
        let quality = crate::ntos::alpc::security_contexts::Quality { level: qos.impersonation_level.probe_get()?.0 as u32, tracking: qos.context_tracking_mode.probe_get()?, effective_only: qos.effective_only.probe_get()? != 0 };
        let flags = attributes.flags.probe_get()?;
        if flags & 0x10_0000 != 0 || quality.tracking > 1 {
            return Ok(INVALID);
        }
        if quality.level > 3 {
            return Ok(0xC000_00A5);
        }
        (flags & 0x03FF_0000, attributes.dup_object_types.probe_get()?, attributes.max_view_size.probe_get()?, quality)
    } else {
        (0x1_0000, 0, 0, crate::ntos::alpc::security_contexts::Quality { level: 0, tracking: 1, effective_only: true })
    };
    // AlpcpCreateClientPort: com rastreamento estático, o contexto do
    // cliente capturado agora (a impersonação sem atributo de segurança usa
    // este, não o token da thread no momento do pedido).
    let connected = if quality.tracking == 0 {
        match crate::ntos::alpc::message::security::capture_client(process::get_current_thread(), &quality)? {
            Ok(identity) => Some(identity),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let initial = PortState {
        service: Some(service.clone()),
        service_process: process::get_system_process(),
        // A sequência conta entregas nesta porta; mesmo sem carga, a
        // conclusão da conexão é a entrega 1.
        message_sequence: 1,
        port_context: 0,
        role: Role::Client,
        port_flags,
        duplicate_object_types,
        maximum_view_size,
        on_disconnect: Some(disconnect_transport),
        security_quality: Some(quality),
        client_security: connected.clone(),
        ..PortState::default()
    };
    let disconnecting = service.clone();
    let port = match port_objects::create(
        "alpc",
        initial,
        maximum,
        1,
        oa,
        Box::new(move |connection| {
            cleanup_transport(connection);
            if let Some(client) = connection.with(|state| state.client_security.take()) {
                let _ = client.release();
            }
            if connection.started() {
                disconnecting.disconnect(connection);
            }
        }),
        port_objects::CreateOptions::default(),
    ) {
        Ok(port) => port,
        Err(error) => {
            if let Some(connected) = &connected {
                let _ = connected.release();
            }
            return if error.status != 0 { Ok(error.status) } else { Err(error) };
        }
    };
    // AlpcpCreateClientPort: com ALPC_PORFLG_WAITABLE_PORT a porta do cliente
    // tem o semáforo em que a espera pelo handle dela fica (o CoreMessaging
    // espera assim as mensagens do registrador).
    if port_flags & WAITABLE_PORT != 0 && !port.make_waitable() {
        dispatcher_objects::collect(port.pointer);
        return Ok(0xC000_009A);
    }
    let result = port.run(|| -> Result<u32, KernelError> {
        port.set_started(true);
        let result = match service.connect(&port, &data, None) {
            Reply::Now(result) => result,
            Reply::Later(_) => return Err(KernelError::new("ALPC service deferred a direct connection")),
        };
        if port.closed() {
            return Ok(0xC000_0037);
        }
        if result.status != 0 {
            return Ok(result.status);
        }
        let mut connection_identity = None;
        if message != 0 {
            let Some(identity) = message_identity::activate(&port, None)? else { return Ok(0xC000_009A) };
            let bytes = reply(&result.data, 10, &identity, None);
            // A resposta de conexão é entregue nesta chamada; não fica na
            // tabela de mensagens.
            message_identity::release(&identity)?;
            connection_identity = Some(identity);
            guest::try_write::<u64>(length, bytes.len() as u64)?;
            if bytes.len() as u64 > capacity {
                return Ok(0xC000_0023);
            }
            state::write_user_bytes(message, &bytes)?;
        }
        if message == 0 && receive_attributes != 0 {
            message_attributes(receive_attributes)?.valid_attributes.probe_set(0)?;
        }
        let object_flags = if oa != 0 { state::user_struct::<ObjectAttributes>(oa)?.attributes.probe_get()? } else { 0 };
        let status = port_objects::publish(&port, out, object_flags)?;
        if status != 0 {
            return Ok(status);
        }
        // O PortHandle publicado acima (lido de volta da saída sondada).
        let handle = guest::try_read::<u64>(out)?;
        port.with(|state| state.port_context = handle);
        if let Some(identity) = &connection_identity {
            if let Err(status) = try_publish_attributes(receive_attributes, &port, 0, 1, identity) {
                return Ok(status);
            }
        }
        add_port(&port);
        crate::debug_print!("[alpc] conectado {} pid={}", path, port.process_id());
        Ok(0)
    });
    dispatcher_objects::collect(port.pointer);
    match result {
        Err(error) if error.status != 0 => Ok(error.status),
        other => other,
    }
}

/// Argumentos de recepção da troca.
#[derive(Clone, Copy)]
pub struct ReceiveArguments {
    pub output: u64,
    pub length: u64,
    pub receive_attributes: u64,
    pub timeout: u64,
}

/// Resultado imediato ou a espera de kernel retomável.
pub enum Exchange {
    Status(u32),
    Wait(kernel_wait::Request),
}

/// Envia um pedido ao serviço; devolve o pedido síncrono, quando houver.
fn send(port: &Arc<Port>, flags: u32, input: u64, send_attributes: u64, mode: u8, legacy: bool, legacy_synchronous: bool) -> Result<Result<Option<Arc<Request>>, u32>, KernelError> {
    if port.with(|state| state.pending.len() + state.jobs.len()) >= 256 {
        return Ok(Err(0xC000_0044));
    }
    // ValidAttributes do OutMessageAttributes (validado por `attributes`).
    let valid = if send_attributes != 0 {
        match message_attributes(send_attributes).and_then(|header| header.valid_attributes.probe_get()) {
            Ok(valid) => valid,
            Err(_) => return Ok(Err(AV)),
        }
    } else {
        0
    };
    let context_address = if valid & 0x2000_0000 != 0 { context_attribute(send_attributes) } else { 0 };
    // OutMessageAttributes é entrada/saída: o emissor conserva o
    // MessageContext opaco e recebe a identidade atribuída pelo kernel.
    if context_address != 0 && !message_buffer::writable(context_address, 32, mode) {
        return Ok(Err(AV));
    }
    // Uma porta LPC (ALPC_PORFLG_LPC_MODE) aceita TotalLength maior que o
    // necessário (AlpcpValidateMessage do modo LPC).
    let lpc_port = port.with(|state| state.port_flags) & crate::ntos::alpc::server::LPC_MODE != 0;
    let captured = match message_buffer::capture_message_with(input, port.maximum(), mode, lpc_port) {
        Ok(captured) => captured,
        Err(status) => return Ok(Err(status)),
    };
    let header = &captured.header;
    // Numa porta LPC, Type 0 é um pedido novo, como no AlpcpSendMessage: o
    // MessageId e o CLIENT_ID que o buffer traz (a resposta anterior, num
    // buffer reaproveitado pelo CsrClientCallServer) não contam.
    let lpc_request = lpc_port && header[4] == 0;
    let reserve_id = if lpc_request { 0 } else { u32::from_le_bytes([header[24], header[25], header[26], header[27]]) };
    // O MessageId de uma resposta que o servidor mandou sem RELEASE_MESSAGE
    // responde a ela (o AlpcpLookupMessage acha a mensagem pendente no
    // cliente, com o CallbackId dela quando o cabeçalho traz um): o envio
    // segue ao servidor como um pedido novo, LPC_REPLY com RELEASE_MESSAGE, e
    // o CLIENT_ID que o buffer reaproveitado traz não conta (o winsrvext do
    // csrss reenvia assim a resposta do lsm.dll, com o próprio CLIENT_ID).
    let callback = u32::from_le_bytes([header[32], header[33], header[34], header[35]]);
    let answer = !lpc_port
        && !legacy
        && reserve_id != 0
        && reserve_id & 0x8000_0000 == 0
        && port.with(|state| match state.answerable.get(&reserve_id) {
            Some(&held) if callback == 0 || callback == held => state.answerable.remove(&reserve_id).is_some(),
            _ => false,
        });
    let reserve_id = if answer { 0 } else { reserve_id };
    // IDs positivos designam associações de mensagem: esta ponta de cliente
    // não tem pedido de servidor correspondente. Reservas têm o bit alto. O
    // reenvio de uma resposta recebida com o atributo de vista UNMAP_EXISTING
    // solta a vista que ela trouxe (o DropMsgAttributes do RPC).
    if reserve_id != 0 && reserve_id & 0x8000_0000 == 0 {
        if valid & message_view::VIEW_ATTRIBUTE != 0 && flags & 0x3_0000 == 0 {
            if let Some(status) = message_view::release_received(port, reserve_id, attribute_address(send_attributes, message_view::VIEW_ATTRIBUTE), mode)? {
                return Ok(if status == 0 { Ok(None) } else { Err(status) });
            }
        }
        // A resposta a uma mensagem que o servidor mandou a esta porta (o
        // callback): volta a quem a mandou.
        if flags & 0x2_0000 == 0 {
            if let Some(status) = crate::ntos::alpc::server::reply_from_client(port, reserve_id, captured.data.clone()) {
                return Ok(if status == 0 { Ok(None) } else { Err(status) });
            }
        }
        return Ok(Err(0xC000_0702));
    }
    let cid_present = header[8..24].iter().any(|&byte| byte != 0);
    if !legacy_synchronous && !lpc_request && !answer && reserve_id == 0 && cid_present {
        return Ok(Err(0xC000_0702));
    }
    let reserve = if reserve_id != 0 { resource_reserves::find(port, reserve_id) } else { None };
    if reserve_id != 0 && reserve.is_none() {
        return Ok(Err(0xC000_02F0));
    }
    if let Some(reserve) = &reserve {
        if reserve.state.lock().busy {
            return Ok(Err(0xC000_0708));
        }
        let status = resource_reserves::ensure_payload(reserve, captured.data.len() as u64)?;
        if status != 0 {
            return Ok(Err(status));
        }
    }
    let datagram = flags & 0x1_0000 != 0;
    if flags & 0x80_0000 != 0 {
        // A porta identifica o System como dono do serviço; a cobrança do
        // processo receptor não é omitida.
        let status = wake_policy::check_system_service(port.with(|state| state.service_process), flags, datagram);
        if status != 0 {
            return Ok(Err(status));
        }
    }
    if let Some(reserve) = &reserve {
        // Ao receber o datagrama, o servidor passa a ter a sua cópia; a
        // reserva de envio pode ser reutilizada.
        resource_reserves::write(reserve, &captured.data, 40)?;
    }
    let Some(identity) = message_identity::activate(port, reserve.as_ref().map(|reserve| reserve.slot.clone()))? else { return Ok(Err(0xC000_009A)) };
    let synchronous = flags & 0x2_0000 != 0;
    // Os bits altos do Type que a mensagem conserva (AlpcpSendMessage): o
    // LPC_KERNELMODE_MESSAGE só de quem envia em KernelMode.
    let type_bits = u16::from_le_bytes([header[4], header[5]]) & if mode == 0 { 0xEF00 } else { 0x6F00 };
    let request = Arc::new(Request { id: identity.identifier, identity: identity.clone(), state: SpinLock::new(RequestState { reserve: reserve.clone(), datagram, synchronous, legacy, legacy_synchronous, sender: current_sender(), answer, type_bits, attributes: valid, ..RequestState::default() }) });
    install_cancellation(port, &request);
    let mut stored = false;
    let mut deferred = false;
    let outcome = (|| -> Result<Result<(), u32>, KernelError> {
        let thread = process::get_current_thread();
        identity.with(|state| state.sender_thread = thread);
        if port.with(|state| state.security_quality).is_some_and(|quality| quality.tracking != 0) {
            process::reference_thread(thread);
            identity.with(|state| {
                state.release_sender = Some(Box::new(move || {
                    let _ = process::dereference_thread(thread);
                }))
            });
        }
        if valid & 0x8000_0000 != 0 {
            match message_security::capture(port, attribute_address(send_attributes, 0x8000_0000), mode)? {
                Err(status) => return Ok(Err(status)),
                Ok(message_security::Captured::Empty) => {}
                Ok(message_security::Captured::Borrowed(borrowed)) => identity.with(|state| state.security = Some(borrowed)),
            }
        }
        if valid & 0x1000_0000 != 0 {
            match message_handles::capture(attribute_address(send_attributes, 0x1000_0000), mode)? {
                Err(status) => return Ok(Err(status)),
                Ok(handles) => identity.with(|state| state.handles = Some(handles)),
            }
        }
        if valid & message_view::VIEW_ATTRIBUTE != 0 {
            match message_view::capture(port, attribute_address(send_attributes, message_view::VIEW_ATTRIBUTE), mode)? {
                Err(status) => return Ok(Err(status)),
                Ok(message_view::Captured::Empty) => {}
                Ok(message_view::Captured::View(carried)) => identity.with(|state| state.view = Some(carried)),
            }
        }
        if context_address != 0 {
            match context_attribute::try_capture(context_address, port.with(|state| state.port_context), &identity) {
                Ok(context) => request.state.lock().context = context,
                Err(status) => return Ok(Err(status)),
            }
        }
        if valid & 0x0400_0000 != 0 {
            let status = direct_event::validate(flags | if reserve_id != 0 { 0x10 } else { 0 }, valid);
            if status != 0 {
                return Ok(Err(status));
            }
            let Ok(event_handle) = state::user_struct::<AlpcDirectAttr>(attribute_address(send_attributes, 0x0400_0000)).and_then(|direct| direct.event.probe_get()) else { return Ok(Err(AV)) };
            if mode != 0 {
                match events::reference(event_handle, 2) {
                    Err(status) => return Ok(Err(status)),
                    Ok(object) => {
                        let mut state = request.state.lock();
                        state.direct = Some(object.pointer);
                        state.release_direct = Some(Box::new(move || events::release(&object)));
                    }
                }
            } else {
                request.state.lock().direct = Some(direct_event::borrow(event_handle));
            }
        }
        request.state.lock().delivered = true;
        let reply = if legacy {
            legacy_service::exchange(port, &captured, &request, datagram)?
        } else {
            let Some(service) = port.with(|state| state.service.clone()) else { return Err(KernelError::new("ALPC port has no service")) };
            service.exchange(port, &captured.data, &request)
        };
        match reply {
            Reply::Now(result) => {
                if (result.status != 0 && !datagram) || port.closed() {
                    return Ok(Err(if result.status != 0 { result.status } else { 0xC000_0037 }));
                }
                if datagram {
                    // O serviço já possui a carga; não resta associação de
                    // resposta no cliente.
                    message_identity::release(&identity)?;
                    request.state.lock().reserve = None;
                }
                let delivery = queue_reply(port, &request, &result)?;
                stored = delivery == 0;
                cleanup_job(&request, Some(delivery));
            }
            Reply::Later(job) => {
                request.state.lock().job = Some(job);
                if port.closed() {
                    return Ok(Err(0xC000_0037));
                }
                if datagram {
                    message_identity::release(&identity)?;
                    request.state.lock().reserve = None;
                }
                let _ = dispatcher_objects::reference(port.pointer);
                request.state.lock().retained = true;
                port.with(|state| state.jobs.push(request.clone()));
                crate::ntos::alpc::kernel_entry::notify_waiters();
                stored = true;
                deferred = true;
            }
        }
        Ok(Ok(()))
    })();
    if !deferred || !stored {
        release_request(port, &request, stored)?;
    }
    match outcome? {
        Err(status) => Ok(Err(status)),
        Ok(()) => Ok(Ok(synchronous.then_some(request))),
    }
}

/// Estado da recepção, compartilhado pela tentativa imediata e pela espera.
struct Receiver {
    port: Arc<Port>,
    synchronous: Option<Arc<Request>>,
    direct_selection: bool,
    selected: u32,
    selected_callback: u32,
    output: u64,
    receive_attributes: u64,
    buffer: Option<Buffer>,
    flags: u32,
    mode: u8,
}

impl Receiver {
    fn interrupted(&self) -> Option<u32> {
        if self.port.with(|state| state.closing) {
            return Some(0xC000_0037);
        }
        let request = self.synchronous.as_ref()?;
        let state = request.state.lock();
        if let Some(status) = state.cancel_status {
            return Some(status);
        }
        state.disconnected.then_some(0xC000_0701)
    }

    fn receive(&self) -> Result<Option<u32>, KernelError> {
        if let Some(status) = self.interrupted() {
            return Ok(Some(status));
        }
        pump();
        if let Some(status) = self.interrupted() {
            return Ok(Some(status));
        }
        let port = &self.port;
        if self.direct_selection {
            let identity = match message_identity::resolve(port, self.selected, self.selected_callback) {
                Ok(identity) => identity,
                Err(status) => return Ok(Some(status)),
            };
            let (queued, direct) = identity.with(|state| (state.queued, state.direct));
            if !queued {
                return Ok(Some(0xC000_0702));
            }
            if !direct {
                return Ok(Some(INVALID));
            }
        }
        let selected = self.selected;
        let found = port.with(|state| {
            let index = if selected != 0 { state.pending.iter().position(|message| message.id == selected) } else { state.pending.iter().position(|message| !message.direct) };
            index.map(|index| {
                let message = &state.pending[index];
                (message.identity.clone(), message.status, message.bytes.clone(), message.context, message.sequence)
            })
        });
        let Some((identity, status, bytes, context, sequence)) = found else { return Ok(None) };
        let take = |port: &Arc<Port>| port.with(|state| state.pending.retain(|message| !Arc::ptr_eq(&message.identity, &identity)));
        if status != 0 {
            take(port);
            message_identity::release(&identity)?;
            return Ok(Some(status));
        }
        // Os buffers de um receptor bloqueado podem ter sido desmapeados por
        // outra thread.
        let header = message_buffer::probe_header(self.output, self.mode);
        if header != 0 {
            return Ok(Some(header));
        }
        let status = attributes(self.receive_attributes, false, self.mode);
        if status != 0 {
            return Ok(Some(status));
        }
        let Some(buffer) = &self.buffer else { return Err(KernelError::new("ALPC receive without buffer")) };
        let delivery = message_buffer::deliver(buffer, bytes.as_deref().unwrap_or(&[]), self.flags & 0x2_0000 != 0);
        if delivery != 0 {
            return Ok(Some(delivery));
        }
        let mut published = try_publish_attributes(self.receive_attributes, port, context, sequence, &identity);
        // A vista que a resposta de um servidor de modo usuário trouxe entra
        // no processo desta porta.
        if let Some(carried) = identity.with(|state| state.reply_view.take()).filter(|_| published.is_ok()) {
            match message_view::deliver(port, self.receive_attributes, &carried)? {
                Ok(Some(binding)) => message_view::remember_received(port, identity.identifier, &binding),
                Ok(None) => {}
                Err(status) => published = Err(status),
            }
        }
        take(port);
        message_identity::release(&identity)?;
        Ok(Some(published.err().unwrap_or(0)))
    }

    fn poll(&self) -> Option<u32> {
        match self.receive() {
            Ok(result) => result,
            Err(error) => {
                crate::debug_print!("[alpc] receive: {}", error);
                Some(0xC000_0001)
            }
        }
    }
}

pub fn exchange_messages(port: &Arc<Port>, flags: u32, input: u64, send_attributes: u64, receive: ReceiveArguments, mode: u8) -> Result<Exchange, KernelError> {
    use Exchange::Status;
    let ReceiveArguments { output, length, receive_attributes, timeout } = receive;
    // O despacho NT ignora os bits baixos e rejeita estas combinações antes
    // do transporte.
    let flags = flags & 0xFFFF_0000;
    if flags & 0x2_0000 != 0 {
        if input == 0 || flags & 0x101_0000 != 0 {
            return Ok(Status(0xC000_00F0));
        }
        if output == 0 {
            return Ok(Status(0xC000_0705));
        }
    } else if input != 0 && flags & 0x100_0000 != 0 {
        return Ok(Status(0xC000_00F0));
    }
    // Uma chamada vazia só referencia a porta.
    if input == 0 && output == 0 {
        return Ok(Status(0));
    }
    // A desconexão bloqueia novos envios, mas não impede drenar respostas.
    let (closing, peer_disconnected, connection_state) = port.with(|state| (state.closing, state.peer_disconnected, state.connection_state));
    if closing || (input != 0 && (port.closed() || peer_disconnected)) {
        return Ok(Status(0xC000_0037));
    }
    if input != 0 && connection_state == port_objects::CONNECTION_PENDING {
        return Ok(Status(0xC000_0707));
    }
    if input != 0 && connection_state == port_objects::CONNECTION_REFUSED {
        return Ok(Status(0xC000_0037));
    }
    if output != 0 && timeout != 0 && !message_buffer::accessible(timeout, 8, mode, false) {
        return Ok(Status(AV));
    }
    // O caminho de kernel trata alerta e modo de espera; o de usuário
    // rejeita Alertable até a entrega real de APC em ring 3.
    if flags & !(if mode != 0 { 0x193_0000 } else { 0x1B3_0000 }) != 0 {
        crate::debug_print!("[alpc] send flags=0x{:x}", flags);
        return Ok(Status(0xC000_00BB));
    }
    let legacy = port.kind == "port";
    let legacy_synchronous = legacy && flags & 0x2_0000 != 0;
    if legacy && !has_port(port) {
        port.with(|state| {
            state.transport_cleanup = true;
            state.on_disconnect = Some(disconnect_transport);
        });
        add_port(port);
    }
    // O ramo LPC chama o emissor legado sem OutMessageAttributes; nem a
    // sondagem desse ponteiro acontece no envio síncrono.
    let send_attributes = if legacy_synchronous { 0 } else { send_attributes };
    let mut status = if input != 0 { attributes(send_attributes, true, mode) } else { 0 };
    if status == 0 && output != 0 {
        status = attributes(receive_attributes, false, mode);
    }
    if status != 0 {
        return Ok(Status(status));
    }
    if output != 0 {
        let header = message_buffer::probe_header(output, mode);
        if header != 0 {
            return Ok(Status(header));
        }
    }
    let buffer = if output != 0 {
        match message_buffer::capture_length(output, length, mode) {
            Ok(buffer) => Some(buffer),
            Err(status) => return Ok(Status(status)),
        }
    } else {
        None
    };
    let kernel_timeout = if mode == 0 && output != 0 {
        match kernel_wait::capture_timeout(timeout, 0) {
            Ok(timeout) => Some(timeout),
            Err(status) => return Ok(Status(status)),
        }
    } else {
        None
    };
    let direct_selection = flags & 0x100_0000 != 0;
    // MessageId e CallbackId pedidos no cabeçalho de recepção (sondado acima).
    let (mut selected, selected_callback) = if direct_selection {
        match state::user_struct::<PortMessage>(output).and_then(|message| Ok((message.message_id.probe_get()?, message.callback_id.probe_get()?))) {
            Ok(selection) => selection,
            Err(_) => return Ok(Status(AV)),
        }
    } else {
        (0, 0)
    };
    if direct_selection && selected == 0 {
        return Ok(Status(INVALID));
    }
    let mut synchronous = None;
    if input != 0 {
        match send(port, flags, input, send_attributes, mode, legacy, legacy_synchronous)? {
            Err(status) => return Ok(Status(status)),
            Ok(Some(request)) => {
                selected = request.id;
                synchronous = Some(request);
            }
            Ok(None) => {}
        }
    }
    if output == 0 {
        return Ok(Status(0));
    }
    let receiver = Arc::new(Receiver { port: port.clone(), synchronous: synchronous.clone(), direct_selection, selected, selected_callback, output, receive_attributes, buffer, flags, mode });
    if let Some(immediate) = receiver.receive()? {
        return Ok(Status(immediate));
    }
    // A espera possui o corpo, independente da tabela ou do último handle;
    // cancelamento, timeout e término liberam a referência uma única vez.
    let _ = dispatcher_objects::reference(port.pointer);
    let released = Arc::new(AtomicBool::new(false));
    let release_wait = {
        let (port, released) = (port.clone(), released.clone());
        move |status: u32| {
            if released.swap(true, Ordering::SeqCst) {
                return;
            }
            if let Some(request) = synchronous.as_ref().filter(|_| [0x102, 0x101, 0xC0, 0xC000_004B, 0xC000_00BB, 0xC000_0120, 0xC000_0701].contains(&status)) {
                // O job pertence ao servidor e conserva seus recursos; só a
                // associação com a resposta do cliente termina.
                request.state.lock().canceled = true;
                let _ = message_identity::release(&request.identity);
            }
            let _ = dispatcher_objects::dereference(port.pointer);
        }
    };
    if mode == 0 {
        let polled = receiver.clone();
        let cleanup = release_wait.clone();
        let operation = kernel_wait::Operation { poll: Box::new(move || polled.port.clone().run(|| polled.poll())), cleanup: Box::new(move |status| cleanup(status)) };
        return match kernel_wait::begin(operation, kernel_timeout.unwrap_or_default(), kernel_wait::select_mode(flags, 0), flags & 0x20_0000 != 0) {
            Ok(request) => Ok(Exchange::Wait(request)),
            Err(error) => {
                release_wait(0xC000_0120);
                Err(error)
            }
        };
    }
    let polled = receiver.clone();
    let wait = Wait { poll: Some(Box::new(move || polled.poll())), cleanup: Some(Box::new(release_wait)), ..Wait::default() };
    Ok(Status(threads::wait_custom(wait, timeout, None)))
}

fn send_receive(handle: u64, flags: u64, input: u64, send_attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    // O frame nativo preserva o HANDLE completo, inclusive pseudo-handles.
    let mut reference = match port_reference::reference(handle, 1, 1)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let port = reference.port.clone();
    let index = reference.handle_index;
    let result = (|| -> Result<u32, KernelError> {
        if !state::probe_syscall_stack(rsp, 32) {
            return Ok(AV);
        }
        let receive = ReceiveArguments { output: state::stack_arg(rsp, 5), length: state::stack_arg(rsp, 6), receive_attributes: state::stack_arg(rsp, 7), timeout: state::stack_arg(rsp, 8) };
        port.run(|| {
            // O lado servidor de uma conexão de usuário (porta de conexão ou
            // de comunicação) tem a fila e as respostas próprias.
            if port.kind == "alpc" && crate::ntos::alpc::server::owns(&port) {
                return crate::ntos::alpc::server::exchange(&port, flags as u32, input, send_attributes, receive);
            }
            if port.kind == "alpc" {
                return Ok(match exchange_messages(&port, flags as u32, input, send_attributes, receive, 1)? {
                    Exchange::Status(status) => status,
                    Exchange::Wait(_) => return Err(KernelError::new("ALPC user exchange produced a kernel wait")),
                });
            }
            match *LPC_SEND_RECEIVE.lock() {
                Some(lpc) => lpc(index as u64, flags, input, send_attributes, rsp),
                None => Ok(0xC000_0008),
            }
        })
    })();
    let _ = reference.release();
    result
}

/// O envio adiado de um WORKER_FACTORY_DEFERRED_WORK (o AlpcpSendMessage do
/// NtWaitForWorkViaWorkerFactory): a mensagem `input` na porta `handle`, com
/// as flags dadas e sem atributos nem recepção. O RPC do servidor manda
/// assim a resposta de um pedido antes de voltar a esperar trabalho.
pub fn deferred_send(handle: u64, flags: u32, input: u64) -> Result<u32, KernelError> {
    if crate::ntos::init::boot_config::TRACE_SYSCALLS {
        if let Ok(bytes) = guest::try_read_bytes(input, 0x80) {
            let hex: alloc::string::String = bytes.iter().map(|byte| alloc::format!("{byte:02x}")).collect();
            crate::debug_print!("[alpc] envio adiado {:#x} flags {:#x}: {}", handle, flags, hex);
        }
    }
    let mut reference = match port_reference::reference(handle, 1, 1)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let port = reference.port.clone();
    let receive = ReceiveArguments { output: 0, length: 0, receive_attributes: 0, timeout: 0 };
    let result = port.run(|| {
        if port.kind == "alpc" && crate::ntos::alpc::server::owns(&port) {
            return crate::ntos::alpc::server::exchange(&port, flags, input, 0, receive);
        }
        if port.kind == "alpc" {
            return Ok(match exchange_messages(&port, flags, input, 0, receive, 1)? {
                Exchange::Status(status) => status,
                Exchange::Wait(_) => return Err(KernelError::new("ALPC deferred send produced a kernel wait")),
            });
        }
        Ok(0xC000_0008)
    });
    let _ = reference.release();
    result
}

/// Transporte do export Zw e dos consumidores internos: oito argumentos
/// exatos, resultado imediato ou continuação.
fn begin_kernel_exchange(arguments: &[u64; 8]) -> Result<Box<dyn Pending>, KernelError> {
    let mut reference = match port_reference::reference(arguments[0], 1, 0)? {
        Ok(reference) => reference,
        Err(status) => return Ok(Box::new(Completed(status))),
    };
    let port = reference.port.clone();
    let receive = ReceiveArguments { output: arguments[4], length: arguments[5], receive_attributes: arguments[6], timeout: arguments[7] };
    // O lado servidor de uma conexão (porta de conexão ou de comunicação de
    // um servidor de kernel) tem a fila e as respostas próprias.
    if port.kind == "alpc" && crate::ntos::alpc::server::owns(&port) {
        // O despacho NT ignora os bits baixos das flags (o contrato LPC de
        // kernel só vem do LpcRequestPort e do LpcSendWaitReceivePort).
        let pending = port.run(|| crate::ntos::alpc::server::begin_kernel_exchange(&port, arguments[1] as u32 & 0xFFFF_0000, arguments[2], receive));
        let _ = reference.release();
        return pending;
    }
    let result = port.run(|| exchange_messages(&port, arguments[1] as u32, arguments[2], arguments[3], receive, 0));
    let _ = reference.release();
    Ok(match result? {
        Exchange::Status(status) => Box::new(Completed(status)),
        Exchange::Wait(request) => Box::new(request),
    })
}

/// Conexões Zw e dos consumidores de kernel: os onze argumentos x64 em
/// KernelMode.
fn begin_connection(arguments: &[u64; 11]) -> Result<Box<dyn Pending>, KernelError> {
    crate::ntos::alpc::connect::port::begin(arguments, 0, false)
}

fn begin_connection_ex(arguments: &[u64; 11]) -> Result<Box<dyn Pending>, KernelError> {
    crate::ntos::alpc::connect::port::begin(arguments, 0, true)
}

fn nt_alpc_send_wait_receive_port(handle: u64, flags: u64, input: u64, attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    // Rastreio de serviços: o PORT_MESSAGE e o começo dos dados enviados.
    if crate::ntos::init::boot_config::TRACE_SYSCALLS && input != 0 && state::probe_user_read(input, 0x68) {
        if let Ok(bytes) = guest::try_read_bytes(input, 0x68) {
            let hex: alloc::string::String = bytes.iter().map(|byte| alloc::format!("{byte:02x}")).collect();
            crate::debug_print!("[alpc] envio de usuario {:#x} flags {:#x}: {}", handle, flags as u32, hex);
        }
    }
    let status = send_receive(handle, flags, input, attributes, rsp)?;
    if status == INVALID {
        let mut detail = alloc::format!("[alpc] invalid send flags=0x{:x}", flags as u32);
        if input != 0 && state::probe_user_read(input, PortMessage::SIZE) {
            if let Ok((kind, id, size)) = state::user_struct::<PortMessage>(input).and_then(|message| Ok((message.u2.s2.type_.probe_get()?, message.message_id.probe_get()?, message.u1.s1.total_length.probe_get()?))) {
                detail.push_str(&alloc::format!(" type={} id={} size={}", kind as u16, id, size as u16));
            }
        }
        if attributes != 0 && state::probe_user_read(attributes, AlpcMessageAttributes::SIZE) {
            if let Ok(valid) = message_attributes(attributes).and_then(|header| header.valid_attributes.probe_get()) {
                detail.push_str(&alloc::format!(" attributes=0x{valid:x}"));
                let at = attribute_address(attributes, 0x0200_0000);
                if valid & 0x0200_0000 != 0 && state::probe_user_read(at, AlpcWorkOnBehalfTicket::SIZE) {
                    if let Ok((thread, time)) = state::user_struct::<AlpcWorkOnBehalfTicket>(at).and_then(|ticket| Ok((ticket.thread_id.probe_get()?, ticket.thread_creation_time_low.probe_get()?))) {
                        detail.push_str(&alloc::format!(" origin={thread}:{time}"));
                    }
                }
            }
        }
        crate::debug_print!("{}", detail);
    }
    Ok(status)
}

/// NtAlpcCreatePort(PortHandle*, ObjectAttributes, PortAttributes).
fn nt_alpc_create_port(out: u64, attributes: u64, port_attributes: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    state::guarded(|| crate::ntos::alpc::server::create_port(out, attributes, port_attributes, 1))
}

/// NtAlpcAcceptConnectPort(PortHandle*, ConnectionPortHandle, Flags,
/// ObjectAttributes, PortAttributes, PortContext, ConnectionRequest,
/// ConnectionMessageAttributes, AcceptConnection).
fn nt_alpc_accept_connect_port(out: u64, connection: u64, _flags: u64, attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 5 * 8) {
        return Ok(AV);
    }
    let (port_attributes, port_context, request, accept) = (state::stack_arg(rsp, 5), state::stack_arg(rsp, 6), state::stack_arg(rsp, 7), state::stack_arg32(rsp, 9) as u8 != 0);
    state::guarded(|| crate::ntos::alpc::server::accept_connect_port_with(out, connection, attributes, port_attributes, port_context, request, accept, 1))
}

/// NtAlpcOpenSenderProcess(ProcessHandle*, PortHandle, PortMessage, Flags,
/// DesiredAccess, ObjectAttributes).
fn nt_alpc_open_sender_process(out: u64, port: u64, message: u64, _flags: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 2 * 8) {
        return Ok(AV);
    }
    state::guarded(|| crate::ntos::alpc::server::open_sender(out, port, message, state::stack_arg32(rsp, 5), state::stack_arg(rsp, 6), false))
}

/// NtAlpcOpenSenderThread(ThreadHandle*, PortHandle, PortMessage, Flags,
/// DesiredAccess, ObjectAttributes).
fn nt_alpc_open_sender_thread(out: u64, port: u64, message: u64, _flags: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 2 * 8) {
        return Ok(AV);
    }
    state::guarded(|| crate::ntos::alpc::server::open_sender(out, port, message, state::stack_arg32(rsp, 5), state::stack_arg(rsp, 6), true))
}

fn nt_alpc_cancel_message(port: u64, flags: u64, context: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    cancel_message::cancel(port, flags as u32, context, 1, cancel_message)
}

fn nt_alpc_create_security_context(handle: u64, flags: u64, attribute: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    services::create_security_context(handle, flags as u32, attribute, 1)
}

fn nt_alpc_delete_security_context(port: u64, flags: u64, context: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    services::delete_security_context(port, flags as u32, context, 1)
}

fn nt_alpc_create_resource_reserve(port: u64, flags: u64, size: u64, output: u64, _rsp: u64) -> Result<u32, KernelError> {
    services::create_resource_reserve(port, flags as u32, size, output, 1)
}

fn nt_alpc_delete_resource_reserve(port: u64, flags: u64, identifier: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    services::delete_resource_reserve(port, flags as u32, identifier as u32, 1)
}

fn nt_alpc_set_information(handle: u64, class: u64, input: u64, length: u64, _rsp: u64) -> Result<u32, KernelError> {
    services::set_information(handle, class as u32, input, length as u32, 1)
}

fn nt_alpc_disconnect_port(handle: u64, flags: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    services::disconnect_port(handle, flags as u32, 1)
}

fn nt_alpc_query_information(handle: u64, class: u64, output: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(AV);
    }
    crate::ntos::alpc::query_information::query(handle, class as u32, output, length as u32, state::stack_arg(rsp, 5), 1)
}

/// O provedor compartilhado conserva as sondagens de UserMode; o pump do
/// transporte roda antes da busca da mensagem.
fn nt_alpc_query_information_message(handle: u64, message: u64, class: u64, output: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 16) {
        return Ok(AV);
    }
    crate::ntos::alpc::query_message::query(handle, message, class as u32, output, state::stack_arg32(rsp, 5), state::stack_arg(rsp, 6), 1, Some(&pump))
}

/// A entrada Nt captura os seis argumentos sem perder bits de SIZE_T ou HANDLE.
fn nt_alpc_create_port_section(handle: u64, flags: u64, section: u64, size: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 16) {
        return Ok(AV);
    }
    services::create_port_section(handle, flags as u32, section, size, state::stack_arg(rsp, 5), state::stack_arg(rsp, 6), 1)
}

fn nt_alpc_create_section_view(handle: u64, flags: u64, attributes: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    services::create_section_view(handle, flags as u32, attributes, 1)
}

/// NtAlpcDeleteSectionView(PortHandle, Flags, ViewBase).
fn nt_alpc_delete_section_view(handle: u64, flags: u64, base: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    services::delete_section_view(handle, flags as u32, base, 1)
}

/// NtAlpcDeletePortSection(PortHandle, Flags, SectionHandle).
fn nt_alpc_delete_port_section(handle: u64, flags: u64, section: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    services::delete_port_section(handle, flags as u32, section, 1)
}

pub fn init() {
    // O fallback LPC registra antes desta camada; os handles do tipo LPC
    // continuam no seu emissor.
    *LPC_SEND_RECEIVE.lock() = state::handler("NtAlpcSendWaitReceivePort");
    state::register_handler("NtAlpcConnectPort", nt_alpc_connect_port);
    state::register_handler("NtAlpcConnectPortEx", nt_alpc_connect_port_ex);
    state::register_handler("NtAlpcCreatePort", nt_alpc_create_port);
    state::register_handler("NtAlpcAcceptConnectPort", nt_alpc_accept_connect_port);
    state::register_handler("NtAlpcOpenSenderProcess", nt_alpc_open_sender_process);
    state::register_handler("NtAlpcOpenSenderThread", nt_alpc_open_sender_thread);
    state::register_handler("NtAlpcSendWaitReceivePort", nt_alpc_send_wait_receive_port);
    state::register_handler("NtAlpcCancelMessage", nt_alpc_cancel_message);
    state::register_handler("NtAlpcCreateSecurityContext", nt_alpc_create_security_context);
    state::register_handler("NtAlpcDeleteSecurityContext", nt_alpc_delete_security_context);
    state::register_handler("NtAlpcCreateResourceReserve", nt_alpc_create_resource_reserve);
    state::register_handler("NtAlpcDeleteResourceReserve", nt_alpc_delete_resource_reserve);
    state::register_handler("NtAlpcSetInformation", nt_alpc_set_information);
    state::register_handler("NtAlpcDisconnectPort", nt_alpc_disconnect_port);
    state::register_handler("NtAlpcQueryInformation", nt_alpc_query_information);
    state::register_handler("NtAlpcQueryInformationMessage", nt_alpc_query_information_message);
    state::register_handler("NtAlpcCreatePortSection", nt_alpc_create_port_section);
    state::register_handler("NtAlpcCreateSectionView", nt_alpc_create_section_view);
    state::register_handler("NtAlpcDeleteSectionView", nt_alpc_delete_section_view);
    state::register_handler("NtAlpcDeletePortSection", nt_alpc_delete_port_section);
    let installed = kernel_entry::install(begin_kernel_exchange).and_then(|_| kernel_entry::install_connection(begin_connection)).and_then(|_| kernel_entry::install_connection_ex(begin_connection_ex));
    if let Err(error) = installed {
        crate::debug_print!("[alpc] {}", error);
    }
    threads::set_pump(threads::pump::ALPC, pump);
}
