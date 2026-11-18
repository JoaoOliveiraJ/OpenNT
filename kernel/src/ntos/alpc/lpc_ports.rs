//! As portas LPC de modo usuário sobre o ALPC.
//!
//! No ntoskrnl 19041 os serviços do LPC antigo são finos sobre as rotinas
//! do ALPC: uma porta LPC é uma ALPC Port (o mesmo AlpcPortObjectType) com o
//! modo LPC (ALPC_PORFLG_LPC_MODE no Flags dos atributos). Aqui eles são o
//! mesmo servidor de usuário de `alpc/server.rs` e o mesmo transporte de
//! cliente de `ps/user/alpc.rs`:
//!
//! - NtCreatePort/NtCreateWaitablePort ([`create_port`]): a porta de
//!   conexão com nome, o MaxMessageLength até o LpcLegacyMaxMessageLength
//!   (0x288); o MaxConnectionInfoLength e o MaxPoolUsage não entram;
//! - NtConnectPort/NtSecureConnectPort ([`connect`]): as capturas do
//!   NtSecureConnectPort (PORT_VIEW de 0x30 bytes, REMOTE_PORT_VIEW de 0x18,
//!   o SECURITY_QUALITY_OF_SERVICE e o SID exigido do servidor), a porta do
//!   cliente com o modo LPC e a qualidade dada, a seção do PORT_VIEW mapeada
//!   no cliente, a mensagem LPC_CONNECTION_REQUEST com a informação de
//!   conexão e o ClientViewSize, e a espera pela decisão do servidor; na
//!   aceitação, o handle, o ViewBase/ViewRemoteBase do PORT_VIEW, o
//!   REMOTE_PORT_VIEW (a seção do servidor no cliente), a informação de
//!   conexão da resposta (AlpcpReceiveLegacyConnectionReply) e o
//!   MaxMessageLength da porta. Funciona com servidores LPC e ALPC (o csrss
//!   aceita a conexão LPC da ntdll pelo NtAlpcAcceptConnectPort e recebe a
//!   vista pelo ALPC_MESSAGE_VIEW_ATTRIBUTE);
//! - NtListenPort, NtReplyWaitReceivePort(Ex) e NtReplyPort
//!   ([`listen`], [`reply_wait_receive`], [`reply`]): a recepção legada do
//!   lado servidor (o PortContext da porta de comunicação, o Type sem os bits
//!   internos) e a resposta pelo MessageId;
//! - NtAcceptConnectPort ([`accept`]) e NtCompleteConnectPort
//!   ([`complete_connect`], que no 19041 só devolve STATUS_SUCCESS: a
//!   aceitação já acorda o cliente);
//! - NtRequestPort e NtRequestWaitReplyPort ([`request`],
//!   [`request_wait_reply`]): o envio do cliente pelo transporte ALPC (o
//!   AlpcpSendMessage com 0x10000, o AlpcpProcessSynchronousRequest com
//!   0x20000), com os status internos do ALPC trocados pelos do LPC; do lado
//!   servidor, a mensagem nova do servidor (`alpc/server.rs`);
//! - NtImpersonateClientOfPort e NtAlpcImpersonateClientOfPort
//!   ([`impersonate_client`]): o nível pedido nas Flags, a mensagem já
//!   recebida e sem LPC_NO_IMPERSONATE, o contexto de segurança que ela
//!   leva ou, com ALLOW_IMPERSONATION na porta do cliente, o contexto
//!   estático da conexão ou a thread que espera a resposta (rastreamento
//!   dinâmico); sem mensagem, o contexto estático da conexão;
//! - NtQueryInformationPort ([`query_information`]): só confere o handle
//!   (READ_CONTROL) e zera o ReturnLength, como o 19041;
//! - NtReplyWaitReplyPort, NtReadRequestData e NtWriteRequestData: as
//!   mensagens com PORT_DATA_INFORMATION e as respostas que esperam outra
//!   resposta não existem no transporte do OpenNT: STATUS_NOT_SUPPORTED,
//!   com registro (nenhum binário da cadeia de boot as usa).
//!
//! As conexões aos serviços hospedados no kernel (`ps/user/lpc.rs`, o nó
//! `Port`) seguem pelo caminho deles.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::port_reference;
use crate::ntos::alpc::security_contexts::Quality;
use crate::ntos::alpc::server::{self, ClientView, LegacyViews, LPC_MODE};
use crate::ntos::alpc::transport::{self, Reply};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{PortMessage, PortView, RemotePortView, SecurityQualityOfService, Sid, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::section::handles::{self as section_handles, Kind};
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::objects::port::{self as port_objects, Port, PortState, Role};
use crate::ntos::ps::process;
use crate::ntos::ps::security::{self as ps_security, CapturedQuality};
use crate::ntos::ps::user::alpc::{self as user_alpc, Exchange, ReceiveArguments};
use crate::ntos::ps::user::sections::{self, MapRequest};
use crate::ntos::ps::user::state;
use crate::rtl::KernelError;

const STATUS_SUCCESS: u32 = 0;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_PORT_MESSAGE_TOO_LONG: u32 = 0xC000_002F;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_PORT_DISCONNECTED: u32 = 0xC000_0037;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_REPLY_MESSAGE_MISMATCH: u32 = 0xC000_021F;
const STATUS_LPC_REPLY_LOST: u32 = 0xC000_0253;
/// Os status internos do ALPC que as entradas LPC trocam.
const STATUS_ALPC_PORT_DISCONNECTED: u32 = 0xC000_0703;
const STATUS_ALPC_REPLY_LOST: u32 = 0xC000_0701;
const STATUS_ALPC_MESSAGE_NOT_FOUND: u32 = 0xC000_0702;

/// PORT_CONNECT e READ_CONTROL (as referências do handle).
const PORT_CONNECT: u32 = 1;
const READ_CONTROL: u32 = 0x2_0000;
/// SECTION_MAP_WRITE | SECTION_MAP_READ da seção de um PORT_VIEW.
const SECTION_MAP_READ_WRITE: u32 = 6;
/// PAGE_READWRITE.
const PAGE_READWRITE: u32 = 4;
/// ALPC_MSGFLG_RELEASE_MESSAGE (o datagrama do NtRequestPort) e
/// ALPC_MSGFLG_SYNC_REQUEST (o NtRequestWaitReplyPort).
const RELEASE_MESSAGE: u32 = 0x1_0000;
const SYNC_REQUEST: u32 = 0x2_0000;
/// Flags da porta de um cliente LPC (AlpcpValidateAndSetPortAttributes de uma
/// porta de comunicação de cliente no modo LPC): LPC_MODE, o bit 16 dos
/// atributos padrão e ALLOW_LPC_REQUESTS.
const CLIENT_PORT_FLAGS: u32 = LPC_MODE | 0x1_0000 | 0x2_0000;
/// O QOS padrão de uma porta LPC sem SECURITY_QUALITY_OF_SERVICE: Anonymous,
/// rastreamento dinâmico, só o efetivo.
const DEFAULT_QUALITY: Quality = Quality { level: 0, tracking: 1, effective_only: true };

/// Os status internos do ALPC trocados pelos do LPC (NtRequestWaitReplyPort,
/// NtReplyWaitReplyPort).
fn legacy_status(status: u32) -> u32 {
    match status {
        STATUS_ALPC_PORT_DISCONNECTED => STATUS_PORT_DISCONNECTED,
        STATUS_ALPC_REPLY_LOST => STATUS_LPC_REPLY_LOST,
        other => other,
    }
}

/// O caminho de um UNICODE_STRING de modo usuário (sondado).
fn capture_name(name: u64) -> Result<Result<String, u32>, KernelError> {
    if !state::probe_user_read(name, UnicodeString::SIZE) {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    }
    let string = state::user_struct::<UnicodeString>(name)?;
    let length = string.length.probe_get()? as u64;
    let buffer = string.buffer.probe_get()?;
    if length % 2 != 0 || !state::probe_user_read(buffer, length) {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    }
    Ok(Ok(state::try_read_user_wide_string(buffer, length / 2)?))
}

/// A porta do handle de usuário, retida durante `body`.
fn with_port(handle: u64, desired: u32, body: impl FnOnce(&Arc<Port>) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    let mut reference = match port_reference::reference(handle, desired, 1)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let port = reference.port.clone();
    let result = port.run(|| body(&port));
    let _ = reference.release();
    result
}

/// A porta do handle é uma conexão a um serviço hospedado no kernel
/// (`ps/user/lpc.rs`).
pub fn kernel_service_handle(handle: u64) -> bool {
    port_objects::resolve(handle, "port").is_some()
}

// ---- NtCreatePort ------------------------------------------------------------

/// NtCreatePort/NtCreateWaitablePort(PortHandle*, ObjectAttributes,
/// MaxConnectionInfoLength, MaxMessageLength, MaxPoolUsage).
pub fn create_port(out: u64, attributes: u64, maximum_message_length: u32, waitable: bool) -> Result<u32, KernelError> {
    state::guarded(|| server::create_legacy_port(out, attributes, maximum_message_length, waitable, 1))
}

// ---- NtSecureConnectPort -----------------------------------------------------

/// O PORT_VIEW do cliente capturado: a seção (SectionHandle), o deslocamento
/// e o tamanho pedidos.
struct ClientViewRequest {
    address: u64,
    section_handle: u64,
    offset: u64,
    size: u64,
}

/// NtSecureConnectPort(PortHandle*, PortName, SecurityQos, ClientView,
/// RequiredServerSid, ServerView, MaxMessageLength, ConnectionInformation,
/// ConnectionInformationLength) de modo usuário a uma porta ALPC de servidor
/// (LPC ou ALPC). NtConnectPort é a mesma chamada sem o SID.
#[allow(clippy::too_many_arguments)]
pub fn connect(out: u64, name: u64, qos: u64, client_view: u64, required_sid: u64, server_view: u64, max_length: u64, information: u64, information_length: u64) -> Result<u32, KernelError> {
    state::guarded(|| connect_captured(out, name, qos, client_view, required_sid, server_view, max_length, information, information_length))
}

/// O nó da porta pelo nome: `Port` (serviço do kernel) ou `AlpcPort`.
pub fn connection_target(name: u64) -> Result<Result<(object_manager::NodeId, String), u32>, KernelError> {
    let path = match capture_name(name)? {
        Ok(path) => path,
        Err(status) => return Ok(Err(status)),
    };
    if path.is_empty() || !path.starts_with('\\') {
        return Ok(Err(STATUS_OBJECT_NAME_INVALID));
    }
    let Some(node) = object_manager::lookup(&path) else { return Ok(Err(STATUS_OBJECT_NAME_NOT_FOUND)) };
    let Some(record) = object_manager::node(node) else { return Ok(Err(STATUS_OBJECT_NAME_NOT_FOUND)) };
    Ok(Ok((node, record.type_name.clone())))
}

#[allow(clippy::too_many_arguments)]
fn connect_captured(out: u64, name: u64, qos: u64, client_view: u64, required_sid: u64, server_view: u64, max_length: u64, information: u64, information_length: u64) -> Result<u32, KernelError> {
    // As capturas na ordem do NtSecureConnectPort.
    if !state::probe_user_write(out, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let capacity = if information_length != 0 {
        if !state::probe_user_read(information_length, 4) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let capacity = guest::try_read::<u32>(information_length)?;
        if !state::probe_user_write(information, capacity as u64) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        capacity
    } else {
        0
    };
    let view_request = if client_view != 0 {
        if !state::probe_user_read(client_view, PortView::SIZE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if guest::try_read::<u32>(client_view)? != PortView::SIZE as u32 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if client_view & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !state::probe_user_write(client_view, PortView::SIZE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let view = state::user_struct::<PortView>(client_view)?;
        Some(ClientViewRequest { address: client_view, section_handle: view.section_handle.probe_get()?, offset: view.section_offset.probe_get()? as u64, size: view.view_size.probe_get()? })
    } else {
        None
    };
    if server_view != 0 {
        if !state::probe_user_read(server_view, RemotePortView::SIZE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if guest::try_read::<u32>(server_view)? != RemotePortView::SIZE as u32 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if server_view & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !state::probe_user_write(server_view, RemotePortView::SIZE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if max_length != 0 && !state::probe_user_write(max_length, 4) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    // O QOS capturado sem conferir o Length, como a cópia do NT; o
    // AlpcpValidateAndSetPortAttributes recusa níveis e modos inválidos.
    let quality = if qos != 0 {
        if !state::probe_user_read(qos, SecurityQualityOfService::SIZE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let source = state::user_struct::<SecurityQualityOfService>(qos)?;
        Quality { level: source.impersonation_level.probe_get()?.0 as u32, tracking: source.context_tracking_mode.probe_get()?, effective_only: source.effective_only.probe_get()? != 0 }
    } else {
        DEFAULT_QUALITY
    };
    let sid = if required_sid != 0 {
        match capture_sid(required_sid)? {
            Ok(sid) => Some(sid),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let (node, type_name) = match connection_target(name)? {
        Ok(target) => target,
        Err(status) => return Ok(status),
    };
    if type_name != "AlpcPort" {
        return Ok(STATUS_OBJECT_TYPE_MISMATCH);
    }
    // O ObReferenceObjectByName(PORT_CONNECT, AlpcPortObjectType,
    // PreviousMode) do AlpcpCreateClientPort: o SeAccessCheck do chamador
    // contra o descritor da porta de conexão.
    if let Err(status) = server::check_connect_access(node, &object_manager::path_of(node).unwrap_or_default()) {
        return Ok(status);
    }
    if quality.level > 3 || quality.tracking > 1 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let Some(listener) = transport::listener_of(node) else { return Ok(STATUS_PORT_DISCONNECTED) };
    let user_server = server::server_of_node(node);
    let server_process = user_server.as_ref().map_or(process::get_system_process(), |server| server.listener().process_pointer);
    if let Some(sid) = &sid {
        // AlpcpCheckConnectionSecurity: o token do dono da porta de conexão
        // não é AppContainer e o usuário dele é o SID exigido.
        if let Err(status) = crate::ntos::alpc::connect::capture::check_server_sid(server_process, sid) {
            return Ok(status);
        }
    }
    let maximum = listener.service.max_message_length();
    if capacity as u64 + PortMessage::SIZE > maximum as u64 {
        return Ok(STATUS_PORT_MESSAGE_TOO_LONG);
    }
    let data = if capacity != 0 { guest::try_read_bytes(information, capacity as usize)? } else { Vec::new() };
    let service = listener.service.clone();
    let disconnecting = service.clone();
    // AlpcpCreateClientPort: com rastreamento estático, o contexto do cliente
    // capturado na conexão (o que a impersonação usa depois).
    let connected = if quality.tracking == 0 {
        match crate::ntos::alpc::message::security::capture_client(process::get_current_thread(), &quality)? {
            Ok(identity) => Some(identity),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let initial = PortState {
        role: Role::Client,
        service: Some(service.clone()),
        service_process: server_process,
        message_sequence: 1,
        port_flags: CLIENT_PORT_FLAGS,
        on_disconnect: Some(user_alpc::disconnect_transport),
        security_quality: Some(quality),
        client_security: connected.clone(),
        ..PortState::default()
    };
    let port = match port_objects::create(
        "alpc",
        initial,
        maximum,
        1,
        0,
        Box::new(move |connection: &Arc<Port>| {
            user_alpc::cleanup_transport(connection);
            if let Some(client) = connection.with(|state| state.client_security.take()) {
                let _ = client.release();
            }
            if connection.started() {
                disconnecting.disconnect(connection);
            }
            for view in connection.with(|state| core::mem::take(&mut state.views)) {
                let _ = sections::unmap(&view, None);
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
    let result = port.run(|| -> Result<u32, KernelError> {
        let view = match &view_request {
            Some(request) => match map_client_view(request)? {
                Ok(view) => {
                    port.with(|state| state.views.push(view.client().clone()));
                    Some(Arc::new(view))
                }
                Err(status) => return Ok(status),
            },
            None => None,
        };
        port.set_started(true);
        let decision = match &user_server {
            Some(server) => server.request_connection(&port, &data, view.clone()),
            None => match service.connect(&port, &data, None) {
                Reply::Now(result) => server::Decision { status: result.status, data: result.data, server_view: None },
                Reply::Later(_) => return Err(KernelError::new("LPC connection to a kernel service was deferred")),
            },
        };
        if port.closed() {
            return Ok(STATUS_PORT_DISCONNECTED);
        }
        if decision.status != STATUS_SUCCESS {
            return Ok(decision.status);
        }
        if let Some(remote) = &decision.server_view {
            port.with(|state| state.views.push(remote.clone()));
        }
        // AlpcpReceiveLegacyConnectionReply e as saídas do NtSecureConnectPort.
        let status = port_objects::publish(&port, out, 0)?;
        if status != 0 {
            return Ok(status);
        }
        let handle = guest::try_read::<u64>(out)?;
        port.with(|state| state.port_context = handle);
        if let (Some(request), Some(view)) = (&view_request, &view) {
            let target = state::user_struct::<PortView>(request.address)?;
            target.view_size.probe_set(view.client().size)?;
            target.view_base.probe_set(view.client().base)?;
            target.view_remote_base.probe_set(view.server().map_or(0, |server| server.base))?;
        }
        if server_view != 0 {
            let target = state::user_struct::<RemotePortView>(server_view)?;
            target.view_size.probe_set(decision.server_view.as_ref().map_or(0, |remote| remote.size))?;
            target.view_base.probe_set(decision.server_view.as_ref().map_or(0, |remote| remote.base))?;
        }
        if information_length != 0 {
            let returned = decision.data.len().min(capacity as usize);
            state::write_user_bytes(information, &decision.data[..returned])?;
            guest::try_write::<u32>(information_length, returned as u32)?;
        }
        if max_length != 0 {
            guest::try_write::<u32>(max_length, port.maximum())?;
        }
        user_alpc::add_port(&port);
        crate::debug_print!("[lpc] pid {} conectado a {} (porta {})", port.process_id(), object_manager::node(node).map_or_else(String::new, |record| record.name.clone()), if user_server.as_ref().is_some_and(|server| server.legacy()) { "LPC" } else { "ALPC" });
        Ok(STATUS_SUCCESS)
    });
    dispatcher_objects::collect(port.pointer);
    match result {
        Err(error) if error.status != 0 => Ok(error.status),
        other => other,
    }
}

/// SeCaptureSid de modo usuário: o SID inteiro (8 + 4 por subautoridade, no
/// máximo 15), sondado.
fn capture_sid(pointer: u64) -> Result<Result<Vec<u8>, u32>, KernelError> {
    if !state::probe_user_read(pointer, 8) {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    }
    let count = state::user_struct::<Sid>(pointer)?.sub_authority_count.probe_get()?;
    let size = 8 + count as u64 * 4;
    if count > 15 || !state::probe_user_read(pointer, size) {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    Ok(Ok(guest::try_read_bytes(pointer, size as usize)?))
}

/// A seção do PORT_VIEW (um handle de seção de dados com SECTION_MAP_READ e
/// SECTION_MAP_WRITE) mapeada no cliente com o deslocamento e o tamanho dados
/// (AlpcpMapLegacyPortView).
fn map_client_view(request: &ClientViewRequest) -> Result<Result<ClientView, u32>, KernelError> {
    let reference = match section_handles::reference(request.section_handle, Kind::Section, SECTION_MAP_READ_WRITE, 1) {
        Ok(reference) => reference,
        Err(STATUS_ACCESS_DENIED) => return Ok(Err(STATUS_ACCESS_DENIED)),
        Err(STATUS_OBJECT_TYPE_MISMATCH) => return Ok(Err(STATUS_OBJECT_TYPE_MISMATCH)),
        Err(_) => return Ok(Err(STATUS_INVALID_HANDLE)),
    };
    let section = reference.section.clone().filter(|section| !section.is_image);
    let mapped = (|| -> Result<Result<ClientView, u32>, KernelError> {
        let Some(section) = section else { return Ok(Err(STATUS_INVALID_HANDLE)) };
        let map = MapRequest { offset: request.offset, size: request.size, protect: PAGE_READWRITE, ..MapRequest::default() };
        Ok(match sections::map(&section, &map)? {
            Ok(view) => Ok(ClientView::new(section, request.offset, view)),
            Err(status) => Err(status),
        })
    })();
    let _ = reference.release();
    mapped
}

// ---- recepção, resposta e aceitação do servidor -------------------------------

/// O cabeçalho de recepção de modo usuário (AlpcpProbeForWriteMessageHeader):
/// ULONG alinhado e os 0x28 bytes graváveis.
fn probe_receive_header(message: u64) -> u32 {
    if message & 3 != 0 {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    if state::probe_user_write(message, PortMessage::SIZE) { STATUS_SUCCESS } else { STATUS_ACCESS_VIOLATION }
}

/// NtReplyWaitReceivePort(Ex)(PortHandle, PortContext*, ReplyMessage,
/// ReceiveMessage[, Timeout]).
pub fn reply_wait_receive(handle: u64, port_context: u64, reply: u64, receive: u64, timeout: u64) -> Result<u32, KernelError> {
    let status = probe_receive_header(receive);
    if status != 0 {
        return Ok(status);
    }
    state::guarded(|| {
        with_port(handle, PORT_CONNECT, |port| {
            if server::owns(port) {
                return server::receive_legacy(port, reply, receive, port_context, timeout, false);
            }
            // A porta de um cliente: a resposta a uma mensagem que o servidor
            // mandou a ele, depois a fila dele (as mensagens novas do
            // servidor).
            if reply != 0 {
                let status = client_reply(port, reply)?;
                if status != STATUS_SUCCESS {
                    return Ok(status);
                }
            }
            if port_context != 0 {
                if !state::probe_user_write(port_context, 8) {
                    return Ok(STATUS_ACCESS_VIOLATION);
                }
                guest::try_write::<u64>(port_context, port.with(|state| state.context))?;
            }
            exchange(port, 0, 0, ReceiveArguments { output: receive, length: 0, receive_attributes: 0, timeout })
        })
    })
}

/// NtListenPort(PortHandle, ConnectionRequest): o NtReplyWaitReceivePortEx
/// repetido até uma mensagem LPC_CONNECTION_REQUEST.
pub fn listen(handle: u64, message: u64) -> Result<u32, KernelError> {
    let status = probe_receive_header(message);
    if status != 0 {
        return Ok(status);
    }
    state::guarded(|| {
        with_port(handle, PORT_CONNECT, |port| {
            if !server::owns(port) {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            server::receive_legacy(port, 0, message, 0, 0, true)
        })
    })
}

/// NtReplyPort(PortHandle, ReplyMessage). Na porta de um cliente, a
/// resposta a uma mensagem que o servidor mandou a ele ([`client_reply`]).
pub fn reply(handle: u64, message: u64) -> Result<u32, KernelError> {
    state::guarded(|| {
        with_port(handle, PORT_CONNECT, |port| {
            if !server::owns(port) {
                return client_reply(port, message);
            }
            Ok(server::reply_legacy(port, message))
        })
    })
}

/// A resposta do cliente, pelo MessageId, a uma mensagem nova do servidor
/// (o callback LPC); sem essa mensagem, STATUS_REPLY_MESSAGE_MISMATCH.
fn client_reply(port: &Arc<Port>, message: u64) -> Result<u32, KernelError> {
    let captured = match crate::ntos::alpc::message::buffer::capture_message_with(message, port.maximum().max(PortMessage::SIZE as u32), 1, true) {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    let at = core::mem::offset_of!(PortMessage, message_id);
    let id = u32::from_le_bytes([captured.header[at], captured.header[at + 1], captured.header[at + 2], captured.header[at + 3]]);
    Ok(server::reply_from_client(port, id, captured.data).unwrap_or(STATUS_REPLY_MESSAGE_MISMATCH))
}

/// NtAcceptConnectPort(PortHandle*, PortContext, ConnectionRequest,
/// AcceptConnection, ServerView, ClientView). STATUS_ALPC... de mensagem
/// cancelada volta como STATUS_INVALID_CID, como o 19041.
pub fn accept(out: u64, port_context: u64, request: u64, accept: bool, server_view: u64, client_view: u64) -> Result<u32, KernelError> {
    state::guarded(|| accept_captured(out, port_context, request, accept, server_view, client_view))
}

fn accept_captured(out: u64, port_context: u64, request: u64, accept: bool, server_view: u64, client_view: u64) -> Result<u32, KernelError> {
    // As capturas do AlpcpAcceptConnectPort no modo LPC.
    if !state::probe_user_write(out, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if !state::probe_user_read(request, PortMessage::SIZE) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let server_section = if server_view != 0 {
        if !state::probe_user_read(server_view, PortView::SIZE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if guest::try_read::<u32>(server_view)? != PortView::SIZE as u32 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if server_view & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !state::probe_user_write(server_view, PortView::SIZE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        Some(state::user_struct::<PortView>(server_view)?)
    } else {
        None
    };
    if client_view != 0 {
        if !state::probe_user_read(client_view, RemotePortView::SIZE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if guest::try_read::<u32>(client_view)? != RemotePortView::SIZE as u32 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if client_view & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !state::probe_user_write(client_view, RemotePortView::SIZE) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    // A seção do PORT_VIEW do servidor, referenciada só na aceitação.
    let mut section_reference = None;
    let mut views = LegacyViews { server_section: None };
    if let (Some(view), true) = (server_section, accept) {
        let reference = match section_handles::reference(view.section_handle.probe_get()?, Kind::Section, SECTION_MAP_READ_WRITE, 1) {
            Ok(reference) => reference,
            Err(STATUS_ACCESS_DENIED) => return Ok(STATUS_ACCESS_DENIED),
            Err(_) => return Ok(STATUS_INVALID_HANDLE),
        };
        let Some(section) = reference.section.clone().filter(|section| !section.is_image) else {
            let _ = reference.release();
            return Ok(STATUS_INVALID_HANDLE);
        };
        views.server_section = Some((section, view.section_offset.probe_get()? as u64, view.view_size.probe_get()?));
        section_reference = Some(reference);
    }
    let accepted = server::accept_legacy(out, port_context, request, accept, views, 1);
    if let Some(reference) = section_reference {
        let _ = reference.release();
    }
    let accepted = match accepted? {
        Ok(accepted) => accepted,
        Err(status) => return Ok(status),
    };
    if !accept {
        return Ok(STATUS_SUCCESS);
    }
    if let (Some(target), Some((local, remote))) = (server_section, &accepted.server_view) {
        target.view_size.probe_set(local.size)?;
        target.view_base.probe_set(local.base)?;
        target.view_remote_base.probe_set(remote.base)?;
    }
    if client_view != 0 {
        let target = state::user_struct::<RemotePortView>(client_view)?;
        target.view_size.probe_set(accepted.client_view.as_ref().map_or(0, |view| view.size))?;
        target.view_base.probe_set(accepted.client_view.as_ref().map_or(0, |view| view.base))?;
    }
    Ok(STATUS_SUCCESS)
}

/// NtCompleteConnectPort(PortHandle): no 19041 a aceitação já concluiu a
/// conexão e o serviço só devolve STATUS_SUCCESS (nem o handle é conferido).
pub fn complete_connect(_handle: u64) -> u32 {
    STATUS_SUCCESS
}

// ---- envio do cliente --------------------------------------------------------

/// A troca de modo usuário pelo transporte ALPC do cliente.
fn exchange(port: &Arc<Port>, flags: u32, input: u64, receive: ReceiveArguments) -> Result<u32, KernelError> {
    Ok(match user_alpc::exchange_messages(port, flags, input, 0, receive, 1)? {
        Exchange::Status(status) => status,
        Exchange::Wait(_) => return Err(KernelError::new("LPC user exchange produced a kernel wait")),
    })
}

/// NtRequestPort(PortHandle, RequestMessage): o datagrama (LPC_DATAGRAM). Do
/// lado servidor é a mensagem nova do servidor (na própria porta de conexão,
/// ou ao cliente de uma porta de comunicação).
pub fn request(handle: u64, message: u64) -> Result<u32, KernelError> {
    let none = ReceiveArguments { output: 0, length: 0, receive_attributes: 0, timeout: 0 };
    state::guarded(|| {
        with_port(handle, PORT_CONNECT, |port| {
            if server::owns(port) {
                return server::exchange(port, RELEASE_MESSAGE, message, 0, none);
            }
            exchange(port, RELEASE_MESSAGE, message, none)
        })
    })
}

/// NtRequestWaitReplyPort(PortHandle, RequestMessage, ReplyMessage): o
/// pedido síncrono (LPC_REQUEST) e a resposta no mesmo serviço. Do lado
/// servidor é a mensagem nova síncrona do servidor.
pub fn request_wait_reply(handle: u64, request: u64, reply: u64) -> Result<u32, KernelError> {
    state::guarded(|| {
        with_port(handle, PORT_CONNECT, |port| {
            let status = probe_receive_header(reply);
            if status != 0 {
                return Ok(status);
            }
            let receive = ReceiveArguments { output: reply, length: 0, receive_attributes: 0, timeout: 0 };
            if server::owns(port) {
                return server::exchange(port, SYNC_REQUEST, request, 0, receive).map(legacy_status);
            }
            exchange(port, SYNC_REQUEST, request, receive).map(legacy_status)
        })
    })
}

/// NtReplyWaitReplyPort(PortHandle, ReplyMessage): a resposta que espera a
/// réplica do cliente não existe no transporte (STATUS_NOT_SUPPORTED).
pub fn reply_wait_reply(handle: u64, message: u64) -> Result<u32, KernelError> {
    let status = probe_receive_header(message);
    if status != 0 {
        return Ok(status);
    }
    state::guarded(|| {
        with_port(handle, PORT_CONNECT, |port| {
            // Numa porta de conexão, STATUS_INVALID_PARAMETER, como o 19041.
            if port.with(|state| state.role) == Role::Listener {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            crate::debug_print!("[lpc] NtReplyWaitReplyPort sem suporte");
            Ok(STATUS_NOT_SUPPORTED)
        })
    })
}

/// NtReadRequestData/NtWriteRequestData(PortHandle, Message, DataEntryIndex,
/// Buffer, BufferSize, NumberOfBytes): o PORT_MESSAGE sem
/// DataInfoOffset dá STATUS_INVALID_PARAMETER, como o LpcpCopyRequestData;
/// as entradas de dados não existem no transporte.
pub fn copy_request_data(handle: u64, message: u64, write: bool) -> Result<u32, KernelError> {
    if !state::probe_user_read(message, PortMessage::SIZE) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    state::guarded(|| {
        let offset = state::user_struct::<PortMessage>(message)?.u2.s2.data_info_offset.probe_get()?;
        if offset == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        with_port(handle, PORT_CONNECT, |_| {
            crate::debug_print!("[lpc] {} com PORT_DATA_INFORMATION sem suporte", if write { "NtWriteRequestData" } else { "NtReadRequestData" });
            Ok(STATUS_NOT_SUPPORTED)
        })
    })
}

// ---- impersonação e consulta --------------------------------------------------

/// NtAlpcImpersonateClientOfPort(PortHandle, Message, Flags) e
/// NtImpersonateClientOfPort(PortHandle, Message) (`legacy`: Flags zero, e a
/// mensagem não achada vira STATUS_REPLY_MESSAGE_MISMATCH), como no 19041:
///
/// - Flags: os bits 2-3 são um nível pedido (Flags acima de 15 dá
///   STATUS_INVALID_PARAMETER); com eles (ou o bit 1) o nível pedido não
///   pode passar do nível do contexto (STATUS_ACCESS_DENIED) e é o da
///   impersonação; o bit 0 escolhe o SeCreateClientSecurityEx, que aqui é o
///   mesmo contexto;
/// - com mensagem (o MessageId não pode ser zero), o AlpcpImpersonateMessage
///   ([`impersonate_message`]);
/// - sem mensagem, o contexto estático da conexão
///   ([`impersonate_connection`]).
pub fn impersonate_client(handle: u64, message: u64, flags: u32, legacy: bool) -> Result<u32, KernelError> {
    let status = state::guarded(|| {
        let id = if message != 0 {
            if !state::probe_user_read(message, PortMessage::SIZE) {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
            let id = state::user_struct::<PortMessage>(message)?.message_id.probe_get()?;
            if id == 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            Some(id)
        } else {
            None
        };
        let level = flags >> 2;
        if level > 3 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        let requested = (flags & ((level << 2) | 2) != 0).then_some(level);
        with_port(handle, PORT_CONNECT, |port| match id {
            Some(id) => impersonate_message(port, id, requested),
            None => impersonate_connection(port, requested),
        })
    })?;
    Ok(if legacy && status == STATUS_ALPC_MESSAGE_NOT_FOUND { STATUS_REPLY_MESSAGE_MISMATCH } else { status })
}

/// ALPC_PORFLG_ALLOW_IMPERSONATION (na porta do cliente) e
/// LPC_NO_IMPERSONATE (no Type da mensagem).
const ALLOW_IMPERSONATION: u32 = 0x1_0000;
const LPC_NO_IMPERSONATE: u16 = 0x4000;

/// AlpcpImpersonateMessage: a mensagem `id` precisa já ter sido recebida e
/// não trazer LPC_NO_IMPERSONATE (STATUS_ACCESS_DENIED). Com o contexto de
/// segurança que o cliente mandou (o atributo de segurança), o token dele;
/// senão a porta do cliente precisa de ALLOW_IMPERSONATION, e o
/// rastreamento estático usa o contexto capturado na conexão, o dinâmico a
/// thread que enviou e espera a resposta (o SeCreateClientSecurity com a
/// qualidade da porta do cliente; sem thread esperando, STATUS_ACCESS_DENIED).
fn impersonate_message(port: &Arc<Port>, id: u32, requested: Option<u32>) -> Result<u32, KernelError> {
    let Some(origin) = server::sender_of(port, id) else { return Ok(STATUS_ALPC_MESSAGE_NOT_FOUND) };
    if !origin.received || origin.message_type & LPC_NO_IMPERSONATE != 0 {
        return Ok(STATUS_ACCESS_DENIED);
    }
    if let Some((token, level, effective_only)) = server::received_security(port, id) {
        let status = match requested {
            Some(requested) if requested > level => Ok(STATUS_ACCESS_DENIED),
            requested => ps_security::impersonate_client(process::get_current_thread(), token, true, effective_only, requested.unwrap_or(level)),
        };
        let _ = crate::ntos::se::token::tokens::release(token);
        return status;
    }
    let Some(client) = port_objects::port_of(origin.client) else { return Ok(STATUS_ACCESS_DENIED) };
    let (flags, quality, connected) = client.with(|state| (state.port_flags, state.security_quality.unwrap_or(DEFAULT_QUALITY), state.client_security.clone()));
    if flags & ALLOW_IMPERSONATION == 0 {
        return Ok(STATUS_ACCESS_DENIED);
    }
    if quality.tracking == 0 {
        if let Some(connected) = connected {
            return impersonate_identity(&connected, requested);
        }
    }
    let thread = origin.sender.thread_pointer;
    if !origin.waiting || thread == 0 || requested.is_some_and(|requested| requested > quality.level) {
        return Ok(STATUS_ACCESS_DENIED);
    }
    impersonate_thread(thread, Quality { level: requested.unwrap_or(quality.level), ..quality })
}

/// NtAlpcImpersonateClientOfPort sem mensagem: o contexto estático
/// capturado na conexão do cliente ligado à porta de comunicação (a porta do
/// cliente precisa de ALLOW_IMPERSONATION e do rastreamento estático; senão,
/// STATUS_ACCESS_DENIED), pelo SeImpersonateClientEx.
fn impersonate_connection(port: &Arc<Port>, requested: Option<u32>) -> Result<u32, KernelError> {
    let Some(client) = server::connected_client(port) else { return Ok(STATUS_ACCESS_DENIED) };
    let (flags, quality, connected) = client.with(|state| (state.port_flags, state.security_quality.unwrap_or(DEFAULT_QUALITY), state.client_security.clone()));
    match connected {
        Some(connected) if flags & ALLOW_IMPERSONATION != 0 && quality.tracking == 0 => impersonate_identity(&connected, requested),
        _ => Ok(STATUS_ACCESS_DENIED),
    }
}

/// A impersonação de um contexto capturado, no nível dele ou no pedido (que
/// não pode passar dele).
fn impersonate_identity(identity: &crate::ntos::alpc::security_contexts::ClientIdentity, requested: Option<u32>) -> Result<u32, KernelError> {
    match requested {
        Some(requested) if requested > identity.level => Ok(STATUS_ACCESS_DENIED),
        requested => ps_security::impersonate_client(process::get_current_thread(), identity.token, true, identity.effective_only, requested.unwrap_or(identity.level)),
    }
}

/// SeCreateClientSecurity da thread do cliente com a qualidade dada e
/// SeImpersonateClientEx na thread corrente (o corpo do NtImpersonateThread).
fn impersonate_thread(thread: u64, quality: Quality) -> Result<u32, KernelError> {
    let captured = CapturedQuality { level: quality.level, tracking: quality.tracking, effective_only: quality.effective_only as u8 };
    ps_security::impersonate_thread(process::get_current_thread(), thread, captured)
}

/// NtQueryInformationPort(PortHandle, PortInformationClass, PortInformation,
/// Length, ReturnLength): o 19041 sonda a saída, confere o handle com
/// READ_CONTROL e só zera o ReturnLength (nenhuma classe devolve dados);
/// sem handle, STATUS_INVALID_INFO_CLASS.
pub fn query_information(handle: u64, information: u64, length: u32, return_length: u64) -> Result<u32, KernelError> {
    if !state::probe_user_write(information, length as u64) || (return_length != 0 && !state::probe_user_write(return_length, 4)) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if handle == 0 {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    let mut reference = match port_reference::reference(handle, READ_CONTROL, 1)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = if return_length != 0 { guest::try_write::<u32>(return_length, 0).map(|_| STATUS_SUCCESS).or(Ok(STATUS_ACCESS_VIOLATION)) } else { Ok(STATUS_SUCCESS) };
    let _ = reference.release();
    result
}
