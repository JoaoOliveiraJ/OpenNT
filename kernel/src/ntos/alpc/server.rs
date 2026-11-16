//! Portas ALPC de servidor, de modo usuário e de modo kernel.
//!
//! O lado servidor do ALPC para processos de usuário (o smss com o
//! `\SmApiPort`, o csrss com o `\Windows\ApiPort`) e para os drivers
//! (o win32kbase pelo ZwAlpcCreatePort e o ZwAlpcAcceptConnectPort, com
//! PreviousMode KernelMode: buffers do chamador sem sonda, handles de kernel
//! com OBJ_KERNEL_HANDLE e a espera de recepção pela continuação de kernel do
//! ZwAlpcSendWaitReceivePort):
//!
//! - NtAlpcCreatePort ([`create_port`]): a porta de conexão, com nome no
//!   namespace (o nó AlpcPort, ao qual o servidor [`UserServer`] fica
//!   associado como o serviço que os clientes encontram) ou sem nome, e o
//!   handle na tabela de quem cria;
//! - a conexão de um cliente (`Service::connect`): a mensagem
//!   LPC_CONNECTION_REQUEST entra na fila do servidor, a IOCP associada à
//!   porta de conexão recebe o aviso e a thread do cliente bloqueia
//!   (`ke::context_switch::wait_until`) até o servidor aceitar ou recusar;
//! - NtAlpcAcceptConnectPort ([`accept_connect_port`]): a porta de
//!   comunicação do servidor, com o PortContext dado, e a resposta de
//!   conexão (os dados da mensagem que o servidor devolve) para o cliente;
//!   a recusa devolve STATUS_PORT_CONNECTION_REFUSED;
//! - os pedidos do cliente (`Service::exchange`): LPC_REQUEST (com
//!   LPC_CONTINUATION_REQUIRED quando o cliente espera a resposta) ou
//!   LPC_DATAGRAM na fila do servidor; a resposta chega ao cliente pela
//!   continuação (o job), quando o servidor envia uma mensagem com o
//!   MessageId do pedido;
//! - a recepção do servidor ([`exchange`], pelo NtAlpcSendWaitReceivePort
//!   na porta de conexão ou de comunicação): a próxima mensagem da fila, com
//!   o ALPC_CONTEXT_ATTR (PortContext da comunicação, sequência e
//!   MessageId), ou a espera até chegar uma (sem prazo, ou o prazo dado;
//!   prazo zero devolve STATUS_TIMEOUT);
//! - o fim de um cliente: LPC_PORT_CLOSED na fila, com o PortContext;
//! - NtAlpcOpenSenderProcess/NtAlpcOpenSenderThread ([`open_sender`]): o
//!   processo ou a thread de quem enviou uma mensagem ainda pendente no
//!   servidor (pelo MessageId do PORT_MESSAGE).
//!
//! As mensagens que o servidor manda por iniciativa própria (MessageId zero)
//! ainda não existem aqui: STATUS_NOT_SUPPORTED, com registro.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::alpc::kernel_entry;
use crate::ntos::alpc::message::buffer::{self as message_buffer, Buffer};
use crate::ntos::alpc::port_reference;
use crate::ntos::alpc::small::context_attribute;
use crate::ntos::alpc::transport::{self, Job, JobResult, Listener, Reply, Request, Sender, Service};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{AlpcMessageAttributes, AlpcPortAttributes, ObjectAttributes, PortMessage};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::port::{self as port_objects, Port, PortState, Role};
use crate::ntos::ps::process;
use crate::ntos::ps::user::registry::parse_user_object_attributes;
use crate::ntos::ps::user::threads::{self, Wait};
use crate::ntos::ps::user::{handles, state};
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u32 = 0;
const STATUS_TIMEOUT: u32 = 0x102;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_PORT_DISCONNECTED: u32 = 0xC000_0037;
const STATUS_PORT_CONNECTION_REFUSED: u32 = 0xC000_0041;
const STATUS_INVALID_PORT_HANDLE: u32 = 0xC000_0042;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_CID: u32 = 0xC000_000B;
const STATUS_REPLY_MESSAGE_MISMATCH: u32 = 0xC000_021F;
/// O AlpcpLookupMessage sem mensagem com o MessageId pedido.
const STATUS_INVALID_MESSAGE: u32 = 0xC000_0702;

/// Tipos de PORT_MESSAGE (o byte baixo de Type).
const LPC_REQUEST: u16 = 1;
const LPC_DATAGRAM: u16 = 3;
const LPC_PORT_CLOSED: u16 = 5;
const LPC_CONNECTION_REQUEST: u16 = 10;
/// O cliente espera a resposta (envio com ALPC_MSGFLG_SYNC_REQUEST).
const LPC_CONTINUATION_REQUIRED: u16 = 0x2000;
/// ALPC_MESSAGE_CONTEXT_ATTRIBUTE.
const CONTEXT_ATTRIBUTE: u32 = 0x2000_0000;
/// O maior PORT_MESSAGE de uma porta ALPC.
const MAXIMUM_MESSAGE_LENGTH: u64 = 0xFFFF;
/// OBJ_INHERIT e OBJ_KERNEL_HANDLE não valem para um handle de usuário.
const OBJ_INHERIT: u32 = 2;
const OBJ_KERNEL_HANDLE: u32 = 0x200;

/// Uma mensagem na fila do servidor, ainda não recebida.
struct Delivery {
    id: u32,
    message_type: u16,
    data: Vec<u8>,
    sender: Sender,
    port_context: u64,
}

/// Uma conexão à espera da decisão do servidor: o status e os dados da
/// resposta de conexão.
struct PendingConnection {
    client: Arc<Port>,
    decision: SpinLock<Option<(u32, Vec<u8>)>>,
}

/// A resposta de um pedido, preenchida quando o servidor responde.
type ReplySlot = Arc<SpinLock<Option<JobResult>>>;

/// O vínculo de um cliente conectado: a porta de comunicação do servidor e o
/// PortContext dela.
struct Link {
    server_port: Arc<Port>,
    context: u64,
}

#[derive(Default)]
struct ServerState {
    next_id: u32,
    sequence: u32,
    queue: VecDeque<Delivery>,
    connections: BTreeMap<u32, Arc<PendingConnection>>,
    requests: BTreeMap<u32, ReplySlot>,
    /// Quem enviou cada mensagem ainda pendente (para o OpenSender*).
    senders: BTreeMap<u32, Sender>,
    /// Clientes conectados, pelo ponteiro da porta do cliente.
    links: BTreeMap<u64, Link>,
    closed: bool,
}

/// O servidor de uma porta de conexão de usuário.
pub struct UserServer {
    listener: Arc<Port>,
    endpoint: SpinLock<Option<Arc<Listener>>>,
    state: SpinLock<ServerState>,
}

/// Servidores pelo ponteiro da porta de conexão; portas de comunicação pelo
/// próprio ponteiro, com o servidor e a porta do cliente.
static SERVERS: SpinLock<BTreeMap<u64, Arc<UserServer>>> = SpinLock::new(BTreeMap::new());
static COMMUNICATION: SpinLock<BTreeMap<u64, (Arc<UserServer>, u64)>> = SpinLock::new(BTreeMap::new());

impl UserServer {
    fn next_id(state: &mut ServerState) -> u32 {
        state.next_id = state.next_id.wrapping_add(1).max(1);
        state.next_id
    }

    /// Põe a mensagem na fila e avisa a IOCP da porta de conexão.
    fn enqueue(&self, delivery: Delivery) {
        self.state.lock().queue.push_back(delivery);
        if let Some(completion) = self.listener.with(|state| state.completion.clone()) {
            completion.notify();
        }
        kernel_entry::notify_waiters();
    }

    /// O servidor fechou a porta de conexão: as conexões pendentes são
    /// recusadas e o nome sai do namespace.
    fn close(&self) {
        let (connections, requests) = {
            let mut state = self.state.lock();
            state.closed = true;
            state.queue.clear();
            (core::mem::take(&mut state.connections), core::mem::take(&mut state.requests))
        };
        for connection in connections.values() {
            *connection.decision.lock() = Some((STATUS_PORT_CONNECTION_REFUSED, Vec::new()));
        }
        for slot in requests.values() {
            *slot.lock() = Some(JobResult { status: STATUS_PORT_DISCONNECTED, ..JobResult::default() });
        }
        if let Some(endpoint) = self.endpoint.lock().take() {
            transport::unregister(&endpoint);
        }
        kernel_entry::notify_waiters();
    }
}

/// A continuação do pedido de um cliente: conclui quando o servidor responde.
struct ReplyJob {
    slot: ReplySlot,
}

impl Job for ReplyJob {
    fn poll(&mut self) -> Option<JobResult> {
        self.slot.lock().take()
    }
}

impl Service for UserServer {
    fn max_message_length(&self) -> u32 {
        self.listener.maximum()
    }

    fn max_connection_info(&self) -> u32 {
        self.listener.maximum().saturating_sub(PortMessage::SIZE as u32)
    }

    /// LPC_CONNECTION_REQUEST na fila; a thread do cliente espera a decisão.
    fn connect(&self, port: &Arc<Port>, data: &[u8], _request: Option<&[u8]>) -> Reply {
        let pending = Arc::new(PendingConnection { client: port.clone(), decision: SpinLock::new(None) });
        let sender = current_sender();
        let id = {
            let mut state = self.state.lock();
            if state.closed {
                return Reply::Now(JobResult { status: STATUS_PORT_CONNECTION_REFUSED, ..JobResult::default() });
            }
            let id = UserServer::next_id(&mut state);
            state.connections.insert(id, pending.clone());
            state.senders.insert(id, sender);
            id
        };
        self.enqueue(Delivery { id, message_type: LPC_CONNECTION_REQUEST, data: Vec::from(data), sender, port_context: 0 });
        let decision = pending.clone();
        let status = kernel_entry::wait_transport(&mut || decision.decision.lock().as_ref().map(|(status, _)| *status), crate::ntos::ke::wait::Deadline::Infinite, 0, false);
        let (status, data) = pending.decision.lock().take().unwrap_or((status, Vec::new()));
        let server = Sender { process: self.listener.process_id(), thread: self.listener.thread_id(), thread_pointer: 0 };
        {
            let mut state = self.state.lock();
            state.connections.remove(&id);
            state.senders.remove(&id);
        }
        Reply::Now(JobResult { status, data, sender: Some(server) })
    }

    /// LPC_REQUEST ou LPC_DATAGRAM na fila; a resposta conclui o job.
    fn exchange(&self, port: &Arc<Port>, data: &[u8], request: &Arc<Request>) -> Reply {
        let (synchronous, datagram, sender) = {
            let state = request.state.lock();
            (state.synchronous, state.datagram, state.sender)
        };
        let slot: ReplySlot = Arc::new(SpinLock::new(None));
        let (id, context) = {
            let mut state = self.state.lock();
            let Some(context) = state.links.get(&port.pointer).map(|link| link.context) else { return Reply::Now(JobResult { status: STATUS_PORT_DISCONNECTED, ..JobResult::default() }) };
            let id = UserServer::next_id(&mut state);
            if !datagram {
                state.requests.insert(id, slot.clone());
            }
            state.senders.insert(id, sender);
            (id, context)
        };
        let message_type = if datagram { LPC_DATAGRAM } else if synchronous { LPC_REQUEST | LPC_CONTINUATION_REQUIRED } else { LPC_REQUEST };
        self.enqueue(Delivery { id, message_type, data: Vec::from(data), sender, port_context: context });
        if datagram {
            return Reply::Now(JobResult::default());
        }
        Reply::Later(Box::new(ReplyJob { slot }))
    }

    /// O cliente saiu: LPC_PORT_CLOSED na fila, com o PortContext dele.
    fn disconnect(&self, port: &Arc<Port>) {
        let (link, id) = {
            let mut state = self.state.lock();
            let Some(link) = state.links.remove(&port.pointer) else { return };
            let id = UserServer::next_id(&mut state);
            (link, id)
        };
        COMMUNICATION.lock().remove(&link.server_port.pointer);
        let sender = Sender { process: port.process_id(), thread: port.thread_id(), thread_pointer: 0 };
        self.enqueue(Delivery { id, message_type: LPC_PORT_CLOSED, data: Vec::new(), sender, port_context: link.context });
    }
}

fn current_sender() -> Sender {
    Sender { process: process::get_current_process_id(), thread: process::get_current_thread_id(), thread_pointer: process::get_current_thread() }
}

/// O servidor de uma porta de conexão ou de comunicação.
fn server_of(port: &Arc<Port>) -> Option<Arc<UserServer>> {
    SERVERS.lock().get(&port.pointer).cloned().or_else(|| COMMUNICATION.lock().get(&port.pointer).map(|(server, _)| server.clone()))
}

/// A porta é o lado servidor de uma conexão de usuário.
pub fn owns(port: &Arc<Port>) -> bool {
    server_of(port).is_some()
}

/// O PORT_MESSAGE x64 que o servidor recebe: o cabeçalho com o tipo, o
/// CLIENT_ID de quem enviou e o MessageId, seguido dos dados.
fn message_bytes(delivery: &Delivery) -> Vec<u8> {
    let header = PortMessage::SIZE as usize;
    let mut bytes = alloc::vec![0u8; header + delivery.data.len()];
    let put16 = |bytes: &mut Vec<u8>, offset: usize, value: u16| bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    put16(&mut bytes, offset_of!(PortMessage, u1.s1.data_length), delivery.data.len() as u16);
    put16(&mut bytes, offset_of!(PortMessage, u1.s1.total_length), (header + delivery.data.len()) as u16);
    put16(&mut bytes, offset_of!(PortMessage, u2.s2.type_), delivery.message_type);
    let process = offset_of!(PortMessage, client_id.unique_process);
    bytes[process..process + 8].copy_from_slice(&delivery.sender.process.to_le_bytes());
    let thread = offset_of!(PortMessage, client_id.unique_thread);
    bytes[thread..thread + 8].copy_from_slice(&delivery.sender.thread.to_le_bytes());
    let id = offset_of!(PortMessage, message_id);
    bytes[id..id + 4].copy_from_slice(&delivery.id.to_le_bytes());
    bytes[header..].copy_from_slice(&delivery.data);
    bytes
}

/// O ALPC_MESSAGE_ATTRIBUTES de recepção (já validado): o ALPC_CONTEXT_ATTR,
/// quando alocado, com o PortContext, a sequência e o MessageId, e o
/// ValidAttributes correspondente.
fn publish_context(attributes: u64, delivery: &Delivery, sequence: u32) -> Result<(), u32> {
    if attributes == 0 {
        return Ok(());
    }
    let header = state::user_struct::<AlpcMessageAttributes>(attributes).map_err(|error| error.status)?;
    let allocated = header.allocated_attributes.probe_get().map_err(|error| error.status)? & CONTEXT_ATTRIBUTE;
    if allocated != 0 {
        let at = crate::ntos::ps::user::alpc::attribute_address(attributes, CONTEXT_ATTRIBUTE);
        context_attribute::try_write(at, delivery.port_context, 0, sequence, delivery.id, 0)?;
    }
    header.valid_attributes.probe_set(allocated).map_err(|error| error.status)
}

/// Entrega a próxima mensagem da fila no buffer do servidor; `None` com a
/// fila vazia. Um buffer pequeno deixa a mensagem na fila
/// (STATUS_BUFFER_TOO_SMALL com o comprimento pedido).
fn receive_one(server: &UserServer, buffer: &Buffer, attributes: u64) -> Option<u32> {
    let mut state = server.state.lock();
    if state.closed {
        return Some(STATUS_PORT_DISCONNECTED);
    }
    let delivery = state.queue.front()?;
    let bytes = message_bytes(delivery);
    let status = message_buffer::deliver(buffer, &bytes, true);
    if status != 0 {
        return Some(status);
    }
    state.sequence = state.sequence.wrapping_add(1);
    let sequence = state.sequence;
    let delivery = state.queue.pop_front()?;
    // Um aviso de fechamento não espera resposta nem abertura do remetente.
    if delivery.message_type == LPC_PORT_CLOSED {
        state.senders.remove(&delivery.id);
    }
    drop(state);
    Some(publish_context(attributes, &delivery, sequence).err().unwrap_or(STATUS_SUCCESS))
}

/// O envio do servidor: a resposta ao pedido do MessageId da mensagem.
fn send_reply(server: &UserServer, input: u64, mode: u8) -> u32 {
    let captured = match message_buffer::capture_message(input, server.listener.maximum().max(PortMessage::SIZE as u32), mode) {
        Ok(captured) => captured,
        Err(status) => return status,
    };
    let id_offset = offset_of!(PortMessage, message_id);
    let id = u32::from_le_bytes([captured.header[id_offset], captured.header[id_offset + 1], captured.header[id_offset + 2], captured.header[id_offset + 3]]);
    if id == 0 {
        crate::debug_print!("[alpc] servidor de usuario: mensagem sem MessageId (envio do servidor) sem suporte");
        return STATUS_NOT_SUPPORTED;
    }
    let slot = {
        let mut state = server.state.lock();
        let slot = state.requests.remove(&id);
        if slot.is_some() {
            state.senders.remove(&id);
        }
        slot
    };
    let Some(slot) = slot else { return STATUS_REPLY_MESSAGE_MISMATCH };
    *slot.lock() = Some(JobResult { status: STATUS_SUCCESS, data: captured.data, sender: Some(current_sender()) });
    kernel_entry::notify_waiters();
    STATUS_SUCCESS
}

/// NtAlpcSendWaitReceivePort na porta de conexão ou de comunicação de um
/// servidor de usuário: a resposta (se houver mensagem de envio) e depois a
/// recepção (se houver buffer), com a espera pela próxima mensagem.
pub fn exchange(port: &Arc<Port>, flags: u32, input: u64, receive: crate::ntos::ps::user::alpc::ReceiveArguments) -> Result<u32, KernelError> {
    let Some(server) = server_of(port) else { return Ok(STATUS_INVALID_PORT_HANDLE) };
    if flags & 0x2_0000 != 0 {
        crate::debug_print!("[alpc] servidor de usuario: pedido sincrono do servidor sem suporte");
        return Ok(STATUS_NOT_SUPPORTED);
    }
    if input != 0 {
        let status = send_reply(&server, input, 1);
        if status != 0 {
            return Ok(status);
        }
    }
    if receive.output == 0 {
        return Ok(STATUS_SUCCESS);
    }
    let header = message_buffer::probe_header(receive.output, 1);
    if header != 0 {
        return Ok(header);
    }
    let status = crate::ntos::ps::user::alpc::attributes(receive.receive_attributes, false, 1);
    if status != 0 {
        return Ok(status);
    }
    let buffer = match message_buffer::capture_length(receive.output, receive.length, 1) {
        Ok(buffer) => buffer,
        Err(status) => return Ok(status),
    };
    if receive.timeout != 0 && !state::probe_user_read(receive.timeout, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if let Some(status) = receive_one(&server, &buffer, receive.receive_attributes) {
        return Ok(status);
    }
    if receive.timeout != 0 && guest::try_read::<i64>(receive.timeout)? == 0 {
        return Ok(STATUS_TIMEOUT);
    }
    let attributes = receive.receive_attributes;
    let waiting = server.clone();
    let wait = Wait { poll: Some(Box::new(move || receive_one(&waiting, &buffer, attributes))), ..Wait::default() };
    Ok(threads::wait_custom(wait, receive.timeout, None))
}

/// Como no ObInsertObject, quem cria a porta recebe o acesso total ao
/// objeto que acabou de criar, sem passar pela DACL do descritor que ele
/// mesmo deu no OBJECT_ATTRIBUTES.
fn creator_options(mode: u8, object_flags: u32) -> port_objects::CreateOptions {
    if mode != 0 {
        return port_objects::CreateOptions { grant_on_create: true, ..port_objects::CreateOptions::default() };
    }
    // Uma porta de kernel com OBJ_KERNEL_HANDLE pertence ao System.
    let owner = if object_flags & OBJ_KERNEL_HANDLE != 0 { process::get_system_process() } else { process::get_current_process() };
    port_objects::CreateOptions { owner_process: Some(owner), kernel_mode: true, grant_on_create: true }
}

/// OBJECT_ATTRIBUTES.Attributes (0 sem OBJECT_ATTRIBUTES); o de modo
/// usuário já foi sondado pelo chamador.
fn object_flags(attributes: u64) -> Result<u32, KernelError> {
    Ok(if attributes != 0 { state::user_struct::<ObjectAttributes>(attributes)?.attributes.probe_get()? } else { 0 })
}

/// O handle de quem criou a porta: um handle de usuário (só OBJ_INHERIT
/// vale), ou, em KernelMode, o ObOpenObjectByPointer com os atributos do
/// chamador (OBJ_KERNEL_HANDLE põe o handle na tabela do System).
fn publish_created(port: &Arc<Port>, out: u64, object_flags: u32, mode: u8) -> Result<u32, KernelError> {
    if mode != 0 {
        return port_objects::publish_created(port, out, object_flags & OBJ_INHERIT);
    }
    let type_pointer = crate::ntos::ob::object_types::user_type("alpc").map_or(0, |object_type| object_type.pointer);
    Ok(crate::ntos::ob::open_pointer::open(port.pointer, object_flags & 0x222, 0, 0x1F_0001, type_pointer, 0, out)? as u32)
}

/// O nome do OBJECT_ATTRIBUTES de kernel de uma porta: `None` sem nome.
fn kernel_port_name(attributes: u64) -> Result<Option<String>, u32> {
    if attributes == 0 {
        return Ok(None);
    }
    // SAFETY: OBJECT_ATTRIBUTES de um chamador de modo kernel.
    if unsafe { ObjectAttributes::at(attributes) }.object_name.get() == 0 {
        return Ok(None);
    }
    let path = crate::ntos::io::file::zw::file_path_from_object_attributes(attributes)?;
    Ok(if path.is_empty() { None } else { Some(path) })
}

/// O nome do OBJECT_ATTRIBUTES de uma porta: `None` sem nome.
fn port_name(attributes: u64) -> Result<Option<String>, u32> {
    if attributes == 0 {
        return Ok(None);
    }
    let parsed = parse_user_object_attributes(attributes).ok_or(STATUS_ACCESS_VIOLATION)?;
    if parsed.path.is_empty() {
        return Ok(None);
    }
    if !parsed.path.starts_with('\\') {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(Some(parsed.path))
}

/// NtAlpcCreatePort(PortHandle*, ObjectAttributes, PortAttributes): a porta
/// de conexão de um servidor de usuário.
pub fn create_port(out: u64, attributes: u64, port_attributes: u64, mode: u8) -> Result<u32, KernelError> {
    if mode != 0 && (!state::probe_user_write(out, 8) || (attributes != 0 && !state::probe_user_read(attributes, ObjectAttributes::SIZE)) || (port_attributes != 0 && !state::probe_user_read(port_attributes, AlpcPortAttributes::SIZE))) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let name = match if mode != 0 { port_name(attributes) } else { kernel_port_name(attributes) } {
        Ok(name) => name,
        Err(status) => return Ok(status),
    };
    let (port_flags, maximum, maximum_view_size, duplicate_object_types) = if port_attributes != 0 {
        let captured = state::user_struct::<AlpcPortAttributes>(port_attributes)?;
        (captured.flags.probe_get()?, captured.max_message_length.probe_get()?, captured.max_view_size.probe_get()?, captured.dup_object_types.probe_get()?)
    } else {
        (0, MAXIMUM_MESSAGE_LENGTH, 0, 0)
    };
    if maximum < PortMessage::SIZE || maximum > MAXIMUM_MESSAGE_LENGTH {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // O nome: o diretório pai existe e o nó ainda não.
    let (parent, leaf) = match &name {
        Some(path) => {
            if object_manager::lookup(path).is_some() {
                return Ok(STATUS_OBJECT_NAME_COLLISION);
            }
            let split = path.rfind('\\').unwrap_or(0);
            let parent = if split == 0 { String::from("\\") } else { String::from(&path[..split]) };
            if object_manager::lookup(&parent).is_none() {
                return Ok(STATUS_OBJECT_PATH_NOT_FOUND);
            }
            (parent, String::from(&path[split + 1..]))
        }
        None => (String::new(), String::new()),
    };
    let initial = PortState { role: Role::Listener, port_flags, maximum_view_size, duplicate_object_types, ..PortState::default() };
    let object_flags = object_flags(attributes)?;
    let port = match port_objects::create("alpc", initial, maximum as u32, 1, attributes, Box::new(|listener: &Arc<Port>| {
        if let Some(server) = SERVERS.lock().remove(&listener.pointer) {
            server.close();
        }
    }), creator_options(mode, object_flags)) {
        Ok(port) => port,
        Err(error) if error.status != 0 => return Ok(error.status),
        Err(error) => return Err(error),
    };
    let server = Arc::new(UserServer { listener: port.clone(), endpoint: SpinLock::new(None), state: SpinLock::new(ServerState::default()) });
    SERVERS.lock().insert(port.pointer, server.clone());
    let result = port.run(|| -> Result<u32, KernelError> {
        if name.is_some() {
            let node = match object_manager::create_object(&parent, &leaf, "AlpcPort", None) {
                Ok(node) => node,
                Err(error) => return Ok(if error.status != 0 { error.status } else { STATUS_OBJECT_NAME_COLLISION }),
            };
            *server.endpoint.lock() = Some(transport::attach(node, server.clone()));
        }
        let status = publish_created(&port, out, object_flags, mode)?;
        if status != 0 {
            return Ok(status);
        }
        port.set_started(true);
        crate::debug_print!("[alpc] porta de servidor {} criada pelo pid {} (modo {})", name.as_deref().unwrap_or("(sem nome)"), port.process_id(), mode);
        Ok(STATUS_SUCCESS)
    });
    if !matches!(result, Ok(STATUS_SUCCESS)) {
        if let Some(server) = SERVERS.lock().remove(&port.pointer) {
            server.close();
        }
    }
    crate::ntos::ob::objects::dispatcher::collect(port.pointer);
    result
}

/// NtAlpcAcceptConnectPort(PortHandle*, ConnectionPortHandle, Flags,
/// ObjectAttributes, PortAttributes, PortContext, ConnectionRequest,
/// ConnectionMessageAttributes, AcceptConnection).
#[allow(clippy::too_many_arguments)]
pub fn accept_connect_port(out: u64, connection: u64, attributes: u64, port_context: u64, request: u64, accept: bool, mode: u8) -> Result<u32, KernelError> {
    let mut reference = match port_reference::reference(connection, 0, mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let listener = reference.port.clone();
    let result = (|| -> Result<u32, KernelError> {
        let Some(server) = SERVERS.lock().get(&listener.pointer).cloned() else { return Ok(STATUS_INVALID_PORT_HANDLE) };
        let captured = match message_buffer::capture_message(request, listener.maximum(), mode) {
            Ok(captured) => captured,
            Err(status) => return Ok(status),
        };
        let id_offset = offset_of!(PortMessage, message_id);
        let id = u32::from_le_bytes([captured.header[id_offset], captured.header[id_offset + 1], captured.header[id_offset + 2], captured.header[id_offset + 3]]);
        let Some(pending) = server.state.lock().connections.get(&id).cloned() else { return Ok(STATUS_REPLY_MESSAGE_MISMATCH) };
        if !accept {
            *pending.decision.lock() = Some((STATUS_PORT_CONNECTION_REFUSED, Vec::new()));
            kernel_entry::notify_waiters();
            return Ok(STATUS_SUCCESS);
        }
        if mode != 0 && !state::probe_user_write(out, 8) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let object_flags = object_flags(attributes)?;
        let initial = PortState { role: Role::Server, port_context, ..PortState::default() };
        let disconnecting = server.clone();
        let client_pointer = pending.client.pointer;
        let communication = match port_objects::create("alpc", initial, listener.maximum(), 1, attributes, Box::new(move |port: &Arc<Port>| {
            COMMUNICATION.lock().remove(&port.pointer);
            disconnecting.state.lock().links.remove(&client_pointer);
        }), creator_options(mode, object_flags)) {
            Ok(port) => port,
            Err(error) if error.status != 0 => return Ok(error.status),
            Err(error) => return Err(error),
        };
        let outcome = communication.run(|| -> Result<u32, KernelError> {
            let status = publish_created(&communication, out, object_flags, mode)?;
            if status != 0 {
                return Ok(status);
            }
            communication.set_started(true);
            COMMUNICATION.lock().insert(communication.pointer, (server.clone(), client_pointer));
            server.state.lock().links.insert(client_pointer, Link { server_port: communication.clone(), context: port_context });
            *pending.decision.lock() = Some((STATUS_SUCCESS, captured.data.clone()));
            kernel_entry::notify_waiters();
            Ok(STATUS_SUCCESS)
        });
        crate::ntos::ob::objects::dispatcher::collect(communication.pointer);
        outcome
    })();
    let _ = reference.release();
    result
}

/// NtAlpcOpenSenderProcess / NtAlpcOpenSenderThread(Handle*, PortHandle,
/// PortMessage, Flags, DesiredAccess, ObjectAttributes): o processo (ou a
/// thread) de quem enviou a mensagem `message`, ainda pendente no servidor.
pub fn open_sender(out: u64, port_handle: u64, message: u64, access: u32, attributes: u64, thread: bool) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) || !state::probe_user_read(message, PortMessage::SIZE) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let mut reference = match port_reference::reference(port_handle, 0, 1)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let port = reference.port.clone();
    let result = (|| -> Result<u32, KernelError> {
        let Some(server) = server_of(&port) else { return Ok(STATUS_INVALID_PORT_HANDLE) };
        let id = state::user_struct::<PortMessage>(message)?.message_id.probe_get()?;
        let Some(sender) = server.state.lock().senders.get(&id).copied() else { return Ok(STATUS_INVALID_MESSAGE) };
        let object_flags = if attributes != 0 { state::user_struct::<ObjectAttributes>(attributes)?.attributes.probe_get()? & OBJ_INHERIT } else { 0 };
        let handle = if thread {
            let found = threads::all().into_iter().find(|candidate| candidate.thread_id == sender.thread && candidate.with(|candidate| !candidate.dead));
            let Some(target) = found else { return Ok(STATUS_INVALID_CID) };
            let granted = match handles::thread_access(&target, access) {
                Ok(granted) => granted,
                Err(status) => return Ok(status),
            };
            match threads::thread_handle(&target, granted, object_flags) {
                Ok(handle) => handle,
                Err(error) if error.status != 0 => return Ok(error.status),
                Err(error) => return Err(error),
            }
        } else {
            let Some(target) = process::list_active_processes().into_iter().find(|entry| entry.pid == sender.process).map(|entry| entry.address) else { return Ok(STATUS_INVALID_CID) };
            let granted = match handles::process_access(target, access) {
                Ok(granted) => granted,
                Err(status) => return Ok(status),
            };
            match handles::open_process_handle(target, granted, object_flags)? {
                Ok(handle) => handle as u64,
                Err(status) => return Ok(status),
            }
        };
        guest::try_write::<u64>(out, handle)?;
        Ok(STATUS_SUCCESS)
    })();
    let _ = reference.release();
    result
}

/// ZwAlpcOpenSenderProcess(ProcessHandle*, PortHandle, PortMessage, Flags,
/// DesiredAccess, ObjectAttributes): o NtAlpcOpenSenderProcess em KernelMode
/// (ntoskrnl 19041 rva 0x5dffa0). A mensagem e os atributos são do chamador
/// de kernel, sem sondas; o ClientId do cabeçalho tem de ser o do remetente
/// (STATUS_INVALID_CID) e o handle sai como no PsOpenProcess, pelo
/// ObOpenObjectByPointer com os atributos do chamador (OBJ_KERNEL_HANDLE dá
/// um handle de kernel).
pub fn open_sender_process_kernel(out: u64, port_handle: u64, message: u64, access: u32, attributes: u64) -> Result<u32, KernelError> {
    let mut reference = match port_reference::reference(port_handle, 0, 0)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let port = reference.port.clone();
    let result = (|| -> Result<u32, KernelError> {
        let Some(server) = server_of(&port) else { return Ok(STATUS_INVALID_PORT_HANDLE) };
        // SAFETY: PPORT_MESSAGE e POBJECT_ATTRIBUTES de um chamador de kernel.
        let header = unsafe { PortMessage::at(message) };
        let Some(sender) = server.state.lock().senders.get(&header.message_id.get()).copied() else { return Ok(STATUS_INVALID_MESSAGE) };
        if header.client_id.unique_process.get() != sender.process || header.client_id.unique_thread.get() != sender.thread {
            return Ok(STATUS_INVALID_CID);
        }
        let Some(target) = process::list_active_processes().into_iter().find(|entry| entry.pid == sender.process).map(|entry| entry.address) else { return Ok(STATUS_INVALID_CID) };
        let object_flags = if attributes != 0 { unsafe { ObjectAttributes::at(attributes) }.attributes.get() } else { 0 };
        let cell = guest::alloc_bytes(8);
        let status = crate::ntos::init::exports::invoke_handler("ObOpenObjectByPointer", &[target, object_flags as u64, 0, access as u64, crate::ntos::ob::object_types::process_type().pointer, 0, cell])? as u32;
        if status == STATUS_SUCCESS {
            // SAFETY: PHANDLE de saída do chamador de kernel.
            unsafe { crate::ntos::inc::field::Field::<u64>::at(out) }.set(guest::read64(cell));
        }
        guest::free_bytes(cell);
        Ok(status)
    })();
    let _ = reference.release();
    result
}

/// ZwAlpcSendWaitReceivePort na porta de conexão ou de comunicação de um
/// servidor de kernel: a resposta e a recepção como em [`exchange`], com os
/// buffers do chamador sem sonda e a espera pela continuação de kernel (o
/// prazo e o modo de espera do ZwAlpcSendWaitReceivePort).
pub fn begin_kernel_exchange(port: &Arc<Port>, flags: u32, input: u64, receive: crate::ntos::ps::user::alpc::ReceiveArguments) -> Result<Box<dyn crate::ntos::alpc::kernel_entry::Pending>, KernelError> {
    use crate::ntos::alpc::kernel_entry::Completed;
    use crate::ntos::alpc::kernel_wait;
    let Some(server) = server_of(port) else { return Ok(Box::new(Completed(STATUS_INVALID_PORT_HANDLE))) };
    if flags & 0x2_0000 != 0 {
        crate::debug_print!("[alpc] servidor de kernel: pedido sincrono do servidor sem suporte");
        return Ok(Box::new(Completed(STATUS_NOT_SUPPORTED)));
    }
    if input != 0 {
        let status = send_reply(&server, input, 0);
        if status != 0 {
            return Ok(Box::new(Completed(status)));
        }
    }
    if receive.output == 0 {
        return Ok(Box::new(Completed(STATUS_SUCCESS)));
    }
    let status = crate::ntos::ps::user::alpc::attributes(receive.receive_attributes, false, 0);
    if status != 0 {
        return Ok(Box::new(Completed(status)));
    }
    let buffer = match message_buffer::capture_length(receive.output, receive.length, 0) {
        Ok(buffer) => buffer,
        Err(status) => return Ok(Box::new(Completed(status))),
    };
    let timeout = match kernel_wait::capture_timeout(receive.timeout, 0) {
        Ok(timeout) => timeout,
        Err(status) => return Ok(Box::new(Completed(status))),
    };
    if let Some(status) = receive_one(&server, &buffer, receive.receive_attributes) {
        return Ok(Box::new(Completed(status)));
    }
    let attributes = receive.receive_attributes;
    let waiting = server.clone();
    let operation = kernel_wait::Operation { poll: Box::new(move || receive_one(&waiting, &buffer, attributes)), cleanup: Box::new(|_| {}) };
    let request = kernel_wait::begin(operation, timeout, kernel_wait::select_mode(flags, 0), flags & 0x20_0000 != 0)?;
    Ok(Box::new(request))
}
