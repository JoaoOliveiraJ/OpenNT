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
//! O mesmo servidor atende as portas LPC (`alpc/lpc_ports.rs`), que no
//! 19041 são portas ALPC com o modo LPC (ALPC_PORFLG_LPC_MODE, 0x1000, no
//! Flags dos atributos): a porta de conexão do NtCreatePort, a recepção
//! legada ([`receive_legacy`], com o PortContext da porta de comunicação e o
//! tipo sem os bits internos), a aceitação sem a porta de conexão
//! ([`accept_legacy`], que acha a conexão pelo MessageId e pelo CLIENT_ID do
//! PORT_MESSAGE) e as vistas de seção do PORT_VIEW e do REMOTE_PORT_VIEW
//! ([`ClientView`]: a seção do cliente, mapeada nele na conexão e no servidor
//! quando ele recebe a conexão com o ALPC_MESSAGE_VIEW_ATTRIBUTE ou a aceita
//! pedindo o REMOTE_PORT_VIEW).
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
use crate::ntos::inc::types::{AlpcDataViewAttr, AlpcMessageAttributes, AlpcPortAttributes, ObjectAttributes, PortMessage};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::port::{self as port_objects, Port, PortState, Role};
use crate::ntos::ps::process;
use crate::ntos::ps::user::registry::parse_user_object_attributes;
use crate::ntos::ps::user::sections::{self, MapRequest, Section, View};
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
const LPC_CLIENT_DIED: u16 = 6;
const LPC_CONNECTION_REQUEST: u16 = 10;
/// O cliente espera a resposta (envio com ALPC_MSGFLG_SYNC_REQUEST).
const LPC_CONTINUATION_REQUIRED: u16 = 0x2000;
/// ALPC_MESSAGE_CONTEXT_ATTRIBUTE.
const CONTEXT_ATTRIBUTE: u32 = 0x2000_0000;
/// ALPC_MESSAGE_VIEW_ATTRIBUTE.
const VIEW_ATTRIBUTE: u32 = 0x4000_0000;
/// O maior PORT_MESSAGE de uma porta ALPC.
const MAXIMUM_MESSAGE_LENGTH: u64 = 0xFFFF;
/// OBJ_INHERIT e OBJ_KERNEL_HANDLE não valem para um handle de usuário.
const OBJ_INHERIT: u32 = 2;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// ALPC_PORFLG_LPC_MODE: a porta é LPC (NtCreatePort, NtConnectPort).
pub const LPC_MODE: u32 = 0x1000;
/// O Type que um receptor LPC vê: os bits de tipo e os de origem (kernel e
/// sem impersonação), sem os internos (o LPC_CONTINUATION_REQUIRED), como o
/// AlpcpReceiveLegacyMessage.
const LEGACY_TYPE_MASK: u16 = 0xC00F;
/// PAGE_READWRITE das vistas de transferência.
const PAGE_READWRITE: u32 = 4;

/// Uma mensagem na fila do servidor, ainda não recebida.
struct Delivery {
    id: u32,
    message_type: u16,
    data: Vec<u8>,
    sender: Sender,
    port_context: u64,
    /// A seção de transferência de uma conexão LPC (o PORT_VIEW do cliente).
    view: Option<Arc<ClientView>>,
}

/// A seção de transferência de um cliente LPC: o PORT_VIEW do NtConnectPort,
/// mapeado no cliente na conexão e no servidor uma vez, quando ele recebe a
/// mensagem de conexão com o ALPC_MESSAGE_VIEW_ATTRIBUTE ou a aceita com o
/// REMOTE_PORT_VIEW. Cada vista sai com a porta do seu lado.
pub struct ClientView {
    section: Arc<Section>,
    offset: u64,
    client: Arc<View>,
    server: SpinLock<Option<Arc<View>>>,
}

impl ClientView {
    pub fn new(section: Arc<Section>, offset: u64, client: Arc<View>) -> Self {
        Self { section, offset, client, server: SpinLock::new(None) }
    }

    /// A vista no processo do cliente.
    pub fn client(&self) -> &Arc<View> {
        &self.client
    }

    /// A vista no servidor, depois de exposta.
    pub fn server(&self) -> Option<Arc<View>> {
        self.server.lock().clone()
    }

    /// Mapeia a seção no processo corrente (o servidor que recebe ou aceita)
    /// com o tamanho da vista do cliente, uma vez só.
    fn expose(&self) -> Result<Arc<View>, u32> {
        if let Some(view) = self.server.lock().clone() {
            return Ok(view);
        }
        let request = MapRequest { offset: self.offset, size: self.client.size, protect: PAGE_READWRITE, ..MapRequest::default() };
        let view = match sections::map(&self.section, &request) {
            Ok(Ok(view)) => view,
            Ok(Err(status)) => return Err(status),
            Err(error) => return Err(if error.status != 0 { error.status } else { 0xC000_0001 }),
        };
        let mut slot = self.server.lock();
        if let Some(existing) = slot.clone() {
            drop(slot);
            let _ = sections::unmap(&view, None);
            return Ok(existing);
        }
        *slot = Some(view.clone());
        Ok(view)
    }

    /// A conexão não foi aceita: a vista do servidor, se exposta, sai.
    fn withdraw(&self) {
        if let Some(view) = self.server.lock().take() {
            let _ = sections::unmap(&view, None);
        }
    }
}

/// A decisão do servidor sobre uma conexão: o status, os dados da resposta de
/// conexão e, numa aceitação LPC com o PORT_VIEW do servidor, a vista da
/// seção dele no processo do cliente.
#[derive(Default)]
pub struct Decision {
    pub status: u32,
    pub data: Vec<u8>,
    pub server_view: Option<Arc<View>>,
}

/// Uma conexão à espera da decisão do servidor.
struct PendingConnection {
    client: Arc<Port>,
    sender: Sender,
    view: Option<Arc<ClientView>>,
    decision: SpinLock<Option<Decision>>,
}

/// Quem enviou uma mensagem ainda pendente: o CLIENT_ID e a ETHREAD da
/// thread e a porta do cliente (a qualidade de segurança dele).
#[derive(Clone, Copy)]
pub struct Origin {
    pub sender: Sender,
    pub client: u64,
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
    /// Quem enviou cada mensagem ainda pendente (para o OpenSender* e a
    /// impersonação do cliente).
    senders: BTreeMap<u32, Origin>,
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
            refuse(connection);
        }
        for slot in requests.values() {
            *slot.lock() = Some(JobResult { status: STATUS_PORT_DISCONNECTED, ..JobResult::default() });
        }
        if let Some(endpoint) = self.endpoint.lock().take() {
            transport::unregister(&endpoint);
        }
        kernel_entry::notify_waiters();
    }

    /// A porta de conexão é LPC (NtCreatePort).
    pub fn legacy(&self) -> bool {
        self.listener.with(|state| state.port_flags) & LPC_MODE != 0
    }

    /// A porta de conexão (o maior PORT_MESSAGE, o dono).
    pub fn listener(&self) -> &Arc<Port> {
        &self.listener
    }

    /// LPC_CONNECTION_REQUEST na fila, com a vista do cliente; a thread do
    /// cliente espera a decisão do servidor.
    pub fn request_connection(&self, port: &Arc<Port>, data: &[u8], view: Option<Arc<ClientView>>) -> Decision {
        let sender = current_sender();
        let pending = Arc::new(PendingConnection { client: port.clone(), sender, view: view.clone(), decision: SpinLock::new(None) });
        let id = {
            let mut state = self.state.lock();
            if state.closed {
                return Decision { status: STATUS_PORT_CONNECTION_REFUSED, ..Decision::default() };
            }
            let id = UserServer::next_id(&mut state);
            state.connections.insert(id, pending.clone());
            state.senders.insert(id, Origin { sender, client: port.pointer });
            id
        };
        self.enqueue(Delivery { id, message_type: LPC_CONNECTION_REQUEST, data: Vec::from(data), sender, port_context: 0, view });
        let decision = pending.clone();
        let status = kernel_entry::wait_transport(&mut || decision.decision.lock().as_ref().map(|decision| decision.status), crate::ntos::ke::wait::Deadline::Infinite, 0, false);
        let decision = pending.decision.lock().take().unwrap_or(Decision { status, ..Decision::default() });
        {
            let mut state = self.state.lock();
            state.connections.remove(&id);
            state.senders.remove(&id);
            // Uma espera interrompida antes da decisão tira a mensagem que o
            // servidor ainda não recebeu.
            state.queue.retain(|delivery| delivery.id != id || delivery.message_type != LPC_CONNECTION_REQUEST);
        }
        if decision.status != STATUS_SUCCESS {
            if let Some(view) = &pending.view {
                view.withdraw();
            }
        }
        decision
    }
}

/// A recusa de uma conexão: STATUS_PORT_CONNECTION_REFUSED para o cliente e
/// a vista dele, se o servidor já a tinha, fora do servidor.
fn refuse(connection: &PendingConnection) {
    if let Some(view) = &connection.view {
        view.withdraw();
    }
    *connection.decision.lock() = Some(Decision { status: STATUS_PORT_CONNECTION_REFUSED, ..Decision::default() });
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
        let decision = self.request_connection(port, data, None);
        let server = Sender { process: self.listener.process_id(), thread: self.listener.thread_id(), thread_pointer: 0 };
        Reply::Now(JobResult { status: decision.status, data: decision.data, sender: Some(server) })
    }

    /// LPC_REQUEST ou LPC_DATAGRAM na fila; a resposta conclui o job.
    fn exchange(&self, port: &Arc<Port>, data: &[u8], request: &Arc<Request>) -> Reply {
        let (synchronous, datagram, mut sender) = {
            let state = request.state.lock();
            (state.synchronous, state.datagram, state.sender)
        };
        // A thread que enviou (para a impersonação do cliente).
        if sender.thread_pointer == 0 {
            sender.thread_pointer = request.identity.with(|state| state.sender_thread);
        }
        let slot: ReplySlot = Arc::new(SpinLock::new(None));
        let (id, context) = {
            let mut state = self.state.lock();
            let Some(context) = state.links.get(&port.pointer).map(|link| link.context) else { return Reply::Now(JobResult { status: STATUS_PORT_DISCONNECTED, ..JobResult::default() }) };
            let id = UserServer::next_id(&mut state);
            if !datagram {
                state.requests.insert(id, slot.clone());
            }
            state.senders.insert(id, Origin { sender, client: port.pointer });
            (id, context)
        };
        let message_type = if datagram { LPC_DATAGRAM } else if synchronous { LPC_REQUEST | LPC_CONTINUATION_REQUIRED } else { LPC_REQUEST };
        self.enqueue(Delivery { id, message_type, data: Vec::from(data), sender, port_context: context, view: None });
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
        self.enqueue(Delivery { id, message_type: LPC_PORT_CLOSED, data: Vec::new(), sender, port_context: link.context, view: None });
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
/// CLIENT_ID de quem enviou, o MessageId e, numa conexão com PORT_VIEW, o
/// ClientViewSize, seguido dos dados. Um receptor LPC vê o Type sem os bits
/// internos.
fn message_bytes(delivery: &Delivery, legacy: bool) -> Vec<u8> {
    let header = PortMessage::SIZE as usize;
    let mut bytes = alloc::vec![0u8; header + delivery.data.len()];
    let put16 = |bytes: &mut Vec<u8>, offset: usize, value: u16| bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    put16(&mut bytes, offset_of!(PortMessage, u1.s1.data_length), delivery.data.len() as u16);
    put16(&mut bytes, offset_of!(PortMessage, u1.s1.total_length), (header + delivery.data.len()) as u16);
    put16(&mut bytes, offset_of!(PortMessage, u2.s2.type_), if legacy { delivery.message_type & LEGACY_TYPE_MASK } else { delivery.message_type });
    let process = offset_of!(PortMessage, client_id.unique_process);
    bytes[process..process + 8].copy_from_slice(&delivery.sender.process.to_le_bytes());
    let thread = offset_of!(PortMessage, client_id.unique_thread);
    bytes[thread..thread + 8].copy_from_slice(&delivery.sender.thread.to_le_bytes());
    let id = offset_of!(PortMessage, message_id);
    bytes[id..id + 4].copy_from_slice(&delivery.id.to_le_bytes());
    if let Some(view) = &delivery.view {
        let size = offset_of!(PortMessage, client_view_size);
        bytes[size..size + 8].copy_from_slice(&view.client.size.to_le_bytes());
    }
    bytes[header..].copy_from_slice(&delivery.data);
    bytes
}

/// O ALPC_MESSAGE_ATTRIBUTES de recepção (já validado): o ALPC_CONTEXT_ATTR,
/// quando alocado, com o PortContext, a sequência e o MessageId; o
/// ALPC_DATA_VIEW_ATTR da vista do cliente exposta no servidor (a base e o
/// tamanho nele), quando alocado; e o ValidAttributes correspondente.
fn publish_attributes(attributes: u64, delivery: &Delivery, sequence: u32, view: Option<&Arc<View>>) -> Result<(), u32> {
    if attributes == 0 {
        return Ok(());
    }
    let header = state::user_struct::<AlpcMessageAttributes>(attributes).map_err(|error| error.status)?;
    let allocated = header.allocated_attributes.probe_get().map_err(|error| error.status)?;
    let mut valid = allocated & CONTEXT_ATTRIBUTE;
    if valid != 0 {
        let at = crate::ntos::ps::user::alpc::attribute_address(attributes, CONTEXT_ATTRIBUTE);
        context_attribute::try_write(at, delivery.port_context, 0, sequence, delivery.id, 0)?;
    }
    if let Some(view) = view.filter(|_| allocated & VIEW_ATTRIBUTE != 0) {
        let at = crate::ntos::ps::user::alpc::attribute_address(attributes, VIEW_ATTRIBUTE);
        let attribute = state::user_struct::<AlpcDataViewAttr>(at).map_err(|error| error.status)?;
        let fill = || -> Result<(), KernelError> {
            attribute.flags.probe_set(0)?;
            attribute.section_handle.probe_set(0)?;
            attribute.view_base.probe_set(view.base)?;
            attribute.view_size.probe_set(view.size)
        };
        fill().map_err(|error| error.status)?;
        valid |= VIEW_ATTRIBUTE;
    }
    header.valid_attributes.probe_set(valid).map_err(|error| error.status)
}

/// O que a recepção faz além de entregar a mensagem.
#[derive(Clone, Copy, Default)]
struct ReceiveOptions {
    /// O receptor é LPC: o Type sem os bits internos.
    legacy: bool,
    /// PVOID *PortContext do NtReplyWaitReceivePort (0: não pedido).
    port_context: u64,
    /// O NtListenPort: só mensagens de conexão; as outras são descartadas.
    connections_only: bool,
}

/// Entrega a próxima mensagem da fila no buffer do servidor; `None` com a
/// fila vazia. Um buffer pequeno deixa a mensagem na fila
/// (STATUS_BUFFER_TOO_SMALL com o comprimento pedido). A vista de uma
/// conexão LPC entra no processo do servidor quando ele pede o atributo de
/// vista.
fn receive_one(server: &UserServer, buffer: &Buffer, attributes: u64, options: ReceiveOptions) -> Option<u32> {
    loop {
        let (id, view) = {
            let mut state = server.state.lock();
            if state.closed {
                return Some(STATUS_PORT_DISCONNECTED);
            }
            let delivery = state.queue.front()?;
            if options.connections_only && delivery.message_type != LPC_CONNECTION_REQUEST {
                let discarded = state.queue.pop_front()?;
                state.senders.remove(&discarded.id);
                continue;
            }
            (delivery.id, delivery.view.clone())
        };
        let wants_view = attributes != 0 && state::user_struct::<AlpcMessageAttributes>(attributes).and_then(|header| header.allocated_attributes.probe_get()).is_ok_and(|allocated| allocated & VIEW_ATTRIBUTE != 0);
        let exposed = match view.filter(|_| wants_view) {
            Some(view) => match view.expose() {
                Ok(exposed) => Some(exposed),
                Err(status) => return Some(status),
            },
            None => None,
        };
        let mut state = server.state.lock();
        if state.queue.front().is_none_or(|delivery| delivery.id != id) {
            continue;
        }
        let delivery = state.queue.front()?;
        let bytes = message_bytes(delivery, options.legacy);
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
        if options.port_context != 0 && guest::try_write::<u64>(options.port_context, delivery.port_context).is_err() {
            return Some(STATUS_ACCESS_VIOLATION);
        }
        return Some(publish_attributes(attributes, &delivery, sequence, exposed.as_ref()).err().unwrap_or(STATUS_SUCCESS));
    }
}

/// O envio do servidor: a resposta ao pedido do MessageId da mensagem.
fn send_reply(server: &UserServer, input: u64, mode: u8) -> u32 {
    // A resposta de um servidor LPC pode trazer TotalLength maior (o buffer
    // da mensagem recebida, reaproveitado).
    let captured = match message_buffer::capture_message_with(input, server.listener.maximum().max(PortMessage::SIZE as u32), mode, server.legacy()) {
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
    reply_and_receive(server, input, receive, ReceiveOptions::default())
}

/// A resposta (se houver mensagem de envio) e depois a recepção (se houver
/// buffer), com a espera pela próxima mensagem: o lado servidor do
/// NtAlpcSendWaitReceivePort e do NtReplyWaitReceivePort(Ex).
fn reply_and_receive(server: Arc<UserServer>, input: u64, receive: crate::ntos::ps::user::alpc::ReceiveArguments, options: ReceiveOptions) -> Result<u32, KernelError> {
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
    if let Some(status) = receive_one(&server, &buffer, receive.receive_attributes, options) {
        return Ok(status);
    }
    if receive.timeout != 0 && guest::try_read::<i64>(receive.timeout)? == 0 {
        return Ok(STATUS_TIMEOUT);
    }
    let attributes = receive.receive_attributes;
    let waiting = server.clone();
    let wait = Wait { poll: Some(Box::new(move || receive_one(&waiting, &buffer, attributes, options))), ..Wait::default() };
    Ok(threads::wait_custom(wait, receive.timeout, None))
}

/// O servidor de usuário dono de um nó AlpcPort (a porta de conexão com
/// nome).
pub fn server_of_node(node: object_manager::NodeId) -> Option<Arc<UserServer>> {
    SERVERS.lock().values().find(|server| server.endpoint.lock().as_ref().is_some_and(|endpoint| endpoint.node == node)).cloned()
}

/// O servidor do lado servidor de uma porta (de conexão ou de comunicação).
pub fn server_for(port: &Arc<Port>) -> Option<Arc<UserServer>> {
    server_of(port)
}

/// O NtReplyWaitReceivePort(Ex) e o NtListenPort numa porta de conexão ou
/// de comunicação de servidor (AlpcpReceiveLegacyMessage): a resposta
/// `reply` (o MessageId de um pedido pendente), depois a próxima mensagem da
/// fila da porta de conexão em `receive`, com o PortContext da porta de
/// comunicação em `port_context` e o Type sem os bits internos se a porta é
/// LPC. `connections_only` é o NtListenPort.
pub fn receive_legacy(port: &Arc<Port>, reply: u64, receive: u64, port_context: u64, timeout: u64, connections_only: bool) -> Result<u32, KernelError> {
    let Some(server) = server_of(port) else { return Ok(STATUS_INVALID_PORT_HANDLE) };
    if port_context != 0 && !state::probe_user_write(port_context, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let options = ReceiveOptions { legacy: server.legacy(), port_context, connections_only };
    let arguments = crate::ntos::ps::user::alpc::ReceiveArguments { output: receive, length: 0, receive_attributes: 0, timeout };
    reply_and_receive(server, reply, arguments, options)
}

/// O LPC_CLIENT_DIED de uma thread que terminou, pela porta de término dela
/// (o datagrama do PspExitThread), com o CreateTime como dados e o
/// CLIENT_ID da thread.
pub fn post_client_died(port: &Arc<Port>, sender: Sender, create_time: u64) {
    post_datagram(port, LPC_CLIENT_DIED, &create_time.to_le_bytes(), sender);
}

/// Um datagrama de kernel (o LpcRequestPort com o tipo dado): na fila do
/// servidor da porta de conexão ou de comunicação, ou do servidor a que a
/// porta de um cliente está ligada (com o PortContext da comunicação).
pub fn post_datagram(port: &Arc<Port>, message_type: u16, data: &[u8], sender: Sender) {
    let listener = SERVERS.lock().get(&port.pointer).cloned();
    let communication = COMMUNICATION.lock().get(&port.pointer).cloned();
    let (server, client) = if let Some(server) = listener {
        (server, None)
    } else if let Some((server, client)) = communication {
        (server, Some(client))
    } else {
        let Some(service) = port.with(|state| state.service.clone()) else { return };
        let found = SERVERS.lock().values().find(|candidate| Arc::as_ptr(candidate).cast::<u8>() == Arc::as_ptr(&service).cast::<u8>()).cloned();
        let Some(server) = found else { return };
        (server, Some(port.pointer))
    };
    let (id, context) = {
        let mut state = server.state.lock();
        if state.closed {
            return;
        }
        let context = client.and_then(|client| state.links.get(&client).map(|link| link.context)).unwrap_or(0);
        (UserServer::next_id(&mut state), context)
    };
    server.enqueue(Delivery { id, message_type, data: data.to_vec(), sender, port_context: context, view: None });
}

/// O NtReplyPort no lado servidor: a resposta ao pedido do MessageId.
pub fn reply_legacy(port: &Arc<Port>, reply: u64) -> u32 {
    match server_of(port) {
        Some(server) => send_reply(&server, reply, 1),
        None => STATUS_INVALID_PORT_HANDLE,
    }
}

/// O remetente (processo, thread e a ETHREAD dele, e a porta do cliente) da
/// mensagem `id` ainda pendente no servidor da porta.
pub fn sender_of(port: &Arc<Port>, id: u32) -> Option<Origin> {
    server_of(port)?.state.lock().senders.get(&id).copied()
}

/// O REMOTE_PORT_VIEW que o servidor pede no NtAcceptConnectPort e o
/// PORT_VIEW que ele oferece (a seção mapeada nele e no cliente).
pub struct LegacyViews {
    pub server_section: Option<(Arc<Section>, u64, u64)>,
}

/// O resultado de uma aceitação LPC: a vista do cliente no servidor (base e
/// tamanho, zero sem PORT_VIEW do cliente) e as duas vistas da seção do
/// servidor (nele e no cliente).
#[derive(Default)]
pub struct LegacyAccepted {
    pub client_view: Option<Arc<View>>,
    pub server_view: Option<(Arc<View>, Arc<View>)>,
}

/// NtAcceptConnectPort(PortHandle*, PortContext, ConnectionRequest,
/// AcceptConnection, ServerView, ClientView) (AlpcpAcceptConnectPort sem a
/// porta de conexão): a conexão é a do MessageId e do CLIENT_ID do
/// PORT_MESSAGE `request`, numa porta de conexão do processo corrente. A
/// recusa conclui a espera do cliente com STATUS_PORT_CONNECTION_REFUSED;
/// a aceitação cria a porta de comunicação do servidor (com o PortContext e o
/// handle em `out`), expõe a vista do cliente no servidor, mapeia a seção do
/// servidor nele e no cliente e responde ao cliente com os dados do
/// PORT_MESSAGE. Devolve o NTSTATUS e as vistas. Em KernelMode (`mode` 0, o
/// ZwAcceptConnectPort) os buffers não são sondados e o handle é de kernel.
pub fn accept_legacy(out: u64, port_context: u64, request: u64, accept: bool, views: LegacyViews, mode: u8) -> Result<Result<LegacyAccepted, u32>, KernelError> {
    let header = match message_buffer::capture_message_with(request, u16::MAX as u32, mode, true) {
        Ok(captured) => captured,
        Err(status) => return Ok(Err(status)),
    };
    let field64 = |offset: usize| u64::from_le_bytes(header.header[offset..offset + 8].try_into().unwrap_or([0; 8]));
    let id_offset = offset_of!(PortMessage, message_id);
    let id = u32::from_le_bytes([header.header[id_offset], header.header[id_offset + 1], header.header[id_offset + 2], header.header[id_offset + 3]]);
    if id == 0 {
        return Ok(Err(STATUS_REPLY_MESSAGE_MISMATCH));
    }
    let (client_process, client_thread) = (field64(offset_of!(PortMessage, client_id.unique_process)), field64(offset_of!(PortMessage, client_id.unique_thread)));
    let current = process::get_current_process();
    let found = SERVERS.lock().values().find_map(|server| {
        if server.listener.process_pointer != current {
            return None;
        }
        let pending = server.state.lock().connections.get(&id).cloned()?;
        (pending.sender.process == client_process && pending.sender.thread == client_thread).then(|| (server.clone(), pending))
    });
    let Some((server, pending)) = found else { return Ok(Err(STATUS_REPLY_MESSAGE_MISMATCH)) };
    if pending.client.closed() {
        return Ok(Err(STATUS_INVALID_CID));
    }
    if !accept {
        refuse(&pending);
        kernel_entry::notify_waiters();
        return Ok(Ok(LegacyAccepted::default()));
    }
    if mode != 0 && !state::probe_user_write(out, 8) {
        return Ok(Err(STATUS_ACCESS_VIOLATION));
    }
    let mut accepted = LegacyAccepted::default();
    if let Some(view) = &pending.view {
        match view.expose() {
            Ok(exposed) => accepted.client_view = Some(exposed),
            Err(status) => return Ok(Err(status)),
        }
    }
    if let Some((section, offset, size)) = &views.server_section {
        let request = MapRequest { offset: *offset, size: *size, protect: PAGE_READWRITE, ..MapRequest::default() };
        let local = match sections::map(section, &request)? {
            Ok(view) => view,
            Err(status) => return Ok(Err(status)),
        };
        let remote = match sections::map(section, &MapRequest { owner_process: Some(pending.client.process_pointer), ..request })? {
            Ok(view) => view,
            Err(status) => {
                let _ = sections::unmap(&local, None);
                return Ok(Err(status));
            }
        };
        accepted.server_view = Some((local, remote));
    }
    let status = establish(&server, &pending, out, port_context, 0, mode, header.data.clone(), &accepted)?;
    if status != STATUS_SUCCESS {
        if let Some((local, remote)) = accepted.server_view.take() {
            let _ = sections::unmap(&local, None);
            let _ = sections::unmap(&remote, None);
        }
        return Ok(Err(status));
    }
    Ok(Ok(accepted))
}

/// A aceitação: a porta de comunicação do servidor (com o modo LPC da porta
/// de conexão, o PortContext e as vistas do lado servidor), o vínculo do
/// cliente e a decisão que acorda o cliente, com os dados da resposta de
/// conexão e a vista da seção do servidor no cliente.
#[allow(clippy::too_many_arguments)]
fn establish(server: &Arc<UserServer>, pending: &Arc<PendingConnection>, out: u64, port_context: u64, attributes: u64, mode: u8, data: Vec<u8>, accepted: &LegacyAccepted) -> Result<u32, KernelError> {
    let object_flags = object_flags(attributes)?;
    let port_flags = server.listener.with(|state| state.port_flags) & LPC_MODE;
    let mut views = Vec::new();
    if let Some(view) = pending.view.as_ref().and_then(|view| view.server()) {
        views.push(view);
    }
    if let Some((local, _)) = &accepted.server_view {
        views.push(local.clone());
    }
    let initial = PortState { role: Role::Server, port_context, port_flags, views, ..PortState::default() };
    let disconnecting = server.clone();
    let client_pointer = pending.client.pointer;
    let communication = match port_objects::create("alpc", initial, server.listener.maximum(), 1, attributes, Box::new(move |port: &Arc<Port>| {
        COMMUNICATION.lock().remove(&port.pointer);
        disconnecting.state.lock().links.remove(&client_pointer);
        for view in port.with(|state| core::mem::take(&mut state.views)) {
            let _ = sections::unmap(&view, None);
        }
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
        let server_view = accepted.server_view.as_ref().map(|(_, remote)| remote.clone());
        *pending.decision.lock() = Some(Decision { status: STATUS_SUCCESS, data, server_view });
        kernel_entry::notify_waiters();
        Ok(STATUS_SUCCESS)
    });
    crate::ntos::ob::objects::dispatcher::collect(communication.pointer);
    outcome
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
    create_listener(out, attributes, name, PortState { role: Role::Listener, port_flags, maximum_view_size, duplicate_object_types, ..PortState::default() }, maximum as u32, mode)
}

/// LpcLegacyMaxMessageLength (o LpcInitSystem do 19041).
pub const LPC_LEGACY_MAXIMUM_MESSAGE_LENGTH: u32 = 0x288;
/// ALPC_PORFLG_ALLOW_LPC_REQUESTS e ALPC_PORFLG_WAITABLE_PORT.
const ALLOW_LPC_REQUESTS: u32 = 0x2_0000;
const WAITABLE_PORT: u32 = 0x4_0000;

/// NtCreatePort/NtCreateWaitablePort(PortHandle*, ObjectAttributes,
/// MaxConnectionInfoLength, MaxMessageLength, MaxPoolUsage) de modo usuário
/// (AlpcpCreateConnectionPort com o modo LPC): a porta de conexão com os
/// atributos padrão do LPC (Flags LPC_MODE|ALLOW_LPC_REQUESTS, mais
/// WAITABLE_PORT na esperável) e o MaxMessageLength dado, que não passa do
/// LpcLegacyMaxMessageLength (STATUS_INVALID_PARAMETER). O
/// MaxConnectionInfoLength e o MaxPoolUsage não entram, como no 19041. Em
/// KernelMode (`mode` 0, o ZwCreatePort do servidor de comandos do
/// Reference Monitor) o OBJECT_ATTRIBUTES de kernel não é sondado e o handle
/// vem do ObOpenObjectByPointer.
pub fn create_legacy_port(out: u64, attributes: u64, maximum_message_length: u32, waitable: bool, mode: u8) -> Result<u32, KernelError> {
    if mode != 0 && (!state::probe_user_write(out, 8) || (attributes != 0 && !state::probe_user_read(attributes, ObjectAttributes::SIZE))) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let name = match if mode != 0 { port_name(attributes) } else { kernel_port_name(attributes) } {
        Ok(name) => name,
        Err(status) => return Ok(status),
    };
    if maximum_message_length > LPC_LEGACY_MAXIMUM_MESSAGE_LENGTH {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let port_flags = LPC_MODE | ALLOW_LPC_REQUESTS | if waitable { WAITABLE_PORT } else { 0 };
    create_listener(out, attributes, name, PortState { role: Role::Listener, port_flags, ..PortState::default() }, maximum_message_length, mode)
}

/// A porta de conexão com o servidor: o nó AlpcPort do nome (o diretório pai
/// existe e o nó ainda não) e o handle de quem cria.
fn create_listener(out: u64, attributes: u64, name: Option<String>, initial: PortState, maximum: u32, mode: u8) -> Result<u32, KernelError> {
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
    let object_flags = object_flags(attributes)?;
    let port = match port_objects::create("alpc", initial, maximum, 1, attributes, Box::new(|listener: &Arc<Port>| {
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
            refuse(&pending);
            kernel_entry::notify_waiters();
            return Ok(STATUS_SUCCESS);
        }
        if mode != 0 && !state::probe_user_write(out, 8) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        // A vista de um cliente LPC já entrou no servidor na recepção (o
        // atributo de vista) ou entra agora, e fica com a comunicação.
        if let Some(view) = &pending.view {
            if let Err(status) = view.expose() {
                return Ok(status);
            }
        }
        establish(&server, &pending, out, port_context, attributes, mode, captured.data.clone(), &LegacyAccepted::default())
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
        let Some(sender) = server.state.lock().senders.get(&id).map(|origin| origin.sender) else { return Ok(STATUS_INVALID_MESSAGE) };
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
        let Some(sender) = server.state.lock().senders.get(&header.message_id.get()).map(|origin| origin.sender) else { return Ok(STATUS_INVALID_MESSAGE) };
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

/// Um pedido síncrono de kernel na própria porta de conexão de um servidor
/// de usuário: como no AlpcpProcessSynchronousRequest com a porta de
/// conexão como destino, a mensagem entra na fila da porta de conexão (um
/// LPC_REQUEST sem porta de comunicação, PortContext zero) e quem pediu
/// espera a resposta pelo MessageId; a resposta volta no buffer de recepção
/// como LPC_REPLY, com o CLIENT_ID de quem respondeu.
fn connection_request(server: &Arc<UserServer>, input: u64, receive: crate::ntos::ps::user::alpc::ReceiveArguments) -> Box<dyn crate::ntos::alpc::kernel_entry::Pending> {
    use crate::ntos::alpc::kernel_entry::Completed;
    let captured = match message_buffer::capture_message_with(input, server.listener.maximum().max(PortMessage::SIZE as u32), 0, server.legacy()) {
        Ok(captured) => captured,
        Err(status) => return Box::new(Completed(status)),
    };
    let sender = current_sender();
    let slot: ReplySlot = Arc::new(SpinLock::new(None));
    let id = {
        let mut state = server.state.lock();
        if state.closed {
            return Box::new(Completed(STATUS_PORT_DISCONNECTED));
        }
        let id = UserServer::next_id(&mut state);
        state.requests.insert(id, slot.clone());
        state.senders.insert(id, Origin { sender, client: 0 });
        id
    };
    let message_type = if server.legacy() { LPC_REQUEST } else { LPC_REQUEST | LPC_CONTINUATION_REQUIRED };
    server.enqueue(Delivery { id, message_type, data: captured.data, sender, port_context: 0, view: None });
    Box::new(ConnectionRequest { server: server.clone(), id, slot, output: receive.output, length: receive.length, done: false })
}

/// A espera do pedido de kernel na porta de conexão.
struct ConnectionRequest {
    server: Arc<UserServer>,
    id: u32,
    slot: ReplySlot,
    output: u64,
    length: u64,
    done: bool,
}

/// LPC_REPLY.
const LPC_REPLY: u16 = 2;

impl crate::ntos::alpc::kernel_entry::Pending for ConnectionRequest {
    fn poll(&mut self) -> Option<u32> {
        if self.done {
            return Some(STATUS_SUCCESS);
        }
        let result = self.slot.lock().take()?;
        self.done = true;
        if result.status != STATUS_SUCCESS || self.output == 0 {
            return Some(result.status);
        }
        let total = PortMessage::SIZE as usize + result.data.len();
        if self.length != 0 && total as u64 > self.length {
            return Some(0xC000_0023);
        }
        let mut bytes = alloc::vec![0u8; total];
        let put = |bytes: &mut Vec<u8>, offset: usize, value: &[u8]| bytes[offset..offset + value.len()].copy_from_slice(value);
        put(&mut bytes, offset_of!(PortMessage, u1.s1.data_length), &(result.data.len() as u16).to_le_bytes());
        put(&mut bytes, offset_of!(PortMessage, u1.s1.total_length), &(total as u16).to_le_bytes());
        put(&mut bytes, offset_of!(PortMessage, u2.s2.type_), &LPC_REPLY.to_le_bytes());
        let replier = result.sender.unwrap_or_default();
        put(&mut bytes, offset_of!(PortMessage, client_id.unique_process), &replier.process.to_le_bytes());
        put(&mut bytes, offset_of!(PortMessage, client_id.unique_thread), &replier.thread.to_le_bytes());
        put(&mut bytes, offset_of!(PortMessage, message_id), &self.id.to_le_bytes());
        bytes[PortMessage::SIZE as usize..].copy_from_slice(&result.data);
        Some(match guest::try_write_bytes(self.output, &bytes) {
            Ok(()) => STATUS_SUCCESS,
            Err(_) => STATUS_ACCESS_VIOLATION,
        })
    }

    /// Sem resposta (prazo, alerta, saída): o pedido sai da fila de
    /// respostas, e uma resposta tardia dá STATUS_REPLY_MESSAGE_MISMATCH.
    fn cancel(&mut self) {
        if self.done {
            return;
        }
        let mut state = self.server.state.lock();
        state.requests.remove(&self.id);
        state.senders.remove(&self.id);
    }
}

/// ZwReplyWaitReceivePort(PortHandle, PortContext*, ReplyMessage,
/// ReceiveMessage) numa porta de servidor LPC de kernel (o
/// AlpcpReceiveLegacyMessage em KernelMode): a resposta `reply` ao pedido do
/// MessageId dela, depois a próxima mensagem da fila em `receive`, com o
/// Type sem os bits internos e o PortContext da porta de comunicação em
/// `port_context`; os buffers do chamador não são sondados e a espera é a
/// continuação de kernel, sem prazo.
pub fn begin_kernel_legacy_receive(port: &Arc<Port>, reply: u64, receive: u64, port_context: u64) -> Result<Box<dyn crate::ntos::alpc::kernel_entry::Pending>, KernelError> {
    use crate::ntos::alpc::kernel_entry::Completed;
    use crate::ntos::alpc::kernel_wait;
    let Some(server) = server_of(port) else { return Ok(Box::new(Completed(STATUS_INVALID_PORT_HANDLE))) };
    if reply != 0 {
        let status = send_reply(&server, reply, 0);
        if status != 0 {
            return Ok(Box::new(Completed(status)));
        }
    }
    if receive == 0 {
        return Ok(Box::new(Completed(STATUS_SUCCESS)));
    }
    let buffer = match message_buffer::capture_length(receive, 0, 0) {
        Ok(buffer) => buffer,
        Err(status) => return Ok(Box::new(Completed(status))),
    };
    let timeout = match kernel_wait::capture_timeout(0, 0) {
        Ok(timeout) => timeout,
        Err(status) => return Ok(Box::new(Completed(status))),
    };
    let options = ReceiveOptions { legacy: server.legacy(), port_context, connections_only: false };
    if let Some(status) = receive_one(&server, &buffer, 0, options) {
        return Ok(Box::new(Completed(status)));
    }
    let waiting = server.clone();
    let operation = kernel_wait::Operation { poll: Box::new(move || receive_one(&waiting, &buffer, 0, options)), cleanup: Box::new(|_| {}) };
    let request = kernel_wait::begin(operation, timeout, 0, false)?;
    Ok(Box::new(request))
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
        // O pedido síncrono de kernel direto à porta de conexão (o win32k
        // manda o LpcSendWaitReceivePort à \Windows\ApiPort do csrss).
        if input != 0 && SERVERS.lock().get(&port.pointer).is_some_and(|owner| Arc::ptr_eq(owner, &server)) {
            return Ok(connection_request(&server, input, receive));
        }
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
    if let Some(status) = receive_one(&server, &buffer, receive.receive_attributes, ReceiveOptions::default()) {
        return Ok(Box::new(Completed(status)));
    }
    let attributes = receive.receive_attributes;
    let waiting = server.clone();
    let operation = kernel_wait::Operation { poll: Box::new(move || receive_one(&waiting, &buffer, attributes, ReceiveOptions::default())), cleanup: Box::new(|_| {}) };
    let request = kernel_wait::begin(operation, timeout, kernel_wait::select_mode(flags, 0), flags & 0x20_0000 != 0)?;
    Ok(Box::new(request))
}
