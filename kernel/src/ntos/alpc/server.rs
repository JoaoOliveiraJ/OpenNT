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
//! - os pedidos do cliente (`Service::exchange`): LPC_REQUEST com
//!   LPC_CONTINUATION_REQUIRED (todo envio sem ALPC_MSGFLG_RELEASE_MESSAGE,
//!   síncrono ou não) ou LPC_DATAGRAM na fila do servidor; a resposta chega
//!   ao cliente pela
//!   continuação (o job), quando o servidor envia uma mensagem com o
//!   MessageId do pedido;
//! - a recepção do servidor ([`exchange`], pelo NtAlpcSendWaitReceivePort
//!   na porta de conexão ou de comunicação): a próxima mensagem da fila, com
//!   o ALPC_CONTEXT_ATTR (PortContext da comunicação, sequência e
//!   MessageId), ou a espera até chegar uma (sem prazo, ou o prazo dado;
//!   prazo zero devolve STATUS_TIMEOUT);
//! - a vista de dados de uma mensagem grande (o atributo de vista,
//!   `alpc/message/view.rs`): a região da seção do cliente entra no processo
//!   do servidor quando ele recebe o pedido, registrada na porta de conexão
//!   (por onde ele a apaga, ou a resposta com UNMAP_EXISTING), e a região da
//!   resposta entra no cliente quando ele a recebe;
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
//! As mensagens que o lado servidor manda por iniciativa própria
//! ([`classify`], como o AlpcpSendMessage: numa porta LPC o Type zero, nas
//! outras o MessageId zero) seguem o AlpcpDispatchNewMessage:
//!
//! - na porta de conexão, a mensagem vai para a própria fila (o dwm.exe manda
//!   à DwmApiPort pelo handle duplicado dela; o win32k, pelo LpcRequestPort e
//!   pelo LpcSendWaitReceivePort), com o PortContext e a sequência da porta
//!   de conexão;
//! - numa porta de comunicação, a mensagem vai para a porta do cliente (o
//!   callback do RPC), que precisa de ALPC_PORFLG_ALLOW_LPC_REQUESTS
//!   (STATUS_LPC_REQUESTS_NOT_ALLOWED sem ela); o cliente a recebe na fila
//!   dele e responde pelo MessageId.
//!
//! Com ALPC_MSGFLG_RELEASE_MESSAGE é um datagrama; com
//! ALPC_MSGFLG_SYNC_REQUEST quem envia espera a resposta (o LPC_REPLY no
//! buffer de recepção); sem as duas, a resposta volta como LPC_REPLY na fila
//! da porta de conexão. O Type conserva os bits altos que o remetente deu
//! (o LPC_KERNELMODE_MESSAGE só de modo kernel).
//!
//! A porta de conexão esperável (NtCreateWaitablePort, ou WAITABLE_PORT nos
//! atributos) tem o KSEMAPHORE do AlpcpInitializePort: cada mensagem posta na
//! fila sem IOCP associada o libera uma vez, e a espera pelo handle da porta
//! é nele (o DefaultObject indireto do tipo ALPC Port).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::alpc::kernel_entry;
use crate::ntos::alpc::message::buffer::{self as message_buffer, Buffer};
use crate::ntos::alpc::message::identity::Identity;
use crate::ntos::alpc::message::view as message_view;
use crate::ntos::alpc::port_reference;
use crate::ntos::alpc::rpc_trace::{self, Direction, Record};
use crate::ntos::alpc::small::context_attribute;
use crate::ntos::alpc::transport::{self, Job, JobResult, Listener, Reply, Request, Sender, Service};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::alpc::message::handles::{self as message_handles, HandleData};
use crate::ntos::alpc::message::identity::Retained;
use crate::ntos::alpc::security_contexts::Borrowed;
use crate::ntos::inc::types::{AlpcDataViewAttr, AlpcMessageAttributes, AlpcPortAttributes, AlpcSecurityAttr, ObjectAttributes, PortMessage};
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
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
/// STATUS_LPC_RECEIVE_BUFFER_EXPECTED: envio síncrono sem buffer de recepção.
const STATUS_LPC_RECEIVE_BUFFER_EXPECTED: u32 = 0xC000_0705;
/// STATUS_LPC_REQUESTS_NOT_ALLOWED: a porta de destino não aceita mensagens
/// novas (sem ALPC_PORFLG_ALLOW_LPC_REQUESTS).
const STATUS_LPC_REQUESTS_NOT_ALLOWED: u32 = 0xC000_0707;
/// ALPC_MSGFLG_RELEASE_MESSAGE e ALPC_MSGFLG_SYNC_REQUEST.
const RELEASE_MESSAGE: u32 = 0x1_0000;
const SYNC_REQUEST: u32 = 0x2_0000;
/// O bit 1 das flags de envio de kernel: o contrato LPC (LpcRequestPort,
/// LpcSendWaitReceivePort), que admite os tipos de sistema.
const KERNEL_LPC_SEND: u32 = 2;

/// Tipos de PORT_MESSAGE (o byte baixo de Type).
const LPC_REQUEST: u16 = 1;
const LPC_REPLY: u16 = 2;
const LPC_DATAGRAM: u16 = 3;
const LPC_PORT_CLOSED: u16 = 5;
const LPC_CLIENT_DIED: u16 = 6;
const LPC_CONNECTION_REQUEST: u16 = 10;
/// A mensagem espera resposta: todo envio novo sem
/// ALPC_MSGFLG_RELEASE_MESSAGE, como no AlpcpDispatchNewMessage.
const LPC_CONTINUATION_REQUIRED: u16 = 0x2000;
/// LPC_KERNELMODE_MESSAGE: a mensagem veio de um chamador em KernelMode.
const LPC_KERNELMODE_MESSAGE: u16 = 0x8000;
/// ALPC_MESSAGE_CONTEXT_ATTRIBUTE.
const CONTEXT_ATTRIBUTE: u32 = 0x2000_0000;
/// ALPC_MESSAGE_VIEW_ATTRIBUTE.
const VIEW_ATTRIBUTE: u32 = 0x4000_0000;
/// ALPC_MESSAGE_TOKEN_ATTRIBUTE (ALPC_TOKEN_ATTR: TokenId, AuthenticationId
/// e ModifiedId do token do cliente).
const TOKEN_ATTRIBUTE: u32 = 0x0800_0000;
/// ALPC_MESSAGE_SECURITY_ATTRIBUTE e ALPC_MESSAGE_HANDLE_ATTRIBUTE.
const SECURITY_ATTRIBUTE: u32 = 0x8000_0000;
const HANDLE_ATTRIBUTE: u32 = 0x1000_0000;
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
#[derive(Default)]
struct Delivery {
    id: u32,
    message_type: u16,
    data: Vec<u8>,
    sender: Sender,
    port_context: u64,
    /// A seção de transferência de uma conexão LPC (o PORT_VIEW do cliente).
    view: Option<Arc<ClientView>>,
    /// A vista de dados que o envio levou (o atributo de vista).
    data_view: Option<Arc<message_view::Carried>>,
    /// A sequência da mensagem na porta de destino (a de comunicação do
    /// cliente, ou a de conexão), que o ALPC_CONTEXT_ATTR publica.
    sequence: u32,
    /// O contexto de segurança e os handles que o envio levou.
    attributes: SentAttributes,
    /// A porta de comunicação do servidor ligada ao cliente que enviou (as
    /// regras de handles dela).
    link_port: Option<Arc<Port>>,
}

/// O contexto de segurança (o atributo de segurança) e os handles (o atributo
/// de handles) que um envio leva ao servidor, tirados da identidade do
/// pedido: ficam com a mensagem até a resposta e são soltos quando ela sai.
#[derive(Default)]
struct SentAttributes {
    handles: Option<Arc<HandleData>>,
    security: Option<Arc<Borrowed>>,
}

impl SentAttributes {
    fn is_empty(&self) -> bool {
        self.handles.is_none() && self.security.is_none()
    }
}

impl Drop for SentAttributes {
    fn drop(&mut self) {
        if let Some(handles) = self.handles.take() {
            handles.release();
        }
        if let Some(security) = self.security.take() {
            security.release();
        }
    }
}

/// Os atributos de um pedido já recebido pelo servidor, até a resposta (o
/// NtAlpcQueryInformationMessage da classe 3 e a impersonação os consultam).
struct Received {
    attributes: SentAttributes,
    link_port: Option<Arc<Port>>,
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
#[derive(Clone, Copy, Default)]
pub struct Origin {
    pub sender: Sender,
    pub client: u64,
    /// A thread que enviou espera a resposta (o envio síncrono: o
    /// KALPC_MESSAGE.WaitingThread que a impersonação dinâmica captura).
    pub waiting: bool,
    /// O Type da mensagem na fila (o LPC_NO_IMPERSONATE, 0x4000, recusa a
    /// impersonação).
    pub message_type: u16,
    /// O servidor já recebeu a mensagem (o estado de mensagem recebida que
    /// o AlpcpImpersonateMessage exige).
    pub received: bool,
}

/// A resposta que volta à fila do servidor como LPC_REPLY (a mensagem nova
/// sem SYNC_REQUEST nem RELEASE_MESSAGE, o AlpcpDispatchReplyToPort): o
/// PortContext e a porta cuja sequência ela avança.
struct Requeue {
    port_context: u64,
    owner: Arc<Port>,
}

/// Os handles que uma resposta leva (o atributo de handles do envio do
/// servidor, capturado como o AlpcpCaptureAttributes faz também nas
/// respostas), até o cliente recebê-la; uma resposta que ninguém recebe os
/// solta com ela.
struct ReplyHandles(SpinLock<Option<Arc<HandleData>>>);

impl Default for ReplyHandles {
    fn default() -> Self {
        Self(SpinLock::new(None))
    }
}

impl Drop for ReplyHandles {
    fn drop(&mut self) {
        if let Some(handles) = self.0.lock().take() {
            handles.release();
        }
    }
}

/// A resposta de um pedido, preenchida quando o servidor responde, com a
/// vista de dados e os handles que ela leva.
struct ReplyCell {
    result: SpinLock<Option<JobResult>>,
    view: SpinLock<Option<Arc<message_view::Carried>>>,
    handles: ReplyHandles,
    /// O servidor respondeu sem ALPC_MSGFLG_RELEASE_MESSAGE.
    continuation: core::sync::atomic::AtomicBool,
    requeue: Option<Requeue>,
}

impl Default for ReplyCell {
    fn default() -> Self {
        Self { result: SpinLock::new(None), view: SpinLock::new(None), handles: ReplyHandles::default(), continuation: core::sync::atomic::AtomicBool::new(false), requeue: None }
    }
}

type ReplySlot = Arc<ReplyCell>;

/// O vínculo de um cliente conectado: a porta de comunicação do servidor e o
/// PortContext dela.
struct Link {
    server_port: Arc<Port>,
    context: u64,
    /// O servidor desconectou ou fechou a porta de comunicação: os envios do
    /// cliente voltam STATUS_PORT_DISCONNECTED.
    disconnected: bool,
}

#[derive(Default)]
struct ServerState {
    next_id: u32,
    queue: VecDeque<Delivery>,
    connections: BTreeMap<u32, Arc<PendingConnection>>,
    requests: BTreeMap<u32, ReplySlot>,
    /// Quem enviou cada mensagem ainda pendente (para o OpenSender* e a
    /// impersonação do cliente).
    senders: BTreeMap<u32, Origin>,
    /// Clientes conectados, pelo ponteiro da porta do cliente.
    links: BTreeMap<u64, Link>,
    /// A vista que cada pedido recebido trouxe ao servidor, até a resposta.
    exposed_views: BTreeMap<u32, Arc<crate::ntos::alpc::section_views::ViewBinding>>,
    /// O contexto de segurança e os handles de cada pedido recebido, até a
    /// resposta.
    received: BTreeMap<u32, Received>,
    /// Pedidos cuja espera do cliente terminou com a desconexão do servidor
    /// (a resposta tardia só limpa o que restou deles).
    abandoned: BTreeSet<u32>,
    /// As mensagens que o servidor mandou a um cliente e que esperam a
    /// resposta dele, por (porta do cliente, MessageId na porta do cliente).
    callbacks: BTreeMap<(u64, u32), ReplySlot>,
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

/// A próxima sequência de uma porta de servidor (o `lock xadd` no contador
/// da porta do AlpcpDispatchNewMessage, do AlpcpDispatchConnectionRequest e
/// do AlpcpDispatchCloseMessage): cada mensagem posta para um cliente
/// conectado avança o contador da porta de comunicação dele; uma conexão, o
/// da porta de conexão. Chamada sob a trava do servidor, que é a única que
/// avança esses contadores; o AlpcBasicInformation lê o mesmo valor.
fn next_sequence(port: &Port) -> u32 {
    let sequence = port.sequence().wrapping_add(1);
    port.set_sequence(sequence);
    sequence
}

impl UserServer {
    fn next_id(state: &mut ServerState) -> u32 {
        state.next_id = state.next_id.wrapping_add(1).max(1);
        state.next_id
    }

    /// Põe a mensagem na fila e avisa a IOCP da porta de conexão. Com um
    /// objeto Callback registrado na porta (o NtAlpcSetInformation 9), o
    /// ExNotifyCallback roda em seguida, no contexto de quem enviou e fora
    /// das travas, como no AlpcpCompleteDispatchMessage do 19041.
    fn enqueue(&self, delivery: Delivery) {
        let id = delivery.id;
        self.state.lock().queue.push_back(delivery);
        match self.listener.with(|state| state.completion.clone()) {
            Some(completion) => completion.notify(),
            // AlpcpCompleteDispatchMessage: sem IOCP, a porta esperável
            // libera o semáforo uma vez por mensagem na fila principal.
            None => self.listener.signal_waitable(),
        }
        kernel_entry::notify_waiters();
        if let Some((object, context)) = self.listener.with(|state| state.callback) {
            let _ = crate::ntos::ex::callbacks::notify(object, context, id as u64);
        }
    }

    /// O servidor fechou a porta de conexão: as conexões pendentes são
    /// recusadas e o nome sai do namespace.
    fn close(&self) {
        let (connections, requests, _queue, _views, _received, callbacks) = {
            let mut state = self.state.lock();
            state.closed = true;
            // As mensagens, vistas e atributos saem fora da trava (a vista de
            // dados solta a seção que retinha; os atributos, os objetos).
            (core::mem::take(&mut state.connections), core::mem::take(&mut state.requests), core::mem::take(&mut state.queue), core::mem::take(&mut state.exposed_views), core::mem::take(&mut state.received), core::mem::take(&mut state.callbacks))
        };
        for connection in connections.values() {
            refuse(connection);
        }
        for slot in requests.values().chain(callbacks.values()) {
            *slot.result.lock() = Some(JobResult { status: STATUS_PORT_DISCONNECTED, ..JobResult::default() });
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
    /// cliente espera a decisão do servidor. O Type é o do
    /// AlpcpFormatConnectionRequest (o LPC_KERNELMODE_MESSAGE que um
    /// chamador em KernelMode pôs na mensagem de conexão) com o
    /// LPC_CONTINUATION_REQUIRED do AlpcpDispatchConnectionRequest: o
    /// servidor distingue por ele o cliente de kernel (o CoreMessagingK do
    /// win32kbase no registrar do CoreMessaging).
    pub fn request_connection(&self, port: &Arc<Port>, data: &[u8], view: Option<Arc<ClientView>>, kernel_mode: bool) -> Decision {
        let message_type = LPC_CONTINUATION_REQUIRED | LPC_CONNECTION_REQUEST | if kernel_mode { LPC_KERNELMODE_MESSAGE } else { 0 };
        let sender = current_sender();
        let pending = Arc::new(PendingConnection { client: port.clone(), sender, view: view.clone(), decision: SpinLock::new(None) });
        let (id, sequence) = {
            let mut state = self.state.lock();
            if state.closed {
                return Decision { status: STATUS_PORT_CONNECTION_REFUSED, ..Decision::default() };
            }
            let id = UserServer::next_id(&mut state);
            state.connections.insert(id, pending.clone());
            state.senders.insert(id, Origin { sender, client: port.pointer, waiting: true, message_type, received: false });
            (id, next_sequence(&self.listener))
        };
        if rpc_trace::enabled() {
            rpc_trace::message(&Record { listener: self.listener.pointer, client_port: port.pointer, client: sender.process, server: self.listener.process_id(), message_type, id, data, ..Record::default() });
        }
        self.enqueue(Delivery { id, message_type, data: Vec::from(data), sender, port_context: 0, view, sequence, ..Delivery::default() });
        let decision = pending.clone();
        let status = kernel_entry::wait_transport(&mut || decision.decision.lock().as_ref().map(|decision| decision.status), crate::ntos::ke::wait::Deadline::Infinite, 0, false);
        let decision = pending.decision.lock().take().unwrap_or(Decision { status, ..Decision::default() });
        if rpc_trace::enabled() {
            rpc_trace::connection_decided(self.listener.pointer, sender.process, self.listener.process_id(), id, decision.status);
        }
        {
            let mut state = self.state.lock();
            state.connections.remove(&id);
            state.senders.remove(&id);
            // Uma espera interrompida antes da decisão tira a mensagem que o
            // servidor ainda não recebeu.
            state.queue.retain(|delivery| delivery.id != id || delivery.message_type & 0xFF != LPC_CONNECTION_REQUEST);
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

/// A continuação do pedido de um cliente: conclui quando o servidor responde;
/// a vista e os handles que a resposta leva ficam com a identidade do pedido
/// até o cliente receber a resposta.
struct ReplyJob {
    slot: ReplySlot,
    identity: Arc<Identity>,
}

impl Job for ReplyJob {
    fn poll(&mut self) -> Option<JobResult> {
        let result = self.slot.result.lock().take()?;
        if let Some(view) = self.slot.view.lock().take() {
            self.identity.with(|state| state.reply_view = Some(view));
        }
        // A identidade que já saiu de todo não guarda mais nada.
        if let Some(handles) = self.slot.handles.0.lock().take() {
            let orphan = self.identity.with(|state| {
                if state.references == 0 {
                    return Some(handles);
                }
                state.reply_handles = Some(handles);
                None
            });
            if let Some(handles) = orphan {
                handles.release();
            }
        }
        if self.slot.continuation.load(core::sync::atomic::Ordering::Acquire) {
            self.identity.with(|state| state.continuation = true);
        }
        Some(result)
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
    /// `request` é o PORT_MESSAGE de conexão já formatado, com o Type que o
    /// chamador de kernel deu.
    fn connect(&self, port: &Arc<Port>, data: &[u8], request: Option<&[u8]>) -> Reply {
        let type_offset = offset_of!(PortMessage, u2.s2.type_);
        let kernel_mode = request.and_then(|bytes| bytes.get(type_offset..type_offset + 2)).is_some_and(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) & LPC_KERNELMODE_MESSAGE != 0);
        let decision = self.request_connection(port, data, None, kernel_mode);
        let server = Sender { process: self.listener.process_id(), thread: self.listener.thread_id(), thread_pointer: 0 };
        Reply::Now(JobResult { status: decision.status, data: decision.data, sender: Some(server) })
    }

    /// LPC_REQUEST ou LPC_DATAGRAM na fila; a resposta conclui o job.
    fn exchange(&self, port: &Arc<Port>, data: &[u8], request: &Arc<Request>) -> Reply {
        let (datagram, answer, synchronous, type_bits, mut sender, sent_attributes) = {
            let state = request.state.lock();
            (state.datagram, state.answer, state.synchronous, state.type_bits, state.sender, state.attributes)
        };
        // A thread que enviou (para a impersonação do cliente).
        if sender.thread_pointer == 0 {
            sender.thread_pointer = request.identity.with(|state| state.sender_thread);
        }
        let slot: ReplySlot = Arc::new(ReplyCell::default());
        // A vista de dados, o contexto de segurança e os handles do envio
        // passam à mensagem do servidor.
        let (data_view, handles, security) = request.identity.with(|state| (state.view.take(), state.handles.take(), state.security.take()));
        let attributes = SentAttributes { handles, security };
        // AlpcpSendMessage: um envio com RELEASE_MESSAGE é LPC_DATAGRAM, os
        // outros LPC_REQUEST, com os bits altos do Type do remetente; o
        // AlpcpDispatchNewMessage liga o 0x2000 em todo envio sem
        // RELEASE_MESSAGE (um pedido assíncrono ou de reserva também espera a
        // resposta). A resposta do cliente a uma mensagem do servidor
        // (MessageId dela) com RELEASE_MESSAGE é LPC_REPLY.
        let message_type = (type_bits & !LPC_CONTINUATION_REQUIRED) | if datagram && answer { LPC_REPLY } else if datagram { LPC_DATAGRAM } else { LPC_REQUEST | LPC_CONTINUATION_REQUIRED };
        let (id, context, sequence, link_port) = {
            let mut state = self.state.lock();
            let Some((context, sequence, link_port)) = state.links.get(&port.pointer).filter(|link| !link.disconnected).map(|link| (link.context, next_sequence(&link.server_port), link.server_port.clone())) else { return Reply::Now(JobResult { status: STATUS_PORT_DISCONNECTED, ..JobResult::default() }) };
            let id = UserServer::next_id(&mut state);
            if !datagram {
                state.requests.insert(id, slot.clone());
            }
            state.senders.insert(id, Origin { sender, client: port.pointer, waiting: synchronous, message_type, received: false });
            (id, context, sequence, link_port)
        };
        if rpc_trace::enabled() {
            let carried = if attributes.security.is_some() { rpc_trace::CARRIED_SECURITY } else { 0 } | if data_view.is_some() { rpc_trace::CARRIED_VIEW } else { 0 } | if attributes.handles.is_some() { rpc_trace::CARRIED_HANDLES } else { 0 };
            rpc_trace::message(&Record { listener: self.listener.pointer, client_port: port.pointer, client: sender.process, server: self.listener.process_id(), message_type, id, attributes: sent_attributes, carried, data, ..Record::default() });
        }
        self.enqueue(Delivery { id, message_type, data: Vec::from(data), sender, port_context: context, data_view, sequence, attributes, link_port: Some(link_port), ..Delivery::default() });
        if datagram {
            return Reply::Now(JobResult::default());
        }
        Reply::Later(Box::new(ReplyJob { slot, identity: request.identity.clone() }))
    }

    /// O cliente saiu: LPC_PORT_CLOSED na fila, com o PortContext dele; as
    /// mensagens que o servidor mandou a ele e ainda esperam resposta
    /// terminam com STATUS_PORT_DISCONNECTED.
    fn disconnect(&self, port: &Arc<Port>) {
        let (link, id, sequence, abandoned) = {
            let mut state = self.state.lock();
            let Some(link) = state.links.remove(&port.pointer) else { return };
            let id = UserServer::next_id(&mut state);
            let sequence = next_sequence(&link.server_port);
            (link, id, sequence, take_callbacks(&mut state, port.pointer))
        };
        fail_slots(&abandoned);
        COMMUNICATION.lock().remove(&link.server_port.pointer);
        let sender = Sender { process: port.process_id(), thread: port.thread_id(), thread_pointer: 0 };
        if rpc_trace::enabled() {
            rpc_trace::message(&Record { listener: self.listener.pointer, client_port: port.pointer, client: sender.process, server: self.listener.process_id(), message_type: LPC_PORT_CLOSED, id, ..Record::default() });
            rpc_trace::client_closed(port.pointer);
        }
        self.enqueue(Delivery { id, message_type: LPC_PORT_CLOSED, sender, port_context: link.context, sequence, ..Delivery::default() });
    }
}

fn current_sender() -> Sender {
    Sender { process: process::get_current_process_id(), thread: process::get_current_thread_id(), thread_pointer: process::get_current_thread() }
}

/// Tira do servidor as mensagens mandadas ao cliente `client` que ainda
/// esperam resposta (chamada sob a trava do servidor).
fn take_callbacks(state: &mut ServerState, client: u64) -> Vec<ReplySlot> {
    let keys: Vec<(u64, u32)> = state.callbacks.keys().copied().filter(|(port, _)| *port == client).collect();
    keys.iter().filter_map(|key| state.callbacks.remove(key)).collect()
}

/// As respostas que não virão: STATUS_PORT_DISCONNECTED para quem espera.
fn fail_slots(slots: &[ReplySlot]) {
    for slot in slots {
        *slot.result.lock() = Some(JobResult { status: STATUS_PORT_DISCONNECTED, ..JobResult::default() });
    }
    if !slots.is_empty() {
        kernel_entry::notify_waiters();
    }
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
/// quando alocado, com o PortContext, a sequência da mensagem na porta de
/// destino e o MessageId; o
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
    // O ALPC_SECURITY_ATTR, como o AlpcpExposeAttributes: Flags zero e o
    // ContextHandle do contexto que o cliente mandou (o PQOS fica como
    // está).
    if let Some(security) = delivery.attributes.security.as_ref().filter(|_| allocated & SECURITY_ATTRIBUTE != 0) {
        let at = crate::ntos::ps::user::alpc::attribute_address(attributes, SECURITY_ATTRIBUTE);
        let attribute = state::user_struct::<AlpcSecurityAttr>(at).map_err(|error| error.status)?;
        attribute.flags.probe_set(0).map_err(|error| error.status)?;
        attribute.context_handle.probe_set(security.handle()).map_err(|error| error.status)?;
        valid |= SECURITY_ATTRIBUTE;
    }
    // O ALPC_HANDLE_ATTR pelas regras da porta de comunicação ligada ao
    // cliente (`message_handles::expose`); na forma indireta o servidor pede
    // cada handle pela classe 3 ([`received_handles`]).
    if let Some((handles, link_port)) = delivery.attributes.handles.as_ref().zip(delivery.link_port.as_ref()).filter(|_| allocated & HANDLE_ATTRIBUTE != 0) {
        if let message_handles::Exposed::Indirect(bytes) | message_handles::Exposed::Duplicated(bytes) = message_handles::expose(handles, link_port, 1) {
            let at = crate::ntos::ps::user::alpc::attribute_address(attributes, HANDLE_ATTRIBUTE);
            guest::try_write_bytes(at, &bytes).map_err(|_| STATUS_ACCESS_VIOLATION)?;
            valid |= HANDLE_ATTRIBUTE;
        }
    }
    // O ALPC_TOKEN_ATTR, como o AlpcpExposeTokenAttribute: TokenId,
    // AuthenticationId e ModifiedId do token efetivo da mensagem (o do
    // contexto de segurança que ela leva, senão o de quem enviou; o RPC do
    // servidor lê a identidade do cliente por ele, o
    // I_RpcBindingInqClientTokenAttributes).
    if allocated & TOKEN_ATTRIBUTE != 0 {
        let token = delivery.attributes.security.as_ref().map(|security| security.token).or_else(|| sender_effective_token(delivery.sender.thread_pointer));
        if let Some(statistics) = token.and_then(|token| crate::ntos::se::token::statistics::encode(token).ok()) {
            let at = crate::ntos::ps::user::alpc::attribute_address(attributes, TOKEN_ATTRIBUTE);
            let mut bytes = [0u8; 24];
            bytes[..8].copy_from_slice(&statistics[..8]);
            bytes[8..16].copy_from_slice(&statistics[8..16]);
            bytes[16..].copy_from_slice(&statistics[48..56]);
            guest::try_write_bytes(at, &bytes).map_err(|_| STATUS_ACCESS_VIOLATION)?;
            valid |= TOKEN_ATTRIBUTE;
        }
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
    /// A recepção legada (AlpcpReceiveLegacyMessage): numa porta de
    /// comunicação do servidor ela é a da porta de conexão
    /// (CommunicationInfo->ConnectionPort), cujas regras de fila vazia
    /// valem.
    on_connection_port: bool,
}

/// A porta cujas regras de fila vazia valem para uma recepção do servidor
/// `server` pelo handle de `port`: a própria porta, ou a de conexão na
/// recepção legada.
fn receiving_port<'a>(server: &'a UserServer, port: &'a Arc<Port>, options: ReceiveOptions) -> &'a Arc<Port> {
    if options.on_connection_port { &server.listener } else { port }
}

/// Entrega a próxima mensagem da fila no buffer do servidor; `None` com a
/// fila vazia. Um buffer pequeno deixa a mensagem na fila
/// (STATUS_BUFFER_TOO_SMALL com o comprimento pedido). A vista de uma
/// conexão LPC entra no processo do servidor quando ele pede o atributo de
/// vista.
fn receive_one(server: &UserServer, buffer: &Buffer, attributes: u64, options: ReceiveOptions) -> Option<u32> {
    loop {
        let (id, view, data_view) = {
            let mut state = server.state.lock();
            if state.closed {
                return Some(STATUS_PORT_DISCONNECTED);
            }
            let delivery = state.queue.front()?;
            if options.connections_only && delivery.message_type & 0xFF != LPC_CONNECTION_REQUEST {
                let discarded = state.queue.pop_front()?;
                state.senders.remove(&discarded.id);
                continue;
            }
            (delivery.id, delivery.view.clone(), delivery.data_view.clone())
        };
        let wants_view = attributes != 0 && state::user_struct::<AlpcMessageAttributes>(attributes).and_then(|header| header.allocated_attributes.probe_get()).is_ok_and(|allocated| allocated & VIEW_ATTRIBUTE != 0);
        let exposed = match view.filter(|_| wants_view) {
            Some(view) => match view.expose() {
                Ok(exposed) => Some(exposed),
                Err(status) => return Some(status),
            },
            None => None,
        };
        // A vista de dados entra no processo do servidor, registrada na porta
        // de conexão (por onde o servidor a apaga). Uma vista que não pode
        // ser mapeada não prende a fila: a mensagem sai sem o atributo.
        let data_binding = match data_view.as_ref().filter(|_| wants_view) {
            Some(carried) => match message_view::expose(&server.listener, carried) {
                Ok(Ok(binding)) => Some((binding, carried.clone())),
                Ok(Err(status)) => {
                    crate::debug_print!("[alpc] vista de dados da mensagem {} sem mapeamento no servidor: {:#x}", id, status);
                    None
                }
                Err(error) => {
                    crate::debug_print!("[alpc] vista de dados da mensagem {} sem mapeamento no servidor: {}", id, error);
                    None
                }
            },
            None => None,
        };
        let mut state = server.state.lock();
        if state.queue.front().is_none_or(|delivery| delivery.id != id) {
            continue;
        }
        let delivery = state.queue.front()?;
        let bytes = message_bytes(delivery, options.legacy);
        if crate::ntos::init::boot_config::TRACE_SYSCALLS {
            crate::debug_print!("[alpc] recepcao do servidor: tipo {:#x} id {} {:02x?}", delivery.message_type, delivery.id, &bytes[..bytes.len().min(0x50)]);
        }
        let status = message_buffer::deliver(buffer, &bytes, true);
        if status != 0 {
            return Some(status);
        }
        let delivery = state.queue.pop_front()?;
        // Um aviso de fechamento não espera resposta nem abertura do remetente.
        if delivery.message_type == LPC_PORT_CLOSED {
            state.senders.remove(&delivery.id);
        } else if let Some(origin) = state.senders.get_mut(&delivery.id) {
            origin.received = true;
        }
        drop(state);
        // Quem recebeu a mensagem (a sondagem da espera roda no contexto da
        // thread que espera, então a thread corrente é a receptora).
        if rpc_trace::enabled() {
            let receiver = current_sender();
            rpc_trace::received(server.listener.pointer, delivery.id, receiver.process, receiver.thread);
        }
        if options.port_context != 0 && guest::try_write::<u64>(options.port_context, delivery.port_context).is_err() {
            return Some(STATUS_ACCESS_VIOLATION);
        }
        let published = publish_attributes(attributes, &delivery, delivery.sequence, exposed.as_ref()).and_then(|_| match &data_binding {
            Some((binding, carried)) => message_view::publish(attributes, binding, carried).map(|_| ()),
            None => Ok(()),
        });
        // Um pedido que espera resposta guarda a vista e os atributos até
        // ela; um datagrama os solta já.
        let mut delivery = delivery;
        if delivery.message_type & 0xFF == LPC_REQUEST {
            let attributes = core::mem::take(&mut delivery.attributes);
            let mut state = server.state.lock();
            if let Some((binding, _)) = data_binding.filter(|_| published.is_ok()) {
                state.exposed_views.insert(delivery.id, binding);
            }
            if !attributes.is_empty() {
                state.received.insert(delivery.id, Received { attributes, link_port: delivery.link_port.clone() });
            }
        }
        drop(delivery);
        return Some(published.err().unwrap_or(STATUS_SUCCESS));
    }
}

/// A vista de dados de uma resposta (o atributo de vista válido no
/// ALPC_MESSAGE_ATTRIBUTES de envio), achada na porta por onde o servidor
/// responde.
/// O segundo valor diz se o atributo pede que a vista que o pedido trouxe ao
/// servidor saia (UNMAP_EXISTING).
fn capture_reply_view(port: &Arc<Port>, attributes: u64, mode: u8) -> Result<(Option<Arc<message_view::Carried>>, bool), u32> {
    if attributes == 0 {
        return Ok((None, false));
    }
    let header = state::user_struct::<AlpcMessageAttributes>(attributes).map_err(|error| error.status)?;
    let (allocated, valid) = (header.allocated_attributes.probe_get().map_err(|error| error.status)?, header.valid_attributes.probe_get().map_err(|error| error.status)?);
    if valid & !allocated != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if valid & VIEW_ATTRIBUTE == 0 {
        return Ok((None, false));
    }
    let at = crate::ntos::ps::user::alpc::attribute_address(attributes, VIEW_ATTRIBUTE);
    let unmap = message_view::unmap_existing(at, mode);
    match message_view::capture(port, at, mode) {
        Ok(Ok(message_view::Captured::View(carried))) => Ok((Some(carried), unmap)),
        Ok(Ok(message_view::Captured::Empty)) => Ok((None, unmap)),
        Ok(Err(status)) => Err(status),
        Err(error) => Err(if error.status != 0 { error.status } else { 0xC000_0001 }),
    }
}

/// O envio do servidor: a resposta ao pedido do MessageId da mensagem, pela
/// porta `port`, com a vista de dados do atributo de envio. Sem
/// ALPC_MSGFLG_RELEASE_MESSAGE (`release` falso) numa porta que não é LPC, a
/// resposta é também um pedido, como no AlpcpSendMessage e no
/// AlpcpDispatchReplyToWaitingThread: o cliente a recebe como LPC_REQUEST
/// com LPC_CONTINUATION_REQUIRED (o bit 9 da mensagem desligado) e o
/// AlpcpReceiveSynchronousReply a deixa pendente nele, que a responde pelo
/// MessageId (o lsm.dll responde assim aos pedidos do winsrvext do csrss na
/// `\SmSsWinStationApiPort`).
fn send_reply(server: &UserServer, port: &Arc<Port>, input: u64, attributes: u64, mode: u8, release: bool) -> u32 {
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
    let (view, unmap) = match capture_reply_view(port, attributes, mode) {
        Ok(captured) => captured,
        Err(status) => return status,
    };
    // O atributo de handles da resposta (o token do UMgrLogonUser do
    // UserManager, um [system_handle] do RPC); uma captura recusada recusa o
    // envio, sem concluir o pedido.
    let handles = match capture_reply_handles(attributes, mode) {
        Ok(handles) => handles,
        Err(status) => return status,
    };
    let (slot, exposed, _received, origin) = {
        let mut state = server.state.lock();
        let slot = state.requests.remove(&id);
        let (exposed, received, origin) = if slot.is_some() || state.abandoned.remove(&id) {
            let origin = state.senders.remove(&id);
            (state.exposed_views.remove(&id), state.received.remove(&id), origin)
        } else {
            (None, None, None)
        };
        (slot, exposed, received, origin)
    };
    if rpc_trace::enabled() {
        let carried = if view.is_some() { rpc_trace::CARRIED_VIEW } else { 0 } | if handles.is_some() { rpc_trace::CARRIED_HANDLES } else { 0 };
        trace_reply(server, slot.as_ref(), origin, id, attributes, release, carried, &captured.data);
    }
    let Some(slot) = slot else {
        if let Some(handles) = handles {
            handles.release();
        }
        return STATUS_REPLY_MESSAGE_MISMATCH;
    };
    // A resposta com UNMAP_EXISTING apaga a vista que o pedido trouxe ao
    // servidor (o AlpcpCaptureViewAttributeInternal com a vista da mensagem).
    if let Some(binding) = exposed.filter(|binding| unmap && !binding.state.lock().deleted) {
        let _ = crate::ntos::alpc::section_views::delete_referenced(&binding);
    }
    slot.continuation.store(!release && !server.legacy(), core::sync::atomic::Ordering::Release);
    complete(server, &slot, id, captured.data, view, handles);
    STATUS_SUCCESS
}

/// Os handles de uma resposta (o ALPC_MESSAGE_HANDLE_ATTRIBUTE válido no
/// ALPC_MESSAGE_ATTRIBUTES de envio), capturados do processo de quem
/// responde como os de um pedido (`message_handles::capture`).
fn capture_reply_handles(attributes: u64, mode: u8) -> Result<Option<Arc<HandleData>>, u32> {
    if attributes == 0 {
        return Ok(None);
    }
    let header = state::user_struct::<AlpcMessageAttributes>(attributes).map_err(|error| error.status)?;
    if header.valid_attributes.probe_get().map_err(|error| error.status)? & HANDLE_ATTRIBUTE == 0 {
        return Ok(None);
    }
    let at = crate::ntos::ps::user::alpc::attribute_address(attributes, HANDLE_ATTRIBUTE);
    match message_handles::capture(at, mode) {
        Ok(Ok(handles)) => Ok(Some(handles)),
        Ok(Err(status)) => Err(status),
        Err(error) => Err(if error.status != 0 { error.status } else { 0xC000_0001 }),
    }
}

/// A linha do `--trace-rpc` da resposta do servidor ao pedido `id`: o Type
/// que o cliente recebe (LPC_REQUEST com LPC_CONTINUATION_REQUIRED quando a
/// resposta sai sem RELEASE_MESSAGE e ele pode respondê-la, como em
/// `ps/user/alpc.rs`), o ValidAttributes do envio e, sem pedido pendente com
/// esse id, a recusa STATUS_REPLY_MESSAGE_MISMATCH.
#[allow(clippy::too_many_arguments)]
fn trace_reply(server: &UserServer, slot: Option<&ReplySlot>, origin: Option<Origin>, id: u32, attributes: u64, release: bool, carried: u32, data: &[u8]) {
    let continuation = slot.is_some_and(|slot| slot.requeue.is_none()) && !release && !server.legacy();
    let message_type = if continuation { LPC_REQUEST | LPC_CONTINUATION_REQUIRED } else { LPC_REPLY };
    let sent_attributes = if attributes != 0 { state::user_struct::<AlpcMessageAttributes>(attributes).and_then(|header| header.valid_attributes.probe_get()).unwrap_or(0) } else { 0 };
    rpc_trace::message(&Record {
        listener: server.listener.pointer,
        client_port: origin.map_or(0, |origin| origin.client),
        client: origin.map_or(0, |origin| origin.sender.process),
        server: server.listener.process_id(),
        direction: Direction::ToClient,
        message_type,
        id,
        attributes: sent_attributes,
        carried,
        data,
        status: slot.is_none().then_some(STATUS_REPLY_MESSAGE_MISMATCH),
    });
}

/// Conclui a resposta ao pedido `id`: a continuação (ou a espera síncrona)
/// de quem enviou, ou, numa mensagem nova do lado servidor sem
/// SYNC_REQUEST, o LPC_REPLY na fila da porta de conexão (o
/// AlpcpDispatchReplyToPort, com o PortContext e a sequência da porta que
/// enviou).
fn complete(server: &UserServer, slot: &ReplySlot, id: u32, data: Vec<u8>, view: Option<Arc<message_view::Carried>>, handles: Option<Arc<HandleData>>) {
    let replier = current_sender();
    if let Some(requeue) = &slot.requeue {
        // O LPC_REPLY na fila do servidor não leva handles.
        if let Some(handles) = handles {
            handles.release();
        }
        let sequence = {
            let _state = server.state.lock();
            next_sequence(&requeue.owner)
        };
        server.enqueue(Delivery { id, message_type: LPC_REPLY, data, sender: replier, port_context: requeue.port_context, data_view: view, sequence, ..Delivery::default() });
        return;
    }
    *slot.view.lock() = view;
    *slot.handles.0.lock() = handles;
    *slot.result.lock() = Some(JobResult { status: STATUS_SUCCESS, data, sender: Some(replier) });
    kernel_entry::notify_waiters();
}

/// O envio do lado servidor: a resposta a um pedido (pelo MessageId) ou uma
/// mensagem nova, com o Type dela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendKind {
    New(u16),
    Reply,
}

/// AlpcpSendMessage. Numa porta LPC (ou no contrato LPC de kernel, o bit 1
/// das flags) o Type decide: zero é uma mensagem nova (LPC_DATAGRAM com
/// RELEASE_MESSAGE, LPC_REQUEST sem), LPC_REQUEST com MessageId é a
/// resposta, os tipos de sistema (3 a 6 e 13 com RELEASE_MESSAGE, 7 a 9 sem)
/// só vêm do contrato LPC de kernel e o resto é STATUS_INVALID_PARAMETER; o
/// bit 0 das flags (só de kernel) é sempre uma resposta. Nas outras portas o
/// MessageId zero (ou o de uma reserva) é a mensagem nova, que não pode
/// trazer CLIENT_ID (STATUS_INVALID_MESSAGE). A mensagem nova conserva os
/// bits altos do Type do remetente: Type & 0xEF00 em KernelMode, & 0x6F00 em
/// UserMode (sem o LPC_KERNELMODE_MESSAGE).
fn classify(header: &[u8; 40], lpc: bool, flags: u32, mode: u8) -> Result<SendKind, u32> {
    let word = |offset: usize| u16::from_le_bytes([header[offset], header[offset + 1]]);
    let message_type = word(offset_of!(PortMessage, u2.s2.type_));
    let id_offset = offset_of!(PortMessage, message_id);
    let id = u32::from_le_bytes([header[id_offset], header[id_offset + 1], header[id_offset + 2], header[id_offset + 3]]);
    let high = message_type & if mode == 0 { 0xEF00 } else { 0x6F00 };
    let low = message_type & 0xFF;
    let release = flags & RELEASE_MESSAGE != 0;
    if lpc || flags & KERNEL_LPC_SEND != 0 {
        if flags & 1 != 0 {
            return if id != 0 { Ok(SendKind::Reply) } else { Err(STATUS_INVALID_PARAMETER) };
        }
        let system = flags & KERNEL_LPC_SEND != 0;
        return match (release, low) {
            (true, 0) => Ok(SendKind::New(high | LPC_DATAGRAM)),
            (true, 3..=6 | 0xD) if system => Ok(SendKind::New(high | low)),
            (false, 0) => Ok(SendKind::New(high | LPC_REQUEST)),
            (false, 1) if id != 0 => Ok(SendKind::Reply),
            (false, 7..=9) if system => Ok(SendKind::New(high | low)),
            _ => Err(STATUS_INVALID_PARAMETER),
        };
    }
    if id != 0 && id & 0x8000_0000 == 0 {
        return Ok(SendKind::Reply);
    }
    let client_id = offset_of!(PortMessage, client_id);
    if header[client_id..client_id + 16].iter().any(|&byte| byte != 0) {
        return Err(STATUS_INVALID_MESSAGE);
    }
    Ok(SendKind::New(high | if release { LPC_DATAGRAM } else { LPC_REQUEST }))
}

/// O cabeçalho da mensagem de envio (sondado em UserMode) classificado pela
/// porta que envia.
fn classify_input(port: &Arc<Port>, input: u64, flags: u32, mode: u8) -> Result<SendKind, u32> {
    if !message_buffer::accessible(input, PortMessage::SIZE, mode, false) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let mut header = [0u8; 40];
    header.copy_from_slice(&message_buffer::read_block(input, PortMessage::SIZE)?);
    classify(&header, port.with(|state| state.port_flags) & LPC_MODE != 0, flags, mode)
}

/// Onde fica a resposta que uma mensagem nova síncrona espera: um pedido na
/// própria fila (pelo id no servidor) ou uma mensagem ao cliente (pela porta
/// dele e pelo MessageId nela).
#[derive(Clone, Copy)]
enum ReplyKey {
    Request(u32),
    Callback(u64, u32),
}

/// A mensagem nova postada: nada a esperar, ou a resposta síncrona.
enum Posted {
    Sent,
    Waiting { key: ReplyKey, slot: ReplySlot, port_context: u64 },
}

/// A mensagem nova do lado servidor (AlpcpDispatchNewMessage): na porta de
/// conexão, a própria fila, com o PortContext e a sequência dela; numa porta
/// de comunicação, a porta do cliente ([`post_to_client`]). O datagrama
/// (RELEASE_MESSAGE) não espera resposta; o envio síncrono a espera em
/// [`SyncReply`]; o resto a recebe como LPC_REPLY na fila do servidor.
fn post_new(server: &Arc<UserServer>, port: &Arc<Port>, flags: u32, captured: message_buffer::Captured, message_type: u16) -> Result<Result<Posted, u32>, KernelError> {
    let datagram = flags & RELEASE_MESSAGE != 0;
    let synchronous = flags & SYNC_REQUEST != 0;
    let message_type = if datagram { message_type & !LPC_CONTINUATION_REQUIRED } else { message_type | LPC_CONTINUATION_REQUIRED };
    let sender = current_sender();
    if !Arc::ptr_eq(&server.listener, port) {
        return post_to_client(server, port, sender, captured, message_type, datagram, synchronous);
    }
    let port_context = port.with(|state| state.port_context);
    let slot: ReplySlot = Arc::new(ReplyCell { requeue: (!synchronous).then(|| Requeue { port_context, owner: port.clone() }), ..ReplyCell::default() });
    let (id, sequence) = {
        let mut state = server.state.lock();
        if state.closed {
            return Ok(Err(STATUS_PORT_DISCONNECTED));
        }
        let id = UserServer::next_id(&mut state);
        if !datagram {
            state.requests.insert(id, slot.clone());
            state.senders.insert(id, Origin { sender, client: 0, waiting: synchronous, message_type, received: false });
        }
        (id, next_sequence(port))
    };
    if crate::ntos::init::boot_config::TRACE_SYSCALLS {
        crate::debug_print!("[alpc] mensagem nova na propria porta de conexao: tipo {:#x} id {} pid {}", message_type, id, sender.process);
    }
    if rpc_trace::enabled() {
        rpc_trace::message(&Record { listener: server.listener.pointer, client: sender.process, server: server.listener.process_id(), message_type, id, data: &captured.data, ..Record::default() });
    }
    server.enqueue(Delivery { id, message_type, data: captured.data, sender, port_context, sequence, ..Delivery::default() });
    Ok(Ok(if synchronous { Posted::Waiting { key: ReplyKey::Request(id), slot, port_context } } else { Posted::Sent }))
}

/// A mensagem nova numa porta de comunicação do servidor (o callback): vai à
/// porta do cliente ligado a ela, que precisa de ALLOW_LPC_REQUESTS
/// (STATUS_LPC_REQUESTS_NOT_ALLOWED) e de espaço para ela
/// (STATUS_BUFFER_TOO_SMALL), como no AlpcpDispatchNewMessage com a porta do
/// cliente como destino. O cliente a recebe na fila dele (o MessageId é o da
/// mensagem na porta dele) e responde por ele ([`reply_from_client`]).
fn post_to_client(server: &Arc<UserServer>, port: &Arc<Port>, sender: Sender, captured: message_buffer::Captured, message_type: u16, datagram: bool, synchronous: bool) -> Result<Result<Posted, u32>, KernelError> {
    let Some((_, client_pointer)) = COMMUNICATION.lock().get(&port.pointer).cloned() else { return Ok(Err(STATUS_PORT_DISCONNECTED)) };
    let port_context = {
        let state = server.state.lock();
        match state.links.get(&client_pointer) {
            Some(link) if !link.disconnected && Arc::ptr_eq(&link.server_port, port) => link.context,
            _ => return Ok(Err(STATUS_PORT_DISCONNECTED)),
        }
    };
    let Some(client) = port_objects::port_of(client_pointer).filter(|client| !client.closed()) else { return Ok(Err(STATUS_PORT_DISCONNECTED)) };
    if client.with(|state| state.port_flags) & ALLOW_LPC_REQUESTS == 0 {
        return Ok(Err(STATUS_LPC_REQUESTS_NOT_ALLOWED));
    }
    if PortMessage::SIZE + captured.data.len() as u64 > client.maximum() as u64 {
        return Ok(Err(STATUS_BUFFER_TOO_SMALL));
    }
    let slot: ReplySlot = Arc::new(ReplyCell { requeue: (!synchronous).then(|| Requeue { port_context, owner: port.clone() }), ..ReplyCell::default() });
    // A resposta pode chegar antes da volta desta chamada: o registro vem
    // antes de a mensagem entrar na fila do cliente.
    let register = |identifier: u32| {
        if !datagram {
            server.state.lock().callbacks.insert((client_pointer, identifier), slot.clone());
        }
        if rpc_trace::enabled() {
            rpc_trace::message(&Record { listener: server.listener.pointer, client_port: client_pointer, client: client.process_id(), server: sender.process, direction: Direction::ToClient, message_type, id: identifier, data: &captured.data, ..Record::default() });
        }
    };
    let identifier = match crate::ntos::ps::user::alpc::post_server_message(&client, message_type, &captured.data, sender, register)? {
        Ok(identifier) => identifier,
        Err(status) => return Ok(Err(status)),
    };
    if crate::ntos::init::boot_config::TRACE_SYSCALLS {
        crate::debug_print!("[alpc] mensagem do servidor ao cliente pid {}: tipo {:#x} id {}", client.process_id(), message_type, identifier);
    }
    Ok(Ok(if synchronous { Posted::Waiting { key: ReplyKey::Callback(client_pointer, identifier), slot, port_context } } else { Posted::Sent }))
}

/// A resposta do cliente a uma mensagem que o servidor mandou a ele (o
/// envio com o MessageId dela na porta do cliente, AlpcpSendMessage com a
/// mensagem recebida): conclui a espera do servidor, ou vira o LPC_REPLY na
/// fila dele. `None` se a porta não tem mensagem do servidor com esse id.
pub fn reply_from_client(client: &Arc<Port>, id: u32, data: Vec<u8>) -> Option<u32> {
    let service = client.with(|state| state.service.clone())?;
    let server = SERVERS.lock().values().find(|candidate| Arc::as_ptr(candidate).cast::<u8>() == Arc::as_ptr(&service).cast::<u8>()).cloned()?;
    let slot = server.state.lock().callbacks.remove(&(client.pointer, id))?;
    if rpc_trace::enabled() {
        rpc_trace::message(&Record { listener: server.listener.pointer, client_port: client.pointer, client: client.process_id(), server: server.listener.process_id(), message_type: LPC_REPLY, id, data: &data, ..Record::default() });
    }
    complete(&server, &slot, id, data, None, None);
    Some(STATUS_SUCCESS)
}

/// A espera de uma mensagem nova síncrona do lado servidor: a resposta vira
/// o LPC_REPLY no buffer de recepção, com o CLIENT_ID de quem respondeu e o
/// MessageId da mensagem, e o ALPC_CONTEXT_ATTR, quando alocado, com o
/// PortContext da porta que enviou. Sem resposta (prazo, alerta, saída), a
/// mensagem sai do registro e da fila, e uma resposta tardia não acha mais o
/// pedido.
struct SyncReply {
    server: Arc<UserServer>,
    key: ReplyKey,
    slot: ReplySlot,
    port_context: u64,
    buffer: Buffer,
    attributes: u64,
    done: bool,
}

impl SyncReply {
    fn take_reply(&mut self) -> Option<u32> {
        if self.done {
            return Some(STATUS_SUCCESS);
        }
        let result = self.slot.result.lock().take()?;
        self.done = true;
        if result.status != STATUS_SUCCESS {
            return Some(result.status);
        }
        let id = match self.key {
            ReplyKey::Request(id) | ReplyKey::Callback(_, id) => id,
        };
        let total = PortMessage::SIZE as usize + result.data.len();
        let mut bytes = alloc::vec![0u8; total];
        let put = |bytes: &mut Vec<u8>, offset: usize, value: &[u8]| bytes[offset..offset + value.len()].copy_from_slice(value);
        put(&mut bytes, offset_of!(PortMessage, u1.s1.data_length), &(result.data.len() as u16).to_le_bytes());
        put(&mut bytes, offset_of!(PortMessage, u1.s1.total_length), &(total as u16).to_le_bytes());
        put(&mut bytes, offset_of!(PortMessage, u2.s2.type_), &LPC_REPLY.to_le_bytes());
        let replier = result.sender.unwrap_or_default();
        put(&mut bytes, offset_of!(PortMessage, client_id.unique_process), &replier.process.to_le_bytes());
        put(&mut bytes, offset_of!(PortMessage, client_id.unique_thread), &replier.thread.to_le_bytes());
        put(&mut bytes, offset_of!(PortMessage, message_id), &id.to_le_bytes());
        bytes[PortMessage::SIZE as usize..].copy_from_slice(&result.data);
        let status = message_buffer::deliver(&self.buffer, &bytes, true);
        if status != STATUS_SUCCESS {
            return Some(status);
        }
        Some(publish_reply_attributes(self.attributes, self.port_context, id).err().unwrap_or(STATUS_SUCCESS))
    }

    fn abandon(&mut self) {
        if self.done {
            return;
        }
        let mut state = self.server.state.lock();
        match self.key {
            ReplyKey::Request(id) => {
                state.requests.remove(&id);
                state.senders.remove(&id);
                state.queue.retain(|delivery| delivery.id != id || delivery.message_type & 0xFF != LPC_REQUEST);
            }
            ReplyKey::Callback(client, id) => {
                state.callbacks.remove(&(client, id));
            }
        }
    }
}

impl crate::ntos::alpc::kernel_entry::Pending for SyncReply {
    fn poll(&mut self) -> Option<u32> {
        self.take_reply()
    }

    fn cancel(&mut self) {
        self.abandon();
    }
}

/// Os atributos de recepção da resposta síncrona: só o ALPC_CONTEXT_ATTR,
/// quando alocado.
fn publish_reply_attributes(attributes: u64, port_context: u64, id: u32) -> Result<(), u32> {
    if attributes == 0 {
        return Ok(());
    }
    let header = state::user_struct::<AlpcMessageAttributes>(attributes).map_err(|error| error.status)?;
    let valid = header.allocated_attributes.probe_get().map_err(|error| error.status)? & CONTEXT_ATTRIBUTE;
    if valid != 0 {
        let at = crate::ntos::ps::user::alpc::attribute_address(attributes, CONTEXT_ATTRIBUTE);
        context_attribute::try_write(at, port_context, 0, 0, id, 0)?;
    }
    header.valid_attributes.probe_set(valid).map_err(|error| error.status)
}

/// NtAlpcSendWaitReceivePort na porta de conexão ou de comunicação de um
/// servidor de usuário: o envio (a resposta pelo MessageId ou a mensagem
/// nova, [`classify`]) e depois a recepção (se houver buffer), com a espera
/// pela próxima mensagem; o envio síncrono espera a resposta dele no buffer
/// de recepção.
pub fn exchange(port: &Arc<Port>, flags: u32, input: u64, send_attributes: u64, receive: crate::ntos::ps::user::alpc::ReceiveArguments) -> Result<u32, KernelError> {
    let Some(server) = server_of(port) else { return Ok(STATUS_INVALID_PORT_HANDLE) };
    // O despacho NT ignora os bits baixos e recusa estas combinações antes
    // do envio.
    let flags = flags & 0xFFFF_0000;
    if flags & SYNC_REQUEST != 0 {
        if input == 0 || flags & 0x101_0000 != 0 {
            return Ok(STATUS_INVALID_PARAMETER_2);
        }
        if receive.output == 0 {
            return Ok(STATUS_LPC_RECEIVE_BUFFER_EXPECTED);
        }
    } else if input != 0 && flags & 0x100_0000 != 0 {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if input != 0 {
        match classify_input(port, input, flags, 1) {
            Err(status) => return Ok(status),
            Ok(SendKind::New(message_type)) => return send_new(&server, port, flags, input, message_type, receive),
            Ok(SendKind::Reply) if flags & SYNC_REQUEST != 0 => {
                crate::debug_print!("[alpc] servidor de usuario: resposta que espera outra resposta sem suporte");
                return Ok(STATUS_NOT_SUPPORTED);
            }
            Ok(SendKind::Reply) => {}
        }
    }
    reply_and_receive(server, port, input, send_attributes, flags & 0x1_0000 != 0, receive, ReceiveOptions::default())
}

/// A mensagem nova de modo usuário do lado servidor: o envio síncrono sonda
/// o buffer de recepção antes de postar e espera a resposta nele; os outros
/// seguem para a recepção, se houver buffer.
fn send_new(server: &Arc<UserServer>, port: &Arc<Port>, flags: u32, input: u64, message_type: u16, receive: crate::ntos::ps::user::alpc::ReceiveArguments) -> Result<u32, KernelError> {
    let synchronous = flags & SYNC_REQUEST != 0;
    let buffer = if synchronous {
        let header = message_buffer::probe_header(receive.output, 1);
        if header != 0 {
            return Ok(header);
        }
        let status = crate::ntos::ps::user::alpc::attributes(receive.receive_attributes, false, 1);
        if status != 0 {
            return Ok(status);
        }
        if receive.timeout != 0 && !state::probe_user_read(receive.timeout, 8) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        match message_buffer::capture_length(receive.output, receive.length, 1) {
            Ok(buffer) => Some(buffer),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let captured = match message_buffer::capture_message_with(input, port.maximum().max(PortMessage::SIZE as u32), 1, server.legacy()) {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    let (key, slot, port_context) = match post_new(server, port, flags, captured, message_type)? {
        Err(status) => return Ok(status),
        Ok(Posted::Waiting { key, slot, port_context }) => (key, slot, port_context),
        Ok(Posted::Sent) => {
            if receive.output == 0 {
                return Ok(STATUS_SUCCESS);
            }
            return reply_and_receive(server.clone(), port, 0, 0, true, receive, ReceiveOptions::default());
        }
    };
    let Some(buffer) = buffer else { return Err(KernelError::new("ALPC synchronous send without receive buffer")) };
    let pending = Arc::new(SpinLock::new(SyncReply { server: server.clone(), key, slot, port_context, buffer, attributes: receive.receive_attributes, done: false }));
    let (polled, abandoned) = (pending.clone(), pending);
    let wait = Wait { poll: Some(Box::new(move || polled.lock().take_reply())), cleanup: Some(Box::new(move |_| abandoned.lock().abandon())), ..Wait::default() };
    Ok(threads::wait_transport(wait, receive.timeout))
}

/// A resposta (se houver mensagem de envio; `release` é o
/// ALPC_MSGFLG_RELEASE_MESSAGE dela) e depois a recepção (se houver buffer),
/// com a espera pela próxima mensagem: o lado servidor do
/// NtAlpcSendWaitReceivePort e do NtReplyWaitReceivePort(Ex).
fn reply_and_receive(server: Arc<UserServer>, port: &Arc<Port>, input: u64, send_attributes: u64, release: bool, receive: crate::ntos::ps::user::alpc::ReceiveArguments, options: ReceiveOptions) -> Result<u32, KernelError> {
    if input != 0 {
        let status = send_reply(&server, port, input, send_attributes, 1, release);
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
    // AlpcpReceiveMessagePort com a fila vazia (`Port::empty_receive_status`).
    if let Some(status) = receiving_port(&server, port, options).empty_receive_status() {
        return Ok(status);
    }
    if receive.timeout != 0 && guest::try_read::<i64>(receive.timeout)? == 0 {
        return Ok(STATUS_TIMEOUT);
    }
    let attributes = receive.receive_attributes;
    let waiting = server.clone();
    let wait = Wait { poll: Some(Box::new(move || receive_one(&waiting, &buffer, attributes, options))), ..Wait::default() };
    Ok(threads::wait_transport(wait, receive.timeout))
}

/// O servidor de usuário dono de um nó AlpcPort (a porta de conexão com
/// nome).
pub fn server_of_node(node: object_manager::NodeId) -> Option<Arc<UserServer>> {
    SERVERS.lock().values().find(|server| server.endpoint.lock().as_ref().is_some_and(|endpoint| endpoint.node == node)).cloned()
}

/// A conexão de modo usuário a uma porta de servidor (o
/// ObReferenceObjectByName do AlpcpCreateClientPort com DesiredAccess
/// PORT_CONNECT): o SeAccessCheck do token efetivo de quem conecta contra o
/// descritor atual da porta de conexão; a recusa é STATUS_ACCESS_DENIED. Os
/// serviços hospedados no kernel não têm porta de conexão e não passam por
/// aqui.
pub fn check_connect_access(node: object_manager::NodeId, path: &str) -> Result<(), u32> {
    let Some(server) = server_of_node(node) else { return Ok(()) };
    let Some(policy) = crate::ntos::ob::objects::dispatcher::security(server.listener.pointer) else { return Ok(()) };
    let Some(alpc_type) = crate::ntos::ob::object_types::user_type("alpc") else { return Err(0xC000_0024) };
    crate::ntos::ob::object_access::check(&policy, crate::ntos::ob::object_access::subject(), PORT_CONNECT, &alpc_type, false).map(|_| ()).inspect_err(|status| {
        crate::debug_print!("[alpc] PORT_CONNECT em {} recusado ao pid {}: {:#x}", path, process::get_current_process_id(), status);
    })
}

/// PORT_CONNECT.
const PORT_CONNECT: u32 = 1;

/// O servidor do lado servidor de uma porta (de conexão ou de comunicação).
pub fn server_for(port: &Arc<Port>) -> Option<Arc<UserServer>> {
    server_of(port)
}

/// As mensagens ainda na fila de uma porta de conexão de servidor (zero em
/// qualquer outra porta): a associação da IOCP avisa cada uma.
pub fn queued_messages(port: &Arc<Port>) -> usize {
    let server = SERVERS.lock().get(&port.pointer).cloned();
    server.map_or(0, |server| server.state.lock().queue.len())
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
    let options = ReceiveOptions { legacy: server.legacy(), port_context, connections_only, on_connection_port: true };
    let arguments = crate::ntos::ps::user::alpc::ReceiveArguments { output: receive, length: 0, receive_attributes: 0, timeout };
    reply_and_receive(server, port, reply, 0, true, arguments, options)
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
    let (id, context, sequence) = {
        let mut state = server.state.lock();
        if state.closed {
            return;
        }
        let (context, sequence) = match client.and_then(|client| state.links.get(&client)) {
            Some(link) => (link.context, next_sequence(&link.server_port)),
            None => (0, next_sequence(&server.listener)),
        };
        (UserServer::next_id(&mut state), context, sequence)
    };
    if rpc_trace::enabled() {
        rpc_trace::message(&Record { listener: server.listener.pointer, client_port: client.unwrap_or(0), client: sender.process, server: server.listener.process_id(), message_type, id, data, ..Record::default() });
    }
    server.enqueue(Delivery { id, message_type, data: data.to_vec(), sender, port_context: context, sequence, ..Delivery::default() });
}

/// O NtReplyPort no lado servidor: a resposta ao pedido do MessageId.
pub fn reply_legacy(port: &Arc<Port>, reply: u64) -> u32 {
    match server_of(port) {
        Some(server) => send_reply(&server, port, reply, 0, 1, true),
        None => STATUS_INVALID_PORT_HANDLE,
    }
}

/// O remetente (processo, thread e a ETHREAD dele, e a porta do cliente) da
/// mensagem `id` ainda pendente no servidor da porta.
pub fn sender_of(port: &Arc<Port>, id: u32) -> Option<Origin> {
    server_of(port)?.state.lock().senders.get(&id).copied()
}

/// A porta do cliente ligado a uma porta de comunicação do servidor (o
/// AlpcpReferenceConnectedPort); `None` em qualquer outra porta.
pub fn connected_client(port: &Arc<Port>) -> Option<Arc<Port>> {
    let (_, client) = COMMUNICATION.lock().get(&port.pointer).cloned()?;
    port_objects::port_of(client)
}

/// Os handles que o pedido `id`, já recebido pelo servidor da porta, levou, e
/// a porta de comunicação ligada ao cliente (o NtAlpcQueryInformationMessage
/// da classe 3 os duplica no servidor).
pub fn received_handles(port: &Arc<Port>, id: u32) -> Option<(Arc<HandleData>, Option<Arc<Port>>)> {
    let server = server_of(port)?;
    let state = server.state.lock();
    let received = state.received.get(&id)?;
    Some((received.attributes.handles.clone()?, received.link_port.clone()))
}

/// O contexto de segurança que o pedido `id`, já recebido pelo servidor da
/// porta, levou: o token capturado (retido para quem chama, que o solta), o
/// nível e o EffectiveOnly.
pub fn received_security(port: &Arc<Port>, id: u32) -> Option<(u64, u32, bool)> {
    let server = server_of(port)?;
    let state = server.state.lock();
    let security = state.received.get(&id)?.attributes.security.as_ref()?;
    crate::ntos::se::token::tokens::retain(security.token).ok()?;
    Some((security.token, security.level, security.effective_only))
}

/// O token efetivo da thread `thread` de um cliente: o de impersonação dela,
/// senão o primário do processo dono (o contexto de segurança dinâmico do
/// AlpcpGetEffectiveTokenMessage).
pub fn sender_effective_token(thread: u64) -> Option<u64> {
    if thread == 0 {
        return None;
    }
    // SAFETY: a thread do cliente está retida enquanto a mensagem existe.
    let owner = unsafe { crate::ntos::inc::types::Ethread::at(thread) }.tcb.process.get();
    crate::ntos::se::token::thread::get(thread).map(|state| state.token).or_else(|| process::get_primary_token(owner))
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
    establish_with(server, pending, out, port_context, attributes, None, mode, data, accepted)
}

/// [`establish`] com o Flags e o DupObjectTypes do ALPC_PORT_ATTRIBUTES da
/// aceitação, que valem para a porta de comunicação (as regras de handles
/// dos pedidos do cliente).
#[allow(clippy::too_many_arguments)]
fn establish_with(server: &Arc<UserServer>, pending: &Arc<PendingConnection>, out: u64, port_context: u64, attributes: u64, port_attributes: Option<(u32, u32)>, mode: u8, data: Vec<u8>, accepted: &LegacyAccepted) -> Result<u32, KernelError> {
    let object_flags = object_flags(attributes)?;
    let (accepted_flags, duplicate_object_types) = port_attributes.unwrap_or((0, 0));
    // AlpcpValidateAndSetPortAttributes de uma porta de comunicação do
    // servidor: o Flags reduzido a 0x3FF0000, sem ALLOW_LPC_REQUESTS (as
    // mensagens novas a ela não existem: o cliente manda à porta de conexão).
    let port_flags = (server.listener.with(|state| state.port_flags) & LPC_MODE) | (accepted_flags & 0x03FF_0000 & !ALLOW_LPC_REQUESTS);
    let mut views = Vec::new();
    if let Some(view) = pending.view.as_ref().and_then(|view| view.server()) {
        views.push(view);
    }
    if let Some((local, _)) = &accepted.server_view {
        views.push(local.clone());
    }
    let initial = PortState { role: Role::Server, port_context, port_flags, duplicate_object_types, views, on_disconnect: Some(communication_disconnected), ..PortState::default() };
    let disconnecting = server.clone();
    let client_pointer = pending.client.pointer;
    // A sequência da porta de comunicação começa em zero: a primeira
    // mensagem do cliente é a 1.
    let communication = match port_objects::create("alpc", initial, server.listener.maximum(), 0, attributes, Box::new(move |port: &Arc<Port>| {
        // O fim da porta também solta os pedidos que o cliente esperava.
        communication_disconnected(port, port, true);
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
        server.state.lock().links.insert(client_pointer, Link { server_port: communication.clone(), context: port_context, disconnected: false });
        let server_view = accepted.server_view.as_ref().map(|(_, remote)| remote.clone());
        *pending.decision.lock() = Some(Decision { status: STATUS_SUCCESS, data, server_view });
        kernel_entry::notify_waiters();
        Ok(STATUS_SUCCESS)
    });
    crate::ntos::ob::objects::dispatcher::collect(communication.pointer);
    outcome
}

/// A porta de comunicação do servidor foi desconectada (NtAlpcDisconnectPort)
/// ou fechada: como o AlpcpDisconnectPort e o AlpcpFlushMessagesPort, os
/// pedidos que o cliente dela ainda espera terminam com
/// STATUS_PORT_DISCONNECTED, e os envios seguintes do cliente também. O
/// vínculo continua até o cliente fechar a porta dele (o LPC_PORT_CLOSED com
/// a sequência seguinte da comunicação) ou até a porta de comunicação sair.
fn communication_disconnected(communication: &Arc<Port>, endpoint: &Arc<Port>, _closing: bool) {
    if !Arc::ptr_eq(communication, endpoint) {
        return;
    }
    let Some((server, client)) = COMMUNICATION.lock().get(&communication.pointer).cloned() else { return };
    let slots: Vec<ReplySlot> = {
        let mut state = server.state.lock();
        match state.links.get_mut(&client) {
            Some(link) if Arc::ptr_eq(&link.server_port, communication) => link.disconnected = true,
            _ => return,
        }
        let ids: Vec<u32> = state.requests.keys().copied().filter(|id| state.senders.get(id).is_some_and(|origin| origin.client == client)).collect();
        let mut slots = Vec::new();
        for id in ids {
            if let Some(slot) = state.requests.remove(&id) {
                state.abandoned.insert(id);
                slots.push(slot);
            }
        }
        // As mensagens que o servidor mandou ao cliente por esta porta
        // também não terão resposta.
        slots.extend(take_callbacks(&mut state, client));
        slots
    };
    for slot in &slots {
        *slot.result.lock() = Some(JobResult { status: STATUS_PORT_DISCONNECTED, ..JobResult::default() });
    }
    if !slots.is_empty() {
        kernel_entry::notify_waiters();
    }
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
    // Sem RootDirectory o nome precisa ser absoluto; com ele, o caminho vem
    // do diretório raiz, inclusive o de um namespace privado (o caminho
    // ancorado no diretório sem nome, que as buscas do namespace resolvem),
    // como no ObpLookupObjectName do ObInsertObject.
    if parsed.root_directory == 0 && !parsed.path.starts_with('\\') {
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
    // AlpcpValidateAndSetPortAttributes: ALPC_PORFLG_SYSTEM_PROCESS só de
    // modo kernel, o Flags reduzido a 0x3FF0000 e, numa porta de conexão,
    // ALLOW_LPC_REQUESTS sempre (ela recebe as mensagens novas).
    if mode != 0 && port_flags & 0x10_0000 != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let port_flags = (port_flags & 0x03FF_0000) | ALLOW_LPC_REQUESTS;
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
                crate::debug_print!("[alpc] porta de servidor {} ja existe (pid {})", path, process::get_current_process_id());
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
    // Um nome de modo usuário passa pelo ObInsertObject: DIRECTORY_CREATE_OBJECT
    // no diretório pai e, sem descritor no OBJECT_ATTRIBUTES, o descritor do
    // SeAssignSecurity com as ACEs herdáveis do pai (num `\RPC Control`, as
    // do descritor liberal do smss).
    let parent_node = if mode != 0 && name.is_some() { object_manager::lookup(&parent) } else { None };
    if let Some(node) = parent_node {
        if let Err(status) = crate::ntos::ob::object_security::check_create_in(node, false) {
            return Ok(status);
        }
    }
    let explicit = if mode != 0 && attributes != 0 { state::user_struct::<ObjectAttributes>(attributes)?.security_descriptor.probe_get()? } else { 0 };
    let waitable = initial.port_flags & WAITABLE_PORT != 0;
    let port = match port_objects::create("alpc", initial, maximum, 0, attributes, Box::new(|listener: &Arc<Port>| {
        if let Some(server) = SERVERS.lock().remove(&listener.pointer) {
            server.close();
        }
        if rpc_trace::enabled() {
            rpc_trace::port_closed(listener.pointer);
        }
    }), creator_options(mode, object_flags)) {
        Ok(port) => port,
        Err(error) if error.status != 0 => return Ok(error.status),
        Err(error) => return Err(error),
    };
    // AlpcpInitializePort de uma porta esperável: o KSEMAPHORE em que a
    // espera pelo handle da porta fica.
    if waitable && !port.make_waitable() {
        crate::ntos::ob::objects::dispatcher::collect(port.pointer);
        return Ok(0xC000_009A);
    }
    let server = Arc::new(UserServer { listener: port.clone(), endpoint: SpinLock::new(None), state: SpinLock::new(ServerState::default()) });
    SERVERS.lock().insert(port.pointer, server.clone());
    if rpc_trace::enabled() {
        rpc_trace::port_created(port.pointer, name.as_deref());
    }
    let result = port.run(|| -> Result<u32, KernelError> {
        if let Some(parent_node) = parent_node.filter(|_| explicit == 0) {
            let Some(alpc_type) = crate::ntos::ob::object_types::user_type("alpc") else { return Err(KernelError::new("ALPC Port type missing")) };
            match crate::ntos::ob::object_security::assign_new(&alpc_type, Some(parent_node), 0, true) {
                Ok(policy) => crate::ntos::ob::objects::dispatcher::set_security(port.pointer, policy),
                Err(status) => return Ok(status),
            }
        }
        if name.is_some() {
            let node = match object_manager::create_object(&parent, &leaf, "AlpcPort", None) {
                Ok(node) => node,
                Err(error) => return Ok(if error.status != 0 { error.status } else { STATUS_OBJECT_NAME_COLLISION }),
            };
            // O endpoint leva o descritor da própria porta (o que o
            // NtAlpcCreatePort recebeu, ou o herdado).
            let security = crate::ntos::ob::objects::dispatcher::security(port.pointer).unwrap_or_default();
            *server.endpoint.lock() = Some(transport::attach_with_security(node, server.clone(), security));
        }
        let status = publish_created(&port, out, object_flags, mode)?;
        if status != 0 {
            return Ok(status);
        }
        port.set_started(true);
        crate::debug_print!("[alpc] porta de servidor {} criada pelo pid {} (modo {})", name.as_deref().unwrap_or("(sem nome)"), port.process_id(), mode);
        if let Some(name) = &name {
            crate::ntos::init::initial_process::server_port_created(name);
        }
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
    accept_connect_port_with(out, connection, attributes, 0, port_context, request, accept, mode)
}

/// [`accept_connect_port`] com o ALPC_PORT_ATTRIBUTES da aceitação
/// (`port_attributes`, zero sem ele): o Flags e o DupObjectTypes passam à
/// porta de comunicação, como no AlpcpAcceptConnectPort.
#[allow(clippy::too_many_arguments)]
pub fn accept_connect_port_with(out: u64, connection: u64, attributes: u64, port_attributes: u64, port_context: u64, request: u64, accept: bool, mode: u8) -> Result<u32, KernelError> {
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
        let accepted_attributes = if port_attributes != 0 {
            if mode != 0 && !state::probe_user_read(port_attributes, AlpcPortAttributes::SIZE) {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
            let captured = state::user_struct::<AlpcPortAttributes>(port_attributes)?;
            Some((captured.flags.probe_get()?, captured.dup_object_types.probe_get()?))
        } else {
            None
        };
        // A vista de um cliente LPC já entrou no servidor na recepção (o
        // atributo de vista) ou entra agora, e fica com a comunicação.
        if let Some(view) = &pending.view {
            if let Err(status) = view.expose() {
                return Ok(status);
            }
        }
        establish_with(&server, &pending, out, port_context, attributes, accepted_attributes, mode, captured.data.clone(), &LegacyAccepted::default())
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
        let status = send_reply(&server, port, reply, 0, 0, true);
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
    let options = ReceiveOptions { legacy: server.legacy(), port_context, connections_only: false, on_connection_port: true };
    if let Some(status) = receive_one(&server, &buffer, 0, options) {
        return Ok(Box::new(Completed(status)));
    }
    if let Some(status) = receiving_port(&server, port, options).empty_receive_status() {
        return Ok(Box::new(Completed(status)));
    }
    let waiting = server.clone();
    let operation = kernel_wait::Operation { poll: Box::new(move || receive_one(&waiting, &buffer, 0, options)), cleanup: Box::new(|_| {}) };
    let request = kernel_wait::begin(operation, timeout, 0, false)?;
    Ok(Box::new(request))
}

/// O envio de modo kernel do lado servidor ([`begin_kernel_exchange`]): a
/// mensagem nova de kernel (o win32k manda pelo LpcSendWaitReceivePort à
/// \Windows\ApiPort do csrss e pelo LpcRequestPort e pelo
/// LpcSendWaitReceivePort à DwmApiPort do dwm.exe) ou a resposta. `Some`
/// com a operação que já decide a chamada; `None` para seguir à recepção.
fn kernel_send(server: &Arc<UserServer>, port: &Arc<Port>, flags: u32, input: u64, send_attributes: u64, receive: &crate::ntos::ps::user::alpc::ReceiveArguments) -> Result<Option<Box<dyn crate::ntos::alpc::kernel_entry::Pending>>, KernelError> {
    use crate::ntos::alpc::kernel_entry::Completed;
    let completed = |status: u32| -> Result<Option<Box<dyn crate::ntos::alpc::kernel_entry::Pending>>, KernelError> { Ok(Some(Box::new(Completed(status)))) };
    let synchronous = flags & SYNC_REQUEST != 0;
    if synchronous && input == 0 {
        return completed(STATUS_INVALID_PARAMETER_2);
    }
    if input == 0 {
        return Ok(None);
    }
    let message_type = match classify_input(port, input, flags, 0) {
        Err(status) => return completed(status),
        Ok(SendKind::Reply) if synchronous => {
            crate::debug_print!("[alpc] servidor de kernel: resposta que espera outra resposta sem suporte");
            return completed(STATUS_NOT_SUPPORTED);
        }
        Ok(SendKind::Reply) => {
            let status = send_reply(server, port, input, send_attributes, 0, flags & RELEASE_MESSAGE != 0);
            return if status != 0 { completed(status) } else { Ok(None) };
        }
        Ok(SendKind::New(message_type)) => message_type,
    };
    let buffer = if synchronous {
        if receive.output == 0 {
            return completed(STATUS_LPC_RECEIVE_BUFFER_EXPECTED);
        }
        match message_buffer::capture_length(receive.output, receive.length, 0) {
            Ok(buffer) => Some(buffer),
            Err(status) => return completed(status),
        }
    } else {
        None
    };
    let captured = match message_buffer::capture_message_with(input, port.maximum().max(PortMessage::SIZE as u32), 0, server.legacy() || flags & KERNEL_LPC_SEND != 0) {
        Ok(captured) => captured,
        Err(status) => return completed(status),
    };
    match (post_new(server, port, flags, captured, message_type)?, buffer) {
        (Err(status), _) => completed(status),
        (Ok(Posted::Waiting { key, slot, port_context }), Some(buffer)) => Ok(Some(Box::new(SyncReply { server: server.clone(), key, slot, port_context, buffer, attributes: receive.receive_attributes, done: false }))),
        (Ok(Posted::Waiting { .. }), None) => Err(KernelError::new("ALPC synchronous kernel send without receive buffer")),
        (Ok(Posted::Sent), _) => Ok(None),
    }
}

/// ZwAlpcSendWaitReceivePort na porta de conexão ou de comunicação de um
/// servidor de kernel: o envio (a resposta com os atributos de envio
/// `send_attributes`) e a recepção como em [`exchange`], com os buffers do
/// chamador sem sonda e a espera pela continuação de kernel (o prazo e o
/// modo de espera do ZwAlpcSendWaitReceivePort).
pub fn begin_kernel_exchange(port: &Arc<Port>, flags: u32, input: u64, send_attributes: u64, receive: crate::ntos::ps::user::alpc::ReceiveArguments) -> Result<Box<dyn crate::ntos::alpc::kernel_entry::Pending>, KernelError> {
    use crate::ntos::alpc::kernel_entry::Completed;
    use crate::ntos::alpc::kernel_wait;
    let Some(server) = server_of(port) else { return Ok(Box::new(Completed(STATUS_INVALID_PORT_HANDLE))) };
    if let Some(decided) = kernel_send(&server, port, flags, input, send_attributes, &receive)? {
        return Ok(decided);
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
    if let Some(status) = port.empty_receive_status() {
        return Ok(Box::new(Completed(status)));
    }
    let attributes = receive.receive_attributes;
    let waiting = server.clone();
    let operation = kernel_wait::Operation { poll: Box::new(move || receive_one(&waiting, &buffer, attributes, ReceiveOptions::default())), cleanup: Box::new(|_| {}) };
    let request = kernel_wait::begin(operation, timeout, kernel_wait::select_mode(flags, 0), flags & 0x20_0000 != 0)?;
    Ok(Box::new(request))
}
