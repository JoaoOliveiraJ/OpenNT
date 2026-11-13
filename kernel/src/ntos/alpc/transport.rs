//! Tipos do transporte de mensagens ALPC/LPC (de `system32/ntos/ps/user/alpc.js`).
//!
//! Mensagens enfileiradas na porta, pedidos entregues aos serviços
//! hospedados no kernel e o contrato desses serviços.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::message::identity::Identity;
use crate::ntos::alpc::resource::reserves::Reserve;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::object_access;
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ps::process;
use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::{KernelError, SpinLock};

/// CLIENT_ID de quem emitiu a mensagem (e a thread dona, quando conhecida).
#[derive(Clone, Copy, Debug, Default)]
pub struct Sender {
    pub process: u64,
    pub thread: u64,
    pub thread_pointer: u64,
}

/// Mensagem na fila da porta (resposta, cancelamento ou pedido).
pub struct Message {
    pub bytes: Option<Vec<u8>>,
    pub context: u64,
    pub reserve: Option<Arc<Reserve>>,
    pub id: u32,
    pub identity: Arc<Identity>,
    pub sequence: u32,
    pub status: u32,
    /// Ausente nas notificações de cancelamento (o CID vai só nos bytes).
    pub sender: Option<Sender>,
    pub synchronous: bool,
    pub direct: bool,
}

/// Continuação de um serviço: `poll` devolve o resultado quando pronto.
pub trait Job: Send + Sync {
    fn poll(&mut self) -> Option<JobResult>;
    fn cleanup(&mut self, _status: u32) {}
}

/// Resultado de um serviço: NTSTATUS, a carga da resposta e o remetente
/// (o servidor registrado quando ausente).
#[derive(Default)]
pub struct JobResult {
    pub status: u32,
    pub data: Vec<u8>,
    pub sender: Option<Sender>,
}

#[derive(Default)]
pub struct RequestState {
    pub context: u64,
    pub reserve: Option<Arc<Reserve>>,
    pub synchronous: bool,
    pub datagram: bool,
    pub legacy: bool,
    pub legacy_synchronous: bool,
    pub direct: Option<u64>,
    pub release_direct: Option<Box<dyn FnOnce() + Send>>,
    pub retained: bool,
    pub canceled: bool,
    pub disconnected: bool,
    pub cleaned: bool,
    pub delivery_status: Option<u32>,
    pub cancellation_queued: bool,
    pub cancel_status: Option<u32>,
    pub server_disconnected: bool,
    pub peer_unavailable: bool,
    pub delivered: bool,
    pub polling: bool,
    pub sender: Sender,
    pub job: Option<Box<dyn Job>>,
    /// Conexão: decisão do servidor (status e PORT_MESSAGE de resposta).
    pub connect_result: Option<(u32, Option<Vec<u8>>)>,
    pub released: bool,
    /// Conexão: CID e thread do servidor registrado.
    pub server: Sender,
    /// Conexão: o PORT_MESSAGE montado entregue ao serviço.
    pub connect_bytes: Vec<u8>,
}

/// Pedido entregue ao servidor: o job pertence ao servidor até concluir.
pub struct Request {
    pub id: u32,
    pub identity: Arc<Identity>,
    pub state: SpinLock<RequestState>,
}

/// Decisão de um serviço: concluída agora ou por uma continuação.
pub enum Reply {
    Now(JobResult),
    Later(Box<dyn Job>),
}

/// Serviço hospedado no kernel por trás de um nome de porta. `connect`
/// recebe a carga da conexão (e, nas entradas Ex/Zw, o PORT_MESSAGE
/// montado); `exchange` cada pedido; `request` o contrato LPC legado.
pub trait Service: Send + Sync {
    fn max_message_length(&self) -> u32;
    /// Limite da informação de conexão LPC.
    fn max_connection_info(&self) -> u32 {
        0
    }
    fn connect(&self, port: &Arc<Port>, data: &[u8], request: Option<&[u8]>) -> Reply;
    fn exchange(&self, _port: &Arc<Port>, _data: &[u8], _request: &Arc<Request>) -> Reply {
        Reply::Now(JobResult { status: 0xC000_00BB, ..JobResult::default() })
    }
    fn disconnect(&self, _port: &Arc<Port>) {}
    /// Pedido LPC: conclui agora (NTSTATUS) ou devolve uma continuação.
    fn request(&self, _port: &Arc<Port>, _message: &Arc<SpinLock<Vec<u8>>>) -> ServiceReply {
        ServiceReply::Now(0xC000_00BB)
    }
}

pub enum ServiceReply {
    Now(u32),
    Later(Box<dyn ServiceContinuation>),
}

pub trait ServiceContinuation: Send {
    fn poll(&mut self) -> Option<u32>;
    fn cleanup(&mut self, _status: u32) {}
}

/// Endpoint registrado: conserva a identidade de quem o registrou; a
/// conexão retém esses donos enquanto existir, sem assumir um SID fixo.
pub struct Listener {
    pub node: NodeId,
    pub process: u64,
    pub thread: u64,
    pub process_id: u64,
    pub thread_id: u64,
    pub security: SecurityPolicy,
    pub service: Arc<dyn Service>,
}

static LISTENERS: SpinLock<BTreeMap<NodeId, Arc<Listener>>> = SpinLock::new(BTreeMap::new());

/// Cria o nó AlpcPort no caminho e associa o serviço ao endpoint.
pub fn register(path: &str, service: Arc<dyn Service>) -> Result<Arc<Listener>, KernelError> {
    let split = path.rfind('\\').unwrap_or(0);
    let parent = if split == 0 { "\\" } else { &path[..split] };
    object_manager::create_directory(parent)?;
    let node = object_manager::create_object(parent, &path[split + 1..], "AlpcPort", None)?;
    let listener = Arc::new(Listener {
        node,
        process: process::get_current_process(),
        thread: process::get_current_thread(),
        process_id: process::get_current_process_id(),
        thread_id: process::get_current_thread_id(),
        security: object_access::capture(object_access::subject()),
        service,
    });
    LISTENERS.lock().insert(node, listener.clone());
    Ok(listener)
}

pub fn listener_of(node: NodeId) -> Option<Arc<Listener>> {
    LISTENERS.lock().get(&node).cloned()
}

/// Retira o endpoint (o nó sai do namespace).
pub fn unregister(listener: &Listener) {
    LISTENERS.lock().remove(&listener.node);
    object_manager::remove_named(listener.node);
}
