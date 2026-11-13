//! RPC local sobre ALPC.
//!
//! Ligação de interface e mensagens NDR32 imediatas, com o layout do
//! RPCRT4 instalado; modos de transferência sem suporte viram RPC faults.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::transport::{Job, JobResult, Reply, Request, Service};
use crate::ntos::ob::objects::port::Port;
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::eprocess;

/// Identidade do cliente da conexão.
#[derive(Clone, Copy, Debug, Default)]
pub struct RpcContext {
    pub process_id: u64,
    pub token: u64,
}

/// Corpo da resposta de uma operação: agora ou numa continuação.
pub enum Body {
    Now(Vec<u8>),
    Later(Box<dyn Pending>),
}

/// Continuação de uma operação: `Ok(None)` ainda pendente; `Err` = RPC status.
pub trait Pending: Send + Sync {
    fn poll(&mut self) -> Result<Option<Vec<u8>>, u32>;
    fn cleanup(&mut self) {}
}

/// Interface servida: `Err` leva o RPC status do fault (1726 por padrão).
pub trait Interface: Send + Sync {
    fn call(&self, context: &RpcContext, operation: u32, arguments: &[u8]) -> Result<Body, u32>;
    fn disconnect(&self, _context: &RpcContext) {}
}

#[derive(Default)]
struct Flow {
    next: u32,
    pending: BTreeSet<u32>,
}

struct Connection {
    bindings: BTreeMap<u32, Arc<dyn Interface>>,
    flows: BTreeMap<u64, Arc<SpinLock<Flow>>>,
    context: RpcContext,
}

pub struct Endpoint {
    interfaces: BTreeMap<String, Arc<dyn Interface>>,
    connections: SpinLock<BTreeMap<u64, Connection>>,
}

fn read32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn rpc_fault(status: u32) -> JobResult {
    crate::debug_print!("[lrpc] fault={}", status);
    let mut bytes = alloc::vec![0u8; 16];
    bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&status.to_le_bytes());
    JobResult { status: 0, data: bytes, sender: None }
}

fn finish(call_id: u32, body: Vec<u8>) -> JobResult {
    if body.len() > 0xEF0 {
        return rpc_fault(1726);
    }
    let mut response = alloc::vec![0u8; 24 + body.len()];
    response[0..4].copy_from_slice(&3u32.to_le_bytes());
    response[12..16].copy_from_slice(&call_id.to_le_bytes());
    response[24..].copy_from_slice(&body);
    JobResult { status: 0, data: response, sender: None }
}

/// Uma chamada pronta para despachar (em ordem dentro do fluxo causal).
struct Call {
    service: Arc<dyn Interface>,
    context: RpcContext,
    operation: u32,
    arguments: Vec<u8>,
    call_id: u32,
    flow: Option<(Arc<SpinLock<Flow>>, u32)>,
}

enum Dispatched {
    Done(JobResult),
    Pending(Box<dyn Pending>, u32),
}

impl Call {
    fn dispatch(&self) -> Dispatched {
        if let Some((flow, sequence)) = &self.flow {
            let mut flow = flow.lock();
            flow.pending.remove(sequence);
            flow.next = sequence.wrapping_add(1);
        }
        match self.service.call(&self.context, self.operation, &self.arguments) {
            Ok(Body::Now(body)) => {
                crate::debug_print!("[lrpc] op={} in={} out={}", self.operation, self.arguments.len(), body.len());
                Dispatched::Done(finish(self.call_id, body))
            }
            Ok(Body::Later(pending)) => Dispatched::Pending(pending, self.call_id),
            Err(status) => {
                crate::debug_print!("[lrpc] rejected op={} size={} status={}", self.operation, self.arguments.len(), status);
                Dispatched::Done(rpc_fault(status))
            }
        }
    }
}

/// Continuação: espera a vez no fluxo e então a resposta da operação. Uma
/// resposta adiada da aplicação não bloqueia as chamadas seguintes.
struct CallJob {
    call: Option<Call>,
    sequence: u32,
    flow: Option<Arc<SpinLock<Flow>>>,
    pending: Option<(Box<dyn Pending>, u32)>,
}

impl Job for CallJob {
    fn poll(&mut self) -> Option<JobResult> {
        if let Some(call) = &self.call {
            if self.flow.as_ref().is_some_and(|flow| flow.lock().next != self.sequence) {
                return None;
            }
            let dispatched = call.dispatch();
            self.call = None;
            match dispatched {
                Dispatched::Done(result) => return Some(result),
                Dispatched::Pending(pending, call_id) => self.pending = Some((pending, call_id)),
            }
        }
        let (pending, call_id) = self.pending.as_mut()?;
        match pending.poll() {
            Ok(None) => None,
            Ok(Some(body)) => Some(finish(*call_id, body)),
            Err(status) => Some(rpc_fault(status)),
        }
    }

    fn cleanup(&mut self, _status: u32) {
        if let Some(flow) = &self.flow {
            flow.lock().pending.remove(&self.sequence);
        }
        if let Some((pending, _)) = self.pending.as_mut() {
            pending.cleanup();
        }
    }
}

impl Endpoint {
    /// Interfaces por `<uuid em hex>:<versão>`.
    pub fn new(interfaces: BTreeMap<String, Arc<dyn Interface>>) -> Self {
        Endpoint { interfaces, connections: SpinLock::new(BTreeMap::new()) }
    }

    /// Bind ou request sobre a conexão da porta (o `exchange` do transporte).
    pub fn exchange_bytes(&self, port: &Arc<Port>, bytes: &[u8]) -> Reply {
        if bytes.len() < 8 {
            return Reply::Now(rpc_fault(1728));
        }
        let kind = read32(bytes, 0);
        if kind == 1 {
            return Reply::Now(self.bind(port, bytes));
        }
        if kind != 0 || bytes.len() < 64 {
            return Reply::Now(rpc_fault(1728));
        }
        let binding = read32(bytes, 16);
        let operation = read32(bytes, 20);
        let (service, context) = {
            let connections = self.connections.lock();
            let Some(connection) = connections.get(&port.pointer) else { return Reply::Now(rpc_fault(1728)) };
            match connection.bindings.get(&binding) {
                Some(service) => (service.clone(), connection.context),
                None => {
                    crate::debug_print!("[lrpc] unknown binding={} operation={}", binding, operation);
                    return Reply::Now(rpc_fault(1728));
                }
            }
        };
        // Cargas por vista, callbacks de objeto e pipes são outros modos.
        let flags = read32(bytes, 8);
        let call_id = read32(bytes, 12);
        if flags & !2 != 0 {
            crate::debug_print!("[lrpc] request flags=0x{:x} op={} size={}", flags, operation, bytes.len());
            return Reply::Now(rpc_fault(1764));
        }
        let mut flow = None;
        let mut sequence = 0;
        if flags & 2 != 0 {
            // LRPC_CAUSAL_FLOW::SendNextCalls: o id do fluxo em +0x48 do
            // PORT_MESSAGE e a sequência crescente em +0x50.
            let id = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
            sequence = read32(bytes, 40);
            if sequence == 0 {
                return Reply::Now(rpc_fault(1728));
            }
            let mut connections = self.connections.lock();
            let Some(connection) = connections.get_mut(&port.pointer) else { return Reply::Now(rpc_fault(1728)) };
            let entry = match connection.flows.get(&id) {
                Some(entry) => entry.clone(),
                None => {
                    if connection.flows.len() >= 256 {
                        return Reply::Now(rpc_fault(1723));
                    }
                    let entry = Arc::new(SpinLock::new(Flow { next: 1, pending: BTreeSet::new() }));
                    connection.flows.insert(id, entry.clone());
                    entry
                }
            };
            {
                let mut state = entry.lock();
                if sequence < state.next || state.pending.contains(&sequence) {
                    return Reply::Now(rpc_fault(1728));
                }
                state.pending.insert(sequence);
            }
            flow = Some(entry);
        }
        let call = Call { service, context, operation, arguments: bytes[64..].to_vec(), call_id, flow: flow.clone().map(|flow| (flow, sequence)) };
        let ready = flow.as_ref().is_none_or(|flow| flow.lock().next == sequence);
        if ready {
            return match call.dispatch() {
                Dispatched::Done(result) => Reply::Now(result),
                Dispatched::Pending(pending, call_id) => Reply::Later(Box::new(CallJob { call: None, sequence, flow, pending: Some((pending, call_id)) })),
            };
        }
        // A ordem de despacho é preservada mesmo quando o ALPC entrega antes
        // uma chamada posterior.
        Reply::Later(Box::new(CallJob { call: Some(call), sequence, flow, pending: None }))
    }

    fn bind(&self, port: &Arc<Port>, bytes: &[u8]) -> JobResult {
        if bytes.len() < 68 {
            return rpc_fault(1728);
        }
        let id: String = bytes[12..28].iter().map(|byte| alloc::format!("{byte:02x}")).collect();
        let version = read32(bytes, 28);
        let service = self.interfaces.get(&alloc::format!("{id}:{version}")).cloned();
        let mut result = alloc::vec![0u8; 72];
        let copied = bytes.len().min(72);
        result[..copied].copy_from_slice(&bytes[..copied]);
        let status: u32 = if service.is_none() { 1717 } else if read32(bytes, 32) & 1 == 0 { 1730 } else { 0 };
        crate::debug_print!("[lrpc] bind={} version={} status={}", id, version, status);
        result[8..12].copy_from_slice(&status.to_le_bytes());
        result[32..36].copy_from_slice(&(if status != 0 { 0u32 } else { 1 }).to_le_bytes());
        if let (0, Some(service)) = (status, service) {
            // O cliente atribui o id de sintaxe antes do Bind; o servidor o
            // indexa (LRPC_SASSOCIATION::AddBinding).
            let binding = u16::from_le_bytes([bytes[36], bytes[37]]) as u32;
            let mut connections = self.connections.lock();
            let Some(connection) = connections.get_mut(&port.pointer) else { return rpc_fault(1728) };
            if let Some(previous) = connection.bindings.get(&binding) {
                if !Arc::ptr_eq(previous, &service) {
                    return rpc_fault(1728);
                }
            }
            connection.bindings.insert(binding, service);
            result[36..38].copy_from_slice(&(binding as u16).to_le_bytes());
            result[38..40].copy_from_slice(&0u16.to_le_bytes());
            result[40..42].copy_from_slice(&0u16.to_le_bytes());
        }
        // Nenhum fluxo nem sintaxe de transferência extra negociados.
        result[44..48].fill(0);
        result[48..52].fill(0);
        result[56..64].fill(0);
        JobResult { status: 0, data: result, sender: None }
    }
}

impl Service for Endpoint {
    fn max_message_length(&self) -> u32 {
        0x1000
    }

    fn max_connection_info(&self) -> u32 {
        0x1000
    }

    fn connect(&self, port: &Arc<Port>, data: &[u8], _request: Option<&[u8]>) -> Reply {
        let process_id = if port.process_pointer != 0 { guest::read64(port.process_pointer + eprocess::UNIQUE_PROCESS_ID) } else { 0 };
        let token = port.token();
        self.connections.lock().insert(port.pointer, Connection { bindings: BTreeMap::new(), flows: BTreeMap::new(), context: RpcContext { process_id, token } });
        if data.is_empty() {
            Reply::Now(JobResult { status: 0, data: Vec::new(), sender: None })
        } else {
            self.exchange_bytes(port, data)
        }
    }

    fn exchange(&self, port: &Arc<Port>, data: &[u8], _request: &Arc<Request>) -> Reply {
        self.exchange_bytes(port, data)
    }

    fn disconnect(&self, port: &Arc<Port>) {
        let connection = self.connections.lock().remove(&port.pointer);
        if let Some(connection) = connection {
            let mut seen: Vec<Arc<dyn Interface>> = Vec::new();
            for service in connection.bindings.into_values() {
                if !seen.iter().any(|candidate| Arc::ptr_eq(candidate, &service)) {
                    service.disconnect(&connection.context);
                    seen.push(service);
                }
            }
        }
    }
}
