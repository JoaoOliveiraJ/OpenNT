//! Conexões LPC/ALPC.
//!
//! O corpo privado de 0x80 bytes espelha contadores e estado (refs +0,
//! handles +8, fechada +0xC, processo +0x10, PID +0x18, TID +0x20, máximo
//! +0x28, sequência +0x2C, pendentes +0x30, jobs +0x34, bytes reservados
//! +0x38, reservas +0x3C, vistas +0x40, operações +0x44, conclusão +0x48,
//! token +0x50, duas bases de vista +0x58/+0x60, iniciada +0x68, limpa +0x6C
//! e chave de conclusão +0x70). A desconexão conserva filas e recursos; a
//! limpeza final exige fechamento e o fim das operações.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks, UserDispatcher};
use crate::ntos::ob::object_access;
use crate::ntos::ob::object_manager::NodeId;
use crate::ntos::alpc::port_sections::{self, SectionRecord};
use crate::ntos::alpc::resource::handles::{Communication, ResourceTable};
use crate::ntos::alpc::resource::reserves::{self as resource_reserves, Reserve};
use crate::ntos::alpc::section_views::{self, ViewBinding};
use crate::ntos::alpc::security_contexts::{self, ClientIdentity, ContextRecord, Quality};
use crate::ntos::alpc::transport::{Message, Request, Service};
use crate::ntos::ps::process;
use crate::ntos::ps::user::state;
use crate::ntos::se::token::tokens;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::Eprocess;
use crate::ntos::mm::guest_memory as guest;

/// Corpo privado da conexão LPC/ALPC (layout do OpenNT; o NT usa
/// ALPC_PORT). Contadores das coleções espelhados sob o estado da porta.
#[repr(C)]
struct PortBody {
    references: Field<u64>,
    handles: Field<u32>,
    closed: Field<u32>,
    process: Field<u64>,
    process_id: Field<u64>,
    thread_id: Field<u64>,
    maximum: Field<u32>,
    sequence: Field<u32>,
    pending: Field<u32>,
    jobs: Field<u32>,
    reserve_bytes: Field<u32>,
    reserves: Field<u32>,
    views: Field<u32>,
    operations: Field<u32>,
    completion_port: Field<u64>,
    token: Field<u64>,
    view_bases: [Field<u64>; 2],
    started: Field<u32>,
    cleaned: Field<u32>,
    completion_key: Field<u64>,
    _reserved: Reserved<8>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PortBody {}

const _: () = {
    assert!(core::mem::size_of::<PortBody>() == 0x80);
    assert!(core::mem::offset_of!(PortBody, closed) == 0xC);
    assert!(core::mem::offset_of!(PortBody, maximum) == 0x28);
    assert!(core::mem::offset_of!(PortBody, operations) == 0x44);
    assert!(core::mem::offset_of!(PortBody, view_bases) == 0x58);
    assert!(core::mem::offset_of!(PortBody, completion_key) == 0x70);
};

pub const SIZE: u64 = PortBody::SIZE;

fn port_body(pointer: u64) -> &'static PortBody {
    // SAFETY: corpos alocados por `create`, liberados só no `dispose`.
    unsafe { PortBody::at(pointer) }
}

/// Estados da conexão de um cliente; zero = sem conexão pendente.
pub const CONNECTION_PENDING: u32 = 1;
pub const CONNECTION_REFUSED: u32 = 2;
pub const CONNECTION_CONNECTED: u32 = 3;
pub const CONNECTION_CANCELED: u32 = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Role {
    #[default]
    None,
    Listener,
    Client,
    Server,
}

/// Associação de conclusão da porta (`alpc/completion_association`).
pub trait PortCompletion: Send + Sync {
    fn notify(&self);
    fn port_pointer(&self) -> u64;
    fn release(&self);
}

#[derive(Default)]
pub struct PortState {
    pub role: Role,
    pub communication: Option<Arc<Communication>>,
    pub connection_port: Option<Arc<Port>>,
    pub service: Option<Arc<dyn Service>>,
    pub service_process: u64,
    pub context: u64,
    pub port_context: u64,
    pub closing: bool,
    pub skip_pending_flush: bool,
    pub peer_disconnected: bool,
    pub server_references_held: bool,
    pub connection_state: u32,
    pub port_flags: u32,
    pub creation_flags: u32,
    pub security_quality: Option<Quality>,
    pub client_security: Option<Arc<ClientIdentity>>,
    pub maximum_view_size: u64,
    pub duplicate_object_types: u32,
    pub exclusive_process: u64,
    pub permanent: bool,
    pub message_sequence: u32,
    pub completion: Option<Arc<dyn PortCompletion>>,
    pub named_node: Option<NodeId>,
    pub transport_cleanup: bool,
    pub on_disconnect: Option<fn(&Arc<Port>, &Arc<Port>, bool)>,
    pub owned_sections: Vec<Arc<SectionRecord>>,
    pub owned_section_views: Vec<Arc<ViewBinding>>,
    pub owned_security_contexts: Vec<Arc<ContextRecord>>,
    pub pending: Vec<Message>,
    pub jobs: Vec<Arc<Request>>,
    pub reserves: BTreeMap<u32, Arc<Reserve>>,
    /// Vistas da seção de transferência LPC (local e supervisor).
    pub views: Vec<Arc<crate::ntos::ps::user::sections::View>>,
}

pub struct Port {
    pub pointer: u64,
    pub kind: &'static str,
    pub process_pointer: u64,
    /// Tabela de recursos própria (a comunicação do listener).
    pub own_resources: ResourceTable,
    state: SpinLock<PortState>,
    cleanup: Box<dyn Fn(&Arc<Port>) + Send + Sync>,
    token: SpinLock<u64>,
}

impl Port {
    /// Altera o estado e publica os contadores das coleções no corpo.
    fn body(&self) -> &'static PortBody {
        port_body(self.pointer)
    }
    pub fn with<R>(&self, body: impl FnOnce(&mut PortState) -> R) -> R {
        let mut state = self.state.lock();
        let result = body(&mut state);
        let mirror = self.body();
        mirror.pending.set(state.pending.len() as u32);
        mirror.jobs.set(state.jobs.len() as u32);
        mirror.reserves.set(state.reserves.len() as u32);
        mirror.views.set(state.views.len() as u32);
        mirror.view_bases[0].set(state.views.first().map_or(0, |view| view.base));
        mirror.view_bases[1].set(state.views.get(1).map_or(0, |view| view.base));
        mirror.completion_port.set(state.completion.as_ref().map_or(0, |completion| completion.port_pointer()));
        result
    }
    pub fn closed(&self) -> bool {
        self.body().closed.get() != 0
    }
    /// Marca a conexão fechada; devolve se ela já estava fechada.
    fn mark_closed(&self) -> bool {
        self.body().closed.atomic().swap(1, Ordering::AcqRel) != 0
    }
    pub fn handles(&self) -> u32 {
        dispatcher_objects::get(self.pointer).map_or(0, |(_, _, handles)| handles)
    }
    pub fn process_id(&self) -> u64 {
        self.body().process_id.get()
    }
    pub fn thread_id(&self) -> u64 {
        self.body().thread_id.get()
    }
    pub fn maximum(&self) -> u32 {
        self.body().maximum.get()
    }
    pub fn sequence(&self) -> u32 {
        self.body().sequence.get()
    }
    pub fn set_sequence(&self, sequence: u32) {
        self.body().sequence.set(sequence);
    }
    pub fn reserve_bytes(&self) -> u32 {
        self.body().reserve_bytes.get()
    }
    /// Soma atômica (as reservas são criadas e liberadas em paralelo).
    pub fn add_reserve_bytes(&self, delta: i64) {
        self.body().reserve_bytes.atomic().fetch_add(delta as u32, Ordering::SeqCst);
    }
    pub fn operations(&self) -> u32 {
        self.body().operations.get()
    }
    pub fn started(&self) -> bool {
        self.body().started.get() != 0
    }
    pub fn set_started(&self, started: bool) {
        self.body().started.set(started as u32);
    }
    pub fn completion_key(&self) -> u64 {
        self.body().completion_key.get()
    }
    pub fn set_completion_key(&self, key: u64) {
        self.body().completion_key.set(key);
    }
    pub fn token(&self) -> u64 {
        *self.token.lock()
    }

    fn cleanup_when_idle(self: &Arc<Self>) {
        let closing = self.with(|state| state.closing);
        if !self.closed() || (!closing && self.kind == "alpc") || self.operations() != 0 {
            return;
        }
        // Só a primeira thread que chega aqui executa a limpeza.
        if self.body().cleaned.atomic().swap(1, Ordering::AcqRel) != 0 {
            return;
        }
        (self.cleanup)(self);
    }

    /// Mesmo repetida, a chamada pode pedir que o fechamento preserve a fila
    /// pendente do par; o retorno repetido continua PORT_DISCONNECTED.
    pub fn disconnect(self: &Arc<Self>, flags: u32) -> u32 {
        if flags & 1 != 0 {
            self.with(|state| state.skip_pending_flush = true);
        }
        if self.mark_closed() {
            return 0xC000_0037;
        }
        notify_disconnect(self, false);
        self.cleanup_when_idle();
        0
    }

    pub fn on_last_handle_close(self: &Arc<Self>) {
        if self.with(|state| core::mem::replace(&mut state.closing, true)) {
            return;
        }
        self.disconnect(0);
        notify_disconnect(self, true);
        self.cleanup_when_idle();
        let _ = section_views::close_owner(self);
        let _ = port_sections::close_owner(self);
        let _ = security_contexts::close_owner(self);
        let _ = resource_reserves::close_owner(self);
    }

    /// Cada operação retém o corpo enquanto executa e reavalia a limpeza.
    pub fn run<R>(self: &Arc<Self>, body: impl FnOnce() -> R) -> R {
        let _ = dispatcher_objects::reference(self.pointer);
        let operations = self.body().operations.atomic();
        operations.fetch_add(1, Ordering::SeqCst);
        let result = body();
        let _ = operations.try_update(Ordering::SeqCst, Ordering::SeqCst, |count| Some(count.saturating_sub(1)));
        self.cleanup_when_idle();
        let _ = dispatcher_objects::dereference(self.pointer);
        result
    }
}

/// Conexões vivas, para desconectar donos em saída.
static PORTS: SpinLock<BTreeMap<u64, Arc<Port>>> = SpinLock::new(BTreeMap::new());

pub fn port_of(pointer: u64) -> Option<Arc<Port>> {
    PORTS.lock().get(&pointer).cloned()
}

pub fn all() -> Vec<Arc<Port>> {
    PORTS.lock().values().cloned().collect()
}

/// A desconexão é local ao endpoint mas altera mensagens da mesma
/// comunicação; retenções protegem os participantes durante os callbacks.
fn notify_disconnect(port: &Arc<Port>, closing: bool) {
    let communication = port.with(|state| state.communication.clone());
    let affected: Vec<(Arc<Port>, fn(&Arc<Port>, &Arc<Port>, bool))> = all()
        .into_iter()
        .filter_map(|candidate| {
            let (handler, same, connected) = candidate.with(|state| (state.on_disconnect, state.communication.as_ref().zip(communication.as_ref()).is_some_and(|(left, right)| Arc::ptr_eq(left, right)), state.connection_port.as_ref().is_some_and(|connection| Arc::ptr_eq(connection, port))));
            let handler = handler.filter(|_| dispatcher_objects::get(candidate.pointer).is_some())?;
            (Arc::ptr_eq(&candidate, port) || same || connected).then_some((candidate, handler))
        })
        .collect();
    for (candidate, _) in &affected {
        let _ = dispatcher_objects::reference(candidate.pointer);
    }
    for (candidate, handler) in &affected {
        handler(candidate, port, closing);
    }
    for (candidate, _) in &affected {
        let _ = dispatcher_objects::dereference(candidate.pointer);
    }
}

fn dispose(pointer: u64) {
    let Some(port) = port_of(pointer) else {
        guest::free_bytes(pointer);
        return;
    };
    port.with(|state| state.closing = true);
    port.disconnect(0);
    port.cleanup_when_idle();
    PORTS.lock().remove(&pointer);
    if let Some(completion) = port.with(|state| state.completion.take()) {
        completion.release();
    }
    let token = core::mem::replace(&mut *port.token.lock(), 0);
    if token != 0 {
        let _ = tokens::release(token);
        port_body(pointer).token.set(0);
    }
    let _ = process::dereference(port.process_pointer);
    guest::free_bytes(pointer);
}

fn before_handle_open(pointer: u64) -> Result<(), KernelError> {
    if port_of(pointer).is_some_and(|port| port.with(|state| state.closing)) {
        return Err(KernelError::with_status("port object status c0000056", 0xC000_0056));
    }
    Ok(())
}

fn on_last_handle_close(pointer: u64) {
    if let Some(port) = port_of(pointer) {
        port.on_last_handle_close();
    }
}

/// Opções de criação: dono (conexões de kernel atribuídas ao System), modo
/// de acesso e concessão na criação.
#[derive(Default)]
pub struct CreateOptions {
    pub owner_process: Option<u64>,
    pub kernel_mode: bool,
    pub grant_on_create: bool,
}

/// Aloca a conexão para o processo ativo, captura a segurança e retém
/// processo e token; o fechamento aguarda o fim das operações.
pub fn create(kind: &'static str, initial: PortState, maximum: u32, sequence: u32, attributes: u64, cleanup: Box<dyn Fn(&Arc<Port>) + Send + Sync>, options: CreateOptions) -> Result<Arc<Port>, KernelError> {
    let process_pointer = options.owner_process.unwrap_or_else(process::get_current_process);
    let usable = process::with_record(process_pointer, |record| !record.exiting && !record.terminated).unwrap_or(false);
    if !usable {
        return Err(KernelError::with_status("port object status c000010a", 0xC000_010A));
    }
    let pointer = guest::alloc_bytes(SIZE);
    if pointer == 0 {
        return Err(KernelError::with_status("port object status c000009a", 0xC000_009A));
    }
    // Alocação zerada: só a identidade e a configuração inicial.
    let body = port_body(pointer);
    body.process.set(process_pointer);
    // Uma conexão de kernel pode atribuir o corpo ao System; as demais
    // conservam a identidade do processo ativo.
    // SAFETY: EPROCESS do dono, com registro vivo (verificado acima).
    body.process_id.set(if options.owner_process.is_some() { unsafe { Eprocess::at(process_pointer) }.unique_process_id.get() } else { process::get_current_process_id() });
    body.thread_id.set(process::get_current_thread_id());
    body.maximum.set(maximum);
    body.sequence.set(sequence);
    let port = Arc::new(Port { pointer, kind, process_pointer, own_resources: crate::ntos::alpc::resource::handles::new_table(), state: SpinLock::new(initial), cleanup, token: SpinLock::new(0) });
    if let Err(error) = dispatcher_objects::create(pointer, kind, dispose, None, attributes, !options.kernel_mode, DispatcherHooks { before_handle_open: Some(before_handle_open), on_last_handle_close: Some(on_last_handle_close) }) {
        guest::free_bytes(pointer);
        return Err(error);
    }
    process::reference(process_pointer);
    PORTS.lock().insert(pointer, port.clone());
    let fail = |status: u32| {
        dispatcher_objects::collect(pointer);
        KernelError::with_status(alloc::format!("port object status {status:x}"), status)
    };
    let policy = dispatcher_objects::security(pointer).unwrap_or_default();
    let object_type = crate::ntos::ob::object_types::user_type(kind).ok_or_else(|| KernelError::new("ALPC Port type missing"))?;
    if let Err(status) = object_access::check(&policy, object_access::subject(), 0x1F_0001, &object_type, options.grant_on_create) {
        return Err(fail(status));
    }
    if kind == "alpc" {
        let Some(token) = process::get_primary_token(process_pointer) else { return Err(fail(0xC000_0022)) };
        tokens::retain(token)?;
        *port.token.lock() = token;
        port_body(pointer).token.set(token);
    }
    port.with(|_| ());
    Ok(port)
}

/// Handle de usuário com os direitos do tipo de porta.
pub fn publish(port: &Arc<Port>, output: u64, attributes: u32) -> Result<u32, KernelError> {
    dispatcher_objects::publish(port.pointer, output, 0x1F_0001, attributes, 0, false, Some(port.clone()))
}

/// O handle de quem acabou de criar a porta (NtAlpcCreatePort e
/// NtAlpcAcceptConnectPort): como no ObInsertObject, o criador recebe os
/// direitos do tipo sem a checagem pela DACL do descritor que ele deu.
pub fn publish_created(port: &Arc<Port>, output: u64, attributes: u32) -> Result<u32, KernelError> {
    dispatcher_objects::publish(port.pointer, output, 0x1F_0001, attributes, 0, true, Some(port.clone()))
}

/// Exige um handle de usuário do tipo pedido e devolve a conexão.
pub fn resolve(handle: u64, kind: &str) -> Option<(Arc<state::UserHandle>, Arc<Port>)> {
    let entry = state::get_user_handle(handle)?;
    if entry.kind() != kind {
        return None;
    }
    let port = entry.downcast::<UserDispatcher>().and_then(|dispatcher| port_of(dispatcher.pointer))?;
    Some((entry, port))
}

/// Processo do outro endpoint, retido: a porta de escuta referencia o
/// próprio dono; serviços hospedados no kernel informam o processo que
/// executa o serviço.
pub struct ConnectedProcess {
    pub process: u64,
    target: Option<Arc<Port>>,
    released: SpinLock<bool>,
}

impl ConnectedProcess {
    pub fn release(&self) -> Result<(), KernelError> {
        let mut released = self.released.lock();
        if *released {
            return Err(KernelError::new("ALPC connected process released twice"));
        }
        *released = true;
        let _ = process::dereference(self.process);
        if let Some(target) = &self.target {
            let _ = dispatcher_objects::dereference(target.pointer);
        }
        Ok(())
    }
}

pub fn reference_connected_process(port: &Arc<Port>) -> Result<Option<ConnectedProcess>, KernelError> {
    let (role, service_process, communication) = port.with(|state| (state.role, state.service_process, state.communication.clone()));
    let mut target: Option<Arc<Port>> = None;
    let mut process_pointer = 0;
    if role == Role::Listener {
        target = Some(port.clone());
    } else if service_process != 0 {
        process_pointer = service_process;
    } else if let (Some(communication), Role::Client | Role::Server) = (communication, role) {
        let other = if role == Role::Client { Role::Server } else { Role::Client };
        for candidate in all() {
            let matches = candidate.with(|state| state.role == other && state.communication.as_ref().is_some_and(|candidate| Arc::ptr_eq(candidate, &communication)));
            if matches && candidate.handles() != 0 {
                if target.is_some() {
                    return Err(KernelError::new("ALPC communication has multiple peer endpoints"));
                }
                target = Some(candidate);
            }
        }
    }
    if let Some(target) = &target {
        process_pointer = target.process_pointer;
    }
    let usable = process::with_record(process_pointer, |record| !record.exiting && !record.terminated).unwrap_or(false);
    if !usable {
        return Ok(None);
    }
    if let Some(target) = &target {
        let _ = dispatcher_objects::reference(target.pointer);
    }
    process::reference(process_pointer);
    Ok(Some(ConnectedProcess { process: process_pointer, target, released: SpinLock::new(false) }))
}

/// A saída do dono encerra o transporte mesmo que outro processo ainda
/// conserve handle ou referência ao corpo.
fn thread_exit(_thread: u64) {
    for port in all() {
        let ending = process::with_record(port.process_pointer, |record| record.exiting || record.terminated).unwrap_or(true);
        if ending {
            port.on_last_handle_close();
        }
    }
}

pub fn init() {
    process::register_thread_exit_routine(thread_exit);
}
