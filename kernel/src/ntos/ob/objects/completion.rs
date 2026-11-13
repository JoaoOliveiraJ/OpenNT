//! Portas de conclusão de E/S — `system32/ntos/ob/completion-objects.js`.
//!
//! Cada porta tem sua fila de pacotes, as threads associadas e o limite de
//! concorrência. O corpo privado de 0x40 bytes espelha os contadores (refs
//! +0, handles +8, fechada +0x10, concorrência +0x14, pacotes +0x18, ativas
//! +0x1c, esperas +0x20); pacotes e esperas ficam nas coleções do kernel.
//! As threads são identificadas pelo ETHREAD; a elegibilidade (morta ou
//! suspensa) vem do gancho instalado por `ps/user/threads`.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const SIZE: u64 = 0x40;

/// Pacote de conclusão: valores próprios ou lidos do pacote nativo.
#[derive(Default)]
pub struct Packet {
    pub key: u64,
    pub context: u64,
    pub status: u32,
    pub information: u64,
    /// Pacote de memória (IoSetIoCompletionEx): os campos são lidos dele.
    pub native_pointer: u64,
    /// Identidade do item (`port.packets.indexOf(item)`): o corpo do pacote
    /// de espera que o publicou.
    pub tag: u64,
    pub on_dequeue: Option<Box<dyn FnOnce() + Send>>,
}

impl Packet {
    /// (key, context, status, information).
    pub fn values(&self) -> (u64, u64, u32, u64) {
        if self.native_pointer != 0 {
            let pointer = self.native_pointer;
            (guest::read64(pointer + 0x18), guest::read64(pointer + 0x20), guest::read32(pointer + 0x28), guest::read64(pointer + 0x30))
        } else {
            (self.key, self.context, self.status, self.information)
        }
    }
}

/// Consumidor esperando: a thread, se ainda espera, e a reserva dos pacotes.
pub struct Waiter {
    pub thread: Option<u64>,
    pub waiting: Option<Box<dyn Fn() -> bool + Send + Sync>>,
    pub reserve: Option<Box<dyn Fn() -> bool + Send + Sync>>,
}

pub struct PortState {
    pub packets: VecDeque<Packet>,
    pub active: BTreeSet<u64>,
    pub waiters: Vec<Arc<Waiter>>,
    pub associated: BTreeSet<u64>,
}

pub struct Port {
    pub pointer: u64,
    pub name: SpinLock<String>,
    pub node: SpinLock<Option<NodeId>>,
    pub exclusive_process: AtomicU64,
    notifying: AtomicBool,
    state: SpinLock<PortState>,
    /// Observadores de cada enfileiramento (pacotes de espera).
    pub listeners: SpinLock<Vec<Arc<dyn Fn() + Send + Sync>>>,
}

impl Port {
    pub fn closed(&self) -> bool {
        guest::read32(self.pointer + 0x10) != 0
    }

    fn set_closed(&self) {
        guest::write32(self.pointer + 0x10, 1);
    }

    pub fn concurrency(&self) -> u32 {
        guest::read32(self.pointer + 0x14)
    }

    /// Altera as coleções e publica os contadores no corpo nativo.
    pub fn with<R>(&self, body: impl FnOnce(&mut PortState) -> R) -> R {
        let mut state = self.state.lock();
        let result = body(&mut state);
        guest::write32(self.pointer + 0x18, state.packets.len() as u32);
        guest::write32(self.pointer + 0x1C, state.active.len() as u32);
        guest::write32(self.pointer + 0x20, state.waiters.len() as u32);
        result
    }
}

static PORTS: SpinLock<BTreeMap<u64, Arc<Port>>> = SpinLock::new(BTreeMap::new());
/// `thread.ioCompletionPort`.
static THREAD_PORT: SpinLock<BTreeMap<u64, Arc<Port>>> = SpinLock::new(BTreeMap::new());
/// Thread elegível (nem morta nem suspensa), instalado por `ps/user/threads`.
static THREAD_ELIGIBLE: SpinLock<Option<fn(u64) -> bool>> = SpinLock::new(None);

pub fn set_thread_eligibility(check: fn(u64) -> bool) {
    *THREAD_ELIGIBLE.lock() = Some(check);
}

pub fn thread_eligible(thread: u64) -> bool {
    eligible(thread)
}

fn eligible(thread: u64) -> bool {
    let check = *THREAD_ELIGIBLE.lock();
    check.is_none_or(|check| check(thread))
}

pub fn port_of(pointer: u64) -> Option<Arc<Port>> {
    PORTS.lock().get(&pointer).cloned()
}

/// Entrega primeiro ao último consumidor esperando, respeitando a
/// concorrência; cada continuação reserva seus pacotes.
pub fn notify(port: &Port) {
    if port.notifying.swap(true, Ordering::AcqRel) {
        return;
    }
    if !port.closed() {
        let waiters = port.with(|state| state.waiters.clone());
        for waiter in waiters.iter().rev() {
            let (empty, saturated) = port.with(|state| (state.packets.is_empty(), state.active.len() as u32 >= port.concurrency()));
            if empty || saturated {
                break;
            }
            if waiter.thread.is_some_and(|thread| !eligible(thread)) {
                continue;
            }
            if waiter.waiting.as_ref().is_some_and(|waiting| !waiting()) {
                continue;
            }
            if !waiter.reserve.as_ref().is_some_and(|reserve| reserve()) {
                break;
            }
        }
    }
    port.notifying.store(false, Ordering::Release);
}

/// Retira a thread da porta e solta a referência da associação.
pub fn dissociate(thread: u64) {
    let Some(port) = THREAD_PORT.lock().remove(&thread) else { return };
    let removed = port.with(|state| {
        state.active.remove(&thread);
        state.associated.remove(&thread)
    });
    if removed {
        notify(&port);
        let _ = dispatcher_objects::dereference(port.pointer);
    }
}

/// Transfere a thread para a porta; uma associação existente só deixa de
/// contar como ativa.
pub fn associate(thread: u64, port: &Arc<Port>) {
    let current = THREAD_PORT.lock().get(&thread).cloned();
    if current.as_ref().is_some_and(|current| Arc::ptr_eq(current, port)) {
        port.with(|state| state.active.remove(&thread));
        return;
    }
    dissociate(thread);
    let _ = dispatcher_objects::reference(port.pointer);
    port.with(|state| state.associated.insert(thread));
    THREAD_PORT.lock().insert(thread, port.clone());
}

/// A espera terminou: a thread associada volta a contar como ativa.
pub fn activate(thread: u64) {
    let port = THREAD_PORT.lock().get(&thread).cloned();
    if let Some(port) = port.filter(|port| !port.closed()) {
        port.with(|state| state.active.insert(thread));
    }
}

/// A thread bloqueou: deixa de contar como ativa e libera consumidores.
pub fn deactivate(thread: u64) {
    let port = THREAD_PORT.lock().get(&thread).cloned();
    if let Some(port) = port {
        port.with(|state| state.active.remove(&thread));
        notify(&port);
    }
}

/// Fecha: remove o nome, drena os pacotes e desfaz as associações.
pub fn close_port(port: &Port) {
    if port.closed() {
        return;
    }
    port.set_closed();
    if let Some(node) = port.node.lock().take() {
        object_manager::remove_named(node);
    }
    let packets: Vec<Packet> = port.with(|state| state.packets.drain(..).collect());
    for packet in packets {
        if let Some(on_dequeue) = packet.on_dequeue {
            on_dequeue();
        }
    }
    let associated: Vec<u64> = port.with(|state| state.associated.iter().copied().collect());
    for thread in associated {
        dissociate(thread);
    }
    port.with(|state| state.active.clear());
}

fn dispose(pointer: u64) {
    if let Some(port) = port_of(pointer) {
        close_port(&port);
    }
    PORTS.lock().remove(&pointer);
    guest::free_bytes(pointer);
}

fn before_handle_open(pointer: u64) -> Result<(), KernelError> {
    if port_of(pointer).is_some_and(|port| port.closed()) {
        return Err(KernelError::with_status("completion port is being deleted", 0xC000_0056));
    }
    Ok(())
}

fn on_last_handle_close(pointer: u64) {
    if let Some(port) = port_of(pointer) {
        close_port(&port);
    }
}

/// Aloca e inicializa o corpo e registra o nome opcional; falhas desfazem
/// a posse antes de liberar a memória.
pub fn create(name: &str, concurrency: u32, attributes: u64, from_user_mode: bool) -> Result<Arc<Port>, KernelError> {
    let pointer = guest::alloc_bytes(SIZE);
    if pointer == 0 {
        return Err(KernelError::with_status("completion body allocation failed", 0xC000_009A));
    }
    for offset in (0..SIZE).step_by(8) {
        guest::write64(pointer + offset, 0);
    }
    guest::write32(pointer + 0x14, concurrency);
    let port = Arc::new(Port { pointer, name: SpinLock::new(String::from(name)), node: SpinLock::new(None), exclusive_process: AtomicU64::new(0), notifying: AtomicBool::new(false), state: SpinLock::new(PortState { packets: VecDeque::new(), active: BTreeSet::new(), waiters: Vec::new(), associated: BTreeSet::new() }), listeners: SpinLock::new(Vec::new()) });
    if let Err(error) = dispatcher_objects::create(pointer, "completion", dispose, None, attributes, from_user_mode, DispatcherHooks { before_handle_open: Some(before_handle_open), on_last_handle_close: Some(on_last_handle_close) }) {
        guest::free_bytes(pointer);
        return Err(error);
    }
    PORTS.lock().insert(pointer, port.clone());
    if !name.is_empty() {
        let cut = name.rfind('\\').unwrap_or(0);
        let parent = if cut == 0 { String::from("\\") } else { String::from(&name[..cut]) };
        match object_manager::create_object(&parent, &name[cut + 1..], "IoCompletion", Some(dispatcher_objects::data(pointer))) {
            Ok(node) => *port.node.lock() = Some(node),
            Err(error) => {
                dispatcher_objects::collect(pointer);
                return Err(error);
            }
        }
    }
    Ok(port)
}

/// Handle de usuário após a checagem de acesso, com a mesma identidade.
pub fn publish(port: &Arc<Port>, output: u64, access: u32, attributes: u32, success: u32, creating: bool) -> Result<u32, KernelError> {
    dispatcher_objects::publish(port.pointer, output, access, attributes, success, creating, Some(port.clone()))
}

/// Enfileira (FIFO) e entrega aos consumidores e observadores.
pub fn enqueue(port: &Port, packet: Packet) {
    port.with(|state| state.packets.push_back(packet));
    notify(port);
    let listeners = port.listeners.lock().clone();
    for listener in listeners {
        listener();
    }
}

/// A saída da thread desfaz a associação que ainda retém uma porta.
fn thread_exit(thread: u64) {
    dissociate(thread);
}

pub fn init() {
    process::register_thread_exit_routine(thread_exit);
}
