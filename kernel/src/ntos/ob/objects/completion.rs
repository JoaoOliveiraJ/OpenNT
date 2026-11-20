//! Portas de conclusão de E/S.
//!
//! O corpo do IoCompletion é uma KQUEUE (0x40), como no 19041: o
//! DISPATCHER_HEADER (Type QueueObject, SignalState = pacotes na fila), o
//! CurrentCount (consumidores ativos) e o MaximumCount (a concorrência).
//! Uma thread de kernel espera a porta direto no KeWaitForMultipleObjects (o
//! win32k espera assim a porta da fila de mensagens de cada thread): a fila
//! com pacotes satisfaz a espera sem consumir, e a fila que ganha pacotes
//! testa as esperas registradas no cabeçalho. Os pacotes, as threads
//! associadas e os consumidores da retirada ficam nas coleções do kernel; a
//! EntryListHead e a ThreadListHead seguem vazias. As threads são
//! identificadas pelo ETHREAD; a elegibilidade (morta ou suspensa) vem do
//! gancho instalado por `ps/user/threads`.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ntos::ke::{queue as ke_queue, wait as ke_wait};
use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{IoMiniCompletionPacketUser, Kqueue};
use crate::ntos::mm::guest_memory as guest;

pub const SIZE: u64 = Kqueue::SIZE;

/// Pacote de conclusão: valores próprios ou lidos do pacote nativo.
#[derive(Default)]
pub struct Packet {
    pub key: u64,
    pub context: u64,
    pub status: u32,
    pub information: u64,
    /// Pacote de memória (IoSetIoCompletionEx): os campos são lidos dele.
    pub native_pointer: u64,
    /// Identidade do item na fila: o corpo do pacote de espera que o
    /// publicou.
    pub tag: u64,
    pub on_dequeue: Option<Box<dyn FnOnce() + Send>>,
}

impl Packet {
    /// (key, context, status, information).
    pub fn values(&self) -> (u64, u64, u32, u64) {
        if self.native_pointer != 0 {
            // SAFETY: pacote de memória em custódia da fila até a retirada.
            let packet = unsafe { IoMiniCompletionPacketUser::at(self.native_pointer) };
            (packet.key_context.get(), packet.apc_context.get(), packet.io_status.get() as u32, packet.io_status_information.get())
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
    /// Fechada pelo último handle ou pelo fim do objeto.
    closed: AtomicBool,
    state: SpinLock<PortState>,
    /// Observadores de cada enfileiramento (pacotes de espera).
    pub listeners: SpinLock<Vec<Arc<dyn Fn() + Send + Sync>>>,
}

impl Port {
    fn queue(&self) -> &'static Kqueue {
        // SAFETY: corpo alocado por `create`, liberado só no `dispose`.
        unsafe { Kqueue::at(self.pointer) }
    }

    pub fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Marca a porta fechada; devolve se ela já estava fechada.
    fn mark_closed(&self) -> bool {
        self.closed.swap(true, Ordering::AcqRel)
    }

    /// A concorrência: o MaximumCount da KQUEUE.
    pub fn concurrency(&self) -> u32 {
        self.queue().maximum_count.get()
    }

    /// Troca o MaximumCount da KQUEUE (a classe 8 do
    /// NtSetInformationWorkerFactory); os consumidores esperando veem o
    /// limite novo na próxima sondagem.
    pub fn set_concurrency(&self, value: u32) {
        self.queue().maximum_count.set(value);
    }

    /// Altera as coleções e publica na KQUEUE os pacotes (SignalState) e os
    /// consumidores ativos (CurrentCount). A fila que ganhou pacotes testa
    /// as esperas do cabeçalho (o KiWaitTest), fora do lock da porta. Com
    /// pacotes na fila e vaga de concorrência, uma vaga liberada ou um
    /// consumidor que saiu também acordam as esperas de usuário paradas na
    /// fila (blocos de notificação, que sondam a retirada): a vez pode ter
    /// passado a uma delas.
    pub fn with<R>(&self, body: impl FnOnce(&mut PortState) -> R) -> R {
        let (result, grew, opened) = {
            let mut state = self.state.lock();
            let (active, waiters) = (state.active.len(), state.waiters.len());
            let result = body(&mut state);
            let queue = self.queue();
            let depth = state.packets.len() as i32;
            let previous = queue.header.signal_state.atomic().swap(depth, Ordering::SeqCst);
            queue.current_count.set(state.active.len() as u32);
            let room = depth > 0 && (state.active.len() as u32) < queue.maximum_count.get();
            (result, depth > previous, room && (state.active.len() < active || state.waiters.len() < waiters))
        };
        if grew {
            ke_wait::signal(self.pointer);
        } else if opened {
            ke_wait::retest(self.pointer);
        }
        result
    }

    /// Lê as coleções sem publicar nada na KQUEUE nem testar esperas (o
    /// depurador do kernel, com a máquina parada).
    pub fn inspect<R>(&self, body: impl FnOnce(&PortState) -> R) -> R {
        body(&self.state.lock())
    }
}

static PORTS: SpinLock<BTreeMap<u64, Arc<Port>>> = SpinLock::new(BTreeMap::new());
/// Porta de conclusão associada a cada thread.
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
            // Os pacotes foram entregues à espera: a thread de kernel parada
            // na retirada volta à fila (a de usuário é sondada).
            if let Some(thread) = waiter.thread {
                crate::ntos::ke::wait::wake(thread);
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
    if port.mark_closed() {
        return;
    }
    // As esperas paradas na fila veem a porta fechada (STATUS_ABANDONED).
    ke_wait::retest(port.pointer);
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
    // SAFETY: alocação nova do tamanho da KQUEUE.
    ke_queue::initialize(unsafe { Kqueue::at(pointer) }, concurrency);
    let port = Arc::new(Port { pointer, name: SpinLock::new(String::from(name)), node: SpinLock::new(None), exclusive_process: AtomicU64::new(0), notifying: AtomicBool::new(false), closed: AtomicBool::new(false), state: SpinLock::new(PortState { packets: VecDeque::new(), active: BTreeSet::new(), waiters: Vec::new(), associated: BTreeSet::new() }), listeners: SpinLock::new(Vec::new()) });
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
    crate::ntos::ke::dispatcher::note_wake();
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
