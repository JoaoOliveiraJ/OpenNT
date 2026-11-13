//! Associações de espera e fábricas de workers.
//!
//! Corpos privados com retenção compartilhada pelos handles. O pacote de
//! espera ocupa 0x50 bytes: refs +0, handles +8, fechado +0xC, fase +0x10
//! (1 associado, 2 enfileirado), porta +0x18, alvo +0x20, chave +0x28,
//! contexto +0x30, status +0x38 e informação +0x40. A fábrica de workers
//! (0xA0 bytes) entra com `ps/user/worker_factory`.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::ntos::ob::objects::completion::Port;
use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks};
use crate::ntos::ps::user::state::UserHandle;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const PACKET_SIZE: u64 = 0x50;
pub const FACTORY_SIZE: u64 = 0xA0;

/// Fase associada: a porta e o alvo retidos pelos handles.
#[derive(Clone)]
pub struct Association {
    pub port_entry: Arc<UserHandle>,
    pub port: Arc<Port>,
    pub target: Arc<UserHandle>,
    pub target_pointer: u64,
}

/// Fase enfileirada: a porta que possui o pacote até a retirada.
#[derive(Clone)]
pub struct Queued {
    pub port: Arc<Port>,
}

#[derive(Default)]
struct Phases {
    association: Option<Association>,
    queued: Option<Queued>,
}

pub struct WaitPacket {
    pub pointer: u64,
    phases: SpinLock<Phases>,
    detach: fn(&Arc<WaitPacket>, bool) -> u32,
}

impl WaitPacket {
    fn phase(&self) -> u32 {
        guest::read32(self.pointer + 0x10)
    }

    pub fn association(&self) -> Option<Association> {
        if self.phase() != 1 {
            return None;
        }
        self.phases.lock().association.clone()
    }

    pub fn set_association(&self, value: Option<Association>) {
        guest::write32(self.pointer + 0x10, value.is_some() as u32);
        guest::write64(self.pointer + 0x18, value.as_ref().map_or(0, |value| value.port.pointer));
        guest::write64(self.pointer + 0x20, value.as_ref().map_or(0, |value| value.target_pointer));
        self.phases.lock().association = value;
    }

    pub fn queued(&self) -> Option<Queued> {
        if self.phase() != 2 {
            return None;
        }
        self.phases.lock().queued.clone()
    }

    pub fn set_queued(&self, value: Option<Queued>) {
        guest::write32(self.pointer + 0x10, if value.is_some() { 2 } else { 0 });
        guest::write64(self.pointer + 0x18, value.as_ref().map_or(0, |value| value.port.pointer));
        guest::write64(self.pointer + 0x20, 0);
        self.phases.lock().queued = value;
    }

    pub fn closed(&self) -> bool {
        guest::read32(self.pointer + 0xC) != 0
    }

    pub fn key(&self) -> u64 {
        guest::read64(self.pointer + 0x28)
    }

    pub fn context(&self) -> u64 {
        guest::read64(self.pointer + 0x30)
    }

    pub fn status(&self) -> u32 {
        guest::read32(self.pointer + 0x38)
    }

    pub fn information(&self) -> u64 {
        guest::read64(self.pointer + 0x40)
    }

    /// Dados de conclusão em duas palavras cada, como a ABI os entrega.
    pub fn set_completion(&self, key: [u32; 2], context: [u32; 2], status: u32, information: [u32; 2]) {
        for (offset, words) in [(0x28, key), (0x30, context), (0x40, information)] {
            guest::write32(self.pointer + offset, words[0]);
            guest::write32(self.pointer + offset + 4, words[1]);
        }
        guest::write32(self.pointer + 0x38, status);
    }
}

static PACKETS: SpinLock<BTreeMap<u64, Arc<WaitPacket>>> = SpinLock::new(BTreeMap::new());

pub fn packet_of(pointer: u64) -> Option<Arc<WaitPacket>> {
    PACKETS.lock().get(&pointer).cloned()
}

fn status_error(status: u32) -> KernelError {
    KernelError::with_status("work object status", status)
}

/// Corpo zerado; aberturas novas são recusadas depois do encerramento.
fn allocate_body(size: u64) -> Result<u64, KernelError> {
    let pointer = guest::alloc_bytes(size);
    if pointer == 0 {
        return Err(status_error(0xC000_009A));
    }
    for offset in (0..size).step_by(8) {
        guest::write64(pointer + offset, 0);
    }
    Ok(pointer)
}

fn before_handle_open(pointer: u64) -> Result<(), KernelError> {
    if guest::read32(pointer + 0xC) != 0 {
        return Err(status_error(0xC000_0056));
    }
    Ok(())
}

/// O último handle desfaz a associação.
fn packet_last_handle_close(pointer: u64) {
    guest::write32(pointer + 0xC, 1);
    if let Some(packet) = packet_of(pointer) {
        (packet.detach)(&packet, true);
    }
}

/// A destruição libera a memória após a última referência.
fn packet_dispose(pointer: u64) {
    if let Some(packet) = packet_of(pointer) {
        (packet.detach)(&packet, true);
    }
    PACKETS.lock().remove(&pointer);
    guest::free_bytes(pointer);
}

/// Pacote com as fases de associação e enfileiramento.
pub fn packet(attributes: u64, detach: fn(&Arc<WaitPacket>, bool) -> u32) -> Result<Arc<WaitPacket>, KernelError> {
    let pointer = allocate_body(PACKET_SIZE)?;
    let packet = Arc::new(WaitPacket { pointer, phases: SpinLock::new(Phases::default()), detach });
    PACKETS.lock().insert(pointer, packet.clone());
    if let Err(error) = dispatcher_objects::create(pointer, "waitpacket", packet_dispose, None, attributes, true, DispatcherHooks { before_handle_open: Some(before_handle_open), on_last_handle_close: Some(packet_last_handle_close) }) {
        PACKETS.lock().remove(&pointer);
        guest::free_bytes(pointer);
        return Err(error);
    }
    Ok(packet)
}

/// Handle com a política de acesso e os atributos de OBJECT_ATTRIBUTES.
pub fn publish(pointer: u64, output: u64, access: u32, attributes: u64, payload: Arc<dyn core::any::Any + Send + Sync>) -> Result<u32, KernelError> {
    dispatcher_objects::publish(pointer, output, access, if attributes != 0 { guest::read32(attributes + 24) } else { 0 }, 0, false, Some(payload))
}

macro_rules! field32 {
    ($get:ident, $set:ident, $offset:expr) => {
        pub fn $get(&self) -> u32 {
            guest::read32(self.pointer + $offset)
        }
        pub fn $set(&self, value: u32) {
            guest::write32(self.pointer + $offset, value);
        }
    };
}

macro_rules! field64 {
    ($get:ident, $set:ident, $offset:expr, $kind:ty) => {
        pub fn $get(&self) -> $kind {
            guest::read64(self.pointer + $offset) as $kind
        }
        pub fn $set(&self, value: $kind) {
            guest::write64(self.pointer + $offset, value as u64);
        }
    };
}

macro_rules! flag {
    ($get:ident, $set:ident, $offset:expr) => {
        pub fn $get(&self) -> bool {
            guest::read32(self.pointer + $offset) != 0
        }
        pub fn $set(&self, value: bool) {
            guest::write32(self.pointer + $offset, value as u32);
        }
    };
}

/// Fábrica de workers: configuração, contadores e prazos no corpo de 0xA0
/// bytes (prioridade +0x10, máximo +0x14, mínimo +0x18, pausada +0x1C,
/// encerrada +0x20, criando +0x24, vínculos +0x28, liberações +0x2C, último
/// status +0x30, workers +0x34, porta +0x38, processo +0x40, PID +0x48,
/// início +0x50, parâmetro +0x58, reserva +0x60, commit +0x68, timeouts
/// +0x70/+0x78/+0x80, nova tentativa +0x88, limite flexível +0x90, fase
/// flexível +0x94 e LoaderWorker +0x98).
pub struct Factory {
    pub pointer: u64,
    pub port_entry: Arc<UserHandle>,
    pub port: Arc<Port>,
    workers: SpinLock<alloc::vec::Vec<Arc<crate::ntos::ps::user::threads::UserThread>>>,
    pub on_queued: SpinLock<Option<Arc<dyn Fn() + Send + Sync>>>,
    dispose: fn(&Arc<Factory>),
    last_close: fn(&Arc<Factory>),
}

impl Factory {
    field32!(priority, set_priority, 0x10);
    field32!(maximum, set_maximum, 0x14);
    field32!(minimum, set_minimum, 0x18);
    field32!(binding_count, set_binding_count, 0x28);
    field32!(release_count, set_release_count, 0x2C);
    field32!(last_status, set_last_status, 0x30);
    field32!(soft_maximum, set_soft_maximum, 0x90);
    field32!(soft_creation_phase, set_soft_creation_phase, 0x94);
    field64!(process_pointer, set_process_pointer, 0x40, u64);
    field64!(process_id, set_process_id, 0x48, u64);
    field64!(start, set_start, 0x50, u64);
    field64!(parameter, set_parameter, 0x58, u64);
    field64!(reserve, set_reserve, 0x60, u64);
    field64!(commit, set_commit, 0x68, u64);
    field64!(timeout, set_timeout, 0x70, i64);
    field64!(retry_timeout, set_retry_timeout, 0x78, i64);
    field64!(idle_timeout, set_idle_timeout, 0x80, i64);
    field64!(retry_at, set_retry_at, 0x88, i64);
    flag!(paused, set_paused, 0x1C);
    flag!(shutdown, set_shutdown, 0x20);
    flag!(creating, set_creating, 0x24);
    flag!(loader_worker, set_loader_worker, 0x98);
    flag!(closed, set_closed, 0xC);

    pub fn workers(&self) -> alloc::vec::Vec<Arc<crate::ntos::ps::user::threads::UserThread>> {
        self.workers.lock().clone()
    }

    /// Inserções e remoções atualizam o contador nativo em +0x34.
    pub fn add_worker(&self, thread: Arc<crate::ntos::ps::user::threads::UserThread>) {
        let mut workers = self.workers.lock();
        if !workers.iter().any(|candidate| Arc::ptr_eq(candidate, &thread)) {
            workers.push(thread);
        }
        guest::write32(self.pointer + 0x34, workers.len() as u32);
    }

    pub fn remove_worker(&self, thread: &Arc<crate::ntos::ps::user::threads::UserThread>) -> bool {
        let mut workers = self.workers.lock();
        let before = workers.len();
        workers.retain(|candidate| !Arc::ptr_eq(candidate, thread));
        guest::write32(self.pointer + 0x34, workers.len() as u32);
        workers.len() != before
    }
}

/// Configuração inicial da fábrica.
pub struct FactoryInitial {
    pub port_entry: Arc<UserHandle>,
    pub port: Arc<Port>,
    pub start: u64,
    pub parameter: u64,
    pub process_pointer: u64,
    pub process_id: u64,
    pub maximum: u32,
    pub reserve: u64,
    pub commit: u64,
}

static FACTORIES: SpinLock<BTreeMap<u64, Arc<Factory>>> = SpinLock::new(BTreeMap::new());

pub fn factory_of(pointer: u64) -> Option<Arc<Factory>> {
    FACTORIES.lock().get(&pointer).cloned()
}

fn factory_last_handle_close(pointer: u64) {
    if let Some(factory) = factory_of(pointer) {
        (factory.last_close)(&factory);
    }
}

/// A liberação final chama `dispose` antes de soltar o corpo.
fn factory_dispose(pointer: u64) {
    if let Some(factory) = FACTORIES.lock().remove(&pointer) {
        (factory.dispose)(&factory);
    }
    guest::free_bytes(pointer);
}

/// Parâmetros, temporizadores e conjunto de workers da fábrica.
pub fn factory(initial: FactoryInitial, attributes: u64, dispose: fn(&Arc<Factory>), last_close: fn(&Arc<Factory>)) -> Result<Arc<Factory>, KernelError> {
    let pointer = allocate_body(FACTORY_SIZE)?;
    let factory = Arc::new(Factory { pointer, port_entry: initial.port_entry, port: initial.port, workers: SpinLock::new(alloc::vec::Vec::new()), on_queued: SpinLock::new(None), dispose, last_close });
    factory.set_start(initial.start);
    factory.set_parameter(initial.parameter);
    factory.set_process_pointer(initial.process_pointer);
    factory.set_process_id(initial.process_id);
    factory.set_maximum(initial.maximum);
    factory.set_reserve(initial.reserve);
    factory.set_commit(initial.commit);
    factory.set_priority(8);
    factory.set_timeout(-100_000_000);
    factory.set_retry_timeout(-10_000_000);
    factory.set_idle_timeout(-100_000_000);
    guest::write64(pointer + 0x38, factory.port.pointer);
    FACTORIES.lock().insert(pointer, factory.clone());
    if let Err(error) = dispatcher_objects::create(pointer, "workerfactory", factory_dispose, None, attributes, true, DispatcherHooks { before_handle_open: Some(before_handle_open), on_last_handle_close: Some(factory_last_handle_close) }) {
        FACTORIES.lock().remove(&pointer);
        guest::free_bytes(pointer);
        return Err(error);
    }
    Ok(factory)
}
