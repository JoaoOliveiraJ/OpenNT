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
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::ObjectAttributes;
use crate::ntos::mm::guest_memory as guest;

/// Início comum dos dois corpos: contagens espelhadas e o fechamento.
#[repr(C)]
struct BodyHeader {
    references: Field<u64>,
    handles: Field<u32>,
    closed: Field<u32>,
}

/// Corpo privado do pacote de espera (layout do OpenNT).
#[repr(C)]
struct WaitPacketBody {
    header: BodyHeader,
    phase: Field<u32>,
    _pad_14: Reserved<4>,
    port: Field<u64>,
    target: Field<u64>,
    key: Field<u64>,
    context: Field<u64>,
    status: Field<u32>,
    _pad_3c: Reserved<4>,
    information: Field<u64>,
    _reserved: Reserved<8>,
}

/// Corpo privado da fábrica de workers (layout do OpenNT).
#[repr(C)]
struct FactoryBody {
    header: BodyHeader,
    priority: Field<u32>,
    maximum: Field<u32>,
    minimum: Field<u32>,
    paused: Field<u32>,
    shutdown: Field<u32>,
    creating: Field<u32>,
    binding_count: Field<u32>,
    release_count: Field<u32>,
    last_status: Field<u32>,
    workers: Field<u32>,
    port: Field<u64>,
    process_pointer: Field<u64>,
    process_id: Field<u64>,
    start: Field<u64>,
    parameter: Field<u64>,
    reserve: Field<u64>,
    commit: Field<u64>,
    timeout: Field<u64>,
    retry_timeout: Field<u64>,
    idle_timeout: Field<u64>,
    retry_at: Field<u64>,
    soft_maximum: Field<u32>,
    soft_creation_phase: Field<u32>,
    loader_worker: Field<u32>,
    _reserved: Reserved<4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for BodyHeader {}
unsafe impl NtStruct for WaitPacketBody {}
unsafe impl NtStruct for FactoryBody {}

const _: () = {
    assert!(core::mem::size_of::<BodyHeader>() == 0x10);
    assert!(core::mem::size_of::<WaitPacketBody>() == 0x50);
    assert!(core::mem::offset_of!(WaitPacketBody, phase) == 0x10);
    assert!(core::mem::offset_of!(WaitPacketBody, key) == 0x28);
    assert!(core::mem::offset_of!(WaitPacketBody, information) == 0x40);
    assert!(core::mem::size_of::<FactoryBody>() == 0xA0);
    assert!(core::mem::offset_of!(FactoryBody, workers) == 0x34);
    assert!(core::mem::offset_of!(FactoryBody, port) == 0x38);
    assert!(core::mem::offset_of!(FactoryBody, soft_maximum) == 0x90);
    assert!(core::mem::offset_of!(FactoryBody, loader_worker) == 0x98);
};

pub const PACKET_SIZE: u64 = WaitPacketBody::SIZE;
pub const FACTORY_SIZE: u64 = FactoryBody::SIZE;

fn header(pointer: u64) -> &'static BodyHeader {
    // SAFETY: corpos alocados por `allocate_body`, vivos até o `dispose`.
    unsafe { BodyHeader::at(pointer) }
}

/// Junta as duas palavras (baixa, alta) de um valor de 64 bits.
fn join(words: [u32; 2]) -> u64 {
    (words[1] as u64) << 32 | words[0] as u64
}

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
    fn body(&self) -> &'static WaitPacketBody {
        // SAFETY: corpo alocado por `packet`, vivo até o `dispose`.
        unsafe { WaitPacketBody::at(self.pointer) }
    }

    fn phase(&self) -> u32 {
        self.body().phase.get()
    }

    pub fn association(&self) -> Option<Association> {
        if self.phase() != 1 {
            return None;
        }
        self.phases.lock().association.clone()
    }

    pub fn set_association(&self, value: Option<Association>) {
        let body = self.body();
        body.phase.set(value.is_some() as u32);
        body.port.set(value.as_ref().map_or(0, |value| value.port.pointer));
        body.target.set(value.as_ref().map_or(0, |value| value.target_pointer));
        self.phases.lock().association = value;
    }

    pub fn queued(&self) -> Option<Queued> {
        if self.phase() != 2 {
            return None;
        }
        self.phases.lock().queued.clone()
    }

    pub fn set_queued(&self, value: Option<Queued>) {
        let body = self.body();
        body.phase.set(if value.is_some() { 2 } else { 0 });
        body.port.set(value.as_ref().map_or(0, |value| value.port.pointer));
        body.target.set(0);
        self.phases.lock().queued = value;
    }

    pub fn closed(&self) -> bool {
        self.body().header.closed.get() != 0
    }

    pub fn key(&self) -> u64 {
        self.body().key.get()
    }

    pub fn context(&self) -> u64 {
        self.body().context.get()
    }

    pub fn status(&self) -> u32 {
        self.body().status.get()
    }

    pub fn information(&self) -> u64 {
        self.body().information.get()
    }

    /// Dados de conclusão em duas palavras cada, como a ABI os entrega;
    /// cada valor de 64 bits vai ao corpo numa única escrita.
    pub fn set_completion(&self, key: [u32; 2], context: [u32; 2], status: u32, information: [u32; 2]) {
        let body = self.body();
        body.key.set(join(key));
        body.context.set(join(context));
        body.information.set(join(information));
        body.status.set(status);
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
    // alloc_bytes devolve memória zerada.
    let pointer = guest::alloc_bytes(size);
    if pointer == 0 {
        return Err(status_error(0xC000_009A));
    }
    Ok(pointer)
}

fn before_handle_open(pointer: u64) -> Result<(), KernelError> {
    if header(pointer).closed.get() != 0 {
        return Err(status_error(0xC000_0056));
    }
    Ok(())
}

/// O último handle desfaz a associação.
fn packet_last_handle_close(pointer: u64) {
    header(pointer).closed.set(1);
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
    // Attributes do OBJECT_ATTRIBUTES do chamador (de modo usuário: sondado).
    let flags = if attributes != 0 {
        match guest::try_read::<u32>(attributes + core::mem::offset_of!(ObjectAttributes, attributes) as u64) {
            Ok(flags) => flags,
            Err(_) => return Ok(0xC000_0005),
        }
    } else {
        0
    };
    dispatcher_objects::publish(pointer, output, access, flags, 0, false, Some(payload))
}

macro_rules! field32 {
    ($get:ident, $set:ident, $field:ident) => {
        pub fn $get(&self) -> u32 {
            self.body().$field.get()
        }
        pub fn $set(&self, value: u32) {
            self.body().$field.set(value);
        }
    };
}

macro_rules! field64 {
    ($get:ident, $set:ident, $field:ident, $kind:ty) => {
        pub fn $get(&self) -> $kind {
            self.body().$field.get() as $kind
        }
        pub fn $set(&self, value: $kind) {
            self.body().$field.set(value as u64);
        }
    };
}

macro_rules! flag {
    ($get:ident, $set:ident, $field:ident) => {
        pub fn $get(&self) -> bool {
            self.body().$field.get() != 0
        }
        pub fn $set(&self, value: bool) {
            self.body().$field.set(value as u32);
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
    fn body(&self) -> &'static FactoryBody {
        // SAFETY: corpo alocado por `factory`, vivo até o `dispose`.
        unsafe { FactoryBody::at(self.pointer) }
    }

    field32!(priority, set_priority, priority);
    field32!(maximum, set_maximum, maximum);
    field32!(minimum, set_minimum, minimum);
    field32!(binding_count, set_binding_count, binding_count);
    field32!(release_count, set_release_count, release_count);
    /// Soma uma liberação atomicamente (o worker que libera e o que consulta
    /// podem rodar em CPUs diferentes).
    pub fn add_release_count(&self) {
        self.body().release_count.atomic().fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
    field32!(last_status, set_last_status, last_status);
    field32!(soft_maximum, set_soft_maximum, soft_maximum);
    field32!(soft_creation_phase, set_soft_creation_phase, soft_creation_phase);
    field64!(process_pointer, set_process_pointer, process_pointer, u64);
    field64!(process_id, set_process_id, process_id, u64);
    field64!(start, set_start, start, u64);
    field64!(parameter, set_parameter, parameter, u64);
    field64!(reserve, set_reserve, reserve, u64);
    field64!(commit, set_commit, commit, u64);
    field64!(timeout, set_timeout, timeout, i64);
    field64!(retry_timeout, set_retry_timeout, retry_timeout, i64);
    field64!(idle_timeout, set_idle_timeout, idle_timeout, i64);
    field64!(retry_at, set_retry_at, retry_at, i64);
    flag!(paused, set_paused, paused);
    flag!(shutdown, set_shutdown, shutdown);
    flag!(creating, set_creating, creating);
    flag!(loader_worker, set_loader_worker, loader_worker);

    pub fn closed(&self) -> bool {
        self.body().header.closed.get() != 0
    }

    pub fn set_closed(&self, value: bool) {
        self.body().header.closed.set(value as u32);
    }

    pub fn workers(&self) -> alloc::vec::Vec<Arc<crate::ntos::ps::user::threads::UserThread>> {
        self.workers.lock().clone()
    }

    /// Inserções e remoções atualizam o contador nativo em +0x34.
    pub fn add_worker(&self, thread: Arc<crate::ntos::ps::user::threads::UserThread>) {
        let mut workers = self.workers.lock();
        if !workers.iter().any(|candidate| Arc::ptr_eq(candidate, &thread)) {
            workers.push(thread);
        }
        self.body().workers.set(workers.len() as u32);
    }

    pub fn remove_worker(&self, thread: &Arc<crate::ntos::ps::user::threads::UserThread>) -> bool {
        let mut workers = self.workers.lock();
        let before = workers.len();
        workers.retain(|candidate| !Arc::ptr_eq(candidate, thread));
        self.body().workers.set(workers.len() as u32);
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
    factory.body().port.set(factory.port.pointer);
    FACTORIES.lock().insert(pointer, factory.clone());
    if let Err(error) = dispatcher_objects::create(pointer, "workerfactory", factory_dispose, None, attributes, true, DispatcherHooks { before_handle_open: Some(before_handle_open), on_last_handle_close: Some(factory_last_handle_close) }) {
        FACTORIES.lock().remove(&pointer);
        guest::free_bytes(pointer);
        return Err(error);
    }
    Ok(factory)
}
