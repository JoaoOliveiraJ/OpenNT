//! Identidade das mensagens ALPC.
//!
//! Cada mensagem viva pertence à porta dona e à geração do seu slot: a
//! reserva conserva o slot; o CallbackId muda a cada uso e rejeita respostas
//! antigas.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::resource::handles::Communication;
use crate::ntos::ob::objects::port::Port;
use crate::rtl::{KernelError, SpinLock};

/// Slot de mensagem: o identificador e a geração ativa.
pub struct Slot {
    pub identifier: u32,
    state: SpinLock<SlotState>,
}

#[derive(Default)]
struct SlotState {
    active: Option<Arc<Identity>>,
    retired: bool,
    on_activate: Option<Arc<dyn Fn() + Send + Sync>>,
    on_release: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl Slot {
    pub fn active(&self) -> Option<Arc<Identity>> {
        self.state.lock().active.clone()
    }
    pub fn set_hooks(&self, on_activate: Arc<dyn Fn() + Send + Sync>, on_release: Arc<dyn Fn() + Send + Sync>) {
        let mut state = self.state.lock();
        state.on_activate = Some(on_activate);
        state.on_release = Some(on_release);
    }
}

/// Atributos retidos pela mensagem (segurança, handles, remetente).
pub trait Retained: Send + Sync {
    fn release(&self);
}

#[derive(Default)]
pub struct IdentityState {
    pub active: bool,
    pub references: u32,
    pub security: Option<Arc<crate::ntos::alpc::security_contexts::Borrowed>>,
    pub handles: Option<Arc<crate::ntos::alpc::message::handles::HandleData>>,
    pub release_sender: Option<Box<dyn FnOnce() + Send>>,
    pub sender_thread: u64,
    pub replied: bool,
    pub queued: bool,
    pub direct: bool,
    pub client_context: u64,
    pub server_context: u64,
    pub canceled: bool,
    pub disconnected: bool,
    /// Operação de cancelamento do pedido (`cancelRequestedBy`).
    pub cancel_requested_by: Option<Arc<dyn Fn(&Arc<Port>, u32) -> Result<u32, KernelError> + Send + Sync>>,
}

pub struct Identity {
    pub port: Arc<Port>,
    pub slot: Arc<Slot>,
    pub identifier: u32,
    pub callback: u32,
    pub reserved: bool,
    pub communication: Option<Arc<Communication>>,
    pub connection_port: Option<Arc<Port>>,
    state: SpinLock<IdentityState>,
}

impl Identity {
    pub fn with<R>(&self, body: impl FnOnce(&mut IdentityState) -> R) -> R {
        body(&mut self.state.lock())
    }
}

struct Registry {
    slots: BTreeMap<u32, Arc<Slot>>,
    released: Vec<u32>,
    next_identifier: u32,
    callback_counter: u32,
}

static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry { slots: BTreeMap::new(), released: Vec::new(), next_identifier: 4, callback_counter: 0 });

/// O contador original de callbacks pula o zero depois do overflow.
pub fn next_callback(previous: u32) -> u32 {
    match previous.wrapping_add(1) {
        0 => 1,
        value => value,
    }
}

/// A sequência de entrega admite zero no overflow.
pub fn next_sequence(previous: u32) -> u32 {
    previous.wrapping_add(1)
}

pub fn allocate_slot() -> Option<Arc<Slot>> {
    let mut registry = REGISTRY.lock();
    let identifier = match registry.released.pop() {
        Some(identifier) => identifier,
        None => {
            let identifier = registry.next_identifier;
            if identifier > 0x3FF_FFFC {
                return None;
            }
            registry.next_identifier += 4;
            // O índice zero de cada bloco é reservado na codificação de handles.
            if registry.next_identifier & 0x3FC == 0 {
                registry.next_identifier += 4;
            }
            identifier
        }
    };
    let slot = Arc::new(Slot { identifier, state: SpinLock::new(SlotState::default()) });
    registry.slots.insert(identifier, slot.clone());
    Some(slot)
}

pub fn release_slot(slot: &Arc<Slot>) -> Result<(), KernelError> {
    let mut registry = REGISTRY.lock();
    if !registry.slots.get(&slot.identifier).is_some_and(|candidate| Arc::ptr_eq(candidate, slot)) || slot.state.lock().active.is_some() {
        return Err(KernelError::new("ALPC message slot released while active or already free"));
    }
    registry.slots.remove(&slot.identifier);
    registry.released.push(slot.identifier);
    Ok(())
}

/// Excluir o handle da reserva não destrói uma mensagem ainda na fila.
pub fn retire_slot(slot: &Arc<Slot>) -> Result<(), KernelError> {
    let active = {
        let mut state = slot.state.lock();
        if state.active.is_some() {
            state.retired = true;
        }
        state.active.is_some()
    };
    if active { Ok(()) } else { release_slot(slot) }
}

pub fn activate(port: &Arc<Port>, reserved: Option<Arc<Slot>>) -> Result<Option<Arc<Identity>>, KernelError> {
    let is_reserved = reserved.is_some();
    let Some(slot) = reserved.or_else(allocate_slot) else { return Ok(None) };
    let live = REGISTRY.lock().slots.get(&slot.identifier).is_some_and(|candidate| Arc::ptr_eq(candidate, &slot));
    if !live || slot.state.lock().active.is_some() {
        return Err(KernelError::new("ALPC message slot cannot be reused while active"));
    }
    let callback = {
        let mut registry = REGISTRY.lock();
        registry.callback_counter = next_callback(registry.callback_counter);
        registry.callback_counter
    };
    let (communication, connection_port) = port.with(|state| (state.communication.clone(), state.connection_port.clone()));
    let identity = Arc::new(Identity { port: port.clone(), slot: slot.clone(), identifier: slot.identifier, callback, reserved: is_reserved, communication, connection_port, state: SpinLock::new(IdentityState { active: true, references: 1, ..IdentityState::default() }) });
    let on_activate = {
        let mut state = slot.state.lock();
        state.active = Some(identity.clone());
        state.on_activate.clone()
    };
    if let Some(hook) = on_activate {
        hook();
    }
    Ok(Some(identity))
}

/// Resolve (identificador, callback): callback zero é o curinga.
pub fn resolve(port: &Arc<Port>, identifier: u32, callback: u32) -> Result<Arc<Identity>, u32> {
    let identity = REGISTRY.lock().slots.get(&identifier).and_then(|slot| slot.active());
    let Some(identity) = identity.filter(|identity| callback == 0 || identity.callback == callback) else { return Err(0xC000_0702) };
    let communication = port.with(|state| state.communication.clone());
    let same_communication = identity.communication.as_ref().zip(communication.as_ref()).is_some_and(|(left, right)| Arc::ptr_eq(left, right));
    if !Arc::ptr_eq(&identity.port, port) && !identity.connection_port.as_ref().is_some_and(|connection| Arc::ptr_eq(connection, port)) && !same_communication {
        return Err(0xC000_0022);
    }
    Ok(identity)
}

pub fn lookup(port: &Arc<Port>, identifier: u32, callback: u32) -> Option<Arc<Identity>> {
    resolve(port, identifier, callback).ok()
}

pub fn release(identity: &Arc<Identity>) -> Result<(), KernelError> {
    if !identity.with(|state| state.active) {
        return Ok(());
    }
    let (retired, on_release) = {
        let mut slot = identity.slot.state.lock();
        if !slot.active.as_ref().is_some_and(|active| Arc::ptr_eq(active, identity)) {
            return Err(KernelError::new("ALPC message generation mismatch"));
        }
        slot.active = None;
        (slot.retired, slot.on_release.clone())
    };
    // A geração liberada não resolve mais: a operação de cancelamento sai
    // com ela (e desfaz o ciclo pedido/identidade).
    identity.with(|state| {
        state.active = false;
        state.cancel_requested_by = None;
    });
    if !identity.reserved || retired {
        release_slot(&identity.slot)?;
    }
    let result = dereference(identity, false);
    if let Some(hook) = on_release {
        hook();
    }
    result
}

/// Consultas podem chamar callbacks de objetos: a retenção impede que um
/// fechamento reentrante destrua os recursos antes do fim da consulta.
pub fn reference(identity: &Arc<Identity>) -> Result<Arc<Identity>, KernelError> {
    let live = identity.with(|state| {
        if !state.active || state.references == 0 {
            return false;
        }
        state.references += 1;
        true
    });
    if !live {
        return Err(KernelError::new("ALPC message is not live"));
    }
    let _ = crate::ntos::ob::objects::dispatcher::reference(identity.port.pointer);
    Ok(identity.clone())
}

pub fn clear_attributes(identity: &Identity) {
    let (security, handles, release_sender) = identity.with(|state| (state.security.take(), state.handles.take(), state.release_sender.take()));
    if let Some(security) = security {
        security.release();
    }
    if let Some(handles) = handles {
        handles.release();
    }
    if let Some(release_sender) = release_sender {
        release_sender();
    }
}

pub fn dereference(identity: &Arc<Identity>, borrowed: bool) -> Result<(), KernelError> {
    let remaining = identity.with(|state| {
        if state.references == 0 {
            return None;
        }
        state.references -= 1;
        Some(state.references)
    });
    let Some(remaining) = remaining else { return Err(KernelError::new("ALPC message reference underflow")) };
    if remaining == 0 {
        clear_attributes(identity);
    }
    if borrowed {
        let _ = crate::ntos::ob::objects::dispatcher::dereference(identity.port.pointer);
    }
    Ok(())
}
