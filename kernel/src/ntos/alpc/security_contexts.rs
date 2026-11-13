//! Identidade de cliente e contextos de segurança ALPC.
//!
//! Rastreamento dinâmico retém o token escolhido; estático cria uma cópia
//! independente. Contextos são recursos da porta, retidos também pelas
//! mensagens em trânsito: a exclusão marca o recurso e o identificador sai
//! da tabela na última referência.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::alpc::resource::handles::{self as resource_handles, Resource, ResourceTable};
use crate::ntos::mm::kernel_pool::PoolQuota;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ps::{pool_quota, process};
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// SECURITY_QUALITY_OF_SERVICE capturado (comprimento e alinhamento não são
/// validados na cópia NT).
#[derive(Clone, Copy, Debug, Default)]
pub struct Quality {
    pub level: u32,
    pub tracking: u8,
    pub effective_only: bool,
}

pub fn quality(pointer: u64, mode: u8) -> Result<Option<Quality>, u32> {
    if pointer == 0 {
        return Ok(None);
    }
    if !message_buffer::accessible(pointer, 12, mode, false) {
        return Err(0xC000_0005);
    }
    Ok(Some(Quality { level: guest::read32(pointer + 4), tracking: guest::read8(pointer + 8), effective_only: guest::read8(pointer + 9) != 0 }))
}

/// Identidade capturada de uma thread; `release` solta o token uma vez.
pub struct ClientIdentity {
    pub token: u64,
    pub level: u32,
    pub effective_only: bool,
    released: SpinLock<bool>,
}

impl ClientIdentity {
    pub fn release(&self) -> Result<(), KernelError> {
        let mut released = self.released.lock();
        if *released {
            return Err(KernelError::new("ALPC client identity released twice"));
        }
        *released = true;
        tokens::release(self.token).map(|_| ())
    }
}

pub fn capture(thread: u64, quality: &Quality) -> Result<Result<Arc<ClientIdentity>, u32>, KernelError> {
    if quality.tracking > 1 {
        return Ok(Err(0xC000_000D));
    }
    if quality.level > 3 {
        return Ok(Err(0xC000_00A5));
    }
    let Some(record) = process::thread_record(thread) else { return Ok(Err(0xC000_0022)) };
    let impersonation = thread_tokens::get(thread);
    if impersonation.as_ref().is_some_and(|impersonation| impersonation.level < 2 || quality.level > impersonation.level) {
        return Ok(Err(0xC000_00A5));
    }
    let Some(source) = impersonation.as_ref().map(|impersonation| impersonation.token).or_else(|| process::get_primary_token(record.process)) else { return Ok(Err(0xC000_0022)) };
    let effective_only = quality.effective_only || impersonation.as_ref().is_some_and(|impersonation| impersonation.effective_only);
    let token = if quality.tracking != 0 {
        tokens::retain(source)
    } else {
        tokens::duplicate(source, quality.level, effective_only, 2).inspect(|&token| {
            let modified = tokens::with(source, |source| source.modified_id).unwrap_or(0);
            tokens::update(token, |token| token.modified_id = modified);
        })
    };
    match token {
        Ok(token) => Ok(Ok(Arc::new(ClientIdentity { token, level: quality.level, effective_only, released: SpinLock::new(false) }))),
        Err(error) if error.status != 0 => Ok(Err(error.status)),
        Err(error) => Err(error),
    }
}

pub struct ContextState {
    pub references: u32,
    pub deleted: bool,
}

pub struct ContextRecord {
    pub pointer: u64,
    pub creator_process: u64,
    charge: SpinLock<Option<PoolQuota>>,
    pub client: Arc<ClientIdentity>,
    pub owner: Arc<Port>,
    pub table: Option<ResourceTable>,
    pub handle: u64,
    pub state: SpinLock<ContextState>,
}

static LIVE: SpinLock<Vec<usize>> = SpinLock::new(Vec::new());

fn live(record: &Arc<ContextRecord>) -> bool {
    LIVE.lock().contains(&(Arc::as_ptr(record) as usize))
}

fn release_charge(charge: Option<PoolQuota>) {
    if let Some(quota) = charge {
        (quota.release)(quota.process_pointer, quota.paged, quota.bytes);
    }
}

fn publish_state(record: &ContextRecord) {
    let state = record.state.lock();
    guest::write64(record.pointer, record.handle);
    guest::write64(record.pointer + 8, state.references as u64);
    guest::write64(record.pointer + 16, record.owner.pointer);
    guest::write64(record.pointer + 24, record.creator_process);
    guest::write64(record.pointer + 32, record.client.token);
    guest::write32(record.pointer + 40, record.client.level);
    guest::write32(record.pointer + 44, state.deleted as u32);
}

pub fn create(port: &Arc<Port>, quality: &Quality, published: bool) -> Result<Result<Arc<ContextRecord>, u32>, KernelError> {
    let pointer = guest::alloc_bytes(0x70);
    if pointer == 0 {
        return Ok(Err(0xC000_009A));
    }
    let creator = process::get_current_process();
    let mut charge: Option<PoolQuota> = None;
    let mut client: Option<Arc<ClientIdentity>> = None;
    let mut process_held = false;
    let mut port_held = false;
    let outcome = (|| -> Result<Result<Arc<ContextRecord>, u32>, KernelError> {
        match pool_quota::charge(creator, true, 0xA0)? {
            Ok(quota) => charge = quota,
            Err(status) => return Ok(Err(status)),
        }
        match capture(process::get_current_thread(), quality)? {
            Ok(identity) => client = Some(identity),
            Err(status) => return Ok(Err(status)),
        }
        // A validação do QoS precede o teste de desconexão.
        if published && port.closed() {
            return Ok(Err(0xC000_009A));
        }
        let table = published.then(|| resource_handles::table_for(port));
        let handle = match &table {
            Some(table) => match resource_handles::available(table) {
                Some(handle) => handle as u64,
                None => return Ok(Err(0xC000_009A)),
            },
            None => u64::MAX,
        };
        if process::reference(creator).is_none() {
            return Err(KernelError::new("ALPC context lost creator"));
        }
        process_held = true;
        if published {
            let _ = dispatcher_objects::reference(port.pointer);
            port_held = true;
        }
        let Some(identity) = client.clone() else { return Err(KernelError::new("ALPC context lost client")) };
        let record = Arc::new(ContextRecord { pointer, creator_process: creator, charge: SpinLock::new(charge.take()), client: identity, owner: port.clone(), table: table.clone(), handle, state: SpinLock::new(ContextState { references: if published { 2 } else { 1 }, deleted: !published }) });
        publish_state(&record);
        LIVE.lock().push(Arc::as_ptr(&record) as usize);
        if let Some(table) = &table {
            port.with(|state| state.owned_security_contexts.push(record.clone()));
            table.lock().insert(handle as u32, Resource::Security(record.clone()));
        }
        Ok(Ok(record))
    })();
    if !matches!(outcome, Ok(Ok(_))) {
        if port_held {
            let _ = dispatcher_objects::dereference(port.pointer);
        }
        if process_held {
            let _ = process::dereference(creator);
        }
        if let Some(identity) = client {
            let _ = identity.release();
        }
        release_charge(charge);
        guest::free_bytes(pointer);
    }
    outcome
}

pub fn retain(record: &Arc<ContextRecord>) -> Result<Arc<ContextRecord>, KernelError> {
    if !live(record) || record.state.lock().references < 1 {
        return Err(KernelError::new("ALPC context is not live"));
    }
    record.state.lock().references += 1;
    publish_state(record);
    Ok(record.clone())
}

pub fn reference(port: &Arc<Port>, handle: u64) -> Result<Result<Arc<ContextRecord>, u32>, KernelError> {
    let Some(Resource::Security(record)) = resource_handles::find(port, handle) else { return Ok(Err(0xC000_0008)) };
    if !live(&record) {
        return Ok(Err(0xC000_0008));
    }
    if !Arc::ptr_eq(&record.owner, port) {
        return Ok(Err(0xC000_0022));
    }
    retain(&record).map(Ok)
}

pub fn release(record: &Arc<ContextRecord>) -> Result<(), KernelError> {
    let (remaining, deleted) = {
        let mut state = record.state.lock();
        if !live(record) || state.references < 1 {
            return Err(KernelError::new("ALPC context reference underflow"));
        }
        state.references -= 1;
        (state.references, state.deleted)
    };
    if remaining != 0 {
        publish_state(record);
        return Ok(());
    }
    if !deleted {
        return Err(KernelError::new("ALPC context lost table reference"));
    }
    LIVE.lock().retain(|&candidate| candidate != Arc::as_ptr(record) as usize);
    if let Some(table) = &record.table {
        table.lock().remove(&(record.handle as u32));
        record.owner.with(|state| state.owned_security_contexts.retain(|candidate| !Arc::ptr_eq(candidate, record)));
    }
    let _ = record.client.release();
    release_charge(record.charge.lock().take());
    let _ = process::dereference(record.creator_process);
    guest::free_bytes(record.pointer);
    if record.table.is_some() {
        let _ = dispatcher_objects::dereference(record.owner.pointer);
    }
    Ok(())
}

pub fn delete_referenced(record: &Arc<ContextRecord>) -> Result<u32, KernelError> {
    if !live(record) {
        return Err(KernelError::new("ALPC context already destroyed"));
    }
    {
        let mut state = record.state.lock();
        if state.deleted {
            return Ok(0xC000_0056);
        }
        state.deleted = true;
    }
    release(record).map(|_| 0)
}

/// Cada mensagem recebe a própria retenção e consulta o token mesmo depois
/// da exclusão do contexto.
pub struct Borrowed {
    pub token: u64,
    pub level: u32,
    pub effective_only: bool,
    record: Arc<ContextRecord>,
    released: SpinLock<bool>,
}

impl crate::ntos::alpc::message::identity::Retained for Borrowed {
    fn release(&self) {
        let mut released = self.released.lock();
        if !*released {
            *released = true;
            drop(released);
            let _ = release(&self.record);
        }
    }
}

pub fn borrow(record: &Arc<ContextRecord>) -> Borrowed {
    Borrowed { token: record.client.token, level: record.client.level, effective_only: record.client.effective_only, record: record.clone(), released: SpinLock::new(false) }
}

pub fn close_owner(port: &Arc<Port>) -> Result<(), KernelError> {
    let records = port.with(|state| state.owned_security_contexts.clone());
    for record in records {
        if !record.state.lock().deleted {
            delete_referenced(&record)?;
        }
    }
    Ok(())
}
