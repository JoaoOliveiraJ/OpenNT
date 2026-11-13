//! Reservas de mensagem ALPC — `system32/ntos/alpc/resource-reserves.js`.
//!
//! A reserva tem o slot de mensagem, o armazenamento do PORT_MESSAGE (com
//! a parte extra cobrada sob demanda) e entra na tabela de recursos com o
//! bit alto no identificador.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::message::identity::{self as message_identity, Slot};
use crate::ntos::alpc::resource::handles::{self as resource_handles, Resource, ResourceTable};
use crate::ntos::mm::kernel_pool::PoolQuota;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ps::{pool_quota, process};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub struct ReserveState {
    pub references: u32,
    pub busy: bool,
    pub deleted: bool,
    pub extra_pointer: u64,
    pub extra_size: u64,
    extra_charges: Vec<PoolQuota>,
    base_charge: Option<PoolQuota>,
}

pub struct Reserve {
    pub pointer: u64,
    pub message_pointer: u64,
    pub slot: Arc<Slot>,
    pub creator_process: u64,
    pub owner: Arc<Port>,
    pub table: ResourceTable,
    pub handle: u32,
    pub identifier: u32,
    pub size: u64,
    pub state: SpinLock<ReserveState>,
}

static LIVE: SpinLock<Vec<usize>> = SpinLock::new(Vec::new());

fn live(record: &Arc<Reserve>) -> bool {
    LIVE.lock().contains(&(Arc::as_ptr(record) as usize))
}

fn release_quota(quota: PoolQuota) {
    (quota.release)(quota.process_pointer, quota.paged, quota.bytes);
}

fn publish_state(record: &Reserve) {
    let state = record.state.lock();
    guest::write32(record.pointer, record.identifier);
    guest::write32(record.pointer + 4, state.deleted as u32);
    guest::write64(record.pointer + 8, state.references as u64);
    guest::write64(record.pointer + 16, record.owner.pointer);
    guest::write64(record.pointer + 24, record.creator_process);
    guest::write64(record.pointer + 32, record.message_pointer);
    guest::write64(record.pointer + 40, record.size);
    guest::write64(record.pointer + 48, state.extra_pointer);
    guest::write64(record.pointer + 56, state.extra_size);
    guest::write32(record.pointer + 64, state.busy as u32);
}

fn release_extra(state: &mut ReserveState) {
    if state.extra_pointer != 0 {
        guest::free_bytes(state.extra_pointer);
    }
    state.extra_pointer = 0;
    state.extra_size = 0;
    for quota in state.extra_charges.drain(..) {
        release_quota(quota);
    }
}

/// Garante armazenamento para a carga: a parte que excede a reserva vai a
/// um bloco extra cobrado do criador.
pub fn ensure_payload(record: &Arc<Reserve>, payload: u64) -> Result<u32, KernelError> {
    if !live(record) {
        return Err(KernelError::new("ALPC reserve storage is not live"));
    }
    let required = payload.saturating_sub(record.size - 40);
    let status = {
        let mut state = record.state.lock();
        if required == 0 {
            release_extra(&mut state);
            0
        } else if required <= state.extra_size {
            return Ok(0);
        } else {
            let previous = state.extra_size;
            if state.extra_pointer != 0 {
                guest::free_bytes(state.extra_pointer);
            }
            state.extra_pointer = guest::alloc_bytes(required);
            if state.extra_pointer == 0 {
                release_extra(&mut state);
                0xC000_009A
            } else {
                match pool_quota::charge(record.creator_process, true, required - previous)? {
                    Err(status) => {
                        release_extra(&mut state);
                        status
                    }
                    Ok(quota) => {
                        state.extra_charges.extend(quota);
                        state.extra_size = required;
                        0
                    }
                }
            }
        }
    };
    publish_state(record);
    Ok(status)
}

/// Endereço do byte `index` no armazenamento (base de 0x120, depois o extra).
fn address(record: &Reserve, index: u64) -> u64 {
    if index < record.size {
        record.message_pointer + 0x120 + index
    } else {
        record.state.lock().extra_pointer + index - record.size
    }
}

pub fn storage_length(record: &Reserve) -> u64 {
    record.size + record.state.lock().extra_size
}

pub fn write(record: &Reserve, bytes: &[u8], offset: u64) -> Result<(), KernelError> {
    if offset + bytes.len() as u64 > storage_length(record) {
        return Err(KernelError::new("ALPC reserve write exceeds owned storage"));
    }
    for (index, &byte) in bytes.iter().enumerate() {
        guest::write8(address(record, offset + index as u64), byte);
    }
    Ok(())
}

pub fn read(record: &Reserve, start: u64, end: u64) -> Result<Vec<u8>, KernelError> {
    if end < start || end > storage_length(record) {
        return Err(KernelError::new("ALPC reserve read exceeds owned storage"));
    }
    Ok((start..end).map(|index| guest::read8(address(record, index))).collect())
}

pub fn release(record: &Arc<Reserve>) -> Result<(), KernelError> {
    let remaining = {
        let mut state = record.state.lock();
        if !live(record) || state.references < 1 {
            return Err(KernelError::new("ALPC reserve reference underflow"));
        }
        state.references -= 1;
        if state.references == 0 && (!state.deleted || state.busy || record.slot.active().is_some()) {
            return Err(KernelError::new("ALPC reserve destroyed while published or busy"));
        }
        state.references
    };
    if remaining != 0 {
        publish_state(record);
        return Ok(());
    }
    LIVE.lock().retain(|&candidate| candidate != Arc::as_ptr(record) as usize);
    record.table.lock().remove(&record.handle);
    record.owner.with(|state| {
        state.reserves.remove(&record.identifier);
    });
    record.owner.add_reserve_bytes(-(record.size as i64));
    message_identity::release_slot(&record.slot)?;
    {
        let mut state = record.state.lock();
        release_extra(&mut state);
        if let Some(quota) = state.base_charge.take() {
            release_quota(quota);
        }
    }
    guest::free_bytes(record.message_pointer);
    guest::free_bytes(record.pointer);
    let _ = process::dereference(record.creator_process);
    let _ = dispatcher_objects::dereference(record.owner.pointer);
    Ok(())
}

fn acquire_message(record: &Arc<Reserve>) {
    {
        let mut state = record.state.lock();
        if !live(record) || state.busy || state.deleted {
            return;
        }
        state.busy = true;
        state.references += 1;
    }
    publish_state(record);
}

fn release_message(record: &Arc<Reserve>) {
    let busy = core::mem::replace(&mut record.state.lock().busy, false);
    if busy {
        let _ = release(record);
    }
}

pub fn create(port: &Arc<Port>, size: u64) -> Result<Result<Arc<Reserve>, u32>, KernelError> {
    if size > 0xFFD7 {
        return Ok(Err(0x8000_0005));
    }
    if size < 40 {
        return Ok(Err(0xC000_000D));
    }
    let pointer = guest::alloc_bytes(0x60);
    if pointer == 0 {
        return Ok(Err(0xC000_009A));
    }
    let creator = process::get_current_process();
    let mut base_charge: Option<PoolQuota> = None;
    let mut message_pointer = 0u64;
    let mut slot: Option<Arc<Slot>> = None;
    let mut record: Option<Arc<Reserve>> = None;
    let mut process_held = false;
    let mut port_held = false;
    let outcome = (|| -> Result<Result<Arc<Reserve>, u32>, KernelError> {
        match pool_quota::charge(creator, true, 0x318)? {
            Ok(quota) => base_charge = quota,
            Err(status) => return Ok(Err(status)),
        }
        message_pointer = guest::alloc_bytes(size + 0x120);
        if message_pointer == 0 {
            return Ok(Err(0xC000_009A));
        }
        slot = message_identity::allocate_slot();
        let Some(slot) = slot.clone() else { return Ok(Err(0xC000_009A)) };
        let table = resource_handles::table_for(port);
        let Some(handle) = resource_handles::available(&table).filter(|&handle| handle <= 0x7FFF_FFFF) else { return Ok(Err(0xC000_009A)) };
        if process::reference(creator).is_none() {
            return Err(KernelError::new("ALPC reserve lost its creator process"));
        }
        process_held = true;
        let created = Arc::new(Reserve { pointer, message_pointer, slot: slot.clone(), creator_process: creator, owner: port.clone(), table: table.clone(), handle, identifier: handle | 0x8000_0000, size, state: SpinLock::new(ReserveState { references: 1, busy: false, deleted: false, extra_pointer: 0, extra_size: 0, extra_charges: Vec::new(), base_charge: base_charge.take() }) });
        record = Some(created.clone());
        LIVE.lock().push(Arc::as_ptr(&created) as usize);
        let status = ensure_payload(&created, size)?;
        if status != 0 {
            return Ok(Err(status));
        }
        if port.closed() {
            return Ok(Err(0xC000_0037));
        }
        let _ = dispatcher_objects::reference(port.pointer);
        port_held = true;
        let (activated, released) = (created.clone(), created.clone());
        slot.set_hooks(alloc::sync::Arc::new(move || acquire_message(&activated)), alloc::sync::Arc::new(move || release_message(&released)));
        table.lock().insert(handle, Resource::Reserve(created.clone()));
        port.with(|state| {
            state.reserves.insert(created.identifier, created.clone());
        });
        port.add_reserve_bytes(size as i64);
        publish_state(&created);
        Ok(Ok(created))
    })();
    if !matches!(outcome, Ok(Ok(_))) {
        if let Some(record) = &record {
            LIVE.lock().retain(|&candidate| candidate != Arc::as_ptr(record) as usize);
            let mut state = record.state.lock();
            release_extra(&mut state);
            base_charge = state.base_charge.take();
        }
        if port_held {
            let _ = dispatcher_objects::dereference(port.pointer);
        }
        if process_held {
            let _ = process::dereference(creator);
        }
        if let Some(slot) = &slot {
            let _ = message_identity::release_slot(slot);
        }
        if message_pointer != 0 {
            guest::free_bytes(message_pointer);
        }
        if let Some(quota) = base_charge {
            release_quota(quota);
        }
        guest::free_bytes(pointer);
    }
    outcome
}

pub fn find(port: &Arc<Port>, identifier: u32) -> Option<Arc<Reserve>> {
    if identifier & 0x8000_0000 == 0 {
        return None;
    }
    match resource_handles::find(port, (identifier & 0x7FFF_FFFF) as u64) {
        Some(Resource::Reserve(record)) if live(&record) => Some(record),
        _ => None,
    }
}

pub fn remove(record: &Arc<Reserve>) -> Result<u32, KernelError> {
    if !live(record) {
        return Err(KernelError::new("ALPC reserve is not live"));
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

pub fn close_owner(port: &Arc<Port>) -> Result<(), KernelError> {
    let records: Vec<Arc<Reserve>> = port.with(|state| state.reserves.values().cloned().collect());
    for record in records {
        if !record.state.lock().deleted {
            remove(&record)?;
        }
    }
    Ok(())
}
