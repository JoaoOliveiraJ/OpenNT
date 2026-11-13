//! Contextos de silo do NT 19041 — `system32/ntos/ps/silo-contexts.js`.
//!
//! 32 slots embutidos e uma extensão preguiçosa de 256. Cada entrada é
//! {EX_PUSH_LOCK, objeto | bit permanente}; a tabela possui uma referência.
//! O contador de referências do objeto fica 0x30 bytes antes do corpo.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::hal::cpu;
use crate::hal::amd64::native_call;
use crate::ntos::ex::push_lock;
use crate::ntos::io::work_items;
use crate::ntos::ke::irql;
use crate::ntos::mm::data_pool;
use crate::ntos::ob::object_manager::ObjectData;
use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::open_pointer::{self, ObjectOwner, Slot};
use crate::ntos::ob::object_access;
use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{ejob, io_workitem, kthread};

const INVALID: u32 = 0xC000_000D;
const NOT_FOUND: u32 = 0xC000_0225;
const NOT_SUPPORTED: u32 = 0xC000_00BB;
const NO_MEMORY: u32 = 0xC000_009A;

#[derive(Clone)]
struct Record {
    allocation: u64,
    dispatch: u64,
    silo: u64,
    cleanup: u64,
    object_type: ObjectType,
    deleting: bool,
    security: SecurityPolicy,
}

struct State {
    slots: BTreeSet<u32>,
    records: BTreeMap<u64, Record>,
    tables: BTreeMap<u64, u64>,
    destroy_routines: Vec<fn(u64)>,
    host: u64,
}

static STATE: SpinLock<State> = SpinLock::new(State { slots: BTreeSet::new(), records: BTreeMap::new(), tables: BTreeMap::new(), destroy_routines: Vec::new(), host: 0 });

pub fn exists(pointer: u64) -> bool {
    STATE.lock().records.contains_key(&pointer)
}

pub fn ref_count(pointer: u64) -> u64 {
    guest::read64(pointer - 0x30)
}

fn live(pointer: u64) -> Result<(), KernelError> {
    let ok = STATE.lock().records.get(&pointer).is_some_and(|record| !record.deleting) && ref_count(pointer) != 0;
    if ok { Ok(()) } else { Err(KernelError::new("invalid silo-context reference")) }
}

fn change_references(pointer: u64, increment: bool) -> Result<u64, KernelError> {
    let address = pointer - 0x30;
    let mut old = guest::read64(address);
    loop {
        if old == 0 || old > 0x7FFF_FFFF_FFFF_FFFE {
            return Err(KernelError::new("silo-context reference underflow/overflow"));
        }
        let next = if increment { old + 1 } else { old - 1 };
        let actual = guest::compare_exchange64(address, old, next)?;
        if actual == old {
            return Ok(next);
        }
        old = actual;
    }
}

pub fn reference(pointer: u64) -> Result<Option<u64>, KernelError> {
    if !exists(pointer) {
        return Ok(None);
    }
    live(pointer)?;
    change_references(pointer, true).map(Some)
}

/// PASSIVE_LEVEL, sem região guardada e com interrupções habilitadas.
pub fn can_delete_now() -> bool {
    if irql::get_irql() != 0 {
        return false;
    }
    let thread = crate::ntos::ps::process::get_current_thread();
    if thread != 0 && guest::read16(thread + kthread::SPECIAL_APC_DISABLE) != 0 {
        return false;
    }
    let flags = cpu::save_and_disable_interrupts();
    cpu::restore_interrupts(flags);
    flags & 0x200 != 0
}

fn destroy(pointer: u64) {
    let Some(record) = STATE.lock().records.get(&pointer).cloned() else { return };
    if record.cleanup != 0 {
        native_call::call(record.cleanup, &[pointer]);
    }
    STATE.lock().records.remove(&pointer);
    let _ = object_types::account(&record.object_type.name, -1, 0);
    let _ = data_pool::free(record.allocation);
    guest::free_bytes(record.dispatch);
}

fn deferred_destroy(_device: u64, pointer: u64) {
    destroy(pointer);
}

/// Sem condições de exclusão imediata, a destruição vai para um work item.
pub fn dereference(pointer: u64) -> Result<Option<u64>, KernelError> {
    if !exists(pointer) {
        return Ok(None);
    }
    live(pointer)?;
    let count = change_references(pointer, false)?;
    if count == 0 {
        let dispatch = {
            let mut state = STATE.lock();
            let record = state.records.get_mut(&pointer).unwrap();
            record.deleting = true;
            record.dispatch
        };
        if can_delete_now() {
            destroy(pointer);
        } else {
            work_items::create_work_item(0, dispatch);
            work_items::queue_kernel_work_item(dispatch, deferred_destroy, pointer, Some(can_delete_now));
        }
    }
    Ok(Some(count))
}

struct SiloOwner;

static OWNER: SiloOwner = SiloOwner;

impl ObjectOwner for SiloOwner {
    fn object_type(&self, pointer: u64) -> ObjectType {
        STATE.lock().records.get(&pointer).map(|record| record.object_type.clone()).unwrap_or_else(|| object_types::silo_context_type(false))
    }
    fn reference(&self, pointer: u64) {
        let _ = reference(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = dereference(pointer);
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        STATE.lock().records.get(&pointer).map(|record| record.security.clone()).unwrap_or_default()
    }
    fn data(&self, _pointer: u64) -> ObjectData {
        ObjectData::default()
    }
}

/// PsCreateSiloContext: pool paginável (1) ou NonPagedPoolNx (0x200).
pub fn create(silo: u64, size: u32, pool_type: u32, cleanup: u64, output: u64) -> Result<u32, KernelError> {
    if pool_type != 1 && pool_type != 0x200 {
        return Ok(INVALID);
    }
    let object_type = object_types::silo_context_type(pool_type == 1);
    let dispatch = guest::alloc_bytes(0x60u64.max(io_workitem::SIZE + 8));
    if dispatch == 0 {
        return Ok(NO_MEMORY);
    }
    let allocation = data_pool::alloc(size as u64 + 0x30);
    if allocation == 0 {
        guest::free_bytes(dispatch);
        return Ok(NO_MEMORY);
    }
    let pointer = allocation + 0x30;
    guest::write64(allocation, 1);
    let security = object_access::capture(object_access::subject());
    STATE.lock().records.insert(pointer, Record { allocation, dispatch, silo, cleanup, object_type: object_type.clone(), deleting: false, security });
    object_types::account(&object_type.name, 1, 0)?;
    open_pointer::register_owner(Slot::Silo, exists, &OWNER);
    guest::write64(output, pointer);
    Ok(0)
}

fn table(silo: u64, create_host: bool) -> u64 {
    if silo != 0 {
        return guest::read64(silo + ejob::SILO_CONTEXT);
    }
    let mut state = STATE.lock();
    if state.host == 0 && create_host {
        state.host = data_pool::alloc(0x208);
    }
    state.host
}

/// Tabela de contextos do silo (o host usa a tabela global).
pub fn create_table(silo: u64) -> Result<u64, KernelError> {
    if silo == 0 {
        return Ok(table(0, true));
    }
    if table(silo, false) != 0 {
        return Err(KernelError::new("silo already owns a context table"));
    }
    let pointer = data_pool::alloc(0x208);
    if pointer == 0 {
        return Ok(0);
    }
    STATE.lock().tables.insert(silo, pointer);
    guest::write64(silo + ejob::SILO_CONTEXT, pointer);
    Ok(pointer)
}

/// Entrada do slot; `writable` cria tabela/extensão e exige slot alocado.
fn slot_entry(silo: u64, slot: u32, writable: bool) -> Result<Result<u64, u32>, KernelError> {
    if slot >= 288 {
        return Ok(Err(INVALID));
    }
    let mut base = table(silo, writable);
    if base == 0 {
        return Ok(Err(if writable { NO_MEMORY } else { NOT_FOUND }));
    }
    if slot >= 32 {
        let pointer = guest::read64(base + 0x200);
        if pointer == 0 && writable {
            let extension = data_pool::alloc(4096);
            if extension == 0 {
                return Ok(Err(NO_MEMORY));
            }
            let old = guest::compare_exchange64(base + 0x200, 0, extension)?;
            if old != 0 {
                data_pool::free(extension)?;
            }
            base = if old != 0 { old } else { extension };
        } else {
            base = pointer;
        }
        if base == 0 {
            return Ok(Err(NOT_FOUND));
        }
    }
    if writable && !STATE.lock().slots.contains(&slot) {
        return Err(KernelError::new("unallocated silo-context slot (native fail-fast 5)"));
    }
    Ok(Ok(base + (if slot < 32 { slot } else { slot - 32 }) as u64 * 16))
}

/// PsAllocSiloContextSlot.
pub fn alloc_slot(output: u64) -> u32 {
    let mut state = STATE.lock();
    match (0..288).find(|slot| !state.slots.contains(slot)) {
        Some(slot) => {
            state.slots.insert(slot);
            guest::write32(output, slot);
            0
        }
        None => NO_MEMORY,
    }
}

/// PsFreeSiloContextSlot: o nativo dá bugcheck 0x199 com tabela não vazia.
pub fn free_slot(slot: u32) -> Result<u32, KernelError> {
    if !STATE.lock().slots.contains(&slot) {
        return Ok(INVALID);
    }
    let silos: Vec<u64> = STATE.lock().tables.keys().copied().collect();
    for silo in silos {
        if let Ok(entry) = slot_entry(silo, slot, false)? {
            if guest::read64(entry + 8) != 0 {
                return Err(KernelError::new("silo-context slot still in use (native bugcheck 0x199)"));
            }
        }
    }
    Ok(release_slot(slot))
}

/// Liberação privada do bitmap (usada pelos monitores).
pub fn release_slot(slot: u32) -> u32 {
    if STATE.lock().slots.remove(&slot) { 0 } else { INVALID }
}

/// PsGetSiloContext / PsGetPermanentSiloContext.
pub fn get_context(silo: u64, slot: u32, output: u64, permanent: bool) -> Result<u32, KernelError> {
    guest::write64(output, 0);
    let entry = match slot_entry(silo, slot, false)? {
        Ok(entry) => entry,
        Err(status) => return Ok(status),
    };
    if !permanent {
        push_lock::acquire_shared(entry, 0)?;
    }
    let value = guest::read64(entry + 8);
    let pointer = value & !1;
    let status = if pointer == 0 {
        NOT_FOUND
    } else if permanent && value & 1 == 0 {
        NOT_SUPPORTED
    } else {
        if !permanent {
            reference(pointer)?;
        }
        guest::write64(output, pointer);
        0
    };
    if !permanent {
        push_lock::release_shared(entry, 0)?;
    }
    Ok(status)
}

/// PsInsertSiloContext / PsInsertPermanentSiloContext.
pub fn insert(silo: u64, slot: u32, pointer: u64, permanent: bool) -> Result<u32, KernelError> {
    live(pointer)?;
    if STATE.lock().records.get(&pointer).map(|record| record.silo) != Some(silo) {
        return Ok(INVALID);
    }
    let entry = match slot_entry(silo, slot, true)? {
        Ok(entry) => entry,
        Err(status) => return Ok(status),
    };
    reference(pointer)?;
    push_lock::acquire_exclusive(entry, 0)?;
    let inserted = guest::read64(entry + 8) == 0;
    if inserted {
        guest::write64(entry + 8, pointer | permanent as u64);
    }
    push_lock::release_exclusive(entry, 0)?;
    if !inserted {
        dereference(pointer)?;
        return Ok(NOT_SUPPORTED);
    }
    Ok(0)
}

/// PsMakeSiloContextPermanent.
pub fn make_permanent(silo: u64, slot: u32) -> Result<u32, KernelError> {
    let entry = match slot_entry(silo, slot, true)? {
        Ok(entry) => entry,
        Err(status) => return Ok(status),
    };
    push_lock::acquire_exclusive(entry, 0)?;
    let value = guest::read64(entry + 8);
    let status = if value & !1 == 0 {
        INVALID
    } else {
        guest::write64(entry + 8, value | 1);
        0
    };
    push_lock::release_exclusive(entry, 0)?;
    Ok(status)
}

/// PsRemoveSiloContext: a referência da tabela passa ao chamador (saída) ou
/// é solta fora do lock.
pub fn remove(silo: u64, slot: u32, output: u64, force: bool) -> Result<u32, KernelError> {
    let entry = match slot_entry(silo, slot, false)? {
        Ok(entry) => entry,
        Err(status) => return Ok(status),
    };
    push_lock::acquire_exclusive(entry, 0)?;
    let value = guest::read64(entry + 8);
    let pointer = value & !1;
    let status = if pointer == 0 {
        NOT_FOUND
    } else if value & 1 != 0 && !force {
        NOT_SUPPORTED
    } else {
        guest::write64(entry + 8, 0);
        0
    };
    push_lock::release_exclusive(entry, 0)?;
    if status != 0 {
        return Ok(status);
    }
    if output != 0 {
        guest::write64(output, pointer);
    } else {
        dereference(pointer)?;
    }
    Ok(0)
}

/// PsReplaceSiloContext.
pub fn replace(silo: u64, slot: u32, pointer: u64, output: u64) -> Result<u32, KernelError> {
    live(pointer)?;
    if STATE.lock().records.get(&pointer).map(|record| record.silo) != Some(silo) {
        return Ok(INVALID);
    }
    let entry = match slot_entry(silo, slot, true)? {
        Ok(entry) => entry,
        Err(status) => return Ok(status),
    };
    reference(pointer)?;
    push_lock::acquire_exclusive(entry, 0)?;
    let previous = guest::read64(entry + 8);
    let inserted = previous & 1 == 0;
    if inserted {
        guest::write64(entry + 8, pointer);
    }
    push_lock::release_exclusive(entry, 0)?;
    if !inserted {
        dereference(pointer)?;
        return Ok(NOT_SUPPORTED);
    }
    if output != 0 {
        guest::write64(output, previous);
    } else if previous != 0 {
        dereference(previous)?;
    }
    Ok(0)
}

/// Desmonta a tabela de um silo: destrutores registrados primeiro, depois
/// as referências de cada entrada.
pub fn destroy_table(silo: u64) -> Result<(), KernelError> {
    let Some(pointer) = STATE.lock().tables.get(&silo).copied() else {
        return Err(KernelError::new("unknown owned silo table"));
    };
    let routines = STATE.lock().destroy_routines.clone();
    for routine in routines {
        routine(silo);
    }
    STATE.lock().tables.remove(&silo);
    guest::write64(silo + ejob::SILO_CONTEXT, 0);
    let extension = guest::read64(pointer + 0x200);
    for slot in 0..if extension != 0 { 288u64 } else { 32 } {
        let entry = if slot < 32 { pointer + slot * 16 } else { extension + (slot - 32) * 16 };
        let context = guest::read64(entry + 8) & !1;
        guest::write64(entry + 8, 0);
        if context != 0 {
            dereference(context)?;
        }
    }
    if extension != 0 {
        data_pool::free(extension)?;
    }
    data_pool::free(pointer)
}

pub fn register_destroy_routine(routine: fn(u64)) {
    let mut state = STATE.lock();
    if !state.destroy_routines.iter().any(|&existing| existing as usize == routine as usize) {
        state.destroy_routines.push(routine);
    }
}

pub fn unregister_destroy_routine(routine: fn(u64)) {
    STATE.lock().destroy_routines.retain(|&existing| existing as usize != routine as usize);
}

pub fn owned_silos() -> Vec<u64> {
    STATE.lock().tables.keys().copied().collect()
}
