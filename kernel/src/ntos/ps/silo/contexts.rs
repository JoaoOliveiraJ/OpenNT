//! Contextos de silo do NT 19041.
//!
//! 32 slots embutidos e uma extensão preguiçosa de 256. Cada entrada é
//! {EX_PUSH_LOCK, objeto | bit permanente}; a tabela possui uma referência.
//! O contador de referências do objeto fica 0x30 bytes antes do corpo.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

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
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::nt_abi::io_workitem;
use crate::ntos::inc::types::{Ejob, Ethread, ExPushLock, ObjectHeader};

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

/// Entrada de slot da tabela de contextos (EJOB.Storage, layout do OpenNT):
/// o push lock da entrada e o objeto com o bit 0 = permanente.
#[repr(C)]
struct SiloSlot {
    lock: ExPushLock,
    object: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SiloSlot {}

/// Tabela de contextos: 32 slots embutidos e a extensão preguiçosa de 256.
#[repr(C)]
struct SiloStorage {
    slots: [SiloSlot; 32],
    /// -> `[SiloSlot; 256]` (uma página)
    extension: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SiloStorage {}

const _: () = {
    assert!(core::mem::size_of::<SiloSlot>() == 0x10);
    assert!(core::mem::size_of::<SiloStorage>() == 0x208);
};

fn storage(table: u64) -> &'static SiloStorage {
    // SAFETY: tabela alocada por este módulo (EJOB.Storage ou a do host).
    unsafe { SiloStorage::at(table) }
}

fn slot_at(entry: u64) -> &'static SiloSlot {
    // SAFETY: entrada devolvida por `slot_entry` dentro de uma tabela viva.
    unsafe { SiloSlot::at(entry) }
}

fn silo_job(silo: u64) -> &'static Ejob {
    // SAFETY: os chamadores passam um EJOB de server silo vivo.
    unsafe { Ejob::at(silo) }
}

/// O cabeçalho de objeto 0x30 bytes antes do corpo do contexto.
fn object_header(pointer: u64) -> &'static ObjectHeader {
    // SAFETY: corpo criado por `create`, com o cabeçalho logo antes.
    unsafe { ObjectHeader::at(pointer - core::mem::offset_of!(ObjectHeader, body) as u64) }
}

pub fn exists(pointer: u64) -> bool {
    STATE.lock().records.contains_key(&pointer)
}

pub fn ref_count(pointer: u64) -> u64 {
    object_header(pointer).pointer_count.get() as u64
}

fn live(pointer: u64) -> Result<(), KernelError> {
    let ok = STATE.lock().records.get(&pointer).is_some_and(|record| !record.deleting) && ref_count(pointer) != 0;
    if ok { Ok(()) } else { Err(KernelError::new("invalid silo-context reference")) }
}

fn change_references(pointer: u64, increment: bool) -> Result<u64, KernelError> {
    let step = |old: u64| if increment { old + 1 } else { old - 1 };
    let previous = object_header(pointer).pointer_count.atomic().try_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
        let old = old as u64;
        (old != 0 && old <= 0x7FFF_FFFF_FFFF_FFFE).then(|| step(old) as i64)
    });
    match previous {
        Ok(previous) => Ok(step(previous as u64)),
        Err(_) => Err(KernelError::new("silo-context reference underflow/overflow")),
    }
}

pub fn reference(pointer: u64) -> Result<Option<u64>, KernelError> {
    if !exists(pointer) {
        return Ok(None);
    }
    live(pointer)?;
    change_references(pointer, true).map(Some)
}

/// PsReferenceSiloContext: o contexto tem de existir.
pub fn reference_existing(pointer: u64) -> Result<(), KernelError> {
    if reference(pointer)?.is_none() {
        return Err(KernelError::new("invalid silo-context reference"));
    }
    Ok(())
}

/// PsDereferenceSiloContext: contagem real; no zero roda o cleanup
/// registrado e libera. O contexto tem de existir.
pub fn dereference_existing(pointer: u64) -> Result<(), KernelError> {
    if dereference(pointer)?.is_none() {
        return Err(KernelError::new("invalid silo-context reference"));
    }
    Ok(())
}

/// PASSIVE_LEVEL, sem região guardada e com interrupções habilitadas.
pub fn can_delete_now() -> bool {
    if irql::get_irql() != 0 {
        return false;
    }
    let thread = crate::ntos::ps::process::get_current_thread();
    // SAFETY: a thread corrente do Process Manager.
    if thread != 0 && unsafe { Ethread::at(thread) }.tcb.special_apc_disable.get() != 0 {
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
    let allocation = data_pool::alloc(size as u64 + core::mem::offset_of!(ObjectHeader, body) as u64);
    if allocation == 0 {
        guest::free_bytes(dispatch);
        return Ok(NO_MEMORY);
    }
    let pointer = allocation + core::mem::offset_of!(ObjectHeader, body) as u64;
    object_header(pointer).pointer_count.set(1);
    let security = object_access::capture(object_access::subject());
    STATE.lock().records.insert(pointer, Record { allocation, dispatch, silo, cleanup, object_type: object_type.clone(), deleting: false, security });
    object_types::account(&object_type.name, 1, 0)?;
    open_pointer::register_owner(Slot::Silo, exists, &OWNER);
    // SAFETY: PVOID* de saída do chamador de kernel.
    unsafe { Field::<u64>::at(output) }.set(pointer);
    Ok(0)
}

fn table(silo: u64, create_host: bool) -> u64 {
    if silo != 0 {
        return silo_job(silo).storage.get();
    }
    let mut state = STATE.lock();
    if state.host == 0 && create_host {
        state.host = data_pool::alloc(SiloStorage::SIZE);
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
    let pointer = data_pool::alloc(SiloStorage::SIZE);
    if pointer == 0 {
        return Ok(0);
    }
    STATE.lock().tables.insert(silo, pointer);
    silo_job(silo).storage.set(pointer);
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
        let table = storage(base);
        let pointer = table.extension.get();
        if pointer == 0 && writable {
            let extension = data_pool::alloc(4096);
            if extension == 0 {
                return Ok(Err(NO_MEMORY));
            }
            let old = match table.extension.atomic().compare_exchange(0, extension, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(previous) | Err(previous) => previous,
            };
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
    Ok(Ok(base + (if slot < 32 { slot } else { slot - 32 }) as u64 * SiloSlot::SIZE))
}

/// PsAllocSiloContextSlot.
pub fn alloc_slot(output: u64) -> u32 {
    let mut state = STATE.lock();
    match (0..288).find(|slot| !state.slots.contains(slot)) {
        Some(slot) => {
            state.slots.insert(slot);
            // SAFETY: ULONG de saída do chamador (ou o slot de um monitor).
            unsafe { Field::<u32>::at(output) }.set(slot);
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
            if slot_at(entry).object.get() != 0 {
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
pub fn get_context(silo: u64, index: u32, output: u64, permanent: bool) -> Result<u32, KernelError> {
    // SAFETY: PVOID* de saída do chamador de kernel.
    let output = unsafe { Field::<u64>::at(output) };
    output.set(0);
    let entry = match slot_entry(silo, index, false)? {
        Ok(entry) => slot_at(entry),
        Err(status) => return Ok(status),
    };
    let lock = entry.lock.value.address();
    if !permanent {
        push_lock::acquire_shared(lock, 0)?;
    }
    let value = entry.object.get();
    let pointer = value & !1;
    let status = if pointer == 0 {
        NOT_FOUND
    } else if permanent && value & 1 == 0 {
        NOT_SUPPORTED
    } else {
        if !permanent {
            reference(pointer)?;
        }
        output.set(pointer);
        0
    };
    if !permanent {
        push_lock::release_shared(lock, 0)?;
    }
    Ok(status)
}

/// PsInsertSiloContext / PsInsertPermanentSiloContext.
pub fn insert(silo: u64, index: u32, pointer: u64, permanent: bool) -> Result<u32, KernelError> {
    live(pointer)?;
    if STATE.lock().records.get(&pointer).map(|record| record.silo) != Some(silo) {
        return Ok(INVALID);
    }
    let entry = match slot_entry(silo, index, true)? {
        Ok(entry) => slot_at(entry),
        Err(status) => return Ok(status),
    };
    let lock = entry.lock.value.address();
    reference(pointer)?;
    push_lock::acquire_exclusive(lock, 0)?;
    let inserted = entry.object.get() == 0;
    if inserted {
        entry.object.set(pointer | permanent as u64);
    }
    push_lock::release_exclusive(lock, 0)?;
    if !inserted {
        dereference(pointer)?;
        return Ok(NOT_SUPPORTED);
    }
    Ok(0)
}

/// PsMakeSiloContextPermanent.
pub fn make_permanent(silo: u64, index: u32) -> Result<u32, KernelError> {
    let entry = match slot_entry(silo, index, true)? {
        Ok(entry) => slot_at(entry),
        Err(status) => return Ok(status),
    };
    let lock = entry.lock.value.address();
    push_lock::acquire_exclusive(lock, 0)?;
    let value = entry.object.get();
    let status = if value & !1 == 0 {
        INVALID
    } else {
        entry.object.set(value | 1);
        0
    };
    push_lock::release_exclusive(lock, 0)?;
    Ok(status)
}

/// PsRemoveSiloContext: a referência da tabela passa ao chamador (saída) ou
/// é solta fora do lock.
pub fn remove(silo: u64, index: u32, output: u64, force: bool) -> Result<u32, KernelError> {
    let entry = match slot_entry(silo, index, false)? {
        Ok(entry) => slot_at(entry),
        Err(status) => return Ok(status),
    };
    let lock = entry.lock.value.address();
    push_lock::acquire_exclusive(lock, 0)?;
    let value = entry.object.get();
    let pointer = value & !1;
    let status = if pointer == 0 {
        NOT_FOUND
    } else if value & 1 != 0 && !force {
        NOT_SUPPORTED
    } else {
        entry.object.set(0);
        0
    };
    push_lock::release_exclusive(lock, 0)?;
    if status != 0 {
        return Ok(status);
    }
    if output != 0 {
        // SAFETY: PVOID* de saída do chamador de kernel.
        unsafe { Field::<u64>::at(output) }.set(pointer);
    } else {
        dereference(pointer)?;
    }
    Ok(0)
}

/// PsReplaceSiloContext.
pub fn replace(silo: u64, index: u32, pointer: u64, output: u64) -> Result<u32, KernelError> {
    live(pointer)?;
    if STATE.lock().records.get(&pointer).map(|record| record.silo) != Some(silo) {
        return Ok(INVALID);
    }
    let entry = match slot_entry(silo, index, true)? {
        Ok(entry) => slot_at(entry),
        Err(status) => return Ok(status),
    };
    let lock = entry.lock.value.address();
    reference(pointer)?;
    push_lock::acquire_exclusive(lock, 0)?;
    let previous = entry.object.get();
    let inserted = previous & 1 == 0;
    if inserted {
        entry.object.set(pointer);
    }
    push_lock::release_exclusive(lock, 0)?;
    if !inserted {
        dereference(pointer)?;
        return Ok(NOT_SUPPORTED);
    }
    if output != 0 {
        // SAFETY: PVOID* de saída do chamador de kernel.
        unsafe { Field::<u64>::at(output) }.set(previous);
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
    silo_job(silo).storage.set(0);
    let extension = storage(pointer).extension.get();
    for index in 0..if extension != 0 { 288u64 } else { 32 } {
        let entry = slot_at(if index < 32 { pointer + index * SiloSlot::SIZE } else { extension + (index - 32) * SiloSlot::SIZE });
        let context = entry.object.get() & !1;
        entry.object.set(0);
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
