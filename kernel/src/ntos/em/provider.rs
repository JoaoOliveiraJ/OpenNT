//! EmProviderRegister e EmProviderDeregister.
//!
//! O provedor é um bloco de 0x48 bytes de pool paginado 'EMpr' (o
//! `EMP_PROVIDER` do ntoskrnl): o DRIVER_OBJECT referenciado em +0, o vetor
//! dos tipos de entrada registrados (+0x08) e a contagem (+0x10), os
//! registros dos callbacks preguiçosos das entradas (+0x18, 0x20 bytes cada)
//! e a contagem (+0x20), o vetor dos callbacks (+0x28) e a contagem (+0x30)
//! e uma LIST_ENTRY (+0x38). `EM_ENTRY_REGISTRATION` = {EntryId,
//! LazyEntryCallback, LazyCallbackContext} e `EM_CALLBACK_REGISTRATION` =
//! {CallbackId, CallbackFunction, Context}, 0x18 bytes cada.
//!
//! Todo tipo de entrada e todo callback precisa existir no banco
//! (STATUS_NOT_FOUND); o callback que já tem outra rotina recusa o registro
//! (STATUS_OBJECT_NAME_COLLISION). Aceito, o registro conta um provedor em
//! cada tipo e um registro em cada callback e enfileira a atualização das
//! regras que os usam (EmpQueueRuleUpdateState). Os provedores do próprio
//! kernel (a HAL e os callbacks embutidos) registram rotinas nativas pelo
//! mesmo caminho, sem DRIVER_OBJECT.

use alloc::vec::Vec;

use crate::ntos::em::database::{self, Routine};
use crate::ntos::em::evaluate;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::ListEntry;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_reference, reference_trace};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const PAGED_POOL: u32 = 1;
const PROVIDER_TAG: u32 = u32::from_le_bytes(*b"EMpr");
/// sizeof(EM_ENTRY_REGISTRATION) e sizeof(EM_CALLBACK_REGISTRATION).
const REGISTRATION_SIZE: u64 = 0x18;
/// O registro do callback preguiçoso de uma entrada.
const LAZY_RECORD_SIZE: u64 = 0x20;

/// O bloco do provedor (0x48 bytes, layout do ntoskrnl).
#[repr(C)]
pub struct EmProvider {
    pub driver_object: Field<u64>,
    pub entries: Field<u64>,
    pub entry_count: Field<u32>,
    _pad_14: Reserved<0x4>,
    pub lazy_records: Field<u64>,
    pub lazy_count: Field<u32>,
    _pad_24: Reserved<0x4>,
    pub callbacks: Field<u64>,
    pub callback_count: Field<u32>,
    _pad_34: Reserved<0x4>,
    pub link: ListEntry,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for EmProvider {}

const _: () = {
    assert!(core::mem::size_of::<EmProvider>() == 0x48);
    assert!(core::mem::offset_of!(EmProvider, lazy_records) == 0x18);
    assert!(core::mem::offset_of!(EmProvider, callbacks) == 0x28);
    assert!(core::mem::offset_of!(EmProvider, link) == 0x38);
};

fn provider_at(address: u64) -> &'static EmProvider {
    // SAFETY: um bloco de provedor alocado por `register`.
    unsafe { EmProvider::at(address) }
}

fn allocate(bytes: u64) -> u64 {
    pool_allocation::allocate_tagged(PAGED_POOL, bytes, PROVIDER_TAG).unwrap_or(0)
}

fn free(block: u64) {
    if block != 0 {
        let _ = pool_allocation::free(block, 0);
    }
}

/// O vetor zerado de `count` elementos de `size` bytes (0 se faltou pool).
fn allocate_zeroed(count: u32, size: u64) -> u64 {
    let block = allocate(count as u64 * size);
    if block != 0 {
        guest::write_bytes(block, &alloc::vec![0u8; (count as u64 * size) as usize]);
    }
    block
}

/// Um tipo de entrada pedido no registro.
pub struct EntryRequest {
    pub guid: Option<[u8; 16]>,
    pub lazy_callback: u64,
    pub lazy_context: u64,
}

/// Um callback pedido no registro.
pub struct CallbackRequest {
    pub guid: Option<[u8; 16]>,
    pub routine: Option<Routine>,
    pub context: u64,
}

/// EmpProviderRegister: os tipos de entrada e os callbacks já lidos.
pub fn register_records(driver_object: u64, entries: &[EntryRequest], callbacks: &[CallbackRequest]) -> Result<u64, u32> {
    let mut database = database::lock();
    let block = allocate(EmProvider::SIZE);
    if block == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let provider = provider_at(block);
    guest::write_bytes(block, &[0u8; EmProvider::SIZE as usize]);
    provider.link.flink.set(provider.link.address());
    provider.link.blink.set(provider.link.address());
    let mut entry_types: Vec<usize> = Vec::new();
    let mut callback_records: Vec<usize> = Vec::new();
    // O que já foi gravado no banco e precisa ser desfeito numa falha.
    let mut assigned: Vec<usize> = Vec::new();
    let status = (|| {
        if !entries.is_empty() {
            let array = allocate_zeroed(entries.len() as u32, 8);
            provider.entries.set(array);
            if array == 0 {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            provider.entry_count.set(entries.len() as u32);
            let lazy = entries.iter().filter(|entry| entry.lazy_callback != 0).count() as u32;
            provider.lazy_count.set(lazy);
            if lazy != 0 {
                let records = allocate_zeroed(lazy, LAZY_RECORD_SIZE);
                provider.lazy_records.set(records);
                if records == 0 {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }
            let mut lazy_index = 0u64;
            for (index, entry) in entries.iter().enumerate() {
                let Some(guid) = entry.guid else { return STATUS_INVALID_PARAMETER };
                let Some(entry_type) = database.search_entry(&guid) else { return STATUS_NOT_FOUND };
                guest::write64(array + index as u64 * 8, database.entry_types[entry_type].guid_address);
                entry_types.push(entry_type);
                if entry.lazy_callback != 0 {
                    let record = provider.lazy_records.get() + lazy_index * LAZY_RECORD_SIZE;
                    guest::write64(record, entry.lazy_callback);
                    guest::write64(record + 8, entry.lazy_context);
                    lazy_index += 1;
                    database.entry_types[entry_type].lazy.push((entry.lazy_callback, entry.lazy_context, block));
                }
            }
        }
        if !callbacks.is_empty() {
            let array = allocate_zeroed(callbacks.len() as u32, 8);
            provider.callbacks.set(array);
            if array == 0 {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            provider.callback_count.set(callbacks.len() as u32);
            for request in callbacks {
                let (Some(guid), Some(routine)) = (request.guid, request.routine) else { return STATUS_INVALID_PARAMETER };
                let Some(callback) = database.search_callback(&guid) else { return STATUS_NOT_FOUND };
                if database.callbacks[callback].routine.is_some_and(|current| current != routine) {
                    return STATUS_OBJECT_NAME_COLLISION;
                }
                callback_records.push(callback);
                database.callbacks[callback].routine = Some(routine);
                database.callbacks[callback].context = request.context;
                assigned.push(callback);
            }
        }
        STATUS_SUCCESS
    })();
    if status != STATUS_SUCCESS {
        for callback in assigned {
            if database.callbacks[callback].registrations == 0 {
                database.callbacks[callback].routine = None;
            }
        }
        for entry_type in &entry_types {
            database.entry_types[*entry_type].lazy.retain(|&(_, _, owner)| owner != block);
        }
        free(provider.entries.get());
        free(provider.lazy_records.get());
        free(provider.callbacks.get());
        free(block);
        return Err(status);
    }
    // Commit: os provedores dos tipos e os registros dos callbacks, e a
    // atualização das regras que os usam.
    for &entry_type in &entry_types {
        database.entry_types[entry_type].provider_count += 1;
        for rule in database.entry_types[entry_type].rules.clone() {
            evaluate::queue_rule_update(rule);
        }
    }
    for &callback in &callback_records {
        database.callbacks[callback].registrations += 1;
        for rule in database.callbacks[callback].rules.clone() {
            evaluate::queue_rule_update(rule);
        }
    }
    PROVIDERS.lock().push((block, entry_types, callback_records));
    if driver_object != 0 {
        let _ = object_reference::reference_with_tag(driver_object, reference_trace::DEFAULT_TAG, true);
    }
    provider.driver_object.set(driver_object);
    Ok(block)
}

/// Os tipos de entrada e os callbacks de cada provedor registrado (o que
/// os vetores do bloco apontam no NT).
static PROVIDERS: crate::rtl::SpinLock<Vec<(u64, Vec<usize>, Vec<usize>)>> = crate::rtl::SpinLock::new(Vec::new());

/// Os argumentos do EmProviderRegister.
pub struct Registration {
    pub driver_object: u64,
    pub entries: u64,
    pub entry_count: u32,
    pub callbacks: u64,
    pub callback_count: u32,
}

/// EmProviderRegister(DriverObject, EntryRegistration, NumberOfEntry,
/// CallbackRegistration, NumberOfCallback, ProviderHandle).
pub fn register(request: &Registration, handle: Option<&Field<u64>>) -> u32 {
    if request.driver_object == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(handle) = handle else { return STATUS_INVALID_PARAMETER };
    if (request.entry_count != 0 && request.entries == 0) || (request.callback_count != 0 && request.callbacks == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    let field = |base: u64, index: u32, offset: u64| guest::read64(base + index as u64 * REGISTRATION_SIZE + offset);
    let guid = |address: u64| (address != 0).then(|| database::guid_at(address));
    let entries: Vec<EntryRequest> = (0..request.entry_count).map(|index| EntryRequest { guid: guid(field(request.entries, index, 0)), lazy_callback: field(request.entries, index, 8), lazy_context: field(request.entries, index, 0x10) }).collect();
    let callbacks: Vec<CallbackRequest> = (0..request.callback_count)
        .map(|index| {
            let routine = field(request.callbacks, index, 8);
            CallbackRequest { guid: guid(field(request.callbacks, index, 0)), routine: (routine != 0).then_some(Routine::Guest(routine)), context: field(request.callbacks, index, 0x10) }
        })
        .collect();
    match register_records(request.driver_object, &entries, &callbacks) {
        Ok(block) => {
            handle.set(block);
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// EmProviderDeregister(ProviderHandle): NULL não faz nada.
pub fn deregister(handle: u64) {
    if handle == 0 {
        return;
    }
    let mut database = database::lock();
    let record = {
        let mut providers = PROVIDERS.lock();
        providers.iter().position(|(block, _, _)| *block == handle).map(|index| providers.remove(index))
    };
    let provider = provider_at(handle);
    if let Some((_, entry_types, callbacks)) = record {
        for entry_type in entry_types {
            database.entry_types[entry_type].lazy.retain(|&(_, _, owner)| owner != handle);
            database.entry_types[entry_type].provider_count -= 1;
            if database.entry_types[entry_type].provider_count == 0 {
                for rule in database.entry_types[entry_type].rules.clone() {
                    evaluate::queue_rule_update(rule);
                }
            }
        }
        for callback in callbacks {
            database.callbacks[callback].registrations -= 1;
            if database.callbacks[callback].registrations == 0 {
                database.callbacks[callback].routine = None;
                for rule in database.callbacks[callback].rules.clone() {
                    evaluate::queue_rule_update(rule);
                }
            }
        }
    }
    free(provider.lazy_records.get());
    let driver_object = provider.driver_object.get();
    if driver_object != 0 {
        let _ = object_reference::dereference_with_tag(driver_object, reference_trace::DEFAULT_TAG, true);
    }
    free(provider.callbacks.get());
    free(handle);
}
