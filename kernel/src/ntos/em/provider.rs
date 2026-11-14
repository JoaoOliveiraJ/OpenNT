//! EmProviderRegister e EmProviderDeregister.
//!
//! O provedor é um bloco de 0x48 bytes de pool paginado 'EMpr' (o
//! `EMP_PROVIDER` do ntoskrnl): o DRIVER_OBJECT referenciado em +0, o vetor
//! das entradas registradas (+0x08) e a contagem (+0x10), os registros dos
//! callbacks preguiçosos das entradas (+0x18, 0x20 bytes cada) e a contagem
//! (+0x20), o vetor dos callbacks (+0x28) e a contagem (+0x30) e uma
//! LIST_ENTRY (+0x38). `EM_ENTRY_REGISTRATION` = {EntryId, LazyEntryCallback,
//! LazyCallbackContext} e `EM_CALLBACK_REGISTRATION` = {CallbackId,
//! CallbackFunction, Context}, 0x18 bytes cada. Toda entrada e todo callback
//! precisa existir no banco; com o banco vazio do OpenNT (veja `em/mod.rs`),
//! só o registro sem entradas nem callbacks é aceito.

use crate::ntos::em::database;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::ListEntry;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_reference, reference_trace};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
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

/// Desfaz um provedor parcial (o caminho de erro do EmpProviderRegister).
fn discard(provider: &EmProvider) {
    free(provider.entries.get());
    free(provider.lazy_records.get());
    free(provider.callbacks.get());
    free(provider.address());
}

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
    let database = database::lock();
    let Some(handle) = handle else { return STATUS_INVALID_PARAMETER };
    if (request.entry_count != 0 && request.entries == 0) || (request.callback_count != 0 && request.callbacks == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    let block = allocate(EmProvider::SIZE);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let provider = provider_at(block);
    for field in [&provider.lazy_records, &provider.callbacks, &provider.entries] {
        field.set(0);
    }
    for field in [&provider.lazy_count, &provider.callback_count, &provider.entry_count] {
        field.set(0);
    }
    provider.link.flink.set(provider.link.address());
    provider.link.blink.set(provider.link.address());
    let registration = |base: u64, index: u32, offset: u64| guest::read64(base + index as u64 * REGISTRATION_SIZE + offset);
    if request.entry_count != 0 {
        let entries = allocate_zeroed(request.entry_count, 8);
        provider.entries.set(entries);
        if entries == 0 {
            discard(provider);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        provider.entry_count.set(request.entry_count);
        let lazy = (0..request.entry_count).filter(|&index| registration(request.entries, index, 8) != 0).count() as u32;
        provider.lazy_count.set(lazy);
        if lazy != 0 {
            let records = allocate_zeroed(lazy, LAZY_RECORD_SIZE);
            provider.lazy_records.set(records);
            if records == 0 {
                discard(provider);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        for index in 0..request.entry_count {
            let id = registration(request.entries, index, 0);
            if id == 0 {
                discard(provider);
                return STATUS_INVALID_PARAMETER;
            }
            if database.search_entry(&database::guid_at(id)).is_none() {
                discard(provider);
                return STATUS_NOT_FOUND;
            }
        }
    }
    if request.callback_count != 0 {
        let callbacks = allocate_zeroed(request.callback_count, 8);
        provider.callbacks.set(callbacks);
        if callbacks == 0 {
            discard(provider);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        provider.callback_count.set(request.callback_count);
        for index in 0..request.callback_count {
            let (id, function) = (registration(request.callbacks, index, 0), registration(request.callbacks, index, 8));
            if function == 0 || id == 0 {
                discard(provider);
                return STATUS_INVALID_PARAMETER;
            }
            if database.search_callback(&database::guid_at(id)).is_none() {
                discard(provider);
                return STATUS_NOT_FOUND;
            }
        }
    }
    let _ = object_reference::reference_with_tag(request.driver_object, reference_trace::DEFAULT_TAG, true);
    provider.driver_object.set(request.driver_object);
    handle.set(block);
    STATUS_SUCCESS
}

/// EmProviderDeregister(ProviderHandle): NULL não faz nada.
pub fn deregister(handle: u64) {
    if handle == 0 {
        return;
    }
    let _database = database::lock();
    let provider = provider_at(handle);
    free(provider.lazy_records.get());
    let driver_object = provider.driver_object.get();
    if driver_object != 0 {
        let _ = object_reference::dereference_with_tag(driver_object, reference_trace::DEFAULT_TAG, true);
    }
    free(provider.callbacks.get());
    free(handle);
}
