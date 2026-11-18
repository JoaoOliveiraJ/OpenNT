//! Keyed events: o tipo KeyedEvent e o objeto permanente
//! `\KernelObjects\CritSecOutOfMemoryEvent`.
//!
//! ExpKeyedEventInitialization (ntoskrnl 19041 rva 0xa6f2ec, do
//! ExpInitSystemPhase1):
//!
//! - ObCreateObjectType("KeyedEvent") com UseDefaultObject, PagedPool,
//!   GenericMapping {0x20001, 0x20002, 0x20000, 0xF0003} e ValidAccessMask
//!   KEYEDEVENT_ALL_ACCESS (0xF0003); o ObCreateObjectTypeEx soma o
//!   SYNCHRONIZE e aponta o DefaultObject para o ObpDefaultObject;
//! - o descritor: DACL com World 0x20003 e Administrators e SYSTEM 0xF0003;
//!   SACL com o rótulo Low (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);
//! - ZwCreateKeyedEvent(KEYEDEVENT_ALL_ACCESS, {nome, OBJ_PERMANENT}, 0): o
//!   NtCreateKeyedEvent (rva 0x7c58f0) cria o corpo de 0x600 bytes, 64 baldes
//!   {push lock, LIST_ENTRY vazia}, e o ObInsertObjectEx publica o nome;
//! - o kernel guarda o objeto em ExpCritSecOutOfMemoryEvent
//!   (ObReferenceObjectByHandle) e fecha o handle. É o keyed event que o
//!   NtWaitForKeyedEvent/NtReleaseKeyedEvent usam quando a ntdll passa o
//!   handle NULL.
//!
//! Os serviços Nt*KeyedEvent não são deste módulo.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ListEntry, ObjectAttributes, ObjectTypeInitializer, PoolType, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_create, object_header, object_types};
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::rtl::KernelError;

/// KEYEDEVENT_ALL_ACCESS.
const KEYEDEVENT_ALL_ACCESS: u32 = 0xF_0003;
/// KEYEDEVENT_WAIT | KEYEDEVENT_WAKE | READ_CONTROL.
const WORLD_ACCESS: u32 = 0x2_0003;
/// OBJECT_TYPE_INITIALIZER.UseDefaultObject.
const USE_DEFAULT_OBJECT: u16 = 0x4;
const OBJ_PERMANENT: u32 = 0x10;
/// SECURITY_MANDATORY_LOW_RID.
const LOW_INTEGRITY: u32 = 0x1000;
/// DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION.
const DACL_AND_LABEL: u32 = 0x14;
const BUCKETS: usize = 64;

pub const CRIT_SEC_OUT_OF_MEMORY_EVENT: &str = "\\KernelObjects\\CritSecOutOfMemoryEvent";

/// Um balde do corpo do keyed event: o push lock e a lista de esperas.
#[repr(C)]
struct KeyedEventBucket {
    lock: Field<u64>,
    wait_list: ListEntry,
}

/// O corpo do objeto KeyedEvent (0x600 bytes).
#[repr(C)]
struct KeyedEventObject {
    buckets: [KeyedEventBucket; BUCKETS],
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for KeyedEventBucket {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for KeyedEventObject {}

const _: () = {
    assert!(core::mem::size_of::<KeyedEventBucket>() == 0x18);
    assert!(core::mem::size_of::<KeyedEventObject>() == 0x600);
};

/// ExpKeyedEventObjectType.
static KEYED_EVENT_TYPE: AtomicU64 = AtomicU64::new(0);
/// ExpCritSecOutOfMemoryEvent: o corpo, com a referência do kernel.
static CRIT_SEC_OUT_OF_MEMORY: AtomicU64 = AtomicU64::new(0);

/// UNICODE_STRING e texto num bloco do convidado (o chamador libera os dois).
fn unicode(text: &str) -> (u64, u64) {
    let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let buffer = guest::alloc_bytes(units.len() as u64 + 2);
    guest::write_bytes(buffer, &units);
    let string = guest::alloc_bytes(UnicodeString::SIZE);
    // SAFETY: UNICODE_STRING recém-alocado.
    let value = unsafe { UnicodeString::at(string) };
    value.length.set(units.len() as u16);
    value.maximum_length.set(units.len() as u16 + 2);
    value.buffer.set(buffer);
    (string, buffer)
}

/// O ObCreateObjectType do tipo KeyedEvent.
fn create_type() -> Result<u64, KernelError> {
    if let Some(existing) = object_types::by_name("KeyedEvent") {
        return Ok(existing.pointer);
    }
    let init = guest::alloc_bytes(ObjectTypeInitializer::SIZE);
    // SAFETY: OBJECT_TYPE_INITIALIZER recém-alocado e zerado.
    let initializer = unsafe { ObjectTypeInitializer::at(init) };
    initializer.length.set(ObjectTypeInitializer::SIZE as u16);
    initializer.object_type_flags.set(USE_DEFAULT_OBJECT);
    let mapping = &initializer.generic_mapping;
    mapping.generic_read.set(0x2_0001);
    mapping.generic_write.set(0x2_0002);
    mapping.generic_execute.set(0x2_0000);
    mapping.generic_all.set(KEYEDEVENT_ALL_ACCESS);
    initializer.valid_access_mask.set(KEYEDEVENT_ALL_ACCESS);
    initializer.pool_type.set(PoolType::PAGED_POOL);
    let (name, buffer) = unicode("KeyedEvent");
    let output = guest::alloc_bytes(8);
    let status = object_types::create_type_ex(name, init, 0, output);
    let created = guest::read64(output);
    for block in [init, name, buffer, output] {
        guest::free_bytes(block);
    }
    if status != 0 {
        return Err(KernelError::with_status(alloc::format!("ObCreateObjectType(KeyedEvent): {status:#x}"), status));
    }
    Ok(created)
}

/// O descritor do ExpKeyedEventInitialization, self-relative no convidado.
fn descriptor() -> u64 {
    let policy = SecurityPolicy {
        dacl: Some(alloc::vec![Ace::allow(sid(1, &[0]), WORLD_ACCESS), Ace::allow(sid(5, &[32, 544]), KEYEDEVENT_ALL_ACCESS), Ace::allow(sid(5, &[18]), KEYEDEVENT_ALL_ACCESS)]),
        integrity: Some(LOW_INTEGRITY),
        ..SecurityPolicy::default()
    };
    let bytes = crate::ntos::se::object_security::encode(&policy, DACL_AND_LABEL);
    let pointer = guest::alloc_bytes(bytes.len() as u64);
    if pointer != 0 {
        guest::write_bytes(pointer, &bytes);
    }
    pointer
}

/// ExpKeyedEventInitialization: o tipo e o objeto permanente, uma vez.
pub fn initialize() -> Result<(), KernelError> {
    if CRIT_SEC_OUT_OF_MEMORY.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let object_type = create_type()?;
    KEYED_EVENT_TYPE.store(object_type, Ordering::Release);
    let (name, buffer) = unicode(CRIT_SEC_OUT_OF_MEMORY_EVENT);
    let security = descriptor();
    let attributes = guest::alloc_bytes(ObjectAttributes::SIZE);
    // SAFETY: OBJECT_ATTRIBUTES recém-alocado.
    let object_attributes = unsafe { ObjectAttributes::at(attributes) };
    object_attributes.length.set(ObjectAttributes::SIZE as u32);
    object_attributes.object_name.set(name);
    object_attributes.attributes.set(OBJ_PERMANENT);
    object_attributes.security_descriptor.set(security);
    let output = guest::alloc_bytes(16);
    let result = crate::ntos::ps::previous_mode::with_kernel(|| -> Result<(), KernelError> {
        let status = object_create::create(0, object_type, attributes, 0, KeyedEventObject::SIZE as u32, 0, 0, output);
        if status != 0 {
            return Err(KernelError::with_status(alloc::format!("NtCreateKeyedEvent: ObCreateObjectEx {status:#x}"), status));
        }
        let object = guest::read64(output);
        // SAFETY: corpo de 0x600 bytes recém-criado.
        let body = unsafe { KeyedEventObject::at(object) };
        for bucket in &body.buckets {
            bucket.lock.set(0);
            bucket.wait_list.flink.set(bucket.wait_list.address());
            bucket.wait_list.blink.set(bucket.wait_list.address());
        }
        let status = object_create::insert(object, KEYEDEVENT_ALL_ACCESS, 0, 0, output + 8)?;
        if status != 0 {
            return Err(KernelError::with_status(alloc::format!("NtCreateKeyedEvent: ObInsertObjectEx {status:#x}"), status));
        }
        // ObReferenceObjectByHandle e ZwClose: o kernel fica com a referência.
        object_header::reference(object, 1);
        CRIT_SEC_OUT_OF_MEMORY.store(object, Ordering::Release);
        crate::ntos::ob::close::close(guest::read64(output + 8), Some(0))?;
        Ok(())
    })
    .and_then(|result| result);
    for block in [name, buffer, security, attributes, output] {
        if block != 0 {
            guest::free_bytes(block);
        }
    }
    result
}
