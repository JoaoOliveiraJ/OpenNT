//! O objeto Session de cada sessão (MmSessionObjectType), como no ntoskrnl
//! 19041:
//!
//! - o tipo "Session" do MiInitializeSessionIds (rva 0xa54d74): Length 0x78,
//!   UseDefaultObject e SecurityRequired, o GenericMapping MiSessionMapping
//!   {0x20001, 0x20002, 0x120001, 0xF0003}, ValidAccessMask 0xF0003 (mais
//!   SYNCHRONIZE pelo objeto padrão), NonPagedPoolNx com cobrança de 0x28 e o
//!   DeleteProcedure MiSessionObjectDelete;
//! - o MiSessionObjectCreate (rva 0x7862a4), do MiSessionCreate: o corpo de
//!   0x28 bytes (um KEVENT de notificação, o MM_SESSION_SPACE em +0x18 e o
//!   grupo de escalonamento em +0x20, nulo sem CPU fair share) nomeado
//!   `\KernelObjects\Session<id>` com a DACL Administrators/SYSTEM
//!   0xF0003, inserido com OBJ_KERNEL_HANDLE e acesso 1; o MM_SESSION_SPACE
//!   guarda o objeto (+0x48) e o handle (+0x50), ganha o bit 0x40 em
//!   LongFlags e uma ProcessReferenceToSession, e o IoState/IoNotification
//!   (IoState IO_SESSION_STATE_INITIALIZED, sequência 1, o evento de
//!   sincronização sinalizado);
//! - o MmGetSessionObjectById (rva 0x206324): o objeto da sessão, com uma
//!   referência, nulo numa sessão com DeletePending;
//! - o MiSessionObjectDelete (rva 0x8c8b20): devolve a ProcessReferenceTo
//!   Session do bit 0x40.
//!
//! O fim da sessão (MiDereferenceSessionFinal) fecha o handle e solta o
//! objeto antes de desfazer o MM_SESSION_SPACE.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::types::{Field, MmSessionSpace, NtStruct, ObjectAttributes, ObjectTypeInitializer, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_create, object_header, object_types};
use crate::ntos::se::model::sid;
use crate::rtl::KernelError;

/// O OBJECT_TYPE do tipo Session (MmSessionObjectType).
static SESSION_TYPE: AtomicU64 = AtomicU64::new(0);

/// MiSessionMapping.
const SESSION_MAPPING: [u32; 4] = [0x20001, 0x20002, 0x12_0001, 0xF_0003];
const SESSION_ALL_ACCESS: u32 = 0xF_0003;
/// UseDefaultObject (0x4) | SecurityRequired (0x8).
const TYPE_FLAGS: u16 = 0x0C;
const NON_PAGED_POOL_NX: u32 = 0x200;
const BODY_SIZE: u32 = 0x28;
/// OBJ_KERNEL_HANDLE.
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// O bit de LongFlags do MM_SESSION_SPACE com a referência do objeto.
const SESSION_OBJECT_REFERENCE: u32 = 0x40;

/// O corpo do objeto Session.
#[repr(C)]
struct SessionObject {
    event: crate::ntos::inc::types::Kevent,
    session: Field<u64>,
    scheduling_group: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SessionObject {}

const _: () = {
    assert!(core::mem::size_of::<SessionObject>() == 0x28);
    assert!(core::mem::offset_of!(SessionObject, session) == 0x18);
};

fn space(session: u64) -> &'static MmSessionSpace {
    // SAFETY: VA global de uma sessão viva (a primeira página).
    unsafe { MmSessionSpace::at(session) }
}

/// UNICODE_STRING do kernel com o texto (o chamador libera os dois blocos).
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

/// MiSessionObjectDelete: a ProcessReferenceToSession do objeto volta à
/// sessão (se ela ainda existe).
extern "win64" fn session_object_delete(object: u64) {
    // SAFETY: corpo do objeto Session sendo removido.
    let session = unsafe { SessionObject::at(object) }.session.get();
    if session == 0 || !super::session::is_live(session) {
        return;
    }
    let flags = space(session).u.long_flags.get();
    if flags & SESSION_OBJECT_REFERENCE != 0 {
        super::session::release_process_reference(session);
    }
}

/// O tipo Session, criado na primeira sessão (o MiInitializeSessionIds do
/// boot), pelo ObCreateObjectTypeEx.
pub fn session_type() -> u64 {
    let current = SESSION_TYPE.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    if let Some(existing) = object_types::by_name("Session") {
        SESSION_TYPE.store(existing.pointer, Ordering::Release);
        return existing.pointer;
    }
    let init = guest::alloc_bytes(ObjectTypeInitializer::SIZE);
    // SAFETY: OBJECT_TYPE_INITIALIZER recém-alocado e zerado.
    let initializer = unsafe { ObjectTypeInitializer::at(init) };
    initializer.length.set(ObjectTypeInitializer::SIZE as u16);
    initializer.object_type_flags.set(TYPE_FLAGS);
    let mapping = &initializer.generic_mapping;
    mapping.generic_read.set(SESSION_MAPPING[0]);
    mapping.generic_write.set(SESSION_MAPPING[1]);
    mapping.generic_execute.set(SESSION_MAPPING[2]);
    mapping.generic_all.set(SESSION_MAPPING[3]);
    initializer.valid_access_mask.set(SESSION_ALL_ACCESS);
    initializer.pool_type.set(crate::ntos::inc::types::PoolType(NON_PAGED_POOL_NX as i32));
    initializer.default_non_paged_pool_charge.set(BODY_SIZE);
    initializer.delete_procedure.set(session_object_delete as extern "win64" fn(u64) as usize as u64);
    let (name, buffer) = unicode("Session");
    let output = guest::alloc_bytes(8);
    let status = object_types::create_type_ex(name, init, 0, output);
    let created = if status == 0 { guest::read64(output) } else { object_types::by_name("Session").map_or(0, |existing| existing.pointer) };
    for block in [init, name, buffer, output] {
        guest::free_bytes(block);
    }
    SESSION_TYPE.store(created, Ordering::Release);
    created
}

/// O descritor do objeto: a DACL com Administrators e SYSTEM (0xF0003).
fn descriptor() -> u64 {
    let entries = [sid(5, &[32, 544]), sid(5, &[18])];
    let size = 8 + entries.iter().map(|entry| 8 + entry.len()).sum::<usize>();
    let mut acl = alloc::vec![0u8; 8];
    acl[0] = 2;
    acl[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    acl[4..6].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    for entry in &entries {
        acl.extend_from_slice(&[0, 0]);
        acl.extend_from_slice(&((8 + entry.len()) as u16).to_le_bytes());
        acl.extend_from_slice(&SESSION_ALL_ACCESS.to_le_bytes());
        acl.extend_from_slice(entry);
    }
    let owned = crate::ntos::se::policy_descriptor::OwnedDescriptor { control: 0x0004, owner: None, group: None, dacl: Some(acl), sacl: None };
    let bytes = crate::ntos::se::set_security::serialize_owned(&owned);
    let pointer = guest::alloc_bytes(bytes.len() as u64);
    guest::write_bytes(pointer, &bytes);
    pointer
}

/// MiSessionObjectCreate(Session): o objeto Session da sessão `session`
/// (a VA global do MM_SESSION_SPACE) e o handle de kernel dele.
pub fn create(session: u64) -> Result<(), KernelError> {
    let object_type = session_type();
    if object_type == 0 {
        return Err(KernelError::new("MmSessionObjectType ausente"));
    }
    let id = space(session).session_id.get();
    let (name, buffer) = unicode(&alloc::format!("\\KernelObjects\\Session{id}"));
    let security = descriptor();
    let attributes = guest::alloc_bytes(ObjectAttributes::SIZE);
    // SAFETY: OBJECT_ATTRIBUTES recém-alocado.
    let object_attributes = unsafe { ObjectAttributes::at(attributes) };
    object_attributes.length.set(ObjectAttributes::SIZE as u32);
    object_attributes.object_name.set(name);
    object_attributes.attributes.set(OBJ_KERNEL_HANDLE);
    object_attributes.security_descriptor.set(security);
    let output = guest::alloc_bytes(16);
    let result = crate::ntos::ps::previous_mode::with_kernel(|| -> Result<(), KernelError> {
        let status = object_create::create(0, object_type, attributes, 0, BODY_SIZE, 0, 0, output);
        if status != 0 {
            return Err(KernelError::with_status(alloc::format!("ObCreateObjectEx do objeto Session: {status:#x}"), status));
        }
        let object = guest::read64(output);
        // SAFETY: corpo de 0x28 bytes recém-criado.
        let body = unsafe { SessionObject::at(object) };
        crate::ntos::ke::dispatcher::initialize_event(body.event.address(), 0, false);
        body.session.set(session);
        body.scheduling_group.set(0);
        let status = object_create::insert(object, 1, 0, 0, output + 8)?;
        if status != 0 {
            return Err(KernelError::with_status(alloc::format!("ObInsertObjectEx do objeto Session: {status:#x}"), status));
        }
        let state = space(session);
        state.u.long_flags.set(state.u.long_flags.get() | SESSION_OBJECT_REFERENCE);
        state.process_reference_to_session.set(state.process_reference_to_session.get() + 1);
        state.session_object_handle.set(guest::read64(output + 8));
        state.session_object.set(object);
        state.io_state.set(crate::ntos::inc::types::IoSessionState::IO_SESSION_STATE_INITIALIZED);
        state.io_state_sequence.set(1);
        crate::ntos::ke::dispatcher::initialize_event(state.io_notification_event.address(), 1, true);
        Ok(())
    })
    .and_then(|result| result);
    for block in [name, buffer, security, attributes, output] {
        guest::free_bytes(block);
    }
    result
}

/// O fim do objeto com a sessão (MiDereferenceSessionFinal): o handle de
/// kernel fecha e a referência do MM_SESSION_SPACE sai.
pub fn release(session: u64) {
    let state = space(session);
    let (object, handle) = (state.session_object.get(), state.session_object_handle.get());
    state.session_object.set(0);
    state.session_object_handle.set(0);
    if handle != 0 {
        let _ = crate::ntos::ps::previous_mode::with_kernel(|| crate::ntos::ob::handles::inserted::close(handle, 0));
    }
    let _ = object;
}

/// MmGetSessionObjectById(SessionId): o objeto Session referenciado, ou 0
/// (sessão inexistente, com DeletePending ou sem objeto).
pub fn by_id(id: u32) -> u64 {
    let Some(session) = super::session::find(id) else { return 0 };
    let state = space(session);
    if state.u.flags.delete_pending() != 0 {
        return 0;
    }
    let object = state.session_object.get();
    if object != 0 && object_header::is_object(object) {
        object_header::reference(object, 1);
        return object;
    }
    0
}
