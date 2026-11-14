//! Objeto evento do Executive: a célula de ExEventObjectType e os serviços
//! de evento em modo kernel (ZwCreateEvent, ZwOpenEvent, ZwSetEvent,
//! ZwResetEvent, ZwClearEvent).
//!
//! ExEventObjectType é um export de dados da `.kdata` (POBJECT_TYPE): a
//! célula guarda o mesmo OBJECT_TYPE "Event" do Object Manager que o
//! ObReferenceObjectByHandle compara, então um driver que referencia um
//! handle de evento com `*ExEventObjectType` recebe o KEVENT.
//!
//! Os serviços seguem o NtCreateEvent/NtSetEvent do 19041 chamados com
//! PreviousMode = KernelMode: a criação inicializa o KEVENT (corpo de
//! dispatcher de `ps/user/events`, com o nome no namespace) e publica o
//! handle pelo ObOpenObjectByPointer (`ob/open_pointer`), na tabela do
//! System quando OBJ_KERNEL_HANDLE; as operações referenciam o handle com
//! EVENT_MODIFY_STATE e o tipo do evento (ObReferenceObjectByHandle), chamam
//! KeSetEvent/KeResetEvent/KeClearEvent e devolvem o estado anterior.

use alloc::string::String;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::ObjectAttributes;
use crate::ntos::init::exports::signed_status;
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_data;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::{object_manager, object_reference, object_types, open_pointer, reference_trace};
use crate::ntos::ps::user::events;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
/// EVENT_MODIFY_STATE.
const EVENT_MODIFY_STATE: u32 = 2;
/// OBJ_OPENIF.
const OBJ_OPENIF: u32 = 0x80;
/// SynchronizationEvent: o maior EVENT_TYPE aceito.
const SYNCHRONIZATION_EVENT: u32 = 1;

/// Endereço da célula de ExEventObjectType (`.kdata`), com o OBJECT_TYPE
/// "Event" do Object Manager.
pub fn event_object_type() -> u64 {
    let type_pointer = object_types::event_type().pointer;
    if kernel_data::read("ExEventObjectType") != type_pointer {
        kernel_data::write("ExEventObjectType", type_pointer);
    }
    kernel_data::required_address("ExEventObjectType")
}

fn object_name(attributes: u64) -> String {
    // SAFETY: ZwOpenEvent recebe POBJECT_ATTRIBUTES de modo kernel.
    guest_strings::read_unicode_string(unsafe { ObjectAttributes::at(attributes) }.object_name.get())
}

/// ZwOpenEvent: evento nomeado do namespace. Devolve o valor nativo do
/// export: o nome inexistente sai como NTSTATUS estendido com sinal e o
/// status da abertura sai estendido com zeros.
pub fn open(output: u64, access: u32, attributes: u64) -> Result<u64, KernelError> {
    let node = object_manager::lookup(&object_name(attributes)).filter(|&node| object_manager::node(node).is_some_and(|node| node.type_name == "Event"));
    let Some(node) = node else { return Ok(signed_status(STATUS_OBJECT_NAME_NOT_FOUND)) };
    Ok(zw_files::open_kernel_object(output, node, access, attributes)? as u64)
}

/// Publica um handle do KEVENT `pointer` com os atributos do chamador.
fn publish_handle(pointer: u64, flags: u32, access: u32, handle_output: u64) -> Result<u32, KernelError> {
    open_pointer::open(pointer, flags, 0, access, object_types::event_type().pointer, 0, handle_output)
}

/// ZwCreateEvent(EventHandle, DesiredAccess, ObjectAttributes, EventType,
/// InitialState): o NtCreateEvent em KernelMode. Um nome existente só é
/// reaberto com OBJ_OPENIF (STATUS_OBJECT_NAME_EXISTS) e se for um evento.
pub fn create(handle_output: u64, access: u32, attributes: u64, event_type: u32, initial_state: bool) -> Result<u32, KernelError> {
    if event_type > SYNCHRONIZATION_EVENT {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: POBJECT_ATTRIBUTES opcional de um chamador de modo kernel.
    let (flags, named) = if attributes != 0 { (unsafe { ObjectAttributes::at(attributes) }.attributes.get(), unsafe { ObjectAttributes::at(attributes) }.object_name.get() != 0) } else { (0, false) };
    let name = if named {
        match zw_files::file_path_from_object_attributes(attributes) {
            Ok(name) => name,
            Err(status) => return Ok(status),
        }
    } else {
        String::new()
    };
    if !name.is_empty() {
        if let Some(existing) = object_manager::lookup(&name) {
            let Some(node) = object_manager::node(existing) else { return Ok(STATUS_OBJECT_NAME_NOT_FOUND) };
            if node.type_name != "Event" {
                return Ok(STATUS_OBJECT_TYPE_MISMATCH);
            }
            if flags & OBJ_OPENIF == 0 {
                return Ok(STATUS_OBJECT_NAME_COLLISION);
            }
            let pointer = node.data.map_or(0, |data| data.native_pointer);
            let status = publish_handle(pointer, flags, access, handle_output)?;
            return Ok(if status != 0 { status } else { STATUS_OBJECT_NAME_EXISTS });
        }
        let cut = name.rfind('\\').unwrap_or(0);
        let parent = if cut == 0 { "\\" } else { &name[..cut] };
        if object_manager::lookup(parent).and_then(object_manager::node).is_none_or(|node| node.type_name != "Directory") {
            return Ok(STATUS_OBJECT_PATH_NOT_FOUND);
        }
    }
    let pointer = guest::alloc_bytes(0x18);
    if pointer == 0 {
        return Ok(STATUS_NO_MEMORY);
    }
    // `create` devolve o corpo ao pool nas próprias falhas.
    if let Err(error) = events::create(pointer, &name, event_type, initial_state, 0, false) {
        return if error.status != 0 { Ok(error.status) } else { Err(error) };
    }
    let status = publish_handle(pointer, flags, access, handle_output)?;
    if status != 0 {
        // Sem handle, ninguém retém o corpo.
        dispatcher_objects::collect(pointer);
    }
    Ok(status)
}

/// Referencia o KEVENT do handle (ObReferenceObjectByHandle com
/// EVENT_MODIFY_STATE, ExEventObjectType e KernelMode), executa `operation`
/// e solta a referência. Devolve o NTSTATUS da referência ou o valor da
/// operação.
fn with_event<T>(handle: u64, operation: impl FnOnce(u64) -> T) -> Result<Result<T, u32>, KernelError> {
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(Err(0xC000_009A));
    }
    let status = object_reference::reference_by_handle(handle, EVENT_MODIFY_STATE, object_types::event_type().pointer, 0, slot, 0)? as u32;
    // SAFETY: célula PVOID recém-alocada.
    let pointer = unsafe { Field::<u64>::at(slot) }.get();
    guest::free_bytes(slot);
    if status & 0x8000_0000 != 0 {
        return Ok(Err(status));
    }
    let value = operation(pointer);
    object_reference::dereference_with_tag(pointer, reference_trace::DEFAULT_TAG, false)?;
    Ok(Ok(value))
}

/// Grava o LONG *PreviousState opcional de um chamador de modo kernel.
fn write_previous(previous: u64, value: u32) {
    if previous != 0 {
        // SAFETY: PLONG de saída de um chamador de modo kernel.
        unsafe { Field::<u32>::at(previous) }.set(value);
    }
}

/// ZwSetEvent(EventHandle, PreviousState): KeSetEvent.
pub fn set(handle: u64, previous: u64) -> Result<u32, KernelError> {
    Ok(match with_event(handle, dispatcher::set_event)? {
        Ok(state) => {
            write_previous(previous, state);
            0
        }
        Err(status) => status,
    })
}

/// ZwResetEvent(EventHandle, PreviousState): KeResetEvent.
pub fn reset(handle: u64, previous: u64) -> Result<u32, KernelError> {
    Ok(match with_event(handle, dispatcher::reset_event)? {
        Ok(state) => {
            write_previous(previous, state);
            0
        }
        Err(status) => status,
    })
}

/// ZwClearEvent(EventHandle): KeClearEvent.
pub fn clear(handle: u64) -> Result<u32, KernelError> {
    Ok(match with_event(handle, dispatcher::clear_event)? {
        Ok(()) => 0,
        Err(status) => status,
    })
}
