//! Eventos nomeados do I/O Manager (IoCreateNotificationEvent /
//! IoCreateSynchronizationEvent) — as rotinas do I/O Manager do NT para
//! eventos compartilhados entre drivers.
//!
//! Conferido contra o ntoskrnl 19041 (IoCreateNotificationEvent rva 0x78d410,
//! IoCreateSynchronizationEvent rva 0x893980): ZwCreateEvent(&Handle,
//! EVENT_ALL_ACCESS (0x1F0003), OBJECT_ATTRIBUTES { ObjectName = EventName,
//! Attributes = OBJ_OPENIF|OBJ_KERNEL_HANDLE (0x280) }, NotificationEvent (0) /
//! SynchronizationEvent (1), InitialState = TRUE); falha -> NULL sem tocar
//! *EventHandle. Depois ObReferenceObjectByHandle(ExEventObjectType) +
//! ObfDereferenceObject (o handle é o dono), *EventHandle = Handle e devolve
//! o KEVENT.
//!
//! Reuso: `ps::user::events::create` (KEVENT + corpo de dispatcher + nome no
//! Object Manager, o mesmo do NtCreateEvent) e `ob::open_pointer::open` para o
//! handle de kernel (o caminho do ObOpenObjectByPointer). O corpo nasce sem
//! referência, então o handle é a única posse: fechar o último handle libera o
//! evento e o nome, como no NT.

use alloc::string::String;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::NtStruct;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::{object_manager, object_types, open_pointer};
use crate::ntos::ps::user::events;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

pub const NOTIFICATION_EVENT: u32 = 0;
pub const SYNCHRONIZATION_EVENT: u32 = 1;
const EVENT_ALL_ACCESS: u32 = 0x1F_0003;
const OBJ_KERNEL_HANDLE: u32 = 0x200;

/// O ZwCreateEvent com OBJ_OPENIF e o handle de kernel em `handle_output`;
/// devolve o KEVENT ou 0 em qualquer falha.
pub fn create(name_pointer: u64, event_type: u32, handle_output: u64) -> Result<u64, KernelError> {
    let name = if name_pointer != 0 { guest_strings::read_unicode_string(name_pointer) } else { String::new() };
    let existing = if name.is_empty() { None } else { object_manager::lookup(&name) };
    let (pointer, created) = match existing {
        Some(node) => {
            // OBJ_OPENIF só reabre um Event; outro tipo é STATUS_OBJECT_TYPE_MISMATCH.
            let Some(node) = object_manager::node(node).filter(|node| node.type_name == "Event") else { return Ok(0) };
            let pointer = node.data.map_or(0, |data| data.native_pointer);
            if pointer == 0 {
                return Ok(0);
            }
            (pointer, false)
        }
        None => {
            if !name.is_empty() {
                let cut = name.rfind('\\').unwrap_or(0);
                let parent = if cut == 0 { "\\" } else { &name[..cut] };
                // STATUS_OBJECT_PATH_NOT_FOUND sem o diretório pai.
                if object_manager::lookup(parent).and_then(object_manager::node).is_none_or(|node| node.type_name != "Directory") {
                    return Ok(0);
                }
            }
            let pointer = guest::alloc_bytes(0x18);
            if pointer == 0 {
                return Ok(0);
            }
            // `create` libera o corpo nas próprias falhas.
            if events::create(pointer, &name, event_type, true, 0, false).is_err() {
                return Ok(0);
            }
            (pointer, true)
        }
    };
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        if created {
            dispatcher_objects::collect(pointer);
        }
        return Ok(0);
    }
    let status = open_pointer::open(pointer, OBJ_KERNEL_HANDLE, 0, EVENT_ALL_ACCESS, object_types::event_type().pointer, 0, slot)?;
    // SAFETY: célula HANDLE recém-alocada (slot).
    let handle = unsafe { Field::<u64>::at(slot) }.get();
    guest::free_bytes(slot);
    if status != 0 {
        if created {
            dispatcher_objects::collect(pointer);
        }
        return Ok(0);
    }
    // SAFETY: PHANDLE EventHandle de saída do chamador de modo kernel.
    unsafe { Field::<u64>::at(handle_output) }.set(handle);
    Ok(pointer)
}
