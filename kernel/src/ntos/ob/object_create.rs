//! Criação de objetos — ObCreateObject, ObInsertObject e
//! ObDeleteCapturedInsertInfo.
//!
//! ObCreateObject aloca o corpo, conta-o no tipo e guarda os
//! OBJECT_ATTRIBUTES capturados até ObInsertObject (que publica o nome no
//! namespace e o handle em `handles::inserted`) ou ObDeleteCapturedInsertInfo
//! (que desfaz a contagem). ObCreateObjectType mora em `object_types`.

use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::ntos::inc::nt_abi::object_attributes;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::handles::inserted;
use crate::ntos::ob::object_manager::{self, ObjectData};
use crate::ntos::ob::object_types;
use crate::ntos::rtl::guest_strings;
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

const OBJ_KERNEL_HANDLE: u32 = 0x200;

/// Create-info captured by ObCreateObject, consumed by ObInsertObject or
/// freed by ObDeleteCapturedInsertInfo. Keyed by the object body pointer.
#[derive(Clone)]
struct Captured {
    type_pointer: u64,
    type_name: String,
    name: Option<String>,
    attributes: u32,
}

static CAPTURED: SpinLock<BTreeMap<u64, Captured>> = SpinLock::new(BTreeMap::new());

/// ObjectType of a created body still in CAPTURED or already in the inserted
/// handle table.
pub fn created_type(body: u64) -> Option<object_types::ObjectType> {
    if let Some(cap) = CAPTURED.lock().get(&body) {
        return object_types::find(cap.type_pointer);
    }
    let pointer = inserted::type_pointer_of(body)?;
    object_types::find(pointer)
}

// --- ObCreateObject -------------------------------------------------------
// NTSTATUS ObCreateObject(KPROCESSOR_MODE ProbeMode, POBJECT_TYPE Type,
//   POBJECT_ATTRIBUTES Attr, KPROCESSOR_MODE OwnerMode, PVOID Reserved,
//   ULONG BodySize, ULONG PagedCharge, ULONG NonPagedCharge, PVOID *Object)
//
// Allocates the object body, counts it on its type, and captures the
// OBJECT_ATTRIBUTES for a later ObInsertObject (RVA 0x7022d0 ->
// ObpAllocateObject stashes the captured create-info in the header).
pub fn create(type_ptr: u64, attr: u64, body_size: u32, out: u64) -> u32 {
    let Some(object_type) = object_types::find(type_ptr) else {
        return STATUS_INVALID_PARAMETER;
    };
    let body = guest::alloc_bytes(body_size.max(1) as u64);
    if body == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let (name, attributes) = if attr != 0 {
        let name_us = guest::read64(attr + object_attributes::OBJECT_NAME);
        let name = (name_us != 0).then(|| guest_strings::read_unicode_string(name_us)).filter(|name| !name.is_empty());
        (name, guest::read32(attr + object_attributes::ATTRIBUTES))
    } else {
        (None, 0)
    };
    // Count the new object on its type (ObpAllocateObject bumps TotalNumberOfObjects).
    let _ = object_types::account(&object_type.name, 1, 0);
    CAPTURED.lock().insert(body, Captured { type_pointer: type_ptr, type_name: object_type.name, name, attributes });
    if out != 0 {
        guest::write64(out, body);
    }
    STATUS_SUCCESS
}

// --- ObInsertObject -------------------------------------------------------
// NTSTATUS ObInsertObject(PVOID Object, PACCESS_STATE AccessState,
//   ACCESS_MASK DesiredAccess, ULONG Bias, PVOID *NewObject, PHANDLE Handle)
//
// Consumes the ObCreateObject create-info, inserts a named body into the
// namespace (best-effort, so the name is visible), and opens a handle in the
// current (or System, for OBJ_KERNEL_HANDLE) table.
pub fn insert(object: u64, desired: u32, new_object_out: u64, handle_out: u64) -> Result<u32, KernelError> {
    let Some(cap) = CAPTURED.lock().remove(&object) else {
        return Ok(STATUS_INVALID_PARAMETER);
    };
    let kernel = cap.attributes & OBJ_KERNEL_HANDLE != 0;

    // Best-effort namespace insertion for a fully-qualified name (\Dir\Leaf).
    if let Some(name) = cap.name.as_deref() {
        let trimmed = name.strip_prefix('\\').unwrap_or(name);
        let (parent, leaf) = trimmed.rsplit_once('\\').unwrap_or(("", trimmed));
        if !leaf.is_empty() {
            let parent_path = alloc::format!("\\{parent}");
            let _ = object_manager::create_object(&parent_path, leaf, &cap.type_name, Some(ObjectData::pointer(object)));
        }
    }

    let handle = inserted::insert(object, cap.type_pointer, cap.type_name, desired, cap.attributes & 7, kernel)?;
    if new_object_out != 0 {
        guest::write64(new_object_out, object);
    }
    if handle_out != 0 {
        guest::write64(handle_out, handle);
    }
    Ok(STATUS_SUCCESS)
}

// --- ObDeleteCapturedInsertInfo -------------------------------------------
// VOID ObDeleteCapturedInsertInfo(PVOID Object): frees the captured
// create-info when a created object is NOT inserted; undoes the object count.
pub fn delete_captured_insert_info(object: u64) {
    if let Some(cap) = CAPTURED.lock().remove(&object) {
        let _ = object_types::account(&cap.type_name, -1, 0);
    }
}
