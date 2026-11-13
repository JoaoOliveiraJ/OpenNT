//! Handles dos objetos inseridos por ObInsertObject — a referência com tag,
//! ObDuplicateObject, ObCloseHandle e ObIsKernelHandle.
//!
//! Cada handle guarda o corpo, o tipo, o acesso concedido e o processo dono.
//! Handles de kernel ficam na tabela do System e valem em qualquer contexto;
//! um handle de usuário só existe para o processo dono. Os handles comuns do
//! Object Manager seguem pelos caminhos de `object_reference` e `close`.

use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::ntos::inc::types::{Field, NtStruct, ObjectHandleInformation};
use crate::ntos::ob::{close, handle_ids, object_types, reference_trace};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

const OBJ_KERNEL_HANDLE: u32 = 0x200;
const DUPLICATE_CLOSE_SOURCE: u32 = 0x0000_0001;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
const KERNEL_HANDLE_MASK: u64 = 0xFFFF_FFFF_8000_0000;

/// One published object handle (the body plus its granted access).
#[derive(Clone)]
struct InsertedHandle {
    body: u64,
    type_pointer: u64,
    type_name: String,
    access: u32,
    attributes: u32,
    owner: u64,
    kernel: bool,
}

static HANDLES: SpinLock<BTreeMap<u64, InsertedHandle>> = SpinLock::new(BTreeMap::new());

fn kernel_handle(id: u32) -> u64 {
    KERNEL_HANDLE_MASK | id as u64
}

// --- ObIsKernelHandle -----------------------------------------------------
// BOOLEAN ObIsKernelHandle(HANDLE Handle): the kernel-handle bit is set and
// the handle is not a pseudo-handle (-1..-6).
pub fn is_kernel_handle(handle: u64) -> bool {
    handle & KERNEL_HANDLE_MASK == KERNEL_HANDLE_MASK && !(-6..=-1).contains(&(handle as i64))
}

/// O handle está na tabela de quem chama? Handles de kernel ficam na tabela
/// do System e valem em qualquer contexto; um handle de usuário só existe
/// na tabela do processo dono — como no NT, outro processo não o enxerga
/// (e recebe STATUS_INVALID_HANDLE pelo caminho comum do Object Manager).
fn visible(entry: &InsertedHandle) -> bool {
    entry.kernel || entry.owner == process::get_current_process()
}

/// Publica o handle de um corpo inserido por ObInsertObject, na tabela do
/// processo corrente (ou do System, para OBJ_KERNEL_HANDLE).
pub fn insert(body: u64, type_pointer: u64, type_name: String, access: u32, attributes: u32, kernel: bool) -> Result<u64, KernelError> {
    let id = handle_ids::allocate(4)?;
    let handle = if kernel { kernel_handle(id) } else { id as u64 };
    let owner = if kernel { process::get_system_process() } else { process::get_current_process() };
    // Count the handle on the type (ObpIncrementHandleCount).
    let _ = object_types::account(&type_name, 0, 1);
    HANDLES.lock().insert(handle, InsertedHandle { body, type_pointer, type_name, access, attributes, owner, kernel });
    Ok(handle)
}

/// Tipo (ponteiro do OBJECT_TYPE) de um corpo que já tem handle publicado.
pub fn type_pointer_of(body: u64) -> Option<u64> {
    HANDLES.lock().values().find(|entry| entry.body == body).map(|entry| entry.type_pointer)
}

/// Referência com tag por um handle desta tabela (ObReferenceObjectByHandleWithTag):
/// `None` quando o handle não é daqui ou não é visível para quem chama.
pub fn reference(handle: u64, access: u32, object_type: u64, mode: u8, tag: u32, out: u64, info: u64) -> Option<u32> {
    if let Some(entry) = HANDLES.lock().get(&handle).cloned().filter(visible) {
        if object_type != 0 && object_type != entry.type_pointer {
            return Some(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if mode != 0 && access & !entry.access != 0 {
            return Some(STATUS_ACCESS_DENIED);
        }
        reference_trace::record(entry.body, tag, 1);
        let _ = object_types::account(&entry.type_name, 1, 0);
        // SAFETY: PVOID* Object e POBJECT_HANDLE_INFORMATION de um chamador de kernel.
        unsafe { Field::<u64>::at(out) }.set(entry.body);
        if info != 0 {
            let info = unsafe { ObjectHandleInformation::at(info) };
            info.handle_attributes.set(entry.attributes);
            info.granted_access.set(entry.access);
        }
        return Some(STATUS_SUCCESS);
    }
    None
}

// --- ObDuplicateObject ----------------------------------------------------
// NTSTATUS ObDuplicateObject(PEPROCESS Source, HANDLE SourceHandle,
//   PEPROCESS Target, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
//   ULONG HandleAttributes, ULONG Options, KPROCESSOR_MODE Mode)
//
// Minimal cross-process path over this handle table: resolve the
// source body, publish a new handle owned by Target, honor
// DUPLICATE_SAME_ACCESS / DUPLICATE_CLOSE_SOURCE. Standard (Object-Manager)
// handles are not duplicated here — see LIMITATIONS.
pub fn duplicate(source_handle: u64, target_process: u64, target_handle_out: u64, desired: u32, handle_attributes: u32, options: u32) -> Result<u32, KernelError> {
    let Some(entry) = HANDLES.lock().get(&source_handle).cloned().filter(visible) else {
        return Ok(STATUS_INVALID_HANDLE);
    };
    let access = if options & DUPLICATE_SAME_ACCESS != 0 { entry.access } else { desired };
    let kernel = handle_attributes & OBJ_KERNEL_HANDLE != 0 || entry.kernel;
    let id = handle_ids::allocate(4)?;
    let handle = if kernel { kernel_handle(id) } else { id as u64 };
    let owner = if kernel {
        process::get_system_process()
    } else if target_process != 0 {
        target_process
    } else {
        process::get_current_process()
    };
    let _ = object_types::account(&entry.type_name, 0, 1);
    HANDLES.lock().insert(handle, InsertedHandle { body: entry.body, type_pointer: entry.type_pointer, type_name: entry.type_name.clone(), access, attributes: handle_attributes & 7, owner, kernel });
    if options & DUPLICATE_CLOSE_SOURCE != 0 {
        if let Some(source) = HANDLES.lock().remove(&source_handle) {
            let _ = object_types::account(&source.type_name, 0, -1);
        }
    }
    if target_handle_out != 0 {
        // SAFETY: PHANDLE TargetHandle de um chamador de kernel.
        unsafe { Field::<u64>::at(target_handle_out) }.set(handle);
    }
    Ok(STATUS_SUCCESS)
}

// --- ObCloseHandle --------------------------------------------------------
// NTSTATUS ObCloseHandle(HANDLE Handle, KPROCESSOR_MODE Mode): same path as
// NtClose with an explicit mode. Handles of this table leave it;
// everything else delegates to close::close.
pub fn close(handle: u64, mode: u8) -> Result<u32, KernelError> {
    // Só fecha um handle da tabela de quem chama; o de outro processo segue
    // para o close comum, que o recusa.
    let removed = {
        let mut handles = HANDLES.lock();
        match handles.get(&handle) {
            Some(entry) if visible(entry) => handles.remove(&handle),
            _ => None,
        }
    };
    if let Some(entry) = removed {
        let _ = object_types::account(&entry.type_name, 0, -1);
        return Ok(STATUS_SUCCESS);
    }
    close::close(handle, Some(mode))
}
