//! ObDuplicateObject, ObCloseHandle e ObIsKernelHandle sobre os handles do
//! Object Manager (os de ObInsertObject e ObOpenObjectByPointer, com a linha
//! na HANDLE_TABLE do processo dono).
//!
//! Handles de kernel ficam na tabela do System e valem em qualquer
//! contexto; um handle de usuário só existe na tabela do processo dono.

use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::ob::object_header::OpenReason;
use crate::ntos::ob::{close, open_pointer};
use crate::ntos::ps::{process, process_context};
use crate::rtl::KernelError;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// OBJ_PROTECT_CLOSE | OBJ_INHERIT | OBJ_AUDIT_OBJECT_CLOSE.
const HANDLE_ATTRIBUTE_MASK: u32 = 0x7;
const DUPLICATE_CLOSE_SOURCE: u32 = 0x1;
const DUPLICATE_SAME_ACCESS: u32 = 0x2;
const DUPLICATE_SAME_ATTRIBUTES: u32 = 0x4;
const KERNEL_HANDLE_MASK: u64 = 0xFFFF_FFFF_8000_0000;

// --- ObIsKernelHandle -----------------------------------------------------
// BOOLEAN ObIsKernelHandle(HANDLE Handle): the kernel-handle bit is set and
// the handle is not a pseudo-handle (-1..-6).
pub fn is_kernel_handle(handle: u64) -> bool {
    handle & KERNEL_HANDLE_MASK == KERNEL_HANDLE_MASK && !(-6..=-1).contains(&(handle as i64))
}

/// Roda `body` no contexto de `target` (o KeStackAttachProcess do
/// ObDuplicateObject); no processo corrente, sem attach.
fn attached<T>(target: u64, body: impl FnOnce() -> T) -> Result<T, KernelError> {
    if target == 0 || target == process::get_current_process() {
        return Ok(body());
    }
    process_context::with_process(target, body)
}

// --- ObDuplicateObject ----------------------------------------------------
// NTSTATUS ObDuplicateObject(PEPROCESS SourceProcess, HANDLE SourceHandle,
//   PEPROCESS TargetProcess, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
//   ULONG HandleAttributes, ULONG Options, KPROCESSOR_MODE PreviousMode)
//
// O handle de origem é procurado na tabela do processo de origem (anexado a
// ele); a cópia entra na tabela do destino (do System com OBJ_KERNEL_HANDLE)
// como ObDuplicateHandle, com o acesso da origem (DUPLICATE_SAME_ACCESS) ou o
// pedido — em UserMode, direitos que a origem não tem são negados — e os
// atributos da origem (DUPLICATE_SAME_ATTRIBUTES) ou os pedidos.
// DUPLICATE_CLOSE_SOURCE fecha a origem no processo de origem, também quando
// o destino é nulo.
#[allow(clippy::too_many_arguments)]
pub fn duplicate(source_process: u64, source_handle: u64, target_process: u64, target_handle_out: u64, desired: u32, handle_attributes: u32, options: u32, mode: u8) -> Result<u32, KernelError> {
    if options & !(DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES) != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let source = if source_process != 0 { source_process } else { process::get_current_process() };
    let close_source = || -> Result<(), KernelError> {
        attached(source, || close::close(source_handle, Some(mode)))??;
        Ok(())
    };
    let resolved = attached(source, || open_pointer::resolve(source_handle, mode != 0))?;
    let resolved = match resolved {
        Some(Ok(resolved)) => resolved,
        Some(Err(status)) => return Ok(status),
        None => return Ok(STATUS_INVALID_HANDLE),
    };
    if target_process == 0 {
        if options & DUPLICATE_CLOSE_SOURCE == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        close_source()?;
        return Ok(STATUS_SUCCESS);
    }
    let access = if options & DUPLICATE_SAME_ACCESS != 0 { resolved.access } else { crate::ntos::ob::object_access::map_generic_access(desired, &resolved.item.object_type) };
    if mode != 0 && access & !resolved.access != 0 {
        return Ok(STATUS_ACCESS_DENIED);
    }
    let attributes = if options & DUPLICATE_SAME_ATTRIBUTES != 0 { resolved.attributes } else { handle_attributes & HANDLE_ATTRIBUTE_MASK };
    let kernel = handle_attributes & OBJ_KERNEL_HANDLE != 0 && target_process == process::get_system_process();
    let owner = if kernel { process::get_system_process() } else { target_process };
    let open_attributes = attributes | if kernel { OBJ_KERNEL_HANDLE } else { 0 };
    let identifier = open_pointer::insert_with(&resolved.item, access, open_attributes, owner, OpenReason::Duplicate, mode)?;
    let handle = if kernel { KERNEL_HANDLE_MASK | identifier as u64 } else { identifier as u64 };
    if target_handle_out != 0 {
        // SAFETY: PHANDLE TargetHandle de um chamador de kernel.
        unsafe { Field::<u64>::at(target_handle_out) }.set(handle);
    }
    if options & DUPLICATE_CLOSE_SOURCE != 0 {
        close_source()?;
    }
    Ok(STATUS_SUCCESS)
}

// --- ObCloseHandle --------------------------------------------------------
// NTSTATUS ObCloseHandle(HANDLE Handle, KPROCESSOR_MODE Mode): o NtClose com
// o modo explícito.
pub fn close(handle: u64, mode: u8) -> Result<u32, KernelError> {
    close::close(handle, Some(mode))
}
