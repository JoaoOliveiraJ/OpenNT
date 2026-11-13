//! NtDuplicateObject de modo kernel (ZwDuplicateObject) — como no Ob do NT
//! (NtDuplicateObject -> ObDuplicateObject).
//!
//! Semântica do NT para PreviousMode = KernelMode:
//!   - Options só admite DUPLICATE_CLOSE_SOURCE (1), DUPLICATE_SAME_ACCESS (2) e
//!     DUPLICATE_SAME_ATTRIBUTES (4); outro bit = STATUS_INVALID_PARAMETER;
//!   - SourceProcessHandle/TargetProcessHandle são handles de processo
//!     (NtCurrentProcess = -1); outro tipo = STATUS_OBJECT_TYPE_MISMATCH;
//!   - TargetProcessHandle NULL só fecha a origem (DUPLICATE_CLOSE_SOURCE);
//!   - o novo handle recebe o acesso da origem (SAME_ACCESS) ou o DesiredAccess
//!     com os bits GENERIC_* mapeados pelo GENERIC_MAPPING do tipo, e os
//!     atributos da origem (SAME_ATTRIBUTES) ou HandleAttributes;
//!     OBJ_KERNEL_HANDLE com destino = System cria um handle de kernel;
//!   - DUPLICATE_CLOSE_SOURCE fecha o handle de origem depois de duplicar.
//!
//! Os handles com linha no Object Manager (arquivos, chaves, eventos,
//! seções, processos...) são duplicados pelo mesmo `open_pointer::insert` do
//! ObOpenObjectByPointer; os da tabela do ObInsertObject seguem pelo
//! `handles::inserted::duplicate` que o ObDuplicateObject do OpenNT já usa.
//! Diferença honesta: no modo kernel o OpenNT não refaz a checagem de acesso
//! contra o descritor do objeto quando o DesiredAccess excede o da origem
//! (o NT a faz no ObpIncrementHandleCount).

use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::ob::object_manager::{self, OpenOptions};
use crate::ntos::ob::open_pointer;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

const DUPLICATE_CLOSE_SOURCE: u32 = 1;
const DUPLICATE_SAME_ACCESS: u32 = 2;
const DUPLICATE_SAME_ATTRIBUTES: u32 = 4;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// OBJ_INHERIT | OBJ_PROTECT_CLOSE-equivalente dos atributos de handle.
const HANDLE_ATTRIBUTE_MASK: u32 = 0x7;
const NT_CURRENT_PROCESS: u64 = u64::MAX;
const KERNEL_HANDLE_BITS: u64 = 0xFFFF_FFFF_8000_0000;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;

/// Processo de um handle de processo (pseudo-handle incluído).
fn process_of(handle: u64) -> Result<u64, u32> {
    if handle == NT_CURRENT_PROCESS {
        return Ok(process::get_current_process());
    }
    match open_pointer::resolve(handle, false) {
        None => Err(STATUS_INVALID_HANDLE),
        Some(Err(status)) => Err(status),
        Some(Ok(resolved)) if resolved.item.object_type.name == "Process" => Ok(resolved.item.pointer),
        Some(Ok(_)) => Err(STATUS_OBJECT_TYPE_MISMATCH),
    }
}

/// Bits GENERIC_* pelo GENERIC_MAPPING do tipo (RtlMapGenericMask).
fn map_generic(desired: u32, mapping: &[u32; 4]) -> u32 {
    let mut access = desired & 0x0FFF_FFFF;
    for (bit, mapped) in [(0x8000_0000u32, mapping[0]), (0x4000_0000, mapping[1]), (0x2000_0000, mapping[2]), (0x1000_0000, mapping[3])] {
        if desired & bit != 0 {
            access |= mapped;
        }
    }
    access
}

/// PHANDLE de saída de um chamador de modo kernel (ZwDuplicateObject).
fn write_handle(target_handle: u64, handle: u64) {
    // SAFETY: PHANDLE de um chamador de modo kernel.
    unsafe { Field::<u64>::at(target_handle) }.set(handle);
}

fn close_source(handle: u64) -> Result<(), KernelError> {
    if open_pointer::close(handle).is_none() {
        crate::ntos::ob::close::close(handle, Some(0))?;
    }
    Ok(())
}

/// Handle com linha no Object Manager mas sem corpo nativo descrito (nós de
/// namespace): reabre o mesmo nó com as opções da origem; sem linha, segue
/// para a tabela do ObInsertObject.
fn duplicate_namespace_handle(source_handle: u64, target: u64, target_handle: u64, desired: u32, attributes: u32, options: u32) -> Result<u32, KernelError> {
    let value = source_handle & !3;
    let kernel_source = value & KERNEL_HANDLE_BITS == KERNEL_HANDLE_BITS;
    let record = if kernel_source || value <= 0x7FFF_FFFF { object_manager::handle_record((value & 0x7FFF_FFFF) as u32) } else { None };
    let Some(record) = record.filter(|record| record.options.kernel_handle == kernel_source && (kernel_source || record.options.owner_process.unwrap_or(0) == process::get_current_process())) else {
        return crate::ntos::ob::handles::inserted::duplicate(source_handle, target, target_handle, desired, attributes, options);
    };
    let access = if options & DUPLICATE_SAME_ACCESS != 0 { record.access } else { desired };
    let handle_attributes = if options & DUPLICATE_SAME_ATTRIBUTES != 0 { record.attributes } else { attributes & HANDLE_ATTRIBUTE_MASK };
    let kernel = attributes & OBJ_KERNEL_HANDLE != 0 && target == process::get_system_process();
    let open_options = OpenOptions {
        access: Some(access),
        attributes: Some(handle_attributes),
        open_attributes: Some(handle_attributes | if kernel { OBJ_KERNEL_HANDLE } else { 0 }),
        kernel_handle: kernel,
        owner_process: Some(if kernel { process::get_system_process() } else { target }),
        on_open: record.options.on_open.clone(),
        on_close: record.options.on_close.clone(),
        extra: record.options.extra.clone(),
    };
    let identifier = object_manager::open_object(record.node, Some(open_options))?;
    let handle = if kernel { KERNEL_HANDLE_BITS | identifier as u64 } else { identifier as u64 };
    if target_handle != 0 {
        write_handle(target_handle, handle);
    }
    if options & DUPLICATE_CLOSE_SOURCE != 0 {
        close_source(source_handle)?;
    }
    Ok(STATUS_SUCCESS)
}

/// ZwDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle,
/// TargetHandle*, DesiredAccess, HandleAttributes, Options).
#[allow(clippy::too_many_arguments)]
pub fn duplicate_object(source_process: u64, source_handle: u64, target_process: u64, target_handle: u64, desired: u32, attributes: u32, options: u32) -> Result<u32, KernelError> {
    if options & !(DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES) != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if let Err(status) = process_of(source_process) {
        return Ok(status);
    }
    if target_process == 0 {
        if options & DUPLICATE_CLOSE_SOURCE == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        close_source(source_handle)?;
        return Ok(STATUS_SUCCESS);
    }
    let target = match process_of(target_process) {
        Ok(target) => target,
        Err(status) => return Ok(status),
    };
    let resolved = match open_pointer::resolve(source_handle, false) {
        Some(Err(status)) => return Ok(status),
        Some(Ok(resolved)) => resolved,
        None => return duplicate_namespace_handle(source_handle, target, target_handle, desired, attributes, options),
    };
    let access = if options & DUPLICATE_SAME_ACCESS != 0 { resolved.access } else { map_generic(desired, &resolved.item.object_type.mapping) & (resolved.item.object_type.valid_access | 0x0100_0000) };
    let handle_attributes = if options & DUPLICATE_SAME_ATTRIBUTES != 0 { resolved.attributes } else { attributes & HANDLE_ATTRIBUTE_MASK };
    let kernel = attributes & OBJ_KERNEL_HANDLE != 0 && target == process::get_system_process();
    let owner = if kernel { process::get_system_process() } else { target };
    let open_attributes = handle_attributes | if kernel { OBJ_KERNEL_HANDLE } else { 0 };
    let identifier = open_pointer::insert(&resolved.item, access, open_attributes, owner)?;
    let handle = if kernel { KERNEL_HANDLE_BITS | identifier as u64 } else { identifier as u64 };
    if target_handle != 0 {
        write_handle(target_handle, handle);
    }
    if options & DUPLICATE_CLOSE_SOURCE != 0 {
        close_source(source_handle)?;
    }
    Ok(STATUS_SUCCESS)
}
