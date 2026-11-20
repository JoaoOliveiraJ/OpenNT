//! ObDuplicateObject, ObCloseHandle e ObIsKernelHandle sobre os handles do
//! Object Manager (os de ObInsertObject e ObOpenObjectByPointer, com a linha
//! na HANDLE_TABLE do processo dono).
//!
//! Handles de kernel ficam na tabela do System e valem em qualquer
//! contexto; um handle de usuário só existe na tabela do processo dono.

use crate::ntos::ob::object_header::OpenReason;
use crate::ntos::ob::object_types::ObjectType;
use crate::ntos::ob::open_pointer::Described;
use crate::ntos::ob::{close, object_access, object_security, open_pointer};
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
const DUPLICATE_NO_RIGHTS_UPGRADE: u32 = 0x8;
/// O atributo de handle que proíbe cópias com direitos além dos dele (o
/// NoRightsUpgrade da HANDLE_TABLE_ENTRY, bit 8 do HandleAttributes que o
/// ObpReferenceProcessObjectByHandle devolve).
pub const HANDLE_NO_RIGHTS_UPGRADE: u32 = 0x8;
/// Os atributos que a linha do handle guarda: OBJ_PROTECT_CLOSE, OBJ_INHERIT,
/// OBJ_AUDIT_OBJECT_CLOSE e o [`HANDLE_NO_RIGHTS_UPGRADE`].
pub const HANDLE_ENTRY_ATTRIBUTES: u32 = 0xF;
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
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

/// Os atributos da cópia no ObDuplicateObject 19041 (0x5f535b..0x5f537b):
/// com DUPLICATE_SAME_ATTRIBUTES os da origem; senão os pedidos mais os
/// bits 2-3 da origem (OBJ_AUDIT_OBJECT_CLOSE e o
/// [`HANDLE_NO_RIGHTS_UPGRADE`], `edi |= src & 0xC`). DUPLICATE_NO_RIGHTS_UPGRADE
/// não recusa nada nesta cópia: só a marca com o bit 8.
pub fn duplicate_attributes(source_attributes: u32, requested: u32, options: u32) -> u32 {
    let attributes = if options & DUPLICATE_SAME_ATTRIBUTES != 0 { source_attributes } else { requested | (source_attributes & 0xC) };
    if options & DUPLICATE_NO_RIGHTS_UPGRADE != 0 {
        attributes | HANDLE_NO_RIGHTS_UPGRADE
    } else {
        attributes
    }
}

/// O acesso da cópia no ObDuplicateObject 19041: o da origem
/// (DUPLICATE_SAME_ACCESS) ou o pedido, com os GENERIC_* mapeados pelo
/// GenericMapping do tipo (RtlMapGenericMask, 0x5f5701) e cortado em
/// ValidAccessMask | ACCESS_SYSTEM_SECURITY (0x5f53c6..0x5f53d0, que também
/// tira o MAXIMUM_ALLOWED). Direitos além dos da origem (0x5f53e2) são
/// recusados quando o handle de origem tem o [`HANDLE_NO_RIGHTS_UPGRADE`]
/// (0x5f55e7) ou o tipo tem SecurityProcedure própria (0x5f55fb); senão o
/// SeCreateAccessState e o ObpGrantAccess(ObDuplicateHandle) no processo de
/// destino (anexado, 0x5f5608..0x5f5663) checam o pedido contra o descritor
/// de `item`, em KernelMode sem recusa. Sem `item` o descritor não é
/// conhecido e o pedido além da origem é recusado.
#[allow(clippy::too_many_arguments)]
pub fn duplicate_access(object_type: &ObjectType, item: Option<&Described>, source_access: u32, source_attributes: u32, desired: u32, options: u32, mode: u8, target: u64) -> Result<Result<u32, u32>, KernelError> {
    let mut access = if options & DUPLICATE_SAME_ACCESS != 0 { source_access } else { desired };
    if access & 0xF000_0000 != 0 {
        access = object_access::map_generic_access(access, object_type);
    }
    access &= object_type.valid_access | ACCESS_SYSTEM_SECURITY;
    if access & !source_access == 0 {
        return Ok(Ok(access));
    }
    if source_attributes & HANDLE_NO_RIGHTS_UPGRADE != 0 || !object_security::uses_default_security_method(object_type) {
        return Ok(Err(STATUS_ACCESS_DENIED));
    }
    let Some(item) = item else { return Ok(Err(STATUS_ACCESS_DENIED)) };
    if mode == 0 {
        return Ok(Ok(access));
    }
    let checked = object_security::has_descriptor(item);
    let policy = object_security::described_policy(item);
    attached(target, || object_access::check(&policy, object_access::subject(), access, object_type, !checked))
}

// --- ObDuplicateObject ----------------------------------------------------
// NTSTATUS ObDuplicateObject(PEPROCESS SourceProcess, HANDLE SourceHandle,
//   PEPROCESS TargetProcess, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
//   ULONG HandleAttributes, ULONG Options, KPROCESSOR_MODE PreviousMode)
//
// O handle de origem é procurado na tabela do processo de origem (anexado a
// ele); a cópia entra na tabela do destino (na do System com
// OBJ_KERNEL_HANDLE e PreviousMode KernelMode, para qualquer destino) como
// ObDuplicateHandle, com o acesso de [`duplicate_access`] (direitos além
// dos da origem passam pelo descritor no destino) e os atributos de
// [`duplicate_attributes`].
// DUPLICATE_CLOSE_SOURCE fecha a origem no processo de origem, também quando
// o destino é nulo.
#[allow(clippy::too_many_arguments)]
pub fn duplicate(source_process: u64, source_handle: u64, target_process: u64, target_handle_out: u64, desired: u32, handle_attributes: u32, options: u32, mode: u8) -> Result<u32, KernelError> {
    if options & !(DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES | DUPLICATE_NO_RIGHTS_UPGRADE) != 0 {
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
    let attributes = duplicate_attributes(resolved.attributes, handle_attributes & HANDLE_ATTRIBUTE_MASK, options);
    // OBJ_KERNEL_HANDLE em KernelMode troca o destino pelo System
    // (PsInitialSystemProcess, a tabela de handles de kernel), qualquer que
    // seja o TargetProcess; em UserMode o bit só é descartado.
    let kernel = handle_attributes & OBJ_KERNEL_HANDLE != 0 && mode == 0;
    let owner = if kernel { process::get_system_process() } else { target_process };
    let access = match duplicate_access(&resolved.item.object_type, Some(&resolved.item), resolved.access, resolved.attributes, desired, options, mode, owner)? {
        Ok(access) => access,
        Err(status) => return Ok(status),
    };
    let open_attributes = attributes | if kernel { OBJ_KERNEL_HANDLE } else { 0 };
    let identifier = open_pointer::insert_with(&resolved.item, access, open_attributes, owner, OpenReason::Duplicate, mode)?;
    let handle = if kernel { KERNEL_HANDLE_MASK | identifier as u64 } else { identifier as u64 };
    if target_handle_out != 0 {
        // O ObDuplicateObject 19041 grava `*TargetHandle` sem exigir
        // alinhamento: o NtDCompositionSendDwmLpcMessage do win32kbase troca
        // os handles no próprio lugar, dentro da mensagem, em endereços
        // alinhados a 4.
        crate::ntos::mm::guest_memory::write64(target_handle_out, handle);
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
