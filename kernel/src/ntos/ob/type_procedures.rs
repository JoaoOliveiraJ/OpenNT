//! As rotinas do OBJECT_TYPE_INITIALIZER de um tipo, chamadas pelo Object
//! Manager nos pontos em que o ntoskrnl 19041 as chama (ABI MS x64):
//!
//! - OpenProcedure(OpenReason, AccessMode, Process, Object, &GrantedAccess,
//!   HandleCount) na abertura de cada handle (ObpIncrementHandleCountEx),
//!   depois de o HandleCount subir; uma falha desfaz a abertura.
//! - CloseProcedure(Process, Object, ProcessHandleCount, SystemHandleCount)
//!   em cada fechamento (ObpDecrementHandleCount/ObCloseHandleTableEntry),
//!   com as contagens anteriores ao fechamento.
//! - OkayToCloseProcedure(Process, Object, Handle, PreviousMode) antes do
//!   fechamento; FALSE recusa com STATUS_HANDLE_NOT_CLOSABLE.
//! - DeleteProcedure(Object) na remoção (ObpRemoveObjectRoutine), em
//!   PASSIVE_LEVEL.
//! - SecurityProcedure(Object, OperationCode, SecurityInformation,
//!   SecurityDescriptor, CapturedLength, ObjectsSecurityDescriptor,
//!   PoolType, GenericMapping, Mode).
//! - QueryNameProcedure(Object, HasObjectName, ObjectNameInfo, Length,
//!   ReturnLength, Mode) no ObQueryNameString.
//!
//! Open e Close rodam anexados ao processo do handle quando ele não é o
//! corrente (Open não anexa na herança), como o KiStackAttachProcess do NT.

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{Field, NtStruct, ObjectType as NativeObjectType};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_header::{HandleOpen, OpenReason};
use crate::ntos::ps::{process, process_context};

/// SECURITY_OPERATION_CODE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SecurityOperation {
    Set = 0,
    Query = 1,
    Delete = 2,
    Assign = 3,
}

fn native(object_type: u64) -> &'static NativeObjectType {
    // SAFETY: OBJECT_TYPE vivo (decodificado da ObTypeIndexTable).
    unsafe { NativeObjectType::at(object_type) }
}

/// Roda `body` anexado a `target` quando ele não é o processo corrente (e
/// se puder ser anexado; um processo já desmontado roda no corrente).
fn attached<T>(target: u64, attach: bool, body: impl FnOnce() -> T) -> T {
    if !attach || target == 0 || target == process::get_current_process() {
        return body();
    }
    let mut body = Some(body);
    let mut result = None;
    let _ = process_context::with_process(target, || {
        if let Some(body) = body.take() {
            result = Some(body());
        }
    });
    match (result, body) {
        (Some(value), _) => value,
        (None, Some(body)) => body(),
        (None, None) => unreachable!("rotina de tipo sem resultado"),
    }
}

/// OpenProcedure: `Ok(())` sem rotina; o acesso concedido que a rotina
/// devolve substitui o da abertura.
pub fn open(object_type: u64, body: u64, open: &mut HandleOpen, handle_count: u32) -> Result<(), u32> {
    let routine = native(object_type).type_info.open_procedure.get();
    if routine == 0 {
        return Ok(());
    }
    let granted = guest::alloc_bytes(4);
    if granted == 0 {
        return Err(0xC000_009A);
    }
    // SAFETY: célula recém-alocada do kernel.
    let cell = unsafe { Field::<u32>::at(granted) };
    cell.set(open.granted);
    let arguments = [open.reason as u64, open.access_mode as u64, open.process, body, granted, handle_count as u64];
    let status = attached(open.process, open.reason != OpenReason::Inherit, || native_call::call(routine, &arguments)) as u32;
    open.granted = cell.get();
    guest::free_bytes(granted);
    if status as i32 >= 0 {
        Ok(())
    } else {
        Err(status)
    }
}

/// CloseProcedure com as contagens anteriores ao fechamento.
pub fn close(object_type: u64, process: u64, body: u64, process_count: u32, system_count: u64) {
    let routine = native(object_type).type_info.close_procedure.get();
    if routine != 0 {
        attached(process, true, || native_call::call(routine, &[process, body, process_count as u64, system_count]));
    }
}

/// OkayToCloseProcedure: TRUE sem rotina.
pub fn okay_to_close(object_type: u64, process: u64, body: u64, handle: u64, previous_mode: u8) -> bool {
    let routine = native(object_type).type_info.okay_to_close_procedure.get();
    if routine == 0 {
        return true;
    }
    attached(process, true, || native_call::call(routine, &[process, body, handle, previous_mode as u64])) as u8 != 0
}

/// DeleteProcedure(Object).
pub fn delete(object_type: u64, body: u64) -> bool {
    let routine = native(object_type).type_info.delete_procedure.get();
    if routine != 0 {
        native_call::call(routine, &[body]);
    }
    routine != 0
}

/// SecurityProcedure; devolve o NTSTATUS (sem rotina, STATUS_SUCCESS).
#[allow(clippy::too_many_arguments)]
pub fn security(object_type: u64, body: u64, operation: SecurityOperation, information: u64, descriptor: u64, captured_length: u64, objects_descriptor: u64, pool_type: u32, mode: u8) -> u32 {
    let info = &native(object_type).type_info;
    let routine = info.security_procedure.get();
    if routine == 0 {
        return 0;
    }
    let arguments = [body, operation as u64, information, descriptor, captured_length, objects_descriptor, pool_type as u64, info.generic_mapping.address(), mode as u64];
    native_call::call(routine, &arguments) as u32
}

/// QueryNameProcedure; `None` quando o tipo não tem rotina.
pub fn query_name(object_type: u64, body: u64, has_name: bool, buffer: u64, length: u32, return_length: u64, mode: u8) -> Option<u32> {
    let routine = native(object_type).type_info.query_name_procedure.get();
    if routine == 0 {
        return None;
    }
    Some(native_call::call(routine, &[body, has_name as u64, buffer, length as u64, return_length, mode as u64]) as u32)
}
