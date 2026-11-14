//! ObSetHandleAttributes: troca o Inherit e o ProtectFromClose de um handle
//! (o OBJECT_HANDLE_FLAG_INFORMATION de um chamador de kernel), e o
//! NtSetInformationObject desse caminho (ObjectHandleFlagInformation), que o
//! ZwSetInformationObject chama com PreviousMode KernelMode; e a
//! ObjectSessionInformation (o SessionId de um diretório), dos dois modos.
//!
//! Como no NT, um handle de kernel (prefixo OBJ_KERNEL_HANDLE) só vale com
//! PreviousMode KernelMode e é procurado na tabela do System; os demais, na
//! tabela do processo corrente (o anexado, durante um attach). Um handle que
//! a tabela não tem é STATUS_ACCESS_DENIED (o ExMapHandleToPointer não o
//! achou). Pedir Inherit num objeto cujo tipo proíbe OBJ_INHERIT
//! (InvalidAttributes) não muda nada e devolve sucesso.

use crate::ntos::inc::types::{NtStruct, ObjectHandleFlagInformation};
use crate::ntos::ob::object_types;
use crate::ntos::ps::user::state;
use crate::ntos::ps::{process, process_context};
use crate::rtl::KernelError;

const KERNEL_HANDLE_MASK: u64 = 0xFFFF_FFFF_8000_0000;
/// OBJ_PROTECT_CLOSE e OBJ_INHERIT nos atributos do handle.
const OBJ_PROTECT_CLOSE: u32 = 1;
const OBJ_INHERIT: u32 = 2;
/// OBJECT_INFORMATION_CLASS.ObjectHandleFlagInformation.
const OBJECT_HANDLE_FLAG_INFORMATION: u32 = 4;
/// OBJECT_INFORMATION_CLASS.ObjectSessionInformation.
const OBJECT_SESSION_INFORMATION: u32 = 5;
/// SE_TCB_PRIVILEGE.
const SE_TCB_PRIVILEGE: u64 = 7;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;

/// Os atributos na tabela corrente: ExSetHandleAttributes com a máscara
/// OBJ_INHERIT | OBJ_PROTECT_CLOSE.
fn apply(handle: u64, inherit: bool, protect_from_close: bool) -> Result<u32, KernelError> {
    let Some(entry) = state::get_user_handle(handle) else { return Ok(STATUS_ACCESS_DENIED) };
    if inherit && object_types::user_type(entry.kind()).is_some_and(|object_type| object_types::invalid_attributes(&object_type) & OBJ_INHERIT != 0) {
        return Ok(0);
    }
    let attributes = (if inherit { OBJ_INHERIT } else { 0 }) | (if protect_from_close { OBJ_PROTECT_CLOSE } else { 0 });
    Ok(match state::change_user_handle_attributes(handle, attributes)? {
        STATUS_INVALID_HANDLE => STATUS_ACCESS_DENIED,
        status => status,
    })
}

/// ObSetHandleAttributes(Handle, HandleFlags, PreviousMode).
pub fn set_handle_attributes(handle: u64, flags: &ObjectHandleFlagInformation, previous_mode: u8) -> Result<u32, KernelError> {
    let (inherit, protect_from_close) = (flags.inherit.get() != 0, flags.protect_from_close.get() != 0);
    if previous_mode == 0 && handle & KERNEL_HANDLE_MASK == KERNEL_HANDLE_MASK {
        return process_context::with_process(process::get_system_process(), || apply(handle, inherit, protect_from_close))?;
    }
    apply(handle, inherit, protect_from_close)
}

/// NtSetInformationObject(ObjectSessionInformation, 5), o ramo do
/// NtSetInformationObject 19041: com SeTcbPrivilege (STATUS_PRIVILEGE_NOT_HELD
/// sem ele; KernelMode sempre o tem), o diretório do handle, referenciado
/// sem acesso pedido pelo tipo Directory, passa a ser da sessão de quem
/// chama (OBJECT_DIRECTORY.SessionId, no corpo do diretório). Nem buffer nem
/// comprimento são lidos. Um handle de outro tipo é
/// STATUS_OBJECT_TYPE_MISMATCH. No NT esse SessionId faz a criação de seções
/// e links no diretório por outra sessão exigir SeCreateGlobalPrivilege
/// (ObpLookupObjectName); o OpenNT ainda não aplica essa restrição.
pub fn set_session_information(handle: u64, previous_mode: u8) -> Result<u32, KernelError> {
    if !crate::ntos::se::privilege::single_privilege_check(SE_TCB_PRIVILEGE, previous_mode as u32) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    let opened = match crate::ntos::ob::handles::namespace::resolve(handle, previous_mode != 0) {
        Ok(opened) => opened,
        // A tabela de usuário só tem objetos que não são diretórios.
        Err(STATUS_INVALID_HANDLE) if state::get_user_handle(handle).is_some() => return Ok(STATUS_OBJECT_TYPE_MISMATCH),
        Err(status) => return Ok(status),
    };
    if !opened.directory {
        return Ok(STATUS_OBJECT_TYPE_MISMATCH);
    }
    crate::ntos::ob::objects::namespace::set_session_id(opened.body, crate::ntos::ps::session::current_process_session_id())?;
    Ok(0)
}

/// NtSetInformationObject em KernelMode (o ZwSetInformationObject):
/// ObjectHandleFlagInformation com exatamente os 2 bytes do
/// OBJECT_HANDLE_FLAG_INFORMATION vai ao ObSetHandleAttributes e
/// ObjectSessionInformation a [`set_session_information`]. A
/// ObjectSessionObjectInformation (6) pede o objeto Session da sessão, que
/// o OpenNT ainda não tem; ela e as demais dão STATUS_INVALID_INFO_CLASS.
pub fn set_information_object(handle: u64, class: u32, information: &ObjectHandleFlagInformation, length: u32) -> Result<u32, KernelError> {
    if class == OBJECT_SESSION_INFORMATION {
        return set_session_information(handle, 0);
    }
    if class != OBJECT_HANDLE_FLAG_INFORMATION {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    if length != ObjectHandleFlagInformation::SIZE as u32 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    set_handle_attributes(handle, information, 0)
}
