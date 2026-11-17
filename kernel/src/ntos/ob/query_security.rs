//! ZwQuerySecurityObject.
//!
//! A tabela real retém o corpo antes de chamar o dono. LengthNeeded é
//! publicado depois do procedimento, inclusive nos erros; um handle inválido
//! não toca os ponteiros de saída. Zw consulta em KernelMode.

use crate::ntos::ob::objects::file as file_objects;
use super::object_types;
use crate::ntos::ob::handles::security as security_handles;
use crate::ntos::cm::key::services as key_services;
use crate::ntos::io::file::native_security as file_security;
use crate::ntos::se::policy_descriptor;
use crate::ntos::se::query_descriptor::{self, QueryResult};
use crate::rtl::KernelError;
use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::io::file::zw as zw_files;

/// O descritor de um objeto pelo SecurityProcedure do tipo: arquivos pelo
/// IRP_MJ_QUERY_SECURITY do driver, dispositivos pelo DEVICE_OBJECT, chaves
/// pelo descritor do nó e os demais pelo descritor do objeto
/// (SeQuerySecurityDescriptorInfo).
fn query_object(pointer: u64, type_name: &str, information: u32, buffer: u64, capacity: u32, requestor_mode: u8) -> Result<QueryResult, KernelError> {
    if type_name == object_types::file_type().name {
        let device = crate::ntos::io::file::information::related_device(pointer)?;
        if device == 0 && (zw_files::file_backing(pointer).is_some() || file_objects::source(pointer).is_some()) {
            return Ok(file_security::query_unsupported_file(information, buffer, capacity));
        }
        return file_security::query_file(pointer, information, buffer, capacity, requestor_mode);
    }
    if type_name == object_types::device_type().name {
        return Ok(file_security::query_device(pointer, information, buffer, capacity));
    }
    if type_name == object_types::key_type().name {
        return key_services::query_security(pointer, information, buffer, capacity);
    }
    let policy = crate::ntos::ob::object_security::object_policy(pointer).ok_or_else(|| KernelError::new("security object has no policy owner"))?;
    let descriptor = policy_descriptor::capture(&policy)?;
    Ok(query_descriptor::query_descriptor(Some(&descriptor), information, buffer, capacity))
}

/// NtQuerySecurityObject(Handle, SecurityInformation, Buffer, Length,
/// LengthNeeded*) de modo usuário, como o 19041 (0x66c0d0): o LengthNeeded
/// e o buffer (alinhado a 4 quando Length não é zero) sondados para escrita
/// antes do handle; o SecurityInformation não é validado, só dá o acesso
/// que o handle precisa (`query_descriptor::query_access_mask`); o
/// SecurityProcedure do tipo devolve as partes que conhece (um buffer curto
/// dá STATUS_BUFFER_TOO_SMALL) e o tamanho vai ao LengthNeeded.
pub fn query_from_user(handle: u64, information: u32, buffer: u64, length: u32, length_needed: u64) -> Result<u32, KernelError> {
    use crate::ntos::ps::user_probe;
    if !user_probe::probe_user_write(length_needed, 4) {
        return Ok(0xC000_0005);
    }
    if length != 0 {
        if buffer & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if !user_probe::probe_user_write(buffer, length as u64) {
            return Ok(0xC000_0005);
        }
    }
    let desired = query_descriptor::query_access_mask(information);
    let (pointer, type_name, access) = match crate::ntos::ob::object_security::resolve_user_handle(handle) {
        Ok(resolved) => resolved,
        Err(status) => return Ok(status),
    };
    if access & desired != desired {
        crate::debug_print!("[ob] NtQuerySecurityObject: handle {:#x} ({}) com acesso {:#x}; as partes {:#x} pedem {:#x}", handle, type_name, access, information, desired);
        return Ok(0xC000_0022);
    }
    let result = query_object(pointer, &type_name, information, buffer, length, 1)?;
    if crate::ntos::mm::guest_memory::try_write::<u32>(length_needed, result.needed as u32).is_err() {
        return Ok(0xC000_0005);
    }
    Ok(result.status)
}

pub fn query(handle: u64, information: u32, buffer: u64, capacity: u32, length_needed: u64) -> Result<u32, KernelError> {
    let mut reference = match security_handles::reference_kernel_handle(handle)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = query_object(reference.pointer, &reference.object_type.name.clone(), information, buffer, capacity, 0);
    reference.release()?;
    let result = result?;
    // SAFETY: PULONG LengthNeeded do chamador (já capturado pelo serviço).
    unsafe { Field::<u32>::at(length_needed) }.set(result.needed as u32);
    Ok(result.status)
}
