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
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::io::file::zw as zw_files;

/// Arquivos nativos vão ao driver por IRP; arquivos de volume/fonte sem
/// ACLs usam o fallback de segurança não suportada.
fn query_file(pointer: u64, information: u32, buffer: u64, capacity: u32) -> Result<QueryResult, KernelError> {
    if guest::read64(pointer + 8) == 0 && (zw_files::file_backing(pointer).is_some() || file_objects::source(pointer).is_some()) {
        return Ok(file_security::query_unsupported_file(information, buffer, capacity));
    }
    file_security::query_file(pointer, information, buffer, capacity, 0)
}

pub fn query(handle: u64, information: u32, buffer: u64, capacity: u32, length_needed: u64) -> Result<u32, KernelError> {
    let mut reference = match security_handles::reference_kernel_handle(handle)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = (|| -> Result<QueryResult, KernelError> {
        let name = reference.object_type.name.as_str();
        if name == object_types::file_type().name {
            query_file(reference.pointer, information, buffer, capacity)
        } else if name == object_types::device_type().name {
            Ok(file_security::query_device(reference.pointer, information, buffer, capacity))
        } else if name == object_types::key_type().name {
            key_services::query_security(reference.pointer, information, buffer, capacity)
        } else {
            let policy = reference.security().ok_or_else(|| KernelError::new("security object has no policy owner"))?;
            let descriptor = policy_descriptor::capture(&policy)?;
            Ok(query_descriptor::query_descriptor(Some(&descriptor), information, buffer, capacity))
        }
    })();
    reference.release()?;
    let result = result?;
    guest::write32(length_needed, result.needed as u32);
    Ok(result.status)
}
