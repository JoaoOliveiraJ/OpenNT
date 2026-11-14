//! ObGetObjectType.
//!
//! Um corpo com OBJECT_HEADER (os criados pelo ObCreateObject) tem o tipo
//! decodificado do TypeIndex do cabeçalho, como o export real (byte 1 do
//! endereço do cabeçalho ^ TypeIndex ^ ObHeaderCookie na ObTypeIndexTable).
//! Os corpos dos outros donos usam a identidade registrada pelo dono (o
//! vínculo direto, o próprio objeto de tipo ou a descrição do dono); os
//! cabeçalhos não são deduzidos dos bytes antes de uma alocação arbitrária.

use alloc::format;

use super::{object_header, object_types, open_pointer};
use crate::rtl::KernelError;

pub fn get(pointer: u64) -> Result<u64, KernelError> {
    if let Some(header) = object_header::header_of(pointer) {
        return Ok(object_header::type_of_header(header));
    }
    let object_type = object_types::bound(pointer)
        .or_else(|| object_types::find(pointer).map(|_| object_types::meta_type()))
        .or_else(|| open_pointer::describe(pointer).map(|described| described.object_type));
    match object_type {
        Some(object_type) => Ok(object_type.pointer),
        None => Err(KernelError::new(format!("ObGetObjectType: invalid native object {pointer:#x}"))),
    }
}
