//! ObGetObjectType — `system32/ntos/ob/get-object-type.js`.
//!
//! OBJECT_TYPE pela identidade registrada pelo dono do corpo (o vínculo
//! direto, o próprio objeto de tipo ou a descrição do dono); os cabeçalhos
//! não são deduzidos dos bytes antes de uma alocação arbitrária.

use alloc::format;

use super::{object_types, open_pointer};
use crate::rtl::KernelError;

pub fn get(pointer: u64) -> Result<u64, KernelError> {
    let object_type = object_types::bound(pointer)
        .or_else(|| object_types::find(pointer).map(|_| object_types::meta_type()))
        .or_else(|| open_pointer::describe(pointer).map(|described| described.object_type));
    match object_type {
        Some(object_type) => Ok(object_type.pointer),
        None => Err(KernelError::new(format!("ObGetObjectType: invalid native object {pointer:#x}"))),
    }
}
