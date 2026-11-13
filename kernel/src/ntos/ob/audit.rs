//! Consulta da auditoria de fechamento de um handle, como no Ob do NT.
//!
//! ObQueryObjectAuditingByHandle (ntoskrnl 19041 rva 0x664ca0): resolve o
//! handle na tabela do processo corrente ou, para handle de kernel vindo de
//! KernelMode, na tabela do sistema; escreve em `*GenerateOnClose` o bit
//! OBJ_AUDIT_OBJECT_CLOSE (4) dos atributos da entrada e devolve
//! STATUS_SUCCESS, ou STATUS_INVALID_HANDLE sem escrever nada.

use crate::ntos::inc::types::Field;
use crate::ntos::ob::close;
use crate::ntos::ps::previous_mode;
use crate::rtl::KernelError;

const OBJ_AUDIT_OBJECT_CLOSE: u32 = 0x04;

/// ObQueryObjectAuditingByHandle(Handle, *GenerateOnClose) -> NTSTATUS. O
/// PBOOLEAN vem de um chamador de kernel (o ntfs passa uma variável local).
pub fn query_object_auditing_by_handle(handle: u64, generate_on_close: &Field<u8>) -> Result<u32, KernelError> {
    let from_user_mode = previous_mode::get()? != 0;
    let Some(attributes) = close::handle_attributes(handle, from_user_mode) else { return Ok(close::STATUS_INVALID_HANDLE) };
    generate_on_close.set((attributes & OBJ_AUDIT_OBJECT_CLOSE != 0) as u8);
    Ok(0)
}
