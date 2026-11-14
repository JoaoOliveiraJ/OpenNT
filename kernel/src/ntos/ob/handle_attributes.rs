//! ObSetHandleAttributes: troca o Inherit e o ProtectFromClose de um handle
//! (o OBJECT_HANDLE_FLAG_INFORMATION de um chamador de kernel), como o
//! NtSetInformationObject(ObjectHandleFlagInformation) faz para o modo
//! usuário.
//!
//! Como no NT, um handle de kernel (prefixo OBJ_KERNEL_HANDLE) só vale com
//! PreviousMode KernelMode e é procurado na tabela do System; os demais, na
//! tabela do processo corrente (o anexado, durante um attach). Handle
//! ausente dá STATUS_INVALID_HANDLE.

use crate::ntos::inc::types::ObjectHandleFlagInformation;
use crate::ntos::ps::user::state;
use crate::ntos::ps::{process, process_context};
use crate::rtl::KernelError;

const KERNEL_HANDLE_MASK: u64 = 0xFFFF_FFFF_8000_0000;
/// OBJ_PROTECT_CLOSE e OBJ_INHERIT nos atributos do handle.
const OBJ_PROTECT_CLOSE: u32 = 1;
const OBJ_INHERIT: u32 = 2;

/// ObSetHandleAttributes(Handle, HandleFlags, PreviousMode).
pub fn set_handle_attributes(handle: u64, flags: &ObjectHandleFlagInformation, previous_mode: u8) -> Result<u32, KernelError> {
    let attributes = (if flags.inherit.get() != 0 { OBJ_INHERIT } else { 0 }) | (if flags.protect_from_close.get() != 0 { OBJ_PROTECT_CLOSE } else { 0 });
    if previous_mode == 0 && handle & KERNEL_HANDLE_MASK == KERNEL_HANDLE_MASK {
        return process_context::with_process(process::get_system_process(), || state::change_user_handle_attributes(handle, attributes))?;
    }
    state::change_user_handle_attributes(handle, attributes)
}
