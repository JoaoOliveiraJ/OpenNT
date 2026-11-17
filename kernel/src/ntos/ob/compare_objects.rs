//! NtCompareObjects(FirstObjectHandle, SecondObjectHandle).
//!
//! Medido no ntoskrnl 19041: cada handle passa pelo
//! ObReferenceObjectByHandle com acesso 0, sem tipo e no PreviousMode do
//! chamador. A falha do primeiro volta como está; a do segundo também,
//! depois de soltar o primeiro. Os dois corpos iguais dão STATUS_SUCCESS e
//! corpos diferentes, STATUS_NOT_SAME_OBJECT (`sub rax, rcx; neg rax; sbb
//! ebx, ebx; and ebx, 0xC00001AC`).

use alloc::sync::Arc;

use super::object_security::resolve_user_handle;
use crate::ntos::ps::user::state;
use crate::rtl::KernelError;

pub const STATUS_NOT_SAME_OBJECT: u32 = 0xC000_01AC;

/// O corpo do objeto de um handle de modo usuário, como o
/// ObReferenceObjectByHandle sem tipo e sem acesso o vê: os pseudo-handles
/// do processo e da thread correntes, a tabela de usuário do processo e o
/// handle nativo do Object Manager. Um objeto do runtime sem corpo nativo é
/// identificado pelo próprio objeto, que os handles duplicados compartilham.
fn object_of(handle: u64) -> Result<u64, u32> {
    if handle == u64::MAX || handle == u64::MAX - 1 {
        return resolve_user_handle(handle).map(|(pointer, _, _)| pointer);
    }
    if let Some(entry) = state::get_user_handle(handle) {
        return Ok(entry.object.native_body().map_or_else(|| Arc::as_ptr(&entry.object) as *const () as u64, |body| body.pointer));
    }
    resolve_user_handle(handle).map(|(pointer, _, _)| pointer)
}

/// NtCompareObjects de modo usuário. Devolve o NTSTATUS.
pub fn compare_from_user(first: u64, second: u64) -> u32 {
    let first = match object_of(first) {
        Ok(pointer) => pointer,
        Err(status) => return status,
    };
    let second = match object_of(second) {
        Ok(pointer) => pointer,
        Err(status) => return status,
    };
    if first == second { 0 } else { STATUS_NOT_SAME_OBJECT }
}

fn nt_compare_objects(first: u64, second: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(compare_from_user(first, second))
}

/// O handler do serviço NtCompareObjects.
pub fn register_user_services() {
    state::register_handler("NtCompareObjects", nt_compare_objects);
}
