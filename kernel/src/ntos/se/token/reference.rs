//! SepReferenceTokenByHandle — `system32/ntos/se/token-reference.js`.
//!
//! A referência sobrevive ao fechamento do handle; `release` ocorre uma vez.

use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::ntos::ke::critical_region;
use crate::ntos::ob::{handle_table, object_manager, object_types};
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// Token referenciado e o acesso concedido pelo handle.
pub struct TokenReference {
    pub token: u64,
    pub granted_access: u32,
    released: bool,
}

impl TokenReference {
    pub fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Err(KernelError::new("Token query reference released twice"));
        }
        self.released = true;
        tokens::release(self.token).map(|_| ())
    }
}

fn retain(token: u64, granted_access: u32) -> Result<TokenReference, KernelError> {
    tokens::retain(token)?;
    Ok(TokenReference { token, granted_access, released: false })
}

/// Referencia o token de um handle. Pseudo-handles -4, -5 e -6 (token
/// primário, de impersonação e efetivo) só com `allow_pseudo_tokens`.
pub fn reference(handle: u64, desired_access: u32, access_mode: u8, allow_pseudo_tokens: bool) -> Result<Result<TokenReference, u32>, KernelError> {
    let signed = handle as i64;
    let from_user_mode = access_mode != 0;
    if (-6..=-4).contains(&signed) {
        if !allow_pseudo_tokens {
            return Ok(Err(0xC000_0008));
        }
        if desired_access & !0x18 != 0 {
            return Ok(Err(0xC000_0022));
        }
        let impersonation = if signed == -4 { None } else { thread_tokens::get(process::get_current_thread()) };
        if signed == -5 && impersonation.is_none() {
            return Ok(Err(0xC000_007C));
        }
        if impersonation.is_some_and(|impersonation| impersonation.level == 0) {
            return Ok(Err(0xC000_00A6));
        }
        let token = impersonation.map(|impersonation| impersonation.token).or_else(|| process::get_primary_token(process::get_current_process()));
        let Some(token) = token else { return Ok(Err(0xC000_007C)) };
        return retain(token, 0x18).map(Ok);
    }
    if signed == -1 || signed == -2 {
        return Ok(Err(0xC000_0024));
    }
    let kernel_handle = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if if kernel_handle { from_user_mode } else { handle > 0x7FFF_FFFF } {
        return Ok(Err(0xC000_0008));
    }
    let owner = if kernel_handle { process::get_system_process() } else { process::get_current_process() };
    let index = (handle & 0x7FFF_FFFC) as u32;
    critical_region::with_critical(|| {
        let table = process_handles::reference(owner)?;
        if table == 0 {
            return Ok(Err(0xC000_0008));
        }
        let result = (|| {
            if process_handles::get(owner) != Some(table) {
                return Err(KernelError::new("Token handle table mismatch"));
            }
            let token_type = object_types::token_type();
            let outcome = handle_table::with_entry(table, index, |entry| {
                match object_manager::handle_record(index) {
                    Some(record) if record.node == entry.identity => {
                        if record.options.kernel_handle != kernel_handle {
                            return Ok(Err(0xC000_0008));
                        }
                    }
                    _ if kernel_handle => return Ok(Err(0xC000_0008)),
                    _ => {}
                }
                if entry.type_name != token_type.name {
                    return Ok(Err(0xC000_0024));
                }
                if from_user_mode && desired_access & !entry.access != 0 {
                    return Ok(Err(0xC000_0022));
                }
                if !tokens::exists(entry.pointer) {
                    return Err(KernelError::new("Live token handle has no owning token"));
                }
                retain(entry.pointer, entry.access).map(Ok)
            })?;
            Ok(outcome.unwrap_or(Err(0xC000_0008)))
        })();
        process_handles::release(owner)?;
        result
    })
}
