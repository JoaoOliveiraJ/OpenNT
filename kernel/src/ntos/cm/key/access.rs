//! Política de acesso às chaves.
//!
//! Consulta o token efetivo da thread, incluindo a impersonação, para
//! conferir os privilégios reais da solicitação.

use crate::ntos::ps::process;
use crate::ntos::se::token::{thread as thread_tokens, tokens};

/// Privilégio presente e ENABLED no sujeito efetivo.
fn has_enabled_privilege(identifier: u64) -> bool {
    thread_tokens::effective(process::get_current_thread(), false)
        .and_then(|token| tokens::with(token, |token| token.privileges.iter().any(|privilege| privilege.id == identifier && privilege.attributes & 2 != 0)))
        .unwrap_or(false)
}

/// Valida a visão WOW64, as opções de backup/restauração e os privilégios;
/// converte direitos genéricos antes de armazená-los no handle.
/// `Ok(acesso)` ou `Err(NTSTATUS)`.
pub fn key_access(desired_access: u32, open_options: u32) -> Result<u32, u32> {
    // As duas seleções WOW64 juntas são inválidas; a visão de 32 bits
    // separada continua não implementada.
    if desired_access & 0x300 == 0x300 {
        return Err(0xC000_000D);
    }
    if desired_access & 0x200 != 0 {
        return Err(0xC000_00BB);
    }
    let mut granted = desired_access & !0x300;
    if open_options & 4 != 0 {
        // REG_OPTION_BACKUP_RESTORE: direitos pelos privilégios de backup e restore.
        granted = (if has_enabled_privilege(17) { 0x102_0019 } else { 0 }) | (if has_enabled_privilege(18) { 0x103_0006 } else { 0 });
        if granted == 0 {
            return Err(0xC000_0061);
        }
    } else {
        // ACCESS_SYSTEM_SECURITY exige SeSecurityPrivilege habilitado.
        if granted & 0x100_0000 != 0 && !has_enabled_privilege(8) {
            return Err(0xC000_0061);
        }
        let generic = granted >> 28;
        granted &= 0x0FFF_FFFF;
        if generic & 1 != 0 {
            granted |= 0xF003F;
        }
        if generic & 2 != 0 {
            granted |= 0x20039;
        }
        if generic & 4 != 0 {
            granted |= 0x20006;
        }
        if generic & 8 != 0 {
            granted |= 0x20019;
        }
        // MAXIMUM_ALLOWED continua uma solicitação; o descritor da chave
        // decide quais direitos podem ser concedidos.
        if granted & !0x31F_003F != 0 {
            return Err(0xC000_0022);
        }
    }
    Ok(granted)
}
