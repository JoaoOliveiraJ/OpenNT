//! Acesso a objetos token.
//!
//! Mapeamento de direitos genéricos e avaliação ordenada da DACL do token.

use crate::ntos::se::model::equal_sids;
use crate::ntos::se::token::tokens;

const VALID_TOKEN_ACCESS_MASK: u32 = 0x1F_01FF;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

/// GENERIC_READ/WRITE/EXECUTE/ALL para direitos de token.
pub fn map_generic_access(mask: u32) -> u32 {
    let mut mask = mask;
    if mask & 0x8000_0000 != 0 {
        mask |= 0x2001A;
    }
    if mask & 0x4000_0000 != 0 {
        mask |= 0x201E0;
    }
    if mask & 0x2000_0000 != 0 {
        mask |= 0x20005;
    }
    if mask & 0x1000_0000 != 0 {
        mask |= 0xF01FF;
    }
    mask & 0x0FFF_FFFF
}

/// Avalia a abertura do token `target` pela identidade `subject`.
/// `Ok(máscara)` ou `Err(NTSTATUS)`; KernelMode segue a regra própria da ABI.
pub fn check(target: u64, subject: Option<u64>, requested: u32, from_kernel_mode: bool) -> Result<u32, u32> {
    let mask = map_generic_access(requested);
    let maximum_allowed = mask & MAXIMUM_ALLOWED != 0;
    let explicit = mask & !MAXIMUM_ALLOWED;
    if explicit & !(VALID_TOKEN_ACCESS_MASK | ACCESS_SYSTEM_SECURITY) != 0 {
        return Err(0xC000_0022);
    }
    if from_kernel_mode {
        return Ok(explicit | if maximum_allowed { VALID_TOKEN_ACCESS_MASK } else { 0 });
    }
    let Some(subject) = subject.and_then(|subject| tokens::get(subject)) else { return Err(0xC000_007C) };
    let Some(security) = tokens::with(target, |token| token.security.clone()) else { return Err(0xC000_0008) };
    // Um privilégio presente mas desabilitado não satisfaz a verificação.
    let enabled = |id: u64| subject.privileges.iter().any(|privilege| privilege.id == id && privilege.attributes & 2 != 0);
    if explicit & ACCESS_SYSTEM_SECURITY != 0 && !enabled(8) {
        return Err(0xC000_0061);
    }
    // O dono começa com READ_CONTROL e WRITE_DAC; a negação acumula à parte
    // para respeitar a ordem das ACEs.
    let mut granted = if equal_sids(&security.owner, &subject.user) { 0x60000 } else { 0 };
    let mut denied = 0;
    if enabled(9) {
        granted |= 0x80000;
    }
    match &security.dacl {
        None => granted = VALID_TOKEN_ACCESS_MASK,
        Some(entries) => {
            for ace in entries {
                let Some(ace_sid) = &ace.sid else { continue };
                // Grupos habilitados concedem; deny-only só participa de negações.
                let matches = equal_sids(ace_sid, &subject.user)
                    || subject.groups.iter().any(|group| equal_sids(ace_sid, &group.sid) && ((group.attributes & 4 != 0 && group.attributes & 0x10 == 0) || (ace.deny && group.attributes & 0x10 != 0)));
                if !matches {
                    continue;
                }
                let rights = map_generic_access(ace.mask) & VALID_TOKEN_ACCESS_MASK;
                if ace.deny {
                    denied |= rights & !granted;
                } else {
                    granted |= rights & !denied;
                }
            }
        }
    }
    if explicit & ACCESS_SYSTEM_SECURITY != 0 {
        granted |= ACCESS_SYSTEM_SECURITY;
    }
    // Todos os direitos explícitos precisam ser concedidos, mesmo com MAXIMUM_ALLOWED.
    if explicit & !granted != 0 {
        return Err(0xC000_0022);
    }
    Ok(explicit | if maximum_allowed { granted } else { 0 })
}
