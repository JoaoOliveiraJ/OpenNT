//! Política de acesso capturada na criação do corpo.
//!
//! A DACL atual do chamador não substitui a política que pertence ao objeto.

use super::object_types::ObjectType;
use crate::ntos::ps::process;
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::ntos::se::token::{thread as thread_tokens, tokens};

/// Dono, grupo e DACL padrão do token; sem token, a identidade de sistema.
pub fn capture(token: Option<u64>) -> SecurityPolicy {
    let captured = token.and_then(|token| {
        tokens::with(token, |token| SecurityPolicy {
            owner: token.owner.clone(),
            group: Some(token.primary_group.clone()),
            dacl: token.default_dacl.clone(),
            ..Default::default()
        })
    });
    captured.unwrap_or_else(|| {
        let system = sid(5, &[18]);
        SecurityPolicy {
            owner: system.clone(),
            group: Some(system.clone()),
            dacl: Some(alloc::vec![Ace::allow(system, 0x1000_0000)]),
            ..Default::default()
        }
    })
}

/// Token efetivo da thread corrente, incluindo a impersonação ativa.
pub fn subject() -> Option<u64> {
    thread_tokens::effective(process::get_current_thread(), false)
}

/// Expande os quatro direitos genéricos pelo mapeamento do tipo.
pub fn map_generic_access(mask: u32, object_type: &ObjectType) -> u32 {
    let mut mask = mask;
    for (index, &mapping) in object_type.mapping.iter().enumerate() {
        if mask & (0x8000_0000 >> index) != 0 {
            mask |= mapping;
        }
    }
    mask & 0x0FFF_FFFF
}

/// Resultado de [`check`]: `Ok(acesso concedido)` ou `Err(NTSTATUS)`.
pub type AccessResult = Result<u32, u32>;

/// Valida máscara, privilégios, DACL e integridade, mantendo os direitos
/// explícitos separados de MAXIMUM_ALLOWED.
pub fn check(policy: &SecurityPolicy, token: Option<u64>, requested: u32, object_type: &ObjectType, from_kernel_mode: bool) -> AccessResult {
    let mask = map_generic_access(requested, object_type);
    let explicit = mask & !0x0200_0000;
    if explicit & !(object_type.valid_access | 0x0100_0000) != 0 {
        return Err(0xC000_0022);
    }
    if from_kernel_mode {
        return Ok(explicit | if mask & 0x0200_0000 != 0 { object_type.valid_access } else { 0 });
    }
    let Some(token) = token.and_then(tokens::get) else { return Err(0xC000_007C) };
    check_token(policy, &token, requested, object_type)
}

/// Avaliação em modo usuário de um sujeito já montado (o token real ou um
/// derivado: sem usuário, com SIDs restritos ou com o pacote do AppContainer).
pub fn check_token(policy: &SecurityPolicy, token: &tokens::Token, requested: u32, object_type: &ObjectType) -> AccessResult {
    let mask = map_generic_access(requested, object_type);
    let maximum_allowed = mask & 0x0200_0000 != 0;
    let explicit = mask & !0x0200_0000;
    if explicit & !(object_type.valid_access | 0x0100_0000) != 0 {
        return Err(0xC000_0022);
    }
    let has_privilege = |id: u64| token.privileges.iter().any(|privilege| privilege.id == id && privilege.attributes & 2 != 0);
    if explicit & 0x0100_0000 != 0 && !has_privilege(8) {
        return Err(0xC000_0061);
    }
    // O dono recebe READ_CONTROL e WRITE_DAC; as entradas seguem a ordem da DACL.
    let mut allowed = if policy.owner == token.user { 0x60000 } else { 0 };
    let mut denied = 0u32;
    if has_privilege(9) {
        allowed |= 0x80000;
    }
    match &policy.dacl {
        None => allowed |= object_type.valid_access,
        Some(dacl) => {
            for entry in dacl {
                if entry.flags & 8 != 0 {
                    continue;
                }
                let Some(entry_sid) = &entry.sid else {
                    if maximum_allowed || explicit & !allowed != 0 {
                        return Err(0xC000_00BB);
                    }
                    continue;
                };
                let matches = *entry_sid == token.user
                    || token.groups.iter().any(|group| {
                        group.sid == *entry_sid
                            && ((group.attributes & 4 != 0 && group.attributes & 16 == 0) || (entry.deny && group.attributes & 16 != 0))
                    });
                if !matches {
                    continue;
                }
                let rights = map_generic_access(entry.mask, object_type) & object_type.valid_access;
                if entry.deny {
                    denied |= rights & !allowed;
                } else {
                    allowed |= rights & !denied;
                }
            }
        }
    }
    allowed &= object_type.valid_access;
    // Integridade abaixo do nível do objeto restringe escrita.
    if let Some(required) = policy.integrity {
        let level = if token.integrity.len() >= 12 {
            u32::from_le_bytes([token.integrity[8], token.integrity[9], token.integrity[10], token.integrity[11]])
        } else {
            0x2000
        };
        if level < required {
            allowed &= !(0xD0000 | (object_type.mapping[1] & 0xFFFF));
        }
    }
    if explicit & 0x0100_0000 != 0 {
        allowed |= 0x0100_0000;
    }
    if explicit & !allowed != 0 {
        return Err(0xC000_0022);
    }
    Ok(explicit | if maximum_allowed { allowed } else { 0 })
}
