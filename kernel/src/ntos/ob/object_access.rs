//! Política de acesso capturada na criação do corpo.
//!
//! A DACL atual do chamador não substitui a política que pertence ao objeto.

use super::object_types::ObjectType;
use crate::ntos::ps::process;
use crate::ntos::se::access_evaluation::{self, Subject};
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::ntos::se::policy_descriptor::{self, OwnedDescriptor};
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

/// O descritor da política de um objeto com as ACEs mapeadas pelo tipo
/// (como o SeAssignSecurity as grava): os componentes que a avaliação lê.
pub fn descriptor_of(policy: &SecurityPolicy, object_type: &ObjectType) -> Result<OwnedDescriptor, u32> {
    let mut descriptor = policy_descriptor::capture(policy).map_err(|_| 0xC000_00BBu32)?;
    if let Some(dacl) = descriptor.dacl.as_mut() {
        access_evaluation::map_acl_generics(dacl, &object_type.mapping);
    }
    Ok(descriptor)
}

/// Avaliação em modo usuário de um sujeito já montado (o token real ou um
/// derivado: sem usuário, com SIDs restritos ou com o pacote do AppContainer)
/// pelo SeAccessCheck (`se/access_evaluation.rs`): o pedido mapeado pelo
/// tipo, os direitos fora do tipo recusados e o MAXIMUM_ALLOWED limitado aos
/// direitos válidos do tipo.
pub fn check_token(policy: &SecurityPolicy, token: &tokens::Token, requested: u32, object_type: &ObjectType) -> AccessResult {
    let mask = map_generic_access(requested, object_type);
    let explicit = mask & !0x0200_0000;
    if explicit & !(object_type.valid_access | 0x0100_0000) != 0 {
        return Err(0xC000_0022);
    }
    let descriptor = descriptor_of(policy, object_type)?;
    let granted = access_evaluation::access_check(Some(&descriptor), &Subject::from_token(token), mask, 0, &object_type.mapping)?;
    Ok(if mask & 0x0200_0000 != 0 { granted & (object_type.valid_access | 0x0100_0000) } else { granted })
}
