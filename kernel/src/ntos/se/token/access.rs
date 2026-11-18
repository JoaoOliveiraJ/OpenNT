//! Acesso a objetos token.
//!
//! Mapeamento de direitos genéricos e a verificação do descritor do token.

use crate::ntos::ob::{object_access, object_types};
use crate::ntos::se::token::tokens;

const VALID_TOKEN_ACCESS_MASK: u32 = 0x1F_01FF;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
/// SeSecurityPrivilege e SE_PRIVILEGE_ENABLED.
const SE_SECURITY_PRIVILEGE: u64 = 8;
const SE_PRIVILEGE_ENABLED: u32 = 2;
/// SecurityImpersonation.
const SECURITY_IMPERSONATION: u32 = 2;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;

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
    // O descritor do token pelo SeAccessCheck (`se/access_evaluation.rs`).
    object_access::check_token(&security, &subject, requested, &object_types::token_type())
}

/// O acesso de quem cria o handle de um token novo, como o ObpCreateHandle
/// do ntoskrnl 19041 (rva 0x643c70) com ObCreateHandle: não há SeAccessCheck;
/// MAXIMUM_ALLOWED vira GENERIC_ALL, os genéricos passam pelo mapeamento do
/// token, ACCESS_SYSTEM_SECURITY exige o SeSecurityPrivilege habilitado no
/// sujeito (SePrivilegeCheck: KernelMode passa, um cliente abaixo de
/// SecurityImpersonation não; senão STATUS_PRIVILEGE_NOT_HELD) e o resto
/// fica no ValidAccessMask do tipo. `subject` é o token de cliente com o
/// nível de impersonação, ou o primário com `None` no nível.
pub fn creator_access(requested: u32, subject: Option<(u64, Option<u32>)>, from_kernel_mode: bool) -> Result<u32, u32> {
    let mut access = requested;
    if access & MAXIMUM_ALLOWED != 0 {
        access = (access & !MAXIMUM_ALLOWED) | GENERIC_ALL;
    }
    let access = map_generic_access(access);
    if access & ACCESS_SYSTEM_SECURITY != 0 && !from_kernel_mode {
        let held = subject
            .filter(|&(_, level)| level.is_none_or(|level| level >= SECURITY_IMPERSONATION))
            .and_then(|(token, _)| tokens::with(token, |token| token.privileges.iter().any(|held| held.id == SE_SECURITY_PRIVILEGE && held.attributes & SE_PRIVILEGE_ENABLED != 0)))
            .unwrap_or(false);
        if !held {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
    }
    Ok(access & (VALID_TOKEN_ACCESS_MASK | ACCESS_SYSTEM_SECURITY))
}
