//! Verificações de token de RtlCapabilityCheck.
//!
//! Compartilham a captura real do token, com validação, status e ordem de
//! saída próprios.

use crate::ntos::se::token::{capability_access as token_capability_access, membership as token_membership};
use crate::rtl::KernelError;
use crate::ntos::se::{out, sid};

/// RtlIsCapabilitySid: cabeçalho, autoridade 15 e primeira subautoridade 3.
pub fn is_capability_identifier(pointer: u64) -> bool {
    let identifier = sid::at(pointer);
    let authority = &identifier.identifier_authority.value;
    identifier.sub_authority_count.get() >= 2
        && identifier.revision.get() == 1
        && authority[..5].iter().all(|byte| byte.get() == 0)
        && authority[5].get() == 15
        && identifier.sub_authority[0].get() == 3
}

/// RtlCheckTokenMembershipEx: ausência de membership é consulta concluída.
pub fn check_membership(handle: u64, sid_pointer: u64, flags: u32, output: u64) -> Result<u32, KernelError> {
    out::<u8>(output).set(0);
    if flags & !3 != 0 {
        return Ok(0xC000_000D);
    }
    token_membership::with_token(handle, |token, context| {
        let identifier = token_membership::read_security_identifier(sid_pointer);
        if context.previous_mode != 0 && context.client_level.is_some_and(|level| level < 2) {
            return Ok(0xC000_00A5);
        }
        if context.previous_mode == 0 || token_capability_access::permits_membership(token, identifier.as_deref(), flags) {
            out::<u8>(output).set(1);
        }
        Ok(0)
    })
}

/// RtlCheckTokenCapability: o wrapper kernel transforma o FALSE do
/// SeAccessCheck em ACCESS_DENIED.
pub fn check_capability(handle: u64, sid_pointer: u64, output: u64) -> Result<u32, KernelError> {
    out::<u8>(output).set(0);
    if !is_capability_identifier(sid_pointer) {
        return Ok(0xC000_000D);
    }
    token_membership::with_token(handle, |token, context| {
        let identifier = token_membership::read_security_identifier(sid_pointer);
        let insufficient = context.client_level.is_some_and(|level| level < 2);
        if context.previous_mode != 0 && (insufficient || !token_capability_access::permits_capability(token, identifier.as_deref())) {
            return Ok(0xC000_0022);
        }
        out::<u8>(output).set(1);
        Ok(0)
    })
}
