//! Verificações de token de RtlCapabilityCheck — `system32/ntos/se/capability-token-checks.js`.
//!
//! Compartilham a captura real do token, com validação, status e ordem de
//! saída próprios.

use crate::ntos::se::token::{capability_access as token_capability_access, membership as token_membership};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// RtlIsCapabilitySid: cabeçalho, autoridade 15 e primeira subautoridade 3.
pub fn is_capability_identifier(pointer: u64) -> bool {
    guest::read8(pointer + 1) >= 2
        && guest::read8(pointer) == 1
        && (2..7).all(|offset| guest::read8(pointer + offset) == 0)
        && guest::read8(pointer + 7) == 15
        && guest::read32(pointer + 8) == 3
}

/// RtlCheckTokenMembershipEx: ausência de membership é consulta concluída.
pub fn check_membership(handle: u64, sid_pointer: u64, flags: u32, output: u64) -> Result<u32, KernelError> {
    guest::write8(output, 0);
    if flags & !3 != 0 {
        return Ok(0xC000_000D);
    }
    token_membership::with_token(handle, |token, context| {
        let identifier = token_membership::read_security_identifier(sid_pointer);
        if context.previous_mode != 0 && context.client_level.is_some_and(|level| level < 2) {
            return Ok(0xC000_00A5);
        }
        if context.previous_mode == 0 || token_capability_access::permits_membership(token, identifier.as_deref(), flags) {
            guest::write8(output, 1);
        }
        Ok(0)
    })
}

/// RtlCheckTokenCapability: o wrapper kernel transforma o FALSE do
/// SeAccessCheck em ACCESS_DENIED.
pub fn check_capability(handle: u64, sid_pointer: u64, output: u64) -> Result<u32, KernelError> {
    guest::write8(output, 0);
    if !is_capability_identifier(sid_pointer) {
        return Ok(0xC000_000D);
    }
    token_membership::with_token(handle, |token, context| {
        let identifier = token_membership::read_security_identifier(sid_pointer);
        let insufficient = context.client_level.is_some_and(|level| level < 2);
        if context.previous_mode != 0 && (insufficient || !token_capability_access::permits_capability(token, identifier.as_deref())) {
            return Ok(0xC000_0022);
        }
        guest::write8(output, 1);
        Ok(0)
    })
}
