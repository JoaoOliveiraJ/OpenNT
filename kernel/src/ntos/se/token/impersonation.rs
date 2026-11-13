//! Política de impersonação do token: SeTokenCanImpersonate (ntoskrnl
//! 19041, 0x6d4100), consultada por PsImpersonateClient antes de dar à
//! thread o token de um cliente.
//!
//! Lê os registros de token do `token/tokens.rs` (não os offsets nativos).
//! Lacunas honestas do modelo, nenhuma das quais concede permissão: sem
//! TrustLevelSid (RtlSidDominatesForTrust sempre domina e nunca pede token
//! ajustado), sem sessões de logon/elevação (o bloco UAC não tem o que
//! comparar) e sem SepIsImpersonationAllowedDueToCapability (capacidade de
//! impersonação não dá atalho).

use crate::ntos::rtl::security::{is_parent_of_child_app_container, sid_dominates};
use crate::ntos::se::model::equal_sids;
use crate::ntos::se::token::tokens::{self, Token};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
/// ANONYMOUS_LOGON_LUID {0x3E6, 0}.
const ANONYMOUS_LOGON_LUID: u64 = 0x3E6;
/// SE_IMPERSONATE_PRIVILEGE (bit 29 de Privileges.Present & Enabled).
const SE_IMPERSONATE_PRIVILEGE: u64 = 29;
const SE_PRIVILEGE_ENABLED: u32 = 0x2;
/// SecurityImpersonation: abaixo disso a impersonação é sempre permitida.
const SECURITY_IMPERSONATION: i32 = 2;

/// Mesmo pacote ou pacote filho do primário (RtlEqualSid, depois
/// RtlIsParentOfChildAppContainer).
fn package_allows(primary: &[u8], client: Option<&[u8]>) -> bool {
    client.is_some_and(|client| equal_sids(primary, client) || is_parent_of_child_app_container(primary, client))
}

/// SeTokenIsRestricted como o OpenNT modela (SIDs restritos ou
/// write-restricted).
fn restricted(token: &Token) -> bool {
    !token.restricted_sids.is_empty() || token.write_restricted
}

/// SeTokenCanImpersonate(PrimaryToken, ClientToken, Level): Ok se o primário
/// pode agir com a identidade do cliente no nível pedido; senão o NTSTATUS
/// (PRIVILEGE_NOT_HELD, ou INVALID_PARAMETER de SIDs de integridade ruins).
pub fn can_impersonate(primary: u64, client: u64, level: u32) -> Result<(), u32> {
    if (level as i32) < SECURITY_IMPERSONATION {
        return Ok(());
    }
    let primary = tokens::get(primary).ok_or(STATUS_INVALID_PARAMETER)?;
    let client = tokens::get(client).ok_or(STATUS_INVALID_PARAMETER)?;
    // Logon anônimo: só o AppContainer do primário restringe.
    if client.authentication_id == ANONYMOUS_LOGON_LUID {
        return match &primary.app_container {
            None => Ok(()),
            Some(package) if package_allows(package, client.app_container.as_deref()) => Ok(()),
            Some(_) => Err(STATUS_PRIVILEGE_NOT_HELD),
        };
    }
    if primary.privileges.iter().any(|privilege| privilege.id == SE_IMPERSONATE_PRIVILEGE && privilege.attributes & SE_PRIVILEGE_ENABLED != 0) {
        return Ok(());
    }
    if !sid_dominates(&primary.integrity, &client.integrity)? {
        return Err(STATUS_PRIVILEGE_NOT_HELD);
    }
    if primary.authentication_id == client.authentication_id {
        return Ok(());
    }
    if !equal_sids(&primary.user, &client.user) {
        return Err(STATUS_PRIVILEGE_NOT_HELD);
    }
    if let Some(package) = &primary.app_container {
        if !package_allows(package, client.app_container.as_deref()) {
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
    }
    if restricted(&primary) && (!restricted(&client) || (!primary.write_restricted && client.write_restricted)) {
        return Err(STATUS_PRIVILEGE_NOT_HELD);
    }
    // Mesma sessão, ou cliente fora da sessão 0.
    if primary.session_id == client.session_id || client.session_id != 0 {
        Ok(())
    } else {
        Err(STATUS_PRIVILEGE_NOT_HELD)
    }
}
