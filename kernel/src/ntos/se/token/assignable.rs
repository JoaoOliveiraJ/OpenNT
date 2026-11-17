//! SeIsTokenAssignableToProcess (ntoskrnl 19041, rva 0x70da14): um token
//! que o PspAllocateProcess aceita como primário de um processo novo sem o
//! SeAssignPrimaryTokenPrivilege de quem cria.
//!
//! Com o token primário do processo corrente (P) e o token pedido (T):
//!
//! - T de impersonação com nível abaixo de SecurityImpersonation dá
//!   STATUS_BAD_IMPERSONATION_LEVEL;
//! - o nível de integridade de P precisa dominar o de T (o RtlSidDominates:
//!   mesma autoridade, as subautoridades iguais menos a última, e a última
//!   de P maior ou igual) e o TrustLevelSid de P, o de T (o
//!   RtlSidDominatesForTrust; os tokens do OpenNT não têm TrustLevelSid, e
//!   sem ele dos dois lados a dominância vale);
//! - T é atribuível quando é filho de P (o SepIsChildTokenByPointer:
//!   ParentTokenId de T igual ao TokenId de P, o caso do token filtrado) ou
//!   irmão (o SepIsSiblingTokenByPointer: o mesmo ParentTokenId e o mesmo
//!   AuthenticationId, ou, com os dois tokens ainda referenciando a sessão
//!   de logon, as duas sessões ligadas uma à outra pelo BuddyLogonId).
//!
//! O token que o lsass cria pelo NtCreateTokenEx para o logon de um serviço
//! do SYSTEM tem ParentTokenId 0, como o token do System de que o
//! services.exe descende, e o AuthenticationId 0x3E7: é irmão do token do
//! services.exe, que cria o svchost pelo CreateProcessAsUserW sem o
//! privilégio habilitado.

use super::tokens::{self, Token};
use crate::ntos::ps::process;
use crate::ntos::se::logon_session;

const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
/// TokenImpersonation e SecurityImpersonation.
const TOKEN_IMPERSONATION: u32 = 2;
const SECURITY_IMPERSONATION: u32 = 2;

/// O RtlSidDominates de dois SIDs: a mesma autoridade e as mesmas
/// subautoridades menos a última, e a última de `dominant` maior ou igual.
fn sid_dominates(dominant: &[u8], other: &[u8]) -> bool {
    if dominant.len() < 12 || dominant.len() != other.len() || dominant[..dominant.len() - 4] != other[..other.len() - 4] {
        return dominant == other;
    }
    let last = |sid: &[u8]| u32::from_le_bytes([sid[sid.len() - 4], sid[sid.len() - 3], sid[sid.len() - 2], sid[sid.len() - 1]]);
    last(dominant) >= last(other)
}

/// SepIsSiblingTokenByPointer: o mesmo ParentTokenId e o mesmo logon, ou os
/// dois logons ligados um ao outro (com os dois tokens referenciando a
/// sessão).
fn is_sibling(caller: &Token, token: &Token) -> bool {
    if token.parent_token_id != caller.parent_token_id {
        return false;
    }
    if token.authentication_id == caller.authentication_id {
        return true;
    }
    if !tokens::references_logon_session(caller) || !tokens::references_logon_session(token) {
        return false;
    }
    let caller_buddy = logon_session::buddy_logon_id(caller.authentication_id, caller.server_silo);
    let token_buddy = logon_session::buddy_logon_id(token.authentication_id, token.server_silo);
    caller_buddy != 0 && caller_buddy == token.authentication_id && token_buddy == caller.authentication_id
}

/// `Ok(atribuível)` ou `Err(NTSTATUS)`.
pub fn is_assignable_to_process(token: u64) -> Result<bool, u32> {
    let Some(primary) = process::get_primary_token(process::get_current_process()) else { return Err(STATUS_UNSUCCESSFUL) };
    let (Some(caller), Some(requested)) = (tokens::get(primary), tokens::get(token)) else { return Err(STATUS_UNSUCCESSFUL) };
    if requested.kind == TOKEN_IMPERSONATION && requested.impersonation_level < SECURITY_IMPERSONATION {
        return Err(STATUS_BAD_IMPERSONATION_LEVEL);
    }
    if !sid_dominates(&caller.integrity, &requested.integrity) {
        return Ok(false);
    }
    Ok(requested.parent_token_id == caller.id || is_sibling(&caller, &requested))
}
