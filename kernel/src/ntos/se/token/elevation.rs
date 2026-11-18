//! O par de tokens do UAC: a elevação de um token, o tipo de elevação e o
//! vínculo entre o token completo e o filtrado.
//!
//! Com o UAC ligado (o LsapShouldSplitToken do lsass: UACInstalled,
//! DbgElevationEnabled da KUSER_SHARED_DATA e um token de logon interativo
//! elevado), o LsapBuildAndCreateToken divide o logon em dois: o token
//! completo, na sessão de logon original, e o filtrado (NtFilterToken com
//! LUA_TOKEN), numa sessão de logon nova. Depois o lsass liga
//! TokenVirtualizationAllowed (23) no filtrado e chama o
//! NtSetInformationToken(completo, TokenLinkedToken, &filtrado), que é o
//! SepLinkLogonSessions ([`link`]). O cliente (o winlogon) recebe o token
//! completo; o TokenLinkedToken do NtQueryInformationToken devolve o outro
//! ([`linked_token_copy`]).
//!
//! Como no ntoskrnl 19041:
//! - TokenElevation (classe 20 do NtQueryInformationToken, rva 0x6d21ee;
//!   [`is_elevated`]): o token é elevado quando o bitmap Present dos
//!   privilégios tem algum de 0x11_2016_0684 (SeCreateToken, SeTcb,
//!   SeTakeOwnership, SeLoadDriver, SeBackup, SeRestore, SeDebug,
//!   SeImpersonate, SeRelabel e SeDelegateSessionUserImpersonate), presente
//!   mesmo desabilitado, ou quando o usuário ou algum grupo passa no
//!   RtlIsElevatedRid ([`is_elevated_rid`]);
//! - TokenElevationType (classe 18, rva 0x6d158a; [`elevation_type`]): pelos
//!   Flags da sessão de logon do token: 4 (a sessão do token filtrado) dá
//!   TokenElevationTypeLimited (3), 2 (a do completo) dá
//!   TokenElevationTypeFull (2), nenhum dos dois TokenElevationTypeDefault
//!   (1). O ramo do modo S sem administrador (SeIsSModeAdminlessEnabled, que
//!   devolve Default no lugar de Limited) não existe no OpenNT;
//! - as sessões de logon guardam o par: cada uma uma cópia primária do seu
//!   token (o token de sessão) e o LogonId da outra (BuddyLogonId); a
//!   filtrada segura uma referência à completa e a solta quando sai
//!   (`se/logon_session.rs`).

use crate::ntos::ps::process;
use crate::ntos::se::logon_session;
use crate::ntos::se::model::Sid;
use crate::ntos::se::privilege;
use crate::ntos::se::token::{duplicate, reference as token_reference, thread as thread_tokens, tokens::{self, Token}};
use crate::rtl::KernelError;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// SeCreateTokenPrivilege.
const SE_CREATE_TOKEN_PRIVILEGE: u64 = 2;
/// TOKEN_ADJUST_DEFAULT | TOKEN_DUPLICATE: o acesso ao handle do token
/// ligado.
const LINKED_TOKEN_ACCESS: u32 = 0x88;
/// Os privilégios que tornam um token elevado (o teste do bitmap Present
/// no NtQueryInformationToken, rva 0x6d2251), por LUID.
pub const ELEVATED_PRIVILEGES: u64 = 0x11_2016_0684;
/// SE_GROUP_USE_FOR_DENY_ONLY e SE_GROUP_INTEGRITY: grupos que o
/// RtlIsElevatedRid ignora.
const SKIPPED_GROUPS: u32 = 0x30;
/// Os RIDs elevados do RtlIsElevatedRid (a tabela de 19 entradas em rva
/// 0x18530): os grupos de administração do domínio e do BUILTIN.
const ELEVATED_RIDS: [u32; 19] = [512, 516, 521, 498, 517, 518, 519, 520, 544, 547, 548, 549, 550, 551, 553, 554, 556, 569, 114];
/// TOKEN_ELEVATION_TYPE.
pub const ELEVATION_TYPE_DEFAULT: u32 = 1;
pub const ELEVATION_TYPE_FULL: u32 = 2;
pub const ELEVATION_TYPE_LIMITED: u32 = 3;

/// RtlIsElevatedRid(SID_AND_ATTRIBUTES*) (ntoskrnl 19041, rva 0x6ed1d0):
/// falso para um grupo deny-only ou de integridade, para um SID sem
/// subautoridade e para os SIDs de serviço e de conta virtual (primeira
/// subautoridade de 80 a 111); senão, o último RID na tabela de RIDs
/// elevados. A autoridade não é olhada.
pub fn is_elevated_rid(identifier: &Sid, attributes: u32) -> bool {
    let count = identifier.get(1).copied().unwrap_or(0) as usize;
    if attributes & SKIPPED_GROUPS != 0 || count == 0 || identifier.len() < 8 + count * 4 {
        return false;
    }
    let sub = |index: usize| u32::from_le_bytes([identifier[8 + index * 4], identifier[9 + index * 4], identifier[10 + index * 4], identifier[11 + index * 4]]);
    !(80..=111).contains(&sub(0)) && ELEVATED_RIDS.contains(&sub(count - 1))
}

/// TokenIsElevated: algum privilégio elevado presente, ou o usuário ou um
/// grupo com RID elevado (o UserAndGroups do NT, que também leva o rótulo de
/// integridade, ignorado pelo RtlIsElevatedRid).
pub fn is_elevated(token: &Token) -> bool {
    token.privileges.iter().any(|privilege| privilege.id < 64 && (ELEVATED_PRIVILEGES >> privilege.id) & 1 != 0)
        || is_elevated_rid(&token.user, token.user_attributes)
        || token.groups.iter().any(|group| is_elevated_rid(&group.sid, group.attributes))
}

/// TokenElevationType pelos Flags da sessão de logon do token.
pub fn elevation_type(token: &Token) -> u32 {
    let flags = logon_session::link_flags(token.authentication_id, token.server_silo);
    if flags & logon_session::SESSION_LIMITED_LINK != 0 {
        ELEVATION_TYPE_LIMITED
    } else if flags & logon_session::SESSION_FULL_LINK != 0 {
        ELEVATION_TYPE_FULL
    } else {
        ELEVATION_TYPE_DEFAULT
    }
}

/// O token do TokenLinkedToken (o ramo da classe 19 do
/// NtQueryInformationToken 19041, rva 0x6d1f0b, depois do tamanho): a
/// sessão irmã da sessão de logon do token, referenciada pelo
/// SepReferenceLogonSessionSilo do BuddyLogonId (sem ela,
/// STATUS_NO_SUCH_LOGON_SESSION, o status que o winlogon e o lsm esperam de
/// um token sem par), e uma cópia (SepDuplicateToken) do token de sessão
/// dela: primária com o SeTcbPrivilege de quem consulta (`tcb`), senão de
/// impersonação no nível SecurityIdentification. A cópia volta referenciada
/// e sem handle, com o descritor do ObInsertObject sem descritor explícito
/// (o dono e a DACL padrão do token efetivo de quem consulta).
pub fn linked_token_copy(token: u64, tcb: bool) -> Result<u64, u32> {
    let Some((logon_id, server_silo)) = tokens::with(token, |record| (record.authentication_id, record.server_silo)) else { return Err(STATUS_INVALID_HANDLE) };
    let (buddy, source) = logon_session::reference_linked_token(logon_id, server_silo)?;
    let copy = if tcb { tokens::duplicate(source, 0, false, 1) } else { tokens::duplicate(source, 1, false, 2) };
    let _ = tokens::release(source);
    logon_session::dereference_direct(buddy, server_silo);
    let copy = copy.map_err(|error| if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES })?;
    let subject = thread_tokens::effective(process::get_current_thread(), false);
    if let Some(policy) = subject.and_then(duplicate::default_policy) {
        tokens::update(copy, |record| record.security = policy);
    }
    Ok(copy)
}

/// SepLinkLogonSessions(Token, LinkedTokenHandle, PreviousMode) (ntoskrnl
/// 19041, rva 0x32c264), a classe TokenLinkedToken do NtSetInformationToken
/// (o handle do token pede TOKEN_ADJUST_DEFAULT | TOKEN_DUPLICATE): o
/// SeCreateTokenPrivilege no modo anterior (STATUS_PRIVILEGE_NOT_HELD); a
/// sessão de logon do token ainda sem token de sessão
/// (STATUS_INVALID_PARAMETER); o token ligado pelo handle, com o mesmo
/// acesso, no modo anterior; o resto é o `logon_session::link_sessions`.
/// Não muda o ModifiedId de nenhum dos dois.
pub fn link(token: u64, linked_handle: u64, mode: u8) -> Result<u32, KernelError> {
    if !privilege::single_privilege_check(SE_CREATE_TOKEN_PRIVILEGE, mode as u32) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    let Some((logon_id, server_silo)) = tokens::with(token, |record| (record.authentication_id, record.server_silo)) else { return Ok(STATUS_INVALID_PARAMETER) };
    if logon_session::holds_session_token(logon_id, server_silo) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let mut linked = match token_reference::reference(linked_handle, LINKED_TOKEN_ACCESS, mode, false)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let status = logon_session::link_sessions(token, linked.token);
    linked.release()?;
    Ok(status)
}
