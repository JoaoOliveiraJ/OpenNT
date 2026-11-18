//! NtCreateToken e NtCreateTokenEx: o token que o LSA monta para um logon.
//!
//! ntoskrnl 10.0.19041: NtCreateToken 0x922680 (chama o NtCreateTokenEx com
//! os atributos de usuário e de dispositivo, os grupos de dispositivo e a
//! política obrigatória nulos), NtCreateTokenEx 0x5dc930 e SepCreateTokenEx
//! 0x201aa0.
//!
//! - Quem chama precisa do SeCreateTokenPrivilege habilitado
//!   (STATUS_PRIVILEGE_NOT_HELD); o TokenType é 1 (primário) ou 2
//!   (impersonação, STATUS_BAD_TOKEN_TYPE fora disso), e um token de
//!   impersonação exige o SECURITY_QUALITY_OF_SERVICE nos ObjectAttributes,
//!   que dá o nível (STATUS_BAD_IMPERSONATION_LEVEL sem ele).
//! - Em UserMode os ponteiros passam pela sonda com alinhamento de ULONG
//!   (STATUS_DATATYPE_MISALIGNMENT) e a captura falha com
//!   STATUS_ACCESS_VIOLATION.
//! - Grupos e privilégios passam pelo SepCreateTokenEx (`shape`): grupos
//!   iguais ao usuário ou a um grupo anterior saem (a última entrada ocupa o
//!   lugar; os marcados SE_GROUP_INTEGRITY ficam); os obrigatórios
//!   (SE_GROUP_MANDATORY) ficam também habilitados e habilitados por padrão;
//!   um usuário ou grupo deny-only habilitado é STATUS_INVALID_PARAMETER, e
//!   deny-only liga TOKEN_IS_FILTERED. Um SID de autoridade S-1-16 com
//!   nível acima de System é STATUS_INVALID_LABEL; com
//!   SE_GROUP_INTEGRITY_ENABLED ele é o grupo de integridade (um segundo é
//!   STATUS_INVALID_PARAMETER). De Medium para cima o token tem
//!   TOKEN_NOT_LOW; abaixo de High (ou sem grupo de integridade, o
//!   IntegrityLevelIndex -1, que vale Untrusted) os privilégios fora da
//!   máscara do LUA ficam desligados, e abaixo de Medium só SeChangeNotify,
//!   SeUndock e SeIncreaseWorkingSet podem ficar ligados. O dono padrão
//!   (nulo = o usuário) precisa ser o usuário ou um grupo com
//!   SE_GROUP_OWNER (STATUS_INVALID_OWNER), e o grupo primário o usuário ou
//!   um dos grupos (STATUS_INVALID_PRIMARY_GROUP). Cada privilégio tem só
//!   os bits ENABLED e ENABLED_BY_DEFAULT (mais USED_FOR_ACCESS e REMOVED,
//!   descartados; outro bit é STATUS_INVALID_PARAMETER), um LUID até 0x24
//!   (STATUS_NO_SUCH_PRIVILEGE) e aparece uma vez só
//!   (STATUS_DUPLICATE_PRIVILEGES); a política obrigatória pedida só aceita
//!   NO_WRITE_UP e NEW_PROCESS_MIN e, sem ela, é 0.
//! - O AuthenticationId é uma sessão de logon que o LSA já criou pelo
//!   RmCreateLogonSession (STATUS_NO_SUCH_LOGON_SESSION sem ela).
//! - O token novo tem SessionId 0 (o LSA grava a sessão do cliente depois,
//!   pelo TokenSessionId), a DACL padrão, a origem (TOKEN_SOURCE) e os
//!   atributos de segurança de usuário pedidos, e entra na tabela de handles
//!   de quem chama com o acesso pedido.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::se::logon_session;
use crate::ntos::se::model::{equal_sids, Ace, Group, Privilege, Sid};
use crate::ntos::se::policy_descriptor;
use crate::ntos::se::token::{access as token_access, duplicate, handles as token_handles, thread as thread_tokens, tokens};
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_OWNER: u32 = 0xC000_005A;
const STATUS_INVALID_PRIMARY_GROUP: u32 = 0xC000_005B;
const STATUS_NO_SUCH_LOGON_SESSION: u32 = 0xC000_005F;
const STATUS_NO_SUCH_PRIVILEGE: u32 = 0xC000_0060;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INVALID_ACL: u32 = 0xC000_0077;
const STATUS_INVALID_SID: u32 = 0xC000_0078;
const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;
const STATUS_BAD_TOKEN_TYPE: u32 = 0xC000_00A8;
const STATUS_DUPLICATE_PRIVILEGES: u32 = 0xC000_01A6;
const STATUS_INVALID_LABEL: u32 = 0xC000_0446;
/// SeCreateTokenPrivilege.
const SE_CREATE_TOKEN_PRIVILEGE: u64 = 2;
/// SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED,
/// SE_GROUP_OWNER, SE_GROUP_USE_FOR_DENY_ONLY, SE_GROUP_INTEGRITY e
/// SE_GROUP_INTEGRITY_ENABLED.
const SE_GROUP_MANDATORY: u32 = 0x1;
const SE_GROUP_ENABLED_BOTH: u32 = 0x6;
const SE_GROUP_OWNER: u32 = 0x8;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
const SE_GROUP_INTEGRITY: u32 = 0x20;
const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x40;
/// A IdentifierAuthority do SeUntrustedMandatorySid (S-1-16).
const MANDATORY_LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x4000;
/// TokenFlags: TOKEN_IS_FILTERED e TOKEN_NOT_LOW.
const TOKEN_IS_FILTERED: u32 = 0x800;
const TOKEN_NOT_LOW: u32 = 0x2000;
/// Bits de LUID_AND_ATTRIBUTES.Attributes fora de ENABLED_BY_DEFAULT,
/// ENABLED, REMOVED e USED_FOR_ACCESS.
const PRIVILEGE_ATTRIBUTES_INVALID: u32 = 0x7FFF_FFF8;
/// SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED.
const PRIVILEGE_ENABLED_BOTH: u32 = 0x3;
/// O maior LUID de privilégio (SeDelegateSessionUserImpersonatePrivilege).
const SE_MAX_PRIVILEGE_LUID: u32 = 0x24;
/// Os privilégios que podem ficar ligados abaixo de High (a máscara do LUA)
/// e abaixo de Medium (SeChangeNotify, SeUndock e SeIncreaseWorkingSet).
const BELOW_HIGH_PRIVILEGES: u64 = 0xFFFF_FFEE_DFE9_F97B;
const BELOW_MEDIUM_PRIVILEGES: u64 = 0x2_0280_0000;
/// TOKEN_MANDATORY_POLICY_NO_WRITE_UP | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN.
const TOKEN_MANDATORY_POLICY_VALID_MASK: u32 = 0x3;
/// O maior número de subautoridades de um SID.
const SID_MAX_SUB_AUTHORITIES: u8 = 15;
/// A maior contagem de grupos ou privilégios aceita na captura.
const MAX_ENTRIES: u32 = 0x1000;

/// Os ponteiros do pedido, na ordem do NtCreateTokenEx.
pub struct Request {
    pub token_handle: u64,
    pub desired_access: u32,
    pub object_attributes: u64,
    pub token_type: u32,
    pub authentication_id: u64,
    pub expiration_time: u64,
    pub user: u64,
    pub groups: u64,
    pub privileges: u64,
    pub user_attributes: u64,
    pub device_attributes: u64,
    pub device_groups: u64,
    pub mandatory_policy: u64,
    pub owner: u64,
    pub primary_group: u64,
    pub default_dacl: u64,
    pub token_source: u64,
}

fn read32(address: u64) -> Result<u32, u32> {
    guest::try_read::<u32>(address).map_err(|_| STATUS_ACCESS_VIOLATION)
}

fn read64(address: u64) -> Result<u64, u32> {
    guest::try_read::<u64>(address).map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// SeCaptureSid: revisão 1, até 15 subautoridades.
fn capture_sid(address: u64) -> Result<Sid, u32> {
    if address == 0 {
        return Err(STATUS_INVALID_SID);
    }
    let header = guest::try_read_bytes(address, 8).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    if header[0] != 1 || header[1] > SID_MAX_SUB_AUTHORITIES {
        return Err(STATUS_INVALID_SID);
    }
    guest::try_read_bytes(address, 8 + header[1] as usize * 4).map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// SeCaptureSidAndAttributesArray de um TOKEN_GROUPS (ULONG GroupCount e o
/// vetor SID_AND_ATTRIBUTES a partir de +8).
fn capture_groups(address: u64) -> Result<Vec<Group>, u32> {
    if address == 0 {
        return Ok(Vec::new());
    }
    let count = read32(address)?;
    if count > MAX_ENTRIES {
        return Err(STATUS_INVALID_PARAMETER);
    }
    (0..count as u64).map(|index| Ok(Group { sid: capture_sid(read64(address + 8 + index * 16)?)?, attributes: read32(address + 16 + index * 16)? })).collect()
}

/// SeCaptureLuidAndAttributesArray de um TOKEN_PRIVILEGES (ULONG
/// PrivilegeCount e o vetor LUID_AND_ATTRIBUTES de 12 bytes a partir de +4).
fn capture_privileges(address: u64) -> Result<Vec<Privilege>, u32> {
    if address == 0 {
        return Ok(Vec::new());
    }
    let count = read32(address)?;
    if count > MAX_ENTRIES {
        return Err(STATUS_INVALID_PARAMETER);
    }
    (0..count as u64).map(|index| Ok(Privilege { id: read64(address + 4 + index * 12)?, attributes: read32(address + 12 + index * 12)? })).collect()
}

/// SeCaptureAcl do TOKEN_DEFAULT_DACL: `None` = sem DACL padrão.
fn capture_default_dacl(address: u64) -> Result<Option<Vec<Ace>>, u32> {
    if address == 0 {
        return Ok(None);
    }
    let acl = read64(address)?;
    if acl == 0 {
        return Ok(None);
    }
    let header = guest::try_read_bytes(acl, 8).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    let size = u16::from_le_bytes([header[2], header[3]]) as usize;
    if !(2..=4).contains(&header[0]) || size < 8 {
        return Err(STATUS_INVALID_ACL);
    }
    let bytes = guest::try_read_bytes(acl, size).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    Ok(Some(policy_descriptor::decode_aces(&bytes)))
}

fn misaligned(pointer: u64) -> bool {
    pointer & 3 != 0
}

/// Os grupos, o rótulo, os privilégios, o dono e o TokenFlags que o
/// SepCreateTokenEx tira do pedido capturado.
pub struct Shaped {
    /// Usuário e grupos sem duplicatas, menos o grupo de integridade (o
    /// registro do token o guarda à parte).
    pub groups: Vec<Group>,
    /// O SID do grupo de integridade; `None` é o IntegrityLevelIndex -1.
    pub integrity: Option<Sid>,
    /// Em ordem de LUID (o bitmap do NT), com ENABLED e ENABLED_BY_DEFAULT
    /// já mascarados pelo nível.
    pub privileges: Vec<Privilege>,
    pub owner: Sid,
    pub token_flags: u32,
}

/// A última subautoridade de um SID (0 sem nenhuma).
fn last_sub_authority(identifier: &Sid) -> u32 {
    let count = identifier.get(1).copied().unwrap_or(0) as usize;
    if count == 0 || identifier.len() < 8 + count * 4 {
        return 0;
    }
    let at = 8 + (count - 1) * 4;
    u32::from_le_bytes([identifier[at], identifier[at + 1], identifier[at + 2], identifier[at + 3]])
}

/// O SepCreateTokenEx (ntoskrnl 19041, 0x201aa0..0x202414) sobre o pedido
/// capturado, na ordem dele: duplicatas, usuário deny-only, grupos (rótulo,
/// grupo primário e dono), privilégios. Devolve o NTSTATUS da primeira
/// recusa.
///
/// Os SIDs de serviço (`NT SERVICE\<serviço>`, S-1-5-80) que o services.exe
/// pede ao LSA (os do svchost com SE_GROUP_OWNER e habilitados por padrão, o
/// do serviço iniciado também habilitado) não têm tratamento à parte: são
/// grupos como os outros, com os atributos pedidos.
pub fn shape(user: &Sid, user_attributes: u32, mut groups: Vec<Group>, privileges: &[Privilege], owner: Option<&Sid>, primary_group: &Sid) -> Result<Shaped, u32> {
    // Duplicatas: cada SID (o usuário primeiro) contra os grupos que vêm
    // depois dele; o repetido sai e a última entrada ocupa o lugar, menos os
    // marcados SE_GROUP_INTEGRITY.
    if !groups.is_empty() {
        let mut reference = user.clone();
        let mut start = 0;
        loop {
            let mut probe = start;
            while probe < groups.len() {
                if groups[probe].attributes & SE_GROUP_INTEGRITY == 0 && equal_sids(&reference, &groups[probe].sid) {
                    groups.swap_remove(probe);
                } else {
                    probe += 1;
                }
            }
            if start >= groups.len() {
                break;
            }
            reference = groups[start].sid.clone();
            start += 1;
            if start >= groups.len() {
                break;
            }
        }
    }
    let mut token_flags = 0;
    if user_attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 {
        if user_attributes & SE_GROUP_ENABLED_BOTH != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        token_flags = TOKEN_IS_FILTERED;
    }
    let mut primary_found = equal_sids(primary_group, user);
    let mut owner_found = owner.is_none_or(|owner| equal_sids(owner, user));
    let mut integrity: Option<(usize, u32)> = None;
    for (index, group) in groups.iter_mut().enumerate() {
        if group.attributes & SE_GROUP_MANDATORY != 0 {
            group.attributes |= SE_GROUP_ENABLED_BOTH;
        }
        if group.attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 {
            if group.attributes & SE_GROUP_ENABLED_BOTH != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            token_flags |= TOKEN_IS_FILTERED;
        }
        if group.sid.get(2..8) == Some(&MANDATORY_LABEL_AUTHORITY[..]) {
            let level = last_sub_authority(&group.sid);
            if level > SECURITY_MANDATORY_SYSTEM_RID {
                return Err(STATUS_INVALID_LABEL);
            }
            if group.attributes & SE_GROUP_INTEGRITY_ENABLED != 0 {
                if integrity.is_some() {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                integrity = Some((index, level));
                if level >= SECURITY_MANDATORY_MEDIUM_RID {
                    token_flags |= TOKEN_NOT_LOW;
                }
            }
        }
        if !primary_found {
            primary_found = equal_sids(primary_group, &group.sid);
        }
        if !owner_found && owner.is_some_and(|owner| equal_sids(owner, &group.sid)) {
            if group.attributes & SE_GROUP_OWNER == 0 {
                return Err(STATUS_INVALID_OWNER);
            }
            owner_found = true;
        }
    }
    if !primary_found {
        return Err(STATUS_INVALID_PRIMARY_GROUP);
    }
    if !owner_found {
        return Err(STATUS_INVALID_OWNER);
    }
    // Privilégios: o bitmap Present do NT, pelo LowPart do LUID.
    let mut present = 0u64;
    let mut shaped_privileges = Vec::with_capacity(privileges.len());
    for privilege in privileges {
        if privilege.attributes & PRIVILEGE_ATTRIBUTES_INVALID != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let luid = privilege.id as u32;
        if luid > SE_MAX_PRIVILEGE_LUID {
            return Err(STATUS_NO_SUCH_PRIVILEGE);
        }
        if present & 1 << luid != 0 {
            return Err(STATUS_DUPLICATE_PRIVILEGES);
        }
        present |= 1 << luid;
        shaped_privileges.push(Privilege { id: luid as u64, attributes: privilege.attributes & PRIVILEGE_ENABLED_BOTH });
    }
    shaped_privileges.sort_unstable_by_key(|privilege| privilege.id);
    let level = integrity.map(|(_, level)| level);
    let mut keep_enabled = |mask: u64| {
        for privilege in shaped_privileges.iter_mut() {
            if (mask >> privilege.id) & 1 == 0 {
                privilege.attributes &= !PRIVILEGE_ENABLED_BOTH;
            }
        }
    };
    if level.is_none_or(|level| level < SECURITY_MANDATORY_HIGH_RID) {
        keep_enabled(BELOW_HIGH_PRIVILEGES);
    }
    if level.is_some_and(|level| level < SECURITY_MANDATORY_MEDIUM_RID) {
        keep_enabled(BELOW_MEDIUM_PRIVILEGES);
    }
    let integrity_sid = integrity.map(|(index, _)| groups.remove(index).sid);
    Ok(Shaped { groups, integrity: integrity_sid, privileges: shaped_privileges, owner: owner.cloned().unwrap_or_else(|| user.clone()), token_flags })
}

/// NtCreateTokenEx de `mode` (0 KernelMode, 1 UserMode); devolve o NTSTATUS.
pub fn create(request: &Request, mode: u8) -> Result<u32, KernelError> {
    let caller = thread_tokens::effective(process::get_current_thread(), false);
    let privileged = mode == 0 || caller.is_some_and(|token| tokens::with(token, |record| record.privileges.iter().any(|entry| entry.id == SE_CREATE_TOKEN_PRIVILEGE && entry.attributes & 2 != 0)).unwrap_or(false));
    if !privileged {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    if mode != 0 {
        let required = [request.authentication_id, request.expiration_time, request.user, request.groups, request.privileges, request.primary_group, request.token_source];
        let optional = [request.user_attributes, request.device_attributes, request.device_groups, request.mandatory_policy, request.owner, request.default_dacl];
        if required.iter().chain(optional.iter()).any(|&pointer| misaligned(pointer)) {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if guest::try_read::<u64>(request.token_handle).and_then(|value| guest::try_write::<u64>(request.token_handle, value)).is_err() {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if !(1..=2).contains(&request.token_type) {
        return Ok(STATUS_BAD_TOKEN_TYPE);
    }
    let quality = match duplicate::capture_quality(request.object_attributes, mode) {
        Ok(quality) => quality,
        Err(status) => return Ok(status),
    };
    if quality.is_none() && request.token_type == 2 {
        return Ok(STATUS_BAD_IMPERSONATION_LEVEL);
    }
    let captured = (|| -> Result<Captured, u32> {
        let authentication_id = read64(request.authentication_id)?;
        let expiration_time = read64(request.expiration_time)?;
        let user = capture_sid(read64(request.user)?)?;
        let user_attributes = read32(request.user + 8)?;
        let groups = capture_groups(request.groups)?;
        let privileges = capture_privileges(request.privileges)?;
        let owner = if request.owner != 0 { Some(capture_sid(read64(request.owner)?)?) } else { None };
        let primary_group = capture_sid(read64(request.primary_group)?)?;
        let default_dacl = capture_default_dacl(request.default_dacl)?;
        let source = guest::try_read_bytes(request.token_source, 16).map_err(|_| STATUS_ACCESS_VIOLATION)?;
        let mandatory_policy = if request.mandatory_policy != 0 { Some(read32(request.mandatory_policy)?) } else { None };
        let security_attributes = if request.user_attributes != 0 { crate::ntos::se::security_attributes::capture_information(request.user_attributes)? } else { Vec::new() };
        Ok(Captured { authentication_id, expiration_time, user, user_attributes, groups, privileges, owner, primary_group, default_dacl, source, mandatory_policy, security_attributes })
    })();
    let mut captured = match captured {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    let shaped = match shape(&captured.user, captured.user_attributes, core::mem::take(&mut captured.groups), &captured.privileges, captured.owner.as_ref(), &captured.primary_group) {
        Ok(shaped) => shaped,
        Err(status) => return Ok(status),
    };
    if captured.mandatory_policy.is_some_and(|policy| policy & !TOKEN_MANDATORY_POLICY_VALID_MASK != 0) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if !logon_session::exists(captured.authentication_id, 0) {
        return Ok(STATUS_NO_SUCH_LOGON_SESSION);
    }
    let subject = caller.unwrap_or(0);
    let creation = match duplicate::capture_creation(request.object_attributes, mode, subject) {
        Ok(creation) => creation,
        Err(status) => return Ok(status),
    };
    let level = quality.unwrap_or(0);
    let token_type = request.token_type;
    let token = tokens::create(None, Some(&|token: &mut tokens::Token| {
        token.authentication_id = captured.authentication_id;
        token.expiration_time = captured.expiration_time;
        token.user = captured.user.clone();
        token.user_attributes = captured.user_attributes;
        token.owner = shaped.owner.clone();
        token.primary_group = captured.primary_group.clone();
        token.kind = token_type;
        token.session_id = 0;
        // Sem grupo de integridade, o rótulo fica vazio: as consultas e a
        // verificação de acesso o tratam como Untrusted (S-1-16-0).
        token.integrity = shaped.integrity.clone().unwrap_or_default();
        token.groups = shaped.groups.clone();
        token.privileges = shaped.privileges.clone();
        token.restricted_sids = Vec::new();
        token.security_attributes = captured.security_attributes.clone();
        token.default_dacl = captured.default_dacl.clone();
        token.impersonation_level = level;
        token.mandatory_policy = captured.mandatory_policy.unwrap_or(0);
        let mut name = [0u8; 8];
        name.copy_from_slice(&captured.source[..8]);
        token.source = Some((name, u64::from_le_bytes(captured.source[8..16].try_into().unwrap_or([0; 8]))));
        token.security = creation.policy.clone();
    }))?;
    tokens::body(token).token_flags.set(shaped.token_flags);
    let mapped = token_access::map_generic_access(request.desired_access);
    let granted = (mapped & 0x1F_01FF) | if mapped & 0x0200_0000 != 0 { 0xF_01FF } else { 0 };
    let result = match token_handles::create(token, granted, creation.flags, mode != 0) {
        Ok(handle) => {
            if guest::try_write::<u64>(request.token_handle, handle).is_err() {
                Ok(STATUS_ACCESS_VIOLATION)
            } else {
                Ok(0)
            }
        }
        Err(error) if error.status != 0 => Ok(error.status),
        Err(error) => Err(error),
    };
    tokens::release(token)?;
    result
}

/// O que a captura leu do chamador.
struct Captured {
    authentication_id: u64,
    expiration_time: u64,
    user: Sid,
    user_attributes: u32,
    groups: Vec<Group>,
    privileges: Vec<Privilege>,
    owner: Option<Sid>,
    primary_group: Sid,
    default_dacl: Option<Vec<Ace>>,
    source: Vec<u8>,
    mandatory_policy: Option<u32>,
    security_attributes: Vec<crate::ntos::se::security_attributes::SecurityAttribute>,
}
