//! NtSetInformationToken.
//!
//! ntoskrnl 10.0.19041 (NtSetInformationToken 0x6ed6b0): as classes aceitas
//! são as da máscara 0x24800f8b5070 (4, 5, 6, 12, 14, 16, 17, 19, 23 a 27, 39,
//! 42 e 45); qualquer outra é STATUS_INVALID_INFO_CLASS antes do handle. O
//! handle pede TOKEN_ADJUST_DEFAULT (TokenSessionId soma
//! TOKEN_ADJUST_SESSIONID, TokenLinkedToken soma TOKEN_DUPLICATE). Cada
//! troca dá um ModifiedId novo ao token.
//!
//! - TokenOwner (4) e TokenPrimaryGroup (5): um TOKEN_OWNER ou
//!   TOKEN_PRIMARY_GROUP de 8 bytes (STATUS_INFO_LENGTH_MISMATCH fora disso);
//!   o dono precisa ser o usuário ou um grupo com SE_GROUP_OWNER
//!   (STATUS_INVALID_OWNER) e o grupo primário o usuário ou um dos grupos
//!   (STATUS_INVALID_PRIMARY_GROUP).
//! - TokenDefaultDacl (6): o TOKEN_DEFAULT_DACL (pelo menos 8 bytes); uma ACL
//!   nula tira a DACL padrão.
//! - TokenSessionId (12): o ULONG (4 bytes), com o SeTcbPrivilege.
//! - TokenSessionReference (14): o ULONG 0 (outro valor é
//!   STATUS_INVALID_PARAMETER), com o SeTcbPrivilege: o token larga a
//!   referência à sessão de logon (TOKEN_SESSION_NOT_REFERENCED em
//!   TokenFlags, o SepStopReferencingLogonSession). O LSA faz isso com o
//!   token de cada sessão que guarda (o LsapSetSessionToken), e a sessão
//!   pode ser apagada com esse token vivo.
//! - TokenSecurityAttributes (39): o
//!   TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION (16 bytes: os
//!   atributos e o vetor de operações), com o SeTcbPrivilege. As operações,
//!   como o AuthzBasepSetSecurityAttributesToken: NONE (0), REPLACE_ALL (1,
//!   troca todos), ADD (2, um nome que já existe é
//!   STATUS_OBJECT_NAME_COLLISION), DELETE (3, um nome ausente é
//!   STATUS_NOT_FOUND) e REPLACE (4, troca ou acrescenta).
//!
//! - TokenAuditPolicy (16): com o SeTcbPrivilege e uma vez só (outro
//!   pedido é STATUS_INVALID_PARAMETER); sem buffer marca o token sem
//!   política, com buffer copia o TOKEN_AUDIT_POLICY de 0x1F bytes.
//! - TokenOrigin (17): o LUID OriginatingLogonSession (8 bytes), com o
//!   SeTcbPrivilege; só o primeiro valor fica. O LSA grava os dois no token
//!   de cada logon (o LsapCreateTokenObject).
//! - TokenIntegrityLevel (25): o TOKEN_MANDATORY_LABEL (16 bytes, o
//!   SID_AND_ATTRIBUTES capturado pelo SeCaptureSidAndAttributesArray) troca
//!   o nível de integridade do token (`set_integrity_level`). O dwminit do
//!   winlogon sobe assim o token da conta DWM-n para System antes do
//!   CreateRestrictedToken, e o LaunchUmfdHostWithVirtualAccount desce o da
//!   conta UMFD-n para Low.
//! - TokenMandatoryPolicy (27): o TOKEN_MANDATORY_POLICY (4 bytes), com o
//!   SeTcbPrivilege; o token primário de um processo vivo (TokenInUse) é
//!   STATUS_TOKEN_ALREADY_IN_USE, e bits fora de NO_WRITE_UP e
//!   NEW_PROCESS_MIN são STATUS_INVALID_PARAMETER (o
//!   SeSetMandatoryPolicyToken). O LsapCreateTokenObject do lsass grava a
//!   política no token de cada logon de serviço.
//!
//! As outras classes aceitas ainda não mudam nada no OpenNT
//! (STATUS_NOT_IMPLEMENTED, com registro).

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::capture;
use crate::ntos::se::model::{equal_sids, Sid};
use crate::ntos::se::policy_descriptor;
use crate::ntos::se::privilege;
use crate::ntos::se::security_attributes::{self, SecurityAttribute};
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_INVALID_OWNER: u32 = 0xC000_005A;
const STATUS_INVALID_PRIMARY_GROUP: u32 = 0xC000_005B;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_TOKEN_ALREADY_IN_USE: u32 = 0xC000_012B;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_ACL: u32 = 0xC000_0077;
const STATUS_INVALID_SID: u32 = 0xC000_0078;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_INVALID_LABEL: u32 = 0xC000_0446;
/// As classes do NtSetInformationToken 19041 (bit = classe).
const VALID_CLASSES: u64 = 0x2480_0F8B_5070;
/// SeTcbPrivilege.
const SE_TCB_PRIVILEGE: u64 = 7;
/// A IdentifierAuthority do SeUntrustedMandatorySid (S-1-16).
const MANDATORY_LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
const SECURITY_MANDATORY_HIGH_RID: u32 = 0x3000;
const SECURITY_MANDATORY_SYSTEM_RID: u32 = 0x4000;
/// TokenFlags: TOKEN_UIACCESS e TOKEN_NOT_LOW.
const TOKEN_UIACCESS: u32 = 0x1000;
const TOKEN_NOT_LOW: u32 = 0x2000;
/// Os privilégios que podem ficar ligados abaixo de High (a máscara do LUA:
/// sem SeCreateToken, SeTcb, SeTakeOwnership, SeLoadDriver, SeBackup,
/// SeRestore, SeDebug, SeImpersonate, SeRelabel e
/// SeDelegateSessionUserImpersonate) e abaixo de Medium (só SeChangeNotify,
/// SeUndock e SeIncreaseWorkingSet), por LUID.
const BELOW_HIGH_PRIVILEGES: u64 = 0xFFFF_FFEE_DFE9_F97B;
const BELOW_MEDIUM_PRIVILEGES: u64 = 0x2_0280_0000;
/// SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED.
const SE_PRIVILEGE_ENABLED_AND_DEFAULT: u32 = 0x3;
/// SE_GROUP_OWNER.
const SE_GROUP_OWNER: u32 = 0x8;
/// TOKEN_MANDATORY_POLICY_NO_WRITE_UP | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN.
const TOKEN_MANDATORY_POLICY_VALID_MASK: u32 = 0x3;

/// O acesso ao handle que a classe pede (`None` = classe recusada).
pub fn required_access(class: u32) -> Option<u32> {
    if class > 63 || VALID_CLASSES & (1 << class) == 0 {
        return None;
    }
    Some(match class {
        12 => 0x180,
        19 => 0x88,
        _ => 0x80,
    })
}

fn capture_sid(address: u64) -> Result<Sid, u32> {
    if address == 0 {
        return Err(STATUS_INVALID_SID);
    }
    let header = guest::try_read_bytes(address, 8).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    if header[0] != 1 || header[1] > 15 {
        return Err(STATUS_INVALID_SID);
    }
    guest::try_read_bytes(address, 8 + header[1] as usize * 4).map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// Aplica as operações de atributos de segurança ao conjunto do token.
fn apply_operations(current: &mut Vec<SecurityAttribute>, attributes: Vec<SecurityAttribute>, operations: &[u32]) -> Result<(), u32> {
    let position = |set: &Vec<SecurityAttribute>, name: &str| set.iter().position(|attribute| attribute.name.eq_ignore_ascii_case(name));
    for (attribute, &operation) in attributes.into_iter().zip(operations) {
        match operation {
            0 => {}
            1 => {
                current.clear();
                current.push(attribute);
            }
            2 => {
                if position(current, &attribute.name).is_some() {
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
                current.push(attribute);
            }
            3 => match position(current, &attribute.name) {
                Some(index) => {
                    current.remove(index);
                }
                None => return Err(STATUS_NOT_FOUND),
            },
            4 => match position(current, &attribute.name) {
                Some(index) => current[index] = attribute,
                None => current.push(attribute),
            },
            _ => return Err(STATUS_INVALID_PARAMETER),
        }
    }
    Ok(())
}

/// A última subautoridade de um SID (0 sem nenhuma).
fn last_sub_authority(sid: &Sid) -> u32 {
    let count = sid.get(1).copied().unwrap_or(0) as usize;
    if count == 0 || sid.len() < 8 + count * 4 {
        return 0;
    }
    let at = 8 + (count - 1) * 4;
    u32::from_le_bytes([sid[at], sid[at + 1], sid[at + 2], sid[at + 3]])
}

/// O TokenIntegrityLevel do NtSetInformationToken (ntoskrnl 19041,
/// 0x6ee53e) com o rótulo já capturado: a autoridade do SID tem de ser a do
/// SeUntrustedMandatorySid (S-1-16) e o nível (a última subautoridade, 0
/// sem nenhuma) no máximo System, senão STATUS_INVALID_LABEL; um token sem
/// grupo de integridade também é STATUS_INVALID_LABEL. Subir o nível exige
/// o SeTcbPrivilege (STATUS_PRIVILEGE_NOT_HELD) e um token que não é o
/// primário de um processo vivo (STATUS_TOKEN_ALREADY_IN_USE); descer tira
/// TOKEN_UIACCESS. O nível novo vai à última subautoridade do SID de
/// integridade do token (STATUS_INVALID_PARAMETER quando não há nenhuma).
/// Abaixo de High, os privilégios fora da máscara do LUA ficam desligados;
/// abaixo de Medium, só SeChangeNotify, SeUndock e SeIncreaseWorkingSet
/// podem ficar ligados e TOKEN_NOT_LOW sai; de Medium para cima,
/// TOKEN_NOT_LOW entra e um token LowBox deixa de ser (o SID de pacote sai
/// da DACL padrão e o pacote e as capacidades são largados). Os privilégios
/// continuam presentes: só os bits Enabled e EnabledByDefault mudam.
fn set_integrity_level(token: u64, label: &Sid, mode: u8) -> u32 {
    if label.len() < 8 || label[2..8] != MANDATORY_LABEL_AUTHORITY {
        return STATUS_INVALID_LABEL;
    }
    let level = last_sub_authority(label);
    if level > SECURITY_MANDATORY_SYSTEM_RID {
        return STATUS_INVALID_LABEL;
    }
    // O NT faz tudo com o token travado; aqui a verificação de privilégio e
    // a busca do processo dono ficam fora da trava dos registros de token.
    let Some(integrity) = tokens::with(token, |record| record.integrity.clone()) else { return STATUS_INVALID_PARAMETER };
    if integrity.is_empty() {
        return STATUS_INVALID_LABEL;
    }
    let current = last_sub_authority(&integrity);
    if level > current {
        if !privilege::single_privilege_check(SE_TCB_PRIVILEGE, mode as u32) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        if tokens::in_use(token) {
            return STATUS_TOKEN_ALREADY_IN_USE;
        }
    }
    let flags = &tokens::body(token).token_flags;
    let clear_flags = |bits: u32| {
        flags.atomic().fetch_and(!bits, core::sync::atomic::Ordering::SeqCst);
    };
    if level < current {
        clear_flags(TOKEN_UIACCESS);
    }
    tokens::update(token, |record| {
        let count = record.integrity.get(1).copied().unwrap_or(0) as usize;
        if count == 0 || record.integrity.len() < 8 + count * 4 {
            return STATUS_INVALID_PARAMETER;
        }
        let at = 8 + (count - 1) * 4;
        record.integrity[at..at + 4].copy_from_slice(&level.to_le_bytes());
        let keep_enabled = |mask: u64, privileges: &mut Vec<crate::ntos::se::model::Privilege>| {
            for privilege in privileges.iter_mut() {
                if privilege.id >= 64 || (mask >> privilege.id) & 1 == 0 {
                    privilege.attributes &= !SE_PRIVILEGE_ENABLED_AND_DEFAULT;
                }
            }
        };
        if level < SECURITY_MANDATORY_HIGH_RID {
            keep_enabled(BELOW_HIGH_PRIVILEGES, &mut record.privileges);
        }
        if level < SECURITY_MANDATORY_MEDIUM_RID {
            keep_enabled(BELOW_MEDIUM_PRIVILEGES, &mut record.privileges);
            clear_flags(TOKEN_NOT_LOW);
        } else {
            // SepRemoveAceFromTokenDefaultDacl: a primeira ACE do SID de
            // pacote; depois o pacote e as capacidades.
            if let Some(package) = record.app_container.take() {
                if let Some(dacl) = record.default_dacl.as_mut() {
                    if let Some(index) = dacl.iter().position(|ace| ace.sid.as_ref() == Some(&package)) {
                        dacl.remove(index);
                    }
                }
                record.capabilities.clear();
            }
            flags.atomic().fetch_or(TOKEN_NOT_LOW, core::sync::atomic::Ordering::SeqCst);
        }
        0
    })
    .unwrap_or(STATUS_INVALID_PARAMETER)
}

/// O corpo do NtSetInformationToken sobre o token já referenciado (o
/// acesso de [`required_access`] já conferido); `mode` é o PreviousMode.
pub fn set(token: u64, class: u32, information: u64, length: u32, mode: u8) -> Result<u32, KernelError> {
    if required_access(class).is_none() {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    let tcb = || privilege::single_privilege_check(SE_TCB_PRIVILEGE, mode as u32);
    let status = match class {
        4 | 5 => {
            if length != 8 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let sid = match guest::try_read::<u64>(information).map_err(|_| STATUS_ACCESS_VIOLATION).and_then(capture_sid) {
                Ok(sid) => sid,
                Err(status) => return Ok(status),
            };
            tokens::update(token, |record| {
                let in_groups = |owner_only: bool| record.groups.iter().any(|group| (!owner_only || group.attributes & SE_GROUP_OWNER != 0) && equal_sids(&group.sid, &sid));
                if class == 4 {
                    if !equal_sids(&record.user, &sid) && !in_groups(true) {
                        return STATUS_INVALID_OWNER;
                    }
                    record.owner = sid.clone();
                } else {
                    if !equal_sids(&record.user, &sid) && !in_groups(false) {
                        return STATUS_INVALID_PRIMARY_GROUP;
                    }
                    record.primary_group = sid.clone();
                }
                0
            })
            .unwrap_or(STATUS_INVALID_PARAMETER)
        }
        6 => {
            if length < 8 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let Ok(acl) = guest::try_read::<u64>(information) else { return Ok(STATUS_ACCESS_VIOLATION) };
            let entries = if acl == 0 {
                None
            } else {
                let Ok(header) = guest::try_read_bytes(acl, 8) else { return Ok(STATUS_ACCESS_VIOLATION) };
                let size = u16::from_le_bytes([header[2], header[3]]) as usize;
                if !(2..=4).contains(&header[0]) || size < 8 {
                    return Ok(STATUS_INVALID_ACL);
                }
                let Ok(bytes) = guest::try_read_bytes(acl, size) else { return Ok(STATUS_ACCESS_VIOLATION) };
                Some(policy_descriptor::decode_aces(&bytes))
            };
            tokens::update(token, |record| record.default_dacl = entries).map_or(STATUS_INVALID_PARAMETER, |_| 0)
        }
        12 => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let Ok(session_id) = guest::try_read::<u32>(information) else { return Ok(STATUS_ACCESS_VIOLATION) };
            if !tcb() {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            tokens::update(token, |record| record.session_id = session_id).map_or(STATUS_INVALID_PARAMETER, |_| 0)
        }
        // TokenSessionReference: só o 0 (o token larga a sessão de logon,
        // o SepStopReferencingLogonSession), com o SeTcbPrivilege. Não muda
        // o ModifiedId.
        14 => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let Ok(value) = guest::try_read::<u32>(information) else { return Ok(STATUS_ACCESS_VIOLATION) };
            if !tcb() {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            if value != 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            tokens::stop_referencing_logon_session(token);
            return Ok(0);
        }
        // TokenAuditPolicy: com o SeTcbPrivilege, uma vez só (um
        // PolicySetStatus já gravado é STATUS_INVALID_PARAMETER); sem
        // buffer o token fica marcado sem política (1), com buffer o
        // TOKEN_AUDIT_POLICY (0x1F bytes, alinhado a 4 em UserMode, o
        // SepCaptureAuditPolicy) é copiado (2).
        16 => {
            if !tcb() {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            if tokens::with(token, |record| record.audit_policy_status != 0).unwrap_or(true) {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            let policy = if information == 0 {
                None
            } else {
                if mode != 0 && information & 3 != 0 {
                    return Ok(STATUS_DATATYPE_MISALIGNMENT);
                }
                let Ok(bytes) = guest::try_read_bytes(information, tokens::TOKEN_AUDIT_POLICY_SIZE) else { return Ok(STATUS_ACCESS_VIOLATION) };
                let mut policy = [0u8; tokens::TOKEN_AUDIT_POLICY_SIZE];
                policy.copy_from_slice(&bytes);
                Some(policy)
            };
            tokens::update(token, |record| match policy {
                Some(policy) => {
                    record.audit_policy = policy;
                    record.audit_policy_status = 2;
                }
                None => record.audit_policy_status = 1,
            })
            .map_or(STATUS_INVALID_PARAMETER, |_| 0)
        }
        // TokenOrigin: o LUID OriginatingLogonSession (8 bytes), com o
        // SeTcbPrivilege; só o primeiro valor fica (um token que já tem a
        // origem a conserva), e o ModifiedId muda de qualquer modo.
        17 => {
            if length != 8 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let Ok(origin) = guest::try_read::<u64>(information) else { return Ok(STATUS_ACCESS_VIOLATION) };
            if !tcb() {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            tokens::update(token, |record| {
                if record.originating_logon_session == 0 {
                    record.originating_logon_session = origin;
                }
            })
            .map_or(STATUS_INVALID_PARAMETER, |_| 0)
        }
        // TokenMandatoryPolicy: o TOKEN_MANDATORY_POLICY (4 bytes) com o
        // SeTcbPrivilege, num token que não é o primário de um processo
        // (STATUS_TOKEN_ALREADY_IN_USE); o SeSetMandatoryPolicyToken aceita
        // só NO_WRITE_UP e NEW_PROCESS_MIN.
        27 => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let Ok(policy) = guest::try_read::<u32>(information) else { return Ok(STATUS_ACCESS_VIOLATION) };
            if !tcb() {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            if tokens::in_use(token) {
                return Ok(STATUS_TOKEN_ALREADY_IN_USE);
            }
            if policy & !TOKEN_MANDATORY_POLICY_VALID_MASK != 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            tokens::update(token, |record| record.mandatory_policy = policy).map_or(STATUS_INVALID_PARAMETER, |_| 0)
        }
        25 => {
            if length < 16 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            match capture::sid_and_attributes_array(information, 1, mode) {
                Ok(label) => set_integrity_level(token, &label[0].sid, mode),
                Err(status) => status,
            }
        }
        39 => {
            if information == 0 || length < 16 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let captured = (|| -> Result<(Vec<SecurityAttribute>, Vec<u32>), u32> {
                let attributes_address = guest::try_read::<u64>(information).map_err(|_| STATUS_ACCESS_VIOLATION)?;
                let operations_address = guest::try_read::<u64>(information + 8).map_err(|_| STATUS_ACCESS_VIOLATION)?;
                if attributes_address == 0 || operations_address == 0 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let attributes = security_attributes::capture_information(attributes_address)?;
                let operations = (0..attributes.len() as u64).map(|index| guest::try_read::<u32>(operations_address + index * 4).map_err(|_| STATUS_ACCESS_VIOLATION)).collect::<Result<Vec<u32>, u32>>()?;
                Ok((attributes, operations))
            })();
            let (attributes, operations) = match captured {
                Ok(captured) => captured,
                Err(status) => return Ok(status),
            };
            if !tcb() {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            tokens::update(token, |record| match apply_operations(&mut record.security_attributes, attributes, &operations) {
                Ok(()) => 0,
                Err(status) => status,
            })
            .unwrap_or(STATUS_INVALID_PARAMETER)
        }
        _ => {
            crate::debug_print!("[se] NtSetInformationToken: classe {} sem efeito no OpenNT", class);
            return Ok(STATUS_NOT_IMPLEMENTED);
        }
    };
    if status == 0 {
        tokens::new_modified_id(token);
    }
    Ok(status)
}
