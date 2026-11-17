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
//! - TokenSecurityAttributes (39): o
//!   TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION (16 bytes: os
//!   atributos e o vetor de operações), com o SeTcbPrivilege. As operações,
//!   como o AuthzBasepSetSecurityAttributesToken: NONE (0), REPLACE_ALL (1,
//!   troca todos), ADD (2, um nome que já existe é
//!   STATUS_OBJECT_NAME_COLLISION), DELETE (3, um nome ausente é
//!   STATUS_NOT_FOUND) e REPLACE (4, troca ou acrescenta).
//!
//! As outras classes aceitas ainda não mudam nada no OpenNT
//! (STATUS_NOT_IMPLEMENTED, com registro).

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
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
const STATUS_INVALID_ACL: u32 = 0xC000_0077;
const STATUS_INVALID_SID: u32 = 0xC000_0078;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// As classes do NtSetInformationToken 19041 (bit = classe).
const VALID_CLASSES: u64 = 0x2480_0F8B_5070;
/// SeTcbPrivilege.
const SE_TCB_PRIVILEGE: u64 = 7;
/// SE_GROUP_OWNER.
const SE_GROUP_OWNER: u32 = 0x8;

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
