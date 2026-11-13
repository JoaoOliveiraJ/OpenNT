//! Verificação de acesso contra um SECURITY_DESCRIPTOR e a identidade do
//! sujeito (SeAccessCheck e SeAccessCheckFromState).
//!
//! Reusa a avaliação ordenada de DACL do `token/access.rs`/`object_security.rs`,
//! dirigida aqui por um descritor e pelo GENERIC_MAPPING do chamador em vez do
//! mapeamento fixo de token.
//!
//! Lacuna honesta: não há caminho de concessão por privilégio ligado a
//! descritores (SeSecurityPrivilege para ACCESS_SYSTEM_SECURITY,
//! SeTakeOwnership para WRITE_OWNER); `*Privileges` sai NULL e esse ramo é
//! pulado — igual ao `token/access.rs`, que só honra 8/9 habilitados no
//! objeto token.

use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::types::{
    AccessAllowedAce, AceHeader, Acl, GenericMapping, NtStruct, SecurityImpersonationLevel, SecuritySubjectContext,
    SidAndAttributes, SidAndAttributesHash, TokenAccessInformation,
};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::model::Sid;
use crate::ntos::se::token::tokens;
use crate::ntos::se::{descriptor, out, sid};

const SECURITY_IMPERSONATION: SecurityImpersonationLevel = SecurityImpersonationLevel::SECURITY_IMPERSONATION;

// ACCESS_MASK bits.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const STANDARD_RIGHTS_ALL: u32 = 0x001F_0000;
const GENERIC_MASK: u32 = 0xF000_0000;

// SECURITY_DESCRIPTOR control + ACE/ACL + group attribute bits.
const DACL_PRESENT: u16 = 0x0004;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
const SE_GROUP_ENABLED: u32 = 0x04;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;

// NTSTATUS.
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;

/// Identidade efetiva usada na avaliação da DACL: SID do usuário e os
/// grupos (SID + atributos). Vale tanto para um objeto token quanto para um
/// TOKEN_ACCESS_INFORMATION capturado.
struct Subject {
    user: Sid,
    groups: Vec<(Sid, u32)>,
}

/// Lê um SID do convidado (cabeçalho de 8 bytes + 4 por subautoridade).
fn read_sid(pointer: u64) -> Sid {
    let count = sid::at(pointer).sub_authority_count.get() as usize;
    guest::read_bytes(pointer, 8 + 4 * count)
}

/// RtlMapGenericMask: expande os quatro bits genéricos pelo GENERIC_MAPPING
/// do chamador (Read/Write/Execute/All em 0/4/8/12) e os remove.
fn map_generic(mut mask: u32, mapping: u64) -> u32 {
    if mapping != 0 {
        let mapping = generic_mapping(mapping);
        if mask & 0x8000_0000 != 0 {
            mask |= mapping.generic_read.get();
        }
        if mask & 0x4000_0000 != 0 {
            mask |= mapping.generic_write.get();
        }
        if mask & 0x2000_0000 != 0 {
            mask |= mapping.generic_execute.get();
        }
        if mask & 0x1000_0000 != 0 {
            mask |= mapping.generic_all.get();
        }
    }
    mask & !GENERIC_MASK
}

fn generic_mapping(mapping: u64) -> &'static GenericMapping {
    // SAFETY: PGENERIC_MAPPING do chamador de SeAccessCheck.
    unsafe { GenericMapping::at(mapping) }
}

/// Conjunto "todo o acesso" para MAXIMUM_ALLOWED: GenericAll do mapeamento
/// mais os direitos padrão.
fn all_access(mapping: u64) -> u32 {
    if mapping != 0 {
        generic_mapping(mapping).generic_all.get() | STANDARD_RIGHTS_ALL
    } else {
        STANDARD_RIGHTS_ALL | 0x1FF
    }
}

fn write_result(granted_out: u64, status_out: u64, granted: u32, status: u32) {
    if granted_out != 0 {
        out::<u32>(granted_out).set(granted);
    }
    if status_out != 0 {
        out::<u32>(status_out).set(status);
    }
}

/// KernelMode concede o pedido inteiro (ou tudo, com MAXIMUM_ALLOWED), como
/// o SeAccessCheck real antes de qualquer avaliação de DACL.
fn kernel_grant(desired: u32, previous: u32, mapping: u64, granted_out: u64, status_out: u64) -> bool {
    let granted = if desired & MAXIMUM_ALLOWED != 0 {
        all_access(mapping) | (desired & !MAXIMUM_ALLOWED) | previous
    } else {
        desired | previous
    };
    write_result(granted_out, status_out, granted, 0);
    true
}

/// Avaliação ordenada da DACL do descritor pela identidade `subject`.
/// `None` = DACL nula (ausente ou ponteiro nulo) → concede tudo; `Some(m)` =
/// máscara acumulada de concessões (deny acumula à parte, respeitando a
/// ordem das ACEs, como em `token/access.rs`).
fn evaluate(descriptor: u64, subject: &Subject) -> Option<u32> {
    let control = descriptor::control(descriptor);
    // O dono recebe READ_CONTROL e WRITE_DAC de saída.
    let owner = descriptor::component(descriptor, control, 0);
    let mut granted = if owner != 0 && read_sid(owner) == subject.user { READ_CONTROL | WRITE_DAC } else { 0 };
    if control & DACL_PRESENT == 0 {
        return None;
    }
    let dacl = descriptor::component(descriptor, control, 3);
    if dacl == 0 {
        return None;
    }
    let mut denied = 0u32;
    // SAFETY: componente DACL do descritor (PACL alinhada a WORD).
    let count = unsafe { Acl::at(dacl) }.ace_count.get();
    let mut cursor = dacl + Acl::SIZE;
    // A DACL não é revalidada aqui: com um AceSize ímpar a entrada seguinte
    // fica desalinhada, então os campos são lidos pelo offset do layout.
    for _ in 0..count {
        let ace_type = guest::read::<u8>(cursor + offset_of!(AceHeader, ace_type) as u64);
        let ace_size = guest::read::<u16>(cursor + offset_of!(AceHeader, ace_size) as u64) as u64;
        if ace_size == 0 {
            break;
        }
        if ace_type == ACCESS_ALLOWED_ACE_TYPE || ace_type == ACCESS_DENIED_ACE_TYPE {
            let mask = guest::read::<u32>(cursor + offset_of!(AccessAllowedAce, mask) as u64);
            let ace_sid = read_sid(cursor + offset_of!(AccessAllowedAce, sid_start) as u64);
            let deny = ace_type == ACCESS_DENIED_ACE_TYPE;
            let matches = ace_sid == subject.user
                || subject.groups.iter().any(|(sid, attributes)| {
                    let attributes = *attributes;
                    *sid == ace_sid
                        && ((attributes & SE_GROUP_ENABLED != 0 && attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0)
                            || (deny && attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0))
                });
            if matches {
                if deny {
                    denied |= mask & !granted;
                } else {
                    granted |= mask & !denied;
                }
            }
        }
        cursor += ace_size;
    }
    Some(granted)
}

/// Decisão comum de SeAccessCheck/SeAccessCheckFromState depois de resolver
/// a identidade e já com `desired` mapeado. `subject` ausente (sujeito não
/// resolvido) nega.
fn decide(descriptor: u64, subject: Option<Subject>, desired: u32, previous: u32, mapping: u64, granted_out: u64, status_out: u64) -> bool {
    let Some(subject) = subject else {
        write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
        return false;
    };
    let maximum = desired & MAXIMUM_ALLOWED != 0;
    let explicit = desired & !MAXIMUM_ALLOWED;
    match evaluate(descriptor, &subject) {
        // DACL nula: todos têm acesso total.
        None => {
            let granted = if maximum { all_access(mapping) | explicit | previous } else { explicit | previous };
            write_result(granted_out, status_out, granted, 0);
            true
        }
        Some(dacl) => {
            let accumulated = dacl | previous;
            if maximum {
                if accumulated == 0 {
                    write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
                    false
                } else {
                    write_result(granted_out, status_out, accumulated, 0);
                    true
                }
            } else if explicit & !accumulated != 0 {
                write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
                false
            } else {
                write_result(granted_out, status_out, explicit | previous, 0);
                true
            }
        }
    }
}

/// SeAccessCheck(Sd, Subj, SubjLocked, Desired, PrevGranted, Privileges**,
/// Map, Mode, GrantedAccess*, AccessStatus*); SubjLocked não é usado.
/// Devolve o BOOLEAN do resultado.
#[allow(clippy::too_many_arguments)]
pub fn access_check(descriptor: u64, subject_context: u64, desired: u32, previous: u32, privileges_out: u64, mapping: u64, mode: u32, granted_out: u64, status_out: u64) -> bool {
    let mut desired = desired;
    // Sem caminho de concessão por privilégio: nenhum privilégio foi usado.
    if privileges_out != 0 {
        out::<u64>(privileges_out).set(0);
    }
    if mode == 0 {
        return kernel_grant(desired, previous, mapping, granted_out, status_out);
    }
    if descriptor == 0 {
        write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
        return false;
    }
    if desired & GENERIC_MASK != 0 {
        desired = map_generic(desired, mapping);
    }
    // Token efetivo: ClientToken ao personificar (>= Impersonation), senão
    // PrimaryToken. Personificação fraca com ClientToken nega.
    // SAFETY: PSECURITY_SUBJECT_CONTEXT capturado pelo chamador.
    let context = unsafe { SecuritySubjectContext::at(subject_context) };
    let client = context.client_token.get();
    let token = if client != 0 {
        if context.impersonation_level.get().0 < SECURITY_IMPERSONATION.0 {
            write_result(granted_out, status_out, 0, STATUS_BAD_IMPERSONATION_LEVEL);
            return false;
        }
        client
    } else {
        context.primary_token.get()
    };
    let subject = tokens::with(token, |token| Subject {
        user: token.user.clone(),
        groups: token.groups.iter().map(|group| (group.sid.clone(), group.attributes)).collect(),
    });
    decide(descriptor, subject, desired, previous, mapping, granted_out, status_out)
}

/// Lê um TOKEN_ACCESS_INFORMATION capturado num `Subject`. SidHash@0 →
/// (SidCount@0, SidAttr@8); SID_AND_ATTRIBUTES = (Sid@0, Attributes@8),
/// stride 0x10; o primeiro SID é o usuário, os demais são grupos.
fn subject_from_access_information(information: u64) -> Option<Subject> {
    if information == 0 {
        return None;
    }
    // SAFETY: PTOKEN_ACCESS_INFORMATION capturado pelo chamador.
    let hash = unsafe { TokenAccessInformation::at(information) }.sid_hash.get();
    if hash == 0 {
        return None;
    }
    // SAFETY: SidHash aponta para o SID_AND_ATTRIBUTES_HASH do mesmo bloco.
    let hash = unsafe { SidAndAttributesHash::at(hash) };
    let count = hash.sid_count.get();
    let array = hash.sid_attr.get();
    if array == 0 || count == 0 {
        return None;
    }
    let mut sids: Vec<(Sid, u32)> = Vec::new();
    // SAFETY: SidAttr tem SidCount entradas.
    for entry in unsafe { SidAndAttributes::array_at(array, count as usize) } {
        let sid = entry.sid.get();
        if sid != 0 {
            sids.push((read_sid(sid), entry.attributes.get()));
        }
    }
    if sids.is_empty() {
        return None;
    }
    let user = sids.remove(0).0;
    Some(Subject { user, groups: sids })
}

/// SeAccessCheckFromState(Sd, PrimaryTokenInfo, ClientTokenInfo, Desired,
/// PrevGranted, Privileges**, Map, Mode, GrantedAccess*, AccessStatus*):
/// mesmo algoritmo, com a identidade vinda de um TOKEN_ACCESS_INFORMATION.
#[allow(clippy::too_many_arguments)]
pub fn access_check_from_state(descriptor: u64, primary_info: u64, client_info: u64, desired: u32, previous: u32, privileges_out: u64, mapping: u64, mode: u32, granted_out: u64, status_out: u64) -> bool {
    let mut desired = desired;
    if privileges_out != 0 {
        out::<u64>(privileges_out).set(0);
    }
    if mode == 0 {
        return kernel_grant(desired, previous, mapping, granted_out, status_out);
    }
    if descriptor == 0 {
        write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
        return false;
    }
    if desired & GENERIC_MASK != 0 {
        desired = map_generic(desired, mapping);
    }
    // ImpersonationLevel do TOKEN_ACCESS_INFORMATION do cliente.
    let information = if client_info != 0 {
        // SAFETY: PTOKEN_ACCESS_INFORMATION do chamador.
        if unsafe { TokenAccessInformation::at(client_info) }.impersonation_level.get().0 < SECURITY_IMPERSONATION.0 {
            write_result(granted_out, status_out, 0, STATUS_BAD_IMPERSONATION_LEVEL);
            return false;
        }
        client_info
    } else {
        primary_info
    };
    let subject = subject_from_access_information(information);
    decide(descriptor, subject, desired, previous, mapping, granted_out, status_out)
}
