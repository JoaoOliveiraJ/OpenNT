//! Manutenção do descritor de segurança de um objeto já criado: troca de
//! componentes (SeSetSecurityDescriptorInfoEx = RtlpSetSecurityObject),
//! cálculo de herança automática e as verificações auxiliares que os FS
//! chamam ao mudar a segurança (NT: `se\semethod.c`, `rtl\sertl.c`).
//!
//! Transcrito do ntoskrnl 19041 (RtlpSetSecurityObject rva 0x6d70a0):
//! - `*ObjectsSecurityDescriptor` NULL -> STATUS_NO_SECURITY_ON_OBJECT; o
//!   atual precisa ser self-relative (STATUS_BAD_DESCRIPTOR_FORMAT).
//! - Owner/Group vêm da modificação quando selecionados, senão do atual;
//!   SID ausente ou inválido -> STATUS_INVALID_OWNER / STATUS_INVALID_PRIMARY_GROUP.
//!   Owner novo precisa ser atribuível pelo token efetivo (usuário, grupo com
//!   SE_GROUP_OWNER ou SeRestorePrivilege), salvo AutoInheritFlags & 8.
//! - DACL selecionada: a da modificação se DACL_PRESENT, senão NULL; o
//!   Control ganha DACL_PRESENT, o PROTECTED da modificação e
//!   DACL_AUTO_INHERITED quando ela traz AUTO_INHERITED|AUTO_INHERIT_REQ. Não
//!   selecionada: a atual com os bits 0x140C dela. A SACL segue o mesmo
//!   modelo (bits 0x2830), mas cada seletor (SACL 8, LABEL 0x10, ATTRIBUTE
//!   0x20, SCOPE 0x40, TRUST 0x80, FILTER 0x100) troca só as ACEs da sua
//!   classe (tipos 17..21; o resto é auditoria).
//! - Com SEF_DACL/SACL_AUTO_INHERIT (1/2) a ACL nova junta as ACEs
//!   explícitas da modificação às herdadas do descritor atual (a menos que a
//!   modificação seja protegida).
//! - RtlpApplyAclToObject mapeia os direitos genéricos das ACLs finais.
//! - O novo descritor self-relative (cabeçalho, SACL, DACL, owner, group) é
//!   alocado e publicado em `*ObjectsSecurityDescriptor`; o antigo NÃO é
//!   liberado — pertence ao chamador (o ntfs passa um ponteiro para dentro do
//!   seu cache de segurança compartilhada).
//! - Descritores, GENERIC_MAPPING e os ponteiros de saída vêm de chamadores
//!   de kernel (o ntfs), então não são sondados; as ACLs são remontadas em
//!   buffers locais e publicadas com uma cópia em bloco.

use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::types::{GenericMapping, NtStruct, SecurityDescriptorRelative};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_access;
use crate::ntos::se::policy_descriptor::OwnedDescriptor;
use crate::ntos::se::token::tokens;
use crate::ntos::se::{descriptor, out, query_descriptor};

const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_INVALID_OWNER: u32 = 0xC000_005A;
const STATUS_INVALID_PRIMARY_GROUP: u32 = 0xC000_005B;
const STATUS_NO_SECURITY_ON_OBJECT: u32 = 0xC000_00D7;
const STATUS_BAD_DESCRIPTOR_FORMAT: u32 = 0xC000_00E7;

// SECURITY_INFORMATION.
const OWNER_SECURITY_INFORMATION: u32 = 0x01;
const GROUP_SECURITY_INFORMATION: u32 = 0x02;
const DACL_SECURITY_INFORMATION: u32 = 0x04;
const SACL_SECURITY_INFORMATION: u32 = 0x08;
const SYSTEM_ACL_SELECTORS: u32 = 0x1F8;

// AutoInheritFlags.
const SEF_DACL_AUTO_INHERIT: u32 = 0x01;
const SEF_SACL_AUTO_INHERIT: u32 = 0x02;
const SEF_AVOID_OWNER_CHECK: u32 = 0x08;

// SECURITY_DESCRIPTOR_CONTROL.
const SE_OWNER_DEFAULTED: u16 = 0x0001;
const SE_GROUP_DEFAULTED: u16 = 0x0002;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_SACL_PROTECTED: u16 = 0x2000;
const SE_SELF_RELATIVE: u16 = 0x8000;
const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
const DACL_CONTROL_BITS: u16 = 0x140C;
const SACL_CONTROL_BITS: u16 = 0x2830;
const DACL_AUTO_INHERIT_PAIR: u16 = 0x0500;
const SACL_AUTO_INHERIT_PAIR: u16 = 0x0A00;

// ACE.
const INHERIT_ONLY_ACE: u8 = 0x08;
const INHERITED_ACE: u8 = 0x10;
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
/// Tipos (< 11) cujo resultado fica restrito a GenericAll; os de auditoria
/// e alarme mantêm também ACCESS_SYSTEM_SECURITY.
const ALLOW_DENY_TYPES: u32 = 0x673;

const SE_GROUP_OWNER: u32 = 0x08;
const SE_PRIVILEGE_ENABLED: u32 = 0x02;
const SE_RESTORE_PRIVILEGE: u64 = 18;

/// ACEs de uma ACL serializada.
fn entries(acl: Option<&Vec<u8>>) -> Vec<Vec<u8>> {
    let Some(acl) = acl else { return Vec::new() };
    let count = u16::from_le_bytes([acl[4], acl[5]]);
    let mut result = Vec::new();
    let mut offset = 8usize;
    for _ in 0..count {
        let size = u16::from_le_bytes([acl[offset + 2], acl[offset + 3]]) as usize;
        if size < 4 || offset + size > acl.len() {
            break;
        }
        result.push(acl[offset..offset + size].to_vec());
        offset += size;
    }
    result
}

fn assemble(revision: u8, aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
    let mut acl = Vec::with_capacity(size);
    acl.extend_from_slice(&[revision, 0]);
    acl.extend_from_slice(&(size as u16).to_le_bytes());
    acl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    acl.extend_from_slice(&[0, 0]);
    for ace in aces {
        acl.extend_from_slice(ace);
    }
    acl
}

/// Classe de seleção de uma ACE de SACL (SECURITY_INFORMATION que a cobre).
fn system_class(ace_type: u8) -> u32 {
    if (17..=21).contains(&ace_type) { 0x10 << (ace_type - 17) } else { SACL_SECURITY_INFORMATION }
}

/// RtlpApplyAclToObject: mapeia os genéricos das ACEs efetivas.
fn apply_acl_to_object(acl: &mut [u8], mapping: Option<[u32; 4]>) {
    let Some(mapping) = mapping else { return };
    let count = u16::from_le_bytes([acl[4], acl[5]]);
    let mut offset = 8usize;
    for _ in 0..count {
        let (ace_type, flags) = (acl[offset], acl[offset + 1]);
        let size = u16::from_le_bytes([acl[offset + 2], acl[offset + 3]]) as usize;
        if size < 8 {
            break;
        }
        if (ace_type < 11 || ace_type == 13 || ace_type == 14) && flags & INHERIT_ONLY_ACE == 0 {
            let mut mask = u32::from_le_bytes([acl[offset + 4], acl[offset + 5], acl[offset + 6], acl[offset + 7]]);
            for (index, value) in mapping.iter().enumerate() {
                if mask & (0x8000_0000 >> index) != 0 {
                    mask |= value;
                }
            }
            mask &= 0x0FFF_FFFF;
            mask &= if ace_type < 11 && ALLOW_DENY_TYPES & (1 << ace_type) != 0 { mapping[3] } else { mapping[3] | ACCESS_SYSTEM_SECURITY };
            acl[offset + 4..offset + 8].copy_from_slice(&mask.to_le_bytes());
        }
        offset += size;
    }
}

/// RtlpComputeMergedAcl com herança automática: explícitas da modificação +
/// herdadas do atual; modificação protegida descarta as herdadas.
fn merge_inherited(current: Option<&Vec<u8>>, modification: Option<&Vec<u8>>, protected: bool) -> Option<Vec<u8>> {
    let explicit: Vec<Vec<u8>> = entries(modification).into_iter().filter(|ace| ace[1] & INHERITED_ACE == 0).collect();
    let inherited: Vec<Vec<u8>> = if protected { Vec::new() } else { entries(current).into_iter().filter(|ace| ace[1] & INHERITED_ACE != 0).collect() };
    if modification.is_none() && inherited.is_empty() {
        return None;
    }
    let revision = modification.or(current).map_or(2, |acl| acl[0]);
    Some(assemble(revision, &[explicit, inherited].concat()))
}

/// Owner atribuível pelo token efetivo (SepValidOwnerSubjectContext).
fn owner_assignable(owner: &[u8]) -> bool {
    let Some(token) = object_access::subject() else { return false };
    tokens::with(token, |token| {
        token.user == owner
            || token.groups.iter().any(|group| group.sid == owner && group.attributes & SE_GROUP_OWNER != 0)
            || token.privileges.iter().any(|privilege| privilege.id == SE_RESTORE_PRIVILEGE && privilege.attributes & SE_PRIVILEGE_ENABLED != 0)
    })
    .unwrap_or(false)
}

fn valid_sid(sid: &[u8]) -> bool {
    sid.len() >= 8 && sid[0] == 1 && sid[1] <= 15 && sid.len() == 8 + 4 * sid[1] as usize
}

fn read_mapping(mapping: u64) -> Option<[u32; 4]> {
    (mapping != 0).then(|| {
        // SAFETY: PGENERIC_MAPPING de um chamador de kernel.
        let mapping = unsafe { GenericMapping::at(mapping) };
        [mapping.generic_read.get(), mapping.generic_write.get(), mapping.generic_execute.get(), mapping.generic_all.get()]
    })
}

/// Descritor self-relative: cabeçalho, SACL, DACL, owner, group.
fn serialize(control: u16, sacl: Option<&Vec<u8>>, dacl: Option<&Vec<u8>>, owner: &[u8], group: &[u8]) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; SecurityDescriptorRelative::SIZE as usize];
    bytes[offset_of!(SecurityDescriptorRelative, revision)] = SECURITY_DESCRIPTOR_REVISION;
    let control_at = offset_of!(SecurityDescriptorRelative, control);
    bytes[control_at..control_at + 2].copy_from_slice(&control.to_le_bytes());
    let components = [
        (offset_of!(SecurityDescriptorRelative, sacl), sacl.map(Vec::as_slice)),
        (offset_of!(SecurityDescriptorRelative, dacl), dacl.map(Vec::as_slice)),
        (offset_of!(SecurityDescriptorRelative, owner), Some(owner)),
        (offset_of!(SecurityDescriptorRelative, group), Some(group)),
    ];
    for (field, component) in components {
        if let Some(component) = component {
            let offset = bytes.len() as u32;
            bytes[field..field + 4].copy_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(component);
            bytes.resize(bytes.len().div_ceil(4) * 4, 0);
        }
    }
    bytes
}

/// SeSetSecurityDescriptorInfoEx(Object, *SecurityInformation, Modification,
/// *ObjectsSecurityDescriptor, AutoInheritFlags, PoolType, GenericMapping).
pub fn set_security_descriptor_info(information_pointer: u64, modification: u64, object_descriptor: u64, auto_inherit_flags: u32, mapping: u64) -> u32 {
    let information = out::<u32>(information_pointer).get();
    let slot = out::<u64>(object_descriptor);
    let old = slot.get();
    if old == 0 {
        return STATUS_NO_SECURITY_ON_OBJECT;
    }
    if descriptor::control(old) & SE_SELF_RELATIVE == 0 {
        return STATUS_BAD_DESCRIPTOR_FORMAT;
    }
    let current = query_descriptor::read_descriptor(old).unwrap_or_default();
    let modified: OwnedDescriptor = query_descriptor::read_descriptor(modification).unwrap_or_default();
    let owner = if information & OWNER_SECURITY_INFORMATION != 0 {
        match modified.owner.as_deref() {
            Some(owner) if valid_sid(owner) && (auto_inherit_flags & SEF_AVOID_OWNER_CHECK != 0 || owner_assignable(owner)) => owner.to_vec(),
            _ => return STATUS_INVALID_OWNER,
        }
    } else {
        match current.owner.as_deref() {
            Some(owner) if valid_sid(owner) => owner.to_vec(),
            _ => return STATUS_INVALID_OWNER,
        }
    };
    let group_source = if information & GROUP_SECURITY_INFORMATION != 0 { &modified.group } else { &current.group };
    let Some(group) = group_source.as_deref().filter(|group| valid_sid(group)).map(<[u8]>::to_vec) else { return STATUS_INVALID_PRIMARY_GROUP };

    let mut control = SE_SELF_RELATIVE;
    let mut dacl = if information & DACL_SECURITY_INFORMATION != 0 {
        control |= SE_DACL_PRESENT | (modified.control & SE_DACL_PROTECTED);
        if modified.control & DACL_AUTO_INHERIT_PAIR == DACL_AUTO_INHERIT_PAIR {
            control |= SE_DACL_AUTO_INHERITED;
        }
        let source = if modified.control & SE_DACL_PRESENT != 0 { modified.dacl.as_ref() } else { None };
        if auto_inherit_flags & SEF_DACL_AUTO_INHERIT != 0 {
            control |= SE_DACL_AUTO_INHERITED;
            merge_inherited(current.dacl.as_ref(), source, modified.control & SE_DACL_PROTECTED != 0)
        } else {
            source.cloned()
        }
    } else {
        control |= current.control & DACL_CONTROL_BITS;
        current.dacl.clone()
    };

    let selectors = information & SYSTEM_ACL_SELECTORS;
    let mut sacl = if selectors != 0 {
        if selectors & SACL_SECURITY_INFORMATION != 0 {
            control |= SE_SACL_PRESENT | (modified.control & SE_SACL_PROTECTED);
            if modified.control & SACL_AUTO_INHERIT_PAIR == SACL_AUTO_INHERIT_PAIR {
                control |= SE_SACL_AUTO_INHERITED;
            }
        } else {
            control |= current.control & SACL_CONTROL_BITS;
        }
        let source = if modified.control & SE_SACL_PRESENT != 0 { modified.sacl.as_ref() } else { None };
        let replaced = if auto_inherit_flags & SEF_SACL_AUTO_INHERIT != 0 && selectors & SACL_SECURITY_INFORMATION != 0 {
            control |= SE_SACL_AUTO_INHERITED;
            merge_inherited(current.sacl.as_ref(), source, modified.control & SE_SACL_PROTECTED != 0)
        } else {
            source.cloned()
        };
        let taken = entries(replaced.as_ref()).into_iter().filter(|ace| selectors & system_class(ace[0]) != 0);
        let kept = entries(current.sacl.as_ref()).into_iter().filter(|ace| selectors & system_class(ace[0]) == 0);
        let aces: Vec<Vec<u8>> = taken.chain(kept).collect();
        if aces.is_empty() && replaced.is_none() && current.sacl.is_none() {
            None
        } else {
            control |= SE_SACL_PRESENT;
            let revision = replaced.as_ref().or(current.sacl.as_ref()).map_or(2, |acl| acl[0]);
            Some(assemble(revision, &aces))
        }
    } else {
        control |= current.control & SACL_CONTROL_BITS;
        current.sacl.clone()
    };
    if information & OWNER_SECURITY_INFORMATION == 0 {
        control |= current.control & SE_OWNER_DEFAULTED;
    }
    if information & GROUP_SECURITY_INFORMATION == 0 {
        control |= current.control & SE_GROUP_DEFAULTED;
    }
    let generic = read_mapping(mapping);
    for acl in [dacl.as_mut(), sacl.as_mut()].into_iter().flatten() {
        apply_acl_to_object(acl, generic);
    }
    let bytes = serialize(control, sacl.as_ref(), dacl.as_ref(), &owner, &group);
    let pointer = guest::alloc_bytes(bytes.len() as u64);
    if pointer == 0 {
        return STATUS_NO_MEMORY;
    }
    guest::write_bytes(pointer, &bytes);
    slot.set(pointer);
    0
}

/// SeComputeAutoInheritByObjectType(ObjectType, Sd, ParentSd): sem política
/// obrigatória registrada para o tipo (SeRegisterObjectTypeMandatoryPolicy
/// não existe no OpenNT, então a tabela é vazia), herda DACL/SACL
/// automaticamente quando o filho não traz a sua e o pai é autoherdado.
pub fn compute_auto_inherit_by_object_type(child: u64, parent: u64) -> u32 {
    if parent == 0 {
        return 0;
    }
    let parent_control = descriptor::control(parent);
    let child_control = if child != 0 { descriptor::control(child) } else { 0 };
    let mut flags = 0;
    if child_control & SE_DACL_PRESENT == 0 && parent_control & SE_DACL_AUTO_INHERITED != 0 {
        flags |= SEF_DACL_AUTO_INHERIT;
    }
    if child_control & SE_SACL_PRESENT == 0 && parent_control & SE_SACL_AUTO_INHERITED != 0 {
        flags |= SEF_SACL_AUTO_INHERIT;
    }
    flags
}

/// SeCheckForCriticalAceRemoval(CurrentSd, NewSd, Subject, *AceRemoved): no
/// 19041 a detecção (SepCheckForCriticalAceRemoval) só alimenta telemetria;
/// a saída é sempre FALSE.
pub fn check_for_critical_ace_removal(ace_removed: u64) {
    out::<u8>(ace_removed).set(0);
}

/// SeAdjustObjectSecurity: `mov eax, STATUS_NOT_IMPLEMENTED; ret` no 19041.
pub fn adjust_object_security() -> u32 {
    STATUS_NOT_IMPLEMENTED
}
