//! Herança de descritores na criação.
//!
//! Atribui ACLs de criação a partir de descritores já capturados. O chamador
//! escolhe e valida owner/group; aqui se aplicam herança e direitos do tipo,
//! sem consultar token nem inventar permissões na leitura.

use alloc::vec::Vec;

use crate::rtl::KernelError;

const OBJECT_ENTRY_TYPES: [u8; 8] = [5, 6, 7, 8, 11, 12, 15, 16];
const MAPPABLE_ENTRY_TYPES: [u8; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14];
const AUDIT_ENTRY_TYPES: [u8; 6] = [2, 3, 7, 8, 13, 14];

/// Descritor capturado: Control, owner, group e ACLs serializadas.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Captured {
    pub control: u16,
    pub owner: Vec<u8>,
    pub group: Vec<u8>,
    pub dacl: Option<Vec<u8>>,
    pub sacl: Option<Vec<u8>>,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Cada entrada conserva o payload, inclusive GUIDs e dados de callbacks.
fn entries(acl: Option<&Vec<u8>>) -> Result<Vec<Vec<u8>>, KernelError> {
    let Some(acl) = acl else { return Ok(Vec::new()) };
    let count = u16_at(acl, 4);
    let mut result = Vec::new();
    let mut offset = 8usize;
    for _ in 0..count {
        let length = u16_at(acl, offset + 2) as usize;
        if length < 4 || offset + length > acl.len() {
            return Err(KernelError::new("invalid captured ACL"));
        }
        result.push(acl[offset..offset + length].to_vec());
        offset += length;
    }
    Ok(result)
}

fn generic_mask(mask: u32, mapping: &[u32; 4], entry_type: u8) -> u32 {
    let mut result = mask & 0x0FFF_FFFF;
    for (index, &value) in mapping.iter().enumerate() {
        if mask & (0x8000_0000 >> index) != 0 {
            result |= value;
        }
    }
    result & (mapping[3] | if AUDIT_ENTRY_TYPES.contains(&entry_type) { 0x0100_0000 } else { 0 })
}

/// ACEs de objeto têm GUIDs opcionais antes do SID.
fn identifier_offset(entry: &[u8]) -> usize {
    if !OBJECT_ENTRY_TYPES.contains(&entry[0]) {
        return 8;
    }
    let flags = u32_at(entry, 8);
    12 + if flags & 1 != 0 { 16 } else { 0 } + if flags & 2 != 0 { 16 } else { 0 }
}

/// CREATOR OWNER (S-1-3-0) e CREATOR GROUP (S-1-3-1) viram owner e group.
fn creator_identifier(entry: &[u8], owner: &[u8], group: &[u8]) -> Option<Vec<u8>> {
    let offset = identifier_offset(entry);
    if entry.len() < offset + 12 || entry[offset] != 1 || entry[offset + 1] != 1 {
        return None;
    }
    if entry[offset + 2..offset + 7].iter().any(|&byte| byte != 0) || entry[offset + 7] != 3 {
        return None;
    }
    match u32_at(entry, offset + 8) {
        0 => Some(owner.to_vec()),
        1 => Some(group.to_vec()),
        _ => None,
    }
}

fn effective_entry(entry: &[u8], flags: u8, mapping: &[u32; 4], replacement: Option<&[u8]>) -> Vec<u8> {
    let mut result = entry.to_vec();
    if let Some(replacement) = replacement {
        let offset = identifier_offset(entry);
        let old_length = 8 + entry[offset + 1] as usize * 4;
        result = Vec::with_capacity(entry.len() - old_length + replacement.len());
        result.extend_from_slice(&entry[..offset]);
        result.extend_from_slice(replacement);
        result.extend_from_slice(&entry[offset + old_length..]);
        let length = result.len() as u16;
        result[2..4].copy_from_slice(&length.to_le_bytes());
    }
    result[1] = flags;
    if MAPPABLE_ENTRY_TYPES.contains(&entry[0]) {
        set_u32(&mut result, 4, generic_mask(u32_at(entry, 4), mapping, entry[0]));
    }
    result
}

/// Uma entrada herdável pode originar duas: a efetiva, com SID e direitos
/// resolvidos, e uma INHERIT_ONLY que conserva as regras dos descendentes.
fn inherit_entry(entry: &[u8], mapping: &[u32; 4], owner: &[u8], group: &[u8], container: bool, automatic: bool, from_parent: bool) -> Vec<Vec<u8>> {
    let flags = entry[1];
    let mappable = MAPPABLE_ENTRY_TYPES.contains(&entry[0]);
    if !from_parent && !automatic {
        let mut copy = entry.to_vec();
        if mappable && flags & 8 == 0 {
            let mask = generic_mask(u32_at(&copy, 4), mapping, entry[0]);
            set_u32(&mut copy, 4, mask);
        }
        return alloc::vec![copy];
    }
    if !from_parent && flags & 16 != 0 {
        return Vec::new();
    }
    let inherited_flag = if from_parent && automatic { 16 } else { 0 };
    let remaining_flags = flags & 0xE0;
    let inheritable = container && flags & 3 != 0 && (!from_parent || flags & 4 == 0);
    let propagation_flags = flags & if from_parent { 3 } else { 7 };
    let mut effective = if from_parent { flags & if container { 2 } else { 1 } != 0 } else { flags & 8 == 0 };
    if from_parent && entry[0] <= 8 && OBJECT_ENTRY_TYPES.contains(&entry[0]) && u32_at(entry, 8) & 2 != 0 {
        effective = false;
    }
    let replacement = if mappable { creator_identifier(entry, owner, group) } else { None };
    let original_mask = u32_at(entry, 4);
    let mapped_mask = generic_mask(original_mask, mapping, entry[0]);
    let requires_mapping = mappable && (replacement.is_some() || mapped_mask != original_mask);
    if mappable && mapped_mask == 0 {
        effective = false;
    }
    let mut result = Vec::new();
    if effective {
        let propagation = if inheritable && !requires_mapping { propagation_flags } else { 0 };
        result.push(effective_entry(entry, remaining_flags | inherited_flag | propagation, mapping, replacement.as_deref()));
    }
    if inheritable && (!effective || requires_mapping) {
        let mut copy = entry.to_vec();
        copy[1] = remaining_flags | inherited_flag | (flags & 16) | propagation_flags | 8;
        result.push(copy);
    }
    result
}

fn assemble(components: &[Vec<u8>], revision: u8) -> Option<Vec<u8>> {
    let length = 8 + components.iter().map(Vec::len).sum::<usize>();
    if length > 0xFFFF {
        return None;
    }
    let mut result = Vec::with_capacity(length);
    result.extend_from_slice(&[revision, 0]);
    result.extend_from_slice(&(length as u16).to_le_bytes());
    result.extend_from_slice(&(components.len() as u16).to_le_bytes());
    result.extend_from_slice(&[0, 0]);
    for entry in components {
        result.extend_from_slice(entry);
    }
    Some(result)
}

struct AssignedAcl {
    control: u16,
    acl: Option<Vec<u8>>,
}

fn assign_acl(parent: Option<&Captured>, creator: &Captured, discretionary: bool, mapping: &[u32; 4], container: bool, automatic: bool) -> Result<Result<AssignedAcl, u32>, KernelError> {
    let (present_bit, defaulted_bit, protected_bit, auto_bit) = if discretionary { (4u16, 8u16, 0x1000u16, 0x400u16) } else { (16, 32, 0x2000, 0x800) };
    let present = creator.control & present_bit != 0;
    let protected_acl = creator.control & protected_bit != 0;
    let defaulted = creator.control & defaulted_bit != 0;
    let creator_acl = if discretionary { creator.dacl.as_ref() } else { creator.sacl.as_ref() };
    let source = if present { creator_acl } else { None };
    let mut control = if protected_acl { protected_bit } else { 0 } | if automatic { auto_bit } else { 0 };
    if automatic && present && source.is_none() && !protected_acl && !defaulted {
        return Ok(Err(0xC000_0077));
    }
    // Rótulos de integridade pertencem à SACL; na DACL o tipo 17 é descartado.
    let applicable = |acl: Option<&Vec<u8>>| -> Result<Vec<Vec<u8>>, KernelError> { Ok(entries(acl)?.into_iter().filter(|entry| !discretionary || entry[0] != 17).collect()) };
    let parent_acl = parent.filter(|parent| parent.control & present_bit != 0).and_then(|parent| if discretionary { parent.dacl.as_ref() } else { parent.sacl.as_ref() });
    let mut inherited = Vec::new();
    if !protected_acl && (automatic || !present || defaulted) {
        for entry in applicable(parent_acl)? {
            inherited.extend(inherit_entry(&entry, mapping, &creator.owner, &creator.group, container, automatic, true));
        }
    }
    let use_creator = present && (!defaulted || inherited.is_empty());
    let mut components = Vec::new();
    if use_creator {
        for entry in applicable(source)? {
            components.extend(inherit_entry(&entry, mapping, &creator.owner, &creator.group, container, automatic, false));
        }
    }
    let inherited_count = inherited.len();
    components.extend(inherited);
    // Um rótulo marca a SACL como autoherdada mesmo sem herança automática.
    if !discretionary && components.iter().any(|entry| entry[0] == 17) {
        control |= auto_bit;
    }
    let has_acl = !components.is_empty() || (use_creator && source.is_some()) || (protected_acl && !present);
    if has_acl || use_creator {
        control |= present_bit;
    }
    if !has_acl && automatic && discretionary {
        control |= protected_bit;
    }
    if !has_acl {
        return Ok(Ok(AssignedAcl { control, acl: None }));
    }
    let parent_revision = if inherited_count > 0 { parent.and_then(|parent| if discretionary { parent.dacl.as_ref() } else { parent.sacl.as_ref() }).map_or(2, |acl| acl[0]) } else { 2 };
    let creator_revision = if use_creator { source.map_or(2, |acl| acl[0]) } else { 2 };
    let revision = 2.max(creator_revision).max(parent_revision);
    Ok(match assemble(&components, revision) {
        Some(acl) => Ok(AssignedAcl { control, acl: Some(acl) }),
        None => Err(0xC000_009A),
    })
}

/// Owner e group já escolhidos pelo contexto de criação; a ACL padrão do
/// token pode vir com DEFAULTED para que a herança prevaleça. `flags`: bit 0
/// herança automática da DACL, bit 1 da SACL.
pub fn assign(parent: Option<&Captured>, creator: &Captured, mapping: &[u32; 4], flags: u32, container: bool) -> Result<Result<Captured, u32>, KernelError> {
    if creator.owner.is_empty() || creator.group.is_empty() {
        return Err(KernelError::new("creation must select owner and group"));
    }
    let discretionary = match assign_acl(parent, creator, true, mapping, container, flags & 1 != 0)? {
        Ok(assigned) => assigned,
        Err(status) => return Ok(Err(status)),
    };
    let system = match assign_acl(parent, creator, false, mapping, container, flags & 2 != 0)? {
        Ok(assigned) => assigned,
        Err(status) => return Ok(Err(status)),
    };
    Ok(Ok(Captured { control: discretionary.control | system.control, owner: creator.owner.clone(), group: creator.group.clone(), dacl: discretionary.acl, sacl: system.acl }))
}
