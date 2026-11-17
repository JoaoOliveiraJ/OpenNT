//! Descritor da política do objeto.
//!
//! Identidades, ACEs, flags e bytes capturados vêm do dono; nada é
//! inferido do handle.

use alloc::vec::Vec;

use super::model::{Ace, SecurityPolicy};
use crate::rtl::KernelError;

const OBJECT_ACE_TYPES: [u8; 8] = [5, 6, 7, 8, 11, 12, 15, 16];

/// Componentes de um descritor (os quatro opcionais).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnedDescriptor {
    pub control: u16,
    pub owner: Option<Vec<u8>>,
    pub group: Option<Vec<u8>>,
    pub dacl: Option<Vec<u8>>,
    pub sacl: Option<Vec<u8>>,
}

/// Formato compacto de uma ACE simples, ou a representação capturada.
fn encode_entry(entry: &Ace) -> Result<Vec<u8>, KernelError> {
    if let Some(raw) = &entry.raw {
        return Ok(raw.clone());
    }
    let Some(sid) = &entry.sid else {
        return Err(KernelError::new("owned security ACE has no SID"));
    };
    let mut bytes = Vec::with_capacity(8 + sid.len());
    bytes.push(entry.deny as u8);
    bytes.push(entry.flags);
    bytes.extend_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
    bytes.extend_from_slice(&entry.mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    Ok(bytes)
}

/// Listas já capturadas têm precedência (conservam revisão e ACEs que o
/// runtime não reduz à forma compacta).
fn encode_discretionary_acl(policy: &SecurityPolicy) -> Result<Option<Vec<u8>>, KernelError> {
    let Some(entries) = &policy.dacl else { return Ok(None) };
    if let Some(bytes) = &policy.dacl_bytes {
        return Ok(Some(bytes.clone()));
    }
    let encoded = entries.iter().map(encode_entry).collect::<Result<Vec<_>, _>>()?;
    let length = 8 + encoded.iter().map(Vec::len).sum::<usize>();
    if length > 0xFFFF {
        return Err(KernelError::new("owned security ACL exceeds its native length"));
    }
    let revision = if encoded.iter().any(|entry| OBJECT_ACE_TYPES.contains(&entry[0])) { 4 } else { 2 };
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(&[revision, 0]);
    bytes.extend_from_slice(&(length as u16).to_le_bytes());
    bytes.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    for entry in encoded {
        bytes.extend_from_slice(&entry);
    }
    Ok(Some(bytes))
}

/// A política NO_WRITE_UP explícita vira uma ACE de integridade (tipo 17).
fn encode_integrity_acl(integrity: u32) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 28];
    bytes[0] = 2;
    bytes[2..4].copy_from_slice(&28u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[8] = 17;
    bytes[10..12].copy_from_slice(&20u16.to_le_bytes());
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 16]);
    bytes[24..28].copy_from_slice(&integrity.to_le_bytes());
    bytes
}

/// Os bits PRESENT descrevem a política atribuída; os demais bits de
/// controle continuam sendo da captura do dono.
pub fn capture(policy: &SecurityPolicy) -> Result<OwnedDescriptor, KernelError> {
    let mut control = policy.control.unwrap_or(0) & 0x7FFF;
    let dacl = encode_discretionary_acl(policy)?;
    // Toda política Rust tem o campo DACL (NULL = presente e nula).
    control |= 4;
    let sacl = policy.sacl.clone().or_else(|| policy.integrity.map(encode_integrity_acl));
    if sacl.is_some() {
        control |= 16;
    }
    Ok(OwnedDescriptor {
        control,
        owner: (!policy.owner.is_empty()).then(|| policy.owner.clone()),
        group: policy.group.clone(),
        dacl,
        sacl,
    })
}

/// As ACEs de uma ACL já lida: as simples (ACCESS_ALLOWED/ACCESS_DENIED com
/// o SID no fim) decodificadas, as demais com os bytes crus.
pub fn decode_aces(bytes: &[u8]) -> Vec<Ace> {
    let mut entries = Vec::new();
    let count = bytes.get(4..6).map_or(0, |count| u16::from_le_bytes([count[0], count[1]]) as usize);
    let mut offset = 8usize;
    for _ in 0..count {
        if offset + 8 > bytes.len() {
            break;
        }
        let (kind, flags) = (bytes[offset], bytes[offset + 1]);
        let size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if size < 8 || offset + size > bytes.len() {
            break;
        }
        let mask = u32::from_le_bytes([bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]]);
        let raw = bytes[offset..offset + size].to_vec();
        let simple = kind <= 1 && size >= 16 && size == 16 + 4 * bytes[offset + 9] as usize;
        entries.push(Ace { sid: simple.then(|| raw[8..].to_vec()), mask, deny: kind == 1, flags, raw: (!simple).then_some(raw) });
        offset += size;
    }
    entries
}

/// A política de um descritor já lido (o inverso de [`capture`]): dono,
/// grupo, Control, a DACL com os bytes originais (e as ACEs simples
/// decodificadas) e a SACL com o nível do rótulo obrigatório. DACL ausente
/// ou nula concede tudo nas duas formas.
pub fn policy_of(descriptor: &OwnedDescriptor) -> SecurityPolicy {
    let dacl_bytes = if descriptor.control & 4 != 0 { descriptor.dacl.clone() } else { None };
    let dacl = dacl_bytes.as_deref().map(decode_aces);
    let sacl = if descriptor.control & 16 != 0 { descriptor.sacl.clone() } else { None };
    let integrity = sacl.as_ref().and_then(|bytes| {
        let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
        let mut offset = 8usize;
        for _ in 0..count {
            let size = u16::from_le_bytes([*bytes.get(offset + 2)?, *bytes.get(offset + 3)?]) as usize;
            if bytes[offset] == 0x11 && size >= 20 {
                let at = offset + size - 4;
                return Some(u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]));
            }
            offset += size.max(4);
        }
        None
    });
    SecurityPolicy {
        owner: descriptor.owner.clone().unwrap_or_default(),
        group: descriptor.group.clone(),
        dacl,
        sacl,
        dacl_bytes,
        integrity,
        control: Some(descriptor.control & 0x7FFF),
    }
}
