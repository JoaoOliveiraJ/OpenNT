//! Política de segurança do namespace de objetos.
//!
//! O mesmo descritor é consultado pelos clientes nativos e usado nas
//! verificações de abertura de diretórios. O nó do namespace é dono da
//! política; ela some quando o nó é recolhido.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::model::{equal_sids, sid, Ace, SecurityPolicy};
use crate::ntos::se::token::tokens;
use crate::ntos::ob::object_manager::NodeId;
use crate::rtl::SpinLock;

static POLICIES: SpinLock<BTreeMap<NodeId, SecurityPolicy>> = SpinLock::new(BTreeMap::new());

fn policy(node: NodeId, system_mask: u32, everyone_mask: u32) -> SecurityPolicy {
    POLICIES
        .lock()
        .entry(node)
        .or_insert_with(|| {
            let system = sid(5, &[18]);
            SecurityPolicy {
                owner: system.clone(),
                group: Some(system.clone()),
                dacl: Some(vec![Ace::allow(system, system_mask), Ace::allow(sid(1, &[0]), everyone_mask)]),
                sacl: None,
                dacl_bytes: None,
                integrity: Some(0x2000),
                control: None,
            }
        })
        .clone()
}

/// Diretório: dono SYSTEM e direitos definidos para SYSTEM e Everyone.
pub fn directory(node: NodeId) -> SecurityPolicy {
    policy(node, 0xF000F, 0x20003)
}

/// Reutiliza a política de diretório ou cria a dos demais objetos.
pub fn namespace(node: NodeId, is_directory: bool) -> SecurityPolicy {
    if is_directory {
        directory(node)
    } else {
        policy(node, 0xF0001, 0x20001)
    }
}

/// O nó foi recolhido: a política deixa de existir.
pub fn forget(node: NodeId) {
    POLICIES.lock().remove(&node);
}

/// Expande direitos genéricos, reúne as concessões aplicáveis e limita
/// escritas pela integridade do token. `Ok(máscara)` ou `Err(NTSTATUS)`.
pub fn access(policy: &SecurityPolicy, token: u64, requested: u32) -> Result<u32, u32> {
    let mut mask = requested;
    if mask & 0x8000_0000 != 0 {
        mask |= 0x20001;
    }
    if mask & 0x4000_0000 != 0 {
        mask |= 0x2000C;
    }
    if mask & 0x2000_0000 != 0 {
        mask |= 0x20002;
    }
    if mask & 0x1000_0000 != 0 {
        mask |= 0xF000F;
    }
    mask &= 0x0FFF_FFFF;
    let Some((user, groups, integrity)) = tokens::with(token, |token| (token.user.clone(), token.groups.clone(), token.integrity.clone())) else {
        return Err(0xC000_0022);
    };
    // O dono já dispõe de READ_CONTROL e WRITE_DAC; as ACEs acrescentam o resto.
    let mut allowed = if equal_sids(&policy.owner, &user) { 0x60000 } else { 0 };
    for ace in policy.dacl.iter().flatten() {
        let Some(ace_sid) = &ace.sid else { continue };
        let member = equal_sids(ace_sid, &user) || groups.iter().any(|group| group.attributes & 4 != 0 && group.attributes & 0x10 == 0 && equal_sids(&group.sid, ace_sid));
        if member {
            allowed |= ace.mask;
        }
    }
    // A primeira subautoridade do SID de integridade contém o nível.
    let level = if integrity.len() >= 12 { u32::from_le_bytes([integrity[8], integrity[9], integrity[10], integrity[11]]) } else { 0x2000 };
    if level < policy.integrity.unwrap_or(0x2000) {
        allowed &= !0xD000C;
    }
    if mask & 0x0200_0000 != 0 {
        mask = (mask & !0x0200_0000) | allowed;
    }
    if mask & !allowed != 0 {
        return Err(0xC000_0022);
    }
    Ok(mask)
}

/// Cabeçalho ACL e ACEs do tipo pedido, cada uma com máscara e SID.
fn encode_acl(entries: &[(Vec<u8>, u32)], ace_type: u8) -> Vec<u8> {
    let size = 8 + entries.iter().map(|(sid, _)| 8 + sid.len()).sum::<usize>();
    let mut bytes = vec![0u8; size];
    bytes[0] = 2;
    bytes[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    let mut offset = 8;
    for (sid, mask) in entries {
        bytes[offset] = ace_type;
        bytes[offset + 2..offset + 4].copy_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&mask.to_le_bytes());
        bytes[offset + 8..offset + 8 + sid.len()].copy_from_slice(sid);
        offset += 8 + sid.len();
    }
    bytes
}

/// SECURITY_DESCRIPTOR_RELATIVE só com os componentes pedidos em `flags`;
/// offsets desde o começo do buffer, zero = componente ausente.
pub fn encode(policy: &SecurityPolicy, flags: u32) -> Vec<u8> {
    let owner = (flags & 1 != 0).then(|| policy.owner.clone());
    let group = (flags & 2 != 0).then(|| policy.group.clone().unwrap_or_default());
    let dacl = (flags & 4 != 0).then(|| {
        let entries: Vec<(Vec<u8>, u32)> = policy.dacl.iter().flatten().filter_map(|ace| ace.sid.clone().map(|sid| (sid, ace.mask))).collect();
        encode_acl(&entries, 0)
    });
    let sacl = (flags & 0x18 != 0).then(|| encode_acl(&[(sid(16, &[policy.integrity.unwrap_or(0x2000)]), 1)], 17));
    let parts = [(4usize, owner), (8, group), (12, sacl.clone()), (16, dacl.clone())];
    let total = 20 + parts.iter().map(|(_, part)| part.as_ref().map_or(0, Vec::len)).sum::<usize>();
    let mut bytes = vec![0u8; total];
    bytes[0] = 1;
    let control = 0x8000u16 | if dacl.is_some() { 4 } else { 0 } | if sacl.is_some() { 16 } else { 0 };
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    let mut offset = 20;
    for (field, part) in parts {
        if let Some(part) = part {
            bytes[field..field + 4].copy_from_slice(&(offset as u32).to_le_bytes());
            bytes[offset..offset + part.len()].copy_from_slice(&part);
            offset += part.len();
        }
    }
    bytes
}
