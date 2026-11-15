//! Política de segurança do namespace de objetos.
//!
//! O mesmo descritor é consultado pelos clientes nativos e usado nas
//! verificações de abertura de diretórios. O nó do namespace é dono da
//! política; ela some quando o nó é recolhido.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::model::{sid, Ace, SecurityPolicy};
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

/// O descritor novo de um nó (o do corpo do diretório ou link trocado).
pub fn replace(node: NodeId, policy: SecurityPolicy) {
    POLICIES.lock().insert(node, policy);
}

/// O nó foi recolhido: a política deixa de existir.
pub fn forget(node: NodeId) {
    POLICIES.lock().remove(&node);
}

/// O acesso de `token` a um diretório do namespace pelo SeAccessCheck
/// (`se/access_evaluation.rs`), com o mapeamento do tipo Directory.
/// `Ok(máscara)` ou `Err(NTSTATUS)`.
pub fn access(policy: &SecurityPolicy, token: u64, requested: u32) -> Result<u32, u32> {
    let Some(subject) = tokens::get(token) else { return Err(0xC000_0022) };
    crate::ntos::ob::object_access::check_token(policy, &subject, requested, &crate::ntos::ob::object_types::directory_type())
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
