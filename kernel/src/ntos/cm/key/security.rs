//! Segurança das chaves — `system32/ntos/cm/key-security.js`.
//!
//! Captura a política da criação e verifica o mesmo descritor que pertence ao
//! nó da hive; handles diferentes nunca recebem políticas independentes.

use alloc::vec::Vec;

use crate::ntos::cm::key::objects as key_objects;
use crate::ntos::cm::key::policy as key_policy;
use crate::ntos::cm::registry;
use crate::ntos::ob::{object_access, object_types};
use crate::ntos::se::inherit_descriptor::Captured;
use crate::ntos::se::model::{Ace, SecurityPolicy};
use crate::ntos::se::policy_descriptor::{self, OwnedDescriptor};
use crate::ntos::se::query_descriptor::{self, QueryResult};
use crate::ntos::se::descriptor;
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

fn enabled_privilege(token: &tokens::Token, identifier: u64) -> bool {
    token.privileges.iter().any(|privilege| privilege.id == identifier && privilege.attributes & 2 != 0)
}

/// ACEs complexas mantêm o payload; o avaliador comum recusa direitos que
/// dependem de uma categoria que ainda não sabe avaliar.
pub fn access_policy(descriptor: &Captured) -> SecurityPolicy {
    let mut policy = SecurityPolicy {
        owner: descriptor.owner.clone(),
        group: Some(descriptor.group.clone()),
        dacl: None,
        control: Some(descriptor.control),
        sacl: descriptor.sacl.clone(),
        ..Default::default()
    };
    if descriptor.control & 4 != 0 {
        if let Some(bytes) = &descriptor.dacl {
            policy.dacl_bytes = Some(bytes.clone());
            let mut entries = Vec::new();
            let mut offset = 8usize;
            let count = u16::from_le_bytes([bytes[4], bytes[5]]);
            for _ in 0..count {
                let length = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
                let ace_type = bytes[offset];
                let flags = bytes[offset + 1];
                let mask = u32::from_le_bytes([bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]]);
                if ace_type == 0 || ace_type == 1 {
                    let end = offset + 16 + bytes[offset + 9] as usize * 4;
                    entries.push(Ace { sid: Some(bytes[offset + 8..end].to_vec()), mask, deny: ace_type == 1, flags, raw: None });
                } else {
                    entries.push(Ace { sid: None, mask, deny: false, flags, raw: Some(bytes[offset..offset + length].to_vec()) });
                }
                offset += length;
            }
            policy.dacl = Some(entries);
        }
    }
    policy
}

/// A captura valida antes de ler os componentes. Owner e group ausentes vêm
/// do sujeito; a DACL padrão dele perde para a herança do pai.
pub fn create(parent: &Captured, source: u64, enforce_access_check: bool) -> Result<Result<Captured, u32>, KernelError> {
    let Some(token) = object_access::subject() else { return Ok(Err(0xC000_007C)) };
    if source != 0 && !descriptor::valid(source) {
        return Ok(Err(0xC000_0079));
    }
    let explicit = if source != 0 { query_descriptor::read_descriptor(source) } else { None };
    let subject = tokens::with(token, |token| (token.user.clone(), token.groups.clone(), token.owner.clone(), token.primary_group.clone(), enabled_privilege(token, 18), enabled_privilege(token, 8)));
    let Some((user, groups, owner, primary_group, restore, security)) = subject else { return Ok(Err(0xC000_007C)) };
    if enforce_access_check {
        if let Some(explicit_owner) = explicit.as_ref().and_then(|explicit| explicit.owner.as_ref()) {
            let owned = *explicit_owner == user || groups.iter().any(|group| group.attributes & 8 != 0 && group.attributes & 16 == 0 && group.sid == *explicit_owner);
            if !owned && !restore {
                return Ok(Err(0xC000_005A));
            }
        }
        if explicit.as_ref().is_some_and(|explicit| explicit.sacl.is_some()) && !security {
            return Ok(Err(0xC000_0061));
        }
    }
    let defaults = policy_descriptor::capture(&object_access::capture(Some(token)))?;
    let explicit = explicit.unwrap_or_default();
    let mut creator = Captured {
        control: explicit.control,
        owner: explicit.owner.clone().unwrap_or(owner),
        group: explicit.group.clone().unwrap_or(primary_group),
        dacl: explicit.dacl.clone(),
        sacl: explicit.sacl.clone(),
    };
    if creator.control & 4 == 0 {
        creator.control |= 12;
        creator.dacl = defaults.dacl;
    }
    key_policy::assign(parent, &creator, Some(explicit.control))
}

/// Verifica o acesso pelo descritor do nó. `Ok(acesso)` ou `Err(NTSTATUS)`.
pub fn access(descriptor: &Captured, desired_access: u32, enforce_access_check: bool) -> Result<u32, u32> {
    if enforce_access_check && desired_access == 0 {
        return Err(0xC000_0022);
    }
    let key_type = object_types::key_type();
    let policy = access_policy(descriptor);
    let mapped = object_access::map_generic_access(desired_access, &key_type);
    // MAXIMUM_ALLOWED usa GenericAll na concessão inicial ou numa DACL NULL;
    // SYNCHRONIZE só entra quando pedido explicitamente.
    let mut desired = desired_access;
    if !enforce_access_check && mapped & 0x200_0000 != 0 {
        desired = (mapped & !0x200_0000) | key_type.mapping[3];
    }
    let result = object_access::check(&policy, object_access::subject(), desired, &key_type, !enforce_access_check);
    if result.is_ok() && enforce_access_check && mapped & 0x200_0000 != 0 && policy.dacl.is_none() {
        return Ok((mapped & !0x200_0000) | key_type.mapping[3]);
    }
    result
}

pub fn owned(descriptor: &Captured) -> OwnedDescriptor {
    OwnedDescriptor { control: descriptor.control, owner: Some(descriptor.owner.clone()), group: Some(descriptor.group.clone()), dacl: descriptor.dacl.clone(), sacl: descriptor.sacl.clone() }
}

/// NtQuerySecurityObject de uma chave pelo descritor do nó.
pub fn query(body: u64, information: u32, buffer: u64, capacity: u32) -> Result<QueryResult, KernelError> {
    let node = key_objects::get(body).ok_or_else(|| KernelError::new("unknown key body"))?.node;
    let snapshot = registry::with_node(node, |key| (key.deleted, key.security.clone())).ok_or_else(|| KernelError::new("key node has no security descriptor"))?;
    if snapshot.0 {
        return Ok(QueryResult { status: 0xC000_017C, needed: capacity as usize, information });
    }
    Ok(query_descriptor::query_descriptor(Some(&owned(&snapshot.1)), information, buffer, capacity))
}
