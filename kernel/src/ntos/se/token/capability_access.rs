//! ACLs de RtlCheckTokenMembershipEx e RtlCheckTokenCapability.
//!
//! A identidade e as restrições vêm do token real.

use alloc::vec::Vec;

use crate::ntos::se::model::{sid, Group, Sid};
use crate::ntos::se::token::tokens::{self, Token};

fn all_application_packages() -> Sid {
    sid(15, &[2, 1])
}

fn all_restricted_application_packages() -> Sid {
    sid(15, &[2, 2])
}

fn contains(identifiers: &[Sid], searched: &[u8]) -> bool {
    identifiers.iter().any(|identifier| identifier.as_slice() == searched)
}

/// Uma ACE de permissão não usa grupos desabilitados ou deny-only.
fn enabled_group(entry: &Group) -> bool {
    entry.attributes & 4 != 0 && entry.attributes & 0x10 == 0
}

/// Só ACEs de permissão, mas com as passagens independentes da identidade
/// normal, das restrições e do AppContainer.
fn permits_allowed_identifiers(token: &Token, allowed: &[Sid], checks_write_access: bool) -> bool {
    let user_allowed = token.user_attributes & 0x10 == 0 && contains(allowed, &token.user);
    let group_allowed = token.groups.iter().any(|group| enabled_group(group) && contains(allowed, &group.sid));
    if !user_allowed && !group_allowed {
        return false;
    }
    if !token.restricted_sids.is_empty() && (!token.write_restricted || checks_write_access) && !token.restricted_sids.iter().any(|entry| contains(allowed, &entry.sid)) {
        return false;
    }
    let Some(app_container) = &token.app_container else { return true };
    // LPAC não participa de ALL_APPLICATION_PACKAGES; a ACE de restricted
    // packages vale também para o AppContainer comum.
    if contains(allowed, &all_restricted_application_packages()) {
        return true;
    }
    if !token.less_privileged_app_container && contains(allowed, &all_application_packages()) {
        return true;
    }
    if contains(allowed, app_container) {
        return true;
    }
    token.capabilities.iter().any(|entry| enabled_group(entry) && contains(allowed, &entry.sid))
}

/// Membership pede só o bit de leitura 1. A flag 2 inclui a ACE LPAC; ambas
/// incluem a ACE de ALL_APPLICATION_PACKAGES.
pub fn permits_membership(token: u64, identifier: Option<&[u8]>, flags: u32) -> bool {
    let mut identifiers: Vec<Sid> = identifier.map(|identifier| alloc::vec![identifier.to_vec()]).unwrap_or_default();
    if flags & 3 != 0 {
        identifiers.push(all_application_packages());
    }
    if flags & 2 != 0 {
        identifiers.push(all_restricted_application_packages());
    }
    tokens::with(token, |record| permits_allowed_identifiers(record, &identifiers, false)).unwrap_or(false)
}

/// Um SeAccessCheck só de ACEs de permissão para `allowed`, sobre o token
/// pelo ponteiro (o SeIsSystemContext pede o acesso 1, que não é escrita).
pub fn permits_identifiers(token: u64, allowed: &[Sid], checks_write_access: bool) -> bool {
    tokens::with(token, |record| permits_allowed_identifiers(record, allowed, checks_write_access)).unwrap_or(false)
}

/// Capability pede 0x10001 (inclui DELETE): WRITE_RESTRICTED também passa
/// pelos SIDs restritos.
pub fn permits_capability(token: u64, identifier: Option<&[u8]>) -> bool {
    tokens::with(token, |record| {
        let mut identifiers: Vec<Sid> = alloc::vec![record.user.clone()];
        if let Some(identifier) = identifier {
            identifiers.push(identifier.to_vec());
        }
        permits_allowed_identifiers(record, &identifiers, true)
    })
    .unwrap_or(false)
}
