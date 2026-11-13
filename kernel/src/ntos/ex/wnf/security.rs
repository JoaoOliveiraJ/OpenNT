//! Acesso aos estados WNF — `system32/ntos/ex/wnf-security.js`.
//!
//! Direitos medidos em ExpWnfCheckCallerAccess: consulta = 1, atualização = 2
//! e consulta explícita entre sessões conhecidas = 0x10.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::ex::wnf::definition::Definition;
use crate::ntos::ex::wnf::name::DecodedName;
use crate::ntos::ob::object_access;
use crate::ntos::ob::object_types::ObjectType;
use crate::ntos::ps::process;
use crate::ntos::se::model::{Ace, Group, SecurityPolicy};
use crate::ntos::se::query_descriptor;
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::KernelError;

const ALL_APPLICATION_PACKAGES: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 1, 0, 0, 0];
const ALL_RESTRICTED_APPLICATION_PACKAGES: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 15, 2, 0, 0, 0, 2, 0, 0, 0];

fn wnf_type() -> ObjectType {
    ObjectType { name: String::from("WnfStateName"), pointer: 0, mapping: [0x12_0001, 2, 0x1F_0000, 0x1F_0013], valid_access: 0x1F_0013 }
}

/// Rótulo obrigatório da SACL: nível e máscara (bit 0 no-write-up, bit 1
/// no-read-up).
struct Label {
    level: u32,
    mask: u32,
}

fn integrity_level(identifier: &[u8]) -> u32 {
    if identifier.len() < 12 {
        return 0x2000;
    }
    u32::from_le_bytes([identifier[8], identifier[9], identifier[10], identifier[11]])
}

/// O descritor já pertence à definição ou instância; DACL ausente concede
/// o acesso (a DACL padrão do chamador não a preenche).
fn read_policy(pointer: u64) -> Option<(SecurityPolicy, Vec<Label>)> {
    let descriptor = query_descriptor::read_descriptor(pointer)?;
    let mut policy = SecurityPolicy { owner: descriptor.owner.clone().unwrap_or_default(), group: descriptor.group.clone(), dacl: None, ..Default::default() };
    if let Some(bytes) = &descriptor.dacl {
        let mut entries = Vec::new();
        let mut offset = 8usize;
        for _ in 0..u16::from_le_bytes([bytes[4], bytes[5]]) {
            let entry_type = bytes[offset];
            let length = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            let mask = u32::from_le_bytes([bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]]);
            entries.push(Ace { sid: (entry_type <= 1).then(|| bytes[offset + 8..offset + length].to_vec()), mask, deny: entry_type == 1, flags: bytes[offset + 1], raw: None });
            offset += length;
        }
        policy.dacl = Some(entries);
    }
    let mut labels = Vec::new();
    if let Some(bytes) = &descriptor.sacl {
        let mut offset = 8usize;
        for _ in 0..u16::from_le_bytes([bytes[4], bytes[5]]) {
            let length = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            if bytes[offset] == 17 && bytes[offset + 1] & 8 == 0 {
                labels.push(Label { level: integrity_level(&bytes[offset + 8..offset + length]), mask: u32::from_le_bytes([bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]]) });
            }
            offset += length;
        }
    }
    Some((policy, labels))
}

fn status_of(result: object_access::AccessResult) -> u32 {
    match result {
        Ok(_) => 0,
        Err(status) => status,
    }
}

/// Passagem pela mesma DACL com outro conjunto de grupos e sem usuário.
fn restricted_pass(policy: &SecurityPolicy, token: &tokens::Token, groups: Vec<Group>, desired: u32) -> u32 {
    let subject = tokens::Token { user: Vec::new(), groups, ..token.clone() };
    status_of(object_access::check_token(policy, &subject, desired, &wnf_type()))
}

/// Verifica o descritor do estado para o sujeito efetivo: rótulos de
/// integridade, DACL, segunda passagem de token restrito e isolamento do
/// AppContainer.
pub fn check(descriptor: u64, desired: u32) -> Result<u32, KernelError> {
    if desired == 0 {
        return Ok(0);
    }
    let thread = process::get_current_thread();
    if thread_tokens::get(thread).is_some_and(|impersonation| impersonation.level < 2) {
        return Ok(0xC000_00A5);
    }
    let Some(pointer) = thread_tokens::effective(thread, false) else { return Ok(0xC000_007C) };
    tokens::retain(pointer)?;
    let result = (|| {
        let Some(token) = tokens::get(pointer) else { return 0xC000_007C };
        let Some((policy, labels)) = read_policy(descriptor) else { return 0xC000_0079 };
        let mapping = wnf_type().mapping;
        for label in &labels {
            if integrity_level(&token.integrity) >= label.level {
                continue;
            }
            if (label.mask & 2 != 0 && desired & mapping[0] != 0) || (label.mask & 1 != 0 && desired & mapping[1] != 0) {
                return 0xC000_0022;
            }
        }
        // Usuário só para negação entra como grupo deny-only.
        let subject = if token.user_attributes & 0x10 != 0 {
            let mut groups = token.groups.clone();
            groups.push(Group { sid: token.user.clone(), attributes: 0x10 });
            tokens::Token { user: Vec::new(), groups, ..token.clone() }
        } else {
            token.clone()
        };
        let mut status = status_of(object_access::check_token(&policy, &subject, desired, &wnf_type()));
        if status != 0 {
            return status;
        }
        // Token restrito: segunda passagem; WRITE_RESTRICTED não restringe a leitura.
        if !token.restricted_sids.is_empty() && !token.write_restricted {
            status = restricted_pass(&policy, &token, token.restricted_sids.iter().map(|entry| Group { sid: entry.sid.clone(), attributes: 4 }).collect(), desired);
        }
        let Some(app_container) = token.app_container.clone().filter(|_| status == 0) else { return status };
        // A autorização do usuário não remove o isolamento do AppContainer.
        let mut identifiers = alloc::vec![Group { sid: app_container, attributes: 4 }, Group { sid: ALL_RESTRICTED_APPLICATION_PACKAGES.to_vec(), attributes: 4 }];
        identifiers.extend(token.capabilities.iter().cloned());
        if !token.less_privileged_app_container {
            identifiers.push(Group { sid: ALL_APPLICATION_PACKAGES.to_vec(), attributes: 4 });
        }
        restricted_pass(&policy, &token, identifiers, desired)
    })();
    tokens::release(pointer)?;
    Ok(result)
}

/// Consulta entre escopos: máquina física é livre; sessão bem conhecida
/// pode ser liberada pelo direito 0x10 da definição; senão exige
/// SeTcbPrivilege habilitado.
pub fn check_cross_scope(name: &DecodedName, lookup_definition: impl FnOnce(u64) -> Result<Result<Definition, u32>, KernelError>) -> Result<u32, KernelError> {
    if name.scope == 3 {
        return Ok(0);
    }
    if name.scope == 1 && name.lifetime == 0 {
        let definition = match lookup_definition(name.decoded_name)? {
            Ok(definition) => definition,
            Err(status) => return Ok(status),
        };
        let status = check(definition.security_descriptor, 0x10)?;
        definition.release();
        if status != 0xC000_0022 {
            return Ok(status);
        }
    }
    let thread = process::get_current_thread();
    if thread_tokens::get(thread).is_some_and(|impersonation| impersonation.level < 2) {
        return Ok(0xC000_0061);
    }
    let privileged = thread_tokens::effective(thread, false).and_then(|token| tokens::with(token, |token| token.privileges.iter().any(|privilege| privilege.id == 7 && privilege.attributes & 2 != 0))).unwrap_or(false);
    Ok(if privileged { 0 } else { 0xC000_0061 })
}
