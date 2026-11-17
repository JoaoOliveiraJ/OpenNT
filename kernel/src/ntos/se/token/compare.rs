//! NtCompareTokens(FirstTokenHandle, SecondTokenHandle, Equal*).
//!
//! Medido no ntoskrnl 19041 (NtCompareTokens, SepCompareSidAndAttributeArrays,
//! AuthzBasepCompareLegacySecurityAttributesInformation):
//!
//! - Em UserMode, `Equal` é sondado para escrita (1 byte) antes de tudo; a
//!   falha volta como STATUS_ACCESS_VIOLATION sem escrever nada.
//! - Os dois handles são referenciados com TOKEN_QUERY (SeTokenObjectType).
//!   Se a referência de um deles falha, `*Equal = FALSE` e o status volta.
//!   O mesmo valor de handle nos dois, ou o mesmo objeto, dá TRUE sem
//!   comparar.
//! - A comparação, nesta ordem: o SID do usuário e os bits 0x14
//!   (SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY) dos atributos dele; o
//!   TokenIsAppContainer dos dois e, com os dois em AppContainer, o SID do
//!   pacote e as capacidades; a presença do TrustLevelSid e, com os dois, o
//!   SID; o SeTokenIsRestricted dos dois e, com os dois restritos, o
//!   SeTokenIsWriteRestricted e os SIDs restritos; as máscaras Enabled e
//!   Present dos privilégios; o MandatoryPolicy; os grupos
//!   (UserAndGroups[1..]); as claims (pClaimAttributes) e os atributos de
//!   segurança.
//! - SepCompareSidAndAttributeArrays: contagens iguais; depois do prefixo
//!   que bate posição a posição, cada entrada restante de um lado precisa de
//!   uma igual (SID e bits 0x14) no resto do outro, nos dois sentidos.
//! - Atributos de segurança: só contam os sem
//!   TOKEN_SECURITY_ATTRIBUTE_COMPARE_IGNORE (0x40) e cujo nome não começa
//!   com "APPID://" (sem caixa). As contagens dos relevantes batem e cada
//!   relevante do primeiro tem, no segundo, um atributo com o mesmo nome,
//!   tipo, flags e número de valores, com cada valor presente no outro.
//!
//! O token do OpenNT guarda o rótulo de integridade fora da lista de grupos
//! (o NT o guarda em UserAndGroups); ele entra na comparação como mais um
//! grupo. O OpenNT não tem TrustLevelSid nem claims de usuário ou
//! dispositivo nos tokens: os dois lados ficam ausentes e iguais.

use alloc::vec::Vec;

use super::tokens::{self, Token};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::state::{self, probe_user_write};
use crate::ntos::ps::user::tokens::lookup;
use crate::ntos::se::model::{Group, Sid};
use crate::ntos::se::security_attributes::{self, AttributeValue, SecurityAttribute};
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const TOKEN_QUERY: u32 = 0x8;
/// SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY.
const COMPARED_GROUP_BITS: u32 = 0x14;
/// SE_PRIVILEGE_ENABLED.
const PRIVILEGE_ENABLED: u32 = 0x2;
/// SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED do rótulo nos grupos.
const INTEGRITY_GROUP: u32 = 0x60;
/// TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE.
const ATTRIBUTE_CASE_SENSITIVE: u32 = 0x2;
/// TOKEN_SECURITY_ATTRIBUTE_COMPARE_IGNORE.
const ATTRIBUTE_COMPARE_IGNORE: u32 = 0x40;

fn same_entry(left: &Group, right: &Group) -> bool {
    left.sid == right.sid && (left.attributes ^ right.attributes) & COMPARED_GROUP_BITS == 0
}

/// SepCompareSidAndAttributeArrays.
fn compare_sid_and_attribute_arrays(left: &[Group], right: &[Group]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let start = left.iter().zip(right).take_while(|(a, b)| same_entry(a, b)).count();
    if start == left.len() {
        return true;
    }
    let (left_rest, right_rest) = (&left[start..], &right[start..]);
    left_rest.iter().all(|entry| right_rest.iter().any(|other| same_entry(entry, other))) && right_rest.iter().all(|entry| left_rest.iter().any(|other| same_entry(entry, other)))
}

/// UserAndGroups[1..] como o NT o guarda: os grupos e o rótulo de
/// integridade.
fn groups_of(token: &Token) -> Vec<Group> {
    let mut groups = token.groups.clone();
    if !token.integrity.is_empty() {
        groups.push(Group { sid: token.integrity.clone(), attributes: INTEGRITY_GROUP });
    }
    groups
}

/// As máscaras Present e Enabled do SEP_TOKEN_PRIVILEGES.
fn privilege_masks(token: &Token) -> (u64, u64) {
    token.privileges.iter().filter(|privilege| privilege.id < 64).fold((0, 0), |(present, enabled), privilege| {
        let bit = 1u64 << privilege.id;
        (present | bit, if privilege.attributes & PRIVILEGE_ENABLED != 0 { enabled | bit } else { enabled })
    })
}

fn restricted(token: &Token) -> bool {
    !token.restricted_sids.is_empty() || token.write_restricted
}

fn relevant(attribute: &SecurityAttribute) -> bool {
    let prefix = "APPID://";
    let name_prefix: alloc::string::String = attribute.name.chars().take(prefix.len()).collect();
    attribute.flags & ATTRIBUTE_COMPARE_IGNORE == 0 && !security_attributes::equal_names(&name_prefix, prefix).unwrap_or(false)
}

fn same_value(left: &AttributeValue, right: &AttributeValue, case_sensitive: bool) -> bool {
    match (left, right) {
        (AttributeValue::Text(a), AttributeValue::Text(b)) if !case_sensitive => security_attributes::equal_names(a, b).unwrap_or(false),
        _ => left == right,
    }
}

/// AuthzBasepCompareSecurityAttribute: contagem de valores, tipo e flags
/// iguais e cada valor do primeiro presente no segundo.
fn same_attribute(left: &SecurityAttribute, right: &SecurityAttribute) -> bool {
    let case_sensitive = left.flags & ATTRIBUTE_CASE_SENSITIVE != 0;
    left.values.len() == right.values.len() && left.kind == right.kind && left.flags == right.flags && left.values.iter().all(|value| right.values.iter().any(|other| same_value(value, other, case_sensitive)))
}

/// AuthzBasepCompareLegacySecurityAttributesInformation.
fn compare_security_attributes(left: &[SecurityAttribute], right: &[SecurityAttribute]) -> bool {
    let left_relevant: Vec<&SecurityAttribute> = left.iter().filter(|attribute| relevant(attribute)).collect();
    let right_relevant = right.iter().filter(|attribute| relevant(attribute)).count();
    if left_relevant.len() != right_relevant {
        return false;
    }
    left_relevant.iter().all(|attribute| {
        right.iter().find(|other| security_attributes::equal_names(&other.name, &attribute.name).unwrap_or(false)).is_some_and(|other| same_attribute(attribute, other))
    })
}

fn sids_equal(left: &Option<Sid>, right: &Option<Sid>) -> bool {
    left == right
}

/// A comparação do NtCompareTokens entre dois tokens distintos.
pub fn equivalent(first: &Token, second: &Token) -> bool {
    if first.user != second.user || (first.user_attributes ^ second.user_attributes) & COMPARED_GROUP_BITS != 0 {
        return false;
    }
    if first.app_container.is_some() != second.app_container.is_some() {
        return false;
    }
    if first.app_container.is_some() && (!sids_equal(&first.app_container, &second.app_container) || !compare_sid_and_attribute_arrays(&first.capabilities, &second.capabilities)) {
        return false;
    }
    if restricted(first) != restricted(second) {
        return false;
    }
    if restricted(first) && (first.write_restricted != second.write_restricted || !compare_sid_and_attribute_arrays(&first.restricted_sids, &second.restricted_sids)) {
        return false;
    }
    let ((first_present, first_enabled), (second_present, second_enabled)) = (privilege_masks(first), privilege_masks(second));
    if first_enabled != second_enabled || first_present != second_present {
        return false;
    }
    if first.mandatory_policy != second.mandatory_policy {
        return false;
    }
    if !compare_sid_and_attribute_arrays(&groups_of(first), &groups_of(second)) {
        return false;
    }
    compare_security_attributes(&first.security_attributes, &second.security_attributes)
}

/// Grava `*Equal` e devolve `status`; a escrita que falha depois da sonda
/// vira a exceção que o SEH do serviço devolve.
fn finish(equal: u64, value: bool, status: u32) -> u32 {
    if guest::try_write::<u8>(equal, value as u8).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    status
}

/// NtCompareTokens de modo usuário. Devolve o NTSTATUS.
pub fn compare_from_user(first_handle: u64, second_handle: u64, equal: u64) -> u32 {
    if !probe_user_write(equal, 1) {
        return STATUS_ACCESS_VIOLATION;
    }
    let first = match lookup(first_handle, TOKEN_QUERY) {
        Ok(token) => token,
        Err(status) => return finish(equal, false, status),
    };
    if first_handle == second_handle {
        return finish(equal, true, 0);
    }
    let second = match lookup(second_handle, TOKEN_QUERY) {
        Ok(token) => token,
        Err(status) => return finish(equal, false, status),
    };
    if first == second {
        return finish(equal, true, 0);
    }
    let (Some(first), Some(second)) = (tokens::get(first), tokens::get(second)) else {
        return finish(equal, false, 0);
    };
    finish(equal, equivalent(&first, &second), 0)
}

fn nt_compare_tokens(first: u64, second: u64, equal: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(compare_from_user(first, second, equal))
}

/// O handler do serviço NtCompareTokens.
pub fn register_user_services() {
    state::register_handler("NtCompareTokens", nt_compare_tokens);
}
