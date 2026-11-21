//! Autoteste das ACEs condicionais na checagem de acesso
//! (`se/conditional_ace.rs` pelo `se/access_evaluation.rs`), contra o
//! SepNormalAccessCheck, o SepMaximumAccessCheck e o
//! AuthzBasepEvaluateAceCondition do ntoskrnl 19041:
//!
//! - o descritor da definição WNF_SHEL_LOCKSCREEN_ACTIVE de uma instalação
//!   (as ACEs de Authenticated Users com `!(WIN://ISMULTISESSIONSKU)`):
//!   fora de um SKU multissessão o atributo do sistema é falso e o usuário
//!   lê; a mesma ACE com a condição sem o `!` não concede;
//! - os atributos de segurança do token (afirmações locais), com o
//!   Exists, as comparações e as operações de conjunto, e o atributo que
//!   falta, que deixa a condição desconhecida (a ACE não vale, nem negada
//!   pelo `!`);
//! - o Member_of e o Member_of_Any sobre os grupos habilitados;
//! - os atributos de recurso da SACL (SYSTEM_RESOURCE_ATTRIBUTE_ACE);
//! - a ACE de callback sem dados, a expressão sem a assinatura `artx` e a
//!   malformada não valem, e a negada de callback não é avaliada;
//! - o MAXIMUM_ALLOWED soma só as ACEs condicionais verdadeiras.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::se::access_evaluation::{access_check, Subject};
use crate::ntos::se::policy_descriptor::OwnedDescriptor;
use crate::ntos::se::security_attributes::{AttributeValue, SecurityAttribute};

type Assert = fn(bool, &str);

/// O mapeamento genérico das definições WNF (o ExpWnfStateNameMapping:
/// leitura 1, escrita 2) e um de arquivo para o MAXIMUM_ALLOWED.
const WNF_MAPPING: [u32; 4] = [0x1, 0x2, 0x0, 0x3];
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_MANDATORY_ENABLED: u32 = 0x7;

fn sid(authority: u8, sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, sub_authorities.len() as u8, 0, 0, 0, 0, 0, authority];
    for value in sub_authorities {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Uma ACE comum (tipo, máscara, SID) com dados depois do SID.
fn ace(kind: u8, mask: u32, sid: &[u8], data: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len() + data.len();
    let size = (size + 3) & !3;
    let mut bytes = vec![kind, 0];
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(data);
    bytes.resize(size, 0);
    bytes
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = aces.iter().flatten().copied().collect();
    let mut bytes = vec![2, 0];
    bytes.extend_from_slice(&((8 + body.len()) as u16).to_le_bytes());
    bytes.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&body);
    bytes
}

/// O descritor com a DACL (e a SACL, com SE_SACL_PRESENT).
fn descriptor(dacl: &[Vec<u8>], sacl: Option<Vec<u8>>) -> OwnedDescriptor {
    let control = 0x8004 | if sacl.is_some() { 0x10 } else { 0 };
    OwnedDescriptor { control, owner: Some(sid(5, &[18])), group: Some(sid(5, &[18])), dacl: Some(acl(dacl)), sacl }
}

/// Os símbolos de uma expressão.
fn name(token: u8, text: &str) -> Vec<u8> {
    let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut bytes = vec![token];
    bytes.extend_from_slice(&(units.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&units);
    bytes
}

fn integer(value: i64) -> Vec<u8> {
    let mut bytes = vec![0x04];
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&[0x03, 0x02]);
    bytes
}

fn sid_literal(sid: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x51];
    bytes.extend_from_slice(&(sid.len() as u32).to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes
}

fn composite(items: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = items.iter().flatten().copied().collect();
    let mut bytes = vec![0x50];
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&body);
    bytes
}

/// `artx` e os símbolos.
fn condition(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"artx".to_vec();
    for part in parts {
        bytes.extend_from_slice(part);
    }
    bytes
}

/// Um usuário autenticado (S-1-5-11 e Users habilitados), com atributos
/// de segurança.
fn user(attributes: Vec<SecurityAttribute>) -> Subject {
    Subject {
        user: sid(5, &[21, 1, 2, 3, 1000]),
        groups: vec![(sid(5, &[11]), SE_GROUP_MANDATORY_ENABLED), (sid(5, &[32, 545]), SE_GROUP_MANDATORY_ENABLED), (sid(5, &[32, 544]), 0x10)],
        integrity: sid(16, &[0x2000]),
        attributes,
        ..Default::default()
    }
}

fn attribute(name: &str, kind: u16, values: Vec<AttributeValue>) -> SecurityAttribute {
    SecurityAttribute { name: String::from(name), kind, flags: 0, values }
}

pub fn run(assert: Assert) {
    let authenticated = sid(5, &[11]);
    let check = |subject: &Subject, aces: &[Vec<u8>], desired: u32| access_check(Some(&descriptor(aces, None)), subject, desired, 0, &WNF_MAPPING);
    let plain = user(Vec::new());

    // O descritor do WNF_SHEL_LOCKSCREEN_ACTIVE: AU lê com
    // !(WIN://ISMULTISESSIONSKU) (o atributo do sistema é falso aqui).
    let not_multi = condition(&[name(0xF8, "WIN://ISMULTISESSIONSKU"), vec![0xA2]]);
    let multi = condition(&[name(0xF8, "WIN://ISMULTISESSIONSKU")]);
    let wnf = vec![ace(0x09, 0x1, &authenticated, &multi), ace(0x00, 0x3, &sid(5, &[18]), &[]), ace(0x09, 0x1, &authenticated, &not_multi)];
    assert(check(&plain, &wnf, 0x1) == Ok(0x1), "acl condicional: AU le a definicao WNF com !(WIN://ISMULTISESSIONSKU) fora do SKU multissessao");
    assert(check(&plain, &wnf[..2], 0x1).is_err(), "acl condicional: (WIN://ISMULTISESSIONSKU) falso nao concede");

    // Atributos locais do token: Exists, ==, Any_of, Contains e o que falta.
    let claims = user(vec![attribute("Projeto", 3, vec![AttributeValue::Text(String::from("Iniciar"))]), attribute("Nivel", 1, vec![AttributeValue::Integer(7)])]);
    let exists = condition(&[name(0xF8, "projeto"), vec![0x87]]);
    let equal = condition(&[name(0xF8, "Nivel"), integer(7), vec![0x80]]);
    let greater = condition(&[name(0xF8, "Nivel"), integer(9), vec![0x84]]);
    let missing = condition(&[name(0xF8, "Ausente"), integer(1), vec![0x80]]);
    let missing_not = condition(&[name(0xF8, "Ausente"), vec![0xA2]]);
    let text = |value: &str| {
        let units: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut bytes = vec![0x10];
        bytes.extend_from_slice(&(units.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&units);
        bytes
    };
    let any_of = condition(&[name(0xF8, "Projeto"), composite(&[text("Busca"), text("INICIAR")]), vec![0x88]]);
    let contains = condition(&[name(0xF8, "Projeto"), composite(&[text("Iniciar"), text("Busca")]), vec![0x86]]);
    let and_or = condition(&[name(0xF8, "Projeto"), vec![0x87], name(0xF8, "Ausente"), vec![0x87], vec![0xA0], name(0xF8, "Nivel"), integer(7), vec![0x80], vec![0xA1]]);
    let grant = |data: &[u8]| check(&claims, &[ace(0x09, 0x1, &authenticated, data)], 0x1).is_ok();
    assert(grant(&exists), "acl condicional: Exists de um atributo local, sem caixa no nome");
    assert(grant(&equal) && !grant(&greater), "acl condicional: == e > sobre um atributo INT64");
    assert(!grant(&missing) && !grant(&missing_not), "acl condicional: atributo que falta e desconhecido (nem o ! concede)");
    assert(grant(&any_of) && !grant(&contains), "acl condicional: Any_of sem caixa e Contains sobre um atributo STRING");
    assert(grant(&and_or), "acl condicional: && e || com tres valores");

    // Pertença: Member_of (todos) e Member_of_Any (algum) sobre os grupos
    // habilitados; Administradores só de negação não conta.
    let users = sid(5, &[32, 545]);
    let admins = sid(5, &[32, 544]);
    let member_all = condition(&[composite(&[sid_literal(&authenticated), sid_literal(&users)]), vec![0x89]]);
    let member_admins = condition(&[sid_literal(&admins), vec![0x89]]);
    let member_any = condition(&[composite(&[sid_literal(&admins), sid_literal(&users)]), vec![0x8B]]);
    let not_member = condition(&[sid_literal(&admins), vec![0x90]]);
    let device = condition(&[sid_literal(&users), vec![0x8A]]);
    let grant_plain = |data: &[u8]| check(&plain, &[ace(0x09, 0x1, &authenticated, data)], 0x1).is_ok();
    assert(grant_plain(&member_all) && !grant_plain(&member_admins), "acl condicional: Member_of com grupos habilitados e um so de negacao");
    assert(grant_plain(&member_any) && grant_plain(&not_member) && !grant_plain(&device), "acl condicional: Member_of_Any, Not_Member_of e Device_Member_of sem grupos de dispositivo");

    // Atributo de recurso da SACL: um CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
    // INT64 "Classe" = 3 numa SYSTEM_RESOURCE_ATTRIBUTE_ACE de Everyone.
    let mut claim = Vec::new();
    claim.extend_from_slice(&0x18u32.to_le_bytes()); // Name
    claim.extend_from_slice(&1u16.to_le_bytes()); // INT64
    claim.extend_from_slice(&0u16.to_le_bytes());
    claim.extend_from_slice(&0u32.to_le_bytes()); // Flags
    claim.extend_from_slice(&1u32.to_le_bytes()); // ValueCount
    claim.extend_from_slice(&0x26u32.to_le_bytes()); // Values[0]
    claim.extend_from_slice(&[0, 0, 0, 0]);
    claim.extend("Classe".encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
    claim.extend_from_slice(&3u64.to_le_bytes());
    let sacl = acl(&[ace(0x12, 0, &sid(1, &[0]), &claim)]);
    let resource = condition(&[name(0xFA, "Classe"), integer(3), vec![0x80]]);
    let with_resource = descriptor(&[ace(0x09, 0x1, &authenticated, &resource)], Some(sacl));
    assert(access_check(Some(&with_resource), &plain, 0x1, 0, &WNF_MAPPING) == Ok(0x1), "acl condicional: atributo de recurso da SACL");
    assert(check(&plain, &[ace(0x09, 0x1, &authenticated, &resource)], 0x1).is_err(), "acl condicional: atributo de recurso sem SACL e desconhecido");

    // Sem dados, sem `artx` ou malformada: a ACE não vale; a negada de
    // callback não é avaliada.
    assert(check(&plain, &[ace(0x09, 0x1, &authenticated, &[])], 0x1).is_err(), "acl condicional: ACE de callback sem dados nao vale");
    assert(check(&plain, &[ace(0x09, 0x1, &authenticated, b"xtra\x87")], 0x1).is_err(), "acl condicional: dados sem a assinatura artx nao valem");
    assert(check(&plain, &[ace(0x09, 0x1, &authenticated, &condition(&[vec![0xA0]]))], 0x1).is_err(), "acl condicional: expressao malformada nao vale");
    let deny = condition(&[sid_literal(&users), vec![0x89]]);
    assert(check(&plain, &[ace(0x0A, 0x1, &authenticated, &deny), ace(0x00, 0x1, &authenticated, &[])], 0x1) == Ok(0x1), "acl condicional: a negada de callback nao e avaliada");

    // MAXIMUM_ALLOWED: só as condicionais verdadeiras somam.
    let both = [ace(0x09, 0x1, &authenticated, &not_multi), ace(0x09, 0x2, &authenticated, &multi)];
    assert(check(&plain, &both, MAXIMUM_ALLOWED) == Ok(0x1), "acl condicional: MAXIMUM_ALLOWED so com as condicoes verdadeiras");
    let _ = SE_GROUP_ENABLED;
}
