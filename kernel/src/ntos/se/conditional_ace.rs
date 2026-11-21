//! As ACEs condicionais: o AuthzBasepEvaluateAceCondition do ntoskrnl 19041
//! (0x24d5f0, com o AuthzBasepEvaluateExpression 0x24ec90 e o
//! AuthzBasepEvaluateSetRelationship 0x24f9fc), que o SepNormalAccessCheck
//! (0x2d16cd) e o SepMaximumAccessCheck (0x2d1f9c) chamam para uma
//! ACCESS_ALLOWED_CALLBACK_ACE com dados depois do SID. A ACE só vale com a
//! condição verdadeira; a ACCESS_DENIED_CALLBACK_ACE não é avaliada por
//! eles.
//!
//! Os dados da aplicação são a expressão binária do MS-DTYP 2.4.4.17: a
//! assinatura `artx` e os símbolos em notação pós-fixa, avaliados numa
//! pilha:
//!
//! - literais: inteiros (0x01..0x04, oito bytes, o sinal e a base), cadeia
//!   UTF-16 (0x10), cadeia de octetos (0x18), composto (0x50, uma lista de
//!   literais) e SID (0x51);
//! - atributos: local (0xF8, os atributos de segurança do token e, sem
//!   eles, os atributos do sistema do AuthzBasepFindSystemSecurityAttribute:
//!   o `WIN://ISMULTISESSIONSKU` BOOLEAN do
//!   AuthzBasepInitializeSystemSecurityAttributes, o RtlIsMultiSessionSku),
//!   de usuário (0xF9), de recurso (0xFA, as SYSTEM_RESOURCE_ATTRIBUTE_ACE
//!   da SACL) e de dispositivo (0xFB);
//! - operadores relacionais (0x80..0x85 e os de conjunto 0x86, 0x88, 0x8E,
//!   0x8F), de existência (0x87, 0x8D), de pertença (0x89..0x8C,
//!   0x90..0x93) e lógicos (0xA0 &&, 0xA1 ||, 0xA2 !).
//!
//! A lógica tem três valores: verdadeiro, falso e desconhecido. Um atributo
//! que falta é desconhecido nas comparações e como valor lógico; o `!` de um
//! desconhecido continua desconhecido. O resultado que não é verdadeiro
//! (inclusive uma expressão malformada) deixa a ACE de fora. Os tokens do
//! OpenNT não levam afirmações de usuário nem de dispositivo nem grupos de
//! dispositivo: esses atributos faltam e as pertenças de dispositivo são
//! falsas.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::se::security_attributes::{equal_names, AttributeValue, SecurityAttribute};

/// O resultado de uma condição.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Truth {
    True,
    False,
    Unknown,
}

impl Truth {
    fn not(self) -> Truth {
        match self {
            Truth::True => Truth::False,
            Truth::False => Truth::True,
            Truth::Unknown => Truth::Unknown,
        }
    }

    fn from_bool(value: bool) -> Truth {
        if value { Truth::True } else { Truth::False }
    }
}

/// O que a avaliação lê do sujeito e do descritor.
pub struct Context<'a> {
    /// O usuário e os grupos que valem para a pertença: (SID, atributos).
    pub user: &'a [u8],
    pub user_attributes: u32,
    pub groups: &'a [(Vec<u8>, u32)],
    /// Os atributos de segurança do token (as afirmações locais).
    pub local: &'a [SecurityAttribute],
    /// A SACL do descritor (as SYSTEM_RESOURCE_ATTRIBUTE_ACE).
    pub sacl: Option<&'a [u8]>,
}

/// A assinatura `artx` dos dados de uma ACE condicional.
const SIGNATURE: [u8; 4] = *b"artx";

/// CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE.
const CASE_SENSITIVE: u32 = 0x2;
/// SE_GROUP_ENABLED e SE_GROUP_USE_FOR_DENY_ONLY.
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
/// SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE.
const RESOURCE_ATTRIBUTE_ACE: u8 = 0x12;
/// O nome do atributo do sistema e o bit DbgMultiSessionSku do
/// KUSER_SHARED_DATA.SharedDataFlags que o RtlIsMultiSessionSku lê.
const MULTI_SESSION_SKU: &str = "WIN://ISMULTISESSIONSKU";
const DBG_MULTI_SESSION_SKU: u32 = 1 << 8;

/// Um valor de operando.
#[derive(Clone, Debug, PartialEq)]
enum Value {
    Signed(i64),
    Unsigned(u64),
    Text(String),
    Octets(Vec<u8>),
    Sid(Vec<u8>),
}

/// Um item da pilha: um resultado lógico, ou um operando (os valores e se
/// as cadeias comparam com caixa; `None` é o atributo que falta).
#[derive(Clone, Debug)]
enum Item {
    Logic(Truth),
    Operand { values: Option<Vec<Value>>, case_sensitive: bool, from_attribute: bool },
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    Some(String::from_utf16_lossy(&units))
}

/// Um literal em `data[at..]`: (valor, tamanho). Os compostos não entram
/// num composto.
fn literal(data: &[u8], at: usize) -> Option<(Vec<Value>, usize)> {
    let token = *data.get(at)?;
    match token {
        0x01..=0x04 => {
            let value = u64_at(data, at + 1)? as i64;
            Some((alloc::vec![Value::Signed(value)], 11))
        }
        0x10 | 0x18 | 0x51 => {
            let length = u32_at(data, at + 1)? as usize;
            let body = data.get(at + 5..at + 5 + length)?;
            let value = match token {
                0x10 => Value::Text(utf16(body)?),
                0x18 => Value::Octets(body.to_vec()),
                _ => Value::Sid(body.to_vec()),
            };
            Some((alloc::vec![value], 5 + length))
        }
        0x50 => {
            let length = u32_at(data, at + 1)? as usize;
            let end = at + 5 + length;
            data.get(at + 5..end)?;
            let mut values = Vec::new();
            let mut cursor = at + 5;
            while cursor < end {
                if matches!(data.get(cursor), Some(0x50)) {
                    return None;
                }
                let (mut inner, size) = literal(data, cursor)?;
                values.append(&mut inner);
                cursor += size;
            }
            (cursor == end).then_some((values, 5 + length))
        }
        _ => None,
    }
}

/// Os valores de um atributo de segurança.
fn attribute_values(attribute: &SecurityAttribute) -> Vec<Value> {
    attribute
        .values
        .iter()
        .filter_map(|value| match (attribute.kind, value) {
            (1, AttributeValue::Integer(number)) => Some(Value::Signed(*number as i64)),
            (2 | 6, AttributeValue::Integer(number)) => Some(Value::Unsigned(*number)),
            (3, AttributeValue::Text(text)) => Some(Value::Text(text.clone())),
            (5, AttributeValue::Bytes(bytes)) => Some(Value::Sid(bytes.clone())),
            (0x10, AttributeValue::Bytes(bytes)) => Some(Value::Octets(bytes.clone())),
            _ => None,
        })
        .collect()
}

/// O atributo de nome `name` numa lista (nomes sem caixa).
fn find<'a>(list: &'a [SecurityAttribute], name: &str) -> Option<&'a SecurityAttribute> {
    list.iter().find(|attribute| equal_names(&attribute.name, name).unwrap_or(false))
}

/// Os atributos do sistema (o WindowsSystemAttributes do kernel).
fn system_attributes() -> Vec<SecurityAttribute> {
    let flags = crate::ntos::mm::shared_user_data::data().map_or(0, |shared| shared.shared_data_flags.get());
    alloc::vec![SecurityAttribute { name: String::from(MULTI_SESSION_SKU), kind: 6, flags: 0, values: alloc::vec![AttributeValue::Integer((flags & DBG_MULTI_SESSION_SKU != 0) as u64)] }]
}

/// Os atributos de recurso da SACL: cada SYSTEM_RESOURCE_ATTRIBUTE_ACE leva,
/// depois do SID, um CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 (o nome, o tipo,
/// as flags e os valores por deslocamentos relativos ao começo dele).
fn resource_attributes(sacl: &[u8]) -> Vec<SecurityAttribute> {
    let mut list = Vec::new();
    let count = sacl.get(4..6).map_or(0, |bytes| u16::from_le_bytes([bytes[0], bytes[1]])) as usize;
    let mut offset = 8usize;
    for _ in 0..count {
        let Some(&kind) = sacl.get(offset) else { break };
        let size = sacl.get(offset + 2..offset + 4).map_or(0, |bytes| u16::from_le_bytes([bytes[0], bytes[1]])) as usize;
        if size < 8 || offset + size > sacl.len() {
            break;
        }
        let ace = &sacl[offset..offset + size];
        offset += size;
        if kind != RESOURCE_ATTRIBUTE_ACE {
            continue;
        }
        let Some(&sub) = ace.get(9) else { continue };
        let claim = &ace[(8 + 8 + 4 * sub as usize).min(ace.len())..];
        if let Some(attribute) = relative_claim(claim) {
            list.push(attribute);
        }
    }
    list
}

/// Um CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1.
fn relative_claim(claim: &[u8]) -> Option<SecurityAttribute> {
    let name_offset = u32_at(claim, 0)? as usize;
    let kind = u16::from_le_bytes(claim.get(4..6)?.try_into().ok()?);
    let flags = u32_at(claim, 8)?;
    let count = u32_at(claim, 12)? as usize;
    let name_end = (name_offset..claim.len()).step_by(2).find(|&at| claim.get(at..at + 2) == Some(&[0, 0]))?;
    let name = utf16(&claim[name_offset..name_end])?;
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let at = u32_at(claim, 16 + 4 * index)? as usize;
        let value = match kind {
            1 | 2 | 6 => AttributeValue::Integer(u64_at(claim, at)?),
            3 => {
                let end = (at..claim.len()).step_by(2).find(|&cursor| claim.get(cursor..cursor + 2) == Some(&[0, 0]))?;
                AttributeValue::Text(utf16(&claim[at..end])?)
            }
            5 | 0x10 => {
                let length = u32_at(claim, at)? as usize;
                AttributeValue::Bytes(claim.get(at + 4..at + 4 + length)?.to_vec())
            }
            _ => return None,
        };
        values.push(value);
    }
    Some(SecurityAttribute { name, kind, flags, values })
}

/// O operando de um atributo: os valores dele, ou `None` sem ele.
fn attribute_operand(context: &Context, token: u8, name: &str) -> Item {
    let found = match token {
        0xF8 => find(context.local, name).cloned().or_else(|| find(&system_attributes(), name).cloned()),
        0xFA => context.sacl.and_then(|sacl| find(&resource_attributes(sacl), name).cloned()),
        _ => None,
    };
    match found {
        Some(attribute) => Item::Operand { values: Some(attribute_values(&attribute)), case_sensitive: attribute.flags & CASE_SENSITIVE != 0, from_attribute: true },
        None => Item::Operand { values: None, case_sensitive: false, from_attribute: true },
    }
}

/// O valor lógico de um item (o operando sozinho: o atributo que falta é
/// desconhecido; um inteiro diferente de zero, uma cadeia, um SID ou octetos
/// não vazios são verdadeiros).
fn truth_of(item: &Item) -> Truth {
    match item {
        Item::Logic(truth) => *truth,
        Item::Operand { values: None, .. } => Truth::Unknown,
        Item::Operand { values: Some(values), .. } => match values.as_slice() {
            [Value::Signed(number)] => Truth::from_bool(*number != 0),
            [Value::Unsigned(number)] => Truth::from_bool(*number != 0),
            [Value::Text(text)] => Truth::from_bool(!text.is_empty()),
            [Value::Octets(bytes)] | [Value::Sid(bytes)] => Truth::from_bool(!bytes.is_empty()),
            _ => Truth::Unknown,
        },
    }
}

/// A ordem de dois valores do mesmo tipo (`None` quando não se comparam).
fn compare(left: &Value, right: &Value, case_sensitive: bool) -> Option<core::cmp::Ordering> {
    let wide = |value: &Value| match value {
        Value::Signed(number) => Some(*number as i128),
        Value::Unsigned(number) => Some(*number as i128),
        _ => None,
    };
    match (left, right) {
        (Value::Text(a), Value::Text(b)) => {
            if case_sensitive {
                Some(a.cmp(b))
            } else {
                let upper = |text: &str| text.encode_utf16().map(|unit| crate::ntos::rtl::unicode_case::upcase_char(unit).unwrap_or(unit)).collect::<Vec<u16>>();
                Some(upper(a).cmp(&upper(b)))
            }
        }
        (Value::Octets(a), Value::Octets(b)) | (Value::Sid(a), Value::Sid(b)) => Some(a.cmp(b)),
        _ => Some(wide(left)?.cmp(&wide(right)?)),
    }
}

fn equal(left: &Value, right: &Value, case_sensitive: bool) -> Option<bool> {
    compare(left, right, case_sensitive).map(|order| order == core::cmp::Ordering::Equal)
}

/// Cada valor de `inner` está em `outer`.
fn subset(inner: &[Value], outer: &[Value], case_sensitive: bool) -> Option<bool> {
    let mut all = true;
    for value in inner {
        let mut found = false;
        for candidate in outer {
            found |= equal(value, candidate, case_sensitive)?;
        }
        all &= found;
    }
    Some(all)
}

/// Um operador relacional ou de conjunto sobre dois operandos.
fn relation(token: u8, left: &Item, right: &Item) -> Truth {
    let (Item::Operand { values: Some(left_values), case_sensitive: left_case, .. }, Item::Operand { values: Some(right_values), case_sensitive: right_case, .. }) = (left, right) else {
        return Truth::Unknown;
    };
    let case_sensitive = *left_case || *right_case;
    let outcome = match token {
        0x80 | 0x81 => (|| Some(subset(left_values, right_values, case_sensitive)? && subset(right_values, left_values, case_sensitive)?))().map(|same| if token == 0x80 { same } else { !same }),
        0x82..=0x85 => match (left_values.as_slice(), right_values.as_slice()) {
            ([a], [b]) => compare(a, b, case_sensitive).map(|order| match token {
                0x82 => order.is_lt(),
                0x83 => order.is_le(),
                0x84 => order.is_gt(),
                _ => order.is_ge(),
            }),
            _ => None,
        },
        0x86 | 0x8E => subset(right_values, left_values, case_sensitive).map(|contains| if token == 0x86 { contains } else { !contains }),
        0x88 | 0x8F => (|| {
            let mut any = false;
            for value in left_values {
                any |= subset(core::slice::from_ref(value), right_values, case_sensitive)?;
            }
            Some(any)
        })()
        .map(|any| if token == 0x88 { any } else { !any }),
        _ => None,
    };
    outcome.map_or(Truth::Unknown, Truth::from_bool)
}

/// O SID está entre o usuário e os grupos habilitados.
fn member(context: &Context, sid: &[u8]) -> bool {
    if context.user == sid && context.user_attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0 {
        return true;
    }
    context.groups.iter().any(|(group, attributes)| group.as_slice() == sid && attributes & SE_GROUP_ENABLED != 0)
}

/// Um operador de pertença sobre um operando de SIDs.
fn membership(context: &Context, token: u8, operand: &Item) -> Truth {
    let Item::Operand { values: Some(values), .. } = operand else { return Truth::Unknown };
    let mut sids = Vec::with_capacity(values.len());
    for value in values {
        let Value::Sid(sid) = value else { return Truth::Unknown };
        sids.push(sid.as_slice());
    }
    let device = matches!(token, 0x8A | 0x8C | 0x91 | 0x93);
    let any = matches!(token, 0x8B | 0x8C | 0x92 | 0x93);
    let check = |sid: &[u8]| !device && member(context, sid);
    let result = if any { sids.iter().any(|sid| check(sid)) } else { !sids.is_empty() && sids.iter().all(|sid| check(sid)) };
    Truth::from_bool(if token >= 0x90 { !result } else { result })
}

/// Avalia a expressão de uma ACE condicional (os dados da aplicação, depois
/// do SID).
pub fn evaluate(data: &[u8], context: &Context) -> Truth {
    evaluate_expression(data, context).unwrap_or(Truth::Unknown)
}

fn evaluate_expression(data: &[u8], context: &Context) -> Option<Truth> {
    if data.get(..4)? != SIGNATURE {
        return None;
    }
    let mut stack: Vec<Item> = Vec::new();
    let mut at = 4usize;
    while at < data.len() {
        let token = data[at];
        match token {
            0x00 => at += 1,
            0x01..=0x04 | 0x10 | 0x18 | 0x50 | 0x51 => {
                let (values, size) = literal(data, at)?;
                stack.push(Item::Operand { values: Some(values), case_sensitive: false, from_attribute: false });
                at += size;
            }
            0xF8..=0xFB => {
                let length = u32_at(data, at + 1)? as usize;
                let name = utf16(data.get(at + 5..at + 5 + length)?)?;
                stack.push(attribute_operand(context, token, &name));
                at += 5 + length;
            }
            0x80..=0x86 | 0x88 | 0x8E | 0x8F => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                stack.push(Item::Logic(relation(token, &left, &right)));
                at += 1;
            }
            0x87 | 0x8D => {
                let Item::Operand { values, from_attribute: true, .. } = stack.pop()? else { return None };
                let exists = values.is_some();
                stack.push(Item::Logic(Truth::from_bool(if token == 0x87 { exists } else { !exists })));
                at += 1;
            }
            0x89..=0x8C | 0x90..=0x93 => {
                let operand = stack.pop()?;
                stack.push(Item::Logic(membership(context, token, &operand)));
                at += 1;
            }
            0xA0 | 0xA1 => {
                let right = truth_of(&stack.pop()?);
                let left = truth_of(&stack.pop()?);
                let result = match (token, left, right) {
                    (0xA0, Truth::False, _) | (0xA0, _, Truth::False) => Truth::False,
                    (0xA0, Truth::True, Truth::True) => Truth::True,
                    (0xA1, Truth::True, _) | (0xA1, _, Truth::True) => Truth::True,
                    (0xA1, Truth::False, Truth::False) => Truth::False,
                    _ => Truth::Unknown,
                };
                stack.push(Item::Logic(result));
                at += 1;
            }
            0xA2 => {
                let operand = truth_of(&stack.pop()?);
                stack.push(Item::Logic(operand.not()));
                at += 1;
            }
            _ => return None,
        }
    }
    match stack.as_slice() {
        [item] => Some(truth_of(item)),
        _ => None,
    }
}
