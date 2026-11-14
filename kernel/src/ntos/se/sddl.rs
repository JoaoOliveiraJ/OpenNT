//! Descritores de segurança escritos em SDDL
//! (SeConvertStringSecurityDescriptorToSecurityDescriptor).
//!
//! Como no ntoskrnl 19041 (rva 0x39df10, sobre o LocalConvertStringSDToSD_Rev1,
//! o mesmo conversor do ConvertStringSecurityDescriptorToSecurityDescriptorW):
//! a entrada é a string (PCWSTR) e a revisão; string ou saída nulas são
//! ERROR_INVALID_PARAMETER e revisão diferente de 1 ERROR_UNKNOWN_REVISION,
//! ambos devolvidos como NTSTATUS 0xC007xxxx (o código Win32 na palavra
//! baixa). O resultado é um SECURITY_DESCRIPTOR self-relative no PagedPool
//! ('SeSd', liberado pelo chamador com ExFreePool), com os componentes na
//! ordem do RtlAbsoluteToSelfRelativeSD (SACL, DACL, dono, grupo), e o
//! tamanho vai para *SecurityDescriptorSize quando pedido.
//!
//! Gramática aceita: os componentes `O:` e `G:` (um SID), `D:` e `S:` (flags
//! P, AI, AR e NO_ACCESS_CONTROL, seguidas das ACEs). Cada ACE é
//! `(tipo;flags;direitos;guid;guid herdado;SID)`; os tipos são as ACEs com
//! máscara e SID (A, D, AU, AL e ML), as flags OI, CI, NP, IO, ID, SA e FA, os
//! direitos os códigos de duas letras (genéricos, padrão, de objeto de
//! diretório, de arquivo, de chave e de rótulo obrigatório) ou um número
//! hexadecimal, e o SID um apelido de duas letras ou `S-1-...`. Os erros são
//! os do conversor original (conferidos contra o do advapi32 desta máquina):
//! SID inválido ERROR_INVALID_SID, direitos ou ACE sem fechamento
//! ERROR_INVALID_ACL, flags de ACE ERROR_INVALID_FLAGS, tipo de ACE ou flag
//! de ACL desconhecidos ERROR_INVALID_DATATYPE, componente desconhecido,
//! repetido ou ACE com campos a mais ERROR_INVALID_PARAMETER. Diferença:
//! ACEs de objeto (OA, OD...), de callback, com GUID ou com atributos de
//! recurso e os apelidos relativos a domínio (DA, DU...) ainda não existem e
//! são recusados (ERROR_INVALID_DATATYPE, ERROR_INVALID_PARAMETER e
//! ERROR_INVALID_SID).

use alloc::vec::Vec;

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::model;

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_FLAGS: u32 = 1004;
const ERROR_UNKNOWN_REVISION: u32 = 1305;
const ERROR_INVALID_ACL: u32 = 1336;
const ERROR_INVALID_SID: u32 = 1337;
const ERROR_INVALID_DATATYPE: u32 = 1804;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// 'SeSd', a tag do SddlpAlloc.
const SDDL_TAG: u32 = 0x6453_6553;
const PAGED_POOL: u32 = 1;

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_SACL_PROTECTED: u16 = 0x2000;
const SE_SELF_RELATIVE: u16 = 0x8000;
const ACL_REVISION: u8 = 2;

/// Apelidos de SID (os que não dependem do domínio).
const ALIASES: &[(&str, u64, &[u32])] = &[
    ("AN", 5, &[7]),
    ("AO", 5, &[32, 548]),
    ("AU", 5, &[11]),
    ("BA", 5, &[32, 544]),
    ("BG", 5, &[32, 546]),
    ("BO", 5, &[32, 551]),
    ("BU", 5, &[32, 545]),
    ("CG", 3, &[1]),
    ("CO", 3, &[0]),
    ("ED", 5, &[9]),
    ("IU", 5, &[4]),
    ("LS", 5, &[19]),
    ("NS", 5, &[20]),
    ("NU", 5, &[2]),
    ("OW", 3, &[4]),
    ("PO", 5, &[32, 550]),
    ("PS", 5, &[10]),
    ("PU", 5, &[32, 547]),
    ("RC", 5, &[12]),
    ("RD", 5, &[32, 555]),
    ("RE", 5, &[32, 552]),
    ("RU", 5, &[32, 554]),
    ("SO", 5, &[32, 549]),
    ("SU", 5, &[6]),
    ("SY", 5, &[18]),
    ("WD", 1, &[0]),
    ("WR", 5, &[33]),
    ("NO", 5, &[32, 556]),
    ("MU", 5, &[32, 558]),
    ("LU", 5, &[32, 559]),
    ("IS", 5, &[32, 568]),
    ("CY", 5, &[32, 569]),
    ("ER", 5, &[32, 573]),
    ("AC", 15, &[2, 1]),
    ("LW", 16, &[4096]),
    ("ME", 16, &[8192]),
    ("MP", 16, &[8448]),
    ("HI", 16, &[12288]),
    ("SI", 16, &[16384]),
];

/// Códigos de direitos de duas letras.
const RIGHTS: &[(&str, u32)] = &[
    ("GA", 0x1000_0000),
    ("GR", 0x8000_0000),
    ("GW", 0x4000_0000),
    ("GX", 0x2000_0000),
    ("RC", 0x0002_0000),
    ("SD", 0x0001_0000),
    ("WD", 0x0004_0000),
    ("WO", 0x0008_0000),
    ("RP", 0x0000_0010),
    ("WP", 0x0000_0020),
    ("CC", 0x0000_0001),
    ("DC", 0x0000_0002),
    ("LC", 0x0000_0004),
    ("SW", 0x0000_0008),
    ("LO", 0x0000_0080),
    ("DT", 0x0000_0040),
    ("CR", 0x0000_0100),
    ("FA", 0x001F_01FF),
    ("FR", 0x0012_0089),
    ("FW", 0x0012_0116),
    ("FX", 0x0012_00A0),
    ("KA", 0x000F_003F),
    ("KR", 0x0002_0019),
    ("KW", 0x0002_0006),
    ("KX", 0x0002_0019),
    ("NR", 0x0000_0001),
    ("NW", 0x0000_0002),
    ("NX", 0x0000_0004),
];

/// Tipos de ACE com máscara e SID.
const ACE_TYPES: &[(&str, u8)] = &[("A", 0x00), ("D", 0x01), ("AU", 0x02), ("AL", 0x03), ("ML", 0x11)];
const ACE_FLAGS: &[(&str, u8)] = &[("OI", 0x01), ("CI", 0x02), ("NP", 0x04), ("IO", 0x08), ("ID", 0x10), ("SA", 0x40), ("FA", 0x80)];

/// O NTSTATUS de um código Win32 do conversor (0xC007xxxx).
fn win32_status(code: u32) -> u32 {
    0xC007_0000 | (code & 0xFFFF)
}

/// Uma ACL montada: flags de controle e os bytes (None = DACL nula).
struct ParsedAcl {
    control: u16,
    bytes: Option<Vec<u8>>,
}

/// Divide `text` em códigos de duas letras da tabela, somando os valores.
fn parse_codes<T: Copy + core::ops::BitOr<Output = T>>(text: &str, table: &[(&str, T)], zero: T) -> Option<T> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut value = zero;
    for index in (0..text.len()).step_by(2) {
        let code = text.get(index..index + 2)?;
        value = value | table.iter().find(|(name, _)| *name == code)?.1;
    }
    Some(value)
}

/// Um número decimal, ou hexadecimal com 0x.
fn parse_number(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Um SID: apelido de duas letras ou `S-1-autoridade-sub...`.
fn parse_sid(text: &str) -> Option<model::Sid> {
    if let Some(rest) = text.strip_prefix("S-1-") {
        let mut parts = rest.split('-');
        let authority = parse_number(parts.next()?)?;
        let subs = parts.map(|part| parse_number(part).and_then(|value| u32::try_from(value).ok())).collect::<Option<Vec<u32>>>()?;
        if authority >= 1 << 48 || subs.len() > 15 {
            return None;
        }
        return Some(model::sid(authority, &subs));
    }
    ALIASES.iter().find(|(name, _, _)| *name == text).map(|(_, authority, subs)| model::sid(*authority, subs))
}

/// Uma ACE `tipo;flags;direitos;guid;guid herdado;SID`.
fn parse_ace(text: &str) -> Result<Vec<u8>, u32> {
    let fields: Vec<&str> = text.split(';').collect();
    if fields.len() != 6 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let ace_type = ACE_TYPES.iter().find(|(name, _)| *name == fields[0]).ok_or(ERROR_INVALID_DATATYPE)?.1;
    let flags = parse_codes(fields[1], ACE_FLAGS, 0u8).ok_or(ERROR_INVALID_FLAGS)?;
    let mask = if fields[2].starts_with("0x") || fields[2].starts_with("0X") { parse_number(fields[2]).and_then(|value| u32::try_from(value).ok()) } else { parse_codes(fields[2], RIGHTS, 0u32) }.ok_or(ERROR_INVALID_ACL)?;
    if !fields[3].is_empty() || !fields[4].is_empty() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let sid = parse_sid(fields[5]).ok_or(ERROR_INVALID_SID)?;
    let size = 8 + sid.len();
    let mut ace = Vec::with_capacity(size);
    ace.push(ace_type);
    ace.push(flags);
    ace.extend_from_slice(&(size as u16).to_le_bytes());
    ace.extend_from_slice(&mask.to_le_bytes());
    ace.extend_from_slice(&sid);
    Ok(ace)
}

/// O corpo de `D:`/`S:`: flags e ACEs entre parênteses.
fn parse_acl(text: &str, dacl: bool) -> Result<ParsedAcl, u32> {
    let (protected, inherited, required, present) = if dacl {
        (SE_DACL_PROTECTED, SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_PRESENT)
    } else {
        (SE_SACL_PROTECTED, SE_SACL_AUTO_INHERITED, SE_SACL_AUTO_INHERIT_REQ, SE_SACL_PRESENT)
    };
    let mut control = present;
    let split = text.find('(').unwrap_or(text.len());
    let (mut flags, mut aces_text) = (&text[..split], &text[split..]);
    let mut null_acl = false;
    while !flags.is_empty() {
        if let Some(rest) = flags.strip_prefix("NO_ACCESS_CONTROL") {
            null_acl = true;
            flags = rest;
        } else if let Some(rest) = flags.strip_prefix("AI") {
            control |= inherited;
            flags = rest;
        } else if let Some(rest) = flags.strip_prefix("AR") {
            control |= required;
            flags = rest;
        } else if let Some(rest) = flags.strip_prefix('P') {
            control |= protected;
            flags = rest;
        } else {
            return Err(ERROR_INVALID_DATATYPE);
        }
    }
    let mut aces = Vec::new();
    let mut count = 0u16;
    while !aces_text.is_empty() {
        let body = aces_text.strip_prefix('(').ok_or(ERROR_INVALID_ACL)?;
        let end = body.find(')').ok_or(ERROR_INVALID_ACL)?;
        aces.extend_from_slice(&parse_ace(&body[..end])?);
        count += 1;
        aces_text = &body[end + 1..];
    }
    if null_acl {
        return if count == 0 { Ok(ParsedAcl { control, bytes: None }) } else { Err(ERROR_INVALID_PARAMETER) };
    }
    let size = 8 + aces.len();
    let mut acl = Vec::with_capacity(size);
    acl.push(ACL_REVISION);
    acl.push(0);
    acl.extend_from_slice(&(size as u16).to_le_bytes());
    acl.extend_from_slice(&count.to_le_bytes());
    acl.extend_from_slice(&[0, 0]);
    acl.extend_from_slice(&aces);
    Ok(ParsedAcl { control, bytes: Some(acl) })
}

/// Índice do próximo componente (`O:`, `G:`, `D:`, `S:`) a partir de `from`,
/// fora de parênteses.
fn next_component(text: &str, from: usize) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0;
    let mut index = from;
    while index + 1 < bytes.len() {
        match bytes[index] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'O' | b'G' | b'D' | b'S' if depth == 0 && bytes[index + 1] == b':' => return index,
            _ => {}
        }
        index += 1;
    }
    bytes.len()
}

/// Os componentes do descritor: (controle, dono, grupo, SACL, DACL).
type Parsed = (u16, Option<model::Sid>, Option<model::Sid>, Option<Vec<u8>>, Option<Vec<u8>>);

fn parse(text: &str) -> Result<Parsed, u32> {
    let text: alloc::string::String = text.chars().filter(|character| !character.is_whitespace()).collect();
    let (mut control, mut owner, mut group, mut sacl, mut dacl) = (SE_SELF_RELATIVE, None, None, None, None);
    let mut index = 0;
    while index < text.len() {
        let end = next_component(&text, index + 2);
        let body = text.get(index + 2..end).ok_or(ERROR_INVALID_PARAMETER)?;
        match text.get(index..index + 2).ok_or(ERROR_INVALID_PARAMETER)? {
            "O:" if owner.is_none() => owner = Some(parse_sid(body).ok_or(ERROR_INVALID_SID)?),
            "G:" if group.is_none() => group = Some(parse_sid(body).ok_or(ERROR_INVALID_SID)?),
            "D:" if control & SE_DACL_PRESENT == 0 => {
                let acl = parse_acl(body, true)?;
                control |= acl.control;
                dacl = acl.bytes;
            }
            "S:" if control & SE_SACL_PRESENT == 0 => {
                let acl = parse_acl(body, false)?;
                control |= acl.control;
                sacl = acl.bytes;
            }
            _ => return Err(ERROR_INVALID_PARAMETER),
        }
        index = end;
    }
    Ok((control, owner, group, sacl, dacl))
}

/// O descritor self-relative: cabeçalho e SACL, DACL, dono e grupo.
fn build((control, owner, group, sacl, dacl): Parsed) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 0x14];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    // Offsets: Owner +4, Group +8, Sacl +0xC, Dacl +0x10.
    for (component, offset_field) in [(sacl.as_deref(), 0xC), (dacl.as_deref(), 0x10), (owner.as_deref(), 4), (group.as_deref(), 8)] {
        if let Some(component) = component {
            let offset = bytes.len() as u32;
            bytes[offset_field..offset_field + 4].copy_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(component);
        }
    }
    bytes
}

/// SeConvertStringSecurityDescriptorToSecurityDescriptor(String,
/// StringSDRevision, SecurityDescriptor*, SecurityDescriptorSize*): devolve
/// o NTSTATUS. As saídas são do chamador de modo kernel.
pub fn convert_string_to_descriptor(string: u64, revision: u32, output: u64, size_output: u64) -> u32 {
    if string == 0 || output == 0 {
        return win32_status(ERROR_INVALID_PARAMETER);
    }
    if revision != 1 {
        return win32_status(ERROR_UNKNOWN_REVISION);
    }
    let mut units = Vec::new();
    let mut cursor = string;
    loop {
        let unit = guest::read16(cursor);
        if unit == 0 {
            break;
        }
        units.push(unit);
        cursor += 2;
    }
    let text = alloc::string::String::from_utf16_lossy(&units);
    let parsed = match parse(&text) {
        Ok(parsed) => parsed,
        Err(code) => return win32_status(code),
    };
    let bytes = build(parsed);
    let descriptor = pool_allocation::allocate_tagged(PAGED_POOL, bytes.len() as u64, SDDL_TAG).unwrap_or(0);
    if descriptor == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(descriptor, &bytes);
    // SAFETY: o PSECURITY_DESCRIPTOR* e o PULONG opcional do chamador.
    unsafe { Field::<u64>::at(output) }.set(descriptor);
    if size_output != 0 {
        // SAFETY: idem.
        unsafe { Field::<u32>::at(size_output) }.set(bytes.len() as u32);
    }
    0
}
