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
//!
//! O caminho inverso, do descritor e dos SIDs para o texto, fica no fim do
//! arquivo: SeConvertSidToStringSid, SeConvertStringSidToSid e
//! SeConvertSecurityDescriptorToStringSecurityDescriptor, com as tabelas de
//! apelidos, tipos, flags e direitos do ntoskrnl 19041 na ordem dele.

use alloc::string::String;
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

// ---- Do descritor e dos SIDs para o texto -----------------------------------
//
// ntoskrnl 19041: SeConvertSidToStringSid (rva 0x597f50, o
// LocalConvertSidToStringSidW), SeConvertStringSidToSid (rva 0x3bffe0, o
// LocalpConvertStringSidToSid) e
// SeConvertSecurityDescriptorToStringSecurityDescriptor (rva 0x3487a0, o
// LocalConvertSDToStringSD_Rev1 com o LocalConvertAclToString). Os buffers
// saem do PagedPool com a tag 'SeSd' (o SddlpAlloc, zerado) e o chamador os
// libera com ExFreePool. Diferença: ACEs com dados de aplicação (expressões
// condicionais das ACEs de callback, atributos de recurso e filtros de
// acesso) ainda não são decodificadas; o descritor que as tem devolve
// ERROR_NOT_SUPPORTED.

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_INVALID_SID: u32 = 0xC000_0078;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_NOT_SUPPORTED: u32 = 50;

/// A tabela de apelidos do SDDL na ordem do InitializeSidLookupTable (63
/// entradas). Os apelidos relativos a domínio (DA, DG, DU, DD, DC, SA, EA,
/// CA, RS, LA, LG, PA e RO) ficam sem SID fora de um domínio e nunca casam.
const SID_LOOKUP: [(&str, Option<(u64, &[u32])>); 63] = [
    ("DA", None),
    ("DG", None),
    ("DU", None),
    ("DD", None),
    ("DC", None),
    ("SA", None),
    ("EA", None),
    ("CA", None),
    ("AO", Some((5, &[32, 548]))),
    ("BO", Some((5, &[32, 551]))),
    ("PO", Some((5, &[32, 550]))),
    ("SO", Some((5, &[32, 549]))),
    ("RE", Some((5, &[32, 552]))),
    ("RS", None),
    ("AU", Some((5, &[11]))),
    ("PS", Some((5, &[10]))),
    ("CO", Some((3, &[0]))),
    ("OW", Some((3, &[4]))),
    ("CG", Some((3, &[1]))),
    ("SY", Some((5, &[18]))),
    ("IU", Some((5, &[4]))),
    ("NU", Some((5, &[2]))),
    ("SU", Some((5, &[6]))),
    ("ED", Some((5, &[9]))),
    ("RC", Some((5, &[12]))),
    ("WR", Some((5, &[33]))),
    ("AN", Some((5, &[7]))),
    ("LA", None),
    ("LG", None),
    ("BA", Some((5, &[32, 544]))),
    ("CY", Some((5, &[32, 569]))),
    ("BG", Some((5, &[32, 546]))),
    ("BU", Some((5, &[32, 545]))),
    ("PU", Some((5, &[32, 547]))),
    ("WD", Some((1, &[0]))),
    ("PA", None),
    ("RU", Some((5, &[32, 554]))),
    ("LS", Some((5, &[19]))),
    ("NS", Some((5, &[20]))),
    ("RD", Some((5, &[32, 555]))),
    ("NO", Some((5, &[32, 556]))),
    ("MU", Some((5, &[32, 558]))),
    ("LU", Some((5, &[32, 559]))),
    ("IS", Some((5, &[32, 568]))),
    ("LW", Some((16, &[4096]))),
    ("ME", Some((16, &[8192]))),
    ("MP", Some((16, &[8448]))),
    ("HI", Some((16, &[12288]))),
    ("SI", Some((16, &[16384]))),
    ("CY", Some((5, &[32, 569]))),
    ("ER", Some((5, &[32, 573]))),
    ("RO", None),
    ("CD", Some((5, &[32, 574]))),
    ("AC", Some((15, &[2, 1]))),
    ("RA", Some((5, &[32, 575]))),
    ("ES", Some((5, &[32, 576]))),
    ("MS", Some((5, &[32, 577]))),
    ("UD", Some((5, &[84, 0, 0, 0, 0, 0]))),
    ("HA", Some((5, &[32, 578]))),
    ("AA", Some((5, &[32, 579]))),
    ("RM", Some((5, &[32, 580]))),
    ("AS", Some((18, &[1]))),
    ("SS", Some((18, &[2]))),
];

/// Tipos de ACE do texto: (nome, tipo, seletor 1 = DACL / 2 = SACL), na ordem
/// do LookupAceTypeInTable.
const TEXT_ACE_TYPES: [(&str, u8, u32); 17] = [
    ("A", 0x00, 1),
    ("D", 0x01, 1),
    ("OA", 0x05, 1),
    ("OD", 0x06, 1),
    ("AU", 0x02, 2),
    ("AL", 0x03, 2),
    ("OU", 0x07, 2),
    ("OL", 0x08, 2),
    ("ML", 0x11, 2),
    ("TL", 0x14, 2),
    ("FL", 0x15, 2),
    ("XA", 0x09, 1),
    ("XD", 0x0A, 1),
    ("RA", 0x12, 2),
    ("SP", 0x13, 2),
    ("XU", 0x0D, 2),
    ("ZA", 0x0B, 1),
];

/// Tipos de ACE de auditoria e alarme, os únicos que aceitam SA e FA.
const AUDIT_ACE_TYPES: &[u8] = &[0x02, 0x03, 0x07, 0x08, 0x0D, 0x0E, 0x0F, 0x10];

/// Flags de ACE do texto: (nome, flag, seletor, tipos de ACE permitidos ou
/// vazio para todos), na ordem do LookupAceFlagsInTable.
const TEXT_ACE_FLAGS: [(&str, u8, u32, &[u8]); 9] = [
    ("CI", 0x02, 3, &[]),
    ("OI", 0x01, 3, &[]),
    ("NP", 0x04, 3, &[]),
    ("IO", 0x08, 3, &[]),
    ("ID", 0x10, 3, &[]),
    ("CR", 0x20, 1, &[0x00]),
    ("TP", 0x40, 2, &[0x15]),
    ("SA", 0x40, 2, AUDIT_ACE_TYPES),
    ("FA", 0x80, 2, AUDIT_ACE_TYPES),
];

/// Direitos do texto: (nome, máscara exata, seletor; 4 = rótulo obrigatório),
/// na ordem do LookupAccessMaskInTable.
const TEXT_RIGHTS: [(&str, u32, u32); 28] = [
    ("NW", 0x0000_0001, 4),
    ("NR", 0x0000_0002, 4),
    ("NX", 0x0000_0004, 4),
    ("RP", 0x0000_0010, 3),
    ("WP", 0x0000_0020, 3),
    ("CC", 0x0000_0001, 3),
    ("DC", 0x0000_0002, 3),
    ("LC", 0x0000_0004, 3),
    ("SW", 0x0000_0008, 3),
    ("LO", 0x0000_0080, 3),
    ("DT", 0x0000_0040, 3),
    ("CR", 0x0000_0100, 3),
    ("RC", 0x0002_0000, 3),
    ("WD", 0x0004_0000, 3),
    ("WO", 0x0008_0000, 3),
    ("SD", 0x0001_0000, 3),
    ("GA", 0x1000_0000, 3),
    ("GR", 0x8000_0000, 3),
    ("GW", 0x4000_0000, 3),
    ("GX", 0x2000_0000, 3),
    ("FA", 0x001F_01FF, 3),
    ("FR", 0x0012_0089, 3),
    ("FW", 0x0012_0116, 3),
    ("FX", 0x0012_00A0, 3),
    ("KA", 0x000F_003F, 3),
    ("KR", 0x0002_0019, 3),
    ("KW", 0x0002_0006, 3),
    ("KX", 0x0002_0019, 3),
];

/// Flags de controle do texto: (nome, bit, 1 = DACL / 2 = SACL), na ordem do
/// LocalGetStringForControl.
const TEXT_CONTROL: [(&str, u16, u32); 6] = [
    ("P", SE_DACL_PROTECTED, 1),
    ("AR", SE_DACL_AUTO_INHERIT_REQ, 1),
    ("AI", SE_DACL_AUTO_INHERITED, 1),
    ("P", SE_SACL_PROTECTED, 2),
    ("AR", SE_SACL_AUTO_INHERIT_REQ, 2),
    ("AI", SE_SACL_AUTO_INHERITED, 2),
];

/// SddlpAlloc: PagedPool 'SeSd', zerado.
fn sddl_allocate(bytes: u64) -> u64 {
    let pointer = pool_allocation::allocate_tagged(PAGED_POOL, bytes, SDDL_TAG).unwrap_or(0);
    if pointer != 0 {
        guest::write_bytes(pointer, &alloc::vec![0u8; bytes as usize]);
    }
    pointer
}

/// SddlpFree.
fn sddl_free(pointer: u64) {
    if pointer != 0 {
        let _ = pool_allocation::free(pointer, 0);
    }
}

/// Um buffer 'SeSd' com o texto e o NUL (`extra` bytes zerados a mais).
fn sddl_text(text: &str, extra: u64) -> u64 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let buffer = sddl_allocate(units.len() as u64 * 2 + 2 + extra);
    if buffer != 0 {
        guest::write_bytes(buffer, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    }
    buffer
}

fn output_cell<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: parâmetro de saída de um chamador de modo kernel.
    unsafe { Field::<T>::at(address) }
}

/// SeConvertSidToStringSid(Sid, StringSid*): o texto do
/// RtlConvertSidToUnicodeString num buffer 'SeSd'.
pub fn convert_sid_to_string(sid: u64, output: u64) -> u32 {
    if sid == 0 || output == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let text = match crate::ntos::rtl::security::sid_text(sid) {
        Ok(text) => text,
        Err(status) => return status,
    };
    let buffer = sddl_text(&text, 0);
    if buffer == 0 {
        return STATUS_NO_MEMORY;
    }
    output_cell::<u64>(output).set(buffer);
    0
}

/// SeConvertStringSidToSid(StringSid, Sid*). Só a forma `S-R-I-S...` é
/// aceita; a busca do texto na tabela de apelidos que vem depois nunca casa,
/// porque nenhum apelido começa com "S-". Uma falha cujo ponto de parada é
/// o fim da string devolve sucesso sem tocar no *Sid; as outras liberam o
/// *Sid anterior e devolvem STATUS_INVALID_SID.
pub fn convert_string_to_sid(string: u64, output: u64) -> u32 {
    if string == 0 || output == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut end = 0u64;
    let status = parse_string_sid(string, output, &mut end);
    if status & 0x8000_0000 == 0 {
        return status;
    }
    let length = crate::ntos::rtl::guest_strings::read_wide_units(string).len() as u64;
    if ((end.wrapping_sub(string) as i64) >> 1) as u32 as u64 == length {
        return 0;
    }
    let cell = output_cell::<u64>(output);
    sddl_free(cell.get());
    cell.set(0);
    STATUS_INVALID_SID
}

fn is_x(unit: u16) -> bool {
    unit.wrapping_sub(0x58) & 0xFFDF == 0
}

/// Terminadores do SID dentro do SDDL na varredura: NUL, espaço, ')', ',' e ';'.
fn scan_terminator(unit: u16) -> bool {
    unit <= 0x3B && (0x0800_1201_0000_0001u64 >> unit) & 1 != 0
}

/// Terminadores aceitos depois de uma subautoridade: NUL, ')', ',', '-' e ';'.
fn value_terminator(unit: u16) -> bool {
    unit <= 0x3B && (0x0800_3200_0000_0001u64 >> unit) & 1 != 0
}

/// Dígitos hexadecimais aceitos na varredura.
fn scan_digit(unit: u16) -> bool {
    let value = unit.wrapping_sub(b'0' as u16);
    value <= 0x36 && (0x007E_0000_007E_03FFu64 >> value) & 1 != 0
}

/// LocalpConvertStringSidToSid(String, Sid*, End*): revisão (decimal ou 0x;
/// até 255), autoridade (até 48 bits, na base da revisão sem 0x) e as
/// subautoridades (na base da revisão sem 0x) até um terminador do SDDL. O
/// SID tem quatro bytes a mais que o necessário, como o original.
fn parse_string_sid(string: u64, output: u64, end: &mut u64) -> u32 {
    let unit = guest::read16;
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return STATUS_NO_MEMORY;
    }
    let mut copy = 0u64;
    let status = (|| -> u32 {
        if unit(string).wrapping_sub(b'S' as u16) & 0xFFDF != 0 || unit(string + 2) != b'-' as u16 {
            return STATUS_INVALID_SID;
        }
        let mut cursor = string + 4;
        let base = if unit(cursor) == b'0' as u16 && is_x(unit(cursor + 2)) { 16 } else { 10 };
        let revision = crate::ntos::rtl::crt::wcstoul(cursor, cell, base);
        let after = guest::read64(cell);
        if revision > 0xFF || after == cursor || unit(after) != b'-' as u16 {
            return STATUS_INVALID_SID;
        }
        cursor = after + 2;
        if unit(cursor) == 0 {
            return STATUS_INVALID_SID;
        }
        let mut dash = cursor;
        while unit(dash) != 0 && unit(dash) != b'-' as u16 {
            dash += 2;
        }
        if unit(dash) == 0 || dash == cursor {
            return STATUS_INVALID_SID;
        }
        let authority_base = if unit(cursor) == b'0' as u16 && is_x(unit(cursor + 2)) { 16 } else { base };
        let authority = crate::ntos::rtl::crt::wcstoui64(cursor, cell, authority_base);
        let separator = guest::read64(cell);
        if authority > 0xFFFF_FFFF_FFFF || separator == cursor || unit(separator) != b'-' as u16 || unit(separator + 2) == 0 {
            return STATUS_INVALID_SID;
        }
        // Varredura: cada '-' abre uma subautoridade, até o terminador.
        let mut dashes: u32 = 0;
        let mut scan = separator;
        let mut values = separator;
        loop {
            if dashes == 0xFF {
                *end = scan;
                return STATUS_INTEGER_OVERFLOW;
            }
            let current = unit(scan);
            if current == b'-' as u16 && unit(scan - 2) != b'-' as u16 {
                dashes += 1;
                if unit(scan + 2) == b'0' as u16 && is_x(unit(scan + 4)) {
                    scan += 4;
                }
                scan += 2;
                continue;
            }
            let next = unit(scan + 2);
            let component = next == b':' as u16 && current.wrapping_sub(b'G' as u16) & 0xFFF3 == 0 && current != b'K' as u16;
            if (current != b'-' as u16 && scan_terminator(current)) || component {
                if unit(scan - 2) == b'-' as u16 {
                    *end = scan - 2;
                    return STATUS_INVALID_SID;
                }
                *end = scan;
                dashes += 1;
                break;
            }
            if !scan_digit(current) {
                *end = scan;
                return STATUS_INVALID_SID;
            }
            if current == b'D' as u16 && next == b':' as u16 {
                // "D:" começa o componente seguinte: as subautoridades são
                // lidas de uma cópia que termina antes dele.
                let length = scan - separator;
                copy = guest::alloc_bytes(length + 2);
                if copy == 0 {
                    return STATUS_NO_MEMORY;
                }
                guest::write_bytes(copy, &guest::read_bytes(separator, length as usize));
                guest::write16(copy + length, 0);
                values = copy;
                *end = scan;
                dashes += 1;
                break;
            }
            scan += 2;
        }
        let count = dashes.saturating_sub(1);
        if count == 0 {
            return STATUS_INVALID_SID;
        }
        let mut sub_authorities = Vec::with_capacity(count as usize);
        let mut cursor = values + 2;
        for _ in 0..count {
            let value_base = if unit(cursor) == b'0' as u16 && is_x(unit(cursor + 2)) { 16 } else { base };
            sub_authorities.push(crate::ntos::rtl::crt::wcstoul(cursor, cell, value_base));
            cursor = guest::read64(cell);
            let stop = unit(cursor);
            let component = unit(cursor + 2) == b':' as u16 && stop.wrapping_sub(b'D' as u16) <= 0xF && (0x8809u32 >> stop.wrapping_sub(b'D' as u16)) & 1 != 0;
            if !value_terminator(stop) && !component {
                return STATUS_INVALID_SID;
            }
            cursor += 2;
        }
        let sid = sddl_allocate(count as u64 * 4 + 0xC);
        if sid == 0 {
            return STATUS_NO_MEMORY;
        }
        let mut bytes = alloc::vec![revision as u8, count as u8];
        bytes.extend_from_slice(&authority.to_be_bytes()[2..]);
        for value in &sub_authorities {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        guest::write_bytes(sid, &bytes);
        output_cell::<u64>(output).set(sid);
        0
    })();
    if copy != 0 {
        guest::free_bytes(copy);
    }
    guest::free_bytes(cell);
    status
}

/// Apelido do SID em `sid` (o LookupSidInTable por SID: a primeira entrada
/// igual pelo RtlEqualSid, que compara revisão e contagem antes do resto).
fn sid_alias(sid: u64) -> Option<&'static str> {
    let (revision, count) = (guest::read8(sid), guest::read8(sid + 1) as usize);
    SID_LOOKUP
        .iter()
        .find(|(_, value)| value.is_some_and(|(authority, subs)| revision == 1 && count == subs.len() && model::equal_sids(&guest::read_bytes(sid, 8 + count * 4), &model::sid(authority, subs))))
        .map(|(name, _)| *name)
}

/// LocalGetStringForSid: o apelido ou o texto S-1-...; a falha do
/// RtlConvertSidToUnicodeString vira o código Win32.
fn sid_string(sid: u64) -> Result<String, u32> {
    if let Some(alias) = sid_alias(sid) {
        return Ok(String::from(alias));
    }
    crate::ntos::rtl::security::sid_text(sid).map_err(crate::ntos::rtl::error::status_to_dos_error)
}

/// LocalGetStringForControl(Control, DACL = 1 / SACL = 2).
fn control_string(control: u16, which: u32) -> String {
    TEXT_CONTROL.iter().filter(|(_, bit, entry)| *entry & which == which && control & bit != 0).map(|(name, _, _)| *name).collect()
}

fn ace_type_name(ace_type: u8, selector: u32) -> Option<&'static str> {
    TEXT_ACE_TYPES.iter().find(|(_, value, entry)| entry & selector == selector && *value == ace_type).map(|(name, _, _)| *name)
}

fn ace_flag_name(flag: u8, selector: u32, ace_type: u8) -> Option<&'static str> {
    TEXT_ACE_FLAGS.iter().find(|(_, value, entry, types)| entry & selector == selector && (types.is_empty() || types.contains(&ace_type)) && *value == flag).map(|(name, _, _, _)| *name)
}

fn right_name(mask: u32, selector: u32) -> Option<&'static str> {
    TEXT_RIGHTS.iter().find(|(_, value, entry)| entry & selector == selector && *value == mask).map(|(name, _, _)| *name)
}

/// SddlpUuidToString: "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x".
fn guid_string(guid: u64) -> String {
    let bytes = guest::read_bytes(guid, 16);
    let mut text = alloc::format!("{:08x}-{:04x}-{:04x}-", guest::read32(guid), guest::read16(guid + 4), guest::read16(guid + 6));
    for (index, byte) in bytes[8..].iter().enumerate() {
        if index == 2 {
            text.push('-');
        }
        text.push_str(&alloc::format!("{byte:02x}"));
    }
    text
}

/// O texto de uma ACL e o tamanho que o LocalConvertAclToString reserva (em
/// bytes: cada ACE conta um caractere a mais que o texto, e os direitos em
/// hexadecimal sempre dez caracteres). DACL presente e nula vira
/// "NO_ACCESS_CONTROL"; ACL ausente ou vazia não tem texto.
fn acl_to_string(acl: u64, present: bool, dacl: bool) -> Result<(Option<String>, u32), u32> {
    if !present {
        return Ok((None, 0));
    }
    if acl == 0 {
        return Ok((Some(String::from("NO_ACCESS_CONTROL")), 0x24));
    }
    let count = guest::read16(acl + 4);
    if count == 0 {
        return Ok((None, 0));
    }
    let selector = if dacl { 1 } else { 2 };
    let (mut text, mut reserved) = (String::new(), 0u32);
    let mut ace = acl + 8;
    for _ in 0..count {
        let (ace_type, flags, size) = (guest::read8(ace), guest::read8(ace + 1), guest::read16(ace + 2));
        let type_name = ace_type_name(ace_type, selector).ok_or(ERROR_INVALID_ACL)?;
        let flag_names: String = (0..8).filter(|bit| flags & (1 << bit) != 0).filter_map(|bit| ace_flag_name(1 << bit, selector, ace_type)).collect();
        reserved += 2 + 2 + type_name.len() as u32 * 2 + flag_names.len() as u32 * 2 + 2;
        let mask = guest::read32(ace + 4);
        let (sid, object, inherited) = if matches!(ace_type, 0x05..=0x08 | 0x0B) {
            let object_flags = guest::read32(ace + 8);
            let object = (object_flags & 1 != 0).then_some(ace + 0xC);
            let inherited = (object_flags & 2 != 0).then_some(ace + 0xC + if object.is_some() { 16 } else { 0 });
            (ace + 0xC + object.map_or(0, |_| 16) + inherited.map_or(0, |_| 16), object, inherited)
        } else {
            (ace + 8, None, None)
        };
        reserved += object.map_or(0, |_| 0x48) + inherited.map_or(0, |_| 0x48);
        // Dados de aplicação depois do SID (LocalGetAceCondition).
        if matches!(ace_type, 0x09 | 0x0A | 0x0B | 0x0D | 0x12 | 0x15) {
            let header = if ace_type == 0x0B { 0xC + object.map_or(0, |_| 16) + inherited.map_or(0, |_| 16) } else { 8 };
            if (size as u32).wrapping_sub(crate::ntos::se::sid::length(sid)).wrapping_sub(header as u32) != 0 {
                return Err(ERROR_NOT_SUPPORTED);
            }
        }
        let rights_selector = if ace_type == 0x11 { 4 } else { selector };
        let (rights, rights_reserved) = match right_name(mask, rights_selector) {
            Some(name) => (String::from(name), name.len() as u32 * 2),
            None => {
                let names: Option<String> = (0..32).filter(|bit| mask & (1u32 << bit) != 0).map(|bit| right_name(1u32 << bit, rights_selector)).collect();
                match names {
                    Some(names) => {
                        let length = names.len() as u32 * 2;
                        (names, length)
                    }
                    None => (alloc::format!("0x{mask:x}"), 0x14),
                }
            }
        };
        reserved += 6 + rights_reserved;
        let sid_text = sid_string(sid)?;
        reserved += sid_text.len() as u32 * 2 + 4;
        text.push('(');
        text.push_str(type_name);
        text.push(';');
        text.push_str(&flag_names);
        text.push(';');
        text.push_str(&rights);
        text.push(';');
        text.push_str(&object.map(guid_string).unwrap_or_default());
        text.push(';');
        text.push_str(&inherited.map(guid_string).unwrap_or_default());
        text.push(';');
        text.push_str(&sid_text);
        text.push(')');
        ace += size as u64;
    }
    if reserved & 1 != 0 {
        reserved += 1;
    }
    Ok((Some(text), reserved))
}

/// SddlFilterSacl: só as ACEs que a SECURITY_INFORMATION pede (rótulo,
/// atributo, política, rótulo de confiança, filtro de acesso ou o resto da
/// SACL), numa cópia 'SeSd' com AclSize e AceCount refeitos.
fn filter_sacl(sacl: u64, information: u32) -> Result<u64, u32> {
    let wanted = |ace_type: u8| match ace_type {
        0x11 => information & 0x10 != 0,
        0x12 => information & 0x20 != 0,
        0x13 => information & 0x40 != 0,
        0x14 => information & 0x80 != 0,
        0x15 => information & 0x100 != 0,
        _ => information & 8 != 0,
    };
    let count = guest::read16(sacl + 4);
    let mut aces = Vec::new();
    let mut ace = sacl + 8;
    for _ in 0..count {
        let size = guest::read16(ace + 2) as u64;
        if wanted(guest::read8(ace)) {
            aces.push((ace, size));
        }
        ace += size;
    }
    let total = 8 + aces.iter().map(|(_, size)| size).sum::<u64>();
    let copy = sddl_allocate((total + 3) & !3);
    if copy == 0 {
        return Err(ERROR_NOT_ENOUGH_MEMORY);
    }
    guest::write_bytes(copy, &guest::read_bytes(sacl, 8));
    guest::write16(copy + 2, total as u16);
    guest::write16(copy + 4, aces.len() as u16);
    let mut cursor = copy + 8;
    for (ace, size) in aces {
        guest::write_bytes(cursor, &guest::read_bytes(ace, size as usize));
        cursor += size;
    }
    Ok(copy)
}

/// LocalConvertSDToStringSD_Rev1: o texto e o tamanho que ele reserva em
/// caracteres, ou o código Win32 do erro.
fn descriptor_to_string(descriptor: u64, information: u32) -> Result<(String, u32), u32> {
    let control = guest::read16(descriptor + 2);
    // Os RtlGet*SecurityDescriptor recusam revisão != 1
    // (STATUS_UNKNOWN_REVISION -> ERROR_UNKNOWN_REVISION).
    let revision_valid = guest::read8(descriptor) == 1;
    let component = |index: u64| if revision_valid { Ok(crate::ntos::se::descriptor::component(descriptor, control, index)) } else { Err(ERROR_UNKNOWN_REVISION) };
    let owner = if information & 1 != 0 { component(0)? } else { 0 };
    let group = if information & 2 != 0 { component(1)? } else { 0 };
    let (dacl_present, dacl) = if information & 4 != 0 { (control & SE_DACL_PRESENT != 0, component(3)?) } else { (false, 0) };
    let (sacl_present, mut sacl) = if information & 0x1F8 != 0 { (control & SE_SACL_PRESENT != 0, component(2)?) } else { (false, 0) };
    let filtered = if sacl_present && sacl != 0 { Some(filter_sacl(sacl, information & 0x1F8)?) } else { None };
    if let Some(copy) = filtered {
        sacl = copy;
    }
    let result = (|| -> Result<(String, u32), u32> {
        if !revision_valid {
            return Err(ERROR_UNKNOWN_REVISION);
        }
        let owner_text = if owner != 0 { Some(sid_string(owner)?) } else { None };
        let group_text = if group != 0 { Some(sid_string(group)?) } else { None };
        let (dacl_control, sacl_control) = (control_string(control, 1), control_string(control, 2));
        let mut reserved = 0u32;
        let sacl_text = if sacl_present {
            let (text, length) = acl_to_string(sacl, true, false)?;
            reserved = length;
            text
        } else {
            None
        };
        let dacl_text = if dacl_present {
            let (text, length) = acl_to_string(dacl, true, true)?;
            reserved += length;
            text
        } else {
            None
        };
        let mut text = String::new();
        for (prefix, value) in [("O:", &owner_text), ("G:", &group_text)] {
            if let Some(value) = value {
                reserved += value.len() as u32 * 2 + 4;
                text.push_str(prefix);
                text.push_str(value);
            }
        }
        for (present, prefix, flags, acl) in [(dacl_present, "D:", &dacl_control, &dacl_text), (sacl_present, "S:", &sacl_control, &sacl_text)] {
            if present {
                reserved += 4 + flags.len() as u32 * 2;
                text.push_str(prefix);
                text.push_str(flags);
                text.push_str(acl.as_deref().unwrap_or(""));
            }
        }
        Ok((text, reserved / 2))
    })();
    if let Some(copy) = filtered {
        sddl_free(copy);
    }
    result
}

/// SeConvertSecurityDescriptorToStringSecurityDescriptor(Sd, Revision,
/// SecurityInformation, String*, StringLength*): devolve o NTSTATUS (os
/// erros do conversor como 0xC007xxxx). Descritor nulo ou nenhuma informação
/// pedida dão a string vazia; o tamanho devolvido é o que o conversor
/// reservou, em caracteres.
pub fn convert_descriptor_to_string(descriptor: u64, revision: u32, information: u32, output: u64, length_output: u64) -> u32 {
    if (descriptor == 0 || information == 0) && output != 0 {
        let buffer = sddl_allocate(2);
        output_cell::<u64>(output).set(buffer);
        if buffer == 0 {
            return win32_status(ERROR_NOT_ENOUGH_MEMORY);
        }
        if length_output != 0 {
            output_cell::<u32>(length_output).set(0);
        }
        return 0;
    }
    if descriptor == 0 || output == 0 || information == 0 {
        return win32_status(ERROR_INVALID_PARAMETER);
    }
    if revision != 1 {
        return win32_status(ERROR_UNKNOWN_REVISION);
    }
    let (text, reserved) = match descriptor_to_string(descriptor, information) {
        Ok(converted) => converted,
        Err(code) => return win32_status(code),
    };
    // O buffer tem o tamanho reservado mais o NUL.
    let extra = (reserved as u64 * 2).saturating_sub(text.encode_utf16().count() as u64 * 2);
    let buffer = sddl_text(&text, extra);
    output_cell::<u64>(output).set(buffer);
    if buffer == 0 {
        return win32_status(ERROR_NOT_ENOUGH_MEMORY);
    }
    if length_output != 0 {
        output_cell::<u32>(length_output).set(reserved);
    }
    0
}
