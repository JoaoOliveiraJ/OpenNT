//! Informação do objeto token consultada pelo kernel: SeQueryInformationToken,
//! os acessores de campo (SeToken*), o AuthenticationId e os atributos de
//! segurança.
//!
//! `SeQueryInformationToken` é a forma *alocadora* (ExAllocatePool): serializa
//! TOKEN_USER/GROUPS/PRIVILEGES/OWNER/PRIMARY_GROUP/STATISTICS a partir do
//! registro mantido em `token/tokens.rs` e devolve o ponteiro na saída (o
//! chamador libera com ExFreePool). Os campos vêm do side-table via
//! `tokens::with`/`tokens::get`, e não dos offsets nativos 0xC0/0xC4/0xC8.
//! As funções que devolvem `u32` devolvem o NTSTATUS.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::model::sid;
use crate::ntos::se::security_attributes;
use crate::ntos::se::token::statistics;
use crate::ntos::se::token::tokens::{self, Token};
use crate::ntos::inc::types::{NtStruct, UnicodeString};
use crate::ntos::se::out;
use crate::rtl::KernelError;

const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// SE_GROUP_ENABLED.
const SE_GROUP_ENABLED: u32 = 0x4;
/// TOKEN_TYPE: 1 = primário, 2 = impersonação.
const TOKEN_IMPERSONATION: u32 = 2;
/// SecurityImpersonation (mínimo para um token de impersonação ser admin).
const SECURITY_IMPERSONATION: u32 = 2;

// ---- SeQueryInformationToken: produtores que serializam o side-table -----

/// TOKEN_USER = SID_AND_ATTRIBUTES (Sid@0, Attributes@8, 16 bytes) + corpo
/// do SID logo após; o ponteiro aponta para esse corpo.
fn encode_token_user(record: &Token, base: u64) -> Vec<u8> {
    let sid = &record.user;
    let mut bytes = vec![0u8; 16 + sid.len()];
    bytes[0..8].copy_from_slice(&(base + 16).to_le_bytes());
    bytes[8..12].copy_from_slice(&record.user_attributes.to_le_bytes());
    bytes[16..16 + sid.len()].copy_from_slice(sid);
    bytes
}

/// TOKEN_GROUPS = GroupCount@0 (+pad) e o array SID_AND_ATTRIBUTES@8; os
/// corpos dos SIDs ficam depois do array, com ponteiros absolutos.
fn encode_token_groups(record: &Token, base: u64) -> Vec<u8> {
    let count = record.groups.len();
    let mut sids_at = 8 + count * 16;
    let total = sids_at + record.groups.iter().map(|group| group.sid.len()).sum::<usize>();
    let mut bytes = vec![0u8; total];
    bytes[0..4].copy_from_slice(&(count as u32).to_le_bytes());
    for (index, group) in record.groups.iter().enumerate() {
        let entry = 8 + index * 16;
        bytes[entry..entry + 8].copy_from_slice(&(base + sids_at as u64).to_le_bytes());
        bytes[entry + 8..entry + 12].copy_from_slice(&group.attributes.to_le_bytes());
        bytes[sids_at..sids_at + group.sid.len()].copy_from_slice(&group.sid);
        sids_at += group.sid.len();
    }
    bytes
}

/// TOKEN_PRIVILEGES = PrivilegeCount@0 e o array LUID_AND_ATTRIBUTES@4
/// (Luid 8 + Attributes 4, stride 12).
fn encode_token_privileges(record: &Token) -> Vec<u8> {
    let count = record.privileges.len();
    let mut bytes = vec![0u8; 4 + count * 12];
    bytes[0..4].copy_from_slice(&(count as u32).to_le_bytes());
    for (index, privilege) in record.privileges.iter().enumerate() {
        let entry = 4 + index * 12;
        bytes[entry..entry + 8].copy_from_slice(&privilege.id.to_le_bytes());
        bytes[entry + 8..entry + 12].copy_from_slice(&privilege.attributes.to_le_bytes());
    }
    bytes
}

/// TOKEN_OWNER / TOKEN_PRIMARY_GROUP: ponteiro@0 para o corpo do SID em @8.
fn encode_sid_struct(sid: &[u8], base: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 8 + sid.len()];
    bytes[0..8].copy_from_slice(&(base + 8).to_le_bytes());
    bytes[8..8 + sid.len()].copy_from_slice(sid);
    bytes
}

/// SeQueryInformationToken(Token, Class, *TokenInformation): aloca a
/// estrutura da classe e devolve o ponteiro em `*output`. Classes comuns
/// implementadas; as demais devolvem STATUS_INVALID_INFO_CLASS.
pub fn query_information(token: u64, class: u32, output: u64) -> Result<u32, KernelError> {
    let Some(record) = tokens::get(token).filter(|record| record.refs > 0) else {
        return Ok(STATUS_INVALID_PARAMETER);
    };
    // Comprimento primeiro: a alocação precede os ponteiros absolutos.
    let length = match class {
        1 => 16 + record.user.len(),
        2 => 8 + record.groups.len() * 16 + record.groups.iter().map(|group| group.sid.len()).sum::<usize>(),
        3 => 4 + record.privileges.len() * 12,
        4 => 8 + record.owner.len(),
        5 => 8 + record.primary_group.len(),
        10 => 56,
        _ => return Ok(STATUS_INVALID_INFO_CLASS),
    };
    let base = guest::alloc_bytes(length as u64);
    if base == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let bytes = match class {
        1 => encode_token_user(&record, base),
        2 => encode_token_groups(&record, base),
        3 => encode_token_privileges(&record),
        4 => encode_sid_struct(&record.owner, base),
        5 => encode_sid_struct(&record.primary_group, base),
        10 => match statistics::encode(token) {
            Ok(statistics) => statistics.to_vec(),
            Err(error) => {
                guest::free_bytes(base);
                return Err(error);
            }
        },
        _ => unreachable!(),
    };
    guest::write_bytes(base, &bytes);
    out::<u64>(output).set(base);
    Ok(0)
}

/// SeQueryAuthenticationIdToken: AuthenticationId lido do campo do token
/// (SYSTEM_LUID no token do Sistema); token desconhecido dá
/// STATUS_INVALID_HANDLE.
pub fn query_authentication_id(token: u64, output: u64) -> u32 {
    if tokens::get(token).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    out::<u64>(output).set(tokens::luid_value(&tokens::body(token).authentication_id));
    0
}

// ---- Acessores de campo (via side-table, não via offset nativo) ----------

/// SeTokenType = TOKEN_TYPE (1 primário, 2 impersonação) do registro.
pub fn token_type(token: u64) -> u32 {
    tokens::with(token, |token| token.kind).unwrap_or(0)
}

/// SeTokenImpersonationLevel: o nível guardado no registro.
pub fn impersonation_level(token: u64) -> u32 {
    tokens::with(token, |token| token.impersonation_level).unwrap_or(0)
}

/// SeTokenIsRestricted: OpenNT modela a restrição pelos SIDs restritos (o
/// NT testa TokenFlags>>4 & 1), que acompanham o write-restricted.
pub fn is_restricted(token: u64) -> bool {
    tokens::with(token, |token| !token.restricted_sids.is_empty() || token.write_restricted).unwrap_or(false)
}

/// SeTokenIsAdmin: Administrators S-1-5-32-544 (export de dado
/// `SeAliasAdminsSid`) habilitado nos grupos e token não restrito; um token
/// de impersonação abaixo de SecurityImpersonation nunca é admin.
pub fn is_admin(token: u64) -> bool {
    let administrators = sid(5, &[32, 544]);
    tokens::with(token, |token| {
        if token.kind == TOKEN_IMPERSONATION && token.impersonation_level < SECURITY_IMPERSONATION {
            return false;
        }
        if !token.restricted_sids.is_empty() || token.write_restricted {
            return false;
        }
        token.groups.iter().any(|group| group.sid == administrators && group.attributes & SE_GROUP_ENABLED != 0)
    })
    .unwrap_or(false)
}

// ---- Atributos de segurança / claims -------------------------------------

/// SeQuerySecurityAttributesTokenAccessInformation(Token, *AttributesInfo):
/// aloca um TOKEN_SECURITY_ATTRIBUTES_INFORMATION com o conjunto de
/// atributos do token e devolve o ponteiro em `*output`. O token do Sistema
/// tem conjunto vazio → cabeçalho bem-formado de 16 bytes (Version=1,
/// AttributeCount=0, pAttributeV1=NULL).
pub fn query_security_attributes_access_information(token: u64, output: u64) -> u32 {
    let Some(record) = tokens::get(token).filter(|record| record.refs > 0) else {
        return STATUS_INVALID_PARAMETER;
    };
    let size = match security_attributes::measure(&record.security_attributes) {
        Ok(size) => size,
        Err(status) => return status,
    };
    let base = guest::alloc_bytes(size);
    if base == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    match security_attributes::encode(&record.security_attributes, base) {
        Ok(bytes) => guest::write_bytes(base, &bytes),
        Err(status) => {
            guest::free_bytes(base);
            return status;
        }
    }
    out::<u64>(output).set(base);
    0
}

/// SeSecurityAttributePresent(Token, Name): existe o claim nomeado? O
/// conjunto vazio do token do Sistema devolve FALSE.
pub fn security_attribute_present(token: u64, name_pointer: u64) -> Result<bool, KernelError> {
    let Some(record) = tokens::get(token).filter(|record| record.refs > 0) else {
        return Ok(false);
    };
    if name_pointer == 0 {
        return Ok(false);
    }
    // UNICODE_STRING: Length@0 (USHORT), Buffer@8 (PWSTR).
    // SAFETY: PUNICODE_STRING do chamador.
    let name = unsafe { UnicodeString::at(name_pointer) };
    let length = name.length.get() as u64;
    let buffer = name.buffer.get();
    if length == 0 || buffer == 0 || length & 1 != 0 {
        return Ok(false);
    }
    let units: Vec<u16> = guest::read_bytes(buffer, length as usize).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let name = String::from_utf16_lossy(&units);
    let present = security_attributes::select(&record.security_attributes, Some(&[name]))?.is_some();
    Ok(present)
}
