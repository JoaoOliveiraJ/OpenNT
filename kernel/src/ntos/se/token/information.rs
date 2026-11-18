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
    let groups = record.groups_with_label();
    let count = groups.len();
    let mut sids_at = 8 + count * 16;
    let total = sids_at + groups.iter().map(|group| group.sid.len()).sum::<usize>();
    let mut bytes = vec![0u8; total];
    bytes[0..4].copy_from_slice(&(count as u32).to_le_bytes());
    for (index, group) in groups.iter().enumerate() {
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

/// TOKEN_INFORMATION_CLASS das classes que não alocam.
const TOKEN_SESSION_ID: u32 = 12;
const TOKEN_VIRTUALIZATION_ALLOWED: u32 = 23;
const TOKEN_VIRTUALIZATION_ENABLED: u32 = 24;
const TOKEN_INTEGRITY_LEVEL: u32 = 25;
const TOKEN_UI_ACCESS: u32 = 26;
const TOKEN_IS_APP_CONTAINER: u32 = 29;
const TOKEN_CAPABILITIES: u32 = 30;
const TOKEN_APP_CONTAINER_SID: u32 = 31;
const TOKEN_APP_CONTAINER_NUMBER: u32 = 32;
const TOKEN_IS_LESS_PRIVILEGED_APP_CONTAINER: u32 = 46;
/// TOKEN_LOWBOX em TokenFlags.
const TOKEN_LOWBOX: u32 = 0x4000;

/// O bit de TokenFlags de cada classe booleana (TOKEN_VIRTUALIZATION_ALLOWED
/// 0x200, TOKEN_VIRTUALIZATION_ENABLED 0x400, TOKEN_UIACCESS 0x1000,
/// TOKEN_LOWBOX 0x4000).
fn token_flag_bit(class: u32) -> Option<u32> {
    match class {
        TOKEN_VIRTUALIZATION_ALLOWED => Some(9),
        TOKEN_VIRTUALIZATION_ENABLED => Some(10),
        TOKEN_UI_ACCESS => Some(12),
        TOKEN_IS_APP_CONTAINER => Some(14),
        _ => None,
    }
}

/// O último SubAuthority de um SID (o RID), 0 sem SubAuthority.
fn last_sub_authority(sid: &[u8]) -> u32 {
    let count = sid.get(1).copied().unwrap_or(0) as usize;
    let at = 8 + 4 * count;
    if count == 0 || sid.len() < at {
        return 0;
    }
    u32::from_le_bytes([sid[at - 4], sid[at - 3], sid[at - 2], sid[at - 1]])
}

/// SeQueryInformationToken(Token, Class, *TokenInformation): aloca a
/// estrutura da classe e devolve o ponteiro em `*output`. Classes comuns
/// implementadas; as demais devolvem STATUS_INVALID_INFO_CLASS. Como no
/// ntoskrnl 19041, as classes escalares não alocam e gravam o ULONG direto
/// em `*output`: a TokenSessionId (12, o SeQuerySessionIdToken que o ndis.sys
/// pede), as booleanas de TokenFlags (23, 24, 26, 29), a
/// TokenIntegrityLevel (25, o RID do SID de integridade), a
/// TokenAppContainerNumber (32, o número do LowboxNumberEntry, 0 sem ele) e
/// a TokenIsLessPrivilegedAppContainer (46, um LowBox com WIN://NOALLAPPPKG).
/// A TokenAppContainerSid (31) aloca um TOKEN_APPCONTAINER_INFORMATION com o
/// SID do pacote logo depois (só o ponteiro nulo sem AppContainer) e a
/// TokenCapabilities (30) um TOKEN_GROUPS. O win32k consulta 25, 26, 31 e 32
/// no callout de processo de todo processo GUI.
pub fn query_information(token: u64, class: u32, output: u64) -> Result<u32, KernelError> {
    let Some(record) = tokens::get(token).filter(|record| record.refs > 0) else {
        return Ok(STATUS_INVALID_PARAMETER);
    };
    if let Some(bit) = token_flag_bit(class) {
        out::<u32>(output).set(tokens::body(token).token_flags.get() >> bit & 1);
        return Ok(0);
    }
    match class {
        TOKEN_SESSION_ID => {
            out::<u32>(output).set(record.session_id);
            return Ok(0);
        }
        TOKEN_INTEGRITY_LEVEL => {
            out::<u32>(output).set(last_sub_authority(&record.integrity));
            return Ok(0);
        }
        TOKEN_APP_CONTAINER_NUMBER => {
            out::<u32>(output).set(record.lowbox_number.map_or(0, |(_, number)| number));
            return Ok(0);
        }
        // TokenIsLessPrivilegedAppContainer (0x6d08a3): um LowBox que o
        // SepCanTokenMatchAllPackageSid recusa.
        TOKEN_IS_LESS_PRIVILEGED_APP_CONTAINER => {
            let lowbox = tokens::body(token).token_flags.get() & TOKEN_LOWBOX != 0;
            out::<u32>(output).set((lowbox && tokens::less_privileged(&record)) as u32);
            return Ok(0);
        }
        // TokenCapabilities (0x6d04e3): um TOKEN_GROUPS alocado com o vetor
        // em +8 e os SIDs depois de sizeof(TOKEN_GROUPS) + Count * 16 (o
        // RtlCopySidAndAttributesArray).
        TOKEN_CAPABILITIES => {
            let count = record.capabilities.len();
            let sids_at = 0x18 + count * 16;
            let length = sids_at + record.capabilities.iter().map(|group| group.sid.len()).sum::<usize>();
            let base = guest::alloc_bytes(length as u64);
            if base == 0 {
                return Ok(STATUS_INSUFFICIENT_RESOURCES);
            }
            let mut bytes = alloc::vec![0u8; length];
            bytes[..4].copy_from_slice(&(count as u32).to_le_bytes());
            let mut sid_at = sids_at;
            for (index, group) in record.capabilities.iter().enumerate() {
                let entry = 8 + index * 16;
                bytes[entry..entry + 8].copy_from_slice(&(base + sid_at as u64).to_le_bytes());
                bytes[entry + 8..entry + 12].copy_from_slice(&group.attributes.to_le_bytes());
                bytes[sid_at..sid_at + group.sid.len()].copy_from_slice(&group.sid);
                sid_at += group.sid.len();
            }
            guest::write_bytes(base, &bytes);
            out::<u64>(output).set(base);
            return Ok(0);
        }
        TOKEN_APP_CONTAINER_SID => {
            let sid = record.app_container.clone().unwrap_or_default();
            let base = guest::alloc_bytes(8 + sid.len() as u64);
            if base == 0 {
                return Ok(STATUS_INSUFFICIENT_RESOURCES);
            }
            guest::write_bytes(base + 8, &sid);
            guest::write64(base, if sid.is_empty() { 0 } else { base + 8 });
            out::<u64>(output).set(base);
            return Ok(0);
        }
        _ => {}
    }
    // Comprimento primeiro: a alocação precede os ponteiros absolutos.
    let length = match class {
        1 => 16 + record.user.len(),
        2 => {
            let groups = record.groups_with_label();
            8 + groups.len() * 16 + groups.iter().map(|group| group.sid.len()).sum::<usize>()
        }
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
    // LUID { ULONG LowPart; LONG HighPart; }: alinhamento de 4 (o win32k
    // pede a saída dentro de uma estrutura, num endereço múltiplo de 4).
    // SAFETY: o PLUID de saída vivo do chamador de kernel.
    tokens::set_luid(unsafe { crate::ntos::inc::types::Luid::at(output) }, tokens::luid_value(&tokens::body(token).authentication_id));
    0
}

/// SeQuerySessionIdToken(Token, *SessionId) (ntoskrnl 19041 rva 0x6773c0):
/// o SessionId do token lido sob o lock dele em leitura, sempre
/// STATUS_SUCCESS (o NT não valida o token).
pub fn query_session_id_token(token: u64, output: u64) -> u32 {
    let session = tokens::with(token, |token| token.session_id).unwrap_or(0);
    out::<u32>(output).set(session);
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

/// SeQueryServerSiloToken(Token, Silo*) (ntoskrnl 19041 rva 0x693660): o
/// SessionId do token, lido sob o lock dele, e o silo da sessão pelo
/// PsGetSiloBySessionId; devolve o NTSTATUS (STATUS_INVALID_SESSION sem a
/// sessão) e grava o silo só no sucesso.
pub fn query_server_silo(token: u64, silo: &crate::ntos::inc::types::Field<u64>) -> u32 {
    let session_id = tokens::with(token, |record| record.session_id).unwrap_or(u32::MAX);
    match crate::ntos::ps::silo::query::silo_by_session_id(session_id) {
        Ok(found) => {
            silo.set(found);
            0
        }
        Err(status) => status,
    }
}
