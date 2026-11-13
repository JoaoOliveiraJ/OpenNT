//! Verificação de acesso contra um SECURITY_DESCRIPTOR e a identidade do
//! sujeito (SeAccessCheck e SeAccessCheckFromState).
//!
//! Reusa a avaliação ordenada de DACL do `token/access.rs`/`object_security.rs`,
//! dirigida aqui por um descritor e pelo GENERIC_MAPPING do chamador em vez do
//! mapeamento fixo de token.
//!
//! Lacuna honesta: não há caminho de concessão por privilégio ligado a
//! descritores (SeSecurityPrivilege para ACCESS_SYSTEM_SECURITY,
//! SeTakeOwnership para WRITE_OWNER); `*Privileges` sai NULL e esse ramo é
//! pulado — igual ao `token/access.rs`, que só honra 8/9 habilitados no
//! objeto token.

use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::types::{
    AccessAllowedAce, AceHeader, Acl, GenericMapping, NtStruct, SecurityImpersonationLevel, SecuritySubjectContext,
    SidAndAttributes, SidAndAttributesHash, TokenAccessInformation,
};
use crate::ntos::inc::types::{AccessReasons, AccessState, Field};
use crate::ntos::inc::types::extra_fs_ntfs::{SeAccessReply, SeAccessRequest, SeSecurityDescriptor};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_types;
use crate::ntos::se::acl;
use crate::ntos::se::model::Sid;
use crate::ntos::se::token::tokens;
use crate::ntos::se::{descriptor, out, sid};

const SECURITY_IMPERSONATION: SecurityImpersonationLevel = SecurityImpersonationLevel::SECURITY_IMPERSONATION;

// ACCESS_MASK bits.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const STANDARD_RIGHTS_ALL: u32 = 0x001F_0000;
const GENERIC_MASK: u32 = 0xF000_0000;

// SECURITY_DESCRIPTOR control + ACE/ACL + group attribute bits.
const DACL_PRESENT: u16 = 0x0004;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
const SE_GROUP_ENABLED: u32 = 0x04;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;

// NTSTATUS.
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;

/// Identidade efetiva usada na avaliação da DACL: SID do usuário e os
/// grupos (SID + atributos). Vale tanto para um objeto token quanto para um
/// TOKEN_ACCESS_INFORMATION capturado.
struct Subject {
    user: Sid,
    groups: Vec<(Sid, u32)>,
}

/// Lê um SID do convidado (cabeçalho de 8 bytes + 4 por subautoridade).
fn read_sid(pointer: u64) -> Sid {
    let count = sid::at(pointer).sub_authority_count.get() as usize;
    guest::read_bytes(pointer, 8 + 4 * count)
}

/// RtlMapGenericMask: expande os quatro bits genéricos pelo GENERIC_MAPPING
/// do chamador (Read/Write/Execute/All em 0/4/8/12) e os remove.
fn map_generic(mut mask: u32, mapping: u64) -> u32 {
    if mapping != 0 {
        let mapping = generic_mapping(mapping);
        if mask & 0x8000_0000 != 0 {
            mask |= mapping.generic_read.get();
        }
        if mask & 0x4000_0000 != 0 {
            mask |= mapping.generic_write.get();
        }
        if mask & 0x2000_0000 != 0 {
            mask |= mapping.generic_execute.get();
        }
        if mask & 0x1000_0000 != 0 {
            mask |= mapping.generic_all.get();
        }
    }
    mask & !GENERIC_MASK
}

fn generic_mapping(mapping: u64) -> &'static GenericMapping {
    // SAFETY: PGENERIC_MAPPING do chamador de SeAccessCheck.
    unsafe { GenericMapping::at(mapping) }
}

/// Conjunto "todo o acesso" para MAXIMUM_ALLOWED: GenericAll do mapeamento
/// mais os direitos padrão.
fn all_access(mapping: u64) -> u32 {
    if mapping != 0 {
        generic_mapping(mapping).generic_all.get() | STANDARD_RIGHTS_ALL
    } else {
        STANDARD_RIGHTS_ALL | 0x1FF
    }
}

fn write_result(granted_out: u64, status_out: u64, granted: u32, status: u32) {
    if granted_out != 0 {
        out::<u32>(granted_out).set(granted);
    }
    if status_out != 0 {
        out::<u32>(status_out).set(status);
    }
}

/// KernelMode concede o pedido inteiro (ou tudo, com MAXIMUM_ALLOWED), como
/// o SeAccessCheck real antes de qualquer avaliação de DACL.
fn kernel_grant(desired: u32, previous: u32, mapping: u64, granted_out: u64, status_out: u64) -> bool {
    let granted = if desired & MAXIMUM_ALLOWED != 0 {
        all_access(mapping) | (desired & !MAXIMUM_ALLOWED) | previous
    } else {
        desired | previous
    };
    write_result(granted_out, status_out, granted, 0);
    true
}

/// Avaliação ordenada da DACL do descritor pela identidade `subject`.
/// `None` = DACL nula (ausente ou ponteiro nulo) → concede tudo; `Some(m)` =
/// máscara acumulada de concessões (deny acumula à parte, respeitando a
/// ordem das ACEs, como em `token/access.rs`).
fn evaluate(descriptor: u64, subject: &Subject) -> Option<u32> {
    let control = descriptor::control(descriptor);
    // O dono recebe READ_CONTROL e WRITE_DAC de saída.
    let owner = descriptor::component(descriptor, control, 0);
    let mut granted = if owner != 0 && read_sid(owner) == subject.user { READ_CONTROL | WRITE_DAC } else { 0 };
    if control & DACL_PRESENT == 0 {
        return None;
    }
    let dacl = descriptor::component(descriptor, control, 3);
    if dacl == 0 {
        return None;
    }
    let mut denied = 0u32;
    // SAFETY: componente DACL do descritor (PACL alinhada a WORD).
    let count = unsafe { Acl::at(dacl) }.ace_count.get();
    let mut cursor = dacl + Acl::SIZE;
    // A DACL não é revalidada aqui: com um AceSize ímpar a entrada seguinte
    // fica desalinhada, então os campos são lidos pelo offset do layout.
    for _ in 0..count {
        let ace_type = guest::read::<u8>(cursor + offset_of!(AceHeader, ace_type) as u64);
        let ace_size = guest::read::<u16>(cursor + offset_of!(AceHeader, ace_size) as u64) as u64;
        if ace_size == 0 {
            break;
        }
        if ace_type == ACCESS_ALLOWED_ACE_TYPE || ace_type == ACCESS_DENIED_ACE_TYPE {
            let mask = guest::read::<u32>(cursor + offset_of!(AccessAllowedAce, mask) as u64);
            let ace_sid = read_sid(cursor + offset_of!(AccessAllowedAce, sid_start) as u64);
            let deny = ace_type == ACCESS_DENIED_ACE_TYPE;
            let matches = ace_sid == subject.user
                || subject.groups.iter().any(|(sid, attributes)| {
                    let attributes = *attributes;
                    *sid == ace_sid
                        && ((attributes & SE_GROUP_ENABLED != 0 && attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0)
                            || (deny && attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0))
                });
            if matches {
                if deny {
                    denied |= mask & !granted;
                } else {
                    granted |= mask & !denied;
                }
            }
        }
        cursor += ace_size;
    }
    Some(granted)
}

/// Decisão comum de SeAccessCheck/SeAccessCheckFromState depois de resolver
/// a identidade e já com `desired` mapeado. `subject` ausente (sujeito não
/// resolvido) nega.
fn decide(descriptor: u64, subject: Option<Subject>, desired: u32, previous: u32, mapping: u64, granted_out: u64, status_out: u64) -> bool {
    let Some(subject) = subject else {
        write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
        return false;
    };
    let maximum = desired & MAXIMUM_ALLOWED != 0;
    let explicit = desired & !MAXIMUM_ALLOWED;
    match evaluate(descriptor, &subject) {
        // DACL nula: todos têm acesso total.
        None => {
            let granted = if maximum { all_access(mapping) | explicit | previous } else { explicit | previous };
            write_result(granted_out, status_out, granted, 0);
            true
        }
        Some(dacl) => {
            let accumulated = dacl | previous;
            if maximum {
                if accumulated == 0 {
                    write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
                    false
                } else {
                    write_result(granted_out, status_out, accumulated, 0);
                    true
                }
            } else if explicit & !accumulated != 0 {
                write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
                false
            } else {
                write_result(granted_out, status_out, explicit | previous, 0);
                true
            }
        }
    }
}

/// SeAccessCheck(Sd, Subj, SubjLocked, Desired, PrevGranted, Privileges**,
/// Map, Mode, GrantedAccess*, AccessStatus*); SubjLocked não é usado.
/// Devolve o BOOLEAN do resultado.
#[allow(clippy::too_many_arguments)]
pub fn access_check(descriptor: u64, subject_context: u64, desired: u32, previous: u32, privileges_out: u64, mapping: u64, mode: u32, granted_out: u64, status_out: u64) -> bool {
    let mut desired = desired;
    // Sem caminho de concessão por privilégio: nenhum privilégio foi usado.
    if privileges_out != 0 {
        out::<u64>(privileges_out).set(0);
    }
    if mode == 0 {
        return kernel_grant(desired, previous, mapping, granted_out, status_out);
    }
    if descriptor == 0 {
        write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
        return false;
    }
    if desired & GENERIC_MASK != 0 {
        desired = map_generic(desired, mapping);
    }
    // Token efetivo: ClientToken ao personificar (>= Impersonation), senão
    // PrimaryToken. Personificação fraca com ClientToken nega.
    // SAFETY: PSECURITY_SUBJECT_CONTEXT capturado pelo chamador.
    let context = unsafe { SecuritySubjectContext::at(subject_context) };
    let client = context.client_token.get();
    let token = if client != 0 {
        if context.impersonation_level.get().0 < SECURITY_IMPERSONATION.0 {
            write_result(granted_out, status_out, 0, STATUS_BAD_IMPERSONATION_LEVEL);
            return false;
        }
        client
    } else {
        context.primary_token.get()
    };
    let subject = tokens::with(token, |token| Subject {
        user: token.user.clone(),
        groups: token.groups.iter().map(|group| (group.sid.clone(), group.attributes)).collect(),
    });
    decide(descriptor, subject, desired, previous, mapping, granted_out, status_out)
}

/// Lê um TOKEN_ACCESS_INFORMATION capturado num `Subject`. SidHash@0 →
/// (SidCount@0, SidAttr@8); SID_AND_ATTRIBUTES = (Sid@0, Attributes@8),
/// stride 0x10; o primeiro SID é o usuário, os demais são grupos.
fn subject_from_access_information(information: u64) -> Option<Subject> {
    if information == 0 {
        return None;
    }
    // SAFETY: PTOKEN_ACCESS_INFORMATION capturado pelo chamador.
    let hash = unsafe { TokenAccessInformation::at(information) }.sid_hash.get();
    if hash == 0 {
        return None;
    }
    // SAFETY: SidHash aponta para o SID_AND_ATTRIBUTES_HASH do mesmo bloco.
    let hash = unsafe { SidAndAttributesHash::at(hash) };
    let count = hash.sid_count.get();
    let array = hash.sid_attr.get();
    if array == 0 || count == 0 {
        return None;
    }
    let mut sids: Vec<(Sid, u32)> = Vec::new();
    // SAFETY: SidAttr tem SidCount entradas.
    for entry in unsafe { SidAndAttributes::array_at(array, count as usize) } {
        let sid = entry.sid.get();
        if sid != 0 {
            sids.push((read_sid(sid), entry.attributes.get()));
        }
    }
    if sids.is_empty() {
        return None;
    }
    let user = sids.remove(0).0;
    Some(Subject { user, groups: sids })
}

/// SeAccessCheckFromState(Sd, PrimaryTokenInfo, ClientTokenInfo, Desired,
/// PrevGranted, Privileges**, Map, Mode, GrantedAccess*, AccessStatus*):
/// mesmo algoritmo, com a identidade vinda de um TOKEN_ACCESS_INFORMATION.
#[allow(clippy::too_many_arguments)]
pub fn access_check_from_state(descriptor: u64, primary_info: u64, client_info: u64, desired: u32, previous: u32, privileges_out: u64, mapping: u64, mode: u32, granted_out: u64, status_out: u64) -> bool {
    let mut desired = desired;
    if privileges_out != 0 {
        out::<u64>(privileges_out).set(0);
    }
    if mode == 0 {
        return kernel_grant(desired, previous, mapping, granted_out, status_out);
    }
    if descriptor == 0 {
        write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
        return false;
    }
    if desired & GENERIC_MASK != 0 {
        desired = map_generic(desired, mapping);
    }
    // ImpersonationLevel do TOKEN_ACCESS_INFORMATION do cliente.
    let information = if client_info != 0 {
        // SAFETY: PTOKEN_ACCESS_INFORMATION do chamador.
        if unsafe { TokenAccessInformation::at(client_info) }.impersonation_level.get().0 < SECURITY_IMPERSONATION.0 {
            write_result(granted_out, status_out, 0, STATUS_BAD_IMPERSONATION_LEVEL);
            return false;
        }
        client_info
    } else {
        primary_info
    };
    let subject = subject_from_access_information(information);
    decide(descriptor, subject, desired, previous, mapping, granted_out, status_out)
}

// ---- Token montado de um TOKEN_ACCESS_INFORMATION e o access check "Ex" -------
//
// SeTokenFromAccessInformation 0x327ef0 / SepTokenFromAccessInformation
// 0x32f5e4 / RtlSidHashInitialize 0x2d6590 e SeAccessCheckFromStateEx
// 0x32f550 (ntoskrnl 19041). O token é uma estrutura `_TOKEN` (0x498 bytes)
// no buffer do chamador, sem objeto Ob e fora da tabela de tokens: só os
// campos que o SepTokenFromAccessInformation preenche.

const STATUS_BUFFER_TOO_SMALL_TOKEN: u32 = 0xC000_0023;
const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x40;

/// RtlSidHashInitialize(SidAttr, Count, Hash): zera o hash; com SidAttr e
/// Count, grava ambos e marca, para os primeiros 64 SIDs, o bit i em
/// Hash[b & 0xF] e Hash[16 + (b >> 4)], onde b é o byte baixo da última
/// subautoridade.
fn sid_hash_initialize(sid_attributes: u64, count: u32, hash: &crate::ntos::inc::types::SidAndAttributesHash) {
    guest::write_bytes(hash.address(), &[0u8; SidAndAttributesHash::SIZE as usize]);
    if sid_attributes == 0 || count == 0 {
        return;
    }
    hash.sid_attr.set(sid_attributes);
    hash.sid_count.set(count);
    // SAFETY: SidAttr tem Count entradas SID_AND_ATTRIBUTES.
    let entries = unsafe { SidAndAttributes::array_at(sid_attributes, count.min(64) as usize) };
    for (index, entry) in entries.iter().enumerate() {
        let sid = sid::at(entry.sid.get());
        let last = sid.sub_authority_count.get() as u64;
        // Byte baixo de SubAuthority[count - 1] (o vetor do NT é ANYSIZE_ARRAY).
        let element = sid.sub_authority[0].address().wrapping_add(last.wrapping_sub(1).wrapping_mul(4));
        // SAFETY: SubAuthority[count - 1] dentro do SID vivo (com count 0 o
        // original lê os bytes 4..7 do próprio SID, como aqui).
        let byte = (unsafe { crate::ntos::inc::types::Field::<u32>::at(element) }.get() & 0xFF) as usize;
        let bit = 1u64 << index;
        let low = &hash.hash[byte & 0xF];
        low.set(low.get() | bit);
        let high = &hash.hash[16 + (byte >> 4)];
        high.set(high.get() | bit);
    }
}

/// Copia um SID_AND_ATTRIBUTES_HASH (contagem, array e hash recalculado).
fn copy_sid_hash(source: u64, count: &crate::ntos::inc::types::Field<u32>, array: &crate::ntos::inc::types::Field<u64>, hash: &crate::ntos::inc::types::SidAndAttributesHash) {
    // SAFETY: os PSID_AND_ATTRIBUTES_HASH do TOKEN_ACCESS_INFORMATION são válidos.
    let source = unsafe { SidAndAttributesHash::at(source) };
    count.set(source.sid_count.get());
    array.set(source.sid_attr.get());
    sid_hash_initialize(source.sid_attr.get(), source.sid_count.get(), hash);
}

/// SepTokenFromAccessInformation(Info, Token).
fn token_from_access_information(information: &TokenAccessInformation, token: &crate::ntos::inc::types::Token) {
    use crate::ntos::inc::types::{LuidAndAttributes, TokenPrivileges, TokenType};
    guest::write_bytes(token.address(), &[0u8; crate::ntos::inc::types::Token::SIZE as usize]);
    token.authentication_id.low_part.set(information.authentication_id.low_part.get());
    token.authentication_id.high_part.set(information.authentication_id.high_part.get());
    let token_type = information.token_type.get();
    token.token_type.set(token_type);
    if token_type == TokenType::TOKEN_IMPERSONATION {
        token.impersonation_level.set(information.impersonation_level.get());
    }
    // Privilégios: só LUIDs 2..36 entram nos bitmaps Present/Enabled/Default.
    // SAFETY: Privileges aponta para o TOKEN_PRIVILEGES do mesmo bloco.
    let privileges = unsafe { TokenPrivileges::at(information.privileges.get()) };
    // SAFETY: PrivilegeCount entradas LUID_AND_ATTRIBUTES seguem o contador.
    let entries = unsafe { LuidAndAttributes::array_at(privileges.privileges[0].address(), privileges.privilege_count.get() as usize) };
    let (mut present, mut enabled, mut default) = (0u64, 0u64, 0u64);
    for entry in entries {
        let luid = entry.luid.low_part.get();
        if luid.wrapping_sub(2) > 0x22 {
            continue;
        }
        let attributes = entry.attributes.get();
        present |= 1 << luid;
        if attributes & 2 != 0 {
            enabled |= 1 << luid;
        }
        if attributes & 1 != 0 {
            default |= 1 << luid;
        }
    }
    token.privileges.present.set(present);
    token.privileges.enabled.set(enabled);
    token.privileges.enabled_by_default.set(default);
    copy_sid_hash(information.sid_hash.get(), &token.user_and_group_count, &token.user_and_groups, &token.sid_hash);
    copy_sid_hash(information.restricted_sid_hash.get(), &token.restricted_sid_count, &token.restricted_sids, &token.restricted_sid_hash);
    copy_sid_hash(information.capabilities_hash.get(), &token.capability_count, &token.capabilities, &token.capabilities_hash);
    if information.package_sid.get() != 0 {
        token.package.set(information.package_sid.get());
    }
    if information.trust_level_sid.get() != 0 {
        token.trust_level_sid.set(information.trust_level_sid.get());
    }
    token.integrity_level_index.set(u32::MAX);
    token.token_flags.set(information.flags.get());
    token.mandatory_policy.set(information.mandatory_policy.policy.get());
    let groups = token.user_and_groups.get();
    if groups != 0 {
        // SAFETY: UserAndGroups tem UserAndGroupCount entradas.
        let entries = unsafe { SidAndAttributes::array_at(groups, token.user_and_group_count.get() as usize) };
        if let Some(index) = entries.iter().position(|entry| entry.attributes.get() & SE_GROUP_INTEGRITY_ENABLED != 0) {
            token.integrity_level_index.set(index as u32);
        }
    }
    token.p_security_attributes.set(information.security_attributes.get());
}

/// SeTokenFromAccessInformation(Info, Token, Length, RequiredLength):
/// Length < sizeof(TOKEN) grava o tamanho e devolve STATUS_BUFFER_TOO_SMALL.
pub fn token_from_access_information_checked(information: &TokenAccessInformation, token: u64, length: u32, required: &crate::ntos::inc::types::Field<u32>) -> u32 {
    let size = crate::ntos::inc::types::Token::SIZE as u32;
    if length < size {
        required.set(size);
        return STATUS_BUFFER_TOO_SMALL_TOKEN;
    }
    // SAFETY: o chamador deu um buffer de pelo menos sizeof(TOKEN) bytes.
    token_from_access_information(information, unsafe { crate::ntos::inc::types::Token::at(token) });
    0
}

/// Identidade de um TOKEN: o token real pela tabela de tokens; um token
/// montado por SeTokenFromAccessInformation pelos campos UserAndGroups
/// (o primeiro SID é o usuário).
fn subject_from_token(token: u64) -> Option<Subject> {
    if token == 0 {
        return None;
    }
    if let Some(subject) = tokens::with(token, |token| Subject {
        user: token.user.clone(),
        groups: token.groups.iter().map(|group| (group.sid.clone(), group.attributes)).collect(),
    }) {
        return Some(subject);
    }
    // SAFETY: token montado no buffer do chamador (layout `_TOKEN`).
    let native = unsafe { crate::ntos::inc::types::Token::at(token) };
    let (count, array) = (native.user_and_group_count.get(), native.user_and_groups.get());
    if count == 0 || array == 0 {
        return None;
    }
    // SAFETY: UserAndGroups tem UserAndGroupCount entradas.
    let entries = unsafe { SidAndAttributes::array_at(array, count as usize) };
    let mut sids: Vec<(Sid, u32)> = entries.iter().filter(|entry| entry.sid.get() != 0).map(|entry| (read_sid(entry.sid.get()), entry.attributes.get())).collect();
    if sids.is_empty() {
        return None;
    }
    let user = sids.remove(0).0;
    Some(Subject { user, groups: sids })
}

/// Nível de personificação de um TOKEN (tabela de tokens ou campo nativo).
fn token_impersonation_level(token: u64) -> i32 {
    tokens::with(token, |token| token.impersonation_level as i32).unwrap_or_else(|| {
        // SAFETY: token montado no buffer do chamador.
        unsafe { crate::ntos::inc::types::Token::at(token) }.impersonation_level.get().0
    })
}

/// SeAccessCheckFromStateEx(Sd, PrimaryToken, ClientToken, Desired,
/// PrevGranted, Privileges**, Map, Mode, GrantedAccess*, AccessStatus*):
/// o NT monta um SECURITY_SUBJECT_CONTEXT {ClientToken, ImpersonationLevel =
/// ClientToken->ImpersonationLevel, PrimaryToken} e chama
/// SeAccessCheckWithHint com o contexto já travado; aqui a mesma decisão de
/// `access_check`, com a identidade lida de cada TOKEN.
#[allow(clippy::too_many_arguments)]
pub fn access_check_from_state_ex(descriptor: u64, primary_token: u64, client_token: u64, desired: u32, previous: u32, privileges_out: u64, mapping: u64, mode: u32, granted_out: u64, status_out: u64) -> bool {
    let mut desired = desired;
    if privileges_out != 0 {
        out::<u64>(privileges_out).set(0);
    }
    if mode == 0 {
        return kernel_grant(desired, previous, mapping, granted_out, status_out);
    }
    if descriptor == 0 {
        write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
        return false;
    }
    if desired & GENERIC_MASK != 0 {
        desired = map_generic(desired, mapping);
    }
    let token = if client_token != 0 {
        if token_impersonation_level(client_token) < SECURITY_IMPERSONATION.0 {
            write_result(granted_out, status_out, 0, STATUS_BAD_IMPERSONATION_LEVEL);
            return false;
        }
        client_token
    } else {
        primary_token
    };
    decide(descriptor, subject_from_token(token), desired, previous, mapping, granted_out, status_out)
}

// ---- SeAccessCheckEx / SeAccessCheckWithHint / restrições de acesso ----------
//
// Access check com requisição/resposta, com hint, e os ajustes por
// restrições de acesso — rótulo de confiança de processo e filtros de acesso.
// A avaliação de DACL é a de `access_check` acima; aqui ficam o contrato
// SE_ACCESS_REQUEST / SE_ACCESS_REPLY e as restrições, transcritos do
// ntoskrnl 19041:
// - SeAccessCheckWithHint (rva 0x2ce400) = SeAccessCheck com um ULONG de
//   hint: bit 4 pula SepFilterCheck, bit 2 a integridade obrigatória, bit 1
//   o atalho de direitos do dono, bit 8 o SeLogAccessFailure. O avaliador do
//   OpenNT não executa nenhuma dessas etapas, então o hint não muda o
//   resultado.
// - SeAccessCheckEx (rva 0x3737f0 -> SepCommonAccessCheckExWithAdminlessChecks
//   0x373854): validação de tamanhos (REPLY 0x28, REQUEST 0x38,
//   SE_SECURITY_DESCRIPTOR 0x10 com Flags <= 7, SE_AUDIT_INFO 0x60), saídas
//   pré-zeradas, AccessReasons limpos (AuthzBasepSetAccessReasons), atalho de
//   KernelMode (GenericAll, sem STANDARD_RIGHTS_ALL), Sd/impersonação/
//   Desired == 0, e ResultListCount == 1 ou igual a ObjectTypeListCount.
//   As três estruturas vêm de um chamador de kernel (o ntfs as monta na
//   pilha), então não são sondadas.
// - O OpenNT não tem processos protegidos: nenhum token carrega
//   TrustLevelSid (TOKEN+0x450 nulo), e não há avaliador de ACEs
//   condicionais, então SYSTEM_ACCESS_FILTER_ACE (0x15) não restringe.

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

const SE_ACCESS_REQUEST_SIZE: u32 = SeAccessRequest::SIZE as u32;
const SE_ACCESS_REPLY_SIZE: u32 = SeAccessReply::SIZE as u32;
const SE_SECURITY_DESCRIPTOR_SIZE: u32 = SeSecurityDescriptor::SIZE as u32;
/// `sizeof(SE_AUDIT_INFO)` (ntifs.h): o quinto argumento só tem o Size conferido.
const SE_AUDIT_INFO_SIZE: u32 = 0x60;

// ACCESS_STATE.Flags: TOKEN_HAS_BACKUP_PRIVILEGE / TOKEN_HAS_RESTORE_PRIVILEGE.
const TOKEN_HAS_BACKUP_PRIVILEGE: u32 = 0x02;
const TOKEN_HAS_RESTORE_PRIVILEGE: u32 = 0x04;

const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 0x14;
const INHERIT_ONLY_ACE: u8 = 0x08;

/// SeAccessCheckWithHint(Sd, Hint, Subject, Locked, Desired, Previous,
/// *Privileges, Mapping, Mode, *Granted, *Status) sem o Hint, que só pula
/// etapas que o avaliador do OpenNT não tem.
#[allow(clippy::too_many_arguments)]
pub fn access_check_with_hint(descriptor: u64, subject: u64, desired: u32, previous: u32, privileges: u64, mapping: u64, mode: u32, granted: u64, status: u64) -> bool {
    access_check(descriptor, subject, desired, previous, privileges, mapping, mode, granted, status)
}

/// AuthzBasepSetAccessReasons(Mask, 0, Reasons, 0, TRUE): zera o motivo de
/// cada bit de acesso ainda pedido.
fn clear_access_reasons(mask: u32, reasons: u64) {
    if reasons == 0 {
        return;
    }
    // SAFETY: PACCESS_REASONS do SE_ACCESS_REPLY de um chamador de kernel.
    let reasons = unsafe { AccessReasons::at(reasons) };
    for (bit, reason) in reasons.data.iter().enumerate() {
        if mask & (1 << bit) != 0 {
            reason.set(0);
        }
    }
}

fn access_request_is_valid(subject: u64, request: u64, reply: &SeAccessReply, audit_info: u64) -> bool {
    if subject == 0 || request == 0 || reply.granted_access.get() == 0 {
        return false;
    }
    // SAFETY: PSE_ACCESS_REQUEST não nulo de um chamador de kernel.
    let request = unsafe { SeAccessRequest::at(request) };
    if request.size.get() != SE_ACCESS_REQUEST_SIZE {
        return false;
    }
    let se_descriptor = request.se_security_descriptor.get();
    if se_descriptor != 0 {
        // SAFETY: PSE_SECURITY_DESCRIPTOR não nulo do pedido.
        let se_descriptor = unsafe { SeSecurityDescriptor::at(se_descriptor) };
        if se_descriptor.size.get() != SE_SECURITY_DESCRIPTOR_SIZE || se_descriptor.flags.get() & !7 != 0 {
            return false;
        }
    }
    audit_info == 0 || out::<u32>(audit_info).get() == SE_AUDIT_INFO_SIZE
}

/// SeAccessCheckEx(Subject, SubjectLocked, AccessRequest, AccessReply,
/// AuditInfo, AccessMode). Com várias entradas de resultado (lista de tipos
/// de objeto), todas recebem o resultado do objeto inteiro: o avaliador do
/// OpenNT não distingue ACEs de objeto por GUID.
pub fn access_check_ex(subject: u64, request: u64, reply: u64, audit_info: u64, mode: u32) -> bool {
    if reply == 0 {
        return false;
    }
    // SAFETY: PSE_ACCESS_REPLY não nulo de um chamador de kernel.
    let reply = unsafe { SeAccessReply::at(reply) };
    if reply.size.get() != SE_ACCESS_REPLY_SIZE || reply.access_status.get() == 0 {
        return false;
    }
    let status = out::<u32>(reply.access_status.get());
    if !access_request_is_valid(subject, request, reply, audit_info) {
        status.set(STATUS_INVALID_PARAMETER);
        return false;
    }
    // SAFETY: validado acima.
    let request = unsafe { SeAccessRequest::at(request) };
    let granted = out::<u32>(reply.granted_access.get());
    granted.set(0);
    status.set(STATUS_ACCESS_DENIED);
    let privileges = reply.privileges.get();
    if privileges != 0 {
        out::<u64>(privileges).set(0);
    }
    let desired = request.desired_access.get();
    let previous = request.previously_granted_access.get();
    let mapping = request.generic_mapping.get();
    clear_access_reasons(desired & !previous & !MAXIMUM_ALLOWED, reply.access_reason.get());
    if mode == 0 {
        let generic_all = if mapping != 0 { generic_mapping(mapping).generic_all.get() } else { 0 };
        granted.set(if desired & MAXIMUM_ALLOWED != 0 { generic_all | (desired & !MAXIMUM_ALLOWED) | previous } else { desired | previous });
        status.set(0);
        return true;
    }
    let se_descriptor = request.se_security_descriptor.get();
    // SAFETY: PSE_SECURITY_DESCRIPTOR já validado.
    let object_descriptor = if se_descriptor != 0 { unsafe { SeSecurityDescriptor::at(se_descriptor) }.security_descriptor.get() } else { 0 };
    if object_descriptor == 0 {
        return false;
    }
    // SAFETY: PSECURITY_SUBJECT_CONTEXT capturado pelo chamador.
    let context = unsafe { SecuritySubjectContext::at(subject) };
    if context.client_token.get() != 0 && context.impersonation_level.get().0 < SECURITY_IMPERSONATION.0 {
        status.set(STATUS_BAD_IMPERSONATION_LEVEL);
        return false;
    }
    if desired == 0 {
        if previous == 0 {
            return false;
        }
        granted.set(previous);
        status.set(0);
        return true;
    }
    let results = reply.result_list_count.get();
    if results != 1 && results != request.object_type_list_count.get() {
        status.set(STATUS_INVALID_PARAMETER);
        return false;
    }
    let allowed = access_check(object_descriptor, subject, desired, previous, privileges, mapping, mode, granted.address(), status.address());
    // SAFETY: GrantedAccess[] e AccessStatus[] têm ResultListCount entradas.
    let (granted_list, status_list) = unsafe { (Field::<u32>::array_at(granted.address(), results as usize), Field::<u32>::array_at(status.address(), results as usize)) };
    for index in 1..results as usize {
        granted_list[index].set(granted.get());
        status_list[index].set(status.get());
    }
    allowed
}

/// SeGetTrustLabelAce: primeira SYSTEM_PROCESS_TRUST_LABEL_ACE efetiva da
/// SACL (endereço da ACE; o layout é o KNOWN_ACE de AccessAllowedAce). As
/// ACEs podem ficar desalinhadas, então são lidas pelo offset do layout.
fn trust_label_ace(object_descriptor: u64) -> Option<u64> {
    if object_descriptor == 0 {
        return None;
    }
    let sacl = descriptor::component(object_descriptor, descriptor::control(object_descriptor), 2);
    if sacl == 0 {
        return None;
    }
    // SAFETY: componente SACL do descritor (PACL alinhada a WORD).
    let count = unsafe { Acl::at(sacl) }.ace_count.get();
    let mut cursor = sacl + Acl::SIZE;
    for _ in 0..count {
        let ace_type = guest::read::<u8>(cursor + offset_of!(AceHeader, ace_type) as u64);
        let ace_flags = guest::read::<u8>(cursor + offset_of!(AceHeader, ace_flags) as u64);
        if ace_type == SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE && ace_flags & INHERIT_ONLY_ACE == 0 {
            return Some(cursor);
        }
        cursor += guest::read::<u16>(cursor + offset_of!(AceHeader, ace_size) as u64) as u64;
    }
    None
}

/// RtlSidDominatesForTrust com o token sem TrustLevelSid: domina só um SID
/// de confiança válido do tipo 0 (S-1-19-0-0); SID inválido não domina. O
/// SID segue a ACE em SidStart.
fn token_dominates(ace: u64) -> bool {
    // SAFETY: a ACE está numa ACL validada (ACEs com AceSize múltiplo de 4,
    // o alinhamento do SID).
    let trust_sid = unsafe { crate::ntos::inc::types::Sid::at(ace + offset_of!(AccessAllowedAce, sid_start) as u64) };
    acl::is_valid_process_trust_label_sid(trust_sid) && trust_sid.sub_authority[0].get() == 0
}

/// SeAdjustAccessStateForAccessConstraints(ObjectType, Sd, AccessState):
/// tira dos acessos concedidos por backup/restore o que o rótulo de
/// confiança do objeto nega a um token que não o domina.
pub fn adjust_access_state_for_access_constraints(object_type: u64, object_descriptor: u64, access_state: &AccessState) {
    let flags = access_state.flags.get();
    if flags & (TOKEN_HAS_BACKUP_PRIVILEGE | TOKEN_HAS_RESTORE_PRIVILEGE) == 0 {
        return;
    }
    let Some(ace) = trust_label_ace(object_descriptor).filter(|&ace| !token_dominates(ace)) else { return };
    let denied = !guest::read::<u32>(ace + offset_of!(AccessAllowedAce, mask) as u64);
    let (backup, restore) = match object_types::find(object_type).map(|object_type| object_type.name).as_deref() {
        Some("File") => (0x0112_0089u32, 0x011F_0116u32),
        Some("Key") => (0x0102_0019, 0x010F_0006),
        _ => (0, 0),
    };
    let mut previously_granted = access_state.previously_granted_access.get();
    if flags & TOKEN_HAS_BACKUP_PRIVILEGE != 0 {
        previously_granted &= !(backup & denied);
    }
    if flags & TOKEN_HAS_RESTORE_PRIVILEGE != 0 {
        previously_granted &= !(restore & denied);
    }
    access_state.previously_granted_access.set(previously_granted);
}

/// SeShouldCheckForAccessRightsFromParent(ObjectType, ChildSd, AccessState):
/// TRUE quando o token domina o rótulo de confiança do filho (ou não há
/// rótulo); sem avaliador de filtros, nenhum filtro corta o acesso pedido.
pub fn should_check_for_access_rights_from_parent(child_descriptor: u64) -> bool {
    trust_label_ace(child_descriptor).is_none_or(token_dominates)
}
