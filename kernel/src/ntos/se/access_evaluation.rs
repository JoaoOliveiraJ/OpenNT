//! A avaliação de acesso do Security Reference Monitor: o
//! SeAccessCheckWithHintWithAdminlessChecks, o SepAccessCheck, o
//! SepMandatoryIntegrityCheck e as passagens SepNormalAccessCheck e
//! SepMaximumAccessCheck do ntoskrnl 19041, sobre os componentes de um
//! SECURITY_DESCRIPTOR já lidos ([`OwnedDescriptor`]) e a identidade do
//! token efetivo ([`Subject`]).
//!
//! Conferido contra o ntoskrnl 19041 (rvas): SeAccessCheckWithHint
//! 0x2ce400 -> SeAccessCheckWithHintWithAdminlessChecks 0x2ce470,
//! SepAccessCheck 0x2cfba0, SepNormalAccessCheck 0x2d1160,
//! SepMaximumAccessCheck 0x2d1a30, SepMandatoryIntegrityCheck 0x2cefb0,
//! SepSidInTokenSidHash 0x347854, SepTokenIsOwner 0x3475a0.
//!
//! Em UserMode, na ordem do NT:
//! 1. descritor nulo, ou nada pedido sem nada já concedido: negado;
//!    nada pedido com acesso já concedido: o já concedido;
//! 2. o rótulo de confiança de processo (o SepTrustLevelCheck, a primeira
//!    SYSTEM_PROCESS_TRUST_LABEL_ACE da SACL que não é inherit-only): o
//!    token cujo TrustLevelSid não o domina só recebe a máscara da ACE mais
//!    ACCESS_SYSTEM_SECURITY; um direito pedido fora dela é negado e o
//!    MAXIMUM_ALLOWED é cortado por ela no fim;
//! 3. integridade obrigatória: o rótulo é a primeira SYSTEM_MANDATORY_LABEL
//!    da SACL (Medium com NO_WRITE_UP quando não há, ou quando ela é
//!    inherit-only); o token que não domina o rótulo só pode GenericRead,
//!    GenericExecute, READ_CONTROL e SYNCHRONIZE, menos a leitura com
//!    NO_READ_UP e a execução com NO_EXECUTE_UP, mais WRITE_OWNER com
//!    SeRelabelPrivilege; um direito pedido fora disso é negado e o
//!    MAXIMUM_ALLOWED é cortado por essa máscara no fim. Só vale para o
//!    token com TOKEN_MANDATORY_POLICY_NO_WRITE_UP;
//! 4. o dono (o usuário que não é só de negação, ou um grupo habilitado;
//!    num token restrito também um SID restrito) recebe READ_CONTROL e
//!    WRITE_DAC já concedidos, a menos que a DACL tenha uma ACE de OWNER
//!    RIGHTS (S-1-3-4), que então vale para ele como as outras; num token
//!    LowBox esses direitos ainda precisam vir das ACEs de pacote no passo 5;
//! 5. o SepAccessCheck: ACCESS_SYSTEM_SECURITY só com SeSecurityPrivilege
//!    (senão STATUS_PRIVILEGE_NOT_HELD); sem DACL (ausente ou nula) tudo é
//!    concedido (GenericAll com MAXIMUM_ALLOWED), exceto a um token LowBox;
//!    WRITE_OWNER pedido sai concedido por SeTakeOwnershipPrivilege ou
//!    SeRelabelPrivilege; DACL vazia nega; senão as ACEs na ordem: sem
//!    MAXIMUM_ALLOWED cada ACE permitida retira seus bits dos pedidos e uma
//!    ACE negada que toca um bit ainda pedido encerra negando; com
//!    MAXIMUM_ALLOWED as permitidas acumulam o que nenhuma negada anterior
//!    tirou e as negadas o que nenhuma permitida anterior deu. Um token
//!    restrito repete a passagem com os SIDs restritos (só os direitos de
//!    escrita num WRITE_RESTRICTED) e o resultado é a interseção; num token
//!    LowBox cada direito pedido também precisa vir de uma ACE de permissão
//!    de pacote ou de capacidade (o SepMatchPackage 0x24deb8 e o
//!    SepMatchCapability 0x31070c: o pacote do token, ALL RESTRICTED
//!    APPLICATION PACKAGES, ALL APPLICATION PACKAGES fora do LPAC e as
//!    capacidades habilitadas), sem que ACEs de negação desses SIDs contem;
//!    com MAXIMUM_ALLOWED o concedido é cortado pelo que essas ACEs dão. O
//!    resultado é o já concedido mais o obtido; zero é negado.
//!
//! As máscaras das ACEs entram como estão (o NT não as mapeia aqui: o
//! SeAssignSecurity e o SeSetSecurityDescriptorInfo já gravam as ACEs
//! mapeadas pelo tipo); o acesso pedido já vem mapeado por quem chama.
//! A ACCESS_ALLOWED_CALLBACK_ACE com dados depois do SID vale como uma ACE
//! de permissão quando a condição dela é verdadeira
//! (`se/conditional_ace.rs`, o AuthzBasepEvaluateAceCondition que o
//! SepNormalAccessCheck e o SepMaximumAccessCheck chamam, com os atributos
//! de segurança do token e os de recurso da SACL); a negada de callback e as
//! compostas não são avaliadas, e as ACEs de objeto só valem sem ObjectType
//! (não há lista de tipos de objeto).

use alloc::vec::Vec;

use crate::ntos::se::conditional_ace::{self, Truth};
use crate::ntos::se::model::{sid, Sid};
use crate::ntos::se::policy_descriptor::OwnedDescriptor;
use crate::ntos::se::security_attributes::SecurityAttribute;
use crate::ntos::se::token::tokens::Token;

// ACCESS_MASK.
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
/// DELETE | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY: os direitos de
/// escrita que não dependem do mapeamento.
const STANDARD_WRITE: u32 = 0x010D_0000;

// SECURITY_DESCRIPTOR.Control.
const DACL_PRESENT: u16 = 0x0004;
const SACL_PRESENT: u16 = 0x0010;

// Tipos e flags de ACE.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
const INHERIT_ONLY_ACE: u8 = 0x08;
/// ACE_OBJECT_TYPE_PRESENT / ACE_INHERITED_OBJECT_TYPE_PRESENT.
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;

// Atributos de grupo.
const SE_GROUP_ENABLED: u32 = 0x04;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;

// Rótulo obrigatório.
const MANDATORY_NO_WRITE_UP: u32 = 0x1;
const MANDATORY_NO_READ_UP: u32 = 0x2;
const MANDATORY_NO_EXECUTE_UP: u32 = 0x4;
/// TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN: o único bit que não liga a
/// verificação de integridade.
const TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN: u32 = 0x2;
/// SECURITY_MANDATORY_MEDIUM_RID: o nível do rótulo padrão.
pub const MEDIUM_INTEGRITY: u32 = 0x2000;

// LUIDs de privilégio.
const SE_SECURITY_PRIVILEGE: u64 = 8;
const SE_TAKE_OWNERSHIP_PRIVILEGE: u64 = 9;
const SE_RELABEL_PRIVILEGE: u64 = 32;

// NTSTATUS.
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;

/// A identidade efetiva de uma verificação: o que o NT lê do TOKEN (os
/// hashes de SIDs, os privilégios habilitados, o IntegrityLevelIndex, o
/// MandatoryPolicy e os TokenFlags de restrição e LowBox).
#[derive(Clone, Debug, Default)]
pub struct Subject {
    pub user: Sid,
    pub user_attributes: u32,
    pub groups: Vec<(Sid, u32)>,
    /// Os SIDs restritos (TOKEN_IS_RESTRICTED quando não vazio).
    pub restricted_sids: Vec<(Sid, u32)>,
    /// TOKEN_WRITE_RESTRICTED.
    pub write_restricted: bool,
    /// LUIDs dos privilégios habilitados.
    pub privileges: Vec<u64>,
    /// O SID de integridade (vazio = IntegrityLevelIndex -1, Untrusted).
    pub integrity: Sid,
    pub mandatory_policy: u32,
    /// O SID do pacote de um token LowBox.
    pub package: Option<Sid>,
    pub capabilities: Vec<(Sid, u32)>,
    pub less_privileged_app_container: bool,
    /// Os atributos de segurança do token (as afirmações locais das ACEs
    /// condicionais).
    pub attributes: Vec<SecurityAttribute>,
    /// O TrustLevelSid do token (o nível de confiança do processo
    /// protegido; nenhum fora dele).
    pub trust_level_sid: Option<Sid>,
}

impl Subject {
    /// A identidade de um token do OpenNT.
    pub fn from_token(token: &Token) -> Self {
        Self {
            user: token.user.clone(),
            user_attributes: token.user_attributes,
            groups: token.groups.iter().map(|group| (group.sid.clone(), group.attributes)).collect(),
            restricted_sids: token.restricted_sids.iter().map(|group| (group.sid.clone(), group.attributes)).collect(),
            write_restricted: token.write_restricted,
            privileges: token.privileges.iter().filter(|privilege| privilege.attributes & 2 != 0).map(|privilege| privilege.id).collect(),
            integrity: token.integrity.clone(),
            mandatory_policy: token.mandatory_policy,
            package: token.app_container.clone(),
            capabilities: token.capabilities.iter().map(|group| (group.sid.clone(), group.attributes)).collect(),
            less_privileged_app_container: crate::ntos::se::token::tokens::less_privileged(token),
            attributes: token.security_attributes.clone(),
            trust_level_sid: token.trust_level_sid.clone(),
        }
    }

    fn privileged(&self, luid: u64) -> bool {
        self.privileges.contains(&luid)
    }

    fn restricted(&self) -> bool {
        !self.restricted_sids.is_empty()
    }

    fn lowbox(&self) -> bool {
        self.package.is_some()
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    bytes.get(offset..offset + 2).map_or(0, |part| u16::from_le_bytes([part[0], part[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    bytes.get(offset..offset + 4).map_or(0, |part| u32::from_le_bytes([part[0], part[1], part[2], part[3]]))
}

/// O SID em `bytes[offset..]` (cabeçalho de 8 bytes e 4 por subautoridade).
fn sid_at(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    let count = *bytes.get(offset + 1)? as usize;
    bytes.get(offset..offset + 8 + 4 * count)
}

/// O último SubAuthority de um SID (o nível de um SID de integridade).
fn last_sub_authority(sid: &[u8]) -> Option<u32> {
    let count = *sid.get(1)? as usize;
    (count != 0).then(|| u32_at(sid, 8 + 4 * (count - 1)))
}

/// Uma ACE de uma ACL: tipo, flags, máscara e o SID (o das ACEs de objeto
/// vem depois dos GUIDs presentes).
struct Entry<'a> {
    kind: u8,
    flags: u8,
    mask: u32,
    sid: Option<&'a [u8]>,
    /// ACE de objeto com ObjectType: só vale para uma lista de tipos.
    object_typed: bool,
    /// Os dados depois do SID de uma ACCESS_ALLOWED_CALLBACK_ACE (a
    /// expressão da condição); sem dados, a ACE não vale.
    condition: Option<&'a [u8]>,
}

/// As ACEs de uma ACL (cabeçalho de 8 bytes; AceCount em +4).
fn entries(acl: &[u8]) -> Vec<Entry<'_>> {
    let count = u16_at(acl, 4) as usize;
    let mut list = Vec::with_capacity(count);
    let mut offset = 8usize;
    for _ in 0..count {
        let Some(&kind) = acl.get(offset) else { break };
        let flags = acl.get(offset + 1).copied().unwrap_or(0);
        let size = u16_at(acl, offset + 2) as usize;
        if size < 8 || offset + size > acl.len() {
            break;
        }
        let ace = &acl[offset..offset + size];
        let mask = u32_at(ace, 4);
        let (sid, object_typed) = match kind {
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE | 0x07 | 0x08 | 0x0B | 0x0C | 0x0F | 0x10 => {
                let object_flags = u32_at(ace, 8);
                let mut at = 12;
                if object_flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                    at += 16;
                }
                if object_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    at += 16;
                }
                (sid_at(ace, at), object_flags & ACE_OBJECT_TYPE_PRESENT != 0)
            }
            _ => (sid_at(ace, 8), false),
        };
        let condition = match (kind, sid) {
            (ACCESS_ALLOWED_CALLBACK_ACE_TYPE, Some(found)) => ace.get(8 + found.len()..).filter(|data| !data.is_empty()),
            _ => None,
        };
        list.push(Entry { kind, flags, mask, sid, object_typed, condition });
        offset += size;
    }
    list
}

/// OWNER RIGHTS (S-1-3-4).
fn owner_rights_sid() -> Sid {
    sid(3, &[4])
}

/// SepSidInTokenSidHash: o usuário que não é só de negação vale para as duas
/// ACEs e o só de negação só para a negada; um grupo habilitado vale para as
/// duas e um só de negação para a negada. Na passagem restrita todos os SIDs
/// restritos seguem a regra dos grupos. OWNER RIGHTS vale para o dono.
fn sid_in_subject(subject: &Subject, ace_sid: &[u8], deny: bool, restricted: bool, is_owner: bool) -> bool {
    if is_owner && ace_sid == owner_rights_sid().as_slice() {
        return true;
    }
    let group_matches = |attributes: u32| attributes & SE_GROUP_ENABLED != 0 || (deny && attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0);
    if restricted {
        return subject.restricted_sids.iter().any(|(entry, attributes)| entry.as_slice() == ace_sid && group_matches(*attributes));
    }
    if !subject.user.is_empty() && subject.user.as_slice() == ace_sid {
        return subject.user_attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0 || deny;
    }
    subject.groups.iter().any(|(entry, attributes)| entry.as_slice() == ace_sid && group_matches(*attributes))
}

/// SepSidInToken(Token, NULL, Sid, DenyAce, FALSE) sobre a identidade do
/// token: o usuário e os grupos pela regra do SepSidInTokenSidHash, fora da
/// passagem restrita e sem OWNER RIGHTS.
pub fn sid_in_token(subject: &Subject, ace_sid: &[u8], deny: bool) -> bool {
    sid_in_subject(subject, ace_sid, deny, false, false)
}

/// O SepMatchPackage e o SepMatchCapability de uma ACE de permissão para um
/// token LowBox. Um SID de pacote (S-1-15-2-...) de duas subautoridades é um
/// dos grupos de todos os pacotes: ALL APPLICATION PACKAGES (S-1-15-2-1)
/// casa fora do LPAC (sem WIN://NOALLAPPPKG), ALL RESTRICTED APPLICATION
/// PACKAGES (S-1-15-2-2) sempre e outro valor nunca; os demais casam com o
/// pacote do token. Um SID de capacidade (S-1-15-3-...) casa com uma
/// capacidade habilitada do token (o SepSidInTokenSidHash do
/// CapabilitiesHash).
fn package_ace_matches(subject: &Subject, ace_sid: &[u8]) -> bool {
    use crate::ntos::se::token::lowbox::{is_capability_sid, is_package_sid};
    if is_package_sid(ace_sid) {
        if ace_sid[1] == 2 {
            return match u32_at(ace_sid, 12) {
                1 => !subject.less_privileged_app_container,
                2 => true,
                _ => false,
            };
        }
        return subject.package.as_deref() == Some(ace_sid);
    }
    is_capability_sid(ace_sid) && subject.capabilities.iter().any(|(entry, attributes)| entry.as_slice() == ace_sid && attributes & SE_GROUP_ENABLED != 0)
}

/// O acesso que a DACL dá ao token LowBox pelas ACEs de permissão de pacote
/// e de capacidade (o que o SepMatchPackage e o SepMatchCapability acumulam
/// durante o SepNormalAccessCheck e o SepMaximumAccessCheck). As ACEs de
/// negação não entram: o SepSidInToken das negadas só olha o usuário e os
/// grupos.
fn package_granted(dacl: &[u8], subject: &Subject, sacl: Option<&[u8]>) -> u32 {
    entries(dacl)
        .iter()
        .filter(|entry| effective(entry) && allows(entry, subject, sacl) && package_ace_matches(subject, entry.sid.unwrap_or_default()))
        .fold(0, |granted, entry| granted | entry.mask)
}

/// A ACE vale para a avaliação (não é inherit-only, tem SID e não é uma ACE
/// de objeto com ObjectType).
fn effective(entry: &Entry) -> bool {
    entry.flags & INHERIT_ONLY_ACE == 0 && entry.sid.is_some() && !entry.object_typed
}

fn is_allow(kind: u8) -> bool {
    kind == ACCESS_ALLOWED_ACE_TYPE || kind == ACCESS_ALLOWED_OBJECT_ACE_TYPE
}

/// A ACE de permissão vale: uma ACE de permissão comum, ou a de callback com
/// a condição verdadeira (o `cmp [rsp+0x78], 1` depois do
/// AuthzBasepEvaluateAceCondition, 0x2d16d2).
fn allows(entry: &Entry, subject: &Subject, sacl: Option<&[u8]>) -> bool {
    if is_allow(entry.kind) {
        return true;
    }
    let Some(condition) = entry.condition else { return false };
    let context = conditional_ace::Context { user: &subject.user, user_attributes: subject.user_attributes, groups: &subject.groups, local: &subject.attributes, sacl };
    conditional_ace::evaluate(condition, &context) == Truth::True
}

fn is_deny(kind: u8) -> bool {
    kind == ACCESS_DENIED_ACE_TYPE || kind == ACCESS_DENIED_OBJECT_ACE_TYPE
}

/// SepNormalAccessCheck: os bits ainda pedidos depois da DACL (zero =
/// tudo concedido; uma ACE negada que toca um pedido encerra a passagem).
fn normal_access_check(dacl: &[u8], sacl: Option<&[u8]>, subject: &Subject, desired: u32, restricted: bool, is_owner: bool) -> u32 {
    let mut remaining = desired;
    for entry in entries(dacl) {
        if remaining == 0 {
            break;
        }
        if !effective(&entry) {
            continue;
        }
        let ace_sid = entry.sid.unwrap_or_default();
        if allows(&entry, subject, sacl) {
            if sid_in_subject(subject, ace_sid, false, restricted, is_owner) {
                remaining &= !entry.mask;
            }
        } else if is_deny(entry.kind) && sid_in_subject(subject, ace_sid, true, restricted, is_owner) && entry.mask & remaining != 0 {
            break;
        }
    }
    remaining
}

/// SepMaximumAccessCheck: o acesso que a DACL dá ao sujeito.
fn maximum_access_check(dacl: &[u8], sacl: Option<&[u8]>, subject: &Subject, restricted: bool, is_owner: bool) -> u32 {
    let (mut granted, mut denied) = (0u32, 0u32);
    for entry in entries(dacl) {
        if !effective(&entry) {
            continue;
        }
        let ace_sid = entry.sid.unwrap_or_default();
        if allows(&entry, subject, sacl) {
            if sid_in_subject(subject, ace_sid, false, restricted, is_owner) {
                granted |= entry.mask & !denied;
            }
        } else if is_deny(entry.kind) && sid_in_subject(subject, ace_sid, true, restricted, is_owner) {
            denied |= entry.mask & !granted;
        }
    }
    granted
}

/// O resultado do SepMandatoryIntegrityCheck.
#[derive(Clone, Copy, Debug)]
pub struct Mandatory {
    /// Os direitos que a integridade permite.
    pub mask: u32,
    /// O token domina o rótulo (nada é cortado).
    pub dominates: bool,
    /// O MandatoryPolicy do token.
    pub policy: u32,
    /// O nível do rótulo do objeto.
    pub object_level: u32,
}

/// A primeira SYSTEM_MANDATORY_LABEL_ACE da SACL: (política, SID); a padrão
/// (Medium, NO_WRITE_UP) sem SACL, sem rótulo ou com o rótulo inherit-only.
fn mandatory_label(descriptor: &OwnedDescriptor) -> (u32, Sid) {
    let default = (MANDATORY_NO_WRITE_UP, sid(16, &[MEDIUM_INTEGRITY]));
    if descriptor.control & SACL_PRESENT == 0 {
        return default;
    }
    let Some(sacl) = &descriptor.sacl else { return default };
    for entry in entries(sacl) {
        if entry.kind != SYSTEM_MANDATORY_LABEL_ACE_TYPE {
            continue;
        }
        if entry.flags & INHERIT_ONLY_ACE != 0 {
            return default;
        }
        return match entry.sid {
            Some(label) => (entry.mask, label.to_vec()),
            None => default,
        };
    }
    default
}

/// O SID de integridade tem a autoridade de rótulo obrigatório (16).
fn is_mandatory_sid(candidate: &[u8]) -> bool {
    candidate.get(2..8) == Some(&[0, 0, 0, 0, 0, 16][..])
}

/// SepMandatoryIntegrityCheck(GenericMapping, Sd, ..., Token, ...).
pub fn mandatory_integrity_check(descriptor: &OwnedDescriptor, subject: &Subject, mapping: &[u32; 4]) -> Result<Mandatory, u32> {
    let [read, write, execute, all] = *mapping;
    let policy = subject.mandatory_policy;
    if policy & !TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN == 0 {
        return Ok(Mandatory { mask: all, dominates: true, policy, object_level: 0 });
    }
    let (label_policy, label) = mandatory_label(descriptor);
    let token_sid = if subject.integrity.is_empty() { sid(16, &[0]) } else { subject.integrity.clone() };
    let object_level = last_sub_authority(&label).unwrap_or(0);
    let dominates = if token_sid == label {
        true
    } else {
        if !is_mandatory_sid(&token_sid) || !is_mandatory_sid(&label) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        match (last_sub_authority(&token_sid), last_sub_authority(&label)) {
            (_, None) => true,
            (token_level, Some(level)) => token_level.unwrap_or(0) >= level,
        }
    };
    let no_write_up_token = policy & MANDATORY_NO_WRITE_UP != 0;
    let mut mask = if no_write_up_token { read | execute | READ_CONTROL | SYNCHRONIZE } else { 0 };
    if dominates {
        if no_write_up_token {
            mask |= all | 0x011F_FFFF;
        }
    } else {
        let can_read = label_policy & MANDATORY_NO_READ_UP == 0;
        let can_execute = label_policy & MANDATORY_NO_EXECUTE_UP == 0;
        let write_bits = write | STANDARD_WRITE;
        let read_bits = read | READ_CONTROL;
        let execute_bits = (execute & !read) | SYNCHRONIZE;
        if label_policy & MANDATORY_NO_READ_UP != 0 {
            let kept = if can_execute { execute_bits } else { 0 };
            mask &= !read_bits | kept;
        }
        if label_policy & MANDATORY_NO_EXECUTE_UP != 0 {
            let kept = if can_read { read_bits } else { 0 };
            mask &= !(execute_bits & !kept);
        }
        if label_policy & MANDATORY_NO_WRITE_UP != 0 {
            let kept = (if can_execute { execute_bits } else { 0 }) | (if can_read { read_bits } else { 0 });
            mask &= !(write_bits & !kept);
        }
    }
    if subject.privileged(SE_RELABEL_PRIVILEGE) {
        mask |= WRITE_OWNER;
    }
    Ok(Mandatory { mask, dominates, policy, object_level })
}

/// SepTokenIsOwner: o dono do descritor é o usuário (que não é só de
/// negação) ou um grupo habilitado; num token restrito, também um SID
/// restrito habilitado.
pub fn subject_is_owner(descriptor: &OwnedDescriptor, subject: &Subject) -> bool {
    let Some(owner) = &descriptor.owner else { return false };
    let owned = if !subject.user.is_empty() && subject.user == *owner {
        subject.user_attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0
    } else {
        subject.groups.iter().any(|(entry, attributes)| entry == owner && attributes & SE_GROUP_ENABLED != 0)
    };
    owned && (!subject.restricted() || subject.restricted_sids.iter().any(|(entry, attributes)| entry == owner && attributes & SE_GROUP_ENABLED != 0))
}

/// A DACL presente tem uma ACE efetiva de OWNER RIGHTS.
fn dacl_has_owner_rights(descriptor: &OwnedDescriptor) -> bool {
    if descriptor.control & DACL_PRESENT == 0 {
        return false;
    }
    let owner_rights = owner_rights_sid();
    descriptor.dacl.as_deref().is_some_and(|dacl| entries(dacl).iter().any(|entry| entry.flags & INHERIT_ONLY_ACE == 0 && entry.sid == Some(owner_rights.as_slice())))
}

/// Os direitos de escrita que um token WRITE_RESTRICTED restringe.
fn write_restriction_mask(mapping: &[u32; 4]) -> u32 {
    (mapping[1] & !(mapping[0] | mapping[2])) | STANDARD_WRITE
}

fn finish(granted: u32) -> Result<u32, u32> {
    if granted == 0 { Err(STATUS_ACCESS_DENIED) } else { Ok(granted) }
}

/// SepAccessCheck: privilégios, DACL, segunda passagem restrita e de pacote.
/// `owner_implied` é o READ_CONTROL/WRITE_DAC que o dono já recebeu antes
/// (o ebx do SepCommonAccessCheckExWithAdminlessChecks, 0x373f3c, que vai ao
/// SepAccessCheck na estrutura do LowBox): um token LowBox também precisa
/// deles nas ACEs de pacote.
fn sep_access_check(descriptor: &OwnedDescriptor, subject: &Subject, desired: u32, previous: u32, mapping: &[u32; 4], is_owner: bool, owner_implied: u32) -> Result<u32, u32> {
    // O LowBox confere o pedido de entrada inteiro contra as ACEs de pacote
    // (o DesiredAccess original do SepAccessCheck, 0x2d0032).
    let requested = desired;
    let (mut desired, mut previous) = (desired, previous);
    if desired & ACCESS_SYSTEM_SECURITY != 0 {
        if !subject.privileged(SE_SECURITY_PRIVILEGE) {
            crate::ntos::ps::user::state::note_denial("privilegio", "", desired, 0);
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        desired &= !ACCESS_SYSTEM_SECURITY;
        previous |= ACCESS_SYSTEM_SECURITY;
        if desired == 0 {
            return finish(previous);
        }
    }
    let dacl = if descriptor.control & DACL_PRESENT != 0 { descriptor.dacl.as_deref() } else { None };
    let Some(dacl) = dacl else {
        if subject.lowbox() {
            return Err(STATUS_ACCESS_DENIED);
        }
        let granted = if desired & MAXIMUM_ALLOWED != 0 { mapping[3] | (desired & !MAXIMUM_ALLOWED) | previous } else { desired | previous };
        return finish(granted);
    };
    if desired & WRITE_OWNER != 0 && (subject.privileged(SE_TAKE_OWNERSHIP_PRIVILEGE) || subject.privileged(SE_RELABEL_PRIVILEGE)) {
        desired &= !WRITE_OWNER;
        previous |= WRITE_OWNER;
        if desired == 0 {
            return finish(previous);
        }
    }
    if u16_at(dacl, 4) == 0 {
        return if desired == MAXIMUM_ALLOWED { finish(previous) } else { Err(STATUS_ACCESS_DENIED) };
    }
    let restriction = if subject.write_restricted { write_restriction_mask(mapping) } else { mapping[3] | 0x001F_FFFF };
    let sacl = if descriptor.control & SACL_PRESENT != 0 { descriptor.sacl.as_deref() } else { None };
    if desired & MAXIMUM_ALLOWED == 0 {
        if normal_access_check(dacl, sacl, subject, desired, false, is_owner) != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        if subject.restricted() && desired & restriction != 0 && normal_access_check(dacl, sacl, subject, desired & restriction, true, is_owner) != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        // O caminho normal do LowBox (0x2d0042): o pedido e os direitos do
        // dono precisam vir das ACEs de pacote e de capacidade.
        if subject.lowbox() && (requested | owner_implied) & !package_granted(dacl, subject, sacl) != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        return finish(previous | desired);
    }
    let mut granted = maximum_access_check(dacl, sacl, subject, false, is_owner);
    if subject.restricted() {
        granted &= maximum_access_check(dacl, sacl, subject, true, is_owner) | !restriction;
    }
    // O MAXIMUM_ALLOWED do LowBox (0x2d0242): o concedido cortado pelas ACEs
    // de pacote, e os direitos do dono saem do já concedido (voltam só se
    // essas ACEs os dão).
    if subject.lowbox() {
        granted &= package_granted(dacl, subject, sacl);
        previous &= !owner_implied;
    }
    if desired & !MAXIMUM_ALLOWED & !granted != 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    finish(previous | granted)
}

/// SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE.
const TRUST_LABEL_ACE_TYPE: u8 = 0x14;

/// O SepTrustLevelCheck do SeAccessCheckWithHintWithAdminlessChecks: o
/// rótulo é a primeira SYSTEM_PROCESS_TRUST_LABEL_ACE da SACL que não é
/// inherit-only (o SeGetTrustLabelAce); sem rótulo, ou com um token cujo
/// TrustLevelSid o domina (RtlSidDominatesForTrust), nada é cortado; senão
/// só a máscara da ACE mais ACCESS_SYSTEM_SECURITY. Um SID de confiança
/// inválido é o NTSTATUS do RtlSidDominatesForTrust.
pub fn trust_level_mask(descriptor: &OwnedDescriptor, subject: &Subject) -> Result<u32, u32> {
    if descriptor.control & SACL_PRESENT == 0 {
        return Ok(u32::MAX);
    }
    let Some(sacl) = descriptor.sacl.as_deref() else { return Ok(u32::MAX) };
    let count = u16_at(sacl, 4) as usize;
    let mut offset = 8usize;
    for _ in 0..count {
        let size = u16_at(sacl, offset + 2) as usize;
        if size < 8 || offset + size > sacl.len() {
            break;
        }
        if sacl[offset] == TRUST_LABEL_ACE_TYPE && sacl[offset + 1] & INHERIT_ONLY_ACE == 0 {
            let label = &sacl[offset + 8..offset + size];
            return match crate::ntos::se::token::trust::dominates(subject.trust_level_sid.as_deref(), Some(label)) {
                Ok(true) => Ok(u32::MAX),
                Ok(false) => Ok(u32_at(sacl, offset + 4) | ACCESS_SYSTEM_SECURITY),
                Err(status) => Err(status),
            };
        }
        offset += size;
    }
    Ok(u32::MAX)
}

/// SeAccessCheck em KernelMode: o pedido inteiro (GenericAll com
/// MAXIMUM_ALLOWED) mais o já concedido, sem olhar o descritor.
pub fn kernel_mode_grant(desired: u32, previous: u32, mapping: &[u32; 4]) -> u32 {
    if desired & MAXIMUM_ALLOWED != 0 { mapping[3] | (desired & !MAXIMUM_ALLOWED) | previous } else { desired | previous }
}

/// SeAccessCheckWithHint em UserMode: `Ok(acesso concedido)` ou
/// `Err(NTSTATUS)`. `desired` já vem mapeado; `descriptor` nulo é negado.
pub fn access_check(descriptor: Option<&OwnedDescriptor>, subject: &Subject, desired: u32, previous: u32, mapping: &[u32; 4]) -> Result<u32, u32> {
    let Some(descriptor) = descriptor else { return Err(STATUS_ACCESS_DENIED) };
    if desired == 0 {
        return if previous == 0 { Err(STATUS_ACCESS_DENIED) } else { Ok(previous) };
    }
    let explicit = desired & !MAXIMUM_ALLOWED;
    // O rótulo de confiança de processo antes da integridade: um direito
    // pedido fora da máscara dele é negado.
    let trust_mask = trust_level_mask(descriptor, subject)?;
    if explicit & trust_mask != explicit {
        return Err(STATUS_ACCESS_DENIED);
    }
    let mandatory = mandatory_integrity_check(descriptor, subject, mapping)?;
    let lowbox_exempt = subject.lowbox() && mandatory.object_level <= MEDIUM_INTEGRITY;
    if mandatory.policy != 0 && mandatory.mask & explicit != explicit && !lowbox_exempt {
        return Err(STATUS_ACCESS_DENIED);
    }
    let (mut remaining, mut previous) = (desired, previous);
    let mut is_owner = false;
    let mut owner_implied = 0;
    if remaining & (MAXIMUM_ALLOWED | WRITE_DAC | READ_CONTROL) != 0 && subject_is_owner(descriptor, subject) {
        is_owner = true;
        if !dacl_has_owner_rights(descriptor) {
            let implied = if remaining & MAXIMUM_ALLOWED != 0 { READ_CONTROL | WRITE_DAC } else { remaining & (READ_CONTROL | WRITE_DAC) };
            remaining &= !(READ_CONTROL | WRITE_DAC);
            previous |= implied;
            owner_implied = implied;
            is_owner = false;
        }
    }
    // Os direitos do dono cobrindo o pedido inteiro bastam, salvo num token
    // LowBox, que ainda passa pelas ACEs de pacote (0x48af28).
    if remaining == 0 && !(subject.lowbox() && owner_implied != 0) {
        return Ok(previous);
    }
    let mut granted = sep_access_check(descriptor, subject, remaining, previous, mapping, is_owner, owner_implied)?;
    if desired & MAXIMUM_ALLOWED != 0 {
        granted &= trust_mask;
        if mandatory.policy != 0 && !mandatory.dominates && !lowbox_exempt {
            granted &= mandatory.mask;
        }
        if granted == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
    }
    Ok(granted)
}

/// Mapeia os bits genéricos das ACEs de uma ACL pelo mapeamento do tipo,
/// como o RtlpNewSecurityObject grava a DACL padrão do token num objeto
/// novo (as ACEs inherit-only ficam como estão).
pub fn map_acl_generics(acl: &mut [u8], mapping: &[u32; 4]) {
    let count = u16_at(acl, 4) as usize;
    let mut offset = 8usize;
    for _ in 0..count {
        let size = u16_at(acl, offset + 2) as usize;
        if size < 8 || offset + size > acl.len() {
            break;
        }
        if acl[offset + 1] & INHERIT_ONLY_ACE == 0 {
            let mut mask = u32_at(acl, offset + 4);
            for (index, &bits) in mapping.iter().enumerate() {
                if mask & (0x8000_0000 >> index) != 0 {
                    mask |= bits;
                }
            }
            mask &= 0x0FFF_FFFF;
            acl[offset + 4..offset + 8].copy_from_slice(&mask.to_le_bytes());
        }
        offset += size;
    }
}
