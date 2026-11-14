//! SeFilterToken: um token novo, restrito a partir de outro.
//!
//! ntoskrnl 10.0.19041: SeFilterToken 0x798c70 -> SepFilterToken 0x5db0fc
//! (KernelMode) -> SepRemoveDisabledGroupsAndPrivileges 0x5da360.
//!
//! - Entrada: TOKEN_GROUPS SidsToDisable, TOKEN_PRIVILEGES PrivilegesToDelete
//!   e TOKEN_GROUPS RestrictedSids (Attributes não nulos nestes são
//!   STATUS_INVALID_PARAMETER, como SID de pacote ou de capacidade, e pedir
//!   WRITE_RESTRICTED sobre um token já restrito, write-restricted ou
//!   sandbox-inert).
//! - O token novo tem TokenId e ModifiedId novos (ModifiedId alocado
//!   primeiro), o tipo, o nível de impersonação, o dono e o resto do token
//!   de origem; TokenFlags = os da origem sem WRITE_RESTRICTED,
//!   SESSION_NOT_REFERENCED e VIRTUALIZE_ENABLED.
//! - SIDs restritos: os pedidos com Attributes 7; numa origem já restrita,
//!   só os que ela também tem (ficar sem nenhum é STATUS_INVALID_PARAMETER).
//!   Havendo algum, IS_RESTRICTED | IS_FILTERED; WRITE_RESTRICTED soma
//!   WRITE_RESTRICTED | IS_RESTRICTED. SANDBOX_INERT liga o flag
//!   sandbox-inert só se quem chama roda num contexto de sistema (o
//!   SepSystemContextSecurityDescriptor: SYSTEM, SERVICE, TrustedInstaller,
//!   RESTRICTED e WRITE_RESTRICTED).
//! - Usuário e grupos (fora os deny-only e de integridade) que estão em
//!   SidsToDisable, ou que têm RID elevado com LUA_TOKEN, viram deny-only
//!   (sem os bits 0..3) e marcam IS_FILTERED; o dono padrão desabilitado
//!   volta a ser o usuário.
//! - DISABLE_MAX_PRIVILEGE deixa só SeChangeNotifyPrivilege; senão,
//!   LUA_TOKEN aplica a máscara de privilégios do LUA e cada LUID 2..=0x24
//!   de PrivilegesToDelete sai. Perder privilégios marca IS_FILTERED.
//!
//! O token resultante volta referenciado e sem handle. A verificação de
//! token sandboxed de quem chama (SepNewTokenAsRestrictedAsProcessToken) não
//! se aplica: o OpenNT não tem processos sandboxed chamando de modo kernel.

use alloc::vec::Vec;
use core::cell::Cell;

use crate::ntos::inc::field::Field;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::se::model::{sid, Group, Sid};
use crate::ntos::se::security_attributes;
use crate::ntos::se::sid as sids;
use crate::ntos::se::token::{capability_access, tokens};
use crate::rtl::KernelError;

pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Flags de SeFilterToken.
pub const DISABLE_MAX_PRIVILEGE: u32 = 0x1;
pub const SANDBOX_INERT: u32 = 0x2;
pub const LUA_TOKEN: u32 = 0x4;
pub const WRITE_RESTRICTED: u32 = 0x8;

/// TokenFlags.
const TOKEN_WRITE_RESTRICTED: u32 = 0x8;
const TOKEN_IS_RESTRICTED: u32 = 0x10;
const TOKEN_SANDBOX_INERT: u32 = 0x40;
const TOKEN_IS_FILTERED: u32 = 0x800;
/// Limpos na cópia: WRITE_RESTRICTED, SESSION_NOT_REFERENCED e
/// VIRTUALIZE_ENABLED.
const COPIED_FLAGS: u32 = 0xFFFF_FBD7;
/// Origem que não aceita WRITE_RESTRICTED: write-restricted, restrita ou
/// sandbox-inert.
const RESTRICTION_FLAGS: u32 = 0x58;

/// SE_GROUP_USE_FOR_DENY_ONLY e SE_GROUP_INTEGRITY.
const DENY_ONLY: u32 = 0x10;
const SKIPPED_GROUPS: u32 = 0x30;
/// SeChangeNotifyPrivilege.
const CHANGE_NOTIFY: u64 = 23;
/// Máscaras de privilégios do LUA (com e sem grupo de RID elevado).
const LUA_ELEVATED_MASK: u64 = 0x6_0288_0000;
const LUA_MASK: u64 = 0xFFFF_FFEE_DFE9_F97B;
/// RIDs elevados do RtlIsElevatedRid (tabela 0x18530).
const ELEVATED_RIDS: [u32; 19] = [512, 516, 521, 498, 517, 518, 519, 520, 544, 547, 548, 549, 550, 551, 553, 554, 556, 569, 114];

/// SID_AND_ATTRIBUTES[] de um TOKEN_GROUPS (ou vazio).
fn groups(pointer: u64) -> Vec<(Sid, u32)> {
    if pointer == 0 {
        return Vec::new();
    }
    let count = guest::read32(pointer) as u64;
    (0..count).map(|index| (sids::read(guest::read64(pointer + 8 + index * 16)), guest::read32(pointer + 16 + index * 16))).collect()
}

/// LowPart dos LUID_AND_ATTRIBUTES de um TOKEN_PRIVILEGES (ou vazio).
fn privileges(pointer: u64) -> Vec<u32> {
    if pointer == 0 {
        return Vec::new();
    }
    let count = guest::read32(pointer) as u64;
    (0..count).map(|index| guest::read32(pointer + 4 + index * 12)).collect()
}

/// RtlIsPackageSid (primeira subautoridade 2) e RtlIsCapabilitySid (3):
/// revisão 1, autoridade 15 e pelo menos duas subautoridades.
fn is_app_package_identifier(identifier: &[u8], first: u32) -> bool {
    identifier.len() >= 12 && identifier[0] == 1 && identifier[1] >= 2 && identifier[2..8] == [0, 0, 0, 0, 0, 15] && u32::from_le_bytes([identifier[8], identifier[9], identifier[10], identifier[11]]) == first
}

/// RtlIsElevatedRid: grupo normal, primeira subautoridade fora de 80..=111
/// (SIDs de serviço) e o último RID na tabela.
fn is_elevated(identifier: &[u8], attributes: u32) -> bool {
    let count = identifier.get(1).copied().unwrap_or(0) as usize;
    if attributes & SKIPPED_GROUPS != 0 || count == 0 || identifier.len() < 8 + count * 4 {
        return false;
    }
    let sub = |index: usize| u32::from_le_bytes([identifier[8 + index * 4], identifier[9 + index * 4], identifier[10 + index * 4], identifier[11 + index * 4]]);
    !(80..=111).contains(&sub(0)) && ELEVATED_RIDS.contains(&sub(count - 1))
}

/// SeIsSystemContext do token primário de quem chama: o acesso 1 do
/// SepSystemContextSecurityDescriptor.
fn caller_is_system_context() -> bool {
    let Some(primary) = process::get_primary_token(process::get_current_process()) else { return false };
    let allowed = [sid(5, &[18]), sid(5, &[6]), sid(5, &[80, 956_008_885, 3_418_522_649, 1_831_038_044, 1_853_292_631, 2_271_478_464]), sid(5, &[12]), sid(5, &[33])];
    capability_access::permits_identifiers(primary, &allowed, false)
}

/// SeFilterToken(ExistingToken, Flags, SidsToDisable, PrivilegesToDelete,
/// RestrictedSids, FilteredToken*) -> NTSTATUS.
pub fn filter_token(existing: u64, flags: u32, sids_to_disable: u64, privileges_to_delete: u64, restricted_sids: u64, filtered: &Field<u64>) -> Result<u32, KernelError> {
    filtered.set(0);
    let disable = groups(sids_to_disable);
    let delete = privileges(privileges_to_delete);
    let restricted = groups(restricted_sids);
    if restricted.iter().any(|(_, attributes)| *attributes != 0) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let source = tokens::get(existing).ok_or_else(|| KernelError::new("SeFilterToken: invalid token"))?;
    let source_flags = tokens::body(existing).token_flags.get();
    if flags & WRITE_RESTRICTED != 0 && source_flags & RESTRICTION_FLAGS != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if restricted.iter().any(|(identifier, _)| is_app_package_identifier(identifier, 2) || is_app_package_identifier(identifier, 3)) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let kept: Vec<Group> = restricted
        .iter()
        .filter(|(identifier, _)| source.restricted_sids.is_empty() || source.restricted_sids.iter().any(|entry| &entry.sid == identifier))
        .map(|(identifier, _)| Group { sid: identifier.clone(), attributes: 7 })
        .collect();
    // ModifiedId e TokenId são alocados antes de qualquer falha do NT.
    let modified = tokens::allocate_luid();
    if !source.restricted_sids.is_empty() && kept.is_empty() {
        tokens::allocate_luid();
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let sandbox_inert = flags & SANDBOX_INERT != 0 && caller_is_system_context();
    let groups_filtered = Cell::new(false);
    let privileges_filtered = Cell::new(false);
    let initialize = |token: &mut tokens::Token| {
        token.modified_id = modified;
        token.kind = source.kind;
        token.impersonation_level = source.impersonation_level;
        token.owner = source.owner.clone();
        token.security_attributes = security_attributes::clone(&source.security_attributes, false);
        token.bno_prefix = source.bno_prefix.clone();
        token.restricted_sids = kept.clone();
        token.write_restricted = flags & WRITE_RESTRICTED != 0;
        // SepRemoveDisabledGroupsAndPrivileges: usuário e grupos.
        let mut elevated = false;
        let mut deny = |identifier: &Sid, attributes: &mut u32| -> bool {
            let listed = *attributes & SKIPPED_GROUPS == 0 && disable.iter().any(|(entry, _)| entry == identifier);
            let lua = !listed && flags & LUA_TOKEN != 0 && is_elevated(identifier, *attributes);
            elevated |= lua;
            if listed || lua {
                *attributes = (*attributes & !0xF) | DENY_ONLY;
            }
            listed || lua
        };
        let user = token.user.clone();
        if deny(&user, &mut token.user_attributes) {
            groups_filtered.set(true);
        }
        let mut owner_reset = false;
        for group in token.groups.iter_mut() {
            if deny(&group.sid, &mut group.attributes) {
                groups_filtered.set(true);
                owner_reset |= group.sid == token.owner;
            }
        }
        if owner_reset {
            token.owner = token.user.clone();
        }
        // Privilégios.
        let before = token.privileges.len();
        if flags & DISABLE_MAX_PRIVILEGE != 0 {
            token.privileges.retain(|privilege| privilege.id == CHANGE_NOTIFY);
        } else {
            if flags & LUA_TOKEN != 0 {
                let mask = if elevated { LUA_ELEVATED_MASK } else { LUA_MASK };
                token.privileges.retain(|privilege| privilege.id < 64 && (mask >> privilege.id) & 1 != 0);
            }
            for &luid in &delete {
                if (2..=0x24).contains(&luid) {
                    token.privileges.retain(|privilege| privilege.id != luid as u64);
                }
            }
        }
        privileges_filtered.set(token.privileges.len() < before);
    };
    let token = tokens::create(Some(existing), Some(&initialize))?;
    let mut token_flags = source_flags & COPIED_FLAGS;
    if sandbox_inert {
        token_flags |= TOKEN_SANDBOX_INERT;
    }
    if !kept.is_empty() {
        token_flags |= TOKEN_IS_RESTRICTED | TOKEN_IS_FILTERED;
    }
    if flags & WRITE_RESTRICTED != 0 {
        token_flags |= TOKEN_WRITE_RESTRICTED | TOKEN_IS_RESTRICTED;
    }
    if groups_filtered.get() || privileges_filtered.get() {
        token_flags |= TOKEN_IS_FILTERED;
    }
    tokens::body(token).token_flags.set(token_flags);
    filtered.set(token);
    Ok(0)
}
