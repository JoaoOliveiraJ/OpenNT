//! NtAdjustPrivilegesToken: liga, desliga ou remove privilégios do token,
//! pelo serviço de modo usuário e pelo ZwAdjustPrivilegesToken (KernelMode).
//!
//! Como no NT, o pedido passa duas vezes pelo SepAdjustPrivileges com o
//! registro do token travado (`tokens::update`): a primeira só conta as
//! mudanças e o tamanho do PreviousState; a segunda muda. Cada LUID do
//! NewState vale pelo bit `1 << LowPart` (LowPart módulo 64) nos privilégios
//! presentes; um ausente não conta e faz o resultado STATUS_NOT_ALL_ASSIGNED.
//! Habilitar um privilégio desabilitado e desabilitar um habilitado são
//! mudanças (o estado anterior vai ao PreviousState); SE_PRIVILEGE_REMOVED
//! tira o privilégio do token e marca TokenFlags. Um token abaixo de High só
//! habilita parte deles: em Medium, nenhum de MEDIUM_DENIED; abaixo de
//! Medium, só os de LOW_ALLOWED (LOWBOX_ALLOWED para AppContainer); um
//! recusado conta como mudança mas deixa o resultado STATUS_NOT_ALL_ASSIGNED.
//! DisableAllPrivileges desabilita todos os habilitados de LUID 0 a 36 e
//! ignora o NewState. O ReturnLength (com PreviousState) é o tamanho do
//! TOKEN_PRIVILEGES das mudanças, no mínimo uma entrada; pequeno demais,
//! nada muda e volta STATUS_BUFFER_TOO_SMALL. Uma mudança feita renova o
//! ModifiedId do token.
//!
//! No modo usuário os buffers são sondados e o NewState capturado por
//! campos; no ZwAdjustPrivilegesToken são do chamador de kernel e o handle é
//! referenciado aqui.

use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::Ordering;

use crate::ntos::inc::types::{LuidAndAttributes, NtStruct, TokenPrivileges};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;
use crate::ntos::se::token::reference;
use crate::ntos::se::token::tokens::{self, Token};
use crate::rtl::KernelError;

const TOKEN_QUERY: u32 = 0x8;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x20;
const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x1;
const SE_PRIVILEGE_ENABLED: u32 = 0x2;
const SE_PRIVILEGE_REMOVED: u32 = 0x4;
/// TokenFlags: privilégios retirados do token / token de AppContainer.
const TOKEN_PRIVILEGES_REMOVED: u32 = 0x800;
const TOKEN_LOWBOX: u32 = 0x4000;
/// Privilégios que um token Medium não habilita (LUIDs 2, 7, 9, 10, 17, 18,
/// 20, 29, 32 e 36).
const MEDIUM_DENIED: u64 = 0x11_2016_0684;
/// Os únicos que um token abaixo de Medium habilita (LUIDs 23, 25 e 33) e,
/// num AppContainer, 23 e 33.
const LOW_ALLOWED: u64 = 0x2_0280_0000;
const LOWBOX_ALLOWED: u64 = 0x2_0080_0000;
/// O maior LUID que o DisableAllPrivileges percorre.
const LAST_PRIVILEGE: u64 = 36;
const MEDIUM_RID: u32 = 0x2000;
const HIGH_RID: u32 = 0x3000;
const STATUS_NOT_ALL_ASSIGNED: u32 = 0x106;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
/// O maior número de privilégios que um NewState pode trazer (os 36 LUIDs
/// conhecidos, com folga): mais que isso é um pedido malformado.
const MAXIMUM_PRIVILEGES: u32 = 0x400;

/// O que uma passada do SepAdjustPrivileges produz.
struct Outcome {
    status: u32,
    /// Entradas do PreviousState (LUID e atributos anteriores), na ordem.
    previous: Vec<(u64, u32)>,
    changes: u32,
    removed: bool,
}

/// RID do rótulo de integridade (S-1-16-RID); sem rótulo, Untrusted (0).
fn integrity_rid(token: &Token) -> u32 {
    let sid = &token.integrity;
    if sid.len() >= 12 && sid[1] >= 1 && sid[2..8] == [0, 0, 0, 0, 0, 16] {
        let at = 8 + (sid[1] as usize - 1) * 4;
        return sid.get(at..at + 4).map_or(0, |rid| u32::from_le_bytes([rid[0], rid[1], rid[2], rid[3]]));
    }
    0
}

/// Os atributos correntes de um LUID do token (ENABLED e ENABLED_BY_DEFAULT),
/// ou None quando ele não está presente.
fn current(token: &Token, bit: u64) -> Option<u32> {
    token.privileges.iter().find(|privilege| privilege.id == bit).map(|privilege| privilege.attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT))
}

fn set_enabled(token: &mut Token, bit: u64, enabled: bool) {
    if let Some(privilege) = token.privileges.iter_mut().find(|privilege| privilege.id == bit) {
        privilege.attributes = if enabled { privilege.attributes | SE_PRIVILEGE_ENABLED } else { privilege.attributes & !SE_PRIVILEGE_ENABLED };
    }
}

/// SepAdjustPrivileges(Token, MakeChanges, DisableAll, NewState...).
fn adjust(token: &mut Token, token_flags: u32, make_changes: bool, disable_all: bool, requests: &[(u64, u32)]) -> Outcome {
    let rid = integrity_rid(token);
    let (high, medium) = (rid >= HIGH_RID, rid >= MEDIUM_RID);
    let mut outcome = Outcome { status: 0, previous: Vec::new(), changes: 0, removed: false };
    if disable_all {
        for bit in 0..=LAST_PRIVILEGE {
            let Some(attributes) = current(token, bit).filter(|attributes| attributes & SE_PRIVILEGE_ENABLED != 0) else { continue };
            if make_changes {
                outcome.previous.push((bit, attributes));
                set_enabled(token, bit, false);
            }
            outcome.changes += 1;
        }
        return outcome;
    }
    let (mut found, mut refused) = (0usize, 0u32);
    for &(luid, wanted) in requests {
        let bit = luid as u32 as u64 & 63;
        let Some(attributes) = current(token, bit) else { continue };
        found += 1;
        let enabled = attributes & SE_PRIVILEGE_ENABLED != 0;
        if wanted & SE_PRIVILEGE_REMOVED != 0 {
            if make_changes {
                token.privileges.retain(|privilege| privilege.id != bit);
                outcome.removed = true;
            }
        } else if wanted & SE_PRIVILEGE_ENABLED != 0 {
            if enabled {
                continue;
            }
            if make_changes {
                outcome.previous.push((luid, attributes));
                let allowed = high
                    || if medium {
                        MEDIUM_DENIED & 1 << bit == 0
                    } else {
                        (if token_flags & TOKEN_LOWBOX != 0 { LOWBOX_ALLOWED } else { LOW_ALLOWED }) & 1 << bit != 0
                    };
                if allowed {
                    set_enabled(token, bit, true);
                } else {
                    refused += 1;
                }
            }
            outcome.changes += 1;
        } else if enabled {
            if make_changes {
                outcome.previous.push((luid, attributes));
                set_enabled(token, bit, false);
            }
            outcome.changes += 1;
        }
    }
    if found < requests.len() || refused > 0 {
        outcome.status = STATUS_NOT_ALL_ASSIGNED;
    }
    outcome
}

/// Bytes do TOKEN_PRIVILEGES com `count` entradas (no mínimo uma).
fn previous_state_length(count: u32) -> u32 {
    if count > 1 { 4 + 12 * count } else { 16 }
}

/// As duas passadas sobre o token referenciado, com os ponteiros de saída
/// já validados para o modo do chamador.
fn adjust_token(token: u64, disable_all: bool, requests: &[(u64, u32)], buffer_length: u32, previous_state: u64, return_length: u64) -> Result<u32, KernelError> {
    let flags = &tokens::body(token).token_flags;
    let Some(preview) = tokens::update(token, |record| adjust(record, flags.get(), false, disable_all, requests)) else { return Ok(STATUS_INVALID_HANDLE) };
    if previous_state != 0 {
        let needed = previous_state_length(preview.changes);
        if return_length != 0 {
            guest::try_write::<u32>(return_length, needed)?;
        }
        if needed > buffer_length {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
    }
    let Some(outcome) = tokens::update(token, |record| adjust(record, flags.get(), true, disable_all, requests)) else { return Ok(STATUS_INVALID_HANDLE) };
    if outcome.removed {
        flags.atomic().fetch_or(TOKEN_PRIVILEGES_REMOVED, Ordering::SeqCst);
    }
    if previous_state != 0 {
        guest::try_write::<u32>(previous_state + offset_of!(TokenPrivileges, privilege_count) as u64, outcome.changes)?;
        let array = previous_state + offset_of!(TokenPrivileges, privileges) as u64;
        let entries: Vec<(u64, u32)> = if outcome.previous.is_empty() { alloc::vec![(0, 0)] } else { outcome.previous };
        for (index, (luid, attributes)) in entries.iter().enumerate() {
            let at = array + index as u64 * LuidAndAttributes::SIZE;
            guest::try_write::<u32>(at + offset_of!(LuidAndAttributes, luid) as u64, *luid as u32)?;
            guest::try_write::<u32>(at + offset_of!(LuidAndAttributes, luid) as u64 + 4, (*luid >> 32) as u32)?;
            guest::try_write::<u32>(at + offset_of!(LuidAndAttributes, attributes) as u64, *attributes)?;
        }
    }
    if outcome.changes > 0 {
        let modified = tokens::allocate_luid();
        tokens::update(token, |record| record.modified_id = modified);
    }
    Ok(outcome.status)
}

/// O TOKEN_PRIVILEGES de entrada de modo usuário: (LUID, atributos) de cada
/// elemento, sondado e lido por campos.
fn capture(new_state: u64) -> Result<Vec<(u64, u32)>, u32> {
    let count_offset = offset_of!(TokenPrivileges, privilege_count) as u64;
    if !user_probe::probe_user_read(new_state + count_offset, 4) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let count = guest::try_read::<u32>(new_state + count_offset).map_err(|error| error.status)?;
    if count > MAXIMUM_PRIVILEGES {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let array = new_state + offset_of!(TokenPrivileges, privileges) as u64;
    if !user_probe::probe_user_read(array, count as u64 * LuidAndAttributes::SIZE) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    (0..count as u64)
        .map(|index| {
            let at = array + index * LuidAndAttributes::SIZE;
            let low = guest::try_read::<u32>(at + offset_of!(LuidAndAttributes, luid) as u64)?;
            let high = guest::try_read::<u32>(at + offset_of!(LuidAndAttributes, luid) as u64 + 4)?;
            let attributes = guest::try_read::<u32>(at + offset_of!(LuidAndAttributes, attributes) as u64)?;
            Ok((low as u64 | (high as u64) << 32, attributes))
        })
        .collect::<Result<Vec<_>, KernelError>>()
        .map_err(|error| error.status)
}

/// NtAdjustPrivilegesToken de modo usuário sobre o token `token` (resolvido
/// com TOKEN_ADJUST_PRIVILEGES, e TOKEN_QUERY quando há PreviousState).
pub fn adjust_privileges(token: u64, disable_all: bool, new_state: u64, buffer_length: u32, previous_state: u64, return_length: u64) -> Result<u32, KernelError> {
    if !disable_all && new_state == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if (previous_state != 0 && !user_probe::probe_user_write(previous_state, buffer_length as u64)) || (return_length != 0 && !user_probe::probe_user_write(return_length, 4)) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let requested = if disable_all {
        Vec::new()
    } else {
        match capture(new_state) {
            Ok(requested) => requested,
            Err(status) => return Ok(status),
        }
    };
    adjust_token(token, disable_all, &requested, buffer_length, previous_state, return_length)
}

/// NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState,
/// BufferLength, PreviousState, ReturnLength) com PreviousMode KernelMode
/// (o ZwAdjustPrivilegesToken): os ponteiros são do chamador de kernel.
pub fn adjust_privileges_token(handle: u64, disable_all: bool, new_state: u64, buffer_length: u32, previous_state: u64, return_length: u64) -> Result<u32, KernelError> {
    if !disable_all && new_state == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let requests: Vec<(u64, u32)> = if disable_all {
        Vec::new()
    } else {
        // SAFETY: o TOKEN_PRIVILEGES do chamador de kernel e as PrivilegeCount entradas dele.
        let state = unsafe { TokenPrivileges::at(new_state) };
        let entries = unsafe { LuidAndAttributes::array_at(state.privileges[0].address(), state.privilege_count.get() as usize) };
        entries.iter().map(|entry| (tokens::luid_value(&entry.luid), entry.attributes.get())).collect()
    };
    let access = TOKEN_ADJUST_PRIVILEGES | if previous_state != 0 { TOKEN_QUERY } else { 0 };
    let mut referenced = match reference::reference(handle, access, 0, false)? {
        Ok(referenced) => referenced,
        Err(status) => return Ok(status),
    };
    let result = adjust_token(referenced.token, disable_all, &requests, buffer_length, previous_state, return_length);
    referenced.release()?;
    result
}
