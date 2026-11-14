//! NtAdjustPrivilegesToken: liga, desliga ou remove privilégios do token.
//!
//! O SepAdjustPrivileges do NT sobre o registro vivo do token (`tokens::
//! update`, que republica o corpo nativo com os bits Present/Enabled):
//!
//! - DisableAllPrivileges desliga todos os ligados e ignora NewState;
//! - senão, cada LUID_AND_ATTRIBUTES de NewState muda o privilégio de mesmo
//!   LUID: SE_PRIVILEGE_REMOVED o tira do token, SE_PRIVILEGE_ENABLED o liga
//!   e a falta dele o desliga; um LUID que o token não tem não muda nada e
//!   a chamada termina com STATUS_NOT_ALL_ASSIGNED;
//! - PreviousState recebe o estado anterior de cada privilégio que mudou;
//!   pequeno demais, nada muda e volta STATUS_BUFFER_TOO_SMALL com o tamanho
//!   em ReturnLength.
//!
//! Os buffers são do chamador de modo usuário (sondados e lidos por campos
//! do TOKEN_PRIVILEGES); o handle já foi resolvido pelo adaptador.

use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::types::{LuidAndAttributes, NtStruct, TokenPrivileges};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

const STATUS_SUCCESS: u32 = 0;
const STATUS_NOT_ALL_ASSIGNED: u32 = 0x0000_0106;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const SE_PRIVILEGE_ENABLED: u32 = 0x2;
const SE_PRIVILEGE_REMOVED: u32 = 0x4;
/// O maior número de privilégios que um NewState pode trazer (os 36 LUIDs
/// conhecidos, com folga): mais que isso é um pedido malformado.
const MAXIMUM_PRIVILEGES: u32 = 0x400;

/// O TOKEN_PRIVILEGES de entrada: (LUID, atributos) de cada elemento.
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

/// O que mudaria em `privileges`: (LUID, atributos anteriores, atributos
/// novos ou `None` para remover), e se algum pedido ficou sem privilégio.
fn plan(privileges: &[crate::ntos::se::model::Privilege], disable_all: bool, requested: &[(u64, u32)]) -> (Vec<(u64, u32, Option<u32>)>, bool) {
    if disable_all {
        let changes = privileges.iter().filter(|held| held.attributes & SE_PRIVILEGE_ENABLED != 0).map(|held| (held.id, held.attributes, Some(held.attributes & !SE_PRIVILEGE_ENABLED))).collect();
        return (changes, false);
    }
    let mut changes: Vec<(u64, u32, Option<u32>)> = Vec::new();
    let mut missing = false;
    for &(id, attributes) in requested {
        let Some(held) = privileges.iter().find(|held| held.id == id) else {
            missing = true;
            continue;
        };
        let new = if attributes & SE_PRIVILEGE_REMOVED != 0 {
            None
        } else if attributes & SE_PRIVILEGE_ENABLED != 0 {
            Some(held.attributes | SE_PRIVILEGE_ENABLED)
        } else {
            Some(held.attributes & !SE_PRIVILEGE_ENABLED)
        };
        if new != Some(held.attributes) && !changes.iter().any(|(changed, _, _)| *changed == id) {
            changes.push((id, held.attributes, new));
        }
    }
    (changes, missing)
}

/// O PreviousState: os privilégios que mudaram, com os atributos de antes.
fn write_previous(previous_state: u64, changes: &[(u64, u32, Option<u32>)]) -> Result<(), KernelError> {
    guest::try_write::<u32>(previous_state + offset_of!(TokenPrivileges, privilege_count) as u64, changes.len() as u32)?;
    let array = previous_state + offset_of!(TokenPrivileges, privileges) as u64;
    for (index, (id, before, _)) in changes.iter().enumerate() {
        let at = array + index as u64 * LuidAndAttributes::SIZE;
        guest::try_write::<u32>(at + offset_of!(LuidAndAttributes, luid) as u64, *id as u32)?;
        guest::try_write::<u32>(at + offset_of!(LuidAndAttributes, luid) as u64 + 4, (*id >> 32) as u32)?;
        guest::try_write::<u32>(at + offset_of!(LuidAndAttributes, attributes) as u64, *before)?;
    }
    Ok(())
}

/// NtAdjustPrivilegesToken sobre o token `token` (resolvido com
/// TOKEN_ADJUST_PRIVILEGES, e TOKEN_QUERY quando há PreviousState).
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
    let Some(privileges) = tokens::with(token, |record| record.privileges.clone()) else { return Ok(0xC000_0008) };
    let (changes, missing) = plan(&privileges, disable_all, &requested);
    let required = (offset_of!(TokenPrivileges, privileges) as u64 + changes.len() as u64 * LuidAndAttributes::SIZE) as u32;
    if return_length != 0 {
        guest::try_write::<u32>(return_length, required)?;
    }
    if previous_state != 0 {
        if buffer_length < required {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        write_previous(previous_state, &changes)?;
    }
    tokens::update(token, |record| {
        for (id, _, new) in &changes {
            match new {
                Some(attributes) => {
                    if let Some(held) = record.privileges.iter_mut().find(|held| held.id == *id) {
                        held.attributes = *attributes;
                    }
                }
                None => record.privileges.retain(|held| held.id != *id),
            }
        }
    });
    Ok(if missing { STATUS_NOT_ALL_ASSIGNED } else { STATUS_SUCCESS })
}
