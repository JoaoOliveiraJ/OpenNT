//! NtAdjustGroupsToken (ntoskrnl 19041, rva 0x5da5f0, com o
//! SepAdjustGroups de rva 0x5da938): liga ou desliga grupos do token, pelo
//! serviço de modo usuário.
//!
//! - Sem ResetToDefault, o NewState é obrigatório (STATUS_INVALID_PARAMETER)
//!   e, de modo usuário, alinhado em 4; o PreviousState é sondado para
//!   escrita com BufferLength e o ReturnLength, como um ULONG. O handle é
//!   referenciado com TOKEN_ADJUST_GROUPS, e TOKEN_QUERY quando há
//!   PreviousState.
//! - Duas passadas sobre o token travado, como no NT: a primeira só conta
//!   as mudanças e o tamanho do PreviousState (o TOKEN_GROUPS das mudanças:
//!   o cabeçalho de 8 bytes, 16 por entrada e os SIDs alinhados em 4), que
//!   vai ao ReturnLength mesmo na recusa; maior que BufferLength, nada muda e
//!   volta STATUS_BUFFER_TOO_SMALL. A segunda muda e grava no PreviousState
//!   os grupos mudados com os atributos de antes e as cópias dos SIDs.
//! - Os grupos do token (sem o usuário) são percorridos em ordem. Com
//!   ResetToDefault, um grupo cujo SE_GROUP_ENABLED difere do
//!   SE_GROUP_ENABLED_BY_DEFAULT volta ao padrão. Sem ele, o grupo achado no
//!   NewState pelo SID muda quando o SE_GROUP_ENABLED pedido difere do
//!   atual: um grupo SE_GROUP_MANDATORY dá STATUS_CANT_DISABLE_MANDATORY e
//!   um SE_GROUP_USE_FOR_DENY_ONLY, STATUS_CANT_ENABLE_DENY_ONLY. Um SID do
//!   NewState que não está no token deixa o resultado
//!   STATUS_NOT_ALL_ASSIGNED.
//! - Uma mudança feita renova o ModifiedId do token.
//!
//! Os tokens do OpenNT guardam o rótulo de integridade fora da lista de
//! grupos, então o SID de integridade no NewState não é achado.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;
use crate::ntos::se::model::{Group, Sid};
use crate::ntos::se::token::tokens::{self, Token};
use crate::rtl::KernelError;

const STATUS_NOT_ALL_ASSIGNED: u32 = 0x0000_0106;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_CANT_DISABLE_MANDATORY: u32 = 0xC000_005D;
const STATUS_INVALID_SID: u32 = 0xC000_0078;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_CANT_ENABLE_DENY_ONLY: u32 = 0xC000_02B3;
const SE_GROUP_MANDATORY: u32 = 0x1;
const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x2;
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
/// O limite do SeCaptureSidAndAttributesArray.
const MAXIMUM_GROUPS: u32 = 0x1000;

/// O resultado de uma passada do SepAdjustGroups.
struct Outcome {
    status: u32,
    /// Os grupos mudados, com os atributos de antes.
    previous: Vec<Group>,
    /// Os bytes dos SIDs mudados, cada um alinhado em 4.
    sid_bytes: u32,
}

fn aligned_sid_length(sid: &Sid) -> u32 {
    (sid.len() as u32 + 3) & !3
}

/// SepAdjustGroups: uma passada; `make_changes` grava os atributos novos.
fn adjust(token: &mut Token, make_changes: bool, reset: bool, requested: &[Group]) -> Outcome {
    let mut outcome = Outcome { status: 0, previous: Vec::new(), sid_bytes: 0 };
    let mut matched = 0u32;
    for group in token.groups.iter_mut() {
        let new_enabled = if reset {
            let state = group.attributes & (SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED);
            if state != SE_GROUP_ENABLED_BY_DEFAULT && state != SE_GROUP_ENABLED {
                continue;
            }
            state == SE_GROUP_ENABLED_BY_DEFAULT
        } else {
            let Some(request) = requested.iter().find(|request| request.sid == group.sid) else { continue };
            matched += 1;
            if (group.attributes ^ request.attributes) & SE_GROUP_ENABLED == 0 {
                continue;
            }
            if group.attributes & SE_GROUP_MANDATORY != 0 {
                return Outcome { status: STATUS_CANT_DISABLE_MANDATORY, ..outcome };
            }
            if group.attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 {
                return Outcome { status: STATUS_CANT_ENABLE_DENY_ONLY, ..outcome };
            }
            request.attributes & SE_GROUP_ENABLED != 0
        };
        outcome.sid_bytes += aligned_sid_length(&group.sid);
        outcome.previous.push(group.clone());
        if make_changes {
            group.attributes = if new_enabled { group.attributes | SE_GROUP_ENABLED } else { group.attributes & !SE_GROUP_ENABLED };
        }
    }
    if !reset && (matched as usize) < requested.len() {
        outcome.status = STATUS_NOT_ALL_ASSIGNED;
    }
    outcome
}

/// O TOKEN_GROUPS de modo usuário (o SeCaptureSidAndAttributesArray):
/// GroupCount, o vetor SID_AND_ATTRIBUTES de +8 e cada SID validado.
fn capture(new_state: u64) -> Result<Vec<Group>, u32> {
    if new_state & 3 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !user_probe::probe_user_read(new_state, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let count = guest::try_read::<u32>(new_state).map_err(|_| STATUS_ACCESS_VIOLATION)?;
    if count > MAXIMUM_GROUPS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let array = new_state + 8;
    if !user_probe::probe_user_read(array, count as u64 * 16) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    (0..count as u64)
        .map(|index| {
            let entry = array + index * 16;
            let sid = guest::try_read::<u64>(entry).map_err(|_| STATUS_ACCESS_VIOLATION)?;
            let attributes = guest::try_read::<u32>(entry + 8).map_err(|_| STATUS_ACCESS_VIOLATION)?;
            if sid == 0 || !user_probe::probe_user_read(sid, 8) {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            let header = guest::try_read_bytes(sid, 8).map_err(|_| STATUS_ACCESS_VIOLATION)?;
            if header[0] != 1 || header[1] > 15 {
                return Err(STATUS_INVALID_SID);
            }
            let length = 8 + header[1] as u64 * 4;
            if !user_probe::probe_user_read(sid, length) {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            Ok(Group { sid: guest::try_read_bytes(sid, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?, attributes })
        })
        .collect()
}

/// NtAdjustGroupsToken de modo usuário sobre o token `token` (resolvido
/// com TOKEN_ADJUST_GROUPS, e TOKEN_QUERY quando há PreviousState).
pub fn adjust_groups(token: u64, reset: bool, new_state: u64, buffer_length: u32, previous_state: u64, return_length: u64) -> Result<u32, KernelError> {
    if !reset && new_state == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if !reset && new_state & 3 != 0 {
        return Ok(STATUS_DATATYPE_MISALIGNMENT);
    }
    // O ProbeForWrite do PreviousState (alinhamento 4) e o ULONG do
    // ReturnLength, só com PreviousState.
    if previous_state != 0 {
        if buffer_length != 0 && previous_state & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_write(previous_state, buffer_length as u64) || return_length == 0 || !user_probe::probe_user_write(return_length, 4) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let requested = if reset {
        Vec::new()
    } else {
        match capture(new_state) {
            Ok(requested) => requested,
            Err(status) => return Ok(status),
        }
    };
    let Some(preview) = tokens::update(token, |record| adjust(record, false, reset, &requested)) else { return Ok(STATUS_INVALID_HANDLE) };
    let needed = 8 + 16 * preview.previous.len() as u32 + preview.sid_bytes;
    if previous_state != 0 {
        guest::try_write::<u32>(return_length, needed)?;
    }
    if preview.status & 0x8000_0000 != 0 {
        return Ok(preview.status);
    }
    if previous_state != 0 && needed > buffer_length {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let Some(outcome) = tokens::update(token, |record| adjust(record, true, reset, &requested)) else { return Ok(STATUS_INVALID_HANDLE) };
    if previous_state != 0 {
        guest::try_write::<u32>(previous_state, outcome.previous.len() as u32)?;
        let mut sid_area = (previous_state + 8 + 16 * outcome.previous.len() as u64 + 3) & !3;
        for (index, group) in outcome.previous.iter().enumerate() {
            let entry = previous_state + 8 + index as u64 * 16;
            guest::try_write::<u64>(entry, sid_area)?;
            guest::try_write::<u32>(entry + 8, group.attributes)?;
            guest::try_write_bytes(sid_area, &group.sid)?;
            sid_area += aligned_sid_length(&group.sid) as u64;
        }
    }
    if !outcome.previous.is_empty() {
        let modified = tokens::allocate_luid();
        tokens::update(token, |record| record.modified_id = modified);
    }
    Ok(outcome.status)
}
