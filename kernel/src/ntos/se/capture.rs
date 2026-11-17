//! Captura dos vetores SID_AND_ATTRIBUTES e LUID_AND_ATTRIBUTES que os
//! serviços de token recebem (ntoskrnl 19041: SeCaptureSidAndAttributesArray
//! 0x5dd560 e SeCaptureLuidAndAttributesArray 0x6089bc).
//!
//! - SeCaptureSidAndAttributesArray: zero entradas é um vetor vazio; mais
//!   de 0x1000 é STATUS_INVALID_PARAMETER. De UserMode o vetor é alinhado a 4
//!   (STATUS_DATATYPE_MISALIGNMENT) e sondado; a primeira passada lê o
//!   SubAuthorityCount de cada SID (acima de 15 é STATUS_INVALID_SID) e sonda
//!   o SID (alinhado a 4) nesse tamanho. A cópia relê o vetor (os
//!   Attributes) e copia cada SID no tamanho da primeira passada; Attributes
//!   com bits em 0x1FFFFF80 são STATUS_INVALID_PARAMETER e um SID que o
//!   RtlValidSid recusa, ou cujo tamanho mudou, é STATUS_INVALID_SID. De
//!   KernelMode nada é sondado nem validado.
//! - SeCaptureLuidAndAttributesArray: zero entradas é um vetor vazio; mais
//!   de 0x42 é STATUS_INVALID_PARAMETER; de UserMode o vetor é alinhado a 4 e
//!   sondado.
//!
//! Uma falha de leitura no meio (a página some entre a sonda e a cópia) é
//! STATUS_ACCESS_VIOLATION, como o `__except` do NT.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;
use crate::ntos::se::model::{Group, Privilege};

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_SID: u32 = 0xC000_0078;

/// O limite de entradas do SeCaptureSidAndAttributesArray.
const MAXIMUM_SIDS: u32 = 0x1000;
/// O limite de entradas do SeCaptureLuidAndAttributesArray.
const MAXIMUM_LUIDS: u32 = 0x42;
/// Bits de Attributes que nenhum SE_GROUP_* usa.
const INVALID_GROUP_ATTRIBUTES: u32 = 0x1FFF_FF80;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;
/// SID_AND_ATTRIBUTES e LUID_AND_ATTRIBUTES.
const SID_AND_ATTRIBUTES_SIZE: u64 = 16;
const LUID_AND_ATTRIBUTES_SIZE: u64 = 12;

fn read<T: guest::GuestScalar>(address: u64) -> Result<T, u32> {
    guest::try_read::<T>(address).map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// SeCaptureSidAndAttributesArray(Array, Count, RequestorMode, ...): os
/// `count` SID_AND_ATTRIBUTES de `array`, copiados.
pub fn sid_and_attributes_array(array: u64, count: u32, mode: u8) -> Result<Vec<Group>, u32> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > MAXIMUM_SIDS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let user = mode != 0;
    let entry = |index: u32| array + index as u64 * SID_AND_ATTRIBUTES_SIZE;
    if user {
        if array & 3 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_read(array, count as u64 * SID_AND_ATTRIBUTES_SIZE) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    // Primeira passada: o ponteiro e o tamanho de cada SID.
    let mut sids = Vec::with_capacity(count as usize);
    for index in 0..count {
        let sid = read::<u64>(entry(index))?;
        if user && !user_probe::probe_user_read(sid + 1, 1) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let sub_authorities = read::<u8>(sid + 1)?;
        if user && sub_authorities > SID_MAX_SUB_AUTHORITIES {
            return Err(STATUS_INVALID_SID);
        }
        let length = 8 + sub_authorities as usize * 4;
        if user {
            if sid & 3 != 0 {
                return Err(STATUS_DATATYPE_MISALIGNMENT);
            }
            if !user_probe::probe_user_read(sid, length as u64) {
                return Err(STATUS_ACCESS_VIOLATION);
            }
        }
        sids.push((sid, length));
    }
    // Cópia: os Attributes relidos do vetor e os SIDs nos tamanhos medidos.
    let mut captured = Vec::with_capacity(count as usize);
    for (index, &(sid, length)) in sids.iter().enumerate() {
        let attributes = read::<u32>(entry(index as u32) + 8)?;
        let bytes = guest::try_read_bytes(sid, length).map_err(|_| STATUS_ACCESS_VIOLATION)?;
        if user {
            if attributes & INVALID_GROUP_ATTRIBUTES != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            // RtlValidSid e RtlLengthSid sobre a cópia.
            if bytes[0] != 1 || bytes[1] > SID_MAX_SUB_AUTHORITIES || 8 + bytes[1] as usize * 4 != length {
                return Err(STATUS_INVALID_SID);
            }
        }
        captured.push(Group { sid: bytes, attributes });
    }
    Ok(captured)
}

/// SeCaptureLuidAndAttributesArray(Array, Count, RequestorMode, ...): os
/// `count` LUID_AND_ATTRIBUTES de `array`.
pub fn luid_and_attributes_array(array: u64, count: u32, mode: u8) -> Result<Vec<Privilege>, u32> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > MAXIMUM_LUIDS {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if mode != 0 {
        if array & 3 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_read(array, count as u64 * LUID_AND_ATTRIBUTES_SIZE) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    (0..count as u64)
        .map(|index| {
            let entry = array + index * LUID_AND_ATTRIBUTES_SIZE;
            let low = read::<u32>(entry)?;
            let high = read::<u32>(entry + 4)?;
            Ok(Privilege { id: low as u64 | (high as u64) << 32, attributes: read::<u32>(entry + 8)? })
        })
        .collect()
}
