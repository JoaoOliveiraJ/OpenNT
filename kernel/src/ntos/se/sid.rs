//! SIDs nativos.
//!
//! Layout `_SID`: revisão, contagem, seis bytes de autoridade e
//! subautoridades ULONG. A aritmética de ponteiros preserva os endereços
//! canônicos de kernel.

use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::types::{Field, NtStruct, Sid, SidIdentifierAuthority};
use crate::ntos::mm::guest_memory as guest;

const MAXIMUM_SUB_AUTHORITIES: u8 = 15;

/// O SID no endereço (o PSID do NT).
pub(crate) fn at(pointer: u64) -> &'static Sid {
    // SAFETY: as rotinas Rtl*Sid recebem um PSID vivo, como no NT.
    unsafe { Sid::at(pointer) }
}

/// SubAuthority[0..count]: o vetor do NT é declarado com um elemento.
pub(crate) fn sub_authorities(sid: &Sid, count: usize) -> &'static [Field<u32>] {
    // SAFETY: o SID ocupa 8 + 4 * count bytes a partir do seu endereço.
    unsafe { Field::<u32>::array_at(sid.sub_authority[0].address(), count) }
}

/// Grava os seis bytes de IdentifierAuthority a partir de um
/// PSID_IDENTIFIER_AUTHORITY.
fn copy_authority(sid: &Sid, authority: u64) {
    // SAFETY: o chamador passa um SID_IDENTIFIER_AUTHORITY vivo (alinhamento 1).
    let authority = unsafe { SidIdentifierAuthority::at(authority) };
    for (target, source) in sid.identifier_authority.value.iter().zip(&authority.value) {
        target.set(source.get());
    }
}

/// Oito bytes de cabeçalho mais quatro por subautoridade (RtlLengthSid).
pub fn length(pointer: u64) -> u32 {
    8 + at(pointer).sub_authority_count.get() as u32 * 4
}

/// RtlValidSid do kernel: endereços de usuário são rejeitados antes da
/// leitura; o ULONG final não é sondado.
pub fn valid(pointer: u64) -> bool {
    if pointer <= crate::ntos::mm::memory_map::USER_PROBE_ADDRESS {
        return false;
    }
    let sid = at(pointer);
    sid.revision.get() & 15 == 1 && sid.sub_authority_count.get() <= MAXIMUM_SUB_AUTHORITIES
}

/// RtlEqualSid: revisão e contagem, depois autoridade e subautoridades.
pub fn equal(first: u64, second: u64) -> bool {
    let (left, right) = (at(first), at(second));
    if left.revision.get() != right.revision.get() || left.sub_authority_count.get() != right.sub_authority_count.get() {
        return false;
    }
    let length = length(first) as usize;
    guest::read_bytes(first.wrapping_add(2), length - 2) == guest::read_bytes(second.wrapping_add(2), length - 2)
}

/// RtlCopySid: usa a contagem da origem sem validar; a cópia temporária
/// preserva o resultado nativo com faixas sobrepostas.
pub fn copy(capacity: u32, destination: u64, source: u64) -> u32 {
    let count = length(source);
    if capacity < count {
        return 0xC000_0023;
    }
    guest::write_bytes(destination, &guest::read_bytes(source, count as usize));
    0
}

/// RtlInitializeSidEx: a contagem é um UCHAR; só o byte baixo é validado.
pub fn initialize_ex(pointer: u64, authority: u64, sub_authority_count: u32, sub_authorities_values: &[u32]) -> u32 {
    let count = (sub_authority_count & 255) as u8;
    if count > MAXIMUM_SUB_AUTHORITIES {
        return 0xC000_000D;
    }
    let sid = at(pointer);
    sid.sub_authority_count.set(count);
    sid.revision.set(1);
    copy_authority(sid, authority);
    for (index, cell) in sub_authorities(sid, count as usize).iter().enumerate() {
        cell.set(sub_authorities_values.get(index).copied().unwrap_or(0));
    }
    0
}

/// Bytes do SID no convidado.
pub fn read(pointer: u64) -> Vec<u8> {
    guest::read_bytes(pointer, length(pointer) as usize)
}

// ---- RtlInitializeSid / RtlSubAuthoritySid / RtlLengthRequiredSid ----------

/// RtlInitializeSid: grava só o cabeçalho de 8 bytes (não toca nas
/// subautoridades, como o NT).
pub fn initialize(pointer: u64, authority: u64, count: u32) -> u32 {
    if count > MAXIMUM_SUB_AUTHORITIES as u32 {
        return 0xC000_000D;
    }
    let sid = at(pointer);
    sid.sub_authority_count.set(count as u8);
    sid.revision.set(1);
    copy_authority(sid, authority);
    0
}

/// RtlSubAuthoritySid: ponteiro para a subautoridade de índice `index` (sem
/// verificação de limite nem leitura, como o NT).
pub fn sub_authority(pointer: u64, index: u64) -> u64 {
    pointer.wrapping_add(offset_of!(Sid, sub_authority) as u64 + index * 4)
}

/// RtlLengthRequiredSid: bytes para um SID com `count` subautoridades.
pub fn length_required(count: u32) -> u32 {
    if count > 0x3FFF_FFF7 {
        return 0xFFFF_FFFF;
    }
    8 + count * 4
}
