//! SIDs nativos — `system32/ntos/se/sid.js`.
//!
//! Layout: revisão, contagem, seis bytes de autoridade e subautoridades
//! ULONG. A aritmética de ponteiros preserva os endereços canônicos de kernel.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;

const MAXIMUM_SUB_AUTHORITIES: u8 = 15;

/// Oito bytes de cabeçalho mais quatro por subautoridade (RtlLengthSid).
pub fn length(pointer: u64) -> u32 {
    8 + guest::read8(pointer.wrapping_add(1)) as u32 * 4
}

/// RtlValidSid do kernel: endereços de usuário são rejeitados antes da
/// leitura; o ULONG final não é sondado.
pub fn valid(pointer: u64) -> bool {
    if pointer <= 0x7FFF_FFFF_0000 {
        return false;
    }
    guest::read8(pointer) & 15 == 1 && guest::read8(pointer.wrapping_add(1)) <= MAXIMUM_SUB_AUTHORITIES
}

/// RtlEqualSid: revisão e contagem, depois autoridade e subautoridades.
pub fn equal(first: u64, second: u64) -> bool {
    if guest::read8(first) != guest::read8(second) || guest::read8(first.wrapping_add(1)) != guest::read8(second.wrapping_add(1)) {
        return false;
    }
    (2..length(first) as u64).all(|offset| guest::read8(first.wrapping_add(offset)) == guest::read8(second.wrapping_add(offset)))
}

/// RtlCopySid: usa a contagem da origem sem validar; a cópia temporária
/// preserva o resultado nativo com faixas sobrepostas.
pub fn copy(capacity: u32, destination: u64, source: u64) -> u32 {
    let count = length(source);
    if capacity < count {
        return 0xC000_0023;
    }
    let bytes: Vec<u8> = (0..count as u64).map(|offset| guest::read8(source.wrapping_add(offset))).collect();
    for (offset, &byte) in bytes.iter().enumerate() {
        guest::write8(destination.wrapping_add(offset as u64), byte);
    }
    0
}

/// RtlInitializeSidEx: a contagem é um UCHAR; só o byte baixo é validado.
pub fn initialize_ex(pointer: u64, authority: u64, sub_authority_count: u32, sub_authorities: &[u32]) -> u32 {
    let count = (sub_authority_count & 255) as u8;
    if count > MAXIMUM_SUB_AUTHORITIES {
        return 0xC000_000D;
    }
    guest::write8(pointer.wrapping_add(1), count);
    guest::write8(pointer, 1);
    guest::write32(pointer.wrapping_add(2), guest::read32(authority));
    guest::write16(pointer.wrapping_add(6), guest::read16(authority.wrapping_add(4)));
    for index in 0..count as usize {
        guest::write32(pointer.wrapping_add(8 + index as u64 * 4), sub_authorities.get(index).copied().unwrap_or(0));
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
    guest::write8(pointer.wrapping_add(1), count as u8);
    guest::write8(pointer, 1);
    guest::write32(pointer.wrapping_add(2), guest::read32(authority));
    guest::write16(pointer.wrapping_add(6), guest::read16(authority.wrapping_add(4)));
    0
}

/// RtlSubAuthoritySid: ponteiro para a subautoridade de índice `index` (sem
/// verificação de limite, como o NT).
pub fn sub_authority(pointer: u64, index: u64) -> u64 {
    pointer.wrapping_add(8 + index * 4)
}

/// RtlLengthRequiredSid: bytes para um SID com `count` subautoridades.
pub fn length_required(count: u32) -> u32 {
    if count > 0x3FFF_FFF7 {
        return 0xFFFF_FFFF;
    }
    8 + count * 4
}
