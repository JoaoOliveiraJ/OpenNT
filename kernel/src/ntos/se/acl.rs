//! Validação estrutural de ACLs e ACEs (RtlValidAcl).
//!
//! A decisão de acesso pertence a outro provedor; tipos desconhecidos de
//! entrada passam só pela verificação mínima do cabeçalho do kernel original.

use crate::ntos::mm::guest_memory as guest;

/// Revisão 1 e até 15 subautoridades; zero = SID inválido.
fn sid_length(pointer: u64) -> i64 {
    let count = guest::read8(pointer + 1);
    if guest::read8(pointer) == 1 && count <= 15 { 8 + count as i64 * 4 } else { 0 }
}

/// Terminador UTF-16 completo dentro da capacidade em bytes.
fn has_wide_terminator(pointer: u64, available: i64) -> bool {
    let mut offset = 0;
    while offset + 1 < available {
        if guest::read16(pointer + offset as u64) == 0 {
            return true;
        }
        offset += 2;
    }
    false
}

/// Atributo de claim relativo à sua base: nome, tabela de deslocamentos e
/// valores, sem ler além de `length`.
fn valid_claim_attribute(claim: u64, length: i64) -> bool {
    if length < 20 || guest::read16(claim + 6) != 0 || guest::read32(claim + 8) & 0xFFC0 != 0 {
        return false;
    }
    let name = guest::read32(claim) as i64;
    let count = guest::read32(claim + 12) as i64;
    let value_type = guest::read16(claim + 4);
    if count == 0 || name > length - 4 || !has_wide_terminator(claim + name as u64, length - name) || count > (length - 16) / 4 || ![1, 2, 3, 5, 6, 16].contains(&value_type) {
        return false;
    }
    for index in 0..count {
        let offset = guest::read32(claim + 16 + index as u64 * 4) as i64;
        let remaining = length - offset;
        if remaining < 0 {
            return false;
        }
        let value = claim + offset as u64;
        match value_type {
            // Inteiros e booleanos ocupam oito bytes; booleanos só 0 ou 1.
            1 | 2 | 6 => {
                if remaining < 8 || (value_type == 6 && guest::read64(value) > 1) {
                    return false;
                }
            }
            3 => {
                if remaining < 2 || !has_wide_terminator(value, remaining) {
                    return false;
                }
            }
            _ => {
                if remaining < 4 {
                    return false;
                }
                let size = guest::read32(value) as i64;
                if (value_type == 5 && size == 0) || size > remaining - 4 {
                    return false;
                }
            }
        }
    }
    true
}

/// Valida a entrada pelo tipo e pela revisão da ACL que a contém.
fn valid_ace(entry: u64, length: i64, revision: u8) -> bool {
    let ace_type = guest::read8(entry);
    // Entradas cujo SID começa diretamente em +8.
    if ace_type <= 20 && (0x1A_660Fu32 >> ace_type) & 1 != 0 {
        if length & 3 != 0 || length < 16 {
            return false;
        }
        let sid = sid_length(entry + 8);
        return sid != 0 && length >= 8 + sid;
    }
    if ace_type == 4 {
        if revision < 3 || length & 3 != 0 || length < 24 || guest::read16(entry + 8) != 1 {
            return false;
        }
        // Entrada composta: dois SIDs consecutivos a partir de +12.
        let first = sid_length(entry + 12);
        if first == 0 || length < first + 24 {
            return false;
        }
        let second = sid_length(entry + 12 + first as u64);
        return second != 0 && length >= 12 + first + second;
    }
    if (5..=8).contains(&ace_type) || matches!(ace_type, 11 | 12 | 15 | 16) {
        if revision < 4 || length & 3 != 0 || length < 12 {
            return false;
        }
        let flags = guest::read32(entry + 8);
        // GUIDs opcionais de 16 bytes antes do SID.
        let guids = (if flags & 1 != 0 { 16 } else { 0 }) + (if flags & 2 != 0 { 16 } else { 0 });
        if length < 24 + guids {
            return false;
        }
        let sid = sid_length(entry + 12 + guids as u64);
        return sid != 0 && length >= 12 + guids + sid;
    }
    if ace_type == 18 || ace_type == 21 {
        if length & 3 != 0 || length < 16 {
            return false;
        }
        let sid = sid_length(entry + 8);
        if sid == 0 {
            return false;
        }
        let offset = sid + 8;
        let remaining = length - offset;
        if ace_type == 21 {
            return remaining >= 6 && guest::read32(entry + offset as u64) == 0x7874_7261;
        }
        return remaining >= 20 && valid_claim_attribute(entry + offset as u64, remaining);
    }
    length >= 4
}

/// RtlValidAcl: percorre as entradas declaradas sem modificar memória.
pub fn valid(pointer: u64) -> bool {
    let revision = guest::read8(pointer);
    if !(2..=4).contains(&revision) || pointer & 1 != 0 {
        return false;
    }
    let length = guest::read16(pointer + 2) as i64;
    let count = guest::read16(pointer + 4);
    if length < 8 {
        return false;
    }
    let mut offset: i64 = 8;
    for _ in 0..count {
        // Pelo menos um byte além do cabeçalho da ACE.
        if offset + 4 >= length || offset & 1 != 0 {
            return false;
        }
        let current = pointer + offset as u64;
        let entry_length = guest::read16(current + 2) as i64;
        if entry_length > length - offset || !valid_ace(current, entry_length, revision) {
            return false;
        }
        offset += entry_length;
    }
    true
}

// ---- construção (RtlCreateAcl / RtlAddAccessAllowedAce[Ex]) -----------------

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_REVISION_MISMATCH: u32 = 0xC000_0059;
const STATUS_INVALID_ACL: u32 = 0xC000_0077;
const STATUS_INVALID_SID: u32 = 0xC000_0078;
const STATUS_ALLOTTED_SPACE_EXCEEDED: u32 = 0xC000_0099;

/// RtlCreateAcl: zera o buffer e grava o cabeçalho ACL vazio.
pub fn create(acl: u64, length: u32, revision: u32) -> u32 {
    if length < 8 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if revision.wrapping_sub(2) > 2 || length > 0xFFFC {
        return STATUS_INVALID_PARAMETER;
    }
    for offset in 0..length as u64 {
        guest::write8(acl.wrapping_add(offset), 0);
    }
    guest::write8(acl, revision as u8);
    guest::write8(acl.wrapping_add(1), 0);
    guest::write16(acl.wrapping_add(2), (length & 0xFFFC) as u16);
    guest::write32(acl.wrapping_add(4), 0);
    0
}

/// RtlpAddKnownAce: acrescenta uma ACE (tipo `ace_type`) ao fim da ACL.
pub fn add_known_ace(acl: u64, ace_revision: u32, ace_flags: u32, mask: u32, sid: u64, ace_type: u8) -> u32 {
    // O NT rejeita aqui um Sid em VA de usuário (ponteiro de modo usuário numa
    // API de kernel); no OpenNT as estruturas do convidado moram na arena, que
    // é baixa, então basta validar a revisão do SID.
    if sid == 0 || guest::read8(sid) & 0xF != 1 {
        return STATUS_INVALID_SID;
    }
    let sub_authority_count = guest::read8(sid.wrapping_add(1)) as u32;
    if sub_authority_count > 15 {
        return STATUS_INVALID_SID;
    }
    let acl_revision = guest::read8(acl) as u32;
    if acl_revision > 4 || ace_revision > 4 {
        return STATUS_REVISION_MISMATCH;
    }
    if ace_flags & !0x1F != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if !valid(acl) {
        return STATUS_INVALID_ACL;
    }
    let acl_size = guest::read16(acl.wrapping_add(2)) as u64;
    let ace_count = guest::read16(acl.wrapping_add(4)) as u32;
    let end = acl.wrapping_add(acl_size);
    let mut cursor = acl.wrapping_add(8);
    for _ in 0..ace_count {
        if cursor >= end {
            return STATUS_INVALID_ACL;
        }
        let size = guest::read16(cursor.wrapping_add(2)) as u64;
        if size == 0 || cursor.wrapping_add(size) > end {
            return STATUS_INVALID_ACL;
        }
        cursor = cursor.wrapping_add(size);
    }
    let sid_length = 8 + sub_authority_count * 4;
    let ace_size = 8 + sid_length as u64;
    if cursor.wrapping_add(ace_size) > end {
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }
    guest::write8(cursor, ace_type);
    guest::write8(cursor.wrapping_add(1), ace_flags as u8);
    guest::write16(cursor.wrapping_add(2), ace_size as u16);
    guest::write32(cursor.wrapping_add(4), mask);
    for offset in 0..sid_length as u64 {
        guest::write8(cursor.wrapping_add(8 + offset), guest::read8(sid.wrapping_add(offset)));
    }
    guest::write16(acl.wrapping_add(4), (ace_count + 1) as u16);
    guest::write8(acl, acl_revision.max(ace_revision) as u8);
    0
}
