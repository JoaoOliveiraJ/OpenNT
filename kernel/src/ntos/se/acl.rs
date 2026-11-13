//! Validação estrutural de ACLs e ACEs — `system32/ntos/se/acl.js` (RtlValidAcl).
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
