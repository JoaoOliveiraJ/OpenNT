//! Validação estrutural de ACLs e ACEs (RtlValidAcl).
//!
//! A decisão de acesso pertence a outro provedor; tipos desconhecidos de
//! entrada passam só pela verificação mínima do cabeçalho do kernel original.
//!
//! O NT só exige ACL e ACEs alinhadas a WORD: o `_ACE_HEADER` (alinhamento
//! 2) é acessado tipado, mas os campos ULONG depois dele, o SID embutido e o
//! atributo de claim podem cair fora do alinhamento natural numa ACL válida.
//! Esses são lidos pelo offset do layout tipado ([`ace_field`]), sem criar
//! referência desalinhada.

use core::mem::offset_of;

use crate::ntos::inc::types::{
    AccessAllowedAce, AccessAllowedObjectAce, AceHeader, Acl, ClaimSecurityAttributeRelativeV1, CompoundAccessAllowedAce,
    NtStruct, Sid, SystemAccessFilterAce,
};
use crate::ntos::mm::guest_memory::{self as guest, GuestScalar};

/// Campo de uma estrutura possivelmente desalinhada dentro de uma ACE, pelo
/// offset do layout: um MOV, como o x64 faz no NT.
fn ace_field<T: GuestScalar>(base: u64, offset: usize) -> T {
    guest::read(base + offset as u64)
}

fn ace_header(entry: u64) -> &'static AceHeader {
    // SAFETY: entradas percorridas a partir de uma ACL alinhada a WORD, com
    // offsets pares (conferidos pelo chamador).
    unsafe { AceHeader::at(entry) }
}

/// Revisão 1 e até 15 subautoridades; zero = SID inválido.
fn sid_length(pointer: u64) -> i64 {
    let count: u8 = ace_field(pointer, offset_of!(Sid, sub_authority_count));
    if ace_field::<u8>(pointer, offset_of!(Sid, revision)) == 1 && count <= 15 { 8 + count as i64 * 4 } else { 0 }
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
    type Claim = ClaimSecurityAttributeRelativeV1;
    if length < 20
        || ace_field::<u16>(claim, offset_of!(Claim, reserved)) != 0
        || ace_field::<u32>(claim, offset_of!(Claim, flags)) & 0xFFC0 != 0
    {
        return false;
    }
    let name = ace_field::<u32>(claim, offset_of!(Claim, name)) as i64;
    let count = ace_field::<u32>(claim, offset_of!(Claim, value_count)) as i64;
    let value_type = ace_field::<u16>(claim, offset_of!(Claim, value_type));
    if count == 0 || name > length - 4 || !has_wide_terminator(claim + name as u64, length - name) || count > (length - 16) / 4 || ![1, 2, 3, 5, 6, 16].contains(&value_type) {
        return false;
    }
    for index in 0..count as usize {
        let offset = ace_field::<u32>(claim, offset_of!(Claim, values) + index * 4) as i64;
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
                // Octeto (16) e FQBN (5): comprimento ULONG seguido dos bytes.
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
    let ace_type = ace_header(entry).ace_type.get();
    // Entradas cujo SID começa diretamente em SidStart (+8).
    let sid_start = offset_of!(AccessAllowedAce, sid_start) as u64;
    if ace_type <= 20 && (0x1A_660Fu32 >> ace_type) & 1 != 0 {
        if length & 3 != 0 || length < 16 {
            return false;
        }
        let sid = sid_length(entry + sid_start);
        return sid != 0 && length >= 8 + sid;
    }
    if ace_type == 4 {
        if revision < 3 || length & 3 != 0 || length < 24 || ace_field::<u16>(entry, offset_of!(CompoundAccessAllowedAce, compound_ace_type)) != 1 {
            return false;
        }
        // Entrada composta: dois SIDs consecutivos a partir de SidStart.
        let compound_sid = offset_of!(CompoundAccessAllowedAce, sid_start) as u64;
        let first = sid_length(entry + compound_sid);
        if first == 0 || length < first + 24 {
            return false;
        }
        let second = sid_length(entry + compound_sid + first as u64);
        return second != 0 && length >= 12 + first + second;
    }
    if (5..=8).contains(&ace_type) || matches!(ace_type, 11 | 12 | 15 | 16) {
        if revision < 4 || length & 3 != 0 || length < 12 {
            return false;
        }
        let flags = ace_field::<u32>(entry, offset_of!(AccessAllowedObjectAce, flags));
        // GUIDs opcionais de 16 bytes antes do SID (ObjectType e
        // InheritedObjectType só ocupam espaço quando presentes).
        let guids = (if flags & 1 != 0 { 16 } else { 0 }) + (if flags & 2 != 0 { 16 } else { 0 });
        if length < 24 + guids {
            return false;
        }
        let sid = sid_length(entry + offset_of!(AccessAllowedObjectAce, object_type) as u64 + guids as u64);
        return sid != 0 && length >= 12 + guids + sid;
    }
    if ace_type == 18 || ace_type == 21 {
        if length & 3 != 0 || length < 16 {
            return false;
        }
        let sid = sid_length(entry + sid_start);
        if sid == 0 {
            return false;
        }
        // Dados de aplicação logo depois do SID.
        let offset = sid + offset_of!(SystemAccessFilterAce, sid_start) as i64;
        let remaining = length - offset;
        if ace_type == 21 {
            // Expressão condicional: assinatura "artx".
            return remaining >= 6 && guest::read32(entry + offset as u64) == 0x7874_7261;
        }
        return remaining >= 20 && valid_claim_attribute(entry + offset as u64, remaining);
    }
    length >= 4
}

/// RtlValidAcl: percorre as entradas declaradas sem modificar memória.
pub fn valid(pointer: u64) -> bool {
    if pointer & 1 != 0 {
        return false;
    }
    // SAFETY: PACL alinhada a WORD (conferido acima).
    let acl = unsafe { Acl::at(pointer) };
    let revision = acl.acl_revision.get();
    if !(2..=4).contains(&revision) {
        return false;
    }
    let length = acl.acl_size.get() as i64;
    let count = acl.ace_count.get();
    if length < 8 {
        return false;
    }
    let mut offset: i64 = Acl::SIZE as i64;
    for _ in 0..count {
        // Pelo menos um byte além do cabeçalho da ACE.
        if offset + 4 >= length || offset & 1 != 0 {
            return false;
        }
        let current = pointer + offset as u64;
        let entry_length = ace_header(current).ace_size.get() as i64;
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
    guest::write_bytes(acl, &alloc::vec![0u8; length as usize]);
    // SAFETY: o chamador entrega o buffer da ACL (PACL).
    let header = unsafe { Acl::at(acl) };
    header.acl_revision.set(revision as u8);
    header.sbz1.set(0);
    header.acl_size.set((length & 0xFFFC) as u16);
    header.ace_count.set(0);
    header.sbz2.set(0);
    0
}

/// RtlpAddKnownAce: acrescenta uma ACE (tipo `ace_type`) ao fim da ACL.
pub fn add_known_ace(acl: u64, ace_revision: u32, ace_flags: u32, mask: u32, sid: u64, ace_type: u8) -> u32 {
    // O NT rejeita aqui um Sid em VA de usuário (ponteiro de modo usuário numa
    // API de kernel); no OpenNT as estruturas do convidado moram na arena, que
    // é baixa, então basta validar a revisão do SID.
    if sid == 0 {
        return STATUS_INVALID_SID;
    }
    let identifier = super::sid::at(sid);
    if identifier.revision.get() & 0xF != 1 {
        return STATUS_INVALID_SID;
    }
    let sub_authority_count = identifier.sub_authority_count.get() as u32;
    if sub_authority_count > 15 {
        return STATUS_INVALID_SID;
    }
    let acl_revision = ace_field::<u8>(acl, offset_of!(Acl, acl_revision)) as u32;
    if acl_revision > 4 || ace_revision > 4 {
        return STATUS_REVISION_MISMATCH;
    }
    if ace_flags & !0x1F != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if !valid(acl) {
        return STATUS_INVALID_ACL;
    }
    // SAFETY: `valid` conferiu o alinhamento e o cabeçalho.
    let header = unsafe { Acl::at(acl) };
    let acl_size = header.acl_size.get() as u64;
    let ace_count = header.ace_count.get() as u32;
    let end = acl.wrapping_add(acl_size);
    let mut cursor = acl.wrapping_add(Acl::SIZE);
    for _ in 0..ace_count {
        if cursor >= end {
            return STATUS_INVALID_ACL;
        }
        let size = ace_header(cursor).ace_size.get() as u64;
        if size == 0 || cursor.wrapping_add(size) > end {
            return STATUS_INVALID_ACL;
        }
        cursor = cursor.wrapping_add(size);
    }
    let sid_length = 8 + sub_authority_count * 4;
    let sid_start = offset_of!(AccessAllowedAce, sid_start) as u64;
    let ace_size = sid_start + sid_length as u64;
    if cursor.wrapping_add(ace_size) > end {
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }
    // ACCESS_ALLOWED/DENIED/SYSTEM_AUDIT/MANDATORY_LABEL compartilham o layout.
    let ace = ace_header(cursor);
    ace.ace_type.set(ace_type);
    ace.ace_flags.set(ace_flags as u8);
    ace.ace_size.set(ace_size as u16);
    guest::write(cursor + offset_of!(AccessAllowedAce, mask) as u64, mask);
    guest::write_bytes(cursor.wrapping_add(sid_start), &guest::read_bytes(sid, sid_length as usize));
    header.ace_count.set((ace_count + 1) as u16);
    header.acl_revision.set(acl_revision.max(ace_revision) as u8);
    0
}
