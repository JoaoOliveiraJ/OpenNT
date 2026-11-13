//! Rotinas de segurança do Rtl sobre estruturas do convidado —
//! RtlMapGenericMask, RtlAddAce, RtlGetSaclSecurityDescriptor,
//! Rtl{Get,Set}GroupSecurityDescriptor, RtlSubAuthorityCountSid e RtlCopyLuid.
//!
//! Validação e leitura dos componentes vêm de `se::{acl, descriptor}`; os
//! NTSTATUS seguem as convenções do componente `se`. Cada rotina com status
//! devolve o NTSTATUS.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::descriptor;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_UNKNOWN_REVISION: u32 = 0xC000_0058; // convenção do componente `se`
const STATUS_INVALID_ACL: u32 = 0xC000_0077;
const STATUS_INVALID_SECURITY_DESCR: u32 = 0xC000_0079;
const STATUS_REVISION_MISMATCH: u32 = 0xC000_0059;

/// Bits do SECURITY_DESCRIPTOR_CONTROL usados aqui.
const SE_GROUP_DEFAULTED: u16 = 0x0002;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SELF_RELATIVE: u16 = 0x8000;

/// RtlMapGenericMask(PACCESS_MASK, PGENERIC_MAPPING): troca os quatro bits
/// GENERIC_* pelos direitos específicos do GENERIC_MAPPING e limpa-os. Puro.
pub fn map_generic_mask(mask_address: u64, mapping: u64) {
    let mut mask = guest::read32(mask_address);
    if mask & 0x8000_0000 != 0 {
        mask |= guest::read32(mapping); // GenericRead
    }
    if mask & 0x4000_0000 != 0 {
        mask |= guest::read32(mapping + 4); // GenericWrite
    }
    if mask & 0x2000_0000 != 0 {
        mask |= guest::read32(mapping + 8); // GenericExecute
    }
    if mask & 0x1000_0000 != 0 {
        mask |= guest::read32(mapping + 12); // GenericAll
    }
    mask &= 0x0FFF_FFFF; // zera GENERIC_{READ,WRITE,EXECUTE,ALL}
    guest::write32(mask_address, mask);
}

/// RtlAddAce(PACL, Rev, StartIndex, AceList, AceListLength): insere ACEs
/// cruas num índice, deslocando a cauda e somando ao AceCount.
pub fn add_ace(acl: u64, ace_revision: u32, start_index: u32, ace_list: u64, ace_list_length: u32) -> u32 {
    let ace_list_len = ace_list_length as u64;
    if !crate::ntos::se::acl::valid(acl) {
        return STATUS_INVALID_ACL;
    }
    let acl_revision = guest::read8(acl) as u32;
    if !(2..=4).contains(&ace_revision) || acl_revision > 4 {
        return STATUS_REVISION_MISMATCH;
    }
    let acl_size = guest::read16(acl + 2) as u64;
    let count = guest::read16(acl + 4) as u64;
    let start = (start_index as u64).min(count);
    // Offset do ponto de inserção (após `start` ACEs) e do fim usado.
    let mut insert_at = 8u64;
    for _ in 0..start {
        insert_at += guest::read16(acl + insert_at + 2) as u64;
    }
    let mut used_end = insert_at;
    for _ in start..count {
        used_end += guest::read16(acl + used_end + 2) as u64;
    }
    if used_end + ace_list_len > acl_size {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // Abre espaço deslocando a cauda para frente (de trás para frente).
    let tail = used_end - insert_at;
    for k in 0..tail {
        let from = acl + used_end - 1 - k;
        guest::write8(from + ace_list_len, guest::read8(from));
    }
    for k in 0..ace_list_len {
        guest::write8(acl + insert_at + k, guest::read8(ace_list + k));
    }
    // Conta as ACEs inseridas e atualiza o cabeçalho.
    let (mut added, mut p) = (0u64, 0u64);
    while p < ace_list_len {
        let size = guest::read16(ace_list + p + 2) as u64;
        if size == 0 {
            break;
        }
        p += size;
        added += 1;
    }
    guest::write16(acl + 4, (count + added) as u16);
    if ace_revision > acl_revision {
        guest::write8(acl, ace_revision as u8);
    }
    0
}

/// RtlGetSaclSecurityDescriptor(PSD, PBOOLEAN Present, PACL*, PBOOLEAN Defaulted).
pub fn get_sacl(sd: u64, present: u64, acl_out: u64, defaulted: u64) -> u32 {
    if guest::read8(sd) != 1 {
        return STATUS_UNKNOWN_REVISION;
    }
    let control = descriptor::control(sd);
    guest::write8(present, (control & SE_SACL_PRESENT != 0) as u8);
    if control & SE_SACL_PRESENT != 0 {
        guest::write64(acl_out, descriptor::component(sd, control, 2));
        guest::write8(defaulted, ((control >> 5) & 1) as u8); // SE_SACL_DEFAULTED=0x20
    }
    0
}

/// RtlGetGroupSecurityDescriptor(PSD, PSID* Group, PBOOLEAN Defaulted).
pub fn get_group(sd: u64, group_out: u64, defaulted: u64) -> u32 {
    if guest::read8(sd) != 1 {
        return STATUS_UNKNOWN_REVISION;
    }
    let control = descriptor::control(sd);
    guest::write64(group_out, descriptor::component(sd, control, 1));
    guest::write8(defaulted, ((control >> 1) & 1) as u8); // SE_GROUP_DEFAULTED=0x2
    0
}

/// RtlSetGroupSecurityDescriptor(PSD, PSID Group, BOOLEAN Defaulted). SD absoluto.
pub fn set_group(sd: u64, group: u64, defaulted: bool) -> u32 {
    if guest::read8(sd) != 1 {
        return STATUS_UNKNOWN_REVISION;
    }
    let control = guest::read16(sd + 2);
    if control & SE_SELF_RELATIVE != 0 {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    guest::write64(sd + 0x10, group); // Group está em +0x10 (owner +8, group +0x10)
    let mut value = control & !SE_GROUP_DEFAULTED;
    if defaulted {
        value |= SE_GROUP_DEFAULTED;
    }
    guest::write16(sd + 2, value);
    0
}

/// RtlSubAuthorityCountSid(PSID) = &Sid->SubAuthorityCount (lea rax,[rcx+1]).
pub fn sub_authority_count(sid: u64) -> u64 {
    sid + 1
}

/// RtlCopyLuid(PLUID Dest, PLUID Src): copia os 8 bytes do LUID.
pub fn copy_luid(destination: u64, source: u64) {
    guest::write64(destination, guest::read64(source));
}
