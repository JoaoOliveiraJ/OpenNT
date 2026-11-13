//! Rotinas de segurança do Rtl sobre estruturas do convidado —
//! RtlMapGenericMask, RtlAddAce, RtlGetSaclSecurityDescriptor,
//! Rtl{Get,Set}GroupSecurityDescriptor, RtlSubAuthorityCountSid e RtlCopyLuid.
//!
//! Validação e leitura dos componentes vêm de `se::{acl, descriptor}`; os
//! NTSTATUS seguem as convenções do componente `se`. Cada rotina com status
//! devolve o NTSTATUS.

use crate::ntos::inc::types::{AceHeader, Acl, Field, GenericMapping, Luid, NtStruct, SecurityDescriptor, Sid, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::descriptor;

// SAFETY (conversões deste arquivo): estruturas e parâmetros de saída do
// chamador (kernel ou driver), vivos e alinhados como no NT.
fn out<T: Copy>(address: u64) -> &'static Field<T> {
    unsafe { Field::<T>::at(address) }
}
fn acl_at(acl: u64) -> &'static Acl {
    unsafe { Acl::at(acl) }
}
fn ace_size(ace: u64) -> u64 {
    // ACEs começam alinhadas a DWORD dentro da ACL.
    unsafe { AceHeader::at(ace) }.ace_size.get() as u64
}
fn descriptor_at(sd: u64) -> &'static SecurityDescriptor {
    unsafe { SecurityDescriptor::at(sd) }
}

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
    let access = out::<u32>(mask_address);
    let mapping = unsafe { GenericMapping::at(mapping) };
    let mut mask = access.get();
    if mask & 0x8000_0000 != 0 {
        mask |= mapping.generic_read.get();
    }
    if mask & 0x4000_0000 != 0 {
        mask |= mapping.generic_write.get();
    }
    if mask & 0x2000_0000 != 0 {
        mask |= mapping.generic_execute.get();
    }
    if mask & 0x1000_0000 != 0 {
        mask |= mapping.generic_all.get();
    }
    mask &= 0x0FFF_FFFF; // zera GENERIC_{READ,WRITE,EXECUTE,ALL}
    access.set(mask);
}

/// RtlAddAce(PACL, Rev, StartIndex, AceList, AceListLength): insere ACEs
/// cruas num índice, deslocando a cauda e somando ao AceCount.
pub fn add_ace(acl: u64, ace_revision: u32, start_index: u32, ace_list: u64, ace_list_length: u32) -> u32 {
    let ace_list_len = ace_list_length as u64;
    if !crate::ntos::se::acl::valid(acl) {
        return STATUS_INVALID_ACL;
    }
    let header = acl_at(acl);
    let acl_revision = header.acl_revision.get() as u32;
    if !(2..=4).contains(&ace_revision) || acl_revision > 4 {
        return STATUS_REVISION_MISMATCH;
    }
    let acl_size = header.acl_size.get() as u64;
    let count = header.ace_count.get() as u64;
    let start = (start_index as u64).min(count);
    // Offset do ponto de inserção (após `start` ACEs) e do fim usado.
    let mut insert_at = Acl::SIZE;
    for _ in 0..start {
        insert_at += ace_size(acl + insert_at);
    }
    let mut used_end = insert_at;
    for _ in start..count {
        used_end += ace_size(acl + used_end);
    }
    if used_end + ace_list_len > acl_size {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // Abre espaço deslocando a cauda para frente (memmove: lida inteira antes).
    let tail = guest::read_bytes(acl + insert_at, (used_end - insert_at) as usize);
    guest::write_bytes(acl + insert_at + ace_list_len, &tail);
    guest::write_bytes(acl + insert_at, &guest::read_bytes(ace_list, ace_list_len as usize));
    // Conta as ACEs inseridas e atualiza o cabeçalho.
    let (mut added, mut p) = (0u64, 0u64);
    while p < ace_list_len {
        let size = ace_size(ace_list + p);
        if size == 0 {
            break;
        }
        p += size;
        added += 1;
    }
    header.ace_count.set((count + added) as u16);
    if ace_revision > acl_revision {
        header.acl_revision.set(ace_revision as u8);
    }
    0
}

/// RtlGetSaclSecurityDescriptor(PSD, PBOOLEAN Present, PACL*, PBOOLEAN Defaulted).
pub fn get_sacl(sd: u64, present: u64, acl_out: u64, defaulted: u64) -> u32 {
    if descriptor_at(sd).revision.get() != 1 {
        return STATUS_UNKNOWN_REVISION;
    }
    let control = descriptor::control(sd);
    out::<u8>(present).set((control & SE_SACL_PRESENT != 0) as u8);
    if control & SE_SACL_PRESENT != 0 {
        out::<u64>(acl_out).set(descriptor::component(sd, control, 2));
        out::<u8>(defaulted).set(((control >> 5) & 1) as u8); // SE_SACL_DEFAULTED=0x20
    }
    0
}

/// RtlGetGroupSecurityDescriptor(PSD, PSID* Group, PBOOLEAN Defaulted).
pub fn get_group(sd: u64, group_out: u64, defaulted: u64) -> u32 {
    if descriptor_at(sd).revision.get() != 1 {
        return STATUS_UNKNOWN_REVISION;
    }
    let control = descriptor::control(sd);
    out::<u64>(group_out).set(descriptor::component(sd, control, 1));
    out::<u8>(defaulted).set(((control >> 1) & 1) as u8); // SE_GROUP_DEFAULTED=0x2
    0
}

/// RtlSetGroupSecurityDescriptor(PSD, PSID Group, BOOLEAN Defaulted). SD absoluto.
pub fn set_group(sd: u64, group: u64, defaulted: bool) -> u32 {
    let descriptor = descriptor_at(sd);
    if descriptor.revision.get() != 1 {
        return STATUS_UNKNOWN_REVISION;
    }
    let control = descriptor.control.get();
    if control & SE_SELF_RELATIVE != 0 {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    descriptor.group.set(group);
    let mut value = control & !SE_GROUP_DEFAULTED;
    if defaulted {
        value |= SE_GROUP_DEFAULTED;
    }
    descriptor.control.set(value);
    0
}

/// RtlSubAuthorityCountSid(PSID) = &Sid->SubAuthorityCount (lea rax,[rcx+1]).
pub fn sub_authority_count(sid: u64) -> u64 {
    sid + 1
}

/// RtlCopyLuid(PLUID Dest, PLUID Src): copia os 8 bytes do LUID.
pub fn copy_luid(destination: u64, source: u64) {
    let (destination, source) = unsafe { (Luid::at(destination), Luid::at(source)) };
    destination.low_part.set(source.low_part.get());
    destination.high_part.set(source.high_part.get());
}

// ---- RtlConvertSidToUnicodeString (rtl-strings) ----------------------------

/// RtlConvertSidToUnicodeString(String, Sid, Allocate): SID inválido ou de
/// revisão != 1 = STATUS_INVALID_SID. O texto é "S-1-" + autoridade (decimal
/// dos 4 bytes baixos big-endian, ou "0x" + hex maiúsculo dos 6 bytes quando
/// algum dos dois altos é não nulo) + "-<subautoridade>" decimal. Com
/// Allocate, RtlCreateUnicodeString (falha = STATUS_NO_MEMORY); senão
/// RtlCopyUnicodeString se Length < MaximumLength, ou STATUS_BUFFER_OVERFLOW.
pub fn convert_sid_to_unicode_string(destination: u64, sid: u64, allocate: bool) -> Result<u32, crate::rtl::KernelError> {
    const STATUS_NO_MEMORY: u32 = 0xC000_0017;
    const STATUS_INVALID_SID: u32 = 0xC000_0078;
    const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
    if !crate::ntos::se::sid::valid(sid) {
        return Ok(STATUS_INVALID_SID);
    }
    // SAFETY: SID validado acima (RtlValidSid).
    let sid = unsafe { Sid::at(sid) };
    if sid.revision.get() != 1 {
        return Ok(STATUS_INVALID_SID);
    }
    let authority: alloc::vec::Vec<u8> = sid.identifier_authority.value.iter().map(Field::get).collect();
    let mut text = alloc::string::String::from("S-1-");
    if authority[0] != 0 || authority[1] != 0 {
        let value = authority.iter().fold(0u64, |value, &byte| value << 8 | byte as u64);
        text.push_str(&alloc::format!("0x{value:X}"));
    } else {
        let value = authority[2..].iter().fold(0u32, |value, &byte| value << 8 | byte as u32);
        text.push_str(&alloc::format!("{value}"));
    }
    // SubAuthority[SubAuthorityCount] continua depois do ANYSIZE_ARRAY de um elemento.
    let count = sid.sub_authority_count.get() as usize;
    // SAFETY: RtlValidSid confere SubAuthorityCount contra o tamanho do SID.
    for sub_authority in unsafe { Field::<u32>::array_at(sid.sub_authority[0].address(), count) } {
        text.push_str(&alloc::format!("-{}", sub_authority.get()));
    }
    // Origem temporária no convidado: UNICODE_STRING (16 bytes) + texto + NUL.
    let bytes = text.len() as u64 * 2;
    let scratch = guest::alloc_bytes(UnicodeString::SIZE + bytes + 2);
    let buffer = scratch + UnicodeString::SIZE;
    guest::write_bytes(buffer, &crate::ntos::rtl::guest_strings::wide_bytes_with_nul(&text));
    let status = if allocate {
        match crate::ntos::rtl::unicode::create(destination, buffer) {
            Ok(0) => STATUS_NO_MEMORY,
            Ok(_) => 0,
            Err(error) => {
                guest::free_bytes(scratch);
                return Err(error);
            }
        }
    } else if bytes >= unsafe { UnicodeString::at(destination) }.maximum_length.get() as u64 {
        STATUS_BUFFER_OVERFLOW
    } else {
        // SAFETY: UNICODE_STRING temporária no início do bloco alocado acima.
        let source = unsafe { UnicodeString::at(scratch) };
        source.length.set(bytes as u16);
        source.maximum_length.set(bytes as u16 + 2);
        source.buffer.set(buffer);
        crate::ntos::rtl::strings_counted::copy(destination, scratch);
        0
    };
    guest::free_bytes(scratch);
    Ok(status)
}

// ---- SIDs de rótulo obrigatório e de pacote (ntoskrnl 19041) ---------------
// RtlSidDominates 0x2520f0, RtlGetAppContainerSidType 0x6ef210 e
// RtlIsParentOfChildAppContainer 0x6ec2a4, sobre SIDs já copiados (bytes).

fn sid_sub_authority(sid: &[u8], index: usize) -> u32 {
    let at = 8 + 4 * index;
    u32::from_le_bytes([sid[at], sid[at + 1], sid[at + 2], sid[at + 3]])
}

/// Autoridade SECURITY_MANDATORY_LABEL_AUTHORITY {0,0,0,0,0,16} e as
/// subautoridades presentes no slice.
fn is_mandatory_label_sid(sid: &[u8]) -> bool {
    sid.len() >= 8 && sid[2..6] == [0, 0, 0, 0] && sid[6] == 0 && sid[7] == 0x10 && sid.len() >= 8 + 4 * sid[1] as usize
}

/// RtlSidDominates: os dois SIDs de rótulo obrigatório (senão
/// STATUS_INVALID_PARAMETER, 0xC000000D); iguais dominam; senão o último RID
/// de `a` (0 sem subautoridades) >= o de `b`, e `b` sem subautoridades é
/// sempre dominado.
pub fn sid_dominates(a: &[u8], b: &[u8]) -> Result<bool, u32> {
    if !is_mandatory_label_sid(a) || !is_mandatory_label_sid(b) {
        return Err(0xC000_000D);
    }
    let (count_a, count_b) = (a[1] as usize, b[1] as usize);
    let length = 8 + 4 * count_a;
    if a[0] == b[0] && count_a == count_b && a[..length] == b[..length] {
        return Ok(true);
    }
    if count_b == 0 {
        return Ok(true);
    }
    let rid_a = if count_a == 0 { 0 } else { sid_sub_authority(a, count_a - 1) };
    Ok(rid_a >= sid_sub_authority(b, count_b - 1))
}

/// RtlGetAppContainerSidType: 2 = pacote pai (8 subautoridades), 1 = filho
/// (12); None = não é SID de pacote S-1-15-2-... (o NT devolve erro).
fn app_container_sid_type(sid: &[u8]) -> Option<u32> {
    if sid.len() < 12 || sid[1] < 2 || sid[0] != 1 || sid[2..8] != [0, 0, 0, 0, 0, 15] || sid_sub_authority(sid, 0) != 2 || sid.len() < 8 + 4 * sid[1] as usize {
        return None;
    }
    match sid[1] {
        8 => Some(2),
        12 => Some(1),
        _ => None,
    }
}

/// RtlIsParentOfChildAppContainer: pai de 8 e filho de 12 subautoridades com
/// as subautoridades 1..7 iguais.
pub fn is_parent_of_child_app_container(parent: &[u8], child: &[u8]) -> bool {
    app_container_sid_type(parent) == Some(2) && app_container_sid_type(child) == Some(1) && (1..8).all(|index| sid_sub_authority(parent, index) == sid_sub_authority(child, index))
}
