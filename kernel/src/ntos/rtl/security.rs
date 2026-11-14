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

/// STATUS_NOT_APPCONTAINER.
const STATUS_NOT_APPCONTAINER: u32 = 0xC000_A200;

/// RtlGetAppContainerSidType(Sid, *SidType) -> NTSTATUS, como no ntoskrnl
/// 19041: um SID S-1-15-2-... com 8 subautoridades é o pacote pai
/// (ParentAppContainerSidType 2), com 12 o filho (ChildAppContainerSidType
/// 1); outro número de subautoridades dá InvalidAppContainerSidType (3) e um
/// SID que não é de pacote (revisão, autoridade, primeira subautoridade ou
/// menos de duas) dá NotAppContainerSidType (0), os dois com
/// STATUS_NOT_APPCONTAINER.
pub fn get_app_container_sid_type(sid: u64, sid_type: u64) -> u32 {
    let (status, kind) = app_container_type_at(sid);
    out::<u32>(sid_type).set(kind);
    status
}

/// O (NTSTATUS, APPCONTAINER_SID_TYPE) do SID em `sid`.
fn app_container_type_at(sid: u64) -> (u32, u32) {
    // SAFETY: o SID do chamador de kernel.
    let header = unsafe { Sid::at(sid) };
    let authority: alloc::vec::Vec<u8> = header.identifier_authority.value.iter().map(Field::get).collect();
    let count = header.sub_authority_count.get();
    if count < 2 || header.revision.get() != 1 || authority != [0, 0, 0, 0, 0, 15] || header.sub_authority[0].get() != 2 {
        return (STATUS_NOT_APPCONTAINER, 0);
    }
    match count {
        8 => (0, 2),
        12 => (0, 1),
        _ => (STATUS_NOT_APPCONTAINER, 3),
    }
}

/// RtlGetAppContainerParent(AppContainerSid, *AppContainerSidParent) ->
/// NTSTATUS: para um SID de pacote filho, um SID novo do pool paginável
/// (tag 'RtPb', liberado por quem chama com ExFreePool) com as oito
/// primeiras subautoridades; para outro SID, STATUS_INVALID_PARAMETER.
pub fn get_app_container_parent(sid: u64, parent_out: u64) -> Result<u32, crate::rtl::KernelError> {
    use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
    out::<u64>(parent_out).set(0);
    if app_container_type_at(sid) != (0, 1) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let parent = kernel_pool::allocate(0x28, AllocateOptions { paged: true, tag: u32::from_le_bytes(*b"RtPb"), ..AllocateOptions::default() })?;
    if parent == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: o SID filho validado acima e o bloco novo de 0x28 bytes (o SID
    // de oito subautoridades).
    let (source, target) = unsafe { (Sid::at(sid), Sid::at(parent)) };
    target.revision.set(1);
    target.sub_authority_count.set(8);
    for (index, byte) in target.identifier_authority.value.iter().enumerate() {
        byte.set(if index == 5 { 15 } else { 0 });
    }
    // SAFETY: os dois SIDs têm ao menos oito subautoridades.
    let (from, to) = unsafe { (Field::<u32>::array_at(source.sub_authority[0].address(), 8), Field::<u32>::array_at(target.sub_authority[0].address(), 8)) };
    for (destination, value) in to.iter().zip(from) {
        destination.set(value.get());
    }
    out::<u64>(parent_out).set(parent);
    Ok(0)
}

/// RtlIsParentOfChildAppContainer: pai de 8 e filho de 12 subautoridades com
/// as subautoridades 1..7 iguais.
pub fn is_parent_of_child_app_container(parent: &[u8], child: &[u8]) -> bool {
    app_container_sid_type(parent) == Some(2) && app_container_sid_type(child) == Some(1) && (1..8).all(|index| sid_sub_authority(parent, index) == sid_sub_authority(child, index))
}

// ---- ACEs, troca de SIDs, normalização e sandbox (ntoskrnl 19045) -----------
//
// RtlFindAceByType 0x2d29c0, RtlOwnerAcesPresent 0x2f43d0 (RtlpOwnerAcesPresent
// 0x2f43f0), RtlReplaceSidInSd 0x9138b0, RtlNormalizeSecurityDescriptor
// 0x2024f0, RtlIsSandboxedToken 0x652b50. Usa os auxiliares do arquivo
// (`out`, `acl_at`) e as estruturas de `inc::types`.

use crate::ntos::inc::types::{AccessAllowedAce, AccessAllowedObjectAce, CompoundAccessAllowedAce, Guid, SecurityDescriptorRelative, SecuritySubjectContext};

const ACE_INHERIT_ONLY: u8 = 0x08;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const COMPOUND_ACE_TYPE: u8 = 0x04;
/// Tipos de ACE de objeto (5..8, 0xB, 0xC, 0xF, 0x10): bitmap 0x199e0 do original.
const OBJECT_ACE_TYPES: u32 = 0x1_99E0;
/// ACE_OBJECT_TYPE_PRESENT / ACE_INHERITED_OBJECT_TYPE_PRESENT.
const ACE_OBJECT_TYPE_PRESENT: u32 = 1;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 2;
/// S-1-3-4 (SeExports->SeOwnerRightsSid).
const OWNER_RIGHTS_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
const SECURITY_MANDATORY_MEDIUM_RID: u32 = 0x2000;
/// ExAllocatePoolWithTag(PagedPool, Length, 'SeSd').
const PAGED_POOL: u32 = 1;
const NORMALIZE_TAG: u32 = 0x6453_6553;

const ACL_HEADER: u64 = core::mem::size_of::<Acl>() as u64;
const SID_HEADER: u64 = core::mem::offset_of!(Sid, sub_authority) as u64;
const RELATIVE_HEADER: u32 = core::mem::size_of::<SecurityDescriptorRelative>() as u32;

// SAFETY (conversões abaixo): ACEs e SIDs dentro de ACLs/SDs do chamador,
// percorridos pelos tamanhos gravados neles, como no NT.
fn ace_header_at(ace: u64) -> &'static AceHeader {
    unsafe { AceHeader::at(ace) }
}
fn sid_at(sid: u64) -> &'static Sid {
    unsafe { Sid::at(sid) }
}
fn relative_at(descriptor: u64) -> &'static SecurityDescriptorRelative {
    unsafe { SecurityDescriptorRelative::at(descriptor) }
}

/// RtlFindAceByType(Acl, AceType, *Index): primeiro ACE do tipo; com `Index`,
/// só a partir de `*Index`, que recebe a posição encontrada. NULL se nenhum.
pub fn find_ace_by_type(acl: u64, ace_type: u32, index: u64) -> u64 {
    if acl == 0 {
        return 0;
    }
    let index = (index != 0).then(|| out::<u32>(index));
    let mut ace = acl + ACL_HEADER;
    for position in 0..acl_at(acl).ace_count.get() as u32 {
        let header = ace_header_at(ace);
        let matches = header.ace_type.get() as u32 == ace_type;
        match index {
            None if matches => return ace,
            Some(index) if matches && position >= index.get() => {
                index.set(position);
                return ace;
            }
            _ => {}
        }
        ace += header.ace_size.get() as u64;
    }
    0
}

/// SID de um ACE para o RtlpOwnerAcesPresent (0 = tipo sem SID examinado).
fn owner_scan_sid(ace: u64) -> u64 {
    let ace_type = ace_header_at(ace).ace_type.get();
    if ace_type <= 0x10 && OBJECT_ACE_TYPES & (1u32 << ace_type) != 0 {
        // SAFETY: ACE de objeto (cabeçalho, máscara e Flags presentes).
        let flags = unsafe { AccessAllowedObjectAce::at(ace) }.flags.get();
        let guid = core::mem::size_of::<Guid>() as u64;
        let mut sid = ace + core::mem::offset_of!(AccessAllowedObjectAce, object_type) as u64;
        if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
            sid += guid;
        }
        if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
            sid += guid;
        }
        return sid;
    }
    match ace_type {
        COMPOUND_ACE_TYPE => ace + core::mem::offset_of!(CompoundAccessAllowedAce, sid_start) as u64,
        0..=0xA | 0xD | 0xE => ace + core::mem::offset_of!(AccessAllowedAce, sid_start) as u64,
        _ => 0,
    }
}

/// RtlOwnerAcesPresent(Acl): algum ACE efetivo (não INHERIT_ONLY) com o SID
/// OWNER RIGHTS (S-1-3-4).
pub fn owner_aces_present(acl: u64) -> bool {
    if acl == 0 {
        return false;
    }
    let mut ace = acl + ACL_HEADER;
    for _ in 0..acl_at(acl).ace_count.get() {
        let header = ace_header_at(ace);
        if header.ace_flags.get() & ACE_INHERIT_ONLY == 0 {
            let sid = owner_scan_sid(ace);
            if sid != 0 {
                let target = sid_at(sid);
                if target.revision.get() == OWNER_RIGHTS_SID[0] && target.sub_authority_count.get() == OWNER_RIGHTS_SID[1] && guest::read_bytes(sid, OWNER_RIGHTS_SID.len()) == OWNER_RIGHTS_SID {
                    return true;
                }
            }
        }
        ace += header.ace_size.get() as u64;
    }
    false
}

/// SID igual ao antigo ou o antigo mais um RID (prefixo de domínio): mesma
/// revisão, contagem igual ou +1, mesma autoridade e as subautoridades do antigo.
fn sid_has_prefix(sid: u64, old: u64) -> bool {
    let (candidate, prefix) = (sid_at(sid), sid_at(old));
    let (count, old_count) = (candidate.sub_authority_count.get(), prefix.sub_authority_count.get());
    let compared = SID_HEADER as usize - 2 + old_count as usize * 4;
    candidate.revision.get() == prefix.revision.get()
        && (count == old_count || count as u32 == old_count as u32 + 1)
        && guest::read_bytes(sid + 2, compared) == guest::read_bytes(old + 2, compared)
}

/// RtlReplaceSidInSd(Sd, OldSid, NewSid, *NumChanges): troca o prefixo
/// `OldSid` pelas subautoridades de `NewSid` no dono, no grupo e nos ACEs
/// (tipos 0..3 e o SID cliente do composto) da DACL e da SACL. O cabeçalho
/// (Revision/Control) é comum às formas absoluta e relativa.
pub fn replace_sid_in_sd(sd: u64, old_sid: u64, new_sid: u64, changes: &Field<u32>) -> u32 {
    changes.set(0);
    let header = relative_at(sd);
    if header.revision.get() != 1 {
        return STATUS_UNKNOWN_REVISION;
    }
    let length = sid_at(old_sid).sub_authority_count.get() as usize * 4;
    let replacement = guest::read_bytes(new_sid + SID_HEADER, length);
    let control = header.control.get();
    let replace = |sid: u64| {
        if sid != 0 && sid_has_prefix(sid, old_sid) {
            guest::write_bytes(sid + SID_HEADER, &replacement);
            changes.set(changes.get() + 1);
        }
    };
    replace(descriptor::component(sd, control, 0));
    replace(descriptor::component(sd, control, 1));
    for index in [3u64, 2] {
        let acl = descriptor::component(sd, control, index);
        if acl == 0 {
            continue;
        }
        let mut ace = acl + ACL_HEADER;
        for _ in 0..acl_at(acl).ace_count.get() {
            let header = ace_header_at(ace);
            match header.ace_type.get() {
                0..=3 => replace(ace + core::mem::offset_of!(AccessAllowedAce, sid_start) as u64),
                COMPOUND_ACE_TYPE => {
                    let server = ace + core::mem::offset_of!(CompoundAccessAllowedAce, sid_start) as u64;
                    replace(server + SID_HEADER + 4 * sid_at(server).sub_authority_count.get() as u64);
                }
                _ => {}
            }
            ace += header.ace_size.get() as u64;
        }
    }
    0
}

/// Componente de um SD relativo cujo offset a normalização reescreve.
#[derive(Clone, Copy)]
enum Component {
    Owner,
    Group,
    Sacl,
    Dacl,
}

fn component_offset(header: &SecurityDescriptorRelative, component: Component) -> &Field<u32> {
    match component {
        Component::Owner => &header.owner,
        Component::Group => &header.group,
        Component::Sacl => &header.sacl,
        Component::Dacl => &header.dacl,
    }
}

/// Destino da normalização: escrito só fora do modo de verificação.
struct NormalizedOutput {
    base: u64,
    write: bool,
}

impl NormalizedOutput {
    fn bytes(&self, offset: u32, bytes: &[u8]) {
        if self.write {
            guest::write_bytes(self.base + offset as u64, bytes);
        }
    }

    fn header(&self) -> Option<&'static SecurityDescriptorRelative> {
        self.write.then(|| relative_at(self.base))
    }

    fn acl(&self, offset: u32) -> Option<&'static Acl> {
        self.write.then(|| acl_at(self.base + offset as u64))
    }
}

/// RtlNormalizeSecurityDescriptor(*Sd, Length, *NewSd, *NewLength, CheckOnly):
/// reempacota um SD self-relative na ordem SACL, DACL, dono, grupo — sem SACL
/// vazia, sem ACCESS_ALLOWED duplicado (comparação de memória do ACE inteiro),
/// com AclSize/AceCount refeitos, enchimento zerado e offsets compactos.
/// Devolve TRUE se algo mudou (CheckOnly: TRUE na primeira diferença, sem
/// escrever). Sem mudança o SD novo alocado é liberado; com mudança e `NewSd`
/// NULL, o SD antigo é liberado e `*Sd` recebe o novo.
pub fn normalize_security_descriptor(sd_cell: &Field<u64>, length: u32, new_sd_cell: u64, new_length_out: u64, check_only: bool) -> Result<bool, crate::rtl::KernelError> {
    let source = sd_cell.get();
    if !descriptor::valid_relative(source, length, 0) {
        return Ok(false);
    }
    let new_sd = (new_sd_cell != 0).then(|| out::<u64>(new_sd_cell));
    let (mut target, mut allocated) = (0u64, false);
    if !check_only {
        match new_sd.map(|cell| cell.get()).filter(|&buffer| buffer != 0) {
            Some(buffer) => target = buffer,
            None => {
                target = crate::ntos::ex::pool_allocation::allocate_tagged(PAGED_POOL, length as u64, NORMALIZE_TAG)?;
                if target == 0 {
                    return Ok(false);
                }
                allocated = true;
            }
        }
        guest::write_bytes(target, &guest::read_bytes(source, RELATIVE_HEADER as usize));
    }
    let output = NormalizedOutput { base: target, write: !check_only };
    let Some((changed, size)) = normalize_into(source, &output, check_only) else {
        // Verificação: primeira diferença achada.
        return Ok(true);
    };
    if changed && !check_only {
        match new_sd {
            None => {
                crate::ntos::ex::pool_allocation::free(source, 0)?;
                sd_cell.set(target);
            }
            Some(cell) if allocated => cell.set(target),
            Some(_) => {}
        }
        if new_length_out != 0 {
            out::<u32>(new_length_out).set(size);
        }
        return Ok(true);
    }
    if allocated {
        crate::ntos::ex::pool_allocation::free(target, 0)?;
    }
    Ok(changed)
}

/// Corpo da normalização: Some((mudou, tamanho)) ou None quando o modo de
/// verificação achou a primeira diferença.
fn normalize_into(source: u64, output: &NormalizedOutput, check_only: bool) -> Option<(bool, u32)> {
    let header = relative_at(source);
    let mut changed = false;
    let mut differ = || {
        changed = true;
        !check_only
    };
    let mut cursor = RELATIVE_HEADER;
    for component in [Component::Sacl, Component::Dacl] {
        let offset = component_offset(header, component).get();
        if offset == 0 {
            continue;
        }
        let acl_address = source + offset as u64;
        let acl = acl_at(acl_address);
        let ace_count = acl.ace_count.get() as u32;
        let new_offset = if matches!(component, Component::Sacl) && ace_count == 0 { 0 } else { cursor };
        if new_offset != offset {
            if !differ() {
                return None;
            }
            if let Some(target) = output.header() {
                component_offset(target, component).set(new_offset);
            }
        }
        if new_offset == 0 {
            continue;
        }
        output.bytes(new_offset, &guest::read_bytes(acl_address, ACL_HEADER as usize));
        cursor += ACL_HEADER as u32;
        let mut kept: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
        let mut earlier: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
        let mut ace = acl_address + ACL_HEADER;
        for _ in 0..ace_count {
            let ace_header = ace_header_at(ace);
            let size = ace_header.ace_size.get() as usize;
            let bytes = guest::read_bytes(ace, size);
            let duplicate = ace_header.ace_type.get() == ACCESS_ALLOWED_ACE_TYPE && if check_only { earlier.contains(&bytes) } else { kept.contains(&bytes) };
            if duplicate {
                if !differ() {
                    return None;
                }
            } else {
                output.bytes(cursor, &bytes);
                cursor += size as u32;
                kept.push(bytes.clone());
            }
            earlier.push(bytes);
            ace += size as u64;
        }
        let aligned = (cursor + 3) & !3;
        let new_size = aligned - new_offset;
        let old_size = acl.acl_size.get() as u32;
        if new_size != old_size {
            if !differ() {
                return None;
            }
            if let Some(target) = output.acl(new_offset) {
                target.acl_size.set(new_size as u16);
            }
        }
        if kept.len() as u32 != ace_count {
            if let Some(target) = output.acl(new_offset) {
                target.ace_count.set(kept.len() as u16);
            }
        }
        if cursor != aligned {
            let same_place = new_offset == offset && new_size == old_size;
            if same_place && guest::read_bytes(source + cursor as u64, (aligned - cursor) as usize).iter().any(|&byte| byte != 0) && !differ() {
                return None;
            }
            output.bytes(cursor, &alloc::vec![0u8; (aligned - cursor) as usize]);
            cursor = aligned;
        }
    }
    for (component, optional) in [(Component::Owner, false), (Component::Group, true)] {
        let offset = component_offset(header, component).get();
        if optional && offset == 0 {
            continue;
        }
        if cursor != offset {
            if !differ() {
                return None;
            }
            if let Some(target) = output.header() {
                component_offset(target, component).set(cursor);
            }
        }
        let sid = source + offset as u64;
        let size = SID_HEADER as u32 + 4 * sid_at(sid).sub_authority_count.get() as u32;
        output.bytes(cursor, &guest::read_bytes(sid, size as usize));
        cursor += size;
    }
    Some((changed, cursor))
}

/// RtlIsSandboxedToken(SubjectContext, PreviousMode): o NT faz um access check
/// de READ_CONTROL contra `SeMediumDaclSd` (sem DACL; SACL = rótulo Medium com
/// NO_READ_UP) e devolve a negação do resultado. Sem DACL só o rótulo decide:
/// sujeito abaixo de Medium (ou personificação abaixo de SecurityImpersonation,
/// que o access check recusa) é sandbox; KernelMode nunca é. Sem SubjectContext,
/// o da thread corrente é capturado e liberado. O ramo de kernel CET (que
/// também marca AppContainers) não se aplica: KeIsKernelCetEnabled é FALSE.
pub fn is_sandboxed_token(subject_context: u64, previous_mode: u8) -> Result<bool, crate::rtl::KernelError> {
    use crate::ntos::inc::types::SecurityImpersonationLevel;
    use crate::ntos::se::subject_context as subject;
    if previous_mode == 0 {
        return Ok(false);
    }
    let captured = if subject_context == 0 {
        let context = guest::alloc_bytes(SecuritySubjectContext::SIZE);
        subject::capture(context)?;
        Some(context)
    } else {
        None
    };
    // SAFETY: SECURITY_SUBJECT_CONTEXT do chamador ou o capturado acima.
    let context = unsafe { SecuritySubjectContext::at(captured.unwrap_or(subject_context)) };
    let client = context.client_token.get();
    let granted = if client != 0 && context.impersonation_level.get().0 < SecurityImpersonationLevel::SECURITY_IMPERSONATION.0 {
        false
    } else {
        let token = if client != 0 { client } else { context.primary_token.get() };
        crate::ntos::se::token::tokens::with(token, |token| integrity_rid(&token.integrity) >= SECURITY_MANDATORY_MEDIUM_RID).unwrap_or(false)
    };
    if let Some(address) = captured {
        subject::release(address)?;
        guest::free_bytes(address);
    }
    Ok(!granted)
}

/// RID do SID de integridade do token; sem rótulo vale Medium (a mesma regra do
/// `se::object_security` do OpenNT).
fn integrity_rid(sid: &[u8]) -> u32 {
    if sid.len() < 12 {
        return SECURITY_MANDATORY_MEDIUM_RID;
    }
    let count = sid[1] as usize;
    let at = 8 + 4 * count.saturating_sub(1);
    if sid.len() < at + 4 {
        return SECURITY_MANDATORY_MEDIUM_RID;
    }
    u32::from_le_bytes([sid[at], sid[at + 1], sid[at + 2], sid[at + 3]])
}

/// RtlAreAllAccessesGranted(GrantedAccess, DesiredAccess): nenhum bit
/// pedido fora do concedido (ntoskrnl 19041, 0x6774e0).
pub fn are_all_accesses_granted(granted: u32, desired: u32) -> bool {
    desired & !granted == 0
}

/// RtlAreAnyAccessesGranted(GrantedAccess, DesiredAccess): algum bit em
/// comum (0x6a5bf0).
pub fn are_any_accesses_granted(granted: u32, desired: u32) -> bool {
    desired & granted != 0
}
