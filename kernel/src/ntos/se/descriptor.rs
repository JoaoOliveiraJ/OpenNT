//! SECURITY_DESCRIPTOR absoluto ou relativo.
//!
//! Leitura, validação, conversão e captura (cópia self-relative na arena do
//! convidado); componentes e entradas de ACL são acessados na memória do
//! convidado. Os dois formatos compartilham o cabeçalho (Revision, Sbz1,
//! Control): o absoluto (`_SECURITY_DESCRIPTOR`) guarda ponteiros, o relativo
//! (`_SECURITY_DESCRIPTOR_RELATIVE`) offsets de 32 bits.

use core::mem::offset_of;

use super::{acl, out, sid};
use crate::ntos::inc::types::{AceHeader, Acl, NtStruct, SecurityDescriptor, SecurityDescriptorRelative};
use crate::ntos::mm::guest_memory as guest;

const SELF_RELATIVE: u16 = 0x8000;
const DACL_PRESENT: u16 = 4;
const SACL_PRESENT: u16 = 16;
/// Tamanho do cabeçalho relativo (`sizeof(SECURITY_DESCRIPTOR_RELATIVE)`).
const RELATIVE_HEADER: u32 = SecurityDescriptorRelative::SIZE as u32;

fn align4(size: u32) -> u32 {
    (size + 3) & !3
}

/// Cabeçalho comum aos dois formatos; a vista relativa tem o menor
/// alinhamento (4) e os mesmos offsets de Revision/Control.
fn header(descriptor: u64) -> &'static SecurityDescriptorRelative {
    // SAFETY: PSECURITY_DESCRIPTOR vivo, como nas rotinas Rtl*SecurityDescriptor.
    unsafe { SecurityDescriptorRelative::at(descriptor) }
}

fn absolute(descriptor: u64) -> &'static SecurityDescriptor {
    // SAFETY: descritor absoluto (SE_SELF_RELATIVE limpo), alinhado a ponteiro.
    unsafe { SecurityDescriptor::at(descriptor) }
}

fn acl_at(pointer: u64) -> &'static Acl {
    // SAFETY: PACL viva (componente do descritor ou parâmetro).
    unsafe { Acl::at(pointer) }
}

/// Índices: proprietário, grupo, SACL, DACL. O modo relativo guarda offsets
/// de 32 bits; o absoluto, ponteiros de 64 bits.
pub fn component(descriptor: u64, control: u16, index: u64) -> u64 {
    if (index == 2 && control & SACL_PRESENT == 0) || (index == 3 && control & DACL_PRESENT == 0) {
        return 0;
    }
    if control & SELF_RELATIVE == 0 {
        // O NT só exige alinhamento ULONG do descritor capturado
        // (ProbeForRead), então os ponteiros são lidos pelo offset do layout.
        let offset = [
            offset_of!(SecurityDescriptor, owner),
            offset_of!(SecurityDescriptor, group),
            offset_of!(SecurityDescriptor, sacl),
            offset_of!(SecurityDescriptor, dacl),
        ][index as usize];
        return guest::read::<u64>(descriptor.wrapping_add(offset as u64));
    }
    let sd = header(descriptor);
    let offset = [&sd.owner, &sd.group, &sd.sacl, &sd.dacl][index as usize].get();
    if offset != 0 { descriptor.wrapping_add(offset as u64) } else { 0 }
}

pub fn control(descriptor: u64) -> u16 {
    header(descriptor).control.get()
}

/// RtlGetOwnerSecurityDescriptor: `owner` e `defaulted` são saídas.
pub fn get_owner(descriptor: u64, owner: u64, defaulted: u64) -> u32 {
    if header(descriptor).revision.get() != 1 {
        return 0xC000_0058;
    }
    let control = control(descriptor);
    out::<u64>(owner).set(component(descriptor, control, 0));
    out::<u8>(defaulted).set((control & 1) as u8);
    0
}

/// RtlGetDaclSecurityDescriptor: ponteiro e origem só com a DACL presente.
pub fn get_dacl(descriptor: u64, present: u64, acl_pointer: u64, defaulted: u64) -> u32 {
    if header(descriptor).revision.get() != 1 {
        return 0xC000_0058;
    }
    let control = control(descriptor);
    out::<u8>(present).set((control & DACL_PRESENT != 0) as u8);
    if control & DACL_PRESENT != 0 {
        out::<u64>(acl_pointer).set(component(descriptor, control, 3));
        out::<u8>(defaulted).set(((control >> 3) & 1) as u8);
    }
    0
}

/// Tamanho alinhado de um componente; ponteiro zero não ocupa espaço.
fn component_length(pointer: u64, index: u64) -> u32 {
    if pointer == 0 {
        return 0;
    }
    align4(if index < 2 { sid::length(pointer) } else { acl_at(pointer).acl_size.get() as u32 })
}

/// RtlLengthSecurityDescriptor: cabeçalho e componentes no formato compacto,
/// inclusive ponteiros compartilhados ou lacunas de um relativo.
pub fn length(descriptor: u64) -> u32 {
    let control = control(descriptor);
    let mut size = if control & SELF_RELATIVE != 0 { RELATIVE_HEADER } else { SecurityDescriptor::SIZE as u32 };
    for index in 0..4 {
        size += component_length(component(descriptor, control, index), index);
    }
    size
}

/// RtlAbsoluteToSelfRelativeSD: só a falha por espaço troca a capacidade
/// pelo tamanho necessário. Ordem compacta: SACL, DACL, dono, grupo.
pub fn absolute_to_relative(descriptor: u64, destination: u64, capacity_pointer: u64) -> u32 {
    let control = control(descriptor);
    if control & SELF_RELATIVE != 0 {
        return 0xC000_00E7;
    }
    let mut pointers = [0u64; 4];
    let mut lengths = [0u32; 4];
    let mut required = RELATIVE_HEADER;
    for index in 0..4 {
        pointers[index] = component(descriptor, control, index as u64);
        lengths[index] = component_length(pointers[index], index as u64);
        required += lengths[index];
    }
    let capacity = out::<u32>(capacity_pointer);
    if capacity.get() < required {
        capacity.set(required);
        return 0xC000_0023;
    }
    if destination == 0 {
        return 0xC000_000D;
    }
    guest::write_bytes(destination, &alloc::vec![0u8; required as usize]);
    let source = header(descriptor);
    let relative = header(destination);
    relative.revision.set(source.revision.get());
    relative.sbz1.set(source.sbz1.get());
    relative.control.set(source.control.get());
    let offsets = [&relative.owner, &relative.group, &relative.sacl, &relative.dacl];
    let mut offset = RELATIVE_HEADER;
    for index in [2usize, 3, 0, 1] {
        if lengths[index] != 0 {
            guest::write_bytes(destination.wrapping_add(offset as u64), &guest::read_bytes(pointers[index], lengths[index] as usize));
            offsets[index].set(offset);
            offset += lengths[index];
        }
    }
    relative.control.set(control | SELF_RELATIVE);
    0
}

/// RtlGetAce: percorre os tamanhos declarados até o índice, escrevendo cada
/// endereço visitado na saída (ordem de escritas das falhas nativas).
pub fn get_ace(acl_pointer: u64, index: u32, output: u64) -> u32 {
    let header = acl_at(acl_pointer);
    let revision = header.acl_revision.get();
    if !(2..=4).contains(&revision) || index >= header.ace_count.get() as u32 {
        return 0xC000_000D;
    }
    let end = acl_pointer.wrapping_add(header.acl_size.get() as u64);
    let mut current = acl_pointer.wrapping_add(Acl::SIZE);
    let output = out::<u64>(output);
    output.set(current);
    for _ in 0..index {
        if current >= end {
            return 0xC000_000D;
        }
        // RtlGetAce não valida a ACL: um AceSize ímpar desalinharia a próxima
        // entrada, então o campo é lido pelo offset, sem referência.
        current = current.wrapping_add(guest::read::<u16>(current + offset_of!(AceHeader, ace_size) as u64) as u64);
        output.set(current);
    }
    if current < end { 0 } else { 0xC000_000D }
}

/// RtlValidSecurityDescriptor.
pub fn valid(descriptor: u64) -> bool {
    if header(descriptor).revision.get() != 1 {
        return false;
    }
    let control = control(descriptor);
    [0u64, 1, 3, 2].iter().all(|&index| {
        let pointer = component(descriptor, control, index);
        pointer == 0 || if index < 2 { sid::valid(pointer) } else { acl::valid(pointer) }
    })
}

/// RtlValidRelativeSecurityDescriptor: offsets e limites dentro de `size`;
/// `required` exige proprietário (bit 0) e grupo (bit 1).
pub fn valid_relative(descriptor: u64, size: u32, required: u32) -> bool {
    if size < RELATIVE_HEADER {
        return false;
    }
    let relative = header(descriptor);
    if relative.revision.get() != 1 {
        return false;
    }
    let control = relative.control.get();
    if control & SELF_RELATIVE == 0 {
        return false;
    }
    let offsets = [&relative.owner, &relative.group, &relative.sacl, &relative.dacl];
    for index in [0usize, 1, 3, 2] {
        if (index == 2 && control & SACL_PRESENT == 0) || (index == 3 && control & DACL_PRESENT == 0) {
            continue;
        }
        let offset = offsets[index].get();
        if offset == 0 {
            if index < 2 && required & (1 << index) != 0 {
                return false;
            }
            continue;
        }
        if offset < RELATIVE_HEADER || offset & 3 != 0 || offset >= size || size - offset < if index < 2 { 12 } else { 8 } {
            return false;
        }
        let pointer = descriptor.wrapping_add(offset as u64);
        if index < 2 {
            let identifier = sid::at(pointer);
            let count = identifier.sub_authority_count.get() as u32;
            if identifier.revision.get() != 1 || count > 15 || size - offset < 8 + count * 4 {
                return false;
            }
        } else if acl_at(pointer).acl_size.get() as u32 > size - offset || !acl::valid(pointer) {
            return false;
        }
    }
    true
}

// ---- construção e escrita (RtlCreate/Set*SecurityDescriptor) ----------------

const OWNER_DEFAULTED: u16 = 0x0001;
const DACL_DEFAULTED: u16 = 0x0008;
const SACL_DEFAULTED: u16 = 0x0020;
const STATUS_UNKNOWN_REVISION: u32 = 0xC000_0058;
const STATUS_INVALID_SECURITY_DESCR: u32 = 0xC000_0079;

fn set_control(descriptor: u64, control: u16) {
    absolute(descriptor).control.set(control);
}

/// RtlCreateSecurityDescriptor: zera o descritor absoluto de 0x28 bytes e
/// grava a revisão 1; só a revisão 1 é aceita.
pub fn create(descriptor: u64, revision: u32) -> u32 {
    if revision != 1 {
        return STATUS_UNKNOWN_REVISION;
    }
    guest::write_bytes(descriptor, &[0u8; SecurityDescriptor::SIZE as usize]);
    absolute(descriptor).revision.set(1);
    0
}

/// Revisão 1 e descritor absoluto (não self-relative) para as escritas.
fn writable(descriptor: u64) -> Option<u32> {
    if header(descriptor).revision.get() != 1 {
        Some(STATUS_UNKNOWN_REVISION)
    } else if control(descriptor) & SELF_RELATIVE != 0 {
        Some(STATUS_INVALID_SECURITY_DESCR)
    } else {
        None
    }
}

/// RtlSetDaclSecurityDescriptor.
pub fn set_dacl(descriptor: u64, present: bool, dacl: u64, defaulted: bool) -> u32 {
    if let Some(status) = writable(descriptor) {
        return status;
    }
    let mut value = control(descriptor);
    if !present {
        value &= !DACL_PRESENT;
        set_control(descriptor, value);
        return 0;
    }
    value |= DACL_PRESENT;
    absolute(descriptor).dacl.set(dacl);
    value &= !DACL_DEFAULTED;
    if defaulted {
        value |= DACL_DEFAULTED;
    }
    set_control(descriptor, value);
    0
}

/// RtlSetSaclSecurityDescriptor.
pub fn set_sacl(descriptor: u64, present: bool, sacl: u64, defaulted: bool) -> u32 {
    if let Some(status) = writable(descriptor) {
        return status;
    }
    let mut value = control(descriptor);
    if !present {
        value &= !SACL_PRESENT;
        set_control(descriptor, value);
        return 0;
    }
    value |= SACL_PRESENT;
    absolute(descriptor).sacl.set(sacl);
    value &= !SACL_DEFAULTED;
    if defaulted {
        value |= SACL_DEFAULTED;
    }
    set_control(descriptor, value);
    0
}

/// RtlSetOwnerSecurityDescriptor (não há bit "present" para o proprietário).
pub fn set_owner(descriptor: u64, owner: u64, defaulted: bool) -> u32 {
    if let Some(status) = writable(descriptor) {
        return status;
    }
    absolute(descriptor).owner.set(owner);
    let mut value = control(descriptor) & !OWNER_DEFAULTED;
    if defaulted {
        value |= OWNER_DEFAULTED;
    }
    set_control(descriptor, value);
    0
}

// ---- captura (SeCapture/ReleaseSecurityDescriptor) --------------------------

const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// SeCaptureSecurityDescriptor: devolve em `*output` uma cópia self-relative
/// do descritor na arena do convidado (ou NULL se a entrada for NULL),
/// validando antes de copiar. Devolve o NTSTATUS.
pub fn capture(input: u64, output: u64) -> u32 {
    let output = out::<u64>(output);
    if input == 0 {
        output.set(0);
        return 0;
    }
    if !valid(input) {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    let length = length(input) as u64;
    let captured = guest::alloc_bytes(length);
    if control(input) & SELF_RELATIVE != 0 {
        guest::write_bytes(captured, &guest::read_bytes(input, length as usize));
    } else {
        // A capacidade é um ULONG do chamador na rotina nativa.
        let capacity = guest::alloc_bytes(4);
        out::<u32>(capacity).set(length as u32);
        let status = absolute_to_relative(input, captured, capacity);
        guest::free_bytes(capacity);
        if status != 0 {
            guest::free_bytes(captured);
            return status;
        }
    }
    output.set(captured);
    0
}

/// SeReleaseSecurityDescriptor: libera a cópia feita pela captura.
pub fn release_captured(captured: u64) {
    if captured != 0 {
        guest::free_bytes(captured);
    }
}

/// SeConvertStringSecurityDescriptorToSecurityDescriptor: sem parser SDDL
/// nesta plataforma; devolve STATUS_NOT_IMPLEMENTED de forma honesta.
pub fn convert_string_to_descriptor() -> u32 {
    STATUS_NOT_IMPLEMENTED
}

// ---- Self-relative -> absoluto (RtlSelfRelativeToAbsoluteSD, ntoskrnl 19041
// 0x7675b0, com RtlpQuerySecurityDescriptor 0x767b04) -------------------------

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_BAD_DESCRIPTOR_FORMAT: u32 = 0xC000_00E7;

/// Bytes do SID (8 + 4n), como o memcpy do original.
fn sid_bytes(sid_pointer: u64) -> u32 {
    8 + 4 * sid::at(sid_pointer).sub_authority_count.get() as u32
}

/// Tamanho do SID como o RtlpQuerySecurityDescriptor informa (8 + 4n,
/// arredondado a 4); ausente = 0.
fn sid_query_length(sid_pointer: u64) -> u32 {
    if sid_pointer == 0 { 0 } else { align4(sid_bytes(sid_pointer)) }
}

/// AclSize arredondado a 4; ausente = 0.
fn acl_query_length(acl_pointer: u64) -> u32 {
    if acl_pointer == 0 { 0 } else { align4(acl_at(acl_pointer).acl_size.get() as u32) }
}

/// Cópia em bloco de um componente para o buffer do chamador.
fn copy_component(destination: u64, source: u64, length: u32) {
    guest::write_bytes(destination, &guest::read_bytes(source, length as usize));
}

/// Buffers de saída de RtlSelfRelativeToAbsoluteSD: o SD absoluto (None =
/// NULL), os buffers de cada componente e as capacidades (PULONG in/out).
pub struct AbsoluteBuffers<'a> {
    pub descriptor: Option<&'a SecurityDescriptor>,
    pub descriptor_size: &'a crate::ntos::inc::types::Field<u32>,
    pub dacl: u64,
    pub dacl_size: &'a crate::ntos::inc::types::Field<u32>,
    pub sacl: u64,
    pub sacl_size: &'a crate::ntos::inc::types::Field<u32>,
    pub owner: u64,
    pub owner_size: &'a crate::ntos::inc::types::Field<u32>,
    pub group: u64,
    pub group_size: &'a crate::ntos::inc::types::Field<u32>,
}

/// RtlSelfRelativeToAbsoluteSD: SD sem SE_SELF_RELATIVE =
/// STATUS_BAD_DESCRIPTOR_FORMAT; se o SD absoluto (0x28) ou algum componente
/// não cabe, grava os cinco tamanhos necessários e devolve
/// STATUS_BUFFER_TOO_SMALL; senão copia os 20 bytes do cabeçalho (os bytes
/// 4..7 do absoluto ficam com o offset do dono, como o memcpy do original),
/// limpa SE_SELF_RELATIVE e os quatro ponteiros, e copia cada componente
/// presente para o buffer dele (SID: 8 + 4n bytes; ACL: AclSize bytes).
pub fn self_relative_to_absolute(relative: u64, out: &AbsoluteBuffers) -> u32 {
    let flags = control(relative);
    if flags & SELF_RELATIVE == 0 {
        return STATUS_BAD_DESCRIPTOR_FORMAT;
    }
    let owner = component(relative, flags, 0);
    let group = component(relative, flags, 1);
    let sacl = component(relative, flags, 2);
    let dacl = component(relative, flags, 3);
    let (owner_length, group_length) = (sid_query_length(owner), sid_query_length(group));
    let (sacl_length, dacl_length) = (acl_query_length(sacl), acl_query_length(dacl));
    let fits = out.descriptor.is_some()
        && out.descriptor_size.get() >= SecurityDescriptor::SIZE as u32
        && owner_length <= out.owner_size.get()
        && dacl_length <= out.dacl_size.get()
        && sacl_length <= out.sacl_size.get()
        && group_length <= out.group_size.get();
    let Some(absolute) = out.descriptor.filter(|_| fits) else {
        out.descriptor_size.set(SecurityDescriptor::SIZE as u32);
        out.group_size.set(group_length);
        out.owner_size.set(owner_length);
        out.sacl_size.set(sacl_length);
        out.dacl_size.set(dacl_length);
        return STATUS_BUFFER_TOO_SMALL;
    };
    copy_component(absolute.address(), relative, RELATIVE_HEADER);
    absolute.control.set(absolute.control.get() & !SELF_RELATIVE);
    for pointer in [&absolute.owner, &absolute.group, &absolute.sacl, &absolute.dacl] {
        pointer.set(0);
    }
    if owner != 0 {
        copy_component(out.owner, owner, sid_bytes(owner));
        absolute.owner.set(out.owner);
    }
    if group != 0 {
        copy_component(out.group, group, sid_bytes(group));
        absolute.group.set(out.group);
    }
    if sacl != 0 {
        copy_component(out.sacl, sacl, acl_at(sacl).acl_size.get() as u32);
        absolute.sacl.set(out.sacl);
    }
    if dacl != 0 {
        copy_component(out.dacl, dacl, acl_at(dacl).acl_size.get() as u32);
        absolute.dacl.set(out.dacl);
    }
    0
}
