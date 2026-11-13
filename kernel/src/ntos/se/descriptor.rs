//! SECURITY_DESCRIPTOR absoluto ou relativo — `system32/ntos/se/descriptor.js`.
//!
//! Leitura, validação, conversão e captura (cópia self-relative na arena do
//! convidado); componentes e entradas de ACL são acessados na memória do
//! convidado.

use super::{acl, sid};
use crate::ntos::mm::guest_memory as guest;

const SELF_RELATIVE: u16 = 0x8000;
const DACL_PRESENT: u16 = 4;
const SACL_PRESENT: u16 = 16;

fn align4(size: u32) -> u32 {
    (size + 3) & !3
}

/// Índices: proprietário, grupo, SACL, DACL. O modo relativo guarda offsets
/// de 32 bits; o absoluto, ponteiros de 64 bits.
pub fn component(descriptor: u64, control: u16, index: u64) -> u64 {
    if (index == 2 && control & SACL_PRESENT == 0) || (index == 3 && control & DACL_PRESENT == 0) {
        return 0;
    }
    if control & SELF_RELATIVE == 0 {
        return guest::read64(descriptor.wrapping_add(8 + index * 8));
    }
    let offset = guest::read32(descriptor.wrapping_add(4 + index * 4));
    if offset != 0 { descriptor.wrapping_add(offset as u64) } else { 0 }
}

pub fn control(descriptor: u64) -> u16 {
    guest::read16(descriptor.wrapping_add(2))
}

/// RtlGetOwnerSecurityDescriptor: `owner` e `defaulted` são saídas.
pub fn get_owner(descriptor: u64, owner: u64, defaulted: u64) -> u32 {
    if guest::read8(descriptor) != 1 {
        return 0xC000_0058;
    }
    let control = control(descriptor);
    guest::write64(owner, component(descriptor, control, 0));
    guest::write8(defaulted, (control & 1) as u8);
    0
}

/// RtlGetDaclSecurityDescriptor: ponteiro e origem só com a DACL presente.
pub fn get_dacl(descriptor: u64, present: u64, acl_pointer: u64, defaulted: u64) -> u32 {
    if guest::read8(descriptor) != 1 {
        return 0xC000_0058;
    }
    let control = control(descriptor);
    guest::write8(present, (control & DACL_PRESENT != 0) as u8);
    if control & DACL_PRESENT != 0 {
        guest::write64(acl_pointer, component(descriptor, control, 3));
        guest::write8(defaulted, ((control >> 3) & 1) as u8);
    }
    0
}

/// Tamanho alinhado de um componente; ponteiro zero não ocupa espaço.
fn component_length(pointer: u64, index: u64) -> u32 {
    if pointer == 0 {
        return 0;
    }
    align4(if index < 2 { sid::length(pointer) } else { guest::read16(pointer.wrapping_add(2)) as u32 })
}

/// RtlLengthSecurityDescriptor: cabeçalho e componentes no formato compacto,
/// inclusive ponteiros compartilhados ou lacunas de um relativo.
pub fn length(descriptor: u64) -> u32 {
    let control = control(descriptor);
    let mut size = if control & SELF_RELATIVE != 0 { 20 } else { 40 };
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
    let mut required = 20;
    for index in 0..4 {
        pointers[index] = component(descriptor, control, index as u64);
        lengths[index] = component_length(pointers[index], index as u64);
        required += lengths[index];
    }
    if guest::read32(capacity_pointer) < required {
        guest::write32(capacity_pointer, required);
        return 0xC000_0023;
    }
    if destination == 0 {
        return 0xC000_000D;
    }
    for offset in 0..required as u64 {
        guest::write8(destination.wrapping_add(offset), 0);
    }
    guest::write32(destination, guest::read32(descriptor));
    let mut offset = 20u32;
    for index in [2usize, 3, 0, 1] {
        if lengths[index] != 0 {
            for byte in 0..lengths[index] as u64 {
                guest::write8(destination.wrapping_add(offset as u64 + byte), guest::read8(pointers[index].wrapping_add(byte)));
            }
            guest::write32(destination.wrapping_add(4 + index as u64 * 4), offset);
            offset += lengths[index];
        }
    }
    guest::write16(destination.wrapping_add(2), control | SELF_RELATIVE);
    0
}

/// RtlGetAce: percorre os tamanhos declarados até o índice, escrevendo cada
/// endereço visitado na saída (ordem de escritas das falhas nativas).
pub fn get_ace(acl_pointer: u64, index: u32, output: u64) -> u32 {
    let revision = guest::read8(acl_pointer);
    if !(2..=4).contains(&revision) || index >= guest::read16(acl_pointer.wrapping_add(4)) as u32 {
        return 0xC000_000D;
    }
    let end = acl_pointer.wrapping_add(guest::read16(acl_pointer.wrapping_add(2)) as u64);
    let mut current = acl_pointer.wrapping_add(8);
    guest::write64(output, current);
    for _ in 0..index {
        if current >= end {
            return 0xC000_000D;
        }
        current = current.wrapping_add(guest::read16(current.wrapping_add(2)) as u64);
        guest::write64(output, current);
    }
    if current < end { 0 } else { 0xC000_000D }
}

/// RtlValidSecurityDescriptor.
pub fn valid(descriptor: u64) -> bool {
    if guest::read8(descriptor) != 1 {
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
    if size < 20 || guest::read8(descriptor) != 1 {
        return false;
    }
    let control = control(descriptor);
    if control & SELF_RELATIVE == 0 {
        return false;
    }
    for index in [0u64, 1, 3, 2] {
        if (index == 2 && control & SACL_PRESENT == 0) || (index == 3 && control & DACL_PRESENT == 0) {
            continue;
        }
        let offset = guest::read32(descriptor.wrapping_add(4 + index * 4));
        if offset == 0 {
            if index < 2 && required & (1 << index) != 0 {
                return false;
            }
            continue;
        }
        if offset < 20 || offset & 3 != 0 || offset >= size || size - offset < if index < 2 { 12 } else { 8 } {
            return false;
        }
        let pointer = descriptor.wrapping_add(offset as u64);
        if index < 2 {
            let count = guest::read8(pointer.wrapping_add(1)) as u32;
            if guest::read8(pointer) != 1 || count > 15 || size - offset < 8 + count * 4 {
                return false;
            }
        } else if guest::read16(pointer.wrapping_add(2)) as u32 > size - offset || !acl::valid(pointer) {
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
    guest::write16(descriptor.wrapping_add(2), control);
}

/// RtlCreateSecurityDescriptor: zera o descritor absoluto de 0x28 bytes e
/// grava a revisão 1; só a revisão 1 é aceita.
pub fn create(descriptor: u64, revision: u32) -> u32 {
    if revision != 1 {
        return STATUS_UNKNOWN_REVISION;
    }
    guest::write_bytes(descriptor, &[0u8; 0x28]);
    guest::write8(descriptor, 1);
    0
}

/// Revisão 1 e descritor absoluto (não self-relative) para as escritas.
fn writable(descriptor: u64) -> Option<u32> {
    if guest::read8(descriptor) != 1 {
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
    guest::write64(descriptor.wrapping_add(0x20), dacl);
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
    guest::write64(descriptor.wrapping_add(0x18), sacl);
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
    guest::write64(descriptor.wrapping_add(0x08), owner);
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
    if input == 0 {
        guest::write64(output, 0);
        return 0;
    }
    if !valid(input) {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    let length = length(input) as u64;
    let captured = guest::alloc_bytes(length);
    if guest::read16(input + 2) & SELF_RELATIVE != 0 {
        for offset in 0..length {
            guest::write8(captured + offset, guest::read8(input + offset));
        }
    } else {
        let capacity = guest::alloc_bytes(4);
        guest::write32(capacity, length as u32);
        let status = absolute_to_relative(input, captured, capacity);
        guest::free_bytes(capacity);
        if status != 0 {
            guest::free_bytes(captured);
            return status;
        }
    }
    guest::write64(output, captured);
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
