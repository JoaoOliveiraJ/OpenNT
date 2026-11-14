//! Codificação dos descritores de memória e porta: CmResourceTypePort (1),
//! CmResourceTypeMemory (3) e CmResourceTypeMemoryLarge (7).
//!
//! Um comprimento acima de 4 GB não cabe no ULONG Length dos descritores e
//! vai em CmResourceTypeMemoryLarge, com o valor deslocado conforme as
//! bandeiras CM_RESOURCE_MEMORY_LARGE_40 (0x200, unidades de 256 bytes),
//! _48 (0x400, unidades de 64 KB) e _64 (0x800, unidades de 4 GB). As
//! rotinas seguem as do ntoskrnl 19041: a decodificação olha só o tipo 1/3
//! e, fora deles, as bandeiras; a codificação escolhe o menor deslocamento
//! que representa o valor exatamente (STATUS_UNSUCCESSFUL se nenhum
//! representa) e grava início, mínimo e máximo antes de saber se o
//! comprimento cabe.

use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{CmPartialResourceDescriptor, IoResourceDescriptor};

pub const CM_RESOURCE_TYPE_PORT: u8 = 1;
pub const CM_RESOURCE_TYPE_MEMORY: u8 = 3;
pub const CM_RESOURCE_TYPE_MEMORY_LARGE: u8 = 7;
const CM_RESOURCE_MEMORY_LARGE_40: u16 = 0x200;
const CM_RESOURCE_MEMORY_LARGE_48: u16 = 0x400;
const CM_RESOURCE_MEMORY_LARGE_64: u16 = 0x800;
const LARGE_FLAGS: u16 = CM_RESOURCE_MEMORY_LARGE_40 | CM_RESOURCE_MEMORY_LARGE_48 | CM_RESOURCE_MEMORY_LARGE_64;

const STATUS_SUCCESS: u32 = 0;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// (limite, deslocamento, bandeira) de cada forma grande, na ordem testada.
const LARGE_FORMS: [(u64, u32, u16); 3] = [
    (0xFF_FFFF_FF00, 8, CM_RESOURCE_MEMORY_LARGE_40),
    (0xFFFF_FFFF_0000, 16, CM_RESOURCE_MEMORY_LARGE_48),
    (0xFFFF_FFFF_0000_0000, 32, CM_RESOURCE_MEMORY_LARGE_64),
];

/// Tipo 1 ou 3: o comprimento cabe no ULONG sem deslocamento.
fn is_small_type(kind: u8) -> bool {
    kind == CM_RESOURCE_TYPE_PORT || kind == CM_RESOURCE_TYPE_MEMORY
}

/// O deslocamento das bandeiras de um descritor grande (0 = nenhuma).
fn large_shift(flags: u16) -> Option<u32> {
    LARGE_FORMS.iter().find(|&&(_, _, flag)| flags & flag != 0).map(|&(_, shift, _)| shift)
}

/// RtlCmDecodeMemIoResource: o comprimento (0 sem forma reconhecida) e,
/// se pedido, o início.
pub fn cm_decode(descriptor: &CmPartialResourceDescriptor, start: Option<&Field<u64>>) -> u64 {
    let length = descriptor.u.generic.length.get() as u64;
    let length = if is_small_type(descriptor.type_.get()) { length } else { large_shift(descriptor.flags.get()).map_or(0, |shift| length << shift) };
    if let Some(start) = start {
        start.set(descriptor.u.generic.start.quad_part.get() as u64);
    }
    length
}

/// O valor deslocado que representa `value` exatamente na forma grande.
fn encode_large(value: u64) -> Option<(u32, u16)> {
    let &(_, shift, flag) = LARGE_FORMS.iter().find(|&&(limit, _, _)| value <= limit)?;
    let shifted = (value >> shift) as u32;
    ((shifted as u64) << shift == value).then_some((shifted, flag))
}

/// RtlCmEncodeMemIoResource(Descriptor, Type, Length, Start).
pub fn cm_encode(descriptor: &CmPartialResourceDescriptor, kind: u8, length: u64, start: u64) -> u32 {
    let large_capable = kind == CM_RESOURCE_TYPE_MEMORY || kind == CM_RESOURCE_TYPE_MEMORY_LARGE;
    if !large_capable && (kind != CM_RESOURCE_TYPE_PORT || length > u32::MAX as u64) {
        return STATUS_INVALID_PARAMETER;
    }
    descriptor.u.generic.start.quad_part.set(start as i64);
    if kind == CM_RESOURCE_TYPE_PORT {
        descriptor.type_.set(CM_RESOURCE_TYPE_PORT);
        descriptor.u.generic.length.set(length as u32);
        return STATUS_SUCCESS;
    }
    let flags = descriptor.flags.get() & !LARGE_FLAGS;
    descriptor.flags.set(flags);
    if length <= u32::MAX as u64 {
        descriptor.type_.set(CM_RESOURCE_TYPE_MEMORY);
        descriptor.u.generic.length.set(length as u32);
        return STATUS_SUCCESS;
    }
    let Some((shifted, flag)) = encode_large(length) else { return STATUS_UNSUCCESSFUL };
    descriptor.type_.set(CM_RESOURCE_TYPE_MEMORY_LARGE);
    descriptor.flags.set(flags | flag);
    descriptor.u.generic.length.set(shifted);
    STATUS_SUCCESS
}

/// As saídas opcionais do RtlIoDecodeMemIoResource.
pub struct IoDecodeOutputs<'a> {
    pub alignment: Option<&'a Field<u64>>,
    pub minimum: Option<&'a Field<u64>>,
    pub maximum: Option<&'a Field<u64>>,
}

/// RtlIoDecodeMemIoResource: o comprimento; alinhamento, mínimo e máximo
/// nas saídas pedidas.
pub fn io_decode(descriptor: &IoResourceDescriptor, outputs: &IoDecodeOutputs) -> u64 {
    let memory = &descriptor.u.memory;
    let (length, alignment) = (memory.length.get() as u64, memory.alignment.get() as u64);
    let (length, alignment) = if is_small_type(descriptor.type_.get()) {
        (length, alignment)
    } else {
        large_shift(descriptor.flags.get()).map_or((0, 0), |shift| (length << shift, alignment << shift))
    };
    if let Some(output) = outputs.alignment {
        output.set(alignment);
    }
    if let Some(output) = outputs.minimum {
        output.set(memory.minimum_address.quad_part.get() as u64);
    }
    if let Some(output) = outputs.maximum {
        output.set(memory.maximum_address.quad_part.get() as u64);
    }
    length
}

/// O alinhamento deslocado da forma grande: dobra o alinhamento até ele
/// caber exato no ULONG deslocado (sem estouro), como o original.
fn encode_alignment(mut alignment: u64, shift: u32) -> Option<u32> {
    loop {
        let shifted = alignment >> shift;
        let truncated = if shift == 32 { shifted } else { shifted as u32 as u64 };
        if truncated << shift == alignment {
            return Some(truncated as u32);
        }
        alignment = alignment.checked_add(alignment)?;
    }
}

/// Os argumentos do RtlIoEncodeMemIoResource.
pub struct IoEncodeRequest {
    pub kind: u8,
    pub length: u64,
    pub alignment: u64,
    pub minimum: u64,
    pub maximum: u64,
}

/// RtlIoEncodeMemIoResource.
pub fn io_encode(descriptor: &IoResourceDescriptor, request: &IoEncodeRequest) -> u32 {
    let IoEncodeRequest { kind, length, alignment, minimum, maximum } = *request;
    let fits = length <= u32::MAX as u64 && alignment <= u32::MAX as u64;
    let large_capable = kind == CM_RESOURCE_TYPE_MEMORY || kind == CM_RESOURCE_TYPE_MEMORY_LARGE;
    if !large_capable && (kind != CM_RESOURCE_TYPE_PORT || !fits) {
        return STATUS_INVALID_PARAMETER;
    }
    let memory = &descriptor.u.memory;
    memory.minimum_address.quad_part.set(minimum as i64);
    memory.maximum_address.quad_part.set(maximum as i64);
    if kind == CM_RESOURCE_TYPE_PORT {
        descriptor.type_.set(CM_RESOURCE_TYPE_PORT);
        memory.length.set(length as u32);
        memory.alignment.set(alignment as u32);
        return STATUS_SUCCESS;
    }
    let flags = descriptor.flags.get() & !LARGE_FLAGS;
    descriptor.flags.set(flags);
    if fits {
        descriptor.type_.set(CM_RESOURCE_TYPE_MEMORY);
        memory.length.set(length as u32);
        memory.alignment.set(alignment as u32);
        return STATUS_SUCCESS;
    }
    let Some(&(limit, shift, flag)) = LARGE_FORMS.iter().find(|&&(limit, _, _)| length <= limit) else { return STATUS_UNSUCCESSFUL };
    let shifted_length = length >> shift;
    let truncated_length = if shift == 32 { shifted_length } else { shifted_length as u32 as u64 };
    if truncated_length << shift != length || alignment > limit {
        return STATUS_UNSUCCESSFUL;
    }
    let Some(shifted_alignment) = encode_alignment(alignment, shift) else { return STATUS_UNSUCCESSFUL };
    descriptor.flags.set(flags | flag);
    descriptor.type_.set(CM_RESOURCE_TYPE_MEMORY_LARGE);
    memory.length.set(truncated_length as u32);
    memory.alignment.set(shifted_alignment);
    STATUS_SUCCESS
}

/// RtlFindClosestEncodableLength: o menor comprimento representável
/// maior ou igual ao pedido.
pub fn find_closest_encodable_length(length: u64, rounded: &Field<u64>) -> u32 {
    if length <= u32::MAX as u64 {
        rounded.set(length);
        return STATUS_SUCCESS;
    }
    let mut value = length;
    for &(limit, shift, _) in &LARGE_FORMS {
        if value > limit {
            continue;
        }
        let unit_mask = !((1u64 << shift) - 1);
        let base = value & unit_mask;
        if base == value {
            rounded.set(value);
            return STATUS_SUCCESS;
        }
        value = base.wrapping_add(1u64 << shift);
        rounded.set(value);
        if shift == 32 || value <= limit {
            return STATUS_SUCCESS;
        }
    }
    rounded.set(0);
    STATUS_UNSUCCESSFUL
}
