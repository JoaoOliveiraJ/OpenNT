//! Serialização das classes de ZwQueryObject.
//!
//! Comprimentos em bytes; cada classe tem sua regra de capacidade e
//! alinhamento.

use alloc::string::String;
use alloc::vec::Vec;

use super::object_types::ObjectType;
use crate::ntos::mm::guest_memory as guest;

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

/// Dados do objeto consultado.
#[derive(Clone)]
pub struct ObjectInformation {
    pub attributes: u32,
    pub object_flags: u32,
    pub access: u32,
    pub handles: u32,
    pub references: u32,
    pub paged_charge: u32,
    pub nonpaged_charge: u32,
    pub name: Option<String>,
    pub object_type: ObjectType,
    pub security_length: u32,
    pub creation_time: u64,
}

/// Resultado: NTSTATUS e o tamanho exigido (quando a classe o informa).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Formatted {
    pub status: u32,
    pub needed: Option<u32>,
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// 104 bytes fixos mais o nome com terminador, arredondado a oito.
pub fn type_size(object_type: &ObjectType) -> u32 {
    let length = units(&object_type.name).len() as u32 * 2 + 2;
    104 + length.div_ceil(8) * 8
}

/// OBJECT_TYPE_INFORMATION: contadores e mapeamento do OBJECT_TYPE e o nome.
/// `offset` entra no tamanho total quando vários tipos dividem o buffer.
pub fn type_info(object_type: &ObjectType, buffer: u64, length: u32, offset: u32) -> Formatted {
    let required = offset + type_size(object_type);
    if length < required {
        return Formatted { status: STATUS_INFO_LENGTH_MISMATCH, needed: Some(required) };
    }
    let source = object_type.pointer;
    for (destination, from) in [(16u64, 0x2Cu64), (20, 0x30), (40, 0x34), (44, 0x38), (64, 0x48), (68, 0x4C), (72, 0x50), (76, 0x54), (80, 0x58), (84, 0x5C), (92, 0x64), (96, 0x68), (100, 0x6C)] {
        guest::write32(buffer + destination, guest::read32(source + from));
    }
    let flags = guest::read8(source + 0x42);
    guest::write8(buffer + 88, (flags >> 3) & 1);
    guest::write8(buffer + 89, (flags >> 4) & 1);
    guest::write8(buffer + 90, guest::read8(source + 0x28));
    guest::write8(buffer + 91, 0);
    let name = units(&object_type.name);
    guest::write16(buffer, name.len() as u16 * 2);
    guest::write16(buffer + 2, name.len() as u16 * 2 + 2);
    guest::write64(buffer + 8, buffer + 104);
    for (index, &unit) in name.iter().enumerate() {
        guest::write16(buffer + 104 + index as u64 * 2, unit);
    }
    guest::write16(buffer + 104 + name.len() as u64 * 2, 0);
    Formatted { status: 0, needed: Some(required) }
}

/// Classes 0 (básica), 1 (nome), 2 (tipo), 3 (todos os tipos) e 4 (flags
/// do handle). Buffers curtos informam o tamanho exigido pela classe.
pub fn format(information: &ObjectInformation, class: u32, buffer: u64, length: u32, types: &[ObjectType]) -> Formatted {
    match class {
        // A lista começa pela quantidade e guarda o status do último item.
        3 => {
            if length < 4 {
                return Formatted { status: STATUS_INFO_LENGTH_MISMATCH, needed: Some(8) };
            }
            guest::write32(buffer, types.len() as u32);
            let mut required = 8;
            let mut status = 0;
            for object_type in types {
                let result = type_info(object_type, buffer + required as u64, length, required);
                required = result.needed.unwrap_or(required);
                status = result.status;
            }
            Formatted { status, needed: Some(required) }
        }
        // A estrutura básica exige exatamente 56 bytes, reservados zerados.
        0 => {
            if length != 56 {
                return Formatted { status: STATUS_INFO_LENGTH_MISMATCH, needed: None };
            }
            guest::write_bytes(buffer, &[0; 56]);
            let name_length = information.name.as_deref().map_or(0, |name| 18 + units(name).len() as u32 * 2);
            for (offset, value) in [
                (0u64, information.attributes | information.object_flags),
                (4, information.access),
                (8, information.handles),
                (12, information.references),
                (16, information.paged_charge),
                (20, information.nonpaged_charge),
                (36, name_length),
                (40, 106 + units(&information.object_type.name).len() as u32 * 2),
                (44, information.security_length),
            ] {
                guest::write32(buffer + offset, value);
            }
            guest::write64(buffer + 48, information.creation_time);
            Formatted { status: 0, needed: Some(56) }
        }
        1 => {
            let name = units(information.name.as_deref().unwrap_or(""));
            let required = if name.is_empty() { 16 } else { 18 + name.len() as u32 * 2 };
            if length < required {
                return Formatted { status: STATUS_INFO_LENGTH_MISMATCH, needed: Some(required) };
            }
            guest::write16(buffer, name.len() as u16 * 2);
            guest::write16(buffer + 2, if name.is_empty() { 0 } else { name.len() as u16 * 2 + 2 });
            guest::write32(buffer + 4, 0);
            guest::write64(buffer + 8, if name.is_empty() { 0 } else { buffer + 16 });
            if !name.is_empty() {
                for (index, &unit) in name.iter().enumerate() {
                    guest::write16(buffer + 16 + index as u64 * 2, unit);
                }
                guest::write16(buffer + 16 + name.len() as u64 * 2, 0);
            }
            Formatted { status: 0, needed: Some(required) }
        }
        2 => type_info(&information.object_type, buffer, length, 0),
        // ProtectFromClose e Inherit.
        4 => {
            if length < 2 {
                return Formatted { status: STATUS_INFO_LENGTH_MISMATCH, needed: Some(2) };
            }
            guest::write8(buffer, (information.attributes & 2 != 0) as u8);
            guest::write8(buffer + 1, (information.attributes & 1 != 0) as u8);
            Formatted { status: 0, needed: Some(2) }
        }
        _ => Formatted { status: 0xC000_0003, needed: None },
    }
}
