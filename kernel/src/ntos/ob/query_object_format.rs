//! Serialização das classes de ZwQueryObject.
//!
//! Comprimentos em bytes; cada classe tem sua regra de capacidade e
//! alinhamento.

use alloc::string::String;
use alloc::vec::Vec;
use core::mem::offset_of;

use super::object_types::ObjectType;
use crate::ntos::inc::types::{self as nt, NtStruct, ObjectBasicInformation, ObjectHandleFlagInformation, ObjectNameInformation, ObjectTypeInformation, ObjectTypesInformation};
use crate::ntos::mm::guest_memory::{self as guest, GuestScalar};

/// Campo de uma estrutura de saída no buffer do chamador. O NtQueryObject
/// aceita buffers alinhados só a ULONG, então os campos são escritos pelo
/// offset do tipo (um MOV da largura do campo), sem exigir o alinhamento
/// natural da estrutura inteira.
fn put<T: GuestScalar>(base: u64, offset: usize, value: T) {
    guest::write(base + offset as u64, value);
}

fn utf16_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

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

/// A estrutura fixa mais o nome com terminador, arredondado a oito.
pub fn type_size(object_type: &ObjectType) -> u32 {
    let length = units(&object_type.name).len() as u32 * 2 + 2;
    ObjectTypeInformation::SIZE as u32 + length.div_ceil(8) * 8
}

/// OBJECT_TYPE_INFORMATION: contadores e mapeamento do OBJECT_TYPE e o nome.
/// `offset` entra no tamanho total quando vários tipos dividem o buffer.
pub fn type_info(object_type: &ObjectType, buffer: u64, length: u32, offset: u32) -> Formatted {
    let required = offset + type_size(object_type);
    if length < required {
        return Formatted { status: STATUS_INFO_LENGTH_MISMATCH, needed: Some(required) };
    }
    // SAFETY: tipos registrados em `object_types` vivem até o desligamento.
    let source = unsafe { nt::ObjectType::at(object_type.pointer) };
    let info = &source.type_info;
    let generic = &info.generic_mapping;
    for (offset, value) in [
        (offset_of!(ObjectTypeInformation, total_number_of_objects), source.total_number_of_objects.get()),
        (offset_of!(ObjectTypeInformation, total_number_of_handles), source.total_number_of_handles.get()),
        (offset_of!(ObjectTypeInformation, high_water_number_of_objects), source.high_water_number_of_objects.get()),
        (offset_of!(ObjectTypeInformation, high_water_number_of_handles), source.high_water_number_of_handles.get()),
        (offset_of!(ObjectTypeInformation, invalid_attributes), info.invalid_attributes.get()),
        (offset_of!(ObjectTypeInformation, generic_mapping.generic_read), generic.generic_read.get()),
        (offset_of!(ObjectTypeInformation, generic_mapping.generic_write), generic.generic_write.get()),
        (offset_of!(ObjectTypeInformation, generic_mapping.generic_execute), generic.generic_execute.get()),
        (offset_of!(ObjectTypeInformation, generic_mapping.generic_all), generic.generic_all.get()),
        (offset_of!(ObjectTypeInformation, valid_access_mask), info.valid_access_mask.get()),
        (offset_of!(ObjectTypeInformation, pool_type), info.pool_type.get().0 as u32),
        (offset_of!(ObjectTypeInformation, default_paged_pool_charge), info.default_paged_pool_charge.get()),
        (offset_of!(ObjectTypeInformation, default_non_paged_pool_charge), info.default_non_paged_pool_charge.get()),
    ] {
        put::<u32>(buffer, offset, value);
    }
    put::<u8>(buffer, offset_of!(ObjectTypeInformation, security_required), info.security_required());
    put::<u8>(buffer, offset_of!(ObjectTypeInformation, maintain_handle_count), info.maintain_handle_count());
    put::<u8>(buffer, offset_of!(ObjectTypeInformation, type_index), source.index.get());
    put::<u8>(buffer, offset_of!(ObjectTypeInformation, reserved_byte), 0);
    let name = units(&object_type.name);
    let text = buffer + ObjectTypeInformation::SIZE;
    put::<u16>(buffer, offset_of!(ObjectTypeInformation, type_name.length), name.len() as u16 * 2);
    put::<u16>(buffer, offset_of!(ObjectTypeInformation, type_name.maximum_length), name.len() as u16 * 2 + 2);
    put::<u64>(buffer, offset_of!(ObjectTypeInformation, type_name.buffer), text);
    let mut bytes = utf16_bytes(&name);
    bytes.extend_from_slice(&[0, 0]);
    guest::write_bytes(text, &bytes);
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
            put::<u32>(buffer, offset_of!(ObjectTypesInformation, number_of_types), types.len() as u32);
            let mut required = offset_of!(ObjectTypesInformation, type_information) as u32;
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
            if length != ObjectBasicInformation::SIZE as u32 {
                return Formatted { status: STATUS_INFO_LENGTH_MISMATCH, needed: None };
            }
            guest::write_bytes(buffer, &[0; ObjectBasicInformation::SIZE as usize]);
            // NameInfoSize: OBJECT_NAME_INFORMATION mais o texto e o terminador.
            let name_length = information.name.as_deref().map_or(0, |name| ObjectNameInformation::SIZE as u32 + 2 + units(name).len() as u32 * 2);
            // TypeInfoSize: a estrutura fixa mais o nome e o terminador.
            let type_length = ObjectTypeInformation::SIZE as u32 + 2 + units(&information.object_type.name).len() as u32 * 2;
            for (offset, value) in [
                (offset_of!(ObjectBasicInformation, attributes), information.attributes | information.object_flags),
                (offset_of!(ObjectBasicInformation, granted_access), information.access),
                (offset_of!(ObjectBasicInformation, handle_count), information.handles),
                (offset_of!(ObjectBasicInformation, pointer_count), information.references),
                (offset_of!(ObjectBasicInformation, paged_pool_charge), information.paged_charge),
                (offset_of!(ObjectBasicInformation, non_paged_pool_charge), information.nonpaged_charge),
                (offset_of!(ObjectBasicInformation, name_info_size), name_length),
                (offset_of!(ObjectBasicInformation, type_info_size), type_length),
                (offset_of!(ObjectBasicInformation, security_descriptor_size), information.security_length),
            ] {
                put::<u32>(buffer, offset, value);
            }
            put::<u64>(buffer, offset_of!(ObjectBasicInformation, creation_time), information.creation_time);
            Formatted { status: 0, needed: Some(ObjectBasicInformation::SIZE as u32) }
        }
        1 => {
            let name = units(information.name.as_deref().unwrap_or(""));
            let header = ObjectNameInformation::SIZE as u32;
            let required = if name.is_empty() { header } else { header + 2 + name.len() as u32 * 2 };
            if length < required {
                return Formatted { status: STATUS_INFO_LENGTH_MISMATCH, needed: Some(required) };
            }
            let text = buffer + ObjectNameInformation::SIZE;
            // Cabeçalho inteiro, com o preenchimento do UNICODE_STRING zerado.
            guest::write_bytes(buffer, &[0u8; ObjectNameInformation::SIZE as usize]);
            put::<u16>(buffer, offset_of!(ObjectNameInformation, name.length), name.len() as u16 * 2);
            put::<u16>(buffer, offset_of!(ObjectNameInformation, name.maximum_length), if name.is_empty() { 0 } else { name.len() as u16 * 2 + 2 });
            put::<u64>(buffer, offset_of!(ObjectNameInformation, name.buffer), if name.is_empty() { 0 } else { text });
            if !name.is_empty() {
                let mut bytes = utf16_bytes(&name);
                bytes.extend_from_slice(&[0, 0]);
                guest::write_bytes(text, &bytes);
            }
            Formatted { status: 0, needed: Some(required) }
        }
        2 => type_info(&information.object_type, buffer, length, 0),
        // ProtectFromClose e Inherit.
        4 => {
            let size = ObjectHandleFlagInformation::SIZE as u32;
            if length < size {
                return Formatted { status: STATUS_INFO_LENGTH_MISMATCH, needed: Some(size) };
            }
            // SAFETY: estrutura de bytes (alinhamento 1) no buffer do chamador.
            let flags = unsafe { ObjectHandleFlagInformation::at(buffer) };
            flags.inherit.set((information.attributes & 2 != 0) as u8);
            flags.protect_from_close.set((information.attributes & 1 != 0) as u8);
            Formatted { status: 0, needed: Some(size) }
        }
        _ => Formatted { status: 0xC000_0003, needed: None },
    }
}
