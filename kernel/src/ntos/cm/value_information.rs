//! Classes KEY_VALUE_*.
//!
//! Preserva cabeçalhos, alinhamento dos dados e os retornos distintos para
//! buffer insuficiente e resultado truncado.

use alloc::vec::Vec;

use super::registry::Value;
use crate::ntos::mm::guest_memory as guest;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Basic(0), Full(1), Partial(2), FullAlign64(3), PartialAlign64(4).
pub fn write(value: &Value, class: u32, output: u64, buffer_length: u32, output_length: u64) -> u32 {
    if class > 4 {
        return 0xC000_0003;
    }
    // As variantes Align64 exigem saída alinhada antes de gravar o tamanho.
    if class >= 3 && output & 7 != 0 {
        return 0x8000_0002;
    }
    let name: Vec<u16> = value.name.encode_utf16().collect();
    let name_length = name.len() * 2;
    let data_length = value.data.len();
    let header = match class {
        1 | 3 => 20,
        4 => 8,
        _ => 12,
    };
    let name_offset = if class == 0 { 12 } else { 20 };
    let mut data_offset = header;
    if class == 1 || class == 3 {
        let alignment = if class == 3 { 8 } else { 4 };
        data_offset = (header + name_length).div_ceil(alignment) * alignment;
    }
    let required = if class == 0 { header + name_length } else { data_offset + data_length };
    // O tamanho exigido é publicado mesmo sem espaço para o cabeçalho.
    if output_length != 0 {
        guest::write32(output_length, required as u32);
    }
    if (buffer_length as usize) < header {
        return 0xC000_0023;
    }
    let mut bytes = alloc::vec![0u8; required];
    put32(&mut bytes, if class == 4 { 0 } else { 4 }, value.value_type);
    match class {
        0 => put32(&mut bytes, 8, name_length as u32),
        1 | 3 => {
            put32(&mut bytes, 8, data_offset as u32);
            put32(&mut bytes, 12, data_length as u32);
            put32(&mut bytes, 16, name_length as u32);
        }
        _ => put32(&mut bytes, if class == 4 { 4 } else { 8 }, data_length as u32),
    }
    if matches!(class, 0 | 1 | 3) {
        for (index, unit) in name.iter().enumerate() {
            bytes[name_offset + index * 2..name_offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    if class != 0 {
        bytes[data_offset..data_offset + data_length].copy_from_slice(&value.data);
    }
    // A cópia truncada preserva o cabeçalho e devolve BUFFER_OVERFLOW.
    guest::write_bytes(output, &bytes[..required.min(buffer_length as usize)]);
    if (buffer_length as usize) < required { 0x8000_0005 } else { 0 }
}
