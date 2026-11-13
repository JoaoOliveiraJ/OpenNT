//! Classes de informação de chave.
//!
//! Os offsets pertencem ao contrato de saída; nomes e tamanhos em bytes
//! UTF-16, sem terminador.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::mm::guest_memory as guest;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn utf16_length(text: &str) -> u32 {
    text.encode_utf16().count() as u32 * 2
}

struct Snapshot {
    name: String,
    last_write_time: u64,
    children: Vec<NodeId>,
    value_names: Vec<u32>,
    value_data: Vec<u32>,
}

/// Basic(0), Node(1), Full(2), Name(3), Cached(4) e HandleTags(7). Buffer
/// menor que o cabeçalho não recebe dados; nome truncado dá BUFFER_OVERFLOW.
pub fn write(node: NodeId, absolute_path: &str, class: u32, output: u64, buffer_length: u32, output_length: u64, handle_tags: u32) -> u32 {
    if class > 4 && class != 7 {
        return 0xC000_0003;
    }
    let Some(key) = registry::with_node(node, |key| Snapshot {
        name: key.name.clone(),
        last_write_time: key.last_write_time,
        children: key.children.iter().map(|&(_, child)| child).collect(),
        value_names: key.values.iter().map(|(_, value)| utf16_length(&value.name)).collect(),
        value_data: key.values.iter().map(|(_, value)| value.data.len() as u32).collect(),
    }) else {
        return 0xC000_017C;
    };
    // NameInformation usa o caminho absoluto; Basic e Node usam o nome do nó.
    let name: Vec<u16> = if class == 3 { absolute_path.encode_utf16().collect() } else { key.name.encode_utf16().collect() };
    let header = [16usize, 24, 44, 4, 40].get(class as usize).copied().unwrap_or(4);
    let required = header + if matches!(class, 0 | 1 | 3) { name.len() * 2 } else { 0 };
    if output_length != 0 {
        guest::write32(output_length, required as u32);
    }
    if (buffer_length as usize) < header {
        return 0xC000_0023;
    }
    // Resposta privada zerada antes de tocar a saída.
    let mut bytes = alloc::vec![0u8; required];
    if class == 7 {
        put32(&mut bytes, 0, handle_tags);
    } else if class == 3 {
        put32(&mut bytes, 0, name.len() as u32 * 2);
    } else {
        put32(&mut bytes, 0, key.last_write_time as u32);
        put32(&mut bytes, 4, (key.last_write_time >> 32) as u32);
        if class == 0 {
            put32(&mut bytes, 12, name.len() as u32 * 2);
        }
        if class == 1 {
            // A hive não armazena string de classe: marcador sem classe.
            put32(&mut bytes, 12, 0xFFFF_FFFF);
            put32(&mut bytes, 20, name.len() as u32 * 2);
        }
        if class == 2 || class == 4 {
            let maximum_subkey = key.children.iter().filter_map(|&child| registry::with_node(child, |child| utf16_length(&child.name))).max().unwrap_or(0);
            let maximum_value_name = key.value_names.iter().copied().max().unwrap_or(0);
            let maximum_value_data = key.value_data.iter().copied().max().unwrap_or(0);
            if class == 2 {
                put32(&mut bytes, 12, 0xFFFF_FFFF);
                put32(&mut bytes, 20, key.children.len() as u32);
                put32(&mut bytes, 24, maximum_subkey);
                put32(&mut bytes, 32, key.value_names.len() as u32);
                put32(&mut bytes, 36, maximum_value_name);
                put32(&mut bytes, 40, maximum_value_data);
            } else {
                put32(&mut bytes, 12, key.children.len() as u32);
                put32(&mut bytes, 16, maximum_subkey);
                put32(&mut bytes, 20, key.value_names.len() as u32);
                put32(&mut bytes, 24, maximum_value_name);
                put32(&mut bytes, 28, maximum_value_data);
                put32(&mut bytes, 32, utf16_length(&key.name));
            }
        }
    }
    if matches!(class, 0 | 1 | 3) {
        for (index, unit) in name.iter().enumerate() {
            bytes[header + index * 2..header + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    guest::write_bytes(output, &bytes[..required.min(buffer_length as usize)]);
    if (buffer_length as usize) < required { 0x8000_0005 } else { 0 }
}
