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
    class: Vec<u16>,
    last_write_time: u64,
    children: Vec<NodeId>,
    /// O tamanho do nome e o do dado de cada valor.
    values: Vec<(u32, u32)>,
}

/// Basic(0), Node(1), Full(2), Name(3), Cached(4) e HandleTags(7), este
/// com as tags do corpo do handle. Buffer menor que o cabeçalho não recebe
/// dados; nome truncado dá BUFFER_OVERFLOW. A classe da chave, como no
/// CmpPopulateKeyNodeInformation e no CmpPopulateKeyFullInformation do
/// 19041: no Node ela vem depois do nome, com o ClassOffset alinhado a 8;
/// no Full, logo depois do cabeçalho (0x2C). Sem classe, ClassOffset é
/// 0xFFFFFFFF. Classe acima de 8 é STATUS_INVALID_PARAMETER (NtQueryKey);
/// Flags (5), Virtualization (6) e Trust (8) ainda não são servidas.
pub fn write(node: NodeId, absolute_path: &str, class: u32, output: u64, buffer_length: u32, output_length: u64, handle_tags: u32) -> u32 {
    if class > 8 {
        return 0xC000_000D;
    }
    if class > 4 && class != 7 {
        return 0xC000_0003;
    }
    let Some(key) = registry::with_node(node, |key| Snapshot {
        name: key.name(),
        class: key.class(),
        last_write_time: key.last_write_time(),
        children: key.children.iter().map(|&(_, child)| child).collect(),
        values: key.value_sizes(),
    }) else {
        return 0xC000_017C;
    };
    // NameInformation usa o caminho absoluto; Basic e Node usam o nome do nó.
    let name: Vec<u16> = if class == 3 { absolute_path.encode_utf16().collect() } else { key.name.encode_utf16().collect() };
    let header = [16usize, 24, 44, 4, 40].get(class as usize).copied().unwrap_or(4);
    let class_length = if matches!(class, 1 | 2) { key.class.len() * 2 } else { 0 };
    // O deslocamento da classe: depois do nome alinhado a 8 (Node) ou do
    // cabeçalho (Full).
    let class_offset = match class {
        1 => (header + name.len() * 2 + 7) & !7,
        _ => header,
    };
    let required = if class_length != 0 { class_offset + class_length } else { header + if matches!(class, 0 | 1 | 3) { name.len() * 2 } else { 0 } };
    // ResultLength e o buffer podem ser de modo usuário (sondados pelo
    // serviço): escritas sondadas, falha = STATUS_ACCESS_VIOLATION.
    if output_length != 0 && guest::try_write::<u32>(output_length, required as u32).is_err() {
        return 0xC000_0005;
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
            put32(&mut bytes, 12, if class_length != 0 { class_offset as u32 } else { 0xFFFF_FFFF });
            put32(&mut bytes, 16, class_length as u32);
            put32(&mut bytes, 20, name.len() as u32 * 2);
        }
        if class == 2 || class == 4 {
            let maximum_subkey = key.children.iter().filter_map(|&child| registry::with_node(child, |child| child.name_length())).max().unwrap_or(0);
            let maximum_value_name = key.values.iter().map(|&(name, _)| name).max().unwrap_or(0);
            let maximum_value_data = key.values.iter().map(|&(_, data)| data).max().unwrap_or(0);
            if class == 2 {
                let maximum_class = key.children.iter().filter_map(|&child| registry::with_node(child, |child| child.class_length())).max().unwrap_or(0);
                put32(&mut bytes, 12, if class_length != 0 { class_offset as u32 } else { 0xFFFF_FFFF });
                put32(&mut bytes, 16, class_length as u32);
                put32(&mut bytes, 20, key.children.len() as u32);
                put32(&mut bytes, 24, maximum_subkey);
                put32(&mut bytes, 28, maximum_class);
                put32(&mut bytes, 32, key.values.len() as u32);
                put32(&mut bytes, 36, maximum_value_name);
                put32(&mut bytes, 40, maximum_value_data);
            } else {
                put32(&mut bytes, 12, key.children.len() as u32);
                put32(&mut bytes, 16, maximum_subkey);
                put32(&mut bytes, 20, key.values.len() as u32);
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
    if class_length != 0 {
        for (index, unit) in key.class.iter().enumerate() {
            bytes[class_offset + index * 2..class_offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    if guest::try_write_bytes(output, &bytes[..required.min(buffer_length as usize)]).is_err() {
        return 0xC000_0005;
    }
    if (buffer_length as usize) < required { 0x8000_0005 } else { 0 }
}
