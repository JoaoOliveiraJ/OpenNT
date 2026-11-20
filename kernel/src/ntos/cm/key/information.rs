//! Classes de informação de chave.
//!
//! Os offsets pertencem ao contrato de saída; nomes e tamanhos em bytes
//! UTF-16, sem terminador.

use alloc::vec::Vec;

use crate::ntos::cm::registry::{self, KeyCounts, KeyView, NodeId};
use crate::ntos::mm::guest_memory as guest;

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// O que as classes de informação leem de uma chave.
struct Snapshot {
    name: Vec<u16>,
    class: Vec<u16>,
    last_write_time: u64,
    counts: KeyCounts,
}

fn snapshot(key: &KeyView) -> Snapshot {
    Snapshot { name: key.name_utf16(), class: key.class(), last_write_time: key.last_write_time(), counts: key.counts() }
}

/// Basic(0), Node(1), Full(2), Name(3), Cached(4) e HandleTags(7), este
/// com as tags do corpo do handle. Buffer menor que o cabeçalho não recebe
/// dados; nome truncado dá BUFFER_OVERFLOW. A classe da chave, como no
/// CmpPopulateKeyNodeInformation e no CmpPopulateKeyFullInformation do
/// 19041: no Node ela vem depois do nome, com o ClassOffset alinhado a 8;
/// no Full, logo depois do cabeçalho (0x2C). Sem classe, ClassOffset é
/// 0xFFFFFFFF. As contagens e os máximos do Full e do Cached são os do KCB
/// (`registry::KeyView::counts`). Classe acima de 8 é
/// STATUS_INVALID_PARAMETER (NtQueryKey); Flags (5), Virtualization (6) e
/// Trust (8) ainda não são servidas.
pub fn write(node: NodeId, absolute_path: &str, class: u32, output: u64, buffer_length: u32, output_length: u64, handle_tags: u32) -> u32 {
    if let Some(status) = refused(class) {
        return status;
    }
    match registry::with_node(node, snapshot) {
        Some(key) => write_snapshot(&key, absolute_path, class, output, buffer_length, output_length, handle_tags),
        None => 0xC000_017C,
    }
}

/// O NtEnumerateKey: a subchave `index` de `node` na ordem da enumeração
/// (CmEnumerateKey, sem criar KCB para ela). `None` quando não há subchave
/// nesse índice.
pub fn write_child(node: NodeId, index: usize, class: u32, output: u64, buffer_length: u32, output_length: u64) -> Option<u32> {
    if let Some(status) = refused(class) {
        return Some(status);
    }
    let key = registry::with_child_at(node, index, snapshot)?;
    Some(write_snapshot(&key, "", class, output, buffer_length, output_length, 0))
}

fn refused(class: u32) -> Option<u32> {
    if class > 8 {
        return Some(0xC000_000D);
    }
    (class > 4 && class != 7).then_some(0xC000_0003)
}

fn write_snapshot(key: &Snapshot, absolute_path: &str, class: u32, output: u64, buffer_length: u32, output_length: u64, handle_tags: u32) -> u32 {
    // NameInformation usa o caminho absoluto; Basic e Node usam o nome do nó.
    let name: Vec<u16> = if class == 3 { absolute_path.encode_utf16().collect() } else { key.name.clone() };
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
        let counts = key.counts;
        if class == 2 {
            put32(&mut bytes, 12, if class_length != 0 { class_offset as u32 } else { 0xFFFF_FFFF });
            put32(&mut bytes, 16, class_length as u32);
            put32(&mut bytes, 20, counts.subkeys);
            put32(&mut bytes, 24, counts.max_name);
            put32(&mut bytes, 28, counts.max_class);
            put32(&mut bytes, 32, counts.values);
            put32(&mut bytes, 36, counts.max_value_name);
            put32(&mut bytes, 40, counts.max_value_data);
        } else if class == 4 {
            put32(&mut bytes, 12, counts.subkeys);
            put32(&mut bytes, 16, counts.max_name);
            put32(&mut bytes, 20, counts.values);
            put32(&mut bytes, 24, counts.max_value_name);
            put32(&mut bytes, 28, counts.max_value_data);
            put32(&mut bytes, 32, key.name.len() as u32 * 2);
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
