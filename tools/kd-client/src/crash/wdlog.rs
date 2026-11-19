//! O log de erros do watchdog de vídeo (WdLog) que o dxgkrnl entrega no
//! bugcheck.
//!
//! O DxgDbgInit do dxgkrnl registra um callback de motivo com o GUID
//! WdDxgkSecondaryDataGUID ({270A33FD-3DA6-460D-BA89-3C1BAE21E39B}); no
//! bugcheck ele copia os anéis do WdLog do watchdog.sys para os dados
//! secundários, que o kernel do OpenNT imprime na serial. O formato:
//!
//! - cabeçalho: um u64 com o número de seções e, para cada uma, um par
//!   (u32 offset, u32 id); pares com id 0 não são seções;
//! - cada seção vai do seu offset até o offset da próxima (ou o fim);
//! - nos anéis, cada entrada tem 0x40 bytes: a sequência, a KTHREAD, o
//!   endereço de retorno (logo depois da chamada `WdLogNewEntry5_*`) e
//!   cinco parâmetros (o status costuma estar no primeiro).
//!
//! Ids vistos: 0x11 asserções, 0x12 erros, 0x13 avisos, 0x14 eventos, 0x15
//! rastro, 0x17 diversos (pouco recurso e outros), 0x18 sem nome conhecido.
//! As seções pequenas (0x9, 0x20, 0x21, 0x30) não têm entradas.

use super::serial::SecondaryRecord;

/// WdDxgkSecondaryDataGUID na ordem dos bytes da memória (`guidBytes`).
pub const GUID: [u8; 16] = [0xfd, 0x33, 0x0a, 0x27, 0xa6, 0x3d, 0x0d, 0x46, 0xba, 0x89, 0x3c, 0x1b, 0xae, 0x21, 0xe3, 0x9b];

/// O tamanho de uma entrada de anel.
pub const ENTRY_SIZE: usize = 0x40;

/// O anel de asserções e o de erros, os que saem sem `--all`.
pub const ASSERTIONS: u32 = 0x11;
pub const ERRORS: u32 = 0x12;

/// O maior número de seções aceito no cabeçalho.
const MAXIMUM_SECTIONS: usize = 256;

/// O nome de um anel.
pub fn ring_name(id: u32) -> Option<&'static str> {
    Some(match id {
        0x11 => "assercoes",
        0x12 => "erros",
        0x13 => "avisos",
        0x14 => "eventos",
        0x15 => "rastro",
        0x17 => "diversos (pouco recurso e outros)",
        _ => return None,
    })
}

/// Uma entrada de anel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub ring: u32,
    /// O offset da entrada nos dados secundários.
    pub offset: usize,
    pub sequence: u64,
    pub thread: u64,
    pub return_address: u64,
    pub parameters: [u64; 5],
}

/// Uma seção do WdLog com as entradas não nulas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub id: u32,
    pub offset: usize,
    pub end: usize,
    pub entries: Vec<Entry>,
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

/// O registro do WdLog entre os dados secundários (o último, se houver mais
/// de um).
pub fn find(records: &[SecondaryRecord]) -> Option<&SecondaryRecord> {
    records.iter().rev().find(|record| record.guid == GUID)
}

/// As seções do WdLog, na ordem dos offsets.
pub fn decode(bytes: &[u8]) -> Result<Vec<Section>, String> {
    let count = u64_at(bytes, 0).ok_or("WdLog sem cabecalho")?;
    if count == 0 || count > MAXIMUM_SECTIONS as u64 {
        return Err(format!("WdLog com {count} secoes no cabecalho"));
    }
    let count = count as usize;
    let header_end = 8 + 8 * count;
    if header_end > bytes.len() {
        return Err(format!("WdLog de {} bytes nao cabe o cabecalho de {count} secoes", bytes.len()));
    }
    // O offset de uma seção pode cair no fim da tabela de pares: no dxgkrnl
    // do 19041 a seção 0x9 (8 bytes) fica no lugar do último par.
    let mut pairs: Vec<(usize, u32)> = (0..count)
        .filter_map(|index| {
            let offset = u32_at(bytes, 8 + 8 * index)? as usize;
            let id = u32_at(bytes, 12 + 8 * index)?;
            (id != 0 && offset >= 8 && offset < bytes.len()).then_some((offset, id))
        })
        .collect();
    pairs.sort_unstable();
    let mut sections = Vec::new();
    for (position, &(offset, id)) in pairs.iter().enumerate() {
        let end = pairs.get(position + 1).map_or(bytes.len(), |next| next.0);
        let mut entries = Vec::new();
        let mut at = offset;
        while at + ENTRY_SIZE <= end {
            let words: [u64; 8] = std::array::from_fn(|index| u64_at(bytes, at + 8 * index).unwrap_or(0));
            if words.iter().any(|&word| word != 0) {
                entries.push(Entry { ring: id, offset: at, sequence: words[0], thread: words[1], return_address: words[2], parameters: [words[3], words[4], words[5], words[6], words[7]] });
            }
            at += ENTRY_SIZE;
        }
        sections.push(Section { id, offset, end, entries });
    }
    Ok(sections)
}

/// O nome de um parâmetro que é um NTSTATUS de erro estendido para 64 bits
/// (`ffffffffc000000d`) ou de 32 bits.
pub fn status_note(value: u64) -> Option<&'static str> {
    let high = value >> 32;
    if high != 0 && high != 0xFFFF_FFFF {
        return None;
    }
    let status = value as u32;
    if !crate::ntstatus::is_error(status) {
        return None;
    }
    crate::ntstatus::name(status)
}

/// Uma entrada em uma linha: sequência, thread, onde (`locate` descreve o
/// endereço de retorno) e os parâmetros, com o nome dos status de erro.
pub fn entry_line(entry: &Entry, locate: &dyn Fn(u64) -> String) -> String {
    let parameters: Vec<String> = entry.parameters.iter().map(|value| format!("{value:x}")).collect();
    let notes: Vec<&str> = entry.parameters.iter().filter_map(|&value| status_note(value)).collect();
    let mut line = format!("  seq={:#x} thr={:x} {}  p={}", entry.sequence, entry.thread, locate(entry.return_address), parameters.join(" "));
    if !notes.is_empty() {
        line.push_str(&format!("  [{}]", notes.join(", ")));
    }
    line
}

/// Os anéis em texto: só asserções e erros, ou todas as seções com
/// entradas (`all`).
pub fn render(sections: &[Section], locate: &dyn Fn(u64) -> String, all: bool) -> String {
    let mut output = String::new();
    for section in sections {
        let shown = if all { !section.entries.is_empty() } else { matches!(section.id, ASSERTIONS | ERRORS) };
        if !shown {
            continue;
        }
        let name = ring_name(section.id).map_or_else(|| format!("anel {:#x}", section.id), |name| format!("anel de {name} ({:#x})", section.id));
        output.push_str(&format!("{name}: {} entradas\n", section.entries.len()));
        for entry in &section.entries {
            output.push_str(&entry_line(entry, locate));
            output.push('\n');
        }
    }
    if !all {
        let hidden: Vec<String> = sections.iter().filter(|section| !matches!(section.id, ASSERTIONS | ERRORS) && !section.entries.is_empty()).map(|section| format!("{:#x} ({})", section.id, section.entries.len())).collect();
        if !hidden.is_empty() {
            output.push_str(&format!("outros aneis com entradas (--all lista): {}\n", hidden.join(", ")));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Um WdLog com cabeçalho de `count` pares e as entradas dadas.
    fn image(pairs: &[(u32, u32)], count: usize, length: usize, entries: &[(usize, [u64; 8])]) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        bytes[..8].copy_from_slice(&(count as u64).to_le_bytes());
        for (index, (offset, id)) in pairs.iter().enumerate() {
            bytes[8 + 8 * index..12 + 8 * index].copy_from_slice(&offset.to_le_bytes());
            bytes[12 + 8 * index..16 + 8 * index].copy_from_slice(&id.to_le_bytes());
        }
        for (at, words) in entries {
            for (index, word) in words.iter().enumerate() {
                bytes[at + 8 * index..at + 8 * index + 8].copy_from_slice(&word.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn sections_end_at_the_next_offset_and_pairs_without_id_are_ignored() {
        // Como no dxgkrnl do 19041: o último par (2, 0) não é seção, e o
        // anel 0x17 vai até o fim dos dados.
        let pairs = [(0x60, 0x9), (0x68, 0x12), (0x128, 0x17), (0, 0), (2, 0)];
        let entry = |sequence: u64| [sequence, 0xffffc000c008b300, 0xfffff80100313ace, 0x507, 0, 0, 0, 0];
        let bytes = image(&pairs, 5, 0x1a8, &[(0x68, entry(0x108)), (0xe8, entry(0x7a)), (0x168, entry(0x9a9))]);
        let sections = decode(&bytes).unwrap();
        let ids: Vec<u32> = sections.iter().map(|section| section.id).collect();
        assert_eq!(ids, [0x9, 0x12, 0x17]);
        assert!(sections[0].entries.is_empty());
        assert_eq!((sections[1].offset, sections[1].end), (0x68, 0x128));
        assert_eq!(sections[1].entries.len(), 2);
        assert_eq!(sections[1].entries[1].sequence, 0x7a);
        assert_eq!(sections[1].entries[0].parameters, [0x507, 0, 0, 0, 0]);
        assert_eq!((sections[2].end, sections[2].entries.len()), (0x1a8, 1));
        assert_eq!(sections[2].entries[0].offset, 0x168);
    }

    #[test]
    fn bad_headers_are_errors() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0; 8]).is_err());
        assert!(decode(&image(&[], 1000, 64, &[])).is_err());
        assert!(decode(&image(&[], 20, 64, &[])).is_err());
    }

    #[test]
    fn renders_the_error_ring_with_status_names() {
        let pairs = [(0x18, 0x12), (0x58, 0x15)];
        let bytes = image(&pairs, 2, 0x98, &[(0x18, [0x42, 0xffffc000c008b300, 0xfffff80100a3eb75, 0xffffffffc000000d, 0, 0, 0, 0]), (0x58, [0x892, 0xffffc000c0091100, 0xfffff8010032e00e, 0, 0, 0x7fd9000, 0, 1])]);
        let sections = decode(&bytes).unwrap();
        let locate = |address: u64| format!("<{address:x}>");
        let text = render(&sections, &locate, false);
        assert!(text.contains("anel de erros (0x12): 1 entradas"), "{text}");
        assert!(text.contains("  seq=0x42 thr=ffffc000c008b300 <fffff80100a3eb75>  p=ffffffffc000000d 0 0 0 0  [STATUS_INVALID_PARAMETER]"), "{text}");
        assert!(text.contains("outros aneis com entradas (--all lista): 0x15 (1)"), "{text}");
        assert!(!text.contains("seq=0x892"));
        let text = render(&sections, &locate, true);
        assert!(text.contains("anel de rastro (0x15): 1 entradas"), "{text}");
        assert!(text.contains("seq=0x892"));
        assert_eq!(status_note(0xffffffffc0000034), Some("STATUS_OBJECT_NAME_NOT_FOUND"));
        assert_eq!(status_note(0x507), None);
        assert_eq!(status_note(0xfffff80100000000), None);
    }
}
