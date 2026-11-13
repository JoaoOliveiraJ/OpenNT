//! Atributos estendidos — `system32/ntos/fs/extended-attributes.js`.
//!
//! FILE_FULL_EA_INFORMATION / FILE_GET_EA_INFORMATION e a ordem de EAs do
//! NTFS. Bytes >= 0x80 são mantidos, como observado no NTFS; nomes ASCII
//! viram maiúsculas.

use alloc::vec::Vec;

const STATUS_INVALID_EA_NAME: u32 = 0x8000_0013;
const STATUS_EA_LIST_INCONSISTENT: u32 = 0x8000_0014;
const STATUS_EA_TOO_LARGE: u32 = 0xC000_0050;

/// Erro com NTSTATUS e o deslocamento da entrada inválida.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EaError {
    pub status: u32,
    pub information: u32,
}

/// Uma entrada de EA (nome em bytes, flags e valor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: Vec<u8>,
    pub flags: u8,
    pub value: Vec<u8>,
}

fn align(value: usize) -> usize {
    (value + 3) & !3
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn fail<T>(status: u32, offset: usize) -> Result<T, EaError> {
    Err(EaError { status, information: offset as u32 })
}

fn name(bytes: &[u8], offset: usize) -> Result<Vec<u8>, EaError> {
    if bytes.is_empty() || bytes.len() >= 255 {
        return fail(STATUS_INVALID_EA_NAME, offset);
    }
    let mut result = Vec::with_capacity(bytes.len());
    for &character in bytes {
        if character < 32 || b"\\/:*?\"<>|,+=[];".contains(&character) {
            return fail(STATUS_INVALID_EA_NAME, offset);
        }
        result.push(if character.is_ascii_lowercase() { character - 32 } else { character });
    }
    Ok(result)
}

/// Lista encadeada de EAs (`names` = FILE_GET_EA_INFORMATION; `disk` aceita
/// o último NextEntryOffset apontando para o fim, como no $EA).
pub fn parse(bytes: &[u8], names: bool, disk: bool) -> Result<Vec<Entry>, EaError> {
    let header = if names { 5 } else { 8 };
    let mut result = Vec::new();
    let mut offset = 0usize;
    if bytes.is_empty() {
        return fail(STATUS_EA_LIST_INCONSISTENT, 0);
    }
    loop {
        if offset + header + 1 > bytes.len() {
            return fail(STATUS_EA_LIST_INCONSISTENT, offset);
        }
        let next = u32_at(bytes, offset) as usize;
        let name_length = bytes[offset + if names { 4 } else { 5 }] as usize;
        let value_length = if names { 0 } else { u16_at(bytes, offset + 6) as usize };
        let size = header + name_length + 1 + value_length;
        if offset + size > bytes.len() || bytes[offset + header + name_length] != 0 || (next != 0 && (next % 4 != 0 || next < align(size) || offset + next > bytes.len() || (!disk && offset + next == bytes.len()))) {
            return fail(STATUS_EA_LIST_INCONSISTENT, offset);
        }
        let flags = if names { 0 } else { bytes[offset + 4] };
        if flags & !0x80 != 0 {
            return fail(STATUS_INVALID_EA_NAME, offset);
        }
        result.push(Entry { name: name(&bytes[offset + header..offset + header + name_length], offset)?, flags, value: bytes[offset + header + name_length + 1..offset + size].to_vec() });
        if next == 0 || (disk && offset + next == bytes.len()) {
            return Ok(result);
        }
        offset += next;
    }
}

fn size(entry: &Entry) -> usize {
    9 + entry.name.len() + entry.value.len()
}

/// FILE_FULL_EA_INFORMATION; fora do disco a última entrada não é alinhada.
pub fn encode(entries: &[Entry], disk: bool) -> Vec<u8> {
    let last = entries.len().saturating_sub(1);
    let total: usize = entries.iter().enumerate().map(|(index, entry)| if disk || index < last { align(size(entry)) } else { size(entry) }).sum();
    let mut bytes = alloc::vec![0u8; total];
    let mut offset = 0;
    for (index, entry) in entries.iter().enumerate() {
        let step = align(size(entry));
        let next = if disk || index < last { step as u32 } else { 0 };
        bytes[offset..offset + 4].copy_from_slice(&next.to_le_bytes());
        bytes[offset + 4] = entry.flags;
        bytes[offset + 5] = entry.name.len() as u8;
        bytes[offset + 6..offset + 8].copy_from_slice(&(entry.value.len() as u16).to_le_bytes());
        bytes[offset + 8..offset + 8 + entry.name.len()].copy_from_slice(&entry.name);
        let value_at = offset + 9 + entry.name.len();
        bytes[value_at..value_at + entry.value.len()].copy_from_slice(&entry.value);
        offset += step;
        if offset > total {
            break;
        }
    }
    bytes
}

/// Tamanhos do $EA_INFORMATION.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub packed: usize,
    pub unpacked: usize,
    pub need: usize,
}

pub fn info(entries: &[Entry]) -> Info {
    Info {
        packed: entries.iter().map(|entry| size(entry) - 4).sum(),
        unpacked: entries.iter().map(|entry| align(size(entry))).sum(),
        need: entries.iter().filter(|entry| entry.flags & 0x80 != 0).count(),
    }
}

/// Aplica um FILE_FULL_EA_INFORMATION: valor vazio remove. As APIs públicas
/// ignoram em silêncio mutações dos EAs reservados `$KERNEL`.
pub fn update(entries: &[Entry], bytes: &[u8], kernel_call: bool) -> Result<Vec<Entry>, EaError> {
    let changes = parse(bytes, false, false)?;
    let mut result = entries.to_vec();
    for entry in changes {
        if entry.name.starts_with(b"$KERNEL") && !kernel_call {
            continue;
        }
        result.retain(|existing| existing.name != entry.name);
        if !entry.value.is_empty() {
            result.push(entry);
        }
    }
    let sizes = info(&result);
    if sizes.packed > 65535 || sizes.unpacked > 65536 {
        return fail(STATUS_EA_TOO_LARGE, 0);
    }
    Ok(result)
}

/// Opções de NtQueryEaFile.
#[derive(Clone, Default)]
pub struct QueryOptions {
    pub names: Option<Vec<u8>>,
    pub index: Option<u32>,
    pub restart: bool,
    pub single: bool,
}

/// Cursor de enumeração do FILE_OBJECT.
#[derive(Clone, Copy, Default)]
pub struct QueryState {
    pub index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryResult {
    pub status: u32,
    pub bytes: Vec<u8>,
    pub information: u32,
}

pub fn query(entries: &[Entry], length: usize, options: &QueryOptions, state: &mut QueryState) -> QueryResult {
    let result = |status: u32, data: &[u8], information: u32| {
        let mut bytes = alloc::vec![0u8; length];
        let copy = data.len().min(length);
        bytes[..copy].copy_from_slice(&data[..copy]);
        QueryResult { status, bytes, information }
    };
    let outcome = (|| -> Result<QueryResult, EaError> {
        let named = options.names.as_ref().is_some_and(|names| !names.is_empty());
        let mut start = 0usize;
        let mut selected: Vec<Entry>;
        if named {
            selected = Vec::new();
            let mut seen: Vec<Vec<u8>> = Vec::new();
            for requested in parse(options.names.as_deref().unwrap_or(&[]), true, false)? {
                if seen.contains(&requested.name) {
                    continue;
                }
                seen.push(requested.name.clone());
                selected.push(entries.iter().find(|entry| entry.name == requested.name).cloned().unwrap_or(requested));
            }
        } else {
            if let Some(index) = options.index {
                let first = index as i64 - 1;
                if first < 0 || first as usize > entries.len() || entries.is_empty() {
                    return Ok(result(0xC000_0051, &[], 0));
                }
                start = first as usize;
            } else {
                if entries.is_empty() {
                    return Ok(result(0xC000_0052, &[], 0));
                }
                start = if options.restart { 0 } else { state.index };
            }
            if start >= entries.len() {
                return Ok(result(0x8000_0012, &[], 0));
            }
            selected = entries[start..].to_vec();
        }
        if options.single {
            selected.truncate(1);
        }
        let mut fits = Vec::new();
        let mut offset = 0;
        for entry in &selected {
            if offset + size(entry) > length {
                break;
            }
            fits.push(entry.clone());
            offset += align(size(entry));
        }
        if fits.is_empty() {
            return Ok(result(0xC000_0023, &[], 0));
        }
        if !named {
            state.index = start + fits.len();
        }
        let encoded = encode(&fits, false);
        let status = if fits.len() < selected.len() { 0x8000_0005 } else { 0 };
        Ok(result(status, &encoded, encoded.len() as u32))
    })();
    outcome.unwrap_or_else(|error| result(error.status, &[], error.information))
}
