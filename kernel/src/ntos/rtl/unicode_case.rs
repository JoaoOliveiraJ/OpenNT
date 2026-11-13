//! Maiúsculas por unidade WCHAR com a tabela NLS instalada.
//!
//! A tabela vem de `C:\Windows\System32\l_intl.nls` no volume montado,
//! lida no primeiro uso; ausência ou estrutura inválida é erro.

use alloc::string::String;
use alloc::vec::Vec;

use crate::rtl::{KernelError, SpinLock};

/// Fonte dos bytes de l_intl.nls.
pub type TableSource = fn() -> Result<Vec<u8>, KernelError>;

static SOURCE: SpinLock<Option<TableSource>> = SpinLock::new(None);
static TABLE: SpinLock<Option<Vec<u16>>> = SpinLock::new(None);

/// Fonte padrão: o arquivo real do volume de boot (`lookup_volume_file`).
fn volume_table() -> Result<Vec<u8>, KernelError> {
    let file = crate::drivers::fs::volume_files::lookup_volume_file("C:\\Windows\\System32\\l_intl.nls").filter(|file| !file.directory()).ok_or_else(|| KernelError::new("NLS: l_intl.nls missing"))?;
    file.read_at(0, file.size())
}

/// Substitui a fonte padrão (volume) por outra.
pub fn set_table_source(source: TableSource) {
    *SOURCE.lock() = Some(source);
}

/// Valida a versão e a extensão da tabela; devolve as palavras do trie.
pub fn read_uppercase(bytes: &[u8]) -> Result<Vec<u16>, KernelError> {
    let word = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    if bytes.len() < 516 || word(0) != 1 {
        return Err(KernelError::new("NLS: invalid casing header"));
    }
    let end = 2 + word(2) as usize * 2;
    if end < 516 || end > bytes.len() {
        return Err(KernelError::new("NLS: invalid uppercase size"));
    }
    Ok((4..end).step_by(2).filter(|offset| offset + 2 <= end).map(word).collect())
}

/// Três níveis indexados pelos grupos de 8, 4 e 4 bits fornecem o delta.
fn lookup(table: &[u16], unit: u16) -> Result<u16, KernelError> {
    let read = |index: usize| table.get(index).copied().ok_or_else(|| KernelError::new("NLS: invalid uppercase trie"));
    let first = read((unit >> 8) as usize)? as usize;
    let second = read(first + ((unit >> 4) & 15) as usize)? as usize;
    let delta = read(second + (unit & 15) as usize)?;
    Ok(unit.wrapping_add(delta))
}

pub fn upcase_char(unit: u16) -> Result<u16, KernelError> {
    let mut table = TABLE.lock();
    if table.is_none() {
        let source = (*SOURCE.lock()).unwrap_or(volume_table);
        *table = Some(read_uppercase(&source()?)?);
    }
    lookup(table.as_ref().unwrap(), unit)
}

/// Conversão por unidade UTF-16, conservando a quantidade de unidades.
pub fn upcase(text: &str) -> Result<String, KernelError> {
    let units: Result<Vec<u16>, KernelError> = text.encode_utf16().map(upcase_char).collect();
    Ok(char::decode_utf16(units?).map(|unit| unit.unwrap_or('\u{FFFD}')).collect())
}

pub fn upcase_units(units: &[u16]) -> Result<Vec<u16>, KernelError> {
    units.iter().map(|&unit| upcase_char(unit)).collect()
}
