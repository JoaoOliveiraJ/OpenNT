//! API_SET_NAMESPACE v6.
//!
//! Lido do apisetschema.dll da mesma instalação das DLLs, com
//! EntryOffset/HashedLength e os aliases por importador do próprio schema.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::mm::sysload::kernel_image_source::ImageSource;
use crate::rtl::KernelError;

#[derive(Clone, Debug, Default)]
struct Entry {
    /// `None`: sem valores (não é um host vazio).
    host: Option<String>,
    aliases: BTreeMap<String, String>,
}

/// Schema carregado: nome completo e nome hash (sem a revisão final).
#[derive(Clone, Debug, Default)]
pub struct Schema {
    entries: BTreeMap<String, usize>,
    hashed: BTreeMap<String, usize>,
    values: Vec<Entry>,
}

impl Schema {
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    /// `None` = contrato desconhecido; `Some("")` = host explicitamente
    /// ausente (só este permite os padrões nativos do IAT).
    pub fn resolve(&self, name: &str, importer: &str) -> Option<String> {
        let mut name = name.to_lowercase();
        if name.ends_with(".dll") {
            name.truncate(name.len() - 4);
        }
        // A revisão final não pertence ao nome hash do contrato v6.
        let index = self.entries.get(&name).or_else(|| name.rfind('-').and_then(|dash| self.hashed.get(&name[..dash])))?;
        let entry = &self.values[*index];
        let parent = importer.replace('\\', "/").rsplit('/').next().unwrap_or("").to_lowercase();
        match entry.aliases.get(&parent) {
            Some(host) => Some(host.clone()),
            None => entry.host.clone(),
        }
    }
}

fn error(message: &str) -> KernelError {
    KernelError::new(message)
}

pub fn parse(bytes: &[u8]) -> Result<Schema, KernelError> {
    let size = if bytes.len() >= 8 { u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize } else { 0 };
    let range = |offset: usize, length: usize| -> Result<(), KernelError> {
        if offset.checked_add(length).is_none_or(|end| end > size) || size > bytes.len() {
            return Err(error("apiset: estrutura fora do schema"));
        }
        Ok(())
    };
    let u32_at = |offset: usize| -> Result<usize, KernelError> {
        range(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]) as usize)
    };
    let wide = |offset: usize, length: usize| -> Result<String, KernelError> {
        range(offset, length)?;
        if length % 2 != 0 {
            return Err(error("apiset: string UTF-16 invalida"));
        }
        let units: Vec<u16> = (0..length / 2).map(|index| u16::from_le_bytes([bytes[offset + index * 2], bytes[offset + index * 2 + 1]])).collect();
        Ok(String::from_utf16_lossy(&units).to_lowercase())
    };
    if u32_at(0)? != 6 {
        return Err(error("apiset: versao de schema nao suportada"));
    }
    let mut schema = Schema::default();
    let count = u32_at(12)?;
    let entry_offset = u32_at(16)?;
    range(entry_offset, count * 24)?;
    for index in 0..count {
        let entry = entry_offset + index * 24;
        let name_offset = u32_at(entry + 4)?;
        let name_length = u32_at(entry + 8)?;
        let hashed_length = u32_at(entry + 12)?;
        if hashed_length > name_length {
            return Err(error("apiset: HashedLength invalido"));
        }
        let name = wide(name_offset, name_length)?;
        let values = u32_at(entry + 16)?;
        let value_count = u32_at(entry + 20)?;
        range(values, value_count * 20)?;
        let mut data = Entry::default();
        for value_index in 0..value_count {
            let value = values + value_index * 20;
            let alias = wide(u32_at(value + 4)?, u32_at(value + 8)?)?;
            let host = wide(u32_at(value + 12)?, u32_at(value + 16)?)?;
            // v6: o primeiro valor é o padrão e os seguintes são aliases.
            if value_index == 0 {
                data.host = Some(host);
            } else if !alias.is_empty() {
                data.aliases.insert(alias, host);
            }
        }
        let position = schema.values.len();
        schema.values.push(data);
        schema.entries.insert(name, position);
        schema.hashed.insert(wide(name_offset, hashed_length)?, position);
    }
    Ok(schema)
}

/// Só a seção `.apiset` do PE (offsets de arquivo): o kernel precisa dela
/// antes de existir um processo de usuário com PEB.ApiSetMap.
pub fn parse_image(source: &dyn ImageSource) -> Result<Schema, KernelError> {
    let read = |offset: u64, length: u64| -> Result<Vec<u8>, KernelError> {
        if offset.checked_add(length).is_none_or(|end| end > source.size()) {
            return Err(error("apiset: PE fora do arquivo"));
        }
        let bytes = source.read_bytes(offset, length)?;
        if bytes.len() as u64 != length {
            return Err(error("apiset: leitura PE incompleta"));
        }
        Ok(bytes)
    };
    let u16_at = |data: &[u8], offset: usize| u16::from_le_bytes([data[offset], data[offset + 1]]) as u64;
    let u32_at = |data: &[u8], offset: usize| u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as u64;
    let dos = read(0, 64)?;
    if u16_at(&dos, 0) != 0x5A4D {
        return Err(error("apiset: MZ invalido"));
    }
    let pe = u32_at(&dos, 60);
    let header = read(pe, 24)?;
    if u32_at(&header, 0) != 0x4550 {
        return Err(error("apiset: PE invalido"));
    }
    let optional_size = u16_at(&header, 20);
    if optional_size < 2 {
        return Err(error("apiset: optional header ausente"));
    }
    let magic = u16_at(&read(pe + 24, optional_size)?, 0);
    if magic != 0x20B && magic != 0x10B {
        return Err(error("apiset: formato PE invalido"));
    }
    let count = u16_at(&header, 6);
    let sections = read(pe + 24 + optional_size, count * 40)?;
    let mut found = None;
    for index in 0..count as usize {
        let header = index * 40;
        let name: Vec<u8> = sections[header..header + 8].iter().copied().take_while(|&byte| byte != 0).collect();
        if name != b".apiset" {
            continue;
        }
        if found.is_some() {
            return Err(error("apiset: secao .apiset duplicada"));
        }
        found = Some(read(u32_at(&sections, header + 20), u32_at(&sections, header + 16))?);
    }
    parse(&found.ok_or_else(|| error("apiset: secao .apiset ausente"))?)
}
