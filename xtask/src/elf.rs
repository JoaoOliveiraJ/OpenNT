//! Leitura mínima de ELF64 little-endian x86-64: seções e símbolos, o
//! suficiente para empacotar o kernel como PE32+.

use std::collections::HashMap;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_NOBITS: u32 = 8;
pub const SHF_WRITE: u64 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXECINSTR: u64 = 4;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub kind: u32,
    pub flags: u64,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub entry_size: u64,
}

pub struct Elf<'a> {
    pub bytes: &'a [u8],
    pub sections: Vec<Section>,
    pub symbols: HashMap<String, u64>,
    pub entry: u64,
}

fn check(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("kernel ELF: {message}"))
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn c_string(table: &[u8], offset: usize) -> Result<String, String> {
    let tail = table.get(offset..).ok_or("kernel ELF: string fora da tabela")?;
    let end = tail.iter().position(|&byte| byte == 0).ok_or("kernel ELF: string sem terminador")?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

impl<'a> Elf<'a> {
    pub fn range(&self, offset: u64, size: u64) -> Result<&'a [u8], String> {
        let start = offset as usize;
        let end = start.checked_add(size as usize).ok_or("kernel ELF: faixa invalida")?;
        self.bytes.get(start..end).ok_or_else(|| "kernel ELF: faixa fora do arquivo".to_string())
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        check(
            bytes.len() >= 64
                && u32_at(bytes, 0) == 0x464C_457F
                && bytes[4] == 2
                && bytes[5] == 1
                && u16_at(bytes, 18) == 62,
            "requer ELF x86-64 little-endian",
        )?;
        let table = u64_at(bytes, 40) as usize;
        let stride = u16_at(bytes, 58) as usize;
        let count = u16_at(bytes, 60) as usize;
        check(stride == 64 && count > 0, "tabela de secoes ausente")?;
        check(table + count * stride <= bytes.len(), "tabela de secoes fora do arquivo")?;

        let mut raw = Vec::with_capacity(count);
        for index in 0..count {
            let at = table + index * stride;
            raw.push((
                u32_at(bytes, at),
                Section {
                    name: String::new(),
                    kind: u32_at(bytes, at + 4),
                    flags: u64_at(bytes, at + 8),
                    address: u64_at(bytes, at + 16),
                    offset: u64_at(bytes, at + 24),
                    size: u64_at(bytes, at + 32),
                    link: u32_at(bytes, at + 40),
                    entry_size: u64_at(bytes, at + 56),
                },
            ));
        }
        let names_index = u16_at(bytes, 62) as usize;
        let names = raw.get(names_index).ok_or("kernel ELF: nomes de secao ausentes")?.1.clone();
        let mut elf = Elf { bytes, sections: Vec::new(), symbols: HashMap::new(), entry: u64_at(bytes, 24) };
        let strings = elf.range(names.offset, names.size)?;
        for (name_offset, mut section) in raw {
            section.name = c_string(strings, name_offset as usize)?;
            elf.sections.push(section);
        }

        let symbol_tables: Vec<Section> =
            elf.sections.iter().filter(|section| section.kind == SHT_SYMTAB).cloned().collect();
        for table in symbol_tables {
            check(table.entry_size == 24 && table.size % 24 == 0, "tabela de simbolos invalida")?;
            let entries = elf.range(table.offset, table.size)?;
            let names = elf.sections.get(table.link as usize).ok_or("kernel ELF: strings de simbolos ausentes")?;
            let names = elf.range(names.offset, names.size)?;
            for entry in entries.chunks_exact(24) {
                if u16_at(entry, 6) == 0 {
                    continue; // símbolo indefinido
                }
                let name = c_string(names, u32_at(entry, 0) as usize)?;
                if !name.is_empty() {
                    elf.symbols.insert(name, u64_at(entry, 8));
                }
            }
        }
        Ok(elf)
    }
}
