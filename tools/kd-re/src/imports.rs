//! Os imports de um PE x64: a tabela comum (diretório 1) e a de carga
//! adiada (diretório 13). Cada entrada é um slot da IAT com a DLL e o nome
//! (ou `#ordinal`), para dar nome às chamadas `call [__imp_X]`, aos
//! trampolins `jmp [__imp_X]` e às leituras da IAT na desmontagem e nas
//! referências cruzadas.
//!
//! Lê pelo `PeImage` do `kd-client`, que traduz RVA em deslocamento tanto no
//! arquivo desta máquina quanto numa imagem já mapeada.

use kd_client::pe::PeImage;
use kd_client::symbols::display_name;

/// IMAGE_FILE_MACHINE_AMD64.
const MACHINE_AMD64: u16 = 0x8664;
/// Mais entradas que isso é tabela corrompida.
const LIMIT: usize = 50_000;

/// Um import: o slot da IAT (endereço absoluto), a DLL e a função.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    pub slot: u64,
    /// O nome da DLL como está na tabela (`ntdll.dll`,
    /// `api-ms-win-core-file-l1-1-0.dll`).
    pub dll: String,
    /// O nome da função, ou `#ordinal`.
    pub name: String,
    /// Da tabela de carga adiada (o slot aponta o trampolim `__imp_load_`
    /// até a primeira chamada).
    pub delayed: bool,
}

impl Import {
    /// `ntdll!NtClose` (a DLL sem a extensão, como os módulos aparecem).
    pub fn display(&self) -> String {
        format!("{}!{}", display_name(&self.dll), self.name)
    }

    /// O nome do slot como os PDBs da Microsoft o chamam, no módulo que
    /// importa: `win32kfull!__imp_ExAllocatePoolWithTag`.
    pub fn slot_name(&self, importer: &str) -> String {
        let prefix = if self.delayed { "__imp_load_" } else { "__imp_" };
        if importer.is_empty() {
            format!("{prefix}{}", self.name)
        } else {
            format!("{importer}!{prefix}{}", self.name)
        }
    }
}

/// Os imports de um módulo, ordenados pelo slot.
#[derive(Clone, Debug, Default)]
pub struct ImportMap {
    entries: Vec<Import>,
}

fn u32_at(image: &PeImage, rva: u32) -> Option<u32> {
    let bytes = image.bytes_at(rva, 4)?;
    (bytes.len() == 4).then(|| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(image: &PeImage, rva: u32) -> Option<u64> {
    let bytes = image.bytes_at(rva, 8)?;
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

fn name_at(image: &PeImage, rva: u32) -> Option<String> {
    if rva == 0 {
        return None;
    }
    let bytes = image.bytes_at(rva, 256)?;
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
    (end > 0).then(|| String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// As entradas de uma tabela de nomes (INT) e os slots da IAT paralela.
fn push_thunks(image: &PeImage, base: u64, dll: &str, lookup: u32, first: u32, delayed: bool, entries: &mut Vec<Import>) {
    if lookup == 0 || first == 0 {
        return;
    }
    for index in 0..8192u32 {
        if entries.len() >= LIMIT {
            return;
        }
        let Some(entry) = u64_at(image, lookup.wrapping_add(index * 8)) else { return };
        if entry == 0 {
            return;
        }
        let name = if entry >> 63 != 0 {
            format!("#{}", entry & 0xFFFF)
        } else {
            // IMAGE_IMPORT_BY_NAME: a dica (2 bytes) e o nome.
            name_at(image, (entry & 0x7FFF_FFFF) as u32 + 2).unwrap_or_else(|| "?".into())
        };
        entries.push(Import { slot: base + first as u64 + index as u64 * 8, dll: dll.to_string(), name, delayed });
    }
}

impl ImportMap {
    /// Os imports do PE carregado em `base`.
    pub fn from_pe(base: u64, image: &PeImage) -> ImportMap {
        let mut entries = Vec::new();
        if image.header.machine != MACHINE_AMD64 {
            return ImportMap { entries };
        }
        // IMAGE_IMPORT_DESCRIPTOR: OriginalFirstThunk, TimeDateStamp,
        // ForwarderChain, Name, FirstThunk (20 bytes).
        if let Some((rva, size)) = image.directory(1).filter(|&(rva, _)| rva != 0) {
            let limit = rva.saturating_add(size.max(20));
            let mut descriptor = rva;
            while descriptor.saturating_add(20) <= limit && entries.len() < LIMIT {
                let original = u32_at(image, descriptor).unwrap_or(0);
                let name = u32_at(image, descriptor + 12).unwrap_or(0);
                let first = u32_at(image, descriptor + 16).unwrap_or(0);
                if name == 0 && first == 0 {
                    break;
                }
                let dll = name_at(image, name).unwrap_or_default();
                let lookup = if original != 0 { original } else { first };
                push_thunks(image, base, &dll, lookup, first, false, &mut entries);
                descriptor += 20;
            }
        }
        // ImgDelayDescr: grAttrs, rvaDLLName, rvaHmod, rvaIAT, rvaINT,
        // rvaBoundIAT, rvaUnloadIAT, dwTimeStamp (32 bytes). No x64 só existe
        // a forma com RVAs (dlattrRva).
        if let Some((rva, size)) = image.directory(13).filter(|&(rva, _)| rva != 0) {
            let limit = rva.saturating_add(size.max(32));
            let mut descriptor = rva;
            while descriptor.saturating_add(32) <= limit && entries.len() < LIMIT {
                let attributes = u32_at(image, descriptor).unwrap_or(0);
                let name = u32_at(image, descriptor + 4).unwrap_or(0);
                let iat = u32_at(image, descriptor + 12).unwrap_or(0);
                let int = u32_at(image, descriptor + 16).unwrap_or(0);
                if name == 0 && iat == 0 {
                    break;
                }
                if attributes & 1 != 0 {
                    let dll = name_at(image, name).unwrap_or_default();
                    push_thunks(image, base, &dll, int, iat, true, &mut entries);
                }
                descriptor += 32;
            }
        }
        entries.sort_by_key(|import| import.slot);
        entries.dedup_by_key(|import| import.slot);
        ImportMap { entries }
    }

    /// O import do slot.
    pub fn get(&self, slot: u64) -> Option<&Import> {
        self.entries.binary_search_by_key(&slot, |import| import.slot).ok().map(|index| &self.entries[index])
    }

    pub fn contains(&self, slot: u64) -> bool {
        self.get(slot).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Import> {
        self.entries.iter()
    }
}

/// O slot da IAT de um trampolim `jmp qword ptr [rip+disp32]` (`FF 25`,
/// com ou sem REX.W) que começa em `address`.
pub fn thunk_slot(address: u64, bytes: &[u8]) -> Option<u64> {
    let (prefix, rest) = match bytes {
        [0x48, rest @ ..] => (1u64, rest),
        _ => (0u64, bytes),
    };
    match rest {
        [0xFF, 0x25, a, b, c, d, ..] => {
            let displacement = i32::from_le_bytes([*a, *b, *c, *d]);
            Some(address.wrapping_add(prefix + 6).wrapping_add(displacement as i64 as u64))
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Um PE64 mapeado mínimo (sem seções; RVA = deslocamento) com os
    /// diretórios dados: (índice, RVA, tamanho).
    pub(crate) fn mapped_pe(size: usize, image_base: u64, directories: &[(usize, u32, u32)]) -> Vec<u8> {
        let mut bytes = vec![0u8; size.max(0x400)];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        let pe = 0x80usize;
        bytes[0x3C..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");
        bytes[pe + 4..pe + 6].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        bytes[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
        let optional = pe + 24;
        bytes[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&image_base.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&(size as u32).to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        for &(index, rva, length) in directories {
            let at = optional + 112 + 8 * index;
            bytes[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&length.to_le_bytes());
        }
        bytes
    }

    pub(crate) fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_text(bytes: &mut [u8], at: usize, text: &str) {
        bytes[at..at + text.len()].copy_from_slice(text.as_bytes());
    }

    #[test]
    fn reads_normal_and_delayed_imports() {
        // Diretório 1 em 0x400 (um descritor e o terminador), diretório 13
        // em 0x480 (um descritor e o terminador).
        let mut bytes = mapped_pe(0x1000, 0x1_4000_0000, &[(1, 0x400, 40), (13, 0x480, 64)]);
        // ntdll.dll: INT em 0x500, IAT em 0x600.
        put_u32(&mut bytes, 0x400, 0x500);
        put_u32(&mut bytes, 0x400 + 12, 0x700);
        put_u32(&mut bytes, 0x400 + 16, 0x600);
        put_text(&mut bytes, 0x700, "ntdll.dll");
        put_u64(&mut bytes, 0x500, 0x720);
        put_u64(&mut bytes, 0x508, (1u64 << 63) | 17);
        put_text(&mut bytes, 0x722, "NtClose");
        put_u64(&mut bytes, 0x600, 0x720);
        put_u64(&mut bytes, 0x608, (1u64 << 63) | 17);
        // Carga adiada: user32.dll, IAT em 0x800, INT em 0x840.
        put_u32(&mut bytes, 0x480, 1);
        put_u32(&mut bytes, 0x484, 0x760);
        put_u32(&mut bytes, 0x48C, 0x800);
        put_u32(&mut bytes, 0x490, 0x840);
        put_text(&mut bytes, 0x760, "user32.dll");
        put_u64(&mut bytes, 0x840, 0x780);
        put_text(&mut bytes, 0x782, "MessageBoxW");
        let image = PeImage::parse_mapped(bytes).expect("PE de teste");
        let base = 0x7FF6_0000_0000;
        let imports = ImportMap::from_pe(base, &image);
        assert_eq!(imports.len(), 3);
        let close = imports.get(base + 0x600).unwrap();
        assert_eq!(close.display(), "ntdll!NtClose");
        assert_eq!(close.slot_name("winlogon"), "winlogon!__imp_NtClose");
        assert_eq!(imports.get(base + 0x608).unwrap().name, "#17");
        let delayed = imports.get(base + 0x800).unwrap();
        assert!(delayed.delayed);
        assert_eq!(delayed.display(), "user32!MessageBoxW");
        assert!(!imports.contains(base + 0x610));
    }

    #[test]
    fn finds_thunk_slots() {
        // jmp qword ptr [rip+0x10] em 0x1000: o slot é 0x1006 + 0x10.
        assert_eq!(thunk_slot(0x1000, &[0xFF, 0x25, 0x10, 0, 0, 0]), Some(0x1016));
        // Com REX.W, a instrução tem 7 bytes.
        assert_eq!(thunk_slot(0x1000, &[0x48, 0xFF, 0x25, 0xF0, 0xFF, 0xFF, 0xFF]), Some(0x1007 - 0x10));
        assert_eq!(thunk_slot(0x1000, &[0xE9, 0, 0, 0, 0]), None);
        assert_eq!(thunk_slot(0x1000, &[0xFF, 0x25, 0]), None);
    }
}
