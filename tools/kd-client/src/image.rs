//! A imagem de um módulo para as análises (busca de referências, strings,
//! padrões, grafo de fluxo, limites de função, referências cruzadas, mapa
//! de memória, imports e tratadores de exceção).
//!
//! A ligação serial com o alvo é lenta para ler imagens inteiras. Por isso a
//! imagem vem, quando dá, do arquivo desta máquina: o PE da Microsoft
//! (cabeçalhos e cada seção na RVA dela) ou o `kernel.elf` do build (as
//! seções alocadas nas VAs em que o kernel roda). Só o que não tem arquivo
//! é lido da memória do alvo. Os patches da sessão são aplicados por cima,
//! então o cache de uma imagem vale até o próximo patch nela.

use std::sync::Arc;

use crate::analysis::decode::{self, Insn};
use crate::elf::{Elf, SHF_ALLOC};
use crate::pe::PeImage;

/// SHF_EXECINSTR do ELF.
const SHF_EXECINSTR: u64 = 4;
/// IMAGE_SCN_MEM_EXECUTE.
const SCN_EXECUTE: u32 = 0x2000_0000;
/// Maior imagem lida da memória do alvo.
const MEMORY_LIMIT: u64 = 8 << 20;

/// A imagem mapeada de um módulo.
#[derive(Clone, Debug, Default)]
pub struct ModuleImage {
    pub base: u64,
    pub end: u64,
    pub name: String,
    /// Os bytes de `base` em diante (o layout mapeado).
    pub bytes: Vec<u8>,
    /// As faixas de código (seções executáveis).
    pub code: Vec<(u64, u64)>,
    /// As seções: nome, início, fim e características (PE) ou flags (ELF).
    pub sections: Vec<(String, u64, u64, u32)>,
    /// De onde veio (`arquivo`, `kernel.elf`, `memoria`).
    pub source: &'static str,
}

impl ModuleImage {
    /// Bytes em `address` (`None` fora da imagem).
    pub fn read(&self, address: u64, length: usize) -> Option<Vec<u8>> {
        if address < self.base || address >= self.base + self.bytes.len() as u64 {
            return None;
        }
        let start = (address - self.base) as usize;
        let end = (start + length).min(self.bytes.len());
        Some(self.bytes[start..end].to_vec())
    }

    /// As instruções do código, por varredura linear de cada seção
    /// executável.
    pub fn instructions(&self) -> Vec<Insn> {
        let mut all = Vec::new();
        for &(start, end) in &self.code {
            if start < self.base || end > self.base + self.bytes.len() as u64 || end <= start {
                continue;
            }
            let slice = &self.bytes[(start - self.base) as usize..(end - self.base) as usize];
            all.extend(decode::decode_all(slice, start));
        }
        all
    }

    /// Os bytes de um patch aplicados por cima.
    pub fn apply(&mut self, address: u64, bytes: &[u8]) {
        for (index, byte) in bytes.iter().enumerate() {
            let at = address + index as u64;
            if at >= self.base && at < self.base + self.bytes.len() as u64 {
                self.bytes[(at - self.base) as usize] = *byte;
            }
        }
    }
}

/// A imagem mapeada a partir do arquivo PE desta máquina.
pub fn from_pe(base: u64, end: u64, name: &str, image: &PeImage) -> ModuleImage {
    let size = (image.header.size_of_image as u64).max(end.saturating_sub(base)).min(256 << 20) as usize;
    let mut bytes = vec![0u8; size];
    let headers = image.sections.iter().map(|section| section.raw as usize).filter(|&raw| raw > 0).min().unwrap_or(0x400).min(image.bytes.len()).min(size);
    bytes[..headers].copy_from_slice(&image.bytes[..headers]);
    let mut code = Vec::new();
    let mut sections = Vec::new();
    for section in &image.sections {
        let start = section.address as usize;
        let length = (section.raw_size as usize).min(section.virtual_size.max(section.raw_size) as usize);
        let raw = section.raw as usize;
        if start < size && raw < image.bytes.len() {
            let copy = length.min(size - start).min(image.bytes.len() - raw);
            bytes[start..start + copy].copy_from_slice(&image.bytes[raw..raw + copy]);
        }
        let section_end = base + section.address as u64 + section.virtual_size.max(section.raw_size) as u64;
        sections.push((section.name.clone(), base + section.address as u64, section_end, section.characteristics));
        if section.characteristics & SCN_EXECUTE != 0 {
            code.push((base + section.address as u64, base + section.address as u64 + section.virtual_size.min(section.raw_size.max(section.virtual_size)) as u64));
        }
    }
    ModuleImage { base, end, name: name.to_string(), bytes, code, sections, source: "arquivo" }
}

/// A imagem do kernel do OpenNT a partir do `kernel.elf` (as seções
/// alocadas, nas VAs ligadas).
pub fn from_elf(bytes: &[u8], name: &str) -> Result<ModuleImage, String> {
    let elf = Elf::parse(bytes)?;
    let allocated: Vec<_> = elf.sections.iter().filter(|section| section.flags & SHF_ALLOC != 0 && section.address != 0 && section.size != 0).collect();
    let base = allocated.iter().map(|section| section.address).min().ok_or("kernel.elf sem secoes alocadas")? & !0xFFF;
    let end = allocated.iter().map(|section| section.address + section.size).max().unwrap_or(base);
    let mut image = vec![0u8; (end - base).min(256 << 20) as usize];
    let mut code = Vec::new();
    let mut sections = Vec::new();
    for section in allocated {
        let start = (section.address - base) as usize;
        // NOBITS (.bss) fica zerado.
        if section.kind != 8 {
            if let Ok(data) = elf.range(section.offset, section.size) {
                let copy = data.len().min(image.len().saturating_sub(start));
                image[start..start + copy].copy_from_slice(&data[..copy]);
            }
        }
        sections.push((section.name.clone(), section.address, section.address + section.size, section.flags as u32));
        if section.flags & SHF_EXECINSTR != 0 {
            code.push((section.address, section.address + section.size));
        }
    }
    Ok(ModuleImage { base, end, name: name.to_string(), bytes: image, code, sections, source: "kernel.elf" })
}

/// A imagem lida da memória do alvo (cabeçalho PE em `base`), até 8 MB.
pub fn from_memory(base: u64, end: u64, name: &str, read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>) -> ModuleImage {
    let size = end.saturating_sub(base).min(MEMORY_LIMIT) as usize;
    let mut bytes = vec![0u8; size];
    let mut offset = 0;
    while offset < size {
        let chunk = (size - offset).min(0x1000);
        if let Some(data) = read(base + offset as u64, chunk) {
            bytes[offset..offset + data.len().min(chunk)].copy_from_slice(&data[..data.len().min(chunk)]);
        }
        offset += chunk;
    }
    let mut code = Vec::new();
    let mut sections = Vec::new();
    if let Some(header) = PeImage::parse_mapped(bytes[..size.min(0x1000)].to_vec()) {
        for section in &header.sections {
            let start = base + section.address as u64;
            let section_end = start + section.virtual_size as u64;
            sections.push((section.name.clone(), start, section_end, section.characteristics));
            if section.characteristics & SCN_EXECUTE != 0 {
                code.push((start, section_end.min(base + size as u64)));
            }
        }
    }
    if code.is_empty() {
        code.push((base, base + size as u64));
    }
    ModuleImage { base, end, name: name.to_string(), bytes, code, sections, source: "memoria" }
}

/// Um import de um PE: o slot da IAT (RVA), a DLL e o nome (ou `#ordinal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Import {
    pub slot: u32,
    pub dll: String,
    pub name: String,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes.get(offset..offset + 4).map(|slice| u32::from_le_bytes(slice.try_into().unwrap_or([0; 4])))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|slice| u64::from_le_bytes(slice.try_into().unwrap_or([0; 8])))
}

fn c_string(bytes: &[u8], offset: usize) -> String {
    let tail = bytes.get(offset..).unwrap_or(&[]);
    let end = tail.iter().position(|&byte| byte == 0).unwrap_or(tail.len()).min(256);
    String::from_utf8_lossy(&tail[..end]).to_string()
}

/// A tabela de imports (diretório 1) de uma imagem mapeada.
pub fn imports(image: &ModuleImage) -> Vec<Import> {
    let bytes = &image.bytes;
    let Some(header) = PeImage::parse_mapped(bytes[..bytes.len().min(0x1000)].to_vec()) else { return Vec::new() };
    let Some((rva, size)) = header.directory(1) else { return Vec::new() };
    let mut imports = Vec::new();
    let mut descriptor = rva as usize;
    while descriptor + 20 <= (rva + size.max(20)) as usize && descriptor + 20 <= bytes.len() && imports.len() < 20000 {
        let original = u32_at(bytes, descriptor).unwrap_or(0);
        let name = u32_at(bytes, descriptor + 12).unwrap_or(0);
        let first = u32_at(bytes, descriptor + 16).unwrap_or(0);
        if name == 0 && first == 0 {
            break;
        }
        let dll = c_string(bytes, name as usize);
        let lookup = if original != 0 { original } else { first };
        for index in 0..4096usize {
            let entry = u64_at(bytes, lookup as usize + index * 8).unwrap_or(0);
            if entry == 0 {
                break;
            }
            let function = if entry >> 63 != 0 { format!("#{}", entry & 0xFFFF) } else { c_string(bytes, (entry & 0x7FFF_FFFF) as usize + 2) };
            imports.push(Import { slot: first + (index * 8) as u32, dll: dll.clone(), name: function });
        }
        descriptor += 20;
    }
    imports
}

/// O tratador de exceção de uma função (do UNWIND_INFO dela): o endereço
/// do tratador, os tipos (EHANDLER, UHANDLER) e, para o
/// `__C_specific_handler`, as faixas de escopo (início, fim, filtro ou
/// tratador, destino).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Handler {
    pub function: u64,
    pub unwind: u64,
    pub flags: u8,
    pub handler: Option<u64>,
    pub scopes: Vec<(u64, u64, u64, u64)>,
}

/// O tratador pelo UNWIND_INFO em `unwind` (RVA) da imagem (seguindo a
/// informação encadeada até a função principal).
pub fn handler(image: &ModuleImage, function: u64, unwind: u32) -> Handler {
    let mut result = Handler { function, unwind: image.base + unwind as u64, ..Default::default() };
    let mut rva = unwind;
    for _ in 0..8 {
        let Some(header) = image.read(image.base + rva as u64, 4) else { return result };
        if header.len() < 4 {
            return result;
        }
        let flags = header[0] >> 3;
        let count = header[2] as usize;
        let after = rva as u64 + 4 + 2 * ((count as u64 + 1) & !1);
        if flags & 4 != 0 {
            // Encadeado: o RUNTIME_FUNCTION da função principal vem depois.
            let Some(entry) = image.read(image.base + after, 12) else { return result };
            rva = u32_at(&entry, 8).unwrap_or(0);
            continue;
        }
        result.flags = flags;
        if flags & 3 != 0 {
            let Some(data) = image.read(image.base + after, 8 + 16 * 32) else { return result };
            let handler_rva = u32_at(&data, 0).unwrap_or(0);
            result.handler = Some(image.base + handler_rva as u64);
            // Tabela de escopo do __C_specific_handler: contagem e entradas.
            let entries = u32_at(&data, 4).unwrap_or(0) as usize;
            if (1..=32).contains(&entries) {
                for index in 0..entries {
                    let at = 8 + index * 16;
                    let field = |offset: usize| u32_at(&data, at + offset).unwrap_or(0) as u64;
                    let (begin, end, filter, target) = (field(0), field(4), field(8), field(12));
                    if begin == 0 || end <= begin || end > image.bytes.len() as u64 {
                        result.scopes.clear();
                        break;
                    }
                    let absolute = |rva: u64| if rva > 1 { image.base + rva } else { rva };
                    result.scopes.push((image.base + begin, image.base + end, absolute(filter), absolute(target)));
                }
            }
        }
        return result;
    }
    result
}

/// Uma imagem compartilhada entre análises.
pub type SharedImage = Arc<ModuleImage>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_code_and_reads_bytes() {
        let mut image = ModuleImage { base: 0x1000, end: 0x1010, name: "teste".into(), bytes: vec![0x90, 0xC3, 0, 0, 0x48, 0x8D, 0x0D, 0, 0, 0, 0, 0xC3, 0, 0, 0, 0], code: vec![(0x1000, 0x100C)], sections: Vec::new(), source: "teste" };
        let instructions = image.instructions();
        assert!(instructions.iter().any(|insn| insn.address == 0x1004 && insn.memory == Some(0x100B)));
        assert_eq!(image.read(0x1000, 2), Some(vec![0x90, 0xC3]));
        assert_eq!(image.read(0x2000, 2), None);
        image.apply(0x1000, &[0xCC]);
        assert_eq!(image.read(0x1000, 1), Some(vec![0xCC]));
    }

    #[test]
    fn reads_a_scope_table() {
        // UNWIND_INFO em 0x100: versão 1, flags EHANDLER, 0 códigos; o
        // tratador em 0x200 e uma faixa [0x10, 0x20) com filtro 1 e
        // destino 0x30.
        let mut bytes = vec![0u8; 0x400];
        bytes[0x100] = 1 | (1 << 3);
        bytes[0x104..0x108].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x108..0x10C].copy_from_slice(&1u32.to_le_bytes());
        for (index, value) in [0x10u32, 0x20, 1, 0x30].iter().enumerate() {
            bytes[0x10C + index * 4..0x110 + index * 4].copy_from_slice(&value.to_le_bytes());
        }
        let image = ModuleImage { base: 0x7000_0000, end: 0x7000_0400, name: "m".into(), bytes, code: Vec::new(), sections: Vec::new(), source: "teste" };
        let handler = handler(&image, 0x7000_0010, 0x100);
        assert_eq!(handler.handler, Some(0x7000_0200));
        assert_eq!(handler.scopes, vec![(0x7000_0010, 0x7000_0020, 1, 0x7000_0030)]);
    }
}
