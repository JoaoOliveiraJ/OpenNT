//! Símbolos do cliente do depurador.
//!
//! - O kernel do OpenNT: a tabela de símbolos do ELF do build
//!   (`<build>/kernel.elf`), com os nomes do Rust legíveis; o kernel roda na
//!   VA em que foi ligado, então os endereços do ELF valem como estão.
//! - Os binários da Microsoft carregados (a lista `monitor lm` do alvo): a
//!   tabela de exports de cada PE, lida do arquivo desta máquina, e, quando o
//!   PDB público dele já está no cache do `cargo xtask nt-types`
//!   (`build/symbols/<nome>.pdb`, com GUID e idade iguais aos do RSDS do
//!   PE), os nomes públicos (S_PUB32) do PDB. Nada é baixado.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::demangle::demangle;
use crate::elf::Elf;
use crate::nt_types::pdb::Msf;

#[derive(Clone, Debug)]
pub struct Symbol {
    pub address: u64,
    pub size: u64,
    pub name: String,
    pub function: bool,
}

#[derive(Debug)]
pub struct Module {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub end: u64,
    /// Ordenados pelo endereço.
    pub symbols: Vec<Symbol>,
    /// De onde vieram os símbolos (para o `lm` do cliente).
    pub source: String,
}

#[derive(Default)]
pub struct Symbols {
    pub modules: Vec<Module>,
    /// Índice do módulo do kernel (o ELF).
    kernel: Option<usize>,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn c_string(bytes: &[u8], at: usize) -> Option<String> {
    let tail = bytes.get(at..)?;
    let end = tail.iter().position(|&byte| byte == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/// Nome base sem diretório (barras dos dois tipos).
pub fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// O PE de um módulo: seções, exports e o RSDS.
struct PeImage {
    bytes: Vec<u8>,
    sections: Vec<(u32, u32, u32, u32)>,
    directories: usize,
}

impl PeImage {
    fn parse(bytes: Vec<u8>) -> Option<Self> {
        let pe = u32_at(&bytes, 0x3C)? as usize;
        if bytes.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let count = u16_at(&bytes, pe + 6)? as usize;
        let optional_size = u16_at(&bytes, pe + 20)? as usize;
        let optional = pe + 24;
        let directories = match u16_at(&bytes, optional)? {
            0x20B => optional + 112,
            0x10B => optional + 96,
            _ => return None,
        };
        let mut sections = Vec::with_capacity(count);
        for index in 0..count {
            let header = optional + optional_size + 40 * index;
            sections.push((u32_at(&bytes, header + 12)?, u32_at(&bytes, header + 8)?, u32_at(&bytes, header + 20)?, u32_at(&bytes, header + 16)?));
        }
        Some(Self { bytes, sections, directories })
    }

    fn offset(&self, rva: u32) -> Option<usize> {
        self.sections.iter().find_map(|&(address, size, raw, raw_size)| (rva >= address && rva - address < size.max(raw_size)).then(|| (raw + rva - address) as usize))
    }

    fn directory(&self, index: usize) -> Option<(u32, u32)> {
        Some((u32_at(&self.bytes, self.directories + 8 * index)?, u32_at(&self.bytes, self.directories + 8 * index + 4)?))
    }

    /// (RVA, nome) dos exports nomeados que não são encaminhamentos.
    fn exports(&self) -> Vec<(u32, String)> {
        let mut exports = Vec::new();
        let Some((rva, size)) = self.directory(0) else { return exports };
        let Some(directory) = self.offset(rva) else { return exports };
        let (Some(names), Some(functions), Some(name_table), Some(ordinals)) = (
            u32_at(&self.bytes, directory + 24),
            u32_at(&self.bytes, directory + 28).and_then(|rva| self.offset(rva)),
            u32_at(&self.bytes, directory + 32).and_then(|rva| self.offset(rva)),
            u32_at(&self.bytes, directory + 36).and_then(|rva| self.offset(rva)),
        ) else {
            return exports;
        };
        for index in 0..names as usize {
            let Some(name) = u32_at(&self.bytes, name_table + 4 * index).and_then(|rva| self.offset(rva)).and_then(|at| c_string(&self.bytes, at)) else { continue };
            let Some(ordinal) = u16_at(&self.bytes, ordinals + 2 * index) else { continue };
            let Some(function) = u32_at(&self.bytes, functions + 4 * ordinal as usize) else { continue };
            if function >= rva && function < rva + size {
                continue;
            }
            exports.push((function, name));
        }
        exports
    }

    /// GUID, idade e nome do PDB (RSDS).
    fn rsds(&self) -> Option<([u8; 16], u32, String)> {
        let (rva, size) = self.directory(6)?;
        let directory = self.offset(rva)?;
        for entry in 0..size as usize / 28 {
            let at = directory + 28 * entry;
            if u32_at(&self.bytes, at + 12)? != 2 {
                continue;
            }
            let data = u32_at(&self.bytes, at + 24)? as usize;
            if self.bytes.get(data..data + 4)? != b"RSDS" {
                continue;
            }
            let guid: [u8; 16] = self.bytes.get(data + 4..data + 20)?.try_into().ok()?;
            return Some((guid, u32_at(&self.bytes, data + 20)?, c_string(&self.bytes, data + 24)?));
        }
        None
    }
}

/// Os nomes públicos (S_PUB32) de um PDB, em RVA pelas seções do PE.
fn pdb_publics(pdb: &Path, image: &PeImage) -> Option<Vec<(u32, String)>> {
    let msf = Msf::parse(std::fs::read(pdb).ok()?).ok()?;
    let (guid, age, _) = image.rsds()?;
    if msf.identity().ok()? != (guid, age) {
        return None;
    }
    let dbi = msf.stream(3).ok()?;
    let records = msf.stream(u16_at(&dbi, 20)? as usize).ok()?;
    let mut publics = Vec::new();
    let mut at = 0;
    while at + 4 <= records.len() {
        let length = u16_at(&records, at)? as usize;
        let kind = u16_at(&records, at + 2)?;
        // S_PUB32: flags, offset, segmento, nome.
        if kind == 0x110E {
            let offset = u32_at(&records, at + 8)?;
            let segment = u16_at(&records, at + 12)? as usize;
            if let (Some(name), Some(&(address, _, _, _))) = (c_string(&records, at + 14), segment.checked_sub(1).and_then(|index| image.sections.get(index))) {
                publics.push((address + offset, name));
            }
        }
        at += 2 + length;
    }
    Some(publics)
}

/// O arquivo desta máquina para um módulo carregado no alvo.
fn host_file(path: &str) -> Option<PathBuf> {
    let windows = PathBuf::from(r"C:\Windows");
    let normalized = path.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    let mut candidates = Vec::new();
    for marker in [r"\systemroot\", r"\windows\"] {
        if let Some(index) = lower.find(marker) {
            candidates.push(windows.join(&normalized[index + marker.len()..]));
        }
    }
    let base = base_name(path);
    candidates.push(windows.join("System32").join(base));
    candidates.push(windows.join("System32").join("drivers").join(base));
    candidates.into_iter().find(|candidate| candidate.is_file())
}

impl Symbols {
    /// Símbolos do kernel a partir do ELF do build.
    pub fn load_kernel(&mut self, elf_path: &Path) -> Result<usize, String> {
        let bytes = std::fs::read(elf_path).map_err(|error| format!("{}: {error}", elf_path.display()))?;
        let elf = Elf::parse(&bytes)?;
        let mut symbols: Vec<Symbol> = elf
            .symbol_entries()?
            .into_iter()
            .filter(|entry| entry.address != 0 && matches!(entry.kind, 0..=2))
            .map(|entry| Symbol { address: entry.address, size: entry.size, name: demangle(&entry.name).unwrap_or(entry.name), function: entry.kind == 2 })
            .collect();
        symbols.sort_by_key(|symbol| symbol.address);
        let allocated = elf.sections.iter().filter(|section| section.flags & crate::elf::SHF_ALLOC != 0 && section.address != 0);
        let base = allocated.clone().map(|section| section.address).min().unwrap_or(0) & !0xFFF;
        let end = allocated.map(|section| section.address + section.size).max().unwrap_or(0);
        let count = symbols.len();
        let module = Module { name: "kernel".into(), path: elf_path.display().to_string(), base, end, symbols, source: "ELF do kernel".into() };
        match self.kernel {
            Some(index) => self.modules[index] = module,
            None => {
                self.kernel = Some(self.modules.len());
                self.modules.push(module);
            }
        }
        Ok(count)
    }

    /// Troca os módulos carregados (fora o kernel) pela lista do alvo:
    /// (base, fim, caminho). `root` é a raiz do repositório (o cache de PDBs).
    pub fn set_modules(&mut self, list: &[(u64, u64, String)], root: &Path) {
        let kernel = self.kernel.map(|index| self.modules.swap_remove(index));
        let mut previous: HashMap<(u64, String), Module> = self.modules.drain(..).map(|module| ((module.base, module.path.clone()), module)).collect();
        self.kernel = None;
        if let Some(kernel) = kernel {
            self.kernel = Some(0);
            self.modules.push(kernel);
        }
        for (base, end, path) in list {
            // A imagem do kernel do OpenNT (o ntoskrnl.exe da lista, com os
            // cabeçalhos antes da primeira seção do ELF) fica com os símbolos
            // do ELF, nunca com os exports do ntoskrnl desta máquina.
            if let Some(index) = self.kernel {
                let kernel = &mut self.modules[index];
                if *base < kernel.end && *end > kernel.base {
                    kernel.base = kernel.base.min(*base);
                    kernel.name = base_name(path).to_string();
                    continue;
                }
            }
            if let Some(module) = previous.remove(&(*base, path.clone())) {
                self.modules.push(module);
                continue;
            }
            self.modules.push(Self::load_module(*base, *end, path, root));
        }
    }

    fn load_module(base: u64, end: u64, path: &str, root: &Path) -> Module {
        let mut module = Module { name: base_name(path).to_string(), path: path.to_string(), base, end, symbols: Vec::new(), source: "sem simbolos".into() };
        let Some(file) = host_file(path) else { return module };
        let Some(image) = std::fs::read(&file).ok().and_then(PeImage::parse) else { return module };
        let mut names: Vec<(u32, String)> = image.exports();
        module.source = format!("exports de {}", file.display());
        if let Some((_, _, pdb_name)) = image.rsds() {
            let cached = root.join("build").join("symbols").join(base_name(&pdb_name));
            if cached.is_file() {
                if let Some(publics) = pdb_publics(&cached, &image) {
                    module.source = format!("{} + PDB {}", module.source, cached.display());
                    names.extend(publics);
                }
            }
        }
        let mut symbols: Vec<Symbol> = names.into_iter().map(|(rva, name)| Symbol { address: base + rva as u64, size: 0, name, function: true }).collect();
        symbols.sort_by_key(|symbol| symbol.address);
        symbols.dedup_by(|a, b| a.address == b.address && a.name == b.name);
        module.symbols = symbols;
        module
    }

    fn module_at(&self, address: u64) -> Option<&Module> {
        self.modules.iter().find(|module| address >= module.base && address < module.end)
    }

    /// `módulo!símbolo+0x10`, `símbolo+0x10` (kernel) ou `módulo+0xRVA`.
    pub fn describe(&self, address: u64) -> String {
        let Some(module) = self.module_at(address) else { return format!("{address:#x}") };
        let kernel = self.kernel.is_some_and(|index| std::ptr::eq(&self.modules[index], module));
        let index = module.symbols.partition_point(|symbol| symbol.address <= address);
        // O último símbolo de função que contém o endereço (ou o mais próximo
        // antes dele, sem tamanho conhecido).
        let found = module.symbols[..index].iter().rev().take(64).find(|symbol| symbol.function && (symbol.size == 0 || address < symbol.address + symbol.size)).or_else(|| module.symbols[..index].last().filter(|symbol| symbol.size == 0 || address < symbol.address + symbol.size));
        let prefix = if kernel { String::new() } else { format!("{}!", module.name) };
        match found {
            Some(symbol) if address == symbol.address => format!("{prefix}{}", symbol.name),
            Some(symbol) => format!("{prefix}{}+{:#x}", symbol.name, address - symbol.address),
            None => format!("{}+{:#x}", module.name, address - module.base),
        }
    }

    /// Um endereço de retorno: o símbolo da instrução de chamada (o byte
    /// anterior), com o deslocamento do próprio endereço.
    pub fn describe_return(&self, address: u64) -> String {
        let before = self.describe(address.wrapping_sub(1));
        match before.rsplit_once("+0x") {
            Some((name, offset)) => match u64::from_str_radix(offset, 16) {
                Ok(offset) => format!("{name}+{:#x}", offset + 1),
                Err(_) => before,
            },
            None if before.starts_with("0x") => format!("{address:#x}"),
            None => format!("{before}+0x1"),
        }
    }

    /// Endereço de um nome: `módulo!símbolo`, o nome completo, o nome sem os
    /// argumentos genéricos ou o fim do caminho (`::nome`).
    pub fn lookup(&self, query: &str) -> Result<u64, String> {
        if let Some((module, name)) = query.split_once('!') {
            let wanted = module.to_ascii_lowercase();
            let module = self
                .modules
                .iter()
                .find(|candidate| {
                    let lower = candidate.name.to_ascii_lowercase();
                    lower == wanted || lower.rsplit_once('.').is_some_and(|(stem, _)| stem == wanted)
                })
                .ok_or_else(|| format!("modulo {module} nao carregado"))?;
            return module.symbols.iter().find(|symbol| symbol.name == name).map(|symbol| symbol.address).ok_or_else(|| format!("{query}: simbolo nao encontrado"));
        }
        let all = || self.modules.iter().flat_map(|module| module.symbols.iter());
        let pick = |matches: Vec<&Symbol>| -> Option<Result<u64, String>> {
            if matches.is_empty() {
                return None;
            }
            let functions: Vec<&&Symbol> = matches.iter().filter(|symbol| symbol.function).collect();
            let chosen: Vec<&Symbol> = if functions.is_empty() { matches.clone() } else { functions.into_iter().copied().collect() };
            let mut addresses: Vec<u64> = chosen.iter().map(|symbol| symbol.address).collect();
            addresses.sort_unstable();
            addresses.dedup();
            if addresses.len() == 1 {
                return Some(Ok(addresses[0]));
            }
            let names: Vec<String> = chosen.iter().take(6).map(|symbol| format!("{} ({:#x})", symbol.name, symbol.address)).collect();
            Some(Err(format!("{query}: ambiguo entre {}", names.join(", "))))
        };
        if let Some(result) = pick(all().filter(|symbol| symbol.name == query).collect()) {
            return result;
        }
        let without_generics = |name: &str| -> String {
            let mut depth = 0;
            let mut output = String::new();
            for character in name.chars() {
                match character {
                    '<' => depth += 1,
                    '>' if depth > 0 => depth -= 1,
                    _ if depth == 0 => output.push(character),
                    _ => {}
                }
            }
            output.replace("::::", "::").trim_end_matches("::").to_string()
        };
        if let Some(result) = pick(all().filter(|symbol| without_generics(&symbol.name) == query).collect()) {
            return result;
        }
        let suffix = format!("::{query}");
        if let Some(result) = pick(all().filter(|symbol| symbol.name.ends_with(&suffix) || without_generics(&symbol.name).ends_with(&suffix)).collect()) {
            return result;
        }
        Err(format!("{query}: simbolo nao encontrado"))
    }
}
