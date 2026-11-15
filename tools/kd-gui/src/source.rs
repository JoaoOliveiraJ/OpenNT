//! A linha de código de um endereço do kernel do OpenNT, pelo DWARF do
//! `kernel.elf` (o build do kernel guarda a informação de depuração): as
//! seções vêm do leitor de ELF do `kd-client` e o `addr2line` resolve
//! endereço -> arquivo e linha. Os arquivos são os do repositório (os
//! caminhos do DWARF são os do build).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use addr2line::gimli::{self, EndianSlice, RunTimeEndian};
use kd_client::elf::Elf;

type Reader = EndianSlice<'static, RunTimeEndian>;

/// Arquivo e linha de um endereço.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub file: String,
    pub line: u32,
}

pub struct LineTable {
    context: addr2line::Context<Reader>,
    /// As faixas do kernel no ELF (fora delas não há linha).
    base: u64,
    end: u64,
    files: HashMap<String, Arc<Vec<String>>>,
    pub path: PathBuf,
}

impl LineTable {
    /// Lê o ELF (os bytes ficam para a sessão inteira: as seções do DWARF
    /// apontam para eles).
    pub fn load(path: &Path) -> Result<LineTable, String> {
        let bytes: &'static [u8] = Box::leak(std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?.into_boxed_slice());
        let elf = Elf::parse(bytes)?;
        if elf.section_bytes(".debug_line").is_none_or(|section| section.is_empty()) {
            return Err(format!("{}: sem .debug_line (build sem informacao de depuracao)", path.display()));
        }
        let dwarf = gimli::Dwarf::load(|section: gimli::SectionId| -> Result<Reader, String> { Ok(EndianSlice::new(elf.section_bytes(section.name()).unwrap_or(&[]), RunTimeEndian::Little)) })?;
        let context = addr2line::Context::from_dwarf(dwarf).map_err(|error| format!("DWARF de {}: {error}", path.display()))?;
        let allocated = elf.sections.iter().filter(|section| section.flags & kd_client::elf::SHF_EXECINSTR != 0 && section.address != 0);
        let base = allocated.clone().map(|section| section.address).min().unwrap_or(0);
        let end = allocated.map(|section| section.address + section.size).max().unwrap_or(0);
        Ok(LineTable { context, base, end, files: HashMap::new(), path: path.to_path_buf() })
    }

    /// Arquivo e linha do endereço (o código embutido conta como a linha
    /// dele, não a da chamada).
    pub fn locate(&self, address: u64) -> Option<Position> {
        if address < self.base || address >= self.end {
            return None;
        }
        let location = self.context.find_location(address).ok()??;
        Some(Position { file: location.file?.to_string(), line: location.line? })
    }

    /// As linhas de um arquivo de código (guardadas depois da primeira
    /// leitura).
    pub fn file(&mut self, path: &str) -> Option<Arc<Vec<String>>> {
        if let Some(lines) = self.files.get(path) {
            return Some(Arc::clone(lines));
        }
        let text = std::fs::read_to_string(path).ok()?;
        let lines = Arc::new(text.lines().map(|line| line.replace('\t', "    ")).collect::<Vec<_>>());
        self.files.insert(path.to_string(), Arc::clone(&lines));
        Some(lines)
    }
}
