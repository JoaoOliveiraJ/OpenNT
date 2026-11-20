//! A linha de código e as variáveis locais de um endereço do kernel do
//! OpenNT, pelo DWARF do `kernel.elf` (o build do kernel guarda a
//! informação de depuração): as seções vêm do leitor de ELF do `opennt-kd`,
//! o `addr2line` resolve endereço -> arquivo e linha e o `gimli` acha os
//! parâmetros e as variáveis do escopo e avalia a posição de cada um (pilha
//! pelo frame base, registrador, lista de posições). Os arquivos são os do
//! repositório (os caminhos do DWARF são os do build).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use addr2line::gimli::{self, EndianSlice, RunTimeEndian};
use opennt_kd::elf::Elf;
use opennt_kd::unwind::ReadMemory;

type Reader = EndianSlice<'static, RunTimeEndian>;

/// Arquivo e linha de um endereço.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub file: String,
    pub line: u32,
}

/// Uma variável local ou parâmetro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Local {
    pub name: String,
    pub type_name: String,
    /// Onde está (`[rbp-0x18]`, `rdi`, `otimizada`).
    pub location: String,
    pub value: String,
    pub parameter: bool,
}

pub struct LineTable {
    context: addr2line::Context<Reader>,
    /// As faixas do kernel no ELF (fora delas não há linha).
    base: u64,
    end: u64,
    files: HashMap<String, Arc<Vec<String>>>,
    pub path: PathBuf,
}

/// Os registradores do DWARF x86-64 pelo número.
const DWARF_REGISTERS: [&str; 17] = ["rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];

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
        let context = addr2line::Context::from_arc_dwarf(Arc::new(dwarf)).map_err(|error| format!("DWARF de {}: {error}", path.display()))?;
        let allocated = elf.sections.iter().filter(|section| section.flags & opennt_kd::elf::SHF_EXECINSTR != 0 && section.address != 0);
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
        let text = std::fs::read_to_string(path).ok().or_else(|| read_beside_elf(&self.path, path))?;
        let lines = Arc::new(text.lines().map(|line| line.replace('\t', "    ")).collect::<Vec<_>>());
        self.files.insert(path.to_string(), Arc::clone(&lines));
        Some(lines)
    }

    /// Os parâmetros e as variáveis dos escopos que contêm `pc`, com os
    /// valores lidos dos registradores do quadro e da memória.
    pub fn locals(&self, pc: u64, registers: &[(String, u64)], memory: &mut dyn ReadMemory) -> Result<Vec<Local>, String> {
        if pc < self.base || pc >= self.end {
            return Err("variaveis locais so no codigo do OpenNT (DWARF do kernel.elf)".into());
        }
        let unit = self.context.find_dwarf_and_unit(pc).skip_all_loads().ok_or("sem unidade do DWARF para o endereco")?;
        let register = |number: u16| -> Option<u64> {
            let name = DWARF_REGISTERS.get(number as usize)?;
            registers.iter().find(|(register, _)| register == name).map(|(_, value)| *value)
        };
        let rbp = register(6);
        let mut cursor = unit.entries();
        // (profundidade, o escopo contém o pc, frame base do subprograma)
        let mut scopes: Vec<(isize, bool, Option<gimli::Expression<Reader>>)> = Vec::new();
        let mut found: Vec<(gimli::UnitOffset, Option<gimli::Expression<Reader>>)> = Vec::new();
        while let Some(entry) = cursor.next_dfs().map_err(|error| error.to_string())? {
            let depth = entry.depth();
            while scopes.last().is_some_and(|(scope_depth, _, _)| *scope_depth >= depth) {
                scopes.pop();
            }
            let parent_contains = scopes.last().is_none_or(|(_, contains, _)| *contains);
            match entry.tag() {
                gimli::DW_TAG_subprogram | gimli::DW_TAG_inlined_subroutine | gimli::DW_TAG_lexical_block => {
                    let mut contains = false;
                    if parent_contains {
                        if let Ok(mut ranges) = unit.die_ranges(entry) {
                            while let Ok(Some(range)) = ranges.next() {
                                if pc >= range.begin && pc < range.end {
                                    contains = true;
                                    break;
                                }
                            }
                        }
                    }
                    let frame_base = match entry.attr_value(gimli::DW_AT_frame_base) {
                        Some(gimli::AttributeValue::Exprloc(expression)) => Some(expression),
                        _ => scopes.last().and_then(|(_, _, base)| base.clone()),
                    };
                    scopes.push((depth, contains, frame_base));
                }
                gimli::DW_TAG_formal_parameter | gimli::DW_TAG_variable => {
                    if let Some((_, true, frame_base)) = scopes.last() {
                        found.push((entry.offset(), frame_base.clone()));
                    }
                }
                _ => {}
            }
        }
        if found.is_empty() {
            return Err("nenhuma variavel no escopo (funcao sem informacao de depuracao)".into());
        }
        let mut locals = Vec::new();
        for (offset, frame_base) in found.into_iter().take(64) {
            let Ok(entry) = unit.entry(offset) else { continue };
            // Variáveis de código embutido trazem nome e tipo pela origem.
            let origin = match entry.attr_value(gimli::DW_AT_abstract_origin) {
                Some(gimli::AttributeValue::UnitRef(origin)) => unit.entry(origin).ok(),
                _ => None,
            };
            let attribute = |name: gimli::DwAt| entry.attr_value(name).or_else(|| origin.as_ref().and_then(|origin| origin.attr_value(name)));
            let Some(name) = attribute(gimli::DW_AT_name).and_then(|value| unit.attr_string(value).ok()).map(|text| text.to_string_lossy().into_owned()) else { continue };
            let (type_name, size) = match attribute(gimli::DW_AT_type) {
                Some(gimli::AttributeValue::UnitRef(type_offset)) => describe_type(&unit, type_offset, 0),
                _ => ("?".into(), 0),
            };
            let parameter = entry.tag() == gimli::DW_TAG_formal_parameter;
            let expression = match entry.attr_value(gimli::DW_AT_location) {
                Some(gimli::AttributeValue::Exprloc(expression)) => Some(expression),
                Some(gimli::AttributeValue::LocationListsRef(list)) => location_at(&unit, list, pc),
                _ => None,
            };
            let Some(expression) = expression else {
                locals.push(Local { name, type_name, location: "otimizada".into(), value: "-".into(), parameter });
                continue;
            };
            let frame_base_value = frame_base.and_then(|base| evaluate(&unit, base, None, &register, rbp, memory).ok()).and_then(|place| match place {
                Place::Register(number) => register(number),
                Place::Address(address) => Some(address),
                Place::Value(value) => Some(value),
            });
            let (location, value) = match evaluate(&unit, expression, frame_base_value, &register, rbp, memory) {
                Ok(Place::Register(number)) => {
                    let name = DWARF_REGISTERS.get(number as usize).copied().unwrap_or("?");
                    (name.to_string(), register(number).map(|value| format_value(value, size)).unwrap_or_else(|| "?".into()))
                }
                Ok(Place::Address(address)) => {
                    let value = if size == 0 || size > 8 {
                        format!("em {address:#x}")
                    } else {
                        match memory.read(address, size as usize) {
                            Ok(bytes) if bytes.len() == size as usize => {
                                let mut raw = [0u8; 8];
                                raw[..bytes.len()].copy_from_slice(&bytes);
                                format_value(u64::from_le_bytes(raw), size)
                            }
                            _ => "ilegivel".into(),
                        }
                    };
                    (format!("[{address:#x}]"), value)
                }
                Ok(Place::Value(value)) => ("valor".into(), format_value(value, size)),
                Err(error) => ("?".into(), error),
            };
            locals.push(Local { name, type_name, location, value, parameter });
        }
        Ok(locals)
    }
}

/// Um caminho relativo do DWARF (o kernel e o stage2 saem com a pasta do
/// workspace trocada por `.`, o trim-paths do Cargo.toml) lido a partir das
/// pastas acima do ELF, a primeira que tiver o arquivo.
fn read_beside_elf(elf: &Path, path: &str) -> Option<String> {
    let relative = Path::new(path);
    if relative.is_absolute() {
        return None;
    }
    elf.ancestors().skip(1).find_map(|folder| std::fs::read_to_string(folder.join(relative)).ok())
}

fn format_value(value: u64, size: u64) -> String {
    let value = if size > 0 && size < 8 { value & ((1u64 << (8 * size)) - 1) } else { value };
    format!("{value:#x} ({value})")
}

/// Onde o valor está.
enum Place {
    Register(u16),
    Address(u64),
    Value(u64),
}

/// A expressão de posição válida em `pc` numa lista de posições.
fn location_at(unit: &gimli::UnitRef<'_, Reader>, list: gimli::LocationListsOffset, pc: u64) -> Option<gimli::Expression<Reader>> {
    let mut locations = unit.locations(list).ok()?;
    while let Ok(Some(entry)) = locations.next() {
        if pc >= entry.range.begin && pc < entry.range.end {
            return Some(entry.data);
        }
    }
    None
}

/// Avalia uma expressão de posição do DWARF.
fn evaluate(unit: &gimli::UnitRef<'_, Reader>, expression: gimli::Expression<Reader>, frame_base: Option<u64>, register: &dyn Fn(u16) -> Option<u64>, rbp: Option<u64>, memory: &mut dyn ReadMemory) -> Result<Place, String> {
    let mut evaluation = expression.evaluation(unit.encoding());
    let mut result = evaluation.evaluate().map_err(|error| error.to_string())?;
    for _ in 0..64 {
        result = match result {
            gimli::EvaluationResult::Complete => break,
            gimli::EvaluationResult::RequiresRegister { register: number, .. } => {
                let value = register(number.0).ok_or_else(|| format!("registrador {} desconhecido", number.0))?;
                evaluation.resume_with_register(gimli::Value::Generic(value)).map_err(|error| error.to_string())?
            }
            gimli::EvaluationResult::RequiresFrameBase => evaluation.resume_with_frame_base(frame_base.ok_or("sem frame base")?).map_err(|error| error.to_string())?,
            // Com frame pointers, o CFA é RBP + 16.
            gimli::EvaluationResult::RequiresCallFrameCfa => evaluation.resume_with_call_frame_cfa(rbp.ok_or("sem RBP")? + 16).map_err(|error| error.to_string())?,
            gimli::EvaluationResult::RequiresMemory { address, size, .. } => {
                let bytes = memory.read(address, size as usize)?;
                let mut raw = [0u8; 8];
                raw[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
                evaluation.resume_with_memory(gimli::Value::Generic(u64::from_le_bytes(raw))).map_err(|error| error.to_string())?
            }
            gimli::EvaluationResult::RequiresRelocatedAddress(address) => evaluation.resume_with_relocated_address(address).map_err(|error| error.to_string())?,
            other => return Err(format!("posicao nao suportada ({other:?})")),
        };
    }
    let pieces = evaluation.result();
    let piece = pieces.first().ok_or("posicao vazia")?;
    match &piece.location {
        gimli::Location::Register { register } => Ok(Place::Register(register.0)),
        gimli::Location::Address { address } => Ok(Place::Address(*address)),
        gimli::Location::Value { value } => Ok(Place::Value(value.to_u64(!0).unwrap_or(0))),
        gimli::Location::Empty => Err("otimizada".into()),
        _ => Err("posicao nao suportada".into()),
    }
}

/// O nome e o tamanho de um tipo do DWARF.
fn describe_type(unit: &gimli::UnitRef<'_, Reader>, offset: gimli::UnitOffset, depth: usize) -> (String, u64) {
    let Ok(entry) = unit.entry(offset) else { return ("?".into(), 0) };
    let name = entry.attr_value(gimli::DW_AT_name).and_then(|value| unit.attr_string(value).ok()).map(|text| text.to_string_lossy().into_owned());
    let size = entry.attr_value(gimli::DW_AT_byte_size).and_then(|value| value.udata_value()).unwrap_or(0);
    let inner = || match entry.attr_value(gimli::DW_AT_type) {
        Some(gimli::AttributeValue::UnitRef(inner)) if depth < 8 => describe_type(unit, inner, depth + 1),
        _ => ("()".into(), 0),
    };
    match entry.tag() {
        gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type => (format!("*{}", name.unwrap_or_else(|| inner().0)), 8),
        gimli::DW_TAG_typedef | gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type => {
            let (inner_name, inner_size) = inner();
            (name.unwrap_or(inner_name), inner_size)
        }
        _ => (name.unwrap_or_else(|| "?".into()), size),
    }
}
