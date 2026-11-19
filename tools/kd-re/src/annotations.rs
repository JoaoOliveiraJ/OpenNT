//! Os comentários que o opennt-re acrescenta às linhas da desmontagem:
//!
//! - o import de cada `call [__imp_X]`, `jmp [__imp_X]` e trampolim, com o
//!   destino real do slot quando difere (a DLL que o carregador escolheu
//!   para um API set, ou o `__imp_load_` de uma carga adiada que ainda não
//!   aconteceu), e o destino de um ponteiro de função global;
//! - o alvo das chamadas protegidas pelo CFG (`__guard_dispatch_icall_fptr`
//!   e companhia): o RAX montado antes da chamada, ou o de verdade na
//!   linha do RIP;
//! - a string de um operando relativo ao RIP e o import lido da IAT;
//! - os nomes de NTSTATUS e HRESULT nos imediatos e os erros do Win32 em
//!   volta de `GetLastError`/`SetLastError`;
//! - os campos dos tipos do PDB nos operandos de memória: `gs:` é a KPCR
//!   no kernel e a TEB no modo usuário, e os registradores com tipo (dado
//!   pelo usuário num endereço, ou deduzido de um campo ponteiro lido antes)
//!   dão nome a `[reg+deslocamento]` (`_EPROCESS.UniqueProcessId`).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use kd_client::analysis::refs::read_string;
use kd_client::types::{Kind, Member, TypeDb};
use kd_client::{Client, Symbols};
use kd_mcp::annotate::Live;

use crate::codes::codes;
use crate::disasm::Line;
use crate::imports::{thunk_slot, Import, ImportMap};

/// IMAGE_SCN_MEM_WRITE.
const SCN_WRITE: u32 = 0x8000_0000;
/// Instruções olhadas para trás atrás de quem montou um registrador.
const LOOKBACK: usize = 16;

/// Os imports de cada módulo, lidos do PE desta máquina na primeira vez.
#[derive(Default)]
pub struct ImportCache {
    maps: HashMap<(u64, String), Arc<ImportMap>>,
}

impl ImportCache {
    /// Os imports do módulo que contém o endereço.
    pub fn load(&mut self, symbols: &Symbols, address: u64) -> Option<Arc<ImportMap>> {
        let module = symbols.module_at(address)?;
        let key = (module.base, module.path.clone());
        if let Some(map) = self.maps.get(&key) {
            return Some(Arc::clone(map));
        }
        let map = Arc::new(module.image.as_ref().map(|image| ImportMap::from_pe(module.base, image)).unwrap_or_default());
        self.maps.insert(key, Arc::clone(&map));
        Some(map)
    }

    /// O import de um slot (do módulo dele, se os imports já foram lidos):
    /// o nome do módulo que importa e o import.
    pub fn get(&self, symbols: &Symbols, slot: u64) -> Option<(String, Import)> {
        let module = symbols.module_at(slot)?;
        let map = self.maps.get(&(module.base, module.path.clone()))?;
        map.get(slot).map(|import| (module.name.clone(), import.clone()))
    }

    /// O nome do slot como o PDB o chamaria (`winlogon!__imp_NtClose`).
    pub fn slot_name(&self, symbols: &Symbols, slot: u64) -> Option<String> {
        self.get(symbols, slot).map(|(importer, import)| import.slot_name(&importer))
    }

    pub fn clear(&mut self) {
        self.maps.clear();
    }
}

/// O tipo dado pelo usuário a um registrador a partir de uma instrução
/// (`rcx` é `_EPROCESS*` em `nt!PspInsertProcess`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterType {
    pub address: u64,
    pub register: String,
    /// `_EPROCESS`, `nt!_ETHREAD`, `win32kbase!tagWND` (com ou sem `*`).
    pub type_name: String,
}

/// Um registrador de 64 bits pelo nome.
pub fn register_named(name: &str) -> Option<Register> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "rax" => Register::RAX,
        "rbx" => Register::RBX,
        "rcx" => Register::RCX,
        "rdx" => Register::RDX,
        "rsi" => Register::RSI,
        "rdi" => Register::RDI,
        "rbp" => Register::RBP,
        "rsp" => Register::RSP,
        "r8" => Register::R8,
        "r9" => Register::R9,
        "r10" => Register::R10,
        "r11" => Register::R11,
        "r12" => Register::R12,
        "r13" => Register::R13,
        "r14" => Register::R14,
        "r15" => Register::R15,
        _ => return None,
    })
}

// ---- os tipos do PDB ----

/// Um ponteiro para uma struct de um PDB.
#[derive(Clone)]
struct Typed {
    types: Arc<TypeDb>,
    index: u32,
}

/// A definição da struct de um índice (atravessa const/volatile e as
/// declarações antecipadas pelo nome).
fn struct_index(types: &TypeDb, index: u32) -> Option<u32> {
    match types.kind(index) {
        Kind::Struct { name, .. } => Some(types.find(&name).unwrap_or_else(|| types.resolve(index))),
        _ => None,
    }
}

/// O K-objeto visto como o E-objeto que começa com ele (o código do kernel
/// lê o KTHREAD da KPRCB e usa como ETHREAD), e o NT_TIB da TEB como a TEB.
fn widen(types: &TypeDb, index: u32) -> u32 {
    let wider = match types.name(index).as_str() {
        "_KTHREAD" => "_ETHREAD",
        "_KPROCESS" => "_EPROCESS",
        "_NT_TIB" => "_TEB",
        _ => return index,
    };
    types.find(wider).unwrap_or(index)
}

/// O membro que cobre `offset`: o de maior deslocamento que ainda o contém
/// (numa união, o primeiro que não é bitfield).
fn covering_member(types: &TypeDb, structure: u32, offset: u64) -> Option<Member> {
    let members = types.members(structure);
    let covering = |member: &&Member| member.offset <= offset && offset < member.offset + types.size(member.ty).max(1);
    let best = members.iter().filter(covering).map(|member| member.offset).max()?;
    let candidates: Vec<&Member> = members.iter().filter(covering).filter(|member| member.offset == best).collect();
    candidates.iter().find(|member| !matches!(types.kind(member.ty), Kind::Bitfield { .. })).or(candidates.first()).map(|member| (*member).clone())
}

/// Um nível do caminho até o campo: o caminho até aqui, o tipo e quanto
/// sobra dentro dele.
struct Level {
    path: String,
    ty: u32,
    remaining: u64,
}

/// Os níveis do caminho de `offset` dentro da struct (structs aninhadas e
/// arrays, até um escalar).
fn field_chain(types: &TypeDb, structure: u32, offset: u64) -> Vec<Level> {
    let mut levels = Vec::new();
    let mut path = String::new();
    let mut current = structure;
    let mut remaining = offset;
    for _ in 0..12 {
        match types.kind(current) {
            Kind::Struct { .. } => {
                let Some(definition) = struct_index(types, current) else { break };
                let Some(member) = covering_member(types, definition, remaining) else { break };
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(&member.name);
                remaining -= member.offset;
                current = member.ty;
            }
            Kind::Array { element, size } => {
                let element_size = types.size(element).max(1);
                if remaining >= size {
                    break;
                }
                let position = remaining / element_size;
                path.push_str(&format!("[{position}]"));
                remaining -= position * element_size;
                current = element;
            }
            _ => break,
        }
        levels.push(Level { path: path.clone(), ty: current, remaining });
    }
    levels
}

/// O caminho do campo de `structure` em `offset` (`Prcb.CurrentThread`,
/// `ImageFileName[3]`, `Flags+0x2`) e o tipo do campo achado.
pub fn field_path(types: &TypeDb, structure: u32, offset: u64) -> Option<(String, u32)> {
    let last = field_chain(types, structure, offset).pop()?;
    let path = if last.remaining == 0 { last.path } else { format!("{}+{:#x}", last.path, last.remaining) };
    Some((path, last.ty))
}

/// A struct que começa exatamente em `offset` (o `lea` de um campo).
fn struct_at(types: &TypeDb, structure: u32, offset: u64) -> Option<u32> {
    if offset == 0 {
        return Some(structure);
    }
    let level = field_chain(types, structure, offset).into_iter().find(|level| level.remaining == 0 && matches!(types.kind(level.ty), Kind::Struct { .. }))?;
    struct_index(types, level.ty)
}

// ---- leitura de bytes ----

type Cache = HashMap<(u64, usize), Option<Vec<u8>>>;

/// Bytes do arquivo desta máquina, das seções sem escrita (código e dados
/// só de leitura): sem passar pela serial.
fn read_file(symbols: &Symbols, address: u64, length: usize) -> Option<Vec<u8>> {
    let module = symbols.module_at(address)?;
    let image = module.image.as_ref()?;
    let rva = u32::try_from(address - module.base).ok()?;
    let section = image.sections.iter().find(|section| rva >= section.address && rva - section.address < section.virtual_size.max(section.raw_size))?;
    if section.characteristics & SCN_WRITE != 0 {
        return None;
    }
    image.bytes_at(rva, length).map(<[u8]>::to_vec)
}

/// Bytes da memória do alvo (cada endereço uma vez por janela).
fn read_live(client: &mut Client, cache: &mut Cache, address: u64, length: usize) -> Option<Vec<u8>> {
    cache.entry((address, length)).or_insert_with(|| client.read_memory(address, length).ok().filter(|bytes| !bytes.is_empty())).clone()
}

fn read_qword(client: &mut Client, cache: &mut Cache, address: u64) -> Option<u64> {
    let bytes = read_live(client, cache, address, 8)?;
    let array: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

/// O símbolo de um valor dentro de um módulo, senão o número.
fn describe_value(symbols: &Symbols, value: u64) -> String {
    if symbols.module_at(value).is_some() {
        symbols.describe(value)
    } else {
        format!("{value:#x}")
    }
}

fn live_register(live: &Live, name: &str) -> Option<u64> {
    live.registers.iter().find(|(register, _)| register == name).map(|(_, value)| *value)
}

// ---- decodificação das linhas ----

fn line_bytes(line: &Line) -> Vec<u8> {
    (0..line.bytes.len() / 2).filter_map(|index| line.bytes.get(index * 2..index * 2 + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok())).collect()
}

fn decode_line(line: &Line) -> Option<Instruction> {
    let bytes = line_bytes(line);
    if bytes.is_empty() {
        return None;
    }
    let mut decoder = Decoder::with_ip(64, &bytes, line.address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    (instruction.code() != Code::INVALID).then_some(instruction)
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(kind, OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32to64)
}

fn is_call(instruction: &Instruction) -> bool {
    matches!(instruction.flow_control(), FlowControl::Call | FlowControl::IndirectCall)
}

/// De onde veio o valor de um registrador antes da linha `index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// `mov reg, [rip+x]`: o conteúdo de `x`.
    Load(u64),
    /// `lea reg, [rip+x]`: o próprio `x`.
    Address(u64),
    /// `mov reg, imm`.
    Immediate(u64),
    /// `mov reg, [base+deslocamento]` na linha dada.
    Line(usize),
}

/// Quem montou `register` antes da linha `index`, no mesmo bloco: segue
/// `mov reg, outro` e para em desvios, em chamadas e no começo de bloco.
fn register_source(lines: &[Line], decoded: &[Option<Instruction>], index: usize, register: Register, targets: &HashSet<u64>) -> Option<Source> {
    let mut wanted = register;
    let lowest = index.saturating_sub(LOOKBACK);
    let mut position = index;
    while position > lowest {
        position -= 1;
        let instruction = decoded[position].as_ref()?;
        if instruction.flow_control() != FlowControl::Next {
            return None;
        }
        if instruction.op_count() >= 1 && instruction.op0_kind() == OpKind::Register && instruction.op0_register().full_register() == wanted {
            match (instruction.mnemonic(), instruction.op1_kind()) {
                (Mnemonic::Mov, OpKind::Memory) if instruction.is_ip_rel_memory_operand() => return Some(Source::Load(instruction.ip_rel_memory_address())),
                (Mnemonic::Lea, OpKind::Memory) if instruction.is_ip_rel_memory_operand() => return Some(Source::Address(instruction.ip_rel_memory_address())),
                (Mnemonic::Mov, OpKind::Memory) => return Some(Source::Line(position)),
                (Mnemonic::Mov, kind) if is_immediate(kind) => return Some(Source::Immediate(instruction.immediate(1))),
                (Mnemonic::Mov, OpKind::Register) if instruction.op1_register().size() == 8 => wanted = instruction.op1_register().full_register(),
                _ => return None,
            }
        }
        if targets.contains(&lines[position].address) || lines[position].label.is_some() {
            return None;
        }
    }
    None
}

/// O nome curto da função chamada (sem o módulo nem o `= ...`).
fn called_function(name: &str) -> &str {
    let first = name.split(" = ").next().unwrap_or(name);
    let first = first.trim_start_matches("-> ");
    let function = first.rsplit('!').next().unwrap_or(first);
    function.split('+').next().unwrap_or(function)
}

/// O alvo da chamada passa pelo despacho do CFG (o destino vai no RAX).
fn is_guard_dispatch(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("guard_dispatch_icall") || lower.contains("guard_xfg_dispatch_icall") || lower.contains("guard_retpoline_icall")
}

// ---- o enriquecimento ----

/// O que o enriquecimento precisa além do cliente.
pub struct Context<'a> {
    pub imports: &'a ImportCache,
    pub register_types: &'a [RegisterType],
    /// Os registradores da parada (a linha do RIP usa os de verdade).
    pub live: Option<&'a Live>,
    /// Pode ler a memória do alvo (os slots da IAT, os ponteiros globais e
    /// as strings fora do arquivo). Sem isso, só o arquivo desta máquina.
    pub read_target: bool,
}

/// Acrescenta os comentários às linhas (no `comment` de cada uma, depois do
/// que já houver).
pub fn enrich(client: &mut Client, lines: &mut [Line], context: &Context) {
    if lines.is_empty() {
        return;
    }
    let decoded: Vec<Option<Instruction>> = lines.iter().map(decode_line).collect();
    let targets: HashSet<u64> = lines.iter().filter_map(|line| line.target).collect();
    let type_notes = type_overlay(client, lines, &decoded, &targets, context.register_types);
    let mut notes: Vec<Vec<String>> = vec![Vec::new(); lines.len()];
    let mut call_names: Vec<Option<String>> = vec![None; lines.len()];
    let mut cache: Cache = HashMap::new();
    let codes = codes();
    for (index, line) in lines.iter().enumerate() {
        let Some(instruction) = decoded[index].as_ref() else { continue };
        let flow = instruction.flow_control();
        let branch = matches!(flow, FlowControl::Call | FlowControl::IndirectCall | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch);
        if let (Some(target), true) = (line.target, branch) {
            // Um trampolim `jmp [__imp_X]` no destino (do arquivo: o kernel
            // do OpenNT não tem trampolins, e ler cada destino pela serial
            // custaria uma ida e volta por chamada).
            let bytes = read_file(&client.symbols, target, 8);
            if let Some(slot) = bytes.as_deref().and_then(|bytes| thunk_slot(target, bytes)) {
                if let Some(text) = slot_text(client, context, &mut cache, slot) {
                    notes[index].push(format!("-> {}", text.trim_start_matches("-> ")));
                    call_names[index] = Some(text);
                }
            }
            if call_names[index].is_none() && is_call(instruction) {
                call_names[index] = Some(client.symbols.describe(target));
            }
        } else if let (Some(slot), true) = (line.memory, branch) {
            if let Some(text) = slot_text(client, context, &mut cache, slot) {
                notes[index].push(text.clone());
                call_names[index] = Some(text);
            }
            if call_names[index].is_none() {
                call_names[index] = client.symbols.name_at(slot);
            }
        } else if let Some(address) = line.memory {
            if let Some((_, import)) = context.imports.get(&client.symbols, address) {
                notes[index].push(format!("IAT de {}", import.display()));
            } else {
                // A string do arquivo (na janela CPU, a da memória já vem
                // nos comentários automáticos do kd-mcp).
                let bytes = read_file(&client.symbols, address, 260);
                if let Some((text, wide)) = bytes.as_deref().and_then(|bytes| read_string(bytes, 4)) {
                    notes[index].push(if wide { format!("L\"{text}\"") } else { format!("\"{text}\"") });
                }
            }
        }
        // O alvo do despacho do CFG (o RAX).
        if is_call(instruction) {
            let mut names: Vec<String> = Vec::new();
            if let Some(target) = line.target {
                names.push(client.symbols.describe(target));
            }
            if let Some(name) = line.memory.and_then(|slot| client.symbols.name_at(slot)) {
                names.push(name);
            }
            names.extend(call_names[index].iter().cloned());
            if names.iter().any(|name| is_guard_dispatch(name)) {
                let resolved = match context.live.filter(|live| live.rip == line.address) {
                    Some(live) => live_register(live, "rax").map(|value| describe_value(&client.symbols, value)),
                    None => register_source(lines, &decoded, index, Register::RAX, &targets).and_then(|source| source_text(client, context, &mut cache, lines, &type_notes, source)),
                };
                if let Some(text) = resolved {
                    notes[index].push(format!("CFG: rax = {text}"));
                    call_names[index] = Some(text);
                }
            }
        }
        // NTSTATUS e HRESULT nos imediatos.
        for operand in 0..instruction.op_count() {
            if matches!(instruction.op_kind(operand), OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64) {
                if let Some(name) = codes.immediate(instruction.immediate(operand)) {
                    notes[index].push(name);
                }
            }
        }
    }
    win32_errors(lines, &decoded, &targets, &call_names, &mut notes);
    for (index, line) in lines.iter_mut().enumerate() {
        let mut parts: Vec<String> = Vec::new();
        if let Some(note) = &type_notes[index] {
            parts.push(note.clone());
        }
        parts.append(&mut notes[index]);
        if parts.is_empty() {
            continue;
        }
        let joined = parts.join("  ");
        line.comment = Some(match line.comment.take() {
            Some(existing) if !existing.is_empty() => format!("{existing}  {joined}"),
            _ => joined,
        });
    }
}

/// O texto de um slot de memória chamado ou saltado: o import (com o
/// destino real quando difere) ou o destino de um ponteiro global.
fn slot_text(client: &mut Client, context: &Context, cache: &mut Cache, slot: u64) -> Option<String> {
    let import = context.imports.get(&client.symbols, slot).map(|(_, import)| import.display());
    let value = if context.read_target { read_qword(client, cache, slot) } else { None };
    let resolved = value.filter(|&value| value != 0 && client.symbols.module_at(value).is_some()).map(|value| client.symbols.describe(value));
    match (import, resolved) {
        (Some(import), Some(resolved)) if !import.eq_ignore_ascii_case(&resolved) => Some(format!("{import} = {resolved}")),
        (Some(import), _) => Some(import),
        (None, Some(resolved)) => Some(format!("-> {resolved}")),
        (None, None) => None,
    }
}

/// O texto de quem montou o registrador.
fn source_text(client: &mut Client, context: &Context, cache: &mut Cache, lines: &[Line], type_notes: &[Option<String>], source: Source) -> Option<String> {
    match source {
        Source::Address(address) | Source::Immediate(address) => client.symbols.module_at(address).map(|_| client.symbols.describe(address)),
        Source::Load(address) => {
            let global = describe_value(&client.symbols, address);
            let value = if context.read_target { read_qword(client, cache, address) } else { None };
            Some(match value.filter(|&value| value != 0) {
                Some(value) => format!("[{global}] -> {}", describe_value(&client.symbols, value)),
                None => format!("[{global}]"),
            })
        }
        Source::Line(position) => match type_notes.get(position).and_then(Option::as_ref) {
            Some(field) => Some(format!("[{field}]")),
            None => lines.get(position).and_then(|line| line.text.split_once(", ")).map(|(_, operand)| operand.trim().to_string()),
        },
    }
}

/// Os erros do Win32: o imediato passado a `SetLastError` e as comparações
/// do valor de `GetLastError` logo depois da chamada.
fn win32_errors(lines: &[Line], decoded: &[Option<Instruction>], targets: &HashSet<u64>, call_names: &[Option<String>], notes: &mut [Vec<String>]) {
    let codes = codes();
    for index in 0..lines.len() {
        let Some(name) = call_names[index].as_deref() else { continue };
        let function = called_function(name);
        if ["SetLastError", "RtlSetLastWin32Error", "RtlRestoreLastWin32Error"].contains(&function) {
            if let Some(Source::Immediate(value)) = register_source(lines, decoded, index, Register::RCX, targets) {
                if let Some(error) = u32::try_from(value).ok().and_then(|value| codes.win32(value)) {
                    notes[index].push(format!("erro {error}"));
                }
            }
        }
        if ["GetLastError", "RtlGetLastWin32Error", "RtlNtStatusToDosError", "RtlNtStatusToDosErrorNoTeb"].contains(&function) {
            for position in index + 1..(index + 10).min(lines.len()) {
                let Some(instruction) = decoded[position].as_ref() else { break };
                if is_call(instruction) {
                    break;
                }
                if matches!(instruction.mnemonic(), Mnemonic::Cmp | Mnemonic::Sub) && instruction.op_count() == 2 && is_immediate(instruction.op1_kind()) {
                    let value = instruction.immediate(1);
                    if let Some(error) = u32::try_from(value).ok().filter(|&value| value < 0x1_0000).and_then(|value| codes.win32(value)) {
                        notes[position].push(error.to_string());
                    }
                }
                if position + 1 < lines.len() && targets.contains(&lines[position + 1].address) {
                    break;
                }
            }
        }
    }
}

/// Os campos dos tipos nos operandos de memória, linha a linha.
fn type_overlay(client: &mut Client, lines: &[Line], decoded: &[Option<Instruction>], targets: &HashSet<u64>, register_types: &[RegisterType]) -> Vec<Option<String>> {
    let mut notes: Vec<Option<String>> = vec![None; lines.len()];
    let uses_gs = decoded.iter().flatten().any(|instruction| instruction.segment_prefix() == Register::GS);
    if !uses_gs && register_types.is_empty() {
        return notes;
    }
    let mut typed: HashMap<Register, Typed> = HashMap::new();
    let mut kernel_types: Option<Option<Arc<TypeDb>>> = None;
    let mut factory = InstructionInfoFactory::new();
    for (index, line) in lines.iter().enumerate() {
        if targets.contains(&line.address) || line.label.is_some() {
            typed.clear();
        }
        for assignment in register_types.iter().filter(|assignment| assignment.address == line.address) {
            let Some(register) = register_named(&assignment.register) else { continue };
            let name = assignment.type_name.trim().trim_end_matches('*').trim();
            if name.is_empty() {
                typed.remove(&register);
                continue;
            }
            if let Ok((types, type_index)) = client.types_for(name) {
                if let Some(structure) = struct_index(&types, type_index) {
                    typed.insert(register, Typed { types, index: structure });
                }
            }
        }
        let Some(instruction) = decoded[index].as_ref() else {
            typed.clear();
            continue;
        };
        let mut produced: Option<(Register, Typed)> = None;
        if let Some(operand) = (0..instruction.op_count()).find(|&operand| instruction.op_kind(operand) == OpKind::Memory) {
            let base = instruction.memory_base();
            let index_register = instruction.memory_index();
            let displacement = instruction.memory_displacement64();
            let destination = (operand != 0 && instruction.op0_kind() == OpKind::Register && instruction.op0_register().size() == 8).then(|| instruction.op0_register().full_register());
            // O `gs:` do código da Microsoft (o do kernel do OpenNT, em Rust,
            // não segue a KPCR em todo deslocamento).
            let own_kernel = client.symbols.module_at(line.address).is_some_and(|module| client.symbols.is_kernel(module));
            let found: Option<(String, Typed, u32)> = if instruction.segment_prefix() == Register::GS && base == Register::None && index_register == Register::None && !own_kernel {
                let types = kernel_types.get_or_insert_with(|| client.type_database()).clone();
                types.and_then(|types| {
                    let name = if line.address >= 0xFFFF_8000_0000_0000 { "_KPCR" } else { "_TEB" };
                    let structure = types.find(name).and_then(|found| struct_index(&types, found))?;
                    let (path, field) = field_path(&types, structure, displacement)?;
                    Some((format!("gs:{}.{path}", types.name(structure)), Typed { types, index: structure }, field))
                })
            } else if base != Register::None && base != Register::RIP && index_register == Register::None {
                typed.get(&base.full_register()).and_then(|pointer| {
                    let (path, field) = field_path(&pointer.types, pointer.index, displacement)?;
                    Some((format!("{}.{path}", pointer.types.name(pointer.index)), pointer.clone(), field))
                })
            } else {
                None
            };
            if let Some((text, owner, field)) = found {
                notes[index] = Some(text);
                if let Some(destination) = destination {
                    let types = &owner.types;
                    let next = match instruction.mnemonic() {
                        Mnemonic::Lea => struct_at(types, owner.index, displacement),
                        Mnemonic::Mov => types.pointee(field).and_then(|target| struct_index(types, target)),
                        _ => None,
                    };
                    if let Some(next) = next {
                        produced = Some((destination, Typed { types: Arc::clone(types), index: widen(types, next) }));
                    }
                }
            }
        } else if instruction.mnemonic() == Mnemonic::Mov && instruction.op_count() == 2 && instruction.op0_kind() == OpKind::Register && instruction.op1_kind() == OpKind::Register && instruction.op0_register().size() == 8 {
            if let Some(pointer) = typed.get(&instruction.op1_register().full_register()) {
                produced = Some((instruction.op0_register().full_register(), pointer.clone()));
            }
        }
        // O que a instrução grava perde o tipo; uma chamada leva os voláteis.
        let written: Vec<Register> = factory
            .info(instruction)
            .used_registers()
            .iter()
            .filter(|used| matches!(used.access(), OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite))
            .map(|used| used.register().full_register())
            .collect();
        for register in written {
            typed.remove(&register);
        }
        if is_call(instruction) {
            for register in [Register::RAX, Register::RCX, Register::RDX, Register::R8, Register::R9, Register::R10, Register::R11] {
                typed.remove(&register);
            }
        }
        if let Some((register, pointer)) = produced {
            typed.insert(register, pointer);
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use kd_client::tpi::Tpi;

    /// Registros de TPI montados à mão (o mesmo formato do `cvinfo.h` que o
    /// leitor do `kd-client` entende).
    struct Records(Vec<Vec<u8>>);

    impl Records {
        fn add(&mut self, kind: u16, mut body: Vec<u8>) -> u32 {
            while (body.len() + 2) % 4 != 0 {
                body.push(0xF0 + (4 - (body.len() + 2) % 4) as u8);
            }
            let mut record = ((body.len() + 2) as u16).to_le_bytes().to_vec();
            record.extend_from_slice(&kind.to_le_bytes());
            record.extend_from_slice(&body);
            self.0.push(record);
            0x1000 + self.0.len() as u32 - 1
        }

        fn member(name: &str, ty: u32, offset: u16) -> Vec<u8> {
            let mut bytes = 0x150Du16.to_le_bytes().to_vec();
            bytes.extend_from_slice(&3u16.to_le_bytes());
            bytes.extend_from_slice(&ty.to_le_bytes());
            bytes.extend_from_slice(&offset.to_le_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            while bytes.len() % 4 != 0 {
                bytes.push(0xF0 + (4 - bytes.len() % 4) as u8);
            }
            bytes
        }

        fn structure(fields: u32, size: u16, name: &str) -> Vec<u8> {
            let mut bytes = 1u16.to_le_bytes().to_vec();
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&fields.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&size.to_le_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            bytes
        }

        fn pointer(target: u32) -> Vec<u8> {
            let mut bytes = target.to_le_bytes().to_vec();
            bytes.extend_from_slice(&((8u32 << 13) | 0x0C).to_le_bytes());
            bytes
        }

        fn build(self) -> TypeDb {
            let records: Vec<u8> = self.0.concat();
            let mut stream = vec![0u8; 56];
            stream[4..8].copy_from_slice(&56u32.to_le_bytes());
            stream[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
            stream[16..20].copy_from_slice(&(records.len() as u32).to_le_bytes());
            stream.extend_from_slice(&records);
            TypeDb::new(Tpi::parse(&stream).expect("TPI de teste"), "teste".into())
        }
    }

    /// `_KPCR` reduzido: Self (`_KPCR*`) em +0x18 e Prcb (`_KPRCB`) em
    /// +0x180; `_KPRCB`: CurrentThread (`_KTHREAD*`) em +8; `_KTHREAD`
    /// com Process em +0x220; `_ETHREAD` com Tcb (`_KTHREAD`) em 0 e Cid
    /// em +0x478; um array de bytes `Name[16]` em +0x10 da KPRCB.
    fn sample() -> TypeDb {
        let mut records = Records(Vec::new());
        let thread_fields = records.add(0x1203, Records::member("Process", 0x0603, 0x220));
        let kthread = records.add(0x1505, Records::structure(thread_fields, 0x430, "_KTHREAD"));
        let kthread_pointer = records.add(0x1002, Records::pointer(kthread));
        let mut ethread_members = Records::member("Tcb", kthread, 0);
        ethread_members.extend(Records::member("Cid", 0x23, 0x478));
        let ethread_fields = records.add(0x1203, ethread_members);
        records.add(0x1505, Records::structure(ethread_fields, 0x500, "_ETHREAD"));
        let mut array = 0x20u32.to_le_bytes().to_vec();
        array.extend_from_slice(&0x23u32.to_le_bytes());
        array.extend_from_slice(&16u16.to_le_bytes());
        array.push(0);
        let name = records.add(0x1503, array);
        let mut prcb_members = Records::member("MxCsr", 0x22, 0);
        prcb_members.extend(Records::member("CurrentThread", kthread_pointer, 8));
        prcb_members.extend(Records::member("Name", name, 0x10));
        let prcb_fields = records.add(0x1203, prcb_members);
        let prcb = records.add(0x1505, Records::structure(prcb_fields, 0x100, "_KPRCB"));
        let mut pcr_members = Records::member("Self", 0x0603, 0x18);
        pcr_members.extend(Records::member("Prcb", prcb, 0x180));
        let pcr_fields = records.add(0x1203, pcr_members);
        records.add(0x1505, Records::structure(pcr_fields, 0x280, "_KPCR"));
        records.build()
    }

    #[test]
    fn names_fields_by_offset() {
        let types = sample();
        let pcr = types.find("_KPCR").unwrap();
        assert_eq!(field_path(&types, pcr, 0x18).map(|(path, _)| path).as_deref(), Some("Self"));
        let (path, field) = field_path(&types, pcr, 0x188).unwrap();
        assert_eq!(path, "Prcb.CurrentThread");
        // O campo é ponteiro para _KTHREAD, que vira _ETHREAD.
        let thread = types.pointee(field).and_then(|target| struct_index(&types, target)).unwrap();
        assert_eq!(types.name(thread), "_KTHREAD");
        let wide = widen(&types, thread);
        assert_eq!(types.name(wide), "_ETHREAD");
        assert_eq!(field_path(&types, wide, 0x478).map(|(path, _)| path).as_deref(), Some("Cid"));
        assert_eq!(field_path(&types, wide, 0x220).map(|(path, _)| path).as_deref(), Some("Tcb.Process"));
        // Array e o meio de um campo.
        assert_eq!(field_path(&types, pcr, 0x193).map(|(path, _)| path).as_deref(), Some("Prcb.Name[3]"));
        assert_eq!(field_path(&types, pcr, 0x18A).map(|(path, _)| path).as_deref(), Some("Prcb.CurrentThread+0x2"));
        assert_eq!(field_path(&types, pcr, 0x1000), None);
        // O lea de um campo struct.
        let prcb = struct_at(&types, pcr, 0x180).unwrap();
        assert_eq!(types.name(prcb), "_KPRCB");
        assert_eq!(struct_at(&types, pcr, 0x188), None);
    }

    #[test]
    fn helpers() {
        assert_eq!(register_named("R12"), Some(Register::R12));
        assert_eq!(register_named("eax"), None);
        assert_eq!(called_function("kernel32!GetLastError = KERNELBASE!GetLastError"), "GetLastError");
        assert_eq!(called_function("-> ntdll!RtlSetLastWin32Error+0x10"), "RtlSetLastWin32Error");
        assert!(is_guard_dispatch("ntdll!__guard_dispatch_icall_fptr"));
        assert!(is_guard_dispatch("nt!guard_dispatch_icall"));
        assert!(!is_guard_dispatch("nt!guard_check_icall"));
    }

    fn line(address: u64, bytes: &str) -> Line {
        Line { address, bytes: bytes.into(), text: String::new(), label: None, comment: None, target: None, memory: None }
    }

    #[test]
    fn finds_register_sources() {
        // mov rax, [rip+0x100]; mov rcx, rax; call ...; mov eax, 0x7a.
        let lines = vec![line(0x1000, "488b0500010000"), line(0x1007, "4889c1"), line(0x100A, "b97a000000")];
        let decoded: Vec<Option<Instruction>> = lines.iter().map(decode_line).collect();
        assert!(decoded.iter().all(Option::is_some));
        let targets = HashSet::new();
        assert_eq!(register_source(&lines, &decoded, 2, Register::RCX, &targets), Some(Source::Load(0x1107)));
        assert_eq!(register_source(&lines, &decoded, 3, Register::RCX, &targets), Some(Source::Immediate(0x7a)));
        // Um começo de bloco no meio interrompe a busca.
        let targets: HashSet<u64> = [0x1007].into_iter().collect();
        assert_eq!(register_source(&lines, &decoded, 2, Register::RCX, &targets), None);
    }
}
