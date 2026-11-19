//! As vistas do opennt-re que o backend monta além do snapshot comum: o
//! processo escolhido, as cinco janelas de memória (Dump 1-5), a pilha em
//! qwords com símbolos, a caixa de informação da instrução escolhida, os
//! tratadores de exceção dos quadros, o grafo de fluxo de uma função, as
//! buscas (referências a strings, constantes, chamadas entre módulos,
//! xrefs, padrões e strings soltas), o mapa de memória, os handles, as
//! threads de usuário, os símbolos de um módulo, os patches e os roteiros.
//! As referências cruzadas saem da análise do módulo inteiro
//! (`crate::analysis`), feita aos poucos numa thread: a janela Xrefs mostra
//! o que já foi analisado e se refaz quando chegam lotes novos.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use opennt_kd::analysis::cfg::{self, EdgeKind, Layout};
use opennt_kd::analysis::decode::{self, Flow, Insn};
use opennt_kd::analysis::notes::{Location, Patch, Patches};
use opennt_kd::analysis::{refs, search};
use opennt_kd::client::Resumed;
use opennt_kd::kd_script::ScriptOptions;
use opennt_kd::unwind::Target as _;
use opennt_kd::user::{self, Handle, UserThread};
use opennt_kd::{Client, Symbols};

use super::{FrameRow, MemoryView, RegisterRow, Snapshot, Worker};
use crate::analysis::{self, ModuleAnalysis, RefKind};
use crate::annotations::{self, ImportCache, RegisterType};
use crate::codes::codes;
use crate::disasm::{self, Line};
use crate::imports::ImportMap;
use crate::scan::{self, ModuleImage, SharedImage};

/// Análises de módulo guardadas ao mesmo tempo (a de um módulo grande pesa
/// dezenas de MB).
const MAX_ANALYSES: usize = 6;

/// Uma linha da janela de pilha: o endereço, o qword e o que ele parece ser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackRow {
    pub address: u64,
    pub value: u64,
    pub note: String,
}

/// O tratador de exceção de um quadro da pilha.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SehRow {
    pub frame: usize,
    pub address: u64,
    pub function: String,
    pub handler: String,
    pub scopes: Vec<String>,
}

/// Um bloco do grafo de fluxo.
#[derive(Clone, Debug)]
pub struct GraphBlock {
    pub start: u64,
    pub end: u64,
    pub lines: Vec<Line>,
    /// (índice do bloco de destino, tipo da aresta).
    pub edges: Vec<(usize, EdgeKind)>,
    pub exit: bool,
}

/// O grafo de fluxo de uma função.
#[derive(Clone, Debug, Default)]
pub struct GraphView {
    pub function: u64,
    pub name: String,
    pub blocks: Vec<GraphBlock>,
    pub layout: Layout,
    /// O bloco com o RIP (ou o endereço pedido).
    pub current: Option<usize>,
    pub focus: u64,
    pub truncated: bool,
    pub error: Option<String>,
}

/// O que procurar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchKind {
    /// Instruções que referenciam texto ASCII ou UTF-16.
    StringReferences,
    /// Instruções com o imediato (ou deslocamento) igual à expressão.
    Constant(String),
    /// Chamadas e saltos para fora do módulo (diretos e pela IAT).
    IntermodularCalls,
    /// Quem referencia o endereço (chamadas, saltos, memória, imediatos).
    References(String),
    /// Bytes com curingas (`48 8B ?? 05`, `"texto"`, `u"texto"`).
    Pattern(String),
    /// Texto solto na memória (sem precisar de referência).
    Strings,
}

impl SearchKind {
    pub fn title(&self) -> String {
        match self {
            SearchKind::StringReferences => "Referências a strings".into(),
            SearchKind::Constant(value) => format!("Constante {value}"),
            SearchKind::IntermodularCalls => "Chamadas entre módulos".into(),
            SearchKind::References(target) => format!("Referências a {target}"),
            SearchKind::Pattern(pattern) => format!("Padrão {pattern}"),
            SearchKind::Strings => "Strings".into(),
        }
    }

    fn key(&self) -> String {
        format!("{self:?}")
    }
}

/// Onde procurar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchScope {
    /// O módulo que contém o endereço.
    Module(u64),
    /// Todos os módulos (os do kernel e os de usuário do processo escolhido).
    AllModules,
    /// Uma faixa: expressão do início e tamanho.
    Range(String, u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchQuery {
    pub kind: SearchKind,
    pub scope: SearchScope,
}

/// Um resultado de busca.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceRow {
    /// A instrução (ou o endereço achado).
    pub address: u64,
    /// `módulo!símbolo+0x..`.
    pub location: String,
    pub disassembly: String,
    /// A string, o destino ou o valor.
    pub text: String,
    /// O endereço referenciado (a string, o destino).
    pub target: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ReferenceView {
    pub title: String,
    pub scope: String,
    pub rows: Vec<ReferenceRow>,
    pub modules: usize,
    pub milliseconds: u128,
    pub error: Option<String>,
    /// Quantos módulos vieram do cache.
    pub cached: usize,
}

/// Uma linha do mapa de memória.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRow {
    pub base: u64,
    pub size: u64,
    /// Image, Private, Mapped, faixa de sistema, seção.
    pub kind: String,
    pub protection: String,
    /// Módulo, arquivo mapeado ou nome da faixa.
    pub name: String,
    /// A seção de uma imagem (`.text`...).
    pub section: String,
    /// Usuário ou Sistema (a metade do espaço de endereços e o módulo).
    pub party: String,
    /// O que há na região (código, dados, cabeçalho PE, pilha, heap).
    pub content: String,
    /// A proteção da alocação (a inicial).
    pub initial_protection: String,
    /// A região é executável (a cor da linha).
    pub executable: bool,
}

/// Uma referência ao endereço pedido, ou uma saída da função dele (a
/// janela Xrefs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XrefRow {
    pub from: u64,
    pub location: String,
    pub kind: String,
    pub disassembly: String,
    /// O endereço referenciado (nas saídas, o destino).
    pub to: u64,
    /// O nome do destino (o import, o símbolo ou `módulo+0xRVA`).
    pub to_name: String,
}

/// O resultado da tecla X.
#[derive(Clone, Debug, Default)]
pub struct XrefView {
    pub target: u64,
    pub name: String,
    pub module: String,
    pub rows: Vec<XrefRow>,
    pub milliseconds: u128,
    /// A análise do módulo já existia (feita antes desta consulta).
    pub cached: bool,
    pub error: Option<String>,
    /// A função que contém o endereço (a `.pdata` com os pedaços juntos,
    /// ou o símbolo com tamanho): começo, nome e quantos pedaços.
    pub function: Option<(u64, String, usize)>,
    /// O que sai dessa função: chamadas, saltos para fora, a IAT, a
    /// memória, os endereços e os imediatos no módulo.
    pub callees: Vec<XrefRow>,
    /// A análise do módulo ainda anda: (lotes prontos, total). As
    /// referências mostradas são as dos lotes prontos.
    pub progress: Option<(usize, usize)>,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryMapView {
    pub title: String,
    pub rows: Vec<MapRow>,
    pub error: Option<String>,
}

/// Os símbolos, exports e imports de um módulo.
#[derive(Clone, Debug, Default)]
pub struct SymbolView {
    pub module: String,
    pub base: u64,
    pub symbols: Vec<(u64, String)>,
    pub exports: Vec<(u64, String)>,
    /// (slot da IAT, DLL, nome, valor do slot no alvo).
    pub imports: Vec<(u64, String, String, u64)>,
    pub source: String,
}

/// O estado das vistas do opennt-re dentro do backend.
pub struct ReState {
    pub dumps: [String; 5],
    pub selected_instruction: Option<u64>,
    pub images: HashMap<u64, (u64, SharedImage)>,
    pub elf_image: Option<SharedImage>,
    pub patches: Patches,
    pub patch_generation: u64,
    pub reference_cache: HashMap<(u64, String), (u64, Vec<ReferenceRow>)>,
    pub graph: Option<Arc<GraphView>>,
    pub references: Option<Arc<ReferenceView>>,
    pub strings: Option<Arc<ReferenceView>>,
    pub memory_map: Option<Arc<MemoryMapView>>,
    pub handles: Option<Arc<Result<Vec<Handle>, String>>>,
    pub user_threads: Option<Arc<Result<Vec<UserThread>, String>>>,
    pub symbol_view: Option<Arc<SymbolView>>,
    /// Os laços por função (início, fim) para a margem da desmontagem.
    pub loops: HashMap<(u64, u64), Vec<opennt_kd::analysis::functions::Loop>>,
    pub xrefs: Option<Arc<XrefView>>,
    /// Os imports de cada módulo (os nomes dos slots da IAT na
    /// desmontagem).
    pub imports: ImportCache,
    /// Os tipos dados aos registradores (o menu "Tipo do registrador").
    pub register_types: Vec<RegisterType>,
    /// A análise de cada módulo, pela base.
    pub analyses: HashMap<u64, Arc<ModuleAnalysis>>,
    /// A janela Xrefs espera a análise do módulo: o endereço pedido e o
    /// andamento já mostrado.
    pub xref_pending: Option<(u64, analysis::Progress)>,
}

impl Drop for ReState {
    /// As threads das análises param junto (um attach novo troca o estado).
    fn drop(&mut self) {
        for analysis in self.analyses.values() {
            analysis.cancel();
        }
    }
}

impl Default for ReState {
    fn default() -> Self {
        ReState {
            // O Dump 1 começa na pilha.
            dumps: ["@rsp".to_string(), String::new(), String::new(), String::new(), String::new()],
            selected_instruction: None,
            images: HashMap::new(),
            elf_image: None,
            patches: Patches::default(),
            patch_generation: 0,
            reference_cache: HashMap::new(),
            graph: None,
            references: None,
            strings: None,
            memory_map: None,
            handles: None,
            user_threads: None,
            symbol_view: None,
            loops: HashMap::new(),
            xrefs: None,
            imports: ImportCache::default(),
            register_types: Vec::new(),
            analyses: HashMap::new(),
            xref_pending: None,
        }
    }
}

/// Lê bytes por um cliente, sem erro (os vazios viram `None`).
fn read(client: &mut Client, address: u64, length: usize) -> Option<Vec<u8>> {
    client.read_memory(address, length).ok().filter(|bytes| !bytes.is_empty())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ")
}

impl Worker {
    /// A imagem do módulo em `address` (do cache, do arquivo desta máquina,
    /// do `kernel.elf` ou da memória do alvo), com os patches aplicados.
    pub(super) fn module_image(&mut self, address: u64) -> Option<SharedImage> {
        let elf = self.config.elf.clone();
        let generation = self.re.patch_generation;
        let client = self.client.as_mut()?;
        let module = client.symbols.module_at(address)?.clone();
        if let Some((cached, image)) = self.re.images.get(&module.base) {
            if *cached == generation {
                return Some(Arc::clone(image));
            }
        }
        let mut image = if client.symbols.is_kernel(client.symbols.module_at(address)?) {
            match &self.re.elf_image {
                Some(image) => (**image).clone(),
                None => {
                    let bytes = std::fs::read(&elf).ok()?;
                    let image = scan::from_elf(&bytes, "kernel").ok()?;
                    self.re.elf_image = Some(Arc::new(image.clone()));
                    image
                }
            }
        } else if let Some(pe) = &module.image {
            scan::from_pe(module.base, module.end, &module.name, pe)
        } else {
            let client = self.client.as_mut()?;
            scan::from_memory(module.base, module.end, &module.name, &mut |at, length| read(client, at, length))
        };
        for patch in &self.re.patches.list {
            if patch.address >= image.base && patch.address < image.base + image.bytes.len() as u64 {
                image.apply(patch.address, &patch.patched);
            }
        }
        let shared = Arc::new(image);
        self.re.images.insert(module.base, (generation, Arc::clone(&shared)));
        Some(shared)
    }

    /// As vistas da parada: processo, Dump 1-5, pilha, caixa de informação,
    /// tratadores, argumentos dos quadros e as vistas carregadas.
    pub(super) fn add_re_views(&mut self, snapshot: &mut Snapshot) {
        let dumps = self.re.dumps.clone();
        let selected = self.re.selected_instruction;
        let Some(client) = self.client.as_mut() else { return };
        snapshot.process = client.process().cloned();
        snapshot.user_mode = client.stopped_in_user_mode();
        for row in &snapshot.registers {
            if let Some(value) = row.value.filter(|&value| client.symbols.module_at(value).is_some()) {
                snapshot.register_notes.insert(row.name.clone(), client.symbols.describe(value));
            }
        }
        // Dump 1-5.
        snapshot.dumps = dumps
            .iter()
            .map(|expression| {
                let mut view = MemoryView { expression: expression.clone(), ..Default::default() };
                if !expression.trim().is_empty() {
                    match client.evaluate(expression) {
                        Ok(address) => {
                            view.address = address;
                            match client.read_memory(address, 0x200) {
                                Ok(bytes) => view.bytes = bytes,
                                Err(error) => view.error = Some(error),
                            }
                        }
                        Err(error) => view.error = Some(error),
                    }
                }
                view
            })
            .collect();
        // A pilha em qwords a partir do RSP (ou da expressão pedida).
        let rsp = snapshot.registers.iter().find(|row| row.name == "rsp").and_then(|row| row.value);
        snapshot.stack_locked = self.stack_expression.trim().is_empty();
        let origin = if snapshot.stack_locked { rsp } else { client.evaluate(&self.stack_expression).ok().map(|address| address & !7) };
        if let Some(origin) = origin {
            if let Ok(bytes) = client.read_memory(origin.wrapping_sub(0x20), 0x220) {
                for (index, chunk) in bytes.chunks_exact(8).enumerate() {
                    let address = origin.wrapping_sub(0x20) + index as u64 * 8;
                    let value = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
                    let mut note = String::new();
                    if client.symbols.module_at(value).is_some() {
                        // Um endereço de retorno da pilha: para quem volta e
                        // de qual função (a do quadro de baixo).
                        let frame = snapshot.frames.iter().enumerate().skip(1).find(|(_, frame)| frame.address == value);
                        note = match frame {
                            Some((index, _)) => {
                                let callee = snapshot.frames.get(index - 1).map(|below| client.symbols.function_at(below.address).map_or_else(|| client.symbols.describe(below.address), |(_, name)| name)).unwrap_or_default();
                                format!("retorno para {} de {callee}", client.symbols.describe_return(value))
                            }
                            None => client.symbols.describe(value),
                        };
                    }
                    snapshot.stack.push(StackRow { address, value, note });
                }
            }
        }
        // Argumentos dos quadros: o espaço de home (rcx, rdx, r8, r9, se a
        // função os guardou) e os dois primeiros da pilha, no RSP do quadro
        // de quem chamou.
        let stacks: Vec<u64> = snapshot.frames.iter().map(|frame| frame.stack).collect();
        for (index, frame) in snapshot.frames.iter_mut().enumerate() {
            if let Some(&caller) = stacks.get(index + 1) {
                if let Ok(bytes) = client.read_memory(caller, 0x30) {
                    frame.arguments = bytes.chunks_exact(8).map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]))).collect();
                }
            }
        }
        // A caixa de informação da instrução escolhida (ou do RIP).
        let rip = snapshot.registers.iter().find(|row| row.name == "rip").and_then(|row| row.value).unwrap_or(0);
        let target = selected.unwrap_or(rip);
        if target != 0 {
            snapshot.info_box = info_box(client, target, &snapshot.registers);
        }
        snapshot.exception = describe_exception(snapshot);
        // LastErrorValue e LastStatusValue da TEB (GS do anel 3).
        if snapshot.user_mode {
            if let Some(teb) = snapshot.registers.iter().find(|row| row.name == "gs_base").and_then(|row| row.value) {
                let error = client.read_integer(teb + 0x68, 4).ok();
                let status = client.read_integer(teb + 0x1250, 4).ok();
                snapshot.last_error = error.map(|error| (error, status.unwrap_or(0)));
            }
        }
        snapshot.patches = self.re.patches.list.clone();
        snapshot.graph = self.re.graph.clone();
        snapshot.references = self.re.references.clone();
        snapshot.strings = self.re.strings.clone();
        snapshot.memory_map = self.re.memory_map.clone();
        snapshot.handles = self.re.handles.clone();
        snapshot.user_threads = self.re.user_threads.clone();
        snapshot.symbol_view = self.re.symbol_view.clone();
        snapshot.xrefs = self.re.xrefs.clone();
        // Os tratadores de exceção dos quadros.
        let frames: Vec<FrameRow> = snapshot.frames.iter().take(16).cloned().collect();
        let mut seh = Vec::new();
        for (index, frame) in frames.iter().enumerate() {
            let address = if index == 0 { frame.address } else { frame.address.wrapping_sub(1) };
            let Some(client) = self.client.as_mut() else { break };
            let Some(table) = client.function_table(address) else { continue };
            let Some(function) = opennt_kd::pe::find_function(&table.functions, (address - table.base) as u32) else { continue };
            let base = table.base;
            let Some(image) = self.module_image(address) else { continue };
            let handler = scan::handler(&image, base + function.begin as u64, function.unwind);
            let Some(client) = self.client.as_ref() else { break };
            let kind = match handler.flags & 3 {
                1 => " (excecao)",
                2 => " (termino)",
                _ => " (excecao e termino)",
            };
            let handler_text = handler.handler.map(|address| format!("{address:#x} {}{kind}", client.symbols.describe(address))).unwrap_or_else(|| "-".into());
            let scopes = handler
                .scopes
                .iter()
                .map(|(begin, end, filter, target)| {
                    let filter_text = if *filter == 1 { "EXCEPTION_EXECUTE_HANDLER".to_string() } else { client.symbols.describe(*filter) };
                    format!("[{begin:#x}, {end:#x}) filtro {filter_text} destino {}", if *target == 0 { "finally".to_string() } else { client.symbols.describe(*target) })
                })
                .collect();
            seh.push(SehRow { frame: index, address: frame.address, function: client.symbols.describe(base + function.begin as u64), handler: handler_text, scopes });
        }
        snapshot.seh = seh;
    }

    /// Os Dumps e a caixa de informação sem montar o snapshot inteiro (um
    /// clique numa linha ou um endereço novo no Dump).
    pub(super) fn update_quick_views(&mut self) -> Result<bool, String> {
        let current = self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).snapshot.clone();
        if current.registers.is_empty() || !self.client.as_ref().is_some_and(Client::is_stopped) {
            return Ok(true);
        }
        let dumps = self.re.dumps.clone();
        let selected = self.re.selected_instruction;
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let mut copy = (*current).clone();
        copy.dumps = dumps
            .iter()
            .map(|expression| {
                let mut view = MemoryView { expression: expression.clone(), ..Default::default() };
                if !expression.trim().is_empty() {
                    match client.evaluate(expression) {
                        Ok(address) => {
                            view.address = address;
                            match client.read_memory(address, 0x200) {
                                Ok(bytes) => view.bytes = bytes,
                                Err(error) => view.error = Some(error),
                            }
                        }
                        Err(error) => view.error = Some(error),
                    }
                }
                view
            })
            .collect();
        let rip = copy.registers.iter().find(|row| row.name == "rip").and_then(|row| row.value).unwrap_or(0);
        let target = selected.unwrap_or(rip);
        copy.info_box = if target != 0 { info_box(client, target, &copy.registers) } else { Vec::new() };
        self.generation += 1;
        copy.generation = self.generation;
        self.publish(|shared| shared.snapshot = Arc::new(copy));
        Ok(false)
    }

    /// Escolhe o processo (EPROCESS) ou volta ao kernel.
    pub(super) fn select_process(&mut self, process: Option<u64>) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let text = process.map(|eprocess| format!("{eprocess:#x}"));
        client.set_process(text.as_deref())?;
        self.re.handles = None;
        self.re.user_threads = None;
        self.re.memory_map = None;
        Ok(true)
    }

    /// O grafo de fluxo da função que contém o endereço da expressão.
    pub(super) fn build_graph(&mut self, expression: &str) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let focus = if expression.trim().is_empty() { client.register("rip")? } else { client.evaluate(expression)? };
        let rip = client.register("rip").unwrap_or(0);
        // A função: a `.pdata` (Microsoft), senão o símbolo do ELF.
        let mut range = None;
        let mut entry = focus;
        if let Some(table) = client.function_table(focus) {
            if let Some(function) = opennt_kd::pe::find_function(&table.functions, (focus - table.base) as u32) {
                entry = table.base + function.begin as u64;
                range = Some((entry, table.base + function.end as u64));
            }
        }
        if range.is_none() {
            if let Some((start, _)) = client.symbols.function_at(focus) {
                entry = start;
                let module = client.symbols.module_at(focus);
                let size = module.and_then(|module| module.symbols.iter().find(|symbol| symbol.address == start).map(|symbol| symbol.size)).unwrap_or(0);
                if size > 0 {
                    range = Some((start, start + size));
                }
            }
        }
        let name = client.symbols.describe(entry);
        let image = self.module_image(entry);
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let mut pages: HashMap<u64, Option<Vec<u8>>> = HashMap::new();
        let mut fetch = |address: u64| -> Option<Insn> {
            let bytes = match &image {
                Some(image) => image.read(address, 16)?,
                None => {
                    let page = address & !0xFFF;
                    let mut out = Vec::new();
                    for base in [page, page + 0x1000] {
                        let entry = pages.entry(base).or_insert_with(|| read(client, base, 0x1000));
                        if let Some(bytes) = entry {
                            out.extend_from_slice(bytes);
                        } else {
                            break;
                        }
                    }
                    let offset = (address - page) as usize;
                    out.get(offset..(offset + 16).min(out.len()))?.to_vec()
                }
            };
            decode::decode(&bytes, address)
        };
        let graph = cfg::build(entry, range, &mut fetch, 20_000);
        let layout = cfg::layout(&graph);
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        self.re.imports.load(&client.symbols, entry);
        let mut blocks = Vec::new();
        for block in &graph.blocks {
            let length = (block.end - block.start) as usize;
            let bytes = match &image {
                Some(image) => image.read(block.start, length).unwrap_or_default(),
                None => client.read_memory(block.start, length).unwrap_or_default(),
            };
            // Os nomes nos operandos e os comentários do arquivo (sem ler a
            // memória do alvo linha a linha: o grafo pode ter milhares).
            let mut lines = disasm::disassemble_named(block.start, &bytes, &client.symbols, Some(&self.re.imports));
            lines.retain(|line| line.address < block.end);
            let context = annotations::Context { imports: &self.re.imports, register_types: &self.re.register_types, live: None, read_target: false };
            annotations::enrich(client, &mut lines, &context);
            let edges = block.edges.iter().filter_map(|edge| graph.block_at(edge.to).filter(|&index| graph.blocks[index].start == edge.to).map(|index| (index, edge.kind))).collect();
            blocks.push(GraphBlock { start: block.start, end: block.end, lines, edges, exit: block.exit });
        }
        let current = graph.block_at(if graph.block_at(rip).is_some() { rip } else { focus });
        let view = GraphView { function: entry, name, blocks, layout, current, focus, truncated: graph.truncated, error: None };
        self.re.graph = Some(Arc::new(view));
        Ok(true)
    }

    /// Uma busca (referências, constantes, chamadas, xrefs, padrões,
    /// strings) num módulo, em todos ou numa faixa.
    pub(super) fn search(&mut self, query: &SearchQuery) -> Result<bool, String> {
        let started = Instant::now();
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        // As imagens a varrer.
        let mut bases: Vec<u64> = Vec::new();
        let mut range_image: Option<ModuleImage> = None;
        let scope_text = match &query.scope {
            SearchScope::Module(address) => {
                let module = client.symbols.module_at(*address).ok_or_else(|| format!("{address:#x} fora dos modulos"))?;
                bases.push(module.base);
                format!("modulo {}", module.name)
            }
            SearchScope::AllModules => {
                bases = client.symbols.modules.iter().map(|module| module.base).collect();
                "todos os modulos".to_string()
            }
            SearchScope::Range(start, length) => {
                let start = client.evaluate(start)?;
                let length = (*length).clamp(1, 16 << 20);
                let mut image = scan::from_memory(start, start + length, "faixa", &mut |at, size| read(client, at, size));
                image.code = vec![(start, start + length)];
                range_image = Some(image);
                format!("{start:#x} + {length:#x}")
            }
        };
        let constant = match &query.kind {
            SearchKind::Constant(text) | SearchKind::References(text) => Some(client.evaluate(text)?),
            _ => None,
        };
        let pattern = match &query.kind {
            SearchKind::Pattern(text) => Some(search::parse_pattern(text)?),
            _ => None,
        };
        let key = query.kind.key();
        let mut rows = Vec::new();
        let mut cached = 0;
        let mut images: Vec<SharedImage> = Vec::new();
        if let Some(image) = range_image {
            images.push(Arc::new(image));
        } else {
            for base in &bases {
                // Do cache, quando a imagem não mudou desde a busca.
                if let Some((generation, found)) = self.re.reference_cache.get(&(*base, key.clone())) {
                    if *generation == self.re.patch_generation {
                        rows.extend(found.iter().cloned());
                        cached += 1;
                        continue;
                    }
                }
                if let Some(image) = self.module_image(*base) {
                    images.push(image);
                }
            }
        }
        // As imagens já carregadas servem de memória para as strings de
        // outro módulo.
        let loaded: Vec<SharedImage> = self.re.images.values().map(|(_, image)| Arc::clone(image)).collect();
        for image in &images {
            let mut memory = |address: u64, length: usize| -> Option<Vec<u8>> { image.read(address, length).or_else(|| loaded.iter().find_map(|other| other.read(address, length))) };
            let found: Vec<(u64, u64, String)> = match &query.kind {
                SearchKind::StringReferences => {
                    let instructions = image.instructions();
                    refs::string_references(&instructions, &mut memory, 4).into_iter().map(|reference| (reference.address, reference.target, if reference.wide { format!("L\"{}\"", reference.text) } else { format!("\"{}\"", reference.text) })).collect()
                }
                SearchKind::Constant(text) => {
                    let instructions = image.instructions();
                    let value = constant.unwrap_or(0);
                    refs::constant_references(&instructions, value).into_iter().map(|address| (address, value, text.clone())).collect()
                }
                SearchKind::References(_) => {
                    let instructions = image.instructions();
                    let value = constant.unwrap_or(0);
                    refs::references_to(&instructions, value).into_iter().map(|(address, kind)| (address, value, format!("{kind:?}"))).collect()
                }
                SearchKind::IntermodularCalls => {
                    let instructions = image.instructions();
                    refs::intermodular_calls(&instructions, (image.base, image.base + image.bytes.len() as u64), &mut memory).into_iter().map(|call| (call.address, call.target, String::new())).collect()
                }
                SearchKind::Pattern(_) => {
                    let pattern = pattern.as_ref().ok_or("padrao invalido")?;
                    pattern.find_all(&image.bytes, image.base, 5000).into_iter().map(|address| (address, address, String::new())).collect()
                }
                SearchKind::Strings => search::strings(&image.bytes, image.base, 5, 20000).into_iter().map(|found| (found.address, found.address, if found.wide { format!("L\"{}\"", found.text) } else { format!("\"{}\"", found.text) })).collect(),
            };
            let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
            self.re.imports.load(&client.symbols, image.base);
            let mut module_rows = Vec::with_capacity(found.len());
            for (address, target, text) in found {
                let code = image.read(address, 16).unwrap_or_default();
                let disassembly = if matches!(query.kind, SearchKind::Strings | SearchKind::Pattern(_)) {
                    hex_bytes(&code[..code.len().min(8)])
                } else {
                    disasm::first_named(address, &code, &client.symbols, Some(&self.re.imports))
                };
                let text = if matches!(query.kind, SearchKind::IntermodularCalls) { client.symbols.describe(target) } else { text };
                module_rows.push(ReferenceRow { address, location: client.symbols.describe(address), disassembly, text, target });
            }
            if matches!(query.scope, SearchScope::Module(_) | SearchScope::AllModules) {
                self.re.reference_cache.insert((image.base, key.clone()), (self.re.patch_generation, module_rows.clone()));
            }
            rows.extend(module_rows);
        }
        rows.sort_by_key(|row| row.address);
        let view = ReferenceView { title: query.kind.title(), scope: scope_text, rows, modules: images.len() + cached, milliseconds: started.elapsed().as_millis(), error: None, cached };
        if query.kind == SearchKind::Strings {
            self.re.strings = Some(Arc::new(view));
        } else {
            self.re.references = Some(Arc::new(view));
        }
        Ok(true)
    }

    /// Monta uma instrução e grava como patch.
    pub(super) fn assemble(&mut self, address: u64, text: &str) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let symbols = client.symbols.clone();
        let bytes = crate::asm::assemble(text, address, &|name| symbols.lookup(name).ok())?;
        // Completa com NOP até o fim da instrução que sai (quando a nova é
        // menor), como um montador de depurador faz.
        let old = client.read_memory(address, 16).unwrap_or_default();
        let mut covered = 0usize;
        while covered < bytes.len() {
            match disasm::instruction_length(address + covered as u64, &old[covered.min(old.len())..]) {
                Some(length) if length > 0 => covered += length,
                _ => break,
            }
        }
        let mut patched = bytes;
        while patched.len() < covered {
            patched.push(0x90);
        }
        self.write_patch(address, &patched)
    }

    /// Grava bytes no alvo e registra o patch (com os bytes originais).
    pub(super) fn write_patch(&mut self, address: u64, bytes: &[u8]) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let original = client.read_memory(address, bytes.len())?;
        if original.len() < bytes.len() {
            return Err(format!("{address:#x}: memoria inacessivel"));
        }
        client.write_memory(address, bytes)?;
        let location = location_of(client, address);
        self.re.patches.add(Patch { location, address, original, patched: bytes.to_vec() });
        self.re.patch_generation += 1;
        Ok(true)
    }

    /// Desfaz o patch que cobre o endereço.
    pub(super) fn revert_patch(&mut self, address: u64) -> Result<bool, String> {
        let patch = self.re.patches.remove(address).ok_or_else(|| format!("nenhum patch em {address:#x}"))?;
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        client.write_memory(patch.address, &patch.original)?;
        self.re.patch_generation += 1;
        Ok(true)
    }

    pub(super) fn revert_all_patches(&mut self) -> Result<bool, String> {
        let addresses: Vec<u64> = self.re.patches.list.iter().map(|patch| patch.address).collect();
        for address in addresses {
            self.revert_patch(address)?;
        }
        Ok(true)
    }

    pub(super) fn export_patches(&mut self, path: &Path) -> Result<bool, String> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, self.re.patches.export()).map_err(|error| format!("{}: {error}", path.display()))?;
        self.transcript("(patches)", Ok(format!("{} patches em {}", self.re.patches.list.len(), path.display())));
        Ok(false)
    }

    /// O mapa de memória: as imagens do kernel com as seções e as faixas
    /// de sistema; com um processo escolhido, as regiões de usuário dele
    /// (as imagens com as seções).
    pub(super) fn load_memory_map(&mut self) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let mut view = MemoryMapView::default();
        let process = client.process().cloned();
        let row = |base: u64, size: u64, kind: &str, protection: String, name: String, section: String, content: String, initial: String| {
            let party = if base < 0x8000_0000_0000 { "Usuário" } else { "Sistema" };
            let executable = protection.contains('X');
            MapRow { base, size, kind: kind.to_string(), protection, name, section, party: party.into(), content, initial_protection: initial, executable }
        };
        match &process {
            Some(context) => {
                view.title = format!("processo {} (PID {}, CR3 {:#x})", context.name, context.pid, context.cr3);
                match client.regions(&format!("{:#x}", context.eprocess)) {
                    Ok(regions) => {
                        let bases: Vec<u64> = regions.iter().filter(|region| region.kind == "Image").map(|region| region.base).collect();
                        for region in regions {
                            let protection = user::protection_text(if region.protect != 0 { region.protect } else { region.allocation_protect });
                            let content = match region.kind.as_str() {
                                "Image" => "imagem".to_string(),
                                "Mapped" => "visão mapeada".to_string(),
                                _ if region.protect & 0xF0 != 0 => "código privado".to_string(),
                                _ => "dados privados".to_string(),
                            };
                            view.rows.push(row(region.base, region.size, &region.kind, protection, region.name.clone(), String::new(), content, user::protection_text(region.allocation_protect)));
                        }
                        for base in bases {
                            if let Some(image) = self.module_image(base) {
                                for (name, start, end, characteristics) in &image.sections {
                                    view.rows.push(row(*start, end - start, "Seção", user::section_protection(*characteristics), image.name.clone(), name.clone(), section_content(name, *characteristics), String::new()));
                                }
                            }
                        }
                    }
                    Err(error) => view.error = Some(error),
                }
            }
            None => {
                view.title = "kernel".into();
                let modules: Vec<(u64, u64, String, bool)> = client.symbols.modules.iter().filter(|module| !module.user).map(|module| (module.base, module.end, module.name.clone(), client.symbols.is_kernel(module))).collect();
                let ranges = client.kernel_ranges().unwrap_or_default();
                for range in ranges {
                    view.rows.push(row(range.start, range.end - range.start, "Faixa", String::new(), range.name.clone(), String::new(), range.name, String::new()));
                }
                for (base, end, name, kernel) in modules {
                    view.rows.push(row(base, end - base, "Image", String::new(), name.clone(), String::new(), "imagem".into(), String::new()));
                    if let Some(image) = self.module_image(base) {
                        for (section, start, finish, flags) in &image.sections {
                            let (protection, content) = if kernel {
                                let content = if flags & 4 != 0 {
                                    "código"
                                } else if flags & 1 != 0 {
                                    "dados"
                                } else {
                                    "dados só de leitura"
                                };
                                (elf_protection(*flags), content.to_string())
                            } else {
                                (user::section_protection(*flags), section_content(section, *flags))
                            };
                            view.rows.push(row(*start, finish - start, "Seção", protection, name.clone(), section.clone(), content, String::new()));
                        }
                    }
                }
            }
        }
        view.rows.sort_by(|a, b| a.base.cmp(&b.base).then(b.size.cmp(&a.size)));
        self.re.memory_map = Some(Arc::new(view));
        Ok(true)
    }

    /// A análise do módulo da imagem (começada na primeira vez numa thread
    /// e refeita depois de um patch) e se ela já existia.
    fn module_analysis(&mut self, image: &SharedImage) -> (Arc<ModuleAnalysis>, bool) {
        let generation = self.re.patch_generation;
        let end = image.base + image.bytes.len() as u64;
        if let Some(existing) = self.re.analyses.get(&image.base) {
            if existing.generation == generation && existing.end == end && existing.name == image.name {
                return (Arc::clone(existing), true);
            }
            existing.cancel();
        }
        let imports = match self.client.as_ref() {
            Some(client) => self.re.imports.load(&client.symbols, image.base).unwrap_or_default(),
            None => Arc::new(ImportMap::default()),
        };
        if self.re.analyses.len() >= MAX_ANALYSES {
            let other = self.re.analyses.keys().copied().find(|&base| base != image.base);
            if let Some(analysis) = other.and_then(|base| self.re.analyses.remove(&base)) {
                analysis.cancel();
            }
        }
        let analysis = ModuleAnalysis::start(Arc::clone(image), imports, generation);
        self.re.analyses.insert(image.base, Arc::clone(&analysis));
        (analysis, false)
    }

    /// Quem referencia o endereço (a análise do módulo dele, com o que já
    /// ficou pronto) e o que sai da função que o contém.
    pub(super) fn xrefs(&mut self, address: u64) -> Result<bool, String> {
        let image = self.module_image(address).ok_or_else(|| format!("{address:#x} fora dos modulos"))?;
        let (analysis, existed) = self.module_analysis(&image);
        let progress = analysis.progress();
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        self.re.imports.load(&client.symbols, address);
        let symbols: &Symbols = &client.symbols;
        let imports: &ImportCache = &self.re.imports;
        let row = |from: u64, to: u64, kind: RefKind| -> XrefRow {
            let disassembly = if kind == RefKind::Data {
                format!("dq {}", annotation_name(symbols, imports, to))
            } else {
                let code = image.read(from, 16).unwrap_or_default();
                disasm::first_named(from, &code, symbols, Some(imports))
            };
            XrefRow { from, location: symbols.describe(from), kind: kind.name().into(), disassembly, to, to_name: annotation_name(symbols, imports, to) }
        };
        let rows: Vec<XrefRow> = analysis.references_to(address).into_iter().map(|reference| row(reference.from, reference.to, reference.kind)).collect();
        // A função: a da .pdata (com os pedaços), senão o símbolo com
        // tamanho (o kernel do OpenNT).
        let function = analysis.function_at(address).cloned().or_else(|| {
            let module = symbols.module_at(address)?;
            let index = module.symbols.partition_point(|symbol| symbol.address <= address);
            let symbol = module.symbols[..index].iter().rev().take(64).find(|symbol| symbol.function && symbol.size != 0 && address < symbol.address + symbol.size)?;
            Some(analysis::plain_function(symbol.address, symbol.address + symbol.size))
        });
        let callees: Vec<XrefRow> = function.as_ref().map(|function| analysis::references_from(&image, &analysis.imports, function).into_iter().map(|reference| row(reference.from, reference.to, reference.kind)).collect()).unwrap_or_default();
        let function_info = function.as_ref().map(|function| (function.start, symbols.describe(function.start), function.chunks.len()));
        let view = XrefView {
            target: address,
            name: symbols.describe(address),
            module: image.name.clone(),
            rows,
            milliseconds: progress.milliseconds,
            cached: existed,
            error: None,
            function: function_info,
            callees,
            progress: (!progress.finished).then_some((progress.done, progress.total)),
        };
        self.re.xref_pending = (!progress.finished).then_some((address, progress));
        self.re.xrefs = Some(Arc::new(view));
        Ok(true)
    }

    /// Com a janela Xrefs esperando a análise do módulo: refaz a resposta
    /// quando ficam prontos mais lotes (a cada décimo do total) e no fim.
    pub(super) fn poll_analysis(&mut self) {
        let Some((address, shown)) = self.re.xref_pending else { return };
        if !self.client.as_ref().is_some_and(Client::is_stopped) {
            return;
        }
        let Some(analysis) = self.re.analyses.values().find(|analysis| address >= analysis.base && address < analysis.end).cloned() else {
            self.re.xref_pending = None;
            return;
        };
        let progress = analysis.progress();
        if progress == shown || (!progress.finished && progress.done < shown.done + (progress.total / 10).max(1)) {
            return;
        }
        if self.xrefs(address).is_err() {
            self.re.xref_pending = None;
            return;
        }
        // Só a janela Xrefs muda: o snapshot publicado ganha a vista nova.
        let current = self.shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).snapshot.clone();
        let mut copy = (*current).clone();
        copy.xrefs = self.re.xrefs.clone();
        self.generation += 1;
        copy.generation = self.generation;
        self.publish(|shared| shared.snapshot = Arc::new(copy));
    }

    /// Dá um tipo a um registrador a partir de uma instrução (vazio tira):
    /// os operandos `[reg+deslocamento]` seguintes ganham o nome do campo.
    pub(super) fn set_register_type(&mut self, address: u64, register: &str, type_name: &str) -> Result<bool, String> {
        let register = register.trim().to_ascii_lowercase();
        if annotations::register_named(&register).is_none() {
            return Err(format!("{register}: um registrador de 64 bits (rax..r15)"));
        }
        let type_name = type_name.trim().to_string();
        if !type_name.is_empty() {
            let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
            client.types_for(type_name.trim_end_matches('*').trim())?;
        }
        self.re.register_types.retain(|entry| !(entry.address == address && entry.register == register));
        if !type_name.is_empty() {
            self.re.register_types.push(RegisterType { address, register, type_name });
        }
        Ok(true)
    }

    /// Grava `size` bytes de `address` num arquivo (o dump da região).
    pub(super) fn dump_to_file(&mut self, address: u64, size: u64, path: &Path) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let size = size.min(256 << 20) as usize;
        let mut bytes = Vec::with_capacity(size);
        // Página a página: uma página sem mapa vira zeros.
        let mut offset = 0usize;
        while offset < size {
            let chunk = (size - offset).min(0x1000 - ((address as usize + offset) & 0xFFF));
            match client.read_memory(address + offset as u64, chunk) {
                Ok(data) if data.len() == chunk => bytes.extend_from_slice(&data),
                _ => bytes.extend(std::iter::repeat_n(0u8, chunk)),
            }
            offset += chunk;
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, &bytes).map_err(|error| format!("{}: {error}", path.display()))?;
        self.transcript("(dump)", Ok(format!("{size:#x} bytes de {address:#x} em {}", path.display())));
        Ok(false)
    }

    /// O deslocamento no arquivo de um endereço (pela seção do PE desta
    /// máquina) vai à área de transferência.
    pub(super) fn copy_file_offset(&mut self, address: u64) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let module = client.symbols.module_at(address).ok_or_else(|| format!("{address:#x} fora dos modulos"))?;
        let image = module.image.clone().ok_or_else(|| format!("{}: sem o arquivo PE nesta maquina", module.name))?;
        let rva = (address - module.base) as u32;
        let offset = image.offset(rva).ok_or_else(|| format!("RVA {rva:#x} fora das secoes do arquivo"))?;
        let text = format!("{offset:#x}");
        self.publish(|shared| shared.clipboard = Some(text));
        Ok(false)
    }

    pub(super) fn load_handles(&mut self) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let process = client.process().map(|context| format!("{:#x}", context.eprocess)).unwrap_or_else(|| "4".into());
        self.re.handles = Some(Arc::new(client.handles(&process)));
        Ok(true)
    }

    pub(super) fn load_user_threads(&mut self) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let process = client.process().map(|context| format!("{:#x}", context.eprocess)).ok_or("escolha um processo (Processos, clique duplo)")?;
        self.re.user_threads = Some(Arc::new(client.user_threads(&process)));
        Ok(true)
    }

    /// Os símbolos, exports e imports do módulo em `base`.
    pub(super) fn load_symbols(&mut self, base: u64) -> Result<bool, String> {
        let image = self.module_image(base);
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let module = client.symbols.module_at(base).ok_or_else(|| format!("{base:#x} fora dos modulos"))?.clone();
        let mut view = SymbolView { module: module.name.clone(), base: module.base, source: module.source.clone(), ..Default::default() };
        view.symbols = module.symbols.iter().map(|symbol| (symbol.address, symbol.name.clone())).collect();
        if let Some(pe) = &module.image {
            view.exports = pe.exports().into_iter().map(|(rva, name)| (module.base + rva as u64, name)).collect();
        }
        if let Some(image) = image {
            for import in scan::imports(&image) {
                let slot = module.base + import.slot as u64;
                let value = client.read_integer(slot, 8).unwrap_or(0);
                view.imports.push((slot, import.dll, import.name, value));
            }
        }
        self.re.symbol_view = Some(Arc::new(view));
        Ok(true)
    }

    /// Roda um roteiro contra o alvo, na linguagem dos roteiros do kd
    /// (`opennt_kd::kd_script`, a mesma do `--script` do test-boot e da
    /// janela do opennt-dbg); a saída vai à transcrição.
    pub(super) fn run_script(&mut self, text: &str) -> Result<bool, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let capture = Arc::new(Mutex::new(String::new()));
        let options = ScriptOptions { capture: Some(Arc::clone(&capture)), ..ScriptOptions::default() };
        let result = client.run_script_with(text, &options);
        let mut text = capture.lock().map(|output| output.clone()).unwrap_or_default();
        match &result {
            Ok(()) => text.push_str("roteiro: fim"),
            Err(error) => text.push_str(&format!("roteiro: {error}")),
        }
        self.transcript("(roteiro)", if result.is_ok() { Ok(text) } else { Err(text) });
        if !self.client.as_ref().is_some_and(Client::is_stopped) {
            self.set_status(super::Status::Running);
            return Ok(false);
        }
        Ok(true)
    }

    /// Roda até o código de usuário: o primeiro quadro da pilha fora do
    /// sistema (num processo, o executável; no kernel, um driver).
    pub(super) fn run_to_user_code(&mut self) -> Result<Resumed, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let frames = client.backtrace(32)?;
        let user = client.stopped_in_user_mode();
        let main = client.symbols.user_modules().next().map(|module| (module.base, module.end));
        let target = frames.iter().skip(1).find(|frame| {
            let Some(module) = client.symbols.module_at(frame.address) else { return false };
            if user {
                main.is_some_and(|(base, end)| frame.address >= base && frame.address < end)
            } else {
                !client.symbols.is_kernel(module) && !module.user
            }
        });
        let frame = target.copied().ok_or("nenhum quadro de codigo de usuario na pilha")?;
        client.run_until(frame.address, Some(frame.stack))?;
        Ok(Resumed::Running)
    }
}

/// O nome de um destino: o import de um slot da IAT, o símbolo ou
/// `módulo+0xRVA`, senão o número.
fn annotation_name(symbols: &Symbols, imports: &ImportCache, address: u64) -> String {
    if let Some((_, import)) = imports.get(symbols, address) {
        return format!("IAT de {}", import.display());
    }
    if symbols.module_at(address).is_some() {
        symbols.describe(address)
    } else {
        format!("{address:#x}")
    }
}

/// A localização módulo + RVA de um endereço (absoluta fora dos módulos).
pub fn location_of(client: &Client, address: u64) -> Location {
    match client.symbols.module_at(address) {
        Some(module) if client.symbols.is_kernel(module) => Location::new("kernel", address - module.base),
        Some(module) => Location::new(&module.name, address - module.base),
        None => Location::absolute(address),
    }
}

/// O conteúdo de uma seção de PE pelo nome e pelas características.
fn section_content(name: &str, characteristics: u32) -> String {
    match name {
        ".text" | "PAGE" | "INIT" => "código".into(),
        ".rdata" => "dados só de leitura".into(),
        ".data" => "dados".into(),
        ".pdata" => "tabela de funções".into(),
        ".rsrc" => "recursos".into(),
        ".reloc" => "relocações".into(),
        _ if characteristics & 0x2000_0000 != 0 => "código".into(),
        _ if characteristics & 0x8000_0000 != 0 => "dados".into(),
        _ => "dados só de leitura".into(),
    }
}

/// A proteção de uma seção do ELF pelas flags (ALLOC, WRITE, EXECINSTR).
fn elf_protection(flags: u32) -> String {
    format!("R{}{}", if flags & 1 != 0 { 'W' } else { '-' }, if flags & 4 != 0 { 'X' } else { '-' })
}

/// O que a parada é, em palavras (exceção de usuário, breakpoint, bugcheck).
fn describe_exception(snapshot: &Snapshot) -> Option<String> {
    let mode = if snapshot.user_mode {
        format!("modo usuario ({})", snapshot.process.as_ref().map_or("?".to_string(), |process| format!("{} PID {}", process.name, process.pid)))
    } else {
        "modo kernel".to_string()
    };
    let reason = match snapshot.stop_signal {
        2 => "pedido de parada",
        4 => "instrucao invalida",
        5 if snapshot.stop.contains("swbreak") => "breakpoint de software",
        5 if snapshot.stop.contains("hwbreak") => "breakpoint de hardware",
        5 if snapshot.stop.contains("watch") => "vigia de memoria",
        5 => "passo ou int 3",
        6 => "bugcheck ou panico",
        8 => "erro de ponto flutuante",
        11 => "violacao de acesso",
        0 => return None,
        _ => "sinal",
    };
    Some(format!("{reason}, {mode}"))
}

/// A caixa de informação: os operandos de memória (endereço e valor) e os
/// registradores lidos pela instrução em `address`.
fn info_box(client: &mut Client, address: u64, registers: &[RegisterRow]) -> Vec<String> {
    let Ok(code) = client.read_memory(address, 16) else { return Vec::new() };
    let value = |name: &str| registers.iter().find(|row| row.name == name).and_then(|row| row.value);
    let mut lines = Vec::new();
    let Some(line) = disasm::disassemble(address, &code, Some(&client.symbols)).into_iter().next() else { return lines };
    for operand in disasm::memory_operands(address, &code, &value) {
        let size = operand.size.clamp(1, 8);
        let shown = client.read_memory(operand.address, size).ok().filter(|bytes| bytes.len() == size).map(|bytes| {
            let mut buffer = [0u8; 8];
            buffer[..size].copy_from_slice(&bytes);
            let number = u64::from_le_bytes(buffer);
            match client.symbols.name_at(number) {
                Some(name) => format!("{number:#x} {name}"),
                None => format!("{number:#x}"),
            }
        });
        let width = match operand.size {
            1 => "byte",
            2 => "word",
            4 => "dword",
            8 => "qword",
            16 => "xmmword",
            _ => "",
        };
        lines.push(format!("{width} ptr [{:#x}] = {}", operand.address, shown.unwrap_or_else(|| "??".into())));
    }
    for name in disasm::read_registers(address, &code) {
        if let Some(number) = value(&name) {
            // O símbolo, ou o nome do NTSTATUS/HRESULT que o valor é.
            let symbol = client.symbols.name_at(number).or_else(|| codes().immediate(number)).map(|name| format!(" {name}")).unwrap_or_default();
            lines.push(format!("{name} = {number:#x}{symbol}"));
        }
    }
    if let Some(target) = line.target {
        lines.push(format!("destino: {target:#x} {}", client.symbols.describe(target)));
    }
    // O imediato que é um código de erro, com o texto da tabela de
    // mensagens do binário.
    if let Some(immediate) = decode::decode(&code, address).and_then(|insn| insn.immediate) {
        if codes().immediate(immediate).is_some() {
            lines.extend(codes().explain(immediate as u32).into_iter().map(|text| format!("imediato {text}")));
        }
    }
    if let Some(insn) = decode::decode(&code, address) {
        if insn.flow == Flow::Conditional {
            if let Some(flags) = value("eflags") {
                lines.push(format!("rflags = {flags:#x}"));
            }
        }
    }
    lines
}
