//! A janela do opennt-re, no arranjo dos depuradores de engenharia
//! reversa: abas no alto (CPU, Grafo, Log, Notas, Breakpoints, Mapa de
//! memória, Pilha de chamadas, SEH, Script, Símbolos, Código-fonte,
//! Referências, Threads, Handles, Rastro e as do OpenNT), a aba CPU com os
//! quatro painéis (desmontagem com a caixa de informação, registradores,
//! Dump 1-5 e pilha), a barra de comando e a barra de estado embaixo.
//!
//! As abas são do `egui_dock`: arrastar uma aba a solta, junta ou divide a
//! área, e o menu Exibir reabre uma aba fechada ou volta ao arranjo padrão.
//! Os painéis só leem o `Snapshot` publicado pelo backend e mandam pedidos;
//! nada aqui espera o alvo. O arranjo, o tema, as expressões observadas, o
//! histórico de comandos e o roteiro ficam num arquivo de estado; os
//! comentários, rótulos e marcadores (por módulo + RVA) e as notas ficam na
//! pasta do build.

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, Key, Modifiers, Pos2, RichText, Sense, Stroke, TextStyle, Ui, Vec2, WidgetText};
use egui_dock::{DockArea, DockState, NodePath, Style, TabViewer};
use kd_client::analysis::notes::{Location, Notes};
use kd_client::{BreakpointKind, Client};
use serde::{Deserialize, Serialize};

use crate::backend::{Backend, Entry, ModuleRow, QueryKind, Request, SearchKind, SearchQuery, SearchScope, Snapshot, Status, Target, TraceView, View};
use crate::launcher::LaunchOptions;
use crate::{cpu, graph, panels, views};

/// As abas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tab {
    Cpu,
    Graph,
    Log,
    Notes,
    Breakpoints,
    MemoryMap,
    CallStack,
    Seh,
    Script,
    Symbols,
    Source,
    References,
    Threads,
    Handles,
    Trace,
    Strings,
    Patches,
    Comments,
    Processes,
    Watch,
    NtObjects,
    Bugcheck,
}

impl Tab {
    pub const ALL: [Tab; 22] = [
        Tab::Cpu,
        Tab::Graph,
        Tab::Log,
        Tab::Notes,
        Tab::Breakpoints,
        Tab::MemoryMap,
        Tab::CallStack,
        Tab::Seh,
        Tab::Script,
        Tab::Symbols,
        Tab::Source,
        Tab::References,
        Tab::Threads,
        Tab::Handles,
        Tab::Trace,
        Tab::Strings,
        Tab::Patches,
        Tab::Comments,
        Tab::Processes,
        Tab::Watch,
        Tab::NtObjects,
        Tab::Bugcheck,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Cpu => "CPU",
            Tab::Graph => "Grafo",
            Tab::Log => "Log",
            Tab::Notes => "Notas",
            Tab::Breakpoints => "Breakpoints",
            Tab::MemoryMap => "Mapa de memória",
            Tab::CallStack => "Pilha de chamadas",
            Tab::Seh => "SEH",
            Tab::Script => "Script",
            Tab::Symbols => "Símbolos",
            Tab::Source => "Código-fonte",
            Tab::References => "Referências",
            Tab::Threads => "Threads",
            Tab::Handles => "Handles",
            Tab::Trace => "Rastro",
            Tab::Strings => "Strings",
            Tab::Patches => "Patches",
            Tab::Comments => "Comentários/Rótulos",
            Tab::Processes => "Processos",
            Tab::Watch => "Observação",
            Tab::NtObjects => "Objetos do NT",
            Tab::Bugcheck => "Bugcheck",
        }
    }
}

/// O arranjo padrão: todas as abas numa fila no alto, a CPU à vista.
pub fn default_layout() -> DockState<Tab> {
    let mut dock = DockState::new(Tab::ALL.to_vec());
    if let Some(path) = dock.find_tab(&Tab::Cpu) {
        let _ = dock.set_active_tab(path);
    }
    dock
}

/// Texto que só cresce (DbgPrint, COM1), em linhas para a rolagem
/// virtual.
#[derive(Default)]
pub(crate) struct LogLines {
    lines: Vec<String>,
    partial: String,
    /// Quanto do texto do backend já entrou.
    consumed: usize,
}

impl LogLines {
    fn sync(&mut self, text: &str) {
        if text.len() < self.consumed || !text.is_char_boundary(self.consumed) {
            *self = LogLines::default();
        }
        let new = &text[self.consumed..];
        self.consumed = text.len();
        for (index, piece) in new.split('\n').enumerate() {
            if index > 0 {
                self.lines.push(std::mem::take(&mut self.partial));
            }
            self.partial.push_str(piece.trim_end_matches('\r'));
        }
    }

    pub(crate) fn count(&self) -> usize {
        self.lines.len() + usize::from(!self.partial.is_empty())
    }

    pub(crate) fn line(&self, index: usize) -> &str {
        self.lines.get(index).map_or(self.partial.as_str(), String::as_str)
    }
}

/// Como uma janela de memória (Dump) aparece.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryFormat {
    HexAscii,
    HexUnicode,
    Words,
    Dwords,
    Qwords,
    Address,
    Float,
    Double,
}

impl MemoryFormat {
    pub const ALL: [MemoryFormat; 8] = [MemoryFormat::HexAscii, MemoryFormat::HexUnicode, MemoryFormat::Words, MemoryFormat::Dwords, MemoryFormat::Qwords, MemoryFormat::Address, MemoryFormat::Float, MemoryFormat::Double];

    pub fn label(self) -> &'static str {
        match self {
            MemoryFormat::HexAscii => "Hex + ASCII",
            MemoryFormat::HexUnicode => "Hex + UTF-16",
            MemoryFormat::Words => "Word (2)",
            MemoryFormat::Dwords => "Dword (4)",
            MemoryFormat::Qwords => "Qword (8)",
            MemoryFormat::Address => "Endereço",
            MemoryFormat::Float => "Float",
            MemoryFormat::Double => "Double",
        }
    }
}

/// O modo do rastro pedido no painel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceMode {
    Count,
    Until,
    Return,
    Enter,
    Leave,
}

impl TraceMode {
    pub(crate) const ALL: [TraceMode; 5] = [TraceMode::Count, TraceMode::Until, TraceMode::Return, TraceMode::Enter, TraceMode::Leave];

    pub(crate) fn label(self) -> &'static str {
        match self {
            TraceMode::Count => "N instruções",
            TraceMode::Until => "até o endereço",
            TraceMode::Return => "até o retorno",
            TraceMode::Enter => "até entrar no módulo",
            TraceMode::Leave => "até sair do módulo",
        }
    }
}

/// O que o painel Rastro mostra.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceDisplay {
    Table,
    Tree,
    Diff,
}

/// Uma caixa de diálogo aberta (atalhos da aba CPU e menus).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Dialog {
    /// Ctrl+G: ir para uma expressão.
    GoTo(String),
    /// `;`: comentário na linha.
    Comment(u64, String),
    /// `:`: rótulo na linha.
    Label(u64, String),
    /// Espaço: montar uma instrução.
    Assemble(u64, String),
    /// Ctrl+B: padrão com curingas (texto, todos os módulos).
    Pattern(String, bool),
    /// Constante (texto, todos os módulos).
    Constant(String, bool),
    /// Faixa de memória: início, tamanho, escrita.
    RangeWatch(String, String, bool),
}

/// O estado salvo entre execuções.
#[derive(Serialize, Deserialize, Default)]
struct Saved {
    layout: Option<DockState<Tab>>,
    light: bool,
    watches: Vec<String>,
    history: Vec<String>,
    script: String,
}

/// O estado da interface (campos de texto, cópias do que o backend
/// publicou). Os campos são do crate: os painéis moram em módulos irmãos.
pub struct UiState {
    pub(crate) snapshot: Arc<Snapshot>,
    pub(crate) status: Status,
    pub(crate) activity: String,
    pub(crate) can_restart: bool,
    pub(crate) transcript: Vec<Entry>,
    pub(crate) console: LogLines,
    pub(crate) serial: LogLines,
    pub(crate) launch_log: LogLines,
    pub(crate) command: String,
    pub(crate) command_focused: bool,
    pub(crate) history: Vec<String>,
    pub(crate) history_index: Option<usize>,
    pub(crate) completions: Arc<Vec<String>>,
    pub(crate) type_names: Arc<Vec<String>>,
    pub(crate) suggestions: Vec<String>,
    pub(crate) selected_code: Option<u64>,
    pub(crate) breakpoint_expression: String,
    pub(crate) breakpoint_kind: BreakpointKind,
    pub(crate) breakpoint_condition: String,
    pub(crate) breakpoint_pass: String,
    pub(crate) breakpoint_log: String,
    pub(crate) breakpoint_command: String,
    pub(crate) breakpoint_group: String,
    pub(crate) breakpoint_deferred: bool,
    /// Edição de um breakpoint: id, condição, contagem, log, comandos, grupo.
    pub(crate) breakpoint_edit: Option<(u32, String, String, String, String, String)>,
    pub(crate) register_edit: Option<(String, String)>,
    pub(crate) memory_edit: Option<(u64, String)>,
    pub(crate) thread_filter: Option<u64>,
    pub(crate) connect_address: String,
    pub(crate) launch: Option<LaunchOptions>,
    /// A geração do snapshot que já rolou o código até o foco.
    pub(crate) scrolled_code: u64,
    pub(crate) scrolled_source: u64,
    pub(crate) scrolled_stack: u64,
    pub(crate) requests: Vec<Request>,
    pub(crate) watches: Vec<String>,
    pub(crate) watch_input: String,
    pub(crate) sent_watches: Vec<String>,
    pub(crate) expanded: BTreeSet<(u64, u32)>,
    pub(crate) sent_expanded: BTreeSet<(u64, u32)>,
    pub(crate) query_kind: QueryKind,
    pub(crate) query_argument: String,
    pub(crate) trace: Option<Arc<TraceView>>,
    pub(crate) reference: Option<Arc<TraceView>>,
    pub(crate) trace_generation: u64,
    pub(crate) trace_mode: TraceMode,
    pub(crate) trace_argument: String,
    pub(crate) trace_count: String,
    pub(crate) trace_over: bool,
    pub(crate) trace_skip: String,
    pub(crate) trace_watch: String,
    pub(crate) trace_qemu_ms: String,
    pub(crate) trace_filter: String,
    pub(crate) trace_display: TraceDisplay,
    pub(crate) trace_selected: Option<usize>,
    pub(crate) trace_rows: Vec<usize>,
    pub(crate) trace_rows_key: (u64, String),
    pub(crate) trace_scroll: Option<usize>,
    pub(crate) trace_tree: Option<(u64, Vec<kd_client::trace::CallNode>)>,
    pub(crate) trace_path: String,
    pub(crate) reference_path: String,
    pub(crate) divergence: Option<Option<(usize, usize)>>,
    pub(crate) light: bool,
    pub(crate) theme_applied: Option<bool>,
    /// Painéis a mostrar no próximo quadro.
    pub(crate) focus_tab: Vec<Tab>,
    pub(crate) bugcheck_seen: u64,
    pub(crate) reset_layout: bool,
    pub(crate) toggle_tab: Option<Tab>,
    // ---- aba CPU e vistas de engenharia reversa ----
    pub(crate) dump_tab: usize,
    pub(crate) dump_inputs: [String; 5],
    pub(crate) dump_formats: [MemoryFormat; 5],
    pub(crate) notes: Notes,
    pub(crate) notes_path: Option<PathBuf>,
    pub(crate) notes_saved: String,
    /// O texto livre da aba Notas.
    pub(crate) session_notes: String,
    pub(crate) session_notes_path: Option<PathBuf>,
    pub(crate) session_notes_saved: String,
    pub(crate) dialog: Option<Dialog>,
    pub(crate) dialog_error: Option<String>,
    /// Os RIPs do último rastro (as instruções executadas na desmontagem).
    pub(crate) executed: Arc<HashSet<u64>>,
    pub(crate) reference_filter: String,
    pub(crate) reference_regex: bool,
    pub(crate) reference_selected: Option<usize>,
    pub(crate) strings_filter: String,
    pub(crate) strings_selected: Option<usize>,
    pub(crate) map_filter: String,
    pub(crate) symbols_filter: String,
    pub(crate) symbols_mode: usize,
    pub(crate) script_text: String,
    pub(crate) script_path: String,
    pub(crate) comments_filter: String,
    pub(crate) graph_zoom: f32,
    pub(crate) graph_offset: Vec2,
    pub(crate) graph_fit: u64,
    pub(crate) log_mode: usize,
    pub(crate) user_exceptions: bool,
    pub(crate) patch_path: String,
    pub(crate) handles_filter: String,
    pub(crate) last_message: String,
}

impl UiState {
    /// A desmontagem da aba CPU num endereço.
    pub(crate) fn go_to_code(&mut self, address: u64) {
        self.selected_code = Some(address);
        self.requests.push(Request::ShowCode(format!("{address:#x}")));
        self.requests.push(Request::SelectInstruction(Some(address)));
        self.focus_tab.push(Tab::Cpu);
    }

    /// O Dump escolhido num endereço.
    pub(crate) fn follow_in_dump(&mut self, address: u64) {
        let index = self.dump_tab.min(4);
        self.dump_inputs[index] = format!("{address:#x}");
        self.requests.push(Request::ShowDump(index, self.dump_inputs[index].clone()));
        self.focus_tab.push(Tab::Cpu);
    }

    /// O módulo que contém o endereço.
    pub(crate) fn module_at(&self, address: u64) -> Option<&ModuleRow> {
        self.snapshot.modules.iter().find(|module| address >= module.base && address < module.end)
    }

    /// A localização módulo + RVA de um endereço (absoluta fora dos
    /// módulos; o kernel do OpenNT é `kernel`).
    pub(crate) fn location(&self, address: u64) -> Location {
        match self.module_at(address) {
            Some(module) if module.source == "ELF do kernel" => Location::new("kernel", address - module.base),
            Some(module) => Location::new(&module.name, address - module.base),
            None => Location::absolute(address),
        }
    }

    /// O endereço de uma localização com os módulos de agora.
    pub(crate) fn address_of(&self, location: &Location) -> Option<u64> {
        if location.module.is_empty() {
            return Some(location.offset);
        }
        let module = self.snapshot.modules.iter().find(|module| if location.module == "kernel" { module.source == "ELF do kernel" } else { module.name.to_ascii_lowercase() == location.module })?;
        Some(module.base + location.offset)
    }

    pub(crate) fn comment_at(&self, address: u64) -> Option<&String> {
        self.notes.comments.get(&self.location(address))
    }

    pub(crate) fn label_at(&self, address: u64) -> Option<&String> {
        self.notes.labels.get(&self.location(address))
    }

    pub(crate) fn bookmarked(&self, address: u64) -> bool {
        self.notes.bookmarks.contains(&self.location(address))
    }

    /// Uma busca no módulo do endereço escolhido (ou em todos).
    pub(crate) fn search(&mut self, kind: SearchKind, all_modules: bool) {
        let address = self.selected_code.or_else(|| current_rip(&self.snapshot)).unwrap_or(0);
        let scope = if all_modules { SearchScope::AllModules } else { SearchScope::Module(address) };
        let strings = kind == SearchKind::Strings;
        self.requests.push(Request::Search(SearchQuery { kind, scope }));
        self.focus_tab.push(if strings { Tab::Strings } else { Tab::References });
    }
}

pub struct DebuggerApp {
    pub backend: Backend,
    dock: DockState<Tab>,
    state: UiState,
    /// O arquivo de estado (`None`: sem persistência, como na captura).
    persist: Option<PathBuf>,
    last_saved: String,
    last_save: Instant,
}

/// As cores, pelo tema.
#[derive(Clone, Copy)]
pub(crate) struct Palette {
    pub(crate) red: Color32,
    pub(crate) yellow: Color32,
    pub(crate) green: Color32,
    pub(crate) blue: Color32,
    pub(crate) dim: Color32,
    pub(crate) focus: Color32,
    /// O fundo da linha do RIP.
    pub(crate) current: Color32,
    /// O fundo das instruções executadas (rastro).
    pub(crate) executed: Color32,
    /// O fundo do endereço com breakpoint.
    pub(crate) breakpoint: Color32,
    pub(crate) comment: Color32,
    pub(crate) label: Color32,
    pub(crate) selection: Color32,
}

pub(crate) fn palette(ui: &Ui) -> Palette {
    if ui.visuals().dark_mode {
        Palette {
            red: Color32::from_rgb(0xE8, 0x5C, 0x5C),
            yellow: Color32::from_rgb(0xF2, 0xC1, 0x4E),
            green: Color32::from_rgb(0x5C, 0xC0, 0x6C),
            blue: Color32::from_rgb(0x6C, 0xA8, 0xF0),
            dim: Color32::from_rgb(0x8A, 0x8F, 0x98),
            focus: Color32::from_rgba_premultiplied(0x50, 0x46, 0x10, 0xA0),
            current: Color32::from_rgb(0x2E, 0x44, 0x6E),
            executed: Color32::from_rgba_premultiplied(0x10, 0x3A, 0x18, 0xA0),
            breakpoint: Color32::from_rgb(0x8A, 0x1E, 0x1E),
            comment: Color32::from_rgb(0x9A, 0xC8, 0x8A),
            label: Color32::from_rgb(0xE0, 0x9A, 0x50),
            selection: Color32::from_rgba_premultiplied(0x40, 0x40, 0x48, 0xA0),
        }
    } else {
        Palette {
            red: Color32::from_rgb(0xC0, 0x20, 0x20),
            yellow: Color32::from_rgb(0x9A, 0x60, 0x00),
            green: Color32::from_rgb(0x1E, 0x7A, 0x32),
            blue: Color32::from_rgb(0x1F, 0x5F, 0xBF),
            dim: Color32::from_rgb(0x70, 0x74, 0x7A),
            focus: Color32::from_rgba_premultiplied(0xF0, 0xD8, 0x70, 0x90),
            current: Color32::from_rgb(0x00, 0x00, 0x00),
            executed: Color32::from_rgba_premultiplied(0xC8, 0xEC, 0xC8, 0xC0),
            breakpoint: Color32::from_rgb(0xFF, 0x00, 0x00),
            comment: Color32::from_rgb(0x00, 0x80, 0x00),
            label: Color32::from_rgb(0xFF, 0x00, 0x00),
            selection: Color32::from_rgb(0xC0, 0xC0, 0xC0),
        }
    }
}

pub(crate) fn mono(text: impl Into<String>) -> RichText {
    RichText::new(text).monospace()
}

pub(crate) fn hex(value: u64) -> String {
    format!("{value:016x}")
}

/// Um número em hexadecimal (com ou sem `0x`).
pub(crate) fn parse_hex(text: &str) -> Option<u64> {
    let text = text.trim().trim_start_matches("0x").replace(['`', '_'], "");
    u64::from_str_radix(&text, 16).ok()
}

/// O arquivo de estado da janela.
pub fn state_path() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("opennt-re").join("estado.json"))
}

impl DebuggerApp {
    pub fn new(backend: Backend, launch: Option<LaunchOptions>, connect_address: String) -> DebuggerApp {
        DebuggerApp {
            backend,
            dock: default_layout(),
            state: UiState {
                snapshot: Arc::new(Snapshot::default()),
                status: Status::Idle,
                activity: String::new(),
                can_restart: false,
                transcript: Vec::new(),
                console: LogLines::default(),
                serial: LogLines::default(),
                launch_log: LogLines::default(),
                command: String::new(),
                command_focused: false,
                history: Vec::new(),
                history_index: None,
                completions: Arc::new(Vec::new()),
                type_names: Arc::new(Vec::new()),
                suggestions: Vec::new(),
                selected_code: None,
                breakpoint_expression: String::new(),
                breakpoint_kind: BreakpointKind::Software,
                breakpoint_condition: String::new(),
                breakpoint_pass: String::new(),
                breakpoint_log: String::new(),
                breakpoint_command: String::new(),
                breakpoint_group: String::new(),
                breakpoint_deferred: false,
                breakpoint_edit: None,
                register_edit: None,
                memory_edit: None,
                thread_filter: None,
                connect_address,
                launch,
                scrolled_code: 0,
                scrolled_source: 0,
                scrolled_stack: 0,
                requests: Vec::new(),
                watches: Vec::new(),
                watch_input: String::new(),
                sent_watches: Vec::new(),
                expanded: BTreeSet::new(),
                sent_expanded: BTreeSet::new(),
                query_kind: QueryKind::Process,
                query_argument: String::new(),
                trace: None,
                reference: None,
                trace_generation: 0,
                trace_mode: TraceMode::Count,
                trace_argument: String::new(),
                trace_count: "2000".into(),
                trace_over: false,
                trace_skip: String::new(),
                trace_watch: String::new(),
                trace_qemu_ms: "500".into(),
                trace_filter: String::new(),
                trace_display: TraceDisplay::Table,
                trace_selected: None,
                trace_rows: Vec::new(),
                trace_rows_key: (u64::MAX, String::new()),
                trace_scroll: None,
                trace_tree: None,
                trace_path: "build/opennt-re/rastro.csv".into(),
                reference_path: "build/opennt-re/referencia.csv".into(),
                divergence: None,
                light: true,
                theme_applied: None,
                focus_tab: Vec::new(),
                bugcheck_seen: 0,
                reset_layout: false,
                toggle_tab: None,
                dump_tab: 0,
                dump_inputs: Default::default(),
                dump_formats: [MemoryFormat::HexAscii, MemoryFormat::HexAscii, MemoryFormat::Qwords, MemoryFormat::Address, MemoryFormat::HexUnicode],
                notes: Notes::default(),
                notes_path: None,
                notes_saved: String::new(),
                session_notes: String::new(),
                session_notes_path: None,
                session_notes_saved: String::new(),
                dialog: None,
                dialog_error: None,
                executed: Arc::new(HashSet::new()),
                reference_filter: String::new(),
                reference_regex: false,
                reference_selected: None,
                strings_filter: String::new(),
                strings_selected: None,
                map_filter: String::new(),
                symbols_filter: String::new(),
                symbols_mode: 0,
                script_text: "# roteiro: comandos do depurador, var, if/while/for, log\n# exemplo:\n# var n = 0\n# while n < 3\n#   p\n#   n = n + 1\n# end\n# log \"rip agora: {@rip:s}\"\n".into(),
                script_path: "build/opennt-re/roteiro.txt".into(),
                comments_filter: String::new(),
                graph_zoom: 1.0,
                graph_offset: Vec2::ZERO,
                graph_fit: u64::MAX,
                log_mode: 0,
                user_exceptions: false,
                patch_path: "build/opennt-re/patches.1337".into(),
                handles_filter: String::new(),
                last_message: String::new(),
            },
            persist: None,
            last_saved: String::new(),
            last_save: Instant::now(),
        }
    }

    /// Com arranjo, tema, expressões, histórico e roteiro salvos em `path`.
    pub fn with_persistence(mut self, path: PathBuf) -> DebuggerApp {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(saved) = serde_json::from_str::<Saved>(&text) {
                if let Some(layout) = saved.layout {
                    self.dock = layout;
                }
                self.state.light = saved.light;
                self.state.watches = saved.watches;
                self.state.history = saved.history;
                if !saved.script.is_empty() {
                    self.state.script_text = saved.script;
                }
            }
        }
        self.persist = Some(path);
        self
    }

    /// Os comentários, rótulos e marcadores (`notas.txt`) e as notas livres
    /// (`anotacoes.txt`) desta pasta.
    pub fn with_notes(mut self, directory: PathBuf) -> DebuggerApp {
        let notes = directory.join("notas.txt");
        self.state.notes = Notes::load(&notes).unwrap_or_default();
        self.state.notes_saved = self.state.notes.to_text();
        self.state.notes_path = Some(notes);
        let free = directory.join("anotacoes.txt");
        self.state.session_notes = std::fs::read_to_string(&free).unwrap_or_default();
        self.state.session_notes_saved = self.state.session_notes.clone();
        self.state.session_notes_path = Some(free);
        self
    }

    /// Expressões na janela de observação (a captura de tela e os testes),
    /// já pedidas ao backend por quem chama.
    pub fn set_watches(&mut self, watches: Vec<String>) {
        self.state.sent_watches = watches.clone();
        self.state.watches = watches;
    }

    /// Troca o arranjo das abas.
    pub fn set_layout(&mut self, dock: DockState<Tab>) {
        self.dock = dock;
    }

    /// Mostra uma aba (a captura de tela).
    pub fn focus(&mut self, tab: Tab) {
        self.state.focus_tab.push(tab);
    }

    /// O tema claro (padrão) ou o escuro.
    pub fn set_light(&mut self, light: bool) {
        self.state.light = light;
    }

    /// Seleciona um registro do rastro (a captura de tela).
    pub fn select_trace_record(&mut self, index: usize) {
        self.state.trace_selected = Some(index);
        self.state.trace_scroll = Some(index);
    }

    /// O filtro da aba Referências (a captura de tela).
    pub fn set_reference_filter(&mut self, filter: &str, regex: bool) {
        self.state.reference_filter = filter.to_string();
        self.state.reference_regex = regex;
    }

    /// A linha escolhida na desmontagem (a captura de tela).
    pub fn select_code(&mut self, address: u64) {
        self.state.selected_code = Some(address);
    }

    /// Um comentário e um rótulo (a captura de tela e os testes).
    pub fn annotate(&mut self, address: u64, comment: &str, label: &str) {
        self.sync();
        let location = self.state.location(address);
        if !comment.is_empty() {
            self.state.notes.set_comment(location.clone(), comment);
        }
        if !label.is_empty() {
            self.state.notes.set_label(location, label);
        }
    }

    fn save(&mut self, force: bool) {
        if let Some(path) = self.state.notes_path.clone() {
            let text = self.state.notes.to_text();
            if text != self.state.notes_saved {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if self.state.notes.save(&path).is_ok() {
                    self.state.notes_saved = text;
                }
            }
        }
        if let Some(path) = self.state.session_notes_path.clone() {
            if self.state.session_notes != self.state.session_notes_saved && (force || self.last_save.elapsed() >= Duration::from_secs(3)) {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if std::fs::write(&path, &self.state.session_notes).is_ok() {
                    self.state.session_notes_saved = self.state.session_notes.clone();
                }
            }
        }
        let Some(path) = &self.persist else { return };
        if !force && self.last_save.elapsed() < Duration::from_secs(3) {
            return;
        }
        self.last_save = Instant::now();
        let saved = Saved { layout: Some(self.dock.clone()), light: self.state.light, watches: self.state.watches.clone(), history: self.state.history.iter().rev().take(200).rev().cloned().collect(), script: self.state.script_text.clone() };
        let Ok(text) = serde_json::to_string(&saved) else { return };
        if text == self.last_saved {
            return;
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(path, &text).is_ok() {
            self.last_saved = text;
        }
    }

    /// Copia o que o backend publicou desde o último quadro.
    fn sync(&mut self) {
        let shared = self.backend.shared();
        let state = &mut self.state;
        if !Arc::ptr_eq(&state.snapshot, &shared.snapshot) {
            state.snapshot = Arc::clone(&shared.snapshot);
            for (index, dump) in state.snapshot.dumps.iter().enumerate() {
                if state.dump_inputs[index].is_empty() {
                    state.dump_inputs[index] = dump.expression.clone();
                }
            }
            if !state.snapshot.stop.is_empty() {
                state.last_message = state.snapshot.stop.split(" [").next().unwrap_or("").to_string();
            }
            // Uma parada por bugcheck abre a análise.
            if state.snapshot.bugcheck.is_some() && state.bugcheck_seen != state.snapshot.generation {
                state.bugcheck_seen = state.snapshot.generation;
                state.focus_tab.push(Tab::Bugcheck);
            }
        }
        state.status = shared.status.clone();
        state.activity = shared.activity.clone();
        state.can_restart = shared.can_restart;
        if shared.transcript.len() < state.transcript.len() {
            state.transcript.clear();
        }
        let known = state.transcript.len();
        state.transcript.extend(shared.transcript[known..].iter().cloned());
        if let Some(entry) = shared.transcript.last().filter(|_| known < shared.transcript.len()) {
            let line = entry.output.lines().last().unwrap_or("").trim();
            if !line.is_empty() {
                state.last_message = format!("{}: {line}", entry.input);
            }
        }
        state.console.sync(&shared.console);
        state.serial.sync(&shared.serial);
        state.launch_log.sync(&shared.launch_log);
        if !Arc::ptr_eq(&state.completions, &shared.completions) {
            state.completions = Arc::clone(&shared.completions);
        }
        if !Arc::ptr_eq(&state.type_names, &shared.type_names) {
            state.type_names = Arc::clone(&shared.type_names);
        }
        if state.trace_generation != shared.trace_generation {
            let new_trace = !match (&state.trace, &shared.trace) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            };
            state.trace_generation = shared.trace_generation;
            state.trace = shared.trace.clone();
            state.reference = shared.reference.clone();
            state.divergence = None;
            if new_trace {
                let length = state.trace.as_ref().map_or(0, |trace| trace.trace.len());
                if state.trace_selected.is_some_and(|index| index >= length) {
                    state.trace_selected = None;
                }
                state.trace_tree = None;
                state.executed = Arc::new(state.trace.as_ref().map(|trace| trace.trace.records.iter().map(|record| record.rip).collect()).unwrap_or_default());
                state.focus_tab.push(Tab::Trace);
            }
        }
    }

    /// Um quadro inteiro da janela.
    pub fn show(&mut self, ui: &mut Ui) {
        self.sync();
        if self.state.theme_applied != Some(self.state.light) {
            crate::apply_theme(ui.ctx(), !self.state.light);
            self.state.theme_applied = Some(self.state.light);
        }
        self.shortcuts(ui);
        let state = &mut self.state;
        let dock = &self.dock;
        let open: Vec<Tab> = Tab::ALL.iter().copied().filter(|tab| dock.find_tab(tab).is_some()).collect();
        egui::Panel::top("menu").show(ui, |ui| menu_bar(ui, state, &open));
        egui::Panel::top("toolbar").show(ui, |ui| toolbar(ui, state));
        egui::Panel::bottom("status").show(ui, |ui| status_bar(ui, state));
        egui::Panel::bottom("command").show(ui, |ui| command_bar(ui, state));
        self.layout_requests();
        egui::CentralPanel::no_frame().show(ui, |ui| {
            let mut style = Style::from_egui(ui.style().as_ref());
            style.tab_bar.fill_tab_bar = true;
            DockArea::new(&mut self.dock).style(style).show_close_buttons(false).show_leaf_close_all_buttons(false).show_leaf_collapse_buttons(false).show_inside(ui, &mut Viewer { state: &mut self.state });
        });
        dialogs(ui, &mut self.state);
        // Observação: as expressões e as vistas abertas vão ao backend.
        if self.state.watches != self.state.sent_watches {
            self.state.sent_watches = self.state.watches.clone();
            self.state.requests.push(Request::SetWatches(self.state.watches.clone()));
        }
        if self.state.expanded != self.state.sent_expanded {
            self.state.sent_expanded = self.state.expanded.clone();
            self.state.requests.push(Request::SetExpanded(self.state.expanded.iter().copied().collect()));
        }
        for request in self.state.requests.drain(..) {
            self.backend.send(request);
        }
        self.save(false);
    }

    /// Reabrir, fechar e focar abas; o arranjo padrão.
    fn layout_requests(&mut self) {
        if std::mem::take(&mut self.state.reset_layout) {
            self.dock = default_layout();
        }
        if let Some(tab) = self.state.toggle_tab.take() {
            match self.dock.find_tab(&tab) {
                Some(path) => {
                    self.dock.remove_tab(path);
                }
                None => self.dock.push_to_first_leaf(tab),
            }
        }
        for tab in std::mem::take(&mut self.state.focus_tab) {
            if self.dock.find_tab(&tab).is_none() {
                self.dock.push_to_first_leaf(tab);
            }
            if let Some(path) = self.dock.find_tab(&tab) {
                let _ = self.dock.set_active_tab(path);
                self.dock.set_focused_node_and_surface(NodePath { surface: path.surface, node: path.node });
            }
        }
    }

    /// Os atalhos de teclado (os de um depurador de engenharia reversa).
    fn shortcuts(&mut self, ui: &Ui) {
        let stopped = self.state.status == Status::Stopped;
        let running = self.state.status == Status::Running;
        let pressed = |modifiers: Modifiers, key: Key| ui.input_mut(|input| input.consume_key(modifiers, key));
        let state = &mut self.state;
        if stopped && pressed(Modifiers::CTRL, Key::F9) {
            state.requests.push(Request::StepOut);
        }
        if stopped && pressed(Modifiers::ALT, Key::F9) {
            state.requests.push(Request::RunToUserCode);
        }
        if stopped && pressed(Modifiers::NONE, Key::F9) {
            state.requests.push(Request::Go);
        }
        if stopped && pressed(Modifiers::NONE, Key::F8) {
            state.requests.push(Request::StepOver);
        }
        if stopped && pressed(Modifiers::NONE, Key::F7) {
            state.requests.push(Request::StepInto);
        }
        if running && (pressed(Modifiers::NONE, Key::F12) || pressed(Modifiers::CTRL, Key::B)) {
            state.requests.push(Request::Break);
        }
        if state.can_restart && pressed(Modifiers::CTRL, Key::F2) {
            state.requests.push(Request::Restart);
        }
        if !stopped || state.dialog.is_some() {
            return;
        }
        let target = state.selected_code.or_else(|| current_rip(&state.snapshot));
        if pressed(Modifiers::NONE, Key::F2) {
            if let Some(address) = target {
                state.requests.push(Request::ToggleBreakpoint(address));
            }
        }
        if pressed(Modifiers::NONE, Key::F4) {
            if let Some(address) = state.selected_code {
                state.requests.push(Request::RunToCursor(address));
            }
        }
        if pressed(Modifiers::CTRL, Key::G) {
            state.dialog = Some(Dialog::GoTo(String::new()));
        }
        if pressed(Modifiers::CTRL, Key::B) {
            state.dialog = Some(Dialog::Pattern(String::new(), false));
        }
        // As teclas de uma letra só valem fora dos campos de texto.
        if ui.ctx().egui_wants_keyboard_input() {
            return;
        }
        let typed: Vec<String> = ui.input(|input| input.events.iter().filter_map(|event| if let egui::Event::Text(text) = event { Some(text.clone()) } else { None }).collect());
        for text in typed {
            match text.as_str() {
                ";" => {
                    if let Some(address) = target {
                        let current = state.comment_at(address).cloned().unwrap_or_default();
                        state.dialog = Some(Dialog::Comment(address, current));
                    }
                }
                ":" => {
                    if let Some(address) = target {
                        let current = state.label_at(address).cloned().unwrap_or_default();
                        state.dialog = Some(Dialog::Label(address, current));
                    }
                }
                "*" => {
                    state.selected_code = None;
                    state.requests.push(Request::ShowCode(String::new()));
                    state.requests.push(Request::SelectInstruction(None));
                    state.focus_tab.push(Tab::Cpu);
                }
                "g" | "G" => {
                    let expression = target.map(|address| format!("{address:#x}")).unwrap_or_default();
                    state.requests.push(Request::Graph(expression));
                    state.focus_tab.push(Tab::Graph);
                }
                _ => {}
            }
        }
        if pressed(Modifiers::NONE, Key::Space) {
            if let Some(address) = target {
                state.dialog = Some(Dialog::Assemble(address, String::new()));
            }
        }
    }
}

impl eframe::App for DebuggerApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.save(true);
    }
}

fn menu_bar(ui: &mut Ui, state: &mut UiState, open: &[Tab]) {
    let stopped = state.status == Status::Stopped;
    let running = state.status == Status::Running;
    egui::MenuBar::new().ui(ui, |ui| {
        ui.menu_button("Arquivo", |ui| {
            if let Some(options) = state.launch.clone() {
                if ui.button("Abrir o OpenNT (compilar e iniciar o QEMU)").clicked() {
                    state.requests.push(Request::Start(Target::Launch(options)));
                }
            }
            if ui.add_enabled(state.can_restart, egui::Button::new("Reiniciar").shortcut_text("Ctrl+F2")).clicked() {
                state.requests.push(Request::Restart);
            }
            if ui.button("Desconectar").clicked() {
                state.requests.push(Request::Disconnect);
            }
            ui.separator();
            if ui.add_enabled(stopped, egui::Button::new("Exportar patches")).clicked() {
                state.requests.push(Request::ExportPatches(PathBuf::from(&state.patch_path)));
            }
        });
        ui.menu_button("Exibir", |ui| {
            for tab in Tab::ALL {
                let mut shown = open.contains(&tab);
                if ui.checkbox(&mut shown, tab.title()).changed() {
                    state.toggle_tab = Some(tab);
                }
            }
            ui.separator();
            if ui.button("Restaurar o arranjo padrão").clicked() {
                state.reset_layout = true;
            }
        });
        ui.menu_button("Depurar", |ui| {
            if ui.add_enabled(stopped, egui::Button::new("Executar").shortcut_text("F9")).clicked() {
                state.requests.push(Request::Go);
            }
            if ui.add_enabled(running, egui::Button::new("Pausar").shortcut_text("F12")).clicked() {
                state.requests.push(Request::Break);
            }
            if ui.add_enabled(stopped, egui::Button::new("Entrar").shortcut_text("F7")).clicked() {
                state.requests.push(Request::StepInto);
            }
            if ui.add_enabled(stopped, egui::Button::new("Passar por cima").shortcut_text("F8")).clicked() {
                state.requests.push(Request::StepOver);
            }
            if ui.add_enabled(stopped, egui::Button::new("Executar até o retorno").shortcut_text("Ctrl+F9")).clicked() {
                state.requests.push(Request::StepOut);
            }
            if ui.add_enabled(stopped, egui::Button::new("Executar até o código de usuário").shortcut_text("Alt+F9")).clicked() {
                state.requests.push(Request::RunToUserCode);
            }
            if ui.add_enabled(stopped && state.selected_code.is_some(), egui::Button::new("Executar até o cursor").shortcut_text("F4")).clicked() {
                if let Some(address) = state.selected_code {
                    state.requests.push(Request::RunToCursor(address));
                }
            }
            ui.separator();
            let mut exceptions = state.user_exceptions;
            if ui.add_enabled(stopped, egui::Checkbox::new(&mut exceptions, "Parar nas exceções de primeira chance do modo usuário")).changed() {
                state.user_exceptions = exceptions;
                state.requests.push(Request::SetUserExceptions(exceptions));
            }
            if ui.add_enabled(stopped, egui::Button::new("Analisar bugcheck (!analyze)")).clicked() {
                state.query_kind = QueryKind::Analyze;
                state.requests.push(Request::Query(QueryKind::Analyze, String::new()));
                state.focus_tab.push(Tab::NtObjects);
            }
        });
        ui.menu_button("Procurar", |ui| {
            ui.label(RichText::new("Módulo atual").strong());
            if ui.add_enabled(stopped, egui::Button::new("Referências a strings")).clicked() {
                state.search(SearchKind::StringReferences, false);
            }
            if ui.add_enabled(stopped, egui::Button::new("Chamadas entre módulos")).clicked() {
                state.search(SearchKind::IntermodularCalls, false);
            }
            if ui.add_enabled(stopped, egui::Button::new("Constante...")).clicked() {
                state.dialog = Some(Dialog::Constant(String::new(), false));
            }
            if ui.add_enabled(stopped, egui::Button::new("Padrão...").shortcut_text("Ctrl+B")).clicked() {
                state.dialog = Some(Dialog::Pattern(String::new(), false));
            }
            if ui.add_enabled(stopped, egui::Button::new("Strings soltas")).clicked() {
                state.search(SearchKind::Strings, false);
            }
            ui.separator();
            ui.label(RichText::new("Todos os módulos").strong());
            if ui.add_enabled(stopped, egui::Button::new("Referências a strings (todos)")).clicked() {
                state.search(SearchKind::StringReferences, true);
            }
            if ui.add_enabled(stopped, egui::Button::new("Chamadas entre módulos (todos)")).clicked() {
                state.search(SearchKind::IntermodularCalls, true);
            }
            if ui.add_enabled(stopped, egui::Button::new("Constante (todos)...")).clicked() {
                state.dialog = Some(Dialog::Constant(String::new(), true));
            }
        });
        ui.menu_button("Aparência", |ui| {
            if ui.radio(state.light, "Tema claro").clicked() {
                state.light = true;
            }
            if ui.radio(!state.light, "Tema escuro").clicked() {
                state.light = false;
            }
        });
    });
}

/// Os ícones da barra de ferramentas (desenhados, sem fonte de ícones).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Icon {
    Restart,
    Close,
    Run,
    Pause,
    StepInto,
    StepOver,
    TillReturn,
    UserCode,
    Comments,
    Labels,
    Bookmarks,
    Patches,
    Graph,
    Script,
    Theme,
}

fn icon_button(ui: &mut Ui, icon: Icon, enabled: bool, tooltip: &str) -> bool {
    let colors = palette(ui);
    let (rect, response) = ui.allocate_exact_size(Vec2::new(28.0, 24.0), if enabled { Sense::click() } else { Sense::hover() });
    let painter = ui.painter_at(rect);
    if enabled && response.hovered() {
        painter.rect_filled(rect, 3.0, ui.visuals().widgets.hovered.bg_fill);
    }
    let color = if !enabled {
        colors.dim.gamma_multiply(0.6)
    } else {
        match icon {
            Icon::Run => colors.green,
            Icon::Pause => colors.yellow,
            Icon::Restart | Icon::Graph => colors.blue,
            Icon::Close => colors.red,
            Icon::Comments => colors.comment,
            Icon::Labels => colors.label,
            _ => ui.visuals().text_color(),
        }
    };
    let stroke = Stroke::new(1.8, color);
    let center = rect.center();
    let at = |x: f32, y: f32| Pos2::new(center.x + x, center.y + y);
    let arrow = |painter: &egui::Painter, tip: Pos2, direction: Vec2| {
        let direction = direction.normalized();
        let side = Vec2::new(-direction.y, direction.x);
        painter.add(egui::Shape::convex_polygon(vec![tip, tip - direction * 5.0 + side * 3.5, tip - direction * 5.0 - side * 3.5], color, Stroke::NONE));
    };
    match icon {
        Icon::Restart => {
            let points: Vec<Pos2> = (0..=16).map(|step| {
                let angle = 0.6 + 5.0 * step as f32 / 16.0;
                at(6.5 * angle.cos(), 6.5 * angle.sin())
            }).collect();
            let end = *points.last().unwrap_or(&center);
            painter.add(egui::Shape::line(points, stroke));
            arrow(&painter, end + Vec2::new(2.0, 2.0), Vec2::new(1.0, 1.4));
        }
        Icon::Close => {
            painter.line_segment([at(-5.0, -5.0), at(5.0, 5.0)], stroke);
            painter.line_segment([at(-5.0, 5.0), at(5.0, -5.0)], stroke);
        }
        Icon::Run => {
            painter.add(egui::Shape::convex_polygon(vec![at(-4.0, -7.0), at(7.0, 0.0), at(-4.0, 7.0)], color, Stroke::NONE));
        }
        Icon::Pause => {
            painter.rect_filled(egui::Rect::from_min_size(at(-6.0, -6.5), Vec2::new(4.0, 13.0)), 1.0, color);
            painter.rect_filled(egui::Rect::from_min_size(at(2.0, -6.5), Vec2::new(4.0, 13.0)), 1.0, color);
        }
        Icon::StepInto => {
            painter.line_segment([at(-6.0, -6.0), at(0.0, -6.0)], stroke);
            painter.line_segment([at(0.0, -6.0), at(0.0, 2.0)], stroke);
            arrow(&painter, at(0.0, 6.0), Vec2::new(0.0, 1.0));
        }
        Icon::StepOver => {
            let points: Vec<Pos2> = (0..=12).map(|step| {
                let angle = std::f32::consts::PI * (1.0 + step as f32 / 12.0);
                at(6.5 * angle.cos(), 2.0 + 6.0 * angle.sin())
            }).collect();
            painter.add(egui::Shape::line(points, stroke));
            arrow(&painter, at(6.5, 5.0), Vec2::new(0.0, 1.0));
        }
        Icon::TillReturn => {
            painter.line_segment([at(-6.0, 5.0), at(4.0, 5.0)], stroke);
            painter.line_segment([at(4.0, 5.0), at(4.0, -3.0)], stroke);
            arrow(&painter, at(4.0, -7.0), Vec2::new(0.0, -1.0));
        }
        Icon::UserCode => {
            painter.circle_stroke(at(0.0, -3.0), 3.0, stroke);
            painter.line_segment([at(-5.0, 7.0), at(5.0, 7.0)], stroke);
            painter.line_segment([at(-4.0, 7.0), at(-4.0, 3.0)], stroke);
            painter.line_segment([at(4.0, 7.0), at(4.0, 3.0)], stroke);
        }
        Icon::Comments => {
            painter.text(center, egui::Align2::CENTER_CENTER, ";", egui::FontId::monospace(16.0), color);
        }
        Icon::Labels => {
            painter.text(center, egui::Align2::CENTER_CENTER, ":", egui::FontId::monospace(16.0), color);
        }
        Icon::Bookmarks => {
            painter.add(egui::Shape::convex_polygon(vec![at(-4.0, -7.0), at(4.0, -7.0), at(4.0, 7.0), at(0.0, 3.0), at(-4.0, 7.0)], color, Stroke::NONE));
        }
        Icon::Patches => {
            painter.rect_stroke(egui::Rect::from_center_size(center, Vec2::new(12.0, 12.0)), 1.0, stroke, egui::StrokeKind::Inside);
            painter.text(center, egui::Align2::CENTER_CENTER, "P", egui::FontId::monospace(10.0), color);
        }
        Icon::Graph => {
            for (x, y) in [(0.0, -6.0), (-5.0, 5.0), (5.0, 5.0)] {
                painter.rect_filled(egui::Rect::from_center_size(at(x, y), Vec2::new(5.0, 4.0)), 0.5, color);
            }
            painter.line_segment([at(0.0, -4.0), at(-5.0, 3.0)], stroke);
            painter.line_segment([at(0.0, -4.0), at(5.0, 3.0)], stroke);
        }
        Icon::Script => {
            for index in 0..3 {
                let y = -5.0 + index as f32 * 5.0;
                painter.line_segment([at(-6.0, y), at(6.0 - index as f32 * 3.0, y)], stroke);
            }
        }
        Icon::Theme => {
            painter.circle_stroke(center, 6.0, stroke);
            painter.add(egui::Shape::convex_polygon((0..=12).map(|step| {
                let angle = std::f32::consts::FRAC_PI_2 + std::f32::consts::PI * step as f32 / 12.0;
                at(6.0 * angle.cos(), 6.0 * angle.sin())
            }).collect(), color, Stroke::NONE));
        }
    }
    let response = response.on_hover_text(tooltip);
    enabled && response.clicked()
}

fn toolbar(ui: &mut Ui, state: &mut UiState) {
    let stopped = state.status == Status::Stopped;
    let running = state.status == Status::Running;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 1.0;
        if icon_button(ui, Icon::Restart, state.can_restart, "Reiniciar: fecha o QEMU, recompila e abre de novo (Ctrl+F2)") {
            state.requests.push(Request::Restart);
        }
        if icon_button(ui, Icon::Close, matches!(state.status, Status::Stopped | Status::Running), "Desconectar") {
            state.requests.push(Request::Disconnect);
        }
        ui.separator();
        if icon_button(ui, Icon::Run, stopped, "Executar (F9)") {
            state.requests.push(Request::Go);
        }
        if icon_button(ui, Icon::Pause, running, "Pausar (F12)") {
            state.requests.push(Request::Break);
        }
        ui.separator();
        if icon_button(ui, Icon::StepInto, stopped, "Entrar (F7)") {
            state.requests.push(Request::StepInto);
        }
        if icon_button(ui, Icon::StepOver, stopped, "Passar por cima (F8)") {
            state.requests.push(Request::StepOver);
        }
        if icon_button(ui, Icon::TillReturn, stopped, "Executar até o retorno (Ctrl+F9)") {
            state.requests.push(Request::StepOut);
        }
        if icon_button(ui, Icon::UserCode, stopped, "Executar até o código de usuário (Alt+F9)") {
            state.requests.push(Request::RunToUserCode);
        }
        ui.separator();
        if icon_button(ui, Icon::Comments, true, "Comentários") {
            state.focus_tab.push(Tab::Comments);
        }
        if icon_button(ui, Icon::Labels, true, "Rótulos") {
            state.focus_tab.push(Tab::Comments);
        }
        if icon_button(ui, Icon::Bookmarks, true, "Marcadores") {
            state.focus_tab.push(Tab::Comments);
        }
        if icon_button(ui, Icon::Patches, true, "Patches") {
            state.focus_tab.push(Tab::Patches);
        }
        if icon_button(ui, Icon::Graph, stopped, "Grafo da função (G)") {
            let expression = state.selected_code.map(|address| format!("{address:#x}")).unwrap_or_default();
            state.requests.push(Request::Graph(expression));
            state.focus_tab.push(Tab::Graph);
        }
        if icon_button(ui, Icon::Script, true, "Script") {
            state.focus_tab.push(Tab::Script);
        }
        if icon_button(ui, Icon::Theme, true, "Tema claro ou escuro") {
            state.light = !state.light;
        }
        ui.separator();
        let connected = matches!(state.status, Status::Stopped | Status::Running);
        if !connected && !matches!(state.status, Status::Launching(_) | Status::Connecting(_)) {
            if let Some(options) = state.launch.clone() {
                if ui.button("Abrir o OpenNT").on_hover_text("cargo xtask debug --launch").clicked() {
                    state.requests.push(Request::Start(Target::Launch(options)));
                }
            }
            ui.add(egui::TextEdit::singleline(&mut state.connect_address).desired_width(140.0).font(TextStyle::Monospace));
            if ui.button("Conectar").clicked() {
                state.requests.push(Request::Start(Target::Connect(state.connect_address.trim().to_string())));
            }
        }
        // O contexto: o kernel ou o processo escolhido.
        let snapshot = Arc::clone(&state.snapshot);
        let colors = palette(ui);
        let context = match &snapshot.process {
            Some(process) => format!("processo: {} (PID {})", process.name, process.pid),
            None => "contexto: kernel".to_string(),
        };
        ui.label(RichText::new(context).color(colors.blue).strong());
    });
}

/// A barra de estado: Pausado/Rodando e a última mensagem.
fn status_bar(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    ui.horizontal(|ui| {
        let (fill, text) = match &state.status {
            Status::Stopped => (Color32::from_rgb(0xC0, 0x30, 0x30), "Pausado".to_string()),
            Status::Running => (Color32::from_rgb(0x20, 0x90, 0x40), "Rodando".to_string()),
            Status::Launching(_) => (Color32::from_rgb(0xB0, 0x80, 0x10), "Abrindo".to_string()),
            Status::Connecting(_) => (Color32::from_rgb(0xB0, 0x80, 0x10), "Conectando".to_string()),
            Status::Idle => (Color32::GRAY, "Sem alvo".to_string()),
            Status::Disconnected(_) => (Color32::GRAY, "Desconectado".to_string()),
        };
        let galley = ui.painter().layout_no_wrap(text.clone(), egui::FontId::proportional(13.0), Color32::WHITE);
        let (rect, _) = ui.allocate_exact_size(Vec2::new(galley.size().x + 16.0, 18.0), Sense::hover());
        ui.painter().rect_filled(rect, 2.0, fill);
        ui.painter().galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
        let message = match &state.status {
            Status::Launching(line) => line.clone(),
            Status::Connecting(address) => format!("conectando a {address}"),
            Status::Disconnected(reason) => reason.lines().next().unwrap_or("").to_string(),
            _ => state.last_message.clone(),
        };
        if state.status == Status::Stopped {
            if let Some(processor) = shown_processor(&state.snapshot) {
                ui.label(mono(format!("CPU {} IRQL {} {}", processor.number, processor.irql, processor.process)).color(colors.blue));
                ui.separator();
            }
        }
        ui.label(mono(message).color(colors.dim));
        if !state.activity.is_empty() {
            ui.separator();
            ui.spinner();
            ui.label(RichText::new(&state.activity).color(colors.yellow));
        }
    });
}

/// A barra de comando (os comandos do `cargo xtask debug`); a saída vai
/// para a aba Log.
fn command_bar(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    if state.command_focused && ui.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Tab)) {
        let (start, found) = completions_for(state);
        match found.len() {
            0 => state.suggestions.clear(),
            1 => {
                state.command = format!("{}{}", &state.command[..start], found[0]);
                if !state.command.ends_with('!') {
                    state.command.push(' ');
                }
                state.suggestions.clear();
            }
            _ => {
                let prefix = common_prefix(&found);
                if prefix.len() > state.command.len() - start {
                    state.command = format!("{}{prefix}", &state.command[..start]);
                }
                state.suggestions = found;
            }
        }
        move_cursor_to_end(ui, egui::Id::new("kd-command"), state.command.chars().count());
    }
    if !state.suggestions.is_empty() {
        ui.horizontal_wrapped(|ui| {
            let mut chosen = None;
            for name in state.suggestions.iter().take(24) {
                if ui.selectable_label(false, mono(name)).clicked() {
                    chosen = Some(name.clone());
                }
            }
            if let Some(name) = chosen {
                let (start, _) = completions_for(state);
                state.command = format!("{}{name} ", &state.command[..start]);
                state.suggestions.clear();
            }
        });
    }
    ui.horizontal(|ui| {
        ui.label(mono("Comando:").color(colors.blue));
        let response = ui.add(egui::TextEdit::singleline(&mut state.command).id(egui::Id::new("kd-command")).font(TextStyle::Monospace).desired_width(f32::INFINITY).hint_text("bp, g, p, r, db, k, .process <pid>, sxe ld:csrss!winsrv.dll... (help; Tab completa)"));
        state.command_focused = response.has_focus();
        if response.changed() {
            state.suggestions.clear();
        }
        if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
            let line = std::mem::take(&mut state.command);
            state.suggestions.clear();
            if !line.trim().is_empty() {
                if state.history.last() != Some(&line) {
                    state.history.push(line.clone());
                }
                state.history_index = None;
                state.requests.push(Request::Command(line));
            }
            response.request_focus();
        }
        if response.has_focus() && !state.history.is_empty() {
            let (up, down) = ui.input(|input| (input.key_pressed(Key::ArrowUp), input.key_pressed(Key::ArrowDown)));
            if up || down {
                let last = state.history.len() - 1;
                let index = match (state.history_index, up) {
                    (None, true) => Some(last),
                    (Some(index), true) => Some(index.saturating_sub(1)),
                    (Some(index), false) if index < last => Some(index + 1),
                    _ => None,
                };
                state.history_index = index;
                state.command = index.map(|index| state.history[index].clone()).unwrap_or_default();
                move_cursor_to_end(ui, response.id, state.command.chars().count());
            }
        }
    });
}

/// As caixas de diálogo (ir para, comentário, rótulo, montar, padrão,
/// constante, faixa).
fn dialogs(ui: &mut Ui, state: &mut UiState) {
    let Some(dialog) = state.dialog.clone() else { return };
    let (title, hint_text, address, mut text) = match &dialog {
        Dialog::GoTo(text) => ("Ir para a expressão", "símbolo, endereço, @rax+8, ntdll!LdrLoadDll...", None, text.clone()),
        Dialog::Comment(address, text) => ("Comentário", "texto do comentário (vazio apaga)", Some(*address), text.clone()),
        Dialog::Label(address, text) => ("Rótulo", "nome do rótulo (vazio apaga)", Some(*address), text.clone()),
        Dialog::Assemble(address, text) => ("Montar", "mov eax, 1 | nop | jmp ntdll!NtClose", Some(*address), text.clone()),
        Dialog::Pattern(text, _) => ("Procurar padrão", "48 8B ?? 05 | \"texto\" | u\"texto\"", None, text.clone()),
        Dialog::Constant(text, _) => ("Procurar constante", "expressão (0xC0000005, @rax...)", None, text.clone()),
        Dialog::RangeWatch(start, _, _) => ("Vigiar faixa de memória", "início (expressão)", None, start.clone()),
    };
    let mut open = true;
    let mut submit = false;
    let mut extra_text = match &dialog {
        Dialog::RangeWatch(_, length, _) => length.clone(),
        _ => String::new(),
    };
    let mut flag = match &dialog {
        Dialog::Pattern(_, all) | Dialog::Constant(_, all) => *all,
        Dialog::RangeWatch(_, _, write) => *write,
        _ => false,
    };
    egui::Window::new(title).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_TOP, Vec2::new(0.0, 120.0)).open(&mut open).show(ui.ctx(), |ui| {
        if let Some(address) = address {
            ui.label(mono(format!("{address:#018x}  {}", state.module_at(address).map(|module| module.name.as_str()).unwrap_or(""))));
        }
        let response = ui.add(egui::TextEdit::singleline(&mut text).font(TextStyle::Monospace).desired_width(420.0).hint_text(hint_text));
        response.request_focus();
        if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
            submit = true;
        }
        match &dialog {
            Dialog::Pattern(..) | Dialog::Constant(..) => {
                ui.checkbox(&mut flag, "em todos os módulos");
            }
            Dialog::RangeWatch(..) => {
                ui.horizontal(|ui| {
                    ui.label("tamanho:");
                    ui.add(egui::TextEdit::singleline(&mut extra_text).font(TextStyle::Monospace).desired_width(80.0));
                    ui.checkbox(&mut flag, "só escrita");
                });
            }
            _ => {}
        }
        if let Some(error) = &state.dialog_error {
            ui.label(RichText::new(error).color(Color32::from_rgb(0xC0, 0x20, 0x20)));
        }
        ui.horizontal(|ui| {
            if ui.button("OK").clicked() {
                submit = true;
            }
            if ui.button("Cancelar").clicked() {
                state.dialog = None;
            }
        });
    });
    if !open {
        state.dialog = None;
        state.dialog_error = None;
        return;
    }
    if state.dialog.is_none() {
        state.dialog_error = None;
        return;
    }
    if !submit {
        state.dialog = Some(match dialog {
            Dialog::GoTo(_) => Dialog::GoTo(text),
            Dialog::Comment(address, _) => Dialog::Comment(address, text),
            Dialog::Label(address, _) => Dialog::Label(address, text),
            Dialog::Assemble(address, _) => Dialog::Assemble(address, text),
            Dialog::Pattern(_, _) => Dialog::Pattern(text, flag),
            Dialog::Constant(_, _) => Dialog::Constant(text, flag),
            Dialog::RangeWatch(_, _, _) => Dialog::RangeWatch(text, extra_text, flag),
        });
        return;
    }
    state.dialog_error = None;
    state.dialog = None;
    match dialog {
        Dialog::GoTo(_) => {
            if !text.trim().is_empty() {
                state.requests.push(Request::ShowCode(text.trim().to_string()));
                state.focus_tab.push(Tab::Cpu);
            }
        }
        Dialog::Comment(address, _) => {
            let location = state.location(address);
            state.notes.set_comment(location, text.trim());
        }
        Dialog::Label(address, _) => {
            let location = state.location(address);
            state.notes.set_label(location, text.trim());
        }
        Dialog::Assemble(address, _) => {
            if !text.trim().is_empty() {
                state.requests.push(Request::Assemble { address, text: text.trim().to_string() });
                // A próxima linha fica pronta para outra instrução.
                state.selected_code = Some(address);
            }
        }
        Dialog::Pattern(_, _) => {
            if !text.trim().is_empty() {
                state.search(SearchKind::Pattern(text.trim().to_string()), flag);
            }
        }
        Dialog::Constant(_, _) => {
            if !text.trim().is_empty() {
                state.search(SearchKind::Constant(text.trim().to_string()), flag);
            }
        }
        Dialog::RangeWatch(_, _, _) => {
            let length = parse_hex(&extra_text).unwrap_or(8);
            state.requests.push(Request::AddRangeWatch(if flag { BreakpointKind::Write } else { BreakpointKind::Access }, text.trim().to_string(), length));
        }
    }
}

struct Viewer<'a> {
    state: &'a mut UiState,
}

impl TabViewer for Viewer<'_> {
    type Tab = Tab;

    fn id(&mut self, tab: &mut Tab) -> egui::Id {
        egui::Id::new(("re-tab", *tab))
    }

    fn title(&mut self, tab: &mut Tab) -> WidgetText {
        tab.title().into()
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Tab) {
        let state = &mut *self.state;
        match tab {
            Tab::Cpu => cpu::cpu_tab(ui, state),
            Tab::Graph => graph::graph_tab(ui, state),
            Tab::Log => views::log_tab(ui, state),
            Tab::Notes => views::notes_tab(ui, state),
            Tab::Breakpoints => views::breakpoints_tab(ui, state),
            Tab::MemoryMap => views::memory_map_tab(ui, state),
            Tab::CallStack => views::call_stack_tab(ui, state),
            Tab::Seh => views::seh_tab(ui, state),
            Tab::Script => views::script_tab(ui, state),
            Tab::Symbols => views::symbols_tab(ui, state),
            Tab::Source => panels::source_panel(ui, state),
            Tab::References => views::references_tab(ui, state, false),
            Tab::Strings => views::references_tab(ui, state, true),
            Tab::Threads => views::threads_tab(ui, state),
            Tab::Handles => views::handles_tab(ui, state),
            Tab::Trace => panels::trace_panel(ui, state),
            Tab::Patches => views::patches_tab(ui, state),
            Tab::Comments => views::comments_tab(ui, state),
            Tab::Processes => {
                panels::processes_panel(ui, state);
            }
            Tab::Watch => {
                panels::watch_panel(ui, state);
                ui.separator();
                panels::locals_panel(ui, state);
            }
            Tab::NtObjects => {
                panels::nt_objects_panel(ui, state);
                ui.separator();
                panels::modules_panel(ui, state);
            }
            Tab::Bugcheck => panels::bugcheck_panel(ui, state),
        }
    }

    fn scroll_bars(&self, _tab: &Tab) -> [bool; 2] {
        [false, false]
    }
}

/// Rola só na vertical até a linha (centralizada), com a margem esquerda
/// à vista.
pub(crate) fn scroll_vertically_to(ui: &Ui, rect: egui::Rect) {
    let left = ui.max_rect().left();
    ui.scroll_to_rect(egui::Rect::from_x_y_ranges(left..=left + 1.0, rect.y_range()), Some(egui::Align::Center));
}

pub(crate) fn row_height(ui: &Ui) -> f32 {
    ui.text_style_height(&TextStyle::Monospace) + 3.0
}

pub(crate) fn hint(ui: &mut Ui, text: &str) {
    let colors = palette(ui);
    ui.label(RichText::new(text).color(colors.dim));
}

pub(crate) fn log_panel(ui: &mut Ui, log: &LogLines, id: &str, empty: &str) {
    if log.count() == 0 {
        hint(ui, empty);
        return;
    }
    let height = row_height(ui);
    egui::ScrollArea::both().id_salt(id).auto_shrink([false, false]).stick_to_bottom(true).show_rows(ui, height, log.count(), |ui, range| {
        for index in range {
            ui.label(mono(log.line(index)));
        }
    });
}

/// As sugestões do autocompletar para o texto do prompt: nomes de comando
/// na primeira palavra, tipos depois de `dt` ou de `(_`, símbolos no resto.
fn completions_for(state: &UiState) -> (usize, Vec<String>) {
    let text = &state.command;
    let start = text.rfind(|character: char| character.is_whitespace() || matches!(character, '(' | '*' | '+' | '-' | ',' | '[')).map_or(0, |index| index + 1);
    let word = &text[start..];
    let first = !text[..start].chars().any(|character| !character.is_whitespace());
    if first {
        return (start, Client::command_names().iter().filter(|name| name.starts_with(word)).map(|name| name.to_string()).collect());
    }
    if word.is_empty() {
        return (start, Vec::new());
    }
    let types = text.trim_start().starts_with("dt ") || word.starts_with('_') || word.starts_with("nt!_");
    let source: &[String] = if types { &state.type_names } else { &state.completions };
    let wanted = word.strip_prefix("nt!").filter(|_| types).unwrap_or(word);
    let from = source.partition_point(|name| name.as_str() < wanted);
    let mut found: Vec<String> = source[from..].iter().take_while(|name| name.starts_with(wanted)).take(40).cloned().collect();
    if found.is_empty() && !types {
        let suffix = format!("::{word}");
        found = source.iter().filter(|name| name.contains(&suffix)).take(40).cloned().collect();
    }
    (start, found)
}

fn common_prefix(names: &[String]) -> String {
    let Some(first) = names.first() else { return String::new() };
    let mut length = first.len();
    for name in &names[1..] {
        length = length.min(first.bytes().zip(name.bytes()).take_while(|(a, b)| a == b).count());
    }
    while !first.is_char_boundary(length) {
        length -= 1;
    }
    first[..length].to_string()
}

fn move_cursor_to_end(ui: &Ui, id: egui::Id, length: usize) {
    if let Some(mut text_state) = egui::text_edit::TextEditState::load(ui.ctx(), id) {
        text_state.cursor.set_char_range(Some(egui::text::CCursorRange::one(egui::text::CCursor::new(length))));
        text_state.store(ui.ctx(), id);
    }
}

/// O RIP da visão (o do processador ou da thread escolhida).
pub(crate) fn current_rip(snapshot: &Snapshot) -> Option<u64> {
    snapshot.registers.iter().find(|row| row.name == "rip").and_then(|row| row.value)
}

/// O processador mostrado (o da parada ou o escolhido).
pub(crate) fn shown_processor(snapshot: &Snapshot) -> Option<&kd_client::monitor::Processor> {
    let number = match snapshot.view {
        View::Cpu(thread) => Some(thread.saturating_sub(1)),
        _ => snapshot.stop_processor,
    }?;
    snapshot.processors.iter().find(|processor| processor.number == number)
}
