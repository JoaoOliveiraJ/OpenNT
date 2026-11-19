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
//! nada aqui espera o alvo. O arranjo (abas, tamanho e posição da janela,
//! painéis divisíveis), o tema, as expressões observadas, o histórico de
//! comandos e o roteiro ficam num arquivo de estado (`layout.rs`); os
//! comentários, rótulos e marcadores (por módulo + RVA) e as notas ficam na
//! pasta do build.
//!
//! A navegação (voltar, avançar, Ir para com a busca aproximada, os
//! marcadores) fica em `navigation.rs`, a barra de estado em `status.rs`, o
//! console e o log de eventos em `console.rs` e a cópia das abas como texto
//! em `copy_text.rs`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, Key, Modifiers, Pos2, RichText, Sense, Stroke, TextStyle, Ui, Vec2, WidgetText};
use egui_dock::{DockArea, DockState, NodePath, Style, TabViewer};
use kd_client::analysis::notes::{Location, Notes};
use kd_client::{BreakpointKind, Client};
use serde::{Deserialize, Serialize};

use crate::backend::{Backend, Entry, ExtraRequest, ExtrasView, ModuleRow, QueryKind, Request, SearchKind, SearchQuery, SearchScope, SharedStore, Snapshot, Status, Target, TimeMode, TraceView, View};
use crate::console::{EventLog, Level, RowCache, TranscriptLines};
use crate::launcher::LaunchOptions;
use crate::layout::{PanelSizes, WindowGeometry};
use crate::navigation::{GoToPalette, History, PendingGoTo, SymbolEntry};
use crate::preferences::{Action, ModuleDb, Preferences, PreferencesUi};
use crate::views::FilteredRows;
use crate::{cpu, explorers, graph, monitors, panels, processes, views};

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
    Exception,
    Watch,
    NtObjects,
    Bugcheck,
    ApiMonitor,
    Irps,
    Types,
    Registry,
    Objects,
    Files,
    Snapshots,
}

impl Tab {
    pub const ALL: [Tab; 30] = [
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
        Tab::Exception,
        Tab::Watch,
        Tab::NtObjects,
        Tab::Bugcheck,
        Tab::ApiMonitor,
        Tab::Irps,
        Tab::Types,
        Tab::Registry,
        Tab::Objects,
        Tab::Files,
        Tab::Snapshots,
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
            Tab::Exception => "Exceção",
            Tab::Watch => "Observação",
            Tab::NtObjects => "Objetos do NT",
            Tab::Bugcheck => "Bugcheck",
            Tab::ApiMonitor => "APIs",
            Tab::Irps => "IRPs",
            Tab::Types => "Tipos",
            Tab::Registry => "Registro",
            Tab::Objects => "Objetos",
            Tab::Files => "Arquivos",
            Tab::Snapshots => "Snapshots",
        }
    }
}

/// O arranjo padrão: todas as abas numa fila no alto, a CPU à vista.
pub fn default_layout() -> DockState<Tab> {
    let mut dock = DockState::new(Tab::ALL.to_vec()).with_translations(crate::layout::translations());
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

pub use crate::dump::MemoryFormat;

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
    /// Edição binária: endereço e os bytes em hexadecimal.
    BinaryEdit(u64, String),
    /// Preencher: endereço, tamanho e o byte.
    Fill(u64, String, String),
    /// Gravar uma faixa num arquivo: início, tamanho e o caminho.
    DumpRegion(u64, String, String),
    /// O tipo de um registrador a partir da linha: `rcx _EPROCESS`
    /// (só o registrador tira o tipo).
    RegisterType(u64, String),
}

/// O estado salvo entre execuções. Cada campo tem padrão: um arquivo de
/// outra versão (com campos a menos ou a mais) ainda vale; o arranjo das
/// abas é lido à parte (`layout::restore_layout`).
#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    layout: Option<serde_json::Value>,
    /// As abas que a versão que gravou conhecia.
    known_tabs: Vec<String>,
    light: bool,
    watches: Vec<String>,
    history: Vec<String>,
    script: String,
    window: Option<WindowGeometry>,
    panels: BTreeMap<String, [f32; 2]>,
    console_open: bool,
    console_mode: usize,
    log_mode: usize,
}

impl Default for Saved {
    fn default() -> Self {
        Saved { layout: None, known_tabs: Vec::new(), light: true, watches: Vec::new(), history: Vec::new(), script: String::new(), window: None, panels: BTreeMap::new(), console_open: false, console_mode: 0, log_mode: 0 }
    }
}

/// A posição e o tamanho da janela salvos (o `main` os passa ao
/// `ViewportBuilder` antes de abrir a janela).
pub fn saved_window(path: &Path) -> Option<WindowGeometry> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<Saved>(&text).ok()?.window
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
    // ---- análise, seleção, editor e servidor MCP ----
    /// O fim de uma seleção de várias linhas (Shift+clique).
    pub(crate) selection_end: Option<u64>,
    /// O modo de destaque (H) e a chave do pedaço clicado.
    pub(crate) highlight_mode: bool,
    pub(crate) highlight_key: Option<String>,
    /// A janela de referências cruzadas (X).
    pub(crate) xrefs_open: bool,
    /// O editor de breakpoints aberto e o erro da última conferência.
    pub(crate) breakpoint_form: Option<crate::editor::BreakpointForm>,
    pub(crate) breakpoint_form_error: Option<String>,
    /// Cada Dump segue a expressão a cada parada (senão o endereço fica).
    pub(crate) dump_sync: [bool; 5],
    /// Quantos argumentos a caixa da convenção mostra.
    pub(crate) argument_count: usize,
    pub(crate) sent_argument_count: usize,
    /// A expressão da janela de pilha quando ela não segue o RSP.
    pub(crate) stack_input: String,
    /// XMM em hexadecimal (0), floats (1) ou doubles (2).
    pub(crate) xmm_format: usize,
    /// A linha do mapa de memória a destacar (seguir no mapa).
    pub(crate) map_highlight: Option<u64>,
    pub(crate) mcp_port: String,
    pub(crate) mcp_address: Option<String>,
    pub(crate) dump_path: String,
    // ---- monitor de APIs, IRPs, tipos, exploradores, snapshots ----
    pub(crate) monitor: monitors::MonitorUi,
    pub(crate) explorer: explorers::ExplorerUi,
    /// O depósito do monitor de APIs e dos IRPs (o backend escreve).
    pub(crate) store: SharedStore,
    pub(crate) extras: ExtrasView,
    pub(crate) prefs: Preferences,
    pub(crate) prefs_ui: PreferencesUi,
    /// O banco por módulo: a pasta, o último gravado e os breakpoints dele
    /// já armados nesta sessão.
    pub(crate) db_dir: Option<PathBuf>,
    pub(crate) db_saved: ModuleDb,
    pub(crate) db_loaded: ModuleDb,
    pub(crate) db_armed: HashSet<(String, u64)>,
    // ---- navegação, console, barra de estado ----
    /// O índice de todos os símbolos carregados (a janela Ir para).
    pub(crate) symbol_index: Arc<Vec<SymbolEntry>>,
    /// O histórico de idas da desmontagem (módulo + RVA).
    pub(crate) navigation: History<Location>,
    pub(crate) goto: GoToPalette,
    /// Uma ida por expressão esperando o snapshot com o resultado.
    pub(crate) pending_goto: Option<PendingGoTo>,
    /// O log de eventos da janela.
    pub(crate) events: EventLog,
    /// O transcrito em linhas (a aba Log e o console).
    pub(crate) transcript_lines: TranscriptLines,
    /// O painel do console embaixo: aberto, o modo (comandos ou eventos), o
    /// filtro, até onde cada modo foi limpo e a lista filtrada.
    pub(crate) console_open: bool,
    pub(crate) console_mode: usize,
    pub(crate) console_filter: String,
    pub(crate) console_cleared: [usize; 2],
    pub(crate) console_rows: RowCache,
    /// O foco vai para a barra de comando no próximo quadro.
    pub(crate) focus_command: bool,
    /// Desde quando o estado do alvo e a tarefa do backend são os de agora
    /// (os relógios da barra de estado).
    pub(crate) status_since: Instant,
    pub(crate) activity_since: Instant,
    /// Copiar a aba ativa no próximo quadro (Ctrl+Shift+C).
    pub(crate) copy_active_tab: bool,
    /// As listas filtradas das abas Símbolos e Referências/Strings.
    pub(crate) symbol_rows: FilteredRows,
    pub(crate) reference_rows: [FilteredRows; 2],
    // ---- processos de usuário e exceções ----
    pub(crate) user: processes::UserUi,
}

impl UiState {
    /// A desmontagem da aba CPU num endereço (a ida entra no histórico).
    pub(crate) fn go_to_code(&mut self, address: u64) {
        self.record_visit(Some(address));
        self.show_code_at(address);
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
    /// A última conferência do que mudou (notas, preferências, banco): no
    /// máximo uma por segundo, porque montar os textos para comparar custa.
    last_check: Instant,
    /// A janela e os painéis do último quadro (vão para o arquivo de estado).
    window: Option<WindowGeometry>,
    panels: PanelSizes,
    /// Os tamanhos dos painéis lidos do arquivo, devolvidos ao egui no
    /// primeiro quadro.
    pending_panels: Option<BTreeMap<String, [f32; 2]>>,
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
    let mut colors = theme_palette(ui);
    let swap = |slot: &mut Color32, name: &str| {
        if let Some(color) = crate::preferences::color_override(ui, name) {
            *slot = color;
        }
    };
    swap(&mut colors.red, "red");
    swap(&mut colors.yellow, "yellow");
    swap(&mut colors.green, "green");
    swap(&mut colors.blue, "blue");
    swap(&mut colors.dim, "dim");
    swap(&mut colors.focus, "focus");
    swap(&mut colors.current, "current");
    swap(&mut colors.executed, "executed");
    swap(&mut colors.breakpoint, "breakpoint");
    swap(&mut colors.comment, "comment");
    swap(&mut colors.label, "label");
    swap(&mut colors.selection, "selection");
    colors
}

/// As cores do tema (claro ou escuro).
fn theme_palette(ui: &Ui) -> Palette {
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
        let store = Arc::clone(&backend.store);
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
                selection_end: None,
                highlight_mode: false,
                highlight_key: None,
                xrefs_open: false,
                breakpoint_form: None,
                breakpoint_form_error: None,
                dump_sync: [true; 5],
                argument_count: 5,
                sent_argument_count: 5,
                stack_input: String::new(),
                xmm_format: 0,
                map_highlight: None,
                mcp_port: "7357".into(),
                mcp_address: None,
                dump_path: "build/opennt-re/regiao.bin".into(),
                monitor: monitors::MonitorUi::new(),
                explorer: explorers::ExplorerUi::new(),
                store,
                extras: ExtrasView::default(),
                prefs: Preferences::default(),
                prefs_ui: PreferencesUi::default(),
                db_dir: None,
                db_saved: ModuleDb::default(),
                db_loaded: ModuleDb::default(),
                db_armed: HashSet::new(),
                symbol_index: Arc::new(Vec::new()),
                navigation: History::default(),
                goto: GoToPalette::default(),
                pending_goto: None,
                events: EventLog::default(),
                transcript_lines: TranscriptLines::default(),
                console_open: false,
                console_mode: 0,
                console_filter: String::new(),
                console_cleared: [0; 2],
                console_rows: RowCache::default(),
                focus_command: false,
                status_since: Instant::now(),
                activity_since: Instant::now(),
                copy_active_tab: false,
                symbol_rows: FilteredRows::default(),
                reference_rows: Default::default(),
                user: processes::UserUi::default(),
            },
            persist: None,
            last_saved: String::new(),
            last_save: Instant::now(),
            last_check: Instant::now(),
            window: None,
            panels: Default::default(),
            pending_panels: None,
        }
    }

    /// Com arranjo, tema, expressões, histórico e roteiro salvos em `path`.
    pub fn with_persistence(mut self, path: PathBuf) -> DebuggerApp {
        if let Ok(text) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<Saved>(&text) {
                Ok(saved) => {
                    match crate::layout::restore_layout(saved.layout, &saved.known_tabs) {
                        Some(layout) => self.dock = layout,
                        None => self.state.events.push(Level::Info, "arranjo das abas salvo ausente ou de outra versão: o padrão"),
                    }
                    self.state.light = saved.light;
                    self.state.watches = saved.watches;
                    self.state.history = saved.history;
                    if !saved.script.is_empty() {
                        self.state.script_text = saved.script;
                    }
                    self.window = saved.window;
                    self.pending_panels = Some(saved.panels);
                    self.state.console_open = saved.console_open;
                    self.state.console_mode = saved.console_mode.min(1);
                    self.state.log_mode = saved.log_mode.min(crate::console::EVENTS_MODE);
                }
                Err(error) => self.state.events.push(Level::Warning, format!("{}: {error} (o estado salvo ficou de fora)", path.display())),
            }
        }
        self.persist = Some(path);
        if let Some(path) = crate::preferences::preferences_path() {
            self.state.prefs = Preferences::load(&path);
            self.state.prefs_ui.saved = self.state.prefs.to_text();
        }
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
        // O banco por módulo: as notas dele entram nas da sessão.
        let db_dir = directory.join("db");
        let db = ModuleDb::load(&db_dir);
        let stored = db.notes();
        for (location, text) in stored.comments {
            self.state.notes.comments.entry(location).or_insert(text);
        }
        for (location, text) in stored.labels {
            self.state.notes.labels.entry(location).or_insert(text);
        }
        self.state.notes.bookmarks.extend(stored.bookmarks);
        self.state.db_saved = db.clone();
        self.state.db_loaded = db;
        self.state.db_dir = Some(db_dir);
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

    /// Abre o editor de breakpoints com o formulário (a captura de tela).
    pub fn open_breakpoint_editor(&mut self, form: crate::editor::BreakpointForm) {
        self.state.breakpoint_form = Some(form);
    }

    /// O filtro de driver do monitor de APIs (a captura de tela).
    pub fn set_api_filter(&mut self, driver: &str, export: &str) {
        self.state.monitor.filter.driver = driver.to_string();
        self.state.monitor.filter.export = export.to_string();
        self.state.monitor.follow = false;
    }

    /// Escolhe uma chamada do monitor de APIs (a captura de tela).
    pub fn select_api_row(&mut self, index: usize) {
        self.state.monitor.selected = Some(index);
    }

    /// Escolhe um IRP do rastreador (a captura de tela).
    pub fn select_irp(&mut self, index: usize) {
        self.state.monitor.irp_selected = Some(index);
    }

    /// A aba Tipos num tipo e num endereço, com as chaves abertas (a
    /// captura de tela).
    pub fn view_type(&mut self, type_name: &str, address: u64, expanded: &[&str]) {
        self.state.explorer.type_name = type_name.to_string();
        self.state.explorer.type_address = format!("{address:#x}");
        self.state.explorer.type_expanded = expanded.iter().map(|key| key.to_string()).collect();
        self.state.explorer.type_sent = None;
    }

    /// A aba Registro numa chave, com os ancestrais abertos e já pedidos
    /// (a captura de tela).
    pub fn set_registry_path(&mut self, path: &str) {
        self.state.explorer.registry_path = path.to_string();
        let mut current = String::new();
        for part in path.trim_start_matches('\\').split('\\') {
            current.push('\\');
            current.push_str(part);
            self.state.explorer.registry_open.insert(current.clone());
            self.state.explorer.registry_requested.insert(current.clone());
        }
    }

    /// Liga o modo de destaque com a chave de um pedaço (a captura de tela).
    pub fn highlight(&mut self, key: &str) {
        self.state.highlight_mode = true;
        self.state.highlight_key = Some(key.to_string());
    }

    /// Abre a janela de referências cruzadas (a captura de tela).
    pub fn show_xrefs(&mut self) {
        self.state.xrefs_open = true;
    }

    /// O formato dos XMM (0 hex, 1 float, 2 double).
    pub fn set_xmm_format(&mut self, format: usize) {
        self.state.xmm_format = format;
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

    /// Grava o que mudou: as notas, as notas livres, o banco por módulo, as
    /// preferências e o arquivo de estado. As comparações montam textos
    /// inteiros (as notas, as preferências em JSON, o banco), então rodam no
    /// máximo uma vez por segundo, e não a cada quadro; na saída, sempre.
    fn save(&mut self, force: bool) {
        if !force && self.last_check.elapsed() < Duration::from_secs(1) {
            return;
        }
        self.last_check = Instant::now();
        if let Some(path) = self.state.notes_path.clone() {
            let text = self.state.notes.to_text();
            if text != self.state.notes_saved {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match self.state.notes.save(&path) {
                    Ok(_) => self.state.notes_saved = text,
                    Err(error) => self.save_failed(&path, &error.to_string()),
                }
            }
        }
        if let Some(path) = self.state.session_notes_path.clone() {
            if self.state.session_notes != self.state.session_notes_saved && (force || self.last_save.elapsed() >= Duration::from_secs(3)) {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&path, &self.state.session_notes) {
                    Ok(()) => self.state.session_notes_saved = self.state.session_notes.clone(),
                    Err(error) => self.save_failed(&path, &error.to_string()),
                }
            }
        }
        self.save_module_db();
        if let Some(path) = crate::preferences::preferences_path().filter(|_| self.persist.is_some()) {
            let text = self.state.prefs.to_text();
            if text != self.state.prefs_ui.saved {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&path, &text) {
                    Ok(()) => self.state.prefs_ui.saved = text,
                    Err(error) => self.save_failed(&path, &error.to_string()),
                }
            }
        }
        let Some(path) = self.persist.clone() else { return };
        if !force && self.last_save.elapsed() < Duration::from_secs(3) {
            return;
        }
        self.last_save = Instant::now();
        let saved = Saved {
            layout: serde_json::to_value(&self.dock).ok(),
            known_tabs: crate::layout::known_tabs(),
            light: self.state.light,
            watches: self.state.watches.clone(),
            history: self.state.history.iter().rev().take(200).rev().cloned().collect(),
            script: self.state.script_text.clone(),
            window: self.window,
            panels: crate::layout::panels_map(&self.panels),
            console_open: self.state.console_open,
            console_mode: self.state.console_mode,
            log_mode: self.state.log_mode,
        };
        let Ok(text) = serde_json::to_string(&saved) else { return };
        if text == self.last_saved {
            return;
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(&path, &text) {
            Ok(()) => self.last_saved = text,
            Err(error) => self.save_failed(&path, &error.to_string()),
        }
    }

    /// Uma gravação que falhou vai para o log de eventos (uma vez por
    /// mensagem seguida) e para a barra de estado.
    fn save_failed(&mut self, path: &Path, error: &str) {
        let message = format!("não gravou {}: {error}", path.display());
        self.state.last_message = message.clone();
        self.state.events.push(Level::Warning, message);
    }

    /// Grava o banco por módulo quando as notas ou os breakpoints mudam, e
    /// arma os breakpoints guardados dos módulos que já carregaram.
    fn save_module_db(&mut self) {
        let Some(directory) = self.state.db_dir.clone() else { return };
        let state = &self.state;
        let mut db = ModuleDb::from_session(&state.notes, &state.snapshot.breakpoints, &|address| state.location(address));
        // Os breakpoints guardados de módulos que ainda não carregaram ficam.
        let loaded: HashSet<String> = state.snapshot.modules.iter().map(|module| if module.source == "ELF do kernel" { "kernel".to_string() } else { module.name.to_ascii_lowercase() }).collect();
        let mut pending = ModuleDb::default();
        for (module, record) in &state.db_loaded.modules {
            if !loaded.contains(module) {
                pending.modules.insert(module.clone(), crate::preferences::ModuleRecord { breakpoints: record.breakpoints.clone(), ..Default::default() });
            }
        }
        db.merge_breakpoints_from(&pending);
        if db != self.state.db_saved && db.save(&directory, &self.state.db_saved).is_ok() {
            self.state.db_saved = db;
        }
    }

    /// Os breakpoints do banco por módulo dos módulos que já estão na
    /// lista (uma vez por sessão), e as paradas em eventos das
    /// preferências (na primeira parada e quando mudam).
    fn apply_session_settings(&mut self) {
        let state = &mut self.state;
        if matches!(state.status, Status::Launching(_) | Status::Connecting(_) | Status::Disconnected(_)) {
            // Uma sessão nova recebe tudo de novo.
            state.prefs_ui.events_sent = None;
            state.db_armed.clear();
            return;
        }
        if state.status != Status::Stopped || state.snapshot.modules.is_empty() {
            return;
        }
        let generation = state.snapshot.generation;
        let events = state.prefs.events.clone();
        let changed = state.prefs_ui.events_sent.as_ref().is_none_or(|(sent, _)| *sent != events);
        if changed && !matches!(state.extras.mode, TimeMode::Replay(..)) {
            let previous = state.prefs_ui.events_sent.as_ref().map(|(sent, _)| sent.clone()).unwrap_or_default();
            for command in events.changes(&previous) {
                state.requests.push(Request::Command(command));
            }
            state.prefs_ui.events_sent = Some((events, generation));
        }
        let mut wanted = Vec::new();
        for module in &state.snapshot.modules {
            let name = if module.source == "ELF do kernel" { "kernel".to_string() } else { module.name.to_ascii_lowercase() };
            let Some(record) = state.db_loaded.modules.get(&name) else { continue };
            for stored in &record.breakpoints {
                let address = module.base + stored.rva;
                if state.db_armed.insert((name.clone(), stored.rva)) && !state.snapshot.breakpoints.iter().any(|breakpoint| breakpoint.address == address) {
                    if let Some(request) = stored.request(address) {
                        wanted.push(request);
                    }
                }
            }
        }
        for request in wanted {
            state.requests.push(Request::AddBreakpointWith(request));
        }
    }

    /// Copia o que o backend publicou desde o último quadro.
    fn sync(&mut self) {
        let shared = self.backend.shared();
        let state = &mut self.state;
        let before = crate::console::Before::of(state);
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
        state.extras = shared.extras.clone();
        state.mcp_address = shared.mcp.clone();
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
        if !Arc::ptr_eq(&state.symbol_index, &shared.symbol_index) {
            state.symbol_index = Arc::clone(&shared.symbol_index);
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
        drop(shared);
        state.transcript_lines.sync(&state.transcript);
        crate::navigation::resolve_pending_goto(state);
        crate::console::observe(state, before);
        // Uma sessão nova: os lugares da anterior podem não existir mais,
        // mas ficam (módulo + RVA); só a ida pendente cai.
        if matches!(state.status, Status::Launching(_) | Status::Connecting(_)) {
            state.pending_goto = None;
        }
    }

    /// Um quadro inteiro da janela.
    pub fn show(&mut self, ui: &mut Ui) {
        self.sync();
        // Os tamanhos dos painéis salvos, antes de os painéis aparecerem.
        if let Some(sizes) = self.pending_panels.take() {
            crate::layout::restore_panels(ui.ctx(), &sizes);
        }
        // Texto que o backend pôs para a área de transferência.
        let clipboard = self.backend.shared.lock().ok().and_then(|mut shared| shared.clipboard.take());
        if let Some(text) = clipboard {
            ui.ctx().copy_text(text.clone());
            self.state.last_message = format!("copiado: {text}");
            self.state.events.push(Level::Info, self.state.last_message.clone());
        }
        if self.state.theme_applied != Some(self.state.light) {
            crate::apply_theme(ui.ctx(), !self.state.light);
            self.state.theme_applied = Some(self.state.light);
            self.state.prefs_ui.applied = None;
        }
        if self.state.prefs_ui.applied.as_ref() != Some(&self.state.prefs) {
            self.state.prefs.apply(ui.ctx(), self.state.prefs_ui.applied.as_ref());
            self.state.prefs_ui.applied = Some(self.state.prefs.clone());
        }
        self.apply_session_settings();
        processes::frame(&mut self.state);
        self.shortcuts(ui);
        // Ctrl+Shift+C: a aba da área com o foco (senão, a CPU).
        if std::mem::take(&mut self.state.copy_active_tab) {
            let tab = self.dock.find_active_focused().map(|(_, tab)| *tab).unwrap_or(Tab::Cpu);
            crate::copy_text::copy_tab(ui.ctx(), &mut self.state, tab);
        }
        let state = &mut self.state;
        let dock = &self.dock;
        let open: Vec<Tab> = Tab::ALL.iter().copied().filter(|tab| dock.find_tab(tab).is_some()).collect();
        egui::Panel::top("menu").show(ui, |ui| menu_bar(ui, state, &open));
        egui::Panel::top("toolbar").show(ui, |ui| toolbar(ui, state));
        egui::Panel::bottom("status").show(ui, |ui| crate::status::status_bar(ui, state));
        egui::Panel::bottom("command").show(ui, |ui| command_bar(ui, state));
        if state.console_open {
            egui::Panel::bottom("re-console").resizable(true).default_size(200.0).min_size(60.0).show(ui, |ui| crate::console::console_panel(ui, state));
        }
        self.layout_requests();
        egui::CentralPanel::no_frame().show(ui, |ui| {
            let mut style = Style::from_egui(ui.style().as_ref());
            style.tab_bar.fill_tab_bar = true;
            DockArea::new(&mut self.dock).style(style).show_close_buttons(false).show_leaf_close_all_buttons(false).show_leaf_collapse_buttons(false).show_inside(ui, &mut Viewer { state: &mut self.state });
        });
        dialogs(ui, &mut self.state);
        crate::preferences::preferences_window(ui.ctx(), &mut self.state.prefs, &mut self.state.prefs_ui);
        crate::preferences::shortcuts_window(ui.ctx(), &self.state.prefs, &mut self.state.prefs_ui);
        crate::cpu::breakpoint_editor(ui, &mut self.state);
        crate::cpu::xrefs_window(ui, &mut self.state);
        // A janela e os painéis de agora (o arquivo de estado os guarda).
        if self.persist.is_some() {
            if let Some(current) = WindowGeometry::current(ui.ctx()) {
                self.window = Some(current.merged(self.window));
            }
            self.panels = crate::layout::capture_panels(ui.ctx());
        }
        if self.state.argument_count != self.state.sent_argument_count {
            self.state.sent_argument_count = self.state.argument_count;
            self.state.requests.push(Request::SetArgumentCount(self.state.argument_count));
        }
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
        if self.state.prefs_ui.capturing.is_some() {
            // O editor de atalhos espera a tecla nova.
            return;
        }
        let state = &mut self.state;
        // As teclas vêm das preferências (o editor de atalhos); as com mais
        // modificadores são conferidas antes.
        let prefs = state.prefs.clone();
        let mut order: Vec<Action> = Action::ALL.to_vec();
        order.sort_by_key(|action| {
            let binding = prefs.binding(*action);
            std::cmp::Reverse(binding.ctrl as u8 + binding.shift as u8 + binding.alt as u8)
        });
        let replay = matches!(state.extras.mode, TimeMode::Replay(_, true));
        let target = state.selected_code.or_else(|| current_rip(&state.snapshot));
        for action in order {
            let wanted = match action {
                Action::Break => running,
                Action::Restart => state.can_restart,
                Action::ReverseStep | Action::ReverseContinue => stopped && replay,
                // As da janela valem sempre.
                Action::CopyView | Action::ToggleConsole | Action::ShowShortcuts => true,
                // O marcador é uma nota: vale com a máquina rodando.
                Action::ToggleBookmark => state.dialog.is_none(),
                _ => stopped && state.dialog.is_none(),
            };
            if !wanted || !prefs.pressed(ui, action) {
                continue;
            }
            match action {
                Action::Go => state.requests.push(Request::Go),
                Action::StepInto => state.requests.push(Request::StepInto),
                Action::StepOver => state.requests.push(Request::StepOver),
                Action::StepOut => state.requests.push(Request::StepOut),
                Action::RunToUserCode => state.requests.push(Request::RunToUserCode),
                Action::Break => state.requests.push(Request::Break),
                Action::Restart => state.requests.push(Request::Restart),
                Action::ToggleBreakpoint => {
                    if let Some(address) = target {
                        state.requests.push(Request::ToggleBreakpoint(address));
                    }
                }
                Action::RunToCursor => {
                    if let Some(address) = state.selected_code {
                        state.requests.push(Request::RunToCursor(address));
                    }
                }
                Action::GoTo => state.dialog = Some(Dialog::GoTo(String::new())),
                Action::Pattern => state.dialog = Some(Dialog::Pattern(String::new(), false)),
                Action::Xrefs => {
                    if let Some(address) = target {
                        state.requests.push(Request::Xrefs(address));
                        state.xrefs_open = true;
                    }
                }
                Action::NewOrigin => {
                    if let Some(address) = state.selected_code {
                        state.requests.push(Request::WriteRegister("rip".into(), address));
                    }
                }
                Action::ReverseStep => state.requests.push(Request::Extra(ExtraRequest::ReverseStep)),
                Action::ReverseContinue => state.requests.push(Request::Extra(ExtraRequest::ReverseContinue)),
                Action::SaveSnapshot => {
                    let name = state.explorer.snapshot_name.trim().to_string();
                    state.requests.push(Request::Extra(ExtraRequest::SnapshotSave(name)));
                    state.focus_tab.push(Tab::Snapshots);
                }
                Action::ViewAsType => {
                    let index = state.dump_tab.min(4);
                    if let Some(dump) = state.snapshot.dumps.get(index) {
                        let address = dump.address;
                        explorers::view_as_type(state, "", address);
                    }
                }
                Action::NavigateBack => {
                    state.navigate_back();
                }
                Action::NavigateForward => {
                    state.navigate_forward();
                }
                Action::ToggleBookmark => {
                    if let Some(address) = target {
                        state.toggle_bookmark_at(address);
                    }
                }
                Action::NextBookmark => state.jump_to_bookmark(true),
                Action::PreviousBookmark => state.jump_to_bookmark(false),
                Action::CopyView => state.copy_active_tab = true,
                Action::ToggleConsole => {
                    state.console_open = !state.console_open;
                    state.focus_command = state.console_open;
                }
                Action::ShowShortcuts => state.prefs_ui.shortcuts_open = !state.prefs_ui.shortcuts_open,
            }
        }
        // Ctrl+B com a máquina rodando também pausa.
        if running && pressed(Modifiers::CTRL, Key::B) {
            state.requests.push(Request::Break);
        }
        if !stopped || state.dialog.is_some() {
            return;
        }
        // Os botões laterais do mouse andam no histórico.
        let (mouse_back, mouse_forward) = ui.input(|input| (input.pointer.button_pressed(egui::PointerButton::Extra1), input.pointer.button_pressed(egui::PointerButton::Extra2)));
        if mouse_back {
            state.navigate_back();
        }
        if mouse_forward {
            state.navigate_forward();
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
                    state.record_visit(None);
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
                "x" | "X" => {
                    if let Some(address) = target {
                        state.requests.push(Request::Xrefs(address));
                        state.xrefs_open = true;
                    }
                }
                "h" | "H" => {
                    state.highlight_mode = !state.highlight_mode;
                    if !state.highlight_mode {
                        state.highlight_key = None;
                    }
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
            if ui.add_enabled(state.can_restart, egui::Button::new("Reiniciar").shortcut_text(key(state, Action::Restart))).clicked() {
                state.requests.push(Request::Restart);
            }
            if ui.button("Desconectar").clicked() {
                state.requests.push(Request::Disconnect);
            }
            if let Some(options) = state.launch.clone() {
                ui.separator();
                let with = |extra: &str| {
                    let mut options = options.clone();
                    options.extra.retain(|argument| argument != "--vm-snapshots" && !argument.starts_with("--record=") && !argument.starts_with("--replay="));
                    if !extra.is_empty() {
                        options.extra.push(extra.to_string());
                    }
                    options
                };
                let recording = format!("--record={}", options.build_dir.join("gravacao.bin").display());
                let replay = format!("--replay={}", options.build_dir.join("gravacao.bin").display());
                if ui.button("Abrir com snapshots (discos em qcow2)").on_hover_text("--vm-snapshots: savevm/loadvm na aba Snapshots").clicked() {
                    state.requests.push(Request::Start(Target::Launch(with("--vm-snapshots"))));
                    state.launch = Some(with("--vm-snapshots"));
                }
                if ui.button("Gravar a execução (TCG)").on_hover_text(&recording).clicked() {
                    state.requests.push(Request::Start(Target::Launch(with(&recording))));
                    state.launch = Some(with(&recording));
                }
                if ui.button("Reproduzir a gravação (voltar no tempo)").on_hover_text(&replay).clicked() {
                    state.requests.push(Request::Start(Target::Launch(with(&replay))));
                    state.launch = Some(with(&replay));
                }
                if ui.button("Abrir sem snapshots nem gravação").clicked() {
                    state.requests.push(Request::Start(Target::Launch(with(""))));
                    state.launch = Some(with(""));
                }
            }
            ui.separator();
            if ui.add_enabled(stopped, egui::Button::new("Exportar patches")).clicked() {
                state.requests.push(Request::ExportPatches(PathBuf::from(&state.patch_path)));
            }
            ui.separator();
            let mut serving = state.mcp_address.is_some();
            ui.horizontal(|ui| {
                if ui.checkbox(&mut serving, "Servidor MCP em 127.0.0.1:").on_hover_text("a IA e você na mesma sessão: o mesmo servidor do opennt-mcp, por HTTP local em /mcp").changed() {
                    state.requests.push(Request::SetMcp(if serving { state.mcp_port.trim().parse().ok() } else { None }));
                }
                ui.add_enabled(!serving, egui::TextEdit::singleline(&mut state.mcp_port).desired_width(50.0));
            });
        });
        ui.menu_button("Exibir", |ui| {
            for tab in Tab::ALL {
                let mut shown = open.contains(&tab);
                if ui.checkbox(&mut shown, tab.title()).changed() {
                    state.toggle_tab = Some(tab);
                }
            }
            ui.separator();
            let mut console = state.console_open;
            if ui.add(egui::Checkbox::new(&mut console, format!("Console embaixo ({})", key(state, Action::ToggleConsole)))).changed() {
                state.console_open = console;
                state.focus_command = console;
            }
            if ui.add(egui::Button::new("Copiar a aba ativa como texto").shortcut_text(key(state, Action::CopyView))).on_hover_text("o botão direito no título de qualquer aba também copia").clicked() {
                state.copy_active_tab = true;
                ui.close();
            }
            ui.separator();
            if ui.button("Restaurar o arranjo padrão").clicked() {
                state.reset_layout = true;
            }
        });
        ui.menu_button("Navegar", |ui| crate::navigation::navigate_menu(ui, state));
        ui.menu_button("Depurar", |ui| {
            if ui.add_enabled(stopped, egui::Button::new("Executar").shortcut_text(key(state, Action::Go))).clicked() {
                state.requests.push(Request::Go);
            }
            if ui.add_enabled(running, egui::Button::new("Pausar").shortcut_text(key(state, Action::Break))).clicked() {
                state.requests.push(Request::Break);
            }
            if ui.add_enabled(stopped, egui::Button::new("Entrar").shortcut_text(key(state, Action::StepInto))).clicked() {
                state.requests.push(Request::StepInto);
            }
            if ui.add_enabled(stopped, egui::Button::new("Passar por cima").shortcut_text(key(state, Action::StepOver))).clicked() {
                state.requests.push(Request::StepOver);
            }
            if ui.add_enabled(stopped, egui::Button::new("Executar até o retorno").shortcut_text(key(state, Action::StepOut))).clicked() {
                state.requests.push(Request::StepOut);
            }
            if ui.add_enabled(stopped, egui::Button::new("Executar até o código de usuário").shortcut_text(key(state, Action::RunToUserCode))).clicked() {
                state.requests.push(Request::RunToUserCode);
            }
            if ui.add_enabled(stopped && state.selected_code.is_some(), egui::Button::new("Executar até o cursor").shortcut_text(key(state, Action::RunToCursor))).clicked() {
                if let Some(address) = state.selected_code {
                    state.requests.push(Request::RunToCursor(address));
                }
            }
            ui.separator();
            let target = state.selected_code.or_else(|| current_rip(&state.snapshot));
            if ui.add_enabled(stopped && target.is_some(), egui::Button::new("Ligar/tirar breakpoint na linha").shortcut_text(key(state, Action::ToggleBreakpoint))).on_hover_text("a linha escolhida na desmontagem, ou a do RIP").clicked() {
                if let Some(address) = target {
                    state.requests.push(Request::ToggleBreakpoint(address));
                }
            }
            if ui.add_enabled(stopped, egui::Button::new("Novo breakpoint...")).clicked() {
                let address = state.selected_code.or_else(|| current_rip(&state.snapshot)).map(|address| format!("{address:#x}")).unwrap_or_default();
                state.breakpoint_form = Some(crate::editor::BreakpointForm::new(BreakpointKind::Software, &address));
            }
            ui.separator();
            let mut exceptions = state.user_exceptions;
            if ui.add_enabled(stopped, egui::Checkbox::new(&mut exceptions, "Parar nas exceções de primeira chance do modo usuário")).changed() {
                state.user_exceptions = exceptions;
                state.requests.push(Request::SetUserExceptions(exceptions));
            }
            let replay = matches!(state.extras.mode, TimeMode::Replay(_, true));
            if ui.add_enabled(stopped && replay, egui::Button::new("Voltar um passo").shortcut_text(state.prefs.binding(Action::ReverseStep).text())).clicked() {
                state.requests.push(Request::Extra(ExtraRequest::ReverseStep));
            }
            if ui.add_enabled(stopped && replay, egui::Button::new("Voltar até o breakpoint").shortcut_text(state.prefs.binding(Action::ReverseContinue).text())).clicked() {
                state.requests.push(Request::Extra(ExtraRequest::ReverseContinue));
            }
            ui.separator();
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
            if ui.add_enabled(stopped, egui::Button::new("Padrão...").shortcut_text(key(state, Action::Pattern))).clicked() {
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
            ui.separator();
            if ui.button("Preferências...").clicked() {
                state.prefs_ui.open = true;
            }
        });
        ui.menu_button("Ajuda", |ui| {
            if ui.add(egui::Button::new("Atalhos de teclado").shortcut_text(key(state, Action::ShowShortcuts))).clicked() {
                state.prefs_ui.shortcuts_open = true;
                ui.close();
            }
            if ui.button("Trocar as teclas...").clicked() {
                state.prefs_ui.open = true;
                state.prefs_ui.tab = 1;
                ui.close();
            }
            if ui.button("Log de eventos da janela").clicked() {
                state.log_mode = crate::console::EVENTS_MODE;
                state.focus_tab.push(Tab::Log);
                ui.close();
            }
        });
    });
}

/// A tecla de uma ação (a das preferências), para os menus e as dicas.
fn key(state: &UiState, action: Action) -> String {
    state.prefs.binding(action).text()
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
    Back,
    Forward,
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
        Icon::Back => {
            painter.line_segment([at(7.0, 0.0), at(-3.0, 0.0)], stroke);
            arrow(&painter, at(-7.0, 0.0), Vec2::new(-1.0, 0.0));
        }
        Icon::Forward => {
            painter.line_segment([at(-7.0, 0.0), at(3.0, 0.0)], stroke);
            arrow(&painter, at(7.0, 0.0), Vec2::new(1.0, 0.0));
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
        if icon_button(ui, Icon::Restart, state.can_restart, &format!("Reiniciar: fecha o QEMU, recompila e abre de novo ({})", key(state, Action::Restart))) {
            state.requests.push(Request::Restart);
        }
        if icon_button(ui, Icon::Close, matches!(state.status, Status::Stopped | Status::Running), "Desconectar") {
            state.requests.push(Request::Disconnect);
        }
        ui.separator();
        if icon_button(ui, Icon::Run, stopped, &format!("Executar ({})", key(state, Action::Go))) {
            state.requests.push(Request::Go);
        }
        if icon_button(ui, Icon::Pause, running, &format!("Pausar ({})", key(state, Action::Break))) {
            state.requests.push(Request::Break);
        }
        ui.separator();
        if icon_button(ui, Icon::StepInto, stopped, &format!("Entrar ({})", key(state, Action::StepInto))) {
            state.requests.push(Request::StepInto);
        }
        if icon_button(ui, Icon::StepOver, stopped, &format!("Passar por cima ({})", key(state, Action::StepOver))) {
            state.requests.push(Request::StepOver);
        }
        if icon_button(ui, Icon::TillReturn, stopped, &format!("Executar até o retorno ({})", key(state, Action::StepOut))) {
            state.requests.push(Request::StepOut);
        }
        if icon_button(ui, Icon::UserCode, stopped, &format!("Executar até o código de usuário ({})", key(state, Action::RunToUserCode))) {
            state.requests.push(Request::RunToUserCode);
        }
        ui.separator();
        // O histórico de idas da desmontagem.
        let back = state.navigation.peek_back().map(Location::display);
        let forward = state.navigation.peek_forward().map(Location::display);
        let back_tip = format!("Voltar ({}){}", key(state, Action::NavigateBack), back.as_ref().map(|place| format!(" para {place}")).unwrap_or_default());
        let forward_tip = format!("Avançar ({}){}", key(state, Action::NavigateForward), forward.as_ref().map(|place| format!(" para {place}")).unwrap_or_default());
        if icon_button(ui, Icon::Back, stopped && back.is_some(), &back_tip) {
            state.navigate_back();
        }
        if icon_button(ui, Icon::Forward, stopped && forward.is_some(), &forward_tip) {
            state.navigate_forward();
        }
        if matches!(state.extras.mode, TimeMode::Replay(..)) {
            let reverse = stopped && matches!(state.extras.mode, TimeMode::Replay(_, true));
            ui.separator();
            if ui.add_enabled(reverse, egui::Button::new("⟲").small()).on_hover_text(format!("Voltar um passo ({})", state.prefs.binding(Action::ReverseStep).text())).clicked() {
                state.requests.push(Request::Extra(ExtraRequest::ReverseStep));
            }
            if ui.add_enabled(reverse, egui::Button::new("⏪").small()).on_hover_text(format!("Voltar até o breakpoint ({})", state.prefs.binding(Action::ReverseContinue).text())).clicked() {
                state.requests.push(Request::Extra(ExtraRequest::ReverseContinue));
            }
        }
        ui.separator();
        if icon_button(ui, Icon::Comments, true, "Comentários") {
            state.focus_tab.push(Tab::Comments);
        }
        if icon_button(ui, Icon::Labels, true, "Rótulos") {
            state.focus_tab.push(Tab::Comments);
        }
        if icon_button(ui, Icon::Bookmarks, true, &format!("Marcadores: o próximo ({}), ligar na linha ({}); a lista no menu Navegar", key(state, Action::NextBookmark), key(state, Action::ToggleBookmark))) {
            if stopped && !state.notes.bookmarks.is_empty() {
                state.jump_to_bookmark(true);
            } else {
                state.focus_tab.push(Tab::Comments);
            }
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
        let console_key = key(state, Action::ToggleConsole);
        if ui.selectable_label(state.console_open, "Console").on_hover_text(format!("a saída dos comandos e os eventos num painel aqui em cima ({console_key})")).clicked() {
            state.console_open = !state.console_open;
            state.focus_command = state.console_open;
        }
        ui.label(mono("Comando:").color(colors.blue));
        let response = ui.add(egui::TextEdit::singleline(&mut state.command).id(egui::Id::new("kd-command")).font(TextStyle::Monospace).desired_width(f32::INFINITY).hint_text("bp, g, p, r, db, k, .process <pid>, sxe ld:csrss!winsrv.dll... (help; Tab completa)"));
        if std::mem::take(&mut state.focus_command) {
            response.request_focus();
        }
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
/// constante, faixa). O Ir para é a janela com a busca aproximada
/// (`navigation::goto_window`).
fn dialogs(ui: &mut Ui, state: &mut UiState) {
    let Some(dialog) = state.dialog.clone() else { return };
    if let Dialog::GoTo(initial) = &dialog {
        if !crate::navigation::goto_window(ui, state, initial) {
            state.dialog = None;
            state.dialog_error = None;
        }
        return;
    }
    let (title, hint_text, address, mut text) = match &dialog {
        Dialog::GoTo(text) => ("Ir para a expressão", "símbolo, endereço, @rax+8, ntdll!LdrLoadDll...", None, text.clone()),
        Dialog::Comment(address, text) => ("Comentário", "texto do comentário (vazio apaga)", Some(*address), text.clone()),
        Dialog::Label(address, text) => ("Rótulo", "nome do rótulo (vazio apaga)", Some(*address), text.clone()),
        Dialog::Assemble(address, text) => ("Montar", "mov eax, 1 | nop | jmp ntdll!NtClose", Some(*address), text.clone()),
        Dialog::Pattern(text, _) => ("Procurar padrão", "48 8B ?? 05 | \"texto\" | u\"texto\"", None, text.clone()),
        Dialog::Constant(text, _) => ("Procurar constante", "expressão (0xC0000005, @rax...)", None, text.clone()),
        Dialog::RangeWatch(start, _, _) => ("Vigiar faixa de memória", "início (expressão)", None, start.clone()),
        Dialog::BinaryEdit(address, text) => ("Edição binária", "bytes em hexadecimal: 90 90 cc", Some(*address), text.clone()),
        Dialog::Fill(address, _, byte) => ("Preencher", "o byte (hexadecimal): 90", Some(*address), byte.clone()),
        Dialog::DumpRegion(address, _, path) => ("Gravar a região num arquivo", "caminho do arquivo", Some(*address), path.clone()),
        Dialog::RegisterType(address, text) => ("Tipo de um registrador", "rcx _EPROCESS | rdx nt!_IRP | rbx win32kbase!tagWND | rcx (tira)", Some(*address), text.clone()),
    };
    let mut open = true;
    let mut submit = false;
    let mut extra_text = match &dialog {
        Dialog::RangeWatch(_, length, _) | Dialog::Fill(_, length, _) | Dialog::DumpRegion(_, length, _) => length.clone(),
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
            Dialog::Fill(..) | Dialog::DumpRegion(..) => {
                ui.horizontal(|ui| {
                    ui.label("tamanho (hexadecimal):");
                    ui.add(egui::TextEdit::singleline(&mut extra_text).font(TextStyle::Monospace).desired_width(100.0));
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
            Dialog::BinaryEdit(address, _) => Dialog::BinaryEdit(address, text),
            Dialog::Fill(address, _, _) => Dialog::Fill(address, extra_text, text),
            Dialog::DumpRegion(address, _, _) => Dialog::DumpRegion(address, extra_text, text),
            Dialog::RegisterType(address, _) => Dialog::RegisterType(address, text),
        });
        return;
    }
    state.dialog_error = None;
    state.dialog = None;
    match dialog {
        Dialog::GoTo(_) => state.go_to_expression(&text),
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
        Dialog::BinaryEdit(address, _) => match crate::backend::parse_pattern(&text) {
            Ok(bytes) if !bytes.is_empty() => state.requests.push(Request::Patch { address, bytes }),
            _ => state.last_message = "edição binária: bytes em hexadecimal".into(),
        },
        Dialog::Fill(address, _, _) => {
            let length = parse_hex(&extra_text).unwrap_or(0).min(0x10000) as usize;
            match u8::from_str_radix(text.trim().trim_start_matches("0x"), 16) {
                Ok(byte) if length > 0 => state.requests.push(Request::Patch { address, bytes: vec![byte; length] }),
                _ => state.last_message = "preencher: um byte em hexadecimal e o tamanho".into(),
            }
        }
        Dialog::DumpRegion(address, _, _) => {
            let size = parse_hex(&extra_text).unwrap_or(0x1000);
            state.dump_path = text.trim().to_string();
            state.requests.push(Request::DumpToFile { address, size, path: PathBuf::from(text.trim()) });
        }
        Dialog::RegisterType(address, _) => {
            let mut words = text.split_whitespace();
            match words.next() {
                Some(register) => {
                    let type_name = words.collect::<Vec<_>>().join(" ");
                    state.requests.push(Request::RegisterType { address, register: register.to_string(), type_name });
                }
                None => state.last_message = "tipo de registrador: o registrador e o tipo (rcx _EPROCESS)".into(),
            }
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
            Tab::Processes => processes::processes_tab(ui, state),
            Tab::Exception => processes::exception_tab(ui, state),
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
            Tab::ApiMonitor => monitors::api_tab(ui, state),
            Tab::Irps => monitors::irp_tab(ui, state),
            Tab::Types => explorers::types_tab(ui, state),
            Tab::Registry => explorers::registry_tab(ui, state),
            Tab::Objects => explorers::objects_tab(ui, state),
            Tab::Files => explorers::files_tab(ui, state),
            Tab::Snapshots => explorers::snapshots_tab(ui, state),
        }
    }

    fn scroll_bars(&self, _tab: &Tab) -> [bool; 2] {
        [false, false]
    }

    /// O botão direito no título de uma aba: copiar o que ela mostra.
    fn context_menu(&mut self, ui: &mut Ui, tab: &mut Tab, _path: NodePath) {
        if ui.button("Copiar a aba como texto").clicked() {
            crate::copy_text::copy_tab(ui.ctx(), self.state, *tab);
            ui.close();
        }
        ui.separator();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{CodeView, Config};

    /// A janela com um backend sem alvo (a thread fica parada esperando).
    fn app() -> DebuggerApp {
        let root = crate::workspace_root();
        let config = Config { root: root.clone(), elf: root.join("build").join("kernel.elf"), serial_log: None, session: None, script: None };
        DebuggerApp::new(Backend::start(config, None, Arc::new(|| {})), None, String::new())
    }

    fn ntfs(base: u64) -> ModuleRow {
        ModuleRow { base, end: base + 0x10_0000, name: "ntfs".into(), file_name: "ntfs.sys".into(), symbols: 0, source: "PDB".into(), pdb: true, pending: false, user: false }
    }

    #[test]
    fn navigation_follows_module_and_rva() {
        let mut app = app();
        app.state.snapshot = Arc::new(Snapshot { modules: vec![ntfs(0x1000_0000)], ..Default::default() });
        app.state.selected_code = Some(0x1000_0100);
        app.state.go_to_code(0x1000_0200);
        app.state.go_to_code(0x1000_0300);
        assert_eq!(app.state.navigation.peek_back(), Some(&Location::new("ntfs", 0x200)));
        // O módulo muda de base (outra sessão): a volta segue o RVA.
        app.state.snapshot = Arc::new(Snapshot { modules: vec![ntfs(0x2000_0000)], ..Default::default() });
        app.state.selected_code = Some(0x2000_0300);
        assert!(app.state.navigate_back());
        assert_eq!(app.state.selected_code, Some(0x2000_0200));
        assert!(app.state.navigate_back());
        assert_eq!(app.state.selected_code, Some(0x2000_0100));
        assert!(!app.state.navigate_back());
        assert!(app.state.navigate_forward());
        assert_eq!(app.state.selected_code, Some(0x2000_0200));
        assert!(app.state.requests.iter().any(|request| matches!(request, Request::ShowCode(text) if text == "0x20000200")));
        // Marcadores: o próximo depois da linha, dando a volta.
        assert!(app.state.toggle_bookmark_at(0x2000_0400));
        assert!(app.state.toggle_bookmark_at(0x2000_0050));
        app.state.jump_to_bookmark(true);
        assert_eq!(app.state.selected_code, Some(0x2000_0400));
        app.state.jump_to_bookmark(true);
        assert_eq!(app.state.selected_code, Some(0x2000_0050));
        app.state.jump_to_bookmark(false);
        assert_eq!(app.state.selected_code, Some(0x2000_0400));
        // A ida por expressão: a linha escolhida vira a do resultado quando o
        // snapshot com o foco novo chega.
        app.state.go_to_expression("ntfs!NtfsFsdCreate");
        let generation = app.state.snapshot.generation;
        app.state.snapshot = Arc::new(Snapshot { generation: generation + 1, modules: vec![ntfs(0x2000_0000)], code: CodeView { focus: 0x2000_0700, ..Default::default() }, ..Default::default() });
        crate::navigation::resolve_pending_goto(&mut app.state);
        assert_eq!(app.state.selected_code, Some(0x2000_0700));
        assert!(app.state.pending_goto.is_none());
        assert!(app.state.navigate_back());
        assert_eq!(app.state.selected_code, Some(0x2000_0400));
    }

    #[test]
    fn saved_state_reads_old_and_partial_files() {
        let old: Saved = serde_json::from_str("{\"light\": false, \"watches\": [\"@rax\"], \"history\": [], \"script\": \"\"}").expect("antigo");
        assert!(!old.light);
        assert_eq!(old.watches, vec!["@rax".to_string()]);
        assert!(old.layout.is_none() && old.window.is_none() && !old.console_open && old.known_tabs.is_empty());
        let empty: Saved = serde_json::from_str("{}").expect("vazio");
        assert!(empty.light, "sem o campo, o tema claro padrão");
        // Ida e volta com o arranjo e a janela.
        let saved = Saved { layout: serde_json::to_value(default_layout()).ok(), known_tabs: crate::layout::known_tabs(), window: Some(WindowGeometry { x: 10.0, y: 20.0, width: 1200.0, height: 800.0, native_scale: 1.0, maximized: false }), console_open: true, ..Saved::default() };
        let back: Saved = serde_json::from_str(&serde_json::to_string(&saved).expect("json")).expect("volta");
        assert!(back.console_open);
        assert_eq!(back.window, saved.window);
        assert!(crate::layout::restore_layout(back.layout, &back.known_tabs).is_some_and(|dock| dock.find_tab(&Tab::Snapshots).is_some()));
    }

    #[test]
    fn draws_the_new_panels_without_a_target() {
        let mut app = app();
        app.state.console_open = true;
        app.state.prefs_ui.shortcuts_open = true;
        app.state.dialog = Some(Dialog::GoTo("ntclose".into()));
        app.state.events.push(Level::Warning, "um aviso");
        let image = crate::offscreen::render(&mut app, [900, 700], 3);
        assert_eq!(image.size, [900, 700]);
        // A janela Ir para segue aberta, com o texto inicial.
        assert!(matches!(app.state.dialog, Some(Dialog::GoTo(_))));
        assert_eq!(app.state.goto.text, "ntclose");
        // A cópia de uma aba sem dados diz por quê.
        assert!(crate::copy_text::tab_text(&app.state, Tab::Bugcheck).is_err());
        assert!(crate::copy_text::tab_text(&app.state, Tab::Log).is_ok());
    }
}
