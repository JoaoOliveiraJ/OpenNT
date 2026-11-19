//! A janela do depurador: menu, barra de ferramentas, painéis encaixáveis
//! (o `egui_dock`: arrastar uma aba a solta, junta ou divide a área; o menu
//! Painéis reabre uma aba fechada) e a barra de estado. Os painéis só leem
//! o `Snapshot` publicado pelo backend e mandam pedidos; nada aqui espera o
//! alvo. O arranjo, o tema, as expressões observadas e o histórico de
//! comandos ficam num arquivo de estado entre uma execução e outra. As
//! vistas do estado da máquina (registradores, pilha, processos, threads,
//! módulos, memória, breakpoints e o log da COM1) ficam em `views`.

mod views;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Align2, Color32, FontId, Key, Modifiers, Pos2, RichText, Sense, Stroke, TextStyle, Ui, Vec2, WidgetText};
use egui_dock::{DockArea, DockState, NodeIndex, NodePath, Style, TabViewer};
use opennt_kd::commands::TraceOptions;
use opennt_kd::{BreakpointKind, Client};
use serde::{Deserialize, Serialize};

use crate::backend::{Backend, Entry, QueryKind, Request, ScriptProgress, Snapshot, Status, Target, TraceView, View};
use crate::disasm::{self, ValueHint};
use crate::launcher::{self, LaunchOptions};
use crate::session::{self, SessionFile};

/// Os painéis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tab {
    Command,
    Disassembly,
    Source,
    Registers,
    Watch,
    Locals,
    Memory,
    CallStack,
    Breakpoints,
    Modules,
    Processes,
    Threads,
    NtObjects,
    Trace,
    Bugcheck,
    DbgPrint,
    Serial,
}

impl Tab {
    pub const ALL: [Tab; 17] = [
        Tab::Disassembly,
        Tab::Source,
        Tab::Registers,
        Tab::Watch,
        Tab::Locals,
        Tab::CallStack,
        Tab::Breakpoints,
        Tab::Modules,
        Tab::Threads,
        Tab::Processes,
        Tab::NtObjects,
        Tab::Bugcheck,
        Tab::Memory,
        Tab::Trace,
        Tab::Command,
        Tab::DbgPrint,
        Tab::Serial,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Command => "Comandos",
            Tab::Disassembly => "Desmontagem",
            Tab::Source => "Código-fonte",
            Tab::Registers => "Registradores",
            Tab::Watch => "Observação",
            Tab::Locals => "Variáveis locais",
            Tab::Memory => "Memória",
            Tab::CallStack => "Pilha de chamadas",
            Tab::Breakpoints => "Breakpoints",
            Tab::Modules => "Módulos",
            Tab::Processes => "Processos e CPUs",
            Tab::Threads => "Threads",
            Tab::NtObjects => "Objetos do NT",
            Tab::Trace => "Rastro",
            Tab::Bugcheck => "Análise do bugcheck",
            Tab::DbgPrint => "DbgPrint",
            Tab::Serial => "Log da COM1",
        }
    }
}

/// O arranjo padrão: desmontagem e código-fonte no centro, registradores e
/// observação à direita, pilha, breakpoints e listas embaixo à direita,
/// comandos e logs embaixo.
pub fn default_layout() -> DockState<Tab> {
    let mut dock = DockState::new(vec![Tab::Disassembly, Tab::Bugcheck]);
    let surface = dock.main_surface_mut();
    let [top, bottom] = surface.split_below(NodeIndex::root(), 0.70, vec![Tab::Command, Tab::Trace, Tab::Memory]);
    surface.split_right(bottom, 0.62, vec![Tab::DbgPrint, Tab::Serial]);
    let [code, right] = surface.split_right(top, 0.66, vec![Tab::Registers, Tab::Watch, Tab::Locals]);
    surface.split_below(code, 0.58, vec![Tab::Source]);
    surface.split_below(right, 0.48, vec![Tab::CallStack, Tab::Breakpoints, Tab::Modules, Tab::Threads, Tab::Processes, Tab::NtObjects]);
    // A desmontagem começa à vista (a análise do bugcheck fica atrás).
    if let Some(path) = dock.find_tab(&Tab::Disassembly) {
        let _ = dock.set_active_tab(path);
    }
    dock
}

/// Texto que só cresce (DbgPrint, COM1), em linhas para a rolagem
/// virtual.
#[derive(Default)]
struct LogLines {
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

    fn count(&self) -> usize {
        self.lines.len() + usize::from(!self.partial.is_empty())
    }

    fn line(&self, index: usize) -> &str {
        self.lines.get(index).map_or(self.partial.as_str(), String::as_str)
    }
}

/// Uma linha do painel de comandos (a rolagem é virtual: um roteiro longo
/// gera milhares de linhas e a janela só desenha as que aparecem).
#[derive(Clone, Debug, PartialEq, Eq)]
struct TranscriptLine {
    kind: LineKind,
    text: String,
    /// A entrada de onde a linha veio (o menu do botão direito copia).
    entry: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineKind {
    Input,
    Output,
    Error,
}

/// As linhas de uma entrada do painel de comandos.
fn push_transcript_lines(lines: &mut Vec<TranscriptLine>, index: usize, entry: &Entry) {
    lines.push(TranscriptLine { kind: LineKind::Input, text: format!("kd> {}", entry.input), entry: index });
    let kind = if entry.error { LineKind::Error } else { LineKind::Output };
    for line in entry.output.trim_end().lines() {
        lines.push(TranscriptLine { kind, text: line.trim_end_matches('\r').to_string(), entry: index });
    }
}

/// O texto do painel de comandos para copiar: uma entrada ou todas.
fn transcript_text(entries: &[Entry], which: Option<usize>) -> String {
    let chosen: Vec<&Entry> = match which {
        Some(index) => entries.get(index).into_iter().collect(),
        None => entries.iter().collect(),
    };
    let mut text = String::new();
    for entry in chosen {
        text.push_str(&format!("kd> {}\n", entry.input));
        if !entry.output.trim().is_empty() {
            text.push_str(entry.output.trim_end());
            text.push('\n');
        }
    }
    text
}

/// Os atalhos de teclado (a janela Ajuda > Atalhos e as dicas dos menus).
/// As teclas de execução são as do WinDbg; Alt+1 a Alt+9 abrem os painéis
/// como no WinDbg.
const SHORTCUTS: [(&str, &str); 27] = [
    ("F5", "continuar"),
    ("Ctrl+B", "parar a máquina (o Ctrl+Break não chega à janela); com um roteiro rodando, para o roteiro antes"),
    ("F10", "passar por cima do call"),
    ("F11", "entrar: um passo"),
    ("Shift+F11", "sair da função (até o retorno)"),
    ("F9", "liga ou tira o breakpoint na linha escolhida da desmontagem (ou no RIP)"),
    ("Ctrl+O", "abrir o OpenNT com outras opções ou conectar a um QEMU aberto"),
    ("Ctrl+Shift+F5", "reiniciar: fecha o QEMU, recompila e abre de novo"),
    ("Shift+F5", "desconectar (um QEMU de fora segue rodando)"),
    ("Ctrl+S", "salvar ou abrir uma sessão"),
    ("Ctrl+R", "rodar um roteiro do kd"),
    ("Ctrl+Shift+R", "rodar de novo o último roteiro"),
    ("Ctrl+Shift+G", "gravar os comandos num roteiro / parar a gravação"),
    ("Ctrl+L", "limpar o painel de comandos"),
    ("Alt+1", "painel Comandos, com o cursor no prompt"),
    ("Alt+2", "Observação"),
    ("Alt+3", "Variáveis locais"),
    ("Alt+4", "Registradores"),
    ("Alt+5", "Memória"),
    ("Alt+6", "Pilha de chamadas"),
    ("Alt+7", "Desmontagem"),
    ("Alt+8", "Código-fonte"),
    ("Alt+9", "Threads"),
    ("Alt+F9", "Breakpoints"),
    ("Tab, setas", "no prompt: completa comandos, símbolos e tipos; histórico"),
    ("Esc", "fecha a janela de diálogo aberta"),
    ("F1", "esta lista"),
];

/// Os painéis de Alt+1 a Alt+9 (a ordem do WinDbg).
const ALT_PANELS: [(Key, Tab); 9] = [
    (Key::Num1, Tab::Command),
    (Key::Num2, Tab::Watch),
    (Key::Num3, Tab::Locals),
    (Key::Num4, Tab::Registers),
    (Key::Num5, Tab::Memory),
    (Key::Num6, Tab::CallStack),
    (Key::Num7, Tab::Disassembly),
    (Key::Num8, Tab::Source),
    (Key::Num9, Tab::Threads),
];

/// Como a memória aparece.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryFormat {
    Bytes,
    Words,
    Dwords,
    Qwords,
    /// Um qword por linha com o símbolo (o `dps` do WinDbg).
    Pointers,
    Ascii,
    Unicode,
}

impl MemoryFormat {
    const ALL: [MemoryFormat; 7] = [MemoryFormat::Bytes, MemoryFormat::Words, MemoryFormat::Dwords, MemoryFormat::Qwords, MemoryFormat::Pointers, MemoryFormat::Ascii, MemoryFormat::Unicode];

    fn label(self) -> &'static str {
        match self {
            MemoryFormat::Bytes => "bytes",
            MemoryFormat::Words => "words (2)",
            MemoryFormat::Dwords => "dwords (4)",
            MemoryFormat::Qwords => "qwords (8)",
            MemoryFormat::Pointers => "ponteiros com símbolo",
            MemoryFormat::Ascii => "ASCII",
            MemoryFormat::Unicode => "UTF-16",
        }
    }

    fn unit(self) -> usize {
        match self {
            MemoryFormat::Words | MemoryFormat::Unicode => 2,
            MemoryFormat::Dwords => 4,
            MemoryFormat::Qwords | MemoryFormat::Pointers => 8,
            _ => 1,
        }
    }
}

/// O modo do rastro pedido no painel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceMode {
    Count,
    Until,
    Return,
    Enter,
    Leave,
}

impl TraceMode {
    const ALL: [TraceMode; 5] = [TraceMode::Count, TraceMode::Until, TraceMode::Return, TraceMode::Enter, TraceMode::Leave];

    fn label(self) -> &'static str {
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
enum TraceDisplay {
    Table,
    Tree,
    Diff,
}

/// O estado salvo entre execuções (os campos que faltam num arquivo velho
/// ficam com o padrão).
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Saved {
    layout: Option<DockState<Tab>>,
    light: bool,
    watches: Vec<String>,
    history: Vec<String>,
    /// As opções do xtask das últimas aberturas (a mais nova antes).
    recent_launch: Vec<String>,
    /// Os últimos endereços conectados.
    recent_connect: Vec<String>,
    /// Os últimos roteiros rodados.
    recent_scripts: Vec<String>,
}

/// O formulário da janela Roteiros (rodar um roteiro do kd e gravar os
/// comandos num roteiro).
#[derive(Clone, Debug, Default)]
struct ScriptForm {
    /// O arquivo do roteiro (relativo à raiz do repositório ou absoluto).
    path: String,
    /// Um roteiro escrito na própria janela.
    text: String,
    /// Onde gravar os comandos.
    record_path: String,
    /// Os roteiros `.kd` da pasta do diretório de build.
    found: Vec<String>,
    error: Option<String>,
}

/// As opções comuns do `xtask` (os botões da janela de abertura).
const COMMON_OPTIONS: [(&str, &str); 8] = [
    ("--initial-process=smss", "a cadeia real: smss, csrss, wininit e winlogon (modo usuário)"),
    ("--display=basic", "o vídeo pelo BasicDisplay.sys e o BasicRender.sys reais"),
    ("--accel=whpx", "WHPX (sem a opção, o debug usa o TCG)"),
    ("--accel=tcg", "TCG (o rastro rápido do QEMU precisa dele)"),
    ("--smp=2", "dois processadores"),
    ("--start-driver=ntfs", "o ntfs.sys real monta o volume"),
    ("--trace-rpc", "cada mensagem ALPC das portas de servidor na COM1"),
    ("--usb", "a controladora xHCI com teclado e tablet USB"),
];

/// O formulário da janela Abrir ou conectar.
#[derive(Clone, Debug, Default)]
struct OpenForm {
    /// As opções do xtask em texto (`--initial-process=smss --display=basic`).
    options: String,
    build_dir: String,
    headless: bool,
    address: String,
    error: Option<String>,
}

/// O formulário da janela Sessões (salvar e abrir uma sessão com nome).
#[derive(Clone, Debug, Default)]
struct SessionForm {
    /// O nome (vira `<build>/opennt-dbg/sessoes/<nome>.json`) ou um caminho.
    name: String,
    /// Ao abrir, também abre o OpenNT (ou conecta ao endereço da sessão).
    open_target: bool,
    /// As sessões da pasta, lidas quando a janela abre.
    saved: Vec<(String, PathBuf)>,
    error: Option<String>,
}

/// Põe `item` no começo de uma lista de recentes, sem repetir e com no
/// máximo `limit` itens.
fn remember_recent(list: &mut Vec<String>, item: &str, limit: usize) {
    list.retain(|known| known != item);
    list.insert(0, item.to_string());
    list.truncate(limit);
}

/// O estado da interface (campos de texto, cópias do que o backend
/// publicou).
pub struct UiState {
    snapshot: Arc<Snapshot>,
    status: Status,
    activity: String,
    can_restart: bool,
    transcript: Vec<Entry>,
    transcript_lines: Vec<TranscriptLine>,
    /// O Ctrl+L: as linhas antes desta saem da vista.
    transcript_start: usize,
    /// A janela Ajuda > Atalhos do teclado.
    shortcuts_help: bool,
    console: LogLines,
    serial: LogLines,
    launch_log: LogLines,
    command: String,
    command_focused: bool,
    history: Vec<String>,
    history_index: Option<usize>,
    completions: Arc<Vec<String>>,
    type_names: Arc<Vec<String>>,
    suggestions: Vec<String>,
    code_address: String,
    selected_code: Option<u64>,
    memory_address: String,
    memory_format: MemoryFormat,
    search_pattern: String,
    search_length: String,
    breakpoint_expression: String,
    breakpoint_kind: BreakpointKind,
    breakpoint_condition: String,
    breakpoint_pass: String,
    breakpoint_deferred: bool,
    condition_edit: Option<(u32, String, String)>,
    register_edit: Option<(String, String)>,
    memory_edit: Option<(u64, String)>,
    thread_filter: Option<u64>,
    connect_address: String,
    launch: Option<LaunchOptions>,
    /// A janela Abrir ou conectar (aberta quando `Some`).
    open_dialog: Option<OpenForm>,
    recent_launch: Vec<String>,
    recent_connect: Vec<String>,
    /// O alvo da sessão, como o backend publicou.
    target: Option<Target>,
    /// O botão Cancelar (vai direto ao backend, fora da fila de pedidos).
    cancel: bool,
    /// A janela Sessões (aberta quando `Some`).
    session_dialog: Option<SessionForm>,
    /// A janela Roteiros (aberta quando `Some`) e os campos dela entre uma
    /// abertura e outra.
    script_dialog: Option<ScriptForm>,
    script_memory: ScriptForm,
    recent_scripts: Vec<String>,
    /// O roteiro rodando e a gravação, como o backend publicou.
    script: Option<ScriptProgress>,
    recording: Option<(PathBuf, usize)>,
    /// A última falha da sessão (o aviso no alto da janela) e qual o
    /// usuário já fechou.
    failure: Option<String>,
    failure_generation: u64,
    dismissed_failure: u64,
    /// A geração do snapshot que já rolou o código até o foco.
    scrolled_code: u64,
    scrolled_source: u64,
    requests: Vec<Request>,
    watches: Vec<String>,
    watch_input: String,
    sent_watches: Vec<String>,
    expanded: BTreeSet<(u64, u32)>,
    sent_expanded: BTreeSet<(u64, u32)>,
    query_kind: QueryKind,
    query_argument: String,
    trace: Option<Arc<TraceView>>,
    reference: Option<Arc<TraceView>>,
    trace_generation: u64,
    trace_mode: TraceMode,
    trace_argument: String,
    trace_count: String,
    trace_over: bool,
    trace_skip: String,
    trace_watch: String,
    trace_qemu_ms: String,
    trace_filter: String,
    trace_display: TraceDisplay,
    trace_selected: Option<usize>,
    trace_rows: Vec<usize>,
    trace_rows_key: (u64, String),
    trace_scroll: Option<usize>,
    trace_tree: Option<(u64, Vec<opennt_kd::trace::CallNode>)>,
    trace_path: String,
    reference_path: String,
    divergence: Option<Option<(usize, usize)>>,
    light: bool,
    theme_applied: Option<bool>,
    /// Painéis a mostrar no próximo quadro.
    focus_tab: Vec<Tab>,
    bugcheck_seen: u64,
    reset_layout: bool,
    toggle_tab: Option<Tab>,
    /// O estado das vistas (`views`).
    views: views::ViewsState,
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
struct Palette {
    red: Color32,
    yellow: Color32,
    green: Color32,
    blue: Color32,
    dim: Color32,
    focus: Color32,
}

fn palette(ui: &Ui) -> Palette {
    if ui.visuals().dark_mode {
        Palette {
            red: Color32::from_rgb(0xE8, 0x5C, 0x5C),
            yellow: Color32::from_rgb(0xF2, 0xC1, 0x4E),
            green: Color32::from_rgb(0x5C, 0xC0, 0x6C),
            blue: Color32::from_rgb(0x6C, 0xA8, 0xF0),
            dim: Color32::from_rgb(0x8A, 0x8F, 0x98),
            focus: Color32::from_rgba_premultiplied(0x50, 0x46, 0x10, 0xA0),
        }
    } else {
        Palette {
            red: Color32::from_rgb(0xC0, 0x20, 0x20),
            yellow: Color32::from_rgb(0x9A, 0x60, 0x00),
            green: Color32::from_rgb(0x1E, 0x7A, 0x32),
            blue: Color32::from_rgb(0x1F, 0x5F, 0xBF),
            dim: Color32::from_rgb(0x70, 0x74, 0x7A),
            focus: Color32::from_rgba_premultiplied(0xF0, 0xD8, 0x70, 0x90),
        }
    }
}

fn mono(text: impl Into<String>) -> RichText {
    RichText::new(text).monospace()
}

fn hex(value: u64) -> String {
    format!("{value:016x}")
}

/// Um número em hexadecimal (com ou sem `0x`).
fn parse_hex(text: &str) -> Option<u64> {
    let text = text.trim().trim_start_matches("0x").replace(['`', '_'], "");
    u64::from_str_radix(&text, 16).ok()
}

/// O arquivo de estado da janela.
pub fn state_path() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("opennt-dbg").join("estado.json"))
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
                transcript_lines: Vec::new(),
                transcript_start: 0,
                shortcuts_help: false,
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
                code_address: String::new(),
                selected_code: None,
                memory_address: String::new(),
                memory_format: MemoryFormat::Bytes,
                search_pattern: String::new(),
                search_length: "0x10000".into(),
                breakpoint_expression: String::new(),
                breakpoint_kind: BreakpointKind::Software,
                breakpoint_condition: String::new(),
                breakpoint_pass: String::new(),
                breakpoint_deferred: false,
                condition_edit: None,
                register_edit: None,
                memory_edit: None,
                thread_filter: None,
                connect_address,
                launch,
                open_dialog: None,
                recent_launch: Vec::new(),
                recent_connect: Vec::new(),
                target: None,
                cancel: false,
                session_dialog: None,
                script_dialog: None,
                script_memory: ScriptForm::default(),
                recent_scripts: Vec::new(),
                script: None,
                recording: None,
                failure: None,
                failure_generation: 0,
                dismissed_failure: 0,
                scrolled_code: 0,
                scrolled_source: 0,
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
                trace_path: "build/opennt-dbg/rastro.csv".into(),
                reference_path: "build/opennt-dbg/referencia.csv".into(),
                divergence: None,
                light: false,
                theme_applied: None,
                focus_tab: Vec::new(),
                bugcheck_seen: 0,
                reset_layout: false,
                toggle_tab: None,
                views: views::ViewsState::default(),
            },
            persist: None,
            last_saved: String::new(),
            last_save: Instant::now(),
        }
    }

    /// Com arranjo, tema, expressões e histórico salvos em `path`.
    pub fn with_persistence(mut self, path: PathBuf) -> DebuggerApp {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(saved) = serde_json::from_str::<Saved>(&text) {
                if let Some(layout) = saved.layout {
                    self.dock = layout;
                }
                self.state.light = saved.light;
                self.state.watches = saved.watches;
                self.state.history = saved.history;
                self.state.recent_launch = saved.recent_launch;
                self.state.recent_connect = saved.recent_connect;
                self.state.recent_scripts = saved.recent_scripts;
            }
        }
        self.persist = Some(path);
        self
    }

    /// Aplica uma sessão salva (o `--session=ARQ`): expressões, memória,
    /// opções de abertura e os breakpoints (no backend).
    pub fn apply_session(&mut self, session: &SessionFile) {
        self.state.apply_session(session);
    }

    /// Um pedido para o backend no próximo quadro, depois dos que já estão
    /// na fila da janela (o `--script` depois dos breakpoints da sessão).
    pub fn queue(&mut self, request: Request) {
        self.state.requests.push(request);
    }

    /// Expressões na janela de observação (a captura de tela e os testes),
    /// já pedidas ao backend por quem chama.
    pub fn set_watches(&mut self, watches: Vec<String>) {
        self.state.sent_watches = watches.clone();
        self.state.watches = watches;
    }

    /// Troca o arranjo dos painéis (a captura de tela do rastro).
    pub fn set_layout(&mut self, dock: DockState<Tab>) {
        self.dock = dock;
    }

    /// Mostra um painel (a captura de tela).
    pub fn focus(&mut self, tab: Tab) {
        self.state.focus_tab.push(tab);
    }

    /// Seleciona um registro do rastro (a captura de tela).
    pub fn select_trace_record(&mut self, index: usize) {
        self.state.trace_selected = Some(index);
        self.state.trace_scroll = Some(index);
    }

    fn save(&mut self, force: bool) {
        let Some(path) = &self.persist else { return };
        if !force && self.last_save.elapsed() < Duration::from_secs(3) {
            return;
        }
        self.last_save = Instant::now();
        let saved = Saved {
            layout: Some(self.dock.clone()),
            light: self.state.light,
            watches: self.state.watches.clone(),
            history: self.state.history.iter().rev().take(200).rev().cloned().collect(),
            recent_launch: self.state.recent_launch.clone(),
            recent_connect: self.state.recent_connect.clone(),
            recent_scripts: self.state.recent_scripts.clone(),
        };
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
            if state.memory_address.is_empty() {
                state.memory_address = state.snapshot.memory.expression.clone();
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
        state.target = shared.target.clone();
        state.script = shared.script.clone();
        state.recording = shared.recording.clone();
        state.failure = shared.failure.clone();
        state.failure_generation = shared.failure_generation;
        if shared.transcript.len() < state.transcript.len() {
            state.transcript.clear();
            state.transcript_lines.clear();
            state.transcript_start = 0;
        }
        let known = state.transcript.len();
        for (offset, entry) in shared.transcript[known..].iter().enumerate() {
            push_transcript_lines(&mut state.transcript_lines, known + offset, entry);
        }
        state.transcript.extend(shared.transcript[known..].iter().cloned());
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
                state.focus_tab.push(Tab::Trace);
            }
        }
        drop(shared);
        views::after_sync(&mut self.state);
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
        if state.failure.is_some() && state.dismissed_failure != state.failure_generation {
            egui::Panel::top("failure").show(ui, |ui| failure_banner(ui, state));
        }
        egui::Panel::bottom("status").show(ui, |ui| status_bar(ui, state));
        self.layout_requests();
        egui::CentralPanel::no_frame().show(ui, |ui| {
            let mut style = Style::from_egui(ui.style().as_ref());
            style.tab_bar.fill_tab_bar = true;
            DockArea::new(&mut self.dock).style(style).show_leaf_close_all_buttons(false).show_leaf_collapse_buttons(false).show_inside(ui, &mut Viewer { state: &mut self.state });
        });
        // As leituras caras que os painéis abertos querem.
        views::sync_wanted(&mut self.state, &open);
        open_dialog(ui, &mut self.state);
        session_dialog(ui, &mut self.state);
        script_dialog(ui, &mut self.state);
        shortcuts_window(ui, &mut self.state);
        if std::mem::take(&mut self.state.cancel) {
            self.backend.cancel();
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

    /// Reabrir, fechar e focar painéis; o arranjo padrão.
    fn layout_requests(&mut self) {
        if std::mem::take(&mut self.state.reset_layout) {
            self.dock = default_layout();
        }
        if let Some(tab) = self.state.toggle_tab.take() {
            match self.dock.find_tab(&tab) {
                Some(path) => {
                    self.dock.remove_tab(path);
                }
                None => self.open_tab(tab),
            }
        }
        for tab in std::mem::take(&mut self.state.focus_tab) {
            if self.dock.find_tab(&tab).is_none() {
                self.open_tab(tab);
            }
            if let Some(path) = self.dock.find_tab(&tab) {
                let _ = self.dock.set_active_tab(path);
                self.dock.set_focused_node_and_surface(NodePath { surface: path.surface, node: path.node });
            }
        }
    }

    /// Abre um painel junto de um vizinho natural (ou na área focada).
    fn open_tab(&mut self, tab: Tab) {
        let neighbor = match tab {
            Tab::Source | Tab::Bugcheck => Tab::Disassembly,
            Tab::Watch | Tab::Locals => Tab::Registers,
            Tab::Breakpoints | Tab::Modules | Tab::Threads | Tab::Processes | Tab::NtObjects => Tab::CallStack,
            Tab::Memory | Tab::Trace => Tab::Command,
            Tab::Serial => Tab::DbgPrint,
            _ => Tab::Disassembly,
        };
        match self.dock.find_tab(&neighbor) {
            Some(path) => {
                self.dock.set_focused_node_and_surface(NodePath { surface: path.surface, node: path.node });
                self.dock.push_to_focused_leaf(tab);
            }
            None => self.dock.push_to_first_leaf(tab),
        }
    }

    /// Os atalhos de teclado. O egui ignora Shift e Alt a mais num atalho
    /// sem eles (o F5 também pegaria o Shift+F5): os com mais modificadores
    /// são conferidos antes.
    fn shortcuts(&mut self, ui: &Ui) {
        let stopped = self.state.ready();
        let running = self.state.status == Status::Running;
        let connected = matches!(self.state.status, Status::Stopped | Status::Running);
        let pressed = |modifiers: Modifiers, key: Key| ui.input_mut(|input| input.consume_key(modifiers, key));
        let ctrl_shift = Modifiers::CTRL | Modifiers::SHIFT;
        if pressed(Modifiers::NONE, Key::F1) {
            self.state.shortcuts_help = !self.state.shortcuts_help;
        }
        if pressed(Modifiers::CTRL, Key::O) && self.state.open_dialog.is_none() {
            self.state.open_form();
        }
        if pressed(ctrl_shift, Key::R) {
            if let Some(last) = self.state.recent_scripts.first().cloned().filter(|_| connected && self.state.script.is_none()) {
                self.state.run_script_file(&last);
            }
        } else if pressed(Modifiers::CTRL, Key::R) {
            self.state.open_scripts();
        }
        if pressed(ctrl_shift, Key::G) {
            self.state.toggle_recording();
        }
        if pressed(Modifiers::CTRL, Key::S) {
            self.state.open_sessions();
        }
        if pressed(Modifiers::CTRL, Key::L) {
            self.state.transcript_start = self.state.transcript_lines.len();
        }
        if pressed(ctrl_shift, Key::F5) {
            if self.state.can_restart && !matches!(self.state.status, Status::Launching(_) | Status::Connecting(_)) {
                self.state.requests.push(Request::Restart);
            }
        } else if pressed(Modifiers::SHIFT, Key::F5) {
            if connected {
                self.state.requests.push(Request::Disconnect);
            }
        } else if stopped && pressed(Modifiers::NONE, Key::F5) {
            self.state.requests.push(Request::Go);
        }
        for (key, tab) in ALT_PANELS {
            if pressed(Modifiers::ALT, key) {
                self.state.focus_tab.push(tab);
                if tab == Tab::Command {
                    ui.memory_mut(|memory| memory.request_focus(egui::Id::new("kd-command")));
                }
            }
        }
        if pressed(Modifiers::ALT, Key::F9) {
            self.state.focus_tab.push(Tab::Breakpoints);
        }
        if stopped && pressed(Modifiers::SHIFT, Key::F11) {
            self.state.requests.push(Request::StepOut);
        }
        if stopped && pressed(Modifiers::NONE, Key::F10) {
            self.state.requests.push(Request::StepOver);
        }
        if stopped && pressed(Modifiers::NONE, Key::F11) {
            self.state.requests.push(Request::StepInto);
        }
        if stopped && pressed(Modifiers::NONE, Key::F9) {
            let target = self.state.selected_code.or_else(|| current_rip(&self.state.snapshot));
            if let Some(address) = target {
                self.state.requests.push(Request::ToggleBreakpoint(address));
            }
        }
        // O Ctrl+Break não chega ao egui (o Windows o entrega como VK_CANCEL):
        // a parada é o Ctrl+B.
        if running && pressed(Modifiers::CTRL, Key::B) {
            self.state.request_break();
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

impl UiState {
    /// O backend está ocupado (um roteiro, a leitura do estado da máquina,
    /// um comando longo): os pedidos esperam na fila dele, então os botões
    /// de execução desligam até ele voltar (segurar o F10 não empilha
    /// passos).
    fn busy(&self) -> bool {
        self.script.is_some() || !self.activity.is_empty()
    }

    /// Parado e com o backend livre: os botões de execução valem.
    fn ready(&self) -> bool {
        self.status == Status::Stopped && !self.busy()
    }

    /// Parar a máquina; com um roteiro rodando, o roteiro para antes (o
    /// pedido de parada espera na fila do backend até ele).
    fn request_break(&mut self) {
        if self.script.is_some() {
            self.cancel = true;
        }
        self.requests.push(Request::Break);
    }

    /// Abre a janela Abrir ou conectar com as opções da última abertura
    /// (as da linha de comando, senão as da última vez).
    fn open_form(&mut self) {
        let recent = self.recent_launch.first().cloned().unwrap_or_default();
        let (options, build_dir, headless) = match &self.launch {
            Some(launch) if !launch.extra.is_empty() => (launch.extra.join(" "), launch.build_dir.display().to_string(), launch.headless),
            Some(launch) => (recent, launch.build_dir.display().to_string(), launch.headless),
            None => (recent, "build".to_string(), false),
        };
        self.open_dialog = Some(OpenForm { options, build_dir, headless, address: self.connect_address.clone(), error: None });
    }

    /// Abre o OpenNT com estas opções e as guarda como as últimas.
    fn launch_with(&mut self, options: LaunchOptions) {
        remember_recent(&mut self.recent_launch, &options.extra.join(" "), 12);
        self.requests.push(Request::Start(Target::Launch(options.clone())));
        self.launch = Some(options);
    }

    /// Conecta a um endereço já conferido e o guarda nos recentes.
    fn connect_to(&mut self, address: String) {
        remember_recent(&mut self.recent_connect, &address, 12);
        self.connect_address = address.clone();
        self.requests.push(Request::Start(Target::Connect(address)));
    }

    /// O diretório de build da sessão (o da última abertura).
    fn build_path(&self) -> PathBuf {
        match &self.launch {
            Some(launch) => launch.build_path(),
            None => crate::workspace_root().join("build"),
        }
    }

    /// A raiz do repositório (a da linha de comando).
    fn root(&self) -> PathBuf {
        self.launch.as_ref().map_or_else(crate::workspace_root, |launch| launch.root.clone())
    }

    /// Abre a janela Sessões com a lista da pasta.
    fn open_sessions(&mut self) {
        let saved = session::list(&session::directory(&self.build_path()));
        let name = self.session_dialog.as_ref().map(|form| form.name.clone()).unwrap_or_default();
        let disconnected = !matches!(self.status, Status::Stopped | Status::Running | Status::Launching(_) | Status::Connecting(_));
        self.session_dialog = Some(SessionForm { name, open_target: disconnected, saved, error: None });
    }

    /// A sessão de agora (os breakpoints o backend põe ao gravar).
    fn current_session(&self) -> SessionFile {
        let (xtask, build_dir, headless) = match &self.launch {
            Some(launch) => (launch.extra.clone(), launch.build_dir.display().to_string(), launch.headless),
            None => (Vec::new(), String::new(), false),
        };
        let connect = match &self.target {
            Some(Target::Connect(address)) => address.clone(),
            _ => String::new(),
        };
        SessionFile { version: session::VERSION, breakpoints: String::new(), watches: self.watches.clone(), memory: self.memory_address.trim().to_string(), xtask, build_dir, headless, connect }
    }

    /// Aplica uma sessão: as expressões e a memória na hora, as opções de
    /// abertura para o próximo Abrir, e os breakpoints pelo backend (na
    /// hora com a máquina parada, senão na próxima parada ou no attach).
    fn apply_session(&mut self, session: &SessionFile) {
        self.watches = session.watches.clone();
        if !session.memory.is_empty() {
            self.memory_address = session.memory.clone();
            self.requests.push(Request::ShowMemory(session.memory.clone()));
        }
        if !session.xtask.is_empty() || !session.build_dir.is_empty() {
            let root = self.root();
            let build_dir = if session.build_dir.is_empty() { PathBuf::from("build") } else { PathBuf::from(&session.build_dir) };
            self.launch = Some(LaunchOptions { root, build_dir, headless: session.headless, extra: session.xtask.clone() });
        }
        if !session.connect.is_empty() {
            self.connect_address = session.connect.clone();
        }
        self.requests.push(Request::LoadBreakpoints(session.breakpoints.clone()));
    }

    /// Abre a janela Roteiros com os roteiros da pasta do diretório de build.
    fn open_scripts(&mut self) {
        let folder = self.build_path().join("opennt-dbg").join("roteiros");
        let mut found: Vec<String> = std::fs::read_dir(&folder)
            .map(|entries| entries.filter_map(Result::ok).map(|entry| entry.path()).filter(|path| path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("kd") || extension.eq_ignore_ascii_case("txt"))).map(|path| self.shown_path(&path)).collect())
            .unwrap_or_default();
        found.sort();
        let previous = self.script_dialog.take().unwrap_or_else(|| std::mem::take(&mut self.script_memory));
        let path = if previous.path.is_empty() { self.recent_scripts.first().cloned().unwrap_or_default() } else { previous.path };
        let record_path = if previous.record_path.is_empty() { self.shown_path(&folder.join("gravado.kd")) } else { previous.record_path };
        self.script_dialog = Some(ScriptForm { path, text: previous.text, record_path, found, error: None });
    }

    /// Um caminho como a janela mostra: relativo à raiz quando dá.
    fn shown_path(&self, path: &std::path::Path) -> String {
        let root = self.root();
        path.strip_prefix(&root).map_or_else(|_| path.display().to_string(), |relative| relative.display().to_string().replace('\\', "/"))
    }

    /// Roda o roteiro de um arquivo e o guarda nos recentes.
    fn run_script_file(&mut self, path: &str) {
        let path = path.trim().to_string();
        remember_recent(&mut self.recent_scripts, &path, 12);
        self.requests.push(Request::RunScriptFile(PathBuf::from(path)));
        self.focus_tab.push(Tab::Command);
    }

    /// Liga a gravação no arquivo da janela Roteiros (ou no padrão) ou a
    /// desliga.
    fn toggle_recording(&mut self) {
        if self.recording.is_some() {
            self.requests.push(Request::StopRecording);
            return;
        }
        let folder = self.build_path().join("opennt-dbg").join("roteiros");
        let path = match self.script_dialog.as_ref().map(|form| form.record_path.trim()).filter(|path| !path.is_empty()) {
            Some(path) => PathBuf::from(path),
            None => match self.script_memory.record_path.trim() {
                "" => folder.join("gravado.kd"),
                path => PathBuf::from(path),
            },
        };
        let xtask = self.launch.as_ref().map(|launch| launch.extra.clone()).unwrap_or_default();
        self.requests.push(Request::StartRecording { path, xtask });
    }

    /// O botão Conectar da barra: o endereço do campo (`HOST:PORTA`, a
    /// porta ou a linha `KD_READY`); um endereço inválido abre a janela
    /// com o erro.
    fn connect_to_typed_address(&mut self) {
        match launcher::parse_connect_address(&self.connect_address) {
            Ok(address) => self.connect_to(address),
            Err(error) => {
                self.open_form();
                if let Some(form) = self.open_dialog.as_mut() {
                    form.error = Some(error);
                }
            }
        }
    }
}

/// As opções de abertura do formulário (a raiz vem da linha de comando).
fn form_launch_options(base: Option<&LaunchOptions>, form: &OpenForm) -> Result<LaunchOptions, String> {
    let extra = launcher::parse_xtask_options(&form.options)?;
    let build_dir = form.build_dir.trim();
    let root = base.map_or_else(crate::workspace_root, |launch| launch.root.clone());
    Ok(LaunchOptions { root, build_dir: PathBuf::from(if build_dir.is_empty() { "build" } else { build_dir }), headless: form.headless, extra })
}

/// A janela Abrir ou conectar: as opções do `xtask` (com os botões das
/// opções comuns e as últimas usadas), o diretório de build, o QEMU sem
/// janela, e o endereço de um QEMU já aberto.
fn open_dialog(ui: &mut Ui, state: &mut UiState) {
    let Some(mut form) = state.open_dialog.take() else { return };
    let colors = palette(ui);
    let mut open = true;
    let mut close = false;
    egui::Window::new("Abrir ou conectar").id(egui::Id::new("kd-open-dialog")).collapsible(false).resizable(false).default_width(660.0).anchor(Align2::CENTER_TOP, Vec2::new(0.0, 90.0)).open(&mut open).show(ui.ctx(), |ui| {
        ui.label(RichText::new("Abrir o OpenNT: compilar com --kd=com2 e iniciar o QEMU").strong());
        let mut submit_launch = false;
        ui.horizontal(|ui| {
            ui.label("Opções do xtask:");
            let response = ui.add(egui::TextEdit::singleline(&mut form.options).font(TextStyle::Monospace).desired_width(500.0).hint_text("--initial-process=smss --display=basic"));
            if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
                submit_launch = true;
            }
        });
        ui.horizontal_wrapped(|ui| {
            for (option, tooltip) in COMMON_OPTIONS {
                if ui.selectable_label(launcher::has_option(&form.options, option), mono(option)).on_hover_text(tooltip).clicked() {
                    form.options = launcher::toggle_option(&form.options, option);
                }
            }
        });
        if !state.recent_launch.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("últimas:").color(colors.dim));
                for recent in state.recent_launch.iter().take(6) {
                    let shown = if recent.is_empty() { "(sem opções)" } else { recent.as_str() };
                    if ui.small_button(mono(shown)).on_hover_text("usar estas opções").clicked() {
                        form.options = recent.clone();
                    }
                }
            });
        }
        ui.horizontal(|ui| {
            ui.label("Diretório de build:");
            ui.add(egui::TextEdit::singleline(&mut form.build_dir).font(TextStyle::Monospace).desired_width(220.0).hint_text("build"));
            ui.checkbox(&mut form.headless, "QEMU sem janela");
        });
        let preview = form_launch_options(state.launch.as_ref(), &form);
        match &preview {
            Ok(options) => hint(ui, &options.command_line()),
            Err(error) => {
                ui.label(RichText::new(error).color(colors.red));
            }
        }
        if ui.add_enabled(preview.is_ok(), egui::Button::new("Abrir")).clicked() || submit_launch {
            match preview {
                Ok(options) => {
                    state.launch_with(options);
                    close = true;
                }
                Err(error) => form.error = Some(error),
            }
        }
        ui.separator();
        ui.label(RichText::new("Conectar a um QEMU já aberto").strong());
        let mut submit_connect = false;
        ui.horizontal(|ui| {
            ui.label("Endereço:");
            let response = ui.add(egui::TextEdit::singleline(&mut form.address).font(TextStyle::Monospace).desired_width(320.0).hint_text("127.0.0.1:1234, a porta ou a linha KD_READY"));
            if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
                submit_connect = true;
            }
            if ui.button("Conectar").clicked() {
                submit_connect = true;
            }
        });
        if !state.recent_connect.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("últimos:").color(colors.dim));
                for recent in state.recent_connect.iter().take(6) {
                    if ui.small_button(mono(recent)).clicked() {
                        form.address = recent.clone();
                    }
                }
            });
        }
        hint(ui, "O cargo xtask debug --launch --no-client imprime KD_READY 127.0.0.1:PORTA (cole a linha inteira); o cargo xtask run --kd=com2 escuta em 127.0.0.1:1234. Desconectar deixa a máquina rodando. Com outro diretório de build, abra o opennt-dbg com --build-dir=DIR (o kernel.elf e o serial.log).");
        if submit_connect {
            match launcher::parse_connect_address(&form.address) {
                Ok(address) => {
                    state.connect_to(address);
                    close = true;
                }
                Err(error) => form.error = Some(error),
            }
        }
        if let Some(error) = &form.error {
            ui.separator();
            ui.label(RichText::new(error).color(colors.red));
        }
        if ui.input(|input| input.key_pressed(Key::Escape)) {
            close = true;
        }
    });
    if open && !close {
        state.open_dialog = Some(form);
    }
}

/// A janela Sessões: grava a sessão de agora com um nome ou abre uma das
/// salvas na pasta do diretório de build (ou por caminho).
fn session_dialog(ui: &mut Ui, state: &mut UiState) {
    let Some(mut form) = state.session_dialog.take() else { return };
    let colors = palette(ui);
    let folder = session::directory(&state.build_path());
    let mut open = true;
    let mut close = false;
    egui::Window::new("Sessões").id(egui::Id::new("kd-session-dialog")).collapsible(false).resizable(false).default_width(560.0).anchor(Align2::CENTER_TOP, Vec2::new(0.0, 90.0)).open(&mut open).show(ui.ctx(), |ui| {
        hint(ui, &format!("Uma sessão guarda os breakpoints, as expressões observadas, a memória e como abrir o alvo. Pasta: {}", folder.display()));
        let mut save = false;
        let mut load: Option<PathBuf> = None;
        ui.horizontal(|ui| {
            ui.label("Nome:");
            let response = ui.add(egui::TextEdit::singleline(&mut form.name).font(TextStyle::Monospace).desired_width(300.0).hint_text("logon, csrss... ou um caminho .json"));
            if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
                save = true;
            }
            if ui.button("Salvar").on_hover_text("grava a sessão de agora com este nome").clicked() {
                save = true;
            }
            if ui.button("Abrir").on_hover_text("abre a sessão com este nome ou caminho").clicked() {
                match session::path_for(&state.root(), &folder, &form.name) {
                    Ok(path) => load = Some(path),
                    Err(error) => form.error = Some(error),
                }
            }
        });
        ui.checkbox(&mut form.open_target, "ao abrir, abrir também o OpenNT com as opções da sessão (ou conectar ao endereço dela)");
        ui.separator();
        if form.saved.is_empty() {
            hint(ui, "nenhuma sessão salva nesta pasta");
        }
        egui::ScrollArea::vertical().id_salt("session-list").max_height(220.0).show(ui, |ui| {
            for (name, path) in &form.saved {
                ui.horizontal(|ui| {
                    if ui.button("abrir").clicked() {
                        load = Some(path.clone());
                    }
                    if ui.selectable_label(form.name == *name, mono(name)).on_hover_text(path.display().to_string()).clicked() {
                        form.name = name.clone();
                    }
                });
            }
        });
        if save {
            match session::path_for(&state.root(), &folder, &form.name) {
                Ok(path) => {
                    let session = state.current_session();
                    state.requests.push(Request::SaveSession { path, session });
                    close = true;
                }
                Err(error) => form.error = Some(error),
            }
        }
        if let Some(path) = load {
            match SessionFile::load(&path) {
                Ok(loaded) => {
                    state.apply_session(&loaded);
                    if form.open_target {
                        if !loaded.connect.is_empty() {
                            state.connect_to(loaded.connect.clone());
                        } else if let Some(options) = state.launch.clone() {
                            state.launch_with(options);
                        }
                    }
                    close = true;
                }
                Err(error) => form.error = Some(error),
            }
        }
        if let Some(error) = &form.error {
            ui.label(RichText::new(error).color(colors.red));
        }
        if ui.input(|input| input.key_pressed(Key::Escape)) {
            close = true;
        }
    });
    if open && !close {
        state.session_dialog = Some(form);
    }
}

/// A janela Roteiros: rodar um roteiro do kd (de um arquivo ou escrito
/// aqui) e gravar os comandos da janela num roteiro.
fn script_dialog(ui: &mut Ui, state: &mut UiState) {
    let Some(mut form) = state.script_dialog.take() else { return };
    let colors = palette(ui);
    let connected = matches!(state.status, Status::Stopped | Status::Running);
    let mut open = true;
    let mut close = false;
    egui::Window::new("Roteiros").id(egui::Id::new("kd-script-dialog")).collapsible(false).resizable(true).default_width(640.0).anchor(Align2::CENTER_TOP, Vec2::new(0.0, 80.0)).open(&mut open).show(ui.ctx(), |ui| {
        ui.label(RichText::new("Rodar um roteiro do kd").strong());
        hint(ui, "A linguagem do --script do cargo xtask test-boot --kd=com2: um comando por linha, # comenta; expect, expect-stop, expect-console, expect-eq, save, save-word, save-thread ($nome), wait-serial, wait-stop [ms], echo, sleep. A saída vai ao painel Comandos; a primeira conferência que falha para o roteiro.");
        let mut run_file = false;
        ui.horizontal(|ui| {
            ui.label("Arquivo:");
            let response = ui.add(egui::TextEdit::singleline(&mut form.path).font(TextStyle::Monospace).desired_width(440.0).hint_text("build/opennt-dbg/roteiros/logon.kd"));
            if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
                run_file = true;
            }
            if ui.add_enabled(connected && state.script.is_none(), egui::Button::new("Rodar")).clicked() {
                run_file = true;
            }
        });
        let quick: Vec<String> = state.recent_scripts.iter().chain(form.found.iter()).take(10).cloned().collect();
        if !quick.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("últimos e da pasta:").color(colors.dim));
                for path in &quick {
                    if ui.small_button(mono(path)).clicked() {
                        form.path = path.clone();
                    }
                }
            });
        }
        ui.collapsing("Escrever o roteiro aqui", |ui| {
            ui.add(egui::TextEdit::multiline(&mut form.text).font(TextStyle::Monospace).desired_rows(6).desired_width(f32::INFINITY).hint_text("bp nt!NtCreateFile\nc\nwait-stop 300000\nk 20"));
            if ui.add_enabled(connected && state.script.is_none() && !form.text.trim().is_empty(), egui::Button::new("Rodar o texto")).clicked() {
                state.requests.push(Request::RunScript { name: "(roteiro da janela)".into(), text: form.text.clone() });
                state.focus_tab.push(Tab::Command);
                close = true;
            }
        });
        if !connected {
            ui.label(RichText::new("o roteiro precisa da conexão com o alvo: abra o OpenNT ou conecte antes (Ctrl+O)").color(colors.yellow));
        }
        if state.script.is_some() && ui.button("Parar o roteiro").clicked() {
            state.cancel = true;
        }
        if run_file && connected && state.script.is_none() {
            if form.path.trim().is_empty() {
                form.error = Some("diga o arquivo do roteiro".into());
            } else {
                let path = form.path.clone();
                state.run_script_file(&path);
                close = true;
            }
        }
        ui.separator();
        ui.label(RichText::new("Gravar os comandos num roteiro").strong());
        hint(ui, "Os comandos digitados, os botões de execução, os breakpoints pela margem e pelo painel viram linhas do roteiro (um c ganha o wait-stop quando a máquina para). O arquivo é recriado; o cabeçalho diz como rodá-lo com o cargo xtask debug --script.");
        match state.recording.clone() {
            Some((path, lines)) => {
                ui.label(mono(format!("gravando em {} ({lines} linhas)", path.display())).color(colors.red));
                if ui.button("Parar a gravação").clicked() {
                    state.requests.push(Request::StopRecording);
                    close = true;
                }
            }
            None => {
                ui.horizontal(|ui| {
                    ui.label("Arquivo:");
                    ui.add(egui::TextEdit::singleline(&mut form.record_path).font(TextStyle::Monospace).desired_width(440.0));
                    if ui.button("Gravar").clicked() {
                        if form.record_path.trim().is_empty() {
                            form.error = Some("diga o arquivo da gravação".into());
                        } else {
                            let xtask = state.launch.as_ref().map(|launch| launch.extra.clone()).unwrap_or_default();
                            state.requests.push(Request::StartRecording { path: PathBuf::from(form.record_path.trim()), xtask });
                            close = true;
                        }
                    }
                });
                let target = PathBuf::from(form.record_path.trim());
                let target = if target.is_absolute() { target } else { state.root().join(target) };
                if target.is_file() {
                    ui.label(RichText::new("o arquivo já existe e será substituído").color(colors.yellow));
                }
            }
        }
        if let Some(error) = &form.error {
            ui.separator();
            ui.label(RichText::new(error).color(colors.red));
        }
        if ui.input(|input| input.key_pressed(Key::Escape)) {
            close = true;
        }
    });
    if open && !close {
        state.script_dialog = Some(form);
    } else {
        // Os campos voltam na próxima abertura.
        state.script_memory = form;
    }
}

/// O aviso de falha no alto da janela (a conexão caiu, o QEMU terminou, a
/// abertura ou o attach falhou): a primeira linha em vermelho, o resto da
/// mensagem (como o QEMU saiu, as últimas linhas da COM1 e do xtask) e os
/// botões para continuar.
fn failure_banner(ui: &mut Ui, state: &mut UiState) {
    let Some(message) = state.failure.clone() else { return };
    let colors = palette(ui);
    let mut lines = message.lines();
    let headline = lines.next().unwrap_or("").to_string();
    let details = lines.collect::<Vec<_>>().join("\n");
    let generation = state.failure_generation;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(&headline).color(colors.red).strong());
        let retry = match &state.target {
            Some(Target::Launch(_)) => Some(("Reiniciar".to_string(), "recompila e abre o OpenNT com as mesmas opções (Ctrl+Shift+F5)".to_string())),
            Some(Target::Connect(address)) => Some((format!("Conectar de novo a {address}"), "a mesma sessão de antes, no mesmo endereço".to_string())),
            None => None,
        };
        if let Some((label, tooltip)) = retry {
            if ui.button(label).on_hover_text(tooltip).clicked() {
                state.requests.push(Request::Restart);
                state.dismissed_failure = generation;
            }
        }
        if ui.button("Abrir ou conectar...").clicked() {
            state.open_form();
        }
        if ui.button("Copiar a mensagem").clicked() {
            ui.ctx().copy_text(message.clone());
        }
        if ui.button("Fechar o aviso").clicked() {
            state.dismissed_failure = generation;
        }
    });
    if !details.trim().is_empty() {
        egui::CollapsingHeader::new("detalhes").id_salt(("kd-failure", generation)).default_open(true).show(ui, |ui| {
            egui::ScrollArea::vertical().id_salt("kd-failure-details").max_height(200.0).show(ui, |ui| {
                ui.label(mono(details.trim()));
            });
        });
    }
}

/// A janela Ajuda > Atalhos do teclado.
fn shortcuts_window(ui: &mut Ui, state: &mut UiState) {
    if !state.shortcuts_help {
        return;
    }
    let mut open = true;
    egui::Window::new("Atalhos do teclado").id(egui::Id::new("kd-shortcuts")).collapsible(false).resizable(false).default_width(520.0).anchor(Align2::RIGHT_TOP, Vec2::new(-20.0, 70.0)).open(&mut open).show(ui.ctx(), |ui| {
        egui::Grid::new("kd-shortcuts-grid").num_columns(2).striped(true).spacing([16.0, 3.0]).show(ui, |ui| {
            for (keys, action) in SHORTCUTS {
                ui.label(mono(keys).strong());
                ui.label(action);
                ui.end_row();
            }
        });
    });
    if !open || ui.input(|input| input.key_pressed(Key::Escape)) {
        state.shortcuts_help = false;
    }
}

fn menu_bar(ui: &mut Ui, state: &mut UiState, open: &[Tab]) {
    let stopped = state.ready();
    let running = state.status == Status::Running;
    egui::MenuBar::new().ui(ui, |ui| {
        let opening = matches!(state.status, Status::Launching(_) | Status::Connecting(_));
        ui.menu_button("Sessão", |ui| {
            if ui.add_enabled(!opening, egui::Button::new("Abrir ou conectar...").shortcut_text("Ctrl+O")).on_hover_text("as opções do xtask, o diretório de build ou o endereço de um QEMU aberto").clicked() {
                state.open_form();
            }
            if let Some(options) = state.launch.clone() {
                if ui.add_enabled(!opening, egui::Button::new("Abrir o OpenNT com as últimas opções")).on_hover_text(options.command_line()).clicked() {
                    state.requests.push(Request::Start(Target::Launch(options)));
                }
            }
            if ui.add_enabled(state.can_restart && !opening, egui::Button::new("Reiniciar (recompilar e abrir de novo)").shortcut_text("Ctrl+Shift+F5")).clicked() {
                state.requests.push(Request::Restart);
            }
            if ui.add_enabled(opening, egui::Button::new("Cancelar a abertura")).clicked() {
                state.cancel = true;
            }
            if ui.add(egui::Button::new("Desconectar").shortcut_text("Shift+F5")).clicked() {
                state.requests.push(Request::Disconnect);
            }
            ui.separator();
            if ui.add(egui::Button::new("Salvar ou abrir sessão...").shortcut_text("Ctrl+S")).on_hover_text("breakpoints, expressões observadas, memória e as opções de abertura num arquivo com nome").clicked() {
                state.open_sessions();
            }
            ui.separator();
            if ui.add_enabled(stopped, egui::Button::new("Recarregar símbolos")).clicked() {
                state.requests.push(Request::ReloadSymbols);
            }
        });
        ui.menu_button("Depurar", |ui| {
            if ui.add_enabled(stopped, egui::Button::new("Continuar").shortcut_text("F5")).clicked() {
                state.requests.push(Request::Go);
            }
            if ui.add_enabled(running, egui::Button::new("Parar").shortcut_text("Ctrl+B")).clicked() {
                state.request_break();
            }
            if ui.add_enabled(stopped, egui::Button::new("Entrar").shortcut_text("F11")).clicked() {
                state.requests.push(Request::StepInto);
            }
            if ui.add_enabled(stopped, egui::Button::new("Passar por cima").shortcut_text("F10")).clicked() {
                state.requests.push(Request::StepOver);
            }
            if ui.add_enabled(stopped, egui::Button::new("Sair da função").shortcut_text("Shift+F11")).clicked() {
                state.requests.push(Request::StepOut);
            }
            if ui.add_enabled(stopped, egui::Button::new("Liga/tira breakpoint").shortcut_text("F9")).clicked() {
                if let Some(address) = state.selected_code.or_else(|| current_rip(&state.snapshot)) {
                    state.requests.push(Request::ToggleBreakpoint(address));
                }
            }
            ui.separator();
            if ui.add_enabled(stopped, egui::Button::new("Analisar bugcheck (!analyze)")).clicked() {
                state.query_kind = QueryKind::Analyze;
                state.requests.push(Request::Query(QueryKind::Analyze, String::new()));
                state.focus_tab.push(Tab::NtObjects);
            }
        });
        ui.menu_button("Roteiro", |ui| {
            if ui.add(egui::Button::new("Rodar um roteiro do kd...").shortcut_text("Ctrl+R")).on_hover_text("a linguagem do --script do cargo xtask test-boot --kd=com2").clicked() {
                state.open_scripts();
            }
            if let Some(last) = state.recent_scripts.first().cloned() {
                if ui.add_enabled(state.script.is_none(), egui::Button::new(format!("Rodar de novo: {last}")).shortcut_text("Ctrl+Shift+R")).clicked() {
                    state.run_script_file(&last);
                }
            }
            if ui.add_enabled(state.script.is_some(), egui::Button::new("Parar o roteiro")).clicked() {
                state.cancel = true;
            }
            ui.separator();
            match &state.recording {
                Some((path, lines)) => {
                    if ui.add(egui::Button::new(format!("Parar a gravação ({lines} linhas em {})", path.display())).shortcut_text("Ctrl+Shift+G")).clicked() {
                        state.requests.push(Request::StopRecording);
                    }
                }
                None => {
                    if ui.button("Gravar os comandos num roteiro...").on_hover_text("os comandos digitados e os botões viram um roteiro que o test-boot roda").clicked() {
                        state.open_scripts();
                    }
                    if ui.add(egui::Button::new("Gravar já (no arquivo da janela Roteiros)").shortcut_text("Ctrl+Shift+G")).clicked() {
                        state.toggle_recording();
                    }
                }
            }
        });
        ui.menu_button("Painéis", |ui| {
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
        ui.menu_button("Aparência", |ui| {
            if ui.radio(!state.light, "Tema escuro").clicked() {
                state.light = false;
            }
            if ui.radio(state.light, "Tema claro").clicked() {
                state.light = true;
            }
        });
        ui.menu_button("Ajuda", |ui| {
            if ui.add(egui::Button::new("Atalhos do teclado").shortcut_text("F1")).clicked() {
                state.shortcuts_help = true;
            }
            if ui.add(egui::Button::new("Limpar o painel de comandos").shortcut_text("Ctrl+L")).clicked() {
                state.transcript_start = state.transcript_lines.len();
            }
        });
    });
}

/// Os ícones da barra de ferramentas (desenhados, sem fonte de ícones).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Icon {
    Go,
    Break,
    StepInto,
    StepOver,
    StepOut,
    Restart,
    Breakpoint,
    Trace,
    Theme,
    /// Abrir ou conectar (o símbolo de ligar).
    Open,
    Disconnect,
    Session,
    Script,
    Record,
    /// A gravação ligada.
    Recording,
}

fn icon_button(ui: &mut Ui, icon: Icon, enabled: bool, tooltip: &str) -> bool {
    let colors = palette(ui);
    let (rect, response) = ui.allocate_exact_size(Vec2::new(30.0, 26.0), if enabled { Sense::click() } else { Sense::hover() });
    let painter = ui.painter_at(rect);
    if enabled && response.hovered() {
        painter.rect_filled(rect, 4.0, ui.visuals().widgets.hovered.bg_fill);
    }
    let color = if !enabled {
        colors.dim.gamma_multiply(0.6)
    } else {
        match icon {
            Icon::Go | Icon::Open => colors.green,
            Icon::Break => colors.yellow,
            Icon::Breakpoint | Icon::Disconnect | Icon::Record | Icon::Recording => colors.red,
            Icon::Restart | Icon::Trace | Icon::Session | Icon::Script => colors.blue,
            _ => ui.visuals().text_color(),
        }
    };
    let stroke = Stroke::new(2.0, color);
    let center = rect.center();
    let at = |x: f32, y: f32| Pos2::new(center.x + x, center.y + y);
    let arrow = |painter: &egui::Painter, tip: Pos2, direction: Vec2| {
        let direction = direction.normalized();
        let side = Vec2::new(-direction.y, direction.x);
        painter.add(egui::Shape::convex_polygon(vec![tip, tip - direction * 6.0 + side * 4.0, tip - direction * 6.0 - side * 4.0], color, Stroke::NONE));
    };
    match icon {
        Icon::Go => {
            painter.add(egui::Shape::convex_polygon(vec![at(-5.0, -7.0), at(7.0, 0.0), at(-5.0, 7.0)], color, Stroke::NONE));
        }
        Icon::Break => {
            painter.rect_filled(egui::Rect::from_min_size(at(-6.0, -7.0), Vec2::new(4.0, 14.0)), 1.0, color);
            painter.rect_filled(egui::Rect::from_min_size(at(2.0, -7.0), Vec2::new(4.0, 14.0)), 1.0, color);
        }
        Icon::StepInto => {
            painter.line_segment([at(0.0, -8.0), at(0.0, 2.0)], stroke);
            arrow(&painter, at(0.0, 4.0), Vec2::new(0.0, 1.0));
            painter.circle_filled(at(0.0, 8.0), 2.0, color);
        }
        Icon::StepOver => {
            let points: Vec<Pos2> = (0..=12).map(|step| {
                let angle = std::f32::consts::PI * (1.0 + step as f32 / 12.0);
                at(7.0 * angle.cos(), 1.0 + 6.0 * angle.sin())
            }).collect();
            painter.add(egui::Shape::line(points, stroke));
            arrow(&painter, at(7.5, 3.0), Vec2::new(0.0, 1.0));
            painter.circle_filled(at(0.0, 8.0), 2.0, color);
        }
        Icon::StepOut => {
            painter.line_segment([at(0.0, 6.0), at(0.0, -4.0)], stroke);
            arrow(&painter, at(0.0, -8.0), Vec2::new(0.0, -1.0));
            painter.line_segment([at(-6.0, 8.0), at(6.0, 8.0)], stroke);
        }
        Icon::Restart => {
            let points: Vec<Pos2> = (0..=16).map(|step| {
                let angle = 0.6 + 5.0 * step as f32 / 16.0;
                at(7.0 * angle.cos(), 7.0 * angle.sin())
            }).collect();
            let end = *points.last().unwrap();
            painter.add(egui::Shape::line(points, stroke));
            arrow(&painter, end + Vec2::new(2.0, 2.0), Vec2::new(1.0, 1.4));
        }
        Icon::Breakpoint => {
            painter.circle_filled(center, 6.5, color);
        }
        Icon::Trace => {
            for (index, width) in [12.0, 8.0, 12.0].iter().enumerate() {
                let y = -6.0 + index as f32 * 6.0;
                painter.line_segment([at(-6.0, y), at(-6.0 + width, y)], stroke);
            }
            arrow(&painter, at(8.0, 6.0), Vec2::new(1.0, 0.0));
        }
        Icon::Open => {
            // Um arco aberto em cima e o traço.
            let points: Vec<Pos2> = (0..=20)
                .map(|step| {
                    let angle = -std::f32::consts::FRAC_PI_2 + 0.7 + (2.0 * std::f32::consts::PI - 1.4) * step as f32 / 20.0;
                    at(7.0 * angle.cos(), 1.0 + 7.0 * angle.sin())
                })
                .collect();
            painter.add(egui::Shape::line(points, stroke));
            painter.line_segment([at(0.0, -8.0), at(0.0, 0.0)], stroke);
        }
        Icon::Disconnect => {
            painter.rect_filled(egui::Rect::from_center_size(center, Vec2::splat(11.0)), 2.0, color);
        }
        Icon::Session => {
            // Um disquete: o corpo, a janela de cima e a etiqueta.
            painter.rect_stroke(egui::Rect::from_center_size(center, Vec2::splat(14.0)), 2.0, Stroke::new(1.5, color), egui::StrokeKind::Inside);
            painter.rect_filled(egui::Rect::from_min_size(at(-4.0, -7.0), Vec2::new(8.0, 4.5)), 0.0, color);
            painter.line_segment([at(-4.0, 3.0), at(4.0, 3.0)], Stroke::new(1.5, color));
        }
        Icon::Script => {
            // Uma página com linhas e o triângulo de rodar.
            painter.rect_stroke(egui::Rect::from_center_size(at(-2.5, 0.0), Vec2::new(11.0, 15.0)), 1.0, Stroke::new(1.5, color), egui::StrokeKind::Inside);
            for index in 0..3 {
                let y = -4.0 + index as f32 * 3.5;
                painter.line_segment([at(-6.0, y), at(0.5, y)], Stroke::new(1.2, color));
            }
            painter.add(egui::Shape::convex_polygon(vec![at(3.0, 1.5), at(9.5, 5.0), at(3.0, 8.5)], color, Stroke::NONE));
        }
        Icon::Record | Icon::Recording => {
            painter.circle_stroke(center, 7.0, Stroke::new(1.5, color));
            painter.circle_filled(center, if icon == Icon::Recording { 5.0 } else { 3.0 }, color);
        }
        Icon::Theme => {
            painter.circle_stroke(center, 6.5, stroke);
            painter.add(egui::Shape::convex_polygon((0..=12).map(|step| {
                let angle = std::f32::consts::FRAC_PI_2 + std::f32::consts::PI * step as f32 / 12.0;
                at(6.5 * angle.cos(), 6.5 * angle.sin())
            }).collect(), color, Stroke::NONE));
        }
    }
    let response = response.on_hover_text(tooltip);
    enabled && response.clicked()
}

fn toolbar(ui: &mut Ui, state: &mut UiState) {
    let stopped = state.ready();
    let running = state.status == Status::Running;
    let colors = palette(ui);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        if icon_button(ui, Icon::Go, stopped, "Continuar (F5)") {
            state.requests.push(Request::Go);
        }
        if icon_button(ui, Icon::Break, running, "Parar a máquina (Ctrl+B)") {
            state.request_break();
        }
        ui.add_space(6.0);
        if icon_button(ui, Icon::StepInto, stopped, "Entrar: um passo, entra no call (F11)") {
            state.requests.push(Request::StepInto);
        }
        if icon_button(ui, Icon::StepOver, stopped, "Passar por cima do call (F10)") {
            state.requests.push(Request::StepOver);
        }
        if icon_button(ui, Icon::StepOut, stopped, "Sair da função: até o retorno (Shift+F11)") {
            state.requests.push(Request::StepOut);
        }
        ui.add_space(6.0);
        if icon_button(ui, Icon::Breakpoint, stopped, "Liga/tira o breakpoint na linha escolhida da desmontagem ou no RIP (F9)") {
            if let Some(address) = state.selected_code.or_else(|| current_rip(&state.snapshot)) {
                state.requests.push(Request::ToggleBreakpoint(address));
            }
        }
        if icon_button(ui, Icon::Trace, stopped, "Rastro de instruções (painel Rastro)") {
            state.focus_tab.push(Tab::Trace);
        }
        let opening = matches!(state.status, Status::Launching(_) | Status::Connecting(_));
        if icon_button(ui, Icon::Restart, state.can_restart && !opening, "Reiniciar: fecha o QEMU, recompila e abre de novo (Ctrl+Shift+F5)") {
            state.requests.push(Request::Restart);
        }
        ui.add_space(6.0);
        if icon_button(ui, Icon::Open, !opening, "Abrir o OpenNT com outras opções do xtask ou conectar a um QEMU aberto (Ctrl+O)") {
            state.open_form();
        }
        if icon_button(ui, Icon::Disconnect, matches!(state.status, Status::Stopped | Status::Running), "Desconectar (Shift+F5): um QEMU aberto pelo depurador fecha; um de fora segue rodando") {
            state.requests.push(Request::Disconnect);
        }
        if icon_button(ui, Icon::Session, true, "Salvar ou abrir uma sessão: breakpoints, expressões, memória e opções de abertura (Ctrl+S)") {
            state.open_sessions();
        }
        if icon_button(ui, Icon::Script, true, "Rodar um roteiro do kd (Ctrl+R); Ctrl+Shift+R roda de novo o último") {
            state.open_scripts();
        }
        let (icon, tooltip) = match &state.recording {
            Some((path, lines)) => (Icon::Recording, format!("Parar a gravação: {lines} linhas em {} (Ctrl+Shift+G)", path.display())),
            None => (Icon::Record, "Gravar os comandos num roteiro que o test-boot roda (Ctrl+Shift+G)".to_string()),
        };
        if icon_button(ui, icon, true, &tooltip) {
            state.toggle_recording();
        }
        ui.add_space(6.0);
        if icon_button(ui, Icon::Theme, true, "Alterna o tema claro e o escuro") {
            state.light = !state.light;
        }
        ui.separator();
        let connected = matches!(state.status, Status::Stopped | Status::Running);
        let opening = matches!(state.status, Status::Launching(_) | Status::Connecting(_));
        if opening {
            if ui.button("Cancelar").on_hover_text("para a abertura: o cargo, o build e o QEMU terminam").clicked() {
                state.cancel = true;
            }
        } else if !connected {
            if let Some(options) = state.launch.clone() {
                if ui.button("Abrir o OpenNT").on_hover_text(options.command_line()).clicked() {
                    state.requests.push(Request::Start(Target::Launch(options)));
                }
            }
            if ui.button("Opções...").on_hover_text("abrir com outras opções do xtask ou conectar a um QEMU aberto (Ctrl+O)").clicked() {
                state.open_form();
            }
            let response = ui.add(egui::TextEdit::singleline(&mut state.connect_address).desired_width(140.0).font(TextStyle::Monospace).hint_text("127.0.0.1:1234"));
            let submit = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
            if ui.button("Conectar").on_hover_text("HOST:PORTA, a porta ou a linha KD_READY do xtask").clicked() || submit {
                state.connect_to_typed_address();
            }
        }
        ui.separator();
        let (color, text) = match &state.status {
            Status::Idle => (colors.dim, "sem alvo".to_string()),
            Status::Launching(line) => (colors.yellow, format!("abrindo: {line}")),
            Status::Connecting(address) => (colors.yellow, format!("conectando a {address}")),
            Status::Running => (colors.green, "rodando".to_string()),
            Status::Stopped => (colors.red, "parado".to_string()),
            Status::Disconnected(reason) => (colors.dim, format!("desconectado: {}", reason.lines().next().unwrap_or(""))),
        };
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 5.0, color);
        ui.label(RichText::new(text).color(color).strong());
    });
}

/// O processador mostrado (o da parada ou o escolhido).
fn shown_processor(snapshot: &Snapshot) -> Option<&opennt_kd::monitor::Processor> {
    let number = match snapshot.view {
        View::Cpu(thread) => Some(thread.saturating_sub(1)),
        _ => snapshot.stop_processor,
    }?;
    snapshot.processors.iter().find(|processor| processor.number == number)
}

fn status_bar(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    ui.horizontal(|ui| {
        let snapshot = &state.snapshot;
        let connection = match &state.status {
            Status::Stopped | Status::Running => "conectado",
            Status::Launching(_) | Status::Connecting(_) => "conectando",
            _ => "desconectado",
        };
        ui.label(RichText::new(connection).color(colors.dim));
        ui.separator();
        let target = match state.status {
            Status::Stopped => RichText::new("parado").color(colors.red),
            Status::Running => RichText::new("rodando").color(colors.green),
            _ => RichText::new("-").color(colors.dim),
        };
        ui.label(target.strong());
        if state.status == Status::Stopped {
            if let Some(processor) = shown_processor(snapshot) {
                ui.separator();
                ui.label(mono(format!("CPU {}", processor.number)));
                ui.separator();
                ui.label(mono(format!("thread {:#x}", processor.thread)));
                ui.separator();
                ui.label(mono(format!("processo {}", if processor.process.is_empty() { "-" } else { &processor.process })));
                ui.separator();
                ui.label(mono(format!("IRQL {}", processor.irql)));
            }
            if !snapshot.stop.is_empty() {
                ui.separator();
                ui.label(mono(snapshot.stop.split(" [").next().unwrap_or("")).color(colors.dim));
            }
        }
        if let Some(progress) = &state.script {
            ui.separator();
            ui.label(RichText::new(format!("roteiro {}/{} (linha {})", progress.index, progress.total, progress.line)).color(colors.yellow).strong()).on_hover_text(&progress.name);
            if ui.small_button("parar").on_hover_text("para o roteiro entre uma linha e outra (ou na espera)").clicked() {
                state.cancel = true;
            }
        }
        if let Some((path, lines)) = &state.recording {
            ui.separator();
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(12.0), Sense::hover());
            ui.painter().circle_filled(rect.center(), 4.5, colors.red);
            ui.label(RichText::new(format!("gravando ({lines} linhas)")).color(colors.red)).on_hover_text(path.display().to_string());
        }
        if !state.activity.is_empty() {
            ui.separator();
            ui.spinner();
            ui.label(RichText::new(&state.activity).color(colors.yellow));
        }
    });
}

struct Viewer<'a> {
    state: &'a mut UiState,
}

impl TabViewer for Viewer<'_> {
    type Tab = Tab;

    fn id(&mut self, tab: &mut Tab) -> egui::Id {
        egui::Id::new(("kd-tab", *tab))
    }

    fn title(&mut self, tab: &mut Tab) -> WidgetText {
        tab.title().into()
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Tab) {
        let state = &mut *self.state;
        match tab {
            Tab::Command => command_panel(ui, state),
            Tab::Disassembly => disassembly_panel(ui, state),
            Tab::Source => source_panel(ui, state),
            Tab::Registers => views::registers_panel(ui, state),
            Tab::Watch => watch_panel(ui, state),
            Tab::Locals => locals_panel(ui, state),
            Tab::Memory => views::memory_panel(ui, state),
            Tab::CallStack => views::call_stack_panel(ui, state),
            Tab::Modules => views::modules_panel(ui, state),
            Tab::Processes => views::processes_panel(ui, state),
            Tab::Threads => views::threads_panel(ui, state),
            Tab::Breakpoints => views::breakpoints_panel(ui, state),
            Tab::NtObjects => nt_objects_panel(ui, state),
            Tab::Trace => trace_panel(ui, state),
            Tab::Bugcheck => bugcheck_panel(ui, state),
            Tab::DbgPrint => log_panel(ui, &state.console, "dbgprint", "(nenhuma saída do DbgPrint ainda)"),
            Tab::Serial => views::serial_panel(ui, state),
        }
    }

    fn scroll_bars(&self, _tab: &Tab) -> [bool; 2] {
        [false, false]
    }
}

/// Rola só na vertical até a linha (centralizada), com a margem esquerda
/// à vista (o `scroll_to_me` centraliza também na horizontal).
fn scroll_vertically_to(ui: &Ui, rect: egui::Rect) {
    let left = ui.max_rect().left();
    ui.scroll_to_rect(egui::Rect::from_x_y_ranges(left..=left + 1.0, rect.y_range()), Some(Align::Center));
}

fn row_height(ui: &Ui) -> f32 {
    ui.text_style_height(&TextStyle::Monospace) + 3.0
}

fn hint(ui: &mut Ui, text: &str) {
    let colors = palette(ui);
    ui.label(RichText::new(text).color(colors.dim));
}

fn log_panel(ui: &mut Ui, log: &LogLines, id: &str, empty: &str) {
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
        // O fim do caminho do Rust (`run_kernel_tasks` acha `kernel::...::run_kernel_tasks`).
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

fn command_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let suggestions_height = if state.suggestions.is_empty() { 0.0 } else { (state.suggestions.len().min(8) as f32) * row_height(ui) + 8.0 };
    let input_height = row_height(ui) + 14.0 + suggestions_height;
    let output_height = (ui.available_height() - input_height).max(40.0);
    // Rolagem virtual: só as linhas à vista são desenhadas (a saída do
    // build e de um roteiro longo têm milhares).
    let height = row_height(ui);
    if state.transcript.is_empty() {
        hint(ui, "comandos do WinDbg e do cargo xtask debug (help): k, r, db/dq, u, bp, bl, bc, g, p, t, gu, lm, dt, !process, !thread, !irp, !devobj, !drvobj, !object, !analyze, trace... Tab completa comandos e símbolos. Menu Roteiro: rodar e gravar roteiros do kd.");
        let lines = state.launch_log.count();
        egui::ScrollArea::both().id_salt("transcript").auto_shrink([false, false]).stick_to_bottom(true).max_height((output_height - height * 2.0).max(20.0)).show_rows(ui, height, lines, |ui, range| {
            for index in range {
                ui.label(mono(state.launch_log.line(index)).color(colors.dim));
            }
        });
    } else {
        let mut copy: Option<Option<usize>> = None;
        let start = state.transcript_start.min(state.transcript_lines.len());
        egui::ScrollArea::both().id_salt("transcript").auto_shrink([false, false]).stick_to_bottom(true).max_height(output_height).show_rows(ui, height, state.transcript_lines.len() - start, |ui, range| {
            for index in range {
                let line = &state.transcript_lines[start + index];
                let color = match line.kind {
                    LineKind::Input => colors.blue,
                    LineKind::Output => ui.visuals().text_color(),
                    LineKind::Error => colors.red,
                };
                let response = ui.add(egui::Label::new(mono(&line.text).color(color)).sense(Sense::click()));
                response.context_menu(|ui| {
                    if ui.button("Copiar este comando e a saída").clicked() {
                        copy = Some(Some(line.entry));
                        ui.close();
                    }
                    if ui.button("Copiar o painel inteiro").clicked() {
                        copy = Some(None);
                        ui.close();
                    }
                });
            }
        });
        if let Some(which) = copy {
            ui.ctx().copy_text(transcript_text(&state.transcript, which));
        }
    }
    // Tab: completa (antes do campo, que usaria a tecla para trocar o foco).
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
        egui::ScrollArea::vertical().id_salt("suggestions").max_height(suggestions_height).show(ui, |ui| {
            let mut chosen = None;
            for name in state.suggestions.iter().take(40) {
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
        let prompt = if state.script.is_some() {
            "kd (roteiro)>"
        } else if state.busy() {
            "kd (ocupado)>"
        } else if state.status == Status::Stopped {
            "kd>"
        } else {
            "kd (rodando)>"
        };
        ui.label(mono(prompt).color(colors.blue)).on_hover_text(if state.busy() { "o backend está ocupado: o comando espera na fila e roda quando ele voltar" } else { "Enter roda; setas trazem o histórico; Tab completa" });
        let response = ui.add(egui::TextEdit::singleline(&mut state.command).id(egui::Id::new("kd-command")).font(TextStyle::Monospace).desired_width(f32::INFINITY).hint_text("comando (help; Tab completa)"));
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

fn move_cursor_to_end(ui: &Ui, id: egui::Id, length: usize) {
    if let Some(mut text_state) = egui::text_edit::TextEditState::load(ui.ctx(), id) {
        text_state.cursor.set_char_range(Some(egui::text::CCursorRange::one(egui::text::CCursor::new(length))));
        text_state.store(ui.ctx(), id);
    }
}

/// O RIP da visão (o do processador ou da thread escolhida).
fn current_rip(snapshot: &Snapshot) -> Option<u64> {
    snapshot.registers.iter().find(|row| row.name == "rip").and_then(|row| row.value)
}

fn disassembly_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    ui.horizontal(|ui| {
        ui.label("Endereço:");
        let response = ui.add(egui::TextEdit::singleline(&mut state.code_address).font(TextStyle::Monospace).desired_width(260.0).hint_text("expressão ou símbolo"));
        if ui.button("Ir").clicked() || (response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter))) {
            state.requests.push(Request::ShowCode(state.code_address.clone()));
        }
        if ui.button("Seguir o RIP").clicked() {
            state.code_address.clear();
            state.selected_code = None;
            state.requests.push(Request::ShowCode(String::new()));
        }
    });
    ui.separator();
    let snapshot = Arc::clone(&state.snapshot);
    if let Some(error) = &snapshot.code.error {
        ui.label(RichText::new(error).color(colors.red));
    }
    if snapshot.code.lines.is_empty() {
        hint(ui, "sem código (a máquina não parou ainda)");
        return;
    }
    let rip = current_rip(&snapshot);
    let scroll = state.scrolled_code != snapshot.generation;
    state.scrolled_code = snapshot.generation;
    let height = row_height(ui);
    let font = FontId::monospace(ui.text_style_height(&TextStyle::Monospace) - 1.0);
    egui::ScrollArea::both().id_salt("code").auto_shrink([false, false]).show(ui, |ui| {
        for line in &snapshot.code.lines {
            if let Some(label) = &line.label {
                ui.label(mono(format!("{label}:")).color(colors.blue).strong());
            }
            let breakpoint = snapshot.breakpoints.iter().find(|breakpoint| breakpoint.address == line.address && !breakpoint.pending && matches!(breakpoint.kind, BreakpointKind::Software | BreakpointKind::Hardware));
            let selected = state.selected_code == Some(line.address);
            let response = ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                let (gutter, click) = ui.allocate_exact_size(Vec2::new(32.0, height), Sense::click());
                if click.clicked() {
                    state.requests.push(Request::ToggleBreakpoint(line.address));
                }
                let click = click.on_hover_text("clique: liga/tira o breakpoint (F9)");
                let painter = ui.painter();
                if let Some(breakpoint) = breakpoint {
                    let center = gutter.left_center() + Vec2::new(8.0, 0.0);
                    if breakpoint.enabled {
                        painter.circle_filled(center, 5.0, colors.red);
                    } else {
                        painter.circle_stroke(center, 5.0, Stroke::new(1.5, colors.red));
                    }
                } else if click.hovered() {
                    painter.circle_stroke(gutter.left_center() + Vec2::new(8.0, 0.0), 5.0, Stroke::new(1.0, colors.dim));
                }
                if Some(line.address) == rip {
                    painter.text(gutter.left_center() + Vec2::new(18.0, 0.0), Align2::LEFT_CENTER, "=>", font.clone(), colors.yellow);
                } else if line.address == snapshot.code.focus {
                    painter.text(gutter.left_center() + Vec2::new(18.0, 0.0), Align2::LEFT_CENTER, "->", font.clone(), colors.green);
                }
                let mut text = format!("{}  {:<16} {}", hex(line.address), line.bytes.chars().take(16).collect::<String>(), line.text);
                if let Some(comment) = &line.comment {
                    text.push_str(&format!("  ; {comment}"));
                }
                let color = if Some(line.address) == rip { colors.yellow } else { ui.visuals().text_color() };
                let label = ui.add(egui::Label::new(mono(text).color(color)).sense(Sense::click()).extend());
                if label.clicked() {
                    state.selected_code = Some(line.address);
                }
                // Botão direito: breakpoint, executar até aqui, memória.
                views::code_line_menu(&label, state, line.address, line.target);
                if let Some(target) = line.target {
                    if label.double_clicked() {
                        state.code_address = format!("{target:#x}");
                        state.requests.push(Request::ShowCode(state.code_address.clone()));
                    }
                    label.on_hover_text("clique: escolhe a linha (F9); clique duplo: vai ao destino");
                }
            });
            let rect = response.response.rect;
            if line.address == snapshot.code.focus {
                ui.painter().rect_filled(rect, 0.0, colors.focus);
                if scroll {
                    scroll_vertically_to(ui, rect);
                }
            } else if selected {
                ui.painter().rect_stroke(rect, 0.0, Stroke::new(1.0, colors.blue), egui::StrokeKind::Inside);
            }
        }
    });
}

fn source_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let Some(source) = &snapshot.source else {
        hint(ui, snapshot.source_error.as_deref().unwrap_or("sem linha de código"));
        return;
    };
    let root = crate::workspace_root();
    let file = std::path::Path::new(&source.file).strip_prefix(&root).map_or_else(|_| source.file.clone(), |relative| relative.display().to_string());
    ui.label(mono(format!("{file}:{}", source.line)).color(colors.blue));
    ui.separator();
    let scroll = state.scrolled_source != snapshot.generation;
    state.scrolled_source = snapshot.generation;
    let font = FontId::monospace(ui.text_style_height(&TextStyle::Monospace) - 1.0);
    egui::ScrollArea::both().id_salt("source").auto_shrink([false, false]).show(ui, |ui| {
        let current = source.line as usize;
        let first = current.saturating_sub(400).max(1);
        let last = (current + 400).min(source.text.len());
        for number in first..=last {
            let Some(text) = source.text.get(number - 1) else { break };
            let is_current = number == current;
            let line = mono(format!("   {number:>5}  {text}")).color(if is_current { colors.yellow } else { ui.visuals().text_color() });
            let response = ui.add(egui::Label::new(line).extend());
            if is_current {
                ui.painter().rect_filled(response.rect, 0.0, colors.focus);
                ui.painter().text(response.rect.left_center(), Align2::LEFT_CENTER, "=>", font.clone(), colors.yellow);
                if scroll {
                    scroll_vertically_to(ui, response.rect);
                }
            }
        }
    });
}

/// Uma árvore de campos tipados (a observação e a vista de struct).
fn typed_tree(ui: &mut Ui, state: &mut UiState, key: (u64, u32), depth: usize) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    match snapshot.typed.get(&key) {
        None => hint(ui, "lendo..."),
        Some(Err(error)) => {
            ui.label(RichText::new(error).color(colors.red));
        }
        Some(Ok(fields)) => {
            for field in fields {
                let line = format!("+{:#05x} {:<26} {:<22} {}", field.offset, field.name, field.type_name, field.value);
                if field.expandable && depth < 6 {
                    let child = (field.address, field.ty);
                    let response = egui::CollapsingHeader::new(mono(line)).id_salt(("typed", key, child, depth)).show(ui, |ui| {
                        typed_tree(ui, state, child, depth + 1);
                    });
                    if response.openness > 0.0 {
                        state.expanded.insert(child);
                    } else {
                        state.expanded.remove(&child);
                    }
                } else {
                    ui.horizontal(|ui| {
                        ui.add_space(18.0);
                        ui.label(mono(line));
                    });
                }
            }
        }
    }
}

fn watch_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    ui.horizontal(|ui| {
        let response = ui.add(egui::TextEdit::singleline(&mut state.watch_input).font(TextStyle::Monospace).desired_width(ui.available_width() - 90.0).hint_text("expressão: @rcx, poi(@rsp+8), (_IRP*)@rdx, ((_DEVICE_OBJECT*)x)->DriverObject"));
        if (ui.button("Observar").clicked() || (response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)))) && !state.watch_input.trim().is_empty() {
            state.watches.push(state.watch_input.trim().to_string());
            state.watch_input.clear();
        }
    });
    ui.separator();
    let snapshot = Arc::clone(&state.snapshot);
    if state.watches.is_empty() {
        hint(ui, "nenhuma expressão. Um cast para um tipo do NT mostra a struct campo a campo (os tipos vêm do PDB do ntoskrnl).");
    }
    if !snapshot.types_note.is_empty() {
        hint(ui, &snapshot.types_note);
    }
    let mut remove = None;
    egui::ScrollArea::both().id_salt("watch").auto_shrink([false, false]).show(ui, |ui| {
        for (index, expression) in state.watches.clone().iter().enumerate() {
            let row = snapshot.watches.iter().find(|row| &row.expression == expression);
            ui.horizontal(|ui| {
                if ui.small_button("x").on_hover_text("tira a expressão").clicked() {
                    remove = Some(index);
                }
                ui.label(mono(expression).color(colors.blue));
                match row.map(|row| &row.value) {
                    Some(Ok(value)) => {
                        ui.label(mono(value));
                    }
                    Some(Err(error)) => {
                        ui.label(RichText::new(error).color(colors.red));
                    }
                    None => hint(ui, "(na próxima parada)"),
                }
                if let Some(row) = row {
                    if !row.type_name.is_empty() {
                        ui.label(RichText::new(&row.type_name).color(colors.dim));
                    }
                }
            });
            if let Some(key) = row.and_then(|row| row.typed) {
                egui::CollapsingHeader::new(mono(format!("campos em {:#x}", key.0))).id_salt(("watch-tree", index, key)).default_open(true).show(ui, |ui| {
                    typed_tree(ui, state, key, 0);
                });
            }
        }
    });
    if let Some(index) = remove {
        state.watches.remove(index);
    }
}

fn locals_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    if snapshot.locals.is_empty() {
        hint(ui, if snapshot.locals_note.is_empty() { "sem variáveis locais" } else { &snapshot.locals_note });
        return;
    }
    egui::ScrollArea::both().id_salt("locals").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("locals-grid").num_columns(4).striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
            for title in ["nome", "tipo", "onde", "valor"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for local in &snapshot.locals {
                ui.label(mono(&local.name).color(if local.parameter { colors.blue } else { ui.visuals().text_color() }));
                ui.label(mono(&local.type_name).color(colors.dim));
                ui.label(mono(&local.location));
                ui.label(mono(&local.value));
                ui.end_row();
            }
        });
        hint(ui, "azul: parâmetro");
    });
}

/// Uma linha de texto com os endereços clicáveis (memória, desmontagem e
/// as vistas do NT pelo menu do botão direito).
fn linked_line(ui: &mut Ui, state: &mut UiState, line: &str, colors: Palette) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        let mut rest = line;
        while let Some(start) = rest.find("0x") {
            let (before, tail) = rest.split_at(start);
            let length = 2 + tail[2..].chars().take_while(|character| character.is_ascii_hexdigit()).count();
            let token = &tail[..length];
            if !before.is_empty() {
                ui.label(mono(before));
            }
            match opennt_kd::parse_number(token).filter(|&value| value > 0xffff) {
                Some(value) => {
                    let response = ui.add(egui::Label::new(mono(token).color(colors.blue)).sense(Sense::click())).on_hover_text("clique: memória; botão direito: abrir como objeto do NT");
                    if response.clicked() {
                        state.memory_address = format!("{value:#x}");
                        state.requests.push(Request::ShowMemory(state.memory_address.clone()));
                        state.focus_tab.push(Tab::Memory);
                    }
                    response.context_menu(|ui| {
                        let mut open = |kind: QueryKind| {
                            state.query_kind = kind;
                            state.query_argument = format!("{value:#x}");
                            state.requests.push(Request::Query(kind, state.query_argument.clone()));
                        };
                        if ui.button("como IRP").clicked() {
                            open(QueryKind::Irp);
                            ui.close();
                        }
                        if ui.button("como DEVICE_OBJECT").clicked() {
                            open(QueryKind::Device);
                            ui.close();
                        }
                        if ui.button("como DRIVER_OBJECT").clicked() {
                            open(QueryKind::Driver);
                            ui.close();
                        }
                        if ui.button("como ETHREAD").clicked() {
                            open(QueryKind::Thread);
                            ui.close();
                        }
                        if ui.button("como EPROCESS").clicked() {
                            open(QueryKind::Process);
                            ui.close();
                        }
                        if ui.button("na desmontagem").clicked() {
                            state.code_address = format!("{value:#x}");
                            state.requests.push(Request::ShowCode(state.code_address.clone()));
                            state.focus_tab.push(Tab::Disassembly);
                            ui.close();
                        }
                        if ui.button("observar").clicked() {
                            state.watches.push(format!("{value:#x}"));
                            ui.close();
                        }
                    });
                }
                None => {
                    ui.label(mono(token));
                }
            }
            rest = &tail[length..];
        }
        if !rest.is_empty() {
            ui.label(mono(rest));
        }
    });
}

fn nt_objects_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let stopped = state.status == Status::Stopped;
    ui.horizontal_wrapped(|ui| {
        egui::ComboBox::from_id_salt("query-kind").selected_text(state.query_kind.label()).width(220.0).show_ui(ui, |ui| {
            for kind in QueryKind::ALL {
                ui.selectable_value(&mut state.query_kind, kind, kind.label());
            }
        });
        let hint_text = match state.query_kind {
            QueryKind::Process => "PID ou EPROCESS (vazio: o corrente)",
            QueryKind::Thread => "ETHREAD (vazio: a corrente)",
            QueryKind::Irp => "endereço do IRP",
            QueryKind::Device => "endereço ou \\Device\\Nome",
            QueryKind::Driver => "endereço, \\Driver\\Nome ou Nome",
            QueryKind::Object => "\\caminho\\do\\objeto",
            QueryKind::Handle => "PID handle",
            QueryKind::Module => "nome do módulo",
            QueryKind::Type => "_IRP endereço",
            QueryKind::Analyze => "",
        };
        let response = ui.add(egui::TextEdit::singleline(&mut state.query_argument).font(TextStyle::Monospace).desired_width(300.0).hint_text(hint_text));
        if (ui.add_enabled(stopped, egui::Button::new("Consultar")).clicked() || (stopped && response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)))) && (!state.query_argument.trim().is_empty() || matches!(state.query_kind, QueryKind::Process | QueryKind::Thread | QueryKind::Analyze)) {
            state.requests.push(Request::Query(state.query_kind, state.query_argument.trim().to_string()));
        }
    });
    ui.separator();
    let snapshot = Arc::clone(&state.snapshot);
    let Some(query) = &snapshot.query else {
        hint(ui, "consultas do NT pelo depurador do OpenNT: processo, thread (estado, motivo da espera, pilha), IRP (pilha de E/S), dispositivo (pilha de dispositivos), driver (tabela de despacho), objeto, handle, módulo e qualquer struct do PDB do ntoskrnl. Os endereços azuis abrem com o botão direito.");
        return;
    };
    ui.label(mono(query.kind.command(&query.argument)).color(colors.blue));
    egui::ScrollArea::both().id_salt("nt-objects").auto_shrink([false, false]).show(ui, |ui| match &query.text {
        Ok(text) => {
            for line in text.lines() {
                linked_line(ui, state, line, colors);
            }
        }
        Err(error) => {
            ui.label(RichText::new(error).color(colors.red));
        }
    });
}

fn bugcheck_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let Some(analysis) = &snapshot.bugcheck else {
        hint(ui, "nenhum bugcheck. Numa parada pelo KeBugCheckEx este painel abre sozinho com o código, os parâmetros explicados, o driver culpado e a pilha.");
        return;
    };
    egui::ScrollArea::both().id_salt("bugcheck").auto_shrink([false, false]).show(ui, |ui| {
        ui.label(RichText::new(format!("{}  ({:#010x})", analysis.name, analysis.code)).color(colors.red).strong().size(20.0));
        ui.label(&analysis.summary);
        ui.add_space(6.0);
        match &analysis.blamed {
            Some((module, reason)) => {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Provável causa:").strong());
                    ui.label(RichText::new(module).color(colors.yellow).strong());
                    ui.label(RichText::new(format!("({reason})")).color(colors.dim));
                });
            }
            None => hint(ui, "nenhum driver fora do kernel na pilha nem nos parâmetros"),
        }
        ui.add_space(6.0);
        ui.label(RichText::new("Parâmetros").strong());
        egui::Grid::new("bugcheck-parameters").num_columns(4).striped(true).spacing([12.0, 3.0]).show(ui, |ui| {
            for (index, parameter) in analysis.parameters.iter().enumerate() {
                ui.label(mono(format!("{}", index + 1)).color(colors.dim));
                ui.label(mono(hex(parameter.value)));
                ui.label(&parameter.label);
                ui.label(mono(&parameter.note).color(colors.blue));
                ui.end_row();
            }
        });
        ui.add_space(6.0);
        ui.label(RichText::new("Pilha").strong());
        for (depth, (address, name)) in analysis.stack.iter().enumerate() {
            let blamed = analysis.blamed.as_ref().is_some_and(|(module, _)| name.starts_with(&format!("{module}!")) || name.starts_with(&format!("{module}+")));
            let text = mono(format!("{depth:02} {} {name}", hex(*address)));
            ui.label(if blamed { text.color(colors.yellow).strong() } else { text });
        }
    });
}

/// As linhas do rastro que passam pelo filtro (símbolo, módulo ou
/// instrução), guardadas até o rastro ou o filtro mudar.
fn trace_rows(state: &mut UiState, trace: &TraceView) {
    let key = (state.trace_generation, state.trace_filter.clone());
    if state.trace_rows_key == key {
        return;
    }
    state.trace_rows_key = key;
    let filter = state.trace_filter.trim().to_ascii_lowercase();
    if filter.is_empty() {
        state.trace_rows = (0..trace.trace.len()).collect();
        return;
    }
    let matching: std::collections::HashSet<u64> = trace
        .info
        .iter()
        .filter(|(_, info)| info.symbol.to_ascii_lowercase().contains(&filter) || info.module.to_ascii_lowercase().contains(&filter) || info.text.to_ascii_lowercase().contains(&filter))
        .map(|(rip, _)| *rip)
        .collect();
    state.trace_rows = trace.trace.records.iter().enumerate().filter(|(_, record)| matching.contains(&record.rip)).map(|(index, _)| index).collect();
}

fn trace_options(state: &UiState) -> TraceOptions {
    let mut options = TraceOptions { count: state.trace_count.trim().parse().unwrap_or(2000), over_calls: state.trace_over, ..Default::default() };
    match state.trace_mode {
        TraceMode::Count => {}
        TraceMode::Until => options.until = state.trace_argument.trim().to_string(),
        TraceMode::Return => options.until_return = true,
        TraceMode::Enter => options.enter_module = state.trace_argument.trim().to_string(),
        TraceMode::Leave => options.leave_module = state.trace_argument.trim().to_string(),
    }
    options.skip_modules = state.trace_skip.split([',', ' ']).filter(|name| !name.trim().is_empty()).map(|name| name.trim().to_string()).collect();
    if let Some((expression, size)) = state.trace_watch.rsplit_once(':').and_then(|(expression, size)| Some((expression.to_string(), size.trim().parse::<u64>().ok()?))) {
        options.watch = expression;
        options.watch_size = size;
    } else if !state.trace_watch.trim().is_empty() {
        options.watch = state.trace_watch.trim().to_string();
    }
    options
}

fn trace_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let stopped = state.status == Status::Stopped;
    ui.horizontal_wrapped(|ui| {
        egui::ComboBox::from_id_salt("trace-mode").selected_text(state.trace_mode.label()).show_ui(ui, |ui| {
            for mode in TraceMode::ALL {
                ui.selectable_value(&mut state.trace_mode, mode, mode.label());
            }
        });
        if matches!(state.trace_mode, TraceMode::Until | TraceMode::Enter | TraceMode::Leave) {
            ui.add(egui::TextEdit::singleline(&mut state.trace_argument).font(TextStyle::Monospace).desired_width(200.0).hint_text(if state.trace_mode == TraceMode::Until { "endereço ou símbolo" } else { "módulo" }));
        }
        ui.label("limite:");
        ui.add(egui::TextEdit::singleline(&mut state.trace_count).font(TextStyle::Monospace).desired_width(70.0));
        ui.checkbox(&mut state.trace_over, "só a função corrente").on_hover_text("as chamadas executam sem gravar (trace por cima)");
        ui.label("pular:");
        ui.add(egui::TextEdit::singleline(&mut state.trace_skip).font(TextStyle::Monospace).desired_width(110.0).hint_text("módulos"));
        ui.label("vigiar:");
        ui.add(egui::TextEdit::singleline(&mut state.trace_watch).font(TextStyle::Monospace).desired_width(120.0).hint_text("expr[:tamanho]"));
        if ui.add_enabled(stopped, egui::Button::new("Rastrear")).on_hover_text("passo a passo dentro do convidado, com os registradores de cada instrução").clicked() {
            state.requests.push(Request::Trace(trace_options(state)));
        }
        ui.separator();
        ui.add(egui::TextEdit::singleline(&mut state.trace_qemu_ms).font(TextStyle::Monospace).desired_width(50.0)).on_hover_text("milissegundos (ou até o endereço do modo 'até o endereço')");
        if ui.add_enabled(stopped, egui::Button::new("Rastro rápido (QEMU)")).on_hover_text("o log de execução do QEMU (TCG): só os RIPs, rastros longos").clicked() {
            let until = if state.trace_mode == TraceMode::Until { state.trace_argument.trim().to_string() } else { String::new() };
            state.requests.push(Request::QemuTrace { milliseconds: state.trace_qemu_ms.trim().parse().unwrap_or(500), until });
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.selectable_value(&mut state.trace_display, TraceDisplay::Table, "Tabela");
        ui.selectable_value(&mut state.trace_display, TraceDisplay::Tree, "Árvore de chamadas");
        ui.selectable_value(&mut state.trace_display, TraceDisplay::Diff, "Comparação");
        ui.separator();
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.trace_filter).font(TextStyle::Monospace).desired_width(160.0).hint_text("módulo, símbolo ou instrução"));
        ui.separator();
        ui.add(egui::TextEdit::singleline(&mut state.trace_path).font(TextStyle::Monospace).desired_width(200.0));
        if ui.add_enabled(state.trace.is_some(), egui::Button::new("Exportar CSV")).clicked() {
            state.requests.push(Request::SaveTrace(crate::workspace_root().join(state.trace_path.trim())));
        }
        if ui.add_enabled(state.trace.is_some(), egui::Button::new("Usar como referência")).clicked() {
            state.requests.push(Request::TraceAsReference);
        }
        ui.add(egui::TextEdit::singleline(&mut state.reference_path).font(TextStyle::Monospace).desired_width(200.0));
        if ui.button("Carregar referência").on_hover_text("um CSV exportado antes (outro boot, outra versão)").clicked() {
            state.requests.push(Request::LoadReference(crate::workspace_root().join(state.reference_path.trim())));
        }
    });
    ui.separator();
    let Some(trace) = state.trace.clone() else {
        hint(ui, "nenhum rastro. Modos: N instruções, até um endereço, até o retorno, até entrar ou sair de um módulo; 'só a função corrente' pula as chamadas; 'pular' executa módulos sem gravar. Também pelo comando trace.");
        return;
    };
    ui.label(mono(format!("{}: {}", trace.title, trace.summary.lines().next().unwrap_or(""))).color(colors.dim));
    match state.trace_display {
        TraceDisplay::Table => trace_table(ui, state, &trace, colors),
        TraceDisplay::Tree => trace_tree(ui, state, &trace),
        TraceDisplay::Diff => trace_diff(ui, state, &trace, colors),
    }
}

fn trace_table(ui: &mut Ui, state: &mut UiState, trace: &TraceView, colors: Palette) {
    trace_rows(state, trace);
    let available = ui.available_width();
    let detail_width = (available * 0.40).clamp(300.0, 560.0);
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(available - detail_width - 12.0);
            let height = row_height(ui);
            let rows = state.trace_rows.clone();
            let mut area = egui::ScrollArea::both().id_salt("trace-table").auto_shrink([false, false]);
            if let Some(index) = state.trace_scroll.take() {
                if let Some(position) = rows.iter().position(|&row| row == index) {
                    area = area.vertical_scroll_offset((position as f32 * height - 120.0).max(0.0));
                }
            }
            ui.add(egui::Label::new(mono(format!("{:>7} {:>3} {:<18} {:<40} {}", "#", "cpu", "RIP", "símbolo", "instrução / mudou")).strong()).truncate());
            area.show_rows(ui, height, rows.len(), |ui, range| {
                for &index in &rows[range] {
                    let record = &trace.trace.records[index];
                    let info = trace.info(record.rip);
                    let symbol = info.map_or("", |info| info.symbol.as_str());
                    let text = info.map_or("", |info| info.text.as_str());
                    let changed: String = trace.trace.changed_at(index).into_iter().take(4).map(|(name, value)| format!(" {name}={value:x}")).collect();
                    let indent = " ".repeat(record.depth.clamp(0, 12) as usize);
                    let line = format!("{index:>7} {:>3} {:<18} {indent}{:<width$} {text}{changed}", record.cpu, format!("{:#x}", record.rip), truncate(symbol, 40usize.saturating_sub(indent.len())), width = 40usize.saturating_sub(indent.len()));
                    let selected = state.trace_selected == Some(index);
                    let response = ui.add(egui::Label::new(mono(line)).sense(Sense::click()).extend());
                    if selected {
                        ui.painter().rect_filled(response.rect, 0.0, colors.focus);
                    }
                    if response.clicked() {
                        state.trace_selected = Some(index);
                    }
                }
            });
        });
        ui.separator();
        ui.vertical(|ui| {
            ui.set_width(detail_width);
            trace_detail(ui, state, trace, colors);
        });
    });
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}

/// O estado no registro escolhido: registradores (os que mudaram em
/// destaque) e os operandos de memória da instrução.
fn trace_detail(ui: &mut Ui, state: &mut UiState, trace: &TraceView, colors: Palette) {
    let Some(index) = state.trace_selected.filter(|&index| index < trace.trace.len()) else {
        hint(ui, "escolha um registro: os registradores e os operandos de memória daquele ponto aparecem aqui");
        return;
    };
    let record = trace.trace.records[index];
    let info = trace.info(record.rip).cloned().unwrap_or_default();
    ui.horizontal(|ui| {
        if ui.add_enabled(index > 0, egui::Button::new("< anterior")).clicked() {
            state.trace_selected = Some(index - 1);
            state.trace_scroll = Some(index - 1);
        }
        if ui.add_enabled(index + 1 < trace.trace.len(), egui::Button::new("próximo >")).clicked() {
            state.trace_selected = Some(index + 1);
            state.trace_scroll = Some(index + 1);
        }
        if ui.button("na desmontagem").clicked() {
            state.code_address = format!("{:#x}", record.rip);
            state.requests.push(Request::ShowCode(state.code_address.clone()));
            state.focus_tab.push(Tab::Disassembly);
        }
    });
    ui.label(mono(format!("registro {index}  CPU {}  thread {:#x}  profundidade {}", record.cpu, record.thread, record.depth)).strong());
    ui.label(mono(format!("{:#x} {}", record.rip, info.symbol)).color(colors.blue));
    ui.label(mono(&info.text).color(colors.yellow));
    if let Some(watch) = record.watch {
        ui.label(mono(format!("vigia = {watch:#x}")));
    }
    if record.skipped > 0 {
        hint(ui, &format!("{} instruções não gravadas antes deste registro (filtro)", record.skipped));
    }
    if trace.trace.source != opennt_kd::trace::Source::Qemu {
        let registers = trace.trace.registers_at(index);
        let next = (index + 1 < trace.trace.len()).then(|| trace.trace.registers_at(index + 1));
        let value_of = |name: &str| opennt_kd::trace::REGISTERS.iter().position(|register| *register == name).map(|position| registers[position]);
        ui.add_space(4.0);
        ui.label(RichText::new("Operandos de memória").strong());
        let operands = disasm::memory_operands(record.rip, &info.bytes, &value_of);
        if operands.is_empty() {
            hint(ui, "nenhum");
        }
        let hint_value = disasm::value_hint(record.rip, &info.bytes);
        for operand in &operands {
            let mask = if operand.size >= 8 { u64::MAX } else { (1u64 << (8 * operand.size)) - 1 };
            let value = match (&hint_value, &next) {
                (Some(ValueHint::LoadInto(register)), Some(next)) if operand.read => opennt_kd::trace::REGISTERS.iter().position(|name| name == register).map(|position| format!(" = {:#x}", next[position] & mask)),
                (Some(ValueHint::StoreFrom(register)), _) if operand.write => value_of(register).map(|value| format!(" = {:#x}", value & mask)),
                (Some(ValueHint::StoreImmediate(value)), _) if operand.write => Some(format!(" = {:#x}", value & mask)),
                _ => None,
            }
            .unwrap_or_default();
            let access = match (operand.read, operand.write) {
                (true, true) => "lê e grava",
                (true, false) => "lê",
                _ => "grava",
            };
            ui.label(mono(format!("{access} [{:#x}] {} bytes{value}", operand.address, operand.size)));
        }
        ui.add_space(4.0);
        ui.label(RichText::new("Registradores (antes da instrução)").strong());
        let changed = trace.trace.changed_at(index);
        egui::Grid::new("trace-registers").num_columns(4).spacing([8.0, 1.0]).show(ui, |ui| {
            for (position, name) in opennt_kd::trace::REGISTERS.iter().enumerate() {
                let highlight = changed.iter().any(|(changed_name, _)| changed_name == name);
                ui.label(mono(*name).color(colors.blue));
                ui.label(mono(hex(registers[position])).color(if highlight { colors.red } else { ui.visuals().text_color() }));
                if position % 2 == 1 {
                    ui.end_row();
                }
            }
        });
        hint(ui, "vermelho: mudou na instrução anterior");
    } else {
        hint(ui, "rastro do QEMU: só os RIPs (sem registradores)");
    }
}

fn trace_tree(ui: &mut Ui, state: &mut UiState, trace: &TraceView) {
    if state.trace_tree.as_ref().is_none_or(|(generation, _)| *generation != state.trace_generation) {
        state.trace_tree = Some((state.trace_generation, trace.trace.call_tree()));
    }
    let Some((_, nodes)) = state.trace_tree.clone() else { return };
    if nodes.is_empty() {
        hint(ui, "rastro vazio");
        return;
    }
    egui::ScrollArea::both().id_salt("trace-tree").auto_shrink([false, false]).show(ui, |ui| {
        for &child in &nodes[0].children {
            tree_node(ui, state, trace, &nodes, child);
        }
    });
}

fn tree_node(ui: &mut Ui, state: &mut UiState, trace: &TraceView, nodes: &[opennt_kd::trace::CallNode], index: usize) {
    let node = &nodes[index];
    let name = trace.info(node.address).map_or_else(|| format!("{:#x}", node.address), |info| info.symbol.rsplit_once("+0x").map_or(info.symbol.clone(), |(name, _)| name.to_string()));
    let label = format!("{name}  ({} instruções, registros {}..{})", node.own, node.start, node.end);
    if node.children.is_empty() {
        ui.horizontal(|ui| {
            ui.add_space(18.0);
            if ui.selectable_label(state.trace_selected == Some(node.start), mono(label)).clicked() {
                state.trace_selected = Some(node.start);
                state.trace_scroll = Some(node.start);
                state.trace_display = TraceDisplay::Table;
            }
        });
        return;
    }
    let response = egui::CollapsingHeader::new(mono(label)).id_salt(("trace-node", index)).default_open(node.depth <= 0).show(ui, |ui| {
        for &child in &node.children {
            tree_node(ui, state, trace, nodes, child);
        }
    });
    if response.header_response.double_clicked() {
        state.trace_selected = Some(node.start);
        state.trace_scroll = Some(node.start);
        state.trace_display = TraceDisplay::Table;
    }
}

fn trace_diff(ui: &mut Ui, state: &mut UiState, trace: &TraceView, colors: Palette) {
    let Some(reference) = state.reference.clone() else {
        hint(ui, "sem referência: 'Usar como referência' guarda o rastro atual; 'Carregar referência' lê um CSV exportado. Depois rode outro rastro e compare.");
        return;
    };
    if state.divergence.is_none() {
        let a: Vec<u64> = trace.trace.records.iter().map(|record| record.rip).collect();
        let b: Vec<u64> = reference.trace.records.iter().map(|record| record.rip).collect();
        state.divergence = Some(opennt_kd::trace::first_divergence(&a, &b));
    }
    let Some(divergence) = state.divergence.flatten() else {
        ui.label(RichText::new(format!("rastros iguais ({} registros)", trace.trace.len())).color(colors.green).strong());
        return;
    };
    let (x, y) = divergence;
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("primeira divergência: registro {x} deste rastro, {y} da referência ({})", reference.title)).color(colors.yellow).strong());
        if ui.button("ir ao registro").clicked() {
            state.trace_selected = Some(x.min(trace.trace.len().saturating_sub(1)));
            state.trace_scroll = state.trace_selected;
            state.trace_display = TraceDisplay::Table;
        }
    });
    let describe = |view: &TraceView, index: usize| -> String {
        match view.trace.records.get(index) {
            Some(record) => format!("{index:>7} {:#018x} {}", record.rip, view.info(record.rip).map_or("", |info| info.symbol.as_str())),
            None => format!("{index:>7} (fim)"),
        }
    };
    ui.columns(2, |columns| {
        columns[0].label(RichText::new("este rastro").strong());
        columns[1].label(RichText::new("referência").strong());
        for offset in -12i64..=12 {
            let (a, b) = (x as i64 + offset, y as i64 + offset);
            if a < 0 || b < 0 {
                continue;
            }
            let color = if offset == 0 { colors.yellow } else if offset < 0 { colors.dim } else { columns[0].visuals().text_color() };
            columns[0].label(mono(describe(trace, a as usize)).color(color));
            columns[1].label(mono(describe(&reference, b as usize)).color(color));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_lists() {
        let mut list = vec!["b".to_string(), "a".to_string()];
        remember_recent(&mut list, "a", 3);
        assert_eq!(list, vec!["a".to_string(), "b".to_string()]);
        remember_recent(&mut list, "c", 2);
        assert_eq!(list, vec!["c".to_string(), "a".to_string()]);
    }

    #[test]
    fn transcript_rows_and_copy() {
        let entries = vec![
            Entry { input: "k 2".into(), output: "00 nt!KiSystemCall64\r\n01 ntdll!NtClose\n".into(), error: false },
            Entry { input: "bp x".into(), output: "simbolo desconhecido".into(), error: true },
            Entry { input: "g".into(), output: String::new(), error: false },
        ];
        let mut lines = Vec::new();
        for (index, entry) in entries.iter().enumerate() {
            push_transcript_lines(&mut lines, index, entry);
        }
        let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
        assert_eq!(texts, vec!["kd> k 2", "00 nt!KiSystemCall64", "01 ntdll!NtClose", "kd> bp x", "simbolo desconhecido", "kd> g"]);
        assert_eq!(lines[4].kind, LineKind::Error);
        assert_eq!(lines[4].entry, 1);
        assert_eq!(transcript_text(&entries, Some(1)), "kd> bp x\nsimbolo desconhecido\n");
        assert_eq!(transcript_text(&entries, Some(9)), "");
        assert!(transcript_text(&entries, None).ends_with("kd> g\n"));
    }

    #[test]
    fn launch_options_from_the_form() {
        let form = OpenForm { options: "--initial-process=smss --display=basic".into(), build_dir: " build/dbg ".into(), headless: true, address: String::new(), error: None };
        let base = LaunchOptions { root: PathBuf::from("raiz"), build_dir: PathBuf::from("build"), headless: false, extra: Vec::new() };
        let options = form_launch_options(Some(&base), &form).unwrap();
        assert_eq!(options.root, PathBuf::from("raiz"));
        assert_eq!(options.build_dir, PathBuf::from("build/dbg"));
        assert!(options.headless);
        assert_eq!(options.extra, vec!["--initial-process=smss".to_string(), "--display=basic".to_string()]);
        let empty = OpenForm { build_dir: String::new(), ..form.clone() };
        assert_eq!(form_launch_options(Some(&base), &empty).unwrap().build_dir, PathBuf::from("build"));
        let wrong = OpenForm { options: "smss".into(), ..form };
        assert!(form_launch_options(Some(&base), &wrong).is_err());
    }
}
