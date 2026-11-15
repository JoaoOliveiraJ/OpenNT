//! A janela do depurador: barra de ferramentas, painéis encaixáveis (o
//! `egui_dock`: arrastar uma aba a solta, junta ou divide a área) e a barra
//! de estado. Os painéis só leem o `Snapshot` publicado pelo backend e
//! mandam pedidos; nada aqui espera o alvo.

use std::sync::Arc;

use eframe::egui::{self, Align, Color32, FontId, Key, Modifiers, RichText, Sense, TextStyle, Ui, Vec2, WidgetText};
use egui_dock::{DockArea, DockState, NodeIndex, Style, TabViewer};
use kd_client::{registers, BreakpointKind};

use crate::backend::{Backend, Entry, Request, Snapshot, Status, Target, View};
use crate::launcher::LaunchOptions;

/// Os painéis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tab {
    Command,
    Disassembly,
    Source,
    Registers,
    Memory,
    CallStack,
    Modules,
    Processes,
    Threads,
    Breakpoints,
    DbgPrint,
    Serial,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Command => "Comando",
            Tab::Disassembly => "Desmontagem",
            Tab::Source => "Fonte",
            Tab::Registers => "Registradores",
            Tab::Memory => "Memória",
            Tab::CallStack => "Pilha de chamadas",
            Tab::Modules => "Módulos",
            Tab::Processes => "Processos",
            Tab::Threads => "Threads",
            Tab::Breakpoints => "Breakpoints",
            Tab::DbgPrint => "DbgPrint",
            Tab::Serial => "COM1 (log do kernel)",
        }
    }
}

/// O arranjo inicial, como o do WinDbg: desmontagem e fonte no centro,
/// registradores à direita, pilha e listas embaixo à direita, comando e
/// logs embaixo.
pub fn default_layout() -> DockState<Tab> {
    let mut dock = DockState::new(vec![Tab::Disassembly]);
    let surface = dock.main_surface_mut();
    let [code, _bottom] = surface.split_below(NodeIndex::root(), 0.64, vec![Tab::Command, Tab::DbgPrint, Tab::Memory, Tab::Serial]);
    let [code, right] = surface.split_right(code, 0.64, vec![Tab::Registers]);
    surface.split_below(code, 0.55, vec![Tab::Source]);
    surface.split_below(right, 0.5, vec![Tab::CallStack, Tab::Breakpoints, Tab::Modules, Tab::Processes, Tab::Threads]);
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

/// O estado da interface (campos de texto, cópias do que o backend
/// publicou).
pub struct UiState {
    snapshot: Arc<Snapshot>,
    status: Status,
    activity: String,
    can_restart: bool,
    transcript: Vec<Entry>,
    console: LogLines,
    serial: LogLines,
    launch_log: LogLines,
    command: String,
    history: Vec<String>,
    history_index: Option<usize>,
    code_address: String,
    memory_address: String,
    breakpoint_expression: String,
    breakpoint_kind: BreakpointKind,
    register_edit: Option<(String, String)>,
    memory_edit: Option<(u64, String)>,
    thread_filter: Option<u64>,
    connect_address: String,
    launch: Option<LaunchOptions>,
    /// A geração do snapshot que já rolou o código até o foco.
    scrolled_code: u64,
    scrolled_source: u64,
    requests: Vec<Request>,
}

pub struct DebuggerApp {
    pub backend: Backend,
    dock: DockState<Tab>,
    state: UiState,
}

const RED: Color32 = Color32::from_rgb(0xE0, 0x4B, 0x4B);
const YELLOW: Color32 = Color32::from_rgb(0xF2, 0xC1, 0x4E);
const GREEN: Color32 = Color32::from_rgb(0x5C, 0xC0, 0x6C);
const BLUE: Color32 = Color32::from_rgb(0x6C, 0xA8, 0xF0);
const DIM: Color32 = Color32::from_rgb(0x8A, 0x8F, 0x98);
const FOCUS_FILL: Color32 = Color32::from_rgba_premultiplied(0x50, 0x46, 0x10, 0xA0);

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
                history: Vec::new(),
                history_index: None,
                code_address: String::new(),
                memory_address: String::new(),
                breakpoint_expression: String::new(),
                breakpoint_kind: BreakpointKind::Software,
                register_edit: None,
                memory_edit: None,
                thread_filter: None,
                connect_address,
                launch,
                scrolled_code: 0,
                scrolled_source: 0,
                requests: Vec::new(),
            },
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
        }
        state.status = shared.status.clone();
        state.activity = shared.activity.clone();
        state.can_restart = shared.can_restart;
        if shared.transcript.len() < state.transcript.len() {
            state.transcript.clear();
        }
        let known = state.transcript.len();
        state.transcript.extend(shared.transcript[known..].iter().cloned());
        state.console.sync(&shared.console);
        state.serial.sync(&shared.serial);
        state.launch_log.sync(&shared.launch_log);
    }

    /// Um quadro inteiro da janela.
    pub fn show(&mut self, ui: &mut Ui) {
        self.sync();
        self.shortcuts(ui);
        let state = &mut self.state;
        egui::Panel::top("toolbar").show(ui, |ui| toolbar(ui, state));
        egui::Panel::bottom("status").show(ui, |ui| status_bar(ui, state));
        egui::CentralPanel::no_frame().show(ui, |ui| {
            let mut style = Style::from_egui(ui.style().as_ref());
            style.tab_bar.fill_tab_bar = true;
            DockArea::new(&mut self.dock).style(style).show_close_buttons(false).show_leaf_close_all_buttons(false).show_leaf_collapse_buttons(false).show_inside(ui, &mut Viewer { state: &mut self.state });
        });
        for request in self.state.requests.drain(..) {
            self.backend.send(request);
        }
    }

    fn shortcuts(&mut self, ui: &Ui) {
        let stopped = self.state.status == Status::Stopped;
        let running = self.state.status == Status::Running;
        let pressed = |modifiers: Modifiers, key: Key| ui.input_mut(|input| input.consume_key(modifiers, key));
        if stopped && pressed(Modifiers::SHIFT, Key::F11) {
            self.state.requests.push(Request::StepOut);
        }
        if stopped && pressed(Modifiers::NONE, Key::F5) {
            self.state.requests.push(Request::Go);
        }
        if stopped && pressed(Modifiers::NONE, Key::F10) {
            self.state.requests.push(Request::StepOver);
        }
        if stopped && pressed(Modifiers::NONE, Key::F11) {
            self.state.requests.push(Request::StepInto);
        }
        if running && pressed(Modifiers::CTRL, Key::B) {
            self.state.requests.push(Request::Break);
        }
    }
}

impl eframe::App for DebuggerApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}

fn toolbar(ui: &mut Ui, state: &mut UiState) {
    let stopped = state.status == Status::Stopped;
    let running = state.status == Status::Running;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        if ui.add_enabled(running, egui::Button::new("Parar (Ctrl+B)")).on_hover_text("pede a parada (0x03)").clicked() {
            state.requests.push(Request::Break);
        }
        if ui.add_enabled(stopped, egui::Button::new("Continuar (F5)")).clicked() {
            state.requests.push(Request::Go);
        }
        if ui.add_enabled(stopped, egui::Button::new("Entrar (F11)")).on_hover_text("um passo (entra no call)").clicked() {
            state.requests.push(Request::StepInto);
        }
        if ui.add_enabled(stopped, egui::Button::new("Passar (F10)")).on_hover_text("passo por cima do call").clicked() {
            state.requests.push(Request::StepOver);
        }
        if ui.add_enabled(stopped, egui::Button::new("Sair (Shift+F11)")).on_hover_text("até o retorno da função").clicked() {
            state.requests.push(Request::StepOut);
        }
        ui.separator();
        if ui.add_enabled(state.can_restart, egui::Button::new("Reiniciar")).on_hover_text("fecha o QEMU, recompila e abre de novo").clicked() {
            state.requests.push(Request::Restart);
        }
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
        if connected && ui.button("Desconectar").clicked() {
            state.requests.push(Request::Disconnect);
        }
        ui.separator();
        let (color, text) = match &state.status {
            Status::Idle => (DIM, "sem alvo".to_string()),
            Status::Launching(line) => (YELLOW, format!("abrindo: {line}")),
            Status::Connecting(address) => (YELLOW, format!("conectando a {address}")),
            Status::Running => (GREEN, "rodando".to_string()),
            Status::Stopped => (RED, "parado".to_string()),
            Status::Disconnected(reason) => (DIM, format!("desconectado: {}", reason.lines().next().unwrap_or(""))),
        };
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(12.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 5.0, color);
        ui.label(RichText::new(text).color(color).strong());
    });
}

fn status_bar(ui: &mut Ui, state: &mut UiState) {
    ui.horizontal(|ui| {
        let snapshot = &state.snapshot;
        if !snapshot.stop.is_empty() {
            ui.label(mono(snapshot.stop.split(" [").next().unwrap_or("")).color(DIM));
        }
        if !state.activity.is_empty() {
            ui.separator();
            ui.spinner();
            ui.label(RichText::new(&state.activity).color(YELLOW));
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
            Tab::Registers => registers_panel(ui, state),
            Tab::Memory => memory_panel(ui, state),
            Tab::CallStack => call_stack_panel(ui, state),
            Tab::Modules => modules_panel(ui, state),
            Tab::Processes => processes_panel(ui, state),
            Tab::Threads => threads_panel(ui, state),
            Tab::Breakpoints => breakpoints_panel(ui, state),
            Tab::DbgPrint => log_panel(ui, &state.console, "dbgprint", "(nenhuma saida do DbgPrint ainda)"),
            Tab::Serial => log_panel(ui, &state.serial, "serial", "(o log da COM1 aparece aqui quando o depurador abre o QEMU)"),
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
    ui.text_style_height(&TextStyle::Monospace) + 2.0
}

fn log_panel(ui: &mut Ui, log: &LogLines, id: &str, empty: &str) {
    if log.count() == 0 {
        ui.label(RichText::new(empty).color(DIM));
        return;
    }
    let height = row_height(ui);
    egui::ScrollArea::both().id_salt(id).auto_shrink([false, false]).stick_to_bottom(true).show_rows(ui, height, log.count(), |ui, range| {
        for index in range {
            ui.label(mono(log.line(index)));
        }
    });
}

fn command_panel(ui: &mut Ui, state: &mut UiState) {
    let input_height = row_height(ui) + 12.0;
    let output_height = (ui.available_height() - input_height).max(40.0);
    egui::ScrollArea::vertical().id_salt("transcript").auto_shrink([false, false]).stick_to_bottom(true).max_height(output_height).show(ui, |ui| {
        if state.transcript.is_empty() {
            ui.label(RichText::new("os comandos do cargo xtask debug (help): bp, bc, bl, x, r, bt, ps, threads, lm, cpus, obj, log, monitor...").color(DIM));
            for index in 0..state.launch_log.count() {
                ui.label(mono(state.launch_log.line(index)).color(DIM));
            }
        }
        for entry in &state.transcript {
            ui.label(mono(format!("kd> {}", entry.input)).color(BLUE));
            if !entry.output.trim().is_empty() {
                ui.label(mono(entry.output.trim_end()).color(if entry.error { RED } else { ui.visuals().text_color() }));
            }
        }
    });
    ui.horizontal(|ui| {
        let prompt = if state.status == Status::Stopped { "kd>" } else { "kd (rodando)>" };
        ui.label(mono(prompt).color(BLUE));
        let response = ui.add(egui::TextEdit::singleline(&mut state.command).font(TextStyle::Monospace).desired_width(f32::INFINITY).hint_text("comando (help)"));
        if response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
            let line = std::mem::take(&mut state.command);
            if !line.trim().is_empty() {
                state.history.push(line.clone());
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
            }
        }
    });
}

/// O RIP da visão (o do processador ou da thread escolhida).
fn current_rip(snapshot: &Snapshot) -> Option<u64> {
    snapshot.registers.iter().find(|row| row.name == "rip").and_then(|row| row.value)
}

fn disassembly_panel(ui: &mut Ui, state: &mut UiState) {
    ui.horizontal(|ui| {
        ui.label("Endereço:");
        let response = ui.add(egui::TextEdit::singleline(&mut state.code_address).font(TextStyle::Monospace).desired_width(260.0).hint_text("expressão ou símbolo"));
        if ui.button("Ir").clicked() || (response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter))) {
            state.requests.push(Request::ShowCode(state.code_address.clone()));
        }
        if ui.button("Seguir o RIP").clicked() {
            state.code_address.clear();
            state.requests.push(Request::ShowCode(String::new()));
        }
    });
    ui.separator();
    let snapshot = Arc::clone(&state.snapshot);
    if let Some(error) = &snapshot.code.error {
        ui.label(RichText::new(error).color(RED));
    }
    if snapshot.code.lines.is_empty() {
        ui.label(RichText::new("sem código (a máquina não parou ainda)").color(DIM));
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
                ui.label(mono(format!("{label}:")).color(BLUE).strong());
            }
            let breakpoint = snapshot.breakpoints.iter().find(|breakpoint| breakpoint.address == line.address && matches!(breakpoint.kind, BreakpointKind::Software | BreakpointKind::Hardware));
            let response = ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                let (gutter, click) = ui.allocate_exact_size(Vec2::new(30.0, height), Sense::click());
                if click.clicked() {
                    state.requests.push(Request::ToggleBreakpoint(line.address));
                }
                let click = click.on_hover_text("clique: liga/tira o breakpoint");
                let painter = ui.painter();
                if let Some(breakpoint) = breakpoint {
                    let center = gutter.left_center() + Vec2::new(8.0, 0.0);
                    if breakpoint.enabled {
                        painter.circle_filled(center, 5.0, RED);
                    } else {
                        painter.circle_stroke(center, 5.0, egui::Stroke::new(1.5, RED));
                    }
                } else if click.hovered() {
                    painter.circle_stroke(gutter.left_center() + Vec2::new(8.0, 0.0), 5.0, egui::Stroke::new(1.0, DIM));
                }
                if Some(line.address) == rip {
                    painter.text(gutter.left_center() + Vec2::new(18.0, 0.0), egui::Align2::LEFT_CENTER, "=>", font.clone(), YELLOW);
                } else if line.address == snapshot.code.focus {
                    painter.text(gutter.left_center() + Vec2::new(18.0, 0.0), egui::Align2::LEFT_CENTER, "->", font.clone(), GREEN);
                }
                let mut text = format!("{}  {:<16} {}", hex(line.address), line.bytes.chars().take(16).collect::<String>(), line.text);
                if let Some(comment) = &line.comment {
                    text.push_str(&format!("  ; {comment}"));
                }
                let color = if Some(line.address) == rip { YELLOW } else { ui.visuals().text_color() };
                let label = ui.add(egui::Label::new(mono(text).color(color)).sense(Sense::click()).extend());
                if let Some(target) = line.target {
                    if label.double_clicked() {
                        state.code_address = format!("{target:#x}");
                        state.requests.push(Request::ShowCode(state.code_address.clone()));
                    }
                    label.on_hover_text("clique duplo: vai ao destino");
                }
            });
            if line.address == snapshot.code.focus {
                ui.painter().rect_filled(response.response.rect, 0.0, FOCUS_FILL);
                if scroll {
                    scroll_vertically_to(ui, response.response.rect);
                }
            }
        }
    });
}

fn source_panel(ui: &mut Ui, state: &mut UiState) {
    let snapshot = Arc::clone(&state.snapshot);
    let Some(source) = &snapshot.source else {
        ui.label(RichText::new(snapshot.source_error.as_deref().unwrap_or("sem linha de código")).color(DIM));
        return;
    };
    let root = crate::workspace_root();
    let file = std::path::Path::new(&source.file).strip_prefix(&root).map_or_else(|_| source.file.clone(), |relative| relative.display().to_string());
    ui.label(mono(format!("{file}:{}", source.line)).color(BLUE));
    ui.separator();
    let scroll = state.scrolled_source != snapshot.generation;
    state.scrolled_source = snapshot.generation;
    egui::ScrollArea::both().id_salt("source").auto_shrink([false, false]).show(ui, |ui| {
        let current = source.line as usize;
        let first = current.saturating_sub(400).max(1);
        let last = (current + 400).min(source.text.len());
        for number in first..=last {
            let Some(text) = source.text.get(number - 1) else { break };
            let is_current = number == current;
            let line = mono(format!("{number:>5}  {text}")).color(if is_current { YELLOW } else { ui.visuals().text_color() });
            let response = ui.add(egui::Label::new(line).extend());
            if is_current {
                ui.painter().rect_filled(response.rect, 0.0, FOCUS_FILL);
                if scroll {
                    scroll_vertically_to(ui, response.rect);
                }
            }
        }
    });
}

fn registers_panel(ui: &mut Ui, state: &mut UiState) {
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal(|ui| {
        let selected = match snapshot.view {
            View::Owner => snapshot.stop_processor.map(|number| number + 1),
            View::Cpu(thread) => Some(thread),
            View::Thread(_) => None,
        };
        let text = match (snapshot.view, selected) {
            (View::Thread(ethread), _) => format!("ETHREAD {ethread:#x}"),
            (_, Some(thread)) => format!("CPU {}", thread - 1),
            _ => "CPU".to_string(),
        };
        egui::ComboBox::from_id_salt("cpu").selected_text(text).show_ui(ui, |ui| {
            for &thread in &snapshot.stopped_threads {
                let owner = snapshot.stop_processor == Some(thread - 1);
                let label = format!("CPU {}{}", thread - 1, if owner { " (parada)" } else { "" });
                if ui.selectable_label(selected == Some(thread), label).clicked() {
                    state.requests.push(Request::SelectCpu(thread));
                }
            }
        });
        ui.label(RichText::new(&snapshot.view_header).color(DIM));
    });
    ui.separator();
    if snapshot.registers.is_empty() {
        ui.label(RichText::new("sem registradores (a máquina não parou ainda)").color(DIM));
        return;
    }
    let editable = snapshot.registers_editable && state.status == Status::Stopped;
    // Duas colunas de pares nome/valor quando cabem (rax..rdi ao lado de
    // r8..r15, como no WinDbg).
    let columns = if ui.available_width() > 480.0 { 2 } else { 1 };
    let rows = snapshot.registers.len().div_ceil(columns);
    egui::ScrollArea::vertical().id_salt("registers").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("register-grid").num_columns(2 * columns).striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
            for index in 0..rows {
                for column in 0..columns {
                    match snapshot.registers.get(index + column * rows) {
                        Some(row) => register_cell(ui, state, row, editable),
                        None => {
                            ui.label("");
                            ui.label("");
                        }
                    }
                }
                ui.end_row();
            }
        });
    });
}

fn register_cell(ui: &mut Ui, state: &mut UiState, row: &crate::backend::RegisterRow, editable: bool) {
    ui.label(mono(&row.name).color(BLUE));
    let editing = state.register_edit.as_ref().is_some_and(|(name, _)| *name == row.name);
    if editing {
        let Some((_, text)) = state.register_edit.as_mut() else { return };
        let response = ui.add(egui::TextEdit::singleline(text).font(TextStyle::Monospace).desired_width(150.0));
        response.request_focus();
        if response.lost_focus() {
            if ui.input(|input| input.key_pressed(Key::Enter)) {
                if let Some(value) = parse_hex(text) {
                    state.requests.push(Request::WriteRegister(row.name.clone(), value));
                }
            }
            state.register_edit = None;
        }
        return;
    }
    let text = match row.value {
        Some(value) if row.name == "eflags" || row.name == "rflags" => format!("{value:08x} {}", registers::flags_text(value)),
        Some(value) if matches!(row.name.as_str(), "cs" | "ss" | "ds" | "es" | "fs" | "gs") => format!("{value:04x}"),
        Some(value) => hex(value),
        None => "????????????????".into(),
    };
    let label = ui.add(egui::Label::new(mono(text).color(if row.changed { RED } else { ui.visuals().text_color() })).sense(Sense::click()));
    if editable && label.on_hover_text("clique para editar (Enter grava)").clicked() {
        state.register_edit = Some((row.name.clone(), row.value.map(hex).unwrap_or_default()));
    }
}

fn memory_panel(ui: &mut Ui, state: &mut UiState) {
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal(|ui| {
        ui.label("Endereço:");
        let response = ui.add(egui::TextEdit::singleline(&mut state.memory_address).font(TextStyle::Monospace).desired_width(260.0).hint_text("expressão: %rsp, símbolo, 0x..."));
        if ui.button("Ir").clicked() || (response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter))) {
            state.requests.push(Request::ShowMemory(state.memory_address.clone()));
        }
        let address = snapshot.memory.address;
        if !snapshot.memory.bytes.is_empty() {
            if ui.button("-0x200").clicked() {
                state.memory_address = format!("{:#x}", address.wrapping_sub(0x200));
                state.requests.push(Request::ShowMemory(state.memory_address.clone()));
            }
            if ui.button("+0x200").clicked() {
                state.memory_address = format!("{:#x}", address.wrapping_add(0x200));
                state.requests.push(Request::ShowMemory(state.memory_address.clone()));
            }
        }
    });
    ui.separator();
    if let Some(error) = &snapshot.memory.error {
        ui.label(RichText::new(error).color(RED));
    }
    if snapshot.memory.bytes.is_empty() {
        ui.label(RichText::new("digite um endereço (clique num byte para editá-lo com a máquina parada)").color(DIM));
        return;
    }
    let editable = state.status == Status::Stopped;
    egui::ScrollArea::both().id_salt("memory").auto_shrink([false, false]).show(ui, |ui| {
        for (row, chunk) in snapshot.memory.bytes.chunks(16).enumerate() {
            let base = snapshot.memory.address + row as u64 * 16;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 5.0;
                ui.label(mono(hex(base)).color(BLUE));
                for (column, &byte) in chunk.iter().enumerate() {
                    let address = base + column as u64;
                    if state.memory_edit.as_ref().is_some_and(|(at, _)| *at == address) {
                        let (_, text) = state.memory_edit.as_mut().unwrap();
                        let response = ui.add(egui::TextEdit::singleline(text).font(TextStyle::Monospace).desired_width(18.0).char_limit(2));
                        response.request_focus();
                        if response.lost_focus() {
                            if ui.input(|input| input.key_pressed(Key::Enter)) {
                                if let Ok(value) = u8::from_str_radix(text.trim(), 16) {
                                    state.requests.push(Request::WriteMemory(address, vec![value]));
                                }
                            }
                            state.memory_edit = None;
                        }
                    } else {
                        let label = ui.add(egui::Label::new(mono(format!("{byte:02x}"))).sense(Sense::click()));
                        if editable && label.clicked() {
                            state.memory_edit = Some((address, format!("{byte:02x}")));
                        }
                    }
                    if column == 7 {
                        ui.add_space(4.0);
                    }
                }
                let text: String = chunk.iter().map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect();
                ui.add_space(8.0);
                ui.label(mono(text).color(DIM));
            });
        }
    });
}

fn call_stack_panel(ui: &mut Ui, state: &mut UiState) {
    let snapshot = Arc::clone(&state.snapshot);
    if snapshot.frames.is_empty() {
        ui.label(RichText::new("sem pilha (a máquina não parou ainda)").color(DIM));
        return;
    }
    egui::ScrollArea::both().id_salt("stack").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("stack-grid").num_columns(3).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for (index, frame) in snapshot.frames.iter().enumerate() {
                let selected = index == snapshot.selected_frame;
                ui.label(mono(format!("#{index:<2}")).color(DIM));
                ui.label(mono(hex(frame.address)));
                if ui.selectable_label(selected, mono(&frame.name)).clicked() {
                    state.requests.push(Request::SelectFrame(index));
                }
                ui.end_row();
            }
        });
    });
}

fn modules_panel(ui: &mut Ui, state: &mut UiState) {
    let snapshot = Arc::clone(&state.snapshot);
    egui::ScrollArea::both().id_salt("modules").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("module-grid").num_columns(5).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["base", "fim", "nome", "símbolos", "origem"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for module in &snapshot.modules {
                ui.label(mono(hex(module.base)));
                ui.label(mono(hex(module.end)));
                ui.label(mono(&module.name).color(BLUE));
                ui.label(mono(module.symbols.to_string()));
                ui.label(RichText::new(&module.source).color(DIM));
                ui.end_row();
            }
        });
    });
}

fn processes_panel(ui: &mut Ui, state: &mut UiState) {
    let snapshot = Arc::clone(&state.snapshot);
    egui::ScrollArea::both().id_salt("processes").auto_shrink([false, false]).show(ui, |ui| {
        ui.label(RichText::new("Processos (clique para filtrar as threads)").strong());
        egui::Grid::new("process-grid").num_columns(5).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["PID", "EPROCESS", "CR3", "threads", "nome"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for process in &snapshot.processes {
                let selected = state.thread_filter == Some(process.pid);
                if ui.selectable_label(selected, mono(process.pid.to_string())).clicked() {
                    state.thread_filter = if selected { None } else { Some(process.pid) };
                }
                ui.label(mono(hex(process.eprocess)));
                ui.label(mono(format!("{:x}", process.cr3)));
                ui.label(mono(process.threads.to_string()));
                ui.label(mono(&process.name).color(BLUE));
                ui.end_row();
            }
        });
        ui.add_space(8.0);
        ui.label(RichText::new("Processadores").strong());
        egui::Grid::new("processor-grid").num_columns(6).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["CPU", "IRQL", "KPCR", "thread", "RIP", "processo"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for processor in &snapshot.processors {
                let label = format!("{}{}", processor.number, if processor.owner { " *" } else { "" });
                if ui.selectable_label(snapshot.view == View::Cpu(processor.number + 1), mono(label)).on_hover_text("registradores e pilha deste processador").clicked() {
                    state.requests.push(Request::SelectCpu(processor.number + 1));
                }
                ui.label(mono(processor.irql.to_string()));
                ui.label(mono(hex(processor.pcr)));
                ui.label(mono(hex(processor.thread)));
                ui.label(mono(hex(processor.rip)));
                ui.label(mono(&processor.process));
                ui.end_row();
            }
        });
    });
}

fn threads_panel(ui: &mut Ui, state: &mut UiState) {
    let snapshot = Arc::clone(&state.snapshot);
    if let Some(pid) = state.thread_filter {
        ui.horizontal(|ui| {
            ui.label(format!("só o processo {pid}"));
            if ui.button("todas").clicked() {
                state.thread_filter = None;
            }
        });
    }
    egui::ScrollArea::both().id_salt("threads").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("thread-grid").num_columns(6).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["PID", "TID", "ETHREAD", "estado", "início", "processo"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for row in snapshot.threads.iter().filter(|row| state.thread_filter.is_none_or(|pid| pid == row.thread.pid)) {
                let thread = &row.thread;
                let running = snapshot.processors.iter().find(|processor| processor.thread == thread.ethread).map(|processor| processor.number + 1);
                let selected = snapshot.view == View::Thread(thread.ethread) || (running.is_some() && running == match snapshot.view {
                    View::Cpu(cpu) => Some(cpu),
                    View::Owner => snapshot.stop_processor.map(|number| number + 1),
                    View::Thread(_) => None,
                });
                ui.label(mono(thread.pid.to_string()));
                ui.label(mono(thread.tid.to_string()));
                if ui.selectable_label(selected, mono(hex(thread.ethread))).on_hover_text("registradores e pilha desta thread").clicked() {
                    state.requests.push(Request::SelectThread(thread.ethread));
                }
                ui.label(mono(&thread.state).color(if thread.state == "Running" { GREEN } else { DIM }));
                ui.label(mono(&row.start));
                ui.label(mono(&thread.process));
                ui.end_row();
            }
        });
    });
}

fn breakpoints_panel(ui: &mut Ui, state: &mut UiState) {
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    ui.horizontal(|ui| {
        let response = ui.add(egui::TextEdit::singleline(&mut state.breakpoint_expression).font(TextStyle::Monospace).desired_width(260.0).hint_text("símbolo ou endereço"));
        egui::ComboBox::from_id_salt("breakpoint-kind").selected_text(state.breakpoint_kind.name()).show_ui(ui, |ui| {
            for kind in [BreakpointKind::Software, BreakpointKind::Hardware, BreakpointKind::Write, BreakpointKind::Access] {
                ui.selectable_value(&mut state.breakpoint_kind, kind, kind.name());
            }
        });
        let submit = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
        if (ui.add_enabled(stopped, egui::Button::new("Adicionar")).clicked() || (submit && stopped)) && !state.breakpoint_expression.trim().is_empty() {
            state.requests.push(Request::AddBreakpoint(state.breakpoint_kind, state.breakpoint_expression.trim().to_string()));
        }
    });
    ui.separator();
    if snapshot.breakpoints.is_empty() {
        ui.label(RichText::new("nenhum breakpoint (clique na margem da desmontagem para ligar um)").color(DIM));
        return;
    }
    egui::ScrollArea::both().id_salt("breakpoints").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("breakpoint-grid").num_columns(6).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["#", "ligado", "tipo", "endereço", "expressão", ""] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for breakpoint in &snapshot.breakpoints {
                ui.label(mono(breakpoint.id.to_string()));
                let mut enabled = breakpoint.enabled;
                if ui.add_enabled(stopped, egui::Checkbox::without_text(&mut enabled)).changed() {
                    state.requests.push(Request::EnableBreakpoint(breakpoint.id, enabled));
                }
                ui.label(breakpoint.kind.name());
                if ui.add(egui::Label::new(mono(hex(breakpoint.address)).color(BLUE)).sense(Sense::click())).on_hover_text("mostra na desmontagem").clicked() {
                    state.code_address = format!("{:#x}", breakpoint.address);
                    state.requests.push(Request::ShowCode(state.code_address.clone()));
                }
                ui.label(mono(&breakpoint.expression));
                if ui.add_enabled(stopped, egui::Button::new("remover")).clicked() {
                    state.requests.push(Request::RemoveBreakpoint(breakpoint.id));
                }
                ui.end_row();
            }
        });
    });
}
