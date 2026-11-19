//! As vistas do estado da máquina parada: registradores (inteiros,
//! segmentos, depuração, SSE/AVX e x87), pilha de chamadas do kernel até o
//! modo usuário, processos e threads com a espera e a prioridade, módulos
//! por processo com o estado do PDB, memória (hexadecimal, ponteiros com
//! símbolo e tipada pelo PDB), breakpoints com as ações e os grupos, o menu
//! das linhas da desmontagem e o log da COM1 com as paradas marcadas.
//!
//! Submódulo do `app`: usa o estado (`UiState`) e os auxiliares de lá.

use std::path::Path;
use std::sync::Arc;

use eframe::egui::{self, Key, RichText, Sense, Stroke, TextStyle, Ui};
use opennt_kd::client::{BreakpointOptions, BreakpointRequest};
use opennt_kd::registers::{self, ExtendedState};
use opennt_kd::{Breakpoint, BreakpointKind};

use super::{hex, hint, mono, palette, parse_hex, row_height, truncate, typed_tree, LogLines, MemoryFormat, Palette, Tab, UiState};
use crate::backend::{FrameRow, ModuleRow, QueryKind, RegisterRow, Request, Snapshot, Status, View, Wanted};
use crate::details::{self, PdbStatus, VectorFormat};

/// Os tipos de breakpoint do formulário.
const BREAKPOINT_KINDS: [BreakpointKind; 9] = [
    BreakpointKind::Software,
    BreakpointKind::Hardware,
    BreakpointKind::Write,
    BreakpointKind::Access,
    BreakpointKind::Module,
    BreakpointKind::Event,
    BreakpointKind::MemoryAccess,
    BreakpointKind::MemoryWrite,
    BreakpointKind::MemoryExecute,
];

/// O estado das vistas (um campo do `UiState`).
pub(super) struct ViewsState {
    vector_format: VectorFormat,
    show_extended: bool,
    thread_details: bool,
    user_stack: bool,
    /// O último `Wanted` mandado ao backend.
    sent_wanted: Option<Wanted>,
    memory_type: String,
    /// As expressões de antes de seguir um ponteiro (o "voltar").
    memory_history: Vec<String>,
    module_filter: String,
    serial_filter: String,
    serial_follow: bool,
    serial_path: String,
    /// As paradas no log da COM1: (linhas do log na hora da parada, a
    /// descrição da parada).
    serial_marks: Vec<(usize, String)>,
    marked_generation: u64,
    /// As linhas que passam no filtro e (filtro, linhas já filtradas).
    serial_rows: Vec<usize>,
    serial_scanned: (String, usize),
    /// Rolar até esta linha do log no próximo quadro.
    serial_scroll: Option<usize>,
    breakpoint_more: bool,
    breakpoint_log: String,
    breakpoint_command: String,
    breakpoint_group: String,
    breakpoint_edit: Option<BreakpointEdit>,
}

impl Default for ViewsState {
    fn default() -> Self {
        ViewsState {
            vector_format: VectorFormat::Hex,
            show_extended: true,
            thread_details: true,
            user_stack: true,
            sent_wanted: None,
            memory_type: String::new(),
            memory_history: Vec::new(),
            module_filter: String::new(),
            serial_filter: String::new(),
            serial_follow: true,
            serial_path: String::new(),
            serial_marks: Vec::new(),
            marked_generation: 0,
            serial_rows: Vec::new(),
            serial_scanned: (String::new(), 0),
            serial_scroll: None,
            breakpoint_more: false,
            breakpoint_log: String::new(),
            breakpoint_command: String::new(),
            breakpoint_group: String::new(),
            breakpoint_edit: None,
        }
    }
}

/// Um breakpoint no editor: as opções que o `edit_breakpoint` troca.
struct BreakpointEdit {
    id: u32,
    kind: BreakpointKind,
    expression: String,
    enabled: bool,
    condition: String,
    pass: String,
    log: String,
    command: String,
    group: String,
    name: String,
    log_condition: String,
    command_condition: String,
    single_shot: bool,
    silent: bool,
    fast_resume: bool,
}

impl BreakpointEdit {
    fn of(breakpoint: &Breakpoint) -> Self {
        let options = &breakpoint.options;
        BreakpointEdit {
            id: breakpoint.id,
            kind: breakpoint.kind,
            expression: breakpoint.expression.clone(),
            enabled: breakpoint.enabled,
            condition: breakpoint.condition.clone(),
            pass: if breakpoint.pass_count > 1 { breakpoint.pass_count.to_string() } else { String::new() },
            log: breakpoint.log.clone(),
            command: breakpoint.command.clone(),
            group: breakpoint.group.clone(),
            name: options.name.clone(),
            log_condition: options.log_condition.clone(),
            command_condition: options.command_condition.clone(),
            single_shot: options.single_shot,
            silent: options.silent,
            fast_resume: options.fast_resume,
        }
    }

    fn request(&self) -> BreakpointRequest {
        let mut request = BreakpointRequest::new(self.kind, &self.expression);
        request.enabled = self.enabled;
        request.condition = self.condition.trim().to_string();
        request.pass_count = self.pass.trim().parse().unwrap_or(0);
        request.log = self.log.trim().to_string();
        request.command = self.command.trim().to_string();
        request.group = self.group.trim().to_string();
        request.options = BreakpointOptions {
            name: self.name.trim().to_string(),
            log_condition: self.log_condition.trim().to_string(),
            command_condition: self.command_condition.trim().to_string(),
            single_shot: self.single_shot,
            silent: self.silent,
            fast_resume: self.fast_resume,
        };
        request
    }
}

/// As leituras caras que os painéis abertos querem vão ao backend quando
/// mudam.
pub(super) fn sync_wanted(state: &mut UiState, open: &[Tab]) {
    let views = &state.views;
    let thread_details = views.thread_details && open.contains(&Tab::Threads);
    let wanted = Wanted {
        extended: views.show_extended && open.contains(&Tab::Registers),
        thread_details,
        thread_filter: if thread_details { state.thread_filter } else { None },
        user_stack: views.user_stack && open.contains(&Tab::CallStack),
    };
    if state.views.sent_wanted != Some(wanted) {
        state.views.sent_wanted = Some(wanted);
        state.requests.push(Request::SetWanted(wanted));
    }
}

/// Depois de copiar o que o backend publicou: cada parada nova marca a
/// posição do log da COM1 (o backend lê o log antes de publicar a parada).
pub(super) fn after_sync(state: &mut UiState) {
    let generation = state.snapshot.generation;
    if generation == 0 || state.views.marked_generation == generation || state.status != Status::Stopped {
        return;
    }
    state.views.marked_generation = generation;
    let stop = state.snapshot.stop.split(" [").next().unwrap_or("").trim().to_string();
    if stop.is_empty() {
        return;
    }
    let line = state.serial.count();
    let marks = &mut state.views.serial_marks;
    // O log recomeçou (outro boot): as marcas antigas não valem mais.
    if marks.last().is_some_and(|(mark, _)| *mark > line) {
        marks.clear();
    }
    // A mesma parada relida (outro painel pediu um snapshot) não marca de novo.
    if marks.last().is_some_and(|(mark, text)| *mark == line && *text == stop) {
        return;
    }
    marks.push((line, stop));
    if marks.len() > 4000 {
        marks.remove(0);
    }
}

/// Mostra uma expressão na memória, guardando a de antes para o "voltar".
fn show_memory(state: &mut UiState, expression: String) {
    let previous = state.snapshot.memory.expression.trim().to_string();
    if !previous.is_empty() && previous != expression {
        state.views.memory_history.push(previous);
        if state.views.memory_history.len() > 64 {
            state.views.memory_history.remove(0);
        }
    }
    state.memory_address = expression;
    state.requests.push(Request::ShowMemory(state.memory_address.clone()));
    state.focus_tab.push(Tab::Memory);
}

fn show_code(state: &mut UiState, address: u64) {
    state.code_address = format!("{address:#x}");
    state.requests.push(Request::ShowCode(state.code_address.clone()));
    state.focus_tab.push(Tab::Disassembly);
}

fn open_query(state: &mut UiState, kind: QueryKind, argument: String) {
    state.query_kind = kind;
    state.query_argument = argument;
    state.requests.push(Request::Query(kind, state.query_argument.clone()));
    state.focus_tab.push(Tab::NtObjects);
}

/// O caminho relativo à raiz do repositório, quando está nela.
fn relative(root: &Path, file: &str) -> String {
    Path::new(file).strip_prefix(root).map_or_else(|_| file.to_string(), |path| path.display().to_string())
}

/// O menu do botão direito numa linha da desmontagem.
pub(super) fn code_line_menu(response: &egui::Response, state: &mut UiState, address: u64, target: Option<u64>) {
    let stopped = state.status == Status::Stopped;
    response.context_menu(|ui| {
        if ui.add_enabled(stopped, egui::Button::new("Liga/tira breakpoint (F9)")).clicked() {
            state.requests.push(Request::ToggleBreakpoint(address));
            ui.close();
        }
        if ui.add_enabled(stopped, egui::Button::new("Executar até aqui")).on_hover_text("breakpoint temporário neste endereço e continuar (qualquer thread)").clicked() {
            state.requests.push(Request::RunTo(address));
            ui.close();
        }
        if let Some(target) = target {
            if ui.button("Ir ao destino").clicked() {
                show_code(state, target);
                ui.close();
            }
        }
        if ui.button("Memória neste endereço").clicked() {
            show_memory(state, format!("{address:#x}"));
            ui.close();
        }
        if ui.button("Copiar o endereço").clicked() {
            ui.ctx().copy_text(format!("{address:#x}"));
            ui.close();
        }
    });
}

// ---- registradores ----------------------------------------------------------

fn is_selector(name: &str) -> bool {
    matches!(name, "cs" | "ss" | "ds" | "es" | "fs" | "gs")
}

fn is_base(name: &str) -> bool {
    matches!(name, "fs_base" | "gs_base")
}

pub(super) fn registers_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal(|ui| {
        let selected = match snapshot.view {
            View::Owner => snapshot.stop_processor.map(|number| number + 1),
            View::Cpu(thread) => Some(thread),
            View::Thread(_) => None,
        };
        let text = match (snapshot.view, selected) {
            (View::Thread(ethread), _) => format!("ETHREAD {ethread:#x}"),
            (_, Some(thread)) => format!("CPU {}", thread.saturating_sub(1)),
            _ => "CPU".to_string(),
        };
        egui::ComboBox::from_id_salt("cpu").selected_text(text).show_ui(ui, |ui| {
            for &thread in &snapshot.stopped_threads {
                let owner = snapshot.stop_processor == Some(thread.saturating_sub(1));
                let label = format!("CPU {}{}", thread.saturating_sub(1), if owner { " (parada)" } else { "" });
                if ui.selectable_label(selected == Some(thread), label).clicked() {
                    state.requests.push(Request::SelectCpu(thread));
                }
            }
        });
        ui.label(RichText::new(&snapshot.view_header).color(colors.dim));
    });
    ui.separator();
    if snapshot.registers.is_empty() {
        hint(ui, "sem registradores (a máquina não parou ainda)");
        return;
    }
    let editable = snapshot.registers_editable && state.status == Status::Stopped;
    egui::ScrollArea::vertical().id_salt("registers").auto_shrink([false, false]).show(ui, |ui| {
        let integers: Vec<&RegisterRow> = snapshot.registers.iter().filter(|row| !is_selector(&row.name) && !is_base(&row.name)).collect();
        integer_grid(ui, state, &integers, editable, colors);
        segment_section(ui, state, &snapshot, editable, colors);
        if matches!(snapshot.view, View::Thread(_)) {
            hint(ui, "thread fora da CPU: só os registradores do quadro de troca");
        } else {
            ui.checkbox(&mut state.views.show_extended, "SSE, AVX, x87 e depuração").on_hover_text("lê o resto do estado do processador a cada parada (com este painel aberto)");
            if state.views.show_extended {
                extended_sections(ui, state, &snapshot, editable, colors);
            }
        }
        hint(ui, "vermelho: mudou desde a parada anterior; clique num valor para editar");
    });
}

/// Nome e valor de um registrador (clique edita, Enter grava).
fn register_cell(ui: &mut Ui, state: &mut UiState, name: &str, value: Option<u64>, changed: bool, editable: bool, colors: Palette) {
    ui.label(mono(name).color(colors.blue));
    let editing = state.register_edit.as_ref().is_some_and(|(editing, _)| editing == name);
    if editing {
        let Some((_, text)) = state.register_edit.as_mut() else { return };
        let response = ui.add(egui::TextEdit::singleline(text).font(TextStyle::Monospace).desired_width(150.0));
        response.request_focus();
        if response.lost_focus() {
            if ui.input(|input| input.key_pressed(Key::Enter)) {
                if let Some(value) = parse_hex(text) {
                    state.requests.push(Request::WriteRegister(name.to_string(), value));
                }
            }
            state.register_edit = None;
        }
        return;
    }
    let text = match value {
        Some(value) if name == "eflags" || name == "rflags" => format!("{value:08x} {}", registers::flags_text(value)),
        Some(value) if is_selector(name) => format!("{value:04x}"),
        Some(value) => hex(value),
        None => "????????????????".into(),
    };
    let label = ui.add(egui::Label::new(mono(text).color(if changed { colors.red } else { ui.visuals().text_color() })).sense(Sense::click()));
    if editable && label.on_hover_text("clique para editar (Enter grava)").clicked() {
        state.register_edit = Some((name.to_string(), value.map(hex).unwrap_or_default()));
    }
}

/// Os inteiros em uma ou duas colunas de nome, valor e símbolo (rax..rdi
/// ao lado de r8..r15, como no WinDbg).
fn integer_grid(ui: &mut Ui, state: &mut UiState, rows: &[&RegisterRow], editable: bool, colors: Palette) {
    let columns = if ui.available_width() > 700.0 { 2 } else { 1 };
    let count = rows.len().div_ceil(columns);
    egui::Grid::new("register-grid").num_columns(3 * columns).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
        for index in 0..count {
            for column in 0..columns {
                match rows.get(index + column * count) {
                    Some(row) => {
                        register_cell(ui, state, &row.name, row.value, row.changed, editable, colors);
                        let symbol = row.symbol.as_deref().unwrap_or("");
                        let label = ui.label(RichText::new(truncate(symbol, 32)).color(colors.dim));
                        if !symbol.is_empty() {
                            label.on_hover_text(symbol);
                        }
                    }
                    None => {
                        ui.label("");
                        ui.label("");
                        ui.label("");
                    }
                }
            }
            ui.end_row();
        }
    });
}

/// O anel do código parado (o RPL do CS).
fn kernel_mode(snapshot: &Snapshot) -> bool {
    snapshot.registers.iter().find(|row| row.name == "cs").and_then(|row| row.value).is_none_or(|cs| cs & 3 == 0)
}

/// Os seletores (tabela, índice, RPL e o uso no NT) e as bases de FS e GS.
fn segment_section(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, editable: bool, colors: Palette) {
    let selectors: Vec<&RegisterRow> = snapshot.registers.iter().filter(|row| is_selector(&row.name)).collect();
    let bases: Vec<&RegisterRow> = snapshot.registers.iter().filter(|row| is_base(&row.name)).collect();
    if selectors.is_empty() && bases.is_empty() {
        return;
    }
    let kernel = kernel_mode(snapshot);
    egui::CollapsingHeader::new("Segmentos").id_salt("registers-segments").default_open(true).show(ui, |ui| {
        egui::Grid::new("segment-grid").num_columns(3).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for row in &selectors {
                register_cell(ui, state, &row.name, row.value, row.changed, editable, colors);
                ui.label(RichText::new(row.value.map(details::segment_text).unwrap_or_default()).color(colors.dim));
                ui.end_row();
            }
            for row in &bases {
                register_cell(ui, state, &row.name, row.value, row.changed, editable, colors);
                let note = match (row.name.as_str(), row.symbol.as_deref()) {
                    (_, Some(symbol)) => symbol.to_string(),
                    ("gs_base", None) if kernel => "o KPCR do processador (modo kernel)".to_string(),
                    ("gs_base", None) => "a TEB da thread (modo usuário)".to_string(),
                    _ => String::new(),
                };
                ui.label(RichText::new(note).color(colors.dim));
                ui.end_row();
            }
        });
    });
}

fn unavailable() -> String {
    "indisponível".to_string()
}

/// Depuração, SSE, AVX e x87/MMX (o `extended_registers` do cliente).
fn extended_sections(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, editable: bool, colors: Palette) {
    let cpu: &ExtendedState = match &snapshot.extended {
        None => {
            hint(ui, "(na próxima parada)");
            return;
        }
        Some(Err(error)) => {
            ui.label(RichText::new(error).color(colors.red));
            return;
        }
        Some(Ok(cpu)) => cpu,
    };
    egui::CollapsingHeader::new("Depuração (DR0-DR3, DR6, DR7)").id_salt("registers-debug").default_open(true).show(ui, |ui| {
        egui::Grid::new("debug-grid").num_columns(3).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for (index, layout) in registers::DEBUG.iter().enumerate() {
                let value = cpu.debug[index];
                let note = match (layout.name, value) {
                    ("dr6", Some(value)) => details::dr6_text(value),
                    ("dr7", Some(value)) => registers::dr7_text(value),
                    (_, Some(_)) => snapshot.debug_symbols.get(index).cloned().flatten().unwrap_or_default(),
                    (_, None) => unavailable(),
                };
                register_cell(ui, state, layout.name, value, false, editable && value.is_some(), colors);
                ui.label(RichText::new(note).color(colors.dim));
                ui.end_row();
            }
        });
    });
    let vector = state.views.vector_format;
    egui::CollapsingHeader::new("SSE (XMM0-XMM15, MXCSR)").id_salt("registers-sse").default_open(false).show(ui, |ui| {
        vector_format_picker(ui, state, "sse");
        egui::Grid::new("xmm-grid").num_columns(2).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for (index, value) in cpu.xmm.iter().copied().enumerate() {
                ui.label(mono(format!("xmm{index}")).color(colors.blue));
                ui.label(mono(value.map_or_else(unavailable, |bytes| details::vector_text(&bytes, vector))));
                ui.end_row();
            }
            if let Some(mxcsr) = cpu.mxcsr {
                ui.label(mono("mxcsr").color(colors.blue));
                ui.label(mono(format!("{mxcsr:08x} {}", registers::mxcsr_text(mxcsr))));
                ui.end_row();
            }
        });
    });
    egui::CollapsingHeader::new("AVX (YMM0-YMM15)").id_salt("registers-avx").default_open(false).show(ui, |ui| {
        if !cpu.ymm_high.iter().any(Option::is_some) {
            hint(ui, "indisponível: o sistema não liga o AVX ou o alvo não manda a metade alta dos YMM");
            return;
        }
        vector_format_picker(ui, state, "avx");
        egui::Grid::new("ymm-grid").num_columns(2).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for index in 0..16 {
                ui.label(mono(format!("ymm{index}")).color(colors.blue));
                ui.label(mono(cpu.ymm(index).map_or_else(unavailable, |bytes| details::vector_text(&bytes, vector))));
                ui.end_row();
            }
        });
    });
    egui::CollapsingHeader::new("x87 e MMX").id_salt("registers-x87").default_open(false).show(ui, |ui| {
        egui::Grid::new("x87-grid").num_columns(3).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for (index, value) in cpu.st.iter().copied().enumerate() {
                ui.label(mono(format!("st{index}")).color(colors.blue));
                match value {
                    Some(bytes) => {
                        ui.label(mono(bytes.iter().rev().map(|byte| format!("{byte:02x}")).collect::<String>()));
                        ui.label(mono(format!("{}", registers::extended_to_f64(&bytes))).color(colors.dim));
                    }
                    None => {
                        ui.label(mono(unavailable()));
                        ui.label("");
                    }
                }
                ui.end_row();
            }
            for index in 0..8 {
                ui.label(mono(format!("mm{index}")).color(colors.blue));
                ui.label(mono(cpu.mmx(index).map_or_else(unavailable, hex)));
                ui.label("");
                ui.end_row();
            }
            for (name, value) in [("fctrl", cpu.fctrl), ("fstat", cpu.fstat), ("ftag", cpu.ftag), ("fop", cpu.fop)] {
                ui.label(mono(name).color(colors.blue));
                ui.label(mono(value.map_or_else(unavailable, |value| format!("{value:04x}"))));
                let note = if name == "fstat" && value.is_some() { format!("topo da pilha: {}", cpu.x87_top()) } else { String::new() };
                ui.label(RichText::new(note).color(colors.dim));
                ui.end_row();
            }
        });
    });
}

fn vector_format_picker(ui: &mut Ui, state: &mut UiState, salt: &str) {
    ui.horizontal(|ui| {
        ui.label("formato:");
        egui::ComboBox::from_id_salt(("vector-format", salt)).selected_text(state.views.vector_format.label()).show_ui(ui, |ui| {
            for format in VectorFormat::ALL {
                ui.selectable_value(&mut state.views.vector_format, format, format.label());
            }
        });
        hint(ui, "lanes da mais alta para a mais baixa");
    });
}

// ---- pilha de chamadas ------------------------------------------------------

pub(super) fn call_stack_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal_wrapped(|ui| {
        ui.checkbox(&mut state.views.user_stack, "do kernel ao modo usuário").on_hover_text(
            "numa thread de um processo de usuário parada no kernel, a pilha segue pelo CONTEXT de usuário salvo da thread; o processo das leituras (.process) passa a ser o dela, a não ser que outro tenha sido escolhido à mão",
        );
        if !snapshot.user_stack_note.is_empty() {
            hint(ui, &snapshot.user_stack_note);
        }
    });
    ui.separator();
    if snapshot.frames.is_empty() {
        hint(ui, "sem pilha (a máquina não parou ainda)");
        return;
    }
    let root = crate::workspace_root();
    egui::ScrollArea::both().id_salt("stack").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("stack-grid").num_columns(7).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["#", "RSP do quadro", "endereço", "módulo", "função", "arquivo:linha", "como"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for (index, frame) in snapshot.frames.iter().enumerate() {
                if frame.user_start {
                    ui.label("");
                    ui.label("");
                    ui.label("");
                    ui.label(RichText::new("modo usuário").color(colors.yellow).strong());
                    ui.label(RichText::new(&snapshot.user_stack_note).color(colors.dim));
                    ui.label("");
                    ui.label("");
                    ui.end_row();
                }
                let selected = index == snapshot.selected_frame;
                ui.label(mono(format!("{index:02}")).color(colors.dim));
                ui.label(mono(hex(frame.stack)).color(colors.dim));
                ui.label(mono(hex(frame.address)).color(if frame.user { colors.green } else { ui.visuals().text_color() }));
                ui.label(mono(&frame.module).color(colors.blue));
                let response = ui.selectable_label(selected, mono(&frame.symbol)).on_hover_text(format!("{}\nclique: mostra o código deste quadro; botão direito: mais", frame.name));
                if response.clicked() {
                    state.requests.push(Request::SelectFrame(index));
                }
                response.context_menu(|ui| frame_menu(ui, state, index, frame));
                match &frame.line {
                    Some((file, line)) => {
                        ui.label(mono(format!("{}:{line}", relative(&root, file)))).on_hover_text(file.as_str());
                    }
                    None => {
                        ui.label("");
                    }
                }
                ui.label(RichText::new(frame.method).color(colors.dim));
                ui.end_row();
            }
        });
    });
}

fn frame_menu(ui: &mut Ui, state: &mut UiState, index: usize, frame: &FrameRow) {
    let stopped = state.status == Status::Stopped;
    if ui.button("Na desmontagem").clicked() {
        show_code(state, frame.address);
        ui.close();
    }
    if ui.button("Memória no RSP do quadro").clicked() {
        show_memory(state, format!("{:#x}", frame.stack));
        ui.close();
    }
    if index > 0 && ui.add_enabled(stopped, egui::Button::new("Executar até voltar a este quadro")).on_hover_text("breakpoint temporário no endereço de retorno (qualquer thread, qualquer profundidade)").clicked() {
        state.requests.push(Request::RunTo(frame.address));
        ui.close();
    }
    if ui.button("Copiar o nome").clicked() {
        ui.ctx().copy_text(frame.name.clone());
        ui.close();
    }
}

// ---- processos e threads ----------------------------------------------------

/// O processo das leituras (`.process`) e o botão de voltar ao processador.
fn process_context_line(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, colors: Palette) {
    let stopped = state.status == Status::Stopped;
    ui.horizontal_wrapped(|ui| match &snapshot.process_context {
        Some(context) => {
            ui.label(RichText::new(format!("processo das leituras: {} (PID {}), EPROCESS {:#x}, CR3 {:#x}, PEB {:#x}", context.name, context.pid, context.eprocess, context.cr3, context.peb)).color(colors.yellow));
            if ui.add_enabled(stopped, egui::Button::new("Voltar ao processador")).on_hover_text(".process 0: as leituras de usuário voltam ao CR3 do processador parado").clicked() {
                state.requests.push(Request::SetProcess(None));
            }
        }
        None => hint(ui, "processo das leituras: o do processador parado (botão direito num processo: .process)"),
    });
    ui.separator();
}

pub(super) fn processes_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    process_context_line(ui, state, &snapshot, colors);
    egui::ScrollArea::both().id_salt("processes").auto_shrink([false, false]).show(ui, |ui| {
        ui.label(RichText::new("Processos (clique: filtra as threads; botão direito: mais)").strong());
        egui::Grid::new("process-grid").num_columns(5).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["PID", "EPROCESS", "CR3", "threads", "nome"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for process in &snapshot.processes {
                let selected = state.thread_filter == Some(process.pid);
                let reading = snapshot.process_context.as_ref().is_some_and(|context| context.eprocess == process.eprocess);
                let user = process.pid > 4;
                let response = ui.selectable_label(selected, mono(process.pid.to_string()));
                if response.clicked() {
                    state.thread_filter = if selected { None } else { Some(process.pid) };
                }
                response.context_menu(|ui| {
                    if ui.button("!process").clicked() {
                        open_query(state, QueryKind::Process, format!("{:#x}", process.eprocess));
                        ui.close();
                    }
                    if ui.add_enabled(stopped && user, egui::Button::new("Usar nas leituras (.process)")).clicked() {
                        state.requests.push(Request::SetProcess(Some(format!("{:#x}", process.eprocess))));
                        ui.close();
                    }
                    if ui.add_enabled(stopped && user, egui::Button::new("Módulos do processo")).clicked() {
                        state.requests.push(Request::SetProcess(Some(format!("{:#x}", process.eprocess))));
                        state.focus_tab.push(Tab::Modules);
                        ui.close();
                    }
                    if ui.button("Threads do processo").clicked() {
                        state.thread_filter = Some(process.pid);
                        state.focus_tab.push(Tab::Threads);
                        ui.close();
                    }
                });
                ui.label(mono(hex(process.eprocess)));
                ui.label(mono(format!("{:x}", process.cr3)));
                ui.label(mono(process.threads.to_string()));
                let label = ui.label(mono(&process.name).color(if reading { colors.yellow } else { colors.blue }));
                if reading {
                    label.on_hover_text("o processo das leituras (.process)");
                }
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

pub(super) fn threads_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal_wrapped(|ui| {
        if let Some(pid) = state.thread_filter {
            ui.label(format!("só o processo {pid}"));
            if ui.button("todas").clicked() {
                state.thread_filter = None;
            }
            ui.separator();
        }
        ui.checkbox(&mut state.views.thread_details, "espera e prioridade").on_hover_text(
            "lê o KTHREAD de cada thread pelos offsets do PDB do ntoskrnl: uma leitura por thread a cada parada (com um processo escolhido, só as dele)",
        );
        if !snapshot.threads_note.is_empty() {
            hint(ui, &snapshot.threads_note);
        }
    });
    egui::ScrollArea::both().id_salt("threads").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("thread-grid").num_columns(9).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["PID", "TID", "ETHREAD", "estado", "espera", "prioridade", "tempo k/u", "início", "processo"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            let filter = state.thread_filter;
            for row in snapshot.threads.iter().filter(|row| filter.is_none_or(|pid| pid == row.thread.pid)) {
                let thread = &row.thread;
                let running = snapshot.processors.iter().find(|processor| processor.thread == thread.ethread).map(|processor| processor.number + 1);
                let shown_cpu = match snapshot.view {
                    View::Cpu(cpu) => Some(cpu),
                    View::Owner => snapshot.stop_processor.map(|number| number + 1),
                    View::Thread(_) => None,
                };
                let selected = snapshot.view == View::Thread(thread.ethread) || (running.is_some() && running == shown_cpu);
                ui.label(mono(thread.pid.to_string()));
                ui.label(mono(thread.tid.to_string()));
                let response = ui.selectable_label(selected, mono(hex(thread.ethread))).on_hover_text("clique: registradores e pilha desta thread; botão direito: !thread");
                if response.clicked() {
                    state.requests.push(Request::SelectThread(thread.ethread));
                }
                response.context_menu(|ui| {
                    if ui.button("!thread").clicked() {
                        open_query(state, QueryKind::Thread, format!("{:#x}", thread.ethread));
                        ui.close();
                    }
                    if ui.button("Memória no ETHREAD").clicked() {
                        state.views.memory_type = "_ETHREAD".to_string();
                        state.requests.push(Request::ShowMemoryAs("_ETHREAD".to_string()));
                        show_memory(state, format!("{:#x}", thread.ethread));
                        ui.close();
                    }
                });
                let detail = row.detail.as_ref();
                let state_text = detail.filter(|detail| !detail.state.is_empty()).map_or(thread.state.as_str(), |detail| detail.state.as_str());
                let state_color = match state_text {
                    "Running" => colors.green,
                    "Ready" | "Standby" | "DeferredReady" => colors.yellow,
                    _ => colors.dim,
                };
                let suspended = detail.and_then(|detail| detail.suspend_count).filter(|&count| count > 0);
                let label = ui.label(mono(match suspended {
                    Some(count) => format!("{state_text} (suspensa {count})"),
                    None => state_text.to_string(),
                }).color(state_color));
                if suspended.is_some() {
                    label.on_hover_text("SuspendCount do KTHREAD");
                }
                let wait = detail
                    .filter(|detail| !detail.wait_reason.is_empty())
                    .map(|detail| if detail.wait_mode.is_empty() { detail.wait_reason.clone() } else { format!("{} ({})", detail.wait_reason, detail.wait_mode) })
                    .unwrap_or_default();
                ui.label(mono(wait));
                let priority = detail
                    .and_then(|detail| detail.priority.map(|priority| match detail.base_priority {
                        Some(base) => format!("{priority} (base {base})"),
                        None => priority.to_string(),
                    }))
                    .unwrap_or_default();
                ui.label(mono(priority));
                let times = detail.and_then(|detail| Some(format!("{}/{}", detail.kernel_time?, detail.user_time?))).unwrap_or_default();
                ui.label(mono(times));
                ui.label(mono(&row.start));
                ui.label(mono(&thread.process));
                ui.end_row();
            }
        });
        hint(ui, "tempo k/u: KernelTime e UserTime do KTHREAD, em tiques do relógio");
    });
}

// ---- módulos ----------------------------------------------------------------

fn module_matches(module: &ModuleRow, filter: &str) -> bool {
    filter.is_empty() || module.name.to_ascii_lowercase().contains(filter) || module.path.to_ascii_lowercase().contains(filter)
}

pub(super) fn modules_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    ui.horizontal_wrapped(|ui| {
        ui.label("processo:");
        let current = snapshot.process_context.as_ref().map_or_else(|| "nenhum (só o sistema)".to_string(), |context| format!("{} (PID {})", context.name, context.pid));
        ui.add_enabled_ui(stopped, |ui| {
            egui::ComboBox::from_id_salt("modules-process").selected_text(current).width(220.0).show_ui(ui, |ui| {
                if ui.selectable_label(snapshot.process_context.is_none(), "nenhum (só o sistema)").clicked() {
                    state.requests.push(Request::SetProcess(None));
                }
                for process in snapshot.processes.iter().filter(|process| process.pid > 4) {
                    let chosen = snapshot.process_context.as_ref().is_some_and(|context| context.eprocess == process.eprocess);
                    if ui.selectable_label(chosen, format!("{} (PID {})", process.name, process.pid)).clicked() {
                        state.requests.push(Request::SetProcess(Some(format!("{:#x}", process.eprocess))));
                    }
                }
            });
        });
        if ui.add_enabled(stopped, egui::Button::new("Recarregar símbolos")).on_hover_text("lê a lista de módulos de novo e troca os PDBs que chegaram").clicked() {
            state.requests.push(Request::ReloadSymbols);
        }
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.views.module_filter).font(TextStyle::Monospace).desired_width(140.0).hint_text("nome ou caminho"));
        let pending = snapshot.modules.iter().filter(|module| module.pending).count();
        if pending > 0 {
            ui.spinner();
            hint(ui, &format!("baixando {pending} PDB(s) do servidor de símbolos"));
        }
    });
    ui.separator();
    let filter = state.views.module_filter.trim().to_ascii_lowercase();
    let user: Vec<&ModuleRow> = snapshot.modules.iter().filter(|module| module.user && module_matches(module, &filter)).collect();
    let system: Vec<&ModuleRow> = snapshot.modules.iter().filter(|module| !module.user && module_matches(module, &filter)).collect();
    egui::ScrollArea::both().id_salt("modules").auto_shrink([false, false]).show(ui, |ui| {
        if snapshot.process_context.is_some() || !user.is_empty() {
            let title = match &snapshot.process_context {
                Some(context) => format!("Usuário: {} (PID {}), {} módulos", context.name, context.pid, user.len()),
                None => format!("Usuário (do último processo das leituras), {} módulos", user.len()),
            };
            ui.label(RichText::new(title).strong());
            if user.is_empty() {
                hint(ui, "nenhum módulo de usuário (a PEB.Ldr vazia e nenhuma imagem no VAD, ou o filtro)");
            } else {
                module_grid(ui, state, "user-module-grid", &user, colors);
            }
            ui.add_space(8.0);
        }
        ui.label(RichText::new(format!("Sistema: {} módulos", system.len())).strong());
        module_grid(ui, state, "module-grid", &system, colors);
    });
}

fn module_grid(ui: &mut Ui, state: &mut UiState, id: &str, modules: &[&ModuleRow], colors: Palette) {
    egui::Grid::new(id).num_columns(7).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
        for title in ["nome", "base", "fim", "tamanho", "símbolos", "PDB", "caminho"] {
            ui.label(RichText::new(title).strong());
        }
        ui.end_row();
        for module in modules {
            if ui.link(mono(&module.name)).on_hover_text("detalhes do módulo (lmv)").clicked() {
                open_query(state, QueryKind::Module, module.name.clone());
            }
            ui.label(mono(hex(module.base)));
            ui.label(mono(hex(module.end)));
            ui.label(mono(format!("{:#x}", module.end.saturating_sub(module.base))));
            ui.label(mono(module.symbols.to_string()));
            let color = match module.status {
                PdbStatus::Elf | PdbStatus::Loaded(_) => colors.green,
                PdbStatus::Downloading => colors.yellow,
                PdbStatus::Failed(_) => colors.red,
                PdbStatus::ExportsOnly | PdbStatus::NoFile => colors.dim,
            };
            let mut tip = match &module.status {
                PdbStatus::Elf => "símbolos e linhas do kernel.elf (DWARF)".to_string(),
                PdbStatus::Loaded(path) => format!("PDB público em {path}"),
                PdbStatus::Downloading => "baixando do servidor de símbolos".to_string(),
                PdbStatus::Failed(error) => format!("o download falhou: {error}"),
                PdbStatus::ExportsOnly => "só os exports do arquivo desta máquina (sem RSDS ou sem download)".to_string(),
                PdbStatus::NoFile => "nenhum arquivo desta máquina para a imagem: sem símbolos nem .pdata (a tabela de funções vem da memória do alvo)".to_string(),
            };
            if !module.pdb_name.is_empty() {
                tip.push_str(&format!("\n{} {}", module.pdb_name, module.pdb_id));
            }
            tip.push_str(&format!("\norigem: {}", module.source));
            ui.label(RichText::new(module.status.label()).color(color)).on_hover_text(tip);
            ui.label(RichText::new(&module.path).color(colors.dim));
            ui.end_row();
        }
    });
}

// ---- memória ----------------------------------------------------------------

/// Segue um ponteiro na janela de memória (o de antes fica para o "voltar").
fn follow_pointer(state: &mut UiState, value: u64) {
    show_memory(state, format!("{value:#x}"));
}

pub(super) fn memory_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    ui.horizontal_wrapped(|ui| {
        ui.label("Endereço:");
        let response = ui.add(egui::TextEdit::singleline(&mut state.memory_address).font(TextStyle::Monospace).desired_width(240.0).hint_text("@rsp, símbolo, 0x..."));
        if ui.button("Ir").clicked() || (response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter))) {
            state.requests.push(Request::ShowMemory(state.memory_address.clone()));
        }
        if ui.add_enabled(!state.views.memory_history.is_empty(), egui::Button::new("< voltar")).on_hover_text("a expressão de antes do último ponteiro seguido").clicked() {
            if let Some(previous) = state.views.memory_history.pop() {
                state.memory_address = previous;
                state.requests.push(Request::ShowMemory(state.memory_address.clone()));
            }
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
        egui::ComboBox::from_id_salt("memory-format").selected_text(state.memory_format.label()).show_ui(ui, |ui| {
            for format in MemoryFormat::ALL {
                ui.selectable_value(&mut state.memory_format, format, format.label());
            }
        });
    });
    ui.horizontal_wrapped(|ui| {
        ui.label("Como tipo:");
        let response = ui.add(egui::TextEdit::singleline(&mut state.views.memory_type).font(TextStyle::Monospace).desired_width(170.0).hint_text("_EPROCESS, _IRP, _PEB..."));
        let submit = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
        if ui.add_enabled(stopped, egui::Button::new("Mostrar")).on_hover_text("a janela também como uma struct do PDB do ntoskrnl, campo a campo").clicked() || (submit && stopped) {
            state.requests.push(Request::ShowMemoryAs(state.views.memory_type.trim().to_string()));
        }
        if !snapshot.memory.type_name.is_empty() && ui.button("Tirar").clicked() {
            state.views.memory_type.clear();
            state.requests.push(Request::ShowMemoryAs(String::new()));
        }
        ui.separator();
        ui.label("Procurar:");
        ui.add(egui::TextEdit::singleline(&mut state.search_pattern).font(TextStyle::Monospace).desired_width(180.0).hint_text("48 8b 05 | \"texto\" | u\"texto\""));
        ui.label("bytes:");
        ui.add(egui::TextEdit::singleline(&mut state.search_length).font(TextStyle::Monospace).desired_width(80.0));
        if ui.add_enabled(stopped, egui::Button::new("Procurar")).on_hover_text("a partir do endereço acima").clicked() {
            let length = parse_hex(&state.search_length).unwrap_or(0x10000);
            state.requests.push(Request::SearchMemory { start: state.memory_address.clone(), length, pattern: state.search_pattern.clone() });
        }
    });
    if let Some(search) = &snapshot.search {
        ui.horizontal_wrapped(|ui| match &search.error {
            Some(error) => {
                ui.label(RichText::new(error).color(colors.red));
            }
            None => {
                ui.label(format!("{} ocorrências de {} a partir de {:#x}:", search.hits.len(), search.pattern, search.start));
                for &hit in search.hits.iter().take(32) {
                    if ui.link(mono(format!("{hit:#x}"))).clicked() {
                        show_memory(state, format!("{hit:#x}"));
                    }
                }
            }
        });
    }
    ui.separator();
    if let Some(error) = &snapshot.memory.error {
        ui.label(RichText::new(error).color(colors.red));
    }
    if let Some(error) = &snapshot.memory.type_error {
        ui.label(RichText::new(error).color(colors.red));
    }
    if snapshot.memory.bytes.is_empty() {
        hint(ui, "digite um endereço (com a máquina parada, clique num byte para editá-lo; os qwords azuis são ponteiros: clique segue, \"voltar\" desfaz)");
        return;
    }
    egui::ScrollArea::both().id_salt("memory").auto_shrink([false, false]).show(ui, |ui| {
        if let Some(key) = snapshot.memory.typed {
            egui::CollapsingHeader::new(mono(format!("{} em {:#x}", snapshot.memory.type_name, key.0))).id_salt(("memory-typed", key)).default_open(true).show(ui, |ui| {
                typed_tree(ui, state, key, 0);
            });
            ui.add_space(4.0);
        }
        match state.memory_format {
            MemoryFormat::Pointers => pointer_rows(ui, state, &snapshot, colors),
            format => byte_rows(ui, state, &snapshot, format, stopped, colors),
        }
    });
}

/// Um qword: azul e clicável quando parece ponteiro (o símbolo na dica).
fn qword_cell(ui: &mut Ui, state: &mut UiState, value: u64, symbol: Option<&str>, colors: Palette) {
    let text = mono(hex(value));
    if !details::looks_like_pointer(value) {
        ui.label(text);
        return;
    }
    let tip = match symbol {
        Some(symbol) => format!("{symbol}\nclique: segue o ponteiro"),
        None => "clique: segue o ponteiro".to_string(),
    };
    if ui.add(egui::Label::new(text.color(colors.blue)).sense(Sense::click())).on_hover_text(tip).clicked() {
        follow_pointer(state, value);
    }
}

/// Um qword por linha com o símbolo (o `dps` do WinDbg).
fn pointer_rows(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, colors: Palette) {
    egui::Grid::new("memory-pointers").num_columns(3).striped(true).spacing([12.0, 1.0]).show(ui, |ui| {
        for (index, chunk) in snapshot.memory.bytes.chunks_exact(8).enumerate() {
            let address = snapshot.memory.address + index as u64 * 8;
            let value = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            let symbol = snapshot.memory.pointers.get(index).cloned().flatten();
            ui.label(mono(hex(address)).color(colors.blue));
            qword_cell(ui, state, value, symbol.as_deref(), colors);
            ui.label(RichText::new(symbol.unwrap_or_default()).color(colors.dim));
            ui.end_row();
        }
    });
}

/// 16 bytes por linha em bytes, words, dwords, qwords, ASCII ou UTF-16.
fn byte_rows(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, format: MemoryFormat, editable: bool, colors: Palette) {
    for (row, chunk) in snapshot.memory.bytes.chunks(16).enumerate() {
        let base = snapshot.memory.address + row as u64 * 16;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            ui.label(mono(hex(base)).color(colors.blue));
            match format {
                MemoryFormat::Bytes => {
                    for (column, &byte) in chunk.iter().enumerate() {
                        let address = base + column as u64;
                        if state.memory_edit.as_ref().is_some_and(|(at, _)| *at == address) {
                            let Some((_, text)) = state.memory_edit.as_mut() else { return };
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
                    ui.label(mono(text).color(colors.dim));
                }
                MemoryFormat::Qwords => {
                    for (piece, bytes) in chunk.chunks(8).enumerate() {
                        let mut raw = [0u8; 8];
                        raw[..bytes.len()].copy_from_slice(bytes);
                        let value = u64::from_le_bytes(raw);
                        let symbol = snapshot.memory.pointers.get(row * 2 + piece).cloned().flatten();
                        qword_cell(ui, state, value, symbol.as_deref(), colors);
                    }
                }
                MemoryFormat::Words | MemoryFormat::Dwords => {
                    let unit = format.unit();
                    for piece in chunk.chunks(unit) {
                        let mut raw = [0u8; 8];
                        raw[..piece.len()].copy_from_slice(piece);
                        ui.label(mono(format!("{:0width$x}", u64::from_le_bytes(raw), width = unit * 2)));
                    }
                }
                MemoryFormat::Ascii => {
                    let text: String = chunk.iter().map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect();
                    ui.label(mono(text));
                }
                MemoryFormat::Unicode => {
                    let text: String = chunk
                        .chunks(2)
                        .map(|pair| {
                            let unit = u16::from_le_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
                            char::from_u32(unit as u32).filter(|character| !character.is_control()).unwrap_or('.')
                        })
                        .collect();
                    ui.label(mono(text));
                }
                MemoryFormat::Pointers => {}
            }
        });
    }
}

// ---- breakpoints ------------------------------------------------------------

pub(super) fn breakpoints_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    ui.horizontal_wrapped(|ui| {
        let hint_text = match state.breakpoint_kind {
            BreakpointKind::Module => "nome do módulo (ntfs.sys)",
            BreakpointKind::Event => "cpr[:nome] | epr[:nome] | ct[:pid] | et[:pid] | ld:processo!dll",
            kind if kind.is_memory() => "endereço (vale a página inteira)",
            _ => "símbolo ou endereço",
        };
        let response = ui.add(egui::TextEdit::singleline(&mut state.breakpoint_expression).font(TextStyle::Monospace).desired_width(240.0).hint_text(hint_text));
        egui::ComboBox::from_id_salt("breakpoint-kind").selected_text(state.breakpoint_kind.name()).show_ui(ui, |ui| {
            for kind in BREAKPOINT_KINDS {
                ui.selectable_value(&mut state.breakpoint_kind, kind, kind.name());
            }
        });
        ui.add(egui::TextEdit::singleline(&mut state.breakpoint_condition).font(TextStyle::Monospace).desired_width(150.0).hint_text("condição (@rcx==0)"));
        ui.add(egui::TextEdit::singleline(&mut state.breakpoint_pass).font(TextStyle::Monospace).desired_width(40.0).hint_text("N"));
        ui.checkbox(&mut state.breakpoint_deferred, "adiado").on_hover_text("aceita um símbolo de um módulo que ainda vai carregar (bu)");
        ui.checkbox(&mut state.views.breakpoint_more, "ações").on_hover_text("log, comandos e grupo do breakpoint novo");
        let submit = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
        if (ui.add_enabled(stopped, egui::Button::new("Adicionar")).clicked() || (submit && stopped)) && !state.breakpoint_expression.trim().is_empty() {
            let mut request = BreakpointRequest::new(state.breakpoint_kind, state.breakpoint_expression.trim());
            request.condition = state.breakpoint_condition.trim().to_string();
            request.pass_count = state.breakpoint_pass.trim().parse().unwrap_or(0);
            request.deferred = state.breakpoint_deferred;
            if state.views.breakpoint_more {
                request.log = state.views.breakpoint_log.trim().to_string();
                request.command = state.views.breakpoint_command.trim().to_string();
                request.group = state.views.breakpoint_group.trim().to_string();
            }
            state.requests.push(Request::AddBreakpointWith(request));
        }
    });
    if state.views.breakpoint_more {
        ui.horizontal_wrapped(|ui| {
            ui.label("log:");
            ui.add(egui::TextEdit::singleline(&mut state.views.breakpoint_log).font(TextStyle::Monospace).desired_width(260.0).hint_text("texto com {expr}: registra e segue sem parar"));
            ui.label("comandos:");
            ui.add(egui::TextEdit::singleline(&mut state.views.breakpoint_command).font(TextStyle::Monospace).desired_width(180.0).hint_text("r; k 5 (separados por ;)"));
            ui.label("grupo:");
            ui.add(egui::TextEdit::singleline(&mut state.views.breakpoint_group).font(TextStyle::Monospace).desired_width(90.0));
        });
    }
    let mut groups: Vec<&str> = snapshot.breakpoints.iter().map(|breakpoint| breakpoint.group.as_str()).filter(|group| !group.is_empty()).collect();
    groups.sort_unstable();
    groups.dedup();
    if !groups.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label("grupos:");
            for group in groups {
                ui.label(mono(group).color(colors.blue));
                if ui.add_enabled(stopped, egui::Button::new("ligar").small()).clicked() {
                    state.requests.push(Request::SetGroupEnabled(group.to_string(), true));
                }
                if ui.add_enabled(stopped, egui::Button::new("desligar").small()).clicked() {
                    state.requests.push(Request::SetGroupEnabled(group.to_string(), false));
                }
                ui.add_space(6.0);
            }
        });
    }
    ui.separator();
    if snapshot.breakpoints.is_empty() {
        hint(ui, "nenhum breakpoint (clique na margem da desmontagem ou F9; os da sessão voltam no próximo attach)");
        return;
    }
    egui::ScrollArea::both().id_salt("breakpoints").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("breakpoint-grid").num_columns(9).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["#", "ligado", "tipo", "endereço", "expressão", "condição / N", "ações", "acertos", ""] {
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
                breakpoint_address(ui, state, breakpoint, colors);
                ui.label(mono(&breakpoint.expression));
                breakpoint_condition(ui, state, breakpoint);
                let mut actions = Vec::new();
                if !breakpoint.log.is_empty() {
                    actions.push("log".to_string());
                }
                if !breakpoint.command.is_empty() {
                    actions.push("comandos".to_string());
                }
                if !breakpoint.group.is_empty() {
                    actions.push(format!("grupo {}", breakpoint.group));
                }
                if breakpoint.options.single_shot {
                    actions.push("uma vez".to_string());
                }
                if breakpoint.options.silent {
                    actions.push("silencioso".to_string());
                }
                let label = ui.label(mono(if actions.is_empty() { "-".to_string() } else { actions.join(", ") }));
                if !breakpoint.log.is_empty() || !breakpoint.command.is_empty() {
                    label.on_hover_text(format!("log: {}\ncomandos: {}", breakpoint.log, breakpoint.command));
                }
                ui.label(mono(breakpoint.hits.to_string()));
                ui.horizontal(|ui| {
                    if ui.add_enabled(stopped, egui::Button::new("editar")).clicked() {
                        state.views.breakpoint_edit = Some(BreakpointEdit::of(breakpoint));
                    }
                    if ui.add_enabled(stopped, egui::Button::new("remover")).clicked() {
                        state.requests.push(Request::RemoveBreakpoint(breakpoint.id));
                    }
                });
                ui.end_row();
            }
        });
        breakpoint_editor(ui, state, colors);
    });
}

fn breakpoint_address(ui: &mut Ui, state: &mut UiState, breakpoint: &Breakpoint, colors: Palette) {
    match breakpoint.kind {
        BreakpointKind::Module => {
            ui.label(mono("ao carregar").color(colors.dim));
        }
        BreakpointKind::Event => {
            ui.label(mono("no evento").color(colors.dim));
        }
        _ if breakpoint.pending => {
            ui.label(mono("(adiado)").color(colors.yellow));
        }
        kind => {
            let mut tip = if kind.is_memory() || matches!(kind, BreakpointKind::Write | BreakpointKind::Access) {
                format!("{} bytes; clique: mostra na memória", breakpoint.length)
            } else {
                "clique: mostra na desmontagem".to_string()
            };
            if breakpoint.process != 0 {
                tip.push_str(&format!("\nprocesso: EPROCESS {:#x}", breakpoint.process));
            }
            if ui.add(egui::Label::new(mono(hex(breakpoint.address)).color(colors.blue)).sense(Sense::click())).on_hover_text(tip).clicked() {
                if kind.is_memory() || matches!(kind, BreakpointKind::Write | BreakpointKind::Access) {
                    show_memory(state, format!("{:#x}", breakpoint.address));
                } else {
                    show_code(state, breakpoint.address);
                }
            }
        }
    }
}

/// A condição e a contagem, editáveis na própria linha.
fn breakpoint_condition(ui: &mut Ui, state: &mut UiState, breakpoint: &Breakpoint) {
    let editing = state.condition_edit.as_ref().is_some_and(|(id, _, _)| *id == breakpoint.id);
    if editing {
        ui.horizontal(|ui| {
            let Some((id, condition, pass)) = state.condition_edit.as_mut() else { return };
            ui.add(egui::TextEdit::singleline(condition).font(TextStyle::Monospace).desired_width(120.0));
            ui.add(egui::TextEdit::singleline(pass).font(TextStyle::Monospace).desired_width(36.0));
            if ui.button("ok").clicked() {
                state.requests.push(Request::SetBreakpointCondition(*id, condition.clone(), pass.trim().parse().unwrap_or(0)));
                state.condition_edit = None;
            }
        });
        return;
    }
    let text = match (breakpoint.condition.is_empty(), breakpoint.pass_count > 1) {
        (true, false) => "-".to_string(),
        (false, false) => breakpoint.condition.clone(),
        (true, true) => format!("a partir de {}", breakpoint.pass_count),
        (false, true) => format!("{} a partir de {}", breakpoint.condition, breakpoint.pass_count),
    };
    if ui.add(egui::Label::new(mono(text)).sense(Sense::click())).on_hover_text("clique para editar a condição e a contagem").clicked() {
        state.condition_edit = Some((breakpoint.id, breakpoint.condition.clone(), if breakpoint.pass_count > 1 { breakpoint.pass_count.to_string() } else { String::new() }));
    }
}

/// O editor das opções de um breakpoint (o botão "editar" da linha).
fn breakpoint_editor(ui: &mut Ui, state: &mut UiState, colors: Palette) {
    let stopped = state.status == Status::Stopped;
    let Some(edit) = state.views.breakpoint_edit.as_mut() else { return };
    let mut save = None;
    let mut close = false;
    ui.add_space(8.0);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.label(RichText::new(format!("breakpoint #{}: {} ({})", edit.id, edit.expression, edit.kind.name())).strong().color(colors.blue));
        egui::Grid::new("breakpoint-editor").num_columns(2).spacing([10.0, 3.0]).show(ui, |ui| {
            let field = |ui: &mut Ui, label: &str, text: &mut String, placeholder: &str| {
                ui.label(label);
                ui.add(egui::TextEdit::singleline(text).font(TextStyle::Monospace).desired_width(320.0).hint_text(placeholder));
                ui.end_row();
            };
            field(ui, "nome", &mut edit.name, "");
            field(ui, "condição", &mut edit.condition, "@rcx==0 (vazia: sempre)");
            field(ui, "a partir do acerto", &mut edit.pass, "N");
            field(ui, "log", &mut edit.log, "texto com {expr}");
            field(ui, "condição do log", &mut edit.log_condition, "vazia: sempre");
            field(ui, "comandos", &mut edit.command, "separados por ;");
            field(ui, "condição dos comandos", &mut edit.command_condition, "vazia: quando para");
            field(ui, "grupo", &mut edit.group, "");
        });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut edit.enabled, "ligado");
            ui.checkbox(&mut edit.single_shot, "uma vez só");
            ui.checkbox(&mut edit.silent, "sem a linha de acerto no log");
            ui.checkbox(&mut edit.fast_resume, "retorno rápido").on_hover_text("quando não para, segue na hora: sem reler os módulos nem a linha de acerto");
        });
        ui.horizontal(|ui| {
            if ui.add_enabled(stopped, egui::Button::new("Gravar")).on_hover_text("os acertos voltam a zero").clicked() {
                save = Some((edit.id, edit.request()));
                close = true;
            }
            if ui.button("Cancelar").clicked() {
                close = true;
            }
        });
    });
    if let Some((id, request)) = save {
        state.requests.push(Request::EditBreakpoint(id, request));
    }
    if close {
        state.views.breakpoint_edit = None;
    }
}

// ---- log da COM1 ------------------------------------------------------------

/// As linhas completas do log que passam no filtro (só as novas a cada
/// quadro; o filtro novo ou o log recomeçado refazem tudo).
fn update_serial_rows(views: &mut ViewsState, log: &LogLines) {
    let filter = views.serial_filter.trim().to_ascii_lowercase();
    let complete = log.lines.len();
    if views.serial_scanned.0 != filter || views.serial_scanned.1 > complete {
        views.serial_rows.clear();
        views.serial_scanned = (filter.clone(), 0);
    }
    if filter.is_empty() {
        views.serial_scanned.1 = complete;
        return;
    }
    for index in views.serial_scanned.1..complete {
        if log.lines[index].to_ascii_lowercase().contains(&filter) {
            views.serial_rows.push(index);
        }
    }
    views.serial_scanned.1 = complete;
}

pub(super) fn serial_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.views.serial_filter).font(TextStyle::Monospace).desired_width(180.0).hint_text("texto (sem diferença de caixa)"));
        ui.checkbox(&mut state.views.serial_follow, "seguir o fim");
        let mut chosen = None;
        if !state.views.serial_marks.is_empty() {
            let marks = &state.views.serial_marks;
            egui::ComboBox::from_id_salt("serial-marks").selected_text(format!("{} paradas", marks.len())).width(320.0).show_ui(ui, |ui| {
                for (index, (line, stop)) in marks.iter().enumerate().rev().take(300) {
                    if ui.selectable_label(false, mono(format!("{:>4}  linha {line}: {}", index + 1, truncate(stop, 70)))).clicked() {
                        chosen = Some(*line);
                    }
                }
            });
        }
        if let Some(line) = chosen {
            state.views.serial_scroll = Some(line);
            state.views.serial_follow = false;
        }
        ui.separator();
        ui.label("arquivo:");
        let response = ui.add(egui::TextEdit::singleline(&mut state.views.serial_path).font(TextStyle::Monospace).desired_width(200.0).hint_text("build/serial.log"));
        let submit = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
        if (ui.button("Abrir").on_hover_text("acompanha este arquivo (o serial.log de um xtask aberto à parte); relativo à raiz do repositório").clicked() || submit) && !state.views.serial_path.trim().is_empty() {
            state.requests.push(Request::SetSerialLog(Some(crate::workspace_root().join(state.views.serial_path.trim()))));
        }
    });
    ui.separator();
    if state.serial.count() == 0 {
        hint(ui, "(o log da COM1 aparece aqui quando o depurador abre o QEMU, ou pelo arquivo acima; cada parada fica marcada em amarelo na linha em que aconteceu)");
        return;
    }
    update_serial_rows(&mut state.views, &state.serial);
    let scroll = state.views.serial_scroll.take();
    let views = &state.views;
    let log = &state.serial;
    let filter = views.serial_scanned.0.as_str();
    let filtered = !filter.is_empty();
    let partial_match = filtered && !log.partial.is_empty() && log.partial.to_ascii_lowercase().contains(filter);
    let row_count = if filtered { views.serial_rows.len() + usize::from(partial_match) } else { log.count() };
    let line_of = |row: usize| if filtered { views.serial_rows.get(row).copied().unwrap_or(log.lines.len()) } else { row };
    let marks = &views.serial_marks;
    let mark_at = |line: usize| {
        let index = marks.partition_point(|(mark, _)| *mark < line);
        marks.get(index).filter(|(mark, _)| *mark == line).map(|(_, stop)| (index + 1, stop.as_str()))
    };
    let height = row_height(ui);
    let mut area = egui::ScrollArea::both().id_salt("serial").auto_shrink([false, false]).stick_to_bottom(views.serial_follow);
    if let Some(line) = scroll {
        let position = if filtered { views.serial_rows.partition_point(|&candidate| candidate < line) } else { line.min(row_count.saturating_sub(1)) };
        area = area.vertical_scroll_offset((position as f32 * height - 120.0).max(0.0));
    }
    area.show_rows(ui, height, row_count, |ui, range| {
        let last = row_count.saturating_sub(1);
        for row in range {
            let line = line_of(row);
            let response = ui.label(mono(log.line(line)));
            let clip = ui.clip_rect();
            let rect = response.rect;
            let mut stops = Vec::new();
            // A parada com o log neste tamanho: a marca fica em cima da
            // próxima linha (ou embaixo da última).
            if let Some(found) = mark_at(line) {
                ui.painter().line_segment([egui::pos2(clip.left(), rect.top()), egui::pos2(clip.right(), rect.top())], Stroke::new(1.5, colors.yellow));
                stops.push(found);
            }
            if row == last && !filtered {
                if let Some(found) = mark_at(log.count()) {
                    ui.painter().line_segment([egui::pos2(clip.left(), rect.bottom()), egui::pos2(clip.right(), rect.bottom())], Stroke::new(1.5, colors.yellow));
                    stops.push(found);
                }
            }
            if !stops.is_empty() {
                let text: Vec<String> = stops.iter().map(|(number, stop)| format!("parada {number}: {stop}")).collect();
                response.on_hover_text(text.join("\n"));
            }
        }
    });
}
