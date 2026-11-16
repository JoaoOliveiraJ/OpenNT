//! A aba CPU: desmontagem com as setas dos desvios e a caixa de informação
//! (em cima, à esquerda), registradores com flags e segmentos (em cima, à
//! direita), Dump 1-5 (embaixo, à esquerda) e a pilha com os endereços de
//! retorno nomeados (embaixo, à direita).

use std::collections::HashMap;
use std::sync::Arc;

use eframe::egui::{self, Align2, Color32, FontId, Key, Pos2, Rect, RichText, Sense, Stroke, TextStyle, Ui, Vec2};
use kd_client::BreakpointKind;

use crate::app::*;
use crate::backend::{Request, SearchKind, Status, View};
use crate::disasm::Line;

pub(crate) fn cpu_tab(ui: &mut Ui, state: &mut UiState) {
    let height = ui.available_height();
    let width = ui.available_width();
    egui::Panel::bottom("cpu-bottom").resizable(true).default_size(height * 0.36).min_size(80.0).show(ui, |ui| {
        egui::Panel::right("cpu-stack").resizable(true).default_size(width * 0.40).min_size(160.0).show(ui, |ui| stack_pane(ui, state));
        egui::CentralPanel::default().show(ui, |ui| dump_pane(ui, state));
    });
    egui::Panel::right("cpu-registers").resizable(true).default_size((width * 0.27).max(300.0)).min_size(200.0).show(ui, |ui| registers_pane(ui, state));
    egui::CentralPanel::default().show(ui, |ui| {
        egui::Panel::bottom("cpu-info").resizable(true).default_size(84.0).min_size(30.0).show(ui, |ui| info_pane(ui, state));
        egui::CentralPanel::default().show(ui, |ui| disassembly_pane(ui, state));
    });
}

/// A cor do mnemônico pela classe da instrução.
fn mnemonic_color(text: &str, colors: Palette, default: Color32) -> Color32 {
    let mnemonic = text.split_whitespace().next().unwrap_or("");
    match mnemonic {
        "call" => colors.blue,
        "ret" | "retn" | "iretq" | "sysret" | "int3" | "ud2" | "hlt" => colors.red,
        "jmp" => colors.yellow,
        _ if mnemonic.starts_with('j') || mnemonic.starts_with("loop") => colors.yellow,
        "push" | "pop" => colors.dim,
        "nop" | "int" => colors.dim,
        _ => default,
    }
}

/// As setas dos desvios que começam e terminam na janela: (de, para,
/// coluna). As colunas não se cruzam em faixas sobrepostas.
fn jump_arrows(lines: &[Line]) -> Vec<(usize, usize, usize)> {
    let index: HashMap<u64, usize> = lines.iter().enumerate().map(|(row, line)| (line.address, row)).collect();
    let mut jumps: Vec<(usize, usize)> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| !line.text.starts_with("call"))
        .filter_map(|(row, line)| line.target.and_then(|target| index.get(&target).map(|&to| (row, to))))
        .filter(|(from, to)| from != to)
        .collect();
    jumps.sort_by_key(|(from, to)| from.abs_diff(*to));
    let mut columns: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut arrows = Vec::new();
    for (from, to) in jumps {
        let (low, high) = (from.min(to), from.max(to));
        let column = columns.iter().position(|used| used.iter().all(|&(a, b)| high < a || low > b)).unwrap_or_else(|| {
            columns.push(Vec::new());
            columns.len() - 1
        });
        columns[column].push((low, high));
        arrows.push((from, to, column.min(7)));
    }
    arrows
}

fn disassembly_pane(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal(|ui| {
        let module = snapshot.code.lines.first().and_then(|line| state.module_at(line.address)).map(|module| module.name.clone()).unwrap_or_default();
        let thread = match snapshot.view {
            View::UserThread(tid) => format!("thread de usuário {tid}"),
            View::Thread(ethread) => format!("ETHREAD {ethread:#x}"),
            View::Cpu(thread) => format!("CPU {}", thread.saturating_sub(1)),
            View::Owner => snapshot.stop_processor.map(|number| format!("CPU {number}")).unwrap_or_default(),
        };
        ui.label(RichText::new(format!("Módulo: {module}")).strong());
        ui.label(RichText::new(thread).color(colors.dim));
        if let Some(exception) = &snapshot.exception {
            ui.label(RichText::new(exception).color(colors.red));
        }
        if ui.small_button("RIP (*)").on_hover_text("volta à instrução corrente").clicked() {
            state.selected_code = None;
            state.requests.push(Request::ShowCode(String::new()));
            state.requests.push(Request::SelectInstruction(None));
        }
        if ui.small_button("Ir para (Ctrl+G)").clicked() {
            state.dialog = Some(Dialog::GoTo(String::new()));
        }
    });
    if let Some(error) = &snapshot.code.error {
        ui.label(RichText::new(error).color(colors.red));
    }
    let lines = &snapshot.code.lines;
    if lines.is_empty() {
        hint(ui, "sem código (a máquina não parou ainda)");
        return;
    }
    let rip = current_rip(&snapshot);
    let font = FontId::monospace(ui.text_style_height(&TextStyle::Monospace) - 1.0);
    let height = row_height(ui);
    let glyph = ui.fonts_mut(|fonts| fonts.glyph_width(&font, '0'));
    let arrows = jump_arrows(lines);
    let arrow_columns = arrows.iter().map(|(_, _, column)| column + 1).max().unwrap_or(0).max(2);
    let gutter = 18.0 + arrow_columns as f32 * 7.0;
    let address_width = glyph * 17.0;
    let bytes_width = glyph * 21.0;
    let text_color = ui.visuals().text_color();
    // Rola até o foco quando chega um snapshot novo.
    let focus_row = lines.iter().position(|line| line.address == snapshot.code.focus);
    let mut area = egui::ScrollArea::both().id_salt("cpu-code").auto_shrink([false, false]);
    let code_key = snapshot.code.focus ^ lines[0].address.rotate_left(32) ^ lines.len() as u64;
    if state.scrolled_code != code_key {
        state.scrolled_code = code_key;
        if let Some(row) = focus_row {
            let viewport = ui.available_height();
            area = area.vertical_scroll_offset((row as f32 * height - viewport * 0.35).max(0.0));
        }
    }
    let mut row_rects: Vec<Rect> = Vec::with_capacity(lines.len());
    let mut clicked_row = None;
    let mut menu_row = None;
    let output = area.show(ui, |ui| {
        let total_width = (gutter + address_width + bytes_width + glyph * 70.0).max(ui.available_width());
        for (row, line) in lines.iter().enumerate() {
            let (rect, response) = ui.allocate_exact_size(Vec2::new(total_width, height), Sense::click());
            row_rects.push(rect);
            let painter = ui.painter_at(rect);
            let selected = state.selected_code == Some(line.address);
            let is_rip = Some(line.address) == rip;
            if is_rip {
                painter.rect_filled(rect, 0.0, colors.current);
            } else if selected {
                painter.rect_filled(rect, 0.0, colors.selection);
            } else if state.executed.contains(&line.address) {
                painter.rect_filled(rect, 0.0, colors.executed);
            }
            let line_color = if is_rip { Color32::WHITE } else { text_color };
            let breakpoint = snapshot.breakpoints.iter().find(|breakpoint| breakpoint.address == line.address && !breakpoint.pending && matches!(breakpoint.kind, BreakpointKind::Software | BreakpointKind::Hardware));
            // A margem: breakpoint e marcador.
            let marker = Pos2::new(rect.left() + 7.0, rect.center().y);
            if let Some(breakpoint) = breakpoint {
                if breakpoint.enabled {
                    painter.circle_filled(marker, 4.5, colors.red);
                } else {
                    painter.circle_stroke(marker, 4.5, Stroke::new(1.5, colors.red));
                }
            }
            if state.bookmarked(line.address) {
                painter.rect_filled(Rect::from_center_size(Pos2::new(rect.left() + 14.0, rect.center().y), Vec2::new(4.0, height - 4.0)), 1.0, colors.blue);
            }
            // O endereço (ou o rótulo do usuário, ou o símbolo da função).
            let mut x = rect.left() + gutter;
            let address_rect = Rect::from_min_size(Pos2::new(x, rect.top()), Vec2::new(address_width - glyph, height));
            if breakpoint.is_some_and(|breakpoint| breakpoint.enabled) {
                painter.rect_filled(address_rect, 0.0, colors.breakpoint);
            }
            let user_label = state.label_at(line.address).cloned();
            let (address_text, address_color) = match (&user_label, &line.label) {
                (Some(label), _) => (format!("{label}:"), colors.label),
                (None, Some(label)) if !is_rip => (format!("<{}>", label.rsplit('!').next().unwrap_or(label)), colors.label),
                _ => (hex(line.address), if breakpoint.is_some_and(|breakpoint| breakpoint.enabled) { Color32::WHITE } else { line_color }),
            };
            painter.text(Pos2::new(x, rect.center().y), Align2::LEFT_CENTER, truncate_to(&address_text, 17), font.clone(), address_color);
            x += address_width;
            let bytes: String = line.bytes.as_bytes().chunks(2).map(|pair| std::str::from_utf8(pair).unwrap_or("")).collect::<Vec<_>>().join(" ");
            painter.text(Pos2::new(x, rect.center().y), Align2::LEFT_CENTER, truncate_to(&bytes, 20), font.clone(), if is_rip { line_color } else { colors.dim });
            x += bytes_width;
            let (mnemonic, operands) = line.text.split_once(' ').unwrap_or((line.text.as_str(), ""));
            let mnemonic_paint = if is_rip { line_color } else { mnemonic_color(&line.text, colors, line_color) };
            painter.text(Pos2::new(x, rect.center().y), Align2::LEFT_CENTER, mnemonic, font.clone(), mnemonic_paint);
            let operand_x = x + glyph * 8.0;
            let galley = painter.layout_no_wrap(operands.trim().to_string(), font.clone(), line_color);
            let operand_width = galley.size().x;
            painter.galley(Pos2::new(operand_x, rect.center().y - galley.size().y / 2.0), galley, line_color);
            let comment_x = (operand_x + operand_width + glyph * 2.0).max(x + glyph * 44.0);
            if let Some(comment) = state.comment_at(line.address) {
                painter.text(Pos2::new(comment_x, rect.center().y), Align2::LEFT_CENTER, format!("; {comment}"), font.clone(), if is_rip { line_color } else { colors.comment });
            } else if let Some(comment) = &line.comment {
                painter.text(Pos2::new(comment_x, rect.center().y), Align2::LEFT_CENTER, comment, font.clone(), if is_rip { line_color } else { colors.dim });
            }
            if response.clicked() || response.secondary_clicked() {
                clicked_row = Some(row);
            }
            if response.double_clicked() {
                if let Some(target) = line.target {
                    state.go_to_code(target);
                } else if let Some(memory) = line.memory {
                    state.follow_in_dump(memory);
                }
            }
            response.context_menu(|ui| {
                menu_row = Some(row);
                code_menu(ui, state, line);
            });
        }
    });
    if let Some(row) = clicked_row.or(menu_row) {
        if let Some(line) = lines.get(row) {
            if state.selected_code != Some(line.address) {
                state.selected_code = Some(line.address);
                state.requests.push(Request::SelectInstruction(Some(line.address)));
            }
        }
    }
    // As setas dos desvios na margem (a da linha escolhida mais forte).
    let clip = output.inner_rect;
    let painter = ui.painter_at(clip);
    let selected_row = state.selected_code.and_then(|address| lines.iter().position(|line| line.address == address)).or_else(|| rip.and_then(|rip| lines.iter().position(|line| line.address == rip)));
    for (from, to, column) in arrows {
        let (Some(start), Some(end)) = (row_rects.get(from), row_rects.get(to)) else { continue };
        let x_edge = start.left() + gutter - 4.0;
        let x = x_edge - 6.0 - column as f32 * 7.0;
        let active = selected_row == Some(from);
        let color = if active { colors.red } else { colors.dim.gamma_multiply(0.7) };
        let stroke = Stroke::new(if active { 1.6 } else { 1.0 }, color);
        let (y0, y1) = (start.center().y, end.center().y);
        painter.line_segment([Pos2::new(x_edge, y0), Pos2::new(x, y0)], stroke);
        painter.line_segment([Pos2::new(x, y0), Pos2::new(x, y1)], stroke);
        painter.line_segment([Pos2::new(x, y1), Pos2::new(x_edge, y1)], stroke);
        painter.add(egui::Shape::convex_polygon(vec![Pos2::new(x_edge + 1.0, y1), Pos2::new(x_edge - 4.0, y1 - 3.0), Pos2::new(x_edge - 4.0, y1 + 3.0)], color, Stroke::NONE));
    }
}

fn truncate_to(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}

/// O menu de contexto de uma linha da desmontagem.
pub(crate) fn code_menu(ui: &mut Ui, state: &mut UiState, line: &Line) {
    let address = line.address;
    let stopped = state.status == Status::Stopped;
    if ui.add_enabled(stopped, egui::Button::new("Breakpoint").shortcut_text("F2")).clicked() {
        state.requests.push(Request::ToggleBreakpoint(address));
        ui.close();
    }
    if ui.add_enabled(stopped, egui::Button::new("Executar até aqui").shortcut_text("F4")).clicked() {
        state.requests.push(Request::RunToCursor(address));
        ui.close();
    }
    ui.separator();
    if ui.add(egui::Button::new("Comentário").shortcut_text(";")).clicked() {
        let current = state.comment_at(address).cloned().unwrap_or_default();
        state.dialog = Some(Dialog::Comment(address, current));
        ui.close();
    }
    if ui.add(egui::Button::new("Rótulo").shortcut_text(":")).clicked() {
        let current = state.label_at(address).cloned().unwrap_or_default();
        state.dialog = Some(Dialog::Label(address, current));
        ui.close();
    }
    if ui.button(if state.bookmarked(address) { "Tirar o marcador" } else { "Marcador" }).clicked() {
        let location = state.location(address);
        state.notes.toggle_bookmark(location);
        ui.close();
    }
    if ui.add_enabled(stopped, egui::Button::new("Montar").shortcut_text("Espaço")).clicked() {
        state.dialog = Some(Dialog::Assemble(address, String::new()));
        ui.close();
    }
    ui.separator();
    if let Some(target) = line.target {
        if ui.button(format!("Seguir na desmontagem ({target:#x})")).clicked() {
            state.go_to_code(target);
            ui.close();
        }
    }
    let follow = line.memory.or(line.target);
    if ui.add_enabled(follow.is_some(), egui::Button::new("Seguir no dump")).clicked() {
        if let Some(target) = follow {
            state.follow_in_dump(target);
        }
        ui.close();
    }
    if ui.button("Seguir este endereço no dump").clicked() {
        state.follow_in_dump(address);
        ui.close();
    }
    if ui.add_enabled(stopped, egui::Button::new("Grafo da função").shortcut_text("G")).clicked() {
        state.requests.push(Request::Graph(format!("{address:#x}")));
        state.focus_tab.push(Tab::Graph);
        ui.close();
    }
    ui.separator();
    ui.add_enabled_ui(stopped, |ui| {
        ui.menu_button("Procurar", |ui| {
            ui.menu_button("Módulo atual", |ui| {
                if ui.button("Referências a strings").clicked() {
                    state.selected_code = Some(address);
                    state.search(SearchKind::StringReferences, false);
                    ui.close();
                }
                if ui.button("Chamadas entre módulos").clicked() {
                    state.selected_code = Some(address);
                    state.search(SearchKind::IntermodularCalls, false);
                    ui.close();
                }
                if ui.button("Constante...").clicked() {
                    state.selected_code = Some(address);
                    state.dialog = Some(Dialog::Constant(String::new(), false));
                    ui.close();
                }
                if ui.button("Padrão...").clicked() {
                    state.selected_code = Some(address);
                    state.dialog = Some(Dialog::Pattern(String::new(), false));
                    ui.close();
                }
                if ui.button("Strings soltas").clicked() {
                    state.selected_code = Some(address);
                    state.search(SearchKind::Strings, false);
                    ui.close();
                }
            });
            ui.menu_button("Todos os módulos", |ui| {
                if ui.button("Referências a strings").clicked() {
                    state.search(SearchKind::StringReferences, true);
                    ui.close();
                }
                if ui.button("Chamadas entre módulos").clicked() {
                    state.search(SearchKind::IntermodularCalls, true);
                    ui.close();
                }
                if ui.button("Constante...").clicked() {
                    state.dialog = Some(Dialog::Constant(String::new(), true));
                    ui.close();
                }
            });
        });
        if ui.button("Referências a este endereço (xrefs)").clicked() {
            state.selected_code = Some(address);
            state.search(SearchKind::References(format!("{address:#x}")), false);
            ui.close();
        }
    });
    if ui.button("Copiar o endereço").clicked() {
        ui.ctx().copy_text(format!("{address:#x}"));
        ui.close();
    }
}

fn info_pane(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    egui::ScrollArea::vertical().id_salt("cpu-info").auto_shrink([false, false]).show(ui, |ui| {
        if snapshot.info_box.is_empty() {
            hint(ui, "caixa de informação: operandos da instrução escolhida");
        }
        for line in &snapshot.info_box {
            ui.label(mono(line));
        }
        if let Some(address) = state.selected_code {
            let location = state.location(address);
            ui.label(mono(location.display()).color(colors.dim));
        }
    });
}

/// A ordem dos registradores gerais na janela.
const GENERAL_ORDER: [&str; 17] = ["rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
const FLAGS: [(&str, u32); 9] = [("ZF", 6), ("PF", 2), ("AF", 4), ("OF", 11), ("SF", 7), ("DF", 10), ("CF", 0), ("TF", 8), ("IF", 9)];
const SEGMENTS: [&str; 6] = ["gs", "fs", "es", "ds", "cs", "ss"];

fn registers_pane(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal(|ui| {
        let selected = match snapshot.view {
            View::Owner => snapshot.stop_processor.map(|number| number + 1),
            View::Cpu(thread) => Some(thread),
            _ => None,
        };
        let text = match (snapshot.view, selected) {
            (View::Thread(ethread), _) => format!("ETHREAD {ethread:#x}"),
            (View::UserThread(tid), _) => format!("TID {tid}"),
            (_, Some(thread)) => format!("CPU {}", thread - 1),
            _ => "CPU".to_string(),
        };
        egui::ComboBox::from_id_salt("re-cpu").selected_text(text).show_ui(ui, |ui| {
            for &thread in &snapshot.stopped_threads {
                let owner = snapshot.stop_processor == Some(thread - 1);
                let label = format!("CPU {}{}", thread - 1, if owner { " (parada)" } else { "" });
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
    let value_of = |name: &str| snapshot.registers.iter().find(|row| row.name == name);
    egui::ScrollArea::vertical().id_salt("re-registers").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("re-register-grid").num_columns(3).spacing([10.0, 1.0]).show(ui, |ui| {
            for name in GENERAL_ORDER {
                if let Some(row) = value_of(name) {
                    register_row(ui, state, row, editable, colors);
                    ui.end_row();
                }
            }
        });
        ui.add_space(6.0);
        let flags = value_of("eflags").and_then(|row| row.value);
        if let Some(flags) = flags {
            ui.label(mono(format!("RFLAGS  {flags:016X}")).strong());
            egui::Grid::new("re-flags").num_columns(6).spacing([8.0, 1.0]).show(ui, |ui| {
                for (index, (name, bit)) in FLAGS.iter().enumerate() {
                    let set = flags >> bit & 1;
                    let label = ui.add(egui::Label::new(mono(format!("{name} {set}")).color(if set != 0 { colors.blue } else { ui.visuals().text_color() })).sense(Sense::click()));
                    if editable && label.on_hover_text("clique duplo: inverte a flag").double_clicked() {
                        state.requests.push(Request::WriteRegister("eflags".into(), flags ^ (1 << bit)));
                    }
                    if index % 3 == 2 {
                        ui.end_row();
                    }
                }
            });
        }
        ui.add_space(6.0);
        egui::Grid::new("re-segments").num_columns(4).spacing([8.0, 1.0]).show(ui, |ui| {
            for (index, name) in SEGMENTS.iter().enumerate() {
                let value = value_of(name).and_then(|row| row.value).map_or("????".to_string(), |value| format!("{value:04X}"));
                ui.label(mono(name.to_ascii_uppercase()).color(colors.blue));
                ui.label(mono(value));
                if index % 2 == 1 {
                    ui.end_row();
                }
            }
        });
        ui.add_space(6.0);
        for name in ["fs_base", "gs_base"] {
            if let Some(value) = value_of(name).and_then(|row| row.value) {
                ui.label(mono(format!("{:<8}{value:016X}", name.to_ascii_uppercase())));
            }
        }
        if snapshot.user_mode {
            ui.label(mono("modo usuário (GS = TEB)").color(colors.green));
        }
        // O que não está acima (o x87/SSE do protocolo e o que vier).
        let shown: Vec<&str> = GENERAL_ORDER.iter().chain(SEGMENTS.iter()).copied().chain(["eflags", "fs_base", "gs_base"]).collect();
        let rest: Vec<_> = snapshot.registers.iter().filter(|row| !shown.contains(&row.name.as_str())).collect();
        if !rest.is_empty() {
            ui.add_space(6.0);
            egui::CollapsingHeader::new("outros").default_open(false).show(ui, |ui| {
                for row in rest {
                    ui.label(mono(format!("{:<8}{}", row.name, row.value.map_or("????".into(), |value| format!("{value:016X}")))));
                }
            });
        }
    });
}

fn register_row(ui: &mut Ui, state: &mut UiState, row: &crate::backend::RegisterRow, editable: bool, colors: Palette) {
    ui.label(mono(row.name.to_ascii_uppercase()).color(colors.blue));
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
        ui.label("");
        return;
    }
    let text = row.value.map_or("????????????????".into(), |value| format!("{value:016X}"));
    let label = ui.add(egui::Label::new(mono(text).color(if row.changed { colors.red } else { ui.visuals().text_color() })).sense(Sense::click()));
    let label = label.on_hover_text("clique duplo: edita (Enter grava); botão direito: seguir");
    if editable && label.double_clicked() {
        state.register_edit = Some((row.name.clone(), row.value.map(hex).unwrap_or_default()));
    }
    if let Some(value) = row.value {
        label.context_menu(|ui| {
            if ui.button("Seguir na desmontagem").clicked() {
                state.go_to_code(value);
                ui.close();
            }
            if ui.button("Seguir no dump").clicked() {
                state.follow_in_dump(value);
                ui.close();
            }
        });
        // O símbolo do valor, quando ele aponta para uma imagem.
        let note = state.snapshot.register_notes.get(&row.name).cloned().or_else(|| state.module_at(value).map(|module| format!("{}+{:#x}", module.name, value - module.base))).unwrap_or_default();
        ui.label(mono(note).color(colors.dim));
    } else {
        ui.label("");
    }
}

fn dump_pane(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal(|ui| {
        for index in 0..5 {
            if ui.selectable_label(state.dump_tab == index, format!("Dump {}", index + 1)).clicked() {
                state.dump_tab = index;
            }
        }
        ui.separator();
        let index = state.dump_tab;
        let response = ui.add(egui::TextEdit::singleline(&mut state.dump_inputs[index]).font(TextStyle::Monospace).desired_width(200.0).hint_text("@rsp, símbolo, 0x..."));
        if ui.small_button("Ir").clicked() || (response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter))) {
            state.requests.push(Request::ShowDump(index, state.dump_inputs[index].clone()));
        }
        let dump = snapshot.dumps.get(index);
        if let Some(dump) = dump.filter(|dump| !dump.bytes.is_empty()) {
            if ui.small_button("-0x200").clicked() {
                state.dump_inputs[index] = format!("{:#x}", dump.address.wrapping_sub(0x200));
                state.requests.push(Request::ShowDump(index, state.dump_inputs[index].clone()));
            }
            if ui.small_button("+0x200").clicked() {
                state.dump_inputs[index] = format!("{:#x}", dump.address.wrapping_add(0x200));
                state.requests.push(Request::ShowDump(index, state.dump_inputs[index].clone()));
            }
        }
        egui::ComboBox::from_id_salt(("dump-format", index)).selected_text(state.dump_formats[index].label()).show_ui(ui, |ui| {
            for format in MemoryFormat::ALL {
                ui.selectable_value(&mut state.dump_formats[index], format, format.label());
            }
        });
    });
    let index = state.dump_tab;
    let Some(dump) = snapshot.dumps.get(index) else {
        hint(ui, "sem memória (a máquina não parou ainda)");
        return;
    };
    if let Some(error) = &dump.error {
        ui.label(RichText::new(error).color(colors.red));
    }
    if dump.bytes.is_empty() {
        hint(ui, "digite um endereço; clique num byte para editá-lo (vira patch); clique duplo num qword segue o ponteiro");
        return;
    }
    let editable = state.status == Status::Stopped;
    let format = state.dump_formats[index];
    egui::ScrollArea::both().id_salt(("dump", index)).auto_shrink([false, false]).show(ui, |ui| {
        for (row, chunk) in dump.bytes.chunks(16).enumerate() {
            let base = dump.address + row as u64 * 16;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(mono(hex(base)).color(colors.blue));
                match format {
                    MemoryFormat::HexAscii | MemoryFormat::HexUnicode => {
                        for (column, &byte) in chunk.iter().enumerate() {
                            let address = base + column as u64;
                            if state.memory_edit.as_ref().is_some_and(|(at, _)| *at == address) {
                                let Some((_, text)) = state.memory_edit.as_mut() else { return };
                                let response = ui.add(egui::TextEdit::singleline(text).font(TextStyle::Monospace).desired_width(18.0).char_limit(2));
                                response.request_focus();
                                if response.lost_focus() {
                                    if ui.input(|input| input.key_pressed(Key::Enter)) {
                                        if let Ok(value) = u8::from_str_radix(text.trim(), 16) {
                                            state.requests.push(Request::Patch { address, bytes: vec![value] });
                                        }
                                    }
                                    state.memory_edit = None;
                                }
                            } else {
                                let patched = snapshot.patches.iter().any(|patch| address >= patch.address && address < patch.address + patch.patched.len() as u64);
                                let label = ui.add(egui::Label::new(mono(format!("{byte:02X}")).color(if patched { colors.red } else { ui.visuals().text_color() })).sense(Sense::click()));
                                if editable && label.clicked() {
                                    state.memory_edit = Some((address, format!("{byte:02x}")));
                                }
                            }
                            if column == 7 {
                                ui.add_space(4.0);
                            }
                        }
                        ui.add_space(8.0);
                        let text: String = if format == MemoryFormat::HexAscii {
                            chunk.iter().map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect()
                        } else {
                            chunk.chunks(2).map(|pair| char::from_u32(u16::from_le_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32).filter(|character| !character.is_control()).unwrap_or('.')).collect()
                        };
                        ui.label(mono(text).color(colors.dim));
                    }
                    MemoryFormat::Words | MemoryFormat::Dwords | MemoryFormat::Qwords | MemoryFormat::Address => {
                        let unit = match format {
                            MemoryFormat::Words => 2,
                            MemoryFormat::Dwords => 4,
                            _ => 8,
                        };
                        for piece in chunk.chunks(unit) {
                            let mut raw = [0u8; 8];
                            raw[..piece.len()].copy_from_slice(piece);
                            let value = u64::from_le_bytes(raw);
                            let label = ui.add(egui::Label::new(mono(format!("{value:0width$X}", width = unit * 2))).sense(Sense::click()));
                            if unit == 8 && label.double_clicked() {
                                state.dump_inputs[index] = format!("{value:#x}");
                                state.requests.push(Request::ShowDump(index, state.dump_inputs[index].clone()));
                            }
                            if format == MemoryFormat::Address {
                                if let Some(module) = state.module_at(value) {
                                    ui.label(mono(format!("{}+{:#x}", module.name, value - module.base)).color(colors.green));
                                }
                            }
                        }
                    }
                    MemoryFormat::Float => {
                        for piece in chunk.chunks(4) {
                            let value = f32::from_le_bytes([piece[0], *piece.get(1).unwrap_or(&0), *piece.get(2).unwrap_or(&0), *piece.get(3).unwrap_or(&0)]);
                            ui.label(mono(format!("{value:>14.6e}")));
                        }
                    }
                    MemoryFormat::Double => {
                        for piece in chunk.chunks(8) {
                            let mut raw = [0u8; 8];
                            raw[..piece.len()].copy_from_slice(piece);
                            ui.label(mono(format!("{:>24.12e}", f64::from_le_bytes(raw))));
                        }
                    }
                }
            });
        }
    });
}

fn stack_pane(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let rsp = snapshot.registers.iter().find(|row| row.name == "rsp").and_then(|row| row.value);
    if snapshot.stack.is_empty() {
        hint(ui, "sem pilha (a máquina não parou ainda)");
        return;
    }
    let height = row_height(ui);
    let mut area = egui::ScrollArea::both().id_salt("cpu-stack").auto_shrink([false, false]);
    if let Some(row) = snapshot.stack.iter().position(|row| Some(row.address) == rsp) {
        let stack_key = rsp.unwrap_or(0) ^ snapshot.stack[0].address.rotate_left(32);
        if state.scrolled_stack != stack_key {
            state.scrolled_stack = stack_key;
            area = area.vertical_scroll_offset((row as f32 * height - height * 2.0).max(0.0));
        }
    }
    area.show(ui, |ui| {
        for row in &snapshot.stack {
            let current = Some(row.address) == rsp;
            let response = ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.label(mono(hex(row.address)).color(if current { colors.red } else { colors.dim }));
                let value = ui.add(egui::Label::new(mono(hex(row.value))).sense(Sense::click()));
                let note_color = if row.note.starts_with("retorno") { colors.red } else { colors.green };
                ui.label(mono(&row.note).color(note_color));
                value
            });
            let value = response.inner;
            if current {
                ui.painter().rect_stroke(response.response.rect, 0.0, Stroke::new(1.0, colors.red), egui::StrokeKind::Inside);
            }
            if value.double_clicked() {
                if state.module_at(row.value).is_some() {
                    state.go_to_code(row.value);
                } else {
                    state.follow_in_dump(row.value);
                }
            }
            let address = row.value;
            value.context_menu(|ui| {
                if ui.button("Seguir na desmontagem").clicked() {
                    state.go_to_code(address);
                    ui.close();
                }
                if ui.button("Seguir no dump").clicked() {
                    state.follow_in_dump(address);
                    ui.close();
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::jump_arrows;
    use crate::disasm::Line;

    fn line(address: u64, text: &str, target: Option<u64>) -> Line {
        Line { address, bytes: String::new(), text: text.into(), label: None, comment: None, target, memory: None }
    }

    #[test]
    fn arrows_get_separate_columns() {
        let lines = vec![line(0, "je 3", Some(3)), line(1, "jmp 4", Some(4)), line(2, "nop", None), line(3, "nop", None), line(4, "call 0", Some(0))];
        let arrows = jump_arrows(&lines);
        assert_eq!(arrows.len(), 2);
        // As duas faixas se sobrepõem: colunas diferentes; a chamada não tem seta.
        assert_ne!(arrows[0].2, arrows[1].2);
    }
}
