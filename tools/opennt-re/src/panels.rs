//! Os painéis herdados do depurador gráfico do kernel, adaptados: código-
//! fonte, observação, variáveis locais, módulos, threads, objetos do NT,
//! análise do bugcheck e o rastro de instruções (a lista de processos fica
//! na aba Processos, `processes.rs`).

use std::sync::Arc;

use eframe::egui::{self, Align2, FontId, Key, RichText, Sense, TextStyle, Ui};
use opennt_kd::commands::TraceOptions;

use crate::app::*;
use crate::backend::{QueryKind, Request, Status, TraceView, View};
use crate::disasm::{self, ValueHint};

pub(crate) fn source_panel(ui: &mut Ui, state: &mut UiState) {
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

pub(crate) fn watch_panel(ui: &mut Ui, state: &mut UiState) {
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
                        // O valor que mudou desde a parada anterior em vermelho.
                        let changed = row.is_some_and(|row| row.changed);
                        ui.label(mono(value).color(if changed { colors.red } else { ui.visuals().text_color() })).on_hover_text(if changed { "mudou desde a parada anterior" } else { "igual à parada anterior" });
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

pub(crate) fn locals_panel(ui: &mut Ui, state: &mut UiState) {
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


pub(crate) fn modules_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    ui.horizontal(|ui| {
        if ui.add_enabled(state.status == Status::Stopped, egui::Button::new("Recarregar símbolos")).on_hover_text("lê a lista de módulos de novo e troca os PDBs que chegaram").clicked() {
            state.requests.push(Request::ReloadSymbols);
        }
        let pending = snapshot.modules.iter().filter(|module| module.pending).count();
        if pending > 0 {
            ui.spinner();
            hint(ui, &format!("baixando {pending} PDB(s) do servidor de símbolos"));
        }
    });
    egui::ScrollArea::both().id_salt("modules").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("module-grid").num_columns(6).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["nome", "base", "fim", "símbolos", "PDB", "origem"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for module in &snapshot.modules {
                if ui.link(mono(&module.name)).on_hover_text("detalhes do módulo (lmv)").clicked() {
                    state.query_kind = QueryKind::Module;
                    state.query_argument = module.name.clone();
                    state.requests.push(Request::Query(QueryKind::Module, module.name.clone()));
                    state.focus_tab.push(Tab::NtObjects);
                }
                ui.label(mono(hex(module.base)));
                ui.label(mono(hex(module.end)));
                ui.label(mono(module.symbols.to_string()));
                ui.label(if module.pdb { RichText::new("sim").color(colors.green) } else if module.pending { RichText::new("baixando").color(colors.yellow) } else { RichText::new("-").color(colors.dim) });
                ui.label(RichText::new(&module.source).color(colors.dim));
                ui.end_row();
            }
        });
    });
}

pub(crate) fn threads_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
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
                let selected = snapshot.view == View::Thread(thread.ethread)
                    || (running.is_some()
                        && running
                            == match snapshot.view {
                                View::Cpu(cpu) => Some(cpu),
                                View::Owner => snapshot.stop_processor.map(|number| number + 1),
                                View::Thread(_) | View::UserThread(_) => None,
                            });
                ui.label(mono(thread.pid.to_string()));
                ui.label(mono(thread.tid.to_string()));
                let response = ui.selectable_label(selected, mono(hex(thread.ethread))).on_hover_text("clique: registradores e pilha desta thread; botão direito: !thread");
                if response.clicked() {
                    state.requests.push(Request::SelectThread(thread.ethread));
                }
                response.context_menu(|ui| {
                    if ui.button("!thread").clicked() {
                        state.query_kind = QueryKind::Thread;
                        state.query_argument = format!("{:#x}", thread.ethread);
                        state.requests.push(Request::Query(QueryKind::Thread, state.query_argument.clone()));
                        state.focus_tab.push(Tab::NtObjects);
                        ui.close();
                    }
                });
                ui.label(mono(&thread.state).color(if thread.state == "Running" { colors.green } else { colors.dim }));
                ui.label(mono(&row.start));
                ui.label(mono(&thread.process));
                ui.end_row();
            }
        });
    });
}


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
                        state.follow_in_dump(value);
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
                            state.go_to_code(value);
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

pub(crate) fn nt_objects_panel(ui: &mut Ui, state: &mut UiState) {
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

pub(crate) fn bugcheck_panel(ui: &mut Ui, state: &mut UiState) {
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

pub(crate) fn trace_panel(ui: &mut Ui, state: &mut UiState) {
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
            state.go_to_code(record.rip);
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