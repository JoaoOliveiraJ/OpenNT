//! As abas de engenharia reversa fora da CPU: Log, Notas, Breakpoints,
//! Mapa de memória, Pilha de chamadas, SEH, Script, Símbolos, Referências e
//! Strings, Threads, Handles, Patches e Comentários/Rótulos.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui::{self, Key, RichText, Sense, TextStyle, Ui};
use kd_client::client::BreakpointRequest;
use kd_client::BreakpointKind;

use crate::app::*;
use crate::backend::{ReferenceRow, Request, SearchKind, SearchQuery, SearchScope, Status, View};

/// O filtro das tabelas: texto sem diferença de caixa ou expressão
/// regular.
pub(crate) struct Filter {
    text: String,
    regex: Option<regex::Regex>,
    pub(crate) error: Option<String>,
}

impl Filter {
    pub(crate) fn new(text: &str, use_regex: bool) -> Filter {
        if use_regex && !text.is_empty() {
            match regex::RegexBuilder::new(text).case_insensitive(true).build() {
                Ok(regex) => Filter { text: String::new(), regex: Some(regex), error: None },
                Err(error) => Filter { text: String::new(), regex: None, error: Some(error.to_string()) },
            }
        } else {
            Filter { text: text.to_lowercase(), regex: None, error: None }
        }
    }

    pub(crate) fn matches(&self, fields: &[&str]) -> bool {
        if let Some(regex) = &self.regex {
            return fields.iter().any(|field| regex.is_match(field));
        }
        if self.error.is_some() {
            return false;
        }
        self.text.is_empty() || fields.iter().any(|field| field.to_lowercase().contains(&self.text))
    }
}

/// As linhas de uma lista grande que passam no filtro, refeitas só quando a
/// lista, a sub-lista ou o filtro mudam: filtrar dezenas de milhares de
/// linhas (com as letras minúsculas de cada campo) a cada quadro deixa a
/// janela lenta.
#[derive(Default)]
pub(crate) struct FilteredRows {
    /// A lista (o endereço do `Arc`), a sub-lista, o texto e se é regex.
    key: Option<(usize, usize, String, bool)>,
    pub(crate) rows: Vec<usize>,
    /// O erro da expressão regular.
    pub(crate) error: Option<String>,
}

impl FilteredRows {
    pub(crate) fn update(&mut self, list: usize, mode: usize, filter: &str, regex: bool, count: usize, matches: impl Fn(usize, &Filter) -> bool) -> &[usize] {
        let key = (list, mode, filter.to_string(), regex);
        if self.key.as_ref() != Some(&key) {
            let compiled = Filter::new(filter, regex);
            self.rows = (0..count).filter(|&index| matches(index, &compiled)).collect();
            self.error = compiled.error.clone();
            self.key = Some(key);
        }
        &self.rows
    }
}

fn header(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).strong());
}

/// A aba Log: as mensagens do depurador (comandos, breakpoints de log,
/// roteiros), o DbgPrint, a COM1 e os eventos da janela, em rolagem
/// virtual.
pub(crate) fn log_tab(ui: &mut Ui, state: &mut UiState) {
    ui.horizontal(|ui| {
        for (index, label) in ["Depurador", "DbgPrint", "COM1", "Eventos"].iter().enumerate() {
            if ui.selectable_label(state.log_mode == index, *label).clicked() {
                state.log_mode = index;
            }
        }
        ui.separator();
        if ui.small_button("Copiar").on_hover_text("copia o texto desta vista").clicked() {
            crate::copy_text::copy_tab(ui.ctx(), state, Tab::Log);
        }
    });
    ui.separator();
    match state.log_mode {
        1 => log_panel(ui, &state.console, "re-dbgprint", "(nenhuma saída do DbgPrint ainda; os breakpoints de log também aparecem aqui)"),
        2 => log_panel(ui, &state.serial, "re-serial", "(o log da COM1 aparece aqui quando o depurador abre o QEMU)"),
        crate::console::EVENTS_MODE => crate::console::events_view(ui, state, "re-log-events"),
        _ => {
            if state.transcript_lines.is_empty() {
                hint(ui, "a saída dos comandos (barra de comando embaixo), dos roteiros e dos breakpoints com comandos aparece aqui");
                if state.launch_log.count() > 0 {
                    log_panel(ui, &state.launch_log, "re-log-launch", "");
                }
            } else {
                crate::console::transcript_view(ui, state, "re-log");
            }
        }
    }
}

/// A aba Notas: texto livre da sessão (gravado na pasta do build).
pub(crate) fn notes_tab(ui: &mut Ui, state: &mut UiState) {
    let path = state.session_notes_path.as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| "(sem pasta de sessão)".into());
    hint(ui, &format!("notas livres desta sessão, gravadas em {path}"));
    egui::ScrollArea::vertical().id_salt("re-notes").auto_shrink([false, false]).show(ui, |ui| {
        ui.add(egui::TextEdit::multiline(&mut state.session_notes).font(TextStyle::Monospace).desired_width(f32::INFINITY).desired_rows(30));
    });
}

/// A aba Breakpoints: tipo, endereço, símbolo, estado, acertos, condição,
/// log, comandos, grupo e processo; edição, grupos e a vigia de faixa.
pub(crate) fn breakpoints_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    ui.horizontal_wrapped(|ui| {
        egui::ComboBox::from_id_salt("re-bp-kind").selected_text(state.breakpoint_kind.name()).show_ui(ui, |ui| {
            for kind in [BreakpointKind::Software, BreakpointKind::Hardware, BreakpointKind::Write, BreakpointKind::Access, BreakpointKind::MemoryAccess, BreakpointKind::MemoryWrite, BreakpointKind::MemoryExecute, BreakpointKind::Module, BreakpointKind::Event] {
                ui.selectable_value(&mut state.breakpoint_kind, kind, kind.name());
            }
        });
        let hint_text = match state.breakpoint_kind {
            BreakpointKind::Module => "módulo (ntfs.sys)",
            BreakpointKind::Event => "cpr[:nome] epr ct et ld:csrss!winsrv.dll",
            _ => "símbolo ou endereço",
        };
        ui.add(egui::TextEdit::singleline(&mut state.breakpoint_expression).font(TextStyle::Monospace).desired_width(220.0).hint_text(hint_text));
        ui.add(egui::TextEdit::singleline(&mut state.breakpoint_condition).font(TextStyle::Monospace).desired_width(140.0).hint_text("condição"));
        ui.add(egui::TextEdit::singleline(&mut state.breakpoint_pass).font(TextStyle::Monospace).desired_width(50.0).hint_text("N"));
        ui.add(egui::TextEdit::singleline(&mut state.breakpoint_log).font(TextStyle::Monospace).desired_width(180.0).hint_text("log: texto {@rcx}"));
        ui.add(egui::TextEdit::singleline(&mut state.breakpoint_command).font(TextStyle::Monospace).desired_width(120.0).hint_text("comandos: r; k"));
        ui.add(egui::TextEdit::singleline(&mut state.breakpoint_group).font(TextStyle::Monospace).desired_width(80.0).hint_text("grupo"));
        ui.checkbox(&mut state.breakpoint_deferred, "adiado");
        if ui.add_enabled(stopped && !state.breakpoint_expression.trim().is_empty(), egui::Button::new("Adicionar")).clicked() {
            let mut request = BreakpointRequest::new(state.breakpoint_kind, &state.breakpoint_expression);
            request.condition = state.breakpoint_condition.clone();
            request.pass_count = state.breakpoint_pass.trim().parse().unwrap_or(0);
            request.deferred = state.breakpoint_deferred;
            request.log = state.breakpoint_log.clone();
            request.command = state.breakpoint_command.clone();
            request.group = state.breakpoint_group.clone();
            state.requests.push(Request::AddBreakpointWith(request));
        }
        if ui.add_enabled(stopped, egui::Button::new("Vigiar faixa...")).on_hover_text("escrita ou acesso numa faixa, com até quatro comparadores de hardware").clicked() {
            state.dialog = Some(Dialog::RangeWatch(String::new(), "10".into(), true));
        }
        if ui.add_enabled(stopped, egui::Button::new("Editor...")).on_hover_text("o editor completo: condição de parada, log e condição de log, comandos e condição de comando, nome, contagem, uma vez só, silencioso, retorno rápido").clicked() {
            state.breakpoint_form = Some(crate::editor::BreakpointForm::new(state.breakpoint_kind, &state.breakpoint_expression));
        }
    });
    // Os grupos.
    let mut groups: Vec<String> = snapshot.breakpoints.iter().map(|breakpoint| breakpoint.group.clone()).filter(|group| !group.is_empty()).collect();
    groups.sort();
    groups.dedup();
    if !groups.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label("grupos:");
            for group in groups {
                let enabled = snapshot.breakpoints.iter().filter(|breakpoint| breakpoint.group == group).any(|breakpoint| breakpoint.enabled);
                if ui.add_enabled(stopped, egui::Button::new(format!("{group} ({})", if enabled { "desligar" } else { "ligar" }))).clicked() {
                    state.requests.push(Request::SetGroupEnabled(group.clone(), !enabled));
                }
            }
        });
    }
    // A edição de um breakpoint.
    if let Some((id, condition, pass, log, command, group)) = state.breakpoint_edit.as_mut() {
        let id = *id;
        let mut apply = false;
        let mut cancel = false;
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("#{id}:"));
            ui.add(egui::TextEdit::singleline(condition).font(TextStyle::Monospace).desired_width(160.0).hint_text("condição"));
            ui.add(egui::TextEdit::singleline(pass).font(TextStyle::Monospace).desired_width(50.0).hint_text("N"));
            ui.add(egui::TextEdit::singleline(log).font(TextStyle::Monospace).desired_width(180.0).hint_text("log"));
            ui.add(egui::TextEdit::singleline(command).font(TextStyle::Monospace).desired_width(140.0).hint_text("comandos"));
            ui.add(egui::TextEdit::singleline(group).font(TextStyle::Monospace).desired_width(80.0).hint_text("grupo"));
            apply = ui.button("Aplicar").clicked();
            cancel = ui.button("Cancelar").clicked();
        });
        if apply {
            let (condition, pass, log, command, group) = (condition.clone(), pass.trim().parse().unwrap_or(0), log.clone(), command.clone(), group.clone());
            state.requests.push(Request::SetBreakpointCondition(id, condition, pass));
            state.requests.push(Request::SetBreakpointActions(id, log, command, group));
            state.breakpoint_edit = None;
        } else if cancel {
            state.breakpoint_edit = None;
        }
    }
    ui.separator();
    egui::ScrollArea::both().id_salt("re-breakpoints").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("re-bp-grid").num_columns(13).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["#", "tipo", "endereço", "símbolo / expressão", "nome", "estado", "acertos", "condição", "log", "comandos", "opções", "grupo", "processo"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for breakpoint in &snapshot.breakpoints {
                let response = ui.add(egui::Label::new(mono(format!("{}", breakpoint.id))).sense(Sense::click()));
                ui.label(breakpoint.kind.name());
                let address = if breakpoint.pending || matches!(breakpoint.kind, BreakpointKind::Module | BreakpointKind::Event) { "-".to_string() } else { hex(breakpoint.address) };
                let link = ui.add(egui::Label::new(mono(address).color(colors.blue)).sense(Sense::click()));
                if link.double_clicked() && breakpoint.address != 0 {
                    state.go_to_code(breakpoint.address);
                }
                ui.label(mono(&breakpoint.expression));
                ui.label(&breakpoint.options.name);
                let mut enabled = breakpoint.enabled;
                if ui.add_enabled(stopped, egui::Checkbox::new(&mut enabled, if breakpoint.pending { "adiado" } else { "" })).changed() {
                    state.requests.push(Request::EnableBreakpoint(breakpoint.id, enabled));
                }
                ui.label(mono(breakpoint.hits.to_string()));
                let pass = if breakpoint.pass_count > 1 { format!(" a partir de {}", breakpoint.pass_count) } else { String::new() };
                ui.label(mono(format!("{}{pass}", breakpoint.condition)));
                let log = if breakpoint.options.log_condition.is_empty() { breakpoint.log.clone() } else { format!("{} (se {})", breakpoint.log, breakpoint.options.log_condition) };
                ui.label(mono(log).color(colors.green));
                let command = if breakpoint.options.command_condition.is_empty() { breakpoint.command.clone() } else { format!("{} (se {})", breakpoint.command, breakpoint.options.command_condition) };
                ui.label(mono(command));
                let options = [(breakpoint.options.single_shot, "uma vez"), (breakpoint.options.silent, "silencioso"), (breakpoint.options.fast_resume, "rápido")].iter().filter(|(on, _)| *on).map(|(_, name)| *name).collect::<Vec<_>>().join(", ");
                ui.label(options);
                ui.label(mono(&breakpoint.group));
                ui.label(mono(if breakpoint.process != 0 { format!("{:#x}", breakpoint.process) } else { String::new() }));
                ui.end_row();
                let id = breakpoint.id;
                let copy = breakpoint.clone();
                response.union(link).context_menu(|ui| {
                    if ui.button("Editar...").clicked() {
                        state.breakpoint_form = Some(crate::editor::BreakpointForm::from_breakpoint(&copy));
                        ui.close();
                    }
                    if ui.button("Editar na linha").clicked() {
                        state.breakpoint_edit = Some((id, copy.condition.clone(), if copy.pass_count > 1 { copy.pass_count.to_string() } else { String::new() }, copy.log.clone(), copy.command.clone(), copy.group.clone()));
                        ui.close();
                    }
                    if ui.add_enabled(stopped, egui::Button::new("Remover")).clicked() {
                        state.requests.push(Request::RemoveBreakpoint(id));
                        ui.close();
                    }
                });
            }
        });
        hint(ui, "botão direito no número: editar ou remover; clique duplo no endereço: vai à aba CPU");
    });
}

/// A aba Mapa de memória.
pub(crate) fn memory_map_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    ui.horizontal(|ui| {
        if ui.add_enabled(stopped, egui::Button::new("Atualizar")).clicked() {
            state.requests.push(Request::LoadMemoryMap);
        }
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.map_filter).desired_width(200.0));
        if let Some(map) = &snapshot.memory_map {
            ui.label(RichText::new(format!("{}: {} linhas", map.title, map.rows.len())).strong());
        }
    });
    let Some(map) = &snapshot.memory_map else {
        hint(ui, "Atualizar lê o mapa: no kernel, as imagens com as seções e as faixas de sistema; com um processo escolhido (aba Processos), as regiões de usuário dele (VAD)");
        return;
    };
    if let Some(error) = &map.error {
        ui.label(RichText::new(error).color(colors.red));
    }
    let filter = Filter::new(&state.map_filter, false);
    let rows: Vec<&crate::backend::MapRow> = map.rows.iter().filter(|row| filter.matches(&[&row.name, &row.kind, &row.section, &row.protection, &row.content, &row.party])).collect();
    let height = row_height(ui);
    let highlight = state.map_highlight;
    hint(ui, "as regiões executáveis ficam em vermelho; botão direito no endereço: seguir, buscas e gravar a região num arquivo");
    egui::ScrollArea::both().id_salt("re-map").auto_shrink([false, false]).show_rows(ui, height, rows.len() + 1, |ui, range| {
        egui::Grid::new("re-map-grid").num_columns(8).striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
            for title in ["Endereço", "Tamanho", "Parte", "Informação", "Conteúdo", "Tipo", "Proteção", "Proteção inicial"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for index in range.start.saturating_sub(1)..range.end.saturating_sub(1).min(rows.len()) {
                let row = rows[index];
                let section = row.kind == "Seção";
                let marked = highlight.is_some_and(|address| address >= row.base && address < row.base + row.size);
                let color = if marked { colors.yellow } else if row.executable { colors.red } else { ui.visuals().text_color() };
                let address = ui.add(egui::Label::new(mono(if section { format!("  {}", hex(row.base)) } else { hex(row.base) }).color(if marked { colors.yellow } else { colors.blue })).sense(Sense::click()));
                ui.label(mono(format!("{:x}", row.size)).color(color));
                ui.label(mono(&row.party).color(colors.dim));
                let info = if row.section.is_empty() { row.name.clone() } else { format!("{} {}", row.name, row.section) };
                ui.label(mono(info).color(color));
                ui.label(mono(&row.content).color(color));
                ui.label(mono(&row.kind).color(if section { colors.dim } else { color }));
                ui.label(mono(&row.protection).color(color));
                ui.label(mono(&row.initial_protection).color(colors.dim));
                ui.end_row();
                let base = row.base;
                let size = row.size;
                if address.double_clicked() {
                    state.follow_in_dump(base);
                }
                address.context_menu(|ui| {
                    if ui.add_enabled(stopped, egui::Button::new("Gravar a região num arquivo...")).clicked() {
                        state.dialog = Some(Dialog::DumpRegion(base, format!("{size:x}"), state.dump_path.clone()));
                        ui.close();
                    }
                    if ui.add_enabled(stopped, egui::Button::new("Breakpoint de memória (acesso)")).clicked() {
                        state.requests.push(Request::AddBreakpointWith({
                            let mut request = BreakpointRequest::new(BreakpointKind::MemoryAccess, &format!("{base:#x}"));
                            request.length = size.min(64 * 0x1000);
                            request
                        }));
                        ui.close();
                    }
                    if ui.button("Seguir no dump").clicked() {
                        state.follow_in_dump(base);
                        ui.close();
                    }
                    if ui.button("Seguir na desmontagem").clicked() {
                        state.go_to_code(base);
                        ui.close();
                    }
                    if ui.button("Strings soltas nesta faixa").clicked() {
                        state.requests.push(Request::Search(SearchQuery { kind: SearchKind::Strings, scope: SearchScope::Range(format!("{base:#x}"), size.min(16 << 20)) }));
                        state.focus_tab.push(Tab::Strings);
                        ui.close();
                    }
                    if ui.button("Referências a strings nesta faixa").clicked() {
                        state.requests.push(Request::Search(SearchQuery { kind: SearchKind::StringReferences, scope: SearchScope::Range(format!("{base:#x}"), size.min(16 << 20)) }));
                        state.focus_tab.push(Tab::References);
                        ui.close();
                    }
                });
            }
        });
    });
}

/// A aba Pilha de chamadas: o endereço do quadro na pilha, para onde volta
/// (Para), de qual função (De), o tamanho do quadro, o comentário, a parte
/// (usuário ou sistema), os argumentos e o método do desenrolar.
pub(crate) fn call_stack_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    if snapshot.frames.is_empty() {
        hint(ui, "sem pilha (a máquina não parou ainda)");
        return;
    }
    hint(ui, "Para: o endereço de retorno; De: a função de onde ele volta; argumentos: os slots de home (rcx, rdx, r8, r9) e os dois primeiros da pilha");
    egui::ScrollArea::both().id_salt("re-callstack").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("re-callstack-grid").num_columns(9).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["#", "Endereço", "Para", "De", "Tamanho", "Comentário", "Parte", "argumentos", "como"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for (index, frame) in snapshot.frames.iter().enumerate() {
                let callee = index.checked_sub(1).and_then(|below| snapshot.frames.get(below));
                let from = callee.map(|below| below.name.split('+').next().unwrap_or(&below.name).to_string()).unwrap_or_default();
                let size = callee.map(|below| frame.stack.saturating_sub(below.stack)).unwrap_or(0);
                let user = frame.address < 0x8000_0000_0000;
                ui.label(mono(format!("{index:02}")).color(colors.dim));
                ui.label(mono(hex(frame.stack)).color(colors.dim));
                let address = ui.add(egui::Label::new(mono(hex(frame.address)).color(colors.blue)).sense(Sense::click()));
                ui.label(mono(&from));
                ui.label(mono(if size != 0 { format!("{size:#x}") } else { String::new() }));
                let comment = if index == 0 { frame.name.clone() } else { format!("retorno para {} de {from}", frame.name) };
                if ui.selectable_label(index == snapshot.selected_frame, mono(comment)).clicked() {
                    state.requests.push(Request::SelectFrame(index));
                    state.focus_tab.push(Tab::Cpu);
                }
                ui.label(RichText::new(if user { "Usuário" } else { "Sistema" }).color(if user { colors.green } else { colors.dim }));
                let arguments = frame.arguments.iter().map(|value| format!("{value:x}")).collect::<Vec<_>>().join(" ");
                ui.label(mono(arguments));
                ui.label(RichText::new(frame.method).color(colors.dim));
                ui.end_row();
                if address.double_clicked() {
                    state.go_to_code(frame.address);
                }
                let target = frame.address;
                address.context_menu(|ui| {
                    if ui.button("Seguir na desmontagem").clicked() {
                        state.go_to_code(target);
                        ui.close();
                    }
                    if ui.button("Copiar o endereço").clicked() {
                        ui.ctx().copy_text(format!("{target:#x}"));
                        ui.close();
                    }
                });
            }
        });
    });
}

/// A aba SEH: a parada em palavras e o tratador de exceção de cada quadro
/// (pelo UNWIND_INFO, com as faixas do __C_specific_handler).
pub(crate) fn seh_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    if let Some(exception) = &snapshot.exception {
        ui.label(RichText::new(format!("parada: {exception}")).strong());
    }
    if !snapshot.stop.is_empty() {
        ui.label(mono(snapshot.stop.split(" [").next().unwrap_or("")).color(colors.dim));
    }
    if let Some((error, status)) = snapshot.last_error {
        ui.label(mono(format!("TEB: LastErrorValue {error:#x}  LastStatusValue {status:#x}")));
    }
    ui.separator();
    if snapshot.seh.is_empty() {
        hint(ui, "nenhum quadro com tratador de exceção na pilha (os tratadores do x64 saem do UNWIND_INFO de cada função)");
        return;
    }
    egui::ScrollArea::both().id_salt("re-seh").auto_shrink([false, false]).show(ui, |ui| {
        for row in &snapshot.seh {
            ui.horizontal(|ui| {
                ui.label(mono(format!("#{:02}", row.frame)).color(colors.dim));
                if ui.link(mono(hex(row.address))).clicked() {
                    state.go_to_code(row.address);
                }
                ui.label(mono(&row.function));
            });
            ui.label(mono(format!("    tratador: {}", row.handler)).color(colors.green));
            for scope in &row.scopes {
                ui.label(mono(format!("    {scope}")).color(colors.dim));
            }
        }
    });
}

/// A aba Script: o editor, rodar, gravar e carregar.
pub(crate) fn script_tab(ui: &mut Ui, state: &mut UiState) {
    let stopped = state.status == Status::Stopped;
    ui.horizontal(|ui| {
        if ui.add_enabled(stopped, egui::Button::new("Executar")).on_hover_text("roda no alvo; a saída vai para a aba Log").clicked() {
            state.requests.push(Request::RunScript(state.script_text.clone()));
            state.log_mode = 0;
        }
        ui.label("arquivo:");
        ui.add(egui::TextEdit::singleline(&mut state.script_path).font(TextStyle::Monospace).desired_width(260.0));
        if ui.button("Carregar").clicked() {
            match std::fs::read_to_string(&state.script_path) {
                Ok(text) => state.script_text = text,
                Err(error) => state.last_message = format!("{}: {error}", state.script_path),
            }
        }
        if ui.button("Gravar").clicked() {
            let path = PathBuf::from(&state.script_path);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            state.last_message = match std::fs::write(&path, &state.script_text) {
                Ok(()) => format!("roteiro gravado em {}", path.display()),
                Err(error) => format!("{}: {error}", path.display()),
            };
        }
    });
    hint(ui, "linguagem: comandos do depurador (bp, g, p, r, db, log...), var x = expr, if/elif/else/end, while/end, for i = a to b/end, break, continue, log \"texto {expr}\", assert, exit; $x entra nos comandos; números em hexadecimal (0n decimal)");
    egui::ScrollArea::vertical().id_salt("re-script").auto_shrink([false, false]).show(ui, |ui| {
        ui.add(egui::TextEdit::multiline(&mut state.script_text).font(TextStyle::Monospace).code_editor().desired_width(f32::INFINITY).desired_rows(28));
    });
}

/// A aba Símbolos: os módulos (kernel e usuário) e, do escolhido, os
/// símbolos, exports e imports.
pub(crate) fn symbols_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    egui::Panel::left("re-symbol-modules").resizable(true).default_size(300.0).show(ui, |ui| {
        header(ui, "Módulos");
        egui::ScrollArea::vertical().id_salt("re-symbol-module-list").auto_shrink([false, false]).show(ui, |ui| {
            for module in &snapshot.modules {
                let selected = snapshot.symbol_view.as_ref().is_some_and(|view| view.base == module.base);
                let label = format!("{}{} {:x}", if module.user { "[u] " } else { "" }, module.name, module.base);
                if ui.add_enabled(stopped, egui::Button::selectable(selected, mono(label))).clicked() {
                    state.requests.push(Request::LoadSymbols(module.base));
                }
            }
        });
    });
    egui::CentralPanel::default().show(ui, |ui| {
        let Some(view) = &snapshot.symbol_view else {
            hint(ui, "escolha um módulo à esquerda");
            return;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} ({:#x})", view.module, view.base)).strong());
            for (index, label) in [format!("Símbolos ({})", view.symbols.len()), format!("Exports ({})", view.exports.len()), format!("Imports ({})", view.imports.len())].iter().enumerate() {
                if ui.selectable_label(state.symbols_mode == index, label).clicked() {
                    state.symbols_mode = index;
                }
            }
            ui.label("filtro:");
            ui.add(egui::TextEdit::singleline(&mut state.symbols_filter).desired_width(200.0));
        });
        ui.label(RichText::new(&view.source).color(colors.dim));
        // A lista filtrada só é refeita quando o módulo, a sub-lista ou o
        // filtro mudam; cada quadro monta só as linhas à vista.
        let mode = state.symbols_mode.min(2);
        let count = match mode {
            1 => view.exports.len(),
            2 => view.imports.len(),
            _ => view.symbols.len(),
        };
        let rows: &[usize] = state.symbol_rows.update(Arc::as_ptr(view) as usize, mode, &state.symbols_filter, false, count, |index, filter| match mode {
            1 => filter.matches(&[&view.exports[index].1]),
            2 => filter.matches(&[&view.imports[index].1, &view.imports[index].2]),
            _ => filter.matches(&[&view.symbols[index].1]),
        });
        let height = row_height(ui);
        let mut go = None;
        egui::ScrollArea::both().id_salt("re-symbol-rows").auto_shrink([false, false]).show_rows(ui, height, rows.len(), |ui, range| {
            for &index in &rows[range] {
                let (address, name, extra) = match mode {
                    1 => (view.exports[index].0, view.exports[index].1.clone(), String::new()),
                    2 => {
                        let (slot, dll, name, value) = &view.imports[index];
                        (*slot, format!("{dll}!{name}"), format!("{value:#x}"))
                    }
                    _ => (view.symbols[index].0, view.symbols[index].1.clone(), String::new()),
                };
                ui.horizontal(|ui| {
                    let link = ui.add(egui::Label::new(mono(hex(address)).color(colors.blue)).sense(Sense::click()));
                    ui.label(mono(name));
                    if !extra.is_empty() {
                        ui.label(mono(format!("-> {extra}")).color(colors.dim));
                    }
                    if link.double_clicked() {
                        go = Some(address);
                    }
                });
            }
        });
        if let Some(address) = go {
            if mode == 2 {
                state.follow_in_dump(address);
            } else {
                state.go_to_code(address);
            }
        }
    });
}

/// As abas Referências e Strings: Endereço | Desmontagem | String, com o
/// filtro (texto ou expressão regular) e a contagem; clique duplo ou Enter
/// vai à instrução na aba CPU.
pub(crate) fn references_tab(ui: &mut Ui, state: &mut UiState, strings: bool) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    let view = if strings { snapshot.strings.clone() } else { snapshot.references.clone() };
    ui.horizontal_wrapped(|ui| {
        if strings {
            if ui.add_enabled(stopped, egui::Button::new("Strings do módulo atual")).clicked() {
                state.search(SearchKind::Strings, false);
            }
            if ui.add_enabled(stopped, egui::Button::new("Strings de todos os módulos")).clicked() {
                state.search(SearchKind::Strings, true);
            }
        } else {
            if ui.add_enabled(stopped, egui::Button::new("Referências a strings (módulo atual)")).clicked() {
                state.search(SearchKind::StringReferences, false);
            }
            if ui.add_enabled(stopped, egui::Button::new("(todos os módulos)")).clicked() {
                state.search(SearchKind::StringReferences, true);
            }
            if ui.add_enabled(stopped, egui::Button::new("Chamadas entre módulos")).clicked() {
                state.search(SearchKind::IntermodularCalls, false);
            }
            if ui.add_enabled(stopped, egui::Button::new("Constante...")).clicked() {
                state.dialog = Some(Dialog::Constant(String::new(), false));
            }
            if ui.add_enabled(stopped, egui::Button::new("Padrão...")).clicked() {
                state.dialog = Some(Dialog::Pattern(String::new(), false));
            }
        }
    });
    let (filter_text, use_regex) = if strings { (state.strings_filter.clone(), state.reference_regex) } else { (state.reference_filter.clone(), state.reference_regex) };
    ui.horizontal(|ui| {
        ui.label("Filtro:");
        let text = if strings { &mut state.strings_filter } else { &mut state.reference_filter };
        ui.add(egui::TextEdit::singleline(text).font(TextStyle::Monospace).desired_width(260.0).hint_text("texto (sem caixa) ou expressão regular"));
        ui.checkbox(&mut state.reference_regex, "regex");
    });
    let Some(view) = view else {
        hint(ui, if strings { "Strings: texto ASCII e UTF-16 solto na imagem (sem precisar de referência)" } else { "Procurar → Referências a strings (menu de contexto da desmontagem ou os botões acima)" });
        return;
    };
    // A lista filtrada fica guardada até o resultado ou o filtro mudarem.
    let cache = &mut state.reference_rows[usize::from(strings)];
    let rows: Vec<&ReferenceRow> = cache.update(Arc::as_ptr(&view) as usize, 0, &filter_text, use_regex, view.rows.len(), |index, filter| {
        let row = &view.rows[index];
        filter.matches(&[&row.text, &row.disassembly, &row.location])
    }).iter().map(|&index| &view.rows[index]).collect();
    let filter_error = cache.error.clone();
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{} em {}: {} de {} resultados", view.title, view.scope, rows.len(), view.rows.len())).strong());
        ui.label(RichText::new(format!("({} módulos, {} do cache, {} ms)", view.modules, view.cached, view.milliseconds)).color(colors.dim));
    });
    if let Some(error) = filter_error.as_ref().or(view.error.as_ref()) {
        ui.label(RichText::new(error).color(colors.red));
    }
    let selected_slot = if strings { &mut state.strings_selected } else { &mut state.reference_selected };
    let mut selected = selected_slot.filter(|&index| index < rows.len());
    // Enter e as setas na lista.
    let mut activate = None;
    if !ui.ctx().egui_wants_keyboard_input() && ui.ui_contains_pointer() {
        ui.input(|input| {
            if input.key_pressed(Key::ArrowDown) {
                selected = Some(selected.map_or(0, |index| (index + 1).min(rows.len().saturating_sub(1))));
            }
            if input.key_pressed(Key::ArrowUp) {
                selected = Some(selected.map_or(0, |index| index.saturating_sub(1)));
            }
            if input.key_pressed(Key::Enter) {
                activate = selected;
            }
        });
    }
    let height = row_height(ui);
    let third = if strings { "String" } else { "String / destino" };
    // Colunas fixas (em caracteres): endereço, desmontagem, string.
    let font = egui::FontId::monospace(ui.text_style_height(&TextStyle::Monospace) - 1.0);
    let glyph = ui.fonts_mut(|fonts| fonts.glyph_width(&font, '0'));
    let columns = [0.0, glyph * 44.0, glyph * 84.0];
    let fit = |text: &str, width: usize| -> String {
        if text.chars().count() <= width {
            text.to_string()
        } else {
            let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
            cut.push('…');
            cut
        }
    };
    {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::hover());
        let painter = ui.painter_at(rect);
        let strong = ui.visuals().strong_text_color();
        for (offset, title) in columns.iter().zip(["Endereço", if strings { "Bytes" } else { "Desmontagem" }, third]) {
            painter.text(egui::pos2(rect.left() + 4.0 + offset, rect.center().y), egui::Align2::LEFT_CENTER, title, egui::FontId::proportional(13.0), strong);
        }
    }
    let mut follow_dump = None;
    egui::ScrollArea::both().id_salt(("re-refs", strings)).auto_shrink([false, false]).show_rows(ui, height, rows.len(), |ui, range| {
        let text_color = ui.visuals().text_color();
        for index in range {
            let row = rows[index];
            let width = (columns[2] + glyph * 120.0).max(ui.available_width());
            let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), Sense::click());
            let painter = ui.painter_at(rect);
            if selected == Some(index) {
                painter.rect_filled(rect, 0.0, colors.selection);
            }
            let y = rect.center().y;
            painter.text(egui::pos2(rect.left() + 4.0 + columns[0], y), egui::Align2::LEFT_CENTER, fit(&row.location, 42), font.clone(), text_color);
            painter.text(egui::pos2(rect.left() + 4.0 + columns[1], y), egui::Align2::LEFT_CENTER, fit(&row.disassembly, 38), font.clone(), text_color);
            painter.text(egui::pos2(rect.left() + 4.0 + columns[2], y), egui::Align2::LEFT_CENTER, fit(&row.text, 160), font.clone(), colors.green);
            if response.clicked() {
                selected = Some(index);
            }
            if response.double_clicked() {
                activate = Some(index);
            }
            let (address, target) = (row.address, row.target);
            response.context_menu(|ui| {
                if ui.button("Ir para a instrução (CPU)").clicked() {
                    activate = Some(index);
                    ui.close();
                }
                if ui.button("Seguir a string no dump").clicked() {
                    follow_dump = Some(target);
                    ui.close();
                }
                if ui.button("Copiar o endereço").clicked() {
                    ui.ctx().copy_text(format!("{address:#x}"));
                    ui.close();
                }
            });
        }
    });
    if let Some(index) = activate {
        if let Some(row) = rows.get(index) {
            let address = row.address;
            state.go_to_code(address);
        }
    }
    if let Some(target) = follow_dump {
        state.follow_in_dump(target);
    }
    if strings {
        state.strings_selected = selected;
    } else {
        state.reference_selected = selected;
    }
}

/// A aba Threads: as threads de kernel (as listas nativas) e, com um
/// processo escolhido, as de usuário (TEB, início, espera, LastError).
pub(crate) fn threads_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    if let Some(process) = &snapshot.process {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Threads de usuário de {} (PID {})", process.name, process.pid)).strong());
            if ui.add_enabled(stopped, egui::Button::new("Atualizar")).clicked() {
                state.requests.push(Request::LoadUserThreads);
            }
        });
        match snapshot.user_threads.as_deref() {
            Some(Ok(threads)) => {
                egui::ScrollArea::horizontal().id_salt("re-user-threads-scroll").show(ui, |ui| {
                    egui::Grid::new("re-user-threads").num_columns(14).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
                        for title in ["n.º", "ID", "Entrada", "TEB", "RIP", "RSP", "Suspensão", "Prioridade", "Estado", "Espera", "LastError", "Tempo de usuário", "Tempo de kernel", "Ciclos"] {
                            ui.label(RichText::new(title).strong());
                        }
                        ui.end_row();
                        for (number, thread) in threads.iter().enumerate() {
                            let selected = snapshot.view == View::UserThread(thread.tid);
                            ui.label(mono(number.to_string()).color(colors.dim));
                            if ui.selectable_label(selected, mono(thread.tid.to_string())).on_hover_text("registradores e pilha de usuário desta thread (o CONTEXT salvo)").clicked() {
                                state.requests.push(Request::SelectUserThread(thread.tid));
                                state.focus_tab.push(Tab::Cpu);
                            }
                            let start = state.module_at(thread.start).map(|module| format!("{}+{:#x}", module.name, thread.start - module.base)).unwrap_or_else(|| format!("{:#x}", thread.start));
                            ui.label(mono(start));
                            ui.label(mono(format!("{:x}", thread.teb)));
                            ui.label(mono(format!("{:x}", thread.rip)));
                            ui.label(mono(format!("{:x}", thread.rsp)));
                            let optional = |value: Option<u64>| value.map_or("-".to_string(), |value| value.to_string());
                            ui.label(mono(optional(thread.suspend_count)));
                            ui.label(mono(optional(thread.priority)));
                            ui.label(mono(&thread.state));
                            ui.label(mono(&thread.wait_reason));
                            ui.label(mono(thread.last_error.map_or("-".into(), |value| format!("{value:#x}"))).color(if thread.last_error.unwrap_or(0) != 0 { colors.red } else { ui.visuals().text_color() }));
                            // Os tempos do KTHREAD são tiques do relógio (15,625 ms).
                            let time = |ticks: Option<u64>| ticks.map_or("-".to_string(), |ticks| format!("{:.3} s", ticks as f64 * 0.015625));
                            ui.label(mono(time(thread.user_time)));
                            ui.label(mono(time(thread.kernel_time)));
                            ui.label(mono(thread.cycles.map_or("-".into(), |cycles| format!("{cycles:#x}"))));
                            ui.end_row();
                        }
                    });
                });
            }
            Some(Err(error)) => {
                ui.label(RichText::new(error).color(colors.red));
            }
            None => hint(ui, "Atualizar lê as threads de usuário do processo"),
        }
        ui.separator();
    }
    crate::panels::threads_panel(ui, state);
}

/// A aba Handles do processo escolhido (ou do System).
pub(crate) fn handles_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    ui.horizontal(|ui| {
        let owner = snapshot.process.as_ref().map_or("System (PID 4)".to_string(), |process| format!("{} (PID {})", process.name, process.pid));
        ui.label(RichText::new(format!("Handles de {owner}")).strong());
        if ui.add_enabled(stopped, egui::Button::new("Atualizar")).clicked() {
            state.requests.push(Request::LoadHandles);
        }
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.handles_filter).desired_width(200.0));
    });
    match snapshot.handles.as_deref() {
        Some(Ok(handles)) => {
            let filter = Filter::new(&state.handles_filter, false);
            let rows: Vec<_> = handles.iter().filter(|handle| filter.matches(&[&handle.kind, &handle.name])).collect();
            ui.label(RichText::new(format!("{} de {} handles", rows.len(), handles.len())).color(colors.dim));
            let height = row_height(ui);
            egui::ScrollArea::both().id_salt("re-handles").auto_shrink([false, false]).show_rows(ui, height, rows.len(), |ui, range| {
                for handle in &rows[range] {
                    ui.horizontal(|ui| {
                        ui.add_sized([70.0, height], egui::Label::new(mono(format!("{:#x}", handle.handle))));
                        let object = ui.add_sized([150.0, height], egui::Label::new(mono(hex(handle.object)).color(colors.blue)).sense(Sense::click()));
                        ui.add_sized([90.0, height], egui::Label::new(mono(format!("{:#x}", handle.access))));
                        ui.add_sized([130.0, height], egui::Label::new(mono(&handle.kind)));
                        ui.label(mono(&handle.name));
                        if object.double_clicked() {
                            state.follow_in_dump(handle.object);
                        }
                    });
                }
            });
        }
        Some(Err(error)) => {
            ui.label(RichText::new(error).color(colors.red));
        }
        None => hint(ui, "Atualizar lê a tabela de handles (a HANDLE_TABLE nativa): handle, objeto, acesso concedido, tipo e nome"),
    }
}

/// A aba Patches: os bytes trocados na sessão, desfazer e exportar.
pub(crate) fn patches_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{} patches", snapshot.patches.len())).strong());
        if ui.add_enabled(stopped && !snapshot.patches.is_empty(), egui::Button::new("Desfazer todos")).clicked() {
            state.requests.push(Request::RevertAllPatches);
        }
        ui.label("exportar para:");
        ui.add(egui::TextEdit::singleline(&mut state.patch_path).font(TextStyle::Monospace).desired_width(260.0));
        if ui.add_enabled(!snapshot.patches.is_empty(), egui::Button::new("Exportar")).clicked() {
            state.requests.push(Request::ExportPatches(PathBuf::from(&state.patch_path)));
        }
    });
    if snapshot.patches.is_empty() {
        hint(ui, "nenhum patch: Espaço na aba CPU monta uma instrução; um byte editado no Dump também vira patch");
        return;
    }
    egui::ScrollArea::both().id_salt("re-patches").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("re-patch-grid").num_columns(5).striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
            for title in ["endereço", "módulo + RVA", "original", "novo", ""] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for patch in &snapshot.patches {
                if ui.link(mono(hex(patch.address))).clicked() {
                    state.go_to_code(patch.address);
                }
                ui.label(mono(patch.location.display()));
                ui.label(mono(patch.original.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" ")).color(colors.dim));
                ui.label(mono(patch.patched.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" ")).color(colors.red));
                if ui.add_enabled(stopped, egui::Button::new("Desfazer")).clicked() {
                    state.requests.push(Request::RevertPatch(patch.address));
                }
                ui.end_row();
            }
        });
    });
}

/// A aba Comentários/Rótulos: comentários, rótulos e marcadores por módulo
/// + RVA (gravados na pasta do build).
pub(crate) fn comments_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    ui.horizontal(|ui| {
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.comments_filter).desired_width(220.0));
        let path = state.notes_path.as_ref().map(|path| path.display().to_string()).unwrap_or_default();
        hint(ui, &format!("gravados em {path}; valem depois de relocação (módulo + RVA)"));
    });
    let filter = Filter::new(&state.comments_filter, false);
    let mut rows: Vec<(&str, kd_client::analysis::notes::Location, String)> = Vec::new();
    for (location, text) in &state.notes.labels {
        rows.push(("rótulo", location.clone(), text.clone()));
    }
    for (location, text) in &state.notes.comments {
        rows.push(("comentário", location.clone(), text.clone()));
    }
    for location in &state.notes.bookmarks {
        rows.push(("marcador", location.clone(), String::new()));
    }
    let mut go = None;
    let mut remove = None;
    egui::ScrollArea::both().id_salt("re-comments").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("re-comment-grid").num_columns(5).striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
            for title in ["tipo", "módulo + RVA", "endereço agora", "texto", ""] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for (kind, location, text) in rows.iter().filter(|(kind, location, text)| filter.matches(&[kind, &location.display(), text])) {
                ui.label(*kind);
                ui.label(mono(location.display()));
                match state.address_of(location) {
                    Some(address) => {
                        if ui.link(mono(hex(address))).clicked() {
                            go = Some(address);
                        }
                    }
                    None => {
                        ui.label(RichText::new("(módulo ausente)").color(colors.dim));
                    }
                }
                ui.label(mono(text).color(if *kind == "comentário" { colors.comment } else { colors.label }));
                if ui.small_button("apagar").clicked() {
                    remove = Some((*kind, location.clone()));
                }
                ui.end_row();
            }
        });
    });
    if let Some(address) = go {
        state.go_to_code(address);
    }
    if let Some((kind, location)) = remove {
        match kind {
            "rótulo" => state.notes.set_label(location, ""),
            "comentário" => state.notes.set_comment(location, ""),
            _ => {
                state.notes.toggle_bookmark(location);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Filter;

    #[test]
    fn filters_by_text_and_regex() {
        let filter = Filter::new("WinSta", false);
        assert!(filter.matches(&["\\Windows\\WinStations"]));
        assert!(!filter.matches(&["csrss"]));
        let filter = Filter::new("^L\"\\\\Windows", true);
        assert!(filter.matches(&["L\"\\Windows\\System32\""]));
        assert!(!filter.matches(&["\"\\Windows\""]));
        let filter = Filter::new("(", true);
        assert!(filter.error.is_some());
        assert!(!filter.matches(&["x"]));
        assert!(Filter::new("", true).matches(&["qualquer"]));
    }
}
