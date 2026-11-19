//! As abas Processos e Exceção do opennt-re.
//!
//! - Processos: a barra do contexto (o kernel ou o processo escolhido, com
//!   sessão, CR3 e PEB; voltar ao kernel, o processo da parada); à esquerda
//!   a lista de processos com sessão, pai e imagem (clique troca o contexto)
//!   e os processadores; à direita os módulos do processo (base, fim,
//!   entrada, símbolos, estado do PDB) com o breakpoint de usuário e as
//!   sugestões de símbolos, as threads de usuário com as pilhas de usuário e
//!   de kernel, os planos de seguir (parar quando o processo for criado ou
//!   carregar uma DLL, e então nos símbolos) e os eventos registrados.
//! - Exceção: a exceção da parada (o EXCEPTION_RECORD explicado, as
//!   exceções guardadas do WinRT, o tipo de uma exceção do C++, o código do
//!   `__fastfail`, a pilha do CONTEXT), um registro pedido por expressão e
//!   os breakpoints prontos (fail-fast, não tratada, entrega, saída com
//!   erro, erros do WinRT). Abre sozinha quando uma parada traz uma exceção.

use std::sync::Arc;

use eframe::egui::{self, Key, RichText, Sense, TextStyle, Ui};
use opennt_kd::client::BreakpointRequest;
use opennt_kd::BreakpointKind;

use crate::app::*;
use crate::backend::{FrameRow, PdbState, ProcessRow, QueryKind, Request, Snapshot, Status, ThreadStacks, UserModuleRow, UserRequest, View};
use crate::exception::{self, Nested, Preset, RecordView, Report, StowedView};
use crate::follow::{self, Event, FollowPlan};

/// As partes da aba Processos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubView {
    Modules,
    Threads,
    Follow,
    Events,
}

/// O estado da interface das abas Processos e Exceção.
pub struct UserUi {
    pub(crate) view: SubView,
    pub(crate) process_filter: String,
    pub(crate) session_filter: Option<u32>,
    pub(crate) module_filter: String,
    pub(crate) selected_thread: Option<u64>,
    // O breakpoint de usuário.
    pub(crate) bp_expression: String,
    pub(crate) bp_condition: String,
    pub(crate) bp_log: String,
    pub(crate) bp_once: bool,
    /// As sugestões do texto (o texto, a lista de nomes de onde vieram).
    pub(crate) bp_suggestions: (String, usize, Vec<String>),
    // O plano de seguir.
    pub(crate) follow_process: String,
    pub(crate) follow_module: String,
    pub(crate) follow_symbols: String,
    pub(crate) follow_condition: String,
    pub(crate) follow_log: String,
    pub(crate) follow_stop: bool,
    pub(crate) follow_once: bool,
    pub(crate) follow_error: Option<String>,
    // Os símbolos de uma DLL pelo arquivo.
    pub(crate) file_module: String,
    pub(crate) file_filter: String,
    pub(crate) file_rows: Vec<usize>,
    pub(crate) file_key: (usize, String),
    // A aba Exceção.
    pub(crate) decode_expression: String,
    pub(crate) decode_pointers: bool,
    /// A parada da última exceção que abriu a aba.
    pub(crate) exception_seen: String,
    // Os eventos registrados (linhas `[evento #n]` do log).
    pub(crate) events: Vec<(u32, Event)>,
    pub(crate) events_scanned: usize,
    pub(crate) events_filter: String,
}

impl Default for UserUi {
    fn default() -> Self {
        UserUi {
            view: SubView::Modules,
            process_filter: String::new(),
            session_filter: None,
            module_filter: String::new(),
            selected_thread: None,
            bp_expression: String::new(),
            bp_condition: String::new(),
            bp_log: String::new(),
            bp_once: false,
            bp_suggestions: (String::new(), 0, Vec::new()),
            follow_process: String::new(),
            follow_module: String::new(),
            follow_symbols: String::new(),
            follow_condition: String::new(),
            follow_log: String::new(),
            follow_stop: false,
            follow_once: false,
            follow_error: None,
            file_module: String::new(),
            file_filter: String::new(),
            file_rows: Vec::new(),
            file_key: (0, String::new()),
            decode_expression: String::new(),
            decode_pointers: false,
            exception_seen: String::new(),
            events: Vec::new(),
            events_scanned: 0,
            events_filter: String::new(),
        }
    }
}

/// Uma vez por quadro: a aba Exceção abre quando uma parada traz uma
/// exceção nova; os eventos novos do log entram na lista.
pub(crate) fn frame(state: &mut UiState) {
    sync_events(state);
    if state.status == Status::Running {
        state.user.exception_seen.clear();
        return;
    }
    let snapshot = Arc::clone(&state.snapshot);
    if let Some(report) = &snapshot.user.exception {
        if report.automatic {
            let key = format!("{}|{}", snapshot.stop, report.how);
            if state.user.exception_seen != key {
                state.user.exception_seen = key;
                state.focus_tab.push(Tab::Exception);
            }
        }
    }
}

/// As linhas `[evento #n] ...` novas do log (a última fica para o quadro
/// seguinte: pode estar pela metade).
fn sync_events(state: &mut UiState) {
    let count = state.console.count();
    if count < state.user.events_scanned {
        state.user.events.clear();
        state.user.events_scanned = 0;
    }
    let end = count.saturating_sub(1);
    for index in state.user.events_scanned..end {
        if let Some(event) = follow::parse_log_line(state.console.line(index)) {
            state.user.events.push(event);
        }
    }
    state.user.events_scanned = state.user.events_scanned.max(end);
    if state.user.events.len() > 20_000 {
        let cut = state.user.events.len() - 10_000;
        state.user.events.drain(..cut);
    }
}

fn event_breakpoint(state: &mut UiState, expression: String) {
    state.requests.push(Request::AddBreakpointWith(BreakpointRequest::new(BreakpointKind::Event, &expression)));
    state.last_message = format!("parada no evento {expression}");
}

/// A aba Processos.
pub(crate) fn processes_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    egui::Panel::top("re-user-context").show(ui, |ui| context_bar(ui, state, &snapshot, stopped, colors));
    egui::Panel::left("re-user-process-list").resizable(true).default_size(460.0).show(ui, |ui| {
        process_list(ui, state, &snapshot, stopped, colors);
        egui::CollapsingHeader::new(RichText::new("Processadores").strong()).id_salt("re-user-processors").default_open(false).show(ui, |ui| processors(ui, state, &snapshot));
    });
    egui::CentralPanel::default().show(ui, |ui| {
        let threads = snapshot.user.threads.as_deref().and_then(|threads| threads.as_ref().ok()).map_or(0, Vec::len);
        ui.horizontal(|ui| {
            let views = [
                (SubView::Modules, format!("Módulos ({})", snapshot.user.modules.len())),
                (SubView::Threads, format!("Threads ({threads})")),
                (SubView::Follow, format!("Seguir ({})", snapshot.user.plans.len())),
                (SubView::Events, format!("Eventos ({})", state.user.events.len())),
            ];
            for (view, label) in views {
                if ui.selectable_label(state.user.view == view, label).clicked() {
                    state.user.view = view;
                }
            }
        });
        ui.separator();
        match state.user.view {
            SubView::Modules => modules_view(ui, state, &snapshot, stopped, colors),
            SubView::Threads => threads_view(ui, state, &snapshot, stopped, colors),
            SubView::Follow => follow_view(ui, state, &snapshot, stopped, colors),
            SubView::Events => events_view(ui, state, colors),
        }
    });
}

/// O contexto das leituras e as ações dele.
fn context_bar(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, stopped: bool, colors: Palette) {
    ui.horizontal_wrapped(|ui| {
        match &snapshot.process {
            Some(process) => {
                let session = snapshot.user.processes.iter().find(|row| row.eprocess == process.eprocess).and_then(|row| row.session).map_or_else(String::new, |session| format!(", sessão {session}"));
                ui.label(RichText::new(format!("Contexto: {} (PID {}{session})", process.name, process.pid)).color(colors.blue).strong());
                ui.label(mono(format!("EPROCESS {:#x}  CR3 {:#x}  PEB {:#x}", process.eprocess, process.cr3, process.peb)).color(colors.dim));
                if ui.add_enabled(stopped, egui::Button::new("Voltar ao kernel")).clicked() {
                    state.requests.push(Request::SelectProcess(None));
                    state.user.selected_thread = None;
                }
                if ui.add_enabled(stopped, egui::Button::new("Recarregar módulos")).on_hover_text("relê a PEB.Ldr e as imagens do VAD do processo").clicked() {
                    state.requests.push(Request::User(UserRequest::ReloadModules));
                }
            }
            None => {
                ui.label(RichText::new("Contexto: kernel").color(colors.blue).strong());
            }
        }
        if ui.add_enabled(stopped, egui::Button::new("Processo da parada")).on_hover_text("o processo do CR3 do processador parado vira o das leituras").clicked() {
            state.requests.push(Request::User(UserRequest::StopContext));
        }
        if ui.add_enabled(stopped, egui::Button::new("Atualizar")).on_hover_text("relê sessão, pai, imagem e estado de saída de todos os processos").clicked() {
            state.requests.push(Request::User(UserRequest::RefreshProcesses));
        }
        if snapshot.user_mode {
            ui.label(RichText::new("parada em modo usuário").color(colors.green));
        }
        if !snapshot.user.message.is_empty() {
            ui.label(RichText::new(snapshot.user.message.as_str()).color(colors.dim));
        }
    });
}

fn process_matches(row: &ProcessRow, filter: &str, session: Option<u32>) -> bool {
    if session.is_some() && row.session != session {
        return false;
    }
    filter.is_empty() || row.name.to_ascii_lowercase().contains(filter) || row.pid.to_string() == filter || row.image.to_ascii_lowercase().contains(filter)
}

/// A lista de processos (PID, sessão, nome, threads, pai, EPROCESS).
fn process_list(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, stopped: bool, colors: Palette) {
    ui.horizontal(|ui| {
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.user.process_filter).desired_width(150.0).hint_text("nome, PID ou caminho"));
        let mut sessions: Vec<u32> = snapshot.user.processes.iter().filter_map(|row| row.session).collect();
        sessions.sort_unstable();
        sessions.dedup();
        let label = state.user.session_filter.map_or_else(|| "todas as sessões".to_string(), |session| format!("sessão {session}"));
        egui::ComboBox::from_id_salt("re-user-session").selected_text(label).show_ui(ui, |ui| {
            ui.selectable_value(&mut state.user.session_filter, None, "todas as sessões");
            for session in sessions {
                ui.selectable_value(&mut state.user.session_filter, Some(session), format!("sessão {session}"));
            }
        });
    });
    if !snapshot.user.types_note.is_empty() {
        hint(ui, &format!("sessão, pai e imagem vêm dos tipos do ntoskrnl: {}", snapshot.user.types_note));
    }
    if snapshot.user.processes.is_empty() {
        hint(ui, "a lista de processos aparece na próxima parada");
        return;
    }
    let filter = state.user.process_filter.trim().to_ascii_lowercase();
    let session = state.user.session_filter;
    let current = snapshot.process.as_ref().map(|process| process.eprocess);
    egui::ScrollArea::both().id_salt("re-user-processes").auto_shrink([false, true]).max_height((ui.available_height() - 30.0).max(80.0)).show(ui, |ui| {
        egui::Grid::new("re-user-process-grid").num_columns(6).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["PID", "sessão", "nome", "threads", "pai", "EPROCESS"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for row in snapshot.user.processes.iter().filter(|row| process_matches(row, &filter, session)) {
                let selected = current == Some(row.eprocess);
                let pid = ui.selectable_label(selected, mono(row.pid.to_string()));
                ui.label(mono(row.session.map_or_else(|| "-".to_string(), |session| session.to_string())));
                let color = if row.exiting() { colors.red } else { colors.blue };
                let mut name = ui.selectable_label(selected, mono(row.name.as_str()).color(color));
                let tip = match (row.image.is_empty(), row.exit_status) {
                    (_, Some(status)) if row.exiting() => format!("{}\nsaindo: {}", row.image, opennt_kd::ntstatus::describe(status)),
                    (false, _) => row.image.clone(),
                    (true, _) => String::new(),
                };
                if !tip.is_empty() {
                    name = name.on_hover_text(tip);
                }
                ui.label(mono(row.threads.to_string()));
                ui.label(mono(row.parent.map_or_else(String::new, |parent| parent.to_string())));
                ui.label(mono(hex(row.eprocess)).color(colors.dim));
                ui.end_row();
                let response = pid.union(name);
                if response.clicked() && stopped && !selected {
                    state.requests.push(Request::SelectProcess(Some(row.eprocess)));
                    state.user.selected_thread = None;
                }
                response.context_menu(|ui| process_menu(ui, state, row, stopped));
            }
        });
    });
    hint(ui, "clique: depura o processo (o contexto troca); botão direito: seguir, paradas e detalhes");
}

fn process_menu(ui: &mut Ui, state: &mut UiState, row: &ProcessRow, stopped: bool) {
    if ui.add_enabled(stopped, egui::Button::new("Trocar o contexto para este processo")).clicked() {
        state.requests.push(Request::SelectProcess(Some(row.eprocess)));
        ui.close();
    }
    if ui.button("Seguir este processo...").on_hover_text("preenche o plano de seguir com o nome").clicked() {
        state.user.follow_process = row.name.clone();
        state.user.view = SubView::Follow;
        ui.close();
    }
    if ui.add_enabled(stopped, egui::Button::new(format!("Parar quando um {} for criado", row.name))).clicked() {
        event_breakpoint(state, format!("cpr:{}", row.name));
        ui.close();
    }
    if ui.add_enabled(stopped, egui::Button::new(format!("Parar quando um {} sair", row.name))).clicked() {
        event_breakpoint(state, format!("epr:{}", row.name));
        ui.close();
    }
    if ui.add_enabled(stopped, egui::Button::new("!process")).clicked() {
        state.query_kind = QueryKind::Process;
        state.query_argument = format!("{:#x}", row.eprocess);
        state.requests.push(Request::Query(QueryKind::Process, state.query_argument.clone()));
        state.focus_tab.push(Tab::NtObjects);
        ui.close();
    }
    if ui.button("Copiar o EPROCESS").clicked() {
        ui.ctx().copy_text(format!("{:#x}", row.eprocess));
        ui.close();
    }
    if !row.image.is_empty() && ui.button("Copiar o caminho da imagem").clicked() {
        ui.ctx().copy_text(row.image.clone());
        ui.close();
    }
}

/// Os processadores (registradores e pilha de cada um).
fn processors(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot) {
    egui::Grid::new("re-user-processor-grid").num_columns(6).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
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
            ui.label(mono(processor.process.as_str()));
            ui.end_row();
        }
    });
}

/// Os nomes que começam com o texto (os `módulo!símbolo` das funções); sem
/// nenhum, os que contêm o resto do texto no módulo pedido.
fn suggestions(names: &[String], typed: &str, limit: usize) -> Vec<String> {
    let from = names.partition_point(|name| name.as_str() < typed);
    let mut found: Vec<String> = names[from..].iter().take_while(|name| name.starts_with(typed)).take(limit).cloned().collect();
    if found.is_empty() {
        let (module, rest) = typed.split_once('!').unwrap_or(("", typed));
        let needle = rest.to_ascii_lowercase();
        if !needle.is_empty() {
            found = names
                .iter()
                .filter(|name| {
                    let (owner, symbol) = name.split_once('!').unwrap_or(("", name.as_str()));
                    (module.is_empty() || owner.eq_ignore_ascii_case(module)) && symbol.to_ascii_lowercase().contains(&needle)
                })
                .take(limit)
                .cloned()
                .collect();
        }
    }
    found
}

/// O breakpoint de usuário no processo escolhido, com as sugestões.
fn breakpoint_bar(ui: &mut Ui, state: &mut UiState, process: u64, stopped: bool) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Breakpoint neste processo:").strong());
        let response = ui.add(egui::TextEdit::singleline(&mut state.user.bp_expression).font(TextStyle::Monospace).desired_width(320.0).hint_text("dwmcore!CD2DContext::InitializeD2D, ntdll!LdrLoadDll, 0x7ff6..."));
        ui.add(egui::TextEdit::singleline(&mut state.user.bp_condition).font(TextStyle::Monospace).desired_width(120.0).hint_text("condição"));
        ui.add(egui::TextEdit::singleline(&mut state.user.bp_log).font(TextStyle::Monospace).desired_width(160.0).hint_text("log: hr={@rcx}"));
        ui.checkbox(&mut state.user.bp_once, "uma vez só");
        let submit = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
        let ready = stopped && !state.user.bp_expression.trim().is_empty();
        let clicked = ui.add_enabled(ready, egui::Button::new("Armar")).on_hover_text("o breakpoint vale só para este processo; um módulo que ainda não carregou nele vira um plano de seguir (arma quando ele carregar)").clicked();
        if ready && (clicked || submit) {
            let mut request = BreakpointRequest::new(BreakpointKind::Software, state.user.bp_expression.trim());
            request.condition = state.user.bp_condition.trim().to_string();
            request.log = state.user.bp_log.trim().to_string();
            request.options.single_shot = state.user.bp_once;
            state.requests.push(Request::User(UserRequest::Breakpoint { process, request }));
        }
    });
    let typed = state.user.bp_expression.trim().to_string();
    let source = Arc::as_ptr(&state.completions) as usize;
    if typed.len() < 3 || typed.contains(char::is_whitespace) {
        return;
    }
    if state.user.bp_suggestions.0 != typed || state.user.bp_suggestions.1 != source {
        let found = suggestions(&state.completions, &typed, 12);
        state.user.bp_suggestions = (typed.clone(), source, found);
    }
    let found = state.user.bp_suggestions.2.clone();
    if found.is_empty() || found.iter().any(|name| *name == typed) {
        return;
    }
    let mut chosen = None;
    ui.horizontal_wrapped(|ui| {
        hint(ui, "sugestões:");
        for name in &found {
            if ui.selectable_label(false, mono(name.as_str())).clicked() {
                chosen = Some(name.clone());
            }
        }
    });
    if let Some(name) = chosen {
        state.user.bp_expression = name;
    }
}

/// Os módulos do processo escolhido.
fn modules_view(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, stopped: bool, colors: Palette) {
    let Some(process) = &snapshot.process else {
        hint(ui, "escolha um processo na lista à esquerda: o contexto troca para ele e os módulos dele aparecem aqui");
        return;
    };
    breakpoint_bar(ui, state, process.eprocess, stopped);
    ui.separator();
    let modules = &snapshot.user.modules;
    let with_pdb = modules.iter().filter(|module| matches!(module.pdb, PdbState::Loaded(_))).count();
    let pending = modules.iter().filter(|module| module.pdb == PdbState::Downloading).count();
    let exports = modules.iter().filter(|module| matches!(module.pdb, PdbState::ExportsOnly(_) | PdbState::NoFile)).count();
    ui.horizontal(|ui| {
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.user.module_filter).desired_width(160.0).hint_text("nome ou caminho"));
        ui.label(RichText::new(format!("{} módulos: {with_pdb} com PDB, {pending} baixando, {exports} só com exports", modules.len())).color(colors.dim));
        if pending > 0 {
            ui.spinner();
        }
    });
    if modules.is_empty() {
        hint(ui, "sem módulos de usuário (o processo ainda não tem a PEB.Ldr, ou o contexto não é este processo)");
        return;
    }
    let filter = state.user.module_filter.trim().to_ascii_lowercase();
    let name = process.name.clone();
    egui::ScrollArea::both().id_salt("re-user-modules").auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("re-user-module-grid").num_columns(8).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
            for title in ["nome", "base", "fim", "tamanho", "entrada", "símbolos", "PDB", "caminho"] {
                ui.label(RichText::new(title).strong());
            }
            ui.end_row();
            for module in modules.iter().filter(|module| filter.is_empty() || module.name.to_ascii_lowercase().contains(&filter) || module.path.to_ascii_lowercase().contains(&filter)) {
                let link = ui.add(egui::Label::new(mono(module.name.as_str()).color(colors.blue)).sense(Sense::click())).on_hover_text("clique: símbolos, exports e imports; botão direito: mais");
                ui.label(mono(hex(module.base)));
                ui.label(mono(hex(module.end)));
                ui.label(mono(format!("{:#x}", module.end.saturating_sub(module.base))));
                ui.label(mono(module.entry.map_or_else(String::new, |entry| format!("{entry:#x}"))));
                ui.label(mono(module.symbols.to_string()));
                let (text, color, tip) = match &module.pdb {
                    PdbState::Loaded(path) => ("PDB", colors.green, path.clone()),
                    PdbState::Downloading => ("baixando", colors.yellow, "o PDB está chegando do servidor de símbolos".to_string()),
                    PdbState::ExportsOnly(reason) => ("só exports", colors.red, reason.clone()),
                    PdbState::NoFile => ("sem arquivo", colors.dim, "a DLL não está nesta máquina (C:\\Windows)".to_string()),
                };
                ui.label(RichText::new(text).color(color)).on_hover_text(tip);
                ui.label(mono(module.path.as_str()).color(colors.dim));
                ui.end_row();
                if link.clicked() && stopped {
                    state.requests.push(Request::LoadSymbols(module.base));
                    state.focus_tab.push(Tab::Symbols);
                }
                link.context_menu(|ui| module_menu(ui, state, module, &name, stopped));
            }
        });
    });
}

fn module_menu(ui: &mut Ui, state: &mut UiState, module: &UserModuleRow, process: &str, stopped: bool) {
    if ui.button("Breakpoint num símbolo deste módulo...").clicked() {
        state.user.bp_expression = format!("{}!", module.name);
        ui.close();
    }
    if ui.add_enabled(stopped, egui::Button::new("Símbolos, exports e imports")).clicked() {
        state.requests.push(Request::LoadSymbols(module.base));
        state.focus_tab.push(Tab::Symbols);
        ui.close();
    }
    if let Some(entry) = module.entry {
        if ui.add_enabled(stopped, egui::Button::new("Ir para o ponto de entrada")).clicked() {
            state.go_to_code(entry);
            ui.close();
        }
    }
    if ui.button("Seguir: este módulo num processo novo igual...").on_hover_text("preenche o plano de seguir com o processo e a DLL").clicked() {
        state.user.follow_process = process.to_string();
        state.user.follow_module = opennt_kd::symbols::base_name(&module.path).to_string();
        state.user.view = SubView::Follow;
        ui.close();
    }
    if ui.button("Copiar a base").clicked() {
        ui.ctx().copy_text(format!("{:#x}", module.base));
        ui.close();
    }
    if ui.button("Copiar o caminho").clicked() {
        ui.ctx().copy_text(module.path.clone());
        ui.close();
    }
}

/// As threads de usuário do processo escolhido e as pilhas da escolhida.
fn threads_view(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, stopped: bool, colors: Palette) {
    let Some(process) = &snapshot.process else {
        hint(ui, "escolha um processo na lista à esquerda: as threads de usuário dele aparecem aqui");
        return;
    };
    match snapshot.user.threads.as_deref() {
        None => hint(ui, "as threads de usuário aparecem na próxima parada"),
        Some(Err(error)) => {
            ui.label(RichText::new(error.as_str()).color(colors.red));
        }
        Some(Ok(threads)) => {
            let shown = snapshot.user.stacks.as_ref().map(|stacks| stacks.tid);
            egui::ScrollArea::both().id_salt("re-user-thread-list").auto_shrink([false, true]).max_height(ui.available_height() * 0.4).show(ui, |ui| {
                egui::Grid::new("re-user-thread-grid").num_columns(8).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
                    for title in ["TID", "estado", "espera", "início", "RIP", "TEB", "LastError", "prioridade"] {
                        ui.label(RichText::new(title).strong());
                    }
                    ui.end_row();
                    for row in threads {
                        let thread = &row.thread;
                        let selected = shown == Some(thread.tid) || state.user.selected_thread == Some(thread.tid);
                        if ui.selectable_label(selected, mono(thread.tid.to_string())).on_hover_text("as pilhas de usuário e de kernel desta thread").clicked() && stopped {
                            state.user.selected_thread = Some(thread.tid);
                            state.requests.push(Request::User(UserRequest::ThreadStacks(Some(thread.tid))));
                        }
                        ui.label(mono(thread.state.as_str()).color(if thread.state == "Running" { colors.green } else { colors.dim }));
                        ui.label(mono(thread.wait_reason.as_str()));
                        ui.label(mono(row.start.as_str()));
                        ui.label(mono(row.rip.as_str()));
                        ui.label(mono(format!("{:#x}", thread.teb)));
                        let error = thread.last_error.unwrap_or(0);
                        ui.label(mono(thread.last_error.map_or_else(|| "-".to_string(), |value| format!("{value:#x}"))).color(if error != 0 { colors.red } else { ui.visuals().text_color() }));
                        ui.label(mono(thread.priority.map_or_else(|| "-".to_string(), |value| value.to_string())));
                        ui.end_row();
                    }
                });
            });
        }
    }
    ui.separator();
    match snapshot.user.stacks.as_deref() {
        Some(stacks) => stacks_view(ui, state, stacks, process.eprocess, stopped, colors),
        None => hint(ui, "escolha uma thread (TID) para ver a pilha de usuário (o CONTEXT salvo) e a de kernel"),
    }
}

fn stacks_view(ui: &mut Ui, state: &mut UiState, stacks: &ThreadStacks, process: u64, stopped: bool, colors: Palette) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("Thread {} (ETHREAD {:#x}, TEB {:#x})", stacks.tid, stacks.ethread, stacks.teb)).strong());
        if ui.add_enabled(stopped, egui::Button::new("Registradores de usuário na CPU")).clicked() {
            state.requests.push(Request::SelectUserThread(stacks.tid));
            state.focus_tab.push(Tab::Cpu);
        }
        if ui.add_enabled(stopped, egui::Button::new("Thread de kernel na CPU")).clicked() {
            state.requests.push(Request::SelectThread(stacks.ethread));
            state.focus_tab.push(Tab::Cpu);
        }
        if ui.button("Fechar").clicked() {
            state.user.selected_thread = None;
            state.requests.push(Request::User(UserRequest::ThreadStacks(None)));
        }
    });
    if !stacks.kernel_header.is_empty() {
        hint(ui, &stacks.kernel_header);
    }
    ui.columns(2, |columns| {
        frame_list(&mut columns[0], state, "Pilha de usuário (o CONTEXT salvo)", &stacks.user, process, stopped, colors, "user");
        frame_list(&mut columns[1], state, "Pilha de kernel", &stacks.kernel, 0, stopped, colors, "kernel");
    });
}

/// Uma pilha: clique duplo vai à desmontagem; botão direito arma um
/// breakpoint no quadro (no processo, se é de usuário).
#[allow(clippy::too_many_arguments)]
fn frame_list(ui: &mut Ui, state: &mut UiState, title: &str, frames: &Result<Vec<FrameRow>, String>, process: u64, stopped: bool, colors: Palette, id: &str) {
    ui.label(RichText::new(title).strong());
    match frames {
        Err(error) => {
            ui.label(RichText::new(error.as_str()).color(colors.red));
        }
        Ok(frames) => {
            egui::ScrollArea::both().id_salt(("re-user-frames", id)).auto_shrink([false, false]).show(ui, |ui| {
                for (index, frame) in frames.iter().enumerate() {
                    let response = ui.add(egui::Label::new(mono(format!("{index:02} {} {}", hex(frame.address), frame.name))).sense(Sense::click())).on_hover_text(format!("RSP {:#x} ({}); clique duplo: desmontagem", frame.stack, frame.method));
                    if response.double_clicked() {
                        state.go_to_code(frame.address);
                    }
                    let address = frame.address;
                    response.context_menu(|ui| {
                        if ui.button("Na desmontagem").clicked() {
                            state.go_to_code(address);
                            ui.close();
                        }
                        if process != 0 && address < 0x8000_0000_0000 {
                            if ui.add_enabled(stopped, egui::Button::new("Breakpoint aqui (neste processo)")).clicked() {
                                let request = BreakpointRequest::new(BreakpointKind::Software, &format!("{address:#x}"));
                                state.requests.push(Request::User(UserRequest::Breakpoint { process, request }));
                                ui.close();
                            }
                        } else if ui.add_enabled(stopped, egui::Button::new("Breakpoint aqui")).clicked() {
                            state.requests.push(Request::ToggleBreakpoint(address));
                            ui.close();
                        }
                        if ui.button("Copiar o endereço").clicked() {
                            ui.ctx().copy_text(format!("{address:#x}"));
                            ui.close();
                        }
                    });
                }
            });
        }
    }
}

/// O plano do formulário.
fn form_plan(user: &UserUi) -> FollowPlan {
    let symbols: Vec<String> = user.follow_symbols.split(|character: char| character == '\n' || character == ';').map(str::trim).filter(|symbol| !symbol.is_empty()).map(String::from).collect();
    let stop_at_trigger = user.follow_stop || symbols.is_empty();
    FollowPlan { id: 0, process: user.follow_process.trim().to_string(), module: user.follow_module.trim().to_string(), symbols, condition: user.follow_condition.trim().to_string(), log: user.follow_log.trim().to_string(), stop_at_trigger, once: user.follow_once }
}

/// Seguir: o formulário do plano, as paradas rápidas, os símbolos de uma
/// DLL pelo arquivo, os planos e o registro de eventos.
fn follow_view(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, stopped: bool, colors: Palette) {
    egui::ScrollArea::vertical().id_salt("re-user-follow").auto_shrink([false, false]).show(ui, |ui| {
        ui.label(RichText::new("Seguir um processo desde a criação").strong());
        hint(ui, "quando o processo carregar a DLL (ou for criado, sem DLL), o depurador troca o contexto para ele, arma os breakpoints só nele e segue sozinho: a próxima parada é num deles. Pela barra de comando: seguir dwm.exe!dwmcore.dll CD2DContext::InitializeD2D (/parar, /uma)");
        egui::Grid::new("re-user-follow-form").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
            ui.label("processo:");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut state.user.follow_process).font(TextStyle::Monospace).desired_width(200.0).hint_text("dwm.exe"));
                let mut names: Vec<String> = snapshot.user.processes.iter().map(|row| row.name.clone()).collect();
                names.sort();
                names.dedup();
                egui::ComboBox::from_id_salt("re-user-follow-names").selected_text("da lista").show_ui(ui, |ui| {
                    for name in names {
                        if ui.selectable_label(false, name.as_str()).clicked() {
                            state.user.follow_process = name;
                        }
                    }
                });
            });
            ui.end_row();
            ui.label("DLL:");
            ui.add(egui::TextEdit::singleline(&mut state.user.follow_module).font(TextStyle::Monospace).desired_width(200.0).hint_text("dwmcore.dll (vazio: a criação do processo)"));
            ui.end_row();
            ui.label("parar em:");
            ui.add(egui::TextEdit::multiline(&mut state.user.follow_symbols).font(TextStyle::Monospace).desired_width(440.0).desired_rows(3).hint_text("CD2DContext::InitializeD2D\ndwmcore!MilFailFastForHR\n(um por linha; sem módulo, o da DLL)"));
            ui.end_row();
            ui.label("condição:");
            ui.add(egui::TextEdit::singleline(&mut state.user.follow_condition).font(TextStyle::Monospace).desired_width(300.0).hint_text("opcional: @rcx != 0"));
            ui.end_row();
            ui.label("log:");
            ui.add(egui::TextEdit::singleline(&mut state.user.follow_log).font(TextStyle::Monospace).desired_width(300.0).hint_text("opcional (com log e sem condição, só registra): hr={@rcx}"));
            ui.end_row();
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut state.user.follow_stop, "parar também na carga (ou na criação)");
            ui.checkbox(&mut state.user.follow_once, "só a primeira vez");
            if ui.add_enabled(stopped, egui::Button::new("Seguir")).clicked() {
                let plan = form_plan(&state.user);
                match plan.validate() {
                    Ok(()) => {
                        state.user.follow_error = None;
                        state.requests.push(Request::User(UserRequest::Follow(plan)));
                    }
                    Err(error) => state.user.follow_error = Some(error),
                }
            }
        });
        if let Some(error) = &state.user.follow_error {
            ui.label(RichText::new(error.as_str()).color(colors.red));
        }
        // As paradas simples (um breakpoint de evento).
        ui.horizontal_wrapped(|ui| {
            let process = state.user.follow_process.trim().to_string();
            let module = state.user.follow_module.trim().to_string();
            let ready = stopped && !process.is_empty();
            hint(ui, "só parar:");
            if ui.add_enabled(ready, egui::Button::new("na criação")).on_hover_text(format!("sxe cpr:{process}")).clicked() {
                event_breakpoint(state, format!("cpr:{process}"));
            }
            if ui.add_enabled(ready, egui::Button::new("na saída")).on_hover_text(format!("sxe epr:{process}")).clicked() {
                event_breakpoint(state, format!("epr:{process}"));
            }
            if ui.add_enabled(ready && !module.is_empty(), egui::Button::new("na carga da DLL")).on_hover_text(format!("sxe ld:{process}!{module}")).clicked() {
                event_breakpoint(state, format!("ld:{process}!{module}"));
            }
        });
        ui.separator();
        file_symbols(ui, state, snapshot, colors);
        ui.separator();
        plans(ui, state, snapshot, stopped, colors);
        ui.separator();
        // O registro de eventos.
        let logging = |expression: &str| snapshot.breakpoints.iter().any(|breakpoint| breakpoint.kind == BreakpointKind::Event && breakpoint.expression.eq_ignore_ascii_case(expression) && !breakpoint.log.is_empty());
        let (mut processes, mut images) = (logging(follow::LOG_CREATE), logging(follow::LOG_IMAGES));
        ui.label(RichText::new("Registro de eventos (sem parar; a lista fica em Eventos)").strong());
        ui.horizontal_wrapped(|ui| {
            let changed_processes = ui.add_enabled(stopped, egui::Checkbox::new(&mut processes, "criação e saída de processos")).changed();
            let changed_images = ui.add_enabled(stopped, egui::Checkbox::new(&mut images, "cargas de DLL (cada carga passa pelo depurador: mais lento)")).changed();
            if changed_processes || changed_images {
                state.requests.push(Request::User(UserRequest::EventLog { processes, images }));
            }
        });
    });
}

/// Os nomes de uma DLL pelo arquivo: clique põe o nome em "parar em".
fn file_symbols(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, colors: Palette) {
    ui.label(RichText::new("Símbolos de uma DLL pelo arquivo (antes de o processo existir)").strong());
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut state.user.file_module).font(TextStyle::Monospace).desired_width(160.0).hint_text("a DLL do plano"));
        if ui.button("Carregar").on_hover_text("exports do arquivo desta máquina e os públicos do PDB do cache").clicked() {
            let module = if state.user.file_module.trim().is_empty() { state.user.follow_module.trim().to_string() } else { state.user.file_module.trim().to_string() };
            state.requests.push(Request::User(UserRequest::FileSymbols(module)));
        }
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.user.file_filter).font(TextStyle::Monospace).desired_width(220.0).hint_text("InitializeD2D"));
    });
    let Some(file) = &snapshot.user.file_symbols else { return };
    hint(ui, &file.source);
    let names = match &file.names {
        Ok(names) => names,
        Err(error) => {
            ui.label(RichText::new(error.as_str()).color(colors.red));
            return;
        }
    };
    let key = (Arc::as_ptr(file) as usize, state.user.file_filter.clone());
    if state.user.file_key != key {
        let needle = state.user.file_filter.trim().to_ascii_lowercase();
        state.user.file_rows = names.iter().enumerate().filter(|(_, name)| needle.is_empty() || name.to_ascii_lowercase().contains(&needle)).map(|(index, _)| index).collect();
        state.user.file_key = key;
    }
    let rows = std::mem::take(&mut state.user.file_rows);
    ui.label(RichText::new(format!("{} de {} nomes de {} (clique: entra em \"parar em\")", rows.len(), names.len(), file.module)).color(colors.dim));
    let height = row_height(ui);
    let mut chosen = None;
    egui::ScrollArea::vertical().id_salt("re-user-file-symbols").auto_shrink([false, true]).max_height(220.0).show_rows(ui, height, rows.len(), |ui, range| {
        for index in range {
            let Some(name) = rows.get(index).and_then(|&row| names.get(row)) else { continue };
            if ui.selectable_label(false, mono(name.as_str())).clicked() {
                chosen = Some(name.clone());
            }
        }
    });
    state.user.file_rows = rows;
    if let Some(name) = chosen {
        let symbol = format!("{}!{name}", file.module);
        if !state.user.follow_symbols.trim().is_empty() && !state.user.follow_symbols.ends_with('\n') {
            state.user.follow_symbols.push('\n');
        }
        state.user.follow_symbols.push_str(&symbol);
    }
}

/// Os planos com o estado de cada processo seguido.
fn plans(ui: &mut Ui, state: &mut UiState, snapshot: &Snapshot, stopped: bool, colors: Palette) {
    ui.label(RichText::new(format!("Planos ({})", snapshot.user.plans.len())).strong());
    if snapshot.user.plans.is_empty() {
        hint(ui, "nenhum plano; os planos ficam em <build>/opennt-re/seguir.txt e voltam na próxima sessão");
        return;
    }
    for plan in &snapshot.user.plans {
        ui.horizontal_wrapped(|ui| {
            ui.label(mono(format!("#{}", plan.id)).color(colors.dim));
            ui.label(mono(plan.plan.describe()));
            let (text, color) = if plan.finished {
                ("concluído", colors.dim)
            } else if plan.trigger_armed {
                ("armado", colors.green)
            } else {
                ("sem o gatilho", colors.red)
            };
            ui.label(RichText::new(text).color(color)).on_hover_text(format!("gatilho: sxe {}", plan.plan.trigger()));
            if ui.add_enabled(stopped, egui::Button::new("Tirar")).on_hover_text("tira o gatilho e os breakpoints armados pelo plano").clicked() {
                state.requests.push(Request::User(UserRequest::Unfollow(plan.id)));
            }
        });
        for line in &plan.instances {
            ui.label(mono(format!("    {line}")).color(colors.dim));
        }
    }
}

/// Os eventos registrados (criação e saída de processos, cargas de DLL).
fn events_view(ui: &mut Ui, state: &mut UiState, colors: Palette) {
    ui.horizontal(|ui| {
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.user.events_filter).desired_width(200.0).hint_text("processo, PID ou DLL"));
        if ui.button("Limpar").clicked() {
            state.user.events.clear();
        }
    });
    if state.user.events.is_empty() {
        hint(ui, "nenhum evento registrado: ligue o registro em Seguir (criação e saída de processos, cargas de DLL)");
        return;
    }
    let needle = state.user.events_filter.trim().to_ascii_lowercase();
    let rows: Vec<usize> = state.user.events.iter().enumerate().filter(|(_, (_, event))| needle.is_empty() || event.process.to_ascii_lowercase().contains(&needle) || event.pid.to_string() == needle || event.path.to_ascii_lowercase().contains(&needle)).map(|(index, _)| index).collect();
    let height = row_height(ui);
    let mut follow = None;
    egui::ScrollArea::both().id_salt("re-user-events").auto_shrink([false, false]).stick_to_bottom(true).show_rows(ui, height, rows.len(), |ui, range| {
        for index in range {
            let Some((id, event)) = rows.get(index).and_then(|&row| state.user.events.get(row)) else { continue };
            ui.horizontal(|ui| {
                ui.label(mono(format!("#{id:<3}")).color(colors.dim));
                ui.label(mono(format!("{:<16}", event.kind.label())));
                ui.label(mono(format!("PID {:<6}", event.pid)));
                if ui.link(mono(event.process.as_str())).on_hover_text("clique: preenche o plano de seguir com o processo (e a DLL)").clicked() {
                    follow = Some(event.clone());
                }
                ui.label(mono(event.detail()).color(colors.dim));
            });
        }
    });
    if let Some(event) = follow {
        state.user.follow_process = event.process.clone();
        if !event.path.is_empty() {
            state.user.follow_module = event.dll().to_string();
        }
        state.user.view = SubView::Follow;
    }
}

// ---- a aba Exceção --------------------------------------------------------------

/// A aba Exceção.
pub(crate) fn exception_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let snapshot = Arc::clone(&state.snapshot);
    let stopped = state.status == Status::Stopped;
    let process = snapshot.process.as_ref().map(|process| process.eprocess);
    ui.horizontal_wrapped(|ui| {
        ui.label("EXCEPTION_RECORD em:");
        let response = ui.add(egui::TextEdit::singleline(&mut state.user.decode_expression).font(TextStyle::Monospace).desired_width(260.0).hint_text("@rcx, poi(@rsp+0x28), 0x3ad0e40"));
        ui.checkbox(&mut state.user.decode_pointers, "é um EXCEPTION_POINTERS");
        let submit = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
        let expression = state.user.decode_expression.trim().to_string();
        let clicked = ui.add_enabled(stopped && !expression.is_empty(), egui::Button::new("Decodificar")).clicked();
        if stopped && !expression.is_empty() && (clicked || submit) {
            state.requests.push(Request::User(UserRequest::DecodeException { expression, pointers: state.user.decode_pointers }));
        }
        if ui.add_enabled(stopped, egui::Button::new("Automático")).on_hover_text("volta a ler a exceção pela parada").clicked() {
            state.user.decode_expression.clear();
            state.requests.push(Request::User(UserRequest::DecodeException { expression: String::new(), pointers: false }));
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Parar no processo escolhido em:").strong());
        for preset in Preset::ALL {
            if ui.add_enabled(stopped && process.is_some(), egui::Button::new(preset.label())).on_hover_text(preset.hint()).clicked() {
                state.requests.push(Request::User(UserRequest::Preset(preset)));
            }
        }
        let mut first = state.user_exceptions;
        if ui.add_enabled(stopped, egui::Checkbox::new(&mut first, "primeira chance (uex)")).on_hover_text("para em toda exceção do anel 3 antes da entrega, em qualquer processo").changed() {
            state.user_exceptions = first;
            state.requests.push(Request::SetUserExceptions(first));
        }
    });
    if process.is_none() {
        hint(ui, "os breakpoints prontos valem para um processo: escolha um na aba Processos");
    }
    ui.separator();
    let Some(report) = snapshot.user.exception.clone() else {
        let places: Vec<&str> = exception::LOCATORS.iter().map(|locator| locator.symbol).collect();
        hint(ui, &format!("nenhuma exceção nesta parada. Ela é lida sozinha numa parada na entrada de {} ou numa exceção de primeira chance do anel 3 (uex); os botões acima armam essas paradas.", places.join(", ")));
        return;
    };
    egui::ScrollArea::both().id_salt("re-exception").auto_shrink([false, false]).show(ui, |ui| report_view(ui, state, &report, &snapshot, stopped, colors));
}

fn address_line(ui: &mut Ui, state: &mut UiState, text: &str, address: u64) {
    let response = ui.add(egui::Label::new(mono(text)).sense(Sense::click())).on_hover_text("clique duplo: desmontagem");
    if response.double_clicked() {
        state.go_to_code(address);
    }
}

fn report_view(ui: &mut Ui, state: &mut UiState, report: &Report, snapshot: &Snapshot, stopped: bool, colors: Palette) {
    ui.label(RichText::new(report.how.as_str()).color(colors.dim));
    if let Some(process) = &snapshot.process {
        ui.label(mono(format!("processo {} (PID {})", process.name, process.pid)).color(colors.blue));
    }
    match &report.record {
        Ok(record) => record_view(ui, state, record, colors, 0),
        Err(error) => {
            ui.label(RichText::new(error.as_str()).color(colors.red));
        }
    }
    for note in &report.notes {
        ui.label(mono(note.as_str()));
    }
    if report.first_chance && ui.add_enabled(stopped && snapshot.process.is_some(), egui::Button::new("Executar até a entrega (ntdll!KiUserExceptionDispatcher)")).on_hover_text("um breakpoint de uma vez só no KiUserExceptionDispatcher deste processo: lá o registro existe e é lido sozinho").clicked() {
        state.requests.push(Request::User(UserRequest::RunToDispatcher));
    }
    if let Some(context) = report.context {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("Pilha no ponto da exceção (CONTEXT em {context:#x})")).strong());
            if ui.small_button("no Dump").clicked() {
                state.follow_in_dump(context);
            }
        });
        if report.context_stack.is_empty() {
            hint(ui, "(o CONTEXT não pôde ser lido ou desenrolado)");
        }
        for (index, (address, name)) in report.context_stack.iter().enumerate() {
            address_line(ui, state, &format!("{index:02} {} {name}", hex(*address)), *address);
        }
    }
}

fn record_view(ui: &mut Ui, state: &mut UiState, record: &RecordView, colors: Palette, depth: usize) {
    ui.label(RichText::new(exception::describe_code(record.code)).color(colors.red).strong().size(if depth == 0 { 18.0 } else { 14.0 }));
    if !record.summary.is_empty() {
        ui.label(RichText::new(record.summary.as_str()).strong());
    }
    egui::Grid::new(("re-exception-record", depth, record.address)).num_columns(2).striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
        ui.label("endereço da exceção");
        let link = ui.add(egui::Label::new(mono(format!("{:#x} {}", record.exception_address, record.symbol)).color(colors.blue)).sense(Sense::click())).on_hover_text("clique duplo: desmontagem");
        if link.double_clicked() && record.exception_address != 0 {
            state.go_to_code(record.exception_address);
        }
        ui.end_row();
        ui.label("flags");
        ui.label(mono(exception::flags_text(record.flags)));
        ui.end_row();
        if record.address != 0 {
            ui.label("registro em");
            if ui.link(mono(format!("{:#x}", record.address))).on_hover_text("no Dump").clicked() {
                state.follow_in_dump(record.address);
            }
            ui.end_row();
        }
        for (index, value) in record.parameters.iter().enumerate() {
            ui.label(format!("parâmetro {index}"));
            ui.label(mono(format!("{value:#x}")));
            ui.end_row();
        }
        for (label, value) in &record.details {
            ui.label(label.as_str());
            ui.label(mono(value.as_str()));
            ui.end_row();
        }
        if let Some(name) = &record.thrown_type {
            ui.label("tipo lançado");
            ui.label(mono(name.as_str()).color(colors.yellow));
            ui.end_row();
        }
    });
    for note in &record.notes {
        hint(ui, note);
    }
    for (index, stowed) in record.stowed.iter().enumerate() {
        egui::CollapsingHeader::new(RichText::new(format!("exceção guardada {index}: {}", exception::hresult_name(stowed.result))).strong()).id_salt(("re-stowed", depth, index, stowed.address)).default_open(true).show(ui, |ui| stowed_view(ui, state, stowed, colors, depth));
    }
    if let Some(chained) = &record.chained {
        egui::CollapsingHeader::new(format!("registro encadeado (ExceptionRecord em {:#x})", record.chained_address)).id_salt(("re-chained", depth, record.chained_address)).default_open(true).show(ui, |ui| record_view(ui, state, chained, colors, depth + 1));
    }
}

fn stowed_view(ui: &mut Ui, state: &mut UiState, stowed: &StowedView, colors: Palette, depth: usize) {
    egui::Grid::new(("re-stowed-grid", depth, stowed.address)).num_columns(2).striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
        ui.label("STOWED_EXCEPTION_INFORMATION em");
        if ui.link(mono(format!("{:#x}", stowed.address))).on_hover_text("no Dump").clicked() {
            state.follow_in_dump(stowed.address);
        }
        ui.end_row();
        ui.label("assinatura e tamanho");
        ui.label(mono(format!("{} {:#x}", stowed.signature, stowed.size)));
        ui.end_row();
        ui.label("HRESULT");
        ui.label(mono(exception::hresult_name(stowed.result)).color(colors.yellow));
        ui.end_row();
        ui.label("forma");
        ui.label(mono(match stowed.form {
            1 => "1 (endereço e pilha)",
            2 => "2 (texto)",
            _ => "?",
        }));
        ui.end_row();
        ui.label("thread");
        ui.label(mono(format!("{} ({:#x})", stowed.thread, stowed.thread)));
        ui.end_row();
        if stowed.exception_address.0 != 0 {
            ui.label("endereço");
            let link = ui.add(egui::Label::new(mono(format!("{:#x} {}", stowed.exception_address.0, stowed.exception_address.1)).color(colors.blue)).sense(Sense::click())).on_hover_text("clique duplo: desmontagem");
            if link.double_clicked() {
                state.go_to_code(stowed.exception_address.0);
            }
            ui.end_row();
        }
        if let Some(text) = &stowed.text {
            ui.label("texto");
            ui.label(mono(format!("\"{text}\"")).color(colors.green));
            ui.end_row();
        }
        if stowed.nested_type != 0 || stowed.nested_address != 0 {
            ui.label("aninhada");
            ui.label(mono(format!("{} em {:#x}", exception::fourcc(stowed.nested_type), stowed.nested_address)));
            ui.end_row();
        }
    });
    if let Some(error) = &stowed.error {
        ui.label(RichText::new(error.as_str()).color(colors.red));
    }
    if !stowed.stack.is_empty() {
        ui.label(RichText::new(format!("pilha guardada ({} quadros)", stowed.stack.len())).strong());
        for (index, (address, name)) in stowed.stack.iter().enumerate() {
            address_line(ui, state, &format!("{index:02} {} {name}", hex(*address)), *address);
        }
    }
    match &stowed.nested {
        Some(Nested::Stowed(inner)) => {
            egui::CollapsingHeader::new("exceção aninhada (STOW)").id_salt(("re-nested-stowed", depth, inner.address)).default_open(true).show(ui, |ui| stowed_view(ui, state, inner, colors, depth + 1));
        }
        Some(Nested::Record(inner)) => {
            egui::CollapsingHeader::new("registro aninhado (W32E)").id_salt(("re-nested-record", depth, inner.address)).default_open(true).show(ui, |ui| record_view(ui, state, inner, colors, depth + 1));
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_suggestions() {
        let mut names: Vec<String> = ["dwmcore!CComposition::Present", "dwmcore!CD2DContext::InitializeD2D", "dwmcore!CD2DContext::PopulateEffectTable", "ntdll!LdrLoadDll"].iter().map(|name| name.to_string()).collect();
        names.sort();
        assert_eq!(suggestions(&names, "dwmcore!CD2D", 10).len(), 2);
        assert_eq!(suggestions(&names, "dwmcore!InitializeD2D", 10), vec!["dwmcore!CD2DContext::InitializeD2D".to_string()]);
        assert_eq!(suggestions(&names, "DWMCORE!populate", 10), vec!["dwmcore!CD2DContext::PopulateEffectTable".to_string()]);
        assert_eq!(suggestions(&names, "LdrLoad", 10), vec!["ntdll!LdrLoadDll".to_string()]);
        assert!(suggestions(&names, "kernelbase!X", 10).is_empty());
    }

    #[test]
    fn form_to_plan() {
        let user = UserUi { follow_process: " dwm.exe ".into(), follow_module: "dwmcore.dll".into(), follow_symbols: "CD2DContext::InitializeD2D\n\n dwmcore!MilFailFastForHR ;".into(), ..Default::default() };
        let plan = form_plan(&user);
        assert_eq!(plan.process, "dwm.exe");
        assert_eq!(plan.symbols, vec!["CD2DContext::InitializeD2D".to_string(), "dwmcore!MilFailFastForHR".to_string()]);
        assert!(!plan.stop_at_trigger);
        assert_eq!(plan.qualified_symbols()[0], "dwmcore!CD2DContext::InitializeD2D");
        // Sem símbolos, o plano para no evento.
        let user = UserUi { follow_process: "LogonUI.exe".into(), ..Default::default() };
        assert!(form_plan(&user).stop_at_trigger);
        assert!(form_plan(&user).validate().is_ok());
    }

    #[test]
    fn process_filter() {
        let row = ProcessRow { pid: 500, name: "dwm.exe".into(), session: Some(1), image: "\\Device\\HarddiskVolume1\\Windows\\System32\\dwm.exe".into(), ..Default::default() };
        assert!(process_matches(&row, "", None));
        assert!(process_matches(&row, "dwm", Some(1)));
        assert!(process_matches(&row, "500", None));
        assert!(process_matches(&row, "system32", None));
        assert!(!process_matches(&row, "dwm", Some(0)));
        assert!(!process_matches(&row, "logonui", None));
    }
}
