//! As abas APIs e IRPs: o monitor de APIs (cada chamada de um driver aos
//! exports do ntoskrnl e da HAL, numa tabela virtual com filtros, o
//! chamador na desmontagem e o CSV) e o rastreador de IRPs (a lista dos
//! IRPs e a linha do tempo de um: os saltos pela pilha de dispositivos, a
//! conclusão e as rotinas de conclusão). As linhas ficam no depósito do
//! backend (`MonitorStore`); a janela só monta a lista filtrada quando a
//! geração ou o filtro mudam.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui::{self, Color32, RichText, Sense, Stroke, TextStyle, Ui, Vec2};
use kd_client::api_monitor::{self, ApiRow};
use kd_client::irp_timeline::{self, IrpLife, Step};
use kd_client::ntstatus;

use crate::app::{hint, mono, palette, row_height, Tab, UiState};
use crate::backend::{ExtraRequest, Request, Status};

/// O estado das duas abas.
#[derive(Default)]
pub(crate) struct MonitorUi {
    pub(crate) modules: String,
    pub(crate) filter: api_monitor::Filter,
    /// As linhas que passam no filtro (índices no depósito) e a chave.
    pub(crate) rows: Vec<usize>,
    pub(crate) rows_key: Option<(u64, api_monitor::Filter, usize)>,
    pub(crate) selected: Option<usize>,
    pub(crate) csv_path: String,
    /// Rola até a última linha quando chegam linhas novas.
    pub(crate) follow: bool,
    pub(crate) irp_filter: irp_timeline::Filter,
    pub(crate) irp_rows: Vec<usize>,
    pub(crate) irp_key: Option<(u64, irp_timeline::Filter, usize)>,
    pub(crate) irp_selected: Option<usize>,
}

impl MonitorUi {
    pub(crate) fn new() -> Self {
        MonitorUi { csv_path: "build/opennt-re/apis.csv".into(), follow: true, ..MonitorUi::default() }
    }
}

fn duration_text(value: u64) -> String {
    let micros = value as f64 / 10.0;
    if micros >= 1000.0 {
        format!("{:.2}ms", micros / 1000.0)
    } else {
        format!("{micros:.1}us")
    }
}

fn controls_enabled(state: &UiState) -> bool {
    state.status == Status::Stopped
}

/// A aba APIs.
pub(crate) fn api_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let store = Arc::clone(&state.store);
    let (enabled, total, lost, dropped, generation) = {
        let store = store.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        (store.api_enabled, store.api_rows.len(), store.lost, store.dropped, store.generation)
    };
    let stopped = controls_enabled(state);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Monitor de APIs").strong());
        ui.label("drivers:");
        ui.add(egui::TextEdit::singleline(&mut state.monitor.modules).hint_text("vazio = todos (ex.: ntfs, ACPI)").desired_width(200.0));
        let label = if enabled { "Desligar" } else { "Ligar" };
        if ui.add_enabled(stopped, egui::Button::new(label)).on_hover_text("com a máquina parada: o alvo passa a gravar as chamadas e as manda em lotes enquanto roda").clicked() {
            let modules: Vec<String> = state.monitor.modules.split([',', ' ']).map(str::trim).filter(|word| !word.is_empty()).map(String::from).collect();
            state.requests.push(Request::Extra(ExtraRequest::ApiMonitor { enable: !enabled, modules }));
        }
        if ui.button("Limpar").clicked() {
            state.requests.push(Request::Extra(ExtraRequest::ClearMonitors));
            state.monitor.selected = None;
        }
        ui.separator();
        ui.label("CSV:");
        ui.add(egui::TextEdit::singleline(&mut state.monitor.csv_path).font(TextStyle::Monospace).desired_width(200.0));
        if ui.button("Exportar").clicked() {
            state.requests.push(Request::Extra(ExtraRequest::ExportApiCsv { path: PathBuf::from(&state.monitor.csv_path), filter: state.monitor.filter.clone() }));
        }
    });
    ui.horizontal(|ui| {
        ui.label("filtros: driver");
        ui.add(egui::TextEdit::singleline(&mut state.monitor.filter.driver).desired_width(110.0));
        ui.label("export");
        ui.add(egui::TextEdit::singleline(&mut state.monitor.filter.export).desired_width(140.0));
        ui.label("status");
        ui.add(egui::TextEdit::singleline(&mut state.monitor.filter.status).desired_width(140.0));
        ui.checkbox(&mut state.monitor.filter.failures_only, "só falhas");
        ui.checkbox(&mut state.monitor.follow, "seguir o fim");
    });
    // A lista filtrada, refeita quando a geração ou o filtro mudam.
    let key = (generation, state.monitor.filter.clone(), total);
    if state.monitor.rows_key.as_ref() != Some(&key) {
        let store = store.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.monitor.rows = if state.monitor.filter.is_empty() { (0..store.api_rows.len()).collect() } else { store.api_rows.iter().enumerate().filter(|(_, row)| state.monitor.filter.matches(row)).map(|(index, _)| index).collect() };
        state.monitor.rows_key = Some(key);
    }
    let status = if enabled { RichText::new("ligado").color(colors.green) } else { RichText::new("desligado").color(colors.dim) };
    ui.horizontal(|ui| {
        ui.label(status);
        ui.label(RichText::new(format!("{} de {total} chamadas; perdidas {lost} no fluxo e {dropped} no alvo", state.monitor.rows.len())).color(colors.dim));
    });
    if total == 0 {
        hint(ui, "Ligar (com a máquina parada) arma o monitor no alvo: cada export do ntoskrnl e da HAL chamado pelos drivers pedidos vira uma linha com os argumentos decodificados, o resultado e o NTSTATUS, a thread, a hora e o chamador. Clique duplo leva ao chamador.");
        return;
    }
    let available = ui.available_height();
    let detail_height = 110.0f32.min(available * 0.35);
    let height = row_height(ui);
    let rows = state.monitor.rows.clone();
    let header = format!("{:>7} {:>11} {:>3} {:>6} {:<12} {:<30} {:<44} {:>9}  {}", "#", "hora", "cpu", "tid", "driver", "export", "resultado", "duração", "argumentos");
    ui.add(egui::Label::new(mono(header).strong()).truncate());
    let store_guard = store.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut area = egui::ScrollArea::both().id_salt("re-api").auto_shrink([false, false]).max_height(available - detail_height - height * 2.5);
    if state.monitor.follow && enabled {
        area = area.stick_to_bottom(true);
    }
    let mut clicked = None;
    let mut go_to = None;
    area.show_rows(ui, height, rows.len(), |ui, range| {
        for &index in &rows[range] {
            let Some(row) = store_guard.api_rows.get(index) else { continue };
            let call = &row.call;
            let line = format!(
                "{:>7} {:>11.1} {:>3} {:>6} {:<12} {:<30} {:<44} {:>9}  {}",
                call.sequence,
                call.time as f64 / 10.0,
                call.cpu,
                call.tid,
                truncate(&row.module, 12),
                truncate(&row.name, 30),
                truncate(&row.result, 44),
                duration_text(call.duration),
                row.arguments
            );
            let color = if row.failed { colors.red } else { ui.visuals().text_color() };
            let response = ui.add(egui::Label::new(mono(line).color(color)).sense(Sense::click()).extend());
            if state.monitor.selected == Some(index) {
                ui.painter().rect_filled(response.rect, 0.0, colors.focus);
            }
            if response.clicked() {
                clicked = Some(index);
            }
            if response.double_clicked() {
                go_to = Some(call.return_address);
            }
            response.context_menu(|ui| {
                if ui.button("Ir para o chamador").clicked() {
                    go_to = Some(call.return_address);
                    ui.close();
                }
                if ui.button("Copiar a linha").clicked() {
                    ui.ctx().copy_text(api_monitor::format_row(row));
                    ui.close();
                }
                if ui.button(format!("Filtrar por {}", row.name)).clicked() {
                    state.monitor.filter.export = row.name.to_string();
                    ui.close();
                }
                if ui.button(format!("Filtrar pelo driver {}", row.module)).clicked() {
                    state.monitor.filter.driver = row.module.clone();
                    ui.close();
                }
            });
        }
    });
    let selected = state.monitor.selected.and_then(|index| store_guard.api_rows.get(index).cloned());
    drop(store_guard);
    if let Some(index) = clicked {
        state.monitor.selected = Some(index);
    }
    if let Some(address) = go_to {
        state.go_to_code(address);
    }
    ui.separator();
    match selected {
        Some(row) => api_detail(ui, state, &row),
        None => hint(ui, "escolha uma chamada: os argumentos com nome, os textos copiados na volta e o chamador aparecem aqui"),
    }
}

fn api_detail(ui: &mut Ui, state: &mut UiState, row: &ApiRow) {
    let colors = palette(ui);
    let call = &row.call;
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{}  #{}", row.name, call.sequence)).strong());
        ui.label(mono(format!("PID {} TID {} ETHREAD {:#x} CPU {}", call.pid, call.tid, call.thread, call.cpu)).color(colors.dim));
        if ui.link(format!("chamador {}", row.caller)).clicked() {
            state.go_to_code(call.return_address);
        }
    });
    egui::ScrollArea::vertical().id_salt("re-api-detail").auto_shrink([false, false]).show(ui, |ui| {
        for part in row.arguments.split(", ") {
            ui.label(mono(format!("  {part}")));
        }
        let status = row.status.map(|status| if ntstatus::is_error(status) { colors.red } else { colors.green }).unwrap_or(colors.blue);
        ui.label(mono(format!("  -> {} em {}", row.result, duration_text(call.duration))).color(status));
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

/// A aba IRPs.
pub(crate) fn irp_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let store = Arc::clone(&state.store);
    let (enabled, total, generation) = {
        let store = store.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        (store.irp_enabled, store.irps.len(), store.generation)
    };
    let stopped = controls_enabled(state);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Rastreador de IRPs").strong());
        let label = if enabled { "Desligar" } else { "Ligar" };
        if ui.add_enabled(stopped, egui::Button::new(label)).on_hover_text("com a máquina parada: cada IofCallDriver, IofCompleteRequest, rotina de conclusão, criação e liberação vira um evento").clicked() {
            state.requests.push(Request::Extra(ExtraRequest::IrpTrace(!enabled)));
        }
        if ui.button("Limpar").clicked() {
            state.requests.push(Request::Extra(ExtraRequest::ClearMonitors));
            state.monitor.irp_selected = None;
        }
        ui.label(if enabled { RichText::new("ligado").color(colors.green) } else { RichText::new("desligado").color(colors.dim) });
        ui.separator();
        ui.label("driver");
        ui.add(egui::TextEdit::singleline(&mut state.monitor.irp_filter.driver).desired_width(110.0));
        ui.label("dispositivo");
        ui.add(egui::TextEdit::singleline(&mut state.monitor.irp_filter.device).desired_width(120.0));
        ui.label("major");
        ui.add(egui::TextEdit::singleline(&mut state.monitor.irp_filter.major).desired_width(90.0));
        ui.checkbox(&mut state.monitor.irp_filter.failures_only, "só falhas");
    });
    let guard = store.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let names = guard.driver_names.clone();
    let driver_name = |driver: u64| names.get(&driver).cloned().unwrap_or_else(|| format!("{driver:#x}"));
    let key = (generation, state.monitor.irp_filter.clone(), total);
    if state.monitor.irp_key.as_ref() != Some(&key) {
        state.monitor.irp_rows = guard.irps.iter().enumerate().filter(|(_, life)| state.monitor.irp_filter.matches(life, &driver_name)).map(|(index, _)| index).collect();
        state.monitor.irp_key = Some(key);
    }
    ui.label(RichText::new(format!("{} de {total} IRPs", state.monitor.irp_rows.len())).color(colors.dim));
    if total == 0 {
        drop(guard);
        hint(ui, "Ligar (com a máquina parada) arma o rastreador: cada IRP aparece com o criador, a major/minor, cada salto pela pilha de dispositivos (driver, rotina, status devolvido), a conclusão e as rotinas de conclusão, com os tempos.");
        return;
    }
    let rows = state.monitor.irp_rows.clone();
    let height = row_height(ui);
    let available = ui.available_width();
    let list_width = (available * 0.45).clamp(360.0, 720.0);
    let mut clicked = None;
    let mut go_to = None;
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(list_width);
            ui.add(egui::Label::new(mono(format!("{:>5} {:<18} {:<26} {:<22} {:>9}", "#", "IRP", "major", "status", "duração")).strong()).truncate());
            egui::ScrollArea::both().id_salt("re-irps").auto_shrink([false, false]).show_rows(ui, height, rows.len(), |ui, range| {
                for &index in &rows[range] {
                    let Some(life) = guard.irps.get(index) else { continue };
                    let status = life.final_status.map(|status| ntstatus::name(status).map_or_else(|| format!("{status:#x}"), str::to_string)).unwrap_or_else(|| if life.hops().any(|hop| hop.status == Some(0x103)) { "PENDING".into() } else { "...".into() });
                    let line = format!("{:>5} {:<18} {:<26} {:<22} {:>9}", life.number, format!("{:#x}", life.address), truncate(&irp_timeline::major_name(life.major), 26), truncate(&status, 22), life.duration().map(duration_text).unwrap_or_default());
                    let failed = life.final_status.is_some_and(ntstatus::is_error);
                    let response = ui.add(egui::Label::new(mono(line).color(if failed { colors.red } else { ui.visuals().text_color() })).sense(Sense::click()).extend());
                    if state.monitor.irp_selected == Some(index) {
                        ui.painter().rect_filled(response.rect, 0.0, colors.focus);
                    }
                    if response.clicked() {
                        clicked = Some(index);
                    }
                }
            });
        });
        ui.separator();
        ui.vertical(|ui| match state.monitor.irp_selected.and_then(|index| guard.irps.get(index)) {
            Some(life) => {
                if let Some(address) = irp_detail(ui, life, &driver_name, colors.red, colors.green, colors.blue, colors.dim) {
                    go_to = Some(address);
                }
            }
            None => hint(ui, "escolha um IRP: a linha do tempo e cada passo aparecem aqui"),
        });
    });
    drop(guard);
    if let Some(index) = clicked {
        state.monitor.irp_selected = Some(index);
    }
    if let Some(address) = go_to {
        state.go_to_code(address);
        state.focus_tab.push(Tab::Cpu);
    }
}

/// A linha do tempo de um IRP: as barras dos saltos (a profundidade em
/// linhas) e os passos em texto. Devolve um endereço clicado.
fn irp_detail(ui: &mut Ui, life: &IrpLife, driver_name: &dyn Fn(u64) -> String, red: Color32, green: Color32, blue: Color32, dim: Color32) -> Option<u64> {
    let mut go_to = None;
    ui.label(RichText::new(format!("IRP #{} {:#x} {} {}", life.number, life.address, irp_timeline::major_name(life.major), irp_timeline::minor_name(life.major, life.minor).unwrap_or(""))).strong());
    ui.label(mono(format!("thread {:#x} PID {} pilha {} final {}", life.thread, life.pid, life.stack, life.status_text())).color(dim));
    let start = life.start;
    let end = life.end.unwrap_or_else(|| life.steps.iter().map(|step| step.time()).max().unwrap_or(start)).max(start + 1);
    let span = (end - start) as f32;
    let width = ui.available_width().max(200.0);
    let hops: Vec<_> = life.hops().collect();
    let lanes = hops.iter().map(|hop| hop.depth).max().unwrap_or(0) + 1;
    let lane_height = 18.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, lane_height * lanes as f32 + 10.0), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_stroke(rect, 2.0, Stroke::new(1.0, dim), egui::StrokeKind::Inside);
    for hop in &hops {
        let x0 = rect.left() + (hop.time - start) as f32 / span * width;
        let x1 = if hop.returned != 0 { rect.left() + (hop.returned - start) as f32 / span * width } else { rect.right() };
        let y = rect.top() + 5.0 + hop.depth as f32 * lane_height;
        let bar = egui::Rect::from_min_max(egui::pos2(x0, y), egui::pos2(x1.max(x0 + 3.0), y + lane_height - 4.0));
        let color = match hop.status {
            Some(status) if ntstatus::is_error(status) => red,
            Some(0x103) => blue,
            Some(_) => green,
            None => dim,
        };
        painter.rect_filled(bar, 2.0, color.gamma_multiply(0.6));
        painter.text(bar.left_center() + Vec2::new(3.0, 0.0), egui::Align2::LEFT_CENTER, driver_name(hop.driver), egui::FontId::monospace(11.0), ui.visuals().text_color());
    }
    for step in &life.steps {
        let x = rect.left() + (step.time() - start) as f32 / span * width;
        let color = match step {
            Step::Completed { .. } => green,
            Step::Routine(_) => blue,
            Step::Freed { .. } => dim,
            _ => continue,
        };
        painter.line_segment([egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())], Stroke::new(1.5, color));
    }
    egui::ScrollArea::vertical().id_salt("re-irp-steps").auto_shrink([false, false]).show(ui, |ui| {
        if let Some(creator) = life.creator {
            if ui.link(mono(format!("criado por {creator:#x}"))).clicked() {
                go_to = Some(creator);
            }
        }
        for step in &life.steps {
            let offset = format!("+{:>9}", duration_text(step.time().saturating_sub(start)));
            match step {
                Step::Created { .. } => {
                    ui.label(mono(format!("{offset} criado")));
                }
                Step::Call(hop) => {
                    ui.horizontal(|ui| {
                        let status = hop.status.map(ntstatus::describe).unwrap_or_else(|| "(sem volta)".into());
                        ui.label(mono(format!("{offset} {}IofCallDriver -> {} dev {:#x} posição {} {} {}", "  ".repeat(hop.depth), driver_name(hop.driver), hop.device, hop.location, irp_timeline::major_name(hop.major), status)));
                        if ui.link(mono("rotina")).on_hover_text(format!("{:#x}", hop.routine)).clicked() {
                            go_to = Some(hop.routine);
                        }
                        if hop.caller != 0 && ui.link(mono("chamador")).on_hover_text(format!("{:#x}", hop.caller)).clicked() {
                            go_to = Some(hop.caller);
                        }
                    });
                }
                Step::Completed { status, information, location, .. } => {
                    ui.label(mono(format!("{offset} IofCompleteRequest {} Information {information:#x} posição {location}", ntstatus::describe(*status))).color(if ntstatus::is_error(*status) { red } else { green }));
                }
                Step::Routine(call) => {
                    ui.horizontal(|ui| {
                        ui.label(mono(format!("{offset} rotina de conclusão ({}) -> {}", driver_name(call.driver), ntstatus::describe(call.result))).color(blue));
                        if ui.link(mono(format!("{:#x}", call.routine))).clicked() {
                            go_to = Some(call.routine);
                        }
                    });
                }
                Step::Freed { .. } => {
                    ui.label(mono(format!("{offset} IoFreeIrp")).color(dim));
                }
            }
        }
    });
    go_to
}
