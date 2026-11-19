//! O console e o log da janela.
//!
//! - As linhas do transcrito (cada comando e a saída dele), feitas aos
//!   poucos e mostradas em rolagem virtual: uma sessão longa tem dezenas de
//!   milhares de linhas, e desenhar todas a cada quadro deixa a janela lenta.
//! - O log de eventos da janela: o estado do alvo, as paradas, os erros dos
//!   comandos, as gravações que falharam e as tarefas do backend que levaram
//!   mais de dois segundos, com o tempo desde a abertura.
//! - O painel do console embaixo (abre e fecha com Ctrl+J): Comandos ou
//!   Eventos, com filtro, cópia e limpeza da vista; a linha de comando
//!   continua na barra de comando logo abaixo.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText, TextStyle, Ui};

use crate::app::{hint, mono, palette, row_height, UiState};
use crate::backend::{Entry, Status};

/// O modo Eventos da aba Log (depois de Depurador, DbgPrint e COM1).
pub(crate) const EVENTS_MODE: usize = 3;

/// Quantos eventos ficam.
const EVENT_LIMIT: usize = 5000;

/// Uma tarefa do backend que leva mais que isto entra no log.
const SLOW_TASK: Duration = Duration::from_secs(2);

/// O tipo de uma linha do transcrito.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LineKind {
    Input,
    Output,
    Error,
}

/// O transcrito em linhas, feito aos poucos (só as entradas novas).
#[derive(Default)]
pub(crate) struct TranscriptLines {
    lines: Vec<(LineKind, String)>,
    entries: usize,
}

impl TranscriptLines {
    pub(crate) fn sync(&mut self, transcript: &[Entry]) {
        if transcript.len() < self.entries {
            *self = TranscriptLines::default();
        }
        for entry in &transcript[self.entries..] {
            self.lines.push((LineKind::Input, format!("> {}", entry.input)));
            let kind = if entry.error { LineKind::Error } else { LineKind::Output };
            for line in entry.output.trim_end().lines() {
                self.lines.push((kind, line.trim_end_matches('\r').to_string()));
            }
        }
        self.entries = transcript.len();
    }

    pub(crate) fn len(&self) -> usize {
        self.lines.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub(crate) fn line(&self, index: usize) -> (LineKind, &str) {
        let (kind, text) = &self.lines[index];
        (*kind, text.as_str())
    }

    /// Tudo, uma linha por linha.
    pub(crate) fn text(&self) -> String {
        let mut text = String::new();
        for (_, line) in &self.lines {
            text.push_str(line);
            text.push('\n');
        }
        text
    }
}

/// A gravidade de um evento.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    Info,
    Warning,
    Error,
}

impl Level {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warning => "aviso",
            Level::Error => "erro",
        }
    }
}

/// Um evento da janela.
#[derive(Clone, Debug)]
pub(crate) struct Event {
    /// O tempo desde a abertura da janela.
    pub(crate) at: Duration,
    pub(crate) level: Level,
    pub(crate) text: String,
}

impl Event {
    pub(crate) fn line(&self) -> String {
        format!("{}  {:<5}  {}", clock(self.at), self.level.label(), self.text)
    }
}

/// `hh:mm:ss.d` desde a abertura.
pub(crate) fn clock(at: Duration) -> String {
    let seconds = at.as_secs();
    format!("{:02}:{:02}:{:02}.{}", seconds / 3600, (seconds % 3600) / 60, seconds % 60, at.subsec_millis() / 100)
}

/// O log de eventos da janela (os mais antigos saem depois de
/// `EVENT_LIMIT`).
pub(crate) struct EventLog {
    started: Instant,
    events: VecDeque<Event>,
    /// Quantos já saíram pelo começo (o número absoluto de um evento é
    /// `dropped + posição`).
    pub(crate) dropped: usize,
    /// A última parada registrada (as releituras da mesma parada não
    /// repetem o evento).
    last_stop: String,
}

impl Default for EventLog {
    fn default() -> Self {
        EventLog { started: Instant::now(), events: VecDeque::new(), dropped: 0, last_stop: String::new() }
    }
}

impl EventLog {
    pub(crate) fn push(&mut self, level: Level, text: impl Into<String>) {
        let text = text.into();
        // A mesma mensagem seguida não se repete.
        if self.events.back().is_some_and(|last| last.level == level && last.text == text) {
            return;
        }
        if self.events.len() >= EVENT_LIMIT {
            self.events.pop_front();
            self.dropped += 1;
        }
        self.events.push_back(Event { at: self.started.elapsed(), level, text });
    }

    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// O evento pela posição de agora.
    pub(crate) fn get(&self, index: usize) -> Option<&Event> {
        self.events.get(index)
    }

    /// O número absoluto depois do último (para as vistas que guardam
    /// índices).
    pub(crate) fn end(&self) -> usize {
        self.dropped + self.events.len()
    }

    pub(crate) fn text(&self) -> String {
        let mut text = String::new();
        for event in &self.events {
            text.push_str(&event.line());
            text.push('\n');
        }
        text
    }
}

/// O que a janela tinha antes de copiar o estado do backend.
pub(crate) struct Before {
    status: Status,
    activity: String,
    generation: u64,
    transcript: usize,
}

impl Before {
    pub(crate) fn of(state: &UiState) -> Before {
        Before { status: state.status.clone(), activity: state.activity.clone(), generation: state.snapshot.generation, transcript: state.transcript.len() }
    }
}

/// O texto do evento de um estado novo.
fn status_event(status: &Status) -> (Level, String) {
    match status {
        Status::Idle => (Level::Info, "sem alvo".to_string()),
        Status::Launching(line) => (Level::Info, format!("abrindo: {line}")),
        Status::Connecting(address) => (Level::Info, format!("conectando a {address}")),
        Status::Running => (Level::Info, "rodando".to_string()),
        Status::Stopped => (Level::Info, "pausado".to_string()),
        Status::Disconnected(reason) => (Level::Warning, format!("desconectado: {}", reason.lines().next().unwrap_or(""))),
    }
}

/// Os eventos do que mudou desde `before`: o estado do alvo, uma parada
/// nova, os erros do transcrito e as tarefas longas do backend. Também
/// acerta os relógios da barra de estado.
pub(crate) fn observe(state: &mut UiState, before: Before) {
    if std::mem::discriminant(&before.status) != std::mem::discriminant(&state.status) {
        state.status_since = Instant::now();
        let (level, text) = status_event(&state.status);
        state.events.push(level, text);
    }
    if state.snapshot.generation != before.generation && state.status == Status::Stopped {
        let stop = state.snapshot.stop.split(" [").next().unwrap_or("").trim().to_string();
        if !stop.is_empty() && stop != state.events.last_stop {
            state.events.last_stop = stop.clone();
            state.events.push(Level::Info, format!("parada: {stop}"));
        }
    }
    if state.status == Status::Running {
        // A próxima parada, mesmo com o mesmo texto, é outra.
        state.events.last_stop.clear();
    }
    let from = before.transcript.min(state.transcript.len());
    for entry in &state.transcript[from..] {
        if entry.error {
            let first = entry.output.lines().find(|line| !line.trim().is_empty()).unwrap_or("").trim();
            state.events.push(Level::Error, format!("{}: {first}", entry.input));
        }
    }
    if before.activity != state.activity {
        let elapsed = state.activity_since.elapsed();
        if !before.activity.is_empty() && elapsed >= SLOW_TASK {
            state.events.push(Level::Info, format!("{} levou {}", before.activity, crate::status::elapsed_text(elapsed)));
        }
        state.activity_since = Instant::now();
    }
}

/// As linhas que passam no filtro, de `from` até o fim, refeitas só quando
/// o modo, o filtro ou o começo mudam; as linhas novas só são conferidas
/// uma vez.
#[derive(Default)]
pub(crate) struct RowCache {
    key: Option<(usize, String, usize)>,
    scanned: usize,
    pub(crate) rows: Vec<usize>,
}

impl RowCache {
    pub(crate) fn update(&mut self, mode: usize, filter: &str, from: usize, end: usize, matches: impl Fn(usize) -> bool) -> &[usize] {
        let key = (mode, filter.to_string(), from);
        if self.key.as_ref() != Some(&key) || end < self.scanned {
            self.key = Some(key);
            self.scanned = from;
            self.rows.clear();
        }
        for index in self.scanned.max(from)..end {
            if matches(index) {
                self.rows.push(index);
            }
        }
        self.scanned = end.max(from);
        &self.rows
    }
}

/// A cor de uma linha do transcrito.
fn line_color(ui: &Ui, kind: LineKind) -> Color32 {
    let colors = palette(ui);
    match kind {
        LineKind::Input => colors.blue,
        LineKind::Output => ui.visuals().text_color(),
        LineKind::Error => colors.red,
    }
}

fn level_color(ui: &Ui, level: Level) -> Color32 {
    let colors = palette(ui);
    match level {
        Level::Info => ui.visuals().text_color(),
        Level::Warning => colors.yellow,
        Level::Error => colors.red,
    }
}

/// O transcrito em rolagem virtual (a aba Log).
pub(crate) fn transcript_view(ui: &mut Ui, state: &UiState, id: &str) {
    let lines = &state.transcript_lines;
    let height = row_height(ui);
    egui::ScrollArea::both().id_salt(id).auto_shrink([false, false]).stick_to_bottom(true).show_rows(ui, height, lines.len(), |ui, range| {
        for index in range {
            let (kind, text) = lines.line(index);
            ui.label(mono(text).color(line_color(ui, kind)));
        }
    });
}

/// O log de eventos em rolagem virtual (a aba Log).
pub(crate) fn events_view(ui: &mut Ui, state: &UiState, id: &str) {
    if state.events.is_empty() {
        hint(ui, "os eventos da janela aparecem aqui: o estado do alvo, as paradas, os erros dos comandos e as tarefas longas");
        return;
    }
    let height = row_height(ui);
    egui::ScrollArea::both().id_salt(id).auto_shrink([false, false]).stick_to_bottom(true).show_rows(ui, height, state.events.len(), |ui, range| {
        for index in range {
            if let Some(event) = state.events.get(index) {
                ui.label(mono(event.line()).color(level_color(ui, event.level)));
            }
        }
    });
}

/// O texto de uma linha do console no modo (0 comandos, 1 eventos) pelo
/// número absoluto.
fn console_line(state: &UiState, mode: usize, index: usize) -> Option<String> {
    if mode == 1 {
        state.events.get(index.checked_sub(state.events.dropped)?).map(Event::line)
    } else {
        (index < state.transcript_lines.len()).then(|| state.transcript_lines.line(index).1.to_string())
    }
}

/// O painel do console: Comandos ou Eventos, com filtro, cópia e limpeza.
pub(crate) fn console_panel(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let mode = state.console_mode.min(1);
    let end = if mode == 1 { state.events.end() } else { state.transcript_lines.len() };
    let from = if mode == 1 { state.console_cleared[1].max(state.events.dropped) } else { state.console_cleared[0] };
    let mut copy = false;
    ui.horizontal(|ui| {
        for (index, label) in ["Comandos", "Eventos"].iter().enumerate() {
            if ui.selectable_label(mode == index, *label).clicked() {
                state.console_mode = index;
            }
        }
        ui.separator();
        ui.label("filtro:");
        ui.add(egui::TextEdit::singleline(&mut state.console_filter).font(TextStyle::Monospace).desired_width(200.0).hint_text("texto, sem caixa"));
        if ui.small_button("Copiar").on_hover_text("copia as linhas que o filtro deixa").clicked() {
            copy = true;
        }
        if ui.small_button("Limpar").on_hover_text("esconde as linhas de até agora (a aba Log guarda tudo)").clicked() {
            state.console_cleared[mode] = end;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Fechar").on_hover_text(format!("fecha o console ({})", state.prefs.binding(crate::preferences::Action::ToggleConsole).text())).clicked() {
                state.console_open = false;
            }
            ui.label(RichText::new("a saída dos comandos da barra de baixo").color(colors.dim).small());
        });
    });
    // A lista filtrada fica fora do estado enquanto a vista a lê.
    let filter = state.console_filter.trim().to_lowercase();
    let mut cache = std::mem::take(&mut state.console_rows);
    cache.update(mode, &filter, from, end, |index| filter.is_empty() || console_line(state, mode, index).is_some_and(|text| text.to_lowercase().contains(&filter)));
    if copy {
        let text: String = cache.rows.iter().filter_map(|&index| console_line(state, mode, index)).map(|text| text + "\n").collect();
        ui.ctx().copy_text(text);
        state.last_message = format!("copiadas {} linhas do console", cache.rows.len());
    }
    if cache.rows.is_empty() {
        hint(ui, if mode == 1 { "nenhum evento (ou o filtro esconde todos)" } else { "a saída dos comandos aparece aqui (barra de comando embaixo; help lista os comandos)" });
    } else {
        let height = row_height(ui);
        let view = &*state;
        egui::ScrollArea::both().id_salt(("re-console", mode)).auto_shrink([false, false]).stick_to_bottom(true).show_rows(ui, height, cache.rows.len(), |ui, range| {
            for &index in &cache.rows[range] {
                if mode == 1 {
                    if let Some(event) = index.checked_sub(view.events.dropped).and_then(|position| view.events.get(position)) {
                        ui.label(mono(event.line()).color(level_color(ui, event.level)));
                    }
                } else if index < view.transcript_lines.len() {
                    let (kind, text) = view.transcript_lines.line(index);
                    ui.label(mono(text).color(line_color(ui, kind)));
                }
            }
        });
    }
    state.console_rows = cache;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(input: &str, output: &str, error: bool) -> Entry {
        Entry { input: input.into(), output: output.into(), error }
    }

    #[test]
    fn transcript_lines_grow_incrementally() {
        let mut lines = TranscriptLines::default();
        let mut transcript = vec![entry("r rip", "rip=fffff800`00001000\r\n", false)];
        lines.sync(&transcript);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines.line(0), (LineKind::Input, "> r rip"));
        assert_eq!(lines.line(1), (LineKind::Output, "rip=fffff800`00001000"));
        transcript.push(entry("bp x", "simbolo x desconhecido\nsegunda linha", true));
        lines.sync(&transcript);
        assert_eq!(lines.len(), 5);
        assert_eq!(lines.line(4), (LineKind::Error, "segunda linha"));
        // Uma entrada sem saída fica só com o comando.
        transcript.push(entry("g", "", false));
        lines.sync(&transcript);
        assert_eq!(lines.len(), 6);
        assert!(lines.text().ends_with("> g\n"));
        // O transcrito limpo recomeça.
        lines.sync(&transcript[..1]);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn event_log_limits_and_deduplicates() {
        let mut log = EventLog::default();
        log.push(Level::Info, "rodando");
        log.push(Level::Info, "rodando");
        assert_eq!(log.len(), 1);
        log.push(Level::Warning, "rodando");
        assert_eq!(log.len(), 2);
        for index in 0..EVENT_LIMIT + 10 {
            log.push(Level::Info, format!("evento {index}"));
        }
        assert_eq!(log.len(), EVENT_LIMIT);
        assert_eq!(log.dropped, 12);
        assert_eq!(log.end(), EVENT_LIMIT + 12);
        assert!(log.get(0).is_some_and(|event| event.text == "evento 10"));
        assert!(log.text().lines().next().is_some_and(|line| line.ends_with("evento 10")));
        assert_eq!(clock(Duration::from_millis(3_723_450)), "01:02:03.4");
    }

    #[test]
    fn row_cache_scans_new_lines_once() {
        let lines = ["alfa", "beta", "alfabeto", "gama"];
        let mut cache = RowCache::default();
        let matches = |index: usize| lines[index].contains("alfa");
        assert_eq!(cache.update(0, "alfa", 0, 2, matches), &[0]);
        assert_eq!(cache.update(0, "alfa", 0, 4, matches), &[0, 2]);
        // Outro começo (a vista limpa) refaz.
        assert_eq!(cache.update(0, "alfa", 1, 4, matches), &[2]);
        // Outro filtro refaz.
        assert_eq!(cache.update(0, "gama", 1, 4, |index: usize| lines[index] == "gama"), &[3]);
    }
}
