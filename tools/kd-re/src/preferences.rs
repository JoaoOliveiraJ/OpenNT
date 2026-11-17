//! As preferências do opennt-re (aparência, atalhos e eventos) e o banco
//! por módulo (comentários, rótulos, marcadores e breakpoints por módulo +
//! RVA, gravados e lidos sozinhos).
//!
//! As preferências ficam em `%APPDATA%/opennt-re/preferencias.json`: o
//! tamanho das fontes, a escala da interface, as cores que trocam as da
//! paleta, a tecla de cada ação (o editor de atalhos) e as paradas em
//! eventos (criação e saída de processo, carga de módulo, exceções do anel
//! 3). O banco fica em `<build>/opennt-re/db/<modulo>.json`, um arquivo
//! por módulo.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eframe::egui::{self, Color32, Key, Modifiers, RichText, Ui};
use kd_client::analysis::notes::{Location, Notes};
use kd_client::client::BreakpointRequest;
use kd_client::{Breakpoint, BreakpointKind};
use serde::{Deserialize, Serialize};

/// As ações com atalho.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Action {
    Go,
    StepInto,
    StepOver,
    StepOut,
    RunToUserCode,
    Break,
    Restart,
    ToggleBreakpoint,
    RunToCursor,
    GoTo,
    Pattern,
    Xrefs,
    NewOrigin,
    ReverseStep,
    ReverseContinue,
    SaveSnapshot,
    ViewAsType,
}

impl Action {
    pub const ALL: [Action; 17] = [
        Action::Go,
        Action::StepInto,
        Action::StepOver,
        Action::StepOut,
        Action::RunToUserCode,
        Action::Break,
        Action::Restart,
        Action::ToggleBreakpoint,
        Action::RunToCursor,
        Action::GoTo,
        Action::Pattern,
        Action::Xrefs,
        Action::NewOrigin,
        Action::ReverseStep,
        Action::ReverseContinue,
        Action::SaveSnapshot,
        Action::ViewAsType,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Action::Go => "Executar",
            Action::StepInto => "Entrar",
            Action::StepOver => "Passar por cima",
            Action::StepOut => "Executar até o retorno",
            Action::RunToUserCode => "Executar até o código de usuário",
            Action::Break => "Pausar",
            Action::Restart => "Reiniciar",
            Action::ToggleBreakpoint => "Ligar ou tirar o breakpoint",
            Action::RunToCursor => "Executar até o cursor",
            Action::GoTo => "Ir para",
            Action::Pattern => "Procurar padrão",
            Action::Xrefs => "Referências cruzadas",
            Action::NewOrigin => "Nova origem",
            Action::ReverseStep => "Voltar um passo",
            Action::ReverseContinue => "Voltar até o breakpoint",
            Action::SaveSnapshot => "Gravar snapshot",
            Action::ViewAsType => "Ver como tipo (o Dump escolhido)",
        }
    }

    /// A tecla padrão.
    pub fn default_binding(self) -> Binding {
        let (key, ctrl, shift, alt) = match self {
            Action::Go => ("F9", false, false, false),
            Action::StepInto => ("F7", false, false, false),
            Action::StepOver => ("F8", false, false, false),
            Action::StepOut => ("F9", true, false, false),
            Action::RunToUserCode => ("F9", false, false, true),
            Action::Break => ("F12", false, false, false),
            Action::Restart => ("F2", true, false, false),
            Action::ToggleBreakpoint => ("F2", false, false, false),
            Action::RunToCursor => ("F4", false, false, false),
            Action::GoTo => ("G", true, false, false),
            Action::Pattern => ("B", true, false, false),
            Action::Xrefs => ("R", true, false, false),
            Action::NewOrigin => ("8", true, false, false),
            Action::ReverseStep => ("F7", true, true, false),
            Action::ReverseContinue => ("F9", true, true, false),
            Action::SaveSnapshot => ("S", true, true, false),
            Action::ViewAsType => ("T", true, true, false),
        };
        Binding { key: key.into(), ctrl, shift, alt }
    }
}

/// Uma tecla com os modificadores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub key: String,
    pub ctrl: bool,
    pub shift: bool,
    pub alt: bool,
}

impl Binding {
    pub fn text(&self) -> String {
        let mut parts = Vec::new();
        if self.ctrl {
            parts.push("Ctrl");
        }
        if self.shift {
            parts.push("Shift");
        }
        if self.alt {
            parts.push("Alt");
        }
        parts.push(&self.key);
        parts.join("+")
    }

    pub fn modifiers(&self) -> Modifiers {
        let mut modifiers = Modifiers::NONE;
        if self.ctrl {
            modifiers |= Modifiers::CTRL;
        }
        if self.shift {
            modifiers |= Modifiers::SHIFT;
        }
        if self.alt {
            modifiers |= Modifiers::ALT;
        }
        modifiers
    }

    pub fn key(&self) -> Option<Key> {
        Key::from_name(&self.key)
    }
}

/// As paradas em eventos.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventOptions {
    /// Parar na criação de processo (`sxe cpr`).
    pub process_create: bool,
    /// Parar na saída de processo (`sxe epr`).
    pub process_exit: bool,
    /// Parar na criação de thread (`sxe ct`).
    pub thread_create: bool,
    /// Módulos (separados por vírgula) que param ao carregar (`sxe ld:`).
    pub module_loads: String,
    /// Parar nas exceções de primeira chance do anel 3 (`uex on`).
    pub user_exceptions: bool,
}

impl EventOptions {
    /// Os comandos que levam o alvo de `previous` a este estado.
    pub fn changes(&self, previous: &EventOptions) -> Vec<String> {
        let mut commands = Vec::new();
        for (now, before, code) in [(self.process_create, previous.process_create, "cpr"), (self.process_exit, previous.process_exit, "epr"), (self.thread_create, previous.thread_create, "ct")] {
            if now != before {
                commands.push(format!("{} {code}", if now { "sxe" } else { "sxd" }));
            }
        }
        if self.user_exceptions != previous.user_exceptions {
            commands.push(format!("uex {}", if self.user_exceptions { "on" } else { "off" }));
        }
        let modules = |text: &str| text.split(',').map(str::trim).filter(|module| !module.is_empty()).map(String::from).collect::<BTreeSet<String>>();
        let (now, before) = (modules(&self.module_loads), modules(&previous.module_loads));
        for module in now.difference(&before) {
            commands.push(format!("sxe ld:{module}"));
        }
        for module in before.difference(&now) {
            commands.push(format!("sxd ld:{module}"));
        }
        commands
    }

    /// Os comandos que deixam o alvo assim.
    pub fn commands(&self) -> Vec<String> {
        let mut commands = vec![
            format!("{} cpr", if self.process_create { "sxe" } else { "sxd" }),
            format!("{} epr", if self.process_exit { "sxe" } else { "sxd" }),
            format!("{} ct", if self.thread_create { "sxe" } else { "sxd" }),
            format!("uex {}", if self.user_exceptions { "on" } else { "off" }),
        ];
        for module in self.module_loads.split(',').map(str::trim).filter(|module| !module.is_empty()) {
            commands.push(format!("sxe ld:{module}"));
        }
        commands
    }
}

/// As preferências.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    /// Tamanho da fonte monoespaçada (a desmontagem, as tabelas).
    pub monospace_size: f32,
    /// Tamanho da fonte do texto comum.
    pub body_size: f32,
    /// Escala da interface (pontos por pixel).
    pub scale: f32,
    /// Cores que trocam as da paleta (nome -> RGB).
    pub colors: BTreeMap<String, [u8; 3]>,
    pub bindings: BTreeMap<Action, Binding>,
    pub events: EventOptions,
}

impl Default for Preferences {
    fn default() -> Self {
        Preferences { monospace_size: 12.5, body_size: 13.0, scale: 1.0, colors: BTreeMap::new(), bindings: BTreeMap::new(), events: EventOptions::default() }
    }
}

/// Os nomes das cores da paleta que podem ser trocadas.
pub const COLOR_NAMES: [&str; 12] = ["red", "yellow", "green", "blue", "dim", "focus", "current", "executed", "breakpoint", "comment", "label", "selection"];

pub fn color_label(name: &str) -> &'static str {
    match name {
        "red" => "vermelho (erros, mudou)",
        "yellow" => "amarelo (avisos)",
        "green" => "verde (sucesso)",
        "blue" => "azul (endereços)",
        "dim" => "apagado (notas)",
        "focus" => "linha escolhida",
        "current" => "linha do RIP",
        "executed" => "instruções executadas",
        "breakpoint" => "breakpoint",
        "comment" => "comentário",
        "label" => "rótulo",
        "selection" => "seleção",
        _ => "?",
    }
}

impl Preferences {
    pub fn binding(&self, action: Action) -> Binding {
        self.bindings.get(&action).cloned().unwrap_or_else(|| action.default_binding())
    }

    /// A tecla da ação foi apertada neste quadro (e é consumida).
    pub fn pressed(&self, ui: &Ui, action: Action) -> bool {
        let binding = self.binding(action);
        let Some(key) = binding.key() else { return false };
        ui.input_mut(|input| input.consume_key(binding.modifiers(), key))
    }

    /// As ações com a mesma tecla de outra.
    pub fn conflicts(&self) -> BTreeSet<Action> {
        let mut conflicts = BTreeSet::new();
        for (index, first) in Action::ALL.iter().enumerate() {
            for second in &Action::ALL[index + 1..] {
                if self.binding(*first) == self.binding(*second) {
                    conflicts.insert(*first);
                    conflicts.insert(*second);
                }
            }
        }
        conflicts
    }

    pub fn load(path: &Path) -> Preferences {
        std::fs::read_to_string(path).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    pub fn to_text(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Aplica a escala e as fontes ao contexto da janela (a escala só
    /// quando muda, para não brigar com a da tela).
    pub fn apply(&self, context: &egui::Context, previous: Option<&Preferences>) {
        let previous_scale = previous.map_or(1.0, |previous| previous.scale);
        if (self.scale - previous_scale).abs() > 0.001 {
            context.set_pixels_per_point(self.scale.clamp(0.6, 3.0));
        }
        context.all_styles_mut(|style| {
            if let Some(font) = style.text_styles.get_mut(&egui::TextStyle::Monospace) {
                font.size = self.monospace_size.clamp(8.0, 32.0);
            }
            if let Some(font) = style.text_styles.get_mut(&egui::TextStyle::Body) {
                font.size = self.body_size.clamp(8.0, 32.0);
            }
            if let Some(font) = style.text_styles.get_mut(&egui::TextStyle::Button) {
                font.size = self.body_size.clamp(8.0, 32.0);
            }
        });
        context.data_mut(|data| data.insert_temp(egui::Id::new("re-palette-overrides"), self.colors.clone()));
    }
}

/// As cores trocadas nas preferências (a paleta as lê do contexto).
pub fn color_override(ui: &Ui, name: &str) -> Option<Color32> {
    ui.ctx().data(|data| data.get_temp::<BTreeMap<String, [u8; 3]>>(egui::Id::new("re-palette-overrides"))).and_then(|colors| colors.get(name).map(|rgb| Color32::from_rgb(rgb[0], rgb[1], rgb[2])))
}

/// O arquivo das preferências.
pub fn preferences_path() -> Option<PathBuf> {
    crate::app::state_path().map(|path| path.with_file_name("preferencias.json"))
}

/// O estado do diálogo.
#[derive(Default)]
pub(crate) struct PreferencesUi {
    pub(crate) open: bool,
    /// A ação esperando a tecla nova.
    pub(crate) capturing: Option<Action>,
    pub(crate) saved: String,
    pub(crate) applied: Option<Preferences>,
    /// As preferências de eventos já mandadas ao alvo nesta sessão.
    pub(crate) events_sent: Option<(EventOptions, u64)>,
    pub(crate) tab: usize,
}

/// O diálogo das preferências: aparência, atalhos e eventos.
pub(crate) fn preferences_window(context: &egui::Context, preferences: &mut Preferences, ui_state: &mut PreferencesUi) {
    if !ui_state.open {
        return;
    }
    let mut open = true;
    egui::Window::new("Preferências").open(&mut open).resizable(true).default_width(560.0).show(context, |ui| {
        ui.horizontal(|ui| {
            for (index, title) in ["Aparência", "Atalhos", "Eventos"].iter().enumerate() {
                if ui.selectable_label(ui_state.tab == index, *title).clicked() {
                    ui_state.tab = index;
                }
            }
        });
        ui.separator();
        match ui_state.tab {
            0 => {
                ui.add(egui::Slider::new(&mut preferences.monospace_size, 8.0..=24.0).text("fonte monoespaçada"));
                ui.add(egui::Slider::new(&mut preferences.body_size, 8.0..=24.0).text("fonte do texto"));
                ui.add(egui::Slider::new(&mut preferences.scale, 0.6..=2.5).text("escala da interface"));
                ui.separator();
                ui.label(RichText::new("Cores (marque para trocar a do tema)").strong());
                egui::Grid::new("re-colors").num_columns(3).show(ui, |ui| {
                    for name in COLOR_NAMES {
                        let mut custom = preferences.colors.contains_key(name);
                        if ui.checkbox(&mut custom, color_label(name)).changed() {
                            if custom {
                                preferences.colors.insert(name.to_string(), [0x80, 0x80, 0x80]);
                            } else {
                                preferences.colors.remove(name);
                            }
                        }
                        if let Some(rgb) = preferences.colors.get_mut(name) {
                            ui.color_edit_button_srgb(rgb);
                        } else {
                            ui.label("tema");
                        }
                        ui.end_row();
                    }
                });
            }
            1 => {
                let conflicts = preferences.conflicts();
                ui.label("clique na tecla de uma ação e aperte a combinação nova (Esc cancela)");
                if let Some(action) = ui_state.capturing {
                    let captured = ui.input(|input| {
                        input.events.iter().find_map(|event| match event {
                            egui::Event::Key { key, pressed: true, modifiers, .. } => Some((*key, *modifiers)),
                            _ => None,
                        })
                    });
                    if let Some((key, modifiers)) = captured {
                        if key != Key::Escape {
                            preferences.bindings.insert(action, Binding { key: key.name().to_string(), ctrl: modifiers.ctrl || modifiers.command, shift: modifiers.shift, alt: modifiers.alt });
                        }
                        ui_state.capturing = None;
                    }
                }
                egui::Grid::new("re-shortcuts").num_columns(3).striped(true).show(ui, |ui| {
                    for action in Action::ALL {
                        ui.label(action.label());
                        let binding = preferences.binding(action);
                        let text = if ui_state.capturing == Some(action) { "aperte a tecla...".to_string() } else { binding.text() };
                        let mut label = RichText::new(text).monospace();
                        if conflicts.contains(&action) {
                            label = label.color(Color32::from_rgb(0xD0, 0x30, 0x30));
                        }
                        if ui.button(label).clicked() {
                            ui_state.capturing = Some(action);
                        }
                        if ui.small_button("padrão").clicked() {
                            preferences.bindings.remove(&action);
                        }
                        ui.end_row();
                    }
                });
                if !conflicts.is_empty() {
                    ui.label(RichText::new("teclas repetidas em vermelho: a primeira ação da lista ganha").color(Color32::from_rgb(0xD0, 0x30, 0x30)));
                }
            }
            _ => {
                ui.label("paradas da máquina (mandadas ao alvo na próxima parada):");
                ui.checkbox(&mut preferences.events.process_create, "criação de processo (sxe cpr)");
                ui.checkbox(&mut preferences.events.process_exit, "saída de processo (sxe epr)");
                ui.checkbox(&mut preferences.events.thread_create, "criação de thread (sxe ct)");
                ui.checkbox(&mut preferences.events.user_exceptions, "exceções de primeira chance do anel 3 (uex)");
                ui.horizontal(|ui| {
                    ui.label("carga de módulos (sxe ld:):");
                    ui.add(egui::TextEdit::singleline(&mut preferences.events.module_loads).hint_text("ntfs.sys, csrss!basesrv.dll").desired_width(260.0));
                });
            }
        }
        ui.separator();
        if ui.button("Restaurar tudo").clicked() {
            *preferences = Preferences::default();
        }
    });
    if !open {
        ui_state.open = false;
        ui_state.capturing = None;
    }
}

// ---- banco por módulo ----

/// Um breakpoint guardado por módulo + RVA.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBreakpoint {
    pub rva: u64,
    pub kind: String,
    pub length: u64,
    #[serde(default)]
    pub condition: String,
    #[serde(default)]
    pub log: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub group: String,
    pub enabled: bool,
}

impl StoredBreakpoint {
    pub fn request(&self, address: u64) -> Option<BreakpointRequest> {
        let kind = BreakpointKind::parse(&self.kind)?;
        let mut request = BreakpointRequest::new(kind, &format!("{address:#x}"));
        request.length = self.length.max(1);
        request.condition = self.condition.clone();
        request.log = self.log.clone();
        request.command = self.command.clone();
        request.group = self.group.clone();
        request.enabled = self.enabled;
        Some(request)
    }
}

/// O banco de um módulo.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRecord {
    #[serde(default)]
    pub comentarios: BTreeMap<String, String>,
    #[serde(default)]
    pub rotulos: BTreeMap<String, String>,
    #[serde(default)]
    pub marcadores: BTreeSet<String>,
    #[serde(default)]
    pub breakpoints: Vec<StoredBreakpoint>,
}

fn rva_key(offset: u64) -> String {
    format!("{offset:#x}")
}

fn parse_rva(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim().trim_start_matches("0x"), 16).ok()
}

/// O banco inteiro: um registro por módulo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModuleDb {
    pub modules: BTreeMap<String, ModuleRecord>,
}

impl ModuleDb {
    /// Monta o banco a partir das notas e dos breakpoints da sessão
    /// (`location` dá módulo + RVA de um endereço).
    pub fn from_session(notes: &Notes, breakpoints: &[Breakpoint], location: &dyn Fn(u64) -> Location) -> ModuleDb {
        let mut db = ModuleDb::default();
        for (place, text) in &notes.comments {
            if !place.module.is_empty() {
                db.modules.entry(place.module.clone()).or_default().comentarios.insert(rva_key(place.offset), text.clone());
            }
        }
        for (place, text) in &notes.labels {
            if !place.module.is_empty() {
                db.modules.entry(place.module.clone()).or_default().rotulos.insert(rva_key(place.offset), text.clone());
            }
        }
        for place in &notes.bookmarks {
            if !place.module.is_empty() {
                db.modules.entry(place.module.clone()).or_default().marcadores.insert(rva_key(place.offset));
            }
        }
        for breakpoint in breakpoints.iter().filter(|breakpoint| !breakpoint.pending && breakpoint.process == 0 && matches!(breakpoint.kind, BreakpointKind::Software | BreakpointKind::Hardware | BreakpointKind::Write | BreakpointKind::Access)) {
            let place = location(breakpoint.address);
            if place.module.is_empty() {
                continue;
            }
            let stored = StoredBreakpoint { rva: place.offset, kind: breakpoint.kind.name().to_string(), length: breakpoint.length, condition: breakpoint.condition.clone(), log: breakpoint.log.clone(), command: breakpoint.command.clone(), group: breakpoint.group.clone(), enabled: breakpoint.enabled };
            db.modules.entry(place.module.clone()).or_default().breakpoints.push(stored);
        }
        db
    }

    /// As notas guardadas no banco.
    pub fn notes(&self) -> Notes {
        let mut notes = Notes::default();
        for (module, record) in &self.modules {
            for (rva, text) in &record.comentarios {
                if let Some(offset) = parse_rva(rva) {
                    notes.set_comment(Location::new(module, offset), text);
                }
            }
            for (rva, text) in &record.rotulos {
                if let Some(offset) = parse_rva(rva) {
                    notes.set_label(Location::new(module, offset), text);
                }
            }
            for rva in &record.marcadores {
                if let Some(offset) = parse_rva(rva) {
                    notes.bookmarks.insert(Location::new(module, offset));
                }
            }
        }
        notes
    }

    /// Lê os arquivos `<modulo>.json` da pasta.
    pub fn load(directory: &Path) -> ModuleDb {
        let mut db = ModuleDb::default();
        let Ok(entries) = std::fs::read_dir(directory) else { return db };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let Some(module) = path.file_stem().map(|stem| stem.to_string_lossy().to_ascii_lowercase()) else { continue };
            if let Some(record) = std::fs::read_to_string(&path).ok().and_then(|text| serde_json::from_str::<ModuleRecord>(&text).ok()) {
                db.modules.insert(module, record);
            }
        }
        db
    }

    /// Grava um arquivo por módulo (e apaga os de módulos que ficaram
    /// vazios).
    pub fn save(&self, directory: &Path, previous: &ModuleDb) -> Result<(), String> {
        std::fs::create_dir_all(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
        for (module, record) in &self.modules {
            if previous.modules.get(module) == Some(record) {
                continue;
            }
            let path = directory.join(format!("{}.json", module.replace(['/', '\\', ':'], "_")));
            let text = serde_json::to_string_pretty(record).map_err(|error| error.to_string())?;
            std::fs::write(&path, text).map_err(|error| format!("{}: {error}", path.display()))?;
        }
        for module in previous.modules.keys().filter(|module| !self.modules.contains_key(*module)) {
            let _ = std::fs::remove_file(directory.join(format!("{module}.json")));
        }
        Ok(())
    }

    /// Junta outro banco (o lido do disco) sem apagar o desta sessão.
    pub fn merge_breakpoints_from(&mut self, other: &ModuleDb) {
        for (module, record) in &other.modules {
            let entry = self.modules.entry(module.clone()).or_default();
            for stored in &record.breakpoints {
                if !entry.breakpoints.iter().any(|existing| existing.rva == stored.rva && existing.kind == stored.kind) {
                    entry.breakpoints.push(stored.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferences_round_trip_and_conflicts() {
        let mut preferences = Preferences::default();
        assert!(preferences.conflicts().is_empty(), "{:?}", preferences.conflicts());
        preferences.bindings.insert(Action::GoTo, Binding { key: "F7".into(), ctrl: false, shift: false, alt: false });
        assert!(preferences.conflicts().contains(&Action::StepInto));
        preferences.colors.insert("red".into(), [1, 2, 3]);
        preferences.events.process_create = true;
        preferences.events.module_loads = "ntfs.sys, beep.sys".into();
        let text = preferences.to_text();
        let back: Preferences = serde_json::from_str(&text).expect("preferencias");
        assert_eq!(back, preferences);
        assert_eq!(back.binding(Action::StepOut).text(), "Ctrl+F9");
        assert!(back.events.commands().contains(&"sxe cpr".to_string()));
        assert!(back.events.commands().contains(&"sxe ld:beep.sys".to_string()));
        // Só o que mudou vai ao alvo.
        assert_eq!(EventOptions::default().changes(&EventOptions::default()), Vec::<String>::new());
        let changes = back.events.changes(&EventOptions::default());
        assert_eq!(changes, vec!["sxe cpr".to_string(), "sxe ld:beep.sys".to_string(), "sxe ld:ntfs.sys".to_string()]);
        let mut fewer = back.events.clone();
        fewer.module_loads = "ntfs.sys".into();
        fewer.process_create = false;
        assert_eq!(fewer.changes(&back.events), vec!["sxd cpr".to_string(), "sxd ld:beep.sys".to_string()]);
        assert!(Binding { key: "F7".into(), ctrl: true, shift: true, alt: false }.key().is_some());
        // Um arquivo antigo sem os campos novos vale com os padrões.
        let partial: Preferences = serde_json::from_str("{\"scale\": 1.5}").expect("parcial");
        assert_eq!(partial.scale, 1.5);
        assert_eq!(partial.monospace_size, 12.5);
    }

    #[test]
    fn module_database_round_trip() {
        let mut notes = Notes::default();
        notes.set_comment(Location::new("ntfs", 0x1234), "comentario");
        notes.set_label(Location::new("ntfs", 0x2000), "rotulo");
        notes.bookmarks.insert(Location::new("acpi", 0x10));
        notes.set_comment(Location::absolute(0x1000), "fora dos modulos");
        let breakpoint = Breakpoint {
            id: 1,
            kind: BreakpointKind::Software,
            address: 0xFFFF_F800_0000_1300,
            length: 1,
            enabled: true,
            expression: "ntfs!X".into(),
            condition: "@rax == 1".into(),
            pass_count: 0,
            hits: 0,
            pending: false,
            log: String::new(),
            command: String::new(),
            group: String::new(),
            process: 0,
            options: Default::default(),
        };
        let db = ModuleDb::from_session(&notes, &[breakpoint], &|address| Location::new("ntfs", address - 0xFFFF_F800_0000_0000));
        assert_eq!(db.modules.len(), 2);
        let ntfs = &db.modules["ntfs"];
        assert_eq!(ntfs.comentarios["0x1234"], "comentario");
        assert_eq!(ntfs.breakpoints[0].rva, 0x1300);
        assert_eq!(ntfs.breakpoints[0].request(0x5000).map(|request| request.condition), Some("@rax == 1".into()));
        let directory = std::env::temp_dir().join(format!("opennt-re-db-{}", std::process::id()));
        db.save(&directory, &ModuleDb::default()).expect("gravar");
        let loaded = ModuleDb::load(&directory);
        assert_eq!(loaded, db);
        let back = loaded.notes();
        assert_eq!(back.comments.get(&Location::new("ntfs", 0x1234)).map(String::as_str), Some("comentario"));
        assert!(back.bookmarks.contains(&Location::new("acpi", 0x10)));
        // Um módulo que ficou vazio sai do disco.
        let mut smaller = db.clone();
        smaller.modules.remove("acpi");
        smaller.save(&directory, &db).expect("gravar de novo");
        assert!(!directory.join("acpi.json").exists());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
