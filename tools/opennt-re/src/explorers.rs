//! As abas Tipos, Registro, Objetos, Arquivos e Snapshots:
//!
//! - Tipos: um endereço como qualquer tipo do PDB ("ver como tipo"), em
//!   árvore: structs, arrays, ponteiros seguidos, listas (LIST_ENTRY pelo
//!   Flink, cada entrada como a struct que a contém) e campos editáveis
//!   (clique duplo no valor);
//! - Registro: as chaves e os valores como o Configuration Manager os
//!   guarda, lidos sob demanda;
//! - Objetos: o namespace do Object Manager (diretórios, links,
//!   dispositivos, drivers), com o tipo, o corpo e o destino;
//! - Arquivos: as pastas e os arquivos do volume do kernel, com a prévia e
//!   a cópia para o hospedeiro;
//! - Snapshots: o modo da máquina, os snapshots (gravar, voltar, apagar) e
//!   os passos para trás da reprodução.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use eframe::egui::{self, RichText, Sense, TextStyle, Ui};
use opennt_kd::explore;
use opennt_kd::struct_view::RowKind;

use crate::app::{hint, mono, palette, row_height, Tab, UiState};
use crate::backend::{ExtraRequest, QueryKind, Request, Status, TimeMode};

/// O estado destas abas.
#[derive(Default)]
pub(crate) struct ExplorerUi {
    pub(crate) type_name: String,
    pub(crate) type_address: String,
    pub(crate) type_expanded: BTreeSet<String>,
    /// O elemento escolhido de cada lista (`Tipo.Campo`).
    pub(crate) type_lists: BTreeMap<String, String>,
    /// O pedido enviado (para pedir de novo só quando muda).
    pub(crate) type_sent: Option<(String, String, BTreeSet<String>, BTreeMap<String, String>, u64)>,
    /// A edição em curso: chave da linha, endereço, tipo e o texto.
    pub(crate) type_edit: Option<(String, u64, u32, String)>,
    pub(crate) list_edit: Option<(String, String)>,
    pub(crate) registry_path: String,
    pub(crate) registry_open: BTreeSet<String>,
    pub(crate) registry_requested: BTreeSet<String>,
    pub(crate) object_path: String,
    pub(crate) object_open: BTreeSet<String>,
    pub(crate) object_requested: BTreeSet<String>,
    pub(crate) file_path: String,
    pub(crate) file_requested: BTreeSet<String>,
    pub(crate) file_save: String,
    pub(crate) snapshot_name: String,
}

impl ExplorerUi {
    pub(crate) fn new() -> Self {
        ExplorerUi {
            type_name: "_EPROCESS".into(),
            registry_path: "\\Registry\\Machine\\SYSTEM\\Select".into(),
            object_path: "\\".into(),
            file_path: "/".into(),
            file_save: "build/opennt-re/arquivo.bin".into(),
            snapshot_name: "passo1".into(),
            ..ExplorerUi::default()
        }
    }
}

/// Abre a aba Tipos com um tipo num endereço (o "ver como tipo" do Dump).
pub(crate) fn view_as_type(state: &mut UiState, type_name: &str, address: u64) {
    if !type_name.is_empty() {
        state.explorer.type_name = type_name.to_string();
    }
    state.explorer.type_address = format!("{address:#x}");
    state.explorer.type_expanded.clear();
    state.explorer.type_sent = None;
    state.focus_tab.push(Tab::Types);
}

// ---- Tipos ----

pub(crate) fn types_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let stopped = state.status == Status::Stopped;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Ver como tipo").strong());
        ui.label("tipo:");
        ui.add(egui::TextEdit::singleline(&mut state.explorer.type_name).hint_text("_EPROCESS, ntdll!_PEB").font(TextStyle::Monospace).desired_width(220.0));
        ui.label("endereço:");
        ui.add(egui::TextEdit::singleline(&mut state.explorer.type_address).hint_text("@rcx, poi(...), 0x...").font(TextStyle::Monospace).desired_width(220.0));
        if ui.add_enabled(stopped, egui::Button::new("Mostrar")).clicked() {
            state.explorer.type_sent = None;
        }
        if ui.button("Fechar tudo").clicked() {
            state.explorer.type_expanded.clear();
        }
    });
    // Sugestões de tipos (o PDB do ntoskrnl).
    let prefix = state.explorer.type_name.trim();
    if prefix.len() >= 3 && !prefix.contains('!') {
        let from = state.type_names.partition_point(|name| name.as_str() < prefix);
        let found: Vec<String> = state.type_names[from..].iter().take_while(|name| name.starts_with(prefix)).take(8).cloned().collect();
        if !(found.len() == 1 && found[0] == prefix) && !found.is_empty() {
            ui.horizontal_wrapped(|ui| {
                for name in found {
                    if ui.small_button(&name).clicked() {
                        state.explorer.type_name = name;
                    }
                }
            });
        }
    }
    let generation = state.snapshot.generation;
    let request = (state.explorer.type_name.clone(), state.explorer.type_address.clone(), state.explorer.type_expanded.clone(), state.explorer.type_lists.clone(), generation);
    if stopped && !state.explorer.type_address.trim().is_empty() && state.explorer.type_sent.as_ref() != Some(&request) {
        state.explorer.type_sent = Some(request);
        state.requests.push(Request::Extra(ExtraRequest::StructView {
            type_name: state.explorer.type_name.clone(),
            address: state.explorer.type_address.clone(),
            expanded: state.explorer.type_expanded.iter().cloned().collect(),
            lists: state.explorer.type_lists.iter().map(|(key, value)| (key.clone(), value.clone())).collect(),
        }));
    }
    let Some(tree) = state.extras.struct_tree.clone() else {
        hint(ui, "um tipo do PDB do ntoskrnl (_EPROCESS, _IRP, _DEVICE_OBJECT...) ou de um módulo (ntdll!_PEB) num endereço; no Dump, o menu \"Ver como tipo\" abre aqui");
        return;
    };
    let tree = match tree.as_ref() {
        Ok(tree) => tree,
        Err(error) => {
            ui.label(RichText::new(error).color(colors.red));
            return;
        }
    };
    ui.label(RichText::new(format!("{} em {:#x} ({:#x} bytes)", tree.type_name, tree.address, tree.size)).color(colors.dim));
    let height = row_height(ui);
    let rows = &tree.rows;
    egui::ScrollArea::both().id_salt("re-types").auto_shrink([false, false]).show_rows(ui, height, rows.len(), |ui, range| {
        for row in &rows[range] {
            ui.horizontal(|ui| {
                ui.add_space(row.depth as f32 * 16.0);
                let marker = if row.expandable { if row.expanded { "▾" } else { "▸" } } else { " " };
                let toggle = ui.add(egui::Label::new(mono(marker)).sense(Sense::click()));
                if toggle.clicked() && row.expandable {
                    if row.expanded {
                        state.explorer.type_expanded.retain(|key| key != &row.key && !key.starts_with(&format!("{}/", row.key)));
                    } else {
                        state.explorer.type_expanded.insert(row.key.clone());
                    }
                }
                ui.label(mono(format!("+{:#05x}", row.offset)).color(colors.dim));
                let name = ui.add(egui::Label::new(mono(format!("{:<28}", row.name)).color(colors.blue)).sense(Sense::click()));
                ui.label(mono(format!("{:<26}", row.type_name)).color(colors.dim));
                let editing = state.explorer.type_edit.as_ref().is_some_and(|(key, ..)| key == &row.key);
                if editing {
                    let mut commit = None;
                    if let Some((_, address, ty, text)) = state.explorer.type_edit.as_mut() {
                        let response = ui.add(egui::TextEdit::singleline(text).font(TextStyle::Monospace).desired_width(180.0));
                        response.request_focus();
                        if ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                            commit = Some((*address, *ty, text.clone()));
                        }
                    }
                    if let Some((address, ty, text)) = commit {
                        state.requests.push(Request::Extra(ExtraRequest::StructEdit { address, ty, text }));
                        state.explorer.type_edit = None;
                        state.explorer.type_sent = None;
                    }
                    if ui.input(|input| input.key_pressed(egui::Key::Escape)) {
                        state.explorer.type_edit = None;
                    }
                } else {
                    let value = ui.add(egui::Label::new(mono(&row.value)).sense(Sense::click()));
                    if value.double_clicked() && row.editable && stopped {
                        let current = row.number.map(|number| format!("{number:#x}")).unwrap_or_default();
                        state.explorer.type_edit = Some((row.key.clone(), row.address, row.ty, current));
                    }
                    value.on_hover_text(format!("{:#x}", row.address));
                }
                name.context_menu(|ui| {
                    if ui.button("Seguir no Dump").clicked() {
                        state.follow_in_dump(row.address);
                        ui.close();
                    }
                    if let Some(pointer) = row.number.filter(|_| matches!(row.kind, RowKind::Pointer | RowKind::ListEntry)) {
                        if ui.button("Abrir o apontado como raiz").clicked() {
                            let target = row.type_name.trim_end_matches('*').to_string();
                            view_as_type(state, if row.kind == RowKind::ListEntry { &row.type_name } else { &target }, pointer);
                            ui.close();
                        }
                        if ui.button("Desmontar o apontado").clicked() {
                            state.go_to_code(pointer);
                            ui.close();
                        }
                    }
                    if row.kind == RowKind::List && ui.button("Tipo do elemento...").clicked() {
                        state.explorer.list_edit = Some((row.key.clone(), state.explorer.type_lists.get(&row.key).cloned().unwrap_or_default()));
                        ui.close();
                    }
                    if ui.button("Copiar o endereço").clicked() {
                        ui.ctx().copy_text(format!("{:#x}", row.address));
                        ui.close();
                    }
                });
            });
        }
    });
    if let Some((key, mut text)) = state.explorer.list_edit.take() {
        let mut keep = true;
        egui::Window::new("Tipo do elemento da lista").collapsible(false).resizable(false).show(ui.ctx(), |ui| {
            ui.label("Tipo.CampoDeLigacao (vazio = o palpite pelas listas conhecidas):");
            ui.add(egui::TextEdit::singleline(&mut text).hint_text("_ETHREAD.ThreadListEntry").font(TextStyle::Monospace).desired_width(260.0));
            ui.horizontal(|ui| {
                if ui.button("Aplicar").clicked() {
                    if text.trim().is_empty() {
                        state.explorer.type_lists.remove(&key);
                    } else {
                        state.explorer.type_lists.insert(key.clone(), text.trim().to_string());
                    }
                    keep = false;
                }
                if ui.button("Cancelar").clicked() {
                    keep = false;
                }
            });
        });
        if keep {
            state.explorer.list_edit = Some((key, text));
        }
    }
}

// ---- Registro ----

fn request_registry(state: &mut UiState, path: &str) {
    if state.explorer.registry_requested.insert(path.to_string()) {
        state.requests.push(Request::Extra(ExtraRequest::RegistryKey(path.to_string())));
    }
}

fn registry_node(ui: &mut Ui, state: &mut UiState, path: &str, name: &str, depth: usize) {
    let open = state.explorer.registry_open.contains(path);
    let selected = state.explorer.registry_path == path;
    ui.horizontal(|ui| {
        ui.add_space(depth as f32 * 14.0);
        let marker = if open { "▾" } else { "▸" };
        if ui.add(egui::Label::new(mono(marker)).sense(Sense::click())).clicked() {
            if open {
                state.explorer.registry_open.remove(path);
            } else {
                state.explorer.registry_open.insert(path.to_string());
                request_registry(state, path);
            }
        }
        let label = if selected { RichText::new(name).strong().underline() } else { RichText::new(name) };
        if ui.add(egui::Label::new(label).sense(Sense::click())).clicked() {
            state.explorer.registry_path = path.to_string();
            request_registry(state, path);
        }
    });
    if !open || depth > 24 {
        return;
    }
    let loaded = state.extras.registry.get(path).cloned();
    match loaded.as_deref() {
        Some(Ok(view)) => {
            for key in view.subkeys.clone() {
                let child = format!("{path}\\{}", key.name);
                registry_node(ui, state, &child, &key.name, depth + 1);
            }
        }
        Some(Err(error)) => {
            ui.label(RichText::new(error).color(palette(ui).red));
        }
        None => hint(ui, "lendo..."),
    }
}

pub(crate) fn registry_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let stopped = state.status == Status::Stopped;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Registro").strong());
        ui.label("caminho:");
        ui.add(egui::TextEdit::singleline(&mut state.explorer.registry_path).font(TextStyle::Monospace).desired_width(420.0));
        if ui.add_enabled(stopped, egui::Button::new("Ler")).clicked() {
            let path = state.explorer.registry_path.clone();
            state.explorer.registry_requested.remove(&path);
            request_registry(state, &path);
        }
        if ui.add_enabled(stopped, egui::Button::new("Reler tudo")).on_hover_text("as chaves lidas antes são pedidas de novo").clicked() {
            state.explorer.registry_requested.clear();
        }
    });
    if !stopped && state.extras.registry.is_empty() {
        hint(ui, "a máquina precisa estar parada: o Registro é lido da arena do Configuration Manager, com as travas do kernel livres");
        return;
    }
    if stopped {
        request_registry(state, "\\Registry");
    }
    let width = ui.available_width();
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width((width * 0.35).clamp(240.0, 480.0));
            egui::ScrollArea::both().id_salt("re-registry-tree").auto_shrink([false, false]).show(ui, |ui| {
                state.explorer.registry_open.insert("\\Registry".into());
                registry_node(ui, state, "\\Registry", "\\Registry", 0);
            });
        });
        ui.separator();
        ui.vertical(|ui| {
            let path = state.explorer.registry_path.clone();
            match state.extras.registry.get(&path).cloned().as_deref() {
                Some(Ok(view)) => {
                    let info = &view.info;
                    ui.label(RichText::new(&info.path).strong());
                    ui.label(mono(format!("{} subchaves, {} valores, escrita {}{}{}", info.subkeys, info.values, explore::nt_time(info.last_write), if info.volatile { ", volátil" } else { "" }, if info.hive.is_empty() { String::new() } else { format!(", hive {}", info.hive) })).color(colors.dim));
                    let height = row_height(ui);
                    ui.add(egui::Label::new(mono(format!("{:<32} {:<22} {:>6}  {}", "nome", "tipo", "bytes", "dados")).strong()).truncate());
                    egui::ScrollArea::both().id_salt("re-registry-values").auto_shrink([false, false]).show_rows(ui, height, view.values.len(), |ui, range| {
                        for value in &view.values[range] {
                            let name = if value.name.is_empty() { "(padrão)" } else { &value.name };
                            let response = ui.add(egui::Label::new(mono(format!("{:<32} {:<22} {:>6}  {}", name, value.kind_name(), value.size, value.display()))).sense(Sense::click()));
                            if response.double_clicked() && stopped {
                                state.requests.push(Request::Extra(ExtraRequest::RegistryValue(path.clone(), value.name.clone())));
                            }
                        }
                    });
                    if let Some(entry) = state.extras.registry_value.clone() {
                        ui.separator();
                        match &entry.1 {
                            Ok(value) => {
                                ui.label(RichText::new(format!("{} ({}, {} bytes)", entry.0, value.kind_name(), value.size)).strong());
                                let mut text = value.display();
                                ui.add(egui::TextEdit::multiline(&mut text).font(TextStyle::Monospace).desired_rows(4).desired_width(f32::INFINITY));
                            }
                            Err(error) => {
                                ui.label(RichText::new(error).color(colors.red));
                            }
                        }
                    }
                }
                Some(Err(error)) => {
                    ui.label(RichText::new(error).color(colors.red));
                }
                None => hint(ui, "escolha uma chave na árvore (ou digite o caminho e Ler); clique duplo num valor mostra os dados inteiros"),
            }
        });
    });
}

// ---- Objetos ----

fn request_objects(state: &mut UiState, path: &str) {
    if state.explorer.object_requested.insert(path.to_string()) {
        state.requests.push(Request::Extra(ExtraRequest::ObjectDirectory(path.to_string())));
    }
}

fn child_path(parent: &str, name: &str) -> String {
    if parent == "\\" {
        format!("\\{name}")
    } else {
        format!("{parent}\\{name}")
    }
}

fn object_node(ui: &mut Ui, state: &mut UiState, path: &str, name: &str, depth: usize) {
    let open = state.explorer.object_open.contains(path);
    ui.horizontal(|ui| {
        ui.add_space(depth as f32 * 14.0);
        if ui.add(egui::Label::new(mono(if open { "▾" } else { "▸" })).sense(Sense::click())).clicked() {
            if open {
                state.explorer.object_open.remove(path);
            } else {
                state.explorer.object_open.insert(path.to_string());
                request_objects(state, path);
            }
        }
        let selected = state.explorer.object_path == path;
        let label = if selected { RichText::new(name).strong().underline() } else { RichText::new(name) };
        if ui.add(egui::Label::new(label).sense(Sense::click())).clicked() {
            state.explorer.object_path = path.to_string();
            request_objects(state, path);
        }
    });
    if !open || depth > 16 {
        return;
    }
    if let Some(Ok(directory)) = state.extras.objects.get(path).cloned().as_deref() {
        for entry in directory.entries.iter().filter(|entry| entry.children > 0 || entry.kind == "Directory") {
            let child = child_path(path, &entry.name);
            object_node(ui, state, &child, &entry.name, depth + 1);
        }
    }
}

pub(crate) fn objects_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let stopped = state.status == Status::Stopped;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Namespace do Object Manager").strong());
        ui.add(egui::TextEdit::singleline(&mut state.explorer.object_path).font(TextStyle::Monospace).desired_width(320.0));
        if ui.add_enabled(stopped, egui::Button::new("Ler")).clicked() {
            let path = state.explorer.object_path.clone();
            state.explorer.object_requested.remove(&path);
            request_objects(state, &path);
        }
        if ui.add_enabled(stopped, egui::Button::new("Reler tudo")).clicked() {
            state.explorer.object_requested.clear();
        }
    });
    if stopped {
        request_objects(state, "\\");
    }
    let width = ui.available_width();
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width((width * 0.3).clamp(220.0, 420.0));
            egui::ScrollArea::both().id_salt("re-objects-tree").auto_shrink([false, false]).show(ui, |ui| {
                state.explorer.object_open.insert("\\".into());
                object_node(ui, state, "\\", "\\", 0);
            });
        });
        ui.separator();
        ui.vertical(|ui| {
            let path = state.explorer.object_path.clone();
            match state.extras.objects.get(&path).cloned().as_deref() {
                Some(Ok(directory)) => {
                    ui.label(RichText::new(format!("{} ({}, {} objetos, corpo {:#x})", directory.path, directory.kind, directory.count, directory.body)).strong());
                    let height = row_height(ui);
                    ui.add(egui::Label::new(mono(format!("{:<36} {:<20} {:<18} {}", "nome", "tipo", "corpo", "destino / arquivo")).strong()).truncate());
                    egui::ScrollArea::both().id_salt("re-objects").auto_shrink([false, false]).show_rows(ui, height, directory.entries.len(), |ui, range| {
                        for entry in &directory.entries[range] {
                            let response = ui.add(egui::Label::new(mono(format!("{:<36} {:<20} {:<18} {}", entry.name, entry.kind, format!("{:#x}", entry.body), entry.target))).sense(Sense::click()));
                            let child = child_path(&path, &entry.name);
                            if response.double_clicked() {
                                if entry.children > 0 || entry.kind == "Directory" {
                                    state.explorer.object_path = child.clone();
                                    state.explorer.object_open.insert(path.clone());
                                    request_objects(state, &child);
                                } else if entry.body != 0 {
                                    open_object(state, &entry.kind, entry.body, &child);
                                }
                            }
                            response.context_menu(|ui| {
                                if entry.body != 0 {
                                    if ui.button("Ver como tipo").clicked() {
                                        let type_name = type_for_object(&entry.kind);
                                        view_as_type(state, type_name, entry.body);
                                        ui.close();
                                    }
                                    if ui.button("Seguir no Dump").clicked() {
                                        state.follow_in_dump(entry.body);
                                        ui.close();
                                    }
                                }
                                if ui.button("Consulta do NT (!object)").clicked() {
                                    state.query_kind = QueryKind::Object;
                                    state.query_argument = child.clone();
                                    state.requests.push(Request::Query(QueryKind::Object, child.clone()));
                                    state.focus_tab.push(Tab::NtObjects);
                                    ui.close();
                                }
                                if ui.button("Copiar o caminho").clicked() {
                                    ui.ctx().copy_text(child.clone());
                                    ui.close();
                                }
                            });
                        }
                    });
                }
                Some(Err(error)) => {
                    ui.label(RichText::new(error).color(colors.red));
                }
                None => hint(ui, "escolha um diretório; clique duplo num dispositivo ou driver abre a consulta do NT, e o menu leva à vista como tipo"),
            }
        });
    });
}

/// O tipo do PDB de um tipo de objeto.
fn type_for_object(kind: &str) -> &'static str {
    match kind {
        "Device" => "_DEVICE_OBJECT",
        "Driver" => "_DRIVER_OBJECT",
        "Process" => "_EPROCESS",
        "Thread" => "_ETHREAD",
        "File" => "_FILE_OBJECT",
        "Event" | "KeyedEvent" => "_KEVENT",
        "Section" => "_SECTION",
        "Directory" => "_OBJECT_DIRECTORY",
        "SymbolicLink" => "_OBJECT_SYMBOLIC_LINK",
        "Type" => "_OBJECT_TYPE",
        "Mutant" => "_KMUTANT",
        "Semaphore" => "_KSEMAPHORE",
        "Timer" => "_KTIMER",
        _ => "_OBJECT_HEADER",
    }
}

fn open_object(state: &mut UiState, kind: &str, body: u64, path: &str) {
    let query = match kind {
        "Device" => Some((QueryKind::Device, format!("{body:#x}"))),
        "Driver" => Some((QueryKind::Driver, format!("{body:#x}"))),
        "Process" => Some((QueryKind::Process, format!("{body:#x}"))),
        "Thread" => Some((QueryKind::Thread, format!("{body:#x}"))),
        _ => None,
    };
    match query {
        Some((kind, argument)) => {
            state.query_kind = kind;
            state.query_argument = argument.clone();
            state.requests.push(Request::Query(kind, argument));
            state.focus_tab.push(Tab::NtObjects);
        }
        None => {
            let _ = path;
            view_as_type(state, type_for_object(kind), body);
        }
    }
}

// ---- Arquivos ----

fn request_files(state: &mut UiState, path: &str) {
    if state.explorer.file_requested.insert(path.to_string()) {
        state.requests.push(Request::Extra(ExtraRequest::FileList(path.to_string())));
    }
}

pub(crate) fn files_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let stopped = state.status == Status::Stopped;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Arquivos do volume").strong());
        if ui.add_enabled(state.explorer.file_path != "/", egui::Button::new("⬆")).on_hover_text("pasta de cima").clicked() {
            let parent = state.explorer.file_path.trim_end_matches('/').rsplit_once('/').map_or("/".to_string(), |(parent, _)| if parent.is_empty() { "/".into() } else { parent.to_string() });
            state.explorer.file_path = parent;
        }
        ui.add(egui::TextEdit::singleline(&mut state.explorer.file_path).font(TextStyle::Monospace).desired_width(380.0));
        if ui.add_enabled(stopped, egui::Button::new("Ler")).clicked() {
            let path = state.explorer.file_path.clone();
            state.explorer.file_requested.remove(&path);
            request_files(state, &path);
        }
    });
    let path = state.explorer.file_path.clone();
    if stopped {
        request_files(state, &path);
    }
    let width = ui.available_width();
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width((width * 0.5).clamp(320.0, 700.0));
            match state.extras.files.get(&path).cloned().as_deref() {
                Some(Ok(entries)) => {
                    let height = row_height(ui);
                    ui.add(egui::Label::new(mono(format!("{:<5} {:>12} {:<19} {}", "", "bytes", "escrita", "nome")).strong()).truncate());
                    egui::ScrollArea::both().id_salt("re-files").auto_shrink([false, false]).show_rows(ui, height, entries.len(), |ui, range| {
                        for entry in &entries[range] {
                            let line = format!("{:<5} {:>12} {:<19} {}", if entry.directory { "<DIR>" } else { "" }, entry.size, explore::nt_time(entry.modified), entry.name);
                            let response = ui.add(egui::Label::new(mono(line).color(if entry.directory { colors.blue } else { ui.visuals().text_color() })).sense(Sense::click()));
                            let full = if path.ends_with('/') { format!("{path}{}", entry.name) } else { format!("{path}/{}", entry.name) };
                            if response.double_clicked() || (response.clicked() && !entry.directory) {
                                if entry.directory {
                                    state.explorer.file_path = full;
                                } else if stopped {
                                    state.requests.push(Request::Extra(ExtraRequest::FileRead { path: full.clone(), offset: 0, length: 4096 }));
                                }
                            }
                        }
                    });
                }
                Some(Err(error)) => {
                    ui.label(RichText::new(error).color(colors.red));
                }
                None => hint(ui, if stopped { "lendo..." } else { "a máquina precisa estar parada: os arquivos vêm do leitor NTFS do kernel" }),
            }
        });
        ui.separator();
        ui.vertical(|ui| match state.extras.file_preview.clone().as_deref() {
            Some(Ok(preview)) => {
                ui.label(RichText::new(format!("{} ({} bytes)", preview.path, preview.size)).strong());
                ui.horizontal(|ui| {
                    ui.label("copiar para:");
                    ui.add(egui::TextEdit::singleline(&mut state.explorer.file_save).font(TextStyle::Monospace).desired_width(260.0));
                    if ui.add_enabled(stopped, egui::Button::new("Copiar")).clicked() {
                        state.requests.push(Request::Extra(ExtraRequest::FileSave { path: preview.path.clone(), destination: PathBuf::from(&state.explorer.file_save) }));
                    }
                });
                let height = row_height(ui);
                let lines: Vec<String> = preview
                    .bytes
                    .chunks(16)
                    .enumerate()
                    .map(|(row, chunk)| {
                        let text: String = chunk.iter().map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect();
                        format!("{:08x}  {:<48} {text}", preview.offset + row as u64 * 16, chunk.iter().map(|byte| format!("{byte:02x} ")).collect::<String>())
                    })
                    .collect();
                egui::ScrollArea::both().id_salt("re-file-preview").auto_shrink([false, false]).show_rows(ui, height, lines.len(), |ui, range| {
                    for line in &lines[range] {
                        ui.label(mono(line));
                    }
                });
            }
            Some(Err(error)) => {
                ui.label(RichText::new(error).color(colors.red));
            }
            None => hint(ui, "clique num arquivo: os primeiros 4 KB aparecem aqui, e Copiar grava o arquivo inteiro no hospedeiro"),
        });
    });
}

// ---- Snapshots e reprodução ----

pub(crate) fn snapshots_tab(ui: &mut Ui, state: &mut UiState) {
    let colors = palette(ui);
    let stopped = state.status == Status::Stopped;
    let mode = state.extras.mode.clone();
    ui.horizontal(|ui| {
        ui.label(RichText::new("Modo da máquina:").strong());
        let color = match &mode {
            TimeMode::Recording(_) => colors.red,
            TimeMode::Replay(..) => colors.yellow,
            TimeMode::Snapshots => colors.green,
            TimeMode::Normal => colors.dim,
        };
        ui.label(RichText::new(mode.label()).color(color).strong());
    });
    match &mode {
        TimeMode::Replay(_, reverse) => {
            ui.horizontal(|ui| {
                if ui.add_enabled(stopped && *reverse, egui::Button::new("⟲ Voltar um passo")).on_hover_text("reverse-stepi do gdbstub do QEMU (Ctrl+Shift+F7)").clicked() {
                    state.requests.push(Request::Extra(ExtraRequest::ReverseStep));
                }
                if ui.add_enabled(stopped && *reverse, egui::Button::new("⏪ Voltar até o breakpoint")).on_hover_text("reverse-continue: o breakpoint ou vigia anterior; sem nenhum, o começo da gravação (Ctrl+Shift+F9)").clicked() {
                    state.requests.push(Request::Extra(ExtraRequest::ReverseContinue));
                }
            });
            hint(ui, "na reprodução a máquina repete a gravação: os breakpoints e os vigias são os do gdbstub do QEMU, e as consultas do OpenNT (processos, objetos, Registro) não respondem");
        }
        TimeMode::Recording(path) => {
            hint(ui, &format!("gravando em {} (TCG com icount): a sessão do depurador entra na gravação; Arquivo > Reproduzir a gravação reabre o QEMU na reprodução, com os passos para trás", path.display()));
        }
        TimeMode::Normal => {
            hint(ui, "os snapshots precisam dos discos em qcow2: Arquivo > Abrir com snapshots (--vm-snapshots) ou Gravar a execução (--record)");
        }
        TimeMode::Snapshots => {}
    }
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("nome:");
        ui.add(egui::TextEdit::singleline(&mut state.explorer.snapshot_name).desired_width(160.0));
        let can = !matches!(mode, TimeMode::Normal);
        if ui.add_enabled(can && stopped, egui::Button::new("Gravar snapshot")).on_hover_text("savevm: a máquina inteira (memória, dispositivos, discos) parada no depurador").clicked() {
            state.requests.push(Request::Extra(ExtraRequest::SnapshotSave(state.explorer.snapshot_name.trim().to_string())));
        }
        if ui.add_enabled(can, egui::Button::new("Atualizar a lista")).clicked() {
            state.requests.push(Request::Extra(ExtraRequest::SnapshotList));
        }
    });
    if !state.extras.message.is_empty() {
        ui.label(RichText::new(&state.extras.message).color(colors.dim));
    }
    match state.extras.snapshots.clone().as_deref() {
        Some(Ok(snapshots)) if snapshots.is_empty() => hint(ui, "nenhum snapshot"),
        Some(Ok(snapshots)) => {
            ui.add(egui::Label::new(mono(format!("{:<24} {:>12} {:<20} {:<16} {}", "nome", "estado", "data", "relógio", "icount")).strong()));
            for snapshot in snapshots {
                ui.horizontal(|ui| {
                    ui.label(mono(format!("{:<24} {:>12} {:<20} {:<16} {}", snapshot.tag, snapshot.vm_size, snapshot.date, snapshot.vm_clock, snapshot.icount)));
                    if ui.add_enabled(stopped, egui::Button::new("Voltar")).on_hover_text("loadvm: a máquina volta a este ponto; os breakpoints da sessão são regravados").clicked() {
                        state.requests.push(Request::Extra(ExtraRequest::SnapshotLoad(snapshot.tag.clone())));
                    }
                    if ui.add_enabled(stopped, egui::Button::new("Apagar")).clicked() {
                        state.requests.push(Request::Extra(ExtraRequest::SnapshotDelete(snapshot.tag.clone())));
                    }
                });
            }
        }
        Some(Err(error)) => {
            ui.label(RichText::new(error).color(colors.red));
        }
        None => {}
    }
}
