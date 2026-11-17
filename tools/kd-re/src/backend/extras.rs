//! As vistas do backend para as ferramentas novas do opennt-re: o monitor
//! de APIs e o rastreador de IRPs (o fluxo de registros do alvo, guardado
//! num depósito que a janela lê direto, sem copiar as centenas de milhares
//! de linhas a cada quadro), a vista de um endereço como tipo do PDB, os
//! exploradores do Registro, do namespace e dos arquivos, os snapshots da
//! máquina e a gravação e a reprodução (os passos para trás).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kd_client::api_monitor::{self, ApiRow};
use kd_client::explore::{FileEntry, KeyInfo, ObjectDirectory, RegistryValue, SubKey};
use kd_client::hmp;
use kd_client::irp_timeline::IrpLife;
use kd_client::monitoring;
use kd_client::struct_view::{self, ListElement, Row};
use kd_client::types::TypeDb;
use kd_client::Client;

use super::{Status, Target, Worker};

/// Os pedidos das abas novas.
#[derive(Clone, Debug)]
pub enum ExtraRequest {
    /// Liga (com os módulos; vazio = todos) ou desliga o monitor de APIs.
    ApiMonitor { enable: bool, modules: Vec<String> },
    IrpTrace(bool),
    ClearMonitors,
    /// As chamadas que passam no filtro, em CSV.
    ExportApiCsv { path: PathBuf, filter: api_monitor::Filter },
    /// Um endereço como tipo: o tipo, a expressão do endereço, as chaves
    /// abertas e o elemento escolhido de cada lista (chave, `Tipo.Campo`).
    StructView { type_name: String, address: String, expanded: Vec<String>, lists: Vec<(String, String)> },
    /// Grava um campo escalar da vista aberta.
    StructEdit { address: u64, ty: u32, text: String },
    RegistryKey(String),
    RegistryValue(String, String),
    ObjectDirectory(String),
    FileList(String),
    FileRead { path: String, offset: u64, length: u64 },
    /// Copia um arquivo do convidado para o hospedeiro.
    FileSave { path: String, destination: PathBuf },
    SnapshotSave(String),
    SnapshotLoad(String),
    SnapshotDelete(String),
    SnapshotList,
    ReverseStep,
    ReverseContinue,
}

/// O modo da máquina (o indicador da barra de estado).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TimeMode {
    #[default]
    Normal,
    /// Discos em overlays qcow2: `savevm`/`loadvm`.
    Snapshots,
    Recording(PathBuf),
    /// A reprodução (com os passos para trás, se o gdbstub os aceita).
    Replay(PathBuf, bool),
}

impl TimeMode {
    pub fn label(&self) -> String {
        match self {
            TimeMode::Normal => "normal".into(),
            TimeMode::Snapshots => "snapshots".into(),
            TimeMode::Recording(path) => format!("GRAVANDO {}", path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()),
            TimeMode::Replay(path, reverse) => format!("REPRODUCAO {}{}", path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default(), if *reverse { " (voltar no tempo)" } else { " (sem passos para tras)" }),
        }
    }

    /// O modo pelas opções do `xtask` de um alvo aberto pelo depurador.
    pub fn of(target: Option<&Target>) -> TimeMode {
        let Some(Target::Launch(options)) = target else { return TimeMode::Normal };
        let path = |value: &str| {
            let path = PathBuf::from(value);
            if path.is_relative() {
                options.root.join(path)
            } else {
                path
            }
        };
        for argument in &options.extra {
            if let Some(value) = argument.strip_prefix("--record=") {
                return TimeMode::Recording(path(value));
            }
            if let Some(value) = argument.strip_prefix("--replay=") {
                return TimeMode::Replay(path(value), false);
            }
            if argument == "--vm-snapshots" {
                return TimeMode::Snapshots;
            }
        }
        TimeMode::Normal
    }
}

/// A árvore de um tipo aberta.
#[derive(Clone)]
pub struct StructTree {
    pub type_name: String,
    pub address: u64,
    pub size: u64,
    pub rows: Vec<Row>,
    pub types: Arc<TypeDb>,
}

impl std::fmt::Debug for StructTree {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StructTree").field("type_name", &self.type_name).field("address", &self.address).field("rows", &self.rows.len()).finish()
    }
}

/// Uma chave do Registro lida.
#[derive(Clone, Debug, Default)]
pub struct RegistryKeyView {
    pub info: KeyInfo,
    pub subkeys: Vec<SubKey>,
    pub values: Vec<RegistryValue>,
}

/// O começo de um arquivo do convidado.
#[derive(Clone, Debug, Default)]
pub struct FilePreview {
    pub path: String,
    pub size: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// O que as abas novas leem do estado publicado.
#[derive(Clone, Debug, Default)]
pub struct ExtrasView {
    pub struct_tree: Option<Arc<Result<StructTree, String>>>,
    pub registry: HashMap<String, Arc<Result<RegistryKeyView, String>>>,
    pub registry_value: Option<Arc<(String, Result<RegistryValue, String>)>>,
    pub objects: HashMap<String, Arc<Result<ObjectDirectory, String>>>,
    pub files: HashMap<String, Arc<Result<Vec<FileEntry>, String>>>,
    pub file_preview: Option<Arc<Result<FilePreview, String>>>,
    pub snapshots: Option<Arc<Result<Vec<hmp::Snapshot>, String>>>,
    pub mode: TimeMode,
    /// A última mensagem das abas novas (erros e confirmações).
    pub message: String,
}

/// O monitor de APIs e os IRPs, lidos pela janela sob a trava.
#[derive(Default)]
pub struct MonitorStore {
    pub api_rows: Vec<ApiRow>,
    /// Linhas já copiadas do cliente desde o começo (contando as cortadas).
    pub copied: usize,
    pub irps: Vec<IrpLife>,
    pub driver_names: HashMap<u64, String>,
    pub api_enabled: bool,
    pub irp_enabled: bool,
    pub lost: u64,
    pub dropped: u64,
    /// Muda a cada cópia nova.
    pub generation: u64,
    /// A geração dos IRPs do cliente já copiada e quando.
    irp_generation: u64,
    irp_copied: Option<std::time::Instant>,
}

pub type SharedStore = Arc<Mutex<MonitorStore>>;

/// O texto de um arquivo de módulos de uma gravação.
fn recording_modules(path: &std::path::Path) -> Vec<(u64, u64, String)> {
    std::fs::read_to_string(monitoring::modules_file(path)).map(|text| monitoring::parse_modules(&text)).unwrap_or_default()
}

impl Worker {
    /// Antes do `attach`: o monitor do QEMU e, na reprodução, os módulos
    /// da gravação.
    pub(super) fn prepare_client(&mut self, client: &mut Client) {
        client.set_qemu_monitor(self.launch.as_ref().and_then(|launch| launch.monitor.clone()));
        let mode = TimeMode::of(self.target.as_ref());
        if let TimeMode::Replay(path, _) = &mode {
            client.set_replay(recording_modules(path));
        }
        self.publish(|shared| {
            shared.extras = ExtrasView { mode, ..ExtrasView::default() };
        });
        if let Ok(mut store) = self.store.lock() {
            *store = MonitorStore::default();
        }
    }

    /// Depois do `attach`: a reprodução diz se aceita os passos para trás.
    pub(super) fn after_attach(&mut self) {
        let reverse = self.client.as_ref().map(Client::reverse_supported);
        self.publish(|shared| {
            if let (TimeMode::Replay(_, flag), Some(reverse)) = (&mut shared.extras.mode, reverse) {
                *flag = reverse;
            }
        });
    }

    /// Copia para o depósito o que o cliente juntou (rodando ou parado).
    pub(super) fn sync_monitors(&mut self) {
        let Some(client) = self.client.as_ref() else { return };
        let monitors = &client.monitors;
        let Ok(mut store) = self.store.lock() else { return };
        let total = monitors.api_trimmed + monitors.api_rows.len();
        let mut changed = false;
        if total > store.copied {
            let start = store.copied.saturating_sub(monitors.api_trimmed);
            store.api_rows.extend_from_slice(&monitors.api_rows[start.min(monitors.api_rows.len())..]);
            store.copied = total;
            if store.api_rows.len() > monitoring::MAX_API_ROWS {
                let cut = store.api_rows.len() - monitoring::MAX_API_ROWS / 2;
                store.api_rows.drain(..cut);
            }
            changed = true;
        }
        // Os IRPs mudam no lugar (a volta de um salto): a cópia inteira, no
        // máximo a cada 300 ms com a máquina rodando.
        let due = store.irp_copied.is_none_or(|at| at.elapsed() >= std::time::Duration::from_millis(300)) || client.is_stopped();
        if monitors.generation != store.irp_generation && due {
            if !monitors.irps.irps.is_empty() || !store.irps.is_empty() {
                store.irps = monitors.irps.irps.clone();
                store.irp_copied = Some(std::time::Instant::now());
                changed = true;
            }
            store.irp_generation = monitors.generation;
        }
        let flags = (monitors.api_enabled, monitors.irp_enabled, monitors.collector.lost, monitors.target_dropped);
        if (store.api_enabled, store.irp_enabled, store.lost, store.dropped) != flags {
            (store.api_enabled, store.irp_enabled, store.lost, store.dropped) = flags;
            changed = true;
        }
        if changed {
            store.generation += 1;
            drop(store);
            (self.notify)();
        }
    }

    /// Numa parada: o que falta do fluxo, os nomes dos drivers dos IRPs e,
    /// numa gravação, os módulos ao lado dela.
    pub(super) fn extras_after_stop(&mut self) {
        let mode = self.shared.lock().map(|shared| shared.extras.mode.clone()).unwrap_or_default();
        let Some(client) = self.client.as_mut() else { return };
        if client.monitors.api_enabled || client.monitors.irp_enabled {
            if let Err(error) = client.fetch_records() {
                let error = format!("fluxo: {error}");
                self.publish(|shared| shared.extras.message = error);
            }
        }
        self.sync_monitors();
        // Os drivers dos IRPs ainda sem nome.
        let wanted: Vec<u64> = {
            let Ok(store) = self.store.lock() else { return };
            let mut drivers = HashSet::new();
            for life in &store.irps {
                for hop in life.hops() {
                    if !store.driver_names.contains_key(&hop.driver) {
                        drivers.insert(hop.driver);
                    }
                }
            }
            drivers.into_iter().take(256).collect()
        };
        if !wanted.is_empty() {
            let Some(client) = self.client.as_mut() else { return };
            let names: Vec<(u64, String)> = wanted.into_iter().map(|driver| (driver, client.driver_name(driver))).collect();
            if let Ok(mut store) = self.store.lock() {
                store.driver_names.extend(names);
                store.generation += 1;
            }
        }
        if let TimeMode::Recording(path) = mode {
            if let Some(client) = self.client.as_ref() {
                let _ = std::fs::write(monitoring::modules_file(&path), monitoring::modules_text(&client.module_list()));
            }
        }
    }

    pub(super) fn extras_message(&self, text: String) {
        self.publish(|shared| shared.extras.message = text);
    }

    /// Um pedido das abas novas; devolve se a parada precisa ser relida.
    pub(super) fn extra(&mut self, request: ExtraRequest) -> Result<bool, String> {
        match request {
            ExtraRequest::ApiMonitor { enable, modules } => {
                let result = if enable { self.with_client(|client| client.api_monitor_start(&modules)) } else { self.with_client(Client::api_monitor_stop) }?;
                self.sync_monitors();
                self.extras_message(result.clone());
                self.transcript(if enable { "(monitor de APIs) ligar" } else { "(monitor de APIs) desligar" }, Ok(result));
                Ok(false)
            }
            ExtraRequest::IrpTrace(enable) => {
                let result = if enable { self.with_client(Client::irp_trace_start) } else { self.with_client(Client::irp_trace_stop) }?;
                self.sync_monitors();
                self.extras_message(result.clone());
                self.transcript(if enable { "(IRPs) ligar" } else { "(IRPs) desligar" }, Ok(result));
                Ok(false)
            }
            ExtraRequest::ClearMonitors => {
                self.with_client(|client| {
                    client.clear_monitors();
                    Ok(())
                })?;
                if let Ok(mut store) = self.store.lock() {
                    let (api_enabled, irp_enabled, copied) = (store.api_enabled, store.irp_enabled, store.copied);
                    *store = MonitorStore { api_enabled, irp_enabled, copied, ..MonitorStore::default() };
                    store.generation = 1;
                }
                if let Some(client) = self.client.as_ref() {
                    if let Ok(mut store) = self.store.lock() {
                        store.copied = client.monitors.api_trimmed + client.monitors.api_rows.len();
                        store.irp_generation = client.monitors.generation;
                    }
                }
                Ok(false)
            }
            ExtraRequest::ExportApiCsv { path, filter } => {
                let text = {
                    let store = self.store.lock().map_err(|_| "deposito do monitor travado")?;
                    api_monitor::to_csv(store.api_rows.iter().filter(|row| filter.matches(row)))
                };
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::write(&path, text).map_err(|error| format!("{}: {error}", path.display()))?;
                self.extras_message(format!("CSV gravado em {}", path.display()));
                Ok(false)
            }
            ExtraRequest::StructView { type_name, address, expanded, lists } => {
                let result = self.build_struct_tree(&type_name, &address, expanded, lists);
                self.publish(|shared| shared.extras.struct_tree = Some(Arc::new(result)));
                Ok(false)
            }
            ExtraRequest::StructEdit { address, ty, text } => {
                let types = self.shared.lock().ok().and_then(|shared| shared.extras.struct_tree.as_ref().and_then(|tree| tree.as_ref().as_ref().ok().map(|tree| Arc::clone(&tree.types))));
                let types = types.ok_or("nenhuma vista de tipo aberta")?;
                self.with_client(|client| client.struct_edit(&types, ty, address, &text))?;
                self.extras_message(format!("{address:#x} = {text}"));
                Ok(true)
            }
            ExtraRequest::RegistryKey(path) => {
                let result = self.with_client(|client| {
                    let (info, subkeys) = client.registry_keys(&path)?;
                    let values = client.registry_values(&path)?;
                    Ok(RegistryKeyView { info, subkeys, values })
                });
                self.publish(|shared| {
                    shared.extras.registry.insert(path, Arc::new(result));
                });
                Ok(false)
            }
            ExtraRequest::RegistryValue(path, name) => {
                let result = self.with_client(|client| client.registry_value(&path, &name));
                self.publish(|shared| shared.extras.registry_value = Some(Arc::new((format!("{path}\\{name}"), result))));
                Ok(false)
            }
            ExtraRequest::ObjectDirectory(path) => {
                let result = self.with_client(|client| client.object_directory(&path));
                self.publish(|shared| {
                    shared.extras.objects.insert(path, Arc::new(result));
                });
                Ok(false)
            }
            ExtraRequest::FileList(path) => {
                let result = self.with_client(|client| client.file_list(&path));
                self.publish(|shared| {
                    shared.extras.files.insert(path, Arc::new(result));
                });
                Ok(false)
            }
            ExtraRequest::FileRead { path, offset, length } => {
                let result = self.with_client(|client| client.file_read(&path, offset, length)).map(|(size, bytes)| FilePreview { path: path.clone(), size, offset, bytes });
                self.publish(|shared| shared.extras.file_preview = Some(Arc::new(result)));
                Ok(false)
            }
            ExtraRequest::FileSave { path, destination } => {
                self.set_activity(&format!("copiando {path}"));
                let result = self.with_client(|client| client.file_read(&path, 0, 64 << 20));
                self.set_activity("");
                let (size, bytes) = result?;
                if let Some(parent) = destination.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::write(&destination, &bytes).map_err(|error| format!("{}: {error}", destination.display()))?;
                self.extras_message(format!("{path} ({size} bytes) gravado em {}", destination.display()));
                Ok(false)
            }
            ExtraRequest::SnapshotSave(name) => {
                self.set_activity(&format!("gravando o snapshot {name}"));
                let result = self.with_client(|client| client.snapshot_save(&name));
                self.set_activity("");
                self.transcript(&format!("snap save {name}"), result.clone());
                self.extras_message(result.clone().unwrap_or_else(|error| error));
                result?;
                self.extra(ExtraRequest::SnapshotList)
            }
            ExtraRequest::SnapshotLoad(name) => {
                self.set_activity(&format!("voltando ao snapshot {name}"));
                let result = self.with_client(|client| client.snapshot_load(&name));
                self.set_activity("");
                self.transcript(&format!("snap load {name}"), result.clone());
                self.extras_message(result.clone().unwrap_or_else(|error| error));
                result?;
                Ok(true)
            }
            ExtraRequest::SnapshotDelete(name) => {
                let result = self.with_client(|client| client.snapshot_delete(&name));
                self.extras_message(result.clone().unwrap_or_else(|error| error));
                result?;
                self.extra(ExtraRequest::SnapshotList)
            }
            ExtraRequest::SnapshotList => {
                let result = self.with_client(|client| client.snapshot_list());
                self.publish(|shared| shared.extras.snapshots = Some(Arc::new(result)));
                Ok(false)
            }
            ExtraRequest::ReverseStep => {
                self.set_activity("voltando um passo (o QEMU carrega o snapshot e reproduz)");
                let result = self.with_client(|client| client.reverse_step());
                self.set_activity("");
                self.transcript("voltar um passo", result.clone());
                result.map(|_| true)
            }
            ExtraRequest::ReverseContinue => {
                self.set_activity("voltando ate o breakpoint anterior");
                let result = self.with_client(|client| client.reverse_continue());
                self.set_activity("");
                self.transcript("voltar ate o breakpoint", result.clone());
                if !self.client.as_ref().is_some_and(Client::is_stopped) {
                    self.set_status(Status::Running);
                    return Ok(false);
                }
                result.map(|_| true)
            }
        }
    }

    fn build_struct_tree(&mut self, type_name: &str, address: &str, expanded: Vec<String>, lists: Vec<(String, String)>) -> Result<StructTree, String> {
        let client = self.client.as_mut().ok_or("sem conexao com o alvo")?;
        let address = client.evaluate(address)?;
        let (types, _) = client.types_for(type_name)?;
        let mut elements = HashMap::new();
        for (key, text) in lists {
            elements.insert(key, struct_view::list_element_named(&types, &text)?);
        }
        let elements: HashMap<String, ListElement> = elements;
        let expanded: HashSet<String> = expanded.into_iter().collect();
        let (types, index, rows) = client.struct_view(type_name, address, &expanded, &elements)?;
        Ok(StructTree { type_name: types.name(index), address, size: types.size(index), rows, types })
    }
}
