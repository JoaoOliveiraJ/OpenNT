//! `cargo xtask status` — páginas de compatibilidade e roadmap do OpenNT.
//!
//! Gera, a partir de dados verificáveis:
//!
//! - `docs/site/index.html`: a visão geral e o glossário;
//! - `docs/site/componentes.html`: componentes e drivers por categoria, com o
//!   estado, o teste que cobre cada um e a fase do roadmap;
//! - `docs/site/testes.html`: os testes automáticos de boot e o que cada um
//!   cobre;
//! - `docs/site/modulos.html`: os módulos planejados de cada subsistema e
//!   quais já têm código;
//! - `docs/site/ntoskrnl.html` e `docs/site/ntoskrnl-<grupo>.html`: quantos
//!   exports do `ntoskrnl.exe` do Windows 10 22H2 (build 19045) o PE do
//!   OpenNT também exporta, por prefixo, com a lista de cada grupo;
//! - `docs/status/*.svg`: selos e gráfico por prefixo, também usados no README;
//! - `docs/ROADMAP.md`: as fases e o estado de cada componente.
//!
//! As listas que crescem (componentes, módulos, exports) aparecem inteiras,
//! com busca e filtro por um script inline pequeno (sem JavaScript, só a
//! busca some).
//!
//! Entradas: o PE de referência (em cache em `docs/status/ntoskrnl-exports.def`),
//! a lista de módulos planejados (`docs/status/modulos-planejados.txt`), a
//! árvore Rust do repositório e o arquivo editado à mão
//! `docs/status/components.toml`.

mod pe;
mod render;
mod sources;
mod toml;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use sources::RustIndex;

pub const USAGE: &str = "uso: cargo xtask status [--reference=NTOSKRNL.EXE]
  --reference=ARQ  le os exports deste ntoskrnl.exe e atualiza docs/status/ntoskrnl-exports.def
                   (sem a opcao, usa o cache; sem cache, usa %SystemRoot%\\System32\\ntoskrnl.exe)
saida: docs/site/{index,componentes,testes,modulos,ntoskrnl,ntoskrnl-*}.html, docs/status/*.svg e docs/ROADMAP.md";

const COMPONENTS: &str = "docs/status/components.toml";
const SITE_DIR: &str = "docs/site";
const STATUS_DIR: &str = "docs/status";

/// Grupos de prefixo, na ordem das páginas.
pub const BUCKETS: &[&str] = &[
    "Ke", "Ke*Irql", "Mm", "Ob", "Ps", "Io", "Ex", "Rtl", "Se", "Zw/Nt", "Cm", "Po", "Hal", "Wmi/Etw", "Fs/FsRtl",
    "Kd", "Inbv", "outros",
];

/// `Ke` casa `KeX`, `KefX`, `KeiX`, `KepX` (convenção do NT: f = rápida,
/// i = interna, p = privada; `x` aparece em `RtlxAnsiStringToUnicodeSize`),
/// mas não `Kernel...`.
fn has_prefix(name: &str, prefix: &str) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else { return false };
    let mut characters = rest.chars();
    match characters.next() {
        Some(character) if character.is_ascii_uppercase() => true,
        Some('f' | 'i' | 'p' | 'x') => characters.next().is_some_and(|character| character.is_ascii_uppercase()),
        _ => false,
    }
}

pub fn bucket(name: &str) -> &'static str {
    let kernel = ["Ke", "Kf", "Ki", "Kx"].iter().any(|prefix| has_prefix(name, prefix));
    if kernel {
        return if name.contains("Irql") { "Ke*Irql" } else { "Ke" };
    }
    const TABLE: &[(&str, &[&str])] = &[
        ("Mm", &["Mm"]),
        ("Ob", &["Ob"]),
        ("Ps", &["Ps"]),
        ("Io", &["Io"]),
        ("Ex", &["Ex"]),
        ("Rtl", &["Rtl"]),
        ("Se", &["Se"]),
        ("Zw/Nt", &["Zw", "Nt"]),
        ("Cm", &["Cm"]),
        ("Po", &["Po"]),
        ("Hal", &["Hal"]),
        ("Wmi/Etw", &["Wmi", "Etw", "Wpp"]),
        ("Fs/FsRtl", &["FsRtl", "Fs"]),
        ("Kd", &["Kd"]),
        ("Inbv", &["Inbv"]),
    ];
    TABLE
        .iter()
        .find(|(_, prefixes)| prefixes.iter().any(|prefix| has_prefix(name, prefix)))
        .map(|(bucket, _)| *bucket)
        .unwrap_or("outros")
}

// ---- modelo das páginas ------------------------------------------------------

pub struct ExportRow {
    pub name: String,
    pub data: bool,
    pub bucket: &'static str,
    pub opennt: bool,
}

#[derive(Clone, Default)]
pub struct Tally {
    pub reference: usize,
    pub opennt: usize,
    pub functions: usize,
    pub functions_opennt: usize,
}

impl Tally {
    pub fn missing(&self) -> usize {
        self.reference - self.opennt
    }
}

pub struct ExportReport {
    pub file_version: Option<String>,
    pub unnamed: usize,
    pub rows: Vec<ExportRow>,
    pub buckets: Vec<(&'static str, Tally)>,
    pub total: Tally,
    pub opennt_extra: Vec<String>,
}

/// Estado de um componente, como aparece para o leitor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Implementado e coberto por um teste automático de boot.
    Works,
    /// Parte implementada, ou implementado sem teste automático.
    InDevelopment,
    /// Previsto numa fase do roadmap.
    Planned,
    /// Fora do escopo atual.
    OutOfScope,
}

pub const STATES: &[State] = &[State::Works, State::InDevelopment, State::Planned, State::OutOfScope];

pub struct TestRow {
    pub id: String,
    pub title: String,
    pub marker: String,
    pub command: String,
    pub description: String,
    /// Arquivo das fontes Rust em que o marcador aparece.
    pub location: Option<String>,
}

/// Um caminho do repositório citado no `components.toml`, conferido.
pub struct PathRef {
    pub path: String,
    pub exists: bool,
}

pub struct ComponentRow {
    pub name: String,
    pub category: String,
    pub icon: String,
    pub description: String,
    /// Declarado "implementado" sem teste automático aparece como
    /// `InDevelopment` ("Parcial"); a página diz que falta o teste.
    pub state: State,
    pub paths: Vec<PathRef>,
    /// Índices em `Report::tests` dos testes que cobrem o componente.
    pub tests: Vec<usize>,
    pub phase: String,
    pub notes: String,
}

pub struct PhaseRow {
    pub number: String,
    pub name: String,
    pub state: String,
    pub scope: String,
}

/// Estado de um módulo planejado.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ModuleState {
    /// O arquivo Rust do módulo existe.
    Done,
    /// O arquivo existe, mas o módulo está declarado parcial em `[parciais]`.
    Partial,
    /// Ainda sem arquivo Rust.
    Pending,
    /// Fora da conta (`[fora_do_escopo]`).
    OutOfScope,
}

pub const MODULE_STATES: &[ModuleState] =
    &[ModuleState::Done, ModuleState::Partial, ModuleState::Pending, ModuleState::OutOfScope];

/// Um módulo planejado (`ntos/ob/handle_table`), com o arquivo que o atende.
pub struct ModuleRow {
    pub name: String,
    pub rust: Option<String>,
    pub state: ModuleState,
    /// Uma suíte de autoteste importa o arquivo do módulo diretamente.
    pub tested: bool,
    /// Motivo declarado em `[parciais]` ou `[fora_do_escopo]`.
    pub note: String,
}

pub struct SubsystemRow {
    pub folder: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub phase: String,
    pub notes: String,
    pub is_tests: bool,
    /// Módulos planejados no escopo, prontos e parciais.
    pub planned: usize,
    pub done: usize,
    pub partial: usize,
    /// Todos os módulos planejados da pasta, inclusive os fora da conta.
    pub modules: Vec<ModuleRow>,
}

impl SubsystemRow {
    pub fn covered(&self) -> usize {
        self.done + self.partial
    }

    pub fn pending(&self) -> usize {
        self.planned - self.covered()
    }

    pub fn out_of_scope(&self) -> usize {
        self.modules.iter().filter(|module| module.state == ModuleState::OutOfScope).count()
    }

    /// Módulos no escopo cujo arquivo alguma suíte de autoteste importa.
    pub fn tested(&self) -> usize {
        self.modules.iter().filter(|module| module.tested && module.state != ModuleState::OutOfScope).count()
    }
}

/// Uma categoria de componentes, na ordem em que aparece no `components.toml`.
pub struct CategoryRow {
    pub name: String,
    pub description: String,
    pub icon: String,
}

pub struct Report {
    pub exports: ExportReport,
    pub subsystems: Vec<SubsystemRow>,
    pub components: Vec<ComponentRow>,
    pub categories: Vec<CategoryRow>,
    pub tests: Vec<TestRow>,
    pub phases: Vec<PhaseRow>,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn count(&self, state: State) -> usize {
        self.components.iter().filter(|row| row.state == state).count()
    }

    /// Módulos no escopo citados diretamente por alguma suíte de autoteste.
    pub fn modules_tested(&self) -> usize {
        self.subsystems.iter().filter(|row| !row.is_tests).map(SubsystemRow::tested).sum()
    }

    /// Componentes que um teste cobre (índices em `components`).
    pub fn covered_by(&self, test: usize) -> Vec<&ComponentRow> {
        self.components.iter().filter(|row| row.tests.contains(&test)).collect()
    }

    /// (prontos, parciais, planejados) somando todos os subsistemas.
    pub fn module_totals(&self) -> (usize, usize, usize) {
        let done = self.subsystems.iter().map(|row| row.done).sum();
        let partial = self.subsystems.iter().map(|row| row.partial).sum();
        let planned = self.subsystems.iter().map(|row| row.planned).sum();
        (done, partial, planned)
    }

    pub fn tests_found(&self) -> usize {
        self.tests.iter().filter(|test| test.location.is_some()).count()
    }
}

// ---- montagem ------------------------------------------------------------------

fn parse_options(arguments: &[String]) -> Result<Option<PathBuf>, String> {
    let mut reference = None;
    for argument in arguments {
        match argument.split_once('=') {
            Some(("--reference", value)) => reference = Some(PathBuf::from(value)),
            _ if argument == "--help" || argument == "-h" => return Err(USAGE.to_string()),
            _ => return Err(format!("opcao desconhecida: {argument}\n{USAGE}")),
        }
    }
    Ok(reference)
}

fn export_report(reference: &sources::Reference, opennt_exports: &[String]) -> ExportReport {
    let opennt: BTreeSet<&str> = opennt_exports.iter().map(String::as_str).collect();
    let names: BTreeSet<&str> = reference.exports.iter().map(|export| export.name.as_str()).collect();

    let mut rows = Vec::new();
    let mut tallies: BTreeMap<&'static str, Tally> = BTreeMap::new();
    let mut total = Tally::default();
    for export in &reference.exports {
        let bucket = bucket(&export.name);
        let covered = opennt.contains(export.name.as_str());
        let tally = tallies.entry(bucket).or_default();
        for target in [tally, &mut total] {
            target.reference += 1;
            target.opennt += covered as usize;
            target.functions += !export.data as usize;
            target.functions_opennt += (covered && !export.data) as usize;
        }
        rows.push(ExportRow { name: export.name.clone(), data: export.data, bucket, opennt: covered });
    }
    let buckets = BUCKETS.iter().map(|name| (*name, tallies.remove(name).unwrap_or_default())).collect();
    ExportReport {
        file_version: reference.file_version.clone(),
        unnamed: reference.unnamed,
        rows,
        buckets,
        total,
        opennt_extra: opennt_exports.iter().filter(|name| !names.contains(name.as_str())).cloned().collect(),
    }
}

/// (pasta-pai, nome) do módulo Rust, com `mod.rs` no lugar da pasta.
fn rust_module_key(path: &str) -> Option<(String, String)> {
    let mut parts: Vec<&str> = path.split('/').collect();
    let file = parts.pop()?;
    let stem = file.strip_suffix(".rs").unwrap_or(file);
    if stem == "mod" || stem == "lib" || stem == "main" {
        let module = parts.pop()?;
        let parent = parts.pop().unwrap_or("");
        return Some((parent.to_string(), module.to_string()));
    }
    Some((parts.pop().unwrap_or("").to_string(), stem.to_string()))
}

fn referenced_by_tests(path: &str, references: &[Vec<String>]) -> bool {
    let Some((parent, module)) = rust_module_key(path) else { return false };
    references
        .iter()
        .any(|segments| segments.windows(2).any(|pair| pair[0] == parent && pair[1] == module))
}

/// Quem usa os autotestes. Um grupo de exports (um `pub mod` num
/// `exports.rs`) conta quando um autoteste chama pelo nome pelo menos um dos
/// seus exports, como a fase 6 faz com `call_export`, ou cita o submódulo do
/// grupo pelo caminho; citar só o `exports.rs` não marca todos os grupos do
/// arquivo. Os demais módulos (e um módulo que é o arquivo inteiro) contam
/// quando um teste cita o seu caminho Rust.
fn used_by_tests(root: &Path, path: &str, module: &str, references: &[Vec<String>], export_calls: &BTreeSet<String>) -> bool {
    if path.ends_with("/exports.rs") {
        if let Some(names) = sources::group_export_names(root, path, module) {
            let submodule = format!("{module}_exports");
            return names.iter().any(|name| export_calls.contains(name))
                || references
                    .iter()
                    .any(|segments| segments.windows(2).any(|pair| pair[0] == "exports" && (pair[1] == module || pair[1] == submodule)));
        }
    }
    referenced_by_tests(path, references)
}

#[allow(clippy::too_many_arguments)]
fn subsystem_rows(
    document: &toml::Document,
    plan: &[sources::PlannedModule],
    index: &RustIndex,
    root: &Path,
    test_refs: &[Vec<String>],
    export_calls: &BTreeSet<String>,
    test_dirs: &[String],
    warnings: &mut Vec<String>,
) -> Vec<SubsystemRow> {
    let aliases = document.table("correspondencias").cloned().unwrap_or_default();
    let partial = document.table("parciais").cloned().unwrap_or_default();
    let outside = document.table("fora_do_escopo").cloned().unwrap_or_default();

    let mut by_folder: BTreeMap<String, Vec<ModuleRow>> = BTreeMap::new();
    for module in plan {
        let folder = module.path.rsplit_once('/').map(|(folder, _)| folder.to_string()).unwrap_or_default();
        let rust = match aliases.string(&module.path) {
            Some("") => None,
            Some(path) => {
                if index.files.contains(path) {
                    Some(path.to_string())
                } else {
                    warnings.push(format!("correspondencias: {} -> {path} nao existe", module.path));
                    None
                }
            }
            None if module.path.starts_with("ntos/test/") => index.find_test(&module.path, test_dirs).map(String::from),
            None => index.find(&module.path).map(String::from),
        };
        let (state, note) = if let Some(reason) = outside.string(&module.path) {
            (ModuleState::OutOfScope, reason)
        } else if rust.is_none() {
            (ModuleState::Pending, "")
        } else if let Some(reason) = partial.string(&module.path) {
            (ModuleState::Partial, reason)
        } else {
            (ModuleState::Done, "")
        };
        let stem = module.path.rsplit('/').next().unwrap_or("");
        let tested = folder != "ntos/test" && rust.as_deref().is_some_and(|path| used_by_tests(root, path, stem, test_refs, export_calls));
        by_folder.entry(folder).or_default().push(ModuleRow {
            name: module.path.clone(),
            rust,
            state,
            tested,
            note: note.to_string(),
        });
    }
    for table in [&aliases, &partial, &outside] {
        for (key, _) in &table.entries {
            if !plan.iter().any(|module| &module.path == key) {
                warnings.push(format!("components.toml cita modulo planejado inexistente: {key}"));
            }
        }
    }

    let summarize = |mut modules: Vec<ModuleRow>, entry: Option<&toml::Table>, folder: &str| {
        modules.sort_by(|left, right| left.name.cmp(&right.name));
        let scope: Vec<&ModuleRow> = modules.iter().filter(|module| module.state != ModuleState::OutOfScope).collect();
        let text = |key: &str| entry.and_then(|table| table.string(key)).unwrap_or_default().to_string();
        SubsystemRow {
            folder: folder.to_string(),
            name: if entry.is_some() { text("nome") } else { folder.to_string() },
            description: text("descricao"),
            icon: entry.and_then(|table| table.string("icone")).unwrap_or("cube").to_string(),
            phase: text("fase"),
            notes: text("notas"),
            is_tests: folder == "ntos/test",
            planned: scope.len(),
            done: scope.iter().filter(|module| module.state == ModuleState::Done).count(),
            partial: scope.iter().filter(|module| module.state == ModuleState::Partial).count(),
            modules,
        }
    };

    let mut rows = Vec::new();
    for entry in document.array("subsistema") {
        let folder = entry.string("pasta").unwrap_or_default().to_string();
        let Some(modules) = by_folder.remove(&folder) else {
            warnings.push(format!("subsistema {folder}: nenhum modulo planejado nessa pasta"));
            continue;
        };
        rows.push(summarize(modules, Some(entry), &folder));
    }
    for (folder, modules) in by_folder {
        warnings.push(format!("pasta sem [[subsistema]] em components.toml: {folder}"));
        rows.push(summarize(modules, None, &folder));
    }
    rows
}

fn test_rows(document: &toml::Document, root: &Path, rust_dirs: &[String], warnings: &mut Vec<String>) -> Vec<TestRow> {
    document
        .array("teste")
        .iter()
        .map(|entry| {
            let marker = entry.string("marcador").unwrap_or_default().to_string();
            let location = sources::find_marker(root, rust_dirs, &marker).unwrap_or(None);
            if location.is_none() {
                warnings.push(format!("marcador {marker} nao aparece nas fontes Rust"));
            }
            TestRow {
                id: entry.string("id").unwrap_or_default().into(),
                title: entry.string("titulo").unwrap_or_default().into(),
                command: entry.string("comando").unwrap_or_default().into(),
                description: entry.string("descricao").unwrap_or_default().into(),
                location,
                marker,
            }
        })
        .collect()
}

fn component_rows(document: &toml::Document, root: &Path, tests: &[TestRow], warnings: &mut Vec<String>) -> Vec<ComponentRow> {
    let category_icons = document.table("icones_categoria").cloned().unwrap_or_default();
    let mut rows = Vec::new();
    for entry in document.array("componente") {
        let name = entry.string("nome").unwrap_or_default().to_string();
        let category = entry.string("categoria").unwrap_or("Outros").to_string();
        let paths: Vec<PathRef> = entry
            .strings("caminhos")
            .into_iter()
            .map(|path| {
                let exists = root.join(&path).exists();
                if !exists {
                    warnings.push(format!("{name}: caminho inexistente: {path}"));
                }
                PathRef { path, exists }
            })
            .collect();
        let mut test_indexes = Vec::new();
        for id in entry.strings("testes") {
            match tests.iter().position(|test| test.id == id) {
                Some(index) => test_indexes.push(index),
                None => warnings.push(format!("{name}: teste desconhecido: {id}")),
            }
        }
        let tested = test_indexes.iter().any(|&index| tests[index].location.is_some());
        let declared = entry.string("estado").unwrap_or("planejado");
        let state = match declared {
            "implementado" if tested => State::Works,
            "implementado" | "em desenvolvimento" => State::InDevelopment,
            "planejado" => State::Planned,
            "fora" => State::OutOfScope,
            other => {
                warnings.push(format!("{name}: estado desconhecido: {other}"));
                State::Planned
            }
        };
        if matches!(state, State::Works | State::InDevelopment) && paths.is_empty() {
            warnings.push(format!("{name}: estado {declared} sem caminhos no repositorio"));
        }
        let icon = entry
            .string("icone")
            .or_else(|| category_icons.string(&category))
            .unwrap_or("cube")
            .to_string();
        rows.push(ComponentRow {
            description: entry.string("descricao").unwrap_or_default().into(),
            phase: entry.string("fase").unwrap_or_default().into(),
            notes: entry.string("notas").unwrap_or_default().into(),
            state,
            paths,
            tests: test_indexes,
            name,
            category,
            icon,
        });
    }
    rows
}

/// Categorias na ordem da primeira aparição, com descrição e ícone do
/// `components.toml`.
fn category_rows(document: &toml::Document, components: &[ComponentRow], warnings: &mut Vec<String>) -> Vec<CategoryRow> {
    let icons = document.table("icones_categoria").cloned().unwrap_or_default();
    let descriptions = document.table("descricoes_categoria").cloned().unwrap_or_default();
    let mut rows: Vec<CategoryRow> = Vec::new();
    for component in components {
        if rows.iter().any(|row| row.name == component.category) {
            continue;
        }
        let description = descriptions.string(&component.category).unwrap_or_default().to_string();
        if description.is_empty() {
            warnings.push(format!("categoria sem texto em [descricoes_categoria]: {}", component.category));
        }
        rows.push(CategoryRow {
            name: component.category.clone(),
            description,
            icon: icons.string(&component.category).unwrap_or("cube").to_string(),
        });
    }
    rows
}

/// Apaga páginas geradas que esta geração não produziu mais (por exemplo, o
/// grupo de exports que ficou vazio), para não deixar links velhos.
fn remove_stale_pages(root: &Path, written: &BTreeSet<String>) -> Result<(), String> {
    let directory = root.join(SITE_DIR);
    let Ok(entries) = fs::read_dir(&directory) else { return Ok(()) };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let generated = name.starts_with("ntoskrnl-") && name.ends_with(".html");
        if generated && !written.contains(&name) {
            fs::remove_file(entry.path()).map_err(|error| format!("{}: {error}", entry.path().display()))?;
        }
    }
    Ok(())
}

fn write(root: &Path, relative: &str, text: &str) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    fs::write(&path, text).map_err(|error| format!("{}: {error}", path.display()))
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    let reference_path = parse_options(arguments)?;
    let root = crate::build::workspace_root();

    let document_text =
        fs::read_to_string(root.join(COMPONENTS)).map_err(|error| format!("{COMPONENTS}: {error}"))?;
    let document = toml::parse(&document_text).map_err(|error| format!("{COMPONENTS}: {error}"))?;
    let sources_table = document.table("fontes").cloned().unwrap_or_default();
    let mut rust_dirs = sources_table.strings("rust");
    if rust_dirs.is_empty() {
        rust_dirs.push("kernel/src".into());
    }
    let test_dirs = sources_table.strings("testes");

    let reference = sources::load_reference(&root, reference_path.as_deref())?;
    let plan = sources::load_plan(&root)?;
    let opennt = sources::opennt_exports();
    let index = RustIndex::build(&root, &rust_dirs)?;
    let test_refs = sources::test_references(&root, &test_dirs)?;
    let export_calls = sources::test_export_calls(&root, &test_dirs)?;

    let mut warnings = Vec::new();
    let subsystems = subsystem_rows(&document, &plan, &index, &root, &test_refs, &export_calls, &test_dirs, &mut warnings);
    let tests = test_rows(&document, &root, &rust_dirs, &mut warnings);
    let components = component_rows(&document, &root, &tests, &mut warnings);
    let categories = category_rows(&document, &components, &mut warnings);
    let phases = document
        .array("fase")
        .iter()
        .map(|entry| PhaseRow {
            number: entry.string("numero").unwrap_or_default().into(),
            name: entry.string("nome").unwrap_or_default().into(),
            state: entry.string("estado").unwrap_or_default().into(),
            scope: entry.string("escopo").unwrap_or_default().into(),
        })
        .collect();

    let report = Report {
        exports: export_report(&reference, &opennt),
        subsystems,
        components,
        categories,
        tests,
        phases,
        warnings,
    };

    let mut pages = BTreeSet::new();
    for (path, text) in render::render(&report) {
        let relative = if path.ends_with(".svg") {
            format!("{STATUS_DIR}/{path}")
        } else if path.ends_with(".md") {
            format!("docs/{path}")
        } else {
            pages.insert(path.clone());
            format!("{SITE_DIR}/{path}")
        };
        write(&root, &relative, &text)?;
    }
    remove_stale_pages(&root, &pages)?;
    for warning in &report.warnings {
        eprintln!("aviso: {warning}");
    }
    let total = &report.exports.total;
    let (done, partial, planned) = report.module_totals();
    println!(
        "OK: {SITE_DIR}/ ({} paginas), {STATUS_DIR}/ e docs/ROADMAP.md  (ntoskrnl {}: OpenNT exporta {}, faltam {}; \
         componentes: {} funcionam de {}; modulos com codigo: {} completos + {} parciais de {})",
        pages.len(),
        total.reference,
        total.opennt,
        total.missing(),
        report.count(State::Works),
        report.components.len(),
        done,
        partial,
        planned
    );
    Ok(())
}
