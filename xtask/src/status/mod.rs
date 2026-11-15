//! `cargo xtask status` — o site de status do OpenNT e o roadmap.
//!
//! Gera, a partir de dados verificáveis, cinco páginas autocontidas em
//! `docs/site/`:
//!
//! - `index.html` (Início): o que é o OpenNT, os números principais, o marco
//!   atual e o próximo;
//! - `o-que-roda.html`: cada binário real da Microsoft que o OpenNT exercita
//!   (e os marcos), com o estado, o que funciona, onde para, o teste que
//!   prova e a captura de tela do fim desse teste;
//! - `componentes.html`: as partes do kernel e o estado de cada uma;
//! - `ntoskrnl.html`: os exports do `ntoskrnl.exe` do Windows 10 22H2 que o
//!   kernel do OpenNT também exporta, por prefixo, com busca;
//! - `testes.html`: como validar (`cargo xtask test-all`) e cada teste.
//!
//! Também grava os selos e o gráfico de `docs/status/*.svg` (usados no
//! README) e o `docs/ROADMAP.md`.
//!
//! Entradas: `docs/status/components.toml` (editado à mão), a lista de
//! exports de referência (`docs/status/ntoskrnl-exports.def`), as tabelas
//! de exports do próprio kernel, as fontes Rust (onde cada marcador de teste
//! aparece) e as capturas em `docs/site/capturas/` (gravadas pelo `cargo
//! xtask capturas`, com a data e o resultado nos textos do PNG). A saída não
//! tem data/hora própria: duas gerações com os mesmos dados dão os mesmos
//! bytes.

mod pe;
mod render;
mod sources;
pub mod toml;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "uso: cargo xtask status [--reference=NTOSKRNL.EXE]
  --reference=ARQ  le os exports deste ntoskrnl.exe e atualiza docs/status/ntoskrnl-exports.def
                   (sem a opcao, usa o cache; sem cache, usa %SystemRoot%\\System32\\ntoskrnl.exe)
saida: docs/site/{index,o-que-roda,componentes,ntoskrnl,testes}.html, docs/status/*.svg e docs/ROADMAP.md
as capturas de tela (docs/site/capturas/<id>.png) vem do cargo xtask capturas";

const COMPONENTS: &str = "docs/status/components.toml";
const SITE_DIR: &str = "docs/site";
const STATUS_DIR: &str = "docs/status";
/// Pasta das capturas, relativa a `docs/site/` (como as páginas a citam).
pub const CAPTURES: &str = "capturas";

/// Categorias de `[[componente]]` que são binários do Windows: o estado de
/// cada binário fica na página O que roda.
pub const WINDOWS_CATEGORIES: &[&str] = &["Drivers do Windows", "Programas do Windows"];

/// Grupos de prefixo dos exports, na ordem da página.
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

// ---- modelo -------------------------------------------------------------------

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
    pub rows: Vec<ExportRow>,
    pub buckets: Vec<(&'static str, Tally)>,
    pub total: Tally,
    /// Nomes que o OpenNT exporta e o ntoskrnl de referência não.
    pub opennt_extra: Vec<String>,
}

/// A captura de tela do fim de um teste (`docs/site/capturas/<id>.png`).
pub struct Capture {
    /// Caminho relativo a `docs/site/`.
    pub file: String,
    pub width: u32,
    pub height: u32,
    pub date: String,
    /// "passou" ou "falhou: motivo", como o test-boot registrou.
    pub result: String,
    /// As linhas da serial que provam o teste (as das saídas esperadas e as
    /// últimas), como o test-boot registrou.
    pub serial: String,
}

impl Capture {
    pub fn passed(&self) -> bool {
        self.result == "passou"
    }
}

pub struct TestRow {
    pub id: String,
    pub title: String,
    pub marker: String,
    pub command: String,
    pub description: String,
    /// `espera_falha = true`: falha conhecida.
    pub expected_failure: bool,
    /// `coberto_pela_suite = true`: as suítes já conferem os marcadores.
    pub covered_by_suite: bool,
    /// Arquivo das fontes Rust em que o marcador aparece.
    pub location: Option<String>,
    pub capture: Option<Capture>,
}

/// Estado de um item da página O que roda.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RunState {
    Runs,
    Partial,
    DoesNotRun,
}

pub const RUN_STATES: &[RunState] = &[RunState::Runs, RunState::Partial, RunState::DoesNotRun];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Milestone,
    Driver,
    Program,
}

pub const GROUPS: &[Group] = &[Group::Milestone, Group::Driver, Group::Program];

/// Um item da página O que roda: um binário (ou um grupo pequeno de
/// binários que andam juntos) ou um marco.
pub struct RunRow {
    pub name: String,
    pub group: Group,
    /// Os binários citados no nome (vazio num marco).
    pub binaries: Vec<String>,
    /// Índices em `Report::tests`; o primeiro dá a captura.
    pub tests: Vec<usize>,
    pub state: RunState,
    /// De onde veio o estado, em palavras (vai para o título do selo).
    pub reason: String,
    pub does: String,
    pub stops: String,
}

/// Estado de um componente do kernel.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Implementado e coberto por um teste automático de boot.
    Works,
    /// Parte implementada, ou implementado sem teste automático.
    Partial,
    /// Previsto numa fase do roadmap.
    Planned,
    /// Fora do escopo atual.
    OutOfScope,
}

pub const STATES: &[State] = &[State::Works, State::Partial, State::Planned, State::OutOfScope];

pub struct ComponentRow {
    pub name: String,
    pub category: String,
    pub description: String,
    pub declared: String,
    pub state: State,
    pub paths: Vec<String>,
    /// Índices em `Report::tests`.
    pub tests: Vec<usize>,
    pub phase: String,
    pub notes: String,
}

pub struct CategoryRow {
    pub name: String,
    pub description: String,
}

pub struct PhaseRow {
    pub number: String,
    pub name: String,
    pub state: String,
    pub scope: String,
}

/// O marco atual e o próximo (`[marco]`).
pub struct Milestone {
    pub current: String,
    pub next: String,
    /// O teste que prova o marco atual.
    pub test: Option<usize>,
}

pub struct Report {
    pub exports: ExportReport,
    pub runs: Vec<RunRow>,
    pub components: Vec<ComponentRow>,
    pub categories: Vec<CategoryRow>,
    pub tests: Vec<TestRow>,
    pub phases: Vec<PhaseRow>,
    pub milestone: Milestone,
    /// Os marcadores que as suítes completas do test-all conferem.
    pub suite_markers: Vec<String>,
    pub warnings: Vec<String>,
}

impl Report {
    /// Um componente das categorias do Windows cujo binário tem item na
    /// página O que roda (o estado dele fica lá).
    pub fn listed_in_runs(&self, component: &ComponentRow) -> bool {
        let listed: BTreeSet<String> = self.runs.iter().flat_map(|row| row.binaries.iter().map(|binary| stem(binary))).collect();
        WINDOWS_CATEGORIES.contains(&component.category.as_str())
            && binary_names(&component.name).iter().any(|binary| listed.contains(&stem(binary)))
    }

    /// Binários (não marcos) por estado: um item com dois binários conta 2.
    pub fn binaries(&self, state: RunState) -> usize {
        self.runs.iter().filter(|row| row.group != Group::Milestone && row.state == state).map(|row| row.binaries.len()).sum()
    }

    pub fn binaries_total(&self) -> usize {
        self.runs.iter().filter(|row| row.group != Group::Milestone).map(|row| row.binaries.len()).sum()
    }
}

// ---- montagem -----------------------------------------------------------------

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
    let mut tallies: std::collections::BTreeMap<&'static str, Tally> = std::collections::BTreeMap::new();
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
    let mut opennt_extra: Vec<String> = opennt_exports.iter().filter(|name| !names.contains(name.as_str())).cloned().collect();
    opennt_extra.sort();
    ExportReport { file_version: reference.file_version.clone(), rows, buckets, total, opennt_extra }
}

fn flag(entry: &toml::Table, key: &str) -> bool {
    matches!(entry.get(key), Some(toml::Value::Bool(true)))
}

/// A captura de um teste, se o `cargo xtask capturas` já a gravou.
fn load_capture(root: &Path, id: &str, warnings: &mut Vec<String>) -> Option<Capture> {
    let file = format!("{CAPTURES}/{id}.png");
    let bytes = fs::read(root.join(SITE_DIR).join(&file)).ok()?;
    let Some(info) = crate::png::read_info(&bytes) else {
        warnings.push(format!("{SITE_DIR}/{file}: PNG ilegivel"));
        return None;
    };
    Some(Capture {
        width: info.width,
        height: info.height,
        date: info.text("opennt-data").unwrap_or_default().to_string(),
        result: info.text("opennt-resultado").unwrap_or_default().to_string(),
        serial: info.text("opennt-serial").unwrap_or_default().trim_end().to_string(),
        file,
    })
}

fn test_rows(document: &toml::Document, root: &Path, rust: &[(String, String)], warnings: &mut Vec<String>) -> Vec<TestRow> {
    let mut rows: Vec<TestRow> = Vec::new();
    for entry in document.array("teste") {
        let id = entry.string("id").unwrap_or_default().to_string();
        if rows.iter().any(|row| row.id == id) {
            warnings.push(format!("[[teste]] repetido: {id}"));
            continue;
        }
        let marker = entry.string("marcador").unwrap_or_default().to_string();
        let location = sources::find_marker(rust, &marker).map(String::from);
        if location.is_none() {
            warnings.push(format!("teste {id}: o marcador {marker} nao aparece nas fontes Rust"));
        }
        let capture = load_capture(root, &id, warnings);
        let expected_failure = flag(entry, "espera_falha");
        match &capture {
            None => warnings.push(format!("teste {id}: sem captura (cargo xtask capturas --only {id})")),
            Some(capture) if !capture.passed() && !expected_failure => {
                warnings.push(format!("teste {id}: a captura de {} registrou falha: {}", capture.date, capture.result))
            }
            _ => {}
        }
        rows.push(TestRow {
            title: entry.string("titulo").unwrap_or_default().into(),
            command: entry.string("comando").unwrap_or_default().into(),
            description: entry.string("descricao").unwrap_or_default().into(),
            expected_failure,
            covered_by_suite: flag(entry, "coberto_pela_suite"),
            location,
            capture,
            marker,
            id,
        });
    }
    rows
}

fn test_indexes(owner: &str, ids: &[String], tests: &[TestRow], warnings: &mut Vec<String>) -> Vec<usize> {
    let mut indexes = Vec::new();
    for id in ids {
        match tests.iter().position(|test| &test.id == id) {
            Some(index) => indexes.push(index),
            None => warnings.push(format!("{owner}: teste desconhecido: {id}")),
        }
    }
    indexes
}

fn component_rows(document: &toml::Document, root: &Path, tests: &[TestRow], warnings: &mut Vec<String>) -> Vec<ComponentRow> {
    let mut rows = Vec::new();
    for entry in document.array("componente") {
        let name = entry.string("nome").unwrap_or_default().to_string();
        let paths = entry.strings("caminhos");
        for path in &paths {
            if !root.join(path).exists() {
                warnings.push(format!("{name}: caminho inexistente: {path}"));
            }
        }
        let indexes = test_indexes(&name, &entry.strings("testes"), tests, warnings);
        let tested = indexes.iter().any(|&index| tests[index].location.is_some());
        let declared = entry.string("estado").unwrap_or("planejado").to_string();
        let state = match declared.as_str() {
            "implementado" if tested => State::Works,
            "implementado" | "em desenvolvimento" => State::Partial,
            "planejado" => State::Planned,
            "fora" => State::OutOfScope,
            other => {
                warnings.push(format!("{name}: estado desconhecido: {other}"));
                State::Planned
            }
        };
        rows.push(ComponentRow {
            category: entry.string("categoria").unwrap_or("Outros").into(),
            description: entry.string("descricao").unwrap_or_default().into(),
            phase: entry.string("fase").unwrap_or_default().into(),
            notes: entry.string("notas").unwrap_or_default().into(),
            tests: indexes,
            declared,
            state,
            paths,
            name,
        });
    }
    rows
}

/// Os nomes de binário de um texto (`ci.dll (Code Integrity)`, `ntdll.dll,
/// KERNEL32 e KERNELBASE`): as palavras com extensão .sys/.dll/.exe e as
/// palavras em caixa alta com dígito ou de seis letras ou mais.
pub fn binary_names(text: &str) -> Vec<String> {
    text.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_' || character == '.'))
        .map(|word| word.trim_matches('.'))
        .filter(|word| {
            let lower = word.to_ascii_lowercase();
            [".sys", ".dll", ".exe"].iter().any(|extension| lower.ends_with(extension))
                || (word.len() >= 6 && word.chars().all(|character| character.is_ascii_uppercase() || character.is_ascii_digit()))
        })
        .map(String::from)
        .collect()
}

fn stem(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower.rsplit_once('.').map_or(lower.clone(), |(stem, _)| stem.to_string())
}

/// Os itens da página O que roda, com o estado derivado dos testes e dos
/// componentes (ver o comentário de `[[roda]]` no `components.toml`).
fn run_rows(document: &toml::Document, tests: &[TestRow], components: &[ComponentRow], warnings: &mut Vec<String>) -> Vec<RunRow> {
    let mut rows = Vec::new();
    for entry in document.array("roda") {
        let name = entry.string("nome").unwrap_or_default().to_string();
        let group = match entry.string("grupo").unwrap_or_default() {
            "marco" => Group::Milestone,
            "driver" => Group::Driver,
            "programa" => Group::Program,
            other => {
                warnings.push(format!("roda {name}: grupo desconhecido: {other:?} (marco, driver ou programa)"));
                Group::Driver
            }
        };
        let binaries = if group == Group::Milestone { Vec::new() } else { binary_names(&name) };
        if group != Group::Milestone && binaries.is_empty() {
            warnings.push(format!("roda {name}: nenhum binario (.sys, .dll, .exe) no nome"));
        }
        let indexes = test_indexes(&format!("roda {name}"), &entry.strings("teste"), tests, warnings);
        let stems: Vec<String> = binaries.iter().map(|binary| stem(binary)).collect();
        // Os componentes de binários do Windows que citam um destes binários.
        let linked: Vec<&ComponentRow> = components
            .iter()
            .filter(|component| WINDOWS_CATEGORIES.contains(&component.category.as_str()))
            .filter(|component| binary_names(&component.name).iter().any(|binary| stems.contains(&stem(binary))))
            .collect();
        let (derived, reason) = if indexes.is_empty() {
            (RunState::DoesNotRun, "sem teste automático".to_string())
        } else if let Some(&index) = indexes.iter().find(|&&index| tests[index].expected_failure) {
            (RunState::Partial, format!("o teste {} é uma falha conhecida", tests[index].id))
        } else if let Some(component) = linked.iter().find(|component| component.declared != "implementado") {
            (RunState::Partial, format!("o componente {} está {}", component.name, component.declared))
        } else {
            (RunState::Runs, format!("o teste {} passa", tests[indexes[0]].id))
        };
        let (state, reason) = match entry.string("estado") {
            None => (derived, reason),
            Some(text) => {
                let state = match text {
                    "roda" => RunState::Runs,
                    "parcial" => RunState::Partial,
                    "nao roda" | "não roda" => RunState::DoesNotRun,
                    other => {
                        warnings.push(format!("roda {name}: estado desconhecido: {other}"));
                        derived
                    }
                };
                if state == derived {
                    warnings.push(format!("roda {name}: estado = {text:?} repete o que os dados ja dizem; tire o campo"));
                }
                (state, "declarado à mão no components.toml (os dados não bastam)".to_string())
            }
        };
        let stops = entry.string("para").unwrap_or_default().to_string();
        if state == RunState::Partial && stops.is_empty() {
            warnings.push(format!("roda {name}: parcial sem `para` (onde ele para)"));
        }
        rows.push(RunRow {
            does: entry.string("faz").unwrap_or_default().to_string(),
            tests: indexes,
            name,
            group,
            binaries,
            state,
            reason,
            stops,
        });
    }
    // Todo binário citado num componente do Windows que um teste exercita
    // aparece na página.
    let listed: BTreeSet<String> = rows.iter().flat_map(|row| row.binaries.iter().map(|binary| stem(binary))).collect();
    for component in components.iter().filter(|component| WINDOWS_CATEGORIES.contains(&component.category.as_str())) {
        for binary in binary_names(&component.name) {
            if !listed.contains(&stem(&binary)) && !component.tests.is_empty() {
                warnings.push(format!("{binary} (componente {}) sem [[roda]]", component.name));
            }
        }
    }
    rows
}

/// Categorias na ordem da primeira aparição.
fn category_rows(document: &toml::Document, components: &[ComponentRow]) -> Vec<CategoryRow> {
    let descriptions = document.table("descricoes_categoria").cloned().unwrap_or_default();
    let mut rows: Vec<CategoryRow> = Vec::new();
    for component in components {
        if !rows.iter().any(|row| row.name == component.category) {
            rows.push(CategoryRow {
                name: component.category.clone(),
                description: descriptions.string(&component.category).unwrap_or_default().to_string(),
            });
        }
    }
    rows
}

/// O marco do `[marco]`; sem ele, as fases em andamento e a próxima.
fn milestone(document: &toml::Document, phases: &[PhaseRow], tests: &[TestRow], warnings: &mut Vec<String>) -> Milestone {
    let table = document.table("marco").cloned().unwrap_or_default();
    let test = table.string("teste").and_then(|id| {
        let found = tests.iter().position(|test| test.id == id);
        if found.is_none() {
            warnings.push(format!("[marco]: teste desconhecido: {id}"));
        }
        found
    });
    let describe = |phase: &PhaseRow| format!("Fase {} — {}: {}", phase.number, phase.name, phase.scope);
    let current = table.string("atual").map(String::from).unwrap_or_else(|| {
        phases.iter().filter(|phase| phase.state == "em andamento").map(describe).collect::<Vec<_>>().join(" ")
    });
    let next = table.string("proximo").map(String::from).unwrap_or_else(|| {
        phases.iter().find(|phase| phase.state.starts_with("planejad")).map(describe).unwrap_or_default()
    });
    Milestone { current, next, test }
}

/// Apaga as páginas de `docs/site/` que esta geração não produziu (o
/// conjunto antigo), sem tocar nas capturas.
fn remove_stale_pages(root: &Path, written: &BTreeSet<String>) -> Result<Vec<String>, String> {
    let directory = root.join(SITE_DIR);
    let mut removed = Vec::new();
    let Ok(entries) = fs::read_dir(&directory) else { return Ok(removed) };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".html") && !written.contains(&name) {
            fs::remove_file(entry.path()).map_err(|error| format!("{}: {error}", entry.path().display()))?;
            removed.push(name);
        }
    }
    removed.sort();
    Ok(removed)
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
    let text = fs::read_to_string(root.join(COMPONENTS)).map_err(|error| format!("{COMPONENTS}: {error}"))?;
    let document = toml::parse(&text).map_err(|error| format!("{COMPONENTS}: {error}"))?;
    let mut rust_dirs = document.table("fontes").map(|table| table.strings("rust")).unwrap_or_default();
    if rust_dirs.is_empty() {
        rust_dirs.push("kernel/src".into());
    }
    let reference = sources::load_reference(&root, reference_path.as_deref())?;
    let rust = sources::rust_sources(&root, &rust_dirs)?;

    let mut warnings = Vec::new();
    let tests = test_rows(&document, &root, &rust, &mut warnings);
    let components = component_rows(&document, &root, &tests, &mut warnings);
    let categories = category_rows(&document, &components);
    let runs = run_rows(&document, &tests, &components, &mut warnings);
    let phases: Vec<PhaseRow> = document
        .array("fase")
        .iter()
        .map(|entry| PhaseRow {
            number: entry.string("numero").unwrap_or_default().into(),
            name: entry.string("nome").unwrap_or_default().into(),
            state: entry.string("estado").unwrap_or_default().into(),
            scope: entry.string("escopo").unwrap_or_default().into(),
        })
        .collect();
    let milestone = milestone(&document, &phases, &tests, &mut warnings);
    // O marcador da suíte (a primeira palavra) e as saídas esperadas dela.
    let suite_markers = crate::test_all::SUITE
        .iter()
        .enumerate()
        .filter_map(|(index, word)| if index == 0 { Some(*word) } else { word.strip_prefix("--expect=") })
        .map(String::from)
        .collect();

    let report = Report {
        exports: export_report(&reference, &sources::opennt_exports()),
        runs,
        components,
        categories,
        tests,
        phases,
        milestone,
        suite_markers,
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
    let removed = remove_stale_pages(&root, &pages)?;
    for warning in &report.warnings {
        eprintln!("aviso: {warning}");
    }
    if !removed.is_empty() {
        println!("paginas antigas apagadas: {}", removed.join(", "));
    }
    let total = &report.exports.total;
    let captures = report.tests.iter().filter(|test| test.capture.is_some()).count();
    println!(
        "OK: {SITE_DIR}/ ({} paginas), {STATUS_DIR}/*.svg e docs/ROADMAP.md  (binarios da Microsoft: {} rodam, {} parciais, \
         {} nao rodam; ntoskrnl {}: OpenNT exporta {}; testes: {}, {} com captura)",
        pages.len(),
        report.binaries(RunState::Runs),
        report.binaries(RunState::Partial),
        report.binaries(RunState::DoesNotRun),
        total.reference,
        total.opennt,
        report.tests.len(),
        captures
    );
    Ok(())
}
