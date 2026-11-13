//! Fontes de dados das páginas de status: o `ntoskrnl.exe` de referência, a
//! lista de módulos planejados e a árvore Rust do OpenNT.
//!
//! A lista de exports do Windows fica em cache em `docs/status/`, para que
//! as páginas possam ser regeneradas numa máquina sem o PE.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::pe::{self, Export};

// Os mesmos arquivos que o `kernel_pe` usa para gerar a EAT e a `.kdata`:
// os exports de função (ordem da ABI) e os de dados.
#[path = "../../../kernel/src/ntos/mm/kernel_data_layout.rs"]
#[allow(dead_code)]
mod kernel_data_layout;
#[path = "../../../kernel/src/ntos/init/export_names.rs"]
#[allow(dead_code)]
mod export_names;

pub const REFERENCE_CACHE: &str = "docs/status/ntoskrnl-exports.def";
pub const PLAN_FILE: &str = "docs/status/modulos-planejados.txt";

/// Prefixo de versão do ntoskrnl.exe do Windows 10 22H2 (build 19045).
const REFERENCE_VERSION_PREFIX: &str = "10.0.19041.";

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_text(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Caminho relativo com `/`, para mensagens e páginas.
pub fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/")
}

fn collect_files(directory: &Path, extension: &str, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_files(&path, extension, files)?;
        } else if path.extension().is_some_and(|value| value == extension) {
            files.push(path);
        }
    }
    Ok(())
}

// ---- referência: ntoskrnl.exe ---------------------------------------------

pub struct Reference {
    pub exports: Vec<Export>,
    pub file_version: Option<String>,
    pub unnamed: usize,
}

fn default_reference_path() -> PathBuf {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    Path::new(&system_root).join("System32").join("ntoskrnl.exe")
}

fn write_reference_cache(path: &Path, reference: &Reference) -> Result<(), String> {
    let data = reference.exports.iter().filter(|export| export.data).count();
    let mut text = String::new();
    text.push_str("; Exports nomeados do ntoskrnl.exe de referencia do OpenNT\n");
    text.push_str("; (Windows 10 22H2, build 19045).\n");
    text.push_str("; Gerado por `cargo xtask status --reference=<ntoskrnl.exe>`; nao editar a mao.\n");
    text.push_str("; So os nomes sao guardados aqui; o binario nunca entra no repositorio.\n");
    text.push_str(&format!(
        "; versao-do-arquivo: {}\n",
        reference.file_version.as_deref().unwrap_or("desconhecida")
    ));
    text.push_str(&format!("; exports-nomeados: {} ({} dados)\n", reference.exports.len(), data));
    text.push_str(&format!("; exports-sem-nome: {}\n", reference.unnamed));
    text.push_str("LIBRARY ntoskrnl.exe\nEXPORTS\n");
    for export in &reference.exports {
        text.push_str(&export.name);
        if export.data {
            text.push_str(" DATA");
        }
        text.push('\n');
    }
    write_text(path, &text)
}

fn read_reference_cache(path: &Path) -> Result<Reference, String> {
    let text = read_text(path)?;
    let mut reference = Reference { exports: Vec::new(), file_version: None, unnamed: 0 };
    for line in text.lines() {
        let line = line.trim();
        if let Some(comment) = line.strip_prefix(';') {
            let comment = comment.trim();
            if let Some(version) = comment.strip_prefix("versao-do-arquivo:") {
                let version = version.trim();
                if version != "desconhecida" {
                    reference.file_version = Some(version.to_string());
                }
            } else if let Some(count) = comment.strip_prefix("exports-sem-nome:") {
                reference.unnamed = count.trim().parse().unwrap_or(0);
            }
            continue;
        }
        if line.is_empty() || line.starts_with("LIBRARY") || line == "EXPORTS" {
            continue;
        }
        let mut words = line.split_whitespace();
        let name = words.next().unwrap_or_default().to_string();
        let data = words.next() == Some("DATA");
        reference.exports.push(Export { name, data });
    }
    if reference.exports.is_empty() {
        return Err(format!("{}: nenhum export na lista", path.display()));
    }
    reference.exports.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(reference)
}

/// Lê a lista de referência. Com `--reference`, lê o PE e reescreve o
/// cache; sem a opção, usa o cache e só cai no PE do sistema se o cache
/// ainda não existir.
pub fn load_reference(root: &Path, explicit: Option<&Path>) -> Result<Reference, String> {
    let cache = root.join(REFERENCE_CACHE);
    let source = match explicit {
        Some(path) => path.to_path_buf(),
        None if cache.exists() => return read_reference_cache(&cache),
        None => default_reference_path(),
    };
    let bytes = fs::read(&source).map_err(|error| {
        format!("{}: {error}\nsem lista de referencia: passe --reference=CAMINHO\\ntoskrnl.exe", source.display())
    })?;
    let parsed = pe::read_exports(&bytes).map_err(|error| format!("{}: {error}", source.display()))?;
    let reference = Reference { exports: parsed.exports, file_version: parsed.file_version, unnamed: parsed.unnamed };
    match &reference.file_version {
        Some(version) if version.starts_with(REFERENCE_VERSION_PREFIX) => {}
        other => eprintln!(
            "aviso: {} tem versao {}; a referencia do OpenNT e o ntoskrnl do Windows 10 22H2 ({}x, build 19045)",
            source.display(),
            other.as_deref().unwrap_or("desconhecida"),
            REFERENCE_VERSION_PREFIX
        ),
    }
    write_reference_cache(&cache, &reference)?;
    println!("referencia: {} exports nomeados de {} -> {}", reference.exports.len(), source.display(), REFERENCE_CACHE);
    Ok(reference)
}

// ---- roadmap: módulos planejados -------------------------------------------

/// Um módulo planejado (`ntos/ob/handle_table`): pasta e nome em snake_case.
#[derive(Clone, Debug)]
pub struct PlannedModule {
    pub path: String,
}

/// Lê `docs/status/modulos-planejados.txt`, editado à mão.
pub fn load_plan(root: &Path) -> Result<Vec<PlannedModule>, String> {
    let mut modules = Vec::new();
    for line in read_text(&root.join(PLAN_FILE))?.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        modules.push(PlannedModule { path: line.to_string() });
    }
    Ok(modules)
}

// ---- OpenNT -----------------------------------------------------------------

/// Exports do PE do kernel do OpenNT: os de função (`export_names`) e os de
/// dados (`kernel_data_layout`), sem repetição.
pub fn opennt_exports() -> Vec<String> {
    let mut names: Vec<String> = export_names::EXPORT_NAMES.iter().map(|name| name.to_string()).collect();
    for entry in kernel_data_layout::DEFINITIONS {
        if !names.iter().any(|name| name == entry.name) {
            names.push(entry.name.to_string());
        }
    }
    names
}

/// Índice dos arquivos `.rs` do OpenNT por (pasta-pai, nome do arquivo).
pub struct RustIndex {
    by_key: BTreeMap<(String, String), Vec<String>>,
    by_stem: BTreeMap<String, Vec<String>>,
    pub files: BTreeSet<String>,
}

impl RustIndex {
    pub fn build(root: &Path, directories: &[String]) -> Result<RustIndex, String> {
        let mut index = RustIndex { by_key: BTreeMap::new(), by_stem: BTreeMap::new(), files: BTreeSet::new() };
        for directory in directories {
            let path = root.join(directory);
            if !path.is_dir() {
                eprintln!("aviso: pasta de fontes Rust inexistente: {directory}");
                continue;
            }
            let mut files = Vec::new();
            collect_files(&path, "rs", &mut files)?;
            for file in files {
                let relative_path = relative(root, &file);
                let stem = file.file_stem().unwrap_or_default().to_string_lossy().into_owned();
                let parent = file
                    .parent()
                    .and_then(Path::file_name)
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                // Como no NT, um arquivo do componente reúne várias rotinas: cada
                // submódulo `pub mod <nome> {` responde como o módulo
                // `<componente>/<nome>`. Os exports moram no componente: cada
                // `ntos/<c>/exports.rs` responde pelo grupo `<c>` e pelos seus
                // submódulos da tabela do ntoskrnl.
                let text = fs::read_to_string(&file).unwrap_or_default();
                let inner: Vec<String> = text
                    .lines()
                    .filter_map(|line| line.strip_prefix("pub mod ").and_then(|rest| rest.strip_suffix(" {")))
                    .map(String::from)
                    .collect();
                if stem == "exports" {
                    index.by_key.entry((String::from("exports"), parent.clone())).or_default().push(relative_path.clone());
                    for name in &inner {
                        let name = name.trim_end_matches("_exports").to_string();
                        index.by_key.entry((String::from("exports"), name)).or_default().push(relative_path.clone());
                    }
                }
                for name in inner {
                    index.by_stem.entry(name.clone()).or_default().push(relative_path.clone());
                    index.by_key.entry((parent.clone(), name)).or_default().push(relative_path.clone());
                }
                index.by_stem.entry(stem.clone()).or_default().push(relative_path.clone());
                index.by_key.entry((parent, stem)).or_default().push(relative_path.clone());
                index.files.insert(relative_path);
            }
        }
        Ok(index)
    }

    /// Arquivo Rust de um módulo planejado (`ntos/ob/object_manager` ->
    /// `.../ob/object_manager.rs`): mesma pasta-pai e mesmo nome. Com vários
    /// candidatos, prefere o que também tem a pasta avó no caminho.
    pub fn find(&self, planned: &str) -> Option<&str> {
        let mut parts: Vec<&str> = planned.split('/').collect();
        let stem = parts.pop()?.to_string();
        let parent = parts.pop()?;
        let grandparent = parts.pop();
        // Os arquivos de núcleo da antiga tabela (lifecycle, irp_builder...)
        // mudaram de pasta: acha pelo nome.
        let candidates = match self.by_key.get(&(parent.to_string(), stem.clone())) {
            Some(found) => found,
            None if parent == "exports" => self.by_stem.get(&stem)?,
            None => return None,
        };
        let preferred = grandparent.and_then(|name| {
            candidates.iter().find(|candidate| candidate.split('/').any(|component| component == name))
        });
        preferred.or_else(|| candidates.first()).map(String::as_str)
    }

    /// Suíte de teste planejada (`ntos/test/handle_table`) -> arquivo de mesmo
    /// nome dentro de uma das pastas de testes, qualquer que seja o nome da
    /// pasta.
    pub fn find_test(&self, planned: &str, test_directories: &[String]) -> Option<&str> {
        let wanted = format!("{}.rs", planned.rsplit('/').next()?);
        self.files
            .iter()
            .find(|path| {
                test_directories.iter().any(|directory| path.starts_with(&format!("{directory}/")))
                    && path.rsplit('/').next() == Some(wanted.as_str())
            })
            .map(String::as_str)
    }
}

/// Exports chamados pelo nome nos autotestes (`call_export("Nome", ...)`): é
/// assim que a fase 6 exercita um grupo de exports.
pub fn test_export_calls(root: &Path, directories: &[String]) -> Result<BTreeSet<String>, String> {
    const CALL: &str = "call_export(\"";
    let mut names = BTreeSet::new();
    for directory in directories {
        let path = root.join(directory);
        if !path.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        collect_files(&path, "rs", &mut files)?;
        for file in files {
            let text = read_text(&file)?;
            let mut rest = text.as_str();
            while let Some(position) = rest.find(CALL) {
                let tail = &rest[position + CALL.len()..];
                let end = tail.find('"').unwrap_or(tail.len());
                names.insert(tail[..end].to_string());
                rest = &tail[end..];
            }
        }
    }
    Ok(names)
}

/// Saldo de chaves de uma linha de Rust, sem contar strings, caracteres e
/// comentários de linha.
fn brace_balance(line: &str) -> i32 {
    let characters: Vec<char> = line.chars().collect();
    let (mut balance, mut index, mut in_string) = (0, 0, false);
    while index < characters.len() {
        let character = characters[index];
        if in_string {
            match character {
                '\\' => index += 1,
                '"' => in_string = false,
                _ => {}
            }
        } else {
            match character {
                '"' => in_string = true,
                '/' if characters.get(index + 1) == Some(&'/') => break,
                '\'' if characters.get(index + 2) == Some(&'\'') => index += 2,
                '{' => balance += 1,
                '}' => balance -= 1,
                _ => {}
            }
        }
        index += 1;
    }
    balance
}

/// Strings citadas nas listas `names: &[...]` e `data_exports: &[...]` de um
/// trecho de código.
fn declared_export_names(code: &str, output: &mut Vec<String>) {
    for marker in ["names: &[", "data_exports: &["] {
        let mut rest = code;
        while let Some(position) = rest.find(marker) {
            let tail = &rest[position + marker.len()..];
            let end = tail.find(']').unwrap_or(tail.len());
            let mut list = &tail[..end];
            while let Some(open) = list.find('"') {
                let after = &list[open + 1..];
                let close = after.find('"').unwrap_or(after.len());
                output.push(after[..close].to_string());
                list = after.get(close + 1..).unwrap_or("");
            }
            rest = &tail[end..];
        }
    }
}

/// Nomes de export (funções e dados) que um grupo declara num `exports.rs`:
/// os do submódulo `pub mod <grupo> {` (ou `<grupo>_exports`) ou, quando o
/// grupo é o próprio componente, os das `Group` fora dos submódulos. `None`
/// quando o módulo planejado corresponde ao arquivo inteiro (sem submódulo
/// com o nome dele), como a tabela em `ntos/init/exports.rs`.
pub fn group_export_names(root: &Path, rust_path: &str, group: &str) -> Option<Vec<String>> {
    let text = fs::read_to_string(root.join(rust_path)).ok()?;
    let component = rust_path.rsplit('/').nth(1).unwrap_or("");
    let mut blocks: BTreeMap<String, String> = BTreeMap::new();
    let mut outside = String::new();
    let mut current: Option<(String, i32, String)> = None;
    for line in text.lines() {
        if let Some((name, depth, body)) = current.as_mut() {
            *depth += brace_balance(line);
            body.push_str(line);
            body.push('\n');
            if *depth <= 0 {
                blocks.insert(name.clone(), std::mem::take(body));
                current = None;
            }
            continue;
        }
        match line.strip_prefix("pub mod ").and_then(|rest| rest.strip_suffix(" {")) {
            Some(name) => current = Some((name.to_string(), 1, String::new())),
            None => {
                outside.push_str(line);
                outside.push('\n');
            }
        }
    }
    let body = match blocks.get(group).or_else(|| blocks.get(&format!("{group}_exports"))) {
        Some(body) => body.as_str(),
        None if group == component => outside.as_str(),
        None => return None,
    };
    let mut names = Vec::new();
    declared_export_names(body, &mut names);
    Some(names)
}

/// Caminhos de módulo citados pelas suítes de teste (`use crate::a::{b, c}`
/// e `crate::a::b` no código), expandidos em segmentos.
pub fn test_references(root: &Path, directories: &[String]) -> Result<Vec<Vec<String>>, String> {
    let mut paths = Vec::new();
    for directory in directories {
        let path = root.join(directory);
        if !path.is_dir() {
            eprintln!("aviso: pasta de testes inexistente: {directory}");
            continue;
        }
        let mut files = Vec::new();
        collect_files(&path, "rs", &mut files)?;
        for file in files {
            let text = read_text(&file)?;
            let code: String = text.lines().map(|line| line.split("//").next().unwrap_or("")).collect::<Vec<_>>().join("\n");
            let mut rest = code.as_str();
            while let Some(position) = rest.find("crate::") {
                let tail = &rest[position + 7..];
                let mut end = 0;
                let mut depth = 0;
                for (index, character) in tail.char_indices() {
                    match character {
                        '{' => depth += 1,
                        '}' if depth > 0 => depth -= 1,
                        _ if depth > 0 => {}
                        c if c.is_ascii_alphanumeric() || c == '_' || c == ':' => {}
                        _ => {
                            end = index;
                            break;
                        }
                    }
                    end = index + character.len_utf8();
                }
                expand_use(&tail[..end], &mut paths);
                rest = &tail[end..];
            }
        }
    }
    Ok(paths)
}

fn expand_use(path: &str, output: &mut Vec<Vec<String>>) {
    let path = path.split_whitespace().collect::<String>();
    if let Some(open) = path.find('{') {
        let prefix = path[..open].trim_end_matches(':');
        let inner = path[open + 1..].strip_suffix('}').unwrap_or(&path[open + 1..]);
        let mut depth = 0;
        let mut start = 0;
        let mut items = Vec::new();
        for (index, character) in inner.char_indices() {
            match character {
                '{' => depth += 1,
                '}' => depth -= 1,
                ',' if depth == 0 => {
                    items.push(&inner[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
        items.push(&inner[start..]);
        for item in items.into_iter().filter(|item| !item.is_empty()) {
            let joined = if prefix.is_empty() { item.to_string() } else { format!("{prefix}::{item}") };
            expand_use(&joined, output);
        }
        return;
    }
    let segments: Vec<String> =
        path.split("::").filter(|segment| !segment.is_empty() && *segment != "self").map(String::from).collect();
    if !segments.is_empty() {
        output.push(segments);
    }
}

/// O marcador aparece no texto como palavra inteira: `SELFTEST_OK` não casa
/// dentro de `PHASE3_SELFTEST_OK`.
fn contains_marker(text: &str, marker: &str) -> bool {
    let word = |character: Option<char>| character.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_');
    let starts_word = marker.chars().next().is_some_and(|character| word(Some(character)));
    let ends_word = marker.chars().last().is_some_and(|character| word(Some(character)));
    text.match_indices(marker).any(|(position, _)| {
        let before = text[..position].chars().next_back();
        let after = text[position + marker.len()..].chars().next();
        !(starts_word && word(before)) && !(ends_word && word(after))
    })
}

/// Procura um marcador de boot nas fontes Rust (como palavra inteira).
pub fn find_marker(root: &Path, directories: &[String], marker: &str) -> Result<Option<String>, String> {
    if marker.is_empty() {
        return Ok(None);
    }
    for directory in directories {
        let path = root.join(directory);
        if !path.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        collect_files(&path, "rs", &mut files)?;
        for file in files {
            if contains_marker(&read_text(&file)?, marker) {
                return Ok(Some(relative(root, &file)));
            }
        }
    }
    Ok(None)
}
