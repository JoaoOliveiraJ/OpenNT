//! Fontes de dados das páginas de status: o `ntoskrnl.exe` de referência, os
//! exports do kernel do OpenNT e os marcadores de boot nas fontes Rust.
//!
//! A lista de exports do Windows fica em cache em `docs/status/`, para que
//! as páginas possam ser regeneradas numa máquina sem o PE.

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
fn relative(root: &Path, path: &Path) -> String {
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

/// As fontes Rust das pastas dadas, lidas uma vez: (caminho relativo, texto).
pub fn rust_sources(root: &Path, directories: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut sources = Vec::new();
    for directory in directories {
        let path = root.join(directory);
        if !path.is_dir() {
            eprintln!("aviso: pasta de fontes Rust inexistente: {directory}");
            continue;
        }
        let mut files = Vec::new();
        collect_files(&path, "rs", &mut files)?;
        for file in files {
            sources.push((relative(root, &file), read_text(&file)?));
        }
    }
    Ok(sources)
}

/// O arquivo das fontes em que o marcador de boot aparece (como palavra
/// inteira).
pub fn find_marker<'a>(sources: &'a [(String, String)], marker: &str) -> Option<&'a str> {
    if marker.is_empty() {
        return None;
    }
    sources.iter().find(|(_, text)| contains_marker(text, marker)).map(|(path, _)| path.as_str())
}
