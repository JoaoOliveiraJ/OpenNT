//! `cargo xtask nt-types` — gera as estruturas do NT de `kernel/src/ntos/inc/types`
//! a partir dos símbolos do ntoskrnl.
//!
//! Entradas: o PDB do ntoskrnl (`build/symbols/ntkrnlmp.pdb`; ausente, é
//! baixado do servidor público de símbolos pelo GUID/idade registrados) e a
//! lista versionada `kernel/src/ntos/inc/types/nt_types.toml` (raízes,
//! famílias e provas de `nt_abi.rs`). Saídas: um arquivo por família
//! (`ke.rs`, `io.rs`...), o `mod.rs` e o bloco de provas no fim de
//! `nt_abi.rs`. Os demais `.rs` do diretório são mantidos à mão (`wdk.rs` e
//! os `extra_*.rs`, com o que os símbolos não têm) e só entram no `mod.rs`.
//!
//! `--check` não escreve nada: regenera em memória e falha se algum arquivo
//! gerado estiver diferente do que está no disco (fim de linha à parte).

mod emit;
mod layout;
mod pdb;
mod proofs;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::status::toml;
use layout::{Generator, Kind};

const CONFIG: &str = "kernel/src/ntos/inc/types/nt_types.toml";

pub const USAGE: &str = "uso: cargo xtask nt-types [--check] [--pdb=ARQ]
  gera kernel/src/ntos/inc/types/*.rs (menos os mantidos a mao) e as provas no fim de nt_abi.rs
  a partir dos simbolos do ntoskrnl; tipos pedidos em kernel/src/ntos/inc/types/nt_types.toml
  --check    nao escreve; falha se algum arquivo gerado estiver desatualizado
  --pdb=ARQ  usa este PDB (padrao: build/symbols/ntkrnlmp.pdb; ausente, baixado do servidor
             publico de simbolos pelo GUID/idade do nt_types.toml)";

const HEADER_MOD: &str = "//! Estruturas do NT — layouts do Windows 10 19041 gerados a partir dos
//! símbolos do ntoskrnl (`build/symbols/ntkrnlmp.pdb`).
//!
//! Gerado; não editar à mão. Os tipos pedidos (raízes, famílias e as provas
//! de `nt_abi.rs`) ficam em `nt_types.toml`, neste diretório. Para
//! regenerar, a partir da raiz do repositório:
//!
//! ```text
//! cargo xtask nt-types           # reescreve os arquivos gerados
//! cargo xtask nt-types --check   # falha se algum estiver desatualizado
//! ```
//!
//! O gerador reescreve este diretório, menos os arquivos mantidos à mão
//! (`wdk.rs` e os `extra_*.rs`: estruturas públicas do WDK/SDK e privadas
//! que não constam dos símbolos, cada uma citando a origem), e o bloco de
//! provas no fim de `nt_abi.rs`. Cada struct é `#[repr(C)]` com o tamanho e
//! os offsets exatos do kernel
//! real — conferidos em compilação por `size_of`/`offset_of!` — e folhas
//! escalares `Field<T>` (uma célula volátil por campo; ponteiros são
//! `Field<u64>`, com o tipo apontado no comentário). Membros que o C
//! sobrepõe (uniões e structs anônimas) ficam em vistas `<Tipo>ViewN`
//! encadeadas por `Deref`, então todo nome do NT é acessado direto:
//! `irp.io_status.status`, `thread.state`, `header.type_`. Bitfields são o
//! inteiro de armazenamento mais `<NOME>_SHIFT`/`<NOME>_MASK` e os métodos
//! `<nome>()`/`set_<nome>()`. Enums são newtypes inteiros com as constantes
//! do NT. Membros `...Fill` que só posicionam outros campos são omitidos.
//!
//! `dead_code` fica liberado aqui como em `nt_abi.rs`: é um cabeçalho — a
//! maior parte dos layouts só passa a ser usada conforme o código migra.
#![allow(dead_code)]

pub use crate::ntos::inc::field::{Field, NtStruct, Reserved, UnalignedField};
use crate::ntos::mm::guest_memory::GuestScalar;

";

/// Uma família (um arquivo de `types/`): nomes explícitos e prefixos.
pub struct Family {
    pub name: String,
    pub doc: String,
    /// Nomes do NT (sem `_` inicial) desta família, conferidos antes de todos os prefixos.
    pub names: Vec<String>,
    /// Prefixos, na ordem das famílias; `NOME$` exige o nome inteiro.
    pub prefixes: Vec<String>,
}

/// Onde uma constante de `nt_abi.rs` é conferida.
pub enum Target {
    /// Caminho de membros (`Tail.Overlay.Thread`) na struct indicada ou na padrão.
    Path(Option<String>, String),
    /// Tamanho da struct indicada ou da padrão.
    SizeOf(Option<String>),
    /// Campo de uma struct mantida à mão (`wdk.rs`), com o valor esperado.
    Rust { rust_type: String, field: String, value: i128 },
}

pub struct Proof {
    pub module: String,
    pub structure: String,
    pub fields: Vec<(String, Target)>,
}

pub struct Config {
    pdb_file: String,
    pdb_name: String,
    pdb_guid: String,
    pdb_age: u32,
    symbol_server: String,
    output: String,
    nt_abi: String,
    glob: Vec<String>,
    roots: Vec<String>,
    families: Vec<Family>,
    proofs: Vec<Proof>,
}

impl Config {
    /// Família de um tipo do NT pelo nome.
    pub fn family_of(&self, nt_name: &str) -> String {
        let name = nt_name.trim_start_matches('_').to_uppercase();
        for family in &self.families {
            if family.names.iter().any(|explicit| *explicit == name) {
                return family.name.clone();
            }
        }
        for family in &self.families {
            for prefix in &family.prefixes {
                let matches = match prefix.strip_suffix('$') {
                    Some(exact) => name == exact,
                    None => name.starts_with(prefix.as_str()),
                };
                if matches {
                    return family.name.clone();
                }
            }
        }
        "misc".into()
    }

    fn load(path: &Path) -> Result<Config, String> {
        let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let document = toml::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        let pdb = document.table("pdb").ok_or("nt_types.toml: falta [pdb]")?;
        let output = document.table("saida").ok_or("nt_types.toml: falta [saida]")?;
        let required = |table: &toml::Table, key: &str| -> Result<String, String> {
            table.string(key).map(str::to_string).ok_or_else(|| format!("nt_types.toml: falta {key}"))
        };
        let pdb_age = match pdb.get("idade") {
            Some(toml::Value::Integer(age)) => *age as u32,
            _ => return Err("nt_types.toml: falta [pdb] idade".into()),
        };
        let mut families = Vec::new();
        for table in document.array("familia") {
            families.push(Family {
                name: required(table, "nome")?,
                doc: required(table, "doc")?,
                names: table.strings("nomes"),
                prefixes: table.strings("prefixos"),
            });
        }
        let mut proofs = Vec::new();
        for table in document.array("prova") {
            let module = required(table, "modulo")?;
            let mut fields = Vec::new();
            for entry in table.strings("campos") {
                let (constant, target) =
                    entry.split_once('=').ok_or_else(|| format!("nt_types.toml: prova {module}: {entry}"))?;
                fields.push((constant.trim().to_string(), parse_target(target.trim())?));
            }
            proofs.push(Proof { module, structure: required(table, "estrutura")?, fields });
        }
        Ok(Config {
            pdb_file: required(pdb, "arquivo")?,
            pdb_name: required(pdb, "nome")?,
            pdb_guid: required(pdb, "guid")?,
            pdb_age,
            symbol_server: required(pdb, "servidor")?,
            output: required(output, "diretorio")?,
            nt_abi: required(output, "nt_abi")?,
            glob: output.strings("reexportados"),
            roots: document.root.strings("raizes"),
            families,
            proofs,
        })
    }
}

/// `Campo.Sub`, `_TIPO:Campo`, `sizeof`, `sizeof(_TIPO)` ou `rust Tipo.campo 0xN`.
fn parse_target(text: &str) -> Result<Target, String> {
    if text == "sizeof" {
        return Ok(Target::SizeOf(None));
    }
    if let Some(inner) = text.strip_prefix("sizeof(").and_then(|rest| rest.strip_suffix(')')) {
        return Ok(Target::SizeOf(Some(inner.to_string())));
    }
    if let Some(rest) = text.strip_prefix("rust ") {
        let mut words = rest.split_whitespace();
        let (path, value) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        let (rust_type, field) = path.split_once('.').ok_or_else(|| format!("nt_types.toml: alvo invalido: {text}"))?;
        let value = i128::from_str_radix(value.trim_start_matches("0x"), 16)
            .map_err(|_| format!("nt_types.toml: valor invalido: {text}"))?;
        return Ok(Target::Rust { rust_type: rust_type.into(), field: field.into(), value });
    }
    Ok(match text.split_once(':') {
        Some((structure, path)) => Target::Path(Some(structure.to_string()), path.to_string()),
        None => Target::Path(None, text.to_string()),
    })
}

struct Options {
    check: bool,
    pdb: Option<PathBuf>,
}

fn parse_options(arguments: &[String]) -> Result<Options, String> {
    let mut options = Options { check: false, pdb: None };
    for argument in arguments {
        match argument.split_once('=') {
            Some(("--pdb", path)) => options.pdb = Some(PathBuf::from(path)),
            _ if argument == "--check" => options.check = true,
            _ if argument == "--help" || argument == "-h" => return Err(USAGE.to_string()),
            _ => return Err(format!("opcao desconhecida: {argument}\n{USAGE}")),
        }
    }
    Ok(options)
}

/// Baixa o PDB do servidor público de símbolos (`<nome>/<GUID><idade>/<nome>`).
fn download(config: &Config, destination: &Path) -> Result<(), String> {
    let url = format!(
        "{}/{name}/{}{:X}/{name}",
        config.symbol_server.trim_end_matches('/'),
        config.pdb_guid,
        config.pdb_age,
        name = config.pdb_name
    );
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let partial = destination.with_extension("pdb.part");
    eprintln!("baixando {url}");
    let status = Command::new("curl")
        .args(["--fail", "--location", "--silent", "--show-error", "--user-agent", "symbol-client/1.0", "--output"])
        .arg(&partial)
        .arg(&url)
        .status()
        .map_err(|error| format!("curl: {error} (instale o curl ou passe --pdb=ARQ)"))?;
    if !status.success() {
        let _ = fs::remove_file(&partial);
        return Err(format!("download do PDB falhou ({status}): {url}"));
    }
    fs::rename(&partial, destination).map_err(|error| format!("{}: {error}", destination.display()))
}

/// Avisa (sem falhar) quando o ntoskrnl.exe desta máquina cita outro PDB.
fn note_host_kernel(config: &Config) {
    let Some(system_root) = std::env::var_os("SystemRoot") else { return };
    let path = Path::new(&system_root).join("System32").join("ntoskrnl.exe");
    let Ok(bytes) = fs::read(&path) else { return };
    if let Ok((guid, age, _)) = pdb::PeFile::parse(&bytes).and_then(|pe| pe.rsds()) {
        if pdb::guid_text(&guid) != config.pdb_guid || age != config.pdb_age {
            eprintln!(
                "aviso: {} cita o PDB {}{age:X}; os tipos seguem o {}{:X} do nt_types.toml",
                path.display(),
                pdb::guid_text(&guid),
                config.pdb_guid,
                config.pdb_age
            );
        }
    }
}

/// Texto de cada arquivo gerado (caminho relativo à raiz) e os gerados que sobram.
struct Generated {
    files: BTreeMap<PathBuf, String>,
    stale: Vec<PathBuf>,
    summary: Vec<String>,
}

fn generate(root: &Path, config: &Config, generator: &Generator) -> Result<Generated, String> {
    let directory = PathBuf::from(&config.output);
    // Caminhos com `/` (os do nt_types.toml), também no Windows.
    let output = |name: &str| PathBuf::from(format!("{}/{name}", config.output.trim_end_matches('/')));
    let mut families: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut enums = 0;
    for key in generator.reachable(&config.roots) {
        let typedef = &generator.types[&key];
        let lines = families.entry(typedef.family.clone()).or_default();
        emit::emit(typedef, lines)?;
        *counts.entry(typedef.family.clone()).or_default() += 1;
        if typedef.kind == Kind::Enum {
            enums += 1;
        }
    }

    // Os `.rs` que não são de família nem o mod.rs são mantidos à mão.
    let family_names: BTreeSet<&str> = config.families.iter().map(|family| family.name.as_str()).collect();
    let mut hand_written: Vec<String> = Vec::new();
    let mut stale = Vec::new();
    let listing = fs::read_dir(root.join(&directory)).map_err(|error| format!("{}: {error}", directory.display()))?;
    for entry in listing {
        let entry = entry.map_err(|error| error.to_string())?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = file_name.strip_suffix(".rs") else { continue };
        if stem == "mod" {
            continue;
        }
        if family_names.contains(stem) {
            if !families.contains_key(stem) {
                stale.push(output(&file_name));
            }
        } else {
            hand_written.push(stem.to_string());
        }
    }
    hand_written.sort();

    let mut files = BTreeMap::new();
    for (family, lines) in &families {
        let doc = &config
            .families
            .iter()
            .find(|candidate| candidate.name == *family)
            .ok_or_else(|| format!("familia sem descricao no nt_types.toml: {family}"))?
            .doc;
        let mut out = vec![
            format!("//! {doc}"),
            "//!".into(),
            "//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.".into(),
            String::new(),
            "use super::*;".into(),
            String::new(),
        ];
        out.extend(lines.iter().cloned());
        while out.last().is_some_and(String::is_empty) {
            out.pop();
        }
        out.push(String::new());
        files.insert(output(&format!("{family}.rs")), out.join("\n"));
    }

    let globbed: BTreeSet<String> = families
        .keys()
        .cloned()
        .chain(hand_written.iter().filter(|name| config.glob.contains(name)).cloned())
        .collect();
    let mut module = String::from(HEADER_MOD);
    for name in &globbed {
        module.push_str(&format!("mod {name};\n"));
    }
    module.push('\n');
    for name in &globbed {
        module.push_str(&format!("pub use {name}::*;\n"));
    }
    let separate: Vec<&String> = hand_written.iter().filter(|name| !config.glob.contains(name)).collect();
    if !separate.is_empty() {
        module.push_str("\n// Mantidos à mão: estruturas que os símbolos não têm (cada arquivo diz a origem).\n");
        for name in separate {
            module.push_str(&format!("pub mod {name};\n"));
        }
    }
    files.insert(output("mod.rs"), module);

    let nt_abi_path = PathBuf::from(&config.nt_abi);
    let original = fs::read_to_string(root.join(&nt_abi_path)).map_err(|error| format!("{}: {error}", nt_abi_path.display()))?;
    let outcome = proofs::rewrite(generator, &config.proofs, &original)?;
    files.insert(nt_abi_path, outcome.text);

    let total: usize = counts.values().sum();
    let mut summary = vec![
        format!("tipos: {total} ({} structs/unioes, {enums} enums)", total - enums),
        format!(
            "familias: {}",
            counts.iter().map(|(family, count)| format!("{family}={count}")).collect::<Vec<_>>().join(", ")
        ),
        format!("provas de nt_abi: {} assercoes", outcome.asserts),
    ];
    for (module, constant, value, label, pdb_value) in &outcome.mismatches {
        summary.push(format!("DIVERGE {module}::{constant} = {value:#x}; simbolos {label} = {pdb_value:#x}"));
    }
    for item in &outcome.unmapped {
        summary.push(format!("sem campo: {item}"));
    }
    Ok(Generated { files, stale, summary })
}

/// Lê o PDB, confere que é o do nt_types.toml (GUID e idade) e decodifica o TPI.
fn open_pdb(config: &Config, path: &Path) -> Result<pdb::Tpi, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let msf = pdb::Msf::parse(bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    let (guid, age) = msf.identity()?;
    if pdb::guid_text(&guid) != config.pdb_guid || age != config.pdb_age {
        return Err(format!(
            "{}: PDB {}{age:X}, mas o nt_types.toml pede {}{:X}",
            path.display(),
            pdb::guid_text(&guid),
            config.pdb_guid,
            config.pdb_age
        ));
    }
    pdb::Tpi::parse(&msf.stream(2)?)
}

/// Arquivos gerados diferentes do disco (fim de linha à parte: o checkout
/// pode converter para CRLF), com o texto atual de cada um.
fn outdated(root: &Path, generated: &Generated) -> Vec<(PathBuf, Option<String>)> {
    let mut outdated = Vec::new();
    for (path, text) in &generated.files {
        let current = fs::read_to_string(root.join(path)).ok();
        if current.as_deref().map(|current| current.replace("\r\n", "\n")).as_ref() != Some(text) {
            outdated.push((path.clone(), current));
        }
    }
    outdated
}

impl Generated {
    /// O que o `--check` reprova: arquivos desatualizados e gerados que sobram.
    fn problems(&self, outdated: &[(PathBuf, Option<String>)]) -> Vec<String> {
        let mut problems: Vec<String> =
            outdated.iter().map(|(path, _)| format!("desatualizado: {}", path.display())).collect();
        problems.extend(self.stale.iter().map(|path| format!("sobrando: {}", path.display())));
        problems
    }
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments)?;
    let root = crate::build::workspace_root();
    let config = Config::load(&root.join(CONFIG))?;

    let pdb_path = match &options.pdb {
        Some(path) => path.clone(),
        None => {
            let path = root.join(&config.pdb_file);
            if !path.exists() {
                download(&config, &path)?;
            }
            path
        }
    };
    let tpi = open_pdb(&config, &pdb_path)?;
    note_host_kernel(&config);
    let mut generator = Generator::new(&tpi, &config);
    generator.close(&config.roots)?;
    let generated = generate(&root, &config, &generator)?;

    let outdated = outdated(&root, &generated);
    if options.check {
        let problems = generated.problems(&outdated);
        if problems.is_empty() {
            println!("nt-types: {} arquivos conferem com os simbolos", generated.files.len());
            return Ok(());
        }
        return Err(format!("{}\nrode `cargo xtask nt-types` para regenerar", problems.join("\n")));
    }
    for (path, current) in outdated {
        let text = &generated.files[&path];
        // Mantém o fim de linha do arquivo existente.
        let text = if current.is_some_and(|current| current.contains("\r\n")) { text.replace('\n', "\r\n") } else { text.clone() };
        fs::write(root.join(&path), text).map_err(|error| format!("{}: {error}", path.display()))?;
        println!("escrito: {}", path.display());
    }
    for path in &generated.stale {
        fs::remove_file(root.join(path)).map_err(|error| format!("{}: {error}", path.display()))?;
        println!("removido: {}", path.display());
    }
    for line in &generated.summary {
        println!("{line}");
    }
    Ok(())
}
