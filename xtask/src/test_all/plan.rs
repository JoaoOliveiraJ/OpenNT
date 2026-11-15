//! A lista de testes do `test-all`: as duas suítes completas e os
//! `[[teste]]` de `docs/status/components.toml`, cada um com os argumentos
//! do `test-boot` que o `comando` dele dá.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::status::toml;

const COMPONENTS: &str = "docs/status/components.toml";

/// A suíte completa de autoteste, rodada com 4 CPUs e com 1 (`--smp`).
const SUITE: &[&str] = &[
    "PHASE3_SELFTEST_OK",
    "900000",
    "--kernel-test-scope=all",
    "--expect=PHASE4_SELFTEST_OK",
    "--expect=PHASE5_SELFTEST_OK",
    "--expect=PHASE6_SELFTEST_OK",
    "--expect=MULTIPROCESS_OK",
    "--expect=PHASE7_SELFTEST_OK",
    "--expect=KBDTEST_OK",
    "--expect=SELFTEST_OK",
];
const SUITE_CPUS: &[u32] = &[4, 1];

/// Folga sobre o prazo e o `--hold` do test-boot antes de dar o processo
/// como travado.
const GRACE: Duration = Duration::from_secs(120);
/// O que o QEMU compromete além da memória do convidado (medido: uns 5 GB
/// de memória privada com `-m 4096`).
const QEMU_OVERHEAD: u64 = 1 << 30;

pub struct Test {
    pub id: String,
    /// Argumentos do `test-boot`, sem `--build-dir` (o test-all escolhe).
    pub arguments: Vec<String>,
    /// Uma das suítes completas (fora do `components.toml`).
    pub suite: bool,
    /// `espera_falha = true`: falha conhecida, contada à parte.
    pub expected_failure: bool,
    /// `coberto_pela_suite = true`: os marcadores dele as suítes já
    /// conferem; só roda quando pedido por `--only`.
    pub covered_by_suite: bool,
    /// As opções de build que o kernel e o volume embutem: execuções com a
    /// mesma chave reaproveitam o kernel compilado.
    pub build_key: String,
    /// Tempo máximo do `test-boot --no-build` (prazo + hold + folga).
    pub limit: Duration,
    /// Commit que o QEMU do teste faz ao subir (a memória do convidado
    /// inteira e o do próprio QEMU), em bytes.
    pub memory: u64,
}

impl Test {
    fn new(id: &str, arguments: Vec<String>, suite: bool, expected_failure: bool, covered_by_suite: bool) -> Result<Test, String> {
        let mut command = vec![String::from("test-boot")];
        command.extend(arguments.iter().cloned());
        let parsed = crate::parse(command).map_err(|error| format!("teste {id}: {error}"))?;
        if parsed.build_only || parsed.no_build || parsed.build.windows_dir.is_some() {
            return Err(format!("teste {id}: --windows-dir, --build-only e --no-build sao escolhidos pelo test-all"));
        }
        let (_, timeout_ms) = crate::marker_and_timeout(&parsed).map_err(|error| format!("teste {id}: {error}"))?;
        let mut options = crate::test_build_options(&parsed);
        options.build_dir = PathBuf::new();
        Ok(Test {
            id: id.to_string(),
            arguments,
            suite,
            expected_failure,
            covered_by_suite,
            // O Debug lista todas as opções, inclusive as que vierem a existir.
            build_key: format!("{options:?}"),
            limit: Duration::from_millis(timeout_ms.saturating_add(parsed.hold_ms)) + GRACE,
            memory: (u64::from(parsed.machine.memory_mb) << 20) + QEMU_OVERHEAD,
        })
    }

    /// O comando como o integrador o digitaria, com a pasta dada.
    pub fn command_line(&self, build_dir: &str, extra: &str) -> String {
        let mut words = vec![String::from("cargo xtask test-boot")];
        words.extend(self.arguments.iter().map(|word| quote(word)));
        words.push(quote(&format!("--build-dir={build_dir}")));
        if !extra.is_empty() {
            words.push(extra.to_string());
        }
        words.join(" ")
    }
}

/// Aspas duplas quando a palavra tem espaço ou caractere especial do shell
/// (as barras ficam como estão: `\n` em `--keys` vale nos dois shells).
fn quote(word: &str) -> String {
    let plain = !word.is_empty() && word.chars().all(|character| character.is_ascii_alphanumeric() || "-_=./:,+@%".contains(character));
    if plain {
        word.to_string()
    } else {
        format!("\"{}\"", word.replace('"', "\\\""))
    }
}

/// Separa um comando de shell em palavras: aspas duplas (com `\"`, `\\`,
/// `\$` e `` \` `` como escapes) e simples agrupam, e uma barra fora das
/// aspas escapa o caractere seguinte. Dentro das aspas duplas, outra barra
/// fica como está (o `\n` de `--keys`, que o test-boot converte).
pub fn split_words(text: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' | '\n' | '\r' => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match characters.next() {
                        None => return Err(format!("aspas duplas sem fechamento: {text}")),
                        Some('"') => break,
                        Some('\\') if matches!(characters.peek(), Some('"' | '\\' | '$' | '`')) => {
                            current.extend(characters.next());
                        }
                        Some(other) => current.push(other),
                    }
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match characters.next() {
                        None => return Err(format!("aspas simples sem fechamento: {text}")),
                        Some('\'') => break,
                        Some(other) => current.push(other),
                    }
                }
            }
            '\\' => {
                in_word = true;
                current.extend(characters.next());
            }
            other => {
                in_word = true;
                current.push(other);
            }
        }
    }
    if in_word {
        words.push(current);
    }
    Ok(words)
}

fn flag(entry: &toml::Table, key: &str) -> Result<bool, String> {
    match entry.get(key) {
        None => Ok(false),
        Some(toml::Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("{key} deve ser true ou false")),
    }
}

/// As duas suítes e os `[[teste]]` do `components.toml`, nesta ordem.
pub fn load(root: &Path) -> Result<Vec<Test>, String> {
    let mut tests = Vec::new();
    for cpus in SUITE_CPUS {
        let mut arguments: Vec<String> = SUITE.iter().map(|word| word.to_string()).collect();
        arguments.push(format!("--smp={cpus}"));
        tests.push(Test::new(&format!("suite-smp{cpus}"), arguments, true, false, false)?);
    }
    let path = root.join(COMPONENTS);
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let document = toml::parse(&text).map_err(|error| format!("{COMPONENTS}: {error}"))?;
    for entry in document.array("teste") {
        let id = entry.string("id").ok_or_else(|| format!("{COMPONENTS}: [[teste]] sem id"))?;
        let command = entry.string("comando").ok_or_else(|| format!("teste {id}: sem comando"))?;
        let words = split_words(command).map_err(|error| format!("teste {id}: {error}"))?;
        let arguments = match words.as_slice() {
            [cargo, xtask, test_boot, rest @ ..] if cargo == "cargo" && xtask == "xtask" && test_boot == "test-boot" => {
                rest.iter().filter(|word| !word.starts_with("--build-dir=")).cloned().collect()
            }
            _ => return Err(format!("teste {id}: o comando nao e um `cargo xtask test-boot`: {command}")),
        };
        let expected_failure = flag(entry, "espera_falha").map_err(|error| format!("teste {id}: {error}"))?;
        let covered_by_suite = flag(entry, "coberto_pela_suite").map_err(|error| format!("teste {id}: {error}"))?;
        if tests.iter().any(|test: &Test| test.id == id) {
            return Err(format!("{COMPONENTS}: id de teste repetido: {id}"));
        }
        tests.push(Test::new(id, arguments, false, expected_failure, covered_by_suite)?);
    }
    Ok(tests)
}

/// Quais suítes entram quando não há `--only`.
#[derive(Clone, Copy, PartialEq)]
pub enum Suites {
    /// As suítes e os `[[teste]]` (padrão).
    Included,
    /// Só as suítes (`--suite`).
    Only,
    /// Só os `[[teste]]` (`--no-suite`).
    Excluded,
}

/// Índices dos testes escolhidos: os de `only` na ordem dada, ou todos os
/// que não são `coberto_pela_suite`; depois saem os de `skip`.
pub fn select(tests: &[Test], only: &[String], skip: &[String], suites: Suites) -> Result<Vec<usize>, String> {
    let find = |id: &str| {
        tests
            .iter()
            .position(|test| test.id == id)
            .ok_or_else(|| format!("teste desconhecido: {id} (cargo xtask test-all --list mostra os ids)"))
    };
    let mut chosen = Vec::new();
    if only.is_empty() {
        for (index, test) in tests.iter().enumerate() {
            let wanted = match suites {
                Suites::Included => true,
                Suites::Only => test.suite,
                Suites::Excluded => !test.suite,
            };
            if wanted && !test.covered_by_suite {
                chosen.push(index);
            }
        }
    } else {
        for id in only {
            let index = find(id)?;
            if !chosen.contains(&index) {
                chosen.push(index);
            }
        }
    }
    for id in skip {
        let index = find(id)?;
        chosen.retain(|&chosen| chosen != index);
    }
    if chosen.is_empty() {
        return Err("nenhum teste selecionado".into());
    }
    Ok(chosen)
}

/// Uma execução: um teste e a pasta dela (`<id>` ou `<id>.<n>` com
/// `--repeat`).
pub struct Run {
    pub name: String,
    pub test: usize,
}

/// As execuções na ordem dos builds: as de mesma configuração juntas (o
/// kernel recompila uma vez por configuração) e os grupos de teste mais
/// longo primeiro, para as suítes começarem cedo.
pub fn runs(tests: &[Test], chosen: &[usize], repeat: usize) -> Vec<Run> {
    let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
    for &index in chosen {
        let key = tests[index].build_key.as_str();
        match groups.iter_mut().find(|(group, _)| *group == key) {
            Some((_, members)) => members.push(index),
            None => groups.push((key, vec![index])),
        }
    }
    let longest = |members: &[usize]| members.iter().map(|&index| tests[index].limit).max().unwrap_or_default();
    groups.sort_by_key(|(_, members)| std::cmp::Reverse(longest(members)));
    let mut runs = Vec::new();
    for (_, members) in groups {
        for index in members {
            for round in 1..=repeat {
                let id = &tests[index].id;
                let name = if repeat > 1 { format!("{id}.{round}") } else { id.clone() };
                runs.push(Run { name, test: index });
            }
        }
    }
    runs
}
