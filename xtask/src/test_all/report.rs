//! O que o `test-all` mostra: a linha de cada teste, o trecho da serial de
//! uma falha e a tabela final.

use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::qemu::{FAILURE_MARKERS, QEMU_KILLED};

/// Linhas mostradas de uma falha.
const EXCERPT_LINES: usize = 12;
/// Linhas de contexto antes da primeira linha que explica a falha.
const CONTEXT_LINES: usize = 4;
/// Linhas da serial que nunca explicam nada (o despejo em hexa das caixas
/// pretas que seguem um STOP).
const NOISE: &[&str] = &["KERNEL_BLACKBOX_BYTES"];
/// Corte de uma linha longa do trecho.
const LINE_WIDTH: usize = 200;

#[derive(Clone, Copy, PartialEq)]
pub enum Verdict {
    Passed,
    Failed,
    /// Falhou, e o `components.toml` diz que falha (`espera_falha`).
    ExpectedFailure,
    /// Passou, mas o `components.toml` diz que falha.
    UnexpectedPass,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Passed => "passou",
            Verdict::Failed => "FALHOU",
            Verdict::ExpectedFailure => "falha esperada",
            Verdict::UnexpectedPass => "PASSOU (esperava falha)",
        }
    }

    pub fn passed(self) -> bool {
        matches!(self, Verdict::Passed | Verdict::UnexpectedPass)
    }
}

pub struct Outcome {
    pub name: String,
    pub verdict: Verdict,
    pub build: Option<Duration>,
    pub test: Option<Duration>,
    /// Motivo da falha (a linha `TEST-BOOT FALHOU`, o erro do build...).
    pub reason: String,
    /// O trecho da serial (ou do log de build) que explica a falha.
    pub excerpt: Vec<String>,
    /// O log da falha, relativo à raiz do workspace.
    pub log: String,
    /// O comando que repete o QEMU na mesma imagem.
    pub repeat_command: String,
    /// O anfitrião de um teste conferido na serial dele (`na_execucao_de`).
    pub host: Option<String>,
}

/// O veredito de um teste na serial de outra execução do mesmo boot (o
/// anfitrião, `na_execucao_de`), com a regra do `test-boot`: os textos da
/// `chain` (o marcador e as `--expect`) em ordem, cada um depois do
/// anterior, e os `unordered` (as `--expect-any`) em qualquer ponto; um
/// marcador de falha antes de um texto reprova, como na espera do
/// test-boot. Devolve o motivo de uma falha.
pub fn derived(serial: &str, chain: &[String], unordered: &[String]) -> Result<(), String> {
    let failure = |from: usize, end: usize| FAILURE_MARKERS.iter().find(|marker| serial[from..end].contains(*marker));
    let mut from = 0;
    let mut previous: Option<&str> = None;
    for needle in chain {
        let Some(offset) = serial[from..].find(needle.as_str()) else {
            if let Some(marker) = failure(from, serial.len()) {
                return Err(format!("falha detectada na serial: {marker}"));
            }
            return Err(match previous {
                Some(previous) => format!("{needle:?} nao aparece na serial do anfitriao depois de {previous:?}"),
                None => format!("{needle:?} nao aparece na serial do anfitriao"),
            });
        };
        let end = from + offset + needle.len();
        if let Some(marker) = failure(from, end) {
            return Err(format!("falha detectada na serial antes de {needle:?}: {marker}"));
        }
        (from, previous) = (end, Some(needle.as_str()));
    }
    for needle in unordered {
        let Some(offset) = serial.find(needle.as_str()) else {
            return Err(format!("{needle:?} nao aparece na serial do anfitriao"));
        };
        if let Some(marker) = failure(0, offset + needle.len()) {
            return Err(format!("falha detectada na serial antes de {needle:?}: {marker}"));
        }
    }
    Ok(())
}

/// Quando `needle` chegou na execução do anfitrião, pela linha
/// `[xtask] "<texto>" aos N s` que o test-boot escreve ao achar cada texto
/// que espera (contado da subida do QEMU; numa `--expect-any`, quando a
/// espera chegou a ele, um limite de cima).
pub fn arrival(console: &str, needle: &str) -> Option<Duration> {
    let prefix = format!("[xtask] {needle:?} aos ");
    let line = console.lines().find_map(|line| line.strip_prefix(prefix.as_str()))?;
    let seconds: f64 = line.strip_suffix(" s")?.trim().parse().ok()?;
    Duration::try_from_secs_f64(seconds).ok()
}

/// `1h02m`, `6m40s`, `47s`.
pub fn duration(time: Duration) -> String {
    let seconds = time.as_secs();
    if seconds >= 3600 {
        format!("{}h{:02}m", seconds / 3600, seconds % 3600 / 60)
    } else if seconds >= 60 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

pub fn read_lossy(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|bytes| String::from_utf8_lossy(&bytes).replace('\r', ""))
}

fn clip(line: &str) -> String {
    match line.char_indices().nth(LINE_WIDTH) {
        Some((cut, _)) => format!("{}...", &line[..cut]),
        None => line.to_string(),
    }
}

/// As linhas que explicam o fim de um log: a partir da primeira que
/// `interesting` aponta (com algumas de contexto antes), ou as últimas.
/// Linhas em branco e despejos em hexa ficam de fora.
pub fn excerpt(text: &str, interesting: impl Fn(&str) -> bool) -> Vec<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty() && !NOISE.iter().any(|noise| line.starts_with(noise)))
        .collect();
    let start = match lines.iter().position(|line| interesting(line)) {
        Some(first) => first.saturating_sub(CONTEXT_LINES),
        None => lines.len().saturating_sub(EXCERPT_LINES),
    };
    lines[start..].iter().take(EXCERPT_LINES).map(|line| clip(line)).collect()
}

/// O trecho de uma serial: do primeiro marcador de falha (pânico, exceção,
/// autoteste, STOP) ou, num prazo esgotado, as últimas linhas.
pub fn serial_excerpt(text: &str) -> Vec<String> {
    excerpt(text, |line| FAILURE_MARKERS.iter().any(|marker| line.contains(marker)))
}

/// O trecho de um log de build: do primeiro erro do compilador.
pub fn build_excerpt(text: &str) -> Vec<String> {
    excerpt(text, |line| line.starts_with("error"))
}

/// O build das imagens foi morto de fora: o cargo (ou o rustc dele) saiu com
/// erro sem diagnóstico nenhum. O `comando falhou` é a falha de um comando
/// do build (`build::run`); um diagnóstico é uma linha `error[...]` ou
/// `error: ...` que não seja o `could not compile` genérico do cargo (os
/// avisos negados também saem como `error:`). As conferências do próprio
/// xtask (o PE, o tamanho do kernel) falham com outra mensagem.
pub fn build_killed(log: &str) -> bool {
    let diagnostic = log.lines().map(str::trim_start).any(|line| line.starts_with("error[") || (line.starts_with("error:") && !line.starts_with("error: could not compile")));
    log.contains("comando falhou (") && !diagnostic
}

/// O QEMU de uma execução foi morto de fora antes da saída esperada: o
/// test-boot deu o motivo [`QEMU_KILLED`] e a serial não tem marcador de
/// falha. Um prazo esgotado, um STOP, um pânico ou um autoteste que falhou
/// nunca contam.
pub fn qemu_killed(console: &str, serial: &str) -> bool {
    failure_reason(console).contains(QEMU_KILLED) && !FAILURE_MARKERS.iter().any(|marker| serial.contains(marker))
}

/// O motivo que o test-boot deu (a linha `TEST-BOOT FALHOU`, sem o caminho
/// da serial, que a tabela já mostra), ou a última linha do log.
pub fn failure_reason(console: &str) -> String {
    let lines = console.lines().map(str::trim).filter(|line| !line.is_empty());
    let reason = lines.clone().rev().find(|line| line.starts_with("TEST-BOOT FALHOU")).or_else(|| lines.last());
    let reason = reason.map(|line| line.rsplit_once(" (serial em ").map_or(line, |(reason, _)| reason));
    reason.map(clip).unwrap_or_else(|| String::from("test-boot terminou sem saida"))
}

/// A tabela final e o detalhe de cada falha; devolve o número de falhas
/// que reprovam a rodada.
pub fn summary(outcomes: &[Outcome], total: Duration) -> usize {
    let width = outcomes.iter().map(|outcome| outcome.name.len()).max().unwrap_or(0).max(5);
    let verdict_width = outcomes.iter().map(|outcome| outcome.verdict.label().len()).max().unwrap_or(0).max(9);
    let time = |time: Option<Duration>| time.map(duration).unwrap_or_else(|| String::from("-"));
    println!();
    let derived = outcomes.iter().filter(|outcome| outcome.host.is_some()).count();
    if derived == 0 {
        println!("resumo ({} execucoes em {})", outcomes.len(), duration(total));
    } else {
        println!("resumo ({} testes, {} execucoes com QEMU, em {})", outcomes.len(), outcomes.len() - derived, duration(total));
    }
    println!("  {:<width$}  {:<verdict_width$}  {:>6}  {:>6}  serial", "teste", "resultado", "build", "tempo");
    for outcome in outcomes {
        let log = if outcome.verdict.passed() { "" } else { outcome.log.as_str() };
        let host = outcome.host.as_ref().map(|host| format!("(na execucao de {host})  ")).unwrap_or_default();
        let line = format!(
            "  {:<width$}  {:<verdict_width$}  {:>6}  {:>6}  {host}{log}",
            outcome.name,
            outcome.verdict.label(),
            time(outcome.build),
            time(outcome.test)
        );
        println!("{}", line.trim_end());
    }
    let count = |verdict: Verdict| outcomes.iter().filter(|outcome| outcome.verdict == verdict).count();
    for (verdict, title) in [(Verdict::Failed, "falhas"), (Verdict::ExpectedFailure, "falhas esperadas (espera_falha no components.toml)")] {
        if count(verdict) == 0 {
            continue;
        }
        println!();
        println!("{title}:");
        for outcome in outcomes.iter().filter(|outcome| outcome.verdict == verdict) {
            println!("  {}: {}", outcome.name, outcome.reason);
            for line in &outcome.excerpt {
                println!("    | {line}");
            }
            if !outcome.repeat_command.is_empty() {
                println!("    repetir: {}", outcome.repeat_command);
            }
        }
    }
    let unexpected: Vec<&str> =
        outcomes.iter().filter(|outcome| outcome.verdict == Verdict::UnexpectedPass).map(|outcome| outcome.name.as_str()).collect();
    if !unexpected.is_empty() {
        println!();
        println!("passaram apesar de espera_falha (tire a marca do components.toml): {}", unexpected.join(", "));
    }
    let failed = count(Verdict::Failed);
    println!();
    println!(
        "{} passaram, {} falharam, {} falhas esperadas",
        count(Verdict::Passed) + unexpected.len(),
        failed,
        count(Verdict::ExpectedFailure)
    );
    failed
}
