//! `cargo xtask crash`: a análise de uma parada pelo log da serial.
//!
//! ```text
//! cargo xtask crash [--build-dir=DIR] [--all] [--sem-simbolos] [--sem-download] [SERIAL.LOG]
//! ```
//!
//! Sem o arquivo, lê `DIR/serial.log` (DIR = `build`). O relatório
//! (`opennt_kd::crash`): a última parada do log com o código, o sentido dos
//! parâmetros no 19041, onde parou (módulo+deslocamento), o módulo culpado
//! e o componente provável; a pilha do bloco `[kcrash]` com os nomes dos
//! PDBs públicos (e do `DIR/kernel.elf` para o kernel do OpenNT); o WdLog
//! do dxgkrnl dos dados secundários do bugcheck (asserções e erros; `--all`:
//! todos os anéis); as apresentações e as mudanças de VidPn da primeira
//! tela e as linhas do dwm.exe.
//!
//! O test-boot que falha com uma parada imprime o mesmo relatório
//! ([`summarize`], só com os PDBs que já estão no cache), e o
//! `test-boot --manual-crash` provoca a parada manual pelo teclado no fim
//! da execução para que os dados secundários saiam na serial.

use std::path::{Path, PathBuf};
use std::time::Duration;

use opennt_kd::crash::{Analysis, LogSymbolizer, ModuleSymbols, NoSymbols, Options};

const USAGE: &str = "uso: cargo xtask crash [--build-dir=DIR] [--all] [--sem-simbolos] [--sem-download] [SERIAL.LOG]
  resume a ultima parada do log (*** STOP ou *** EXCECAO DE KERNEL): o codigo e o sentido dos
  parametros no 19041, onde parou (modulo+deslocamento), o modulo culpado, o componente provavel
  e a pilha do [kcrash] com os nomes dos PDBs publicos; decodifica o WdLog do dxgkrnl dos dados
  secundarios do bugcheck e lista as apresentacoes e mudancas de VidPn da primeira tela
  sem o arquivo, le DIR/serial.log (DIR = build); o kernel do OpenNT usa DIR/kernel.elf
  --all           todos os aneis do WdLog e todas as linhas do dwm
  --sem-simbolos  so os nomes que o kernel escreveu (sem PDB nem kernel.elf)
  --sem-download  so os PDBs que ja estao no cache (build/symbols ou OPENNT_SYMBOLS)
  um boot que nao para nao tem o WdLog: rode o test-boot com --manual-crash";

/// Quanto o `crash` espera os PDBs que estão sendo baixados.
const PDB_WAIT: Duration = Duration::from_secs(180);

/// As tabelas de nomes dos módulos do relatório.
fn symbolizer(analysis: &Analysis, build_dir: &Path, download: bool) -> LogSymbolizer {
    let root = crate::build::workspace_root();
    let elf = build_dir.join("kernel.elf");
    let kernel = elf.is_file().then_some((elf.as_path(), crate::kernel_pe::BASE));
    let mut symbolizer = LogSymbolizer::new(&root, kernel, &analysis.modules(), download);
    if symbolizer.pending() {
        eprintln!("[crash] baixando PDBs do servidor de simbolos...");
        if !symbolizer.wait_for_pdbs(PDB_WAIT) {
            eprintln!("aviso: alguns PDBs nao chegaram em {} s; esses modulos ficam com os exports", PDB_WAIT.as_secs());
        }
    }
    if kernel.is_none() {
        eprintln!("aviso: {} nao existe: os quadros do kernel do OpenNT ficam sem nome", elf.display());
    }
    for note in &symbolizer.notes {
        eprintln!("aviso: {note}");
    }
    symbolizer
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    let mut build_dir = PathBuf::from("build");
    let mut log = None;
    let mut options = Options::default();
    let mut symbols = true;
    let mut download = true;
    for argument in arguments {
        match argument.split_once('=') {
            Some(("--build-dir", value)) => build_dir = PathBuf::from(value),
            None if argument == "--all" => options.all = true,
            None if argument == "--sem-simbolos" => symbols = false,
            None if argument == "--sem-download" => download = false,
            None if argument == "--help" || argument == "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            None if !argument.starts_with("--") => log = Some(PathBuf::from(argument)),
            _ => return Err(format!("{USAGE}\nopcao desconhecida: {argument}")),
        }
    }
    let build_dir = crate::build::in_workspace(&build_dir);
    let log = log.unwrap_or_else(|| build_dir.join("serial.log"));
    let bytes = std::fs::read(&log).map_err(|error| format!("{}: {error}", log.display()))?;
    let analysis = Analysis::parse(&String::from_utf8_lossy(&bytes));
    println!("== {}: {} linhas", log.display(), analysis.lines.len());
    if symbols {
        let symbolizer = symbolizer(&analysis, &build_dir, download);
        println!("simbolos: {}", symbolizer.sources());
        print!("{}", analysis.report(&symbolizer, options));
    } else {
        print!("{}", analysis.report(&NoSymbols, options));
    }
    Ok(())
}

/// O relatório no fim de um test-boot (a falha com uma parada ou o
/// `--manual-crash`): os nomes vêm só dos PDBs do cache e do kernel.elf ao
/// lado do log, para o teste não esperar downloads.
pub fn summarize(log: &Path, text: &str) {
    let analysis = Analysis::parse(text);
    if analysis.crash.is_none() && analysis.wdlog.is_none() {
        return;
    }
    let directory = log.parent().unwrap_or(Path::new("."));
    let symbolizer = symbolizer(&analysis, directory, false);
    let symbols: &dyn ModuleSymbols = &symbolizer;
    println!("\n[xtask] analise da parada (cargo xtask crash {} para os PDBs que faltam no cache):", log.display());
    print!("{}", analysis.report(symbols, Options::default()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_checked() {
        assert!(run(&["--opcao-que-nao-existe".to_string()]).unwrap_err().contains("opcao desconhecida"));
        assert!(run(&["--help".to_string()]).is_ok());
    }
}
