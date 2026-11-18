//! `cargo xtask heap-census`: dá nomes ao censo do heap do kernel.
//!
//! O kernel imprime o censo (`kernel/src/hal/heap_census.rs`) na falha do
//! heap e, com `--heap-census`, a cada 4 MB a mais de uso: uma linha de
//! abertura `[heap-census] MOTIVO: usado=... base=0x...` e uma linha por
//! local, com os bytes e blocos vivos e a cadeia de retornos em offsets da
//! imagem do kernel. Aqui os retornos viram nomes pelos símbolos do
//! kernel.elf do build, e cada local é atribuído à primeira função da
//! cadeia que não é do alocador nem da biblioteca (`alloc::`, `core::`); os
//! locais da mesma função somam numa tabela por função.
//!
//! ```text
//! cargo xtask heap-census [--build-dir=DIR] [--all] [SERIAL.LOG]
//! ```
//!
//! Sem o arquivo, lê `DIR/serial.log` (DIR = `build`). Mostra o último censo
//! do log; `--all` mostra todos. O test-boot que falha com um censo na
//! serial imprime o resumo do último.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kd_client::Symbols;

const USAGE: &str = "uso: cargo xtask heap-census [--build-dir=DIR] [--all] [SERIAL.LOG]";

/// Um local do censo: bytes e blocos vivos, alocações e a cadeia (VAs).
struct Site {
    bytes: u64,
    blocks: u64,
    allocations: u64,
    chain: Vec<Option<u64>>,
}

/// Um censo do log: a linha de abertura e os locais.
struct Census {
    header: String,
    sites: Vec<Site>,
}

fn field(line: &str, name: &str) -> Option<String> {
    let start = line.find(&format!("{name}="))? + name.len() + 1;
    Some(line[start..].split_whitespace().next().unwrap_or("").to_string())
}

fn number(text: &str) -> Option<u64> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Os censos do texto da serial, na ordem.
fn parse(text: &str) -> Vec<Census> {
    let mut list: Vec<Census> = Vec::new();
    let mut base = 0u64;
    for line in text.lines() {
        let Some(at) = line.find("[heap-census] ") else { continue };
        let line = &line[at + "[heap-census] ".len()..];
        if !line.starts_with('#') {
            base = field(line, "base").and_then(|text| number(&text)).unwrap_or(0);
            list.push(Census { header: line.to_string(), sites: Vec::new() });
            continue;
        }
        let Some(census) = list.last_mut() else { continue };
        let value = |name: &str| field(line, name).and_then(|text| number(&text)).unwrap_or(0);
        let chain = line.split_once("cadeia=").map_or(Vec::new(), |(_, rest)| rest.split_whitespace().map(|word| if word == "?" { None } else { u64::from_str_radix(word, 16).ok().map(|offset| base + offset) }).collect());
        census.sites.push(Site { bytes: value("bytes"), blocks: value("blocos"), allocations: value("alocacoes"), chain });
    }
    list
}

/// Funções do alocador e da biblioteca: o local é a primeira fora delas.
fn plumbing(name: &str) -> bool {
    let name = name.trim_start_matches('<');
    if ["kernel::hal::kmalloc", "kernel::hal::heap_census"].iter().any(|prefix| name.starts_with(prefix)) {
        return true;
    }
    if name.starts_with("kernel::") {
        return false;
    }
    // `<[T]>::to_vec`, `<u8 as alloc::...>::from_elem`: tipos da biblioteca.
    ["alloc::", "core::", "__rust", "__rdl", "hashbrown::", "[", "&"].iter().any(|prefix| name.starts_with(prefix)) || name.contains(" as alloc::") || name.contains(" as core::")
}

fn function(symbols: &Symbols, address: u64) -> String {
    symbols.function_at(address.wrapping_sub(1)).map_or_else(|| format!("{address:#x}"), |(_, name)| name)
}

/// O dono de um local: a primeira função da cadeia fora do alocador.
fn owner(symbols: &Symbols, site: &Site) -> String {
    for frame in &site.chain {
        let Some(address) = frame else { return String::from("(driver convidado)") };
        let name = function(symbols, *address);
        if !plumbing(&name) {
            return name;
        }
    }
    String::from("(sem cadeia)")
}

fn short(name: &str, width: usize) -> String {
    if name.chars().count() <= width {
        return name.to_string();
    }
    let tail: String = name.chars().rev().take(width - 1).collect::<Vec<_>>().into_iter().rev().collect();
    format!("…{tail}")
}

fn print(symbols: &Symbols, census: &Census) {
    // Sem o prefixo da serial: a saída do xtask não é relida como censo.
    println!("censo do heap: {}", census.header);
    let mut owners: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for site in &census.sites {
        let entry = owners.entry(owner(symbols, site)).or_default();
        entry.0 += site.bytes;
        entry.1 += site.blocks;
        entry.2 += 1;
    }
    let mut ranked: Vec<_> = owners.into_iter().collect();
    ranked.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    let listed: u64 = census.sites.iter().map(|site| site.bytes).sum();
    println!("  por funcao ({} locais listados, {:.1} MB):", census.sites.len(), listed as f64 / 1048576.0);
    for (name, (bytes, blocks, sites)) in ranked.iter().take(40) {
        println!("  {:>9.1} KB {:>8} blocos {:>4} locais  {}", *bytes as f64 / 1024.0, blocks, sites, short(name, 110));
    }
    println!("  maiores locais:");
    for site in census.sites.iter().take(15) {
        println!("  {:>9.1} KB {:>8} blocos {:>9} alocacoes", site.bytes as f64 / 1024.0, site.blocks, site.allocations);
        for frame in &site.chain {
            match frame {
                Some(address) => println!("      {}", short(&symbols.describe_return(*address), 120)),
                None => println!("      (fora do kernel)"),
            }
        }
    }
}

fn load_symbols(elf: &Path) -> Result<Symbols, String> {
    let mut symbols = Symbols::default();
    symbols.load_kernel(elf)?;
    Ok(symbols)
}

/// O resumo do último censo de um log de test-boot que falhou (nada quando
/// a serial não tem censo ou o kernel.elf não está ao lado dela).
pub fn summarize_failure(log: &Path, text: &str) {
    let list = parse(text);
    let Some(census) = list.iter().rev().find(|census| !census.sites.is_empty()) else { return };
    let elf = log.with_file_name("kernel.elf");
    match load_symbols(&elf) {
        Ok(symbols) => print(&symbols, census),
        Err(error) => eprintln!("aviso: censo do heap sem simbolos ({error})"),
    }
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    let mut build_dir = PathBuf::from("build");
    let mut log = None;
    let mut all = false;
    for argument in arguments {
        match argument.split_once('=') {
            Some(("--build-dir", value)) => build_dir = PathBuf::from(value),
            None if argument == "--all" => all = true,
            None if argument == "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            None if !argument.starts_with("--") => log = Some(PathBuf::from(argument)),
            _ => return Err(format!("{USAGE}\nopcao desconhecida: {argument}")),
        }
    }
    let log = log.unwrap_or_else(|| build_dir.join("serial.log"));
    let bytes = std::fs::read(&log).map_err(|error| format!("{}: {error}", log.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let list = parse(&text);
    if list.is_empty() {
        return Err(format!("{}: nenhum censo do heap ([heap-census])", log.display()));
    }
    let symbols = load_symbols(&build_dir.join("kernel.elf"))?;
    let shown = if all { &list[..] } else { &list[list.len() - 1..] };
    for census in shown {
        print(&symbols, census);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_census_the_kernel_prints() {
        let text = "x\n[heap-census] falha do heap: usado=0x100 total=0x200 blocos=3 locais=2 base=0xfffff80040000000\n[heap-census] #1 bytes=0x80 blocos=2 alocacoes=9 local=5 cadeia= 1a2b 3c4d ?\n[heap-census] #2 bytes=0x40 blocos=1 alocacoes=1 local=7 cadeia= 10\n";
        let list = parse(text);
        assert_eq!(list.len(), 1);
        assert!(list[0].header.starts_with("falha do heap"));
        assert_eq!(list[0].sites.len(), 2);
        let first = &list[0].sites[0];
        assert_eq!((first.bytes, first.blocks, first.allocations), (0x80, 2, 9));
        assert_eq!(first.chain, vec![Some(0xFFFF_F800_4000_1A2B), Some(0xFFFF_F800_4000_3C4D), None]);
        assert_eq!(list[0].sites[1].chain, vec![Some(0xFFFF_F800_4000_0010)]);
    }

    #[test]
    fn library_frames_are_plumbing() {
        assert!(plumbing("alloc::raw_vec::finish_grow"));
        assert!(plumbing("<alloc::vec::Vec<T> as core::clone::Clone>::clone"));
        assert!(plumbing("kernel::hal::kmalloc::kmalloc"));
        assert!(!plumbing("kernel::ntos::mm::pe_loader::load_prepared"));
        assert!(!plumbing("<kernel::ntos::ob::Object as core::ops::Drop>::drop"));
        assert!(plumbing("<u8 as alloc::vec::spec_from_elem::SpecFromElem>::from_elem"));
        assert!(plumbing("<[T]>::to_vec"));
    }
}
