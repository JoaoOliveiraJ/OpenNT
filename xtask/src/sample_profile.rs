//! `cargo xtask perfil`: resume o perfil por amostragem (`--perfil`) de uma
//! serial.
//!
//! O kernel (`kernel/src/ntos/kd/sampler.rs`) escreve, a cada linha `[perf]`,
//! a janela em linhas `[pf]`: o anel 3 por (pid, módulo+deslocamento), o
//! anel 0 pela pilha crua (RIP e endereços de retorno), os serviços por
//! (pid, número) e as imagens de kernel (`[pf] m`). Aqui as janelas
//! escolhidas se somam e os endereços viram nomes: os do kernel pelo
//! `kernel.elf` ao lado da serial, os dos drivers e dos módulos de usuário
//! pelos arquivos desta máquina (exports, ou o PDB do cache de símbolos sem
//! download), os números de serviço pelos stubs da ntdll.dll e do win32u.dll
//! desta máquina (`mov r10, rcx; mov eax, número`).
//!
//! ```text
//! cargo xtask perfil [--de=S] [--ate=S] [--pid=N] [--top=N] [SERIAL.LOG]
//! ```
//!
//! Sem o arquivo, lê `build/serial.log`. `--de`/`--ate` escolhem as janelas
//! pelo uptime (segundos) da linha `[perf]` que as fecha; `--pid` fica com um
//! processo.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use opennt_kd::pdb::SymbolStore;
use opennt_kd::pe::PeImage;
use opennt_kd::symbols::host_file;
use opennt_kd::Symbols;

const USAGE: &str = "uso: cargo xtask perfil [--de=S] [--ate=S] [--pid=N] [--top=N] [SERIAL.LOG]";

/// Base sintética do primeiro módulo de usuário (cada módulo ganha a sua,
/// para os símbolos da máquina resolverem módulo+deslocamento).
const USER_BASE: u64 = 0x7000_0000_0000;
const USER_STRIDE: u64 = 0x1_0000_0000;

/// O que as janelas escolhidas somaram.
#[derive(Default)]
struct Profile {
    windows: u64,
    first_ms: u64,
    last_ms: u64,
    samples: u64,
    names: BTreeMap<u64, String>,
    images: Vec<(u64, u64, String)>,
    /// (pid, módulo, deslocamento) -> amostras do anel 3.
    user: HashMap<(u64, String, u64), u64>,
    /// (pid, pilha) -> amostras do anel 0.
    kernel: HashMap<(u64, Vec<u64>), u64>,
    /// (pid, número) -> (chamadas, falhas, us, trocas).
    services: HashMap<(u64, u32), [u64; 4]>,
}

fn hex(text: &str) -> Option<u64> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

/// As linhas `[pf]` das janelas que fecham no intervalo [de, até] (ms).
fn parse(text: &str, from_ms: u64, to_ms: u64, pid_filter: Option<u64>) -> Profile {
    let mut profile = Profile::default();
    let mut now = 0u64;
    // A base dos endereços do anel 0, da linha `[pf] janela` (as janelas sem
    // ela, de um kernel anterior, trazem os endereços inteiros).
    let mut base = 0u64;
    let wanted = |pid: u64| pid_filter.is_none_or(|filter| filter == pid);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("[perf] t=") {
            now = rest.split_whitespace().next().and_then(|value| value.parse().ok()).unwrap_or(now);
            continue;
        }
        let Some(rest) = line.strip_prefix("[pf] ") else { continue };
        let mut words = rest.split_whitespace();
        let kind = words.next().unwrap_or("");
        let fields: Vec<&str> = words.collect();
        // Os nomes e as imagens valem em qualquer janela.
        match kind {
            "p" if fields.len() >= 2 => {
                if let Ok(pid) = fields[0].parse() {
                    profile.names.insert(pid, fields[1..].join(" "));
                }
                continue;
            }
            "m" if fields.len() >= 3 => {
                if let (Some(base), Some(size)) = (hex(fields[0]), hex(fields[1])) {
                    profile.images.push((base, base + size, fields[2..].join(" ")));
                }
                continue;
            }
            "janela" => base = fields.iter().position(|&word| word == "base").and_then(|at| fields.get(at + 1)).and_then(|word| hex(word)).unwrap_or(0),
            _ => {}
        }
        if now < from_ms || now > to_ms {
            continue;
        }
        match kind {
            "janela" => {
                if profile.windows == 0 {
                    profile.first_ms = now;
                }
                profile.windows += 1;
                profile.last_ms = now;
            }
            "u" if fields.len() >= 3 => {
                let (Ok(pid), Ok(count)) = (fields[0].parse::<u64>(), fields[1].parse::<u64>()) else { continue };
                if !wanted(pid) {
                    continue;
                }
                let (module, offset) = fields[2].rsplit_once('+').unwrap_or((fields[2], "0"));
                *profile.user.entry((pid, module.to_string(), hex(offset).unwrap_or(0))).or_insert(0) += count;
                profile.samples += count;
            }
            "k" if fields.len() >= 3 => {
                let (Ok(pid), Ok(count)) = (fields[0].parse::<u64>(), fields[1].parse::<u64>()) else { continue };
                if !wanted(pid) {
                    continue;
                }
                let stack: Vec<u64> = fields[2..].iter().filter_map(|word| hex(word)).map(|offset| base.wrapping_add(offset)).collect();
                *profile.kernel.entry((pid, stack)).or_insert(0) += count;
                profile.samples += count;
            }
            "s" if fields.len() >= 6 => {
                let values: Vec<u64> = fields[..5].iter().filter_map(|word| word.parse().ok()).collect();
                let (Some(number), true) = (hex(fields[5]), values.len() == 5) else { continue };
                if !wanted(values[0]) {
                    continue;
                }
                let entry = profile.services.entry((values[0], number as u32)).or_insert([0; 4]);
                for (cell, value) in entry.iter_mut().zip(&values[1..]) {
                    *cell += value;
                }
            }
            _ => {}
        }
    }
    profile.images.sort();
    profile.images.dedup();
    profile
}

/// Número do serviço -> nome, pelos stubs da ntdll.dll e do win32u.dll desta
/// máquina.
fn service_names() -> HashMap<u32, String> {
    let mut names = HashMap::new();
    for file in ["ntdll.dll", "win32u.dll"] {
        let Some(path) = host_file(file) else { continue };
        let Some(image) = std::fs::read(&path).ok().and_then(PeImage::parse) else { continue };
        for (rva, name) in image.exports() {
            if !(name.starts_with("Nt") || name.starts_with("Zw")) {
                continue;
            }
            if let Some(code) = image.bytes_at(rva, 8) {
                if code[..4] == [0x4C, 0x8B, 0xD1, 0xB8] {
                    let number = u32::from_le_bytes([code[4], code[5], code[6], code[7]]);
                    let entry = names.entry(number).or_insert_with(|| name.clone());
                    if entry.starts_with("Zw") && name.starts_with("Nt") {
                        *entry = name;
                    }
                }
            }
        }
    }
    names
}

/// Os símbolos: o kernel pelo ELF, os drivers e os módulos de usuário pelos
/// arquivos desta máquina, com o cache de PDBs (sem download).
fn load_symbols(elf: &Path, profile: &Profile, user_modules: &[String]) -> (Symbols, HashMap<String, u64>) {
    let mut symbols = Symbols::default();
    if let Err(error) = symbols.load_kernel(elf) {
        eprintln!("aviso: sem os simbolos do kernel ({error})");
    }
    let root = crate::build::workspace_root();
    let mut store = SymbolStore::offline(root.join("build").join("symbols"));
    if let Some(main) = std::env::var_os("OPENNT_SYMBOLS") {
        store.search.extend(std::env::split_paths(&main));
    }
    symbols.store = Some(store);
    symbols.set_modules(&profile.images, &root);
    let mut bases = HashMap::new();
    let mut list = Vec::new();
    for (index, module) in user_modules.iter().enumerate() {
        let base = USER_BASE + index as u64 * USER_STRIDE;
        let size = host_file(module).and_then(|path| std::fs::read(path).ok()).and_then(PeImage::parse).map_or(USER_STRIDE, |image| image.header.size_of_image as u64);
        bases.insert(module.clone(), base);
        list.push((base, base + size, module.clone()));
    }
    symbols.set_user_modules(1, &list, &root);
    (symbols, bases)
}

/// O nome da função de um endereço de retorno (o byte da chamada).
fn caller(symbols: &Symbols, address: u64) -> String {
    symbols.function_at(address.wrapping_sub(1)).map_or_else(|| symbols.describe(address), |(_, name)| name)
}

fn function(symbols: &Symbols, address: u64) -> String {
    symbols.function_at(address).map_or_else(|| symbols.describe(address), |(_, name)| name)
}

fn short(name: &str, width: usize) -> String {
    if name.chars().count() <= width {
        return name.to_string();
    }
    let tail: String = name.chars().rev().take(width - 1).collect::<Vec<_>>().into_iter().rev().collect();
    format!("…{tail}")
}

fn ranked<K: Clone>(map: HashMap<K, u64>) -> Vec<(K, u64)> {
    let mut list: Vec<(K, u64)> = map.into_iter().collect();
    list.sort_by(|a, b| b.1.cmp(&a.1));
    list
}

fn percent(part: u64, total: u64) -> f64 {
    100.0 * part as f64 / total.max(1) as f64
}

fn report(profile: Profile, elf: &Path, top: usize) {
    let process = |pid: u64| format!("{} {}", pid, profile.names.get(&pid).map_or("?", String::as_str));
    let total = profile.samples;
    println!("perfil: {} janelas (t={:.0}..{:.0} s), {} amostras", profile.windows, profile.first_ms as f64 / 1000.0, profile.last_ms as f64 / 1000.0, total);
    let mut user_modules: Vec<String> = profile.user.keys().map(|key| key.1.clone()).collect();
    user_modules.sort();
    user_modules.dedup();
    let (symbols, bases) = load_symbols(elf, &profile, &user_modules);

    // Por processo: anel 3 e anel 0.
    let mut per_process: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for ((pid, _, _), count) in &profile.user {
        per_process.entry(*pid).or_default().0 += count;
    }
    for ((pid, _), count) in &profile.kernel {
        per_process.entry(*pid).or_default().1 += count;
    }
    let mut processes: Vec<_> = per_process.into_iter().collect();
    processes.sort_by(|a, b| (b.1 .0 + b.1 .1).cmp(&(a.1 .0 + a.1 .1)));
    println!("\npor processo (pelo CR3; o anel 0 inclui os servicos dele):");
    println!("  {:>6} {:>6} {:>6} {:>6}  processo", "total%", "usu%", "ker%", "amostr");
    for (pid, (user, kernel)) in processes.iter().take(top) {
        println!("  {:>6.1} {:>6.1} {:>6.1} {:>6}  {}", percent(user + kernel, total), percent(*user, total), percent(*kernel, total), user + kernel, process(*pid));
    }

    // Anel 0: própria e inclusiva por função.
    let mut own: HashMap<String, u64> = HashMap::new();
    let mut inclusive: HashMap<String, u64> = HashMap::new();
    let mut own_by_process: HashMap<(u64, String), u64> = HashMap::new();
    let mut kernel_total = 0;
    for ((pid, stack), count) in &profile.kernel {
        kernel_total += count;
        let Some((&rip, frames)) = stack.split_first() else { continue };
        let name = function(&symbols, rip);
        *own.entry(name.clone()).or_insert(0) += count;
        *own_by_process.entry((*pid, name.clone())).or_insert(0) += count;
        let mut seen = vec![name];
        for &frame in frames {
            let name = caller(&symbols, frame);
            if !seen.contains(&name) {
                seen.push(name);
            }
        }
        for name in seen {
            *inclusive.entry(name).or_insert(0) += count;
        }
    }
    println!("\nanel 0: {} amostras ({:.1}%), funcao propria:", kernel_total, percent(kernel_total, total));
    for (name, count) in ranked(own).into_iter().take(top) {
        println!("  {:>6.1}% {:>6}  {}", percent(count, total), count, short(&name, 120));
    }
    println!("\nanel 0, inclusivo (a funcao em qualquer ponto das {} primeiras posicoes da pilha):", 7);
    for (name, count) in ranked(inclusive).into_iter().take(top) {
        println!("  {:>6.1}% {:>6}  {}", percent(count, total), count, short(&name, 120));
    }
    println!("\nanel 0 por processo e funcao propria:");
    for ((pid, name), count) in ranked(own_by_process).into_iter().take(top) {
        println!("  {:>6.1}% {:>6}  {:<22} {}", percent(count, total), count, short(&process(pid), 22), short(&name, 100));
    }
    // As pilhas mais frequentes.
    let mut stacks: HashMap<Vec<u64>, u64> = HashMap::new();
    for ((_, stack), count) in &profile.kernel {
        *stacks.entry(stack.clone()).or_insert(0) += count;
    }
    println!("\nanel 0, pilhas mais frequentes:");
    for (stack, count) in ranked(stacks).into_iter().take(top / 2) {
        println!("  {:>6.1}% {:>6}", percent(count, total), count);
        for (index, &address) in stack.iter().enumerate() {
            let text = if index == 0 { symbols.describe(address) } else { symbols.describe_return(address) };
            println!("           {}", short(&text, 120));
        }
    }

    // Anel 3: por (processo, módulo) e por (processo, função).
    let mut by_module: HashMap<(u64, String), u64> = HashMap::new();
    let mut by_function: HashMap<(u64, String), u64> = HashMap::new();
    let mut user_total = 0;
    for ((pid, module, offset), count) in &profile.user {
        user_total += count;
        *by_module.entry((*pid, module.clone())).or_insert(0) += count;
        let name = match bases.get(module) {
            Some(base) => symbols.describe(base + offset),
            None => format!("{module}+{offset:#x}"),
        };
        // Sem o deslocamento dentro da função: soma por função.
        let name = match name.rsplit_once("+0x") {
            Some((function, _)) if function.contains('!') => function.to_string(),
            _ => name,
        };
        *by_function.entry((*pid, name)).or_insert(0) += count;
    }
    println!("\nanel 3: {} amostras ({:.1}%), por processo e modulo:", user_total, percent(user_total, total));
    for ((pid, module), count) in ranked(by_module).into_iter().take(top) {
        println!("  {:>6.1}% {:>6}  {:<22} {}", percent(count, total), count, short(&process(pid), 22), module);
    }
    println!("\nanel 3, por processo e funcao:");
    for ((pid, name), count) in ranked(by_function).into_iter().take(top) {
        println!("  {:>6.1}% {:>6}  {:<22} {}", percent(count, total), count, short(&process(pid), 22), short(&name, 100));
    }

    // Serviços.
    let names = service_names();
    let name = |number: u32| names.get(&number).cloned().unwrap_or_else(|| format!("#{number:#x}"));
    let mut services: Vec<_> = profile.services.iter().collect();
    services.sort_by(|a, b| b.1[2].cmp(&a.1[2]));
    println!("\nservicos por tempo sem troca de thread (us; as chamadas que trocaram ficam de fora do tempo):");
    println!("  {:>9} {:>8} {:>7} {:>7} {:>8}  processo / servico", "us", "chamadas", "falhas", "trocas", "us/cham");
    for ((pid, number), values) in services.iter().take(top) {
        let calls = values[0].saturating_sub(values[3]).max(1);
        println!("  {:>9} {:>8} {:>7} {:>7} {:>8.1}  {:<22} {}", values[2], values[0], values[1], values[3], values[2] as f64 / calls as f64, short(&process(*pid), 22), name(*number));
    }
    services.sort_by(|a, b| b.1[0].cmp(&a.1[0]));
    println!("\nservicos por chamadas:");
    for ((pid, number), values) in services.iter().take(top) {
        println!("  {:>9} {:>8} {:>7} {:>7}  {:<22} {}", values[2], values[0], values[1], values[3], short(&process(*pid), 22), name(*number));
    }
    let mut by_service: HashMap<u32, [u64; 4]> = HashMap::new();
    for ((_, number), values) in &profile.services {
        let entry = by_service.entry(*number).or_insert([0; 4]);
        for (cell, value) in entry.iter_mut().zip(values) {
            *cell += value;
        }
    }
    let mut by_service: Vec<_> = by_service.into_iter().collect();
    by_service.sort_by(|a, b| b.1[2].cmp(&a.1[2]));
    println!("\nservicos somados em todos os processos, por tempo:");
    for (number, values) in by_service.iter().take(top) {
        let calls = values[0].saturating_sub(values[3]).max(1);
        println!("  {:>9} {:>8} {:>7} {:>7} {:>8.1}  {}", values[2], values[0], values[1], values[3], values[2] as f64 / calls as f64, name(*number));
    }
}

pub fn run(arguments: &[String]) -> Result<(), String> {
    let mut log = None;
    let (mut from, mut to, mut pid, mut top) = (0.0f64, f64::MAX, None, 40usize);
    for argument in arguments {
        match argument.split_once('=') {
            Some(("--de", value)) => from = value.parse().map_err(|_| format!("--de invalido: {value}"))?,
            Some(("--ate", value)) => to = value.parse().map_err(|_| format!("--ate invalido: {value}"))?,
            Some(("--pid", value)) => pid = Some(value.parse().map_err(|_| format!("--pid invalido: {value}"))?),
            Some(("--top", value)) => top = value.parse().map_err(|_| format!("--top invalido: {value}"))?,
            None if argument == "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            None if !argument.starts_with("--") => log = Some(PathBuf::from(argument)),
            _ => return Err(format!("{USAGE}\nopcao desconhecida: {argument}")),
        }
    }
    let log = log.unwrap_or_else(|| PathBuf::from("build").join("serial.log"));
    let bytes = std::fs::read(&log).map_err(|error| format!("{}: {error}", log.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let to_ms = if to == f64::MAX { u64::MAX } else { (to * 1000.0) as u64 };
    let profile = parse(&text, (from * 1000.0) as u64, to_ms, pid);
    if profile.windows == 0 {
        return Err(format!("{}: nenhuma janela do perfil ([pf]) no intervalo", log.display()));
    }
    report(profile, &log.with_file_name("kernel.elf"), top);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_windows_the_kernel_prints() {
        let text = "[perf] t=5000 ms: hlt 0 ms\n[pf] janela 3 amostras (0 perdidas no total) base fffff80040000000\n[pf] p 240 services.exe\n[pf] m fffff80100000000 6000 win32k.sys\n[pf] u 240 2 KERNELBASE.dll+2dc43\n[pf] k 240 1 12345 23456\n[pf] s 240 10 1 25 2 1d\n[perf] t=10000 ms: hlt 0 ms\n[pf] janela 1 amostras (0 perdidas no total)\n[pf] u 4 1 ntdll.dll+10\n";
        let profile = parse(text, 0, 6000, None);
        assert_eq!((profile.windows, profile.samples), (1, 3));
        assert_eq!(profile.names.get(&240).map(String::as_str), Some("services.exe"));
        assert_eq!(profile.images, vec![(0xFFFF_F801_0000_0000, 0xFFFF_F801_0000_6000, String::from("win32k.sys"))]);
        assert_eq!(profile.user.get(&(240, String::from("KERNELBASE.dll"), 0x2dc43)), Some(&2));
        assert_eq!(profile.kernel.get(&(240, vec![0xFFFF_F800_4001_2345, 0xFFFF_F800_4002_3456])), Some(&1));
        assert_eq!(profile.services.get(&(240, 0x1d)), Some(&[10, 1, 25, 2]));
        let all = parse(text, 0, u64::MAX, Some(4));
        assert_eq!((all.windows, all.samples), (2, 1));
    }
}
