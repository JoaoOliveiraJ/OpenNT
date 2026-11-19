//! Símbolos do cliente do depurador.
//!
//! - O kernel do OpenNT: a tabela de símbolos do ELF do build
//!   (`<build>/kernel.elf`), com os nomes do Rust legíveis; o kernel roda na
//!   VA em que foi ligado, então os endereços do ELF valem como estão.
//! - Os binários da Microsoft carregados (a lista `monitor lm` do alvo): a
//!   tabela de exports de cada PE, lida do arquivo desta máquina, a tabela de
//!   funções (`.pdata`, para a pilha) e os nomes públicos (S_PUB32) do PDB
//!   público dele, do cache `build/symbols` (baixado do servidor de símbolos
//!   quando falta, em segundo plano).
//!
//! Os módulos aparecem pelo nome sem extensão (`ntfs!NtfsCommonCreate+0x1a3`,
//! como no WinDbg); a busca aceita o nome com ou sem extensão, e `nt` é o
//! kernel.
//!
//! Os módulos de usuário de um processo (a PEB.Ldr do processo escolhido ou
//! da parada) entram à parte (`set_user_modules`): a lista de módulos do
//! kernel não os apaga, e a troca de processo troca só eles.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::demangle::demangle;
use super::elf::{Elf, SHF_ALLOC};
use super::pdb::{self, SymbolStore};
use super::pe::{find_function, PeImage};
use super::unwind::FunctionTable;

#[derive(Clone, Debug)]
pub struct Symbol {
    pub address: u64,
    pub size: u64,
    pub name: String,
    pub function: bool,
}

#[derive(Clone)]
pub struct Module {
    /// O nome sem extensão (`ntfs`, `ACPI`, `ntoskrnl`).
    pub name: String,
    /// O nome do arquivo (`ntfs.sys`).
    pub file_name: String,
    pub path: String,
    pub base: u64,
    pub end: u64,
    /// Ordenados pelo endereço.
    pub symbols: Vec<Symbol>,
    /// De onde vieram os símbolos (para o `lm` do cliente).
    pub source: String,
    /// O arquivo desta máquina (cabeçalho, `.pdata`, código).
    pub image: Option<Arc<PeImage>>,
    /// A tabela de funções (`.pdata`).
    pub unwind: Option<Arc<FunctionTable>>,
    /// O PDB de onde vieram os nomes.
    pub pdb: Option<PathBuf>,
    /// O PDB está sendo baixado: o módulo é recarregado quando chegar.
    pub pdb_pending: bool,
    /// Módulo de usuário (do processo de `Symbols::user_process`).
    pub user: bool,
}

impl std::fmt::Debug for Module {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Module").field("name", &self.name).field("base", &format_args!("{:#x}", self.base)).field("end", &format_args!("{:#x}", self.end)).field("symbols", &self.symbols.len()).field("source", &self.source).finish()
    }
}

impl Module {
    pub fn new(name: &str, path: &str, base: u64, end: u64, symbols: Vec<Symbol>, source: &str) -> Self {
        Module { name: display_name(name), file_name: base_name(name).to_string(), path: path.to_string(), base, end, symbols, source: source.to_string(), image: None, unwind: None, pdb: None, pdb_pending: false, user: false }
    }
}

#[derive(Clone, Default)]
pub struct Symbols {
    pub modules: Vec<Module>,
    /// Índice do módulo do kernel (o ELF).
    kernel: Option<usize>,
    /// Muda a cada troca de módulos (quem guarda uma cópia sabe quando
    /// renovar).
    pub generation: u64,
    /// O cache de PDBs (sem ele, nada de PDB nem download).
    pub store: Option<SymbolStore>,
    /// O EPROCESS dos módulos de usuário carregados (0 = nenhum).
    pub user_process: u64,
}

/// Nome base sem diretório (barras dos dois tipos).
pub fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// O nome de exibição: sem diretório e sem a extensão de imagem.
pub fn display_name(path: &str) -> String {
    let base = base_name(path);
    match base.rsplit_once('.') {
        Some((stem, extension)) if ["sys", "exe", "dll"].contains(&extension.to_ascii_lowercase().as_str()) && !stem.is_empty() => stem.to_string(),
        _ => base.to_string(),
    }
}

/// O arquivo desta máquina para um módulo carregado no alvo.
pub fn host_file(path: &str) -> Option<PathBuf> {
    let windows = PathBuf::from(r"C:\Windows");
    let normalized = path.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    let mut candidates = Vec::new();
    for marker in [r"\systemroot\", r"\windows\"] {
        if let Some(index) = lower.find(marker) {
            candidates.push(windows.join(&normalized[index + marker.len()..]));
        }
    }
    let base = base_name(path);
    candidates.push(windows.join("System32").join(base));
    candidates.push(windows.join("System32").join("drivers").join(base));
    candidates.into_iter().find(|candidate| candidate.is_file())
}

impl Symbols {
    /// Símbolos do kernel a partir do ELF do build.
    pub fn load_kernel(&mut self, elf_path: &Path) -> Result<usize, String> {
        let bytes = std::fs::read(elf_path).map_err(|error| format!("{}: {error}", elf_path.display()))?;
        let elf = Elf::parse(&bytes)?;
        let mut symbols: Vec<Symbol> = elf
            .symbol_entries()?
            .into_iter()
            .filter(|entry| entry.address != 0 && matches!(entry.kind, 0..=2))
            .map(|entry| Symbol { address: entry.address, size: entry.size, name: demangle(&entry.name).unwrap_or(entry.name), function: entry.kind == 2 })
            .collect();
        symbols.sort_by_key(|symbol| symbol.address);
        let allocated = elf.sections.iter().filter(|section| section.flags & SHF_ALLOC != 0 && section.address != 0);
        let base = allocated.clone().map(|section| section.address).min().unwrap_or(0) & !0xFFF;
        let end = allocated.map(|section| section.address + section.size).max().unwrap_or(0);
        let count = symbols.len();
        let module = Module::new("kernel", &elf_path.display().to_string(), base, end, symbols, "ELF do kernel");
        self.set_kernel(module);
        Ok(count)
    }

    /// O módulo do kernel (os símbolos do ELF, sem prefixo de módulo).
    pub fn set_kernel(&mut self, module: Module) {
        match self.kernel {
            Some(index) => self.modules[index] = module,
            None => {
                self.kernel = Some(self.modules.len());
                self.modules.push(module);
            }
        }
        self.generation += 1;
    }

    /// Acrescenta um módulo já com os símbolos (ordenados pelo endereço).
    pub fn add_module(&mut self, module: Module) {
        self.modules.push(module);
        self.generation += 1;
    }

    /// O módulo do kernel, se o ELF foi carregado.
    pub fn kernel(&self) -> Option<&Module> {
        self.kernel.map(|index| &self.modules[index])
    }

    /// O módulo é o kernel do OpenNT.
    pub fn is_kernel(&self, module: &Module) -> bool {
        self.kernel.is_some_and(|index| std::ptr::eq(&self.modules[index], module))
    }

    /// Troca os módulos carregados (fora o kernel) pela lista do alvo:
    /// (base, fim, caminho). `root` é a raiz do repositório (o cache de PDBs).
    pub fn set_modules(&mut self, list: &[(u64, u64, String)], root: &Path) {
        if self.store.is_none() {
            self.store = Some(SymbolStore::new(root));
        }
        let signature = |modules: &[Module]| -> Vec<(u64, u64, String, usize)> { modules.iter().map(|module| (module.base, module.end, module.name.clone(), module.symbols.len())).collect() };
        let before = signature(&self.modules);
        let kernel = self.kernel.map(|index| self.modules.swap_remove(index));
        let (user, system): (Vec<Module>, Vec<Module>) = self.modules.drain(..).partition(|module| module.user);
        let mut previous: HashMap<(u64, String), Module> = system.into_iter().map(|module| ((module.base, module.path.clone()), module)).collect();
        self.kernel = None;
        if let Some(kernel) = kernel {
            self.kernel = Some(0);
            self.modules.push(kernel);
        }
        for (base, end, path) in list {
            // A imagem do kernel do OpenNT (o ntoskrnl.exe da lista, com os
            // cabeçalhos antes da primeira seção do ELF) fica com os símbolos
            // do ELF, nunca com os exports do ntoskrnl desta máquina.
            if let Some(index) = self.kernel {
                let kernel = &mut self.modules[index];
                if *base < kernel.end && *end > kernel.base {
                    kernel.base = kernel.base.min(*base);
                    kernel.name = display_name(path);
                    kernel.file_name = base_name(path).to_string();
                    continue;
                }
            }
            if let Some(module) = previous.remove(&(*base, path.clone())) {
                if !module.pdb_pending || self.store.as_ref().is_some_and(|store| store.busy()) {
                    self.modules.push(module);
                    continue;
                }
            }
            let module = self.load_module(*base, *end, path);
            self.modules.push(module);
        }
        self.modules.extend(user);
        if signature(&self.modules) != before {
            self.generation += 1;
        }
    }

    /// Troca os módulos de usuário pelos do processo `process` (EPROCESS):
    /// (base, fim, caminho). Os de mesma base e caminho ficam como estão.
    pub fn set_user_modules(&mut self, process: u64, list: &[(u64, u64, String)], root: &Path) {
        if self.store.is_none() {
            self.store = Some(SymbolStore::new(root));
        }
        let kernel = self.kernel.map(|index| (self.modules[index].base, self.modules[index].path.clone()));
        let (user, system): (Vec<Module>, Vec<Module>) = self.modules.drain(..).partition(|module| module.user);
        self.modules = system;
        self.kernel = kernel.and_then(|(base, path)| self.modules.iter().position(|module| module.base == base && module.path == path));
        let mut previous: HashMap<(u64, String), Module> = user.into_iter().map(|module| ((module.base, module.path.clone()), module)).collect();
        for (base, end, path) in list {
            let module = match previous.remove(&(*base, path.clone())) {
                Some(module) if !module.pdb_pending || self.store.as_ref().is_some_and(|store| store.busy()) => module,
                _ => {
                    let mut module = self.load_module(*base, *end, path);
                    module.user = true;
                    module
                }
            };
            self.modules.push(module);
        }
        self.user_process = process;
        self.generation += 1;
    }

    /// Os módulos de usuário carregados.
    pub fn user_modules(&self) -> impl Iterator<Item = &Module> {
        self.modules.iter().filter(|module| module.user)
    }

    /// Algum PDB ainda está chegando.
    pub fn pending(&self) -> bool {
        self.modules.iter().any(|module| module.pdb_pending)
    }

    fn load_module(&self, base: u64, end: u64, path: &str) -> Module {
        let mut module = Module::new(path, path, base, end, Vec::new(), "sem simbolos");
        let Some(file) = host_file(path) else { return module };
        let Some(image) = std::fs::read(&file).ok().and_then(PeImage::parse) else { return module };
        let image = Arc::new(image);
        let mut names: Vec<(u32, String)> = image.exports();
        module.source = format!("exports de {}", file.display());
        if let Some(store) = &self.store {
            match store.request(&image) {
                Some(pdb_path) => {
                    if let Some(publics) = pdb::publics(&pdb_path, &image) {
                        module.source = format!("PDB {} + exports", pdb_path.display());
                        names.extend(publics);
                        module.pdb = Some(pdb_path);
                    }
                }
                None => {
                    let pdb_name = image.rsds().map(|(_, _, name)| base_name(&name).to_string()).unwrap_or_default();
                    match store.fetch_state(&pdb_name) {
                        Some(pdb::Fetch::Downloading) => {
                            module.pdb_pending = true;
                            module.source = format!("{} (baixando {pdb_name})", module.source);
                        }
                        Some(pdb::Fetch::Failed(error)) => module.source = format!("{} (PDB indisponivel: {})", module.source, error.lines().next().unwrap_or("")),
                        None => {}
                    }
                }
            }
        }
        let functions = image.runtime_functions();
        if !functions.is_empty() {
            module.unwind = Some(Arc::new(FunctionTable { base, functions, image: Some(Arc::clone(&image)) }));
        }
        let mut symbols: Vec<Symbol> = names.into_iter().map(|(rva, name)| Symbol { address: base + rva as u64, size: 0, name, function: true }).collect();
        symbols.sort_by_key(|symbol| symbol.address);
        symbols.dedup_by(|a, b| a.address == b.address && a.name == b.name);
        module.symbols = symbols;
        module.image = Some(image);
        module
    }

    pub fn module_at(&self, address: u64) -> Option<&Module> {
        self.modules.iter().find(|module| address >= module.base && address < module.end)
    }

    /// Um módulo pelo nome (com ou sem extensão, sem diferença de caixa;
    /// `nt` e `kernel` são o kernel).
    pub fn module_named(&self, name: &str) -> Option<&Module> {
        let wanted = name.to_ascii_lowercase();
        if wanted == "nt" || wanted == "kernel" {
            if let Some(kernel) = self.kernel() {
                return Some(kernel);
            }
        }
        self.modules.iter().find(|module| module.name.to_ascii_lowercase() == wanted || module.file_name.to_ascii_lowercase() == wanted)
    }

    fn prefix(&self, module: &Module) -> String {
        if self.is_kernel(module) {
            String::new()
        } else {
            format!("{}!", module.name)
        }
    }

    /// O símbolo de função que contém o endereço (ou o mais próximo antes
    /// dele, quando o tamanho não é conhecido): o começo e o nome
    /// (`módulo!nome` fora do kernel).
    pub fn function_at(&self, address: u64) -> Option<(u64, String)> {
        let module = self.module_at(address)?;
        let index = module.symbols.partition_point(|symbol| symbol.address <= address);
        let symbol = module.symbols[..index].iter().rev().take(64).find(|symbol| symbol.function && (symbol.size == 0 || address < symbol.address + symbol.size))?;
        Some((symbol.address, format!("{}{}", self.prefix(module), symbol.name)))
    }

    /// O nome de um endereço quando ele cai num símbolo (`None` quando o
    /// `describe` só teria o número ou `módulo+0xRVA`).
    pub fn name_at(&self, address: u64) -> Option<String> {
        let text = self.describe(address);
        let module = self.module_at(address)?;
        (!text.starts_with("0x") && !text.starts_with(&format!("{}+0x", module.name))).then_some(text)
    }

    /// `símbolo` cobre `address`: pelo tamanho, quando conhecido. Sem tamanho
    /// (os exports de um módulo sem PDB), o endereço tem de cair na função da
    /// `.pdata` em que o símbolo começa; num módulo com PDB, ou sem função na
    /// `.pdata` para o endereço, vale o símbolo mais próximo antes dele.
    fn covers(module: &Module, symbol: &Symbol, address: u64) -> bool {
        if symbol.size != 0 {
            return address < symbol.address + symbol.size;
        }
        if module.pdb.is_some() {
            return true;
        }
        let (Some(table), Ok(rva)) = (&module.unwind, u32::try_from(address - module.base)) else { return true };
        match find_function(&table.functions, rva) {
            Some(function) => (function.begin as u64..function.end as u64).contains(&(symbol.address - module.base)),
            None => true,
        }
    }

    /// `módulo!símbolo+0x10`, `símbolo+0x10` (kernel) ou `módulo+0xRVA`
    /// quando nenhum símbolo cobre o endereço.
    pub fn describe(&self, address: u64) -> String {
        let Some(module) = self.module_at(address) else { return format!("{address:#x}") };
        let index = module.symbols.partition_point(|symbol| symbol.address <= address);
        // O último símbolo de função que contém o endereço (ou o mais próximo
        // antes dele, sem tamanho conhecido, na mesma função da .pdata).
        let found = module.symbols[..index].iter().rev().take(64).find(|symbol| symbol.function && Self::covers(module, symbol, address)).or_else(|| module.symbols[..index].last().filter(|symbol| Self::covers(module, symbol, address)));
        let prefix = self.prefix(module);
        match found {
            Some(symbol) if address == symbol.address => format!("{prefix}{}", symbol.name),
            Some(symbol) => format!("{prefix}{}+{:#x}", symbol.name, address - symbol.address),
            None => format!("{}+{:#x}", module.name, address - module.base),
        }
    }

    /// Um endereço de retorno: o símbolo da instrução de chamada (o byte
    /// anterior), com o deslocamento do próprio endereço.
    pub fn describe_return(&self, address: u64) -> String {
        let before = self.describe(address.wrapping_sub(1));
        match before.rsplit_once("+0x") {
            Some((name, offset)) => match u64::from_str_radix(offset, 16) {
                Ok(offset) => format!("{name}+{:#x}", offset + 1),
                Err(_) => before,
            },
            None if before.starts_with("0x") => format!("{address:#x}"),
            None => format!("{before}+0x1"),
        }
    }

    /// Endereço de um nome: `módulo!símbolo`, o nome completo, o nome sem os
    /// argumentos genéricos ou o fim do caminho (`::nome`).
    pub fn lookup(&self, query: &str) -> Result<u64, String> {
        if let Some((module, name)) = query.split_once('!') {
            let module = self.module_named(module).ok_or_else(|| format!("modulo {module} nao carregado"))?;
            if let Some(symbol) = module.symbols.iter().find(|symbol| symbol.name == name) {
                return Ok(symbol.address);
            }
            // `ksecdd!$entry`: o ponto de entrada.
            if name == "$entry" {
                if let Some(image) = &module.image {
                    return Ok(module.base + image.header.entry_point as u64);
                }
            }
            return Err(format!("{query}: simbolo nao encontrado"));
        }
        let all = || self.modules.iter().flat_map(|module| module.symbols.iter());
        let pick = |matches: Vec<&Symbol>| -> Option<Result<u64, String>> {
            if matches.is_empty() {
                return None;
            }
            let functions: Vec<&&Symbol> = matches.iter().filter(|symbol| symbol.function).collect();
            let chosen: Vec<&Symbol> = if functions.is_empty() { matches.clone() } else { functions.into_iter().copied().collect() };
            let mut addresses: Vec<u64> = chosen.iter().map(|symbol| symbol.address).collect();
            addresses.sort_unstable();
            addresses.dedup();
            if addresses.len() == 1 {
                return Some(Ok(addresses[0]));
            }
            let names: Vec<String> = chosen.iter().take(6).map(|symbol| format!("{} ({:#x})", symbol.name, symbol.address)).collect();
            Some(Err(format!("{query}: ambiguo entre {}", names.join(", "))))
        };
        if let Some(result) = pick(all().filter(|symbol| symbol.name == query).collect()) {
            return result;
        }
        if let Some(result) = pick(all().filter(|symbol| without_generics(&symbol.name) == query).collect()) {
            return result;
        }
        let suffix = format!("::{query}");
        if let Some(result) = pick(all().filter(|symbol| symbol.name.ends_with(&suffix) || without_generics(&symbol.name).ends_with(&suffix)).collect()) {
            return result;
        }
        Err(format!("{query}: simbolo nao encontrado"))
    }

    /// Nomes que começam com o texto (o autocompletar): `módulo!` restringe
    /// ao módulo.
    pub fn complete(&self, prefix: &str, limit: usize) -> Vec<String> {
        let mut found = Vec::new();
        if let Some((module_name, name)) = prefix.split_once('!') {
            if let Some(module) = self.module_named(module_name) {
                for symbol in &module.symbols {
                    if symbol.name.starts_with(name) {
                        found.push(format!("{}!{}", module.name, symbol.name));
                        if found.len() >= limit {
                            break;
                        }
                    }
                }
            }
        } else {
            for module in &self.modules {
                if module.name.to_ascii_lowercase().starts_with(&prefix.to_ascii_lowercase()) {
                    found.push(format!("{}!", module.name));
                }
            }
            for symbol in self.modules.iter().flat_map(|module| module.symbols.iter()) {
                if found.len() >= limit {
                    break;
                }
                if symbol.name.starts_with(prefix) {
                    found.push(symbol.name.clone());
                }
            }
        }
        found.sort();
        found.dedup();
        found.truncate(limit);
        found
    }
}

fn without_generics(name: &str) -> String {
    let mut depth = 0;
    let mut output = String::new();
    for character in name.chars() {
        match character {
            '<' => depth += 1,
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => output.push(character),
            _ => {}
        }
    }
    output.replace("::::", "::").trim_end_matches("::").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol(address: u64, size: u64, name: &str) -> Symbol {
        Symbol { address, size, name: name.into(), function: true }
    }

    fn sample() -> Symbols {
        let mut symbols = Symbols { store: Some(SymbolStore::offline(PathBuf::from("."))), ..Default::default() };
        symbols.set_kernel(Module::new(
            "kernel",
            "build/kernel.elf",
            0xfffff800_40000000,
            0xfffff800_41000000,
            vec![
                symbol(0xfffff800_40001000, 0x100, "kernel::ntos::init::main::kmain"),
                symbol(0xfffff800_40002000, 0x80, "kernel::ntos::ke::run_kernel_tasks"),
                symbol(0xfffff800_40003000, 0x40, "<kernel::ntos::io::Irp as core::fmt::Debug>::fmt"),
                symbol(0xfffff800_40004000, 0x40, "kernel::ntos::ps::create<u64>"),
            ],
            "teste",
        ));
        // Exports sem tamanho.
        symbols.add_module(Module::new(
            r"\SystemRoot\System32\Drivers\ksecdd.sys",
            r"\SystemRoot\System32\Drivers\ksecdd.sys",
            0xfffff800_42000000,
            0xfffff800_42010000,
            vec![symbol(0xfffff800_42001000, 0, "SspiInitAsyncInterface"), symbol(0xfffff800_42002000, 0, "KSecRegisterSecurityProvider")],
            "teste",
        ));
        symbols
    }

    #[test]
    fn describes_addresses() {
        let symbols = sample();
        assert_eq!(symbols.describe(0xfffff800_40002000), "kernel::ntos::ke::run_kernel_tasks");
        assert_eq!(symbols.describe(0xfffff800_40002010), "kernel::ntos::ke::run_kernel_tasks+0x10");
        // Depois do fim da função (tamanho conhecido): só módulo+RVA.
        assert_eq!(symbols.describe(0xfffff800_40002100), "kernel+0x2100");
        assert_eq!(symbols.describe(0xfffff800_42001004), "ksecdd!SspiInitAsyncInterface+0x4");
        assert_eq!(symbols.describe(0x1234), "0x1234");
        assert_eq!(symbols.name_at(0xfffff800_40002100), None);
        assert_eq!(symbols.name_at(0xfffff800_40001008).as_deref(), Some("kernel::ntos::init::main::kmain+0x8"));
    }

    #[test]
    fn return_addresses_use_the_call_byte() {
        let symbols = sample();
        // Um retorno logo depois do fim da função (chamada que não volta)
        // ainda é da função que chamou.
        assert_eq!(symbols.describe_return(0xfffff800_40001100), "kernel::ntos::init::main::kmain+0x100");
        assert_eq!(symbols.describe_return(0xfffff800_40001005), "kernel::ntos::init::main::kmain+0x5");
        assert_eq!(symbols.describe_return(0x1234), "0x1234");
    }

    #[test]
    fn looks_up_names() {
        let symbols = sample();
        assert_eq!(symbols.lookup("kernel::ntos::ke::run_kernel_tasks"), Ok(0xfffff800_40002000));
        assert_eq!(symbols.lookup("run_kernel_tasks"), Ok(0xfffff800_40002000));
        assert_eq!(symbols.lookup("kernel::ntos::ps::create"), Ok(0xfffff800_40004000));
        assert_eq!(symbols.lookup("ksecdd!SspiInitAsyncInterface"), Ok(0xfffff800_42001000));
        assert_eq!(symbols.lookup("ksecdd.sys!KSecRegisterSecurityProvider"), Ok(0xfffff800_42002000));
        assert_eq!(symbols.lookup("nt!kernel::ntos::ke::run_kernel_tasks"), Ok(0xfffff800_40002000));
        assert!(symbols.lookup("nada!x").is_err());
        assert!(symbols.lookup("inexistente").is_err());
        assert_eq!(symbols.complete("ksecdd!Ss", 5), vec!["ksecdd!SspiInitAsyncInterface".to_string()]);
        assert_eq!(symbols.complete("kse", 5), vec!["ksecdd!".to_string()]);
    }

    #[test]
    fn functions_and_generation() {
        let mut symbols = sample();
        assert_eq!(symbols.function_at(0xfffff800_40002040), Some((0xfffff800_40002000, "kernel::ntos::ke::run_kernel_tasks".into())));
        assert_eq!(symbols.function_at(0xfffff800_42001800), Some((0xfffff800_42001000, "ksecdd!SspiInitAsyncInterface".into())));
        let generation = symbols.generation;
        // A mesma lista não muda a geração; um módulo a menos muda.
        let list = vec![(0xfffff800_42000000, 0xfffff800_42010000, r"\SystemRoot\System32\Drivers\ksecdd.sys".to_string())];
        symbols.set_modules(&list, Path::new("."));
        assert_eq!(symbols.generation, generation);
        symbols.set_modules(&[], Path::new("."));
        assert_eq!(symbols.generation, generation + 1);
        assert_eq!(symbols.modules.len(), 1);
    }

    #[test]
    fn exports_cover_only_their_pdata_function() {
        use super::super::pe::RuntimeFunction;
        let base = 0xfffff800_43000000;
        let mut module = Module::new(r"\SystemRoot\System32\drivers\pci.sys", r"\SystemRoot\System32\drivers\pci.sys", base, base + 0x20000, vec![symbol(base + 0x1000, 0, "PciExport")], "teste");
        let functions = vec![RuntimeFunction { begin: 0x1000, end: 0x1040, unwind: 0 }, RuntimeFunction { begin: 0xf800, end: 0xf900, unwind: 0 }];
        module.unwind = Some(Arc::new(FunctionTable { base, functions, image: None }));
        let mut symbols = Symbols::default();
        symbols.add_module(module);
        assert_eq!(symbols.describe(base + 0x1010), "pci!PciExport+0x10");
        // Numa função da .pdata sem export: módulo+RVA.
        assert_eq!(symbols.describe(base + 0xf88e), "pci+0xf88e");
        assert_eq!(symbols.describe_return(base + 0xf88e), "pci+0xf88e");
        // Sem função na .pdata para o endereço: o export mais próximo.
        assert_eq!(symbols.describe(base + 0x2000), "pci!PciExport+0x1000");
    }

    #[test]
    fn display_names() {
        assert_eq!(display_name(r"\SystemRoot\System32\Drivers\Ntfs.sys"), "Ntfs");
        assert_eq!(display_name("ntoskrnl.exe"), "ntoskrnl");
        assert_eq!(display_name("bootvid.dll"), "bootvid");
        assert_eq!(display_name("kernel"), "kernel");
        assert_eq!(display_name("x.mui"), "x.mui");
    }
}
