//! Símbolos do cliente do depurador.
//!
//! - O kernel do OpenNT: a tabela de símbolos do ELF do build
//!   (`<build>/kernel.elf`), com os nomes do Rust legíveis; o kernel roda na
//!   VA em que foi ligado, então os endereços do ELF valem como estão.
//! - Os binários da Microsoft carregados (a lista `monitor lm` do alvo e a
//!   PEB.Ldr dos processos): a tabela de exports de cada PE, a tabela de
//!   funções (`.pdata`, para a pilha) e os símbolos do PDB dele (`pdb.rs`: os
//!   públicos e, quando o PDB os tem, os procedimentos com tamanho e as
//!   linhas). O arquivo desta máquina só vale quando é a imagem carregada (o
//!   mesmo tamanho; na dúvida, a data e o checksum do cabeçalho no alvo).
//!   Sem ele, a identidade do PDB, as seções e os exports saem da memória do
//!   alvo.
//! - Os PDBs ficam no cache (`build/symbols` ou as pastas de
//!   `OPENNT_SYMBOLS`) e faltando são baixados do servidor de símbolos: o de
//!   um driver assim que o módulo aparece (no fundo da fila); o de um módulo
//!   de usuário na primeira vez que alguém usa o módulo (um endereço
//!   descrito, uma busca por nome). `refresh` junta os que chegaram; uma
//!   busca por `módulo!nome` e a pilha esperam o do módulo
//!   (`wait_module_pdb`, `wait_pdb_at`).
//!
//! Os módulos aparecem pelo nome sem extensão (`ntfs!NtfsCommonCreate+0x1a3`,
//! como no WinDbg); a busca aceita o nome com ou sem extensão, e `nt` é o
//! kernel. Um endereço que nenhum símbolo cobre sai como `módulo+0xRVA`; uma
//! parte separada (fria) de uma função, sem símbolo próprio, sai como a
//! função dona dela mais o deslocamento.
//!
//! Os módulos de usuário de um processo (a PEB.Ldr do processo escolhido ou
//! da parada) entram à parte (`set_user_modules`): a lista de módulos do
//! kernel não os apaga, e a troca de processo troca só eles. Os de outro
//! processo ficam guardados pela base e pelo caminho: voltar a ele, ou a
//! mesma DLL na mesma base em outro processo, não relê o PE nem o PDB.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::demangle::demangle;
use super::elf::{Elf, SHF_ALLOC};
use super::pdb::{self, Fetch, LineTable, PdbId, PdbSection, SymbolStore};
use super::pe::{codeview_entries, exports_in_region, find_function, rsds_record, PeImage, RuntimeFunction};
use super::unwind::{FunctionTable, UnwindInfo};

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
    /// A identidade do PDB (o RSDS do arquivo desta máquina ou do alvo).
    pub pdb_id: Option<PdbId>,
    /// As seções da imagem (o PDB dá os endereços por seção).
    pub sections: Vec<PdbSection>,
    /// De onde vieram os nomes antes do PDB (`exports de ...`, `imagem do
    /// alvo`).
    pub origin: String,
    /// As linhas de código, quando o PDB as tem.
    pub lines: Option<Arc<LineTable>>,
    /// O PDB já foi pedido (o de um módulo de usuário espera o primeiro uso).
    pdb_requested: Arc<AtomicBool>,
    /// O PDB do cache não pôde ser lido: não é relido a cada parada.
    pdb_broken: bool,
}

impl std::fmt::Debug for Module {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Module").field("name", &self.name).field("base", &format_args!("{:#x}", self.base)).field("end", &format_args!("{:#x}", self.end)).field("symbols", &self.symbols.len()).field("source", &self.source).finish()
    }
}

impl Module {
    pub fn new(name: &str, path: &str, base: u64, end: u64, symbols: Vec<Symbol>, source: &str) -> Self {
        Module {
            name: display_name(name),
            file_name: base_name(name).to_string(),
            path: path.to_string(),
            base,
            end,
            symbols,
            source: source.to_string(),
            image: None,
            unwind: None,
            pdb: None,
            pdb_pending: false,
            user: false,
            pdb_id: None,
            sections: Vec::new(),
            origin: source.to_string(),
            lines: None,
            pdb_requested: Arc::new(AtomicBool::new(false)),
            pdb_broken: false,
        }
    }

    /// O PDB já foi pedido ao cache ou ao servidor.
    pub fn pdb_requested(&self) -> bool {
        self.pdb_requested.load(Ordering::Relaxed)
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
    /// Os módulos de usuário de outros processos, pela base e pelo caminho.
    user_cache: HashMap<(u64, String), Module>,
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

/// Arredonda para a página.
fn align_page(value: u64) -> u64 {
    value.saturating_add(0xFFF) & !0xFFF
}

/// O RVA cai numa seção de código (sem seções conhecidas, sim).
fn is_code(sections: &[PdbSection], rva: u32) -> bool {
    match sections.iter().filter(|section| section.address <= rva).max_by_key(|section| section.address) {
        Some(section) => section.code,
        None => sections.is_empty(),
    }
}

/// Em ordem de endereço; o mesmo nome no mesmo endereço fica uma vez (o que
/// tem tamanho, se um deles tem).
fn sort_symbols(symbols: &mut Vec<Symbol>) {
    symbols.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.name.cmp(&b.name)).then_with(|| b.size.cmp(&a.size)));
    symbols.dedup_by(|later, earlier| later.address == earlier.address && later.name == earlier.name);
}

/// O que o depurador lê de uma imagem na memória do alvo.
struct TargetImage {
    stamp: u32,
    size: u32,
    checksum: u32,
    sections: Vec<PdbSection>,
    id: Option<PdbId>,
    exports: Vec<(u32, String)>,
}

impl TargetImage {
    /// O cabeçalho (com as seções), o RSDS e os exports da imagem em
    /// `base`, lidos do alvo.
    fn read(base: u64, read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>) -> Option<Self> {
        let image = read(base, 0x400).and_then(PeImage::parse_mapped).or_else(|| read(base, 0x1000).and_then(PeImage::parse_mapped))?;
        let mut id = None;
        if let Some((rva, size)) = image.directory(6).filter(|&(rva, size)| rva != 0 && size != 0) {
            if let Some(directory) = read(base + rva as u64, (size as usize).min(28 * 16)) {
                for (data, length) in codeview_entries(&directory) {
                    if let Some((guid, age, name)) = read(base + data as u64, (length as usize).clamp(24, 0x200)).as_deref().and_then(rsds_record) {
                        id = Some(PdbId::new(&name, guid, age)).filter(|id| !id.name.is_empty());
                        break;
                    }
                }
            }
        }
        let exports = match image.directory(0) {
            Some((rva, size)) if rva != 0 && size != 0 && size <= 0x10_0000 => read(base + rva as u64, size as usize).map(|region| exports_in_region(&region, rva)).unwrap_or_default(),
            _ => Vec::new(),
        };
        Some(Self { stamp: image.header.time_date_stamp, size: image.header.size_of_image, checksum: image.header.checksum, sections: PdbSection::of_image(&image), id, exports })
    }

    /// O arquivo desta máquina é esta imagem (o ImageBase do cabeçalho muda
    /// com a relocação; a data, o tamanho e o checksum não).
    fn same_image(&self, image: &PeImage) -> bool {
        image.header.time_date_stamp == self.stamp && image.header.size_of_image == self.size && image.header.checksum == self.checksum
    }
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
        self.set_modules_from(list, root, &mut |_, _| None);
    }

    /// O `set_modules` com a memória do alvo (`read(endereço, tamanho)`): o
    /// cabeçalho de uma imagem sem arquivo nesta máquina, ou com um arquivo
    /// de outro tamanho, sai dela.
    pub fn set_modules_from(&mut self, list: &[(u64, u64, String)], root: &Path, read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>) {
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
            // Um módulo que já estava fica como está; o PDB que chegou para
            // ele entra no `refresh_modules` abaixo.
            if let Some(module) = previous.remove(&(*base, path.clone())) {
                self.modules.push(module);
                continue;
            }
            let module = self.load_module(*base, *end, path, false, &mut *read);
            self.modules.push(module);
        }
        self.modules.extend(user);
        self.refresh_modules();
        if signature(&self.modules) != before {
            self.generation += 1;
        }
    }

    /// Troca os módulos de usuário pelos do processo `process` (EPROCESS):
    /// (base, fim, caminho). Os de mesma base e caminho ficam como estão.
    pub fn set_user_modules(&mut self, process: u64, list: &[(u64, u64, String)], root: &Path) {
        self.set_user_modules_from(process, list, root, &mut |_, _| None);
    }

    /// O `set_user_modules` com a memória do alvo (veja `set_modules_from`).
    /// Os módulos do processo anterior ficam guardados para a volta.
    pub fn set_user_modules_from(&mut self, process: u64, list: &[(u64, u64, String)], root: &Path, read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>) {
        if self.store.is_none() {
            self.store = Some(SymbolStore::new(root));
        }
        let kernel = self.kernel.map(|index| (self.modules[index].base, self.modules[index].path.clone()));
        let (user, system): (Vec<Module>, Vec<Module>) = self.modules.drain(..).partition(|module| module.user);
        self.modules = system;
        self.kernel = kernel.and_then(|(base, path)| self.modules.iter().position(|module| module.base == base && module.path == path));
        for module in user {
            self.user_cache.insert((module.base, module.path.clone()), module);
        }
        for (base, end, path) in list {
            let module = match self.user_cache.remove(&(*base, path.clone())) {
                Some(module) => module,
                None => self.load_module(*base, *end, path, true, &mut *read),
            };
            self.modules.push(module);
        }
        self.refresh_modules();
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

    /// Lê o módulo: o PE desta máquina (se é a imagem carregada) ou o
    /// cabeçalho do alvo, os exports, a `.pdata` e o PDB do cache. O PDB de
    /// um driver que falta é pedido já; o de um módulo de usuário, no
    /// primeiro uso.
    fn load_module(&self, base: u64, end: u64, path: &str, user: bool, read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>) -> Module {
        let mut module = Module::new(path, path, base, end, Vec::new(), "sem simbolos");
        module.user = user;
        let host = host_file(path).and_then(|file| {
            let image = PeImage::parse(std::fs::read(&file).ok()?)?;
            Some((file, Arc::new(image)))
        });
        // O mesmo tamanho basta; senão (ou sem o arquivo) o cabeçalho do alvo
        // decide.
        let same_size = |image: &PeImage| align_page(image.header.size_of_image as u64) == align_page(end.saturating_sub(base));
        let target = match &host {
            Some((_, image)) if same_size(&**image) => None,
            _ => TargetImage::read(base, &mut *read),
        };
        let mut other_version = None;
        let host = match (host, &target) {
            (Some((file, image)), Some(target)) if !target.same_image(&image) => {
                other_version = Some(file);
                None
            }
            (host, _) => host,
        };
        let mut symbols: Vec<Symbol> = match (&host, &target) {
            (Some((file, image)), _) => {
                module.origin = format!("exports de {}", file.display());
                module.pdb_id = PdbId::of_image(image);
                module.sections = PdbSection::of_image(image);
                let functions = image.runtime_functions();
                if !functions.is_empty() {
                    module.unwind = Some(Arc::new(FunctionTable { base, functions, image: Some(Arc::clone(image)) }));
                }
                module.image = Some(Arc::clone(image));
                image.exports().into_iter().map(|(rva, name)| Symbol { address: base + rva as u64, size: 0, name, function: is_code(&module.sections, rva) }).collect()
            }
            (None, Some(target)) => {
                module.origin = match &other_version {
                    Some(file) => format!("imagem do alvo ({} e outra versao)", file.display()),
                    None => "imagem do alvo".to_string(),
                };
                module.pdb_id = target.id.clone();
                module.sections = target.sections.clone();
                target.exports.iter().map(|(rva, name)| Symbol { address: base + *rva as u64, size: 0, name: name.clone(), function: is_code(&module.sections, *rva) }).collect()
            }
            (None, None) => return module,
        };
        sort_symbols(&mut symbols);
        module.symbols = symbols;
        module.source = module.origin.clone();
        if let Some(store) = &self.store {
            Self::load_pdb(&mut module, store, !user);
        }
        module
    }

    /// Procura o PDB do módulo no cache e o junta. Sem ele, com `download`,
    /// pede o download; o texto de origem diz o estado.
    fn load_pdb(module: &mut Module, store: &SymbolStore, download: bool) {
        let Some(id) = module.pdb_id.clone() else { return };
        let found = if download {
            module.pdb_requested.store(true, Ordering::Relaxed);
            store.request(&id)
        } else {
            store.find(&id)
        };
        match found {
            Some(path) => {
                module.pdb_requested.store(true, Ordering::Relaxed);
                Self::merge_pdb(module, &path, &id);
            }
            None => Self::note_pdb_state(module, store, &id),
        }
    }

    /// A marca de pendente e o texto de origem pelo estado do download.
    fn note_pdb_state(module: &mut Module, store: &SymbolStore, id: &PdbId) {
        let state = store.state(id);
        let requested = module.pdb_requested();
        module.pdb_pending = state == Some(Fetch::Downloading);
        module.source = match state {
            Some(Fetch::Downloading) => format!("{} (baixando {})", module.origin, id.name),
            Some(Fetch::Failed(error)) => format!("{} (PDB indisponivel: {})", module.origin, error.lines().next().unwrap_or("")),
            None if !requested => format!("{} ({} pedido no primeiro uso)", module.origin, id.name),
            None if !store.download => format!("{} ({} fora do cache)", module.origin, id.name),
            None => module.origin.clone(),
        };
    }

    /// Junta os símbolos e as linhas do PDB aos do módulo.
    fn merge_pdb(module: &mut Module, path: &Path, id: &PdbId) -> bool {
        module.pdb_pending = false;
        let Some(data) = pdb::load(path, id, &module.sections) else {
            module.source = format!("{} (PDB {} ilegivel)", module.origin, path.display());
            module.pdb_broken = true;
            return false;
        };
        let base = module.base;
        module.symbols.extend(data.symbols.into_iter().map(|symbol| Symbol { address: base + symbol.rva as u64, size: symbol.size as u64, name: symbol.name, function: symbol.function }));
        sort_symbols(&mut module.symbols);
        module.lines = data.lines.map(Arc::new);
        module.pdb = Some(path.to_path_buf());
        module.source = format!("PDB {}{} + {}", path.display(), if data.private { " (privado)" } else { "" }, module.origin);
        true
    }

    /// Junta os PDBs que chegaram aos módulos que os pediram e atualiza o
    /// estado dos outros; `true` se algo mudou. Sem download novo nem disco
    /// quando nada chegou.
    fn refresh_modules(&mut self) -> bool {
        let Some(store) = self.store.clone() else { return false };
        let mut changed = false;
        for module in &mut self.modules {
            if module.pdb.is_some() || module.pdb_broken || !module.pdb_requested() {
                continue;
            }
            let Some(id) = module.pdb_id.clone() else { continue };
            let before = (module.pdb_pending, module.source.clone());
            if store.state(&id).is_none() && store.arrived(&id) {
                Self::load_pdb(module, &store, false);
            } else {
                Self::note_pdb_state(module, &store, &id);
            }
            changed |= module.pdb.is_some() || module.pdb_pending != before.0 || module.source != before.1;
        }
        changed
    }

    /// Os PDBs que chegaram desde a última vez entram nos módulos (kernel e
    /// usuário); `true` se os símbolos mudaram. Barato: só consulta a fila.
    pub fn refresh(&mut self) -> bool {
        let changed = self.refresh_modules();
        if changed {
            self.generation += 1;
        }
        changed
    }

    /// Procura de novo no disco o PDB de todo módulo que ainda está sem ele
    /// (um PDB posto no cache à mão). `everything`: esquece as falhas e pede
    /// os que faltam, inclusive os dos módulos de usuário ainda não usados;
    /// sem ele, só os já pedidos voltam à fila. Devolve quantos módulos
    /// ganharam o PDB.
    pub fn reload_pdbs(&mut self, everything: bool) -> usize {
        let Some(store) = self.store.clone() else { return 0 };
        if everything {
            store.forget_failures();
        }
        let mut loaded = 0;
        for module in &mut self.modules {
            if everything {
                module.pdb_broken = false;
            }
            if module.pdb.is_none() && module.pdb_id.is_some() && !module.pdb_broken {
                let download = everything || module.pdb_requested();
                Self::load_pdb(module, &store, download);
                loaded += module.pdb.is_some() as usize;
            }
        }
        if loaded > 0 {
            self.generation += 1;
        }
        loaded
    }

    /// Os módulos ainda sem PDB: (nome, estado) para o `.reload`.
    pub fn missing_pdbs(&self) -> Vec<(String, String)> {
        self.modules.iter().filter(|module| module.pdb.is_none() && module.pdb_id.is_some() && module.pdb_requested()).map(|module| (module.name.clone(), module.source.clone())).collect()
    }

    /// Põe com pressa (na frente da fila) o PDB do módulo do endereço, sem
    /// esperar.
    pub fn prefetch_at(&self, address: u64) {
        let Some(module) = self.module_at(address) else { return };
        if module.pdb.is_some() {
            return;
        }
        module.pdb_requested.store(true, Ordering::Relaxed);
        if let (Some(store), Some(id)) = (&self.store, &module.pdb_id) {
            if store.find(id).is_none() {
                store.enqueue(id, true);
            }
        }
    }

    /// Espera com pressa o PDB de um módulo (pelo nome) que ainda não o tem;
    /// `true` se os símbolos mudaram.
    pub fn wait_module_pdb(&mut self, name: &str) -> bool {
        match self.module_index(name) {
            Some(index) => self.wait_pdb_of(index),
            None => false,
        }
    }

    /// Espera com pressa o PDB do módulo de um endereço.
    pub fn wait_pdb_at(&mut self, address: u64) -> bool {
        match self.modules.iter().position(|module| address >= module.base && address < module.end) {
            Some(index) => self.wait_pdb_of(index),
            None => false,
        }
    }

    fn wait_pdb_of(&mut self, index: usize) -> bool {
        let Some(store) = self.store.clone() else { return false };
        let module = &mut self.modules[index];
        let Some(id) = module.pdb_id.clone() else { return false };
        if module.pdb.is_some() || module.pdb_broken {
            return false;
        }
        module.pdb_requested.store(true, Ordering::Relaxed);
        match store.fetch_now(&id, store.wait) {
            Some(path) => {
                Self::merge_pdb(module, &path, &id);
                self.generation += 1;
                true
            }
            None => {
                Self::note_pdb_state(module, &store, &id);
                false
            }
        }
    }

    /// O primeiro uso de um módulo pede o PDB dele (no fundo da fila).
    fn touch(&self, module: &Module) {
        if module.pdb.is_some() || module.pdb_requested.swap(true, Ordering::Relaxed) {
            return;
        }
        if let (Some(store), Some(id)) = (&self.store, &module.pdb_id) {
            store.enqueue(id, false);
        }
    }

    pub fn module_at(&self, address: u64) -> Option<&Module> {
        self.modules.iter().find(|module| address >= module.base && address < module.end)
    }

    fn module_index(&self, name: &str) -> Option<usize> {
        let wanted = name.to_ascii_lowercase();
        if wanted == "nt" || wanted == "kernel" {
            if let Some(index) = self.kernel {
                return Some(index);
            }
        }
        self.modules.iter().position(|module| module.name.to_ascii_lowercase() == wanted || module.file_name.to_ascii_lowercase() == wanted)
    }

    /// Um módulo pelo nome (com ou sem extensão, sem diferença de caixa;
    /// `nt` e `kernel` são o kernel).
    pub fn module_named(&self, name: &str) -> Option<&Module> {
        self.module_index(name).map(|index| &self.modules[index])
    }

    fn prefix(&self, module: &Module) -> String {
        if self.is_kernel(module) {
            String::new()
        } else {
            format!("{}!", module.name)
        }
    }

    /// O símbolo de função que começa exatamente em `address`.
    fn symbol_starting_at(module: &Module, address: u64) -> Option<&Symbol> {
        let index = module.symbols.partition_point(|symbol| symbol.address < address);
        module.symbols[index..].iter().take_while(|symbol| symbol.address == address).find(|symbol| symbol.function)
    }

    /// A função dona de uma parte separada do código (a entrada da `.pdata`
    /// do endereço é encadeada, UNW_FLAG_CHAININFO, ou aponta outra entrada
    /// pelo bit 0). Só com o arquivo desta máquina (os UNWIND_INFO saem
    /// dele).
    fn primary_function(module: &Module, rva: u32) -> Option<RuntimeFunction> {
        let table = module.unwind.as_ref()?;
        let image = table.image.as_ref()?;
        let mut function = find_function(&table.functions, rva)?;
        let mut chained = false;
        for _ in 0..8 {
            let parent = if function.unwind & 1 != 0 {
                let entry = image.bytes_at(function.unwind & !1, 12)?;
                Some(RuntimeFunction { begin: u32::from_le_bytes(entry.get(0..4)?.try_into().ok()?), end: u32::from_le_bytes(entry.get(4..8)?.try_into().ok()?), unwind: u32::from_le_bytes(entry.get(8..12)?.try_into().ok()?) })
            } else {
                let count = *image.bytes_at(function.unwind, 4)?.get(2)? as usize;
                UnwindInfo::parse(image.bytes_at(function.unwind, UnwindInfo::size(count))?)?.chained
            };
            match parent {
                Some(parent) if parent.begin != function.begin => {
                    function = parent;
                    chained = true;
                }
                _ => break,
            }
        }
        chained.then_some(function)
    }

    /// O símbolo da função dona quando o endereço cai numa parte separada
    /// (fria) sem símbolo próprio.
    fn fragment_symbol(module: &Module, address: u64) -> Option<&Symbol> {
        let rva = u32::try_from(address - module.base).ok()?;
        let table = module.unwind.as_ref()?;
        let own = find_function(&table.functions, rva)?;
        if Self::symbol_starting_at(module, module.base + own.begin as u64).is_some() {
            return None;
        }
        let primary = Self::primary_function(module, rva)?;
        let start = module.base + primary.begin as u64;
        if start > address {
            return None;
        }
        Self::symbol_starting_at(module, start)
    }

    /// O símbolo de função que contém o endereço (ou o mais próximo antes
    /// dele, quando o tamanho não é conhecido): o começo e o nome
    /// (`módulo!nome` fora do kernel). Numa parte fria, a função dona.
    pub fn function_at(&self, address: u64) -> Option<(u64, String)> {
        let module = self.module_at(address)?;
        self.touch(module);
        if let Some(symbol) = Self::fragment_symbol(module, address) {
            return Some((symbol.address, format!("{}{}", self.prefix(module), symbol.name)));
        }
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

    /// `arquivo:linha` do código no endereço, quando o PDB do módulo tem
    /// linhas.
    pub fn line_at(&self, address: u64) -> Option<String> {
        let module = self.module_at(address)?;
        let lines = module.lines.as_ref()?;
        let (file, line) = lines.at(u32::try_from(address - module.base).ok()?)?;
        Some(format!("{file}:{line}"))
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
    /// quando nenhum símbolo cobre o endereço. Uma parte fria sem símbolo
    /// próprio sai como a função dona mais o deslocamento.
    pub fn describe(&self, address: u64) -> String {
        let Some(module) = self.module_at(address) else { return format!("{address:#x}") };
        self.touch(module);
        let prefix = self.prefix(module);
        if let Some(symbol) = Self::fragment_symbol(module, address) {
            return format!("{prefix}{}+{:#x}", symbol.name, address - symbol.address);
        }
        let index = module.symbols.partition_point(|symbol| symbol.address <= address);
        // O último símbolo de função que contém o endereço (ou o mais próximo
        // antes dele, sem tamanho conhecido, na mesma função da .pdata).
        let found = module.symbols[..index].iter().rev().take(64).find(|symbol| symbol.function && Self::covers(module, symbol, address)).or_else(|| module.symbols[..index].last().filter(|symbol| Self::covers(module, symbol, address)));
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

    /// Por que um nome não está num módulo (o estado do PDB dele).
    fn pdb_hint(module: &Module) -> String {
        if module.pdb.is_some() || (module.pdb_id.is_none() && module.image.is_none() && module.sections.is_empty()) {
            return String::new();
        }
        if module.pdb_pending {
            return format!(" (o PDB de {} ainda esta chegando; .reload /w espera)", module.name);
        }
        format!(" ({}: {})", module.name, module.source)
    }

    /// Endereço de um nome: `módulo!símbolo`, o nome completo, o nome sem os
    /// argumentos genéricos ou o fim do caminho (`::nome`).
    pub fn lookup(&self, query: &str) -> Result<u64, String> {
        if let Some((module, name)) = query.split_once('!') {
            let module = self.module_named(module).ok_or_else(|| format!("modulo {module} nao carregado"))?;
            self.touch(module);
            if let Some(symbol) = module.symbols.iter().find(|symbol| symbol.name == name) {
                return Ok(symbol.address);
            }
            // `ksecdd!$entry`: o ponto de entrada.
            if name == "$entry" {
                if let Some(image) = &module.image {
                    return Ok(module.base + image.header.entry_point as u64);
                }
            }
            return Err(format!("{query}: simbolo nao encontrado{}", Self::pdb_hint(module)));
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

    /// Os símbolos que casam com um padrão com `*` e `?` (`módulo!padrão`,
    /// o módulo também com curingas; sem `!`, todos os módulos): endereço e
    /// nome completo, em ordem de endereço, no máximo `limit`.
    pub fn search(&self, pattern: &str, limit: usize) -> Vec<(u64, String)> {
        let (module_pattern, name_pattern) = pattern.split_once('!').map_or(("*", pattern), |(module, name)| (module, name));
        let module_pattern = module_pattern.to_ascii_lowercase();
        let mut found = Vec::new();
        for module in &self.modules {
            let kernel_alias = self.is_kernel(module) && (module_pattern == "nt" || module_pattern == "kernel");
            if !kernel_alias && !wildcard_match(&module_pattern, &module.name.to_ascii_lowercase()) && !wildcard_match(&module_pattern, &module.file_name.to_ascii_lowercase()) {
                continue;
            }
            if pattern.contains('!') {
                self.touch(module);
            }
            for symbol in module.symbols.iter().filter(|symbol| wildcard_match(name_pattern, &symbol.name)) {
                if found.len() >= limit {
                    break;
                }
                found.push((symbol.address, format!("{}{}", self.prefix(module), symbol.name)));
            }
        }
        found.sort();
        found.dedup();
        found
    }

    /// Nomes que começam com o texto (o autocompletar): `módulo!` restringe
    /// ao módulo.
    pub fn complete(&self, prefix: &str, limit: usize) -> Vec<String> {
        let mut found = Vec::new();
        if let Some((module_name, name)) = prefix.split_once('!') {
            if let Some(module) = self.module_named(module_name) {
                self.touch(module);
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

/// `*` (qualquer sequência) e `?` (um caractere).
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
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
        assert!(symbols.lookup("nada!x").unwrap_err().contains("nao carregado"));
        assert!(symbols.lookup("ksecdd!Falta").unwrap_err().contains("nao encontrado"));
        assert!(symbols.lookup("inexistente").is_err());
        assert_eq!(symbols.complete("ksecdd!Ss", 5), vec!["ksecdd!SspiInitAsyncInterface".to_string()]);
        assert_eq!(symbols.complete("kse", 5), vec!["ksecdd!".to_string()]);
    }

    #[test]
    fn searches_with_wildcards() {
        let symbols = sample();
        assert_eq!(symbols.search("ksecdd!*Security*", 10), vec![(0xfffff800_42002000, "ksecdd!KSecRegisterSecurityProvider".to_string())]);
        assert_eq!(symbols.search("nt!*run_kernel?tasks", 10), vec![(0xfffff800_40002000, "kernel::ntos::ke::run_kernel_tasks".to_string())]);
        assert_eq!(symbols.search("k*!Sspi*", 10).len(), 1);
        assert_eq!(symbols.search("*", 3).len(), 3);
        assert!(wildcard_match("a*b?d", "aXXbcd"));
        assert!(!wildcard_match("a*b?d", "aXXbd"));
        assert!(wildcard_match("*", ""));
        assert!(!wildcard_match("", "x"));
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
    fn cold_fragments_belong_to_their_function() {
        use super::super::pe::tests::tiny_pe;
        // .pdata: a função em 0x1000 e a parte fria dela em 0x1100, com o
        // UNWIND_INFO encadeado (flags 4) apontando a função principal.
        let pdata = [RuntimeFunction { begin: 0x1000, end: 0x1040, unwind: 0x2018 }, RuntimeFunction { begin: 0x1100, end: 0x1180, unwind: 0x2020 }];
        let mut rdata = vec![0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0];
        rdata.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
        rdata.extend_from_slice(&0x1000u32.to_le_bytes());
        rdata.extend_from_slice(&0x1040u32.to_le_bytes());
        rdata.extend_from_slice(&0x2018u32.to_le_bytes());
        let image = Arc::new(PeImage::parse(tiny_pe(&pdata, &rdata, false)).unwrap());
        let base = 0x7ff6_0000_0000;
        let mut module = Module::new("teste.dll", r"C:\Windows\System32\teste.dll", base, base + 0x3000, vec![symbol(base + 0x1000, 0, "Funcao"), symbol(base + 0x1090, 0, "Outra")], "teste");
        module.unwind = Some(Arc::new(FunctionTable { base, functions: image.runtime_functions(), image: Some(Arc::clone(&image)) }));
        module.pdb = Some(PathBuf::from("teste.pdb"));
        let mut symbols = Symbols::default();
        symbols.add_module(module);
        // Sem a regra da parte fria, o símbolo mais próximo (Outra) levaria.
        assert_eq!(symbols.describe(base + 0x1120), "teste!Funcao+0x120");
        assert_eq!(symbols.function_at(base + 0x1120), Some((base + 0x1000, "teste!Funcao".into())));
        assert_eq!(symbols.describe(base + 0x1010), "teste!Funcao+0x10");
        assert_eq!(symbols.describe(base + 0x10a0), "teste!Outra+0x10");
    }

    #[test]
    fn user_modules_are_kept_per_process() {
        let mut symbols = sample();
        let list = vec![(0x7ffa_0000_0000, 0x7ffa_0001_0000, r"C:\OpenNT\naoexiste\kd_teste_um.dll".to_string()), (0x7ffb_0000_0000, 0x7ffb_0001_0000, r"C:\OpenNT\naoexiste\kd_teste_dois.dll".to_string())];
        symbols.set_user_modules(0x1000, &list, Path::new("."));
        assert_eq!(symbols.user_modules().count(), 2);
        assert!(symbols.module_named("kd_teste_um").is_some_and(|module| module.user));
        // Outro processo com só a segunda DLL: a primeira sai, mas fica
        // guardada para a volta.
        symbols.set_user_modules(0x2000, &list[1..], Path::new("."));
        assert_eq!(symbols.user_modules().count(), 1);
        assert!(symbols.module_named("kd_teste_um").is_none());
        symbols.set_user_modules(0x1000, &list, Path::new("."));
        assert_eq!(symbols.user_modules().count(), 2);
        // Os módulos do kernel continuam.
        assert!(symbols.module_named("ksecdd").is_some());
        assert!(symbols.kernel().is_some());
    }

    #[test]
    fn modules_from_target_memory() {
        // Uma imagem que não existe nesta máquina: o cabeçalho, as seções e os
        // exports saem da memória do alvo.
        use super::super::pe::tests::tiny_pe;
        let mut mapped = tiny_pe(&[], &[], true);
        // Na imagem mapeada o RVA é o offset: a .rdata (arquivo 0x600) vai
        // para 0x2000.
        mapped.resize(0x3000, 0);
        let rdata: Vec<u8> = mapped[0x600..0x800].to_vec();
        mapped[0x2000..0x2200].copy_from_slice(&rdata);
        let base = 0xfffff800_44000000u64;
        let mut read = |address: u64, length: usize| -> Option<Vec<u8>> {
            let start = usize::try_from(address.checked_sub(base)?).ok()?;
            mapped.get(start..(start + length).min(mapped.len())).map(<[u8]>::to_vec)
        };
        let mut symbols = Symbols { store: Some(SymbolStore::offline(PathBuf::from("."))), ..Default::default() };
        symbols.set_modules_from(&[(base, base + 0x3000, r"\SystemRoot\System32\drivers\naoexiste_kd.sys".to_string())], Path::new("."), &mut read);
        let module = symbols.module_named("naoexiste_kd").unwrap();
        assert_eq!(module.origin, "imagem do alvo");
        assert_eq!(module.sections.len(), 2);
        assert!(!module.sections[0].code);
        assert_eq!(symbols.lookup("naoexiste_kd!Funcao"), Ok(base + 0x1010));
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
