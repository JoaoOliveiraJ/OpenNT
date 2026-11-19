//! Os nomes de `módulo+RVA` para a análise de um log, sem o alvo.
//!
//! O log só tem nomes de módulo e deslocamentos (e os exports que o kernel
//! achou). Os nomes vêm das mesmas tabelas do depurador ([`Symbols`]): os
//! exports e a `.pdata` do arquivo desta máquina e os públicos do PDB do
//! servidor de símbolos (o cache `build/symbols`); o `ntoskrnl.exe` do log é
//! o kernel do OpenNT, com os símbolos do `kernel.elf` do build na ImageBase
//! do PE do kernel. Cada módulo ganha uma base própria nas tabelas (uma
//! faixa fora das VAs reais), então só a RVA importa.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::pdb::SymbolStore;
use crate::pe::PeImage;
use crate::symbols::{host_file, Symbols};

/// Os nomes de `módulo+RVA`.
pub trait ModuleSymbols {
    /// O nome (`Funcao+0x10`, sem o módulo) de `rva` em `module` (o nome
    /// do arquivo, como o log o escreve). `return_address`: o endereço é um
    /// retorno, e o nome é o da instrução de chamada (o byte anterior).
    fn name(&self, module: &str, rva: u64, return_address: bool) -> Option<String>;
}

/// Nenhum nome além dos que o log já traz.
pub struct NoSymbols;

impl ModuleSymbols for NoSymbols {
    fn name(&self, _module: &str, _rva: u64, _return_address: bool) -> Option<String> {
        None
    }
}

/// O nome do kernel no log: o `ntoskrnl.exe` da lista de módulos é a imagem
/// do kernel do OpenNT.
pub fn is_opennt_kernel(module: &str) -> bool {
    matches!(module.to_ascii_lowercase().as_str(), "ntoskrnl.exe" | "ntkrnlmp.exe")
}

/// Um módulo a carregar: o nome do arquivo, o caminho como o log o escreve
/// e o tamanho da imagem, quando o log o diz.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleRef {
    pub name: String,
    pub path: String,
    pub size: Option<u64>,
}

/// Onde as tabelas põem os módulos: faixas de 256 MB a partir daqui, longe
/// do kernel (0xFFFFF800_40000000) e das imagens reais.
const SYNTHETIC_BASE: u64 = 0xFFFF_E000_0000_0000;
const SYNTHETIC_SPAN: u64 = 0x1000_0000;

/// O nome de `address` nas tabelas, sem o prefixo do módulo; `None` quando
/// só há o `módulo+RVA`.
pub fn symbol_name(symbols: &Symbols, address: u64, return_address: bool) -> Option<String> {
    let module = symbols.module_at(address)?;
    let text = if return_address { symbols.describe_return(address) } else { symbols.describe(address) };
    if text.starts_with("0x") || text.starts_with(&format!("{}+0x", module.name)) {
        return None;
    }
    let prefix = format!("{}!", module.name);
    Some(text.strip_prefix(prefix.as_str()).unwrap_or(&text).to_string())
}

/// O SizeOfImage do arquivo desta máquina.
fn image_size(path: &str) -> Option<u64> {
    let file = host_file(path)?;
    Some(PeImage::parse(std::fs::read(file).ok()?)?.header.size_of_image as u64)
}

/// Um driver do repositório de drivers (o BasicDisplay.sys, o E1G6032E.sys)
/// quando o log só traz o nome.
fn driver_store_file(name: &str) -> Option<PathBuf> {
    let repository = Path::new(r"C:\Windows\System32\DriverStore\FileRepository");
    std::fs::read_dir(repository).ok()?.filter_map(Result::ok).map(|entry| entry.path().join(name)).find(|candidate| candidate.is_file())
}

/// As tabelas de nomes dos módulos de um log.
pub struct LogSymbolizer {
    symbols: Symbols,
    root: PathBuf,
    list: Vec<(u64, u64, String)>,
    bases: HashMap<String, u64>,
    /// A ImageBase do PE do kernel, quando o `kernel.elf` foi lido.
    kernel_base: Option<u64>,
    /// Avisos (arquivo que falta, kernel.elf ilegível).
    pub notes: Vec<String>,
}

impl LogSymbolizer {
    /// `root`: a raiz do repositório (o cache de PDBs); `kernel`: o
    /// `kernel.elf` do build e a ImageBase do PE do kernel; `download`: os
    /// PDBs que faltam no cache são baixados (em segundo plano, ver
    /// [`Self::wait_for_pdbs`]).
    pub fn new(root: &Path, kernel: Option<(&Path, u64)>, modules: &[ModuleRef], download: bool) -> Self {
        let mut symbols = Symbols::default();
        let mut notes = Vec::new();
        let mut store = SymbolStore::new(root);
        store.download &= download;
        symbols.store = Some(store);
        let kernel_base = match kernel {
            Some((elf, base)) => match symbols.load_kernel(elf) {
                Ok(_) => Some(base),
                Err(error) => {
                    notes.push(format!("sem os simbolos do kernel do OpenNT: {error}"));
                    None
                }
            },
            None => None,
        };
        let mut list = Vec::new();
        let mut bases = HashMap::new();
        for module in modules {
            let key = module.name.to_ascii_lowercase();
            if key.is_empty() || is_opennt_kernel(&key) || bases.contains_key(&key) {
                continue;
            }
            let path = if host_file(&module.path).is_some() { module.path.clone() } else { driver_store_file(&module.name).map_or_else(|| module.path.clone(), |file| file.display().to_string()) };
            if host_file(&path).is_none() {
                notes.push(format!("{}: arquivo nao encontrado nesta maquina (sem nomes)", module.name));
            }
            let size = module.size.filter(|&size| size > 0).or_else(|| image_size(&path)).unwrap_or(SYNTHETIC_SPAN).min(SYNTHETIC_SPAN);
            let base = SYNTHETIC_BASE + SYNTHETIC_SPAN * list.len() as u64;
            bases.insert(key, base);
            list.push((base, base + size, path));
        }
        symbols.set_modules(&list, root);
        Self { symbols, root: root.to_path_buf(), list, bases, kernel_base, notes }
    }

    fn busy(&self) -> bool {
        self.symbols.store.as_ref().is_some_and(SymbolStore::busy)
    }

    /// Algum PDB ainda está chegando.
    pub fn pending(&self) -> bool {
        self.symbols.pending()
    }

    /// Espera os downloads de PDB (até `timeout`) e recarrega os módulos
    /// que os esperavam. Verdadeiro quando nada ficou pendente.
    pub fn wait_for_pdbs(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while self.symbols.pending() && self.busy() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
        if self.symbols.pending() && !self.busy() {
            let list = self.list.clone();
            self.symbols.set_modules(&list, &self.root);
        }
        !self.symbols.pending()
    }

    /// De onde vêm os nomes de cada módulo, em uma linha.
    pub fn sources(&self) -> String {
        let names: Vec<String> = self
            .symbols
            .modules
            .iter()
            .map(|module| {
                let kind = if self.symbols.is_kernel(module) {
                    "kernel.elf"
                } else if module.pdb.is_some() {
                    "PDB"
                } else if module.pdb_pending {
                    "PDB baixando"
                } else if module.image.is_some() {
                    "so exports"
                } else {
                    "sem arquivo"
                };
                format!("{} ({kind})", module.name)
            })
            .collect();
        names.join(", ")
    }
}

impl ModuleSymbols for LogSymbolizer {
    fn name(&self, module: &str, rva: u64, return_address: bool) -> Option<String> {
        let address = if is_opennt_kernel(module) { self.kernel_base?.checked_add(rva)? } else { self.bases.get(&module.to_ascii_lowercase())?.checked_add(rva)? };
        symbol_name(&self.symbols, address, return_address)
    }
}

/// Uma tabela fixa de nomes (os testes): (módulo, RVA do começo, nome); um
/// nome cobre até 0x1000 bytes.
#[cfg(test)]
pub(crate) struct Table(Vec<(String, u64, String)>);

#[cfg(test)]
impl Table {
    pub(crate) fn new(entries: &[(&str, u64, &str)]) -> Self {
        Table(entries.iter().map(|(module, start, name)| (module.to_string(), *start, name.to_string())).collect())
    }
}

#[cfg(test)]
impl ModuleSymbols for Table {
    fn name(&self, module: &str, rva: u64, return_address: bool) -> Option<String> {
        let probe = if return_address { rva.checked_sub(1)? } else { rva };
        self.0
            .iter()
            .filter(|(owner, start, _)| owner.eq_ignore_ascii_case(module) && *start <= probe && probe - *start < 0x1000)
            .max_by_key(|(_, start, _)| *start)
            .map(|(_, start, name)| if rva == *start { name.clone() } else { format!("{name}+{:#x}", rva - start) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::{Module, Symbol};

    fn symbol(address: u64, size: u64, name: &str) -> Symbol {
        Symbol { address, size, name: name.into(), function: true }
    }

    #[test]
    fn names_come_from_the_tables_without_the_module_prefix() {
        let mut symbols = Symbols::default();
        symbols.set_kernel(Module::new("kernel", "build/kernel.elf", 0xfffff800_40001000, 0xfffff800_41000000, vec![symbol(0xfffff800_4047af00, 0x100, "kernel::ntos::ps::thread_callout")], "teste"));
        let base = SYNTHETIC_BASE;
        symbols.add_module(Module::new("win32kfull.sys", "win32kfull.sys", base, base + 0x3b4000, vec![symbol(base + 0xe9620, 0, "xxxDwmStopRedirection")], "teste"));
        let bases = HashMap::from([("win32kfull.sys".to_string(), base)]);
        let symbolizer = LogSymbolizer { symbols, root: PathBuf::new(), list: Vec::new(), bases, kernel_base: Some(0xfffff800_40000000), notes: Vec::new() };
        assert_eq!(symbolizer.name("ntoskrnl.exe", 0x47afc3, true).as_deref(), Some("kernel::ntos::ps::thread_callout+0xc3"));
        assert_eq!(symbolizer.name("WIN32KFULL.SYS", 0xe9655, false).as_deref(), Some("xxxDwmStopRedirection+0x35"));
        assert_eq!(symbolizer.name("win32kfull.sys", 0x100, false), None);
        assert_eq!(symbolizer.name("cdd.dll", 0x10, false), None);
        assert_eq!(symbolizer.name("ntoskrnl.exe", 0x2000000, false), None);
        assert_eq!(symbolizer.sources(), "kernel (kernel.elf), win32kfull (sem arquivo)");
    }

    #[test]
    fn the_test_table_resolves_returns_by_the_call_byte() {
        let table = Table::new(&[("dxgkrnl.sys", 0x21e000, "DXGADAPTER::DdiPresentDisplayOnly")]);
        assert_eq!(table.name("dxgkrnl.sys", 0x21e00e, true).as_deref(), Some("DXGADAPTER::DdiPresentDisplayOnly+0xe"));
        assert_eq!(table.name("dxgkrnl.sys", 0x21e000, false).as_deref(), Some("DXGADAPTER::DdiPresentDisplayOnly"));
        assert_eq!(table.name("dxgkrnl.sys", 0x21e000, true), None);
        assert_eq!(table.name("cdd.dll", 0x21e00e, false), None);
        assert!(!is_opennt_kernel("dxgkrnl.sys") && is_opennt_kernel("NTOSKRNL.EXE"));
    }
}
