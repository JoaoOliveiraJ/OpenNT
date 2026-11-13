//! Carga de imagens do sistema — o `sysload` do NT: bibliotecas de kernel e
//! drivers de export, a fonte dos bytes das imagens, a resolução de
//! encaminhamentos de exports e os API sets do kernel.
//!
//! Bibliotecas de kernel e drivers de export — `system32/win32/kernel-libraries.js`.
//!
//! Drivers de export importados entram pelo DllInitialize (o DriverEntry do
//! PE não é API de inicialização); bibliotecas sem entrada (o hal.dll com os
//! seus encaminhamentos reais) só publicam exports; um .sys comum importado
//! sobe como driver pelo lifecycle. Cada importador retém os módulos que
//! fornecem os seus endereços nativos.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use self::kernel_image_source::ImageSource;
use crate::ntos::inc::nt_abi::driver_object;
use crate::ntos::{init::exports, io::lifecycle};
use crate::ntos::mm::pe_loader::{self, ImageDependency, ImportSymbol, LoadOptions, PeImage, ResolvedImport};
use self::pe_resolver::{ExportedModule, Symbol};
use crate::hal::amd64::native_call;
use crate::ntos::ob::object_manager;
use crate::rtl::{KernelError, SpinLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Driver,
    ExportDriver,
    Entryless,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Ready,
    Unloading,
    Unloaded,
}

struct Record {
    name: String,
    driver_name: String,
    kind: Kind,
    state: State,
    references: u32,
    pinned: bool,
    /// DRIVER_OBJECT e nó do namespace de um driver comum.
    driver: u64,
    driver_node: Option<object_manager::NodeId>,
    /// Imagem própria (drivers de export e bibliotecas sem entrada).
    image: Option<PeImage>,
    module: Arc<ExportedModule>,
    initialize_status: Option<u32>,
    unload_status: Option<u32>,
}

type Shared = Arc<SpinLock<Record>>;

static LOADED: SpinLock<BTreeMap<String, Shared>> = SpinLock::new(BTreeMap::new());
static LOADING: SpinLock<BTreeSet<String>> = SpinLock::new(BTreeSet::new());

fn normalize(name: &str) -> Result<String, KernelError> {
    let name = name.to_lowercase();
    let stem = name.trim_end_matches(".exe").trim_end_matches(".dll");
    if stem == "ntoskrnl" || stem == "ntkrnlmp" {
        return Ok(String::from("ntoskrnl.exe"));
    }
    let valid = name.chars().all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || matches!(character, '_' | '.' | '-'));
    if !valid || !(name.ends_with(".dll") || name.ends_with(".sys")) || name.len() <= 4 {
        return Err(KernelError::new(alloc::format!("invalid kernel library name: {name}")));
    }
    Ok(name)
}

/// O dono de serviço pode descarregar um driver emprestado depois do último
/// import: a imagem antiga não é reaproveitada sem o dono no namespace.
fn cached(name: &str) -> Result<Option<Shared>, KernelError> {
    let Some(record) = LOADED.lock().get(name).cloned() else { return Ok(None) };
    let stale = {
        let state = record.lock();
        state.kind == Kind::Driver && object_manager::lookup(&alloc::format!("\\Driver\\{}", state.driver_name)) != state.driver_node
    };
    if stale {
        let mut state = record.lock();
        if state.references != 0 {
            return Err(KernelError::new(alloc::format!("referenced kernel driver lost its owner: {name}")));
        }
        state.state = State::Unloaded;
        drop(state);
        LOADED.lock().remove(name);
        return Ok(None);
    }
    Ok(Some(record))
}

fn call(address: u64, arguments: &[u64]) -> u32 {
    native_call::call(address, arguments) as u32
}

/// DllInitialize(RegistryPath) com o caminho do serviço do módulo.
fn initialize(record: &mut Record) -> Result<(), KernelError> {
    let service = record.name.trim_end_matches(".sys").trim_end_matches(".dll");
    let path = alloc::format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{service}");
    let units: Vec<u16> = path.encode_utf16().collect();
    let buffer = guest::alloc_bytes((units.len() as u64 + 1) * 2);
    if buffer == 0 {
        return Err(KernelError::with_status("kernel library registry path allocation failed", 0xC000_009A));
    }
    let string = guest::alloc_bytes(16);
    if string == 0 {
        guest::free_bytes(buffer);
        return Err(KernelError::with_status("kernel library registry string allocation failed", 0xC000_009A));
    }
    for (index, unit) in units.iter().enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    guest::write16(string, units.len() as u16 * 2);
    guest::write16(string + 2, (units.len() as u16 + 1) * 2);
    guest::write64(string + 8, buffer);
    crate::debug_print!("[kernel-library] DllInitialize {}", record.name);
    let entry = record.module.exports.exports.get("DllInitialize").copied().unwrap_or(0);
    let status = call(entry, &[string]);
    guest::free_bytes(string);
    guest::free_bytes(buffer);
    record.initialize_status = Some(status);
    if status & 0x8000_0000 != 0 {
        return Err(KernelError::with_status(alloc::format!("DllInitialize {} returned 0x{status:x}", record.name), status));
    }
    Ok(())
}

fn unload(shared: &Shared) -> Result<bool, KernelError> {
    let (kind, name, driver_name, driver) = {
        let mut record = shared.lock();
        if record.references != 0 || record.pinned || record.state != State::Ready {
            return Ok(false);
        }
        if record.kind == Kind::ExportDriver && !record.module.exports.exports.contains_key("DllUnload") {
            return Ok(false);
        }
        record.state = State::Unloading;
        (record.kind, record.name.clone(), record.driver_name.clone(), record.driver)
    };
    let restore = |shared: &Shared| shared.lock().state = State::Ready;
    match kind {
        Kind::ExportDriver => {
            let entry = shared.lock().module.exports.exports.get("DllUnload").copied().unwrap_or(0);
            let status = call(entry, &[]);
            shared.lock().unload_status = Some(status);
            if status & 0x8000_0000 != 0 {
                restore(shared);
                return Ok(false);
            }
        }
        Kind::Driver => {
            if driver == 0 || guest::read64(driver + driver_object::DRIVER_UNLOAD) == 0 || !lifecycle::unload_driver(&driver_name) {
                restore(shared);
                return Ok(false);
            }
        }
        Kind::Entryless => {}
    }
    // O DllUnload já teve sucesso: a limpeza das dependências não volta a
    // publicar a imagem desinicializada.
    LOADED.lock().remove(&name);
    let image = {
        let mut record = shared.lock();
        record.state = State::Unloaded;
        record.image.take()
    };
    if let Some(mut image) = image {
        image.release()?;
    }
    Ok(true)
}

/// Cabeçalho de módulo nativo AMD64 PE32+ (subsistema nativo).
fn check_header(name: &str, source: &Arc<dyn ImageSource>) -> Result<(), KernelError> {
    if source.size() < 64 {
        return Err(KernelError::new(alloc::format!("truncated kernel library: {name}")));
    }
    let dos = source.read_bytes(0, 64)?;
    let pe = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as u64;
    if u16::from_le_bytes([dos[0], dos[1]]) != 0x5A4D || pe > source.size().saturating_sub(96) {
        return Err(KernelError::new(alloc::format!("invalid kernel library header: {name}")));
    }
    let header = source.read_bytes(pe, 96)?;
    let word = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
    if u32::from_le_bytes([header[0], header[1], header[2], header[3]]) != 0x4550 || word(4) != 0x8664 || word(24) != 0x20B || word(92) != 1 {
        return Err(KernelError::new(alloc::format!("kernel module must be native AMD64 PE32+: {name}")));
    }
    Ok(())
}

fn exported(name: &str, exports: BTreeMap<String, u64>) -> Arc<ExportedModule> {
    Arc::new(ExportedModule { name: String::from(name), exports: crate::ntos::rtl::image::pe_exports::Exports { exports, ..Default::default() } })
}

fn get(name: &str) -> Result<Shared, KernelError> {
    let name = normalize(name)?;
    if LOADING.lock().contains(&name) {
        return Err(KernelError::new(alloc::format!("circular kernel module import: {name}")));
    }
    if let Some(previous) = cached(&name)? {
        if previous.lock().state != State::Ready {
            return Err(KernelError::new(alloc::format!("kernel module is unloading: {name}")));
        }
        return Ok(previous);
    }
    let source = kernel_image_source::source_for(&name)?;
    check_header(&name, &source)?;
    let driver_name = String::from(name.trim_end_matches(".sys"));
    LOADING.lock().insert(name.clone());
    let result = (|| -> Result<Record, KernelError> {
        let existing = if name.ends_with(".sys") { object_manager::lookup(&alloc::format!("\\Driver\\{driver_name}")) } else { None };
        if let Some(node) = existing {
            let driver = lifecycle::initialized_driver(&driver_name).ok_or_else(|| KernelError::new(alloc::format!("existing driver is not initialized: {name}")))?;
            let exports = lifecycle::driver_exports(&driver_name).unwrap_or_default();
            return Ok(Record { name: name.clone(), driver_name: driver_name.clone(), kind: Kind::Driver, state: State::Ready, references: 0, pinned: true, driver, driver_node: Some(node), image: None, module: exported(&name, exports), initialize_status: None, unload_status: None });
        }
        let image = pe_loader::load_from_source(source.clone(), &LoadOptions { allow_preferred_va: name.ends_with(".dll"), image_name: Some(String::from(source.name())), ..LoadOptions::default() })?;
        let module = Arc::new(ExportedModule { name: name.clone(), exports: image.exports.clone() });
        let mut record = Record { name: name.clone(), driver_name: driver_name.clone(), kind: Kind::Entryless, state: State::Ready, references: 0, pinned: false, driver: 0, driver_node: None, image: None, module, initialize_status: None, unload_status: None };
        if image.exports.exports.contains_key("DllInitialize") {
            record.kind = Kind::ExportDriver;
            record.image = Some(image);
            if let Err(error) = initialize(&mut record) {
                if let Some(mut image) = record.image.take() {
                    let _ = image.release();
                }
                return Err(error);
            }
        } else if image.entry_point == 0 {
            record.image = Some(image);
        } else if name.ends_with(".sys") {
            // Driver comum importado: sobe pelo lifecycle, que é o dono da
            // imagem e do DriverEntry.
            let mut image = image;
            image.release()?;
            lifecycle::load_driver(&alloc::format!("/{name}"), &lifecycle::DriverOptions::default()).map_err(|error| error.error)?;
            record.kind = Kind::Driver;
            record.driver = lifecycle::initialized_driver(&driver_name).unwrap_or(0);
            record.driver_node = object_manager::lookup(&alloc::format!("\\Driver\\{driver_name}"));
            record.module = exported(&name, lifecycle::driver_exports(&driver_name).unwrap_or_default());
        } else {
            let mut image = image;
            let _ = image.release();
            return Err(KernelError::new(alloc::format!("kernel DLL has no DllInitialize: {name}")));
        }
        Ok(record)
    })();
    LOADING.lock().remove(&name);
    let shared = Arc::new(SpinLock::new(result?));
    LOADED.lock().insert(name, shared.clone());
    Ok(shared)
}

/// Carga fixada (hal.dll, cng.sys): o módulo fica pela vida do boot.
pub fn load(name: &str) -> Result<Arc<ExportedModule>, KernelError> {
    let name = normalize(name)?;
    if name == "ntoskrnl.exe" {
        return Ok(Arc::new(exports::export_module()?));
    }
    let record = get(&name)?;
    let mut state = record.lock();
    state.pinned = true;
    if state.driver != 0 {
        lifecycle::pin_kernel_library(state.driver);
    }
    Ok(state.module.clone())
}

/// Referência de import retida pelo importador.
struct Lease(Shared);

impl ImageDependency for Lease {
    fn retain(&self) {
        let mut record = self.0.lock();
        record.references += 1;
        if record.driver != 0 {
            lifecycle::add_import_reference(record.driver, 1);
        }
    }
    fn release(&self) -> Result<(), KernelError> {
        let last = {
            let mut record = self.0.lock();
            if record.references == 0 {
                return Err(KernelError::new("kernel module reference underflow"));
            }
            record.references -= 1;
            if record.driver != 0 {
                lifecycle::add_import_reference(record.driver, -1);
            }
            record.references == 0
        };
        if last {
            unload(&self.0)?;
        }
        Ok(())
    }
}

/// Lease explícito (`acquire`): a imagem fica viva até `release`.
pub struct Acquired {
    lease: Option<Lease>,
    pub image_base: u64,
    pub size_of_image: u64,
    pub module: Arc<ExportedModule>,
}

impl Acquired {
    pub fn export(&self, name: &str) -> Option<u64> {
        self.module.exports.exports.get(name).copied()
    }

    pub fn release(&mut self) -> Result<(), KernelError> {
        match self.lease.take() {
            Some(lease) => lease.release(),
            None => Err(KernelError::new("kernel library lease already released")),
        }
    }
}

/// Carga com referência própria, devolvida pelo chamador (`acquire`).
pub fn acquire(name: &str) -> Result<Acquired, KernelError> {
    let record = get(&normalize(name)?)?;
    let lease = Lease(record.clone());
    lease.retain();
    let state = record.lock();
    let (image_base, size_of_image) = state.image.as_ref().map_or((0, 0), |image| (image.image_base, image.size_of_image));
    Ok(Acquired { lease: Some(lease), image_base, size_of_image, module: state.module.clone() })
}

/// Resolve o export (com os encaminhamentos) e devolve os módulos que o
/// importador passa a reter.
pub fn lookup(name: &str, symbol: &ImportSymbol) -> Result<(u64, Vec<Arc<dyn ImageDependency>>), KernelError> {
    let mut dependencies: Vec<Shared> = Vec::new();
    let result = (|| {
        let mut module = |target: &str, _from: &str| -> Result<Arc<ExportedModule>, KernelError> {
            let target = normalize(target)?;
            if target == "ntoskrnl.exe" {
                return Ok(Arc::new(exports::export_module()?));
            }
            let record = get(&target)?;
            let module = record.lock().module.clone();
            if !dependencies.iter().any(|candidate| Arc::ptr_eq(candidate, &record)) {
                dependencies.push(record);
            }
            Ok(module)
        };
        let first = module(name, "")?;
        let symbol = match symbol {
            ImportSymbol::Name(name) => Symbol::Name(name.clone()),
            ImportSymbol::Ordinal(ordinal) => Symbol::Ordinal(*ordinal),
        };
        pe_resolver::resolve_export(&first, &symbol, &mut module, &mut BTreeSet::new())
    })();
    match result {
        Ok(address) => Ok((address, dependencies.into_iter().map(|record| Arc::new(Lease(record)) as Arc<dyn ImageDependency>).collect())),
        Err(error) => {
            for record in dependencies.iter().rev() {
                let _ = unload(record);
            }
            Err(error)
        }
    }
}

fn import(dll: &str, symbol: &ImportSymbol) -> Option<ResolvedImport> {
    match lookup(dll, symbol) {
        Ok((address, dependencies)) => Some(ResolvedImport::Address { address, dependencies }),
        Err(error) => {
            crate::debug_print!("[kernel-library] {}!{:?}: {}", dll, symbol, error.message);
            None
        }
    }
}

/// Resolvedores do loader de PE (`init/main.js`): hal.dll pelas bibliotecas,
/// wmilib.sys e wpprecorder.sys pelos exports do kernel, e qualquer outro
/// .sys como driver de export ou driver importado.
pub fn register_resolvers() {
    static REGISTERED: SpinLock<bool> = SpinLock::new(false);
    let mut registered = REGISTERED.lock();
    if *registered {
        return;
    }
    *registered = true;
    pe_loader::register_resolver(|dll| dll.eq_ignore_ascii_case("hal.dll"), Arc::new(import));
    let kernel = |dll: &str, symbol: &ImportSymbol| match symbol {
        ImportSymbol::Name(name) => exports::lookup(dll, name),
        ImportSymbol::Ordinal(ordinal) => exports::lookup_ordinal(dll, *ordinal),
    };
    pe_loader::register_resolver(|dll| dll.eq_ignore_ascii_case("wmilib.sys"), Arc::new(kernel));
    pe_loader::register_resolver(|dll| dll.eq_ignore_ascii_case("wpprecorder.sys"), Arc::new(kernel));
    pe_loader::register_resolver(|dll| dll.to_lowercase().ends_with(".sys"), Arc::new(import));
}

/// Estado do módulo (`state`): tipo, estado, referências, fixação e os
/// status de inicialização e descarga.
pub fn state(name: &str) -> Option<(String, String, u32, bool, Option<u32>, Option<u32>)> {
    let record = cached(&normalize(name).ok()?).ok()??;
    let record = record.lock();
    Some((alloc::format!("{:?}", record.kind), alloc::format!("{:?}", record.state), record.references, record.pinned, record.initialize_status, record.unload_status))
}

pub mod kernel_image_source {
    //! Fonte de bytes de imagens nativas — `system32/win32/kernel-image-source.js`.
    //!
    //! Lê imagens dos sistemas de arquivos do boot; ler uma imagem não a
    //! registra como carregada nem executa sua inicialização.

    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use crate::drivers::fs::{memory_file_system, ntfs};
    use crate::rtl::KernelError;

    /// Origem dos bytes de uma imagem PE (arquivo ou memória).
    pub trait ImageSource: Send + Sync {
        fn name(&self) -> &str;
        fn size(&self) -> u64;
        fn read_bytes(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError>;
        /// O volume oferece a cópia direta de setores para a memória física.
        fn supports_copy_to_physical(&self) -> bool {
            false
        }
        /// Cópia direta dos setores para a memória física, quando o volume a
        /// oferece (`None` = sem esse caminho).
        fn copy_to_physical(&self, _offset: u64, _address: u64, _length: u64) -> Option<Result<(), KernelError>> {
            None
        }
    }

    /// Imagem mantida em memória (arquivo do VFS ou bytes de teste).
    pub struct MemorySource {
        pub name: String,
        pub bytes: Vec<u8>,
    }

    impl ImageSource for MemorySource {
        fn name(&self) -> &str {
            &self.name
        }
        fn size(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_bytes(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
            let start = (offset as usize).min(self.bytes.len());
            let end = (offset.saturating_add(length) as usize).min(self.bytes.len());
            Ok(self.bytes[start..end].to_vec())
        }
    }

    /// Imagem no volume NTFS montado.
    pub struct NtfsSource {
        name: String,
        path: String,
        size: u64,
        has_runs: bool,
        volume: Arc<ntfs::Ntfs>,
    }

    impl ImageSource for NtfsSource {
        fn name(&self) -> &str {
            &self.name
        }
        fn size(&self) -> u64 {
            self.size
        }
        fn read_bytes(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
            Ok(self.volume.read_range(&self.path, offset, length)?.unwrap_or_default())
        }
        fn supports_copy_to_physical(&self) -> bool {
            self.has_runs
        }
        fn copy_to_physical(&self, offset: u64, address: u64, length: u64) -> Option<Result<(), KernelError>> {
            self.has_runs.then(|| self.volume.copy_range_to_physical(&self.path, offset, address, length))
        }
    }

    /// Fonte da imagem pelo nome (minúsculas, `[a-z0-9_.-]+.(dll|sys|exe)`):
    /// primeiro o VFS em memória, depois o volume NTFS.
    /// Fonte de um caminho completo de driver: o disco em memória (bundle)
    /// primeiro, depois o volume NTFS. Devolve também se veio do NTFS (onde os
    /// drivers de serviço carregam na base preferida). `None` = não encontrado.
    pub fn source_for_path(path: &str) -> Result<Option<(Arc<dyn ImageSource>, bool)>, KernelError> {
        if let Some(bytes) = memory_file_system::read_bytes(path) {
            return Ok(Some((Arc::new(MemorySource { name: alloc::format!("\\FS{}", path.replace('/', "\\")), bytes }), false)));
        }
        let Some(volume) = ntfs::mounted() else { return Ok(None) };
        let Some(layout) = volume.file_layout(path)? else { return Ok(None) };
        debug_print!("[ntoskrnl] {} via NTFS ({} bytes, streaming/DMA)", path, layout.size);
        let source = NtfsSource { name: alloc::format!("\\NTFS{}", path.replace('/', "\\")), size: layout.size, has_runs: layout.runs.is_some(), path: alloc::string::String::from(path), volume };
        Ok(Some((Arc::new(source), true)))
    }

    pub fn source_for(name: &str) -> Result<Arc<dyn ImageSource>, KernelError> {
        let name = name.to_lowercase();
        let valid = name.chars().all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || matches!(character, '_' | '.' | '-')) && [".dll", ".sys", ".exe"].iter().any(|extension| name.len() > extension.len() && name.ends_with(extension));
        if !valid {
            return Err(KernelError::new(alloc::format!("invalid kernel image name: {name}")));
        }
        let path = alloc::format!("/{name}");
        if let Some(bytes) = memory_file_system::read_bytes(&path) {
            return Ok(Arc::new(MemorySource { name: alloc::format!("\\FS\\{name}"), bytes }));
        }
        let volume = ntfs::mounted().ok_or_else(|| KernelError::new(alloc::format!("kernel image not found: {name}")))?;
        let layout = volume.file_layout(&path)?.ok_or_else(|| KernelError::new(alloc::format!("kernel image not found: {name}")))?;
        Ok(Arc::new(NtfsSource { name: alloc::format!("\\NTFS\\{name}"), size: layout.size, has_runs: layout.runs.is_some(), path, volume }))
    }
}

pub mod pe_resolver {
    //! Resolução de exports com encaminhamentos — `system32/win32/pe-resolver.js`.
    //!
    //! Um encaminhamento pode terminar em outro encaminhamento, nome ou ordinal.
    //! Ciclos são detectados por símbolo (ciclos entre DLLs são permitidos).

    use alloc::collections::BTreeSet;
    use alloc::string::{String, ToString};
    use alloc::sync::Arc;

    use crate::ntos::rtl::image::pe_exports::Exports;
    use crate::rtl::KernelError;

    /// Módulo com nome e tabela de exports.
    #[derive(Clone, Debug)]
    pub struct ExportedModule {
        pub name: String,
        pub exports: Exports,
    }

    /// Símbolo procurado: nome ou ordinal.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Symbol {
        Name(String),
        Ordinal(u32),
    }

    pub type ModuleLoader<'a> = dyn FnMut(&str, &str) -> Result<Arc<ExportedModule>, KernelError> + 'a;

    pub fn resolve_export(module: &ExportedModule, symbol: &Symbol, load_module: &mut ModuleLoader, chain: &mut BTreeSet<String>) -> Result<u64, KernelError> {
        let direct = match symbol {
            Symbol::Name(name) => module.exports.exports.get(name).copied(),
            Symbol::Ordinal(ordinal) => module.exports.exports_by_ordinal.get(ordinal).copied(),
        };
        if let Some(address) = direct {
            return Ok(address);
        }
        let target = match symbol {
            Symbol::Name(name) => module.exports.forwarders.get(name).cloned(),
            Symbol::Ordinal(ordinal) => module.exports.forwarders_by_ordinal.get(ordinal).cloned(),
        };
        let key = match symbol {
            Symbol::Name(name) => alloc::format!("{}!{}", module.name, name),
            Symbol::Ordinal(ordinal) => alloc::format!("{}!#{}", module.name, ordinal),
        };
        let Some(target) = target else { return Err(KernelError::new(alloc::format!("export ausente: {key}"))) };
        if chain.contains(&key) {
            return Err(KernelError::new(alloc::format!("ciclo de encaminhamentos: {key}")));
        }
        if chain.len() >= 128 {
            return Err(KernelError::new("cadeia de encaminhamentos excessiva"));
        }
        chain.insert(key.clone());
        let result = (|| {
            let separator = target.rfind('.').filter(|&index| index > 0 && index != target.len() - 1).ok_or_else(|| KernelError::new(alloc::format!("encaminhamento PE invalido: {target}")))?;
            let mut dll = target[..separator].to_string();
            let lower = dll.to_lowercase();
            if ![".dll", ".sys", ".exe"].iter().any(|extension| lower.ends_with(extension)) {
                dll.push_str(".dll");
            }
            let next_text = &target[separator + 1..];
            let next = match next_text.strip_prefix('#') {
                Some(digits) => {
                    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(KernelError::new(alloc::format!("ordinal encaminhado invalido: {target}")));
                    }
                    let ordinal: u64 = digits.parse().unwrap_or(u64::MAX);
                    if ordinal > 0xFFFF {
                        return Err(KernelError::new(alloc::format!("ordinal encaminhado fora da faixa: {target}")));
                    }
                    Symbol::Ordinal(ordinal as u32)
                }
                None => Symbol::Name(next_text.to_string()),
            };
            let next_module = load_module(&dll, &module.name)?;
            resolve_export(&next_module, &next, load_module, chain)
        })();
        chain.remove(&key);
        result
    }
}

pub mod kernel_api_set {
    //! API sets do kernel — `system32/win32/kernel-api-set.js`.
    //!
    //! O schema é lido do apisetschema.dll da instalação na primeira consulta.

    use alloc::string::String;

    use crate::ntos::rtl::api_set::{self, Schema};
    use crate::ntos::mm::sysload::kernel_image_source;
    use crate::rtl::{KernelError, SpinLock};

    static SCHEMA: SpinLock<Option<Schema>> = SpinLock::new(None);

    /// `None` = contrato desconhecido; `Some("")` = host explicitamente ausente.
    pub fn resolve(name: &str, importer: &str) -> Result<Option<String>, KernelError> {
        if SCHEMA.lock().is_none() {
            let schema = api_set::parse_image(kernel_image_source::source_for("apisetschema.dll")?.as_ref())?;
            let mut cached = SCHEMA.lock();
            if cached.is_none() {
                *cached = Some(schema);
            }
        }
        Ok(SCHEMA.lock().as_ref().and_then(|schema| schema.resolve(name, importer)))
    }
}
