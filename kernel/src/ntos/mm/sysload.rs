//! Carga de imagens do sistema — o `sysload` do NT: bibliotecas de kernel e
//! drivers de export, a fonte dos bytes das imagens, a resolução de
//! encaminhamentos de exports e os API sets do kernel.
//!
//! Bibliotecas de kernel e drivers de export.
//!
//! Drivers de export importados entram pelo DllInitialize (o DriverEntry do
//! PE não é API de inicialização); bibliotecas sem entrada (o hal.dll com os
//! seus encaminhamentos reais) só publicam exports; um .sys comum importado
//! sobe como driver pelo lifecycle. Cada importador retém os módulos que
//! fornecem os seus endereços nativos.
//!
//! Ciclos de imports (o netio.sys e o ndis.sys importam um do outro) seguem
//! o MiResolveImageReferences: a imagem em carga já está na lista de imagens
//! carregadas com LOAD_IN_PROGRESS, e o import que volta a ela usa os exports
//! dessa entrada sem reter referência. A DLL nova de um import ganha
//! DRIVER_DEPENDENT_DLL e o DllInitialize logo depois da própria carga.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use self::kernel_image_source::ImageSource;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{DriverObject, KldrDataTableEntry, UnicodeString};
use crate::ntos::{init::exports, io::lifecycle};
use crate::ntos::mm::loaded_images;
use crate::ntos::mm::pe_loader::{self, ImageDependency, ImportSymbol, LoadOptions, PeImage, ResolvedImport};
use self::pe_resolver::{ExportedModule, Symbol};
use crate::hal::amd64::native_call;
use crate::ntos::ob::object_manager;
use crate::ntos::rtl::guest_strings;
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
    /// A KLDR_DATA_TABLE_ENTRY de uma imagem do MmLoadSystemImage achada
    /// pelo import de outra (0 nos demais): cada import retém o LoadCount
    /// dela.
    loader_entry: u64,
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
        let unloaded_image = state.loader_entry != 0 && loaded_system_image_entry(name) != Some(state.loader_entry);
        unloaded_image || state.kind == Kind::Driver && object_manager::lookup(&alloc::format!("\\Driver\\{}", state.driver_name)) != state.driver_node
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

/// MmCallDllInitialize: DllInitialize(RegistryPath) com o caminho do serviço
/// do módulo (o BaseDllName até o primeiro ponto). A trava do registro não
/// fica presa durante a chamada: a entrada já está publicada, e uma carga
/// aninhada a acha como no NT.
fn initialize(shared: &Shared) -> Result<(), KernelError> {
    let (name, entry) = {
        let record = shared.lock();
        (record.name.clone(), record.module.exports.exports.get("DllInitialize").copied().unwrap_or(0))
    };
    let service = name.split('.').next().unwrap_or(&name);
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
    let characters: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(buffer, &characters);
    // SAFETY: UNICODE_STRING recém-alocado.
    let registry_path = unsafe { UnicodeString::at(string) };
    registry_path.length.set(units.len() as u16 * 2);
    registry_path.maximum_length.set((units.len() as u16 + 1) * 2);
    registry_path.buffer.set(buffer);
    crate::debug_print!("[kernel-library] DllInitialize {}", name);
    let status = call(entry, &[string]);
    guest::free_bytes(string);
    guest::free_bytes(buffer);
    shared.lock().initialize_status = Some(status);
    crate::debug_print!("[kernel-library] DllInitialize {} -> {:#x}", name, status);
    if status & 0x8000_0000 != 0 {
        return Err(KernelError::with_status(alloc::format!("DllInitialize {name} returned 0x{status:x}"), status));
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
            // SAFETY: DRIVER_OBJECT vivo do driver carregado.
            if driver == 0 || unsafe { DriverObject::at(driver) }.driver_unload.get() == 0 || !lifecycle::unload_driver(&driver_name) {
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

/// Módulo de uma imagem cujos imports estão sendo resolvidos (LOAD_IN_PROGRESS
/// na lista de imagens carregadas): o fim de um ciclo de imports. Como no
/// MiResolveImageReferences, o importador usa os exports da entrada em carga
/// sem reter referência (o LoadCount não sobe).
fn resolving_module(name: &str) -> Option<Arc<ExportedModule>> {
    let image = loaded_images::find_by_base_name(name).filter(|image| image.loader_flags & loaded_images::LOAD_IN_PROGRESS != 0)?;
    let exports = pe_loader::resolving_exports(image.id)?;
    Some(Arc::new(ExportedModule { name: String::from(name), exports }))
}

/// Módulo de uma imagem que o MmLoadSystemImage já carregou (de sistema ou
/// de sessão) com esse nome-base: como no MiResolveImageReferences, o import
/// de outra imagem acha a entrada na lista de imagens carregadas pelo
/// BaseDllName e usa os exports dela, sem carregar outra cópia. O registro
/// devolvido é fixado: a imagem pertence a quem a carregou (o
/// MmUnloadSystemImage).
fn loaded_system_image_module(name: &str) -> Option<Shared> {
    let image = loaded_images::find_by_base_name(name).filter(|image| image.loader_flags & loaded_images::LOAD_IN_PROGRESS == 0)?;
    if crate::ntos::mm::session_image::exports_of(image.image_base).is_none() && !SYSTEM_IMAGES.lock().values().any(|loaded| loaded.image_base == image.image_base) {
        return None;
    }
    let exports = match crate::ntos::mm::session_image::exports_of(image.image_base) {
        Some(exports) => exports,
        None => SYSTEM_IMAGES.lock().values().find(|loaded| loaded.image_base == image.image_base).map(|loaded| loaded.exports.clone())?,
    };
    let entry = system_image_entry(image.id).ok().flatten()?;
    let module = Arc::new(ExportedModule { name: String::from(name), exports });
    let driver_name = String::from(name.trim_end_matches(".sys"));
    Some(Arc::new(SpinLock::new(Record { name: String::from(name), driver_name, kind: Kind::Entryless, state: State::Ready, references: 0, pinned: true, driver: 0, driver_node: None, image: None, module, initialize_status: None, unload_status: None, loader_entry: entry })))
}

/// O registro do módulo, carregando-o na primeira vez. `dependent` = carga
/// pelo import de outra imagem (o MiLoadImportDll): a imagem nova ganha
/// DRIVER_DEPENDENT_DLL. O DllInitialize de uma DLL nova roda logo depois da
/// carga dela, com o registro já publicado, antes de o importador seguir para
/// os imports seguintes (MiLoadImportDll -> MmCallDllInitialize).
fn get(name: &str, dependent: bool) -> Result<Shared, KernelError> {
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
    if let Some(loaded) = loaded_system_image_module(&name) {
        LOADED.lock().insert(name, loaded.clone());
        return Ok(loaded);
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
            return Ok(Record { name: name.clone(), driver_name: driver_name.clone(), kind: Kind::Driver, state: State::Ready, references: 0, pinned: true, driver, driver_node: Some(node), image: None, module: exported(&name, exports), initialize_status: None, unload_status: None, loader_entry: 0 });
        }
        let (entry_rva, has_initialize) = pe_loader::file_entry_and_initialize(source.as_ref())?;
        if name.ends_with(".sys") && entry_rva != 0 && !has_initialize {
            // Driver comum importado: sobe pelo lifecycle, que é o dono da
            // imagem (mapeada uma vez) e do DriverEntry.
            lifecycle::load_driver(&alloc::format!("/{name}"), &lifecycle::DriverOptions::default()).map_err(|error| error.error)?;
            let driver = lifecycle::initialized_driver(&driver_name).unwrap_or(0);
            let driver_node = object_manager::lookup(&alloc::format!("\\Driver\\{driver_name}"));
            let module = exported(&name, lifecycle::driver_exports(&driver_name).unwrap_or_default());
            return Ok(Record { name: name.clone(), driver_name: driver_name.clone(), kind: Kind::Driver, state: State::Ready, references: 0, pinned: false, driver, driver_node, image: None, module, initialize_status: None, unload_status: None, loader_entry: 0 });
        }
        if !has_initialize && entry_rva != 0 {
            return Err(KernelError::new(alloc::format!("kernel DLL has no DllInitialize: {name}")));
        }
        // FullDllName de uma DLL carregada pelo import (o MiFormFullImageName
        // junta o diretório do importador e o nome): os drivers e as suas
        // bibliotecas ficam em System32\drivers, as DLLs de kernel em System32.
        let full_name = if name.ends_with(".sys") { lifecycle::system_driver_path(&name) } else { alloc::format!("\\SystemRoot\\System32\\{name}") };
        let image = pe_loader::load_from_source(source.clone(), &LoadOptions { image_name: Some(full_name), ..LoadOptions::default() })?;
        if dependent {
            if let Some(loaded) = image.loaded_image.as_ref() {
                loaded_images::update_flags(loaded.id, loaded_images::DRIVER_DEPENDENT_DLL, 0);
            }
        }
        let module = Arc::new(ExportedModule { name: name.clone(), exports: image.exports.clone() });
        let kind = if has_initialize { Kind::ExportDriver } else { Kind::Entryless };
        Ok(Record { name: name.clone(), driver_name: driver_name.clone(), kind, state: State::Ready, references: 0, pinned: false, driver: 0, driver_node: None, image: Some(image), module, initialize_status: None, unload_status: None, loader_entry: 0 })
    })();
    LOADING.lock().remove(&name);
    let record = result?;
    let needs_initialize = record.kind == Kind::ExportDriver;
    let shared = Arc::new(SpinLock::new(record));
    LOADED.lock().insert(name.clone(), shared.clone());
    if needs_initialize {
        if let Err(error) = initialize(&shared) {
            LOADED.lock().remove(&name);
            let image = {
                let mut record = shared.lock();
                record.state = State::Unloaded;
                record.image.take()
            };
            if let Some(mut image) = image {
                let _ = image.release();
            }
            return Err(error);
        }
    }
    Ok(shared)
}

/// Carga fixada (hal.dll, cng.sys): o módulo fica pela vida do boot.
pub fn load(name: &str) -> Result<Arc<ExportedModule>, KernelError> {
    let name = normalize(name)?;
    if name == "ntoskrnl.exe" {
        return Ok(Arc::new(exports::export_module()?));
    }
    let record = get(&name, false)?;
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
        // As referências de import contam por símbolo; a imagem do
        // MmLoadSystemImage ganha uma só no LoadCount enquanto alguma existe.
        if record.loader_entry != 0 && record.references == 1 {
            reference_system_image(record.loader_entry);
        }
    }
    fn release(&self) -> Result<(), KernelError> {
        let (last, loader_entry) = {
            let mut record = self.0.lock();
            if record.references == 0 {
                return Err(KernelError::new("kernel module reference underflow"));
            }
            record.references -= 1;
            if record.driver != 0 {
                lifecycle::add_import_reference(record.driver, -1);
            }
            (record.references == 0, record.loader_entry)
        };
        if loader_entry != 0 {
            return if last { dereference_system_image(loader_entry) } else { Ok(()) };
        }
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
    let record = get(&normalize(name)?, false)?;
    let lease = Lease(record.clone());
    lease.retain();
    let state = record.lock();
    let (image_base, size_of_image) = state.image.as_ref().map_or((0, 0), |image| (image.image_base, image.size_of_image));
    Ok(Acquired { lease: Some(lease), image_base, size_of_image, module: state.module.clone() })
}

/// O módulo de um encaminhamento de export de uma imagem de kernel. O
/// texto do encaminhamento não traz a extensão ("NDIS.NdisMatchPdoWithPacket"):
/// o MiSnapThunk procura na PsLoadedModuleList a imagem cujo BaseDllName
/// começa com "<módulo>." (RtlPrefixString, sem distinguir maiúsculas), então
/// "NDIS" casa com o NDIS.SYS carregado. Sem imagem carregada com esse
/// prefixo, vale o nome como veio (uma DLL de kernel, `<módulo>.dll`).
fn forwarder_module(target: &str) -> Result<String, KernelError> {
    let stem = target.rsplit_once('.').map_or(target, |(stem, _)| stem);
    let prefix = alloc::format!("{}.", stem.to_lowercase());
    let found = loaded_images::list().into_iter().find_map(|image| {
        let base = String::from(image.name.rsplit(['\\', '/']).next().unwrap_or(&image.name)).to_lowercase();
        base.starts_with(&prefix).then_some(base)
    });
    match found {
        Some(base) => normalize(&base),
        None => normalize(target),
    }
}

/// Resolve o export (com os encaminhamentos) e devolve os módulos que o
/// importador passa a reter.
pub fn lookup(name: &str, symbol: &ImportSymbol) -> Result<(u64, Vec<Arc<dyn ImageDependency>>), KernelError> {
    let mut dependencies: Vec<Shared> = Vec::new();
    let result = (|| {
        let mut module = |target: &str, from: &str| -> Result<Arc<ExportedModule>, KernelError> {
            let target = if from.is_empty() { normalize(target)? } else { forwarder_module(target)? };
            if target == "ntoskrnl.exe" {
                return Ok(Arc::new(exports::export_module()?));
            }
            if let Some(module) = resolving_module(&target) {
                return Ok(module);
            }
            let record = get(&target, true)?;
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

/// Uma DLL de modo kernel que uma imagem do sistema importa (a pshed.dll do
/// pci.sys, como o MiResolveImageReferences carrega de System32): o arquivo
/// existe no disco em memória ou no volume. As DLLs de modo usuário (ntdll e
/// as demais) nunca passam pelo loader de imagens do kernel.
fn kernel_library(dll: &str) -> bool {
    let lower = dll.to_lowercase();
    lower.ends_with(".dll") && lower != "hal.dll" && lower != "ntdll.dll" && kernel_image_source::source_for(&lower).is_ok()
}

/// Resolvedores do loader de PE: hal.dll pelas bibliotecas, qualquer .sys
/// (wmilib.sys, WppRecorder.sys...) como driver de export ou driver
/// importado e as DLLs de modo kernel presentes no volume.
pub fn register_resolvers() {
    static REGISTERED: SpinLock<bool> = SpinLock::new(false);
    let mut registered = REGISTERED.lock();
    if *registered {
        return;
    }
    *registered = true;
    pe_loader::register_resolver(|dll| dll.eq_ignore_ascii_case("hal.dll"), Arc::new(import));
    pe_loader::register_resolver(|dll| dll.to_lowercase().ends_with(".sys"), Arc::new(import));
    pe_loader::register_resolver(kernel_library, Arc::new(import));
}

/// Estado do módulo (`state`): tipo, estado, referências, fixação e os
/// status de inicialização e descarga.
pub fn state(name: &str) -> Option<(String, String, u32, bool, Option<u32>, Option<u32>)> {
    let record = cached(&normalize(name).ok()?).ok()??;
    let record = record.lock();
    Some((alloc::format!("{:?}", record.kind), alloc::format!("{:?}", record.state), record.references, record.pinned, record.initialize_status, record.unload_status))
}

/// MmGetSystemRoutineAddress: endereço chamável do export do kernel
/// (trampolim ou dado real) cujo nome vem no UNICODE_STRING `name_string`,
/// como o GetProcAddress de kernel; nome desconhecido devolve NULL.
pub fn system_routine_address(name_string: u64) -> Result<u64, KernelError> {
    let name = guest_strings::read_unicode_string(name_string);
    match exports::lookup("", &name) {
        Some(ResolvedImport::Thunk(id)) => exports::thunk_address(id as u64),
        Some(ResolvedImport::Address { address, .. }) => Ok(address),
        None => {
            // SAFETY: o UNICODE_STRING do chamador de kernel.
            let string = unsafe { UnicodeString::at(name_string) };
            let (length, buffer) = (string.length.get(), string.buffer.get());
            let raw: String = guest::read_bytes(buffer, length.min(32) as usize).into_iter().map(|byte| byte as char).collect();
            debug_print!("[mm] NAO ACHOU: \"{}\" (len={} buf={:#x} raw=\"{}\")", name, length, buffer, raw);
            Ok(0)
        }
    }
}

pub mod kernel_image_source {
    //! Fonte de bytes de imagens nativas.
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
    /// primeiro, depois o volume NTFS. `None` = não encontrado.
    pub fn source_for_path(path: &str) -> Result<Option<Arc<dyn ImageSource>>, KernelError> {
        if let Some(bytes) = memory_file_system::read_bytes(path) {
            return Ok(Some(Arc::new(MemorySource { name: alloc::format!("\\FS{}", path.replace('/', "\\")), bytes })));
        }
        let Some(volume) = ntfs::mounted() else { return Ok(None) };
        let Some(layout) = volume.file_layout(path)? else { return Ok(None) };
        debug_print!("[ntoskrnl] {} via NTFS ({} bytes, streaming/DMA)", path, layout.size);
        let source = NtfsSource { name: ntfs::nt_path(path), size: layout.size, has_runs: layout.runs.is_some(), path: alloc::string::String::from(path), volume };
        Ok(Some(Arc::new(source)))
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
        Ok(Arc::new(NtfsSource { name: ntfs::nt_path(&path), size: layout.size, has_runs: layout.runs.is_some(), path, volume }))
    }
}

pub mod pe_resolver {
    //! Resolução de exports com encaminhamentos.
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
    //! API sets do kernel.
    //!
    //! O schema é lido do apisetschema.dll da instalação na primeira consulta.

    use alloc::string::String;

    use crate::ntos::rtl::api_set::{self, Schema};
    use crate::ntos::mm::sysload::kernel_image_source;
    use crate::rtl::{KernelError, SpinLock};

    static SCHEMA: SpinLock<Option<Schema>> = SpinLock::new(None);

    /// `None` = contrato desconhecido; `Some("")` = host explicitamente ausente.
    pub fn resolve(name: &str, importer: &str) -> Result<Option<String>, KernelError> {
        // O OpenNT não oferece Windows Error Reporting (nenhum dump de kernel
        // ao vivo): o apiset do werkernel fica com host vazio para cair no
        // default nativo do próprio driver (stub não-bloqueante da extensão
        // opcional), em vez de exigir o werkernel.sys e sua cadeia.
        if name.len() >= 25 && name.get(..25).is_some_and(|prefix| prefix.eq_ignore_ascii_case("ext-ms-win-ntos-werkernel")) {
            return Ok(Some(String::new()));
        }
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

// ---- MmLoadSystemImage / MmUnloadSystemImage (mm-system-image) --------------
//
// Contrato do ntoskrnl 19041:
// - MmLoadSystemImage(ImageFileName, NamePrefix, LoadedBaseName, LoadFlags,
//   *ImageHandle, *ImageBaseAddress): `LoadFlags & 0x7FFFFFFC` ->
//   STATUS_INVALID_PARAMETER_4 antes de tudo; depois MmLoadSystemImageEx.
// - O Ex zera *ImageBaseAddress primeiro; MM_LOAD_IMAGE_IN_SESSION (1) junto
//   com MM_LOAD_IMAGE_AND_LOCKDOWN (2) -> STATUS_INVALID_PARAMETER_4.
// - Nomes de MiGenerateSystemImageNames: base = LoadedBaseName ou o último
//   componente, com NamePrefix na frente.
// - Imagem já na lista do loader: *ImageHandle = a KLDR_DATA_TABLE_ENTRY,
//   *ImageBaseAddress = DllBase; Flags & 0x04000000 ->
//   STATUS_IMAGE_ALREADY_LOADED_AS_DLL; carga de sessão -> sucesso; senão
//   STATUS_IMAGE_ALREADY_LOADED (sem incrementar LoadCount).
// - Imagem nova: mapeia, reloca, resolve os imports (as dependências recebem
//   o DllInitialize), cria a entrada do loader e notifica a carga; o ponto de
//   entrada da própria imagem NÃO é chamado.
// - MmUnloadSystemImage(ImageHandle): MiUnloadSystemImage; sempre sucesso.
//
// - Carga de sessão (MM_LOAD_IMAGE_IN_SESSION): o processo corrente precisa
//   de EPROCESS.Flags.ProcessInSession, senão STATUS_NO_MEMORY. A imagem nova
//   vai para a faixa de imagens de sessão e entra na sessão corrente
//   (`mm::session_image`); uma imagem de sessão já carregada por outra sessão
//   entra nesta na mesma VA (MiSessionInsertImage, LoadCount + 1), com as
//   páginas graváveis próprias, e a que esta sessão já tem devolve sucesso.
//   MmUnloadSystemImage de uma imagem de sessão a tira da sessão corrente; a
//   última sessão a descarrega. As dependências seguem o resolvedor global
//   (o MiLoadImportDll do NT as carregaria na sessão quando ainda não estão
//   carregadas no sistema).
//
// O OpenNT guarda as imagens de kernel do System32 na raiz do volume de boot,
// então a busca usa só o nome do arquivo (a mesma fonte do sysload). Arquivo
// ausente = STATUS_OBJECT_NAME_NOT_FOUND, o resultado do ZwOpenFile do
// MiObtainSectionForDriver.

const SYSTEM_IMAGE_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const SYSTEM_IMAGE_NAME_NOT_FOUND: u32 = 0xC000_0034;
const SYSTEM_IMAGE_INVALID_FORMAT: u32 = 0xC000_007B;
const SYSTEM_IMAGE_ALREADY_LOADED: u32 = 0xC000_010E;
const SYSTEM_IMAGE_ALREADY_LOADED_AS_DLL: u32 = 0xC000_019D;
const MM_LOAD_IMAGE_IN_SESSION: u32 = 1;
const MM_LOAD_IMAGE_AND_LOCKDOWN: u32 = 2;

/// Imagens carregadas por MmLoadSystemImage, pela entrada do loader.
static SYSTEM_IMAGES: SpinLock<BTreeMap<u64, PeImage>> = SpinLock::new(BTreeMap::new());

fn system_image_file_name(path: &str) -> &str {
    path.rsplit(|character| character == '\\' || character == '/').next().unwrap_or(path)
}

/// Entrada nativa e base de uma imagem já listada com o mesmo nome-base.
fn system_image_already_loaded(base_name: &str) -> Result<Option<(u64, u64)>, KernelError> {
    let (_, entries) = crate::ntos::mm::loaded_images::native_list()?;
    Ok(entries.into_iter().find(|(image, _)| system_image_file_name(&image.name).eq_ignore_ascii_case(base_name)).map(|(image, entry)| (entry, image.image_base)))
}

fn system_image_entry(id: u64) -> Result<Option<u64>, KernelError> {
    let (_, entries) = crate::ntos::mm::loaded_images::native_list()?;
    Ok(entries.into_iter().find(|(image, _)| image.id == id).map(|(_, entry)| entry))
}

/// MmLoadSystemImage: devolve o NTSTATUS e grava as duas saídas.
pub fn load_system_image(file_name: u64, prefix: u64, loaded_base_name: u64, flags: u32, handle_out: u64, base_out: u64) -> Result<u32, KernelError> {
    if flags & 0x7FFF_FFFC != 0 {
        return Ok(SYSTEM_IMAGE_INVALID_PARAMETER_4);
    }
    // SAFETY: PVOID* de saída do chamador de kernel.
    let (handle_out, base_out) = unsafe { (Field::<u64>::at(handle_out), Field::<u64>::at(base_out)) };
    base_out.set(0);
    let session = flags & MM_LOAD_IMAGE_IN_SESSION != 0;
    if session && flags & MM_LOAD_IMAGE_AND_LOCKDOWN != 0 {
        return Ok(SYSTEM_IMAGE_INVALID_PARAMETER_4);
    }
    // SAFETY: o EPROCESS corrente (PsGetCurrentProcess).
    if session && unsafe { crate::ntos::inc::types::Eprocess::at(crate::ntos::ps::process::get_current_process()) }.process_in_session() == 0 {
        return Ok(crate::ntos::mm::session_image::STATUS_NO_MEMORY);
    }
    let path = guest_strings::read_unicode_string(file_name);
    let file = String::from(system_image_file_name(&path));
    let mut base_name = if loaded_base_name != 0 { guest_strings::read_unicode_string(loaded_base_name) } else { file.clone() };
    if prefix != 0 {
        base_name = alloc::format!("{}{}", guest_strings::read_unicode_string(prefix), base_name);
    }
    let full_name = alloc::format!("{}{}", &path[..path.len() - file.len()], base_name);

    if let Some((entry, image_base)) = system_image_already_loaded(&base_name)? {
        handle_out.set(entry);
        base_out.set(image_base);
        // SAFETY: a entrada nativa da imagem já listada.
        if unsafe { KldrDataTableEntry::at(entry) }.flags.get() & loaded_images::DRIVER_DEPENDENT_DLL != 0 {
            return Ok(SYSTEM_IMAGE_ALREADY_LOADED_AS_DLL);
        }
        if session && crate::ntos::mm::session_image::is_session_image(image_base) {
            return Ok(match crate::ntos::mm::session_image::load_into_current(image_base) {
                Ok(_) => {
                    crate::ntos::init::initial_process::session_image_loaded(crate::ntos::mm::session::session_id(crate::ntos::ps::process::get_current_process()), &base_name);
                    0
                }
                Err(error) => {
                    debug_print!("[mm] MmLoadSystemImage {} na sessao: {}", path, error);
                    base_out.set(0);
                    if error.status & 0x8000_0000 != 0 { error.status } else { 0xC000_009A }
                }
            });
        }
        return Ok(if session { 0 } else { SYSTEM_IMAGE_ALREADY_LOADED });
    }

    let Ok(source) = kernel_image_source::source_for(&file) else { return Ok(SYSTEM_IMAGE_NAME_NOT_FOUND) };
    let mut image = match pe_loader::load_from_source(source, &LoadOptions { image_name: Some(full_name), session, ..LoadOptions::default() }) {
        Ok(image) => image,
        Err(error) => {
            debug_print!("[mm] MmLoadSystemImage {}: {}", path, error);
            return Ok(if error.status & 0x8000_0000 != 0 { error.status } else { SYSTEM_IMAGE_INVALID_FORMAT });
        }
    };
    let entry = match image.loaded_image.as_ref().map(|loaded| loaded.id) {
        Some(id) => system_image_entry(id)?,
        None => None,
    };
    let Some(entry) = entry else {
        if session {
            crate::ntos::mm::session_image::discard_new(&image);
        }
        image.release()?;
        return Err(KernelError::new("MmLoadSystemImage: kernel image without loader entry"));
    };
    handle_out.set(entry);
    base_out.set(image.image_base);
    if session {
        crate::ntos::mm::session_image::register(entry, image);
        crate::ntos::init::initial_process::session_image_loaded(crate::ntos::mm::session::session_id(crate::ntos::ps::process::get_current_process()), &base_name);
    } else {
        SYSTEM_IMAGES.lock().insert(entry, image);
    }
    Ok(0)
}

/// A entrada do loader de uma imagem do MmLoadSystemImage ainda listada
/// com esse nome-base.
fn loaded_system_image_entry(name: &str) -> Option<u64> {
    let image = loaded_images::find_by_base_name(name)?;
    system_image_entry(image.id).ok().flatten()
}

/// O import de outra imagem retém uma imagem do MmLoadSystemImage
/// (MiResolveImageReferences: LoadCount + 1).
fn reference_system_image(entry: u64) {
    // SAFETY: a KLDR_DATA_TABLE_ENTRY viva da imagem listada.
    let count = &unsafe { KldrDataTableEntry::at(entry) }.load_count;
    count.set(count.get().wrapping_add(1));
}

/// Solta uma referência de uma imagem do MmLoadSystemImage (o
/// MiUnloadSystemImage): a imagem de sistema só sai quando o LoadCount
/// chega a zero, e o import que a retinha a solta depois de um
/// MmUnloadSystemImage de quem a carregou (o hidparse.sys do win32k, liberado
/// pela classe 27 com o win32kfull.sys ainda importando dele). A imagem de
/// sessão sai da sessão pelo MmUnloadSystemImage ou no fim da sessão; o
/// import só conta.
fn dereference_system_image(entry: u64) -> Result<(), KernelError> {
    // SAFETY: a KLDR_DATA_TABLE_ENTRY viva da imagem listada.
    let count = &unsafe { KldrDataTableEntry::at(entry) }.load_count;
    let remaining = count.get().saturating_sub(1);
    count.set(remaining);
    if remaining != 0 {
        return Ok(());
    }
    let image = SYSTEM_IMAGES.lock().remove(&entry);
    if let Some(mut image) = image {
        image.release()?;
    }
    Ok(())
}

/// MmUnloadSystemImage: descarrega só o que MmLoadSystemImage carregou.
pub fn unload_system_image(handle: u64) -> Result<(), KernelError> {
    if SYSTEM_IMAGES.lock().contains_key(&handle) {
        return dereference_system_image(handle);
    }
    // SAFETY: a KLDR_DATA_TABLE_ENTRY do ImageHandle.
    let base = if handle != 0 { unsafe { KldrDataTableEntry::at(handle) }.dll_base.get() } else { 0 };
    if base != 0 && crate::ntos::mm::session_image::entry_of(base) == Some(handle) {
        crate::ntos::mm::session_image::unload_from_current(base)?;
    }
    Ok(())
}

// ---- MmChangeImageProtection (mm-change-image-protection) -------------------
//
// ntoskrnl 19041 (0x6fe5c0): MmChangeImageProtection(Mdl, Address, Size,
// Mode), a troca de proteção do código de uma imagem de sistema que o
// próprio driver reescreve (o clipsp.sys, com as seções PAGEwx):
// - Mode fora de {1, 2}, MDL sem exatamente MDL_PAGES_LOCKED entre os três
//   bits baixos (travado, sem mapeamento de sistema, fora do pool), com
//   ByteOffset ou ByteCount fora de página: STATUS_INVALID_PARAMETER;
// - sob o PsLoadedModuleResource, a entrada do loader do StartVa do MDL
//   (MiLookupDataTableEntry; ausente = STATUS_NOT_FOUND); o MDL e a faixa
//   [Address, Address + Size) precisam caber na imagem, com Size não nulo
//   (STATUS_CONFLICTING_ADDRESSES); Flags & 0x80000 marca uma troca em
//   andamento (STATUS_SHARING_VIOLATION), senão é ligado e o LoadCount
//   referencia a imagem até o fim;
// - imagem num mapeamento grande (MI_IS_PHYSICAL_ADDRESS) e páginas de PFN
//   protótipo = STATUS_CONFLICTING_ADDRESSES; páginas com o privilégio 0x40
//   do MiGetPagePrivilege = STATUS_INVALID_PAGE_PROTECTION;
// - MiSetImageProtection(MDL, MM_READONLY): as PTEs do MDL ficam somente
//   leitura e sem execução (no OpenNT só sem execução: ver
//   `set_image_protection`);
// - Mode 1: o SeCiCallbacks->CiValidateDynamicCodePages(contexto de
//   assinatura da seção da imagem, Mdl, Address, Size, Address - DllBase)
//   aprova o código novo (callback ausente = STATUS_NOT_IMPLEMENTED; a falha
//   volta com as páginas somente leitura) e o MiSetImageProtection devolve
//   MM_EXECUTE_READ;
// - Mode 2: as páginas ficam somente leitura (o MiClearPfnImageVerified só
//   existe com a CFG do kernel ligada);
// - desliga o 0x80000 e solta a referência (MiUnloadSystemImage).
// No OpenNT as imagens de kernel não têm SECTION nem contexto de assinatura
// por imagem (a CI devolve signatureContext 0), então o contexto é NULL; não
// há PFNs protótipo nem privilégios de página (VTL), e a CFG do kernel fica
// desligada (sem a variante 0x13 do MM_EXECUTE_READ).

const CHANGE_PROTECTION_INVALID_PARAMETER: u32 = 0xC000_000D;
const CHANGE_PROTECTION_NOT_FOUND: u32 = 0xC000_0225;
const CHANGE_PROTECTION_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
const CHANGE_PROTECTION_SHARING_VIOLATION: u32 = 0xC000_0043;
const CHANGE_PROTECTION_NOT_IMPLEMENTED: u32 = 0xC000_0002;
/// KLDR_DATA_TABLE_ENTRY.Flags: troca de proteção em andamento.
const IMAGE_PROTECTION_CHANGING: u32 = 0x0008_0000;
/// MDL_MAPPED_TO_SYSTEM_VA | MDL_PAGES_LOCKED | MDL_SOURCE_IS_NONPAGED_POOL e
/// o único valor aceito entre eles.
const MDL_LOW_FLAGS: i16 = 7;
const MDL_PAGES_LOCKED: i16 = 2;
/// Proteções do MiSetImageProtection (MM_*).
pub const MM_READONLY: u32 = 1;
pub const MM_EXECUTE_READ: u32 = 3;
pub const MM_EXECUTE_READWRITE: u32 = 6;

/// MiSetImageProtection/MiSetSystemCodeProtection: reescreve as PTEs de 4 KB
/// de [address, address + length) com a proteção MM_* dada. A execução segue
/// a proteção (MM_READONLY tira, MM_EXECUTE_READ e MM_EXECUTE_READWRITE
/// dão); a escrita fica como o carregador a mapeou, porque no OpenNT o
/// MmMapLockedPagesSpecifyCache de um MDL devolve a própria VA da imagem (não
/// um alias), e é por ela que o driver reescreve o código.
pub fn set_image_protection(address: u64, length: u64, protection: u32) -> Result<(), KernelError> {
    const NX: u64 = 1 << 63;
    let base = address & !0xFFF;
    let count = (address + length - base).div_ceil(0x1000);
    let mut pages = Vec::new();
    for index in 0..count {
        let va = base + index * 0x1000;
        let page = crate::ntos::mm::paging::query_page(va, false).ok_or_else(|| KernelError::new("MiSetImageProtection: image page not mapped"))?;
        if page.page_size != 0x1000 {
            return Err(KernelError::new("MiSetImageProtection: image page is not a 4 KB leaf"));
        }
        pages.push((va, page.entry_address));
    }
    let previous = crate::ntos::ke::irql::raise_irql(2);
    for &(va, entry) in &pages {
        loop {
            let before = crate::hal::physical::read64(entry);
            let after = if protection == MM_READONLY { before | NX } else { before & !NX };
            if crate::hal::physical::compare_exchange64(entry, before, after) == before {
                break;
            }
        }
        crate::hal::cpu::invalidate_page(va);
    }
    let flushed = if pages.is_empty() { Ok(()) } else { crate::ntos::ke::smp::flush_remote_tlb(false) };
    crate::ntos::ke::irql::lower_irql(previous as u64);
    flushed
}

/// MmChangeImageProtection(Mdl, Address, Size, Mode) -> NTSTATUS.
pub fn change_image_protection(mdl: u64, address: u64, size: u64, mode: u32) -> Result<u32, KernelError> {
    if !(1..=2).contains(&mode) {
        return Ok(CHANGE_PROTECTION_INVALID_PARAMETER);
    }
    // SAFETY: o PMDL travado do driver.
    let descriptor = unsafe { crate::ntos::inc::types::Mdl::at(mdl) };
    let byte_count = descriptor.byte_count.get() as u64;
    if descriptor.mdl_flags.get() & MDL_LOW_FLAGS != MDL_PAGES_LOCKED || descriptor.byte_offset.get() != 0 || byte_count & 0xFFF != 0 {
        return Ok(CHANGE_PROTECTION_INVALID_PARAMETER);
    }
    let start = descriptor.start_va.get();
    let (_, entries) = crate::ntos::mm::loaded_images::native_list()?;
    let Some(entry) = entries.into_iter().find(|(image, _)| start >= image.image_base && start < image.image_base + image.size_of_image).map(|(_, entry)| entry) else {
        return Ok(CHANGE_PROTECTION_NOT_FOUND);
    };
    // SAFETY: a entrada nativa do loader da imagem, viva enquanto listada.
    let loader = unsafe { KldrDataTableEntry::at(entry) };
    let base = loader.dll_base.get();
    let end = base + loader.size_of_image.get() as u64;
    let last = address.wrapping_add(size);
    if start + byte_count > end || address < base || last > end || last.wrapping_sub(1) < address {
        return Ok(CHANGE_PROTECTION_CONFLICTING_ADDRESSES);
    }
    if loader.flags.get() & IMAGE_PROTECTION_CHANGING != 0 {
        return Ok(CHANGE_PROTECTION_SHARING_VIOLATION);
    }
    loader.flags.set(loader.flags.get() | IMAGE_PROTECTION_CHANGING);
    loader.load_count.set(loader.load_count.get().wrapping_add(1));
    let result = (|| -> Result<u32, KernelError> {
        if crate::ntos::mm::paging::query_page(base, false).is_some_and(|page| page.page_size != 0x1000) {
            return Ok(CHANGE_PROTECTION_CONFLICTING_ADDRESSES);
        }
        set_image_protection(start, byte_count, MM_READONLY)?;
        if mode == 1 {
            let Some(status) = crate::ntos::se::code_integrity::validate_dynamic_code_pages(0, mdl, address, size, address - base) else {
                return Ok(CHANGE_PROTECTION_NOT_IMPLEMENTED);
            };
            if status & 0x8000_0000 != 0 {
                return Ok(status);
            }
            set_image_protection(start, byte_count, MM_EXECUTE_READ)?;
        }
        Ok(0)
    })();
    loader.flags.set(loader.flags.get() & !IMAGE_PROTECTION_CHANGING);
    loader.load_count.set(loader.load_count.get().wrapping_sub(1));
    result
}

// ---- MiCompactServiceTable e a carga que estende as tabelas de serviço ------
//
// (append de `ke-service-tables` ao mm/sysload.rs. Usa o que o arquivo já
// importa — `BTreeSet`, `Vec`, `Field`, `NtStruct`, `guest`, `SpinLock`,
// `KernelError` — e o `load_system_image`/`unload_system_image` acima, sem
// linhas `use` novas.)
//
// No ntoskrnl 19041, NtSetSystemInformation(SystemExtendServiceTableInformation)
// carrega "\SystemRoot\System32\win32k.sys" com LoadFlags 0x80000005; o bit 4
// faz o MmLoadSystemImageEx chamar o MiCompactServiceTable depois de
// relocar/resolver a imagem nova (e antes do DriverEntry). Ele acha os seis
// exports W32pServiceTable[Filter], W32pServiceLimit[Filter] e
// W32pArgumentTable[Filter] (faltou um: STATUS_PROCEDURE_NOT_FOUND), torna as
// duas tabelas graváveis (MiSetImageProtection), converte primeiro a filtro e
// depois a principal com o KeCompactServiceTable e as devolve a somente
// leitura. No disco as tabelas guardam RVAs (seção TABLERO, somente leitura,
// sem relocações); depois disso ficam no formato `(relativo << 4) | args` que
// o KeAddSystemServiceTable publica. Aqui a reescrita passa pelo alias
// físico das páginas (o mesmo efeito do RW -> escrita -> RO, sem mexer nas
// PTEs), e cada imagem é convertida uma única vez.

/// STATUS_PROCEDURE_NOT_FOUND (um dos exports W32p* ausente).
const SERVICE_TABLE_PROCEDURE_NOT_FOUND: u32 = 0xC000_007A;
/// O bit do LoadFlags do MmLoadSystemImageEx que pede a compactação.
pub const MM_LOAD_IMAGE_EXTENDS_SERVICE_TABLE: u32 = 4;
/// (tabela, limite, argumentos) na ordem do MiCompactServiceTable: a filtro
/// primeiro, depois a principal.
const SERVICE_TABLE_EXPORTS: [(&str, &str, &str); 2] = [
    ("W32pServiceTableFilter", "W32pServiceLimitFilter", "W32pArgumentTableFilter"),
    ("W32pServiceTable", "W32pServiceLimit", "W32pArgumentTable"),
];

/// Bases de imagem cujas tabelas já foram convertidas.
static COMPACTED_SERVICE_TABLES: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());

/// RtlFindExportedRoutineByName com um nome do kernel.
fn service_table_export(image_base: u64, name: &str) -> u64 {
    let mut text: Vec<u8> = name.as_bytes().to_vec();
    text.push(0);
    let pointer = guest::alloc_bytes(text.len() as u64);
    if pointer == 0 {
        return 0;
    }
    guest::write_bytes(pointer, &text);
    let address = crate::ntos::rtl::image::find_exported_routine_by_name(image_base, pointer);
    guest::free_bytes(pointer);
    address
}

/// Grava `values` a partir de `address` pelo alias físico de cada página
/// (a página da imagem continua somente leitura).
fn write_read_only_words(address: u64, values: &[u32]) -> Result<(), KernelError> {
    let bytes: Vec<u8> = values.iter().flat_map(|value| value.to_le_bytes()).collect();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let va = address + offset as u64;
        let chunk = ((0x1000 - (va & 0xFFF)) as usize).min(bytes.len() - offset);
        let physical = crate::ntos::mm::paging::translate(va);
        if physical == 0 {
            return Err(KernelError::new("MiCompactServiceTable: service table page not resident"));
        }
        crate::hal::physical::write_bytes(physical, &bytes[offset..offset + chunk]);
        offset += chunk;
    }
    Ok(())
}

/// MiCompactServiceTable(imagem): Ok(NTSTATUS).
pub fn compact_service_tables(image_base: u64) -> Result<u32, KernelError> {
    let mut tables = Vec::new();
    for (table, limit, arguments) in SERVICE_TABLE_EXPORTS {
        let addresses = [service_table_export(image_base, table), service_table_export(image_base, limit), service_table_export(image_base, arguments)];
        if addresses.contains(&0) {
            return Ok(SERVICE_TABLE_PROCEDURE_NOT_FOUND);
        }
        tables.push(addresses);
    }
    for [table, limit, arguments] in tables {
        // SAFETY: exports da imagem recém-carregada: o ULONG do limite, o
        // vetor de RVAs e o de bytes de argumentos com `count` entradas.
        let count = unsafe { Field::<u32>::at(limit) }.get() as usize;
        let (routines, argument_bytes) = unsafe { (Field::<u32>::array_at(table, count), Field::<u8>::array_at(arguments, count)) };
        let values = crate::ntos::ke::service_tables::compact_entries(table, image_base, routines, argument_bytes);
        write_read_only_words(table, &values)?;
    }
    Ok(0)
}

/// MmLoadSystemImageEx(ImageFileName, NULL, NULL, LoadFlags, ...) da
/// SystemExtendServiceTableInformation: a carga do MmLoadSystemImage (bits 0
/// e 1) e, com MM_LOAD_IMAGE_EXTENDS_SERVICE_TABLE, a compactação das
/// tabelas da imagem na primeira carga; falha na compactação descarrega.
pub fn load_system_image_extending_services(file_name: u64, flags: u32, handle_out: u64, base_out: u64) -> Result<u32, KernelError> {
    let status = load_system_image(file_name, 0, 0, flags & 3, handle_out, base_out)?;
    if status & 0x8000_0000 != 0 || flags & MM_LOAD_IMAGE_EXTENDS_SERVICE_TABLE == 0 {
        return Ok(status);
    }
    // SAFETY: as saídas acabaram de ser gravadas pelo MmLoadSystemImage.
    let (handle, image_base) = unsafe { (Field::<u64>::at(handle_out).get(), Field::<u64>::at(base_out).get()) };
    if !COMPACTED_SERVICE_TABLES.lock().insert(image_base) {
        return Ok(status);
    }
    let compacted = compact_service_tables(image_base);
    if !matches!(compacted, Ok(0)) {
        COMPACTED_SERVICE_TABLES.lock().remove(&image_base);
        unload_system_image(handle)?;
    }
    compacted
}
