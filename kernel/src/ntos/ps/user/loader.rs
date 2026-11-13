//! Loader de processos de usuário.
//!
//! A parte do kernel do que o NT faz com ZwCreateUserProcess: a ntdll real
//! do volume (com o mapa SSN → nome), o apiset schema real, os dados NLS,
//! as entradas LDR_DATA_TABLE_ENTRY e o binding de imports contra as
//! tabelas de exports reais das DLLs. Os módulos carregados e a ntdll
//! vivem em `LOADED_MODULES`/`NTDLL_MODULE`; o schema parseado, em `API_SET`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::memory;
use super::state::{self, write_unicode_string, write_user_bytes, write_user_wide, RegionKind, UserRegion};
use super::structures::insert_tail_list;
use super::syscall_scan;
use crate::hal::bundle;
use crate::ntos::ex::system_services;
use crate::drivers::fs::ntfs::{self, Ntfs};
use crate::drivers::fs::volume_files::{self, VolumeFile};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::rtl::api_set::{self, Schema};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::types::extra_ps_user::ApiSetNamespace;
use crate::ntos::inc::types::{ImageDosHeader, ImageImportByName, ImageImportDescriptor, ImageNtHeaders64, ImageThunkData64, LdrDataTableEntry, NtStruct, PebLdrData};

/// Índice do diretório de imports no DataDirectory do cabeçalho opcional.
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
use crate::ntos::ob::objects::file::FileSource;
use crate::ntos::mm::sysload::kernel_image_source::ImageSource;
use crate::ntos::rtl::image::pe_exports::Exports;
use crate::ntos::mm::pe_loader::{self, ImportSymbol, LoadOptions, ResolvedImport};
use crate::ntos::mm::sysload::pe_resolver::{self, ExportedModule, Symbol};

/// A ABI única de syscalls do bring-up, a mesma tabela que o build usa para
/// gerar a ntdll do bundle.
pub use crate::ntos::ke::services::SYSCALLS;

/// Módulo carregado no processo.
pub struct Module {
    pub name: String,
    pub full_name: String,
    pub image_base: u64,
    pub size_of_image: u64,
    pub entry_point: u64,
    pub exports: Exports,
    pub is_exe: bool,
    pub notification_source: Option<Arc<dyn FileSource>>,
}

impl Module {
    fn exported(&self) -> Arc<ExportedModule> {
        Arc::new(ExportedModule { name: self.name.clone(), exports: self.exports.clone() })
    }
}

/// Bytes de uma imagem em memória como fonte de arquivo (notificações e a
/// seção de imagem do processo).
pub struct BytesSource {
    pub name: String,
    pub bytes: Arc<Vec<u8>>,
}

impl FileSource for BytesSource {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, KernelError> {
        let start = (offset as usize).min(self.bytes.len());
        let end = start.saturating_add(length).min(self.bytes.len());
        Ok(self.bytes[start..end].to_vec())
    }
}

/// Imagem do processo sem vista de seção (ntdll, schema, DLLs do loader).
pub struct ImageRegion {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub file: Option<Arc<VolumeFile>>,
}

impl UserRegion for ImageRegion {
    fn base(&self) -> u64 {
        self.base
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn name(&self) -> Option<String> {
        Some(self.name.clone())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn push_image(base: u64, size: u64, name: String, file: Option<Arc<VolumeFile>>) {
    state::with(|state| state.regions(RegionKind::ProcessImages).push(Arc::new(ImageRegion { base, size, name, file })));
}

/// O volume de onde vêm a ntdll, o schema e o NLS.
static NTFS_VOLUME: SpinLock<Option<Arc<Ntfs>>> = SpinLock::new(None);
static LOADED_MODULES: SpinLock<BTreeMap<String, Arc<Module>>> = SpinLock::new(BTreeMap::new());
static NTDLL_MODULE: SpinLock<Option<Arc<Module>>> = SpinLock::new(None);
static API_SET: SpinLock<Option<Arc<Schema>>> = SpinLock::new(None);
/// A ntdll mapeada, registrada para as entradas LDR dos processos.
static NTDLL_IMAGE: SpinLock<(u64, u64)> = SpinLock::new((0, 0));

pub fn ntfs_volume() -> Option<Arc<Ntfs>> {
    let cached = NTFS_VOLUME.lock().clone();
    if cached.is_some() {
        return cached;
    }
    // O mesmo volume montado da E/S de arquivos (vê o que o boot escreveu).
    let volume = volume_files::volume().or_else(|| ntfs::mount(1).ok());
    *NTFS_VOLUME.lock() = volume.clone();
    volume
}

pub fn loaded_module(name: &str) -> Option<Arc<Module>> {
    LOADED_MODULES.lock().get(name).cloned()
}

pub fn ntdll_module() -> Option<Arc<Module>> {
    NTDLL_MODULE.lock().clone()
}

/// Reinício por processo: a ntdll sobrevive ao reset.
pub fn reset_loaded_modules() {
    let ntdll = ntdll_module();
    let mut modules = LOADED_MODULES.lock();
    modules.clear();
    if let Some(ntdll) = ntdll {
        modules.insert(String::from("ntdll.dll"), ntdll);
    }
}

/// A ntdll é mapeada uma vez por espaço de endereços e resolve os imports
/// por nome: a real do volume ou, sem ela, a de bring-up do bundle.
pub fn ensure_ntdll() -> Result<(), KernelError> {
    if state::with(|state| state.ntdll_exports.is_some()) {
        return Ok(());
    }
    let (bytes, origin) = read_ntdll_input()?;
    map_ntdll(bytes, origin)
}

pub fn read_ntdll_input() -> Result<(Vec<u8>, &'static str), KernelError> {
    if let Some(bytes) = ntfs_volume().and_then(|volume| volume.read_bytes("/NTDLL.DLL").ok().flatten()) {
        return Ok((bytes, "real (NTFS)"));
    }
    if let Some(bytes) = bundle::read("apps/ntdll.dll") {
        return Ok((bytes.to_vec(), "bring-up (bundle)"));
    }
    Err(KernelError::new("ntdll.dll ausente (NTFS e bundle)"))
}

fn ntdll_resolver(_dll: &str, symbol: &ImportSymbol) -> Option<ResolvedImport> {
    let ImportSymbol::Name(name) = symbol else { return None };
    let address = state::with(|state| state.ntdll_exports.as_ref().and_then(|exports| exports.get(name).copied()))?;
    Some(ResolvedImport::Address { address, dependencies: Vec::new() })
}

pub fn map_ntdll(bytes: Vec<u8>, origin: &str) -> Result<(), KernelError> {
    let source_name = if origin == "real (NTFS)" { "\\NTFS\\NTDLL.DLL" } else { "\\BootBundle\\apps\\ntdll.dll" };
    let image = pe_loader::load_user(bytes.clone(), &LoadOptions { notify_image: false, ..LoadOptions::default() })?;
    let exports = image.exports.exports.clone();
    state::with(|state| {
        state.ntdll_exports = Some(exports.clone());
        state.ntdll_image_base = image.image_base;
    });
    *NTDLL_IMAGE.lock() = (image.image_base, image.size_of_image);
    push_image(image.image_base, image.size_of_image, String::from(source_name), None);
    let module = Arc::new(Module {
        name: String::from("ntdll.dll"),
        full_name: String::from("C:\\Windows\\System32\\ntdll.dll"),
        image_base: image.image_base,
        size_of_image: image.size_of_image,
        entry_point: image.entry_point,
        exports: image.exports.clone(),
        is_exe: false,
        notification_source: Some(Arc::new(BytesSource { name: String::from(source_name), bytes: Arc::new(bytes) })),
    });
    LOADED_MODULES.lock().insert(String::from("ntdll.dll"), module.clone());
    *NTDLL_MODULE.lock() = Some(module);
    system_services::register(&syscall_scan::scan_syscall_stubs(&exports))?;
    pe_loader::register_resolver(|dll| dll.eq_ignore_ascii_case("ntdll.dll"), Arc::new(ntdll_resolver));
    let mapped = state::with(|state| state.name_by_number.len());
    crate::debug_print!("[usermode] ntdll.dll {} em {:#x} ({} exports, {} syscalls mapeados)", origin, image.image_base, exports.len(), mapped);
    // Sanidade da ABI: todo syscall implementado pelo kernel existe na DLL.
    for &(name, _) in SYSCALLS {
        if !exports.contains_key(name) {
            crate::debug_print!("[usermode] AVISO: ntdll sem {}", name);
        }
    }
    Ok(())
}

fn require_volume(purpose: &str) -> Result<Arc<Ntfs>, KernelError> {
    ntfs_volume().ok_or_else(|| KernelError::new(alloc::format!("NTFS indisponivel p/ {purpose}")))
}

/// O schema mora na seção .apiset; o ApiSetMap aponta para o
/// API_SET_NAMESPACE no início dela, mapeada como imagem.
pub fn ensure_api_set_schema() -> Result<(), KernelError> {
    if state::with(|state| state.api_set_map_va != 0) {
        return Ok(());
    }
    let volume = require_volume("apisetschema")?;
    let bytes = volume.read_bytes("/APISETSCHEMA.DLL")?.ok_or_else(|| KernelError::new("APISETSCHEMA.DLL ausente no volume"))?;
    let image = pe_loader::load_user(bytes, &LoadOptions { skip_imports: true, no_execute: true, notify_image: false, ..LoadOptions::default() })?;
    let section = image.sections.iter().find(|section| section.name == ".apiset").ok_or_else(|| KernelError::new("apisetschema sem secao .apiset"))?;
    let map = image.image_base + section.va as u64;
    state::with(|state| state.api_set_map_va = map);
    push_image(image.image_base, image.size_of_image, String::from("\\NTFS\\APISETSCHEMA.DLL"), None);
    crate::debug_print!("[usermode] apiset schema em {:#x} ({} bytes)", map, section.virtual_size);
    Ok(())
}

/// Dados NLS reais (C_1252/C_437/l_intl.nls), compartilhados entre
/// processos: o RtlInitNlsTables da ntdll os lê pelo PEB.
pub fn ensure_nls_data() -> Result<state::NlsVas, KernelError> {
    if let Some(vas) = state::with(|state| state.nls_vas) {
        return Ok(vas);
    }
    let volume = require_volume("dados NLS")?;
    state::with(|state| state.nls_vas = Some(state::NlsVas::default()));
    for (path, key) in [("/C_1252.NLS", 0), ("/C_437.NLS", 1), ("/L_INTL.NLS", 2)] {
        let bytes = volume.read_bytes(path)?.ok_or_else(|| KernelError::new(alloc::format!("{path} ausente no volume")))?;
        let va = memory::map_shared_user_region((bytes.len() as u64).div_ceil(0x1000) * 0x1000)?;
        write_user_bytes(va, &bytes)?;
        state::with(|state| {
            if let Some(vas) = state.nls_vas.as_mut() {
                match key {
                    0 => vas.ansi = va,
                    1 => vas.oem = va,
                    _ => vas.unicode = va,
                }
            }
        });
        crate::debug_print!("[usermode] NLS {} em {:#x} ({} bytes)", path, va, bytes.len());
    }
    Ok(state::with(|state| state.nls_vas.unwrap_or_default()))
}

/// Schema v6 parseado uma vez do mapeamento real.
pub fn parse_api_set_schema() -> Result<(), KernelError> {
    if API_SET.lock().is_some() {
        return Ok(());
    }
    let base = state::with(|state| state.api_set_map_va);
    // SAFETY: a seção .apiset mapeada pelo próprio loader do kernel.
    let size = unsafe { ApiSetNamespace::at(base) }.size.get() as usize;
    let bytes = guest::read_bytes(base, size);
    let schema = api_set::parse(&bytes)?;
    crate::debug_print!("[usermode] apiset schema: contratos parseados");
    *API_SET.lock() = Some(Arc::new(schema));
    Ok(())
}

/// Área de strings das entradas LDR (bump próprio por processo).
pub fn place_user_string(text: &str) -> Result<u64, KernelError> {
    let need = (text.encode_utf16().count() as u64 + 1) * 2 + 8;
    let (next, end) = state::with(|state| (state.next_ldr_string_va, state.ldr_string_region_end));
    if next == 0 || next + need > end {
        let region = memory::map_user_region(0x4000)?;
        state::with(|state| {
            state.next_ldr_string_va = region;
            state.ldr_string_region_end = region + 0x4000;
        });
    }
    let va = state::with(|state| {
        let va = state.next_ldr_string_va;
        state.next_ldr_string_va += need;
        va
    });
    write_user_wide(va, text);
    Ok(va)
}

/// A mesma entrada para o exe, a ntdll e as DLLs carregadas; a ordem de
/// inicialização é a de carga (dependências primeiro).
pub fn create_ldr_entry(module: &Module) -> Result<u64, KernelError> {
    let entry = memory::map_user_region(LdrDataTableEntry::SIZE)?;
    // SAFETY: região do processo recém-comprometida pelo kernel.
    let record = unsafe { LdrDataTableEntry::at(entry) };
    record.dll_base.set(module.image_base);
    // RVA 0 no PE é EntryPoint nulo, não a base.
    let entry_point = if module.is_exe || module.entry_point <= module.image_base { 0 } else { module.entry_point };
    record.entry_point.set(entry_point);
    record.size_of_image.set(module.size_of_image as u32);
    let full = place_user_string(&module.full_name)?;
    write_unicode_string(record.full_dll_name.address(), full, &module.full_name);
    let base = place_user_string(&module.name)?;
    write_unicode_string(record.base_dll_name.address(), base, &module.name);
    // LDRP_STATIC_LINK | LDRP_ENTRY_PROCESSED [| LDRP_IMAGE_DLL].
    record.flags.set(0x4002 | if module.is_exe { 0 } else { 0x4 });
    record.obsolete_load_count.set(0xFFFF);
    // SAFETY: o PEB_LDR_DATA do processo corrente, montado pelo kernel.
    let ldr = unsafe { PebLdrData::at(state::with(|state| state.current_ldr_va)) };
    insert_tail_list(&ldr.in_load_order_module_list, &record.in_load_order_links);
    insert_tail_list(&ldr.in_memory_order_module_list, &record.in_memory_order_links);
    insert_tail_list(&ldr.in_initialization_order_module_list, &record.in_initialization_order_links);
    Ok(entry)
}

/// Nome ASCII com NUL da imagem mapeada pelo kernel.
fn read_ascii(cursor: u64) -> String {
    guest_strings::read_c_string(cursor)
}

/// Resolve cada import da imagem mapeada contra os exports reais das DLLs,
/// carregadas recursivamente antes (a dependência precisa estar pronta).
pub fn bind_imports(image_base: u64, depth: u32) -> Result<(), KernelError> {
    let importer = state::with(|state| state.regions(RegionKind::ProcessImages).iter().find(|image| image.base() == image_base).and_then(|image| image.name())).unwrap_or_default();
    // SAFETY: imagem mapeada pelo loader do kernel (cabeçalhos validados na carga).
    let headers = unsafe { ImageNtHeaders64::at(image_base + ImageDosHeader::at(image_base).e_lfanew.get() as u64) };
    let directory = headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address.get() as u64;
    if directory == 0 {
        return Ok(());
    }
    let mut descriptor = image_base + directory;
    loop {
        // SAFETY: tabela de imports da imagem, terminada por um descritor nulo.
        let import = unsafe { ImageImportDescriptor::at(descriptor) };
        let lookup = import.original_first_thunk.get() as u64;
        let name = import.name.get() as u64;
        let iat = import.first_thunk.get() as u64;
        if lookup == 0 && name == 0 && iat == 0 {
            return Ok(());
        }
        let dependency_name = read_ascii(image_base + name);
        crate::debug_print!("[usermode]   imports de {}", dependency_name);
        let dependency = load_dll_by_name(&dependency_name, depth + 1, &importer)?.exported();
        let table = if lookup != 0 { lookup } else { iat };
        let mut slot = 0u64;
        loop {
            // SAFETY: vetores de thunks da tabela de imports, terminados por zero.
            let (thunk, bound) = unsafe { (ImageThunkData64::at(image_base + table + slot * ImageThunkData64::SIZE), ImageThunkData64::at(image_base + iat + slot * ImageThunkData64::SIZE)) };
            let value = thunk.u1.ordinal.get();
            if value == 0 {
                break;
            }
            // IMAGE_ORDINAL_FLAG64, ou o RVA do IMAGE_IMPORT_BY_NAME.
            let symbol = if value >> 63 != 0 { Symbol::Ordinal(value as u32 & 0xFFFF) } else { Symbol::Name(read_ascii(unsafe { ImageImportByName::at(image_base + value as u32 as u64) }.name.as_ptr() as u64)) };
            let mut loader = |name: &str, parent: &str| load_dll_by_name(name, depth + 1, parent).map(|module| module.exported());
            let address = pe_resolver::resolve_export(&dependency, &symbol, &mut loader, &mut BTreeSet::new())?;
            bound.u1.function.set(address);
            slot += 1;
        }
        descriptor += ImageImportDescriptor::SIZE;
    }
}

/// Fonte de imagem sobre um arquivo do volume.
struct VolumeImageSource {
    name: String,
    file: Arc<VolumeFile>,
}

impl ImageSource for VolumeImageSource {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        self.file.size()
    }
    fn read_bytes(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
        self.file.read_at(offset, length)
    }
    fn supports_copy_to_physical(&self) -> bool {
        true
    }
    fn copy_to_physical(&self, offset: u64, address: u64, length: u64) -> Option<Result<(), KernelError>> {
        Some(self.file.copy_to_physical(offset, address, length))
    }
}

/// Carrega uma DLL do volume: mapeia, registra e resolve os imports.
pub fn load_dll_by_name(dll_name: &str, depth: u32, importer: &str) -> Result<Arc<Module>, KernelError> {
    if depth > 128 {
        return Err(KernelError::new(alloc::format!("cadeia de dependencias excessiva: {dll_name}")));
    }
    let lower = dll_name.to_lowercase();
    // apiset: contrato → hospedeira.
    let file_name = if lower.starts_with("api-") || lower.starts_with("ext-") {
        let schema = API_SET.lock().clone();
        schema.and_then(|schema| schema.resolve(&lower, importer)).ok_or_else(|| KernelError::new(alloc::format!("apiset sem host: {dll_name}")))?
    } else {
        lower.clone()
    };
    if let Some(module) = loaded_module(&file_name) {
        return Ok(module);
    }
    if file_name != lower {
        crate::debug_print!("[usermode] carrega DLL: {} (host: {})", dll_name, file_name);
    } else {
        crate::debug_print!("[usermode] carrega DLL: {}", dll_name);
    }
    let file = volume_files::lookup_volume_file(&alloc::format!("\\??\\C:\\Windows\\System32\\{file_name}"))
        .or_else(|| volume_files::lookup_volume_file(&file_name))
        .ok_or_else(|| KernelError::new(alloc::format!("DLL ausente no volume: {file_name}")))?;
    let image_name = alloc::format!("\\NTFS{}", file.volume_path().replace('/', "\\"));
    let source: Arc<dyn ImageSource> = Arc::new(VolumeImageSource { name: image_name.clone(), file: file.clone() });
    let image = pe_loader::load_from_source(source, &LoadOptions { user_space: true, skip_imports: true, image_name: Some(image_name), ..LoadOptions::default() })?;
    let module = Arc::new(Module {
        name: file_name.clone(),
        full_name: alloc::format!("C:\\Windows\\System32\\{file_name}"),
        image_base: image.image_base,
        size_of_image: image.size_of_image,
        entry_point: image.entry_point,
        exports: image.exports.clone(),
        is_exe: false,
        notification_source: None,
    });
    LOADED_MODULES.lock().insert(file_name.to_string(), module.clone());
    push_image(image.image_base, image.size_of_image, file.nt_path(), Some(file));
    bind_imports(image.image_base, depth + 1)?;
    // Dependências inicializadas antes do importador.
    create_ldr_entry(&module)?;
    Ok(module)
}
