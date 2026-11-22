//! Loader de executáveis PE32+ (x86-64).
//!
//! Faz o parse do PE, copia cabeçalhos e seções para frames do PFN, mapeia a
//! imagem na VA escolhida, aplica relocações, semeia o cookie GS e resolve a
//! IAT pelos resolvedores registrados (endereços nativos de outros módulos ou
//! exports do kernel). Os encaminhamentos de exports são resolvidos pelo
//! gerenciador de módulos.
//!
//! Imagem de kernel (driver, hal.dll, biblioteca de export): como no
//! MiLoadSystemImage do NT, a VA vem do espaço de sistema (a janela
//! `memory_map::SYSTEM_IMAGE_BASE..TOP`), nunca da ImageBase do cabeçalho, e
//! a imagem é relocada pela diferença; a entrada dela entra na lista de
//! imagens carregadas antes dos imports, com LOAD_IN_PROGRESS ligado até a
//! IAT estar resolvida (o MiConstructLoaderEntry antes do
//! MiResolveImageImports). Imagem de usuário: sempre do processo
//! corrente (o anexado, quando há attach), mapeada na raiz carregada; a base
//! preferida do cabeçalho quando a faixa está livre no espaço dele (o VAD,
//! as faixas de sistema e as PTEs da raiz), senão a primeira faixa livre a
//! partir de 64 KB (relocada). A liberação desfaz as PTEs na mesma raiz.
//!
//! Imagem de sessão (`LoadOptions::session`, o MM_LOAD_IMAGE_IN_SESSION):
//! a VA vem da faixa de imagens de sessão (a mesma em todas as sessões), os
//! frames da carga ficam como a cópia mestra (relocada, com a IAT e o cookie)
//! e nada é mapeado no sistema: a imagem pronta entra na sessão corrente
//! pelo `mm::session_image`, com o código nos frames mestres e cópias
//! privadas das páginas graváveis.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::mm::sysload::kernel_image_source::{ImageSource, MemorySource};
use crate::ntos::rtl::image::pe_exports::{self, Exports};
use crate::ntos::rtl::image::pe_image_information;
use crate::ntos::rtl::image::pe_metadata_reader::MetadataReader;
use crate::hal::{cpu, physical};
use crate::ntos::ke::smp;
use crate::ntos::mm::section::{address as section_address, image_header};
use crate::ntos::mm::{kernel_address, loaded_images, memory_map, paging, pfn, process_address_space};
use crate::ntos::ob::objects::file::FileSource;
use crate::ntos::ps::notify::image as image_notify;
use crate::rtl::{KernelError, SpinLock};

/// Bytes por trampolim da tabela de thunks (`hal::amd64::win32_thunk`).
const STUB_SIZE: u64 = 10;
/// IMAGE_FILE_RELOCS_STRIPPED: a imagem só roda na própria ImageBase.
const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
/// STATUS_CONFLICTING_ADDRESSES: imagem sem relocações fora da ImageBase.
const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
/// STATUS_INSUFFICIENT_RESOURCES: sem VA de sistema ou sem frames.
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Faixas de VA das imagens.
struct Arenas {
    /// Primeira VA nunca usada da janela de imagens de sistema.
    next_system: u64,
    /// Faixas devolvidas da janela de sistema (base, tamanho), ordenadas e
    /// coalescidas, todas abaixo de `next_system`.
    free_system: Vec<(u64, u64)>,
    /// Primeira VA nunca usada e faixas devolvidas da faixa de imagens de
    /// sessão.
    next_session: u64,
    free_session: Vec<(u64, u64)>,
    /// Faixas ocupadas pelas imagens de usuário (raiz, base, fim), por raiz:
    /// a mesma VA pode estar em uso em dois espaços. As de kernel ficam só na
    /// janela de sistema e nunca entram aqui.
    preferred_ranges: Vec<(u64, u64, u64)>,
}

static ARENAS: SpinLock<Arenas> = SpinLock::new(Arenas {
    next_system: memory_map::SYSTEM_IMAGE_BASE,
    free_system: Vec::new(),
    next_session: memory_map::SESSION_IMAGE_BASE,
    free_session: Vec::new(),
    preferred_ranges: Vec::new(),
});

/// Reserva a faixa de uma imagem de kernel na janela de sistema: a primeira
/// que couber a partir da base, em múltiplos de `SYSTEM_IMAGE_ALIGN` (o papel
/// da reserva de PTEs de sistema do MiLoadSystemImage).
/// Com `session`, a reserva vem da faixa de imagens de sessão.
fn reserve_image_range(size: u64, session: bool) -> Result<(u64, u64), KernelError> {
    let length = size.div_ceil(memory_map::SYSTEM_IMAGE_ALIGN) * memory_map::SYSTEM_IMAGE_ALIGN;
    if length == 0 {
        return Err(KernelError::new("PE: SizeOfImage nulo"));
    }
    let mut arenas = ARENAS.lock();
    let arenas = &mut *arenas;
    let (next, free, top) = if session { (&mut arenas.next_session, &mut arenas.free_session, memory_map::SESSION_IMAGE_TOP) } else { (&mut arenas.next_system, &mut arenas.free_system, memory_map::SYSTEM_IMAGE_TOP) };
    if let Some(index) = free.iter().position(|&(_, available)| available >= length) {
        let base = free[index].0;
        free[index].0 += length;
        free[index].1 -= length;
        if free[index].1 == 0 {
            free.remove(index);
        }
        return Ok((base, base + length));
    }
    let base = *next;
    if top - base < length {
        return Err(KernelError::with_status("janela de imagens de sistema esgotada", STATUS_INSUFFICIENT_RESOURCES));
    }
    *next = base + length;
    Ok((base, base + length))
}

/// Devolve a faixa à janela de sistema, coalesce com as vizinhas e recua o
/// topo usado quando a última faixa livre encosta nele.
fn release_system_image_range((base, top): (u64, u64)) {
    let mut arenas = ARENAS.lock();
    let arenas = &mut *arenas;
    let session = memory_map::is_session_address(base);
    let (next, free) = if session { (&mut arenas.next_session, &mut arenas.free_session) } else { (&mut arenas.next_system, &mut arenas.free_system) };
    free.push((base, top - base));
    free.sort_unstable();
    let mut index = 0;
    while index + 1 < free.len() {
        if free[index].0 + free[index].1 == free[index + 1].0 {
            free[index].1 += free[index + 1].1;
            free.remove(index + 1);
        } else {
            index += 1;
        }
    }
    if let Some(&(last, length)) = free.last() {
        if last + length == *next {
            *next = last;
            free.pop();
        }
    }
}

fn preferred_range_is_free(ranges: &[(u64, u64, u64)], root: u64, base: u64, size: u64) -> bool {
    ranges.iter().filter(|&&(owner, _, _)| owner == root).all(|&(_, used_base, used_top)| !(base < used_top && base + size > used_base))
}

/// O que o Ps lê do cabeçalho antes de mapear a imagem.
#[derive(Clone, Copy, Debug)]
pub struct ImageLayout {
    pub preferred_base: u64,
    pub size_of_image: u64,
    /// FileHeader.Characteristics (IMAGE_FILE_*).
    pub characteristics: u16,
    /// OptionalHeader.DllCharacteristics.
    pub dll_characteristics: u16,
}

/// ImageBase preferida, SizeOfImage e as características do cabeçalho, sem
/// mapear nada (o Ps cria o processo, e o espaço dele, antes de a imagem ser
/// mapeada nele).
pub fn image_layout(source: &dyn ImageSource) -> Result<ImageLayout, KernelError> {
    let metadata = MetadataReader::new(source);
    if metadata.read_u16(0)? != 0x5A4D {
        return Err(KernelError::new("MZ ausente (nao e PE)"));
    }
    let pe_header = metadata.read_u32(0x3C)? as u64;
    if metadata.read_u32(pe_header)? != 0x4550 {
        return Err(KernelError::new("assinatura PE ausente"));
    }
    let optional = pe_header + 24;
    if metadata.read_u16(optional)? != 0x20B {
        return Err(KernelError::new("nao e PE32+"));
    }
    let preferred_base = metadata.read_u32(optional + 24)? as u64 | (metadata.read_u32(optional + 28)? as u64) << 32;
    Ok(ImageLayout { preferred_base, size_of_image: metadata.read_u32(optional + 56)? as u64, characteristics: metadata.read_u16(pe_header + 22)? as u16, dll_characteristics: metadata.read_u16(optional + 70)? as u16 })
}

/// Dependência retida por um import nativo (outro módulo carregado).
pub trait ImageDependency: Send + Sync {
    fn retain(&self);
    fn release(&self) -> Result<(), KernelError>;
}

/// Resultado de um resolvedor: endereço nativo (com as dependências que o
/// importador passa a reter) ou índice da tabela de trampolins.
pub enum ResolvedImport {
    Address { address: u64, dependencies: Vec<Arc<dyn ImageDependency>> },
    Thunk(u32),
}

/// Símbolo importado: nome ou ordinal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportSymbol {
    Name(String),
    Ordinal(u32),
}

pub type ImportLookup = Arc<dyn Fn(&str, &ImportSymbol) -> Option<ResolvedImport> + Send + Sync>;

struct Resolver {
    pattern: fn(&str) -> bool,
    lookup: ImportLookup,
}

/// Imagens nativas carregadas (base → tamanho e seções), para a residência
/// das imagens de drivers (`mm::image_paging`).
static NATIVE_IMAGES: SpinLock<alloc::collections::BTreeMap<u64, (u64, Vec<SectionInfo>)>> = SpinLock::new(alloc::collections::BTreeMap::new());

/// Tamanho e seções de um driver nativo carregado por este loader.
pub fn native_image(image_base: u64) -> Option<(u64, Vec<SectionInfo>)> {
    NATIVE_IMAGES.lock().get(&image_base).cloned()
}

/// Exports das imagens de kernel cujos imports estão sendo resolvidos (as
/// entradas com LOAD_IN_PROGRESS), pelo id da imagem carregada: lidos da
/// imagem já mapeada e relocada, antes de qualquer import.
static RESOLVING: SpinLock<alloc::collections::BTreeMap<u64, Arc<Exports>>> = SpinLock::new(alloc::collections::BTreeMap::new());

/// Exports de uma imagem em resolução de imports (`None` = a imagem já
/// terminou a carga ou não é deste loader).
pub fn resolving_exports(id: u64) -> Option<Arc<Exports>> {
    RESOLVING.lock().get(&id).cloned()
}

/// Ponto de entrada (RVA) e presença do export DllInitialize, lidos do
/// arquivo sem mapear a imagem: o sysload decide por eles se um import é
/// uma DLL (DllInitialize, ou sem ponto de entrada) ou um driver.
pub fn file_entry_and_initialize(source: &dyn ImageSource) -> Result<(u64, bool), KernelError> {
    let metadata = MetadataReader::new(source);
    let pe_header = metadata.read_u32(0x3C)? as u64;
    let coff = pe_header + 4;
    let section_count = metadata.read_u16(coff + 2)? as u64;
    let optional = coff + 20;
    let section_table = optional + metadata.read_u16(coff + 16)? as u64;
    let entry_rva = metadata.read_u32(optional + 16)? as u64;
    let size_of_image = metadata.read_u32(optional + 56)? as u64;
    let size_of_headers = metadata.read_u32(optional + 60)? as u64;
    let (export_rva, export_size) = (metadata.read_u32(optional + 112)? as u64, metadata.read_u32(optional + 116)? as u64);
    let read_rva = |rva: u64, length: u64| -> Result<Vec<u8>, KernelError> {
        if rva.checked_add(length).is_none_or(|end| end > size_of_image) {
            return Err(KernelError::new(alloc::format!("PE: RVA {rva:#x} fora da imagem")));
        }
        source.read_bytes(section_file_offset(&metadata, section_table, section_count, size_of_headers, rva)?, length)
    };
    let exports = pe_exports::read_exports(&read_rva, 0, size_of_image, export_rva, export_size)?;
    Ok((entry_rva, exports.exports.contains_key("DllInitialize")))
}

/// Os nomes dos módulos que a imagem importa (o API set já resolvido para o
/// módulo que o hospeda), sem resolver nada: o que o winload lê para trazer
/// as dependências dos drivers de boot.
pub fn import_names(source: &dyn ImageSource) -> Result<Vec<String>, KernelError> {
    let metadata = MetadataReader::new(source);
    let pe_header = metadata.read_u32(0x3C)? as u64;
    let coff = pe_header + 4;
    let section_count = metadata.read_u16(coff + 2)? as u64;
    let optional = coff + 20;
    let section_table = optional + metadata.read_u16(coff + 16)? as u64;
    let size_of_headers = metadata.read_u32(optional + 60)? as u64;
    let import_rva = metadata.read_u32(optional + 120)? as u64;
    let mut names = Vec::new();
    if import_rva == 0 {
        return Ok(names);
    }
    let importer = String::from(source.name());
    let mut descriptor = section_file_offset(&metadata, section_table, section_count, size_of_headers, import_rva)?;
    loop {
        let ilt_rva = metadata.read_u32(descriptor)?;
        let name_rva = metadata.read_u32(descriptor + 12)? as u64;
        let iat_rva = metadata.read_u32(descriptor + 16)?;
        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }
        let dll = read_c_string(&metadata, section_file_offset(&metadata, section_table, section_count, size_of_headers, name_rva)?)?;
        let lower = dll.to_lowercase();
        let host = if lower.starts_with("api-") || lower.starts_with("ext-") { crate::ntos::mm::sysload::kernel_api_set::resolve(&dll, &importer)? } else { Some(dll) };
        if let Some(host) = host {
            names.push(host);
        }
        descriptor += 20;
    }
    Ok(names)
}

static RESOLVERS: SpinLock<Vec<Resolver>> = SpinLock::new(Vec::new());
/// (base física, quantidade) da tabela de trampolins.
static THUNK_TABLE: SpinLock<Option<(u64, u32)>> = SpinLock::new(None);

pub fn register_resolver(pattern: fn(&str) -> bool, lookup: ImportLookup) {
    RESOLVERS.lock().push(Resolver { pattern, lookup });
}

pub fn set_thunk_table(table: Option<(u64, u32)>) {
    *THUNK_TABLE.lock() = table;
}

fn resolve(dll: &str, symbol: &ImportSymbol) -> Option<ResolvedImport> {
    let lookup = RESOLVERS.lock().iter().find(|resolver| (resolver.pattern)(dll)).map(|resolver| resolver.lookup.clone())?;
    lookup(dll, symbol)
}

/// Decisão da integridade de código sobre a imagem.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodeIntegrity {
    pub status: u32,
    pub validation_mode: u32,
    pub signature_context: u64,
    pub signing_level: u32,
}

/// Validação da CI: decisão, fonte retida e liberação.
pub struct Validation {
    pub result: CodeIntegrity,
    pub source: Arc<dyn ImageSource>,
    pub release: Box<dyn FnOnce() + Send>,
}

pub type KernelImageValidator = fn(&Arc<dyn ImageSource>, &LoadOptions) -> Result<Validation, KernelError>;

static VALIDATOR: SpinLock<Option<KernelImageValidator>> = SpinLock::new(None);

/// Instalado pela CI depois da inicialização da política original.
pub fn register_kernel_image_validator(validator: KernelImageValidator) -> Result<(), KernelError> {
    let mut current = VALIDATOR.lock();
    if current.is_some() {
        return Err(KernelError::new("invalid kernel image validator registration"));
    }
    *current = Some(validator);
    Ok(())
}

/// Vista parcial de uma imagem de usuário.
#[derive(Clone, Copy, Debug)]
pub struct UserView {
    pub base: u64,
    pub offset: u64,
    pub size: u64,
}

/// Sem `user_space`, a imagem é de kernel e vai para a janela de sistema.
#[derive(Clone, Debug)]
pub struct LoadOptions {
    pub user_space: bool,
    pub skip_imports: bool,
    pub user_view: Option<UserView>,
    pub no_execute: bool,
    pub skip_relocations: bool,
    pub skip_security_cookie: bool,
    pub image_name: Option<String>,
    pub notify_image: bool,
    /// Imagem de sessão (MM_LOAD_IMAGE_IN_SESSION): VA de sessão, frames
    /// mestres, mapeada na sessão corrente por `mm::session_image`.
    pub session: bool,
    /// Com `user_space`: só as páginas protótipo da control area de uma
    /// seção de imagem (`mm/section/image_segment.rs`), na ImageBase do
    /// cabeçalho, sem VA, sem mapeamento em raiz alguma e sem a tabela de
    /// exports; as vistas mapeiam esses frames.
    pub prototype: bool,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self { user_space: false, skip_imports: false, user_view: None, no_execute: false, skip_relocations: false, skip_security_cookie: false, image_name: None, notify_image: true, session: false, prototype: false }
    }
}

/// A proteção Win32 de cada página de uma imagem de usuário pelas
/// características das seções que a cobrem (os cabeçalhos são legíveis):
/// PAGE_NOACCESS fora de toda seção, PAGE_READONLY/READWRITE e as variantes
/// EXECUTE. Sem execução (SEC_IMAGE_NO_EXECUTE), tudo é PAGE_READONLY. A
/// imagem plana é toda MM_EXECUTE_WRITECOPY: PAGE_EXECUTE_READWRITE sobre a
/// cópia privada de cada vista.
fn user_page_protection(page: u64, size_of_headers: u64, sections: &[SectionInfo], no_execute: bool, flat: bool) -> u32 {
    if no_execute {
        return 2;
    }
    if flat {
        return 0x40;
    }
    let mut characteristics = if page < size_of_headers { 0x4000_0000u32 } else { 0 };
    for section in sections {
        let start = section.va as u64;
        let length = section.virtual_size.max(section.raw_size) as u64;
        if page < start + length && page + 4096 > start {
            characteristics |= section.characteristics;
        }
    }
    let present = characteristics & 0xE000_0000 != 0;
    let writable = characteristics & 0x8000_0000 != 0;
    let nx = characteristics & 0x2000_0000 == 0;
    if !present {
        1
    } else if nx {
        if writable { 4 } else { 2 }
    } else if writable {
        0x40
    } else {
        0x20
    }
}

/// A proteção Win32 de cada página de uma imagem de usuário já carregada
/// pelas seções do PE ([`user_page_protection`], o SizeOfHeaders lido do
/// cabeçalho no primeiro frame): a que a vista de imagem do 19041 dá a cada
/// página, para quem mapeia as páginas da imagem em outros processos (a
/// ntdll de sistema, `ps/user/loader`).
pub fn user_section_protections(image: &PeImage) -> Vec<u32> {
    let Some(&header) = image.pages.first() else { return Vec::new() };
    let e_lfanew = physical::read32(header + 0x3C) as u64;
    // IMAGE_NT_HEADERS64: Signature (4), FileHeader (20), e o SizeOfHeaders
    // a 60 bytes do IMAGE_OPTIONAL_HEADER64.
    let size_of_headers = if e_lfanew + 24 + 64 <= 0x1000 { physical::read32(header + e_lfanew + 24 + 60) as u64 } else { 0x1000 };
    (0..image.size_of_image.div_ceil(0x1000)).map(|index| user_page_protection(index * 0x1000, size_of_headers, &image.sections, false, false)).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub va: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedImportRecord {
    pub dll: String,
    pub name: String,
    pub rva: u64,
    pub address: u64,
    pub native_default: bool,
}

#[derive(Default)]
struct Owned {
    /// Faixa da janela de imagens de sistema (imagem de kernel).
    system_range: Option<(u64, u64)>,
    /// Faixa em `preferred_ranges` (imagem de usuário).
    range: Option<(u64, u64, u64)>,
    /// A raiz em que as páginas de uma imagem de usuário foram mapeadas (a
    /// do processo dono); 0 numa imagem de kernel (metade de sistema, a
    /// mesma em toda raiz).
    root: u64,
    mapped: Vec<u64>,
    dependencies: Vec<Arc<dyn ImageDependency>>,
    registered: Option<u64>,
    native_base: Option<u64>,
    /// Frames do PFN da imagem, um por página.
    frames: Vec<u64>,
    released: bool,
}

impl Owned {
    fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        if let Some(id) = self.registered.take() {
            loaded_images::unregister(id)?;
        }
        if let Some(base) = self.native_base.take() {
            NATIVE_IMAGES.lock().remove(&base);
        }
        let root = if self.root != 0 { self.root } else { paging::current_root() };
        // A imagem de um processo volta antes do espaço dele (o término
        // devolve o VAD e as imagens antes do MmDeleteProcessAddressSpace);
        // uma raiz que já não existe não é editada.
        if self.root != 0 && !self.mapped.is_empty() && !process_address_space::is_root(root) {
            debug_print!("[pe] imagem de usuario em {:#x}: a raiz {:#x} ja foi devolvida", self.mapped[0], root);
            self.mapped.clear();
        }
        for &address in &self.mapped {
            paging::unmap_page_in(root, address, paging::MapOptions::default());
        }
        let mut failure = None;
        // Outra CPU pode guardar a tradução antiga: a VA de sistema e os
        // frames só voltam ao uso depois da invalidação em todas.
        if self.system_range.is_some() && !self.mapped.is_empty() {
            if let Err(error) = smp::flush_remote_tlb(false) {
                debug_print!("[pe] imagem de sistema retida: {}", error);
                self.system_range = None;
                self.frames.clear();
                failure = Some(error);
            }
        }
        self.mapped.clear();
        if let Some(range) = self.range.take() {
            let mut arenas = ARENAS.lock();
            // A faixa é por raiz: só a desta imagem sai.
            if let Some(index) = arenas.preferred_ranges.iter().position(|&candidate| candidate == range) {
                arenas.preferred_ranges.remove(index);
            }
        }
        if let Some(range) = self.system_range.take() {
            release_system_image_range(range);
        }
        for &frame in &self.frames {
            pfn::free_page(frame);
        }
        self.frames.clear();
        for dependency in self.dependencies.drain(..).rev() {
            if let Err(error) = dependency.release() {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

/// Imagem carregada.
pub struct PeImage {
    pub entry_point: u64,
    pub image_base: u64,
    pub size_of_image: u64,
    /// A tabela de exports, compartilhada com os módulos que a usam.
    pub exports: Arc<Exports>,
    /// Frame da primeira página (as demais não são contíguas).
    pub physical_base: u64,
    pub preferred_base: u64,
    /// Frames de uma imagem de usuário ou os frames mestres de uma imagem de
    /// sessão (vazio na de kernel). Os de uma carga protótipo passam a quem
    /// recebe a imagem, que os devolve ao PFN (a control area da seção de
    /// imagem): a carga não guarda outra lista deles.
    pub pages: Vec<u64>,
    pub page_protects: Vec<u32>,
    pub sections: Vec<SectionInfo>,
    pub resolved_imports: Vec<ResolvedImportRecord>,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub image_information: [u8; pe_image_information::INFORMATION_SIZE],
    pub code_integrity: Option<CodeIntegrity>,
    pub loader_flags: u32,
    pub loaded_image: Option<loaded_images::LoadedImage>,
    owned: Owned,
}

impl PeImage {
    /// Desfaz mapeamentos, registro, faixa de VA, frames e dependências.
    pub fn release(&mut self) -> Result<(), KernelError> {
        self.owned.release()
    }

    /// A imagem que fica carregada não guarda o relatório dos imports
    /// resolvidos (a IAT já tem os endereços): só quem carrega e confere na
    /// hora o lê.
    pub fn drop_import_report(mut self) -> PeImage {
        self.resolved_imports = Vec::new();
        self
    }
}

/// Fonte do arquivo entregue às notificações de imagem.
struct NotifySource {
    name: String,
    source: Arc<dyn ImageSource>,
}

impl FileSource for NotifySource {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        self.source.size()
    }
    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, KernelError> {
        self.source.read_bytes(offset, length as u64)
    }
}

/// A notificação de carga de imagem (PsSetLoadImageNotifyRoutine) de uma
/// imagem já mapeada: de sistema, ou de usuário no processo corrente.
fn notify_loaded(image_base: u64, size_of_image: u64, name: &str, source: Arc<dyn ImageSource>, system: bool, no_execute: bool) -> Result<(), KernelError> {
    let notify = image_notify::NotifyOptions { system, name: Some(String::from(name)), no_execute, source: Some(Arc::new(NotifySource { name: String::from(name), source })), ..Default::default() };
    image_notify::notify(image_notify::Image { image_base, size_of_image }, &notify)
}

/// A notificação de uma imagem de usuário carregada com `notify_image:
/// false`, depois de o chamador a pôr no VAD do processo corrente: os
/// callbacks leem a imagem no processo dono.
pub fn notify_user_image(image_base: u64, size_of_image: u64, name: &str, source: Arc<dyn ImageSource>) -> Result<(), KernelError> {
    notify_loaded(image_base, size_of_image, name, source, false, false)
}

/// Imagem em memória (bundle/VFS).
pub fn load(bytes: Vec<u8>, options: &LoadOptions) -> Result<PeImage, KernelError> {
    load_from_source(Arc::new(MemorySource { name: String::new(), bytes }), options)
}

/// Processo de usuário (ring 3): base preferida alta sobre frames PFN.
pub fn load_user(bytes: Vec<u8>, options: &LoadOptions) -> Result<PeImage, KernelError> {
    let options = LoadOptions { user_space: true, ..options.clone() };
    load_from_source(Arc::new(MemorySource { name: String::new(), bytes }), &options)
}

/// A decisão da CI sobre uma imagem antes de a carregar, com a fonte solta
/// logo depois: o papel do winload, que valida os drivers de boot antes de
/// deixá-los no loader block (`sysload::kernel_image_source::preload_boot_images`).
/// `None` sem a CI instalada ou numa falha da validação.
pub fn validate_early(source: &Arc<dyn ImageSource>, options: &LoadOptions) -> Option<CodeIntegrity> {
    let validator = (*VALIDATOR.lock())?;
    let validation = validator(source, options).ok()?;
    let result = validation.result;
    (validation.release)();
    Some(result)
}

/// O arquivo validado pela CI fica retido durante a cópia e os imports; a
/// recusa acontece antes de qualquer imagem executável ser publicada. Uma
/// imagem do loader block traz a decisão que a CI deu antes
/// ([`ImageSource::loader_validation`]), como o NT não valida de novo os
/// drivers de boot que o winload carregou.
pub fn load_from_source(source: Arc<dyn ImageSource>, options: &LoadOptions) -> Result<PeImage, KernelError> {
    if let Some(code_integrity) = source.loader_validation().filter(|_| !options.user_space) {
        if code_integrity.status & 0x8000_0000 != 0 {
            return Err(KernelError::with_status("CI rejected kernel image", code_integrity.status));
        }
        return load_prepared(source, options, Some(code_integrity));
    }
    let validator = *VALIDATOR.lock();
    let Some(validator) = validator.filter(|_| !options.user_space) else { return load_prepared(source, options, None) };
    let validation = validator(&source, options)?;
    let code_integrity = validation.result;
    let result = if code_integrity.status & 0x8000_0000 != 0 {
        Err(KernelError::with_status("CI rejected kernel image", code_integrity.status))
    } else {
        load_prepared(validation.source.clone(), options, Some(code_integrity))
    };
    (validation.release)();
    result
}

/// A imagem durante a carga: um frame do PFN por página, não contíguos.
struct Mapping {
    frames: Vec<u64>,
}

impl Mapping {
    /// Offset da imagem -> endereço físico.
    fn to_phys(&self, offset: u64) -> u64 {
        self.frames[(offset / 0x1000) as usize] + offset % 0x1000
    }

    fn write(&self, offset: u64, bytes: &[u8]) {
        let mut done = 0usize;
        while done < bytes.len() {
            let at = offset + done as u64;
            let length = ((0x1000 - at % 0x1000) as usize).min(bytes.len() - done);
            physical::write_bytes(self.to_phys(at), &bytes[done..done + length]);
            done += length;
        }
    }

    fn read_bytes(&self, offset: u64, length: usize) -> Vec<u8> {
        (0..length as u64).map(|index| physical::read8(self.to_phys(offset + index))).collect()
    }

    /// Zera a imagem fora das faixas `covered` (início, fim), que as cópias
    /// do arquivo preenchem por inteiro: o BSS, o resto das páginas e os
    /// vãos entre as seções. Cada byte da imagem sai do arquivo ou é zero,
    /// sem passar duas vezes pela mesma página.
    fn zero_outside(&self, covered: &mut [(u64, u64)]) {
        covered.sort_unstable();
        let total = self.frames.len() as u64 * 0x1000;
        let mut at = 0u64;
        for &(start, end) in covered.iter().chain(core::iter::once(&(total, total))) {
            let start = start.min(total);
            while at < start {
                let length = (0x1000 - at % 0x1000).min(start - at);
                physical::zero(self.to_phys(at), length as usize);
                at += length;
            }
            at = at.max(end.min(total));
        }
    }

    /// Um campo que cruza a página passa byte a byte (frames não contíguos).
    fn read32(&self, offset: u64) -> u32 {
        if offset % 0x1000 > 0x1000 - 4 {
            let bytes = self.read_bytes(offset, 4);
            return u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        physical::read32(self.to_phys(offset))
    }

    fn write32(&self, offset: u64, value: u32) {
        if offset % 0x1000 > 0x1000 - 4 {
            self.write(offset, &value.to_le_bytes());
            return;
        }
        physical::write32(self.to_phys(offset), value);
    }

    fn read16(&self, offset: u64) -> u16 {
        let bytes = self.read_bytes(offset, 2);
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    fn write16(&self, offset: u64, value: u16) {
        self.write(offset, &value.to_le_bytes());
    }

    fn read64(&self, offset: u64) -> u64 {
        self.read32(offset) as u64 | (self.read32(offset + 4) as u64) << 32
    }

    fn write64(&self, offset: u64, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }
}

fn load_prepared(source: Arc<dyn ImageSource>, options: &LoadOptions, code_integrity: Option<CodeIntegrity>) -> Result<PeImage, KernelError> {
    let metadata = MetadataReader::new(source.as_ref());
    if metadata.read_u16(0)? != 0x5A4D {
        return Err(KernelError::new("MZ ausente (nao e PE)"));
    }
    let pe_header = metadata.read_u32(0x3C)? as u64;
    if metadata.read_u32(pe_header)? != 0x4550 {
        return Err(KernelError::new("assinatura PE ausente"));
    }
    let coff = pe_header + 4;
    if metadata.read_u16(coff)? != 0x8664 {
        return Err(KernelError::new("so suportamos PE x86-64"));
    }
    let section_count = metadata.read_u16(coff + 2)? as u64;
    let optional_size = metadata.read_u16(coff + 16)? as u64;
    let optional = coff + 20;
    if metadata.read_u16(optional)? != 0x20B {
        return Err(KernelError::new("nao e PE32+"));
    }
    let entry_rva = metadata.read_u32(optional + 16)? as u64;
    let preferred_base = metadata.read_u32(optional + 24)? as u64 | (metadata.read_u32(optional + 28)? as u64) << 32;
    let size_of_image = metadata.read_u32(optional + 56)? as u64;
    let size_of_headers = metadata.read_u32(optional + 60)? as u64;
    let export_rva = metadata.read_u32(optional + 112)? as u64;
    let export_size = metadata.read_u32(optional + 116)? as u64;
    let import_rva = metadata.read_u32(optional + 120)? as u64;
    let reloc_rva = metadata.read_u32(optional + 152)? as u64;
    let reloc_size = metadata.read_u32(optional + 156)? as u64;
    let section_table = optional + optional_size;
    let mut sections = Vec::new();
    for index in 0..section_count {
        let header = section_table + index * 40;
        let mut name = String::new();
        for character in 0..8 {
            let byte = metadata.read_u8(header + character)?;
            if byte == 0 {
                break;
            }
            name.push(byte as u8 as char);
        }
        sections.push(SectionInfo { name, virtual_size: metadata.read_u32(header + 8)?, va: metadata.read_u32(header + 12)?, raw_size: metadata.read_u32(header + 16)?, characteristics: metadata.read_u32(header + 36)? });
    }
    // SectionAlignment menor que a página num cabeçalho válido: o arquivo
    // mapeado plano, todo MM_EXECUTE_WRITECOPY (`mm/section/image_header.rs`).
    // Lido pelas páginas de metadados já em cache.
    let read_metadata = |offset: u64, length: u64| -> Result<Option<Vec<u8>>, KernelError> {
        if offset.checked_add(length).is_none_or(|end| end > source.size()) {
            return Ok(None);
        }
        (0..length).map(|index| metadata.read_u8(offset + index).map(|byte| byte as u8)).collect::<Result<Vec<u8>, KernelError>>().map(Some)
    };
    let flat = image_header::parse(source.size(), &read_metadata).ok().and_then(Result::ok).is_some_and(|header| header.flat);
    let user_space = options.user_space;
    let session = options.session && !user_space;
    let prototype = options.prototype && user_space;
    let user_view = if user_space && !prototype { options.user_view } else { None };
    let (view_offset, view_size) = user_view.map_or((0, size_of_image), |view| (view.offset, view.size));
    if let Some(view) = user_view {
        if view.base % memory_map::ALLOCATION_GRANULARITY != 0 || !memory_map::is_user_range(view.base, view_size) || view_offset % 4096 != 0 || view_size % 4096 != 0 || view_offset + view_size > size_of_image.div_ceil(0x1000) * 0x1000 {
            return Err(KernelError::new("PE: invalid partial view"));
        }
    }
    // Uma imagem de usuário é do processo corrente, na raiz carregada. A
    // escolha da VA sem vista vê tudo o que já ocupa o espaço dele (lido
    // antes da trava das faixas de imagem).
    let user_root = if user_space && !prototype { paging::current_root() } else { 0 };
    let occupied_user = if user_space && !prototype && user_view.is_none() { crate::ntos::ps::user::memory::occupied(crate::ntos::ps::user::memory::Space::current()) } else { Vec::new() };
    if size_of_image == 0 || size_of_headers > size_of_image {
        return Err(KernelError::new("PE: SizeOfImage invalido"));
    }
    let characteristics = metadata.read_u16(coff + 18)? as u16;
    let mut owned = Owned::default();
    let mut image_base = preferred_base;
    let mut relocation_delta: i64 = 0;
    let image_name = options.image_name.clone().unwrap_or_else(|| source.name().to_string());
    let result = (|| -> Result<PeImage, KernelError> {
        if prototype {
            // As páginas protótipo ficam na ImageBase do cabeçalho; a ntdll
            // de cada processo reloca a própria vista quando ela cai em outra
            // base (STATUS_IMAGE_NOT_AT_BASE).
            image_base = preferred_base;
        } else if user_space {
            let mut arenas = ARENAS.lock();
            let target = match user_view {
                Some(view) => {
                    if !preferred_range_is_free(&arenas.preferred_ranges, user_root, view.base, view_size) {
                        return Err(KernelError::new("PE: requested view conflicts"));
                    }
                    view.base - view_offset
                }
                // Como no NT: a ImageBase do cabeçalho quando a faixa está
                // livre (um .exe em 0x1_4000_0000), senão a primeira faixa
                // livre da metade de usuário, e a imagem é relocada.
                None => {
                    let mut occupied = occupied_user;
                    occupied.extend(arenas.preferred_ranges.iter().filter(|&&(root, _, _)| root == user_root).map(|&(_, base, top)| section_address::Region { base, size: top - base }));
                    let at = |base: u64| section_address::find(&section_address::FindOptions { base, size: size_of_image, root: user_root, ..section_address::FindOptions::default() }, &occupied);
                    let preferred = (preferred_base % memory_map::ALLOCATION_GRANULARITY == 0 && memory_map::is_user_range(preferred_base, size_of_image)).then(|| at(preferred_base).ok()).flatten();
                    match preferred {
                        Some(base) => base,
                        None => at(0).map_err(|status| KernelError::with_status("espaco de imagens de usuario esgotado", status))?,
                    }
                }
            };
            let range = (user_root, target + view_offset, target + view_offset + view_size);
            arenas.preferred_ranges.push(range);
            drop(arenas);
            owned.range = Some(range);
            owned.root = user_root;
            image_base = target;
            relocation_delta = image_base.wrapping_sub(preferred_base) as i64;
            if relocation_delta != 0 && reloc_rva == 0 {
                debug_print!("[pe] sem .reloc: imagem position-independent (data), mapeada em {:#x}", image_base);
            }
        } else {
            // MiLoadSystemImage: a VA vem da janela de sistema e a imagem é
            // relocada pela diferença; sem relocações, só na ImageBase.
            if reloc_rva == 0 && characteristics & IMAGE_FILE_RELOCS_STRIPPED != 0 {
                return Err(KernelError::with_status("PE: imagem de kernel sem relocacoes", STATUS_CONFLICTING_ADDRESSES));
            }
            let range = reserve_image_range(size_of_image, session)?;
            owned.system_range = Some(range);
            image_base = range.0;
            relocation_delta = image_base.wrapping_sub(preferred_base) as i64;
        }
        owned.frames.reserve_exact(size_of_image.div_ceil(0x1000) as usize);
        let frame_use = if prototype {
            pfn::FrameUse::ImagePrototype
        } else if user_space {
            pfn::FrameUse::UserImage
        } else {
            pfn::FrameUse::DriverImage
        };
        for _ in 0..size_of_image.div_ceil(0x1000) {
            let frame = pfn::alloc_page_for(frame_use);
            if frame == 0 {
                return Err(KernelError::with_status("PFN esgotado carregando imagem", STATUS_INSUFFICIENT_RESOURCES));
            }
            owned.frames.push(frame);
        }
        let physical_base = owned.frames[0];
        let mapping = Mapping { frames: owned.frames.clone() };
        let rva_to_file_offset = |rva: u64| section_file_offset(&metadata, section_table, section_count, size_of_headers, rva);
        debug_print!("[pe] base={:#x} (fisico {:#x}) imagem={} bytes, {} secoes", image_base, physical_base, size_of_image, section_count);
        // Copia cabeçalhos e seções e zera o resto da imagem (o BSS). A
        // imagem plana é o arquivo inteiro a partir do offset zero, até o fim
        // da última página (os bytes fora das seções também).
        let mut copies = Vec::new();
        let mut covered = Vec::new();
        if flat {
            copies.push((0u64, 0u64, source.size().min(owned.frames.len() as u64 * 0x1000)));
        } else {
            let headers = source.read_bytes(0, size_of_headers)?;
            mapping.write(0, &headers);
            covered.push((0, headers.len() as u64));
            for index in 0..section_count {
                let header = section_table + index * 40;
                let virtual_address = metadata.read_u32(header + 12)? as u64;
                let raw_size = metadata.read_u32(header + 16)? as u64;
                let raw_pointer = metadata.read_u32(header + 20)? as u64;
                if raw_size == 0 {
                    continue;
                }
                if virtual_address + raw_size > size_of_image || raw_pointer + raw_size > source.size() {
                    return Err(KernelError::new("PE: secao fora da imagem ou do arquivo"));
                }
                copies.push((virtual_address, raw_pointer, raw_size));
            }
        }
        covered.extend(copies.iter().map(|&(virtual_address, _, raw_size)| (virtual_address, virtual_address + raw_size)));
        mapping.zero_outside(&mut covered);
        for (virtual_address, raw_pointer, raw_size) in copies {
            if source.supports_copy_to_physical() && raw_size >= 0x1000 {
                // Agrupa frames fisicamente contíguos; nunca cruza um salto.
                let mut copied = 0u64;
                while copied < raw_size {
                    let rva = virtual_address + copied;
                    let target = mapping.to_phys(rva);
                    let mut take = (raw_size - copied).min(0x1000 - rva % 0x1000);
                    while copied + take < raw_size && mapping.to_phys(rva + take) == target + take {
                        take += 0x1000.min(raw_size - copied - take);
                    }
                    source.copy_to_physical(raw_pointer + copied, target, take).unwrap_or_else(|| Err(KernelError::new("PE: copia direta indisponivel")))?;
                    copied += take;
                }
                continue;
            }
            // Sem cópia direta: uma página por leitura, direto no frame dela
            // (nenhum buffer do tamanho da seção no heap).
            let mut copied = 0u64;
            while copied < raw_size {
                let rva = virtual_address + copied;
                let chunk = (raw_size - copied).min(0x1000 - rva % 0x1000);
                let bytes = source.read_bytes(raw_pointer + copied, chunk)?;
                mapping.write(rva, &bytes);
                // Uma leitura curta deixa o resto da faixa em zeros.
                if (bytes.len() as u64) < chunk {
                    physical::zero(mapping.to_phys(rva + bytes.len() as u64), (chunk - bytes.len() as u64) as usize);
                }
                copied += chunk;
            }
        }
        let mut page_protects = Vec::new();
        // As páginas protótipo não entram em raiz alguma: só a proteção de
        // cada página, que as vistas aplicam.
        if prototype {
            page_protects = (0..size_of_image.div_ceil(0x1000)).map(|index| user_page_protection(index * 0x1000, size_of_headers, &sections, options.no_execute, flat)).collect();
        }
        // Mapeia a VA escolhida sobre os frames (PTEs de 4 KB; supervisor na
        // imagem de kernel). A imagem de sessão só entra na sessão depois de
        // pronta (`mm::session_image`).
        if !session && !prototype {
            let mut page = view_offset;
            while page < view_offset + view_size {
                let backing = owned.frames[(page / 0x1000) as usize];
                let protect = if user_view.is_some() { user_page_protection(page, size_of_headers, &sections, options.no_execute, flat) } else if options.no_execute { 2 } else { 0x40 };
                let (present, writable, nx) = (protect != 1, matches!(protect, 4 | 0x40), !matches!(protect, 0x20 | 0x40));
                let flags = (if present { paging::PAGE_PRESENT } else { 0 }) | (if writable { paging::PAGE_RW } else { 0 }) | (if user_space { paging::PAGE_USER } else { 0 });
                let index = (page / 4096) as usize;
                if page_protects.len() <= index {
                    page_protects.resize(index + 1, 0);
                }
                page_protects[index] = protect;
                let mapped = if user_space { paging::map_page_in(user_root, image_base + page, backing, flags, paging::MapOptions { nx, ..Default::default() }) } else { paging::map_page(image_base + page, backing, flags, paging::MapOptions { nx, ..Default::default() }) };
                if !mapped {
                    return Err(KernelError::new(alloc::format!("mapPage falhou p/ imagem em {image_base:#x}")));
                }
                owned.mapped.push(image_base + page);
                page += 0x1000;
            }
            debug_print!("[pe] VA {:#x} mapeada ({} paginas)", image_base, size_of_image.div_ceil(0x1000));
            // Verificação real: a página do entry point traduz de volta.
            let entry_page = entry_rva & !0xFFF;
            let expected = owned.frames.get((entry_page / 0x1000) as usize).copied().unwrap_or(0);
            let probe = if user_space { paging::translate_in(user_root, image_base + entry_page) } else { paging::translate(image_base + entry_page) };
            if entry_page >= view_offset && entry_page < view_offset + view_size && probe != expected {
                return Err(KernelError::new(alloc::format!("mapeamento VA quebrado: entry traduz p/ {probe:#x} (esperado {expected:#x})")));
            }
        }
        // Relocação (IMAGE_BASE_RELOCATION): DIR64, HIGHLOW e HIGH.
        let delta = relocation_delta as u64;
        if !options.skip_relocations && relocation_delta != 0 && reloc_rva != 0 {
            let mut count = 0u32;
            let mut block = rva_to_file_offset(reloc_rva)?;
            let end = block + reloc_size;
            while block < end {
                let page_rva = metadata.read_u32(block)? as u64;
                let block_size = metadata.read_u32(block + 4)? as u64;
                if block_size == 0 {
                    break;
                }
                for entry_index in 0..(block_size - 8) / 2 {
                    let entry = metadata.read_u16(block + 8 + entry_index * 2)?;
                    let entry_type = entry >> 12;
                    let target = page_rva + (entry & 0xFFF) as u64;
                    let width = match entry_type {
                        10 => 8,
                        2 => 4,
                        1 => 2,
                        _ => 0,
                    };
                    if target + width > size_of_image {
                        return Err(KernelError::new(alloc::format!("PE: relocacao fora da imagem em {target:#x}")));
                    }
                    match entry_type {
                        10 => {
                            mapping.write64(target, mapping.read64(target).wrapping_add(delta));
                            count += 1;
                        }
                        2 => {
                            mapping.write32(target, mapping.read32(target).wrapping_add(delta as u32));
                            count += 1;
                        }
                        1 => {
                            let value = mapping.read16(target) as i64;
                            let full = (value << 16) + relocation_delta;
                            mapping.write16(target, (full.div_euclid(0x10000) & 0xFFFF) as u16);
                            count += 1;
                        }
                        0 => {}
                        other => return Err(KernelError::new(alloc::format!("reloc tipo {other} nao suportado"))),
                    }
                }
                block += block_size;
            }
            debug_print!("[pe] relocada p/ {:#x} ({} fixups)", image_base, count);
        }
        // Cookie GS: semente de 48 bits, nunca 0 nem o padrão do link.
        if !options.skip_security_cookie {
            let tsc = cpu::rdtsc();
            let mut seed_low = (tsc as u32) ^ (image_base as u32);
            let seed_high = ((tsc >> 32) as u32 ^ 0x9E37) & 0xFFFF;
            if seed_low | seed_high == 0 {
                seed_low = 0x2545_F491;
            }
            if seed_high == 0x2B99 && seed_low == 0x2DDF_A232 {
                seed_low ^= 0x10F3;
            }
            let mut cookie = 0u64;
            let load_config_rva = metadata.read_u32(optional + 192)? as u64;
            let load_config_size = metadata.read_u32(optional + 196)? as u64;
            if load_config_rva != 0 && load_config_size >= 0x60 && load_config_rva + 0x60 <= size_of_image {
                cookie = mapping.read64(load_config_rva + 0x58);
                if cookie < image_base || cookie + 8 > image_base + size_of_image {
                    cookie = 0;
                }
            }
            if cookie == 0 {
                let mut offset = 0u64;
                while offset + 8 <= size_of_image.min(0x80_0000) {
                    if mapping.read32(offset) == 0x2DDF_A232 && mapping.read32(offset + 4) == 0x2B99 {
                        cookie = image_base + offset;
                        break;
                    }
                    offset += 4;
                }
            }
            if cookie != 0 {
                mapping.write32(cookie - image_base, seed_low);
                mapping.write32(cookie - image_base + 4, seed_high);
                debug_print!("[pe] security cookie semeado em {:#x}", cookie);
            }
        }
        let entry_point = if entry_rva != 0 { image_base.wrapping_add(entry_rva) } else { 0 };
        let read_rva = |rva: u64, length: u64| -> Result<Vec<u8>, KernelError> {
            if rva.checked_add(length).is_none_or(|end| end > size_of_image) {
                return Err(KernelError::new(alloc::format!("PE: RVA {rva:#x} fora da imagem")));
            }
            Ok(mapping.read_bytes(rva, length as usize))
        };
        // As páginas protótipo de uma seção de imagem não guardam a tabela de
        // exports: a ntdll de cada processo resolve os imports pela imagem
        // mapeada (`image_segment::exports` lê a tabela quando alguém pede).
        let exports = Arc::new(if prototype { pe_exports::Exports::default() } else { pe_exports::read_exports(&read_rva, image_base, size_of_image, export_rva, export_size)? });
        // O bit consumido por ObRegisterCallbacks é uma decisão da CI, não
        // uma promessa do cabeçalho: contrato integral aceito no modo 2.
        let loader_flags = match code_integrity {
            Some(ci) if ci.status == 0 && ci.validation_mode == 2 && ci.signature_context == 0 && (2..=15).contains(&ci.signing_level) => 0x20,
            _ => 0,
        };
        let (checksum, time_date_stamp) = (metadata.read_u32(optional + 64)?, metadata.read_u32(coff + 4)?);
        // Como no MmLoadSystemImageEx, a entrada da imagem de kernel entra na
        // lista de imagens carregadas (MiConstructLoaderEntry) antes de os
        // imports serem resolvidos, com LOAD_IN_PROGRESS ligado: um ciclo de
        // imports (netio.sys <-> ndis.sys) acha esta entrada e se resolve
        // pelos exports dela. A imagem de sessão só é registrada depois de
        // entrar na sessão (o registro a lê pela VA).
        let mut loaded_image = None;
        if !user_space && !session {
            let description = loaded_images::ImageDescription { image_base, size_of_image, entry_point, checksum, time_date_stamp, loader_flags: loader_flags | loaded_images::LOAD_IN_PROGRESS, release_paging: Some(crate::ntos::mm::image_paging::release_image) };
            let loaded = loaded_images::register(description, &image_name)?;
            owned.registered = Some(loaded.id);
            NATIVE_IMAGES.lock().insert(image_base, (size_of_image, sections.clone()));
            owned.native_base = Some(image_base);
            RESOLVING.lock().insert(loaded.id, exports.clone());
            loaded_image = Some(loaded.id);
        }
        let resolved = resolve_imports(&ImportContext { metadata: &metadata, mapping: &mapping, options, importer: &image_name, image_base, size_of_image, import_rva, sections: &sections, section_table, section_count, size_of_headers }, &mut owned);
        let loaded_image = loaded_image.and_then(|id| {
            RESOLVING.lock().remove(&id);
            loaded_images::update_flags(id, 0, loaded_images::LOAD_IN_PROGRESS)
        });
        let resolved_imports = resolved?;
        debug_print!("[pe] entry point = {:#x}", entry_point);
        let image_information = pe_image_information::capture(&metadata, source.size(), coff, optional, image_base, flat)?;
        Ok(PeImage {
            entry_point,
            image_base,
            size_of_image,
            exports,
            physical_base,
            preferred_base,
            pages: if prototype {
                core::mem::take(&mut owned.frames)
            } else if user_space || session {
                owned.frames.clone()
            } else {
                Vec::new()
            },
            page_protects,
            sections: sections.clone(),
            resolved_imports,
            checksum,
            time_date_stamp,
            image_information,
            code_integrity,
            loader_flags,
            loaded_image,
            owned: Owned::default(),
        })
    })();
    match result {
        Ok(mut image) => {
            image.owned = owned;
            // A imagem de sessão entra na sessão corrente antes do registro e
            // das notificações, que a leem pela VA; a residência das imagens
            // de drivers (`image_paging`) é da janela de sistema, e a imagem
            // de sessão fica de fora.
            if session {
                if let Err(error) = crate::ntos::mm::session_image::map_new(&image) {
                    let _ = image.release();
                    return Err(error);
                }
                let registered = loaded_images::register(loaded_images::ImageDescription { image_base: image.image_base, size_of_image, entry_point: image.entry_point, checksum: image.checksum, time_date_stamp: image.time_date_stamp, loader_flags: image.loader_flags, release_paging: None }, &image_name);
                match registered {
                    Ok(loaded) => {
                        image.owned.registered = Some(loaded.id);
                        image.loaded_image = Some(loaded);
                    }
                    Err(error) => {
                        crate::ntos::mm::session_image::discard_new(&image);
                        let _ = image.release();
                        return Err(error);
                    }
                }
            }
            if options.notify_image {
                if let Err(error) = notify_loaded(image.image_base, size_of_image, &image_name, source.clone(), !user_space, options.no_execute) {
                    if session {
                        crate::ntos::mm::session_image::discard_new(&image);
                    }
                    let _ = image.release();
                    return Err(error);
                }
            }
            Ok(image)
        }
        Err(error) => {
            let _ = owned.release();
            Err(error)
        }
    }
}

/// O que a resolução de imports lê da imagem em carga.
struct ImportContext<'a> {
    metadata: &'a MetadataReader<'a>,
    mapping: &'a Mapping,
    options: &'a LoadOptions,
    importer: &'a str,
    image_base: u64,
    size_of_image: u64,
    import_rva: u64,
    sections: &'a [SectionInfo],
    section_table: u64,
    section_count: u64,
    size_of_headers: u64,
}

/// RVA -> offset no arquivo pela tabela de seções.
fn section_file_offset(metadata: &MetadataReader, section_table: u64, section_count: u64, size_of_headers: u64, rva: u64) -> Result<u64, KernelError> {
    for index in 0..section_count {
        let header = section_table + index * 40;
        let virtual_size = metadata.read_u32(header + 8)? as u64;
        let virtual_address = metadata.read_u32(header + 12)? as u64;
        let raw_size = metadata.read_u32(header + 16)? as u64;
        let raw_pointer = metadata.read_u32(header + 20)? as u64;
        if rva >= virtual_address && rva < virtual_address + virtual_size.max(raw_size) {
            return Ok(raw_pointer + (rva - virtual_address));
        }
    }
    if rva < size_of_headers {
        return Ok(rva);
    }
    Err(KernelError::new(alloc::format!("RVA invalido: {rva:#x}")))
}

fn read_c_string(metadata: &MetadataReader, mut offset: u64) -> Result<String, KernelError> {
    let mut text = String::new();
    loop {
        let byte = metadata.read_u8(offset)?;
        if byte == 0 {
            return Ok(text);
        }
        text.push(byte as u8 as char);
        offset += 1;
    }
}

/// Resolve a IAT pelos resolvedores registrados (o MiResolveImageReferences
/// de uma imagem de kernel): as dependências nativas ficam em `owned`.
fn resolve_imports(context: &ImportContext, owned: &mut Owned) -> Result<Vec<ResolvedImportRecord>, KernelError> {
    let (metadata, mapping, options) = (context.metadata, context.mapping, context.options);
    let (image_base, size_of_image, import_rva, sections) = (context.image_base, context.size_of_image, context.import_rva, context.sections);
    let user_space = options.user_space;
    let rva_to_file_offset = |rva: u64| section_file_offset(metadata, context.section_table, context.section_count, context.size_of_headers, rva);
    let read_c_string = |offset: u64| read_c_string(metadata, offset);
    let mut resolved_imports = Vec::new();
    if import_rva != 0 && !options.skip_imports {
        let importer = String::from(context.importer);
        let mut descriptor = rva_to_file_offset(import_rva)?;
        loop {
            let ilt_rva = metadata.read_u32(descriptor)? as u64;
            let name_rva = metadata.read_u32(descriptor + 12)? as u64;
            let iat_rva = metadata.read_u32(descriptor + 16)? as u64;
            if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
                break;
            }
            let dll = read_c_string(rva_to_file_offset(name_rva)?)?;
            let lower = dll.to_lowercase();
            let host = if lower.starts_with("api-") || lower.starts_with("ext-") { crate::ntos::mm::sysload::kernel_api_set::resolve(&dll, &importer)? } else { Some(dll.clone()) };
            let Some(host) = host else { return Err(KernelError::new(alloc::format!("API set desconhecido: {dll}"))) };
            debug_print!("[pe] imports de {}", dll);
            let mut slot = 0u64;
            loop {
                let entry = rva_to_file_offset(if ilt_rva != 0 { ilt_rva } else { iat_rva })? + slot * 8;
                let low = metadata.read_u32(entry)?;
                let high = metadata.read_u32(entry + 4)?;
                if low == 0 && high == 0 {
                    break;
                }
                if iat_rva == 0 || iat_rva + slot * 8 > size_of_image - 8 {
                    return Err(KernelError::new("PE: IAT fora da imagem"));
                }
                let iat = iat_rva + slot * 8;
                let symbol = if high & 0x8000_0000 != 0 {
                    ImportSymbol::Ordinal(low & 0xFFFF)
                } else {
                    if high != 0 {
                        return Err(KernelError::new("PE: RVA de import invalido"));
                    }
                    ImportSymbol::Name(read_c_string(rva_to_file_offset(low as u64)? + 2)?)
                };
                let label = match &symbol {
                    ImportSymbol::Ordinal(ordinal) => alloc::format!("ordinal #{ordinal}"),
                    ImportSymbol::Name(name) => name.clone(),
                };
                if host.is_empty() {
                    // Default opcional do linker no IAT (já relocado): o
                    // ponteiro original precisa cair numa seção executável.
                    let address = mapping.read64(iat);
                    let rva = address.wrapping_sub(image_base);
                    let executable = rva < size_of_image && sections.iter().any(|section| section.characteristics & 0x2000_0000 != 0 && rva >= section.va as u64 && rva < section.va as u64 + section.virtual_size.max(section.raw_size) as u64);
                    if !executable {
                        return Err(KernelError::new(alloc::format!("API set sem default nativo executavel: {dll}!{label}")));
                    }
                    resolved_imports.push(ResolvedImportRecord { dll: dll.clone(), name: label, rva: iat, address, native_default: true });
                    slot += 1;
                    continue;
                }
                match resolve(&host, &symbol) {
                    None => return Err(KernelError::new(alloc::format!("API nao suportada: {dll}!{label}"))),
                    Some(ResolvedImport::Address { address, dependencies }) => {
                        for dependency in dependencies {
                            if !owned.dependencies.iter().any(|held| Arc::ptr_eq(held, &dependency)) {
                                dependency.retain();
                                owned.dependencies.push(dependency);
                            }
                        }
                        mapping.write64(iat, address);
                        resolved_imports.push(ResolvedImportRecord { dll: dll.clone(), name: label, rva: iat, address, native_default: false });
                    }
                    Some(ResolvedImport::Thunk(id)) => {
                        // Ring 3 não alcança trampolins supervisores.
                        if user_space {
                            return Err(KernelError::new(alloc::format!("API do kernel ({dll}!{label}) inalcancavel de ring 3")));
                        }
                        let Some((table, count)) = *THUNK_TABLE.lock() else { return Err(KernelError::new("tabela de trampolins indisponivel")) };
                        if id >= count {
                            return Err(KernelError::new(alloc::format!("apiId {id} alem da tabela de trampolins ({count})")));
                        }
                        let address = kernel_address::image_address(table + id as u64 * STUB_SIZE)?;
                        mapping.write64(iat, address);
                        resolved_imports.push(ResolvedImportRecord { dll: dll.clone(), name: label, rva: iat, address, native_default: false });
                    }
                }
                slot += 1;
            }
            descriptor += 20;
        }
    }
    Ok(resolved_imports)
}
