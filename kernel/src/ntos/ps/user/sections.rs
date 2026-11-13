//! Seções de dados e de imagem.
//!
//! Seções de dados são donas de seus PFNs. Handles e vistas mantêm o objeto
//! vivo de forma independente; toda vista é alias das mesmas páginas
//! confirmadas da control area. Seções de arquivo compartilham a control
//! area pela identidade do arquivo, guardam a cópia original de cada página
//! lida e só gravam de volta as diferenças. Vistas copy-on-write recebem
//! páginas privadas pela falta de escrita.
//!
//! Modelo Rust: a seção, a control area e a vista são `Arc` com o estado
//! mutável sob `SpinLock`; nenhum lock atravessa leituras de arquivo,
//! paginação ou a coleta do objeto.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::state::{self, Region, RegionKind, UserRegion};
use crate::hal::{cpu, physical};
use crate::ntos::ke::smp;
use crate::ntos::mm::section::map_view_parameters;
use crate::ntos::mm::page_residency::{self, FaultResult, Provider};
use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::mm::section::secured_views;
use crate::ntos::mm::section::views::{self as section_views, OwnedView};
use crate::ntos::mm::system_image_pages::{self, ImageRange};
use crate::ntos::mm::pfn;
use crate::ntos::mm::section::{address as section_address, cache as section_cache};
use crate::ntos::ob::object_manager::{self, NodeId, ObjectData};
use crate::ntos::ob::objects::section::{self as section_objects, SectionState};
use crate::rtl::{KernelError, SpinLock};

pub const PAGE: u64 = 4096;
pub const GRANULARITY: u64 = 65536;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const COMPATIBILITY: [u32; 8] = [1, 11, 17, 187, 15, 11, 255, 187];

fn writable(protect: u32) -> bool {
    protect & 255 == 4 || protect & 255 == 0x40
}

fn copy_on_write(protect: u32) -> bool {
    protect & 255 == 8 || protect & 255 == 0x80
}

fn executable(protect: u32) -> bool {
    protect & 0xF0 != 0
}

/// Arquivo que sustenta uma seção (`mm/section/file`).
pub trait SectionFile: Send + Sync {
    /// Identidade que compartilha a control area entre seções do arquivo.
    fn identity(&self) -> Option<String> {
        None
    }
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError>;
    /// Cópia direta para a memória física (sem buffer intermediário).
    fn has_copy_to_physical(&self) -> bool {
        false
    }
    fn copy_to_physical(&self, _offset: u64, _address: u64, _length: u64) -> Result<(), KernelError> {
        Err(KernelError::new("section file has no physical copy"))
    }
    fn write_at(&self, _offset: u64, _data: &[u8]) -> Result<(), KernelError> {
        Err(KernelError::with_status("section file is read-only", 0xC000_0185))
    }
    fn nt_path(&self) -> Option<String> {
        None
    }
    /// Nome-base do arquivo.
    fn base_name(&self) -> Option<String> {
        None
    }
}

/// Paginação de sistema de uma control area (`mm/system_view_paging`).
pub trait AreaPaging: Send + Sync {
    fn materialize(&self, section: &Arc<Section>) -> Result<(), KernelError>;
    fn release(&self);
}

/// Chave de compartilhamento de uma control area de imagem.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AreaKey {
    Identity(String),
    Section(u64),
}

/// Control area: PFNs por página, cópias originais, vistas e referências.
pub struct Area {
    pub frames: BTreeMap<u64, u64>,
    pub original: BTreeMap<u64, u64>,
    pub references: u32,
    pub views: Vec<Arc<View>>,
    pub identity: Option<String>,
    pub cache: u32,
    pub image_layout: Vec<ImageRange>,
    pub image_key: Option<AreaKey>,
    pub system_paging: Option<Arc<dyn AreaPaging>>,
}

impl Area {
    pub fn new(identity: Option<String>, cache: u32) -> Self {
        Self { frames: BTreeMap::new(), original: BTreeMap::new(), references: 0, views: Vec::new(), identity, cache, image_layout: Vec::new(), image_key: None, system_paging: None }
    }
}

pub type AreaRef = Arc<SpinLock<Area>>;

/// Estado mutável da seção.
pub struct SectionMut {
    pub area: Option<AreaRef>,
    pub area_released: bool,
    pub views: Vec<OwnedView>,
    pub destroyed: bool,
    pub node: Option<NodeId>,
    pub release_file: Option<Box<dyn FnOnce() + Send>>,
    pub partition: Option<Box<dyn FnOnce() + Send>>,
    pub image_file_object: u64,
    pub mapped_base: u64,
    pub mapped_size: u64,
    pub cache_flags: u32,
    /// Nome publicado (o NtCreateSection publica depois de criar).
    pub name: Option<String>,
}

pub struct Section {
    pointer: AtomicU64,
    pub size: u64,
    pub maximum_size: u64,
    /// Proteção da seção; a CSR rebaixa a da SharedSection depois de
    /// mapeá-la (nenhum cliente obtém vista gravável).
    page_protect: AtomicU32,
    pub attributes: u32,
    pub file: Option<Arc<dyn SectionFile>>,
    pub is_image: bool,
    pub no_execute: bool,
    pub large: bool,
    pub permanent: bool,
    pub state: SpinLock<SectionMut>,
}

impl Section {
    pub fn page_protect(&self) -> u32 {
        self.page_protect.load(Ordering::SeqCst)
    }

    pub fn set_page_protect(&self, protect: u32) {
        self.page_protect.store(protect, Ordering::SeqCst);
    }

    /// O corpo nativo _SECTION.
    pub fn pointer(&self) -> u64 {
        self.pointer.load(Ordering::Acquire)
    }

    pub fn name(&self) -> Option<String> {
        self.state.lock().name.clone()
    }

    /// A control area, mesmo depois de a seção soltá-la.
    pub fn control_area(&self) -> Option<AreaRef> {
        self.state.lock().area.clone()
    }

    /// PFN da página (nenhum depois da destruição).
    pub fn frame(&self, page: u64) -> Option<u64> {
        let area = {
            let state = self.state.lock();
            if state.area_released {
                return None;
            }
            state.area.clone()?
        };
        let frame = area.lock().frames.get(&page).copied();
        frame
    }

    pub fn frames(&self) -> Vec<(u64, u64)> {
        let area = {
            let state = self.state.lock();
            if state.area_released {
                return Vec::new();
            }
            match state.area.clone() {
                Some(area) => area,
                None => return Vec::new(),
            }
        };
        let frames = area.lock().frames.iter().map(|(&page, &frame)| (page, frame)).collect();
        frames
    }

    pub fn view_count(&self) -> usize {
        self.state.lock().views.len()
    }

    fn count_pages(&self) -> u64 {
        self.size / PAGE
    }
}

/// Retirada em curso de uma vista (cursor para nova tentativa).
#[derive(Clone, Default)]
pub struct Retirement {
    pub pages: Vec<u64>,
    pub next: usize,
    pub tables: Vec<u64>,
    pub acknowledged: bool,
}

pub struct ViewMut {
    pub regions: Option<RegionKind>,
    pub frames: BTreeMap<u64, u64>,
    pub private_frames: BTreeMap<u64, u64>,
    pub committed_pages: BTreeSet<u64>,
    pub page_protects: BTreeMap<u64, u32>,
    pub retirement: Option<Retirement>,
    pub unmapped: bool,
    /// Retenções de leitura (`mm/section/secured_views`).
    pub secured_reads: Vec<u64>,
    pub system_paging: bool,
    /// Falha de page-in vira STATUS_IN_PAGE_ERROR em vez de bugcheck.
    pub in_page_exceptions: bool,
    /// Retirada pelo dono (ALPC) na liberação do processo.
    pub release_process_view: Option<Arc<dyn Fn() -> Result<(), KernelError> + Send + Sync>>,
}

pub struct View {
    pub base: u64,
    pub size: u64,
    pub offset: u64,
    pub section: Arc<Section>,
    pub protect: u32,
    pub allocation_protect: u32,
    pub no_change: bool,
    pub supervisor: bool,
    pub system_space: bool,
    pub large: bool,
    pub owner_process: Option<u64>,
    pub inherit: u32,
    pub name: Option<String>,
    pub state: SpinLock<ViewMut>,
}

impl UserRegion for View {
    fn base(&self) -> u64 {
        self.base
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn committed_pages(&self) -> Option<BTreeSet<u64>> {
        Some(self.state.lock().committed_pages.clone())
    }
    fn page_protect(&self, index: u64) -> Option<u32> {
        self.state.lock().page_protects.get(&index).copied().filter(|&protect| protect != 0)
    }
    fn protect(&self) -> u32 {
        self.protect
    }
    fn allocation_protect(&self) -> u32 {
        self.allocation_protect
    }
    fn section(&self) -> Option<Arc<Section>> {
        Some(self.section.clone())
    }
    fn name(&self) -> Option<String> {
        self.name.clone()
    }
}

impl View {
    pub fn retiring(&self) -> bool {
        self.state.lock().retirement.is_some()
    }
}

static SECTIONS: SpinLock<BTreeMap<u64, Arc<Section>>> = SpinLock::new(BTreeMap::new());
static FILE_AREAS: SpinLock<BTreeMap<String, AreaRef>> = SpinLock::new(BTreeMap::new());
static VIEWS: SpinLock<Vec<Arc<View>>> = SpinLock::new(Vec::new());

pub fn by_pointer(pointer: u64) -> Option<Arc<Section>> {
    SECTIONS.lock().get(&pointer).cloned()
}

fn remote_flush() -> Result<(), KernelError> {
    smp::flush_remote_tlb(false)
}

fn view_address(view: &View, offset: u64) -> u64 {
    view.base.wrapping_add(offset)
}

fn same_view(left: &Arc<View>, right: &Arc<View>) -> bool {
    Arc::ptr_eq(left, right)
}

/// SEC_IMAGE não herda a proteção máxima de uma seção de dados: as vistas
/// PE já têm frames privados. Seções de dados seguem a tabela nativa.
pub fn compatible(is_image: bool, page_protect: u32, protect: u32) -> bool {
    if is_image {
        return [1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80].contains(&protect);
    }
    let mask = map_view_parameters::protection(page_protect);
    mask >= 0 && map_view_parameters::protection(protect) >= 0 && protect & !(COMPATIBILITY[(mask & 7) as usize] | 0x700) == 0
}

fn flags(view: &View, protect: u32, private_page: bool) -> u64 {
    (if view.supervisor { 0 } else { paging::PAGE_USER })
        | (if protect & 255 == 1 { 0 } else { paging::PAGE_PRESENT })
        | (if writable(protect) || (copy_on_write(protect) && private_page) { paging::PAGE_RW } else { 0 })
        | (if view.section.page_protect() & 0x200 != 0 {
            0x18
        } else if view.section.page_protect() & 0x400 != 0 {
            0x80
        } else {
            0
        })
}

/// Publica a página da seção (ou a privada) na vista; uma vista em remoção
/// nunca recebe novos aliases.
fn attach_page(view: &View, page: u64) -> bool {
    let first_page = view.offset / PAGE;
    let (private, protect_override, system_paging, committed) = {
        let state = view.state.lock();
        if state.retirement.is_some() {
            return true;
        }
        if page < first_page || page - first_page >= view.size / PAGE {
            return true;
        }
        let index = page - first_page;
        (state.private_frames.get(&index).copied(), state.page_protects.get(&index).copied().filter(|&protect| protect != 0), state.system_paging, state.committed_pages.contains(&index))
    };
    let index = page - first_page;
    let frame = private.or_else(|| view.section.frame(page));
    let protect = protect_override.unwrap_or_else(|| if view.section.is_image { system_image_pages::protection(&view.section, page) } else { view.protect });
    let Some(frame) = frame else {
        // Proteção de uma página paginada altera a reserva; nunca publica PFN zero.
        return system_paging && committed && paging::map_page(view_address(view, index * PAGE), 0, 0x200, MapOptions { nx: !executable(protect), ..MapOptions::default() });
    };
    if view.large && index % 512 != 0 {
        return true;
    }
    let address = view_address(view, index * PAGE);
    let page_flags = flags(view, protect, private.is_some());
    let mapped = if view.large { paging::map_large_page(address, frame, page_flags, !executable(protect)) } else { paging::map_page(address, frame, page_flags, MapOptions { nx: !executable(protect), ..MapOptions::default() }) };
    if !mapped {
        return false;
    }
    let mut state = view.state.lock();
    let span = if view.large { 512 } else { 1 };
    for offset in 0..span {
        state.frames.insert(index + offset, frame + offset * PAGE);
        state.committed_pages.insert(index + offset);
        state.page_protects.insert(index + offset, protect);
    }
    true
}

/// Guarda os bytes lidos (base da comparação do writeback) num PFN próprio;
/// a cópia nunca é publicada numa vista.
fn capture_original_file_page(area: &AreaRef, page_index: u64, source_frame: u64) -> Result<(), KernelError> {
    let previous = area.lock().original.get(&page_index).copied();
    let original = match previous {
        Some(frame) => frame,
        None => pfn::alloc_page(),
    };
    if original == 0 {
        return Err(KernelError::with_status("section original page allocation failed", 0xC000_0017));
    }
    physical::write_bytes(original, &physical::read_bytes(source_frame, PAGE as usize));
    area.lock().original.insert(page_index, original);
    Ok(())
}

/// A cópia pertence à control area; rollback e destruição devolvem o
/// frame exatamente uma vez.
fn release_original_file_page(area: &AreaRef, page_index: u64) -> Result<(), KernelError> {
    let Some(original) = area.lock().original.get(&page_index).copied() else { return Ok(()) };
    if !pfn::free_page(original) {
        return Err(KernelError::new("section lost original page ownership"));
    }
    area.lock().original.remove(&page_index);
    Ok(())
}

fn status_of(error: &KernelError, default: u32) -> u32 {
    if error.status != 0 {
        error.status
    } else {
        default
    }
}

/// Confirma páginas: PFNs zerados, leitura do arquivo em trechos contíguos
/// de até 1 MiB (o backing só é publicado depois de todas as leituras),
/// atributo de cache e alias em cada vista; qualquer falha desfaz tudo.
pub fn commit(section: &Arc<Section>, first: u64, count: u64) -> Result<u32, KernelError> {
    if first > MAX_SAFE_INTEGER || count > MAX_SAFE_INTEGER || first + count > section.count_pages() {
        return Ok(0xC000_000D);
    }
    if section.large && (first % 512 != 0 || count % 512 != 0) {
        return Ok(0xC000_000D);
    }
    let Some(area) = section.control_area() else { return Err(KernelError::new("section without control area")) };
    let existing = section.frames().len() as u64;
    if count > pfn::free_count() + existing {
        return Ok(0xC000_012D);
    }
    let mut added: Vec<u64> = Vec::new();
    let mut status = 0u32;
    let mut page = first;
    while page < first + count {
        if section.frame(page).is_some() {
            page += 1;
            continue;
        }
        let span = if section.large { 512 } else { 1 };
        let frame = if section.large { pfn::alloc_contiguous_default(512, 512) } else { pfn::alloc_page() };
        if frame == 0 {
            status = 0xC000_0017;
            break;
        }
        physical::zero(frame, (span * PAGE) as usize);
        {
            let mut owner = area.lock();
            for offset in 0..span {
                owner.frames.insert(page + offset, frame + offset * PAGE);
                added.push(page + offset);
            }
        }
        page += span;
    }
    let frame_of = |page: u64| area.lock().frames.get(&page).copied().unwrap_or(0);
    if status == 0 {
        if let Some(file) = &section.file {
            let result = (|| -> Result<(), KernelError> {
                let mut index = 0usize;
                while index < added.len() {
                    let page = added[index];
                    let frame = frame_of(page);
                    let mut span = 1u64;
                    while span < 256 && index + (span as usize) < added.len() && added[index + span as usize] == page + span && frame_of(page + span) == frame + span * PAGE {
                        span += 1;
                    }
                    if section.is_image {
                        system_image_pages::fill(section, page, frame, span)?;
                    } else if page * PAGE < file.size() {
                        let length = (span * PAGE).min(file.size() - page * PAGE);
                        if file.has_copy_to_physical() {
                            file.copy_to_physical(page * PAGE, frame, length)?;
                        } else {
                            let data = file.read_at(page * PAGE, length)?;
                            if data.len() as u64 != length {
                                return Err(KernelError::new("Short section read"));
                            }
                            physical::write_bytes(frame, &data);
                        }
                        for offset in 0..length.div_ceil(PAGE) {
                            capture_original_file_page(&area, page + offset, frame + offset * PAGE)?;
                        }
                    }
                    index += span as usize;
                }
                Ok(())
            })();
            if let Err(error) = result {
                debug_print!("[section] file read failed: {}", error.message);
                status = status_of(&error, 0xC000_0185);
                if status & 0x8000_0000 == 0 {
                    status = 0xC000_0185;
                }
            }
        }
    }
    let added_frames: Vec<u64> = added.iter().map(|&page| frame_of(page)).collect();
    if status == 0 && !section_cache::set(&added_frames, section.page_protect())? {
        status = 0xC000_0017;
    }
    if status == 0 {
        let views = area.lock().views.clone();
        'pages: for &page in &added {
            for view in &views {
                if !attach_page(view, page) {
                    status = 0xC000_0017;
                    break 'pages;
                }
            }
        }
    }
    if status != 0 {
        section_cache::restore(&added_frames)?;
        let views = area.lock().views.clone();
        for &page in &added {
            for view in &views {
                let first_page = view.offset / PAGE;
                if page < first_page || page - first_page >= view.size / PAGE {
                    continue;
                }
                let index = page - first_page;
                if view.large {
                    if index % 512 == 0 {
                        paging::unmap_large_page(view_address(view, index * PAGE), None);
                    }
                } else {
                    paging::unmap_page(view_address(view, index * PAGE), MapOptions::default());
                }
                let mut state = view.state.lock();
                state.committed_pages.remove(&index);
                state.frames.remove(&index);
                state.page_protects.remove(&index);
            }
            let frame = area.lock().frames.remove(&page);
            if let Some(frame) = frame {
                pfn::free_page(frame);
            }
            release_original_file_page(&area, page)?;
        }
    }
    Ok(status)
}

/// A última referência da control area devolve cache, PFNs e cópias; o nome
/// é removido e o arquivo e a partição retidos são soltos.
fn destroy_section(section: &Arc<Section>) -> Result<(), KernelError> {
    let (area, released) = {
        let state = section.state.lock();
        (state.area.clone(), state.area_released)
    };
    if let Some(area) = area.filter(|_| !released) {
        let references = area.lock().references;
        if references < 1 {
            return Err(KernelError::new("section area reference underflow"));
        }
        if references == 1 {
            let frames: Vec<(u64, u64)> = area.lock().frames.iter().map(|(&page, &frame)| (page, frame)).collect();
            section_cache::restore(&frames.iter().map(|&(_, frame)| frame).collect::<Vec<u64>>())?;
            let system_paging = area.lock().system_paging.clone();
            if let Some(system_paging) = system_paging {
                system_paging.release();
            }
            for (page, frame) in frames {
                if !pfn::free_page(frame) {
                    return Err(KernelError::new("section lost backing ownership"));
                }
                area.lock().frames.remove(&page);
            }
            let originals: Vec<u64> = area.lock().original.keys().copied().collect();
            for page in originals {
                release_original_file_page(&area, page)?;
            }
            let (identity, image_key) = {
                let owner = area.lock();
                (owner.identity.clone(), owner.image_key.clone())
            };
            if let Some(identity) = identity {
                FILE_AREAS.lock().remove(&identity);
            }
            if let Some(key) = image_key {
                system_image_pages::release_image(&key);
            }
        }
        area.lock().references -= 1;
        section.state.lock().area_released = true;
    }
    let node = section.state.lock().node.take();
    if let Some(node) = node {
        object_manager::remove_named(node);
    } else if let Some(name) = section.name() {
        let pointer = section.pointer();
        let owned = object_manager::lookup(&name).and_then(object_manager::node).and_then(|node| node.data).is_some_and(|data| pointer != 0 && data.native_pointer == pointer);
        if owned {
            object_manager::unlink(&name);
        }
    }
    let release_file = section.state.lock().release_file.take();
    if let Some(release_file) = release_file {
        release_file();
    }
    let partition = section.state.lock().partition.take();
    if let Some(partition) = partition {
        partition();
    }
    Ok(())
}

/// Destrutor chamado pela coleta do objeto nativo.
fn destroy_by_pointer(pointer: u64) -> Result<(), KernelError> {
    let Some(section) = by_pointer(pointer) else { return Ok(()) };
    destroy_section(&section)?;
    section.state.lock().destroyed = true;
    SECTIONS.lock().remove(&pointer);
    Ok(())
}

/// Opções de criação de uma seção de dados.
#[derive(Clone, Default)]
pub struct CreateOptions {
    pub size: u64,
    pub page_protect: u32,
    pub attributes: u32,
    pub name: Option<String>,
    pub file: Option<Arc<dyn SectionFile>>,
    pub large: bool,
    pub permanent: bool,
    /// `None` = SEC_COMMIT nos atributos.
    pub committed: Option<bool>,
}

/// Seção criada ou o NTSTATUS da recusa.
pub type Created = Result<Arc<Section>, u32>;

fn split_name(name: &str) -> (String, String) {
    let cut = name.rfind('\\');
    let parent = match cut {
        Some(0) => String::from("\\"),
        Some(index) => String::from(&name[..index]),
        None => String::from(&name[..name.len().saturating_sub(1)]),
    };
    let leaf = String::from(&name[cut.map_or(0, |index| index + 1)..]);
    (parent, leaf)
}

/// Nome livre com diretório pai existente.
fn check_name(name: &str) -> Option<u32> {
    if object_manager::lookup(name).is_some() {
        return Some(0xC000_0035);
    }
    let (parent, _) = split_name(name);
    let parent_is_directory = object_manager::lookup(if parent.is_empty() { "\\" } else { &parent }).and_then(object_manager::node).is_some_and(|node| node.type_name == "Directory");
    if !parent_is_directory {
        return Some(0xC000_003A);
    }
    None
}

fn publish_name(name: &str, pointer: u64) -> Result<(), KernelError> {
    let (parent, leaf) = split_name(name);
    object_manager::create_object(if parent.is_empty() { "\\" } else { &parent }, &leaf, "Section", Some(ObjectData::pointer(pointer)))?;
    Ok(())
}

fn register(section: &Arc<Section>) -> Result<u64, KernelError> {
    let pointer = section_objects::register(SectionState { size: section.size, name: section.name().unwrap_or_default(), permanent: section.permanent, ..SectionState::default() }, destroy_by_pointer)?;
    if pointer != 0 {
        section.pointer.store(pointer, Ordering::Release);
        SECTIONS.lock().insert(pointer, section.clone());
    }
    Ok(pointer)
}

fn new_section(size: u64, maximum_size: u64, page_protect: u32, attributes: u32, name: Option<String>, file: Option<Arc<dyn SectionFile>>, is_image: bool, no_execute: bool, large: bool, permanent: bool, area: Option<AreaRef>) -> Arc<Section> {
    Arc::new(Section {
        pointer: AtomicU64::new(0),
        size,
        maximum_size,
        page_protect: AtomicU32::new(page_protect),
        attributes,
        file,
        is_image,
        no_execute,
        large,
        permanent,
        state: SpinLock::new(SectionMut { area, area_released: false, views: Vec::new(), destroyed: false, node: None, release_file: None, partition: None, image_file_object: 0, mapped_base: 0, mapped_size: 0, cache_flags: 0, name }),
    })
}

/// Seção de dados (pagefile ou arquivo): tamanho arredondado à página, a
/// control area do arquivo reutilizada com o mesmo atributo de cache, SEC_COMMIT
/// confirmando tudo de uma vez.
pub fn create(options: CreateOptions) -> Result<Created, KernelError> {
    let CreateOptions { size, page_protect, attributes, name, file, large, permanent, committed } = options;
    if size == 0 || size > 0xFFFF_FFFF_FFFF_F000 {
        return Ok(Err(if size == 0 { 0xC000_0040 } else { 0xC000_000D }));
    }
    if ![2, 4, 8, 0x10, 0x20, 0x40, 0x80].contains(&(page_protect & 255)) || page_protect & !0x6FF != 0 {
        return Ok(Err(0xC000_0045));
    }
    if let Some(status) = name.as_deref().and_then(check_name) {
        return Ok(Err(status));
    }
    let rounded = (size + 4095) & !4095;
    let identity = file.as_ref().and_then(|file| file.identity());
    let area = identity.as_ref().and_then(|identity| FILE_AREAS.lock().get(identity).cloned()).unwrap_or_else(|| Arc::new(SpinLock::new(Area::new(identity.clone(), page_protect & 0x600))));
    if area.lock().cache != page_protect & 0x600 {
        return Ok(Err(0xC000_004E));
    }
    area.lock().references += 1;
    if let Some(identity) = &identity {
        FILE_AREAS.lock().insert(identity.clone(), area.clone());
    }
    let section = new_section(rounded, size, page_protect, attributes, name.clone(), file, false, false, large, permanent, Some(area));
    let committed = committed.unwrap_or(attributes & 0x0800_0000 != 0);
    let status = if committed { commit(&section, 0, section.count_pages())? } else { 0 };
    if status != 0 {
        destroy_section(&section)?;
        return Ok(Err(status));
    }
    if register(&section)? == 0 {
        destroy_section(&section)?;
        return Ok(Err(0xC000_009A));
    }
    if let Some(name) = &name {
        publish_name(name, section.pointer())?;
    }
    Ok(Ok(section))
}

pub fn open(name: &str) -> Created {
    let Some(node) = object_manager::lookup(name).and_then(object_manager::node) else { return Err(0xC000_0034) };
    if node.type_name != "Section" {
        return Err(0xC000_0024);
    }
    node.data.and_then(|data| by_pointer(data.native_pointer)).ok_or(0xC000_0024)
}

fn read_exact(file: &Arc<dyn SectionFile>, offset: u64, length: u64) -> Result<Option<Vec<u8>>, KernelError> {
    let bytes = file.read_at(offset, length)?;
    Ok(if bytes.len() as u64 == length { Some(bytes) } else { None })
}

/// SEC_IMAGE: valida o PE32+ AMD64 e o SizeOfImage; o layout virtual é
/// preparado na primeira vista.
pub fn create_image(file: Arc<dyn SectionFile>, name: Option<String>, page_protect: u32, no_execute: bool) -> Result<Created, KernelError> {
    if no_execute && page_protect != 2 {
        return Ok(Err(0xC000_0045));
    }
    let header = (|| -> Result<Result<u64, u32>, KernelError> {
        let Some(dos) = read_exact(&file, 0, 64)? else { return Ok(Err(0xC000_007B)) };
        if dos[0] != 0x4D || dos[1] != 0x5A {
            return Ok(Err(0xC000_007B));
        }
        let portable = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]) as u64;
        if file.size() < 88 || portable > file.size() - 88 {
            return Ok(Err(0xC000_007B));
        }
        let Some(bytes) = read_exact(&file, portable, 88)? else { return Ok(Err(0xC000_007B)) };
        let word = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let dword = |offset: usize| u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
        if dword(0) != 0x4550 || word(4) != 0x8664 || word(20) < 64 || word(24) != 0x20B {
            return Ok(Err(0xC000_007B));
        }
        let size = dword(80) as u64;
        if size == 0 || size % PAGE != 0 {
            return Ok(Err(0xC000_007B));
        }
        Ok(Ok(size))
    })();
    let size = match header {
        Ok(Ok(size)) => size,
        Ok(Err(status)) => return Ok(Err(status)),
        Err(_) => return Ok(Err(0xC000_0185)),
    };
    if let Some(status) = name.as_deref().and_then(check_name) {
        return Ok(Err(status));
    }
    let section = new_section(size, size, page_protect, if no_execute { 0x1100_0000 } else { 0x0100_0000 }, name.clone(), Some(file), true, no_execute, false, false, None);
    if register(&section)? == 0 {
        return Ok(Err(0xC000_009A));
    }
    if let Some(name) = &name {
        publish_name(name, section.pointer())?;
    }
    Ok(Ok(section))
}

/// Retenção por handle, pelo dono consultado na abertura.
pub fn retain(section: &Section) -> Result<(), KernelError> {
    section_objects::retain(section.pointer())
}

pub fn release(section: &Section) -> Result<(), KernelError> {
    section_objects::release(section.pointer())
}

/// Parâmetros de mapeamento de uma vista.
#[derive(Clone, Copy, Default)]
pub struct MapRequest {
    pub offset: u64,
    pub protect: u32,
    pub size: u64,
    pub reserve: bool,
    pub flexible_large: bool,
    pub alignment: u64,
    pub base: u64,
    pub system_space: bool,
    pub supervisor: bool,
    pub owner_process: Option<u64>,
    pub top_down: bool,
    pub no_change: bool,
    pub inherit: u32,
    pub regions: Option<RegionKind>,
    pub commit_size: u64,
    pub upper: Option<u64>,
    pub minimum: Option<u64>,
    pub wrap: bool,
}

/// Vista mapeada ou o NTSTATUS da recusa.
pub type Mapped = Result<Arc<View>, u32>;

fn occupied_regions() -> Vec<section_address::Region> {
    let mut regions: Vec<section_address::Region> = state::with(|state| state.user_regions.iter().chain(state.process_images.iter()).chain(state.shared_user_regions.iter()).map(|region| section_address::Region { base: region.base(), size: region.size() }).collect());
    regions.extend(VIEWS.lock().iter().map(|view| section_address::Region { base: view.base, size: view.size }));
    regions.extend(section_views::all().iter().map(|view| section_address::Region { base: view.base(), size: view.size() }));
    regions
}

/// Mapeia a vista: alinhamento, proteção compatível, extensão, endereço
/// livre (cursor de usuário, de cima ou compartilhado), commit pedido e
/// alias das páginas já confirmadas.
pub fn map(section: &Arc<Section>, options: &MapRequest) -> Result<Mapped, KernelError> {
    if section.state.lock().destroyed {
        return Ok(Err(0xC000_0008));
    }
    let offset = options.offset;
    if offset > MAX_SAFE_INTEGER || offset % GRANULARITY != 0 {
        return Ok(Err(0xC000_0220));
    }
    if !compatible(section.is_image, section.page_protect(), options.protect) {
        return Ok(Err(0xC000_004E));
    }
    let requested: i128 = if options.size != 0 { options.size as i128 } else { section.size as i128 - offset as i128 };
    let size = if requested <= 0 { 0 } else { (requested as u128).div_ceil(PAGE as u128) * PAGE as u128 };
    if size == 0 || size > MAX_SAFE_INTEGER as u128 || (!options.reserve && offset as u128 + size > section.size as u128) {
        return Ok(Err(0xC000_001F));
    }
    let size = size as u64;
    let large_view = section.large && (!options.flexible_large || (offset % 0x20_0000 == 0 && size % 0x20_0000 == 0));
    let alignment = if large_view {
        0x20_0000
    } else if options.alignment != 0 {
        options.alignment
    } else {
        GRANULARITY
    };
    if large_view && (offset % alignment != 0 || size % alignment != 0 || copy_on_write(options.protect)) {
        return Ok(Err(0xC000_0220));
    }
    let base = options.base;
    if options.system_space {
        if !options.supervisor || options.owner_process.is_some() {
            return Ok(Err(0xC000_000D));
        }
        if base % alignment != 0 {
            return Ok(Err(0xC000_0220));
        }
    } else if base != 0 && (base > MAX_SAFE_INTEGER || base % alignment != 0) {
        return Ok(Err(0xC000_0220));
    }
    let start = state::with(|state| {
        if options.supervisor {
            state.next_shared_va
        } else if options.top_down {
            state.next_user_alloc_high
        } else {
            state.next_user_alloc_va
        }
    });
    let find = section_address::FindOptions { system_space: options.system_space, size, alignment, base, top_down: options.top_down, upper: options.upper, minimum: options.minimum, start, wrap: options.wrap };
    let base = match section_address::find(&find, &occupied_regions()) {
        Ok(base) => base,
        Err(status) => return Ok(Err(status)),
    };
    // Uma vista nova não herda buracos de uma control area paginada.
    let system_paging = section.control_area().and_then(|area| area.lock().system_paging.clone());
    if let Some(system_paging) = system_paging {
        system_paging.materialize(section)?;
    }
    let view = Arc::new(View {
        base,
        size,
        offset,
        section: section.clone(),
        protect: options.protect,
        allocation_protect: options.protect,
        no_change: options.no_change || section.attributes & 0x0040_0000 != 0,
        supervisor: options.supervisor,
        system_space: options.system_space,
        large: large_view,
        owner_process: options.owner_process,
        inherit: if options.inherit != 0 { options.inherit } else { 2 },
        name: section.file.as_ref().and_then(|file| file.nt_path()),
        state: SpinLock::new(ViewMut { regions: options.regions, frames: BTreeMap::new(), private_frames: BTreeMap::new(), committed_pages: BTreeSet::new(), page_protects: BTreeMap::new(), retirement: None, unmapped: false, secured_reads: Vec::new(), system_paging: false, in_page_exceptions: false, release_process_view: None }),
    });
    let available = section.size.saturating_sub(offset);
    let commit_size = options.commit_size.min(size).min(available);
    let status = if commit_size != 0 { commit(section, offset / PAGE, commit_size.div_ceil(PAGE))? } else { 0 };
    if status != 0 {
        return Ok(Err(status));
    }
    for (page, _) in section.frames() {
        if page < offset / PAGE || page >= (offset + size) / PAGE {
            continue;
        }
        if !attach_page(&view, page) {
            let committed: Vec<u64> = view.state.lock().committed_pages.iter().copied().collect();
            for index in committed {
                if view.large {
                    if index % 512 == 0 {
                        paging::unmap_large_page(view_address(&view, index * PAGE), None);
                    }
                } else {
                    paging::unmap_page(view_address(&view, index * PAGE), MapOptions::default());
                }
            }
            return Ok(Err(0xC000_0017));
        }
    }
    section.state.lock().views.push(OwnedView::Data(view.clone()));
    section_objects::update(section.pointer(), |state| state.views += 1);
    if let Some(area) = section.control_area() {
        area.lock().views.push(view.clone());
    }
    VIEWS.lock().push(view.clone());
    if section.is_image || copy_on_write(view.protect) {
        install_faults()?;
    }
    if let Some(owner) = options.owner_process {
        section_views::register(OwnedView::Data(view.clone()), owner, false);
    }
    let region: Region = view.clone();
    state::with(|state| {
        if let Some(kind) = options.regions {
            if kind != RegionKind::Detached {
                state.regions(kind).push(region);
            }
        } else if view.supervisor {
            state.section_kernel_views.push(region);
            if !view.system_space {
                state.next_shared_va = state.next_shared_va.max(base + size + GRANULARITY);
            }
        } else {
            state.user_regions.push(region);
            if options.top_down {
                state.next_user_alloc_high = base - GRANULARITY;
            } else {
                state.next_user_alloc_va = state.next_user_alloc_va.max(base + size + GRANULARITY);
            }
        }
    });
    Ok(Ok(view))
}

/// Retira a vista: grava o arquivo, remove as PTEs (cursor retomável),
/// espera os ACKs de TLB antes de liberar PFNs e tabelas, grava de novo o
/// que uma CPU possa ter escrito pelo TLB antigo e só então solta o
/// backing. Uma falha conserva a vista para nova tentativa.
pub fn unmap(view: &Arc<View>, authority: Option<&secured_views::SecuredToken>) -> Result<(), KernelError> {
    if !VIEWS.lock().iter().any(|candidate| same_view(candidate, view)) {
        return Err(KernelError::new("invalid or duplicate section view removal"));
    }
    let security = secured_views::unmap_status(view, authority);
    if security != 0 {
        return Err(KernelError::with_status("section view is secured by its kernel owner", security));
    }
    if view.state.lock().retirement.is_none() {
        // Se a persistência falhar, as PTEs e a propriedade continuam válidas.
        flush(&view.section)?;
        let mut state = view.state.lock();
        let pages = state.committed_pages.iter().copied().filter(|&index| !view.large || index % 512 == 0).collect();
        state.retirement = Some(Retirement { pages, ..Retirement::default() });
    }
    let mut retirement = view.state.lock().retirement.take().unwrap_or_default();
    let result = (|| -> Result<(), KernelError> {
        while retirement.next < retirement.pages.len() {
            let address = view_address(view, retirement.pages[retirement.next] * PAGE);
            let removed = if view.large { paging::unmap_large_page(address, Some(&mut retirement.tables)) } else { paging::unmap_page(address, MapOptions { deferred_tables: Some(&mut retirement.tables), ..MapOptions::default() }) };
            if !removed {
                return Err(KernelError::new("section view page removal failed"));
            }
            retirement.next += 1;
        }
        if !retirement.acknowledged {
            // Nenhum PFN, tabela ou intervalo é reutilizado antes dos ACKs.
            if !retirement.tables.is_empty() {
                cpu::reload_cr3();
            }
            remote_flush()?;
            retirement.acknowledged = true;
        }
        flush(&view.section)?;
        let private: Vec<u64> = view.state.lock().private_frames.values().copied().collect();
        section_cache::restore(&private)?;
        while let Some(&frame) = retirement.tables.last() {
            if !pfn::free_page(frame) {
                return Err(KernelError::new("section view lost table ownership"));
            }
            retirement.tables.pop();
        }
        let private: Vec<(u64, u64)> = view.state.lock().private_frames.iter().map(|(&index, &frame)| (index, frame)).collect();
        for (index, frame) in private {
            if !pfn::free_page(frame) {
                return Err(KernelError::new("section lost private page"));
            }
            view.state.lock().private_frames.remove(&index);
        }
        Ok(())
    })();
    view.state.lock().retirement = Some(retirement);
    result?;
    let section = &view.section;
    let owned = OwnedView::Data(view.clone());
    section.state.lock().views.retain(|candidate| !candidate.same(&owned));
    section_objects::update(section.pointer(), |state| state.views = state.views.saturating_sub(1));
    if let Err(error) = section_objects::collect(section.pointer()) {
        // A última vista conserva o objeto até a devolução terminar.
        section.state.lock().views.push(owned);
        section_objects::update(section.pointer(), |state| state.views += 1);
        return Err(error);
    }
    if let Some(area) = section.control_area() {
        area.lock().views.retain(|candidate| !same_view(candidate, view));
    }
    VIEWS.lock().retain(|candidate| !same_view(candidate, view));
    let kind = {
        let mut state = view.state.lock();
        state.unmapped = true;
        state.regions
    };
    section_views::forget(&OwnedView::Data(view.clone()));
    let region: Region = view.clone();
    let kind = kind.unwrap_or(if view.supervisor { RegionKind::KernelViews } else { RegionKind::User });
    state::with(|state| state.remove_region(kind, &region));
    Ok(())
}

/// Compara com os bytes lidos desta control area: páginas não alteradas
/// nunca sobrescrevem I/O independente; frames COW privados nunca são
/// gravados. Só as diferenças são escritas, e a cópia só é atualizada
/// depois de o dispositivo aceitar a escrita.
pub fn flush(section: &Section) -> Result<(), KernelError> {
    let Some(file) = &section.file else { return Ok(()) };
    let Some(area) = section.control_area() else { return Ok(()) };
    let originals: Vec<(u64, u64)> = area.lock().original.iter().map(|(&page, &frame)| (page, frame)).collect();
    for (page, original) in originals {
        let Some(frame) = section.frame(page) else { continue };
        let length = PAGE.min(file.size().saturating_sub(page * PAGE)) as usize;
        let current = physical::read_bytes(frame, length);
        let saved = physical::read_bytes(original, length);
        if current == saved {
            continue;
        }
        let mut first: Option<usize> = None;
        for index in 0..=length {
            let changed = index < length && current[index] != saved[index];
            if changed && first.is_none() {
                first = Some(index);
            }
            if !changed {
                if let Some(start) = first.take() {
                    let bytes = &current[start..index];
                    file.write_at(page * PAGE + start as u64, bytes).map_err(|error| KernelError::with_status(format!("section writeback failed: {}", error.message), status_of(&error, 0xC000_0185)))?;
                    physical::write_bytes(original + start as u64, bytes);
                }
            }
        }
    }
    Ok(())
}

/// Falta de escrita presente numa página copy-on-write: copia para um PFN
/// privado com o atributo de cache da seção e republica a página.
pub fn fault(address: u64, error: u32) -> bool {
    if error & 27 != 3 {
        return false;
    }
    let views = VIEWS.lock().clone();
    for view in views {
        if view.retiring() || address < view.base || address >= view.base + view.size {
            continue;
        }
        if error & 4 != 0 && view.supervisor {
            return false;
        }
        let index = (address - view.base) / PAGE;
        let (protect, committed, private, original) = {
            let state = view.state.lock();
            (state.page_protects.get(&index).copied().filter(|&protect| protect != 0).unwrap_or(view.protect), state.committed_pages.contains(&index), state.private_frames.contains_key(&index), state.frames.get(&index).copied().unwrap_or(0))
        };
        if !copy_on_write(protect) || !committed || private {
            return false;
        }
        let frame = pfn::alloc_page();
        if frame == 0 {
            return false;
        }
        physical::write_bytes(frame, &physical::read_bytes(original, PAGE as usize));
        let published = (|| {
            if !section_cache::set(&[frame], view.section.page_protect()).unwrap_or(false) {
                return false;
            }
            view.state.lock().private_frames.insert(index, frame);
            if !attach_page(&view, index + view.offset / PAGE) {
                return false;
            }
            let _ = remote_flush();
            true
        })();
        if !published {
            view.state.lock().private_frames.remove(&index);
            let _ = section_cache::restore(&[frame]);
            pfn::free_page(frame);
        }
        return published;
    }
    false
}

fn residency_fault(address: u64, error: u32) -> FaultResult {
    if fault(address, error) {
        FaultResult::Resolved
    } else {
        FaultResult::NotMine
    }
}

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// O provedor COW só trata faltas; nunca resolve endereços escalares.
fn install_faults() -> Result<(), KernelError> {
    if INSTALLED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    page_residency::register("section-cow", Provider { fault: residency_fault, resolve: |_| Ok(None), reclaim: |_| Ok(0), prepare: || Ok(()), resolve_range: Some((0, 0)) })
}

/// A política 0x400000 do NtMapViewOfSection pertence à VAD de dados;
/// SEC_NO_CHANGE vale para toda vista e precede os modificadores de cache.
/// Vistas de imagem mantêm a política PE própria.
pub fn protection_status(view: &View, protect: u32) -> u32 {
    if view.section.is_image {
        return 0;
    }
    if view.no_change && protect != view.allocation_protect {
        return 0xC000_0045;
    }
    // NtProtectVirtualMemory recusa mudança de cache em seções de dados.
    if protect & 0x600 != 0 {
        return 0xC000_00F2;
    }
    if !compatible(false, view.section.page_protect(), protect) || !compatible(false, view.allocation_protect, protect) {
        return 0xC000_004E;
    }
    secured_views::protection_status(view, protect)
}

/// Troca a proteção de páginas confirmadas (PAGE_GUARD ainda não é
/// entregue, então é recusado em vez de apagado das PTEs).
pub fn protect_view(view: &View, base: u64, size: u64, protect: u32) -> u32 {
    if view.retiring() {
        return 0xC000_0019;
    }
    let status = protection_status(view, protect);
    if status != 0 {
        return status;
    }
    if protect & 0x100 != 0 {
        return 0xC000_00BB;
    }
    if copy_on_write(protect) && install_faults().is_err() {
        return 0xC000_0017;
    }
    let first = base.wrapping_sub(view.base) / PAGE;
    let count = size / PAGE;
    if view.large && (first % 512 != 0 || count % 512 != 0) {
        return 0xC000_000D;
    }
    if (first..first + count).any(|index| !view.state.lock().committed_pages.contains(&index)) {
        return 0xC000_002D;
    }
    let mut old: Vec<Option<u32>> = Vec::new();
    for index in first..first + count {
        old.push(view.state.lock().page_protects.insert(index, protect));
        if !attach_page(view, index + view.offset / PAGE) {
            for (position, restored) in (first..=index).enumerate() {
                match old[position] {
                    Some(previous) => view.state.lock().page_protects.insert(restored, previous),
                    None => view.state.lock().page_protects.remove(&restored),
                };
                attach_page(view, restored + view.offset / PAGE);
            }
            let _ = remote_flush();
            return 0xC000_0017;
        }
    }
    let _ = remote_flush();
    0
}

pub fn commit_view(view: &View, base: u64, size: u64, protect: u32) -> Result<u32, KernelError> {
    if view.retiring() {
        return Ok(0xC000_0019);
    }
    if !compatible(view.section.is_image, view.section.page_protect(), protect) {
        return Ok(0xC000_004E);
    }
    commit(&view.section, (view.offset + base - view.base) / PAGE, size / PAGE)
}

/// Página de arquivo restaurada (paginação de sistema).
pub fn restore_file_page(section: &Arc<Section>, page: u64) -> Result<u32, KernelError> {
    commit(section, page, 1)
}

/// Vistas de sistema pelo registro do alocador.
pub fn system_views() -> Vec<Arc<View>> {
    VIEWS.lock().iter().filter(|view| view.supervisor && view.owner_process.is_none()).cloned().collect()
}

/// Busca sem alocar no conjunto vivo (acessos escalares de convidado).
pub fn find_system_view(address: u64) -> Option<Arc<View>> {
    VIEWS.lock().iter().find(|view| view.supervisor && view.owner_process.is_none() && !view.retiring() && address >= view.base && address < view.base + view.size).cloned()
}

/// Todas as vistas de seção vivas.
pub fn views() -> Vec<Arc<View>> {
    VIEWS.lock().clone()
}

/// Liga a falta de seção às sondas de escrita de usuário.
pub fn init() {
    state::set_section_fault(fault);
}
