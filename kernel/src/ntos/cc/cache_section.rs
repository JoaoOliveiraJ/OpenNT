//! A seção do Cache Manager sobre o stream (`SharedCacheMap->Section`).
//!
//! No 19041 o CcInitializeCacheMap cria uma seção de dados sobre o stream
//! file (MmCreateSection com o FILE_OBJECT), que usa a control area do
//! stream achada pelos SECTION_OBJECT_POINTERS, e cada VACB é uma vista
//! dela no cache do sistema (MmMapViewInSystemCache). Assim a página que um
//! ReadFile/WriteFile vê pelo cache é o mesmo frame que toda vista de
//! usuário do arquivo mapeia: uma cópia só dos dados.
//!
//! Aqui é igual: a seção do cache é uma seção de `ps::user::sections` sobre o
//! arquivo do file system (`mm/section/fsd_file`), com a identidade dos
//! SECTION_OBJECT_POINTERS, e cada vista de 256 KB do Cc é uma vista dela
//! no espaço de sistema. Uma página que falta é confirmada na control area
//! pela leitura de paginação (ou zerada, quando o Cc vai sobrescrevê-la
//! inteira ou ela passa do fim do arquivo) e publicada em todas as vistas;
//! uma página que outra seção já confirmou é só publicada na vista do Cc.
//! O purge do Cc tira da control area as páginas que nenhuma vista de fora
//! do cache usa (o MmPurgeSection).
//!
//! Diferenças declaradas: a seção do cache nasce com o tamanho máximo
//! [`SECTION_SIZE`] (as páginas existem só quando confirmadas, então não há
//! MmExtendSection a fazer quando o arquivo cresce); o MmPurgeSection do NT
//! também tira páginas da lista de espera, que o OpenNT não tem. As escritas
//! pelo cache saem pelo flush do Cc; a seção do cache não liga o writeback
//! das vistas de usuário.

use alloc::sync::Arc;

use super::layout::{PAGE_SIZE, VIEW_SIZE};
use super::vacb;
use crate::ntos::mm::section::file::{self as section_file, CapturedFile};
use crate::ntos::mm::section::fsd_file;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::user::sections::{self, CreateOptions, MapRequest, Section, SectionFile, View};
use crate::rtl::KernelError;

/// Tamanho da seção do cache (1 TB).
pub const SECTION_SIZE: u64 = 1 << 40;
/// PAGE_READWRITE.
const PAGE_READWRITE: u32 = 4;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// A seção do cache de um SharedCacheMap e o arquivo dela.
pub struct CacheSection {
    pub section: Arc<Section>,
    pub file: Arc<CapturedFile>,
}

impl CacheSection {
    /// O corpo nativo _SECTION (SharedCacheMap->Section).
    pub fn pointer(&self) -> u64 {
        self.section.pointer()
    }

    /// A identidade da control area do stream.
    pub fn identity(&self) -> alloc::string::String {
        self.file.identity().unwrap_or_default()
    }
}

/// A seção do cache do stream `file` (com `pointers` e o FileSize do
/// CC_FILE_SIZES). `None` para um arquivo que não é servido por um file
/// system pela pilha dele, ou se a seção não pôde ser criada: o mapa usa
/// então vistas de páginas próprias.
pub fn create(file: u64, pointers: u64, file_size: u64) -> Option<Arc<CacheSection>> {
    if fsd_file::section_pointers(file) != pointers || pointers == 0 {
        return None;
    }
    let captured = section_file::capture_stream(file, pointers, file_size);
    let backing: Arc<dyn SectionFile> = captured.clone();
    let section = match sections::create(CreateOptions { size: SECTION_SIZE, page_protect: PAGE_READWRITE, file: Some(backing), committed: Some(false), cache: true, ..CreateOptions::default() }) {
        Ok(Ok(section)) => section,
        Ok(Err(status)) => {
            debug_print!("[cc] secao do cache do arquivo {:#x} recusada: {:#x}", file, status);
            return None;
        }
        Err(error) => {
            debug_print!("[cc] secao do cache do arquivo {:#x}: {}", file, error.message);
            return None;
        }
    };
    // A seção usa a referência do stream file que o mapa já guarda: ela sai
    // (`release`, depois das vistas) antes de o mapa soltar o FILE_OBJECT.
    section_objects::reference(section.pointer());
    Some(Arc::new(CacheSection { section, file: captured }))
}

/// Solta a referência do mapa: a seção sai com a última vista.
pub fn release(cache_section: &CacheSection) {
    if let Err(error) = section_objects::dereference(cache_section.pointer()) {
        debug_print!("[cc] secao do cache {:#x}: {}", cache_section.pointer(), error.message);
    }
}

/// A vista `index` (256 KB) no espaço de sistema (MmMapViewInSystemCache),
/// já com as páginas que a control area tem.
pub fn map_view(cache_section: &CacheSection, index: u64) -> Option<Arc<View>> {
    let request = MapRequest { offset: vacb::view_offset(index), size: VIEW_SIZE, protect: PAGE_READWRITE, system_space: true, supervisor: true, ..MapRequest::default() };
    match sections::map(&cache_section.section, &request) {
        Ok(Ok(view)) => Some(view),
        Ok(Err(status)) => {
            debug_print!("[cc] vista {:#x} da secao do cache recusada: {:#x}", index, status);
            None
        }
        Err(error) => {
            debug_print!("[cc] vista {:#x} da secao do cache: {}", index, error.message);
            None
        }
    }
}

/// Retira a vista do cache (sem o writeback das vistas de usuário).
pub fn unmap_view(view: &Arc<View>) {
    if let Err(error) = sections::unmap_cache_view(view) {
        debug_print!("[cc] retirada da vista {:#x}: {}", view.base, error.message);
    }
}

/// Páginas [first, first + count) da vista que a control area já tem.
pub fn present(cache_section: &CacheSection, first_page: u64, count: u64) -> u64 {
    sections::present_mask(&cache_section.section, first_page, count)
}

/// Confirma as páginas [first, first + count) (lidas do arquivo com `read`,
/// senão zeradas) e as publica na vista do Cc. `file_size` é o FileSize que
/// o mapa conhece: limita a leitura de paginação. Devolve o NTSTATUS.
pub fn fill(cache_section: &CacheSection, view: &View, first_page: u64, count: u64, read: bool, file_size: u64) -> Result<u32, KernelError> {
    cache_section.file.note_size(file_size);
    let status = sections::commit_pages(&cache_section.section, first_page, count, read)?;
    if status != 0 {
        return Ok(status);
    }
    Ok(if sections::attach_pages(view, first_page, count) { 0 } else { STATUS_NO_MEMORY })
}

/// Publica na vista do Cc as páginas que outra seção confirmou.
pub fn attach(view: &View, first_page: u64, count: u64) -> bool {
    sections::attach_pages(view, first_page, count)
}

/// O MmPurgeSection de [start, end) (bytes): as páginas que nenhuma vista
/// de fora do cache usa saem da control area. false se alguma ficou.
pub fn purge(cache_section: &CacheSection, start: u64, end: u64) -> bool {
    let first = start / PAGE_SIZE;
    let last = end.min(SECTION_SIZE).div_ceil(PAGE_SIZE);
    if first >= last {
        return true;
    }
    let section = cache_section.section.clone();
    match sections::purge_file_pages(&cache_section.section, first, last, &|view| Arc::ptr_eq(&view.section, &section)) {
        Ok(purged) => purged,
        Err(error) => {
            debug_print!("[cc] purge da secao do cache: {}", error.message);
            false
        }
    }
}

/// O FILE_OBJECT da paginação troca (CcChangeBackingFileObject).
pub fn change_file(cache_section: &CacheSection, file: u64) {
    if let Err(error) = cache_section.file.replace_pointer(file) {
        debug_print!("[cc] troca do arquivo da secao do cache: {}", error.message);
    }
}
