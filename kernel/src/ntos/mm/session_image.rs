//! Imagens de sessão: MmLoadSystemImage com MM_LOAD_IMAGE_IN_SESSION.
//!
//! Como no Windows 10 19041 (MiGetSystemAddressForImage na faixa de imagens
//! de sessão, MiSessionInsertImage/MiSessionRemoveImage e os protótipos por
//! sessão das páginas graváveis):
//!
//! - a imagem é carregada uma vez (`pe_loader` com `LoadOptions::session`):
//!   a VA vem da faixa de imagens de sessão e é a mesma em toda sessão que a
//!   carrega, e os frames da carga (relocados, com a IAT resolvida e o cookie
//!   semeado) são a cópia mestra;
//! - cada sessão que a carrega ([`map_new`] na primeira, [`load_into_current`]
//!   nas demais, com LoadCount + 1) mapeia nas próprias tabelas as páginas
//!   de código e somente leitura sobre os frames mestres, compartilhados e
//!   sem escrita, e as páginas graváveis sobre cópias privadas da sessão,
//!   feitas da mestra quando a sessão carrega a imagem: o copy-on-write dos
//!   protótipos por sessão já resolvido, que é o que o NT faz com as seções
//!   não pagináveis de uma imagem de sessão (todas as seções graváveis do
//!   win32k*.sys e do cdd.dll são NOT_PAGED). Duas sessões veem globais
//!   separados na mesma VA;
//! - cada sessão conta as cargas da imagem (o ImageCountInThisSession do
//!   nó da imagem na sessão, que o MiSessionInsertImage incrementa quando a
//!   imagem já está nela: o MmLoadSystemImage devolve sucesso sem mexer no
//!   LoadCount). O MmUnloadSystemImage numa sessão ([`unload_from_current`])
//!   desconta uma carga; a última desfaz a vista da sessão e devolve as
//!   cópias privadas, e o fim da sessão ([`release_session`], o
//!   MiSessionUnloadAllImages) desfaz tudo de uma vez; a última sessão
//!   devolve a imagem mestra (VA, frames e a entrada do loader).
//!
//! As imagens de sistema (drivers da janela de sistema) não passam por aqui.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::pe_loader::PeImage;
use super::{pfn, session};
use crate::hal::physical;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::KldrDataTableEntry;
use crate::rtl::{KernelError, SpinLock};

const PAGE: u64 = 0x1000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// STATUS_NO_MEMORY: a carga de sessão fora de uma sessão.
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PageKind {
    writable: bool,
    executable: bool,
}

/// Uma imagem de sessão carregada.
struct SharedImage {
    image: PeImage,
    /// A KLDR_DATA_TABLE_ENTRY (o ImageHandle).
    entry: u64,
    kinds: Vec<PageKind>,
    /// As sessões (VA global) que a carregaram, com as cargas de cada uma.
    sessions: BTreeMap<u64, u32>,
}

static IMAGES: SpinLock<BTreeMap<u64, SharedImage>> = SpinLock::new(BTreeMap::new());
/// As cópias privadas de cada (sessão, base): (página, frame).
static VIEWS: SpinLock<BTreeMap<(u64, u64), Vec<(usize, u64)>>> = SpinLock::new(BTreeMap::new());

/// A proteção de cada página pelas seções (o cabeçalho e os vãos ficam
/// somente leitura, sem execução).
fn page_kinds(image: &PeImage) -> Vec<PageKind> {
    let pages = image.size_of_image.div_ceil(PAGE) as usize;
    (0..pages)
        .map(|index| {
            let page = index as u64 * PAGE;
            let characteristics = image.sections.iter().filter(|section| page < section.va as u64 + section.virtual_size.max(section.raw_size) as u64 && page + PAGE > section.va as u64).fold(0, |all, section| all | section.characteristics);
            PageKind { writable: characteristics & IMAGE_SCN_MEM_WRITE != 0, executable: characteristics & IMAGE_SCN_MEM_EXECUTE != 0 }
        })
        .collect()
}

fn copy_page(source: u64, target: u64) {
    for offset in (0..PAGE).step_by(8) {
        physical::write64(target + offset, physical::read64(source + offset));
    }
}

/// Desfaz a vista de `base` na sessão `pointer` e devolve as cópias.
fn unmap_view(pointer: u64, base: u64, pages: usize) -> Result<(), KernelError> {
    let addresses: Vec<u64> = (0..pages as u64).map(|index| base + index * PAGE).collect();
    session::unmap_pages(pointer, &addresses)?;
    for (_, frame) in VIEWS.lock().remove(&(pointer, base)).unwrap_or_default() {
        pfn::free_page(frame);
    }
    Ok(())
}

/// Mapeia a imagem `base` (frames mestres `masters`) na sessão `pointer`.
fn map_view(pointer: u64, base: u64, masters: &[u64], kinds: &[PageKind]) -> Result<(), KernelError> {
    let mut private = Vec::new();
    let mut result = Ok(());
    for (index, (&master, kind)) in masters.iter().zip(kinds).enumerate() {
        let frame = if kind.writable {
            let copy = pfn::alloc_page();
            if copy == 0 {
                result = Err(KernelError::with_status("no frame for a session image page", 0xC000_009A));
                break;
            }
            copy_page(master, copy);
            private.push((index, copy));
            copy
        } else {
            master
        };
        if let Err(error) = session::map_page(pointer, base + index as u64 * PAGE, frame, kind.writable, kind.executable) {
            result = Err(error);
            break;
        }
    }
    VIEWS.lock().insert((pointer, base), private);
    if result.is_err() {
        let _ = unmap_view(pointer, base, masters.len());
    }
    result
}

/// A imagem recém-carregada entra na sessão corrente (chamado pelo
/// `pe_loader` antes do registro e das notificações).
pub fn map_new(image: &PeImage) -> Result<(), KernelError> {
    let pointer = session::current();
    if pointer == 0 {
        return Err(KernelError::with_status("session image load outside a session", STATUS_NO_MEMORY));
    }
    map_view(pointer, image.image_base, &image.pages, &page_kinds(image))
}

/// Desfaz a vista de [`map_new`] de uma carga que falhou depois dela.
pub fn discard_new(image: &PeImage) {
    let pointer = session::current();
    if pointer != 0 && VIEWS.lock().contains_key(&(pointer, image.image_base)) {
        if let Err(error) = unmap_view(pointer, image.image_base, image.pages.len()) {
            crate::debug_print!("[mm] vista de sessao de {:#x} retida: {}", image.image_base, error);
        }
    }
}

/// Registra a imagem carregada por [`map_new`] na sessão corrente, com a
/// entrada do loader.
pub fn register(entry: u64, image: PeImage) {
    let kinds = page_kinds(&image);
    let mut sessions = BTreeMap::new();
    sessions.insert(session::current(), 1);
    IMAGES.lock().insert(image.image_base, SharedImage { image, entry, kinds, sessions });
}

/// A imagem em `base` é uma imagem de sessão.
pub fn is_session_image(base: u64) -> bool {
    IMAGES.lock().contains_key(&base)
}

/// A entrada do loader de uma imagem de sessão.
pub fn entry_of(base: u64) -> Option<u64> {
    IMAGES.lock().get(&base).map(|image| image.entry)
}

/// Os exports de uma imagem de sessão (o import de outra imagem a acha na
/// lista de imagens carregadas).
pub fn exports_of(base: u64) -> Option<alloc::sync::Arc<crate::ntos::rtl::image::pe_exports::Exports>> {
    IMAGES.lock().get(&base).map(|image| image.image.exports.clone())
}

/// O frame mestre da página de `va` (0 fora de uma imagem de sessão).
pub fn master_frame(va: u64) -> u64 {
    let images = IMAGES.lock();
    images.range(..=va).next_back().filter(|(&base, image)| va < base + image.image.size_of_image).map_or(0, |(&base, image)| image.image.pages.get(((va - base) / PAGE) as usize).copied().unwrap_or(0))
}

/// As sessões que carregaram a imagem `base`.
pub fn sessions_of(base: u64) -> Vec<u64> {
    IMAGES.lock().get(&base).map_or(Vec::new(), |image| image.sessions.keys().copied().collect())
}

fn adjust_load_count(entry: u64, difference: i32) {
    // SAFETY: a KLDR_DATA_TABLE_ENTRY viva da imagem de sessão.
    let count = &unsafe { KldrDataTableEntry::at(entry) }.load_count;
    count.set((count.get() as i32 + difference).max(0) as u16);
}

/// MiSessionInsertImage de uma imagem já carregada: a sessão corrente a
/// mapeia (LoadCount + 1) se ainda não a tem; se já tem, conta mais uma
/// carga nela. Devolve se mapeou agora.
pub fn load_into_current(base: u64) -> Result<bool, KernelError> {
    let pointer = session::current();
    if pointer == 0 {
        return Err(KernelError::with_status("session image load outside a session", STATUS_NO_MEMORY));
    }
    let (masters, kinds, entry) = {
        let mut images = IMAGES.lock();
        let Some(image) = images.get_mut(&base) else { return Err(KernelError::new("not a session image")) };
        if let Some(loads) = image.sessions.get_mut(&pointer) {
            *loads += 1;
            return Ok(false);
        }
        (image.image.pages.clone(), image.kinds.clone(), image.entry)
    };
    map_view(pointer, base, &masters, &kinds)?;
    if let Some(image) = IMAGES.lock().get_mut(&base) {
        image.sessions.insert(pointer, 1);
    }
    adjust_load_count(entry, 1);
    Ok(true)
}

/// Desconta uma carga da imagem `base` na sessão `pointer` (todas, com
/// `all`); sem cargas, tira a imagem da sessão (LoadCount - 1), e a última
/// sessão devolve a imagem mestra.
fn remove_from(pointer: u64, base: u64, all: bool) -> Result<(), KernelError> {
    let (pages, entry) = {
        let mut images = IMAGES.lock();
        let Some(image) = images.get_mut(&base) else { return Ok(()) };
        let Some(loads) = image.sessions.get_mut(&pointer) else {
            return Err(KernelError::new("session image not loaded in this session"));
        };
        if !all && *loads > 1 {
            *loads -= 1;
            return Ok(());
        }
        (image.image.pages.len(), image.entry)
    };
    unmap_view(pointer, base, pages)?;
    let last = {
        let mut images = IMAGES.lock();
        let image = images.get_mut(&base).expect("session image vanished");
        image.sessions.remove(&pointer);
        if image.sessions.is_empty() { images.remove(&base) } else { None }
    };
    match last {
        Some(mut image) => image.image.release(),
        None => {
            adjust_load_count(entry, -1);
            Ok(())
        }
    }
}

/// MmUnloadSystemImage de uma imagem de sessão, na sessão corrente.
pub fn unload_from_current(base: u64) -> Result<(), KernelError> {
    remove_from(session::current(), base, false)
}

/// MiSessionUnloadAllImages: as imagens que a sessão carregou saem dela.
pub fn release_session(pointer: u64) {
    let bases: Vec<u64> = IMAGES.lock().iter().filter(|(_, image)| image.sessions.contains_key(&pointer)).map(|(&base, _)| base).collect();
    for base in bases {
        if let Err(error) = remove_from(pointer, base, true) {
            crate::debug_print!("[mm] imagem de sessao {:#x} retida no fim da sessao: {}", base, error);
        }
    }
}
