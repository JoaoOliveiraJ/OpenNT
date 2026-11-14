//! Posse de vistas de seção por processo.
//!
//! Cada vista tem o processo dono e a raiz em que está mapeada (a do dono:
//! cada processo de usuário tem a sua). A mesma VA pode estar em vistas de
//! processos diferentes; a escolha de endereço e as buscas olham a raiz do
//! espaço (`OwnedView::root`).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::mm::pfn;
use crate::ntos::ke::smp;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::user::sections::{self, Section, View};
use crate::ntos::ps::user::state::{Region, RegionKind, UserRegion};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::pe_loader::PeImage;

/// Vista de imagem mapeada pelo loader (`image_view`).
pub struct ImageView {
    pub base: u64,
    pub size: u64,
    pub section: Option<Arc<Section>>,
    /// Token de posse do loader; vistas iniciais antigas não têm.
    pub image: SpinLock<Option<PeImage>>,
    /// PFNs das vistas iniciais sem token.
    pub pages: Vec<u64>,
    pub regions: SpinLock<Option<RegionKind>>,
    /// Proteções e frames das páginas reprotegidas.
    pub page_protects: SpinLock<alloc::collections::BTreeMap<u64, u32>>,
    pub protected_frames: SpinLock<alloc::collections::BTreeMap<u64, u64>>,
    /// Nome nativo do arquivo da imagem.
    pub name: Option<alloc::string::String>,
    /// PAGE_READONLY nas seções sem execução, senão a proteção pedida.
    pub allocation_protect: u32,
    /// A raiz do processo em que a vista foi mapeada.
    pub root: u64,
}

impl UserRegion for ImageView {
    fn base(&self) -> u64 {
        self.base
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn section(&self) -> Option<Arc<Section>> {
        self.section.clone()
    }
    fn name(&self) -> Option<alloc::string::String> {
        self.name.clone()
    }
    fn allocation_protect(&self) -> u32 {
        self.allocation_protect
    }
    fn page_protect(&self, index: u64) -> Option<u32> {
        self.page_protects.lock().get(&index).copied()
    }
    fn frame(&self, index: u64) -> Option<u64> {
        self.pages.get(index as usize).copied().or_else(|| self.protected_frames.lock().get(&index).copied())
    }
    fn record_protect(&self, index: u64, protect: u32, physical: u64) -> bool {
        self.page_protects.lock().insert(index, protect);
        self.protected_frames.lock().insert(index, physical);
        true
    }
}

/// Vista com dono: dados (seção) ou imagem.
#[derive(Clone)]
pub enum OwnedView {
    Data(Arc<View>),
    Image(Arc<ImageView>),
}

impl OwnedView {
    pub fn same(&self, other: &OwnedView) -> bool {
        match (self, other) {
            (OwnedView::Data(left), OwnedView::Data(right)) => Arc::ptr_eq(left, right),
            (OwnedView::Image(left), OwnedView::Image(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    pub fn base(&self) -> u64 {
        match self {
            OwnedView::Data(view) => view.base,
            OwnedView::Image(view) => view.base,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            OwnedView::Data(view) => view.size,
            OwnedView::Image(view) => view.size,
        }
    }

    /// A raiz em que a vista está mapeada.
    pub fn root(&self) -> u64 {
        match self {
            OwnedView::Data(view) => view.root,
            OwnedView::Image(view) => view.root,
        }
    }

    pub fn region(&self) -> Region {
        match self {
            OwnedView::Data(view) => view.clone(),
            OwnedView::Image(view) => view.clone(),
        }
    }
}

struct Owned {
    view: OwnedView,
    owner_process: u64,
    image_view: bool,
}

static OWNED: SpinLock<Vec<Owned>> = SpinLock::new(Vec::new());

pub fn register(view: OwnedView, process: u64, image: bool) {
    let mut owned = OWNED.lock();
    owned.retain(|entry| !entry.view.same(&view));
    owned.push(Owned { view, owner_process: process, image_view: image });
}

pub fn forget(view: &OwnedView) {
    OWNED.lock().retain(|entry| !entry.view.same(view));
}

/// Regiões do processo: vistas de dados e imagens.
pub struct ProcessRegions {
    pub user_regions: Vec<OwnedView>,
    pub process_images: Vec<OwnedView>,
}

pub fn regions(process: u64) -> ProcessRegions {
    let owned = OWNED.lock();
    let list = owned.iter().filter(|entry| entry.owner_process == process);
    let (images, data): (Vec<&Owned>, Vec<&Owned>) = list.partition(|entry| entry.image_view);
    ProcessRegions { user_regions: data.into_iter().map(|entry| entry.view.clone()).collect(), process_images: images.into_iter().map(|entry| entry.view.clone()).collect() }
}

fn is_image_view(view: &OwnedView) -> bool {
    OWNED.lock().iter().find(|entry| entry.view.same(view)).is_some_and(|entry| entry.image_view)
}

/// Vistas de dados voltam a `sections::unmap`; vistas de imagem soltam o
/// token do loader (ou os PFNs reais das vistas iniciais, nunca um sucesso
/// sintético), invalidam os TLBs e liberam a seção.
pub fn unmap(view: &OwnedView) -> Result<(), KernelError> {
    let image = match view {
        OwnedView::Data(data) if !is_image_view(view) => return sections::unmap(data, None),
        OwnedView::Data(_) => return Err(KernelError::new("data view registered as image view")),
        OwnedView::Image(image) => image.clone(),
    };
    let token = image.image.lock().take();
    match token {
        Some(mut loaded) => {
            if let Err(error) = loaded.release() {
                *image.image.lock() = Some(loaded);
                return Err(error);
            }
        }
        None => {
            let mut offset = 0;
            while offset < image.size {
                paging::unmap_page_in(image.root, image.base + offset, MapOptions::default());
                if let Some(&frame) = image.pages.get((offset / 4096) as usize) {
                    pfn::free_page(frame);
                }
                offset += 4096;
            }
        }
    }
    smp::flush_remote_tlb(false)?;
    let kind = *image.regions.lock();
    if let Some(kind) = kind {
        let region: Region = image.clone();
        crate::ntos::ps::user::memory::remove_region(kind, &region);
    }
    forget(view);
    if let Some(section) = &image.section {
        section.state.lock().views.retain(|candidate| !candidate.same(view));
        section_objects::update(section.pointer(), |state| state.views = state.views.saturating_sub(1));
        section_objects::collect(section.pointer())?;
    }
    Ok(())
}

/// O ALPC conserva referências de mensagens e consumidores: o dono conclui
/// a retirada antes de o espaço do processo ser solto.
pub fn release_process(process: u64) -> Result<(), KernelError> {
    let candidates: Vec<OwnedView> = OWNED.lock().iter().filter(|entry| entry.owner_process == process).map(|entry| entry.view.clone()).collect();
    for view in candidates {
        let still_owned = OWNED.lock().iter().any(|entry| entry.view.same(&view) && entry.owner_process == process);
        if !still_owned {
            continue;
        }
        let release = match &view {
            OwnedView::Data(data) => data.state.lock().release_process_view.clone(),
            OwnedView::Image(_) => None,
        };
        match release {
            Some(release) => release()?,
            None => unmap(&view)?,
        }
    }
    Ok(())
}

/// Vista do processo que contém o endereço.
pub fn find(process: u64, address: u64) -> Option<OwnedView> {
    OWNED.lock().iter().find(|entry| entry.owner_process == process && address >= entry.view.base() && address < entry.view.base() + entry.view.size()).map(|entry| entry.view.clone())
}

pub fn all() -> Vec<OwnedView> {
    OWNED.lock().iter().map(|entry| entry.view.clone()).collect()
}
