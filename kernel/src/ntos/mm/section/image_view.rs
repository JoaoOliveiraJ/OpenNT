//! Vista de seção de imagem pelo loader.
//!
//! A imagem é preparada pelo loader de PE com a vista parcial pedida, sem
//! imports nem relocações (a ntdll real faz o binding). A vista entra nas
//! listas do processo e da seção e dispara a notificação de imagem.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::mm::section::map_view_parameters::View as Request;
use crate::ntos::mm::section::address::{self as section_address, FindOptions};
use crate::ntos::mm::section::views::{self as section_views, ImageView, OwnedView};
use crate::ntos::ob::objects::file::FileSource;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::notify::image::{self as image_notify, Image, NotifyOptions};
use crate::ntos::ps::process_context;
use crate::ntos::ps::user::sections::{Section, SectionFile};
use crate::ntos::ps::user::state::{self, Region, RegionKind};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::sysload::kernel_image_source::ImageSource;
use crate::ntos::mm::pe_loader::{self, LoadOptions, UserView};

/// Vista mapeada, o status (0 ou STATUS_IMAGE_NOT_AT_BASE) e o offset.
pub struct Mapped {
    pub view: Arc<ImageView>,
    pub status: u32,
    pub offset: u64,
}

/// O arquivo da seção como origem do loader e da notificação.
struct SectionSource {
    name: String,
    file: Arc<dyn SectionFile>,
}

impl ImageSource for SectionSource {
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
        self.file.has_copy_to_physical()
    }
    fn copy_to_physical(&self, offset: u64, address: u64, length: u64) -> Option<Result<(), KernelError>> {
        self.file.has_copy_to_physical().then(|| self.file.copy_to_physical(offset, address, length))
    }
}

impl FileSource for SectionSource {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        self.file.size()
    }
    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, KernelError> {
        self.file.read_at(offset, length as u64)
    }
}

fn read32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
}

fn occupied() -> Vec<section_address::Region> {
    let mut regions: Vec<section_address::Region> = state::with(|state| state.user_regions.iter().chain(state.process_images.iter()).chain(state.shared_user_regions.iter()).map(|region| section_address::Region { base: region.base(), size: region.size() }).collect());
    regions.extend(section_views::all().iter().map(|view| section_address::Region { base: view.base(), size: view.size() }));
    regions
}

pub fn map(section: &Arc<Section>, request: &Request, process: u64, regions: RegionKind) -> Result<Result<Mapped, u32>, KernelError> {
    let Some(file) = section.file.clone() else { return Ok(Err(0xC000_0185)) };
    // O cabeçalho PE dá a base preferida.
    let preferred = (|| {
        let dos = file.read_at(0, 64).ok()?;
        let pe = read32(&dos, 0x3C)? as u64;
        let header = file.read_at(pe, 88).ok()?;
        header.get(48..56).map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])))
    })();
    let Some(preferred) = preferred else { return Ok(Err(0xC000_0185)) };
    let (offset, size) = (request.offset, request.size);
    let top_down = request.allocation & 0x10_0000 != 0;
    let options = FindOptions { base: request.base, size, upper: Some(request.upper), alignment: 65536, top_down, start: if top_down { 0 } else { 0x1_8000_0000 }, ..FindOptions::default() };
    let occupied = occupied();
    let mut found = None;
    if request.base == 0 && preferred <= (1 << 53) - 1 && preferred >= 0x1_0000_0000 {
        found = section_address::find(&FindOptions { base: preferred + offset, ..options }, &occupied).ok();
    }
    let base = match found {
        Some(base) => base,
        None => match section_address::find(&options, &occupied) {
            Ok(base) => base,
            Err(status) => return Ok(Err(status)),
        },
    };
    let name = file.nt_path().or_else(|| section.name()).unwrap_or_default();
    let source = Arc::new(SectionSource { name: name.clone(), file: file.clone() });
    let load = LoadOptions { user_space: true, skip_imports: true, skip_relocations: true, skip_security_cookie: true, notify_image: false, no_execute: section.no_execute, user_view: Some(UserView { base, offset, size }), ..LoadOptions::default() };
    let image = match pe_loader::load_from_source(source.clone(), &load) {
        Ok(image) => image,
        Err(error) if error.status != crate::ntos::inc::status::STATUS_UNSUCCESSFUL => return Ok(Err(error.status)),
        Err(error) => {
            crate::debug_print!("[section-image] {}", error.message);
            return Ok(Err(if error.message.contains("PFN") || error.message.contains("mapPage") { 0xC000_0017 } else { 0xC000_007B }));
        }
    };
    let first = (offset / 4096) as usize;
    let last = ((offset + size) / 4096) as usize;
    let pages: Vec<u64> = image.pages.get(first..last.min(image.pages.len())).map_or_else(Vec::new, <[u64]>::to_vec);
    let page_protects = image.page_protects.get(first..last.min(image.page_protects.len())).unwrap_or(&[]).iter().enumerate().map(|(index, &protect)| (index as u64, protect)).collect();
    let exports = image.exports.exports.clone();
    let (image_base, preferred_base, size_of_image) = (image.image_base, image.preferred_base, image.size_of_image);
    let view = Arc::new(ImageView {
        base,
        size,
        section: Some(section.clone()),
        image: SpinLock::new(Some(image)),
        pages,
        regions: SpinLock::new(Some(regions)),
        page_protects: SpinLock::new(page_protects),
        protected_frames: SpinLock::new(alloc::collections::BTreeMap::new()),
        name: Some(name.clone()),
        allocation_protect: if section.no_execute { 2 } else { request.protect },
    });
    let owned = OwnedView::Image(view.clone());
    section.state.lock().views.push(owned.clone());
    section_objects::update(section.pointer(), |state| state.views += 1);
    let region: Region = view.clone();
    state::with(|state| {
        if regions != RegionKind::Detached {
            state.regions(regions).push(region);
        }
    });
    section_views::register(owned.clone(), process, true);
    let finish = || -> Result<(), KernelError> {
        let dll_name = file.base_name().unwrap_or_else(|| String::from(&name[name.rfind(['\\', '/']).map_or(0, |at| at + 1)..]));
        if offset == 0 && size == section.size && regions == RegionKind::ProcessImages {
            state::with(|state| state.mapped_image_exports.insert(dll_name.to_ascii_lowercase(), exports.clone()));
            if state::with(|state| !state.capture_export.is_empty()) {
                crate::ntos::ps::user::call_capture::arm(&dll_name, &exports);
            }
        }
        if !section.no_execute {
            let file_object = section.state.lock().image_file_object;
            let notify_source: Arc<dyn FileSource> = source.clone();
            process_context::with_process(process, || image_notify::notify(Image { image_base, size_of_image }, &NotifyOptions { name: Some(name.clone()), file_object, source: Some(notify_source), ..NotifyOptions::default() }))??;
        }
        Ok(())
    };
    if let Err(error) = finish() {
        section_views::unmap(&owned)?;
        return Err(error);
    }
    Ok(Ok(Mapped { view, status: if image_base == preferred_base { 0 } else { 0x4000_0003 }, offset }))
}
