//! Vista de seção de imagem (o MiMapViewOfImageSection).
//!
//! A vista mapeia, na raiz do processo alvo, as páginas da control area da
//! imagem (`image_segment`: as páginas protótipo montadas uma vez por
//! arquivo, sem imports nem relocações; a ntdll real faz o binding e reloca
//! a vista que cai fora da ImageBase). A vista entra nas listas do processo
//! e da seção e dispara a notificação de imagem.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

use crate::ntos::mm::section::map_view_parameters::View as Request;
use crate::ntos::mm::memory_map;
use crate::ntos::mm::section::address::{self as section_address, FindOptions};
use crate::ntos::ps::user::memory as user_memory;
use crate::ntos::mm::section::views::{self as section_views, ImageView, OwnedView};
use crate::ntos::ob::objects::file::FileSource;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::notify::image::{self as image_notify, Image, NotifyOptions};
use crate::ntos::ps::process_context;
use crate::ntos::ps::user::sections::{Section, SectionFile};
use crate::ntos::ps::user::state::{self, Region, RegionKind};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::section::image_segment;

/// Vista mapeada, o status (0 ou STATUS_IMAGE_NOT_AT_BASE) e o offset.
pub struct Mapped {
    pub view: Arc<ImageView>,
    pub status: u32,
    pub offset: u64,
}

/// O arquivo da seção como origem da notificação de imagem.
struct SectionSource {
    name: String,
    file: Arc<dyn SectionFile>,
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
    let space = user_memory::Space::of(process);
    let root = space.root();
    let options = FindOptions { base: request.base, size, upper: Some(request.upper), alignment: memory_map::ALLOCATION_GRANULARITY, top_down, root, ..FindOptions::default() };
    let name = file.nt_path().or_else(|| section.name()).unwrap_or_default();
    let source = Arc::new(SectionSource { name: name.clone(), file: file.clone() });
    // A control area da imagem (montada uma vez por arquivo, lendo o
    // arquivo) não depende da VA e vem antes da AddressCreationLock: com um
    // SharedLock retido o PFN não roda o modified page writer na hora.
    let segment = match image_segment::of_section(section, &name)? {
        Ok(segment) => segment,
        Err(status) => return Ok(Err(status)),
    };
    // A vista cabe nas páginas da control area (o SizeOfImage arredondado).
    if offset % 4096 != 0 || size % 4096 != 0 || offset.checked_add(size).is_none_or(|end| end > segment.frames.len() as u64 * 4096) {
        return Ok(Err(0xC000_007B));
    }
    // Da escolha da faixa até a vista entrar no VAD: a AddressCreationLock.
    let _creation = user_memory::address_creation(space);
    let occupied = user_memory::occupied(space);
    // Sem base pedida: a ImageBase do cabeçalho quando está livre, senão a
    // primeira faixa livre (STATUS_IMAGE_NOT_AT_BASE).
    let mut found = None;
    let wanted = preferred.wrapping_add(offset);
    if request.base == 0 && wanted % memory_map::ALLOCATION_GRANULARITY == 0 && memory_map::is_user_range(wanted, size) {
        found = section_address::find(&FindOptions { base: wanted, ..options }, &occupied).ok();
    }
    let base = match found {
        Some(base) => base,
        None => match section_address::find(&options, &occupied) {
            Ok(base) => base,
            Err(status) => return Ok(Err(status)),
        },
    };
    // A vista sobre a control area, na raiz do processo alvo.
    let pages = match image_segment::map_view(&segment, root, base, offset, size) {
        Ok(pages) => pages,
        Err(status) => return Ok(Err(status)),
    };
    let (image_base, preferred_base, size_of_image) = (base - offset, segment.preferred_base, segment.size_of_image);
    let view = Arc::new(ImageView {
        base,
        size,
        section: Some(section.clone()),
        segment: segment.clone(),
        pages: SpinLock::new(pages),
        regions: SpinLock::new(Some(regions)),
        name: Some(name.clone()),
        allocation_protect: if section.no_execute { 2 } else { request.protect },
        root,
        unmapped: AtomicBool::new(false),
    });
    let owned = OwnedView::Image(view.clone());
    section.state.lock().views.push(owned.clone());
    section_objects::update(section.pointer(), |state| state.views += 1);
    // A vista entra no VAD do processo alvo.
    let region: Region = view.clone();
    user_memory::insert_region(space, regions, region);
    section_views::register(owned.clone(), process, true);
    let finish = || -> Result<(), KernelError> {
        let dll_name = file.base_name().unwrap_or_else(|| String::from(&name[name.rfind(['\\', '/']).map_or(0, |at| at + 1)..]));
        if offset == 0 && size == section.size() && regions == RegionKind::ProcessImages {
            crate::ntos::init::initial_process::image_mapped(process, &dll_name);
        }
        // A captura de chamada de teste (`call_capture`) lê os exports das
        // páginas protótipo só quando está armada.
        if offset == 0 && size == section.size() && regions == RegionKind::ProcessImages && state::with(|state| !state.capture_export.is_empty()) {
            let exports = image_segment::exports(&segment, image_base)?;
            crate::ntos::ps::user::call_capture::arm(&dll_name, &exports.exports);
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
