//! A control area de uma seção de imagem (SEC_IMAGE).
//!
//! Como o MiCreateImageFileMap do NT, a imagem é montada uma vez por arquivo
//! nas páginas protótipo da control area: frames do PFN com os cabeçalhos e
//! as seções do PE no layout virtual, zerados no resto, sem relocação, sem
//! imports e sem cookie de segurança (a ntdll de cada processo faz isso na
//! própria vista). Todas as seções do mesmo arquivo usam a mesma control
//! area, como o ImageSectionObject dos SECTION_OBJECT_POINTERS: a chave é a
//! identidade do arquivo (`SectionFile::identity`) e, sem ela, o próprio
//! objeto seção. A seção retém a control area enquanto existe, e cada vista
//! também; a última referência devolve os frames ao PFN.
//!
//! Uma vista ([`map_view`]) mapeia as páginas de código e somente leitura
//! sobre os frames protótipo, compartilhados entre os processos e sem
//! escrita, e as páginas graváveis sobre cópias privadas do processo, feitas
//! na hora do mapeamento: é o copy-on-write do protótipo já resolvido, como
//! o NT faz com as páginas graváveis de uma imagem de sessão. Uma página
//! compartilhada que o NtProtectVirtualMemory torna gravável ganha a cópia
//! privada antes da troca ([`write_copy`]): no NT, PAGE_READWRITE numa vista
//! de imagem vira PAGE_WRITECOPY e a primeira escrita copia a página. Assim a
//! relocação e a IAT que a ntdll de um processo grava nunca aparecem em outro.
//!
//! Nada aqui guarda a imagem no heap do kernel: só os vetores de frames e de
//! proteções (12 bytes por página). A tabela de exports não é montada; quem
//! precisa dela ([`exports`]) a lê das páginas protótipo.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::hal::physical;
use crate::ntos::mm::paging::{self, MapOptions};
use crate::ntos::mm::pe_loader::{self, LoadOptions, PeImage};
use crate::ntos::mm::pfn;
use crate::ntos::mm::sysload::kernel_image_source::ImageSource;
use crate::ntos::ps::user::sections::{Section, SectionFile};
use crate::ntos::rtl::image::pe_exports::{self, Exports};
use crate::rtl::{KernelError, SpinLock};

const PAGE: u64 = 0x1000;
/// STATUS_INSUFFICIENT_RESOURCES.
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// A control area de uma imagem: as páginas protótipo e a proteção de cada
/// página pelas características das seções do PE.
pub struct ImageSegment {
    key: SegmentKey,
    /// A carga que é dona dos frames (devolvidos no `Drop`).
    image: SpinLock<Option<PeImage>>,
    /// Um frame do PFN por página da imagem.
    pub frames: Vec<u64>,
    /// PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE ou as variantes EXECUTE.
    pub protections: Vec<u32>,
    /// A ImageBase do cabeçalho (a das páginas protótipo).
    pub preferred_base: u64,
    pub size_of_image: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SegmentKey {
    File(String),
    Section(u64),
}

/// As control areas vivas, para que uma nova seção do mesmo arquivo use a
/// mesma (a seção e as vistas guardam as referências fortes).
static SEGMENTS: SpinLock<BTreeMap<SegmentKey, Weak<ImageSegment>>> = SpinLock::new(BTreeMap::new());

impl Drop for ImageSegment {
    fn drop(&mut self) {
        {
            let mut segments = SEGMENTS.lock();
            if segments.get(&self.key).is_some_and(|weak| weak.strong_count() == 0) {
                segments.remove(&self.key);
            }
        }
        if let Some(mut image) = self.image.lock().take() {
            if let Err(error) = image.release() {
                crate::debug_print!("[section-image] control area {:?}: {}", self.key, error);
            }
        }
    }
}

/// A página é gravável (PAGE_READWRITE ou PAGE_EXECUTE_READWRITE).
pub fn writable(protect: u32) -> bool {
    matches!(protect, 4 | 0x40)
}

/// Flags de PTE de usuário de uma página com a proteção Win32 `protect`.
pub fn pte_flags(protect: u32) -> (u64, bool) {
    let flags = paging::PAGE_USER | if protect != 1 { paging::PAGE_PRESENT } else { 0 } | if writable(protect) { paging::PAGE_RW } else { 0 };
    (flags, !matches!(protect, 0x10 | 0x20 | 0x40 | 0x80))
}

/// O arquivo da seção como origem do loader.
struct SegmentSource {
    name: String,
    file: Arc<dyn SectionFile>,
}

impl ImageSource for SegmentSource {
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

fn key_of(section: &Section) -> SegmentKey {
    section.file.as_ref().and_then(|file| file.identity()).map_or(SegmentKey::Section(section.pointer()), SegmentKey::File)
}

/// A control area da seção: a que ela já retém, a viva do mesmo arquivo ou
/// uma nova, montada das páginas do arquivo. `Ok(Err(status))` é a recusa
/// do formato ou a falta de memória.
pub fn of_section(section: &Arc<Section>, name: &str) -> Result<Result<Arc<ImageSegment>, u32>, KernelError> {
    if let Some(segment) = section.state.lock().image_segment.clone() {
        return Ok(Ok(segment));
    }
    let Some(file) = section.file.clone() else { return Ok(Err(0xC000_0185)) };
    let key = key_of(section);
    let existing = SEGMENTS.lock().get(&key).and_then(Weak::upgrade);
    let segment = match existing {
        Some(segment) => segment,
        None => {
            let source: Arc<dyn ImageSource> = Arc::new(SegmentSource { name: String::from(name), file });
            let options = LoadOptions { user_space: true, prototype: true, skip_imports: true, skip_relocations: true, skip_security_cookie: true, notify_image: false, no_execute: section.no_execute, ..LoadOptions::default() };
            let mut image = match pe_loader::load_from_source(source, &options) {
                Ok(image) => image,
                Err(error) if error.status != crate::ntos::inc::status::STATUS_UNSUCCESSFUL => return Ok(Err(error.status)),
                Err(error) => {
                    crate::debug_print!("[section-image] {}: {}", name, error.message);
                    return Ok(Err(if error.message.contains("PFN") { STATUS_INSUFFICIENT_RESOURCES } else { 0xC000_007B }));
                }
            };
            // Os vetores passam para a control area (a carga guardada só
            // devolve os frames, pela lista própria dela).
            let (frames, protections) = (core::mem::take(&mut image.pages), core::mem::take(&mut image.page_protects));
            let created = Arc::new(ImageSegment { key: key.clone(), frames, protections, preferred_base: image.preferred_base, size_of_image: image.size_of_image, image: SpinLock::new(Some(image)) });
            // Outra seção do mesmo arquivo pode ter montado a dela enquanto
            // esta lia o arquivo: fica a primeira, e esta volta ao PFN.
            let mut segments = SEGMENTS.lock();
            match segments.get(&key).and_then(Weak::upgrade) {
                Some(winner) => {
                    drop(segments);
                    drop(created);
                    winner
                }
                None => {
                    segments.insert(key, Arc::downgrade(&created));
                    created
                }
            }
        }
    };
    let mut state = section.state.lock();
    Ok(Ok(state.image_segment.get_or_insert(segment).clone()))
}

/// As páginas de uma vista: o frame de cada página (protótipo ou cópia
/// privada) e quais são privadas.
pub struct ViewPages {
    pub frames: Vec<u64>,
    pub private: Vec<bool>,
    pub protections: Vec<u32>,
}

impl ViewPages {
    /// Devolve as cópias privadas ao PFN.
    pub fn release_private(&mut self) {
        for (frame, private) in self.frames.iter().zip(self.private.iter_mut()) {
            if *private && pfn::free_page(*frame) {
                *private = false;
            }
        }
    }
}

fn private_copy(source: u64) -> Option<u64> {
    let frame = pfn::alloc_page();
    if frame == 0 {
        return None;
    }
    physical::write_bytes(frame, &physical::read_bytes(source, PAGE as usize));
    Some(frame)
}

/// Mapeia as páginas `[offset, offset + size)` da imagem em `base` na raiz
/// `root`. Uma falha desfaz o que mapeou.
pub fn map_view(segment: &ImageSegment, root: u64, base: u64, offset: u64, size: u64) -> Result<ViewPages, u32> {
    let first = (offset / PAGE) as usize;
    let count = (size / PAGE) as usize;
    if first + count > segment.frames.len() {
        return Err(0xC000_000D);
    }
    let mut pages = ViewPages { frames: Vec::with_capacity(count), private: Vec::with_capacity(count), protections: Vec::with_capacity(count) };
    for index in 0..count {
        let protect = segment.protections[first + index];
        let master = segment.frames[first + index];
        let (frame, private) = if writable(protect) {
            match private_copy(master) {
                Some(frame) => (frame, true),
                None => {
                    unmap_pages(root, base, &mut pages);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
            }
        } else {
            (master, false)
        };
        pages.frames.push(frame);
        pages.private.push(private);
        pages.protections.push(protect);
        let (flags, nx) = pte_flags(protect);
        if !paging::map_page_in(root, base + index as u64 * PAGE, frame, flags, MapOptions { nx, ..MapOptions::default() }) {
            unmap_pages(root, base, &mut pages);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
    }
    Ok(pages)
}

/// Tira as PTEs da vista (se a raiz ainda existe) e devolve as cópias
/// privadas. Quem chama invalida os TLBs antes de soltar a control area.
pub fn unmap_pages(root: u64, base: u64, pages: &mut ViewPages) {
    if crate::ntos::mm::process_address_space::is_root(root) {
        for index in 0..pages.frames.len() {
            paging::unmap_page_in(root, base + index as u64 * PAGE, MapOptions::default());
        }
    } else {
        crate::debug_print!("[section-image] vista em {:#x}: a raiz {:#x} ja foi devolvida", base, root);
    }
    pages.release_private();
}

/// A cópia privada de uma página compartilhada da vista que vai ficar
/// gravável (o PAGE_WRITECOPY resolvido). `Ok(None)` = a página já é
/// privada.
pub fn write_copy(pages: &mut ViewPages, index: usize) -> Result<Option<u64>, u32> {
    let Some(&frame) = pages.frames.get(index) else { return Ok(None) };
    if pages.private[index] {
        return Ok(None);
    }
    let copy = private_copy(frame).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    pages.frames[index] = copy;
    pages.private[index] = true;
    Ok(Some(copy))
}

/// A tabela de exports da imagem, lida das páginas protótipo na base
/// `image_base` (a da vista).
pub fn exports(segment: &ImageSegment, image_base: u64) -> Result<Exports, KernelError> {
    let read_rva = |rva: u64, length: u64| -> Result<Vec<u8>, KernelError> {
        if rva.checked_add(length).is_none_or(|end| end > segment.size_of_image) {
            return Err(KernelError::new("PE: RVA fora da imagem"));
        }
        let mut bytes = Vec::with_capacity(length as usize);
        let mut at = rva;
        while at < rva + length {
            let take = (PAGE - at % PAGE).min(rva + length - at);
            bytes.extend_from_slice(&physical::read_bytes(segment.frames[(at / PAGE) as usize] + at % PAGE, take as usize));
            at += take;
        }
        Ok(bytes)
    };
    let header = u32::from_le_bytes(read_rva(0x3C, 4)?.try_into().unwrap_or([0; 4])) as u64;
    let directory = read_rva(header + 24 + 112, 8)?;
    let (rva, size) = (u32::from_le_bytes([directory[0], directory[1], directory[2], directory[3]]) as u64, u32::from_le_bytes([directory[4], directory[5], directory[6], directory[7]]) as u64);
    pe_exports::read_exports(&read_rva, image_base, segment.size_of_image, rva, size)
}
