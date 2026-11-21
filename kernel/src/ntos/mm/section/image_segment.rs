//! A control area de uma seção de imagem (SEC_IMAGE).
//!
//! Como o MiCreateImageFileMap do NT, a imagem é montada uma vez por arquivo
//! nas páginas protótipo da control area: frames do PFN com os cabeçalhos e
//! as seções do PE no layout virtual, zerados no resto, sem relocação, sem
//! imports e sem cookie de segurança (a ntdll de cada processo faz isso na
//! própria vista). Todas as seções do mesmo arquivo usam a mesma control
//! area, como o ImageSectionObject dos SECTION_OBJECT_POINTERS: a chave é o
//! arquivo do volume pelo registro do MFT (`SectionFile::file_id`, igual em
//! toda abertura, também nas do modo usuário, que têm cada uma o seu
//! FILE_OBJECT), senão a identidade do arquivo (`SectionFile::identity`) e,
//! sem ela, o próprio objeto seção. A seção retém a control area enquanto
//! existe, e cada vista também; a de um arquivo segue, sem uso, na lista
//! das control areas sem uso (a MmUnusedSegmentList, [`RETAINED`]) até a
//! pressão de memória ou o limite dela devolverem os frames ao PFN, ou até o
//! arquivo mudar. A imagem plana (SectionAlignment menor que a página,
//! `image_header`) é o arquivo inteiro a partir do offset zero, com todas
//! as páginas graváveis por cópia.
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
    /// A carga protótipo (solta no `Drop`).
    image: SpinLock<Option<PeImage>>,
    /// Um frame do PFN por página da imagem, desta control area (a carga os
    /// entrega a ela e o `Drop` os devolve ao PFN).
    pub frames: Vec<u64>,
    /// PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE ou as variantes EXECUTE.
    pub protections: Vec<u32>,
    /// A ImageBase do cabeçalho (a das páginas protótipo).
    pub preferred_base: u64,
    pub size_of_image: u64,
    /// A versão do arquivo quando as páginas foram lidas
    /// (`SectionFile::version`); sem ela a control area não fica na lista
    /// das sem uso.
    version: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SegmentKey {
    File(String),
    Section(u64),
}

/// As control areas vivas, para que uma nova seção do mesmo arquivo use a
/// mesma (a seção e as vistas guardam as referências fortes).
static SEGMENTS: SpinLock<BTreeMap<SegmentKey, Weak<ImageSegment>>> = SpinLock::new(BTreeMap::new());

/// As control areas de arquivo retidas, da usada há mais tempo à mais
/// recente: a MmUnusedSegmentList do 19041. O MiCheckControlArea põe nela a
/// control area de imagem que perdeu a última seção e a última vista, com as
/// páginas protótipo (em standby) ainda válidas, e o MiDeleteUnusedSegments
/// só as devolve sob pressão de memória. Assim um processo novo que mapeia a
/// kernelbase, ou o LoadLibrary do WARP depois do FreeLibrary, não lê o
/// arquivo de novo. Uma control area daqui sem outra referência é a sem uso;
/// as sem uso passam de [`unused_budget`] ou voltam ao PFN pela recuperação
/// de memória (`page_residency`), a mais antiga primeiro.
static RETAINED: SpinLock<alloc::collections::VecDeque<Arc<ImageSegment>>> = SpinLock::new(alloc::collections::VecDeque::new());
static RECLAIM_REGISTERED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// As páginas protótipo que as control areas sem uso podem reter: um oitavo
/// da memória física, até 128 MB.
fn unused_budget() -> u64 {
    (pfn::total_count() / 8).min(128 * 1024 * 1024 / PAGE)
}

/// Só a lista retém a control area (o próprio chamador conta `extra`).
fn unused(segment: &Arc<ImageSegment>, extra: usize) -> bool {
    Arc::strong_count(segment) <= 1 + extra
}

/// Tira da lista as sem uso mais antigas até as restantes caberem em
/// `budget` páginas; devolve as tiradas, para o `Drop` rodar fora da trava.
fn trim(retained: &mut alloc::collections::VecDeque<Arc<ImageSegment>>, budget: u64) -> Vec<Arc<ImageSegment>> {
    let mut held: u64 = retained.iter().filter(|segment| unused(segment, 0)).map(|segment| segment.frames.len() as u64).sum();
    let mut evicted = Vec::new();
    let mut index = 0;
    while held > budget && index < retained.len() {
        if unused(&retained[index], 0) {
            if let Some(segment) = retained.remove(index) {
                held -= segment.frames.len() as u64;
                evicted.push(segment);
            }
        } else {
            index += 1;
        }
    }
    evicted
}

/// Põe a control area no fim da lista (a mais recente).
fn retain(segment: &Arc<ImageSegment>) {
    if segment.version.is_none() || !matches!(segment.key, SegmentKey::File(_)) {
        return;
    }
    if !RECLAIM_REGISTERED.swap(true, core::sync::atomic::Ordering::AcqRel) {
        let provider = crate::ntos::mm::page_residency::Provider {
            fault: |_, _| crate::ntos::mm::page_residency::FaultResult::NotMine,
            resolve: |_| Ok(None),
            reclaim: reclaim_unused,
            prepare: || Ok(()),
            resolve_range: Some((0, 0)),
        };
        if let Err(error) = crate::ntos::mm::page_residency::register("unused image segments", provider) {
            crate::debug_print!("[section-image] {}", error);
        }
    }
    let evicted = {
        let mut retained = RETAINED.lock();
        if let Some(position) = retained.iter().position(|existing| Arc::ptr_eq(existing, segment)) {
            retained.remove(position);
        }
        retained.push_back(segment.clone());
        trim(&mut retained, unused_budget())
    };
    drop(evicted);
}

/// Tira da lista uma control area retida (o arquivo mudou).
fn forget(segment: &Arc<ImageSegment>) {
    let removed = {
        let mut retained = RETAINED.lock();
        retained.iter().position(|existing| Arc::ptr_eq(existing, segment)).and_then(|position| retained.remove(position))
    };
    drop(removed);
}

/// A recuperação de memória: devolve ao PFN as control areas sem uso mais
/// antigas até liberar `count` frames (o MiDeleteUnusedSegments). Com a
/// lista em uso (a recuperação nasceu de uma alocação dentro dela), nada.
fn reclaim_unused(count: u64) -> Result<u64, KernelError> {
    let before = pfn::free_count();
    let evicted = {
        let Some(mut retained) = RETAINED.try_lock() else { return Ok(0) };
        let mut freed = 0;
        let mut evicted = Vec::new();
        let mut index = 0;
        while freed < count && index < retained.len() {
            if unused(&retained[index], 0) {
                if let Some(segment) = retained.remove(index) {
                    freed += segment.frames.len() as u64;
                    evicted.push(segment);
                }
            } else {
                index += 1;
            }
        }
        evicted
    };
    drop(evicted);
    Ok(pfn::free_count().saturating_sub(before))
}

/// Devolve ao PFN todas as control areas sem uso (o que a pressão de
/// memória faria aos poucos). Devolve quantas páginas soltou.
pub fn flush_unused() -> u64 {
    let evicted = trim(&mut RETAINED.lock(), 0);
    let pages = evicted.iter().map(|segment| segment.frames.len() as u64).sum();
    drop(evicted);
    pages
}

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
        for &frame in &self.frames {
            pfn::free_page(frame);
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

/// A chave da control area de um arquivo: o arquivo do volume pelo
/// registro do MFT e a sequência (`SectionFile::file_id`), a mesma em toda
/// abertura, pelo ZwCreateFile ou pelo modo usuário, como o
/// SECTION_OBJECT_POINTERS do FCB no NT; sem ele, a identidade do arquivo.
/// As páginas protótipo de uma seção SEC_IMAGE_NO_EXECUTE (a carga só de
/// recursos) saem todas PAGE_READONLY, sem as cópias graváveis do .data:
/// elas formam outra control area do mesmo arquivo.
fn file_key(file: &dyn SectionFile, no_execute: bool) -> Option<SegmentKey> {
    let key = file.file_id().or_else(|| file.identity())?;
    Some(SegmentKey::File(if no_execute { alloc::format!("{key}:noexecute") } else { key }))
}

fn key_of(section: &Section) -> SegmentKey {
    section.file.as_deref().and_then(|file| file_key(file, section.no_execute)).unwrap_or(SegmentKey::Section(section.pointer()))
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
    // Uma control area sem uso cujo arquivo mudou desde a leitura não serve
    // mais (no NT, a abertura do arquivo para escrita a apaga pelo
    // MmFlushImageSection): sai da lista e outra é montada.
    let existing = match existing {
        Some(segment) if unused(&segment, 1) && segment.version.is_some() && segment.version != file.version() => {
            forget(&segment);
            None
        }
        other => other,
    };
    let segment = match existing {
        Some(segment) => {
            retain(&segment);
            segment
        }
        None => {
            let version = file.version();
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
            // Os frames e as proteções passam para a control area, que
            // devolve os frames ao PFN no fim.
            let (frames, protections) = (core::mem::take(&mut image.pages), core::mem::take(&mut image.page_protects));
            let created = Arc::new(ImageSegment { key: key.clone(), frames, protections, preferred_base: image.preferred_base, size_of_image: image.size_of_image, image: SpinLock::new(Some(image)), version });
            // Outra seção do mesmo arquivo pode ter montado a dela enquanto
            // esta lia o arquivo: fica a primeira, e esta volta ao PFN.
            let mut segments = SEGMENTS.lock();
            let segment = match segments.get(&key).and_then(Weak::upgrade) {
                Some(winner) => {
                    drop(segments);
                    drop(created);
                    winner
                }
                None => {
                    segments.insert(key, Arc::downgrade(&created));
                    drop(segments);
                    created
                }
            };
            retain(&segment);
            segment
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
    let frame = pfn::alloc_page_for(pfn::FrameUse::ImageCopy);
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

/// NtAreMappedFilesTheSame(File1MappedAsAnImage, File2MappedAsFile) no
/// processo corrente (ntoskrnl 19041, 0x6a0330):
/// - um endereço sem alocação (sem VAD) é STATUS_INVALID_ADDRESS;
/// - os dois na mesma alocação, STATUS_SUCCESS;
/// - memória privada ou uma vista sem arquivo (de pagefile),
///   STATUS_CONFLICTING_ADDRESSES;
/// - senão STATUS_SUCCESS só quando a control area da primeira vista é a de
///   imagem do arquivo da segunda (o ImageSectionObject dos
///   SECTION_OBJECT_POINTERS dele), e STATUS_NOT_SAME_DEVICE nos outros
///   casos.
///
/// As duas vistas podem ser de dados ou de imagem (o VAD de cada endereço):
/// o LdrpFindLoadedDllByMappingLockHeld da ntdll (0x145b8) passa a base de
/// uma DLL já carregada e a da imagem que acabou de mapear, e com
/// STATUS_SUCCESS usa o módulo que já existe em vez de carregar uma segunda
/// cópia do mesmo arquivo aberto por outro caminho. A control area de uma
/// vista de imagem é a da imagem do arquivo; a de uma vista de dados não é
/// a de imagem de arquivo nenhum. No NT o arquivo tem uma só control area
/// de imagem; aqui cada abertura de modo usuário pode montar a dela, então
/// a imagem também é a do arquivo da segunda vista quando os dois são o
/// mesmo arquivo do volume (`SectionFile::file_id`).
///
/// O EXE e a ntdll que a criação do processo mapeia não são vistas de seção
/// no OpenNT: um endereço neles dá STATUS_CONFLICTING_ADDRESSES.
pub fn are_mapped_files_the_same(image_address: u64, file_address: u64) -> u32 {
    use crate::ntos::mm::section::views::{self, OwnedView};
    use core::sync::atomic::Ordering;
    const STATUS_INVALID_ADDRESS: u32 = 0xC000_0141;
    const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
    const STATUS_NOT_SAME_DEVICE: u32 = 0xC000_00D4;
    const MEM_FREE: u32 = 0x1_0000;
    let highest = crate::ntos::mm::memory_map::HIGHEST_USER_ADDRESS;
    if image_address > highest || file_address > highest {
        return STATUS_INVALID_ADDRESS;
    }
    let process = crate::ntos::ps::process::get_current_process();
    let (first, second) = (crate::ntos::mm::query_virtual::describe_address(process, image_address), crate::ntos::mm::query_virtual::describe_address(process, file_address));
    if first.state == MEM_FREE || second.state == MEM_FREE {
        return STATUS_INVALID_ADDRESS;
    }
    if first.allocation_base == second.allocation_base {
        return 0;
    }
    // A vista viva do processo no endereço, com a seção dela e, numa vista
    // de imagem, a control area da imagem.
    let view_at = |address: u64| match views::find(process, address)? {
        OwnedView::Data(view) if !view.retiring() => Some((view.section.clone(), None)),
        OwnedView::Image(view) if !view.unmapped.load(Ordering::Acquire) => Some((view.section.clone()?, Some(view.segment.clone()))),
        _ => None,
    };
    let (Some((image_section, image_segment)), Some((file_section, file_view_segment))) = (view_at(image_address), view_at(file_address)) else { return STATUS_CONFLICTING_ADDRESSES };
    let (Some(image_file), Some(file)) = (image_section.file.as_ref(), file_section.file.as_ref()) else { return STATUS_CONFLICTING_ADDRESSES };
    let file_segment = match file_key(file.as_ref(), image_section.no_execute) {
        Some(key) => SEGMENTS.lock().get(&key).and_then(Weak::upgrade),
        None => file_view_segment.or_else(|| file_section.state.lock().image_segment.clone()),
    };
    let same_file = image_file.file_id().is_some_and(|id| file.file_id().as_ref() == Some(&id));
    match (image_segment, file_segment) {
        (Some(first), Some(second)) if Arc::ptr_eq(&first, &second) => 0,
        (Some(_), _) if same_file => 0,
        _ => STATUS_NOT_SAME_DEVICE,
    }
}
