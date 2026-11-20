//! Arquivos de paginação: o MmPagingFile[] da partição do sistema do
//! ntoskrnl 19041 (MI_VISIBLE_PARTITION.PagingFile e NumberOfPagingFiles,
//! até 16), cada um descrito por um MMPAGING_FILE no pool.
//!
//! - MiCreatePagefile (rva 0x7b7930): Size e MinimumSize = o mínimo pedido,
//!   MaximumSize = o máximo, FreeSpace = FreeReservationSpace = Size - 2,
//!   File, FileHandle, PageFileName e o bitmap de espaço do tamanho máximo:
//!   todos os bits ligados (ocupados) e livres só os de 2 a Size - 1, então
//!   as duas primeiras páginas nunca guardam página nenhuma (um PTE de
//!   arquivo de paginação tem sempre PageFileHigh diferente de zero).
//! - MiInsertPageFileInList (rva 0x7b76b0): no máximo 16 arquivos na
//!   partição do sistema (STATUS_TOO_MANY_PAGING_FILES); PageFileNumber é a
//!   posição na lista; o commit do sistema ganha Size no limite e
//!   MaximumSize no limite máximo, com as duas páginas reservadas cobradas
//!   (MiIncreaseCommitLimits); o primeiro arquivo cria a thread do
//!   MiModifiedPageWriter (`mm/modified_writer`).
//! - MiFindFreePageFileSpace/MiReleasePageFileSpace: o espaço sai do bitmap
//!   em faixas contíguas (o MiFindPageFileWriteCluster junta até 16 páginas
//!   numa escrita) e volta a ele quando a cópia deixa de valer; FreeSpace,
//!   PeakUsage e HighestPage do MMPAGING_FILE acompanham.
//! - E/S de paginação: a leitura é o IoPageRead e a escrita o
//!   IoSynchronousPageWrite do FILE_OBJECT do arquivo (IRP_MJ_READ/WRITE com
//!   IRP_PAGING_IO | IRP_NOCACHE | IRP_SYNCHRONOUS_PAGING_IO, `mm/page_io`),
//!   com um MDL que descreve os frames, enviados ao file system dono do
//!   volume pelo IoGetRelatedDeviceObject.
//! - MmGetPageFileInformation (rva 0x6a1644): a SystemPageFileInformation
//!   (`page_file_information`).
//! - Extensão até o MaximumSize (`extend`): o MiFinishPageFileExtension
//!   (rva 0x543530) libera no bitmap as páginas novas, soma-as a Size,
//!   FreeSpace e FreeReservationSpace e, se o modified page writer esperava
//!   espaço no arquivo (AdriftMdls, ligado pelo MiPageFileNoFreeSpace), o
//!   acorda (RescanPageFilesEvent); o MiUpdatePagingFileMinimum (rva
//!   0x543e7c) soma a extensão ao MinimumSize.
//!
//! Diferenças declaradas: o NT reserva espaço por VAD
//! (FreeReservationSpace, MiReservePageFileSpace) e mantém hashes das
//! páginas gravadas; o OpenNT só aloca espaço na escrita, e o
//! FreeReservationSpace acompanha o FreeSpace. O AdriftMdls volta a zero
//! quando a extensão acorda o writer (no NT, quando o writer revarre os
//! arquivos).

pub mod create;
pub mod extend;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::MmpagingFile;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map as map;
use crate::rtl::SpinLock;

/// Arquivos de paginação da partição do sistema.
pub const MAXIMUM_PAGING_FILES: usize = 16;
/// Páginas do começo de todo arquivo que nunca guardam página.
pub const RESERVED_PAGES: u64 = 2;
/// Páginas de uma escrita do modified page writer (MM_MAXIMUM_WRITE_CLUSTER).
pub const MAXIMUM_WRITE_CLUSTER: usize = 16;
pub const STATUS_TOO_MANY_PAGING_FILES: u32 = 0xC000_0097;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const PAGE: u64 = map::PAGE_SIZE;

/// Onde mora a cópia de uma página: o arquivo (PageFileLow) e a página
/// dentro dele (PageFileHigh).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub file: u32,
    pub offset: u64,
}

/// Um arquivo de paginação da lista.
struct PagingFile {
    /// O MMPAGING_FILE no pool.
    descriptor: u64,
    file_object: u64,
    name: String,
    size: u64,
    minimum: u64,
    maximum: u64,
    free: u64,
    peak: u64,
    highest: u64,
    /// Bit ligado = página ocupada; tem MaximumSize bits.
    bitmap: Vec<u64>,
    hint: u64,
    /// O arquivo de troca de working sets (Priority com o bit 31): fica fora
    /// do commit, da paginação comum e da SystemPageFileInformation.
    working_set_swap: bool,
    /// AdriftMdls: o modified page writer achou o arquivo cheio e espera a
    /// extensão.
    adrift: bool,
}

impl PagingFile {
    fn descriptor(&self) -> &'static MmpagingFile {
        // SAFETY: o MMPAGING_FILE alocado em `create` e vivo enquanto o
        // arquivo está na lista.
        unsafe { MmpagingFile::at(self.descriptor) }
    }

    fn used(&self, page: u64) -> bool {
        self.bitmap[(page / 64) as usize] & (1 << (page % 64)) != 0
    }

    fn set(&mut self, page: u64, used: bool) {
        let word = &mut self.bitmap[(page / 64) as usize];
        if used {
            *word |= 1 << (page % 64);
        } else {
            *word &= !(1 << (page % 64));
        }
    }

    /// Espelha os contadores no MMPAGING_FILE.
    fn publish(&self) {
        let descriptor = self.descriptor();
        descriptor.size.set(self.size);
        descriptor.free_space.set(self.free);
        descriptor.free_reservation_space.set(self.free);
        descriptor.peak_usage.set(self.peak);
        descriptor.highest_page.set(self.highest);
    }

    /// MiFindFreePageFileSpace: a primeira faixa livre de até `wanted`
    /// páginas (pelo menos uma) a partir da dica, dando a volta uma vez.
    fn allocate(&mut self, wanted: u64) -> Option<(u64, u64)> {
        if self.free == 0 {
            return None;
        }
        let start = self.hint.clamp(RESERVED_PAGES, self.size);
        for (from, to) in [(start, self.size), (RESERVED_PAGES, start)] {
            let mut page = from;
            while page < to {
                if self.used(page) {
                    page += 1;
                    continue;
                }
                let mut count = 1;
                while count < wanted && page + count < to && !self.used(page + count) {
                    count += 1;
                }
                for index in page..page + count {
                    self.set(index, true);
                }
                self.free -= count;
                let in_use = self.size - RESERVED_PAGES - self.free;
                self.peak = self.peak.max(in_use);
                self.highest = self.highest.max(page + count - 1);
                self.hint = page + count;
                self.publish();
                return Some((page, count));
            }
        }
        None
    }

    /// MiReleasePageFileSpace.
    fn release(&mut self, page: u64) {
        if page < RESERVED_PAGES || page >= self.size || !self.used(page) {
            return;
        }
        self.set(page, false);
        self.free += 1;
        self.publish();
    }

    /// MiFinishPageFileExtension: as `pages` depois de Size entram livres;
    /// devolve o AdriftMdls de antes.
    fn finish_extension(&mut self, pages: u64) -> bool {
        let pages = pages.min(self.maximum - self.size);
        for page in self.size..self.size + pages {
            self.set(page, false);
        }
        self.size += pages;
        self.free += pages;
        let descriptor = self.descriptor();
        descriptor.refresh_allocation_cluster.set(descriptor.refresh_allocation_cluster.get().wrapping_add(1));
        self.publish();
        let adrift = core::mem::replace(&mut self.adrift, false);
        descriptor.set_adrift_mdls(0);
        adrift
    }
}

static FILES: SpinLock<Vec<PagingFile>> = SpinLock::new(Vec::new());
/// MI_VISIBLE_PARTITION.NumberOfPagingFiles.
static NUMBER_OF_PAGING_FILES: AtomicU32 = AtomicU32::new(0);

/// O que [`create::create_paging_file`] montou para a lista.
pub struct NewPagingFile {
    pub file_object: u64,
    pub handle: u64,
    pub name: String,
    pub minimum: u64,
    pub maximum: u64,
    /// Priority com o bit 31 (WsSwapPagefile).
    pub working_set_swap: bool,
}

/// MiCreatePagefile + MiInsertPageFileInList: o MMPAGING_FILE no pool, o
/// bitmap de espaço, a posição na lista e os limites do commit. Devolve o
/// número do arquivo ou o NTSTATUS da recusa.
pub fn insert(new: NewPagingFile) -> Result<u32, u32> {
    let descriptor_address = guest::alloc_bytes(MmpagingFile::SIZE);
    let units: Vec<u16> = new.name.encode_utf16().collect();
    let name_buffer = guest::alloc_bytes(units.len() as u64 * 2 + 2);
    if descriptor_address == 0 || name_buffer == 0 {
        for block in [descriptor_address, name_buffer] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(name_buffer, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    // SAFETY: bloco recém-alocado do tamanho do MMPAGING_FILE.
    let descriptor = unsafe { MmpagingFile::at(descriptor_address) };
    descriptor.size.set(new.minimum);
    descriptor.minimum_size.set(new.minimum);
    descriptor.maximum_size.set(new.maximum);
    descriptor.file.set(new.file_object);
    descriptor.file_handle.set(new.handle);
    descriptor.page_file_name.length.set(units.len() as u16 * 2);
    descriptor.page_file_name.maximum_length.set(units.len() as u16 * 2 + 2);
    descriptor.page_file_name.buffer.set(name_buffer);
    let mut bitmap = alloc::vec![u64::MAX; new.maximum.div_ceil(64) as usize];
    for page in RESERVED_PAGES..new.minimum {
        bitmap[(page / 64) as usize] &= !(1 << (page % 64));
    }
    let free = new.minimum - RESERVED_PAGES;
    let file = PagingFile { descriptor: descriptor_address, file_object: new.file_object, name: new.name, size: new.minimum, minimum: new.minimum, maximum: new.maximum, free, peak: 0, highest: 0, bitmap, hint: RESERVED_PAGES, working_set_swap: new.working_set_swap, adrift: false };
    file.publish();
    if file.working_set_swap {
        // WsSwapPagefile | NoReservations | SwapSupported (0x30 | 0x80).
        file.descriptor().set_ws_swap_pagefile(1);
        file.descriptor().set_no_reservations(1);
        file.descriptor().set_swap_supported(1);
    }
    let number = {
        let mut files = FILES.lock();
        // Um só arquivo de troca de working sets (MiNumberWsSwapPagefiles).
        if files.len() >= MAXIMUM_PAGING_FILES || (file.working_set_swap && files.iter().any(|existing| existing.working_set_swap)) {
            drop(files);
            guest::free_bytes(name_buffer);
            guest::free_bytes(descriptor_address);
            return Err(STATUS_TOO_MANY_PAGING_FILES);
        }
        // O arquivo de troca não entra no commit (MiInsertPageFileInList só
        // chama o MiIncreaseCommitLimits sem os flags 0x50).
        if !file.working_set_swap {
            if !super::commit::increase_limits(file.size, file.maximum) {
                drop(files);
                guest::free_bytes(name_buffer);
                guest::free_bytes(descriptor_address);
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            super::commit::charge_unchecked(RESERVED_PAGES);
        }
        let number = files.len() as u32;
        file.descriptor().set_page_file_number(number as u16);
        file.descriptor().set_node_inserted(1);
        files.push(file);
        NUMBER_OF_PAGING_FILES.store(files.len() as u32, Ordering::Release);
        number
    };
    super::modified_writer::start();
    extend::start();
    Ok(number)
}

/// O que a extensão consulta de um arquivo da lista
/// (MI_VISIBLE_PARTITION.PagingFile[número]).
#[derive(Clone, Copy, Debug)]
pub struct ExtensionView {
    pub number: u32,
    pub size: u64,
    pub maximum: u64,
    pub file_object: u64,
    /// Fica fora da extensão por commit (flags 0x50 do MMPAGING_FILE).
    pub working_set_swap: bool,
}

/// Os arquivos da lista, na ordem dela.
pub fn extension_views() -> Vec<ExtensionView> {
    FILES.lock().iter().enumerate().map(|(number, file)| ExtensionView { number: number as u32, size: file.size, maximum: file.maximum, file_object: file.file_object, working_set_swap: file.working_set_swap }).collect()
}

/// MiFinishPageFileExtension(Partition, PagingFile, Pages), depois que o
/// file system aceitou o novo fim do arquivo: devolve se o modified page
/// writer esperava espaço nele (AdriftMdls).
pub fn finish_extension(number: u32, pages: u64) -> bool {
    FILES.lock().get_mut(number as usize).is_some_and(|file| file.finish_extension(pages))
}

/// MiUpdatePagingFileMinimum(PagingFile, Pages).
pub fn update_minimum(number: u32, pages: u64) {
    if let Some(file) = FILES.lock().get_mut(number as usize) {
        file.minimum = (file.minimum + pages).min(file.maximum);
        file.descriptor().minimum_size.set(file.minimum);
    }
}

/// A parte do MiPageFileNoFreeSpace de cada arquivo comum: sem FreeSpace, o
/// arquivo fica com AdriftMdls. Devolve se algum ficou.
pub fn mark_full_files_adrift() -> bool {
    let mut marked = false;
    for file in FILES.lock().iter_mut().filter(|file| !file.working_set_swap && file.free == 0) {
        file.adrift = true;
        file.descriptor().set_adrift_mdls(1);
        marked = true;
    }
    marked
}

/// A soma do FreeSpace dos arquivos comuns.
pub fn free_pages() -> u64 {
    FILES.lock().iter().filter(|file| !file.working_set_swap).fold(0u64, |sum, file| sum.saturating_add(file.free))
}

/// MmNumberOfPagingFiles.
pub fn count() -> u32 {
    NUMBER_OF_PAGING_FILES.load(Ordering::Acquire)
}

/// Espaço para até `wanted` páginas contíguas num arquivo (o primeiro com
/// espaço); devolve o primeiro slot e quantas páginas couberam.
pub fn allocate(wanted: u64) -> Option<(Slot, u64)> {
    let mut files = FILES.lock();
    for (number, file) in files.iter_mut().enumerate().filter(|(_, file)| !file.working_set_swap) {
        if let Some((offset, count)) = file.allocate(wanted.max(1)) {
            return Some((Slot { file: number as u32, offset }, count));
        }
    }
    None
}

/// MiReleasePageFileSpace(Slot).
pub fn release(slot: Slot) {
    if let Some(file) = FILES.lock().get_mut(slot.file as usize) {
        file.release(slot.offset);
    }
}

/// O FILE_OBJECT do arquivo de paginação `number`.
fn file_object(number: u32) -> Option<u64> {
    FILES.lock().get(number as usize).map(|file| file.file_object)
}

/// Arquivos em criação: o NtCreatePagingFile já grava a primeira página
/// pela E/S de paginação antes de o arquivo entrar na lista.
static CREATING: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// Marca (ou desmarca) o FILE_OBJECT de um arquivo de paginação em criação.
pub fn mark_creating(file_object: u64, creating: bool) {
    let mut list = CREATING.lock();
    list.retain(|&candidate| candidate != file_object);
    if creating {
        list.push(file_object);
    }
}

/// O FILE_OBJECT é de um arquivo de paginação (MmIsFileObjectAPagingFile).
pub fn is_paging_file(file_object: u64) -> bool {
    file_object != 0 && (FILES.lock().iter().any(|file| file.file_object == file_object) || CREATING.lock().contains(&file_object))
}

/// O arquivo da lista com esse nome (sem diferença de maiúsculas):
/// (MinimumSize, MaximumSize, Size), em páginas.
pub fn find_by_name(name: &str) -> Option<(u64, u64, u64)> {
    FILES.lock().iter().find(|file| file.name.eq_ignore_ascii_case(name)).map(|file| (file.minimum, file.maximum, file.size))
}

/// Uma entrada da SystemPageFileInformation.
#[derive(Clone, Debug)]
pub struct Information {
    pub total_size: u64,
    pub total_in_use: u64,
    pub peak_usage: u64,
    pub minimum: u64,
    pub maximum: u64,
    pub name: String,
}

/// Os arquivos da lista, na ordem dela, sem o de troca de working sets
/// (o MmGetPageFileInformation pula os flags 0x50).
pub fn information() -> Vec<Information> {
    FILES
        .lock()
        .iter()
        .filter(|file| !file.working_set_swap)
        .map(|file| Information { total_size: file.size, total_in_use: file.size - file.free - RESERVED_PAGES, peak_usage: file.peak, minimum: file.minimum, maximum: file.maximum, name: file.name.clone() })
        .collect()
}

/// Um IRP de paginação síncrono ao arquivo `number` em `offset` (páginas),
/// com os frames: IoPageRead (`read`) ou IoSynchronousPageWrite
/// (`mm/page_io`). Devolve o NTSTATUS final.
fn page_io(number: u32, offset: u64, frames: &[u64], read: bool) -> u32 {
    let Some(file) = file_object(number) else { return 0xC000_0008 };
    file_page_io(file, offset, frames, read)
}

/// [`page_io`] sobre o FILE_OBJECT.
fn file_page_io(file: u64, offset: u64, frames: &[u64], read: bool) -> u32 {
    crate::ntos::mm::page_io::transfer(file, offset * PAGE, frames, read).0
}

/// Grava os frames nas páginas `slot.offset..` do arquivo (a escrita do
/// modified page writer).
pub fn write(slot: Slot, frames: &[u64]) -> u32 {
    page_io(slot.file, slot.offset, frames, false)
}

/// Grava os frames em `offset` (páginas) de um arquivo de paginação ainda
/// fora da lista (a primeira página no NtCreatePagingFile).
pub fn write_file_object(file: u64, offset: u64, frames: &[u64]) -> u32 {
    file_page_io(file, offset, frames, false)
}

/// Lê a página do slot no frame (a leitura da falta de página).
pub fn read(slot: Slot, frame: u64) -> u32 {
    page_io(slot.file, slot.offset, &[frame], true)
}
