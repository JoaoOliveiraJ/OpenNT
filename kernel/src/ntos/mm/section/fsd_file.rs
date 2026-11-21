//! Arquivos servidos por um file system (o ntfs.sys real, um filtro sobre
//! ele) como backing de seção: o arquivo de uma seção de dados ou de imagem
//! que não é do volume do próprio kernel.
//!
//! Como no 19041:
//! - a control area é a do stream, achada pelos SECTION_OBJECT_POINTERS do
//!   FCB (`FileObject->SectionObjectPointer`): todos os FILE_OBJECTs do
//!   mesmo stream, de qualquer handle, e o stream file do Cache Manager
//!   usam a mesma ([`identity`]);
//! - a criação da seção roda com o arquivo adquirido para sincronização de
//!   seção (MiCallCreateSectionFilters -> FsRtlAcquireToCreateMappedSection,
//!   SyncTypeCreateSection com a proteção pedida, pelos FS_FILTER_CALLBACKS
//!   do file system e dos filtros: `fsrtl/fs_filter`), e o tamanho vem do
//!   FsRtlGetFileSize;
//! - os bytes vêm por IoPageRead e voltam por IoSynchronousPageWrite, com
//!   um MDL dos frames (`mm/page_io`), nunca pelo cache: a página que o Cc e
//!   o Mm compartilham é o frame da control area;
//! - antes de ler a imagem, o MiCreateImageFileMap (0x700be4) chama o
//!   MiFlushDataSection (0x35a4b0), que grava as páginas modificadas da
//!   seção de dados do arquivo (MmFlushSection): aqui, as páginas sujas do
//!   cache (CcFlushCache) e as das vistas de dados ([`flush_data_section`]).
//!
//! Uma leitura vai em grupos de até 16 páginas por IRP (o cluster de
//! leitura do Mm); as páginas são zeradas antes, e o fim do arquivo
//! (STATUS_END_OF_FILE, uma leitura curta) deixa o resto em zero, como a
//! página protótipo além do fim do arquivo no NT. Uma escrita de página
//! inteira pode passar do fim do arquivo: o file system corta a escrita de
//! paginação no FileSize.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hal::physical;
use crate::ntos::cc;
use crate::ntos::fsrtl::fs_filter::{self, SectionSync};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_fsrtl::FsrtlCommonFcbHeader;
use crate::ntos::inc::types::{FileObject, FsFilterSectionSyncType, LargeInteger};
use crate::ntos::io::file::information;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{page_io, pfn};
use crate::rtl::KernelError;

const PAGE: u64 = 0x1000;
/// Páginas por IRP de paginação.
const CLUSTER: usize = 16;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

fn file_object(file: u64) -> &'static FileObject {
    // SAFETY: FILE_OBJECT vivo, retido pela seção ou por quem a cria.
    unsafe { FileObject::at(file) }
}

/// `FileObject->SectionObjectPointer` de um arquivo servido por um file
/// system (0 para um dispositivo sem file system, ou para um arquivo do
/// volume do kernel, que não manda IRPs a uma pilha).
pub fn section_pointers(file: u64) -> u64 {
    if !information::related_device(file).is_ok_and(|device| device != 0) {
        return 0;
    }
    file_object(file).section_object_pointer.get()
}

/// A chave da control area do stream: os SECTION_OBJECT_POINTERS do FCB.
pub fn identity(pointers: u64) -> String {
    format!("sop:{pointers:x}")
}

/// FsRtlGetFileSize: o EndOfFile do stream; diretório e falhas do file
/// system voltam como o status.
pub fn file_size(file: u64) -> Result<u64, u32> {
    let cell = guest::alloc_bytes(LargeInteger::SIZE);
    if cell == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let status = information::get_size(file, cell).unwrap_or(0xC000_0001);
    // SAFETY: LARGE_INTEGER recém-alocado.
    let size = unsafe { LargeInteger::at(cell) }.quad_part.get() as u64;
    guest::free_bytes(cell);
    if status & 0x8000_0000 != 0 {
        return Err(status);
    }
    Ok(size)
}

/// O FileSize do cabeçalho comum do FCB (FsContext), sem IRP: o limite das
/// escritas de paginação do writer de páginas mapeadas. None sem FsContext.
pub fn header_file_size(file: u64) -> Option<u64> {
    let context = file_object(file).fs_context.get();
    if context == 0 {
        return None;
    }
    // SAFETY: o FsContext de um arquivo de file system começa pelo cabeçalho comum do FCB.
    Some(unsafe { FsrtlCommonFcbHeader::at(context) }.file_size.quad_part.get() as u64)
}

/// FsRtlSetFileSize: o arquivo cresce até o tamanho máximo pedido pela
/// seção de dados (o MiCreateDataFileMap). Devolve o NTSTATUS.
pub fn set_file_size(file: u64, size: u64) -> u32 {
    information::set_size(file, size).unwrap_or(0xC000_0001)
}

/// FSRTL_COMMON_FCB_HEADER.Flags: FSRTL_FLAG_USER_MAPPED_FILE.
pub const FSRTL_FLAG_USER_MAPPED_FILE: u8 = 0x20;

/// O CcZeroEndOfLastPage (0x2d78ac) que o MiCreateSectionCommon chama em
/// toda seção de dados de usuário: liga FSRTL_FLAG_USER_MAPPED_FILE no
/// cabeçalho do FCB (`or byte [FsContext+4], 0x20`, com o arquivo adquirido).
/// A página parcial do fim não precisa ir ao disco nem sair do cache: o
/// cache e a seção usam o mesmo frame.
pub fn mark_user_mapped(file: u64) {
    let context = file_object(file).fs_context.get();
    if context == 0 {
        return;
    }
    // SAFETY: o FsContext de um arquivo de file system começa pelo cabeçalho comum do FCB.
    let header = unsafe { FsrtlCommonFcbHeader::at(context) };
    header.flags.atomic().fetch_or(FSRTL_FLAG_USER_MAPPED_FILE, core::sync::atomic::Ordering::SeqCst);
}

/// O nome NT do arquivo (o IopQueryName: o dispositivo do volume e o nome
/// que o file system dá ao stream).
pub fn name(file: u64) -> Option<String> {
    match information::query_object_name(file) {
        Ok(Ok(units)) => Some(String::from_utf16_lossy(&units)),
        _ => None,
    }
}

/// O arquivo adquirido para a criação de uma seção; o `Drop` faz o
/// FsRtlReleaseFile.
pub struct CreateSectionLock {
    file: u64,
    /// O status da aquisição (0, ou o informativo do file system).
    pub status: u32,
}

impl Drop for CreateSectionLock {
    fn drop(&mut self) {
        let _ = fs_filter::release_file(self.file);
    }
}

/// FsRtlAcquireToCreateMappedSection(FileObject, SectionPageProtection):
/// FsRtlAcquireFileExclusiveCommon com SyncTypeCreateSection. Um status de
/// sucesso informativo também deixa o arquivo adquirido: o callback do
/// ntfs.sys devolve STATUS_FILE_LOCKED_WITH_ONLY_READERS (0x12A) ou
/// STATUS_FILE_LOCKED_WITH_WRITERS (0x12B), que vão no lock.
pub fn acquire_for_create_section(file: u64, page_protection: u32) -> Result<CreateSectionLock, u32> {
    let parameters = SectionSync { sync_type: FsFilterSectionSyncType::SYNC_TYPE_CREATE_SECTION.0 as u32, page_protection, flags: 0, output_information: 0 };
    match fs_filter::acquire_file_exclusive_common(file, &parameters) {
        Ok(status) if status & 0x8000_0000 == 0 => Ok(CreateSectionLock { file, status }),
        Ok(status) => Err(status),
        Err(error) => Err(if error.status != 0 { error.status } else { 0xC000_0001 }),
    }
}

/// O MiFlushDataSection: grava as páginas sujas do cache do stream
/// (CcFlushCache do arquivo inteiro) e as que as vistas da seção de dados
/// alteraram, antes de a imagem ser lida do disco.
pub fn flush_data_section(file: u64) {
    let pointers = file_object(file).section_object_pointer.get();
    if pointers == 0 {
        return;
    }
    if let Err(error) = cc::flush::flush_cache(pointers, 0, 0, 0) {
        debug_print!("[section] CcFlushCache antes da imagem: {:?}", error);
    }
    if let Err(error) = crate::ntos::ps::user::sections::flush_identity(&identity(pointers)) {
        debug_print!("[section] flush da secao de dados antes da imagem: {}", error.message);
    }
}

/// IoPageRead dos `frames` a partir da página `first_page` do arquivo de
/// `size` bytes: os frames são zerados antes, e páginas além do fim do
/// arquivo não vão ao disco.
pub fn read_frames(file: u64, size: u64, first_page: u64, frames: &[u64]) -> Result<(), KernelError> {
    for &frame in frames {
        physical::zero(frame, PAGE as usize);
    }
    let last = size.div_ceil(PAGE);
    let wanted = (last.saturating_sub(first_page) as usize).min(frames.len());
    let mut done = 0usize;
    while done < wanted {
        let count = (wanted - done).min(CLUSTER);
        let (status, _) = page_io::transfer(file, (first_page + done as u64) * PAGE, &frames[done..done + count], true);
        if status & 0x8000_0000 != 0 && status != STATUS_END_OF_FILE {
            return Err(KernelError::with_status(format!("IoPageRead da pagina {:#x}: {status:#x}", first_page + done as u64), status));
        }
        done += count;
    }
    Ok(())
}

/// IoSynchronousPageWrite dos `frames` na página `first_page` do arquivo.
pub fn write_frames(file: u64, first_page: u64, frames: &[u64]) -> Result<(), KernelError> {
    let mut done = 0usize;
    while done < frames.len() {
        let count = (frames.len() - done).min(CLUSTER);
        let (status, _) = page_io::transfer(file, (first_page + done as u64) * PAGE, &frames[done..done + count], false);
        if status & 0x8000_0000 != 0 {
            return Err(KernelError::with_status(format!("IoSynchronousPageWrite da pagina {:#x}: {status:#x}", first_page + done as u64), status));
        }
        done += count;
    }
    Ok(())
}

/// Frames emprestados do PFN para uma leitura intermediária.
struct Bounce {
    frames: Vec<u64>,
}

impl Bounce {
    fn new(count: usize) -> Result<Self, KernelError> {
        let mut bounce = Self { frames: Vec::with_capacity(count) };
        for _ in 0..count {
            let frame = pfn::alloc_page();
            if frame == 0 {
                return Err(KernelError::with_status("sem frames para a leitura da secao", STATUS_INSUFFICIENT_RESOURCES));
            }
            bounce.frames.push(frame);
        }
        Ok(bounce)
    }
}

impl Drop for Bounce {
    fn drop(&mut self) {
        for &frame in &self.frames {
            pfn::free_page(frame);
        }
    }
}

/// Os bytes [offset, offset + length) do arquivo, lidos por páginas inteiras
/// em frames intermediários e entregues a `sink(posição, bytes)`.
fn read_through_bounce(file: u64, size: u64, offset: u64, length: u64, mut sink: impl FnMut(u64, &[u8])) -> Result<(), KernelError> {
    let end = offset.checked_add(length).ok_or_else(|| KernelError::with_status("faixa da secao estoura", STATUS_IN_PAGE_ERROR))?;
    let mut page = offset / PAGE;
    while page * PAGE < end {
        let count = (end.div_ceil(PAGE) - page).min(CLUSTER as u64) as usize;
        let bounce = Bounce::new(count)?;
        read_frames(file, size, page, &bounce.frames)?;
        for (index, &frame) in bounce.frames.iter().enumerate() {
            let page_start = (page + index as u64) * PAGE;
            let (low, high) = (offset.max(page_start), end.min(page_start + PAGE));
            if low < high {
                sink(low - offset, &physical::read_bytes(frame + (low - page_start), (high - low) as usize));
            }
        }
        page += count as u64;
    }
    Ok(())
}

/// [offset, offset + length) do arquivo num buffer (o cabeçalho da imagem,
/// um trecho pequeno).
pub fn read_at(file: u64, size: u64, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
    let length = length.min(size.saturating_sub(offset));
    let mut data = alloc::vec![0u8; length as usize];
    read_through_bounce(file, size, offset, length, |at, bytes| data[at as usize..at as usize + bytes.len()].copy_from_slice(bytes))?;
    Ok(data)
}

/// [offset, offset + length) do arquivo na memória física contínua em
/// `address`: páginas inteiras alinhadas vão direto aos frames de destino;
/// as pontas, por frames intermediários (uma página lida inteira poria no
/// destino bytes do arquivo além do trecho pedido).
pub fn copy_to_physical(file: u64, size: u64, offset: u64, address: u64, length: u64) -> Result<(), KernelError> {
    let mut done = 0u64;
    if offset % PAGE == 0 && address % PAGE == 0 {
        let whole = length / PAGE;
        let mut page = 0u64;
        while page < whole {
            let count = (whole - page).min(CLUSTER as u64);
            let frames: Vec<u64> = (0..count).map(|index| address + (page + index) * PAGE).collect();
            read_frames(file, size, offset / PAGE + page, &frames)?;
            page += count;
        }
        done = whole * PAGE;
    }
    if done < length {
        read_through_bounce(file, size, offset + done, length - done, |at, bytes| physical::write_bytes(address + done + at, bytes))?;
    }
    Ok(())
}

/// Escrita de bytes soltos: as páginas que os cobrem são lidas, alteradas e
/// gravadas inteiras pela escrita de paginação.
pub fn write_at(file: u64, size: u64, offset: u64, data: &[u8]) -> Result<(), KernelError> {
    let end = offset + data.len() as u64;
    let first = offset / PAGE;
    let count = (end.div_ceil(PAGE) - first) as usize;
    let mut page = 0usize;
    while page < count {
        let take = (count - page).min(CLUSTER);
        let bounce = Bounce::new(take)?;
        read_frames(file, size, first + page as u64, &bounce.frames)?;
        for (index, &frame) in bounce.frames.iter().enumerate() {
            let page_start = (first + (page + index) as u64) * PAGE;
            let (low, high) = (offset.max(page_start), end.min(page_start + PAGE));
            if low < high {
                physical::write_bytes(frame + (low - page_start), &data[(low - offset) as usize..(high - offset) as usize]);
            }
        }
        write_frames(file, first + page as u64, &bounce.frames)?;
        page += take;
    }
    Ok(())
}
