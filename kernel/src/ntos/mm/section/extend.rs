//! NtExtendSection e MmExtendSection (ntoskrnl 19041 0x669290 e 0x66933c):
//! uma seção de dados de arquivo cresce com o arquivo.
//!
//! O NtExtendSection de modo usuário sonda o LARGE_INTEGER NewSectionSize
//! (alinhado a 4, gravável), referencia a seção com SECTION_EXTEND_SIZE e
//! grava de volta em NewSectionSize o tamanho que o MmExtendSection deixar,
//! qualquer que seja o status (uma exceção nessa escrita não muda o status).
//!
//! O MmExtendSection: seção de imagem, de \Device\PhysicalMemory ou sem
//! arquivo é STATUS_SECTION_NOT_EXTENDED; um tamanho acima de
//! 0x3FFFFFFFFFF000 é STATUS_SECTION_TOO_BIG. Um tamanho que não passa do
//! SizeOfSection não muda nada e volta como o SizeOfSection. Acima do
//! arquivo, a seção tem de ser gravável (PAGE_READWRITE ou
//! PAGE_EXECUTE_READWRITE na proteção da seção, senão
//! STATUS_SECTION_NOT_EXTENDED) e o arquivo é estendido como pelo
//! FsRtlSetFileSize (o mesmo resize do MmCreateSection, `section/file`);
//! então o SizeOfSection e o tamanho em páginas da seção crescem. As vistas
//! que já existem continuam do tamanho delas.

use alloc::sync::Arc;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::section::handles::{self as section_handles, Kind};
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::user::sections::{self, Section};
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_SECTION_TOO_BIG: u32 = 0xC000_0040;
const STATUS_SECTION_NOT_EXTENDED: u32 = 0xC000_0087;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
/// SECTION_EXTEND_SIZE.
const SECTION_EXTEND_SIZE: u32 = 0x10;
/// O maior tamanho de seção (MmExtendSection 0x669395).
const MAXIMUM_SECTION_SIZE: u64 = 0x3F_FFFF_FFFF_F000;

/// MmExtendSection(Section, NewSectionSize*, IgnoreFileSizeChecking = FALSE).
pub fn extend(section: &Arc<Section>, new_size: &mut u64) -> Result<u32, KernelError> {
    if section.is_image || crate::ntos::mm::section::physical_memory::is_physical_memory(section.pointer()) {
        return Ok(STATUS_SECTION_NOT_EXTENDED);
    }
    let Some(file) = section.file.clone() else { return Ok(STATUS_SECTION_NOT_EXTENDED) };
    if *new_size > MAXIMUM_SECTION_SIZE {
        return Ok(STATUS_SECTION_TOO_BIG);
    }
    if *new_size <= section.maximum_size() {
        *new_size = section.maximum_size();
        return Ok(0);
    }
    if *new_size > file.file_size() {
        if section.page_protect() & 0x44 == 0 {
            return Ok(STATUS_SECTION_NOT_EXTENDED);
        }
        let status = match file.set_size(*new_size) {
            Some(result) => result?,
            None => STATUS_SECTION_NOT_EXTENDED,
        };
        if status != 0 {
            return Ok(status);
        }
    }
    // As páginas novas entram na control area como as da criação (lidas do
    // arquivo e postas nas vistas que as cobrem).
    let old_pages = section.count_pages();
    section.extend(*new_size);
    let new_pages = section.count_pages();
    if new_pages > old_pages {
        let status = sections::commit(section, old_pages, new_pages - old_pages)?;
        if status != 0 {
            return Ok(status);
        }
    }
    let pointer = section.pointer();
    let size = section.size();
    section_objects::update(pointer, |state| state.size = size);
    // SAFETY: o corpo _SECTION da seção, retido pela referência de quem
    // estende.
    unsafe { crate::ntos::inc::types::Section::at(pointer) }.size_of_section.set(size);
    Ok(0)
}

/// NtExtendSection(SectionHandle, NewSectionSize*) em `mode`.
pub fn nt_extend_section(section_handle: u64, size_pointer: u64, mode: u8) -> Result<u32, KernelError> {
    if mode != 0 {
        if size_pointer & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_write(size_pointer, 8) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let Ok(mut new_size) = guest::try_read::<u64>(size_pointer) else { return Ok(STATUS_ACCESS_VIOLATION) };
    let reference = match section_handles::reference(section_handle, Kind::Section, SECTION_EXTEND_SIZE, mode) {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let status = match reference.section.clone() {
        Some(section) => extend(&section, &mut new_size),
        None => Ok(STATUS_SECTION_NOT_EXTENDED),
    };
    reference.release()?;
    let status = status?;
    let _ = guest::try_write::<u64>(size_pointer, new_size);
    Ok(status)
}
