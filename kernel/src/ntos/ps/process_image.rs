//! Identidade executável do processo.
//!
//! A seção de imagem mapeada, as referências do OB e o nome de auditoria
//! pertencem ao processo; a fonte do arquivo é o mesmo fluxo de bytes que o
//! loader PE consumiu: criação, consultas (PsReferenceProcessFilePointer,
//! SeLocateProcessImageName) e liberação.

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use super::process::{self, Executable, ImageProvider, ProcessImage};
use crate::ntos::ex::rundown;
use crate::ntos::mm::data_pool;
use crate::ntos::ob::objects::{file as file_objects, section as section_objects};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eprocess, UnicodeString};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A seção de imagem leva o FILE_OBJECT da fonte; a destruição o solta.
fn release_image_file(section: u64) -> Result<(), KernelError> {
    if let Some(state) = section_objects::state(section) {
        file_objects::dereference(state.image_file_object)?;
    }
    Ok(())
}

/// Seção de imagem com o FILE_OBJECT da fonte exata e o nome de auditoria
/// (UNICODE_STRING no pool) do processo.
pub fn create(executable: &Executable) -> Result<ProcessImage, KernelError> {
    let name = String::from(executable.source.name());
    let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    if units.is_empty() || units.len() > 32766 {
        return Err(KernelError::new("invalid full image name"));
    }
    let file = file_objects::create_source(executable.source.clone())?;
    let state = section_objects::SectionState { size: executable.image_size, image_file_object: file, ..section_objects::SectionState::default() };
    let section = match section_objects::register(state, release_image_file) {
        Ok(0) | Err(_) => {
            let _ = file_objects::dereference(file);
            return Err(KernelError::new("image section allocation failed"));
        }
        Ok(section) => section,
    };
    section_objects::reference(section);
    let cache = data_pool::alloc(UnicodeString::SIZE + units.len() as u64 * 2 + 2);
    if cache == 0 {
        let _ = section_objects::dereference(section);
        return Err(KernelError::new("image name allocation failed"));
    }
    // SAFETY: UNICODE_STRING recém-alocado, com o buffer logo depois.
    let name = unsafe { UnicodeString::at(cache) };
    name.length.set((units.len() * 2) as u16);
    name.maximum_length.set((units.len() * 2 + 2) as u16);
    name.buffer.set(cache + UnicodeString::SIZE);
    let characters: alloc::vec::Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(cache + UnicodeString::SIZE, &characters);
    Ok(ProcessImage { id: NEXT_ID.fetch_add(1, Ordering::Relaxed), section_native_pointer: section, file, cache })
}

fn provider_release_section(image: &ProcessImage) {
    let _ = release_section(image);
}

fn provider_destroy(image: &ProcessImage) {
    let _ = destroy(image);
}

static PROVIDER: ImageProvider = ImageProvider { create, release_section: provider_release_section, destroy: provider_destroy };

/// Instala a criação de imagens em `ps/process`.
pub fn init() {
    process::set_image_provider(&PROVIDER);
}

/// Libera a referência da seção uma única vez (o chamador marca a imagem).
pub fn release_section(image: &ProcessImage) -> Result<(), KernelError> {
    section_objects::dereference(image.section_native_pointer)?;
    Ok(())
}

pub fn destroy(image: &ProcessImage) -> Result<(), KernelError> {
    data_pool::free(image.cache)
}

/// Referencia o FILE_OBJECT da seção de imagem sob a proteção de rundown do
/// processo.
pub fn reference_file(process: u64, output: u64) -> Result<u32, KernelError> {
    // SAFETY: PEPROCESS do chamador de kernel.
    let process = unsafe { Eprocess::at(process) };
    let protection = process.rundown_protect.count.address();
    if !rundown::acquire(protection)? {
        return Ok(0xC000_0001);
    }
    let file = (|| -> Result<Option<u64>, KernelError> {
        let section = process.section_object.get();
        if section == 0 {
            return Ok(None);
        }
        let file = section_objects::file_object(section)?;
        if file != 0 {
            file_objects::reference(file)?;
        }
        Ok(Some(file))
    })();
    rundown::release(protection)?;
    let Some(file) = file? else { return Ok(0xC000_0001) };
    // SAFETY: PFILE_OBJECT* de saída do chamador de kernel.
    unsafe { Field::<u64>::at(output) }.set(file);
    Ok(0)
}

/// Cópia do UNICODE_STRING de auditoria (cabeçalho e MaximumLength bytes)
/// em pool de dados.
pub fn locate_name(process: u64, output: u64) -> Result<u32, KernelError> {
    // SAFETY: PEPROCESS do chamador de kernel.
    let cache = unsafe { Eprocess::at(process) }.se_audit_process_creation_info.image_file_name.get();
    if cache == 0 {
        return Ok(0xC000_0225);
    }
    // SAFETY: o nome de auditoria (UNICODE_STRING) criado por `create`.
    let source = unsafe { UnicodeString::at(cache) };
    let maximum = source.maximum_length.get() as u64;
    let copy = data_pool::alloc(UnicodeString::SIZE + maximum);
    if copy == 0 {
        return Ok(0xC000_0017);
    }
    // SAFETY: cópia recém-alocada (cabeçalho + MaximumLength bytes).
    let target = unsafe { UnicodeString::at(copy) };
    target.length.set(source.length.get());
    target.maximum_length.set(source.maximum_length.get());
    target.buffer.set(source.buffer.get());
    let buffer = source.buffer.get();
    if buffer != 0 {
        target.buffer.set(copy + UnicodeString::SIZE);
        guest::write_bytes(copy + UnicodeString::SIZE, &guest::read_bytes(buffer, maximum as usize));
    }
    // SAFETY: PUNICODE_STRING* de saída do chamador de kernel.
    unsafe { Field::<u64>::at(output) }.set(copy);
    Ok(0)
}
