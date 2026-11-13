//! Identidade executável do processo — `system32/ntos/ps/process-image.js`.
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
use crate::ntos::inc::nt_abi::eprocess;

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
    let cache = data_pool::alloc(18 + units.len() as u64 * 2);
    if cache == 0 {
        let _ = section_objects::dereference(section);
        return Err(KernelError::new("image name allocation failed"));
    }
    guest::write16(cache, (units.len() * 2) as u16);
    guest::write16(cache + 2, (units.len() * 2 + 2) as u16);
    guest::write64(cache + 8, cache + 16);
    for (index, &unit) in units.iter().enumerate() {
        guest::write16(cache + 16 + index as u64 * 2, unit);
    }
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
    let protection = process + eprocess::RUNDOWN_PROTECT;
    if !rundown::acquire(protection)? {
        return Ok(0xC000_0001);
    }
    let file = (|| -> Result<Option<u64>, KernelError> {
        let section = guest::read64(process + eprocess::SECTION_OBJECT);
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
    guest::write64(output, file);
    Ok(0)
}

/// Cópia do UNICODE_STRING de auditoria (cabeçalho e MaximumLength bytes)
/// em pool de dados.
pub fn locate_name(process: u64, output: u64) -> Result<u32, KernelError> {
    let cache = guest::read64(process + eprocess::AUDIT_IMAGE_NAME);
    if cache == 0 {
        return Ok(0xC000_0225);
    }
    let maximum = guest::read16(cache + 2) as u64;
    let copy = data_pool::alloc(16 + maximum);
    if copy == 0 {
        return Ok(0xC000_0017);
    }
    for offset in 0..16 {
        guest::write8(copy + offset, guest::read8(cache + offset));
    }
    let buffer = guest::read64(cache + 8);
    if buffer != 0 {
        guest::write64(copy + 8, copy + 16);
        for offset in 0..maximum {
            guest::write8(copy + 16 + offset, guest::read8(buffer + offset));
        }
    }
    guest::write64(output, copy);
    Ok(0)
}
