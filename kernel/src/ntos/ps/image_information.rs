//! ProcessImageInformation (classe 37).
//!
//! Consulta a seção que pertence ao processo referenciado, com o mesmo
//! rundown e a mesma ordem do kernel NT. O SECTION_IMAGE_INFORMATION
//! capturado vem do dono das seções de imagem (Mm), que instala o provedor
//! junto com os processos de usuário.

use alloc::vec::Vec;

use super::process;
use crate::ntos::ex::rundown;
use crate::ntos::ob::process_reference;
use crate::ntos::ob::objects::section as section_objects;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Ethread};
use crate::ntos::rtl::image::pe_image_information::INFORMATION_SIZE;

/// Seção → `None` sem registro de seção; `Some(None)` = não é imagem;
/// `Some(Some(bytes))` = informação capturada da imagem.
pub type SectionImage = fn(u64) -> Option<Option<Vec<u8>>>;

static SECTION_IMAGE: SpinLock<Option<SectionImage>> = SpinLock::new(None);

pub fn set_section_image(provider: SectionImage) {
    *SECTION_IMAGE.lock() = Some(provider);
}

pub fn query(process_handle: u64, output: u64, length: u32, returned: u64, access_mode: u8, probe_output: Option<fn(u64, u64) -> bool>) -> Result<u32, KernelError> {
    if length as usize != INFORMATION_SIZE {
        return Ok(0xC000_0004);
    }
    let mut reference = match process_reference::reference(process_handle, 0x1000, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let process_pointer = reference.pointer;
    // SAFETY: a thread corrente do Process Manager.
    let owning = unsafe { Ethread::at(process::get_current_thread()) }.tcb.process.get();
    let remote = process_pointer != owning;
    // SAFETY: EPROCESS referenciado pelo handle.
    let target = unsafe { Eprocess::at(process_pointer) };
    let rundown_pointer = target.rundown_protect.count.address();
    let mut section = 0;
    let mut retained = false;
    // A comparação usa a dona da thread, não ApcState.Process: uma thread
    // anexada a outro processo ainda precisa proteger a seção desse alvo.
    let selected = (|| -> Result<Option<u32>, KernelError> {
        if remote && !rundown::acquire(rundown_pointer)? {
            return Ok(Some(0xC000_010A));
        }
        let result = (|| -> Result<Option<u32>, KernelError> {
            section = target.section_object.get();
            if section == 0 {
                return Ok(Some(if remote { 0xC000_000D } else { 0xC000_010A }));
            }
            if remote {
                if section_objects::reference(section).is_none() {
                    return Err(KernelError::new("process image section is not registered"));
                }
                retained = true;
            }
            Ok(None)
        })();
        if remote {
            rundown::release(rundown_pointer)?;
        }
        result
    })();
    // O NT solta a referência de EPROCESS antes de copiar a informação;
    // para outro processo, a referência própria da seção sustenta a cópia.
    reference.release()?;
    let result = (|| -> Result<u32, KernelError> {
        if let Some(status) = selected? {
            return Ok(status);
        }
        let provider = *SECTION_IMAGE.lock();
        let Some(record) = provider.and_then(|provider| provider(section)) else {
            return Err(KernelError::new("missing process image section"));
        };
        let Some(information) = record else { return Ok(0xC000_0049) };
        if information.len() != INFORMATION_SIZE {
            return Err(KernelError::new("loaded image has no captured SECTION_IMAGE_INFORMATION"));
        }
        if probe_output.is_some_and(|probe| !probe(output, INFORMATION_SIZE as u64)) {
            return Ok(0xC000_0005);
        }
        // Saída de modo usuário: a cópia é sondada (a página pode sumir).
        if guest::try_write_bytes(output, &information).is_err() {
            return Ok(0xC000_0005);
        }
        Ok(0)
    })();
    if retained {
        section_objects::dereference(section)?;
    }
    let status = result?;
    // A escrita por último preserva o caso ReturnLength aliased à saída.
    if status == 0 && returned != 0 && guest::try_write::<u32>(returned, INFORMATION_SIZE as u32).is_err() {
        return Ok(0xC000_0005);
    }
    Ok(status)
}
