//! Consulta de seção em modo kernel (ZwQuerySection).
//!
//! A ordem do NtQuerySection do 19041: a classe define o tamanho exigido
//! (SectionBasicInformation 0x18, SectionImageInformation 0x40,
//! SectionRelocationInformation e SectionOriginalBaseInformation 8; outra
//! classe dá STATUS_INVALID_INFO_CLASS) e um buffer menor dá
//! STATUS_INFO_LENGTH_MISMATCH antes do handle; depois o
//! ObReferenceObjectByHandle com SECTION_QUERY e MmSectionObjectType, e o
//! MmGetSectionInformation. A informação básica traz BaseAddress (só as
//! seções baseadas têm um; o OpenNT não as cria), AllocationAttributes e
//! MaximumSize; as classes de imagem numa seção que não é de imagem dão
//! STATUS_SECTION_NOT_IMAGE. *ResultLength recebe o tamanho no sucesso.
//!
//! Lacuna: as seções de imagem do OpenNT não guardam o
//! SECTION_IMAGE_INFORMATION do segmento, então as classes de imagem numa
//! seção de imagem dão STATUS_NOT_SUPPORTED.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::SectionBasicInformation;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_reference, object_types, reference_trace};
use crate::ntos::ps::user::sections;
use crate::rtl::KernelError;

const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_SECTION_NOT_IMAGE: u32 = 0xC000_0049;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
/// SECTION_QUERY.
const SECTION_QUERY: u32 = 1;

/// Tamanho exigido por classe.
fn required_length(class: u32) -> Option<u64> {
    match class {
        0 => Some(SectionBasicInformation::SIZE),
        1 => Some(0x40),
        2 | 3 => Some(8),
        _ => None,
    }
}

/// ZwQuerySection(SectionHandle, SectionInformationClass, SectionInformation,
/// SectionInformationLength, ResultLength) em KernelMode.
pub fn query(handle: u64, class: u32, information: u64, length: u64, result_length: u64) -> Result<u32, KernelError> {
    let Some(required) = required_length(class) else { return Ok(STATUS_INVALID_INFO_CLASS) };
    if length < required {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(0xC000_009A);
    }
    let status = object_reference::reference_by_handle(handle, SECTION_QUERY, object_types::section_type().pointer, 0, slot, 0)? as u32;
    // SAFETY: célula PVOID recém-alocada.
    let pointer = unsafe { Field::<u64>::at(slot) }.get();
    guest::free_bytes(slot);
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    let result = (|| {
        let Some(section) = sections::by_pointer(pointer) else { return STATUS_INVALID_HANDLE };
        if class != 0 {
            return if section.is_image { STATUS_NOT_SUPPORTED } else { STATUS_SECTION_NOT_IMAGE };
        }
        guest::write_bytes(information, &[0; SectionBasicInformation::SIZE as usize]);
        // SAFETY: buffer de saída de um chamador de modo kernel, com o tamanho conferido.
        let basic = unsafe { SectionBasicInformation::at(information) };
        basic.allocation_attributes.set(section.attributes);
        basic.maximum_size.quad_part.set(section.maximum_size as i64);
        if result_length != 0 {
            // SAFETY: PSIZE_T de saída do chamador de modo kernel.
            unsafe { Field::<u64>::at(result_length) }.set(required);
        }
        0
    })();
    object_reference::dereference_with_tag(pointer, reference_trace::DEFAULT_TAG, false)?;
    Ok(result)
}
