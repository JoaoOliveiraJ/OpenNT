//! MmGetImageFileSignatureInformation.
//!
//! Consulta o cache da seção de imagem. Não valida certificados e não
//! transforma a ausência de cache em confiança.

use crate::ntos::ex::spin_lock;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{ControlArea, FileObject, Segment, SectionObjectPointers};

/// Nível de assinatura guardado no segmento da imagem do FILE_OBJECT (0 =
/// sem seção de imagem ou control area em transição).
pub fn query(file_object: u64) -> u64 {
    // SAFETY: o FILE_OBJECT referenciado pelo chamador.
    let section_pointers = unsafe { FileObject::at(file_object) }.section_object_pointer.get();
    if section_pointers == 0 {
        return 0;
    }
    // SAFETY: FILE_OBJECT.SectionObjectPointer aponta para o SECTION_OBJECT_POINTERS do arquivo.
    let pointers = unsafe { SectionObjectPointers::at(section_pointers) };
    loop {
        let control_area = pointers.image_section_object.get();
        if control_area == 0 {
            return 0;
        }
        // SAFETY: a CONTROL_AREA da seção de imagem, revalidada sob o lock.
        let area = unsafe { ControlArea::at(control_area) };
        let lock = area.control_area_lock.address();
        let previous = spin_lock::acquire_exclusive(lock);
        // Revalida a associação já com a exclusão; o byte é lido sob o lock.
        let result = if pointers.image_section_object.get() != control_area {
            None
        } else if area.u.flags.being_deleted() != 0 || area.u.flags.being_created() != 0 {
            // BeingDeleted e BeingCreated: segmento transitório.
            Some(0)
        } else {
            // SAFETY: CONTROL_AREA.Segment de uma área viva.
            Some(unsafe { Segment::at(area.segment.get()) }.segment_flags.image_signing_level() as u64)
        };
        let _ = spin_lock::release_exclusive(lock, previous);
        if let Some(level) = result {
            return level;
        }
    }
}
