//! MmGetImageFileSignatureInformation.
//!
//! Consulta o cache da seção de imagem. Não valida certificados e não
//! transforma a ausência de cache em confiança.

use crate::ntos::ex::spin_lock;
use crate::ntos::mm::guest_memory as guest;

// Layouts do ntoskrnl de referência (instruções e PDB).
const SECTION_OBJECT_POINTERS_OFFSET: u64 = 0x28;
const IMAGE_SECTION_OFFSET: u64 = 0x10;
const CONTROL_AREA_FLAGS_OFFSET: u64 = 0x38;
const CONTROL_AREA_LOCK_OFFSET: u64 = 0x48;
const SEGMENT_SIGNATURE_BYTE_OFFSET: u64 = 0xF;

/// Nível de assinatura guardado no segmento da imagem do FILE_OBJECT (0 =
/// sem seção de imagem ou control area em transição).
pub fn query(file_object: u64) -> u64 {
    let section_pointers = guest::read64(file_object + SECTION_OBJECT_POINTERS_OFFSET);
    if section_pointers == 0 {
        return 0;
    }
    loop {
        let control_area = guest::read64(section_pointers + IMAGE_SECTION_OFFSET);
        if control_area == 0 {
            return 0;
        }
        let lock = control_area + CONTROL_AREA_LOCK_OFFSET;
        let previous = spin_lock::acquire_exclusive(lock);
        // Revalida a associação já com a exclusão; o byte é lido sob o lock.
        let result = if guest::read64(section_pointers + IMAGE_SECTION_OFFSET) != control_area {
            None
        } else if guest::read32(control_area + CONTROL_AREA_FLAGS_OFFSET) & 3 != 0 {
            // BeingDeleted e BeingCreated: segmento transitório.
            Some(0)
        } else {
            let segment = guest::read64(control_area);
            Some((guest::read8(segment + SEGMENT_SIGNATURE_BYTE_OFFSET) >> 4) as u64)
        };
        let _ = spin_lock::release_exclusive(lock, previous);
        if let Some(level) = result {
            return level;
        }
    }
}
