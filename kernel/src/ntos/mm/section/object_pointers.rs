//! SECTION_OBJECT_POINTERS que os file systems guardam no FCB —
//! DataSectionObject, SharedCacheMap, ImageSectionObject — e o fechamento
//! forçado das seções do arquivo: MmForceSectionClosed (RVA 0x3108d0 ->
//! MiForceSectionClosed 0x310910 -> MiAttemptSectionDelete 0x3109b4,
//! ntoskrnl 10.0.19045).
//!
//! O NT tenta a seção de dados e, se não houver CONTROL_AREA de dados, a de
//! imagem; o resultado é TRUE quando não há seção ou quando ela pôde ser
//! apagada (ou marcada para apagar), FALSE quando ainda está em uso. As
//! seções do OpenNT (`ps::user::sections`) compartilham a control area pela
//! identidade do arquivo e não publicam CONTROL_AREA nos
//! SECTION_OBJECT_POINTERS do FCB de um driver — o caso comum aqui é "sem
//! seção", com o resultado exato do NT. Uma CONTROL_AREA nativa publicada é
//! avaliada pelos contadores do NT (NumberOfSectionReferences,
//! NumberOfMappedViews, u.Flags.BeingCreated); o MiCleanSection que apagaria
//! uma CONTROL_AREA ociosa não existe no OpenNT, então ela é relatada como
//! ainda em uso.

use core::sync::atomic::Ordering;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ControlArea, SectionObjectPointers};

/// u.Flags.BeingCreated.
const BEING_CREATED: u32 = 0x02;
/// u.Flags bit 18, ligado quando o fechamento atrasado encontra a seção em uso.
const DELETE_ON_CLOSE: u32 = 1 << 18;

/// Resultado do MiForceSectionClosed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ForceClose {
    NoSection,
    InUse,
}

/// MiForceSectionClosed(Pointers, Flags) para um dos dois slots.
fn force_closed(slot: &Field<u64>, delay_close: bool) -> ForceClose {
    let pointer = slot.get();
    if pointer == 0 {
        return ForceClose::NoSection;
    }
    // SAFETY: um slot de SECTION_OBJECT_POINTERS não nulo aponta para uma CONTROL_AREA.
    let control_area = unsafe { ControlArea::at(pointer) };
    let flags = &control_area.u.long_flags;
    let busy = control_area.number_of_section_references.get() != 0 || control_area.number_of_mapped_views.get() != 0 || flags.get() & BEING_CREATED != 0;
    if busy && delay_close {
        // LOCK BTS no u.Flags da CONTROL_AREA (o NT o faz sob o lock dela).
        flags.atomic().fetch_or(DELETE_ON_CLOSE, Ordering::SeqCst);
    }
    // Ociosa, o NT apagaria (MiRemoveUnusedSegment + MiCleanSection) e devolveria
    // "apagada"; sem teardown de CONTROL_AREA nativa no OpenNT ela fica em uso.
    ForceClose::InUse
}

/// MmForceSectionClosed(SectionObjectPointer, DelayClose).
pub fn force_section_closed(pointers: &SectionObjectPointers, delay_close: bool) -> bool {
    let mut result = force_closed(&pointers.data_section_object, delay_close);
    if result == ForceClose::NoSection {
        result = force_closed(&pointers.image_section_object, delay_close);
    }
    result != ForceClose::InUse
}
