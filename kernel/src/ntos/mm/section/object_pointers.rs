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

use crate::ntos::ex::spin_lock;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{ControlArea, SectionObjectPointers};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

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

// ---- MmFlushImageSection, MmCanFileBeTruncated,
// ---- MmDoesFileHaveUserWritableReferences (mm-file-sections) ------------------
//
// ntoskrnl 10.0.19041: MmFlushImageSection 0x3107a0, MmCanFileBeTruncated
// 0x2f9380 -> MiCanFileBeTruncatedInternal 0x2f93fc (MiFindLastSubsection
// 0x2f974c, MiEndingOffset 0x29ced0), MmDoesFileHaveUserWritableReferences
// 0x2f7c00 -> MiDoesControlAreaHaveUserWritableReferences 0x2f7d14. O NT
// segura o spin lock global de associação SOP->CONTROL_AREA e o da
// CONTROL_AREA; aqui, como em `backing_file`, a associação é revalidada sob
// o lock da CONTROL_AREA. Sem CONTROL_AREA publicada (todo arquivo de file
// system no OpenNT hoje) os resultados são os do NT para "sem seção".

/// MmFlushForDelete / MmFlushForWrite.
pub const MM_FLUSH_FOR_DELETE: u32 = 0;
pub const MM_FLUSH_FOR_WRITE: u32 = 1;

/// u.Flags.BeingDeleted.
const BEING_DELETED: u32 = 0x01;
/// u.Flags.NoModifiedWriting.
const NO_MODIFIED_WRITING: u32 = 0x08;
/// u.Flags.Image.
const IMAGE: u32 = 0x20;

/// `_SUBSECTION` (0x38 bytes, símbolos do ntoskrnl 19041): o que o
/// MiEndingOffset lê. Numa seção de dados de arquivo o `_MSUBSECTION`
/// estende o SUBSECTION com o nó da árvore de subseções em +0x38.
#[repr(C)]
struct Subsection {
    control_area: Field<u64>,
    subsection_base: Field<u64>,
    next_subsection: Field<u64>,
    _global_per_session_head: Reserved<0x8>,
    /// u.SubsectionFlags: StartingSector4132 nos bits 6..16 e
    /// SectorEndOffset nos bits 20..32.
    flags: Field<u32>,
    starting_sector: Field<u32>,
    number_of_full_sectors: Field<u32>,
    ptes_in_subsection: Field<u32>,
    _u1: Reserved<0x8>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for Subsection {}

const _: () = {
    assert!(core::mem::size_of::<Subsection>() == 0x38);
    assert!(core::mem::offset_of!(Subsection, next_subsection) == 0x10);
    assert!(core::mem::offset_of!(Subsection, flags) == 0x20);
    assert!(core::mem::offset_of!(Subsection, starting_sector) == 0x24);
    assert!(core::mem::offset_of!(Subsection, number_of_full_sectors) == 0x28);
};

/// A primeira subseção segue a CONTROL_AREA; numa seção de dados de arquivo
/// a raiz da árvore de subseções fica depois do primeiro `_MSUBSECTION`
/// (0x80 + 0x90).
const FIRST_SUBSECTION: u64 = 0x80;
const SUBSECTION_TREE_ROOT: u64 = 0x110;
/// MSUBSECTION.SubsectionNode.
const SUBSECTION_NODE: u64 = 0x38;

/// Avalia `test` com a CONTROL_AREA do slot presa; None sem CONTROL_AREA.
fn with_control_area<T>(slot: &Field<u64>, test: impl Fn(&ControlArea) -> T) -> Result<Option<T>, KernelError> {
    loop {
        let address = slot.get();
        if address == 0 {
            return Ok(None);
        }
        // SAFETY: CONTROL_AREA publicada na SOP pelo Mm.
        let control_area = unsafe { ControlArea::at(address) };
        let lock = control_area.control_area_lock.address();
        let previous = spin_lock::acquire_exclusive(lock);
        if slot.get() != address {
            spin_lock::release_exclusive(lock, previous)?;
            continue;
        }
        let result = test(control_area);
        spin_lock::release_exclusive(lock, previous)?;
        return Ok(Some(result));
    }
}

/// MiAttemptSectionDelete(ControlArea, ..., 0) da seção de imagem: em uso
/// (referências de seção, vistas ou BeingCreated), ou ociosa — que o NT
/// apagaria (MiCleanSection); sem teardown de CONTROL_AREA nativa no
/// OpenNT ela fica, e o resultado é o de em uso.
fn image_section_deleted(_control_area: &ControlArea) -> bool {
    false
}

/// MmFlushImageSection(SectionPointer, FlushType) -> BOOLEAN.
pub fn flush_image_section(pointers: &SectionObjectPointers, flush_type: u32) -> Result<bool, KernelError> {
    if flush_type == MM_FLUSH_FOR_DELETE {
        // Seção de dados com usuários, em criação ou com páginas travadas.
        let busy = with_control_area(&pointers.data_section_object, |control_area| {
            control_area.number_of_user_references.get() != 0 || control_area.u.long_flags.get() & BEING_CREATED != 0 || control_area.locked_pages.get() > 1
        })?;
        if busy == Some(true) {
            return Ok(false);
        }
    }
    Ok(with_control_area(&pointers.image_section_object, image_section_deleted)?.unwrap_or(true))
}

/// MiEndingOffset: o fim (em bytes) do trecho do arquivo de uma subseção.
fn ending_offset(subsection: &Subsection) -> u64 {
    // SAFETY: Subsection->ControlArea de uma CONTROL_AREA viva.
    let control_area = unsafe { ControlArea::at(subsection.control_area.get()) };
    let flags = subsection.flags.get();
    let sector_end = (flags >> 20) as u64;
    let full = subsection.number_of_full_sectors.get() as u64;
    let starting = subsection.starting_sector.get() as u64;
    if control_area.u.long_flags.get() & IMAGE != 0 {
        return ((full + starting) << 9) + sector_end;
    }
    let high = (flags & 0xFFC0) as u64;
    ((((high << 26) | starting) + full) << 12) + sector_end
}

/// A última subseção: na seção de arquivo, o nó mais à direita da árvore
/// (MiFindLastSubsection); daí em diante pela lista NextSubsection.
fn last_subsection(control_area: &ControlArea) -> &'static Subsection {
    let mut address = control_area.address() + FIRST_SUBSECTION;
    if control_area.file_pointer.value.get() != 0 {
        let mut node = guest::read64(control_area.address() + SUBSECTION_TREE_ROOT);
        let mut rightmost = 0;
        while node != 0 {
            rightmost = node;
            node = guest::read64(node + 8);
        }
        address = rightmost.wrapping_sub(SUBSECTION_NODE);
    }
    loop {
        // SAFETY: subseções encadeadas da CONTROL_AREA presa.
        let subsection = unsafe { Subsection::at(address) };
        let next = subsection.next_subsection.get();
        if next == 0 {
            return subsection;
        }
        address = next;
    }
}

/// MmCanFileBeTruncated(SectionPointer, NewFileSize*) -> BOOLEAN. O
/// arredondamento do tamanho para a página vai para uma cópia local, como
/// no NT.
pub fn can_file_be_truncated(pointers: &SectionObjectPointers, new_file_size: Option<u64>) -> Result<bool, KernelError> {
    if pointers.image_section_object.get() != 0 && !flush_image_section(pointers, MM_FLUSH_FOR_WRITE)? {
        return Ok(false);
    }
    let allowed = with_control_area(&pointers.data_section_object, |control_area| {
        let flags = control_area.u.long_flags.get();
        if flags & (BEING_DELETED | BEING_CREATED) != 0 {
            return false;
        }
        if control_area.locked_pages.get() > 1 && flags & NO_MODIFIED_WRITING == 0 {
            return false;
        }
        if control_area.number_of_user_references.get() == 0 {
            return true;
        }
        let Some(size) = new_file_size else { return false };
        size >= ending_offset(last_subsection(control_area))
    })?;
    Ok(allowed.unwrap_or(true))
}

/// MmDoesFileHaveUserWritableReferences(SectionPointer) -> ULONG (0 ou 1):
/// WritableUserReferences, ou mais de uma página travada. O desconto da
/// CONTROL_AREA especial da partição não se aplica: o OpenNT não tem
/// MI_PARTITION.
pub fn does_file_have_user_writable_references(pointers: &SectionObjectPointers) -> Result<u32, KernelError> {
    let writable = with_control_area(&pointers.data_section_object, |control_area| {
        control_area.u2.e2.writable_user_references.get() != 0 || control_area.locked_pages.get() > 1
    })?;
    Ok(writable.unwrap_or(false) as u32)
}
