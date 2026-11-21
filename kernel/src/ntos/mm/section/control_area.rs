//! A CONTROL_AREA nativa da seção de dados de um arquivo de file system,
//! publicada no SECTION_OBJECT_POINTERS do FCB (DataSectionObject), como o
//! MiCreateDataFileMap (ntoskrnl 19041 0x6fa9c0) e o MiInsertNewControlArea
//! a publicam.
//!
//! O file system e as rotinas do Mm que recebem os SECTION_OBJECT_POINTERS
//! (MmCanFileBeTruncated, MmFlushImageSection, MmForceSectionClosed,
//! MmDoesFileHaveUserWritableReferences, MmChangeSectionBackingFile,
//! MmPrefetchPages, o CcFlushCache sem SharedCacheMap) sabem pelo slot se o
//! arquivo tem seção de dados. A control area do OpenNT (`Area`, em
//! `ps::user::sections`) é a dona das páginas; a CONTROL_AREA nativa espelha
//! os contadores dela:
//!
//! - NumberOfSectionReferences: as seções (as de usuário e a do Cache
//!   Manager);
//! - NumberOfMappedViews e NumberOfSystemCacheViews: as vistas, e as do
//!   cache entre elas;
//! - NumberOfUserReferences: as seções e as vistas que não são do cache;
//!   WritableUserReferences: as graváveis entre elas;
//! - NumberOfPfnReferences: as páginas residentes;
//! - u.Flags.File, FilePointer (o FILE_OBJECT que criou a control area, com
//!   uma referência dela; MmChangeSectionBackingFile o troca) e LockedPages
//!   começando em 1.
//!
//! A memória é a do MiCreateDataFileMap: a CONTROL_AREA, o MSUBSECTION que
//! cobre o arquivo mapeado logo depois (NumberOfFullSectors em páginas e o
//! SectorEndOffset do resto), a raiz da árvore de subseções e o SEGMENT. A
//! associação SOP -> CONTROL_AREA muda só sob [`ASSOCIATION`], que quem lê o
//! slot também segura (o papel do lock de associação do NT): a CONTROL_AREA
//! retirada do slot nunca é lida depois de liberada.

use core::sync::atomic::Ordering;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{ControlArea, Msubsection, RtlAvlTree, SectionObjectPointers, Segment};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_reference, reference_trace};
use crate::rtl::SpinLock;

const PAGE: u64 = 0x1000;
/// MSUBSECTION, raiz da árvore de subseções e SEGMENT depois da CONTROL_AREA.
const SUBSECTION_OFFSET: u64 = ControlArea::SIZE;
const TREE_ROOT_OFFSET: u64 = SUBSECTION_OFFSET + Msubsection::SIZE;
const SEGMENT_OFFSET: u64 = TREE_ROOT_OFFSET + RtlAvlTree::SIZE;
const ALLOCATION: u64 = SEGMENT_OFFSET + Segment::SIZE;
/// u.Flags.BeingDeleted e u.Flags.File.
const BEING_DELETED: u32 = 1 << 0;
const FILE: u32 = 1 << 7;
/// Referências em cache do EX_FAST_REF.
const MAX_FAST_REFS: u64 = 0xF;

/// A troca do slot e a leitura dele pelos consumidores.
static ASSOCIATION: SpinLock<()> = SpinLock::new(());

/// A CONTROL_AREA publicada: o endereço dela e o SECTION_OBJECT_POINTERS.
pub struct NativeControlArea {
    pub address: u64,
    pub pointers: u64,
}

/// Os contadores que a CONTROL_AREA espelha.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub sections: u64,
    pub user_sections: u64,
    pub writable_user_sections: u64,
    pub views: u64,
    pub cache_views: u64,
    pub writable_user_views: u64,
    pub resident_pages: u64,
}

fn control_area(address: u64) -> &'static ControlArea {
    // SAFETY: CONTROL_AREA alocada por `publish` e viva até `unpublish`.
    unsafe { ControlArea::at(address) }
}

fn sop(pointers: u64) -> &'static SectionObjectPointers {
    // SAFETY: SECTION_OBJECT_POINTERS do FCB do file system dono do arquivo.
    unsafe { SectionObjectPointers::at(pointers) }
}

/// Lê o slot de dados de `pointers` com a associação presa e chama `test`
/// com a CONTROL_AREA publicada (None sem seção de dados).
pub fn with_data_section<T>(pointers: u64, test: impl FnOnce(Option<&ControlArea>) -> T) -> T {
    let _association = ASSOCIATION.lock();
    let address = sop(pointers).data_section_object.get();
    test((address != 0).then(|| control_area(address)))
}

/// O mesmo para um slot qualquer (dados ou imagem) de um SECTION_OBJECT_POINTERS.
pub fn with_slot<T>(slot: &crate::ntos::inc::field::Field<u64>, test: impl FnOnce(Option<&ControlArea>) -> T) -> T {
    let _association = ASSOCIATION.lock();
    let address = slot.get();
    test((address != 0).then(|| control_area(address)))
}

/// Cria a CONTROL_AREA do arquivo `file` (o FILE_OBJECT, que ela passa a
/// referenciar) de `size` bytes e a publica no DataSectionObject de
/// `pointers`. None se o slot já tem outra (a publicação da outra criação
/// fica) ou sem memória.
pub fn publish(pointers: u64, file: u64, size: u64) -> Option<NativeControlArea> {
    if pointers == 0 || file == 0 {
        return None;
    }
    let address = guest::alloc_bytes(ALLOCATION);
    if address == 0 {
        return None;
    }
    guest::write_bytes(address, &alloc::vec![0u8; ALLOCATION as usize]);
    let area = control_area(address);
    area.segment.set(address + SEGMENT_OFFSET);
    area.list_head.flink.set(area.list_head.address());
    area.list_head.blink.set(area.list_head.address());
    area.u.long_flags.set(FILE);
    area.locked_pages.set(1);
    // SAFETY: MSUBSECTION, raiz e SEGMENT dentro da alocação zerada acima.
    let (subsection, root, segment) = unsafe { (Msubsection::at(address + SUBSECTION_OFFSET), RtlAvlTree::at(address + TREE_ROOT_OFFSET), Segment::at(address + SEGMENT_OFFSET)) };
    subsection.core.control_area.set(address);
    subsection.dereference_list.flink.set(subsection.dereference_list.address());
    subsection.dereference_list.blink.set(subsection.dereference_list.address());
    root.root.set(subsection.subsection_node.address());
    segment.control_area.set(address);
    set_size(address, size);
    if object_reference::reference_with_tag(file, reference_trace::DEFAULT_TAG, false).is_err() {
        guest::free_bytes(address);
        return None;
    }
    area.file_pointer.object.set(file);
    let published = {
        let _association = ASSOCIATION.lock();
        sop(pointers).data_section_object.atomic().compare_exchange(0, address, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    };
    if !published {
        let _ = object_reference::dereference_with_tag(file, reference_trace::DEFAULT_TAG, false);
        guest::free_bytes(address);
        return None;
    }
    Some(NativeControlArea { address, pointers })
}

/// O tamanho mapeado do arquivo: a subseção (páginas inteiras e o resto) e
/// o SEGMENT.
pub fn set_size(address: u64, size: u64) {
    // SAFETY: MSUBSECTION e SEGMENT da CONTROL_AREA viva.
    let (subsection, segment) = unsafe { (Msubsection::at(address + SUBSECTION_OFFSET), Segment::at(address + SEGMENT_OFFSET)) };
    let pages = size.div_ceil(PAGE);
    subsection.core.u.subsection_flags.set_sector_end_offset((size % PAGE) as u16);
    subsection.core.number_of_full_sectors.set((size / PAGE) as u32);
    subsection.core.ptes_in_subsection.set(pages as u32);
    segment.total_number_of_ptes.set(pages as u32);
    segment.size_of_segment.set(pages * PAGE);
}

/// O tamanho mapeado que a CONTROL_AREA descreve.
pub fn size(native: &NativeControlArea) -> u64 {
    // SAFETY: MSUBSECTION da CONTROL_AREA viva.
    let subsection = unsafe { Msubsection::at(native.address + SUBSECTION_OFFSET) };
    subsection.core.number_of_full_sectors.get() as u64 * PAGE + subsection.core.u.subsection_flags.sector_end_offset() as u64
}

/// O tamanho mapeado da CONTROL_AREA publicada nos SECTION_OBJECT_POINTERS
/// (0 sem seção de dados).
pub fn published_size(pointers: u64) -> u64 {
    with_data_section(pointers, |area| area.map_or(0, |area| size(&NativeControlArea { address: area.address(), pointers })))
}

/// Os contadores novos na CONTROL_AREA.
pub fn update(native: &NativeControlArea, counters: &Counters) {
    let area = control_area(native.address);
    area.number_of_section_references.set(counters.sections);
    area.number_of_mapped_views.set(counters.views);
    area.number_of_user_references.set(counters.user_sections + counters.views - counters.cache_views);
    area.number_of_pfn_references.set(counters.resident_pages);
    area.u2.e2.number_of_system_cache_views.set(counters.cache_views as u32);
    area.u2.e2.writable_user_references.set((counters.writable_user_sections + counters.writable_user_views) as i32);
}

/// O FILE_OBJECT da paginação (FilePointer, sem as referências em cache).
pub fn file_object(native: &NativeControlArea) -> u64 {
    control_area(native.address).file_pointer.object.get() & !MAX_FAST_REFS
}

/// u.Flags.NoModifiedWriting (o MmDisableModifiedWriteOfSection do Cc).
pub fn no_modified_writing(native: &NativeControlArea) -> bool {
    control_area(native.address).u.flags.no_modified_writing() != 0
}

/// Tira a CONTROL_AREA do slot (BeingDeleted antes), solta a referência do
/// FILE_OBJECT (com as que o EX_FAST_REF guarda em cache) e libera a memória.
pub fn unpublish(native: NativeControlArea) {
    let area = control_area(native.address);
    area.u.long_flags.atomic().fetch_or(BEING_DELETED, Ordering::SeqCst);
    {
        let _association = ASSOCIATION.lock();
        let _ = sop(native.pointers).data_section_object.atomic().compare_exchange(native.address, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
    let pointer = area.file_pointer.object.get();
    let (file, cached) = (pointer & !MAX_FAST_REFS, pointer & MAX_FAST_REFS);
    for _ in 0..cached + 1 {
        let _ = object_reference::dereference_with_tag(file, reference_trace::DEFAULT_TAG, false);
    }
    guest::free_bytes(native.address);
}
