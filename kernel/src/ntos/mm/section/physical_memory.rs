//! A seção da memória física, `\Device\PhysicalMemory`, como o
//! MiSectionInitialization do ntoskrnl 19041 (rva 0xa55074) a cria no boot,
//! logo depois do tipo Section:
//! - a CONTROL_AREA da memória física (no NT, a do MiState) com
//!   u.Flags.PhysicalMemory (bit 10) e NumberOfSectionReferences = 1, e um
//!   SEGMENT de 0x48 bytes do pool não paginável (tag 'MmSg') ligado a ela
//!   nos dois sentidos (CONTROL_AREA.Segment e SEGMENT.ControlArea);
//! - o corpo SECTION do ObCreateObject(KernelMode, MmSectionObjectType) com
//!   o nome e os atributos OBJ_PERMANENT | OBJ_KERNEL_EXCLUSIVE (0x10010):
//!   u1.ControlArea na CONTROL_AREA, SizeOfSection = 0xFFFFFFFFFFFF,
//!   u.Flags = 0 e InitialPageProtection = 0x40 (o resto do DWORD de +0x3C
//!   fica como está);
//! - o ObInsertObject (SECTION_MAP_READ) publica o nome e o handle é fechado
//!   em seguida: o objeto fica pelo OBJ_PERMANENT, sem handles.
//!
//! O OBJ_KERNEL_EXCLUSIVE dá ao objeto o KernelOnlyAccess: abrir handle em
//! UserMode (ou com OBJ_FORCE_ACCESS_CHECK) dá STATUS_ACCESS_DENIED
//! (`ob/objects/section.rs`). O ZwOpenSection de modo kernel abre; o
//! VIDMM_GLOBAL::Init do dxgmms2.sys o abre com SECTION_ALL_ACCESS ao
//! iniciar um adaptador de renderização. Vistas desta seção (o
//! MiMapViewOfPhysicalSection do NT, que mapeia frames físicos) ainda não
//! existem: o NtMapViewOfSection recusa e avisa na serial.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::{ControlArea, NtStruct, Section, Segment};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager::{self, ObjectData};
use crate::ntos::ob::objects::section::{self as section_objects, SectionState};
use crate::rtl::KernelError;

pub const NAME: &str = "\\Device\\PhysicalMemory";
const DIRECTORY: &str = "\\Device";
const LEAF: &str = "PhysicalMemory";
/// SizeOfSection: os 48 bits de endereço físico.
const SIZE_OF_SECTION: u64 = 0xFFFF_FFFF_FFFF;
/// InitialPageProtection do corpo (bits 0..=11 de +0x3C).
const INITIAL_PAGE_PROTECTION: u32 = 0x40;
const NON_PAGED_POOL_NX: u32 = 0x200;
/// 'MmSg'.
const SEGMENT_TAG: u32 = u32::from_le_bytes(*b"MmSg");

/// O corpo SECTION publicado (0 antes do `initialize`).
static SECTION: AtomicU64 = AtomicU64::new(0);

/// O objeto é permanente: nunca chega à destruição.
fn destroy(_pointer: u64) -> Result<(), KernelError> {
    Err(KernelError::new("\\Device\\PhysicalMemory e permanente"))
}

/// O corpo SECTION de `\Device\PhysicalMemory`.
pub fn section() -> u64 {
    SECTION.load(Ordering::Acquire)
}

/// `pointer` é a seção da memória física.
pub fn is_physical_memory(pointer: u64) -> bool {
    pointer != 0 && pointer == section()
}

/// MiSectionInitialization: a CONTROL_AREA, o SEGMENT e a seção nomeada.
/// Idempotente.
pub fn initialize() -> Result<(), KernelError> {
    if section() != 0 {
        return Ok(());
    }
    let control_area_address = guest::alloc_bytes(ControlArea::SIZE);
    if control_area_address == 0 {
        return Err(KernelError::new("CONTROL_AREA da memoria fisica"));
    }
    let segment_address = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, Segment::SIZE, SEGMENT_TAG)?;
    if segment_address == 0 {
        guest::free_bytes(control_area_address);
        return Err(KernelError::new("SEGMENT da memoria fisica"));
    }
    guest::write_bytes(segment_address, &[0u8; Segment::SIZE as usize]);
    // SAFETY: CONTROL_AREA e SEGMENT recém-alocados, do tamanho dos tipos.
    let (control_area, segment) = unsafe { (ControlArea::at(control_area_address), Segment::at(segment_address)) };
    control_area.segment.set(segment_address);
    control_area.number_of_section_references.set(1);
    control_area.u.flags.set_physical_memory(1);
    segment.control_area.set(control_area_address);
    let pointer = section_objects::register(SectionState { size: SIZE_OF_SECTION, name: alloc::string::String::from(NAME), permanent: true, kernel_only: true, ..SectionState::default() }, destroy)?;
    if pointer == 0 {
        return Err(KernelError::with_status("corpo SECTION da memoria fisica", 0xC000_009A));
    }
    // SAFETY: corpo SECTION de 0x40 bytes que o registro acabou de alocar.
    let body = unsafe { Section::at(pointer) };
    body.u1.control_area.set(control_area_address);
    body.u.long_flags.set(0);
    body.set_initial_page_protection(INITIAL_PAGE_PROTECTION);
    object_manager::create_object(DIRECTORY, LEAF, "Section", Some(ObjectData::pointer(pointer)))?;
    SECTION.store(pointer, Ordering::Release);
    Ok(())
}
