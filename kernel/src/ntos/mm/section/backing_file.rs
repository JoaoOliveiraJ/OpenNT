//! Troca do FILE_OBJECT que sustenta uma seção — MmChangeSectionBackingFile
//! (RVA 0x31c484 no ntoskrnl 19045), alcançado por
//! FsRtlChangeBackingFileObject.
//!
//! A CONTROL_AREA da seção de dados (SECTION_OBJECT_POINTERS.DataSectionObject)
//! ou de imagem (ImageSectionObject) guarda o arquivo em FilePointer
//! (EX_FAST_REF com 4 bits de referências em cache). Com a CONTROL_AREA
//! presa (spin lock exclusivo ControlAreaLock) e fora de BeingDeleted,
//! FilePointer passa a apontar para o novo FILE_OBJECT — sem dono atual
//! informado, troca qualquer arquivo; com dono, só se for ele.
//! ObFastReplaceObject (0x277500) referencia o novo por MAX_FAST_REFS (15),
//! troca com `xchg` para `novo | 0xF` e devolve ao antigo as referências em
//! cache; depois o NT soma +1 ao novo e solta +1 do antigo (tag 'Dflt').
//! PrefetchCreated é desligado quando a thread corrente não está em prefetch
//! (ETHREAD.SameThreadApcFlags.Prefetching).
//!
//! Diferenças declaradas: o NT segura também um spin lock global de
//! associação SOP->CONTROL_AREA; aqui a associação é revalidada sob o lock
//! da CONTROL_AREA (como `mm::image_file_signature`). As referências do
//! object manager são ajustadas logo depois de soltar o lock, porque o OB do
//! OpenNT pode apagar objetos de forma síncrona (o NT adia a deleção). Sem
//! CONTROL_AREA publicada na SOP — o caso de todo arquivo de driver no
//! OpenNT hoje — o resultado é o do NT: STATUS_SUCCESS sem mudança.

use core::sync::atomic::Ordering;

use crate::ntos::ex::spin_lock;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{ControlArea, Ethread, FileObject, SectionObjectPointers};
use crate::ntos::ob::object_reference;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

pub const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
pub const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;

const MAX_FAST_REFS: u64 = 0xF;
/// 'Dflt'.
const TAG: u32 = 0x746C_6644;

/// Qual CONTROL_AREA trocar (Flags de MmChangeSectionBackingFile).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BackingSection {
    Data = 1,
    Image = 2,
}

/// Troca feita sob o lock: (antigo, referências em cache do antigo).
fn replace_under_lock(control_area: &ControlArea, current: Option<&FileObject>, new: &FileObject) -> Option<(u64, u64)> {
    let flags = &control_area.u.flags;
    let mut replaced = None;
    if flags.being_deleted() == 0 {
        let pointer = &control_area.file_pointer.value;
        let object = pointer.get() & !MAX_FAST_REFS;
        let matches = match current {
            None => object != 0,
            Some(current) => object == current.address(),
        };
        if matches {
            let previous = pointer.atomic().swap(new.address() | MAX_FAST_REFS, Ordering::SeqCst);
            replaced = Some((previous & !MAX_FAST_REFS, previous & MAX_FAST_REFS));
        }
    }
    // SAFETY: a thread corrente.
    let thread = unsafe { Ethread::at(process::get_current_thread()) };
    if flags.prefetch_created() != 0 && thread.prefetching() == 0 {
        flags.set_prefetch_created(0);
    }
    replaced
}

/// MmChangeSectionBackingFile(CurrentFileObject, NewFileObject, Flags) -> NTSTATUS.
pub fn change_section_backing_file(current: Option<&FileObject>, new: &FileObject, section: BackingSection) -> Result<u32, KernelError> {
    let pointers_address = new.section_object_pointer.get();
    if let Some(current) = current {
        if current.section_object_pointer.get() != pointers_address {
            return Ok(STATUS_INVALID_PARAMETER_2);
        }
    }
    // SAFETY: SECTION_OBJECT_POINTERS do FCB do file system dono do arquivo.
    let pointers = unsafe { SectionObjectPointers::at(pointers_address) };
    let slot: &Field<u64> = match section {
        BackingSection::Data => &pointers.data_section_object,
        BackingSection::Image => &pointers.image_section_object,
    };
    let replaced = loop {
        let address = slot.get();
        if address == 0 {
            return Ok(0);
        }
        // SAFETY: CONTROL_AREA publicada na SOP pelo Mm.
        let control_area = unsafe { ControlArea::at(address) };
        let lock = control_area.control_area_lock.address();
        let previous = spin_lock::acquire_exclusive(lock);
        if slot.get() != address {
            spin_lock::release_exclusive(lock, previous)?;
            continue;
        }
        let replaced = replace_under_lock(control_area, current, new);
        spin_lock::release_exclusive(lock, previous)?;
        break replaced;
    };
    if let Some((old, cached)) = replaced {
        // ObFastReplaceObject + ObfReferenceObjectWithTag(new) +
        // ObDereferenceObjectDeferDeleteWithTag(old).
        for _ in 0..MAX_FAST_REFS + 1 {
            object_reference::reference_with_tag(new.address(), TAG, false)?;
        }
        for _ in 0..cached + 1 {
            object_reference::dereference_with_tag(old, TAG, false)?;
        }
    }
    Ok(0)
}
