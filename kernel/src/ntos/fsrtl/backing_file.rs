//! FsRtlChangeBackingFileObject (RVA 0x394790 no ntoskrnl 19045): troca o
//! FILE_OBJECT que sustenta a seção de dados, a de imagem ou o shared cache
//! map de um stream.
//!
//! Flags diferente de zero -> STATUS_INVALID_PARAMETER_4. ChangeBackingType:
//! 0 ChangeDataControlArea -> MmChangeSectionBackingFile(.., 1);
//! 1 ChangeImageControlArea -> MmChangeSectionBackingFile(.., 2);
//! 2 ChangeSharedCacheMap -> CcChangeBackingFileObject (Cache Manager);
//! outro -> STATUS_INVALID_PARAMETER_3.

use crate::ntos::cc::cache_map;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::FileObject;
use crate::ntos::mm::section::backing_file::{self, BackingSection, STATUS_INVALID_PARAMETER_3};
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const CHANGE_DATA_CONTROL_AREA: u32 = 0;
const CHANGE_IMAGE_CONTROL_AREA: u32 = 1;
const CHANGE_SHARED_CACHE_MAP: u32 = 2;

/// FsRtlChangeBackingFileObject(CurrentFileObject, NewFileObject,
/// ChangeBackingType, Flags) -> NTSTATUS. `current` é opcional (NULL troca
/// qualquer arquivo associado).
pub fn change_backing_file_object(current: Option<&FileObject>, new: &FileObject, change_type: u32, flags: u32) -> Result<u32, KernelError> {
    if flags != 0 {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    match change_type {
        CHANGE_DATA_CONTROL_AREA => backing_file::change_section_backing_file(current, new, BackingSection::Data),
        CHANGE_IMAGE_CONTROL_AREA => backing_file::change_section_backing_file(current, new, BackingSection::Image),
        CHANGE_SHARED_CACHE_MAP => cache_map::change_backing_file_object(current.map_or(0, |file| file.address()), new.address()),
        _ => Ok(STATUS_INVALID_PARAMETER_3),
    }
}
