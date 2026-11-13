//! MmMapViewInSystemSpace(Ex).
//!
//! A ordem das leituras e escritas segue o wrapper original, inclusive com
//! buffers sobrepostos. O mapeamento pertence ao provedor de seções e usa
//! PFNs e PTEs reais.

use alloc::sync::Arc;

use crate::ntos::mm::{system_image_pages, system_view_paging};
use crate::ntos::ke::irql;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::user::sections::{self, MapRequest, Section, View};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

fn status_of<T>(error: KernelError) -> Result<Result<T, u32>, KernelError> {
    if error.status != 0 {
        Ok(Err(error.status))
    } else {
        Err(error)
    }
}

/// MiInsertInSystemSpace: reserva menor que 65536 blocos de 64 KiB, vista
/// global com commit integral para imagens e registro na paginação.
pub fn insert(section: &Arc<Section>, size: u64, offset: u64, flags: u64) -> Result<Result<Arc<View>, u32>, KernelError> {
    if size > 0xFFFF_0000 {
        return Ok(Err(0xC000_001F));
    }
    if size == 0 || offset >= section.size {
        return Ok(Err(0xC000_0017));
    }
    if offset as u128 + size as u128 > section.size as u128 {
        return Ok(Err(0xC000_001F));
    }
    if let Err(error) = system_image_pages::prepare(section) {
        return status_of(error);
    }
    let request = MapRequest { size, offset, protect: section.page_protect(), supervisor: true, system_space: true, flexible_large: true, commit_size: if section.is_image { size } else { 0 }, ..MapRequest::default() };
    let mapped = match sections::map(section, &request) {
        Ok(mapped) => mapped,
        Err(error) => return status_of(error),
    };
    let view = match mapped {
        Ok(view) => view,
        Err(status) => return Ok(Err(status)),
    };
    if let Err(error) = system_view_paging::register(&view, flags) {
        sections::unmap(&view, None)?;
        return status_of(error);
    }
    Ok(Ok(view))
}

/// A entrada sem Ex mantém o offset zero na pilha do kernel original:
/// `None` representa só esse valor local, nunca um ponteiro do convidado.
fn read_section_offset(offset_pointer: Option<u64>) -> Result<u64, KernelError> {
    offset_pointer.map_or(Ok(0), guest::try_read64)
}

fn align_section_offset(offset_pointer: Option<u64>) -> Result<(), KernelError> {
    match offset_pointer {
        Some(pointer) => guest::try_write16(pointer, 0),
        None => Ok(()),
    }
}

fn map_with_offset(section_pointer: u64, base_pointer: u64, size_pointer: u64, offset_pointer: Option<u64>, flags: u64) -> Result<u32, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("system view mapping above APC_LEVEL"));
    }
    if flags & !1 != 0 {
        return Ok(0xC000_00F4);
    }
    let Some(section) = sections::by_pointer(section_pointer).filter(|_| section_objects::is_section(section_pointer)) else { return Err(KernelError::new("invalid SECTION pointer for system view")) };
    section_objects::reference(section_pointer);
    let result = (|| -> Result<u32, KernelError> {
        let size = guest::try_read64(size_pointer)?;
        if size != 0 {
            let delta = match offset_pointer {
                Some(pointer) => (guest::try_read32(pointer)? & 0xFFFF) as u64,
                None => 0,
            };
            let Some(total) = size.checked_add(delta) else { return Ok(0xC000_001F) };
            guest::try_write64(size_pointer, total)?;
            align_section_offset(offset_pointer)?;
            let remaining = guest::try_read64(section_pointer + 0x30)?.wrapping_sub(read_section_offset(offset_pointer)?);
            if guest::try_read64(size_pointer)? > remaining {
                return Ok(0xC000_001F);
            }
        } else {
            align_section_offset(offset_pointer)?;
            let whole = guest::try_read64(section_pointer + 0x30)?.wrapping_sub(read_section_offset(offset_pointer)?);
            guest::try_write64(size_pointer, whole)?;
        }
        let view = match insert(&section, guest::try_read64(size_pointer)?, read_section_offset(offset_pointer)?, flags)? {
            Ok(view) => view,
            Err(status) => return Ok(status),
        };
        if let Err(error) = guest::try_write64(base_pointer, view.base) {
            sections::unmap(&view, None)?;
            return Err(error);
        }
        Ok(0)
    })();
    section_objects::dereference(section_pointer)?;
    result
}

/// MmMapViewInSystemSpaceEx: um offset nulo continua acesso inválido.
pub fn map(section_pointer: u64, base_pointer: u64, size_pointer: u64, offset_pointer: u64, flags: u64) -> Result<u32, KernelError> {
    map_with_offset(section_pointer, base_pointer, size_pointer, Some(offset_pointer), flags)
}

/// MmMapViewInSystemSpace: ViewSize zero publica o tamanho integral.
pub fn map_from_start(section_pointer: u64, base_pointer: u64, size_pointer: u64) -> Result<u32, KernelError> {
    map_with_offset(section_pointer, base_pointer, size_pointer, None, 0)
}
