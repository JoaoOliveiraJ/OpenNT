//! NtMapViewOfSection — `system32/ntos/mm/map-view.js`.
//!
//! Captura todos os ponteiros do chamador antes de anexar ao alvo, valida
//! pelo `map-view-parameters` e recusa (em vez de converter em vista comum)
//! as políticas ainda sem implementação real: PAGE_GUARD, CFG e promoção a
//! páginas grandes. Vistas de imagem passam por `mm/section-image-view`
//! (loader de usuário).

use crate::ntos::mm::section::map_view_parameters::{self, Decoded, MapInput, SectionTraits};
use crate::ntos::mm::section::handles::{self as section_handles, Kind, Reference};
use crate::ntos::mm::section::views::{self as section_views, OwnedView};
use crate::ntos::ke::irql;
use crate::ntos::ps::user::sections::{self, MapRequest};
use crate::ntos::ps::user::state::{self, RegionKind};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::eprocess;

#[allow(clippy::too_many_arguments)]
pub fn map(section_handle: u64, process_handle: u64, base_pointer: u64, zero_bits: u64, commit_size: u64, offset_pointer: u64, size_pointer: u64, inherit: u32, allocation: u32, protect: u32, mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("section mapping requires PASSIVE_LEVEL"));
    }
    let prefix = match map_view_parameters::prefix(zero_bits, protect) {
        Ok(prefix) => prefix,
        Err(status) => return Ok(status),
    };
    let process = match section_handles::reference(process_handle, Kind::Process, 8, mode) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    let mut section_reference: Option<Reference> = None;
    let result = (|| -> Result<u32, KernelError> {
        let reference = match section_handles::reference(section_handle, Kind::Section, prefix.access, mode) {
            Ok(reference) => section_reference.insert(reference),
            Err(status) => return Ok(status),
        };
        // O NT captura os ponteiros do chamador antes de anexar ao alvo.
        if mode != 0 && offset_pointer % 4 != 0 {
            return Ok(0x8000_0002);
        }
        if mode != 0 && (!state::probe_user_write(base_pointer, 8) || !state::probe_user_write(size_pointer, 8) || (offset_pointer != 0 && !state::probe_user_write(offset_pointer, 8))) {
            return Ok(0xC000_0005);
        }
        let captured = (|| -> Result<(u64, u64, u64), KernelError> { Ok((guest::try_read64(base_pointer)?, guest::try_read64(size_pointer)?, if offset_pointer != 0 { guest::try_read64(offset_pointer)? } else { 0 })) })();
        let Ok((base, size, offset)) = captured else { return Ok(0xC000_0005) };
        let Some(section) = reference.section.clone() else { return Ok(0xC000_0024) };
        let traits = SectionTraits { is_image: section.is_image, size: section.size, page_protect: section.page_protect(), cache_flags: section.state.lock().cache_flags };
        let input = MapInput { zero: zero_bits, protect, base, size, offset, allocation, inherit, numa_nodes: 0, commit: commit_size };
        let request = match map_view_parameters::decode(&traits, &input, Some(prefix)) {
            Decoded::Status(status) => return Ok(status),
            Decoded::Boundary(reason) => Err(reason),
            Decoded::View(view) => Ok(view),
        };
        if process.process_terminating() {
            return Ok(0xC000_010A);
        }
        let boundary = match &request {
            Err(reason) => Some(*reason),
            Ok(view) if view.protect & 0x100 != 0 => Some("guard"),
            Ok(_) if protect & 0x4000_0000 != 0 => Some("cfg"),
            Ok(view) if view.allocation & 0x2000_0000 != 0 && !section.large => Some("promote-large-pages"),
            Ok(_) => None,
        };
        if let Some(reason) = boundary {
            let name = section.file.as_ref().and_then(|file| file.nt_path()).or_else(|| section.name()).unwrap_or_default();
            debug_print!("[section-map-boundary] reason={} image={} name={} allocation=0x{:x} protect=0x{:x} section=0x{:x}", reason, section.is_image as u8, name, allocation, protect, section_handle);
            return Ok(0xC000_00BB);
        }
        let Ok(request) = request else { return Ok(0xC000_00BB) };
        if section.no_execute && protect != 2 {
            return Ok(0xC000_0045);
        }
        let pid = guest::read64(process.pointer + eprocess::UNIQUE_PROCESS_ID);
        let active = pid == state::with(|state| state.current_process_id);
        let regions = if !active {
            RegionKind::Detached
        } else if section.is_image {
            RegionKind::ProcessImages
        } else {
            RegionKind::User
        };
        if section.is_image {
            let mapped = match crate::ntos::mm::section::image_view::map(&section, &request, process.pointer, regions)? {
                Ok(mapped) => mapped,
                Err(status) => return Ok(status),
            };
            let written = guest::try_write64(base_pointer, mapped.view.base).and_then(|_| guest::try_write64(size_pointer, mapped.view.size)).and_then(|_| if offset_pointer != 0 { guest::try_write64(offset_pointer, mapped.offset) } else { Ok(()) });
            if written.is_err() {
                section_views::unmap(&OwnedView::Image(mapped.view))?;
                return Ok(0xC000_0005);
            }
            return Ok(mapped.status);
        }
        let mapped = sections::map(
            &section,
            &MapRequest {
                base: request.base,
                size: request.size,
                offset: request.offset,
                protect: request.protect,
                commit_size: request.commit,
                alignment: request.alignment,
                upper: Some(request.upper),
                reserve: request.allocation & 0x2000 != 0,
                top_down: request.allocation & 0x10_0000 != 0,
                no_change: request.allocation & 0x40_0000 != 0,
                regions: Some(regions),
                owner_process: Some(process.pointer),
                inherit: request.inherit,
                ..MapRequest::default()
            },
        )?;
        let view = match mapped {
            Ok(view) => view,
            Err(status) => return Ok(status),
        };
        let written = guest::try_write64(base_pointer, view.base).and_then(|_| guest::try_write64(size_pointer, view.size)).and_then(|_| if offset_pointer != 0 { guest::try_write64(offset_pointer, view.offset) } else { Ok(()) });
        if written.is_err() {
            section_views::unmap(&OwnedView::Data(view))?;
            return Ok(0xC000_0005);
        }
        Ok(0)
    })();
    if let Some(reference) = section_reference {
        reference.release()?;
    }
    process.release()?;
    result
}

/// NtUnmapViewOfSection.
pub fn unmap(process_handle: u64, base: u64, mode: u8) -> Result<u32, KernelError> {
    crate::ntos::mm::section::unmap_view::unmap(process_handle, base, mode)
}
