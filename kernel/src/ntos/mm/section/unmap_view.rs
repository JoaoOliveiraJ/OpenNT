//! NtUnmapViewOfSection.
//!
//! Uma falha síncrona de writeback conserva a vista e o backing: o chamador
//! pode repetir sem perder bytes sujos.

use alloc::sync::Arc;

use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
use crate::ntos::mm::section::handles::{self as section_handles, Kind};
use crate::ntos::mm::section::views::{self as section_views, ImageView, OwnedView};
use crate::ntos::ke::irql;
use crate::ntos::ps::user::sections::View;
use crate::ntos::ps::user::state::{self, RegionKind};
use crate::rtl::KernelError;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;

/// Base de usuário acima do limite = MEMORY_NOT_ALLOCATED (só modo usuário).
pub fn validate_base(base: u64, mode: u8) -> u32 {
    if mode == 1 && base >= USER_ADDRESS_LIMIT {
        0xC000_0019
    } else {
        0
    }
}

pub fn unmap(handle: u64, base: u64, mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("section unmapping requires PASSIVE_LEVEL"));
    }
    let status = validate_base(base, mode);
    if status != 0 {
        return Ok(status);
    }
    let process = match section_handles::reference(handle, Kind::Process, 8, mode) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    let result = (|| -> Result<u32, KernelError> {
        if process.process_terminating() {
            return Ok(0xC000_010A);
        }
        let contains = |region_base: u64, size: u64| base >= region_base && base < region_base + size;
        let mut view = section_views::find(process.pointer, base);
        if view.is_none() && unsafe { Eprocess::at(process.pointer) }.unique_process_id.get() == state::with(|state| state.current_process_id) {
            let (data, image) = state::with(|state| {
                let data = state.user_regions.iter().find(|region| region.as_any().downcast_ref::<View>().is_some() && contains(region.base(), region.size())).cloned();
                let image = state.process_images.iter().find(|region| contains(region.base(), region.size())).cloned();
                (data, image)
            });
            view = data.and_then(|region| sections_view(&region)).map(OwnedView::Data);
            if view.is_none() {
                if let Some(image) = image.and_then(|region| image_view(&region)) {
                    *image.regions.lock() = Some(RegionKind::ProcessImages);
                    view = Some(OwnedView::Image(image));
                }
            }
        }
        let Some(view) = view else { return Ok(0xC000_0019) };
        match section_views::unmap(&view) {
            Ok(()) => Ok(0),
            Err(error) if error.status != 0 => Ok(error.status),
            Err(error) => Err(error),
        }
    })();
    process.release()?;
    result
}

/// A vista de dados viva com a mesma identidade da região.
fn sections_view(region: &state::Region) -> Option<Arc<View>> {
    crate::ntos::ps::user::sections::views().into_iter().find(|view| {
        let candidate: state::Region = view.clone();
        state::same_region(&candidate, region)
    })
}

/// A vista de imagem registrada com a mesma identidade da região.
fn image_view(region: &state::Region) -> Option<Arc<ImageView>> {
    section_views::all().into_iter().find_map(|view| match view {
        OwnedView::Image(image) => {
            let candidate: state::Region = image.clone();
            state::same_region(&candidate, region).then_some(image)
        }
        OwnedView::Data(_) => None,
    })
}
