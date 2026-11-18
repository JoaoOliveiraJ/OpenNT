//! NtUnmapViewOfSection / NtUnmapViewOfSectionEx.
//!
//! Uma falha síncrona de writeback conserva a vista e o backing: o chamador
//! pode repetir sem perder bytes sujos.
//!
//! Como o NtUnmapViewOfSectionEx (rva 0x61e440) e o MiUnmapViewOfSection
//! (rva 0x61e510) do 19041:
//! - Flags além de MEM_UNMAP_WITH_TRANSIENT_BOOST (1) e
//!   MEM_PRESERVE_PLACEHOLDER (2) dão STATUS_INVALID_PARAMETER_3 antes de
//!   tudo; o NtUnmapViewOfSection é o Ex com Flags 0 e o MmUnmapViewOfSection
//!   chama o MiUnmapViewOfSection com Flags 0.
//! - Com MEM_PRESERVE_PLACEHOLDER, uma base fora do começo de página dá
//!   STATUS_INVALID_PARAMETER_2 (depois do handle). Depois da busca do VAD e
//!   da checagem de segurança, a base precisa ser o começo do VAD e o VAD
//!   precisa ter sido mapeado sobre um placeholder (o evento 0x80 do VAD);
//!   senão STATUS_CONFLICTING_ADDRESSES. O OpenNT não mapeia vistas sobre
//!   placeholders (MEM_REPLACE_PLACEHOLDER é recusado no
//!   `map_view_parameters`), então toda vista dá essa resposta.
//! - MEM_UNMAP_WITH_TRANSIENT_BOOST só chega ao MiDeleteVad (flag 4 do
//!   MiDeletePagablePteRange): as páginas soltas vão para a lista de espera
//!   com prioridade aumentada. O OpenNT não tem prioridade de página na
//!   lista de espera; a vista desmapeia igual.
//! - Uma vista com uma faixa protegida por MmSecureVirtualMemory recusa com
//!   STATUS_INVALID_PAGE_PROTECTION (o MiCheckSecuredVad da remoção sobre o
//!   VAD inteiro, num processo sem VmDeleted), em qualquer modo; uma vista
//!   SEC_NO_CHANGE sem faixa protegida desmapeia normalmente, também de modo
//!   usuário (`mm/secure_memory.rs`).
//! - Um processo saindo só recusa com STATUS_PROCESS_IS_TERMINATING depois do
//!   EPROCESS.Flags.VmDeleted (o MiObtainReferencedVadEx, 0x21b31d), que o
//!   MmCleanProcessAddressSpace liga depois do callout de saída do win32k:
//!   no callout e nas rotinas de saída as vistas do processo que sai ainda
//!   desmapeiam (CddBitmapSw::OnCloseProcess e Release do cdd). O
//!   MiUnmapViewOfSection anexa sozinho a um alvo que não é o corrente.

use alloc::sync::Arc;

use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
use crate::ntos::mm::secure_memory;
use crate::ntos::mm::section::handles::{self as section_handles, Kind};
use crate::ntos::mm::section::views::{self as section_views, ImageView, OwnedView};
use crate::ntos::ke::irql;
use crate::ntos::ps::user::memory::Space;
use crate::ntos::ps::user::sections::View;
use crate::ntos::ps::user::state::{self, RegionKind};
use crate::rtl::KernelError;

/// MEM_UNMAP_WITH_TRANSIENT_BOOST.
pub const MEM_UNMAP_WITH_TRANSIENT_BOOST: u32 = 0x1;
/// MEM_PRESERVE_PLACEHOLDER.
pub const MEM_PRESERVE_PLACEHOLDER: u32 = 0x2;

const STATUS_NOT_MAPPED_VIEW: u32 = 0xC000_0019;
const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;

/// Base de usuário acima do limite = STATUS_NOT_MAPPED_VIEW (só modo usuário).
pub fn validate_base(base: u64, mode: u8) -> u32 {
    if mode == 1 && base >= USER_ADDRESS_LIMIT {
        STATUS_NOT_MAPPED_VIEW
    } else {
        0
    }
}

/// NtUnmapViewOfSection = NtUnmapViewOfSectionEx com Flags 0.
pub fn unmap(handle: u64, base: u64, mode: u8) -> Result<u32, KernelError> {
    unmap_ex(handle, base, mode, 0)
}

/// NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, Flags).
pub fn unmap_ex(handle: u64, base: u64, mode: u8, flags: u32) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("section unmapping requires PASSIVE_LEVEL"));
    }
    if flags & !(MEM_UNMAP_WITH_TRANSIENT_BOOST | MEM_PRESERVE_PLACEHOLDER) != 0 {
        return Ok(STATUS_INVALID_PARAMETER_3);
    }
    let status = validate_base(base, mode);
    if status != 0 {
        return Ok(status);
    }
    let process = match section_handles::reference(handle, Kind::Process, 8, mode) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    let preserve_placeholder = flags & MEM_PRESERVE_PLACEHOLDER != 0;
    let result = (|| -> Result<u32, KernelError> {
        if preserve_placeholder && base & 0xFFF != 0 {
            return Ok(STATUS_INVALID_PARAMETER_2);
        }
        // Só o VmDeleted recusa (MiObtainReferencedVadEx 0x21b31d): no callout
        // de saída do win32k o processo que sai ainda desmapeia.
        if process.process_vm_deleted() {
            return Ok(0xC000_010A);
        }
        let contains = |region_base: u64, size: u64| base >= region_base && base < region_base + size;
        let mut view = section_views::find(process.pointer, base);
        if view.is_none() {
            // As vistas do VAD do processo alvo sem registro de posse.
            let space = Space::of(process.pointer);
            let data = space.regions().into_iter().find(|region| region.as_any().downcast_ref::<View>().is_some() && contains(region.base(), region.size()));
            let image = space.images().into_iter().find(|region| contains(region.base(), region.size()));
            view = data.and_then(|region| sections_view(&region)).map(OwnedView::Data);
            if view.is_none() {
                if let Some(image) = image.and_then(|region| image_view(&region)) {
                    *image.regions.lock() = Some(RegionKind::ProcessImages);
                    view = Some(OwnedView::Image(image));
                }
            }
        }
        let Some(view) = view else { return Ok(STATUS_NOT_MAPPED_VIEW) };
        // MiCheckSecuredVad(0x55) do VAD inteiro: uma faixa do
        // MmSecureVirtualMemory na vista recusa a remoção.
        if !secure_memory::vm_deleted(process.pointer) {
            let secured = secure_memory::check_vad(process.pointer, &view.region(), view.base(), view.size(), secure_memory::PROBE_DELETE);
            if secured != 0 {
                return Ok(secured);
            }
        }
        // MEM_PRESERVE_PLACEHOLDER: a base no começo do VAD e o placeholder
        // de onde a vista veio (nenhuma vista do OpenNT veio de um).
        if preserve_placeholder {
            return Ok(STATUS_CONFLICTING_ADDRESSES);
        }
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
