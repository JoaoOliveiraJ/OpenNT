//! NtQueryVirtualMemory de usuário — `system32/ntos/ps/user/memory-query.js`.
//!
//! Layouts NT x64 distintos por classe (phnt/ntmmapi.h,
//! MEMORY_INFORMATION_CLASS). `describe` também serve ao serviço de kernel
//! (`mm/query-virtual`), com o contexto de regiões do processo alvo.

use alloc::string::String;
use alloc::vec::Vec;

use super::state::{self, Region};
use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT as MAX_USER;
use crate::ntos::mm::paging;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const PAGE: u64 = 0x1000;

/// Regiões consultadas (`context` do original; o padrão é o estado `S`).
#[derive(Clone, Default)]
pub struct Context {
    pub user_regions: Vec<Region>,
    pub process_images: Vec<Region>,
}

impl Context {
    pub fn current() -> Self {
        state::with(|state| Self { user_regions: state.user_regions.clone(), process_images: state.process_images.clone() })
    }

    fn is_image(&self, region: &Region) -> bool {
        self.process_images.iter().any(|image| state::same_region(image, region))
    }
}

/// Uma faixa homogênea a partir do endereço.
#[derive(Clone)]
pub struct Info {
    pub base: u64,
    pub size: u64,
    pub allocation_base: u64,
    pub protect: u32,
    pub allocation_protect: u32,
    pub state: u32,
    pub kind: u32,
    pub region: Option<Region>,
    pub image: Option<Region>,
}

pub fn page_protection(region: &Region, index: u64, context: &Context) -> u32 {
    region.page_protect(index).filter(|&protect| protect != 0).unwrap_or_else(|| match region.protect() {
        0 => {
            if context.is_image(region) {
                0x40
            } else {
                4
            }
        }
        protect => protect,
    })
}

fn contains(region: &Region, va: u64) -> bool {
    va >= region.base() && va < region.base() + region.size()
}

/// Região livre até a próxima alocação, ou a faixa da região com o mesmo
/// estado de commit e a mesma proteção.
pub fn describe(va: u64, context: &Context) -> Info {
    let base = va & !(PAGE - 1);
    let image = context.process_images.iter().find(|region| contains(region, va)).cloned();
    let region = image.clone().or_else(|| context.user_regions.iter().find(|region| contains(region, va)).cloned());
    let Some(region) = region else {
        let mut end = MAX_USER;
        for candidate in context.user_regions.iter().chain(context.process_images.iter()) {
            if candidate.base() > base && candidate.base() < end {
                end = candidate.base();
            }
        }
        return Info { base, size: end - base, allocation_base: 0, protect: 0, allocation_protect: 0, state: 0x10000, kind: 0, region: None, image: None };
    };
    let index = (base - region.base()) / PAGE;
    let pages = region.committed_pages();
    let committed = match &pages {
        Some(pages) => pages.contains(&index),
        None => image.is_some() || region.committed() || paging::translate(base) != 0,
    };
    let mut end = region.base() + region.size();
    let protection = page_protection(&region, index, context);
    for page in index + 1..region.size() / PAGE {
        let next_committed = pages.as_ref().map_or(committed, |pages| pages.contains(&page));
        if next_committed != committed || (committed && page_protection(&region, page, context) != protection) {
            end = region.base() + page * PAGE;
            break;
        }
    }
    let allocation_protect = match (region.allocation_protect(), region.protect()) {
        (0, 0) => {
            if image.is_some() {
                0x40
            } else {
                4
            }
        }
        (0, protect) => protect,
        (protect, _) => protect,
    };
    let kind = if image.is_some() {
        0x0100_0000
    } else if region.section().is_some() {
        0x4_0000
    } else {
        0x2_0000
    };
    Info { base, size: end - base, allocation_base: region.base(), allocation_protect, protect: if committed { protection } else { 0 }, state: if committed { 0x1000 } else { 0x2000 }, kind, region: Some(region), image }
}

/// `NativeFileName.fromView`: arquivo da seção, senão o nome nativo.
pub fn view_name(region: &Region) -> Option<String> {
    if let Some(file) = region.section().and_then(|section| section.file.clone()) {
        return file.nt_path().filter(|name| name.starts_with('\\'));
    }
    region.name().filter(|name| name.starts_with('\\'))
}

/// Páginas confirmadas da região (`committedPages.size`), ou a região
/// inteira quando confirmada sem rastreio por página.
pub fn committed_bytes(info: &Info) -> u64 {
    let Some(region) = &info.region else { return 0 };
    match region.committed_pages() {
        Some(pages) => pages.len() as u64 * PAGE,
        None if info.state == 0x1000 => region.size(),
        None => 0,
    }
}

/// O syscall de usuário NtQueryVirtualMemory (processo corrente).
pub fn query_virtual_memory(_process: u64, base_va: u64, info_class: u64, buffer_va: u64, user_rsp: u64) -> Result<u32, KernelError> {
    let class = info_class as u32;
    let length = state::stack_arg(user_rsp, 5);
    let return_length = state::stack_arg(user_rsp, 6);
    if base_va >= MAX_USER {
        return Ok(0xC000_000D);
    }
    if length > (1 << 53) - 1 {
        return Ok(0xC000_000D);
    }
    if return_length != 0 && !state::probe_user_write(return_length, 8) {
        return Ok(0xC000_0005);
    }
    let prepare = |need: u64| -> u32 {
        if return_length != 0 {
            guest::write64(return_length, need);
        }
        if length < need {
            return 0xC000_0004;
        }
        if buffer_va == 0 || !state::probe_user_write(buffer_va, need) {
            return 0xC000_0005;
        }
        0
    };
    let context = Context::current();
    let info = describe(base_va, &context);
    match class {
        0 => {
            let status = prepare(0x30);
            if status != 0 {
                return Ok(status);
            }
            guest::write64(buffer_va, info.base);
            guest::write64(buffer_va + 8, info.allocation_base);
            guest::write32(buffer_va + 16, info.allocation_protect);
            guest::write32(buffer_va + 20, 0);
            guest::write64(buffer_va + 24, info.size);
            guest::write32(buffer_va + 32, info.state);
            guest::write32(buffer_va + 36, info.protect);
            guest::write32(buffer_va + 40, info.kind);
            guest::write32(buffer_va + 44, 0);
            Ok(0)
        }
        2 => {
            let Some(name) = info.image.as_ref().or(info.region.as_ref()).and_then(view_name) else { return Ok(0xC000_0019) };
            let status = prepare(16 + (name.encode_utf16().count() as u64 + 1) * 2);
            if status != 0 {
                return Ok(status);
            }
            state::write_user_wide(buffer_va + 16, &name);
            state::write_unicode_string(buffer_va, buffer_va + 16, &name);
            Ok(0)
        }
        3 | 7 => {
            let need = if length >= 0x30 { 0x30 } else { 0x20 };
            let status = prepare(need);
            if status != 0 {
                return Ok(status);
            }
            let Some(region) = &info.region else { return Ok(0xC000_00A0) };
            let kind = if info.image.is_some() {
                4
            } else {
                match region.section() {
                    Some(section) if section.file.is_some() => 2,
                    Some(_) => 8,
                    None => 1,
                }
            };
            guest::write64(buffer_va, info.allocation_base);
            guest::write32(buffer_va + 8, info.allocation_protect);
            guest::write32(buffer_va + 12, kind);
            guest::write64(buffer_va + 16, region.size());
            guest::write64(buffer_va + 24, committed_bytes(&info));
            if need == 0x30 {
                guest::write64(buffer_va + 32, 0);
                guest::write64(buffer_va + 40, 0);
            }
            Ok(0)
        }
        4 => {
            // Vetor MEMORY_WORKING_SET_EX_INFORMATION (entrada e saída).
            if length == 0 || length % 16 != 0 {
                return Ok(0xC000_0004);
            }
            let status = prepare(length);
            if status != 0 {
                return Ok(status);
            }
            let mut offset = 0;
            while offset < length {
                let va = guest::read64(buffer_va + offset);
                let page = describe(va, &context);
                let valid = va < MAX_USER && paging::translate(va) != 0;
                guest::write64(buffer_va + offset + 8, if valid { 1 + page.protect as u64 * 16 } else { 0 });
                offset += 16;
            }
            Ok(0)
        }
        6 => {
            // MEMORY_IMAGE_INFORMATION.
            let status = prepare(24);
            if status != 0 {
                return Ok(status);
            }
            let Some(image) = &info.image else { return Ok(0xC000_0019) };
            guest::write64(buffer_va, image.base());
            guest::write64(buffer_va + 8, image.size());
            guest::write32(buffer_va + 16, 0);
            guest::write32(buffer_va + 20, 0);
            Ok(0)
        }
        _ => Ok(0xC000_0003),
    }
}
