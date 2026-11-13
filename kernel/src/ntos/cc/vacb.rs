//! Vistas do cache (VACBs), como no Cache Manager do NT.
//!
//! Cada vista cobre VACB_MAPPING_GRANULARITY (256 KB) alinhados do arquivo e
//! é memória de sistema contínua com PFNs independentes
//! (`mm::independent_pages`), dona dos dados em cache. O estado por página
//! (válida, suja, em leitura, em escrita) são máscaras de 64 bits. Um `Vacb`
//! nativo (BaseAddress, SharedCacheMap, FileOffset|ActiveCount) acompanha a
//! vista: CcMapData devolve `vacb | 1`, como o NT.
//!
//! As vistas são criadas sob demanda; acima do orçamento a vista limpa e sem
//! referências menos usada é reciclada. Alocar e liberar páginas mexe nas
//! tabelas e nos TLBs, então acontece fora do lock do Cc.
//!
//! Também ficam aqui as cópias entre a memória do cache e a do chamador: o
//! buffer do chamador pode ser de modo usuário, então passa pelas cópias
//! sondadas de `guest_memory` (STATUS_ACCESS_VIOLATION vira o
//! STATUS_INVALID_USER_BUFFER do CcCopyRead/CcCopyWrite).

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::cache_map::{CacheManager, View, CACHE};
use super::layout::{self, PAGE_SIZE, VIEW_SHIFT, VIEW_SIZE};
use super::status::{CcResult, Failure};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_cc::Vacb;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::independent_pages;
use crate::rtl::KernelError;

/// Orçamento de vistas (32 MB de cache) antes de reciclar vistas limpas.
pub const VIEW_BUDGET: u64 = 128;

pub fn view_index(offset: u64) -> u64 {
    offset >> VIEW_SHIFT
}

pub fn view_offset(index: u64) -> u64 {
    index << VIEW_SHIFT
}

/// O `Vacb` nativo de uma vista.
pub fn vacb_at(address: u64) -> &'static Vacb {
    // SAFETY: VACB alocado por `ensure_view` (ou o `vacb | 1` que o Cc devolveu
    // ao file system, já sem a marca).
    unsafe { Vacb::at(address) }
}

/// Páginas [first, last] (inclusivo) de uma vista.
pub fn page_mask(first: u64, last: u64) -> u64 {
    if first > last || first >= layout::PAGES_PER_VIEW {
        return 0;
    }
    let high = if last >= 63 { u64::MAX } else { (1u64 << (last + 1)) - 1 };
    high & (u64::MAX << first)
}

/// Páginas da vista `index` tocadas pelo intervalo de bytes [start, end).
pub fn range_mask(index: u64, start: u64, end: u64) -> u64 {
    let view_start = view_offset(index);
    let view_end = view_start + VIEW_SIZE;
    let (low, high) = (start.max(view_start), end.min(view_end));
    if low >= high {
        return 0;
    }
    page_mask((low - view_start) / PAGE_SIZE, (high - 1 - view_start) / PAGE_SIZE)
}

/// Vistas tocadas por [start, end).
pub fn views_in(start: u64, end: u64) -> core::ops::RangeInclusive<u64> {
    if end <= start {
        return 1..=0;
    }
    view_index(start)..=view_index(end - 1)
}

/// Libera páginas e VACB de vistas já retiradas da tabela (fora do lock).
pub fn free_views(views: Vec<View>) {
    for view in views {
        if let Err(error) = independent_pages::free(view.base) {
            debug_print!("[cc] view {:#x} release failed: {}", view.base, error);
        }
        guest::free_bytes(view.vacb);
    }
}

/// Retira as vistas limpas e sem uso menos recentes até caber no orçamento.
fn evict(cache: &mut CacheManager) -> Vec<View> {
    let mut retired = Vec::new();
    while cache.view_count >= VIEW_BUDGET {
        let mut victim: Option<(u64, u64, u64)> = None;
        for (&base, map) in cache.maps.iter() {
            for (&index, view) in map.views.iter() {
                let idle = view.refs == 0 && view.dirty == 0 && view.reading == 0 && view.writing == 0;
                if idle && victim.is_none_or(|(_, _, last)| view.last_use < last) {
                    victim = Some((base, index, view.last_use));
                }
            }
        }
        let Some((base, index, _)) = victim else { break };
        if let Some(view) = cache.maps.get_mut(&base).and_then(|map| map.views.remove(&index)) {
            cache.view_count -= 1;
            retired.push(view);
        }
    }
    retired
}

/// Garante a vista `index` do mapa `base`. Não chamar com o lock preso.
pub fn ensure_view(base: u64, index: u64) -> CcResult<()> {
    let retired = {
        let mut cache = CACHE.lock();
        let Some(map) = cache.maps.get(&base) else { return Err(Failure::Kernel(KernelError::new("cache map vanished"))) };
        if map.views.contains_key(&index) {
            return Ok(());
        }
        evict(&mut cache)
    };
    free_views(retired);
    let memory = independent_pages::allocate(VIEW_SIZE, 0)?;
    if memory == 0 {
        return Err(Failure::Raise(layout::status::INSUFFICIENT_RESOURCES));
    }
    let vacb = guest::alloc_bytes(Vacb::SIZE);
    if vacb == 0 {
        let _ = independent_pages::free(memory);
        return Err(Failure::Raise(layout::status::INSUFFICIENT_RESOURCES));
    }
    let native = vacb_at(vacb);
    native.base_address.set(memory);
    native.shared_cache_map.set(base);
    native.overlay.file_offset.quad_part.set(view_offset(index) as i64);
    let view = View { base: memory, vacb, valid: 0, dirty: 0, reading: 0, writing: 0, refs: 0, maps: 0, last_use: 0 };
    let unused = {
        let mut cache = CACHE.lock();
        cache.tick += 1;
        let tick = cache.tick;
        let installed = match cache.maps.get_mut(&base) {
            Some(map) if !map.views.contains_key(&index) => {
                map.views.insert(index, View { last_use: tick, ..view });
                true
            }
            _ => false,
        };
        if installed {
            cache.view_count += 1;
            None
        } else {
            Some(view)
        }
    };
    if let Some(view) = unused {
        free_views(alloc::vec![view]);
    }
    Ok(())
}

/// Marca uso recente (LRU).
pub fn touch(cache: &mut CacheManager, base: u64, index: u64) {
    cache.tick += 1;
    let tick = cache.tick;
    if let Some(view) = cache.maps.get_mut(&base).and_then(|map| map.views.get_mut(&index)) {
        view.last_use = tick;
    }
}

/// ActiveCount do VACB nativo (16 bits baixos de Overlay.FileOffset).
pub fn publish_active_count(view: &View) {
    vacb_at(view.vacb).overlay.active_count.atomic().store(view.maps as u16, Ordering::SeqCst);
}

/// (mapa, vista) de um VACB nativo.
pub fn owner_of_vacb(vacb: u64) -> (u64, u64) {
    let native = vacb_at(vacb);
    (native.shared_cache_map.get(), view_index(native.overlay.file_offset.quad_part.get() as u64 & !0xFFFF))
}

/// Cache -> buffer do chamador (talvez de modo usuário): cópia em bloco
/// sondada. `Err` = endereço do chamador sem mapeamento.
pub fn copy_to_caller(destination: u64, source: u64, length: u64) -> Result<(), ()> {
    // SAFETY: `source` é memória de vista do próprio Cc, residente e referenciada
    // pelo chamador durante a cópia.
    let bytes = unsafe { core::slice::from_raw_parts(source as *const u8, length as usize) };
    guest::try_write_bytes(destination, bytes).map_err(|_| ())
}

/// Buffer do chamador (talvez de modo usuário) -> cache: leitura sondada e
/// escrita em bloco na vista.
pub fn copy_from_caller(destination: u64, source: u64, length: u64) -> Result<(), ()> {
    let bytes = guest::try_read_bytes(source, length as usize).map_err(|_| ())?;
    guest::write_bytes(destination, &bytes);
    Ok(())
}

/// Zera `length` bytes de memória do próprio Cc (vista ou buffer de zeros).
pub fn zero_bytes(destination: u64, length: u64) {
    // SAFETY: memória de vista ou de páginas independentes do Cc, residente.
    unsafe { core::ptr::write_bytes(destination as *mut u8, 0, length as usize) }
}

/// Zera as páginas `mask` de uma vista.
pub fn zero_pages(view_base: u64, mask: u64) {
    for (first, count) in runs(mask) {
        zero_bytes(view_base + first * PAGE_SIZE, count * PAGE_SIZE);
    }
}

/// Corridas contíguas (primeira página, quantidade) de uma máscara.
pub fn runs(mask: u64) -> Vec<(u64, u64)> {
    let mut result = Vec::new();
    let mut page = 0;
    while page < layout::PAGES_PER_VIEW {
        if mask & (1 << page) == 0 {
            page += 1;
            continue;
        }
        let first = page;
        while page < layout::PAGES_PER_VIEW && mask & (1 << page) != 0 {
            page += 1;
        }
        result.push((first, page - first));
    }
    result
}
