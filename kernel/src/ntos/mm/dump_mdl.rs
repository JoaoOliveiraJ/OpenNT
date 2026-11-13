//! Janela de mapeamento do dump legado — `system32/ntos/mm/dump-mdl.js`.
//!
//! Uma janela pré-reservada de 32 PTEs de sistema. Os chamadores serializam
//! seu uso; o próximo mapeamento substitui a vista do MDL anterior. Mapear
//! nunca aloca frames nem tabelas.

use core::sync::atomic::{AtomicBool, Ordering};

use super::paging::{self, MapOptions};
use super::{memory_map as map, physical_layout};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const BASE: u64 = map::KERNEL_DUMP_VIRTUAL_BASE;
const PAGES: u64 = 32;
static READY: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicBool = AtomicBool::new(false);

fn reserve(page: u64) -> bool {
    paging::map_page(BASE + page * 4096, 0, 0x200, MapOptions { nx: true, ..Default::default() })
}

/// Entradas não presentes possuídas retêm a hierarquia pré-alocada.
pub fn init() -> Result<(), KernelError> {
    if READY.load(Ordering::Acquire) {
        return Ok(());
    }
    for count in 0..PAGES {
        if !reserve(count) {
            for page in 0..count {
                paging::unmap_page(BASE + page * 4096, MapOptions::default());
            }
            return Err(KernelError::new("dump window page tables exhausted"));
        }
    }
    READY.store(true, Ordering::Release);
    Ok(())
}

/// A seleção PAT do alias primário: misturar tipos de cache é inválido.
fn cache_flags(physical: u64) -> u64 {
    match paging::query_page(physical, false) {
        Some(page) if page.physical_address == physical => (page.flags & 0x18) | if page.pat { 0x80 } else { 0 },
        _ => 0,
    }
}

pub fn map(mdl: u64) -> Result<(), KernelError> {
    if !READY.load(Ordering::Acquire) {
        return Err(KernelError::new("dump window is not initialized"));
    }
    if BUSY.swap(true, Ordering::AcqRel) {
        return Err(KernelError::new("dump mapping reentrancy"));
    }
    let result = (|| {
        let bytes = guest::try_read32(mdl + 0x28)? as u64;
        let offset = guest::try_read32(mdl + 0x2C)? as u64;
        let count = (bytes + offset).div_ceil(4096);
        if bytes == 0 || offset >= 4096 || count > PAGES {
            return Err(KernelError::new("invalid MDL for the 32-page dump window"));
        }
        let admitted = physical_layout::ranges();
        let mut frames = alloc::vec::Vec::new();
        for index in 0..count {
            let frame = guest::try_read64(mdl + 0x30 + index * 8)?.wrapping_mul(4096);
            if !admitted.iter().any(|&(base, top)| frame >= base && frame + 4096 <= top) {
                return Err(KernelError::new("dump MDL references a PFN outside admitted RAM"));
            }
            frames.push((frame, cache_flags(frame)));
        }
        // Valida o MDL inteiro antes de substituir qualquer parte da vista.
        for index in 0..count {
            if !reserve(index) {
                return Err(KernelError::new("reserved dump PTE disappeared"));
            }
        }
        guest::try_write64(mdl + 0x18, BASE + offset)?;
        for (index, &(frame, cache)) in frames.iter().enumerate() {
            if !paging::map_page(BASE + index as u64 * 4096, frame, 0x63 | cache, MapOptions { nx: true, ..Default::default() }) {
                return Err(KernelError::new("reserved dump mapping failed"));
            }
        }
        guest::try_write16(mdl + 0xA, guest::try_read16(mdl + 0xA)? | 0x11)
    })();
    BUSY.store(false, Ordering::Release);
    result
}

/// Desmontagem interna (testes/desligamento), não um export.
pub fn clear() -> Result<(), KernelError> {
    if !READY.load(Ordering::Acquire) {
        return Ok(());
    }
    if BUSY.load(Ordering::Acquire) {
        return Err(KernelError::new("dump mapping is active"));
    }
    for page in 0..PAGES {
        if !reserve(page) {
            return Err(KernelError::new("reserved dump PTE disappeared"));
        }
    }
    Ok(())
}
