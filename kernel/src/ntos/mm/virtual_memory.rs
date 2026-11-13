//! VirtualAlloc/VirtualFree do kernel.
//!
//! Páginas virtuais na janela de sistema `KERNEL_VIRTUAL_ALLOC_BASE..TOP`
//! (256 MB), cada uma lastreada por um frame do PFN e mapeada em PTE de
//! supervisor na tabela real, com reuso de faixas livres.

use alloc::vec::Vec;

use super::paging::{self, MapOptions};
use super::{memory_map as map, pfn};
use crate::rtl::SpinLock;

const PAGE: u64 = map::PAGE_SIZE;

struct VirtualSpace {
    next_free_va: u64,
    free_ranges: Vec<(u64, u64)>, // (va, páginas), reusadas primeiro
}

static SPACE: SpinLock<VirtualSpace> =
    SpinLock::new(VirtualSpace { next_free_va: map::KERNEL_VIRTUAL_ALLOC_BASE, free_ranges: Vec::new() });

/// Aloca `size` bytes (arredonda a páginas); VA ou 0.
pub fn alloc(size: u64) -> u64 {
    let pages = size.div_ceil(PAGE);
    let va = {
        let mut space = SPACE.lock();
        if let Some(index) = space.free_ranges.iter().position(|&(_, count)| count == pages) {
            space.free_ranges.remove(index).0
        } else {
            if space.next_free_va + pages * PAGE > map::KERNEL_VIRTUAL_ALLOC_TOP {
                return 0;
            }
            let va = space.next_free_va;
            space.next_free_va += pages * PAGE;
            va
        }
    };
    for page in 0..pages {
        let frame = pfn::alloc_page();
        let mapped = frame != 0
            && paging::map_page(va + page * PAGE, frame, paging::PAGE_PRESENT | paging::PAGE_RW, MapOptions::default());
        if !mapped {
            for previous in 0..page {
                pfn::free_page(paging::translate(va + previous * PAGE) & !0xFFF);
                paging::unmap_page(va + previous * PAGE, MapOptions::default());
            }
            return 0;
        }
    }
    va
}

pub fn free(va: u64, size: u64) {
    let pages = size.div_ceil(PAGE);
    for page in 0..pages {
        let pa = paging::translate(va + page * PAGE);
        if pa != 0 {
            // Desmapeia antes: o PFN recusa liberar frame ainda referenciado.
            paging::unmap_page(va + page * PAGE, MapOptions::default());
            pfn::free_page(pa & !0xFFF);
        }
    }
    SPACE.lock().free_ranges.push((va, pages));
}
