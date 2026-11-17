//! PTEs de sistema (o MiReserveSystemPtes/MiReleaseSystemPtes do NT).
//!
//! Faixas de VA da janela `SYSTEM_PTE_BASE..SYSTEM_PTE_TOP`, reservadas em
//! páginas inteiras e mapeadas sobre frames dados, com PTEs de supervisor RW
//! e sem execução. É onde o MmMapLockedPagesSpecifyCache em KernelMode põe as
//! páginas travadas de um buffer de usuário: a VA de sistema vale em
//! qualquer processo, o que a VA de usuário do buffer não faz (um driver que
//! completa o pedido no contexto de outro processo grava pela VA de sistema).
//!
//! O registro das faixas ocupadas é um mapa base -> páginas; a busca é a
//! primeira faixa livre a partir do cursor da última reserva.

use alloc::collections::BTreeMap;

use super::memory_map as map;
use super::paging::{self, MapOptions};
use crate::rtl::SpinLock;

const PAGE: u64 = 0x1000;

struct Window {
    used: BTreeMap<u64, u64>,
    cursor: u64,
}

static WINDOW: SpinLock<Window> = SpinLock::new(Window { used: BTreeMap::new(), cursor: map::SYSTEM_PTE_BASE });

fn reserve(pages: u64) -> Option<u64> {
    let size = pages.checked_mul(PAGE)?;
    let mut window = WINDOW.lock();
    for start in [window.cursor, map::SYSTEM_PTE_BASE] {
        let mut base = start;
        while base.checked_add(size).is_some_and(|end| end <= map::SYSTEM_PTE_TOP) {
            // A primeira faixa ocupada que cruza [base, base + size).
            let blocking = window.used.range(..base + size).next_back().filter(|&(&used, &count)| used + count * PAGE > base).map(|(&used, &count)| used + count * PAGE);
            match blocking {
                Some(after) => base = after,
                None => {
                    window.used.insert(base, pages);
                    window.cursor = base + size;
                    return Some(base);
                }
            }
        }
    }
    None
}

fn release(base: u64) -> Option<u64> {
    WINDOW.lock().used.remove(&base)
}

/// A VA pertence à janela das PTEs de sistema.
pub fn contains(address: u64) -> bool {
    (map::SYSTEM_PTE_BASE..map::SYSTEM_PTE_TOP).contains(&address)
}

/// Reserva `frames.len()` PTEs e mapeia cada frame numa; `cache` são os
/// bits PCD/PWT/PAT da folha. 0 sem VA ou sem tabela.
pub fn map_frames(frames: &[u64], cache: u64) -> u64 {
    if frames.is_empty() {
        return 0;
    }
    let Some(base) = reserve(frames.len() as u64) else { return 0 };
    for (index, &frame) in frames.iter().enumerate() {
        if !paging::map_page(base + index as u64 * PAGE, frame, paging::PAGE_PRESENT | paging::PAGE_RW | cache, MapOptions { nx: true, ..MapOptions::default() }) {
            for done in 0..index as u64 {
                paging::unmap_page(base + done * PAGE, MapOptions::default());
            }
            release(base);
            return 0;
        }
    }
    base
}

/// Desfaz o mapeamento que começa na página de `address` e devolve as PTEs.
/// `false` = nenhuma reserva começa ali.
pub fn unmap(address: u64) -> bool {
    let base = address & !(PAGE - 1);
    let Some(pages) = release(base) else { return false };
    for index in 0..pages {
        paging::unmap_page(base + index * PAGE, MapOptions::default());
    }
    let _ = crate::ntos::ke::smp::flush_remote_tlb(false);
    true
}
