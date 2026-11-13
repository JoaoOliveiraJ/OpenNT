//! Retenção de residência de buffers de I/O direto.
//! A posse do buffer continua com o chamador até o I/O terminar.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::paging;
use crate::ntos::inc::status::STATUS_ACCESS_VIOLATION;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

static HELD: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

#[derive(Clone, Copy, Debug)]
pub struct PinnedPage {
    pub va: u64,
    pub frame: u64,
}

/// Retenção ativa; `release` devolve as páginas (duas vezes é erro).
pub struct Pin {
    pub pages: Vec<PinnedPage>,
    released: bool,
}

fn unpin(pages: &[PinnedPage]) {
    let mut held = HELD.lock();
    for page in pages {
        match held.get(&page.va).copied() {
            Some(1) => {
                held.remove(&page.va);
            }
            Some(count) => {
                held.insert(page.va, count - 1);
            }
            None => {}
        }
    }
}

impl Pin {
    pub fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Err(KernelError::new("double I/O unpin"));
        }
        self.released = true;
        unpin(&self.pages);
        Ok(())
    }
}

pub fn pin(pointer: u64, length: u64, write: bool) -> Result<Pin, KernelError> {
    let mut pages = Vec::new();
    if length == 0 {
        return Ok(Pin { pages, released: false });
    }
    let end = pointer as u128 + length as u128;
    if pointer == 0 || end > u64::MAX as u128 + 1 {
        return Err(KernelError::with_status("invalid direct buffer", STATUS_ACCESS_VIOLATION));
    }
    let mut va = pointer & !4095;
    while (va as u128) < end {
        // Falta pela residência do provedor dono antes de consultar a PTE.
        let mapping = guest::try_read8(va).ok().and_then(|_| paging::query_page(va, false));
        let valid = mapping.is_some_and(|mapping| !write || mapping.access & 2 != 0);
        if !valid {
            unpin(&pages);
            return Err(KernelError::with_status("invalid direct buffer page", STATUS_ACCESS_VIOLATION));
        }
        *HELD.lock().entry(va).or_insert(0) += 1;
        pages.push(PinnedPage { va, frame: mapping.unwrap().physical_address / 4096 * 4096 });
        va = match va.checked_add(4096) {
            Some(next) => next,
            None => break,
        };
    }
    Ok(Pin { pages, released: false })
}

pub fn is_pinned(va: u64) -> bool {
    HELD.lock().contains_key(&(va & !4095))
}

pub fn count() -> usize {
    HELD.lock().len()
}
