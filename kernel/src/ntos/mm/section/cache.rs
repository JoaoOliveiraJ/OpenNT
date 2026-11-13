//! Tipo de cache dos PFNs de seção.
//!
//! Todo alias de um PFN de seção usa o mesmo tipo PAT, inclusive o alias de
//! identidade usado para zerar e para I/O de arquivo. O mapeamento antigo
//! volta antes de o frame reentrar no alocador geral de PFNs.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::mm::paging::{self, MapOptions};
use crate::hal::cpu;
use crate::ntos::ke::smp;
use crate::rtl::{KernelError, SpinLock};

/// Flags e NX originais de cada frame alterado.
static OWNED: SpinLock<BTreeMap<u64, (u64, bool)>> = SpinLock::new(BTreeMap::new());

fn flush() -> Result<(), KernelError> {
    cpu::flush_caches();
    cpu::reload_cr3();
    smp::flush_remote_tlb(true)
}

fn map(frame: u64, flags: u64, nx: bool) -> bool {
    paging::map_page(frame, frame, flags, MapOptions { nx, skip_invalidate: false, deferred_tables: None })
}

/// PAGE_NOCACHE (PCD|PWT) ou PAGE_WRITECOMBINE (PAT) no alias de identidade.
/// `Ok(false)` = faltou memória para dividir uma página grande.
pub fn set(frames: &[u64], protection: u32) -> Result<bool, KernelError> {
    let flags = if protection & 0x200 != 0 { 0x18 } else if protection & 0x400 != 0 { 0x80 } else { 0 };
    if flags == 0 {
        return Ok(true);
    }
    let mut changed = Vec::new();
    let result = (|| -> Result<(), (bool, KernelError)> {
        for &frame in frames {
            if OWNED.lock().contains_key(&frame) {
                return Err((false, KernelError::new("section cache frame already owned")));
            }
            let mut page = paging::query_page(frame, false).filter(|page| page.physical_address == frame).ok_or((false, KernelError::new("section PFN lacks identity mapping")))?;
            if page.page_size != 4096 {
                if !paging::split_large_page(frame, false) {
                    return Err((true, KernelError::new("section cache table allocation failed")));
                }
                page = paging::query_page(frame, false).ok_or((false, KernelError::new("section PFN lacks identity mapping")))?;
            }
            OWNED.lock().insert(frame, (page.flags, page.nx));
            changed.push(frame);
            if !map(frame, (page.flags & !0x98) | flags, page.nx) {
                return Err((false, KernelError::new("section cache mapping failed")));
            }
        }
        flush().map_err(|error| (false, error))
    })();
    match result {
        Ok(()) => Ok(true),
        Err((allocation, error)) => {
            restore(&changed)?;
            if allocation { Ok(false) } else { Err(error) }
        }
    }
}

/// Restaura o tipo de cache original. Uma falha de ACK conserva a obrigação
/// de invalidar: repetir o restore não libera um PFN cuja tradução antiga
/// ainda exista em outra CPU.
pub fn restore(frames: &[u64]) -> Result<(), KernelError> {
    let mut restored = Vec::new();
    for &frame in frames {
        let Some((flags, nx)) = OWNED.lock().get(&frame).copied() else { continue };
        if !map(frame, flags, nx) {
            return Err(KernelError::new("cannot restore section PFN cache"));
        }
        restored.push(frame);
    }
    if !restored.is_empty() {
        flush()?;
    }
    let mut owned = OWNED.lock();
    for frame in restored {
        owned.remove(&frame);
    }
    Ok(())
}
