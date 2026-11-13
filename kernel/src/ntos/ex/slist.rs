//! SLIST_HEADER x64.
//!
//! Profundidade nos 16 bits baixos, sequência nos 48 seguintes e o primeiro
//! ponteiro na segunda palavra; CMPXCHG16B conserva o par sob concorrência.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::SlistHeader;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory::{self as guest, STATUS_ACCESS_VIOLATION};

const POINTER_MASK: u64 = !15;

fn header_at(head: u64) -> &'static SlistHeader {
    // SAFETY: os exports recebem o PSLIST_HEADER do chamador.
    unsafe { SlistHeader::at(head) }
}

/// InitializeSListHead: o desalinhamento levanta STATUS_DATATYPE_MISALIGNMENT.
pub fn initialize(head: u64) -> Result<(), KernelError> {
    if head & 15 != 0 {
        return Err(KernelError::with_status("STATUS_DATATYPE_MISALIGNMENT", 0x8000_0002));
    }
    let header = header_at(head);
    header.alignment.set(0);
    header.region.set(0);
    Ok(())
}

/// CMPXCHG16B no par (Alignment, Region); devolve o par anterior.
fn exchange(header: &SlistHeader, expected: (u64, u64), replacement: (u64, u64)) -> Result<(u64, u64), KernelError> {
    guest::compare_exchange128(header.address(), expected, replacement)
}

/// Comparar com zero dá uma observação atômica mesmo com a lista vazia.
fn read_header(header: &SlistHeader) -> Result<(u64, u64), KernelError> {
    exchange(header, (0, 0), (0, 0))
}

/// InterlockedPushEntrySList: encadeia antes de publicar o novo par.
pub fn push(head: u64, entry: u64) -> Result<u64, KernelError> {
    let header = header_at(head);
    let mut expected = read_header(header)?;
    loop {
        let previous = expected.1 & POINTER_MASK;
        // SLIST_ENTRY.Next da entrada do chamador.
        guest::try_write::<u64>(entry, previous)?;
        let observed = exchange(header, expected, (expected.0.wrapping_add(0x10001), entry))?;
        if observed == expected {
            return Ok(previous);
        }
        expected = observed;
    }
}

/// InterlockedPopEntrySList: só Depth decresce (DEC BX); a
/// sequência muda nas inserções, impedindo ABA.
pub fn pop(head: u64) -> Result<u64, KernelError> {
    let header = header_at(head);
    let mut expected = read_header(header)?;
    loop {
        let first = expected.1 & POINTER_MASK;
        if first == 0 {
            return Ok(0);
        }
        // SLIST_ENTRY.Next do primeiro: a entrada pode ter sido liberada por
        // outro consumidor entre a observação e a leitura.
        let next = match guest::try_read::<u64>(first) {
            Ok(next) => next,
            Err(error) => {
                // Só essa mudança autoriza repetir.
                if error.status != STATUS_ACCESS_VIOLATION {
                    return Err(error);
                }
                let current = read_header(header)?;
                if current == expected {
                    return Err(error);
                }
                expected = current;
                continue;
            }
        };
        let counters = (expected.0 & !0xFFFF) | (expected.0.wrapping_sub(1) & 0xFFFF);
        let observed = exchange(header, expected, (counters, next))?;
        if observed == expected {
            return Ok(first);
        }
        expected = observed;
    }
}

/// InterlockedFlushSList: destaca a cadeia e zera Depth/Next, mantendo a
/// sequência acumulada.
pub fn flush(head: u64) -> Result<u64, KernelError> {
    let header = header_at(head);
    let mut expected = read_header(header)?;
    loop {
        let observed = exchange(header, expected, (expected.0 & !0xFFFF, 0))?;
        if observed == expected {
            return Ok(expected.1 & POINTER_MASK);
        }
        expected = observed;
    }
}

/// QueryDepthSList: HeaderX64.Depth.
pub fn depth(head: u64) -> u16 {
    header_at(head).header_x64.depth() as u16
}

/// FirstEntrySList: sem remover a entrada nem alterar os contadores.
pub fn first(head: u64) -> u64 {
    header_at(head).region.get() & POINTER_MASK
}
