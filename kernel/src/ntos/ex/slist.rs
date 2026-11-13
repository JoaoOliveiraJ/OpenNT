//! SLIST_HEADER x64.
//!
//! Profundidade nos 16 bits baixos, sequência nos 48 seguintes e o primeiro
//! ponteiro na segunda palavra; CMPXCHG16B conserva o par sob concorrência.

use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory::{self as guest, STATUS_ACCESS_VIOLATION};

const POINTER_MASK: u64 = !15;

/// InitializeSListHead: o desalinhamento levanta STATUS_DATATYPE_MISALIGNMENT.
pub fn initialize(head: u64) -> Result<(), KernelError> {
    if head & 15 != 0 {
        return Err(KernelError::with_status("STATUS_DATATYPE_MISALIGNMENT", 0x8000_0002));
    }
    guest::write64(head, 0);
    guest::write64(head + 8, 0);
    Ok(())
}

/// Comparar com zero dá uma observação atômica mesmo com a lista vazia.
fn read_header(head: u64) -> Result<(u64, u64), KernelError> {
    guest::compare_exchange128(head, (0, 0), (0, 0))
}

/// InterlockedPushEntrySList: encadeia antes de publicar o novo par.
pub fn push(head: u64, entry: u64) -> Result<u64, KernelError> {
    let mut expected = read_header(head)?;
    loop {
        let previous = expected.1 & POINTER_MASK;
        guest::try_write64(entry, previous)?;
        let observed = guest::compare_exchange128(head, expected, (expected.0.wrapping_add(0x10001), entry))?;
        if observed == expected {
            return Ok(previous);
        }
        expected = observed;
    }
}

/// InterlockedPopEntrySList: só Depth decresce (o DEC BX do original); a
/// sequência muda nas inserções, impedindo ABA.
pub fn pop(head: u64) -> Result<u64, KernelError> {
    let mut expected = read_header(head)?;
    loop {
        let first = expected.1 & POINTER_MASK;
        if first == 0 {
            return Ok(0);
        }
        let next = match guest::try_read64(first) {
            Ok(next) => next,
            Err(error) => {
                // Outro consumidor pode ter liberado a entrada entre a observação
                // e a leitura; só essa mudança autoriza repetir.
                if error.status != STATUS_ACCESS_VIOLATION {
                    return Err(error);
                }
                let current = read_header(head)?;
                if current == expected {
                    return Err(error);
                }
                expected = current;
                continue;
            }
        };
        let counters = (expected.0 & !0xFFFF) | (expected.0.wrapping_sub(1) & 0xFFFF);
        let observed = guest::compare_exchange128(head, expected, (counters, next))?;
        if observed == expected {
            return Ok(first);
        }
        expected = observed;
    }
}

/// InterlockedFlushSList: destaca a cadeia e zera Depth/Next, mantendo a
/// sequência acumulada.
pub fn flush(head: u64) -> Result<u64, KernelError> {
    let mut expected = read_header(head)?;
    loop {
        let observed = guest::compare_exchange128(head, expected, (expected.0 & !0xFFFF, 0))?;
        if observed == expected {
            return Ok(expected.1 & POINTER_MASK);
        }
        expected = observed;
    }
}

pub fn depth(head: u64) -> u16 {
    guest::read16(head)
}

/// FirstEntrySList: sem remover a entrada nem alterar os contadores.
pub fn first(head: u64) -> u64 {
    guest::read64_single(head + 8) & POINTER_MASK
}
