//! Módulos pequenos do Mm: `address-validity.js`, `mdl-size.js` e
//! `page-fault-failure.js`.

use crate::ntos::ke::irql;
use crate::rtl::{KernelError, SpinLock};

use super::paging;

/// MmIsAddressValid: consulta só mapeamentos residentes, sem page-in nem lock.
pub fn is_address_valid(address: u64) -> Result<bool, KernelError> {
    if irql::get_irql() > irql::DISPATCH_LEVEL {
        return Err(KernelError::new("MmIsAddressValid above DISPATCH_LEVEL"));
    }
    let upper = address >> 47;
    if upper != 0 && upper != 0x1FFFF {
        return Ok(false);
    }
    Ok(paging::access_flags(address) & paging::PAGE_PRESENT != 0)
}

/// Tamanho do MDL x64: cabeçalho de 48 bytes e um PFN de 8 bytes por página
/// abrangida, com as somas de 64 bits do original (inclusive o estouro).
pub fn size_of_memory_descriptor(base_address: u64, byte_length: u64) -> u64 {
    let page_offset = base_address & 0xFFF;
    let rounded_span = byte_length.wrapping_add(page_offset).wrapping_add(0xFFF);
    0x30 + (rounded_span >> 12) * 8
}

/// Causa de uma falha real de page-in até o SEH da mesma trap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFaultFailure {
    pub address: u64,
    pub error_code: u32,
    pub status: u32,
}

static PENDING_FAILURE: SpinLock<Option<PageFaultFailure>> = SpinLock::new(None);

pub fn clear_page_fault_failure() {
    *PENDING_FAILURE.lock() = None;
}

pub fn record_page_fault_failure(address: u64, error_code: u32, status: u32) -> Result<(), KernelError> {
    if status & 0x8000_0000 == 0 {
        return Err(KernelError::new("page-in failure requires failing NTSTATUS"));
    }
    *PENDING_FAILURE.lock() = Some(PageFaultFailure { address, error_code, status });
    Ok(())
}

/// Endereço e error code impedem que outra exceção consuma o resultado.
pub fn consume_page_fault_failure(address: u64, error_code: u32) -> Option<PageFaultFailure> {
    let failure = PENDING_FAILURE.lock().take();
    failure.filter(|failure| failure.address == address && failure.error_code == error_code)
}
