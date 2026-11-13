//! Módulos pequenos do Mm: validade de endereço, tamanho de MDL, falha de
//! página e a sondagem de endereços de usuário
//! (ProbeForRead/ProbeForWrite).

use crate::ntos::ke::irql;
use crate::rtl::{KernelError, SpinLock};

use super::{memory_map, paging};

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

/// ProbeForRead/ProbeForWrite: valida faixa e alinhamento, sem ler a
/// memória do usuário. Este caminho ainda para a máquina em vez de levantar
/// uma exceção NT capturável; a permissão de escrita por página continua
/// pendente.
pub fn probe_user_address(address: u64, length: u64, alignment: u32) {
    let alignment = if alignment == 0 { 1 } else { alignment as u64 };
    if length == 0 {
        return;
    }
    let highest = memory_map::USER_ADDRESS_LIMIT - 1;
    if address > highest || length > highest - address + 1 || address % alignment != 0 {
        debug_print!("[mm] ProbeForRead/Write: endereco invalido {:#x} len {:#x} — kernel SEH dispatch not implemented", address, length);
        crate::hal::cpu::halt_forever();
    }
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
