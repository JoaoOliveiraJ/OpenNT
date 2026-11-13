//! Acessos protegidos a VAs.
//!
//! Cada acesso confirma a proteção efetiva da página e deixa o provedor real
//! resolver paginação/COW antes de tocar os bytes. A falha vira
//! STATUS_ACCESS_VIOLATION, ou STATUS_IN_PAGE_ERROR quando a carga da
//! página falhou.

use crate::ntos::mm::{page_residency, paging, small};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Falha de acesso com o NTSTATUS do original.
fn fault(address: u64, in_page_status: Option<u32>) -> KernelError {
    KernelError::with_status(alloc::format!("resource memory access at {address:#x}"), if in_page_status.is_none() { 0xC000_0005 } else { 0xC000_0006 })
}

/// O NTSTATUS de uma falha de acesso deste módulo (`ResourceAccessFault`);
/// `None` para qualquer outro erro, que segue para o seu dispatcher.
pub fn access_status(error: &KernelError) -> Option<u32> {
    error.message.starts_with("resource memory access at ").then_some(error.status)
}

/// Confere a faixa: canônica, presente e (para escrita) gravável, com até
/// duas faltas reais por página (page-in e cópia privada de WRITECOPY).
pub fn check(address: u64, length: u64, write: bool) -> Result<u64, KernelError> {
    let Some(end) = address.checked_add(length) else { return Err(fault(address, None)) };
    if address < 0xFFFF_8000_0000_0000 && end > 0x8000_0000_0000 {
        return Err(fault(address, None));
    }
    let required = if write { 3 } else { 1 };
    let mut current = address;
    while current < end {
        let mut access = paging::access_flags(current);
        let mut attempt = 0;
        while access & required != required && attempt < 2 {
            let error_code = (access & 1) as u32 | if write { 2 } else { 0 };
            if !page_residency::fault(current, error_code) {
                let failure = small::consume_page_fault_failure(current, error_code);
                return Err(fault(current, failure.map(|failure| failure.status)));
            }
            access = paging::access_flags(current);
            attempt += 1;
        }
        if access & required != required {
            return Err(fault(current, None));
        }
        current = (current & !4095) + 4096;
    }
    Ok(address)
}

pub fn read8(address: u64) -> Result<u8, KernelError> {
    Ok(guest::read8(check(address, 1, false)?))
}

pub fn read16(address: u64) -> Result<u16, KernelError> {
    Ok(guest::read16(check(address, 2, false)?))
}

pub fn read32(address: u64) -> Result<u32, KernelError> {
    Ok(guest::read32(check(address, 4, false)?))
}

pub fn read64(address: u64) -> Result<u64, KernelError> {
    Ok(guest::read64(check(address, 8, false)?))
}

pub fn write8(address: u64, value: u8) -> Result<(), KernelError> {
    guest::write8(check(address, 1, true)?, value);
    Ok(())
}

pub fn write16(address: u64, value: u16) -> Result<(), KernelError> {
    guest::write16(check(address, 2, true)?, value);
    Ok(())
}

pub fn write32(address: u64, value: u32) -> Result<(), KernelError> {
    guest::write32(check(address, 4, true)?, value);
    Ok(())
}

pub fn write64(address: u64, value: u64) -> Result<(), KernelError> {
    guest::write64(check(address, 8, true)?, value);
    Ok(())
}
