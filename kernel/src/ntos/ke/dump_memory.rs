//! Acesso de captura de dump.
//!
//! Só páginas já residentes; cópias por página física, sem executar o
//! chamador nem paginar em IRQL elevado.

use alloc::vec;
use alloc::vec::Vec;

use crate::hal::physical;
use crate::ntos::mm::paging::{self, PageQuery};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory::address_fault;

const PAGE: u64 = 0x1000;

/// Endereços não canônicos nunca viram aliases pela caminhada da PML4.
fn mapped_page(address: u64, writing: bool) -> Option<PageQuery> {
    let upper = address >> 47;
    if upper != 0 && upper != 0x1FFFF {
        return None;
    }
    let mapping = paging::query_page(address, false)?;
    if mapping.access & paging::PAGE_PRESENT == 0 || (writing && mapping.access & paging::PAGE_RW == 0) {
        return None;
    }
    Some(mapping)
}

/// Prefixo residente, inclusive quando acaba no meio do intervalo.
pub fn readable_length(address: u64, byte_length: u64, backwards: bool) -> u64 {
    let mut completed = 0;
    while completed < byte_length {
        let current = if backwards { address.wrapping_sub(completed) } else { address.wrapping_add(completed) };
        if mapped_page(current, false).is_none() {
            break;
        }
        let offset = current & 0xFFF;
        completed += (byte_length - completed).min(if backwards { offset + 1 } else { PAGE - offset });
    }
    completed
}

pub fn read(address: u64, byte_length: usize) -> Result<Vec<u8>, KernelError> {
    let mut result = vec![0u8; byte_length];
    let mut offset = 0usize;
    while offset < byte_length {
        let current = address.wrapping_add(offset as u64);
        let mapping = mapped_page(current, false).ok_or_else(|| address_fault(current))?;
        let chunk = (byte_length - offset).min((PAGE - (current & 0xFFF)) as usize);
        result[offset..offset + chunk].copy_from_slice(&physical::read_bytes(mapping.physical_address, chunk));
        offset += chunk;
    }
    Ok(result)
}

/// Respeita o limite da página e sua permissão.
pub fn write(address: u64, bytes: &[u8]) -> Result<(), KernelError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let current = address.wrapping_add(offset as u64);
        let mapping = mapped_page(current, true).ok_or_else(|| address_fault(current))?;
        let chunk = (bytes.len() - offset).min((PAGE - (current & 0xFFF)) as usize);
        physical::write_bytes(mapping.physical_address, &bytes[offset..offset + chunk]);
        offset += chunk;
    }
    Ok(())
}
