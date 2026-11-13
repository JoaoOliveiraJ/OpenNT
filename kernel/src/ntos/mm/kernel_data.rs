//! Células de dados exportadas pelo PE do kernel — `system32/ntos/mm/kernel-data.js`.
//!
//! A tabela de exports, as importações nativas e o kernel compartilham os
//! mesmos bytes da seção `.kdata`; não há cópias no heap.

use core::sync::atomic::{AtomicU64, Ordering};

use super::kernel_data_layout::{self as layout, KernelDataEntry};
use super::{kernel_address, memory_map as map};
use crate::hal::physical;
use crate::rtl::KernelError;

static SECTION_PHYSICAL_ADDRESS: AtomicU64 = AtomicU64::new(0);

/// Localiza `.kdata` e confirma tamanho, escrita e ausência de execução.
fn section() -> Result<u64, KernelError> {
    let cached = SECTION_PHYSICAL_ADDRESS.load(Ordering::Relaxed);
    if cached != 0 {
        return Ok(cached);
    }
    let image = map::KERNEL_IMAGE_BASE;
    let pe = physical::read32(image + 60) as u64;
    let count = physical::read16(image + pe + 6) as u64;
    let table = image + pe + 24 + physical::read16(image + pe + 20) as u64;
    let required = layout::required_byte_length();
    for index in 0..count {
        let header = table + index * 40;
        let name: alloc::vec::Vec<u8> =
            (0..8).map(|offset| physical::read8(header + offset)).take_while(|&byte| byte != 0).collect();
        if name != b".kdata" {
            continue;
        }
        if (physical::read32(header + 8) as u64) < required
            || physical::read32(header + 36) & 0xA000_0000 != 0x8000_0000
        {
            return Err(KernelError::new("invalid kernel data section"));
        }
        let address = image + physical::read32(header + 12) as u64;
        // Valida o último byte contra os limites da imagem publicada.
        kernel_address::virtual_address(address + required - 1)?;
        SECTION_PHYSICAL_ADDRESS.store(address, Ordering::Relaxed);
        return Ok(address);
    }
    Err(KernelError::new("kernel data section absent"))
}

fn entry(name: &str) -> Result<(u64, &'static KernelDataEntry), KernelError> {
    let (index, entry) =
        layout::find(name).ok_or_else(|| KernelError::new(alloc::format!("unknown kernel data export: {name}")))?;
    Ok((layout::offset_of(index), entry))
}

fn cell(name: &str) -> (u64, &'static KernelDataEntry) {
    let (offset, entry) = entry(name).unwrap_or_else(|error| panic!("{error}"));
    let section = section().unwrap_or_else(|error| panic!("{error}"));
    (section + offset, entry)
}

/// Endereço virtual da célula que a tabela de exports também publica.
pub fn address(name: &str) -> Result<u64, KernelError> {
    let (offset, _) = entry(name)?;
    kernel_address::virtual_address(section()? + offset)
}

/// Endereço e extensão completa do armazenamento.
pub fn region(name: &str) -> Result<(u64, u64), KernelError> {
    let (_, entry) = entry(name)?;
    Ok((address(name)?, entry.storage_size))
}

pub fn read(name: &str) -> u64 {
    let (at, entry) = cell(name);
    match entry.size {
        1 => physical::read8(at) as u64,
        4 => physical::read32(at) as u64,
        8 => physical::read32(at) as u64 | (physical::read32(at + 4) as u64) << 32,
        _ => panic!("unsupported kernel data width"),
    }
}

/// A largura do export limita os bits publicados.
pub fn write(name: &str, value: u64) {
    let (at, entry) = cell(name);
    match entry.size {
        1 => physical::write8(at, value as u8),
        4 => physical::write32(at, value as u32),
        8 => {
            physical::write32(at, value as u32);
            physical::write32(at + 4, (value >> 32) as u32);
        }
        _ => panic!("unsupported kernel data width"),
    }
}
