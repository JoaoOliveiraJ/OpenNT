//! Células de dados exportadas pelo PE do kernel.
//!
//! A tabela de exports, as importações nativas e o kernel compartilham os
//! mesmos bytes da seção `.kdata`; não há cópias no heap.

use core::sync::atomic::{AtomicU64, Ordering};

use super::kernel_data_layout::{self as layout, KernelDataEntry};
use super::{kernel_address, memory_map as map};
use crate::hal::physical;
use crate::ntos::inc::types::{ImageDosHeader, ImageNtHeaders64, ImageSectionHeader};
use crate::rtl::KernelError;

/// Campo de um cabeçalho PE da imagem do kernel lido pelo endereço do campo:
/// o e_lfanew não garante o alinhamento natural das estruturas inteiras.
macro_rules! header_field {
    ($at:expr, $type:ty, $($field:tt)+) => {
        $at + core::mem::offset_of!($type, $($field)+) as u64
    };
}

static SECTION_PHYSICAL_ADDRESS: AtomicU64 = AtomicU64::new(0);

/// Localiza `.kdata` e confirma tamanho, escrita e ausência de execução.
fn section() -> Result<u64, KernelError> {
    let cached = SECTION_PHYSICAL_ADDRESS.load(Ordering::Relaxed);
    if cached != 0 {
        return Ok(cached);
    }
    let image = map::KERNEL_IMAGE_BASE;
    let pe = physical::read32(header_field!(image, ImageDosHeader, e_lfanew)) as u64;
    let headers = image + pe;
    let count = physical::read16(header_field!(headers, ImageNtHeaders64, file_header.number_of_sections)) as u64;
    let table = header_field!(headers, ImageNtHeaders64, optional_header)
        + physical::read16(header_field!(headers, ImageNtHeaders64, file_header.size_of_optional_header)) as u64;
    let required = layout::required_byte_length();
    for index in 0..count {
        let header = table + index * core::mem::size_of::<ImageSectionHeader>() as u64;
        let name = physical::read_bytes(header_field!(header, ImageSectionHeader, name), 8);
        let name: alloc::vec::Vec<u8> = name.into_iter().take_while(|&byte| byte != 0).collect();
        if name != b".kdata" {
            continue;
        }
        // Misc.VirtualSize; Characteristics: gravável e não executável.
        if (physical::read32(header_field!(header, ImageSectionHeader, misc)) as u64) < required
            || physical::read32(header_field!(header, ImageSectionHeader, characteristics)) & 0xA000_0000 != 0x8000_0000
        {
            return Err(KernelError::new("invalid kernel data section"));
        }
        let address = image + physical::read32(header_field!(header, ImageSectionHeader, virtual_address)) as u64;
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

/// Endereço de uma célula que precisa existir, para os getters dos exports
/// de dados: a falta para o kernel com o nome do export.
pub fn required_address(name: &str) -> u64 {
    address(name).unwrap_or_else(|error| panic!("{name}: {error}"))
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
        // Ponteiros exportados: uma única leitura de 64 bits.
        8 => physical::read64(at),
        _ => panic!("unsupported kernel data width"),
    }
}

/// A largura do export limita os bits publicados.
pub fn write(name: &str, value: u64) {
    let (at, entry) = cell(name);
    match entry.size {
        1 => physical::write8(at, value as u8),
        4 => physical::write32(at, value as u32),
        // Uma única escrita de 64 bits: drivers leem a célula concorrentemente.
        8 => physical::write64(at, value),
        _ => panic!("unsupported kernel data width"),
    }
}
