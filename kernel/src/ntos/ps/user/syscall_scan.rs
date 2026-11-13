//! Números de serviço das bibliotecas nativas.
//!
//! Só os stubs `Nt*` no padrão canônico (`mov r10, rcx; mov eax, SSN`)
//! entram; o primeiro nome de cada SSN vence, na ordem da tabela de
//! exports (alfabética, como o PE exige).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::image::pe_exports;

fn collect(exports: &BTreeMap<String, u64>, read32: impl Fn(u64) -> Option<u32>) -> BTreeMap<u32, String> {
    let mut map = BTreeMap::new();
    for (name, &address) in exports {
        if !name.starts_with("Nt") || read32(address) != Some(0xB8D1_8B4C) {
            continue;
        }
        if let Some(number) = read32(address + 4) {
            map.entry(number).or_insert_with(|| name.clone());
        }
    }
    map
}

/// Stubs da ntdll já mapeada.
pub fn scan_syscall_stubs(exports: &BTreeMap<String, u64>) -> BTreeMap<u32, String> {
    collect(exports, |address| guest::try_read::<u32>(address).ok())
}

fn truncated() -> KernelError {
    KernelError::new("truncated syscall ABI image")
}

/// Lê a ABI da biblioteca antes de qualquer processo ser mapeado: só um
/// vetor temporário com a imagem montada pelas seções.
pub fn scan_syscall_image(bytes: &[u8]) -> Result<BTreeMap<u32, String>, KernelError> {
    let bounds = |offset: usize, size: usize| if offset.checked_add(size).is_some_and(|end| end <= bytes.len()) { Ok(()) } else { Err(truncated()) };
    let u16_at = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let u32_at = |offset: usize| u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
    bounds(0, 64)?;
    let pe = u32_at(0x3C) as usize;
    bounds(pe, 24)?;
    if u16_at(0) != 0x5A4D || u32_at(pe) != 0x4550 || u16_at(pe + 4) != 0x8664 {
        return Err(KernelError::new("syscall ABI requires an AMD64 PE image"));
    }
    let count = u16_at(pe + 6) as usize;
    let optional_size = u16_at(pe + 20) as usize;
    let optional = pe + 24;
    bounds(optional, optional_size)?;
    if optional_size < 240 || u16_at(optional) != 0x20B || count > 96 {
        return Err(KernelError::new("invalid syscall ABI PE headers"));
    }
    let size = u32_at(optional + 56) as usize;
    let headers = u32_at(optional + 60) as usize;
    if size == 0 || size > 64 * 1024 * 1024 || headers > size || headers < optional + optional_size + count * 40 {
        return Err(KernelError::new("invalid syscall ABI image size"));
    }
    bounds(0, headers)?;
    let mut image = vec![0u8; size];
    image[..headers].copy_from_slice(&bytes[..headers]);
    let mut regions: Vec<(usize, usize)> = vec![(0, headers)];
    for index in 0..count {
        let at = optional + optional_size + index * 40;
        bounds(at, 40)?;
        let virtual_size = u32_at(at + 8) as usize;
        let rva = u32_at(at + 12) as usize;
        let raw_size = u32_at(at + 16) as usize;
        let raw_offset = u32_at(at + 20) as usize;
        let length = virtual_size.max(raw_size);
        bounds(raw_offset, raw_size)?;
        if rva + length > size || regions.iter().any(|&(start, end)| rva < end && rva + length > start) {
            return Err(KernelError::new("overlapping or invalid syscall ABI section"));
        }
        regions.push((rva, rva + length));
        image[rva..rva + raw_size].copy_from_slice(&bytes[raw_offset..raw_offset + raw_size]);
    }
    let read_rva = |rva: u64, length: u64| -> Result<Vec<u8>, KernelError> {
        let (start, end) = (rva as usize, (rva + length) as usize);
        image.get(start..end).map(|slice| slice.to_vec()).ok_or_else(truncated)
    };
    let exports = pe_exports::read_exports(&read_rva, 0, size as u64, u32_at(optional + 112) as u64, u32_at(optional + 116) as u64)?;
    Ok(collect(&exports.exports, |address| {
        let at = address as usize;
        image.get(at..at + 4).map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
    }))
}
