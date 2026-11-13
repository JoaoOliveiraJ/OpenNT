//! Consultas do Mm sobre imagens, RAM e MDLs:
//! `system-module-information.js`, `physical-ranges.js` e `protect-mdl.js`.

use alloc::vec;
use alloc::vec::Vec;

use super::kernel_pool::{self, AllocateOptions};
use super::loaded_images::{self, LoadedImage};
use super::{paging, physical_layout};
use crate::hal::cpu;
use crate::ntos::ke::{irql, smp};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

// ---- SystemModuleInformation (11) e SystemModuleInformationEx (77) ---------
// Layout conferido em ExpQueryModuleInformationEx: registros EX de 320 bytes
// com NextOffset=320 e depois um USHORT zero separado.

fn module_bytes(image: &LoadedImage, index: usize, extended: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; if extended { 320 } else { 296 }];
    let at = if extended { 8 } else { 0 };
    if extended {
        bytes[0..2].copy_from_slice(&320u16.to_le_bytes());
    }
    // Section/MappedBase não são usados pelo codificador nativo.
    bytes[at + 16..at + 24].copy_from_slice(&image.image_base.to_le_bytes());
    bytes[at + 24..at + 28].copy_from_slice(&(image.size_of_image as u32).to_le_bytes());
    bytes[at + 28..at + 32].copy_from_slice(&image.loader_flags.to_le_bytes());
    bytes[at + 32..at + 34].copy_from_slice(&(index as u16).to_le_bytes());
    bytes[at + 36..at + 38].copy_from_slice(&1u16.to_le_bytes()); // uma referência de carga
    let name: Vec<char> = image.name.replace('/', "\\").chars().take(255).collect();
    let file_offset = name.iter().rposition(|&character| character == '\\').map_or(0, |position| position + 1);
    bytes[at + 38..at + 40].copy_from_slice(&(file_offset as u16).to_le_bytes());
    for (position, &character) in name.iter().enumerate() {
        bytes[at + 40 + position] = if (character as u32) <= 255 { character as u8 } else { b'?' };
    }
    if extended {
        bytes[304..308].copy_from_slice(&image.checksum.to_le_bytes());
        bytes[308..312].copy_from_slice(&image.time_date_stamp.to_le_bytes());
    }
    bytes
}

pub fn query_system_modules(class: u32, output: u64, length: u64, returned: u64) -> Result<u32, KernelError> {
    if class != 11 && class != 77 {
        return Ok(0xC000_0003);
    }
    if length > 0xFFFF_FFFF {
        return Ok(0xC000_000D);
    }
    let records = loaded_images::list();
    let extended = class == 77;
    let (header, stride) = if extended { (2, 320) } else { (8, 296) };
    let needed = header + records.len() as u64 * stride;
    if returned != 0 {
        guest::try_write32(returned, needed as u32)?;
    }
    if length < header {
        return Ok(0xC000_0004);
    }
    if output == 0 {
        return Ok(0xC000_0005);
    }
    if extended {
        guest::try_write16(output, 0)?;
    } else {
        guest::try_write32(output, records.len() as u32)?;
        guest::try_write32(output + 4, 0)?;
    }
    let mut cursor = if extended { 0 } else { 8 };
    for (index, image) in records.iter().enumerate() {
        if cursor + stride + if extended { 2 } else { 0 } > length {
            break;
        }
        // Buffers curtos recebem só registros completos.
        guest::try_write_bytes(output + cursor, &module_bytes(image, index, extended))?;
        cursor += stride;
        if extended {
            guest::try_write16(output + cursor, 0)?;
        }
    }
    Ok(if length < needed { 0xC000_0004 } else { 0 })
}

// ---- MmGetPhysicalMemoryRanges --------------------------------------------

/// Array de PHYSICAL_MEMORY_RANGE terminado por zero, no pool não paginável.
pub fn query_physical_ranges() -> Result<u64, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("MmGetPhysicalMemoryRanges requires PASSIVE_LEVEL"));
    }
    let ranges = physical_layout::ranges();
    let options = AllocateOptions { paged: false, nx: true, tag: 0x6850_6D4D, zero: false, ..Default::default() };
    let pointer = kernel_pool::allocate((ranges.len() as u64 + 1) * 16, options)?;
    if pointer == 0 {
        return Ok(0);
    }
    let mut at = pointer;
    for (base, top) in ranges {
        guest::write64(at, base);
        guest::write64(at + 8, top - base);
        at += 16;
    }
    guest::write64(at, 0);
    guest::write64(at + 8, 0);
    Ok(pointer)
}

// ---- MmProtectMdlSystemAddress ---------------------------------------------
// Muda mapeamentos supervisores reais. Uma folha não presente retém PFN e
// cache; o bit de software 11 marca o NOACCESS deste gerenciador.

const NX: u64 = 1 << 63;
const FRAME: u64 = 0x000F_FFFF_FFFF_F000;
const NOACCESS: u64 = 0x800;

pub fn protect_mdl(mdl: u64, protection: u32) -> Result<u32, KernelError> {
    if irql::get_irql() > 2 {
        return Err(KernelError::new("MmProtectMdlSystemAddress above DISPATCH_LEVEL"));
    }
    if guest::try_read16(mdl + 0xA)? & 1 == 0 {
        return Ok(0xC000_0019);
    }
    let mapped = guest::try_read64(mdl + 0x18)?;
    if paging::query_page(mapped, true).is_some_and(|page| page.page_size != 4096) {
        return Ok(0xC000_00BB);
    }
    if ![1, 2, 4, 0x10, 0x20, 0x40].contains(&protection) {
        return Ok(0xC000_0045);
    }
    let count = (guest::try_read32(mdl + 0x28)? as u64 + (mapped & 4095)).div_ceil(4096);
    let base = mapped & !4095;
    let mut pages = Vec::new();
    for index in 0..count {
        let va = base + index * 4096;
        let page = paging::query_page(va, true).ok_or_else(|| KernelError::new("mapped MDL has no page table"))?;
        if page.page_size != 4096 {
            return Ok(0xC000_00BB);
        }
        let before = guest::read64(page.entry_address);
        if before & 1 == 0 && before & NOACCESS == 0 {
            return Err(KernelError::new("mapped MDL has an invalid PTE"));
        }
        pages.push((va, page.entry_address, before & FRAME));
    }
    let writable = protection == 4 || protection == 0x40;
    let executable = protection & 0x70 != 0;
    let previous = irql::raise_irql(2);
    let result = (|| -> Result<(), KernelError> {
        for &(va, at, frame) in &pages {
            loop {
                let before = guest::read64(at);
                if before & FRAME != frame {
                    return Err(KernelError::new("MDL mapping changed during protection"));
                }
                let mut after = before & !(3 | NX | NOACCESS);
                if protection == 1 {
                    after |= NOACCESS | NX;
                } else {
                    after |= 1;
                    if writable {
                        after |= 2;
                    }
                    if !executable {
                        after |= NX;
                    }
                }
                if guest::compare_exchange64(at, before, after)? == before {
                    break;
                }
            }
            cpu::invalidate_page(va);
        }
        if !pages.is_empty() {
            smp::flush_remote_tlb(false)?;
        }
        Ok(())
    })();
    irql::lower_irql(previous as u64);
    result.map(|_| 0)
}
