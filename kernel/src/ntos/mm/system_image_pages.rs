//! Backing compartilhado de seções de imagem.
//!
//! Copia o layout virtual do PE para o espaço global, sem executar entry
//! point, resolver imports ou aplicar relocações. A control area é
//! compartilhada pela identidade do arquivo (ou pela própria seção).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::hal::physical;
use crate::ntos::ps::user::sections::{Area, AreaKey, AreaRef, Section, SectionFile};
use crate::rtl::{KernelError, SpinLock};

/// Faixa do layout virtual: cabeçalhos ou uma seção PE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageRange {
    pub base: u64,
    pub length: u64,
    pub file_offset: u64,
    pub raw_size: u64,
    pub flags: u32,
}

static IMAGE_AREAS: SpinLock<BTreeMap<AreaKey, AreaRef>> = SpinLock::new(BTreeMap::new());

fn read(file: &Arc<dyn SectionFile>, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
    if offset.checked_add(length).is_none_or(|end| end > file.size()) {
        return Err(KernelError::with_status("image section read exceeds file", 0xC000_007B));
    }
    let source = file.read_at(offset, length)?;
    if source.len() as u64 != length {
        return Err(KernelError::with_status("short image section read", 0xC000_0185));
    }
    Ok(source)
}

fn invalid(message: &str) -> KernelError {
    KernelError::with_status(message, 0xC000_007B)
}

/// Cabeçalhos (legíveis) e as seções do PE, validadas contra o
/// SizeOfImage da seção e o tamanho do arquivo.
pub fn layout(section: &Section) -> Result<Vec<ImageRange>, KernelError> {
    let file = section.file.as_ref().ok_or_else(|| invalid("image section without file"))?;
    let dos = read(file, 0, 64)?;
    let word = |bytes: &[u8], offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let dword = |bytes: &[u8], offset: usize| u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
    let portable_offset = dword(&dos, 0x3C) as u64;
    let header = read(file, portable_offset, 88)?;
    let count = word(&header, 6) as u64;
    let optional_size = word(&header, 20) as u64;
    let headers_size = dword(&header, 84) as u64;
    if word(&dos, 0) != 0x5A4D || dword(&header, 0) != 0x4550 || word(&header, 4) != 0x8664 || word(&header, 24) != 0x20B || optional_size < 64 || dword(&header, 80) as u64 != section.size || headers_size > section.size || headers_size > file.size() {
        return Err(invalid("invalid system image section"));
    }
    let table = read(file, portable_offset + 24 + optional_size, count * 40)?;
    let mut ranges = vec![ImageRange { base: 0, length: headers_size, file_offset: 0, raw_size: headers_size, flags: 0x4000_0000 }];
    for index in 0..count as usize {
        let position = index * 40;
        let base = dword(&table, position + 12) as u64;
        let raw_size = dword(&table, position + 16) as u64;
        let file_offset = dword(&table, position + 20) as u64;
        let length = raw_size.max(dword(&table, position + 8) as u64);
        if base + length > section.size || file_offset + raw_size > file.size() {
            return Err(invalid("invalid image section range"));
        }
        ranges.push(ImageRange { base, length, file_offset, raw_size, flags: dword(&table, position + 36) });
    }
    Ok(ranges)
}

/// Liga a seção de imagem à control area compartilhada.
pub fn prepare(section: &Arc<Section>) -> Result<(), KernelError> {
    if !section.is_image || section.control_area().is_some() {
        return Ok(());
    }
    let key = section.file.as_ref().and_then(|file| file.identity()).map_or(AreaKey::Section(section.pointer()), AreaKey::Identity);
    let existing = IMAGE_AREAS.lock().get(&key).cloned();
    let area = match existing {
        Some(area) => area,
        None => {
            let mut area = Area::new(None, 0);
            area.image_layout = layout(section)?;
            area.image_key = Some(key.clone());
            let area = Arc::new(SpinLock::new(area));
            IMAGE_AREAS.lock().insert(key, area.clone());
            area
        }
    };
    area.lock().references += 1;
    section.state.lock().area = Some(area);
    Ok(())
}

/// Liberação da imagem na última referência da control area.
pub fn release_image(key: &AreaKey) {
    IMAGE_AREAS.lock().remove(key);
}

/// Proteção da página pelas faixas que a cobrem.
pub fn protection(section: &Section, page: u64) -> u32 {
    if section.no_execute {
        return 2;
    }
    let start = page * 4096;
    let mut flags = 0u32;
    if let Some(area) = section.control_area() {
        for range in &area.lock().image_layout {
            if start < range.base + range.length && start + 4096 > range.base {
                flags |= range.flags;
            }
        }
    }
    let execute = flags & 0x2000_0000 != 0;
    let readable = flags & 0x4000_0000 != 0;
    let copy = flags & 0x8000_0000 != 0;
    if execute {
        if copy {
            0x80
        } else if readable {
            0x20
        } else {
            0x10
        }
    } else if copy {
        8
    } else if readable {
        2
    } else {
        1
    }
}

/// Preenche `page_count` páginas a partir de `page` com os bytes crus das
/// faixas; o resto fica zerado.
pub fn fill(section: &Section, page: u64, frame: u64, page_count: u64) -> Result<(), KernelError> {
    let file = section.file.as_ref().ok_or_else(|| invalid("image section without file"))?;
    let byte_length = page_count * 4096;
    let direct = file.has_copy_to_physical();
    let mut data = if direct { Vec::new() } else { vec![0u8; byte_length as usize] };
    if direct {
        physical::zero(frame, byte_length as usize);
    }
    let start = page * 4096;
    let ranges = section.control_area().map(|area| area.lock().image_layout.clone()).unwrap_or_default();
    for range in ranges {
        let first = start.max(range.base);
        let end = (start + byte_length).min(range.base + range.raw_size);
        if first >= end {
            continue;
        }
        let offset = range.file_offset + first - range.base;
        if offset + end - first > file.size() {
            return Err(invalid("image section read exceeds file"));
        }
        if direct {
            file.copy_to_physical(offset, frame + first - start, end - first)?;
        } else {
            let bytes = read(file, offset, end - first)?;
            let at = (first - start) as usize;
            data[at..at + bytes.len()].copy_from_slice(&bytes);
        }
    }
    if !direct {
        physical::write_bytes(frame, &data);
    }
    Ok(())
}
