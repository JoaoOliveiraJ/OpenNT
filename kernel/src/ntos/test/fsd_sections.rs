//! Seções de dados sobre um arquivo servido pelo ntfs.sys real (o volume E:
//! do disco NVMe, `--storage=nvme`), pelos exports, como um driver faria:
//!
//! - um arquivo de três páginas é gravado pelo cache (ZwWriteFile);
//! - ZwCreateSection(PAGE_READWRITE, SEC_COMMIT) sobre o handle e
//!   MmMapViewInSystemSpace: a vista mostra o que o cache tem (a seção e o
//!   cache usam a mesma página: a control area do stream, pelos
//!   SECTION_OBJECT_POINTERS);
//! - uma segunda seção, por outro handle do mesmo arquivo, tem a mesma
//!   página: o que a primeira vista grava aparece na segunda na hora;
//! - um ZwReadFile pelo cache lê o que a vista gravou;
//! - a retirada das vistas grava a página pela escrita de paginação
//!   (IoSynchronousPageWrite), e uma leitura sem cache
//!   (FILE_NO_INTERMEDIATE_BUFFERING), que vai ao disco, confirma os bytes.
//!
//! A serial mostra `[fsd-section]` em cada passo e `NVME_SECTION_OK` no fim.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::test::file_system_mount::object_attributes;
use crate::ntos::test::phase6::call_export;

const FILE_NAME: &str = "OPENNT-SECAO.BIN";
const PAGE: u64 = 0x1000;
const PAGES: u64 = 3;
const FILE_GENERIC_READ: u64 = 0x0012_0089;
const FILE_GENERIC_WRITE: u64 = 0x0012_0116;
const FILE_ATTRIBUTE_NORMAL: u64 = 0x80;
const FILE_SHARE_ALL: u64 = 7;
const FILE_OPEN: u64 = 1;
const FILE_OVERWRITE_IF: u64 = 5;
const FILE_SYNCHRONOUS_IO_NONALERT: u64 = 0x20;
const FILE_NON_DIRECTORY_FILE: u64 = 0x40;
const FILE_NO_INTERMEDIATE_BUFFERING: u64 = 0x08;
const SECTION_ALL_ACCESS: u64 = 0x000F_001F;
const PAGE_READWRITE: u64 = 4;
const SEC_COMMIT: u64 = 0x0800_0000;

/// O byte da página `page` no padrão `round`.
fn pattern(round: u8, page: u64, offset: u64) -> u8 {
    round.wrapping_mul(31).wrapping_add((page as u8).wrapping_mul(7)).wrapping_add(offset as u8)
}

fn page_bytes(round: u8, page: u64) -> Vec<u8> {
    (0..PAGE).map(|offset| pattern(round, page, offset)).collect()
}

/// Blocos do convidado do teste, devolvidos no fim.
struct Scratch {
    block: u64,
    buffer: u64,
    aligned: u64,
}

impl Scratch {
    fn new() -> Option<Self> {
        let block = guest::alloc_bytes(0x800);
        let buffer = guest::alloc_bytes(PAGES * PAGE);
        // A leitura sem cache exige buffer alinhado ao setor.
        let aligned = crate::ntos::mm::independent_pages::allocate(PAGES * PAGE, 0).unwrap_or(0);
        if block == 0 || buffer == 0 || aligned == 0 {
            return None;
        }
        Some(Self { block, buffer, aligned })
    }
    fn handle(&self) -> u64 {
        self.block + 0x300
    }
    fn iosb(&self) -> u64 {
        self.block + 0x310
    }
    fn offset(&self) -> u64 {
        self.block + 0x320
    }
    fn cell(&self, index: u64) -> u64 {
        self.block + 0x340 + index * 8
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        guest::free_bytes(self.block);
        guest::free_bytes(self.buffer);
        let _ = crate::ntos::mm::independent_pages::free(self.aligned);
    }
}

fn export(name: &str, arguments: &[u64]) -> u32 {
    call_export(name, arguments).unwrap_or(u64::MAX) as u32
}

fn open(scratch: &Scratch, path: &str, access: u64, disposition: u64, options: u64) -> Result<u64, String> {
    let attributes = object_attributes(scratch.block, path);
    let status = export("ZwCreateFile", &[scratch.handle(), access, attributes, scratch.iosb(), 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_ALL, disposition, options | FILE_NON_DIRECTORY_FILE, 0, 0]);
    if status != 0 {
        return Err(format!("ZwCreateFile({path}, opcoes {options:#x}) devolveu {status:#x}"));
    }
    Ok(guest::read64(scratch.handle()))
}

fn transfer(scratch: &Scratch, handle: u64, write: bool, buffer: u64, length: u64, offset: u64) -> Result<u64, String> {
    guest::write64(scratch.offset(), offset);
    let status = export(if write { "ZwWriteFile" } else { "ZwReadFile" }, &[handle, 0, 0, 0, scratch.iosb(), buffer, length, scratch.offset(), 0]);
    let count = guest::read64(scratch.iosb() + 8);
    if status != 0 {
        return Err(format!("{} em {offset:#x} devolveu {status:#x}", if write { "ZwWriteFile" } else { "ZwReadFile" }));
    }
    Ok(count)
}

/// Uma seção de dados sobre o handle e a vista dela no espaço de sistema:
/// (handle da seção, objeto, base).
fn map_section(scratch: &Scratch, file: u64, slot: u64) -> Result<(u64, u64, u64), String> {
    let section_cell = scratch.cell(slot * 4);
    let object_cell = scratch.cell(slot * 4 + 1);
    let base_cell = scratch.cell(slot * 4 + 2);
    let size_cell = scratch.cell(slot * 4 + 3);
    let created = export("ZwCreateSection", &[section_cell, SECTION_ALL_ACCESS, 0, 0, PAGE_READWRITE, SEC_COMMIT, file]);
    if created != 0 {
        return Err(format!("ZwCreateSection devolveu {created:#x}"));
    }
    let section = guest::read64(section_cell);
    let section_type = crate::ntos::ob::object_types::section_type().pointer;
    let referenced = export("ObReferenceObjectByHandle", &[section, SECTION_ALL_ACCESS, section_type, 0, object_cell, 0]);
    if referenced != 0 {
        export("ZwClose", &[section]);
        return Err(format!("ObReferenceObjectByHandle da secao devolveu {referenced:#x}"));
    }
    let object = guest::read64(object_cell);
    guest::write64(base_cell, 0);
    guest::write64(size_cell, 0);
    let mapped = export("MmMapViewInSystemSpace", &[object, base_cell, size_cell]);
    if mapped != 0 {
        export("ObDereferenceObject", &[object]);
        export("ZwClose", &[section]);
        return Err(format!("MmMapViewInSystemSpace devolveu {mapped:#x}"));
    }
    Ok((section, object, guest::read64(base_cell)))
}

fn unmap_section(section: u64, object: u64, base: u64) -> Result<(), String> {
    let unmapped = export("MmUnmapViewInSystemSpace", &[base]);
    export("ObDereferenceObject", &[object]);
    let closed = export("ZwClose", &[section]);
    if unmapped != 0 || closed != 0 {
        return Err(format!("MmUnmapViewInSystemSpace {unmapped:#x}, ZwClose da secao {closed:#x}"));
    }
    Ok(())
}

fn scenario(scratch: &Scratch, volume: &str) -> Result<(), String> {
    let path = format!("{volume}\\{FILE_NAME}");
    // 1. Três páginas pelo cache.
    let writer = open(scratch, &path, FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT)?;
    let initial: Vec<u8> = (0..PAGES).flat_map(|page| page_bytes(1, page)).collect();
    guest::write_bytes(scratch.buffer, &initial);
    let written = transfer(scratch, writer, true, scratch.buffer, PAGES * PAGE, 0)?;
    debug_print!("[fsd-section] {} gravado pelo cache: {} bytes", path, written);
    if written != PAGES * PAGE {
        return Err(format!("escrita pelo cache com {written} bytes"));
    }
    // O cache vai ao disco agora (CcFlushCache pelo IRP_MJ_FLUSH_BUFFERS):
    // depois disso só a seção grava a página 1.
    let flushed = export("ZwFlushBuffersFile", &[writer, scratch.iosb()]);
    if flushed != 0 {
        return Err(format!("ZwFlushBuffersFile devolveu {flushed:#x}"));
    }
    // 2. A seção e a vista mostram o que o cache tem.
    let (first_section, first_object, first_base) = map_section(scratch, writer, 0)?;
    let seen = guest::read_bytes(first_base, (PAGES * PAGE) as usize);
    debug_print!("[fsd-section] vista de sistema {:#x}: {}", first_base, if seen == initial { "igual ao cache" } else { "DIFERENTE do cache" });
    if seen != initial {
        return Err(String::from("a vista nao mostra os bytes gravados pelo cache"));
    }
    // 3. Outro handle, outra seção: a mesma página.
    let reader = open(scratch, &path, FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT)?;
    let (second_section, second_object, second_base) = map_section(scratch, reader, 1)?;
    let changed = page_bytes(2, 1);
    guest::write_bytes(first_base + PAGE, &changed);
    let shared = guest::read_bytes(second_base + PAGE, PAGE as usize) == changed;
    let frames = (crate::ntos::mm::paging::translate(first_base + PAGE), crate::ntos::mm::paging::translate(second_base + PAGE));
    debug_print!("[fsd-section] segunda secao em {:#x}: pagina 1 {} (frames {:#x} e {:#x})", second_base, if shared { "compartilhada" } else { "NAO compartilhada" }, frames.0, frames.1);
    if !shared || frames.0 != frames.1 {
        return Err(String::from("as duas secoes do arquivo nao usam a mesma pagina"));
    }
    // 4. O cache lê o que a vista gravou.
    guest::write_bytes(scratch.buffer, &alloc::vec![0u8; PAGE as usize]);
    let read = transfer(scratch, reader, false, scratch.buffer, PAGE, PAGE)?;
    let cached = guest::read_bytes(scratch.buffer, PAGE as usize) == changed;
    debug_print!("[fsd-section] ZwReadFile pelo cache depois da escrita na vista: {} bytes, {}", read, if cached { "iguais" } else { "DIFERENTES" });
    if read != PAGE || !cached {
        return Err(String::from("o cache nao ve a escrita da vista"));
    }
    // 5. A retirada grava a página; a leitura sem cache vai ao disco.
    unmap_section(second_section, second_object, second_base)?;
    unmap_section(first_section, first_object, first_base)?;
    export("ZwClose", &[reader]);
    export("ZwClose", &[writer]);
    let direct = open(scratch, &path, FILE_GENERIC_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING)?;
    crate::ntos::cc::vacb::zero_bytes(scratch.aligned, PAGES * PAGE);
    let read = transfer(scratch, direct, false, scratch.aligned, PAGES * PAGE, 0);
    export("ZwClose", &[direct]);
    let read = read?;
    let disk = guest::read_bytes(scratch.aligned, (PAGES * PAGE) as usize);
    let expected: Vec<u8> = (0..PAGES).flat_map(|page| if page == 1 { page_bytes(2, 1) } else { page_bytes(1, page) }).collect();
    debug_print!("[fsd-section] leitura sem cache: {} bytes, {}", read, if disk == expected { "a pagina da vista esta no disco" } else { "DIFERENTE do esperado" });
    if read != PAGES * PAGE || disk != expected {
        return Err(String::from("a escrita da vista nao chegou ao disco"));
    }
    Ok(())
}

/// O cenário sobre o volume `volume` (`\??\E:`).
pub fn run(volume: &str) -> Result<(), String> {
    let scratch = Scratch::new().ok_or_else(|| String::from("sem memoria para o teste"))?;
    scenario(&scratch, volume)
}
