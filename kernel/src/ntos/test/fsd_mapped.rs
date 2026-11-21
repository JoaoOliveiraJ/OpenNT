//! A seção de dados de um arquivo do ntfs.sys real paginada sob demanda,
//! com a CONTROL_AREA publicada no FCB, o writer de páginas mapeadas, o
//! flush em grupos, o NtExtendSection e a leitura em cache assíncrona (o
//! volume E: do disco NVMe, `--storage=nvme`), pelos exports, como um driver
//! faria:
//!
//! - um arquivo de 64 páginas gravado sem cache: o FCB não tem seção de
//!   dados;
//! - ZwCreateSection(PAGE_READWRITE, SEC_COMMIT) não lê o arquivo (nenhuma
//!   página na control area) e publica a CONTROL_AREA no DataSectionObject
//!   (uma seção, uma referência de usuário, u.Flags.File, o FILE_OBJECT em
//!   FilePointer); a vista de sistema conta como vista mapeada, e o toque na
//!   página 5 traz só ela e o cluster seguinte, com os bytes do arquivo;
//! - com a vista gravável, MmDoesFileHaveUserWritableReferences é 1, o
//!   MmCanFileBeTruncated recusa um tamanho menor que o mapeado e o
//!   ZwSetInformationFile(FileEndOfFileInformation) do ntfs.sys devolve
//!   STATUS_USER_MAPPED_FILE;
//! - oito páginas vizinhas alteradas pela vista saem num IRP de paginação só
//!   pelo CcFlushCache sem SharedCacheMap (o MmFlushSection);
//! - dezesseis páginas alteradas pela vista, sem flush nem retirada, saem
//!   pelo writer de páginas mapeadas num IRP só;
//! - uma segunda seção estendida (MmExtendSection) além do fim do arquivo
//!   faz o ntfs.sys estender o arquivo, e a vista grava uma página da faixa
//!   nova;
//! - fechadas as seções, o DataSectionObject volta a zero;
//! - uma leitura em cache de um handle assíncrono numa página que ninguém
//!   trouxe passa pelo CcAsyncCopyRead do ntfs.sys e conclui pelo evento;
//! - a leitura sem cache do arquivo inteiro tem cada página esperada.
//!
//! A serial mostra `[fsd-mapped]` em cada passo e `FSD_MAPPED_OK` no fim.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{ControlArea, FileObject, SectionObjectPointers};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{mapped_writer, page_io};
use crate::ntos::ps::user::sections;
use crate::ntos::test::file_system_mount::object_attributes;
use crate::ntos::test::phase6::call_export;

const FILE_NAME: &str = "FSD-MAPA.BIN";
const PAGE: u64 = 0x1000;
const PAGES: u64 = 64;
const EXTENDED_PAGES: u64 = 80;
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
const EVENT_ALL_ACCESS: u64 = 0x001F_0003;
const PAGE_READWRITE: u64 = 4;
const SEC_COMMIT: u64 = 0x0800_0000;
const FILE_STANDARD_INFORMATION: u64 = 5;
const FILE_END_OF_FILE_INFORMATION: u64 = 20;
const STATUS_PENDING: u32 = 0x103;
const STATUS_USER_MAPPED_FILE: u32 = 0xC000_0243;
/// u.Flags.File da CONTROL_AREA.
const CONTROL_AREA_FILE: u32 = 1 << 7;

/// O byte `offset` da página `page` no padrão `round` (0 = página zerada).
fn pattern(round: u8, page: u64, offset: u64) -> u8 {
    if round == 0 {
        return 0;
    }
    round.wrapping_mul(29).wrapping_add((page as u8).wrapping_mul(11)).wrapping_add(offset as u8).wrapping_add(1)
}

fn page_bytes(round: u8, page: u64) -> Vec<u8> {
    (0..PAGE).map(|offset| pattern(round, page, offset)).collect()
}

/// O padrão de cada página no fim do teste.
fn final_round(page: u64) -> u8 {
    match page {
        24..=39 => 3,
        40..=47 => 2,
        0..=63 => 1,
        70 => 4,
        _ => 0,
    }
}

/// Blocos do convidado do teste.
struct Scratch {
    block: u64,
    aligned: u64,
}

impl Scratch {
    fn new() -> Option<Self> {
        let block = guest::alloc_bytes(0x1000);
        let aligned = crate::ntos::mm::independent_pages::allocate(EXTENDED_PAGES * PAGE, 0).unwrap_or(0);
        (block != 0 && aligned != 0).then_some(Self { block, aligned })
    }
    fn cell(&self, index: u64) -> u64 {
        self.block + 0x400 + index * 8
    }
    fn iosb(&self) -> u64 {
        self.block + 0x380
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        guest::free_bytes(self.block);
        let _ = crate::ntos::mm::independent_pages::free(self.aligned);
    }
}

fn export(name: &str, arguments: &[u64]) -> u32 {
    call_export(name, arguments).unwrap_or(u64::MAX) as u32
}

fn open(scratch: &Scratch, path: &str, access: u64, disposition: u64, options: u64) -> Result<u64, String> {
    let attributes = object_attributes(scratch.block, path);
    let handle = scratch.cell(60);
    let status = export("ZwCreateFile", &[handle, access, attributes, scratch.iosb(), 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_ALL, disposition, options | FILE_NON_DIRECTORY_FILE, 0, 0]);
    if status != 0 {
        return Err(format!("ZwCreateFile({path}, opcoes {options:#x}) devolveu {status:#x}"));
    }
    Ok(guest::read64(handle))
}

fn transfer(scratch: &Scratch, handle: u64, write: bool, buffer: u64, length: u64, offset: u64) -> Result<u64, String> {
    let offset_cell = scratch.cell(61);
    guest::write64(offset_cell, offset);
    let status = export(if write { "ZwWriteFile" } else { "ZwReadFile" }, &[handle, 0, 0, 0, scratch.iosb(), buffer, length, offset_cell, 0]);
    if status != 0 {
        return Err(format!("{} em {offset:#x} devolveu {status:#x}", if write { "ZwWriteFile" } else { "ZwReadFile" }));
    }
    Ok(guest::read64(scratch.iosb() + 8))
}

fn set_end_of_file(scratch: &Scratch, handle: u64, size: u64) -> u32 {
    let information = scratch.cell(62);
    guest::write64(information, size);
    export("ZwSetInformationFile", &[handle, scratch.iosb(), information, 8, FILE_END_OF_FILE_INFORMATION])
}

fn end_of_file(scratch: &Scratch, handle: u64) -> Result<u64, String> {
    let information = scratch.block + 0x300;
    let status = export("ZwQueryInformationFile", &[handle, scratch.iosb(), information, 24, FILE_STANDARD_INFORMATION]);
    if status != 0 {
        return Err(format!("ZwQueryInformationFile devolveu {status:#x}"));
    }
    Ok(guest::read64(information + 8))
}

/// O objeto de um handle (referenciado; o chamador solta).
fn object_of(scratch: &Scratch, handle: u64, access: u64, kind: u64) -> Result<u64, String> {
    let cell = scratch.cell(63);
    let status = export("ObReferenceObjectByHandle", &[handle, access, kind, 0, cell, 0]);
    if status != 0 {
        return Err(format!("ObReferenceObjectByHandle devolveu {status:#x}"));
    }
    Ok(guest::read64(cell))
}

/// Uma seção de dados sobre o handle (com o tamanho máximo pedido, 0 = o
/// do arquivo): (handle, objeto).
fn create_section(scratch: &Scratch, file: u64, maximum: u64) -> Result<(u64, u64), String> {
    let (section_cell, size_cell) = (scratch.cell(50), scratch.cell(51));
    guest::write64(size_cell, maximum);
    let created = export("ZwCreateSection", &[section_cell, SECTION_ALL_ACCESS, 0, if maximum != 0 { size_cell } else { 0 }, PAGE_READWRITE, SEC_COMMIT, file]);
    if created != 0 {
        return Err(format!("ZwCreateSection devolveu {created:#x}"));
    }
    let section = guest::read64(section_cell);
    let object = object_of(scratch, section, SECTION_ALL_ACCESS, crate::ntos::ob::object_types::section_type().pointer)?;
    Ok((section, object))
}

fn map_system(scratch: &Scratch, object: u64) -> Result<u64, String> {
    let (base_cell, size_cell) = (scratch.cell(52), scratch.cell(53));
    guest::write64(base_cell, 0);
    guest::write64(size_cell, 0);
    let mapped = export("MmMapViewInSystemSpace", &[object, base_cell, size_cell]);
    if mapped != 0 {
        return Err(format!("MmMapViewInSystemSpace devolveu {mapped:#x}"));
    }
    Ok(guest::read64(base_cell))
}

fn close_section(section: u64, object: u64, base: u64) -> Result<(), String> {
    let unmapped = if base != 0 { export("MmUnmapViewInSystemSpace", &[base]) } else { 0 };
    export("ObDereferenceObject", &[object]);
    let closed = export("ZwClose", &[section]);
    if unmapped != 0 || closed != 0 {
        return Err(format!("MmUnmapViewInSystemSpace {unmapped:#x}, ZwClose da secao {closed:#x}"));
    }
    Ok(())
}

/// Espera (até ~10 s) uma passada do writer de páginas mapeadas que comece
/// depois da chamada.
fn writer_pass(scratch: &Scratch) -> bool {
    let before = mapped_writer::statistics().2;
    mapped_writer::wake();
    let interval = scratch.cell(64);
    guest::write64(interval, (-500_000i64) as u64);
    for _ in 0..200 {
        if mapped_writer::statistics().2 >= before + 2 {
            return true;
        }
        if mapped_writer::statistics().2 > before {
            // A passada em curso pode ter começado antes das escritas: mais uma.
            mapped_writer::wake();
        }
        export("KeDelayExecutionThread", &[0, 0, interval]);
    }
    false
}

fn control_area_of(pointers: &SectionObjectPointers) -> Option<&'static ControlArea> {
    let address = pointers.data_section_object.get();
    // SAFETY: a CONTROL_AREA que o Mm publicou, viva enquanto a seção do teste existe.
    (address != 0).then(|| unsafe { ControlArea::at(address) })
}

fn scenario(scratch: &Scratch, volume: &str) -> Result<(), String> {
    let path = format!("{volume}\\{FILE_NAME}");
    // 1. 64 páginas sem cache: nenhuma seção de dados no FCB.
    let writer = open(scratch, &path, FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING)?;
    let initial: Vec<u8> = (0..PAGES).flat_map(|page| page_bytes(1, page)).collect();
    guest::write_bytes(scratch.aligned, &initial);
    let extended = set_end_of_file(scratch, writer, PAGES * PAGE);
    let written = transfer(scratch, writer, true, scratch.aligned, PAGES * PAGE, 0);
    export("ZwClose", &[writer]);
    if extended != 0 || written.as_ref().ok() != Some(&(PAGES * PAGE)) {
        return Err(format!("arquivo sem cache: EndOfFile {extended:#x}, escrita {written:?}"));
    }
    let handle = open(scratch, &path, FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT)?;
    let file = object_of(scratch, handle, 0, 0)?;
    // SAFETY: o FILE_OBJECT referenciado acima e o SECTION_OBJECT_POINTERS do FCB dele.
    let pointers_address = unsafe { FileObject::at(file) }.section_object_pointer.get();
    let pointers = unsafe { SectionObjectPointers::at(pointers_address) };
    debug_print!("[fsd-mapped] {} gravado sem cache: DataSectionObject {:#x}", path, pointers.data_section_object.get());
    if pointers.data_section_object.get() != 0 {
        return Err(String::from("o FCB tem seção de dados antes de qualquer seção"));
    }

    // 2. A seção não lê o arquivo e publica a CONTROL_AREA.
    let (section, object) = create_section(scratch, handle, 0)?;
    let owner = sections::by_pointer(object).ok_or_else(|| String::from("secao sem registro"))?;
    let resident = sections::present_mask(&owner, 0, PAGES);
    let control = control_area_of(pointers).ok_or_else(|| String::from("DataSectionObject vazio depois do ZwCreateSection"))?;
    debug_print!(
        "[fsd-mapped] ZwCreateSection: paginas residentes {:#x}; CONTROL_AREA {:#x}: secoes {}, usuario {}, vistas {}, flags {:#x}, FilePointer {:#x} (arquivo {:#x})",
        resident,
        control.address(),
        control.number_of_section_references.get(),
        control.number_of_user_references.get(),
        control.number_of_mapped_views.get(),
        control.u.long_flags.get(),
        control.file_pointer.value.get(),
        file
    );
    if resident != 0 || control.number_of_section_references.get() != 1 || control.number_of_user_references.get() != 1 || control.number_of_mapped_views.get() != 0 || control.u.long_flags.get() & CONTROL_AREA_FILE == 0 || control.file_pointer.value.get() & !0xF != file {
        return Err(String::from("a secao leu o arquivo ou a CONTROL_AREA nao tem os contadores da secao"));
    }
    let base = map_system(scratch, object)?;
    let first = guest::read_bytes(base + 5 * PAGE, PAGE as usize);
    let resident = sections::present_mask(&owner, 0, PAGES);
    debug_print!("[fsd-mapped] vista {:#x}: vistas mapeadas {}, pagina 5 {}, residentes {:#x}", base, control.number_of_mapped_views.get(), if first == page_bytes(1, 5) { "com os bytes do arquivo" } else { "DIFERENTE" }, resident);
    if control.number_of_mapped_views.get() != 1 || first != page_bytes(1, 5) || resident & 0x3F != 0x20 || resident.count_ones() > 16 || resident & (1 << 63) != 0 {
        return Err(String::from("a falta da pagina 5 nao trouxe so ela e o cluster seguinte"));
    }

    // 3. Vista gravável: referências de escrita e o truncamento recusado.
    let size_cell = scratch.cell(54);
    guest::write64(size_cell, 4 * PAGE);
    let writable = export("MmDoesFileHaveUserWritableReferences", &[pointers_address]);
    let smaller = export("MmCanFileBeTruncated", &[pointers_address, size_cell]) as u8;
    guest::write64(size_cell, PAGES * PAGE);
    let same = export("MmCanFileBeTruncated", &[pointers_address, size_cell]) as u8;
    let truncated = set_end_of_file(scratch, handle, 4 * PAGE);
    debug_print!("[fsd-mapped] referencias de escrita {}, MmCanFileBeTruncated: 4 paginas {}, 64 paginas {}; EndOfFile de 4 paginas pelo ntfs.sys {:#x}", writable, smaller, same, truncated);
    if writable != 1 || smaller != 0 || same != 1 || truncated != STATUS_USER_MAPPED_FILE {
        return Err(String::from("o arquivo mapeado com escrita aceitou o truncamento"));
    }

    // 4. Oito páginas vizinhas pelo MmFlushSection do CcFlushCache, num IRP.
    if !writer_pass(scratch) {
        return Err(String::from("o writer de paginas mapeadas nao fez a passada"));
    }
    for page in 40..48 {
        guest::write_bytes(base + page * PAGE, &page_bytes(2, page));
    }
    let before = page_io::write_statistics();
    let flushed = export("CcFlushCache", &[pointers_address, 0, 0, scratch.iosb()]);
    let after = page_io::write_statistics();
    let pending = sections::modified_count(&owner);
    debug_print!("[fsd-mapped] CcFlushCache {:#x} (IoStatus {:#x}): {} IRPs, {} paginas, {} pendentes", flushed, guest::read32(scratch.iosb()), after.0 - before.0, after.1 - before.1, pending);
    if guest::read32(scratch.iosb()) != 0 || after.0 - before.0 != 1 || after.1 - before.1 != 8 || pending != 0 {
        return Err(String::from("o flush nao gravou as oito paginas num IRP"));
    }

    // 5. Dezesseis páginas só pela vista: o writer as grava num IRP.
    for page in 24..40 {
        guest::write_bytes(base + page * PAGE, &page_bytes(3, page));
    }
    let before = page_io::write_statistics();
    let pages_before = mapped_writer::statistics().0;
    if !writer_pass(scratch) {
        return Err(String::from("o writer de paginas mapeadas nao fez a passada"));
    }
    let after = page_io::write_statistics();
    let by_writer = mapped_writer::statistics().0 - pages_before;
    let pending = sections::modified_count(&owner);
    debug_print!("[fsd-mapped] writer de paginas mapeadas: {} paginas, {} IRPs, {} pendentes", by_writer, after.0 - before.0, pending);
    if by_writer != 16 || after.0 - before.0 != 1 || after.1 - before.1 != 16 || pending != 0 {
        return Err(String::from("o writer nao gravou as dezesseis paginas num IRP"));
    }

    // 6. MmExtendSection além do fim do arquivo.
    let (big_section, big_object) = create_section(scratch, handle, PAGES * PAGE)?;
    let big = sections::by_pointer(big_object).ok_or_else(|| String::from("secao sem registro"))?;
    let mut new_size = EXTENDED_PAGES * PAGE;
    let status = crate::ntos::mm::section::extend::extend(&big, &mut new_size).map_err(|error| format!("MmExtendSection: {}", error.message))?;
    let file_size = end_of_file(scratch, handle)?;
    let mapped_size = crate::ntos::mm::section::control_area::published_size(pointers_address);
    debug_print!("[fsd-mapped] MmExtendSection {:#x}: secao {:#x}, arquivo {:#x}, CONTROL_AREA {:#x}", status, new_size, file_size, mapped_size);
    if status != 0 || new_size != EXTENDED_PAGES * PAGE || file_size != EXTENDED_PAGES * PAGE || mapped_size != EXTENDED_PAGES * PAGE {
        return Err(String::from("o MmExtendSection nao estendeu a secao e o arquivo"));
    }
    let big_base = map_system(scratch, big_object)?;
    let tail_zero = guest::read_bytes(big_base + 66 * PAGE, PAGE as usize).iter().all(|&byte| byte == 0);
    guest::write_bytes(big_base + 70 * PAGE, &page_bytes(4, 70));
    if !tail_zero {
        return Err(String::from("a faixa nova da secao estendida nao veio zerada"));
    }

    // 7. Fechadas as seções (a retirada grava), o slot volta a zero.
    close_section(big_section, big_object, big_base)?;
    close_section(section, object, base)?;
    drop(big);
    drop(owner);
    let slot = pointers.data_section_object.get();
    let cache_map = pointers.shared_cache_map.get();
    debug_print!("[fsd-mapped] secoes fechadas: DataSectionObject {:#x}, SharedCacheMap {:#x}", slot, cache_map);
    if slot != 0 && cache_map == 0 {
        return Err(String::from("a CONTROL_AREA ficou no FCB sem secao"));
    }
    export("ObDereferenceObject", &[file]);
    export("ZwClose", &[handle]);

    // 8. Leitura em cache assíncrona numa página que ninguém trouxe.
    let asynchronous = open(scratch, &path, FILE_GENERIC_READ, FILE_OPEN, 0)?;
    let event_cell = scratch.cell(55);
    let created = export("ZwCreateEvent", &[event_cell, EVENT_ALL_ACCESS, 0, 0, 0]);
    if created != 0 {
        export("ZwClose", &[asynchronous]);
        return Err(format!("ZwCreateEvent devolveu {created:#x}"));
    }
    let event = guest::read64(event_cell);
    let (offset_cell, timeout) = (scratch.cell(56), scratch.cell(57));
    guest::write64(offset_cell, 60 * PAGE);
    guest::write64(timeout, (-100_000_000i64) as u64);
    guest::write32(scratch.iosb(), STATUS_PENDING);
    let buffer = scratch.aligned;
    crate::ntos::cc::vacb::zero_bytes(buffer, PAGE);
    let issued = export("ZwReadFile", &[asynchronous, event, 0, 0, scratch.iosb(), buffer, PAGE, offset_cell, 0]);
    let waited = if issued == STATUS_PENDING { export("ZwWaitForSingleObject", &[event, 0, timeout]) } else { 0 };
    let (code, count) = (guest::read32(scratch.iosb()), guest::read64(scratch.iosb() + 8));
    let data = guest::read_bytes(buffer, PAGE as usize);
    export("ZwClose", &[event]);
    export("ZwClose", &[asynchronous]);
    debug_print!("[fsd-mapped] leitura assincrona: ZwReadFile {:#x}, espera {:#x}, IoStatus {:#x}/{}, {}", issued, waited, code, count, if data == page_bytes(1, 60) { "bytes certos" } else { "bytes DIFERENTES" });
    if (issued != 0 && issued != STATUS_PENDING) || waited != 0 || code != 0 || count != PAGE || data != page_bytes(1, 60) {
        return Err(String::from("a leitura em cache assincrona nao concluiu"));
    }

    // 9. O arquivo inteiro do disco.
    let direct = open(scratch, &path, FILE_GENERIC_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING)?;
    crate::ntos::cc::vacb::zero_bytes(scratch.aligned, EXTENDED_PAGES * PAGE);
    let read = transfer(scratch, direct, false, scratch.aligned, EXTENDED_PAGES * PAGE, 0);
    export("ZwClose", &[direct]);
    let read = read?;
    let wrong: Vec<u64> = (0..EXTENDED_PAGES).filter(|&page| guest::read_bytes(scratch.aligned + page * PAGE, PAGE as usize) != page_bytes(final_round(page), page)).collect();
    debug_print!("[fsd-mapped] leitura sem cache: {} bytes, paginas erradas {:?}", read, wrong);
    if read != EXTENDED_PAGES * PAGE || !wrong.is_empty() {
        return Err(String::from("o disco nao tem o que as vistas gravaram"));
    }
    Ok(())
}

/// O cenário sobre o volume `volume` (`\??\E:`).
pub fn run(volume: &str) -> Result<(), String> {
    let scratch = Scratch::new().ok_or_else(|| String::from("sem memoria para o teste"))?;
    scenario(&scratch, volume)
}
