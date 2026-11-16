//! Arquivo de paginação e working set (`mm/paging_file`, `mm/working_set`,
//! `mm/modified_writer`, `mm/commit`, `mm/memory_information`), no fim da
//! fase 7:
//!
//! - NtCreatePagingFile recusa, antes de tocar arquivo: Priority com bits
//!   reservados, com o bit 31 e o 30, e o bit 23 com outro
//!   (STATUS_INVALID_PARAMETER_4); de modo usuário, o UNICODE_STRING
//!   desalinhado (STATUS_DATATYPE_MISALIGNMENT); mínimo abaixo de 1 MB ou
//!   acima do teto (STATUS_INVALID_PARAMETER_2); máximo abaixo do mínimo
//!   (STATUS_INVALID_PARAMETER_3); nome vazio ou de mais de 256 bytes
//!   (STATUS_OBJECT_NAME_INVALID); o bit 23 sozinho, depois da captura
//!   (STATUS_NOT_SUPPORTED).
//! - Sem arquivo de paginação, a SystemPageFileInformation devolve a
//!   primeira entrada zerada e ReturnLength 0; um buffer menor que uma
//!   entrada é STATUS_INFO_LENGTH_MISMATCH com 0x20 (0x28 na Ex). A
//!   SystemPerformanceInformation devolve o commit do sistema e recusa
//!   menos de 0x138 bytes com ReturnLength 0x158.
//! - Um arquivo de paginação de 1 MB a 2 MB em D:: a lista ganha o arquivo
//!   com 256 páginas, o limite de commit sobe 256 páginas e o commit cobra
//!   as duas reservadas; a mesma chamada de novo acha o arquivo na lista, e
//!   um máximo menor é STATUS_INVALID_PARAMETER_3.
//! - Num processo parado com espaço próprio, 16 páginas privadas gravadas:
//!   o esvaziamento do working set deixa a PTE de transição (Valid 0, Transition,
//!   Protection MM_READWRITE, Write e o mesmo frame); o modified page writer
//!   grava as páginas e o reaproveitamento deixa a PTE de arquivo de
//!   paginação (PageFileLow = o arquivo, PageFileHigh a partir de 2, a
//!   mesma proteção) e devolve os frames; a SystemPageFileInformation conta
//!   as páginas em uso; a releitura, anexada, traz tudo de volta pelo
//!   IoPageRead, intacto; um segundo corte leva as páginas limpas direto à
//!   reserva, sem nova escrita, com a mesma cópia; uma página escrita de
//!   novo perde a cópia; a liberação devolve o espaço do arquivo.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::paging_file::create::create_paging_file;
use crate::ntos::mm::{commit, modified_writer, paging, paging_file, working_set};
use crate::ntos::ps::create::{self, ImageOrigin};
use crate::ntos::ps::process_context;
use crate::ntos::ps::user::memory::{self, PrivateRegion, Space};
use crate::ntos::ps::user::process::{self as user_process, RunOptions};
use crate::ntos::ps::user::state;
use crate::ntos::mm::process_address_space as address_space;
use core::sync::atomic::Ordering;

type Assert = fn(bool, &str);

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const NAME: &str = "\\??\\D:\\OPENNT-PAGEFILE.SYS";
const MEGABYTE: u64 = 0x10_0000;
const PAGES: u64 = 16;
const PAGE: u64 = 0x1000;
const MAGIC: u64 = 0x0DD0_C0FF_EE00_5EED;

/// Os blocos de kernel do teste: o UNICODE_STRING, os tamanhos e o nome.
struct Block {
    address: u64,
}

impl Block {
    fn new() -> Option<Self> {
        let address = guest::alloc_bytes(0x400);
        (address != 0).then_some(Self { address })
    }

    /// Prepara nome (`length` bytes do texto, ou o texto inteiro), mínimo e
    /// máximo; devolve (nome, mínimo, máximo).
    fn request(&self, name: &str, length: Option<u16>, minimum: u64, maximum: u64) -> (u64, u64, u64) {
        let units: Vec<u8> = name.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        guest::write_bytes(self.address + 0x100, &units);
        guest::write16(self.address, length.unwrap_or(units.len() as u16));
        guest::write16(self.address + 2, length.unwrap_or(units.len() as u16));
        guest::write64(self.address + 8, self.address + 0x100);
        guest::write64(self.address + 0x20, minimum);
        guest::write64(self.address + 0x28, maximum);
        (self.address, self.address + 0x20, self.address + 0x28)
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        guest::free_bytes(self.address);
    }
}

fn create(block: &Block, name: &str, length: Option<u16>, minimum: u64, maximum: u64, mode: u8, priority: u32) -> u32 {
    let (name, minimum, maximum) = block.request(name, length, minimum, maximum);
    create_paging_file(name, minimum, maximum, mode, priority).unwrap_or(1)
}

pub fn run(assert: Assert) {
    let Some(block) = Block::new() else {
        assert(false, "pagefile: memoria do teste");
        return;
    };
    validation(assert, &block);
    information_without_files(assert);
    if paging_file::count() != 0 {
        assert(false, "pagefile: nenhum arquivo de paginacao antes do teste");
        return;
    }
    let before = commit::snapshot();
    assert(create(&block, NAME, None, MEGABYTE, 2 * MEGABYTE, 0, 0) == 0 && paging_file::count() == 1, "pagefile: NtCreatePagingFile cria o arquivo de 1 MB a 2 MB em D: e o poe na lista");
    let after = commit::snapshot();
    let files = paging_file::information();
    let listed = files.first().is_some_and(|file| file.total_size == 256 && file.total_in_use == 0 && file.minimum == 256 && file.maximum == 512 && file.name == NAME);
    assert(listed && after.limit == before.limit + 256 && after.limit_maximum == before.limit_maximum + 512 && after.committed >= before.committed + 2, "pagefile: o MMPAGING_FILE tem 256 paginas e o commit ganha o limite e cobra as duas reservadas");
    assert(create(&block, NAME, None, MEGABYTE, 2 * MEGABYTE, 0, 0) == 0 && create(&block, NAME, None, MEGABYTE, MEGABYTE, 0, 0) == STATUS_INVALID_PARAMETER_3 && paging_file::count() == 1, "pagefile: o arquivo ja na lista e achado de novo, e o maximo menor e recusado");
    paging(assert);
}

fn validation(assert: Assert, block: &Block) {
    let name = "\\??\\D:\\OPENNT-NAOCRIADO.SYS";
    let priorities = create(block, name, None, MEGABYTE, MEGABYTE, 0, 1) == STATUS_INVALID_PARAMETER_4
        && create(block, name, None, MEGABYTE, MEGABYTE, 0, 0xC000_0000) == STATUS_INVALID_PARAMETER_4
        && create(block, name, None, MEGABYTE, MEGABYTE, 0, 0x0180_0000) == STATUS_INVALID_PARAMETER_4;
    let (name_pointer, minimum, maximum) = block.request(name, None, MEGABYTE, MEGABYTE);
    let misaligned = create_paging_file(name_pointer + 2, minimum, maximum, 1, 0).unwrap_or(1) == STATUS_DATATYPE_MISALIGNMENT;
    let sizes = create(block, name, None, MEGABYTE - 1, MEGABYTE, 0, 0) == STATUS_INVALID_PARAMETER_2
        && create(block, name, None, 0x1000_0000_0000, 0x1000_0000_0000, 0, 0) == STATUS_INVALID_PARAMETER_2
        && create(block, name, None, 2 * MEGABYTE, MEGABYTE, 0, 0) == STATUS_INVALID_PARAMETER_3;
    let names = create(block, name, Some(0), MEGABYTE, MEGABYTE, 0, 0) == STATUS_OBJECT_NAME_INVALID && create(block, name, Some(0x102), MEGABYTE, MEGABYTE, 0, 0) == STATUS_OBJECT_NAME_INVALID;
    let unsupported = create(block, name, None, MEGABYTE, MEGABYTE, 0, 0x80_0000) == STATUS_NOT_SUPPORTED;
    assert(priorities && misaligned && sizes && names && unsupported && paging_file::count() == 0, "pagefile: NtCreatePagingFile valida Priority, alinhamento, tamanhos e nome antes de criar o arquivo");
}

/// Uma consulta pelo handler de usuário, com o buffer numa região do System.
fn query(class: u64, buffer: u64, length: u64, returned: u64) -> u32 {
    state::handler("NtQuerySystemInformation").map_or(1, |handler| handler(class, buffer, length, returned, 0).unwrap_or(1))
}

fn information_without_files(assert: Assert) {
    let Ok(block) = memory::map_user_region(0x1000) else {
        assert(false, "pagefile: memoria de usuario");
        return;
    };
    let (buffer, returned) = (block, block + 0x800);
    guest::write_bytes(buffer, &[0xAA; 0x40]);
    let empty = query(18, buffer, 0x100, returned) == 0 && guest::read32(returned) == 0 && guest::read32(buffer) == 0 && guest::read32(buffer + 4) == 0;
    let short = query(18, buffer, 0x10, returned) == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 0x20 && query(144, buffer, 0x20, returned) == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 0x28;
    assert(empty && short, "pagefile: SystemPageFileInformation sem arquivos e com buffer curto");
    let before = commit::snapshot();
    guest::write_bytes(buffer, &[0xAA; 0x160]);
    let full = query(2, buffer, 0x158, returned) == 0 && guest::read32(returned) == 0x158;
    let after = commit::snapshot();
    let committed = guest::read32(buffer + 0x30) as u64;
    let counters = guest::read32(buffer + 0x2C) != 0 && committed >= before.committed.min(after.committed) && committed <= before.committed.max(after.committed) && guest::read32(buffer + 0x34) as u64 == after.limit && guest::read32(buffer + 0x38) as u64 >= committed && guest::read8(buffer + 0x158) == 0xAA;
    let prefix = query(2, buffer, 0x140, returned) == 0 && guest::read32(returned) == 0x140 && query(2, buffer, 0x100, returned) == STATUS_INFO_LENGTH_MISMATCH && guest::read32(returned) == 0x158;
    assert(full && counters && prefix, "pagefile: SystemPerformanceInformation com o commit do sistema, 0x158 bytes ou o prefixo pedido");
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}

/// O exe parado do processo de teste: só NtTerminateProcess.
fn parked_image() -> Option<Vec<u8>> {
    let live = state::with(|state| state.name_by_number.iter().find(|(_, name)| name.as_str() == "NtTerminateProcess").map(|(&number, _)| number));
    let terminate = live.or_else(|| crate::ntos::ex::service_abi::NATIVE.entries.iter().find(|entry| entry.1 == "NtTerminateProcess").map(|entry| entry.0))?;
    let mut code = alloc::vec![0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xD2, 0x49, 0x89, 0xCA, 0xB8];
    code.extend_from_slice(&terminate.to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x05, 0xEB, 0xFE]);
    Some(crate::ntos::test::phase7::single_section_image(0x1_4000_0000, 0x0022, b".text", 0x6000_0020, 0x1000, &code))
}

fn pte(root: u64, va: u64) -> u64 {
    paging::read_leaf_in(root, va).unwrap_or(0)
}

/// O formato de transição: Valid 0, Write, Protection, Transition e o frame.
fn transition(entry: u64, frame: u64) -> bool {
    entry & 1 == 0 && entry & (1 << 11) != 0 && entry & 0x000F_FFFF_FFFF_F000 == frame && (entry >> 5) & 0x1F == 4 && entry & 2 != 0
}

/// O formato de arquivo de paginação: Valid 0, sem Transition, a proteção,
/// PageFileLow = 0 e PageFileHigh a partir de 2.
fn page_file(entry: u64) -> Option<u64> {
    (entry & 1 == 0 && entry & (1 << 11) == 0 && (entry >> 5) & 0x1F == 4 && (entry >> 12) & 0xF == 0 && entry >> 32 >= 2).then_some(entry >> 32)
}

fn paging(assert: Assert) {
    let Some(image) = parked_image() else {
        assert(false, "pagefile: numero do NtTerminateProcess");
        return;
    };
    let request = user_process::windows_process_request(ImageOrigin::Bytes(image), "paginado.exe", "C:\\paginado.exe", &RunOptions::default());
    let Ok(child) = create::create_user_process(&request) else {
        assert(false, "pagefile: processo de teste parado");
        return;
    };
    let process = child.process_pointer;
    let root = address_space::root_of(process).unwrap_or(0);
    let Ok(cells) = memory::map_user_region(0x1000) else {
        assert(false, "pagefile: memoria do teste");
        return;
    };
    guest::write64(cells, 0);
    guest::write64(cells + 8, PAGES * PAGE);
    let allocated = memory::allocate_in(Space::of(process), cells, cells + 8, 0x3000, 4, 0, 0, 0x1_0000).unwrap_or(1) == 0;
    let base = guest::read64(cells);
    let region = Space::of(process).find(base);
    let owner = region.as_ref().and_then(|region| region.as_any().downcast_ref::<PrivateRegion>());
    let (Some(region), Some(owner), true) = (region.clone(), owner, allocated && root != 0) else {
        assert(false, "pagefile: regiao privada no processo de teste");
        return;
    };
    let write_all = || process_context::with_process(process, || (0..PAGES).all(|page| (0..PAGE / 8).all(|word| guest::try_write::<u64>(base + page * PAGE + word * 8, (base + page * PAGE + word * 8) ^ MAGIC).is_ok()))).unwrap_or(false);
    let read_all = || process_context::with_process(process, || (0..PAGES).all(|page| (0..PAGE / 8).all(|word| guest::try_read::<u64>(base + page * PAGE + word * 8).is_ok_and(|value| value == (base + page * PAGE + word * 8) ^ MAGIC)))).unwrap_or(false);
    let frames: Vec<u64> = (0..PAGES).map(|page| owner.state.lock().frames.get(&page).copied().unwrap_or(0)).collect();
    assert(write_all() && frames.iter().all(|&frame| frame != 0), "pagefile: as 16 paginas gravadas no processo de teste");
    // O working set do processo esvaziado (MiEmptyWorkingSet).
    let nonresident = working_set::nonresident_pages();
    working_set::empty_working_set(process);
    let transitioned = (0..PAGES).all(|page| transition(pte(root, base + page * PAGE), frames[page as usize]) && owner.state.lock().paging.get(&page).is_some_and(|paged| paged.transition && paged.slot.is_none()));
    assert(transitioned && working_set::nonresident_pages() >= nonresident + PAGES, "pagefile: o corte deixa PTEs de transicao com o frame, a protecao e o Write");
    let written_before = working_set::COUNTERS.dirty_pages_written.load(Ordering::Relaxed);
    modified_writer::write_modified(u64::MAX / 2);
    let free_before = crate::ntos::mm::pfn::free_count();
    modified_writer::repurpose(u64::MAX / 2);
    let offsets: Vec<Option<u64>> = (0..PAGES).map(|page| page_file(pte(root, base + page * PAGE))).collect();
    let in_file = offsets.iter().all(Option::is_some) && (0..PAGES).all(|page| !owner.state.lock().frames.contains_key(&page));
    let written = working_set::COUNTERS.dirty_pages_written.load(Ordering::Relaxed) - written_before;
    let in_use = paging_file::information().first().map_or(0, |file| file.total_in_use);
    assert(in_file && written >= PAGES && in_use >= PAGES && crate::ntos::mm::pfn::free_count() >= free_before + PAGES, "pagefile: o modified page writer grava as paginas e a reserva vira PTE de arquivo de paginacao, com os frames devolvidos");
    let reads_before = working_set::COUNTERS.page_reads.load(Ordering::Relaxed);
    let intact = read_all();
    let reads = working_set::COUNTERS.page_reads.load(Ordering::Relaxed) - reads_before;
    let valid_again = (0..PAGES).all(|page| pte(root, base + page * PAGE) & 1 != 0 && owner.state.lock().clean.contains_key(&page));
    assert(intact && reads >= PAGES && valid_again, "pagefile: a releitura traz as paginas do arquivo pelo IoPageRead, intactas e limpas");
    // Páginas limpas: direto à reserva, sem nova escrita, com a mesma cópia.
    let written_before = working_set::COUNTERS.dirty_pages_written.load(Ordering::Relaxed);
    working_set::empty_working_set(process);
    modified_writer::repurpose(u64::MAX / 2);
    let same = (0..PAGES).all(|page| page_file(pte(root, base + page * PAGE)) == offsets[page as usize]);
    assert(same && working_set::COUNTERS.dirty_pages_written.load(Ordering::Relaxed) == written_before, "pagefile: paginas limpas voltam a reserva sem escrita, com a mesma copia no arquivo");
    // Uma página escrita de novo perde a cópia.
    let dirtied = process_context::with_process(process, || guest::try_write::<u64>(base, 7).is_ok()).unwrap_or(false) && pte(root, base) & 0x41 == 0x41;
    working_set::empty_working_set(process);
    let modified = owner.state.lock().paging.get(&0).is_some_and(|paged| paged.transition && paged.slot.is_none());
    assert(dirtied && modified, "pagefile: a pagina escrita de novo vai para a lista de modificadas, sem a copia antiga");
    // A liberação devolve o espaço do arquivo.
    guest::write64(cells, base);
    guest::write64(cells + 8, 0);
    let freed = memory::free_in(Space::of(process), cells, cells + 8, 0x8000).unwrap_or(1) == 0;
    let in_use = paging_file::information().first().map_or(u64::MAX, |file| file.total_in_use);
    assert(freed && in_use == 0 && pte(root, base) == 0, "pagefile: a liberacao devolve o espaco do arquivo de paginacao e limpa as PTEs");
    drop(region);
    drop(child);
    if let Some(cells_region) = memory::find_region(cells) {
        memory::release_private_region(&cells_region);
    }
}
