//! KDDEBUGGER_DATA64 deste boot.
//!
//! Layout público de wdbgexts.h; campos sem representação NT ficam nulos.
//! O bitmap do alocador não é apresentado como array de MMPFN e PteBase só
//! existe com mapeamento recursivo real.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{dump_memory, pcr};
use crate::ntos::mm::{kernel_data, memory_map, native_pfn_database, physical_layout, recursive_mapping};
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{eprocess, kthread};

pub const DATA_BYTE_LENGTH: usize = 0x380;
const SUPPORT_BYTE_LENGTH: usize = 0x1000;

static STORAGE: AtomicU64 = AtomicU64::new(0);

/// O bloco e as células auxiliares ficam válidos durante todo o boot.
pub fn initialize() -> Result<u64, KernelError> {
    let current = STORAGE.load(Ordering::Acquire);
    if current != 0 {
        return Ok(current);
    }
    let address = guest::alloc_bytes((DATA_BYTE_LENGTH + SUPPORT_BYTE_LENGTH) as u64);
    if address == 0 {
        return Err(KernelError::new("debugger data allocation failed"));
    }
    STORAGE.store(address, Ordering::Release);
    Ok(address)
}

/// Fotografia coerente das estruturas existentes.
pub struct Snapshot {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub pfn_database: u64,
}

fn put16(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Não ativa sessão KD nem altera flags, threads ou tabelas de páginas.
pub fn snapshot(module_list_head: u64) -> Result<Snapshot, KernelError> {
    let address = initialize()?;
    let mut bytes = alloc::vec![0u8; DATA_BYTE_LENGTH + SUPPORT_BYTE_LENGTH];
    let processor_block = pcr::get_pcr_address() + pcr::layout::PRCB;
    let ranges = physical_layout::ranges();
    let descriptor_offset = DATA_BYTE_LENGTH + 0x80;
    let descriptor_length = 16 + ranges.len() * 16;
    if descriptor_length > bytes.len() - descriptor_offset {
        return Err(KernelError::new("physical memory descriptor exceeds debugger storage"));
    }
    // Cabeçalho de lista KD com um bloco, tag KDBG e o tamanho da 19041.
    put64(&mut bytes, 0, address);
    put64(&mut bytes, 8, address);
    put32(&mut bytes, 0x10, 0x4742_444B);
    put32(&mut bytes, 0x14, DATA_BYTE_LENGTH as u64);
    put64(&mut bytes, 0x18, memory_map::KERNEL_VIRTUAL_BASE);
    put16(&mut bytes, 0x36, 4 << 2);
    put64(&mut bytes, 0x48, module_list_head);
    put64(&mut bytes, 0x50, process::get_active_process_head());
    put64(&mut bytes, 0x1C8, kernel_data::address("MmHighestUserAddress")?);
    put64(&mut bytes, 0x1D8, kernel_data::address("MmUserProbeAddress")?);
    // As variáveis apontadas contêm números/ponteiros; o descritor físico vem
    // da RAM admitida no boot.
    put64(&mut bytes, 0x218, address + DATA_BYTE_LENGTH as u64);
    put64(&mut bytes, DATA_BYTE_LENGTH, processor_block);
    put64(&mut bytes, 0x138, address + DATA_BYTE_LENGTH as u64 + 8);
    put64(&mut bytes, DATA_BYTE_LENGTH + 8, memory_map::PAGE_SIZE);
    put64(&mut bytes, 0x270, address + DATA_BYTE_LENGTH as u64 + 16);
    put64(&mut bytes, DATA_BYTE_LENGTH + 16, address + descriptor_offset as u64);
    put32(&mut bytes, descriptor_offset, ranges.len() as u64);
    let mut total_pages = 0u64;
    for (index, (first, end)) in ranges.iter().enumerate() {
        let pages = (end - first) / 4096;
        let entry = descriptor_offset + 16 + index * 16;
        put64(&mut bytes, entry, first / 4096);
        put64(&mut bytes, entry + 8, pages);
        total_pages += pages;
    }
    put64(&mut bytes, descriptor_offset + 8, total_pages);
    let lowest = ranges.first().map_or(0, |range| range.0 / 4096);
    let highest = ranges.last().map_or(0, |range| range.1 / 4096 - 1);
    for (field, cell, value) in [(0xE8, DATA_BYTE_LENGTH + 24, lowest), (0xF0, DATA_BYTE_LENGTH + 32, highest), (0xF8, DATA_BYTE_LENGTH + 40, total_pages)] {
        put64(&mut bytes, field, address + cell as u64);
        put64(&mut bytes, cell, value);
    }
    // Offsets e tamanhos dos corpos que o escalonador mantém.
    for (field, value) in [
        (0x29E, kthread::INITIAL_STACK),
        (0x2A0, kthread::APC_STATE_PROCESS),
        (0x2A2, kthread::STATE),
        (0x2A8, eprocess::SIZE),
        (0x2AA, eprocess::PEB),
        (0x2AE, eprocess::DIRECTORY_TABLE_BASE),
        (0x2B0, 0xAF00),
        (0x2B4, pcr::layout::PRCB_CURRENT_THREAD - pcr::layout::PRCB),
        (0x2BE, pcr::layout::PRCB_NUMBER - pcr::layout::PRCB),
        (0x2C0, kthread::SIZE),
        (0x2E0, pcr::layout::SIZE),
        (0x2E2, pcr::layout::SELF),
        (0x2E4, pcr::layout::CURRENT_PRCB),
        (0x2E6, pcr::layout::PRCB),
        (0x350, pcr::layout::PRCB_IDLE_THREAD - pcr::layout::PRCB),
    ] {
        put16(&mut bytes, field, value);
    }
    put32(&mut bytes, 0x340, 0x30);
    put32(&mut bytes, 0x344, 0x38);
    put32(&mut bytes, 0x34C, kthread::IRP_LIST_HEAD);
    put64(&mut bytes, 0x360, recursive_mapping::layout().map_or(0, |layout| layout.page_table_base));
    let frames = native_pfn_database::information();
    // MmPfnDatabase é uma variável de ponteiro, como no KDBG da imagem NT.
    put64(&mut bytes, 0xC0, frames.map_or(0, |frames| frames.variable_address));
    dump_memory::write(address, &bytes)?;
    bytes.truncate(DATA_BYTE_LENGTH);
    Ok(Snapshot { address, bytes, pfn_database: frames.map_or(0, |frames| frames.base) })
}
