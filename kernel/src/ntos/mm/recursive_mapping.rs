//! Janela supervisora para as tabelas que a CPU realmente usa.
//! O frame da PML4 reaparece nos
//! quatro níveis; não há cópias de PTEs.

use super::memory_map as map;
use crate::hal::{cpu, physical};
use crate::rtl::KernelError;

const PHYSICAL_FRAME_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const NO_EXECUTE: u64 = 1 << 63;
const PRESENT_WRITABLE: u64 = 3;
const USER_OR_LARGE_PAGE: u64 = 0x84;

#[derive(Clone, Copy, Debug)]
pub struct RecursiveLayout {
    pub table_index: u64,
    pub page_table_base: u64,
    pub page_directory_base: u64,
    pub directory_pointer_base: u64,
    pub root_table_address: u64,
}

fn reserved_layout() -> RecursiveLayout {
    let index = map::PAGE_TABLE_RECURSIVE_INDEX;
    assert!((256..=511).contains(&index), "recursive page-table window must be in the supervisor half");
    let page_table_base = 0xFFFF_0000_0000_0000 | (index << 39);
    let page_directory_base = page_table_base | (index << 30);
    let directory_pointer_base = page_directory_base | (index << 21);
    let root_table_address = directory_pointer_base | (index << 12);
    RecursiveLayout { table_index: index, page_table_base, page_directory_base, directory_pointer_base, root_table_address }
}

fn root_entry(layout: &RecursiveLayout) -> u64 {
    physical::read64(map::PML4_PHYS + layout.table_index * 8)
}

fn owns_root_mapping(entry: u64) -> bool {
    entry & PHYSICAL_FRAME_MASK == map::PML4_PHYS
        && entry & PRESENT_WRITABLE == PRESENT_WRITABLE
        && entry & USER_OR_LARGE_PAGE == 0
        && entry & NO_EXECUTE != 0
}

/// A base só é entregue quando existe a entrada válida nas tabelas.
pub fn layout() -> Option<RecursiveLayout> {
    let layout = reserved_layout();
    owns_root_mapping(root_entry(&layout)).then_some(layout)
}

/// Fase 0, antes dos APs e de imagens nativas. Uma entrada ocupada pertence
/// a outro mapeamento: falha sem sobrescrevê-la.
pub fn initialize() -> Result<RecursiveLayout, KernelError> {
    let reserved = reserved_layout();
    let previous = root_entry(&reserved);
    if owns_root_mapping(previous) {
        return Ok(reserved);
    }
    if previous != 0 {
        return Err(KernelError::new("recursive page-table reservation already occupied"));
    }
    let entry_address = map::PML4_PHYS + reserved.table_index * 8;
    let entry = map::PML4_PHYS | PRESENT_WRITABLE | NO_EXECUTE;
    physical::write32(entry_address + 4, (entry >> 32) as u32);
    physical::write32(entry_address, entry as u32);
    cpu::reload_cr3();
    layout().ok_or_else(|| KernelError::new("recursive page-table mapping was not installed"))
}
