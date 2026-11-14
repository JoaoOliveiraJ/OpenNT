//! Estruturas públicas do Rtl que os símbolos do ntoskrnl não têm, usadas
//! pelo heap, pelas tabelas de página de código, pelas listas de faixas e
//! pelas tabelas de mensagens, no mesmo estilo das geradas:
//! `RTL_RANGE_LIST_ITERATOR` (ntddk.h), `RTL_HEAP_PARAMETERS`
//! (ntifs.h/ntddk.h), `CPTABLEINFO` (ntnls.h) e os blocos de tabela de
//! mensagens `MESSAGE_RESOURCE_*` (winnt.h). Tamanho e offsets conferidos em
//! compilação.
//!
//! As de átomo (`_RTL_ATOM_TABLE`, `_RTL_ATOM_TABLE_ENTRY`,
//! `_RTL_ATOM_TABLE_REFERENCE`) e as de lista de faixas (`_RTL_RANGE_LIST`,
//! `_RTLP_RANGE_LIST_ENTRY`) constam dos símbolos e são geradas
//! (`types/rtl.rs`); ficam reexportadas aqui.

use super::{Field, NtStruct, Reserved};

pub use super::{RtlAtomTable, RtlAtomTableEntry, RtlAtomTableReference, RtlRangeList, RtlpRangeListEntry};

/// `RTL_HEAP_PARAMETERS` (ntifs.h).
#[repr(C)]
pub struct RtlHeapParameters {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub segment_reserve: Field<u64>,
    pub segment_commit: Field<u64>,
    pub de_commit_free_block_threshold: Field<u64>,
    pub de_commit_total_free_threshold: Field<u64>,
    pub maximum_allocation_size: Field<u64>,
    pub virtual_memory_threshold: Field<u64>,
    pub initial_commit: Field<u64>,
    pub initial_reserve: Field<u64>,
    /// -> `PRTL_HEAP_COMMIT_ROUTINE`
    pub commit_routine: Field<u64>,
    pub reserved: [Field<u64>; 2],
}

unsafe impl NtStruct for RtlHeapParameters {}

/// `CPTABLEINFO` (ntnls.h): a descrição de uma tabela c_<página>.nls que o
/// RtlInitCodePageTable monta sobre os bytes da tabela.
#[repr(C)]
pub struct CpTableInfo {
    pub code_page: Field<u16>,
    pub maximum_character_size: Field<u16>,
    pub default_char: Field<u16>,
    pub uni_default_char: Field<u16>,
    pub trans_default_char: Field<u16>,
    pub trans_uni_default_char: Field<u16>,
    pub dbcs_code_page: Field<u16>,
    pub lead_byte: [Field<u8>; 12],
    _pad_1a: Reserved<0x6>,
    /// -> `USHORT`
    pub multi_byte_table: Field<u64>,
    /// -> `void`
    pub wide_char_table: Field<u64>,
    /// -> `USHORT`
    pub dbcs_ranges: Field<u64>,
    /// -> `USHORT`
    pub dbcs_offsets: Field<u64>,
}

unsafe impl NtStruct for CpTableInfo {}

/// `MESSAGE_RESOURCE_BLOCK` (winnt.h).
#[repr(C)]
pub struct MessageResourceBlock {
    pub low_id: Field<u32>,
    pub high_id: Field<u32>,
    pub offset_to_entries: Field<u32>,
}

unsafe impl NtStruct for MessageResourceBlock {}

/// `MESSAGE_RESOURCE_DATA` (winnt.h; os blocos seguem `number_of_blocks`).
#[repr(C)]
pub struct MessageResourceData {
    pub number_of_blocks: Field<u32>,
    pub blocks: [MessageResourceBlock; 1],
}

unsafe impl NtStruct for MessageResourceData {}

/// `MESSAGE_RESOURCE_ENTRY` (winnt.h; o texto segue `flags`).
#[repr(C)]
pub struct MessageResourceEntry {
    pub length: Field<u16>,
    pub flags: Field<u16>,
}

unsafe impl NtStruct for MessageResourceEntry {}

/// `RTL_RANGE_LIST_ITERATOR` (ntddk.h).
#[repr(C)]
pub struct RtlRangeListIterator {
    /// -> `LIST_ENTRY` (a cabeça da RTL_RANGE_LIST)
    pub range_list_head: Field<u64>,
    /// -> `LIST_ENTRY` (a sublista da faixa fundida em curso, ou NULL)
    pub merged_head: Field<u64>,
    /// -> `RTL_RANGE`
    pub current: Field<u64>,
    pub stamp: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for RtlRangeListIterator {}

const _: () = {
    assert!(core::mem::size_of::<RtlRangeListIterator>() == 0x20);
    assert!(core::mem::offset_of!(RtlRangeListIterator, current) == 0x10);
    assert!(core::mem::offset_of!(RtlRangeListIterator, stamp) == 0x18);
};

const _: () = {
    assert!(core::mem::size_of::<RtlHeapParameters>() == 0x60);
    assert!(core::mem::offset_of!(RtlHeapParameters, virtual_memory_threshold) == 0x30);
    assert!(core::mem::offset_of!(RtlHeapParameters, initial_commit) == 0x38);
    assert!(core::mem::offset_of!(RtlHeapParameters, initial_reserve) == 0x40);
    assert!(core::mem::offset_of!(RtlHeapParameters, commit_routine) == 0x48);
    assert!(core::mem::size_of::<CpTableInfo>() == 0x40);
    assert!(core::mem::offset_of!(CpTableInfo, dbcs_code_page) == 0xc);
    assert!(core::mem::offset_of!(CpTableInfo, lead_byte) == 0xe);
    assert!(core::mem::offset_of!(CpTableInfo, multi_byte_table) == 0x20);
    assert!(core::mem::offset_of!(CpTableInfo, wide_char_table) == 0x28);
    assert!(core::mem::offset_of!(CpTableInfo, dbcs_ranges) == 0x30);
    assert!(core::mem::offset_of!(CpTableInfo, dbcs_offsets) == 0x38);
    assert!(core::mem::size_of::<MessageResourceBlock>() == 0xc);
    assert!(core::mem::offset_of!(MessageResourceData, blocks) == 0x4);
    assert!(core::mem::size_of::<MessageResourceEntry>() == 0x4);
};
