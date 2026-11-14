//! Estruturas do Rtl usadas pelas tabelas de átomos, pelo heap, pelas
//! tabelas de página de código e pelas listas de faixas, no mesmo estilo
//! das geradas.
//!
//! As de átomo (`_RTL_ATOM_TABLE`, `_RTL_ATOM_TABLE_ENTRY`,
//! `_RTL_ATOM_TABLE_REFERENCE`) e as de lista de faixas (`_RTL_RANGE_LIST`,
//! `_RTLP_RANGE_LIST_ENTRY`) vêm dos símbolos do ntoskrnl 19041; as demais
//! são públicas e não constam dos símbolos: `RTL_RANGE_LIST_ITERATOR`
//! (ntddk.h), `RTL_HEAP_PARAMETERS`
//! (ntifs.h/ntddk.h), `CPTABLEINFO` (ntnls.h) e os blocos de tabela de
//! mensagens `MESSAGE_RESOURCE_*` (winnt.h). Tamanho e offsets conferidos em
//! compilação.

use super::{ExPushLock, ListEntry};
use super::{Field, NtStruct, Reserved};

/// `_RTL_ATOM_TABLE` (0x28 bytes com o primeiro balde; os demais seguem).
#[repr(C)]
pub struct RtlAtomTable {
    pub signature: Field<u32>,
    pub reference_count: Field<u32>,
    pub push_lock: ExPushLock,
    /// -> `_HANDLE_TABLE`
    pub ex_handle_table: Field<u64>,
    pub flags: Field<u32>,
    pub number_of_buckets: Field<u32>,
    /// -> `_RTL_ATOM_TABLE_ENTRY` (vetor de `number_of_buckets`).
    pub buckets: [Field<u64>; 1],
}

unsafe impl NtStruct for RtlAtomTable {}

/// `_RTL_ATOM_TABLE_REFERENCE`.
#[repr(C)]
pub struct RtlAtomTableReference {
    pub low_box_list: ListEntry,
    pub low_box_id: Field<u32>,
    pub reference_count: Field<u16>,
    pub flags: Field<u16>,
}

unsafe impl NtStruct for RtlAtomTableReference {}

/// `_RTL_ATOM_TABLE_ENTRY` (o nome segue em `name`, com o terminador).
#[repr(C)]
pub struct RtlAtomTableEntry {
    /// -> `_RTL_ATOM_TABLE_ENTRY`
    pub hash_link: Field<u64>,
    pub handle_index: Field<u16>,
    pub atom: Field<u16>,
    _pad_c: Reserved<0x4>,
    pub reference: RtlAtomTableReference,
    pub name_length: Field<u8>,
    _pad_29: Reserved<0x1>,
    pub name: [Field<u16>; 1],
    _pad_2c: Reserved<0x4>,
}

unsafe impl NtStruct for RtlAtomTableEntry {}

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

/// `_RTL_RANGE_LIST` (símbolos do ntoskrnl 19041).
#[repr(C)]
pub struct RtlRangeList {
    pub list_head: ListEntry,
    pub flags: Field<u32>,
    pub count: Field<u32>,
    pub stamp: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for RtlRangeList {}

/// `_RTLP_RANGE_LIST_ENTRY` (símbolos do ntoskrnl 19041). Os primeiros 0x22
/// bytes são o `RTL_RANGE` público que os iteradores entregam. A união
/// `Allocated`/`Merged`: `user_data`/`owner` numa faixa comum; numa faixa
/// fundida os mesmos 16 bytes são a LIST_ENTRY da sublista
/// ([`RtlpRangeListEntry::merged_list_head`]).
#[repr(C)]
pub struct RtlpRangeListEntry {
    pub start: Field<u64>,
    pub end: Field<u64>,
    /// `Allocated.UserData` (ou `Merged.ListHead.Flink`).
    pub user_data: Field<u64>,
    /// `Allocated.Owner` (ou `Merged.ListHead.Blink`).
    pub owner: Field<u64>,
    pub attributes: Field<u8>,
    pub public_flags: Field<u8>,
    pub private_flags: Field<u16>,
    _pad_24: Reserved<0x4>,
    pub list_entry: ListEntry,
}

unsafe impl NtStruct for RtlpRangeListEntry {}

impl RtlpRangeListEntry {
    /// `Merged.ListHead`: a LIST_ENTRY da sublista, sobre `user_data`/`owner`.
    pub fn merged_list_head(&self) -> &ListEntry {
        // SAFETY: os 16 bytes em +0x10 são a LIST_ENTRY da união Merged.
        unsafe { ListEntry::at(self.user_data.address()) }
    }
}

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
    assert!(core::mem::size_of::<RtlRangeList>() == 0x20);
    assert!(core::mem::offset_of!(RtlRangeList, flags) == 0x10);
    assert!(core::mem::offset_of!(RtlRangeList, count) == 0x14);
    assert!(core::mem::offset_of!(RtlRangeList, stamp) == 0x18);
    assert!(core::mem::size_of::<RtlpRangeListEntry>() == 0x38);
    assert!(core::mem::offset_of!(RtlpRangeListEntry, user_data) == 0x10);
    assert!(core::mem::offset_of!(RtlpRangeListEntry, owner) == 0x18);
    assert!(core::mem::offset_of!(RtlpRangeListEntry, attributes) == 0x20);
    assert!(core::mem::offset_of!(RtlpRangeListEntry, public_flags) == 0x21);
    assert!(core::mem::offset_of!(RtlpRangeListEntry, private_flags) == 0x22);
    assert!(core::mem::offset_of!(RtlpRangeListEntry, list_entry) == 0x28);
    assert!(core::mem::size_of::<RtlRangeListIterator>() == 0x20);
    assert!(core::mem::offset_of!(RtlRangeListIterator, current) == 0x10);
    assert!(core::mem::offset_of!(RtlRangeListIterator, stamp) == 0x18);
};

const _: () = {
    assert!(core::mem::size_of::<RtlAtomTable>() == 0x28);
    assert!(core::mem::offset_of!(RtlAtomTable, push_lock) == 0x8);
    assert!(core::mem::offset_of!(RtlAtomTable, ex_handle_table) == 0x10);
    assert!(core::mem::offset_of!(RtlAtomTable, flags) == 0x18);
    assert!(core::mem::offset_of!(RtlAtomTable, number_of_buckets) == 0x1c);
    assert!(core::mem::offset_of!(RtlAtomTable, buckets) == 0x20);
    assert!(core::mem::size_of::<RtlAtomTableReference>() == 0x18);
    assert!(core::mem::offset_of!(RtlAtomTableReference, low_box_id) == 0x10);
    assert!(core::mem::offset_of!(RtlAtomTableReference, reference_count) == 0x14);
    assert!(core::mem::offset_of!(RtlAtomTableReference, flags) == 0x16);
    assert!(core::mem::size_of::<RtlAtomTableEntry>() == 0x30);
    assert!(core::mem::offset_of!(RtlAtomTableEntry, handle_index) == 0x8);
    assert!(core::mem::offset_of!(RtlAtomTableEntry, atom) == 0xa);
    assert!(core::mem::offset_of!(RtlAtomTableEntry, reference) == 0x10);
    assert!(core::mem::offset_of!(RtlAtomTableEntry, name_length) == 0x28);
    assert!(core::mem::offset_of!(RtlAtomTableEntry, name) == 0x2a);
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
