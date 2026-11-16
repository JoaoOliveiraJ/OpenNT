//! Estruturas públicas do WDK que não constam dos símbolos do ntoskrnl e
//! que o Ke usa (mantido à mão no estilo de `wdk.rs`: `#[repr(C)]`, folhas
//! `Field<T>`, `size_of`/`offset_of!` conferidos em compilação). O
//! `_KTIMER2` consta dos símbolos e é gerado (`types/ke.rs`); fica
//! reexportado aqui.

use super::*;

pub use super::Ktimer2;

/// `_KBUGCHECK_CALLBACK_RECORD` (wdm.h; 0x40 bytes): o registro do chamador
/// de KeRegisterBugCheckCallback.
#[repr(C)]
pub struct KbugcheckCallbackRecord {
    pub entry: ListEntry,
    /// -> `KBUGCHECK_CALLBACK_ROUTINE` (Buffer, Length)
    pub callback_routine: Field<u64>,
    /// -> `void`
    pub buffer: Field<u64>,
    pub length: Field<u32>,
    _pad_24: Reserved<0x4>,
    /// -> `UCHAR` (texto do componente)
    pub component: Field<u64>,
    pub checksum: Field<u64>,
    /// `KBUGCHECK_BUFFER_DUMP_STATE`
    pub state: Field<u8>,
    _pad_39: Reserved<0x7>,
}

unsafe impl NtStruct for KbugcheckCallbackRecord {}

const _: () = {
    assert!(core::mem::size_of::<KbugcheckCallbackRecord>() == 0x40);
    assert!(core::mem::offset_of!(KbugcheckCallbackRecord, entry) == 0x0);
    assert!(core::mem::offset_of!(KbugcheckCallbackRecord, callback_routine) == 0x10);
    assert!(core::mem::offset_of!(KbugcheckCallbackRecord, buffer) == 0x18);
    assert!(core::mem::offset_of!(KbugcheckCallbackRecord, length) == 0x20);
    assert!(core::mem::offset_of!(KbugcheckCallbackRecord, component) == 0x28);
    assert!(core::mem::offset_of!(KbugcheckCallbackRecord, checksum) == 0x30);
    assert!(core::mem::offset_of!(KbugcheckCallbackRecord, state) == 0x38);
};

/// `_KADDRESS_RANGE` (wdm.h; 0x10 bytes): um bloco de memória do triage dump.
#[repr(C)]
pub struct KaddressRange {
    /// -> `void`
    pub address: Field<u64>,
    pub size: Field<u64>,
}

unsafe impl NtStruct for KaddressRange {}

const _: () = {
    assert!(core::mem::size_of::<KaddressRange>() == 0x10);
    assert!(core::mem::offset_of!(KaddressRange, address) == 0x0);
    assert!(core::mem::offset_of!(KaddressRange, size) == 0x8);
};

/// `_KTRIAGE_DUMP_DATA_ARRAY` (wdm.h; 0x40 bytes com um bloco): a lista de
/// blocos que um callback KbCallbackTriageDumpData acrescenta ao triage dump
/// (KeInitializeTriageDumpDataArray/KeAddTriageDumpDataBlock). `Blocks` tem
/// `NumBlocksTotal` entradas.
#[repr(C)]
pub struct KtriageDumpDataArray {
    pub list: ListEntry,
    pub num_blocks_used: Field<u32>,
    pub num_blocks_total: Field<u32>,
    pub data_size: Field<u32>,
    pub max_data_size: Field<u32>,
    pub component_name_buffer_length: Field<u32>,
    _pad_24: Reserved<0x4>,
    /// -> `UCHAR`
    pub component_name: Field<u64>,
    pub blocks: [KaddressRange; 1],
}

unsafe impl NtStruct for KtriageDumpDataArray {}

const _: () = {
    assert!(core::mem::size_of::<KtriageDumpDataArray>() == 0x40);
    assert!(core::mem::offset_of!(KtriageDumpDataArray, list) == 0x0);
    assert!(core::mem::offset_of!(KtriageDumpDataArray, num_blocks_used) == 0x10);
    assert!(core::mem::offset_of!(KtriageDumpDataArray, num_blocks_total) == 0x14);
    assert!(core::mem::offset_of!(KtriageDumpDataArray, data_size) == 0x18);
    assert!(core::mem::offset_of!(KtriageDumpDataArray, max_data_size) == 0x1c);
    assert!(core::mem::offset_of!(KtriageDumpDataArray, component_name_buffer_length) == 0x20);
    assert!(core::mem::offset_of!(KtriageDumpDataArray, component_name) == 0x28);
    assert!(core::mem::offset_of!(KtriageDumpDataArray, blocks) == 0x30);
};

