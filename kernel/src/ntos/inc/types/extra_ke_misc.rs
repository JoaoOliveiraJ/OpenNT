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

