//! Estruturas públicas do WDK que não constam dos símbolos do ntoskrnl e
//! que o Ke usa (mantido à mão no estilo de `wdk.rs`: `#[repr(C)]`, folhas
//! `Field<T>`, `size_of`/`offset_of!` conferidos em compilação), e o
//! `_KTIMER2` dos símbolos, que o gerador não emitiu.

use super::*;

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

/// `_KTIMER2` (símbolos do ntoskrnl 19041; 0x88 bytes). `RbNodes` (dois
/// RTL_BALANCED_NODE das coleções) e o `ListEntry` sobreposto ficam como
/// bytes reservados: o OpenNT não usa as árvores de coleção.
#[repr(C)]
pub struct Ktimer2 {
    pub header: DispatcherHeader,
    _rb_nodes: Reserved<0x30>,
    pub due_time: [Field<u64>; 2],
    pub period: Field<u64>,
    /// -> `PTIMER2_CALLBACK` codificado
    pub callback: Field<u64>,
    /// -> `void` codificado
    pub callback_context: Field<u64>,
    /// -> `PTIMER2_DISABLE_CALLBACK` codificado
    pub disable_callback: Field<u64>,
    /// -> `void` codificado
    pub disable_context: Field<u64>,
    pub absolute_system_time: Field<u8>,
    pub type_flags: Field<u8>,
    pub collection_index: [Field<u8>; 2],
    _pad_84: Reserved<0x4>,
}

unsafe impl NtStruct for Ktimer2 {}

const _: () = {
    assert!(core::mem::size_of::<Ktimer2>() == 0x88);
    assert!(core::mem::offset_of!(Ktimer2, due_time) == 0x48);
    assert!(core::mem::offset_of!(Ktimer2, period) == 0x58);
    assert!(core::mem::offset_of!(Ktimer2, callback) == 0x60);
    assert!(core::mem::offset_of!(Ktimer2, disable_context) == 0x78);
    assert!(core::mem::offset_of!(Ktimer2, absolute_system_time) == 0x80);
    assert!(core::mem::offset_of!(Ktimer2, type_flags) == 0x81);
    assert!(core::mem::offset_of!(Ktimer2, collection_index) == 0x82);
};
