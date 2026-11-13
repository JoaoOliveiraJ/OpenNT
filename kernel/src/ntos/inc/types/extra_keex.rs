//! Estruturas públicas do WDK que não constam dos símbolos do ntoskrnl e
//! que os grupos Ke de processadores usam (mantido à mão no estilo de
//! `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`, `size_of`/`offset_of!`
//! conferidos em compilação).

use super::*;

/// `_KE_PROCESSOR_CHANGE_NOTIFY_CONTEXT` (wdm.h; 0x10 bytes): o contexto que
/// KeRegisterProcessorChangeCallback entrega ao callback do driver.
#[repr(C)]
pub struct KeProcessorChangeNotifyContext {
    /// `KE_PROCESSOR_CHANGE_NOTIFY_STATE` (0 AddStartNotify, 1
    /// AddCompleteNotify, 2 AddFailureNotify).
    pub state: Field<i32>,
    pub nt_number: Field<u32>,
    /// NTSTATUS
    pub status: Field<i32>,
    pub proc_number: ProcessorNumber,
}

unsafe impl NtStruct for KeProcessorChangeNotifyContext {}

const _: () = {
    assert!(core::mem::size_of::<KeProcessorChangeNotifyContext>() == 0x10);
    assert!(core::mem::offset_of!(KeProcessorChangeNotifyContext, state) == 0x0);
    assert!(core::mem::offset_of!(KeProcessorChangeNotifyContext, nt_number) == 0x4);
    assert!(core::mem::offset_of!(KeProcessorChangeNotifyContext, status) == 0x8);
    assert!(core::mem::offset_of!(KeProcessorChangeNotifyContext, proc_number) == 0xc);
};

/// KE_PROCESSOR_CHANGE_NOTIFY_STATE (wdm.h).
pub mod processor_change_state {
    pub const ADD_START_NOTIFY: i32 = 0;
    pub const ADD_COMPLETE_NOTIFY: i32 = 1;
    pub const ADD_FAILURE_NOTIFY: i32 = 2;
}

/// KE_PROCESSOR_CHANGE_ADD_EXISTING (wdm.h).
pub const KE_PROCESSOR_CHANGE_ADD_EXISTING: u32 = 1;
