//! Os parâmetros dos callouts do Win32k, que os símbolos do ntoskrnl não
//! têm (layout lido de PspExitThread/PsConvertToGuiThread do ntoskrnl
//! 19041).
//!
//! Mantido à mão, no estilo de `types`: `#[repr(C)]`, folhas `Field<T>`,
//! `size_of`/`offset_of!` conferidos em compilação. O contexto de segurança
//! do cliente, o `_TOKEN_CONTROL` e o `_TEB32` constam dos símbolos e são
//! gerados (`types/se.rs`, `ps.rs`); ficam reexportados aqui.

use super::*;

pub use super::{SecurityClientContext, Teb32, TokenControl};

/// Parâmetro do callout de thread do Win32k (PsW32ThreadCallout, tipo 1):
/// a ETHREAD e o PSW32THREADCALLOUTTYPE (0 = inicialização em
/// PsConvertToGuiThread, 1 = saída em PspExitThread). 0x10 bytes.
#[repr(C)]
pub struct Win32ThreadCalloutParameters {
    pub thread: Field<u64>,
    pub callout_type: Field<u32>,
    _reserved_0c: Reserved<4>,
}

unsafe impl NtStruct for Win32ThreadCalloutParameters {}

/// Parâmetro do callout de processo do Win32k (PsW32ProcessCallout, tipo 0):
/// o EPROCESS e Initialize (FALSE na saída do último thread em
/// PspExitThread). 0x10 bytes.
#[repr(C)]
pub struct Win32ProcessCalloutParameters {
    pub process: Field<u64>,
    pub initialize: Field<u32>,
    _reserved_0c: Reserved<4>,
}

unsafe impl NtStruct for Win32ProcessCalloutParameters {}

const _: () = {
    assert!(core::mem::size_of::<Win32ThreadCalloutParameters>() == 0x10);
    assert!(core::mem::offset_of!(Win32ThreadCalloutParameters, callout_type) == 0x08);
    assert!(core::mem::size_of::<Win32ProcessCalloutParameters>() == 0x10);
    assert!(core::mem::offset_of!(Win32ProcessCalloutParameters, initialize) == 0x08);
};
