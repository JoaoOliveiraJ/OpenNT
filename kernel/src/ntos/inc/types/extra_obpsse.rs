//! Os parâmetros dos callouts do Win32k e os registros internos dos
//! atributos de segurança do token, que os símbolos do ntoskrnl não têm
//! (layouts lidos de PspExitThread/PsConvertToGuiThread e de
//! AuthzBasepCopyoutInternalSecurityAttributes do ntoskrnl 19041).
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

/// Registro de um atributo de segurança no formato interno do token, que
/// segue o `_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION` (layout lido de
/// AuthzBasepCopyoutInternalSecurityAttributes do ntoskrnl 19041). 0x70
/// bytes.
#[repr(C)]
pub struct AuthzbasepSecurityAttribute {
    /// Elo na SecurityAttributesList do cabeçalho.
    pub list_link: ListEntry,
    _reserved_10: Reserved<0x10>,
    pub name: UnicodeString,
    pub value_type: Field<u16>,
    _pad_32: Reserved<0x2>,
    pub flags: Field<u32>,
    _reserved_38: Reserved<0x4>,
    pub value_count: Field<u32>,
    _reserved_40: Reserved<0x8>,
    /// Lista dos AuthzbasepSecurityAttributeValue.
    pub values: ListEntry,
    _reserved_58: Reserved<0x8>,
    /// Segunda lista do registro, vazia na cópia.
    pub list_60: ListEntry,
}

unsafe impl NtStruct for AuthzbasepSecurityAttribute {}

/// Valor de um atributo no formato interno (0x40 bytes): o elo na lista de
/// valores do atributo e, a partir de `value`, o inteiro, a UNICODE_STRING
/// de um STRING, a versão de um FQBN (com o nome em `name`) ou o ponteiro
/// dos bytes de um SID/OCTET_STRING (com o tamanho no ULONG de `name`).
#[repr(C)]
pub struct AuthzbasepSecurityAttributeValue {
    pub list_link: ListEntry,
    _reserved_10: Reserved<0x18>,
    pub value: Field<u64>,
    pub name: UnicodeString,
}

unsafe impl NtStruct for AuthzbasepSecurityAttributeValue {}

const _: () = {
    assert!(core::mem::size_of::<AuthzbasepSecurityAttribute>() == 0x70);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, name) == 0x20);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, value_type) == 0x30);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, flags) == 0x34);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, value_count) == 0x3c);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, values) == 0x48);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttribute, list_60) == 0x60);
    assert!(core::mem::size_of::<AuthzbasepSecurityAttributeValue>() == 0x40);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttributeValue, value) == 0x28);
    assert!(core::mem::offset_of!(AuthzbasepSecurityAttributeValue, name) == 0x30);
};
