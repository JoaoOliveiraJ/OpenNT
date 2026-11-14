//! A forma de 32 bits (WOW64) do atributo de contexto ALPC, que os símbolos
//! do ntoskrnl não têm.
//!
//! Mantido à mão, no estilo de `types`: `#[repr(C)]`, folhas `Field<T>`,
//! `size_of`/`offset_of!` conferidos em compilação. A mensagem LPC de 32
//! bits (`_PORT_MESSAGE32`, com o `_CLIENT_ID32`) consta dos símbolos e é
//! gerada (`types/alpc.rs`, `ps.rs`); fica reexportada aqui.

use super::*;

pub use super::{ClientId32, PortMessage32};

/// `_ALPC_CONTEXT_ATTR` na forma de 32 bits (NtAlpcCancelMessage com o
/// layout compacto; 0x14 bytes): os ponteiros de contexto viram ULONG.
#[repr(C)]
pub struct AlpcContextAttr32 {
    pub port_context: Field<u32>,
    pub message_context: Field<u32>,
    pub sequence: Field<u32>,
    pub message_id: Field<u32>,
    pub callback_id: Field<u32>,
}

unsafe impl NtStruct for AlpcContextAttr32 {}

const _: () = {
    assert!(core::mem::size_of::<AlpcContextAttr32>() == 0x14);
    assert!(core::mem::offset_of!(AlpcContextAttr32, port_context) == 0x0);
    assert!(core::mem::offset_of!(AlpcContextAttr32, message_context) == 0x4);
    assert!(core::mem::offset_of!(AlpcContextAttr32, sequence) == 0x8);
    assert!(core::mem::offset_of!(AlpcContextAttr32, message_id) == 0xc);
    assert!(core::mem::offset_of!(AlpcContextAttr32, callback_id) == 0x10);
};
