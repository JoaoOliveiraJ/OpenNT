//! Estruturas usadas pelo Ob/ALPC que o gerador não emite: as formas de 32
//! bits (WOW64) da mensagem LPC e do atributo de contexto ALPC.
//!
//! Mantido à mão, no estilo de `types`: `#[repr(C)]`, folhas `Field<T>`,
//! `size_of`/`offset_of!` conferidos em compilação.

use super::*;

/// `_PORT_MESSAGE32` (símbolos do ntoskrnl; 0x18 bytes): cabeçalho LPC com
/// ponteiros de 32 bits, selecionado pelo NtAlpc* quando a mensagem vem de
/// um processo WOW64.
#[repr(C)]
pub struct PortMessage32 {
    pub u1: PortMessageU1,
    pub u2: PortMessageU2,
    pub client_id: ClientId32,
    pub message_id: Field<u32>,
    pub callback_id: Field<u32>,
}

/// `_CLIENT_ID32` (símbolos do ntoskrnl; 0x8 bytes).
#[repr(C)]
pub struct ClientId32 {
    pub unique_process: Field<u32>,
    pub unique_thread: Field<u32>,
}

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

unsafe impl NtStruct for PortMessage32 {}
unsafe impl NtStruct for ClientId32 {}
unsafe impl NtStruct for AlpcContextAttr32 {}

const _: () = {
    assert!(core::mem::size_of::<PortMessage32>() == 0x18);
    assert!(core::mem::offset_of!(PortMessage32, u1) == 0x0);
    assert!(core::mem::offset_of!(PortMessage32, u2) == 0x4);
    assert!(core::mem::offset_of!(PortMessage32, client_id) == 0x8);
    assert!(core::mem::offset_of!(PortMessage32, message_id) == 0x10);
    assert!(core::mem::offset_of!(PortMessage32, callback_id) == 0x14);
    assert!(core::mem::size_of::<ClientId32>() == 0x8);
    assert!(core::mem::offset_of!(ClientId32, unique_process) == 0x0);
    assert!(core::mem::offset_of!(ClientId32, unique_thread) == 0x4);
    assert!(core::mem::size_of::<AlpcContextAttr32>() == 0x14);
    assert!(core::mem::offset_of!(AlpcContextAttr32, port_context) == 0x0);
    assert!(core::mem::offset_of!(AlpcContextAttr32, message_context) == 0x4);
    assert!(core::mem::offset_of!(AlpcContextAttr32, sequence) == 0x8);
    assert!(core::mem::offset_of!(AlpcContextAttr32, message_id) == 0xc);
    assert!(core::mem::offset_of!(AlpcContextAttr32, callback_id) == 0x10);
};
