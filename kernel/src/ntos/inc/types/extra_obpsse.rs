//! Estruturas usadas pelo Ps/Se que o gerador não emite: o contexto de
//! segurança do cliente e o TOKEN_CONTROL do `ntifs.h` (WDK), a parte do
//! `_TEB32` que a impersonação toca (símbolos do ntoskrnl) e os parâmetros
//! dos callouts do Win32k (layout lido de PspExitThread/PsConvertToGuiThread
//! do ntoskrnl 19041).
//!
//! Mantido à mão, no estilo de `types`: `#[repr(C)]`, folhas `Field<T>`,
//! `size_of`/`offset_of!` conferidos em compilação.

use super::*;

/// `TOKEN_CONTROL` (ntifs.h; 0x28 bytes): identidade de um token para o
/// rastreamento de contexto de um servidor remoto.
#[repr(C)]
pub struct TokenControl {
    pub token_id: Luid,
    pub authentication_id: Luid,
    pub modified_id: Luid,
    pub token_source: TokenSource,
}

unsafe impl NtStruct for TokenControl {}

/// `SECURITY_CLIENT_CONTEXT` (ntifs.h; 0x48 bytes): o que
/// SeCreateClientSecurity entrega e SeImpersonateClient(Ex) consome.
#[repr(C)]
pub struct SecurityClientContext {
    pub security_qos: SecurityQualityOfService,
    _reserved_0c: Reserved<4>,
    pub client_token: Field<u64>,
    pub directly_access_client_token: Field<u8>,
    pub direct_access_effective_only: Field<u8>,
    pub server_is_remote: Field<u8>,
    _reserved_1b: Reserved<1>,
    pub client_token_control: TokenControl,
    _reserved_44: Reserved<4>,
}

unsafe impl NtStruct for SecurityClientContext {}

/// `_TEB32` (símbolos do ntoskrnl; 0x1000 bytes) do processo WOW64: só os
/// campos que PspWriteTebImpersonationInfo escreve; o resto é reservado. Fica
/// em `TEB + ROUND_TO_PAGES(sizeof(TEB))` (o WOW64_GET_TEB32 do NT).
#[repr(C)]
pub struct Teb32 {
    _reserved_0: Reserved<0xF9C>,
    pub is_impersonating: Field<u32>,
    _reserved_fa0: Reserved<0x24>,
    pub mui_impersonation: Field<u32>,
    _reserved_fc8: Reserved<0x38>,
}

unsafe impl NtStruct for Teb32 {}

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
    assert!(core::mem::size_of::<TokenControl>() == 0x28);
    assert!(core::mem::offset_of!(TokenControl, authentication_id) == 0x08);
    assert!(core::mem::offset_of!(TokenControl, modified_id) == 0x10);
    assert!(core::mem::offset_of!(TokenControl, token_source) == 0x18);
    assert!(core::mem::size_of::<SecurityClientContext>() == 0x48);
    assert!(core::mem::offset_of!(SecurityClientContext, client_token) == 0x10);
    assert!(core::mem::offset_of!(SecurityClientContext, directly_access_client_token) == 0x18);
    assert!(core::mem::offset_of!(SecurityClientContext, direct_access_effective_only) == 0x19);
    assert!(core::mem::offset_of!(SecurityClientContext, server_is_remote) == 0x1A);
    assert!(core::mem::offset_of!(SecurityClientContext, client_token_control) == 0x1C);
    assert!(core::mem::size_of::<Teb32>() == 0x1000);
    assert!(core::mem::offset_of!(Teb32, is_impersonating) == 0xF9C);
    assert!(core::mem::offset_of!(Teb32, mui_impersonation) == 0xFC4);
    assert!(core::mem::size_of::<Win32ThreadCalloutParameters>() == 0x10);
    assert!(core::mem::offset_of!(Win32ThreadCalloutParameters, callout_type) == 0x08);
    assert!(core::mem::size_of::<Win32ProcessCalloutParameters>() == 0x10);
    assert!(core::mem::offset_of!(Win32ProcessCalloutParameters, initialize) == 0x08);
};
