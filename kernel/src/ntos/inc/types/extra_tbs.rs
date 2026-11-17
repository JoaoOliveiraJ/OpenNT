//! Estruturas da API de TPM de kernel do tbs.sys (o `tbs.h` do SDK) que não
//! constam dos símbolos do ntoskrnl (mantido à mão no estilo de `wdk.rs`:
//! `#[repr(C)]`, folhas `Field<T>`, `size_of`/`offset_of!` conferidos em
//! compilação).

use super::*;

/// `TBS_CONTEXT_PARAMS2` (8 bytes): a versão (TBS_CONTEXT_VERSION_TWO = 2) e
/// os bits requestRaw (0), includeTpm12 (1) e includeTpm20 (2) do
/// Tbsi_Context_Create.
#[repr(C)]
pub struct TbsContextParams2 {
    pub version: Field<u32>,
    pub flags: Field<u32>,
}

unsafe impl NtStruct for TbsContextParams2 {}

const _: () = {
    assert!(core::mem::size_of::<TbsContextParams2>() == 0x8);
    assert!(core::mem::offset_of!(TbsContextParams2, version) == 0x0);
    assert!(core::mem::offset_of!(TbsContextParams2, flags) == 0x4);
};
