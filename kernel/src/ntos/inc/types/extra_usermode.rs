//! Estruturas públicas de serviços Nt* de modo usuário que não constam dos
//! símbolos do ntoskrnl nem de `wdk.rs`: o argumento do NtContinueEx, o
//! dado de callback das APCs de usuário e o texto que o user32 passa aos
//! serviços do win32k.
//!
//! Mesmo estilo de `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`, layout x64 e
//! asserções de tamanho e de todos os offsets. Cada estrutura cita o
//! cabeçalho de origem e onde o layout foi conferido.

use super::*;

/// `KCONTINUE_ARGUMENT` (SDK `winnt.h`; argumento do NtContinueEx e o
/// bloco que o KiInitializeUserApc deixa em CONTEXT+0x4F0; conferido no
/// KiContinueEx e no KiUserApcDispatcher da 19045; 0x18 bytes). O
/// ContinueType não é conferido pelo kernel; `continue_flags` usa
/// [`KCONTINUE_FLAG_TEST_ALERT`] e [`KCONTINUE_FLAG_DELIVER_APC`].
#[repr(C)]
pub struct KcontinueArgument {
    /// `KCONTINUE_TYPE` (UNWIND 0, RESUME 1, LONGJUMP 2, SET 3).
    pub continue_type: Field<u32>,
    pub continue_flags: Field<u32>,
    pub reserved: [Field<u64>; 2],
}

unsafe impl NtStruct for KcontinueArgument {}

/// `KCONTINUE_RESUME`: o tipo que o KiInitializeUserApc grava.
pub const KCONTINUE_RESUME: u32 = 1;
/// `KCONTINUE_FLAG_TEST_ALERT`.
pub const KCONTINUE_FLAG_TEST_ALERT: u32 = 1;
/// `KCONTINUE_FLAG_DELIVER_APC`.
pub const KCONTINUE_FLAG_DELIVER_APC: u32 = 2;

const _: () = {
    assert!(core::mem::size_of::<KcontinueArgument>() == 0x18);
    assert!(core::mem::offset_of!(KcontinueArgument, continue_type) == 0x0);
    assert!(core::mem::offset_of!(KcontinueArgument, continue_flags) == 0x4);
    assert!(core::mem::offset_of!(KcontinueArgument, reserved) == 0x8);
};

/// `APC_CALLBACK_DATA` (SDK `winnt.h`, QUEUE_USER_APC_CALLBACK_DATA_CONTEXT
/// do QueueUserAPC2; o KiInitializeUserApc o monta em CONTEXT+0x510 e passa
/// o endereço no lugar do SystemArgument1; 0x20 bytes).
#[repr(C)]
pub struct ApcCallbackData {
    /// O SystemArgument1 original (o `dwData` do QueueUserAPC2).
    pub parameter: Field<u64>,
    /// -> `_CONTEXT`
    pub context_record: Field<u64>,
    pub reserved0: Field<u64>,
    pub reserved1: Field<u64>,
}

unsafe impl NtStruct for ApcCallbackData {}

/// `LARGE_STRING` do win32k (o nome de classe e o título que o user32 passa
/// ao NtUserCreateWindowEx; o VerNtUserCreateWindowEx do user32 19041
/// entrega o ponteiro do nome da classe no segundo argumento, 0x7766; 0x10
/// bytes). O segundo ULONG guarda o tamanho máximo e a marca de texto ANSI;
/// quem confere um nome UTF-16 lê só o `length` e o `buffer`.
#[repr(C)]
pub struct LargeString {
    /// Bytes do texto em `buffer`.
    pub length: Field<u32>,
    pub maximum_length_and_flags: Field<u32>,
    /// O texto; abaixo de 0x10000, um átomo de classe em vez do nome.
    pub buffer: Field<u64>,
}

unsafe impl NtStruct for LargeString {}

const _: () = {
    assert!(core::mem::size_of::<LargeString>() == 0x10);
    assert!(core::mem::offset_of!(LargeString, length) == 0x0);
    assert!(core::mem::offset_of!(LargeString, maximum_length_and_flags) == 0x4);
    assert!(core::mem::offset_of!(LargeString, buffer) == 0x8);
};

const _: () = {
    assert!(core::mem::size_of::<ApcCallbackData>() == 0x20);
    assert!(core::mem::offset_of!(ApcCallbackData, parameter) == 0x0);
    assert!(core::mem::offset_of!(ApcCallbackData, context_record) == 0x8);
    assert!(core::mem::offset_of!(ApcCallbackData, reserved0) == 0x10);
    assert!(core::mem::offset_of!(ApcCallbackData, reserved1) == 0x18);
};
