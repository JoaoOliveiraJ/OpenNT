//! Estruturas da interface x86 BIOS da HAL que não constam dos símbolos do
//! ntoskrnl nem dos cabeçalhos do WDK (mantido à mão no estilo de `wdk.rs`:
//! `#[repr(C)]`, folhas `Field<T>`, `size_of`/`offset_of!` conferidos em
//! compilação). O layout é o que o x86BiosCall do ntoskrnl 19041 lê e grava
//! (XmEmulateStream copia os sete registradores de 32 bits e os dois
//! seletores de 16 bits na entrada e devolve os sete registradores na
//! saída), o mesmo que o BasicDisplay.sys monta na pilha antes da chamada.

use super::*;

/// `X86_BIOS_REGISTERS` (0x20 bytes): registradores de entrada e saída de
/// uma interrupção de BIOS emulada.
#[repr(C)]
pub struct X86BiosRegisters {
    pub eax: Field<u32>,
    pub ecx: Field<u32>,
    pub edx: Field<u32>,
    pub ebx: Field<u32>,
    pub ebp: Field<u32>,
    pub esi: Field<u32>,
    pub edi: Field<u32>,
    pub seg_ds: Field<u16>,
    pub seg_es: Field<u16>,
}

unsafe impl NtStruct for X86BiosRegisters {}

const _: () = {
    assert!(core::mem::size_of::<X86BiosRegisters>() == 0x20);
    assert!(core::mem::offset_of!(X86BiosRegisters, eax) == 0x0);
    assert!(core::mem::offset_of!(X86BiosRegisters, ecx) == 0x4);
    assert!(core::mem::offset_of!(X86BiosRegisters, edx) == 0x8);
    assert!(core::mem::offset_of!(X86BiosRegisters, ebx) == 0xC);
    assert!(core::mem::offset_of!(X86BiosRegisters, ebp) == 0x10);
    assert!(core::mem::offset_of!(X86BiosRegisters, esi) == 0x14);
    assert!(core::mem::offset_of!(X86BiosRegisters, edi) == 0x18);
    assert!(core::mem::offset_of!(X86BiosRegisters, seg_ds) == 0x1C);
    assert!(core::mem::offset_of!(X86BiosRegisters, seg_es) == 0x1E);
};
