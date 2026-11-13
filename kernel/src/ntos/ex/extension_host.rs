//! Host de extensões do Executive (ExRegisterExtension).
//!
//! Cada registro EX_EXTENSION_REGISTRATION (InfoVersion @0,
//! ExtensionVersion @2, FunctionTable @8) entra numa tabela de até 512
//! extensões, o limite real.

use alloc::vec::Vec;

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Tabela de extensões (ExRegisterExtension): o limite real é 512.
static EXTENSIONS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// EX_EXTENSION_REGISTRATION (InfoVersion @0, ExtensionVersion @2,
/// FunctionTable @8) numa tabela de até 512 extensões. Grava o registro em
/// `extension` e devolve o NTSTATUS.
pub fn register(extension: u64, info_version: u16, function_table: u64) -> u32 {
    let mut table = EXTENSIONS.lock();
    if table.len() >= 512 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let record = guest::alloc_bytes(ExtensionRecord::SIZE);
    if record == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: alocação nova do tamanho do registro.
    let body = unsafe { ExtensionRecord::at(record) };
    body.version.set(info_version);
    body.reserved.set(0);
    body.function_table.set(function_table);
    table.push(record);
    drop(table);
    // SAFETY: o PEX_EXTENSION de saída do chamador (modo kernel).
    unsafe { Field::<u64>::at(extension) }.set(record);
    0
}

/// Registro opaco devolvido como EX_EXTENSION: versão e tabela de funções.
#[repr(C)]
struct ExtensionRecord {
    version: Field<u16>,
    reserved: Field<u16>,
    _pad_4: Reserved<0x4>,
    function_table: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ExtensionRecord {}

const _: () = assert!(core::mem::size_of::<ExtensionRecord>() == 0x10);
