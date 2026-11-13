//! Host de extensões do Executive (ExRegisterExtension).
//!
//! Cada registro EX_EXTENSION_REGISTRATION (InfoVersion @0,
//! ExtensionVersion @2, FunctionTable @8) entra numa tabela de até 512
//! extensões, o limite real.

use alloc::vec::Vec;

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
    let record = guest::alloc_bytes(0x10);
    if record == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write16(record, info_version);
    guest::write16(record + 2, 0);
    guest::write64(record + 8, function_table);
    table.push(record);
    drop(table);
    guest::write64(extension, record);
    0
}
