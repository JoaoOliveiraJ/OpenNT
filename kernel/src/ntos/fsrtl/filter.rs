//! Registro de filtros de sistema de arquivos no FsRtl — a tabela do Filter
//! Manager (FsRtlRegisterFltMgrCalls) e os callbacks de filtro por driver
//! (FsRtlRegisterFileSystemFilterCallbacks).
//!
//! `RegisterFltMgrCalls` publica a tabela do FltMgr (o `xchg` de uma
//! instrução já existente em `drivers::fs::filter_callbacks`) e é a única
//! dependência real do `DriverEntry` do `fltmgr.sys`.

use crate::drivers::fs::filter_callbacks;
use crate::ntos::inc::types::{DriverExtension, DriverObject, FsFilterCallbacks, NtStruct};
use crate::ntos::mm::guest_memory as guest;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// FsRtlRegisterFltMgrCalls(Callbacks) -> previous (RVA 0x7d5640).
/// Uma instrução: `xchg [FltMgrCallbacks], rcx`. ** Única dependência real
/// do DriverEntry do fltmgr.sys. ** Ligado ao swap já existente.
pub fn register_flt_mgr_calls(callbacks: u64) -> u64 {
    filter_callbacks::exchange_callbacks(callbacks)
}

/// FsRtlRegisterFileSystemFilterCallbacks(DriverObject, Callbacks) ->
/// NTSTATUS (RVA 0x39a7b0). NULL em qualquer argumento -> INVALID_PARAMETER;
/// aloca `Callbacks->SizeOfFsFilterCallbacks` bytes de NonPagedPoolNx com a
/// tag 'FSmg', copia a tabela e guarda o ponteiro em
/// `DriverObject->DriverExtension->FsFilterCallbacks`.
pub fn register_file_system_filter_callbacks(driver_object: u64, callbacks: u64) -> u32 {
    if driver_object == 0 || callbacks == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    const TAG_FSMG: u64 = 0x676D_5346; // 'FSmg'
    const NON_PAGED_POOL_NX: u64 = 0x200;
    // SAFETY: DRIVER_OBJECT e FS_FILTER_CALLBACKS do driver chamador.
    let (driver, table) = unsafe { (DriverObject::at(driver_object), FsFilterCallbacks::at(callbacks)) };
    let size = table.size_of_fs_filter_callbacks.get() as u64;
    // SAFETY: a DRIVER_EXTENSION que o Io alocou para o driver.
    let extension = unsafe { DriverExtension::at(driver.driver_extension.get()) };
    let pool = crate::ntos::init::exports::invoke_handler("ExAllocatePoolWithTag", &[NON_PAGED_POOL_NX, size, TAG_FSMG])
        .unwrap_or(0);
    if pool == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(pool, &guest::read_bytes(callbacks, size as usize));
    extension.fs_filter_callbacks.set(pool);
    0
}
