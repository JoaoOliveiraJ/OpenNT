//! Referência de thread por handle.
//!
//! Retém a ETHREAD na tabela que realmente possui o handle, antes de soltar
//! a trava da entrada.

use crate::ntos::ob::{handle_table, object_manager, object_types};
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ke::critical_region;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// ETHREAD referenciada; pertence ao consumidor até `release`, mesmo se o
/// handle for fechado.
pub struct ThreadReference {
    pub pointer: u64,
    released: bool,
}

impl ThreadReference {
    pub fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Err(KernelError::new("thread handle reference released twice"));
        }
        self.released = true;
        // As threads de sistema (fase 7) também coletam uma thread nativa
        // já terminada; até lá toda ETHREAD pertence ao Process Manager.
        process::dereference_thread(self.pointer).map(|_| ())
    }
}

fn retain(pointer: u64) -> Result<ThreadReference, KernelError> {
    if process::reference_thread(pointer).is_none() {
        return Err(KernelError::new("live thread handle has no owning ETHREAD"));
    }
    Ok(ThreadReference { pointer, released: false })
}

/// `-2` é a thread corrente (inclusive anexada a outro processo); `-1`
/// (processo) não é thread.
pub fn reference(handle: u64, desired_access: u32, access_mode: u8) -> Result<Result<ThreadReference, u32>, KernelError> {
    let signed = handle as i64;
    let from_user_mode = access_mode != 0;
    if signed == -2 {
        return retain(process::get_current_thread()).map(Ok);
    }
    if signed == -1 {
        return Ok(Err(STATUS_OBJECT_TYPE_MISMATCH));
    }
    let kernel_handle = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if if kernel_handle { from_user_mode } else { handle > 0x7FFF_FFFF } {
        return Ok(Err(STATUS_INVALID_HANDLE));
    }
    let owner = if kernel_handle { process::get_system_process() } else { process::get_current_process() };
    let index = (handle & 0x7FFF_FFFC) as u32;
    critical_region::with_critical(|| {
        // O rundown protege a tabela; a trava protege a entrada.
        let table = process_handles::reference(owner)?;
        if table == 0 {
            return Ok(Err(STATUS_INVALID_HANDLE));
        }
        let result = (|| {
            if process_handles::get(owner) != Some(table) {
                return Err(KernelError::new("thread handle table ownership mismatch"));
            }
            let thread_type = object_types::thread_type();
            let outcome = handle_table::with_entry(table, index, |entry| {
                match object_manager::handle_record(index) {
                    Some(record) if record.node == entry.identity => {
                        if record.options.kernel_handle != kernel_handle {
                            return Ok(Err(STATUS_INVALID_HANDLE));
                        }
                    }
                    _ if kernel_handle => return Ok(Err(STATUS_INVALID_HANDLE)),
                    _ => {}
                }
                if entry.type_name != thread_type.name {
                    return Ok(Err(STATUS_OBJECT_TYPE_MISMATCH));
                }
                if from_user_mode && desired_access & !entry.access != 0 {
                    return Ok(Err(STATUS_ACCESS_DENIED));
                }
                retain(entry.pointer).map(Ok)
            })?;
            Ok(outcome.unwrap_or(Err(STATUS_INVALID_HANDLE)))
        })();
        process_handles::release(owner)?;
        result
    })
}
