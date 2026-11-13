//! Referência de processo por handle.
//!
//! QUERY_INFORMATION também satisfaz QUERY_LIMITED_INFORMATION nas tabelas
//! criadas pelos provedores anteriores; os demais direitos são distintos.

use super::{handle_table, object_manager, object_types};
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ke::critical_region;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// EPROCESS referenciado; `release` ocorre uma única vez.
pub struct ProcessReference {
    pub pointer: u64,
    released: bool,
}

impl ProcessReference {
    pub fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Err(KernelError::new("process handle reference released twice"));
        }
        self.released = true;
        process::dereference(self.pointer).map(|_| ())
    }
}

fn retain(pointer: u64) -> Result<ProcessReference, KernelError> {
    if process::reference(pointer).is_none() {
        return Err(KernelError::new("live process handle has no owning EPROCESS"));
    }
    Ok(ProcessReference { pointer, released: false })
}

/// `-1` é o processo corrente; `-2` (thread) não é processo.
pub fn reference(handle: u64, desired_access: u32, access_mode: u8) -> Result<Result<ProcessReference, u32>, KernelError> {
    let signed = handle as i64;
    let from_user_mode = access_mode != 0;
    if signed == -1 {
        return retain(process::get_current_process()).map(Ok);
    }
    if signed == -2 {
        return Ok(Err(0xC000_0024));
    }
    let kernel_handle = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if if kernel_handle { from_user_mode } else { handle > 0x7FFF_FFFF } {
        return Ok(Err(0xC000_0008));
    }
    let owner = if kernel_handle { process::get_system_process() } else { process::get_current_process() };
    let index = (handle & 0x7FFF_FFFC) as u32;
    critical_region::with_critical(|| {
        let table = process_handles::reference(owner)?;
        if table == 0 {
            return Ok(Err(0xC000_0008));
        }
        let result = (|| {
            if process_handles::get(owner) != Some(table) {
                return Err(KernelError::new("process handle table mismatch"));
            }
            let process_type = object_types::process_type();
            let outcome = handle_table::with_entry(table, index, |entry| {
                match object_manager::handle_record(index) {
                    Some(record) if record.node == entry.identity => {
                        if record.options.kernel_handle != kernel_handle {
                            return Ok(Err(0xC000_0008));
                        }
                    }
                    _ if kernel_handle => return Ok(Err(0xC000_0008)),
                    _ => {}
                }
                if entry.type_name != process_type.name {
                    return Ok(Err(0xC000_0024));
                }
                let access = entry.access | if entry.access & 0x400 != 0 { 0x1000 } else { 0 };
                if from_user_mode && desired_access & !access != 0 {
                    return Ok(Err(0xC000_0022));
                }
                retain(entry.pointer).map(Ok)
            })?;
            Ok(outcome.unwrap_or(Err(0xC000_0008)))
        })();
        process_handles::release(owner)?;
        result
    })
}
