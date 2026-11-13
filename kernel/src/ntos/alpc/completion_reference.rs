//! Referência da IOCP pela tabela dona.
//!
//! Resolve a porta na tabela de handles do processo (ou do System, para
//! handles de kernel) e retém o corpo antes de destravar a entrada: handles
//! de usuário e de kernel chegam à mesma fila de conclusão.

use alloc::sync::Arc;

use crate::ntos::ke::critical_region;
use crate::ntos::ob::objects::completion::{self as completion_objects, Port};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::{handle_table, object_manager, object_types};
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// Porta retida; `release` solta a referência uma única vez.
pub struct Reference {
    pub port: Arc<Port>,
    released: bool,
}

impl Reference {
    pub fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Err(KernelError::new("ALPC completion reference released twice"));
        }
        self.released = true;
        dispatcher_objects::dereference(self.port.pointer).map(|_| ())
    }
}

pub fn reference(handle: u64, access_mode: u8) -> Result<Result<Reference, u32>, KernelError> {
    if matches!(handle as i64, -1 | -2) {
        return Ok(Err(0xC000_0024));
    }
    let from_user_mode = access_mode != 0;
    let kernel_handle = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if if kernel_handle { from_user_mode } else { handle > 0x7FFF_FFFF } {
        return Ok(Err(0xC000_0008));
    }
    let owner = if kernel_handle { process::get_system_process() } else { process::get_current_process() };
    let index = (handle & 0x7FFF_FFFC) as u32;
    critical_region::enter_critical()?;
    let result = (|| -> Result<Result<Reference, u32>, KernelError> {
        let table = process_handles::reference(owner)?;
        if table == 0 {
            return Ok(Err(0xC000_0008));
        }
        let outcome = (|| {
            if process_handles::get(owner) != Some(table) {
                return Err(KernelError::new("ALPC completion table ownership mismatch"));
            }
            let completion = object_types::user_type("completion").map(|object_type| object_type.name);
            let found = handle_table::with_entry(table, index, |row| {
                if let Some(native) = object_manager::handle_record(index).filter(|record| record.node == row.identity) {
                    if (native.attributes & 0x200 != 0) != kernel_handle {
                        return Ok(Err(0xC000_0008));
                    }
                } else if kernel_handle {
                    return Ok(Err(0xC000_0008));
                }
                if completion.as_deref() != Some(row.type_name.as_str()) {
                    return Ok(Err(0xC000_0024));
                }
                if from_user_mode && row.access & 2 == 0 {
                    return Ok(Err(0xC000_0022));
                }
                let live = dispatcher_objects::get(row.pointer).is_some_and(|(kind, _, _)| kind == "completion");
                let Some(port) = completion_objects::port_of(row.pointer).filter(|_| live) else { return Err(KernelError::new("Live completion handle has no owning queue")) };
                let _ = dispatcher_objects::reference(port.pointer);
                Ok(Ok(Reference { port, released: false }))
            })?;
            Ok(found.unwrap_or(Err(0xC000_0008)))
        })();
        let _ = process_handles::release(owner);
        outcome
    })();
    let _ = critical_region::leave_critical();
    result
}
