//! Referência da porta ALPC pela tabela dona.
//!
//! Retém o corpo antes de soltar a entrada travada; o corpo retido
//! sobrevive ao último fechamento e a desconexão não destrói a referência.

use alloc::sync::Arc;

use crate::ntos::ke::critical_region;
use crate::ntos::ob::objects::port::{self as port_objects, Port};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::{handle_table, object_manager, object_types};
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// Porta retida; `release` solta a referência uma única vez.
pub struct PortReference {
    pub port: Arc<Port>,
    pub handle_index: u32,
    released: bool,
}

impl PortReference {
    pub fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Err(KernelError::new("ALPC port reference released twice"));
        }
        self.released = true;
        dispatcher_objects::dereference(self.port.pointer).map(|_| ())
    }
}

fn retain(port: Arc<Port>, handle_index: u32) -> PortReference {
    let _ = dispatcher_objects::reference(port.pointer);
    PortReference { port, handle_index, released: false }
}

pub fn reference(handle: u64, desired: u32, access_mode: u8) -> Result<Result<PortReference, u32>, KernelError> {
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
    let result = (|| -> Result<Result<PortReference, u32>, KernelError> {
        let table = process_handles::reference(owner)?;
        if table == 0 {
            return Ok(Err(0xC000_0008));
        }
        let outcome = (|| {
            if process_handles::get(owner) != Some(table) {
                return Err(KernelError::new("ALPC handle table ownership mismatch"));
            }
            // LPC e ALPC compartilham o mesmo tipo NT; o transporte escolhe
            // seu protocolo depois.
            let port_type = object_types::user_type("alpc").map(|object_type| object_type.name);
            let found = handle_table::with_entry(table, index, |row| {
                if let Some(native) = object_manager::handle_record(index).filter(|record| record.node == row.identity) {
                    if (native.attributes & 0x200 != 0) != kernel_handle {
                        return Ok(Err(0xC000_0008));
                    }
                } else if kernel_handle || (from_user_mode && row.attributes & 0x200 != 0) {
                    return Ok(Err(0xC000_0008));
                }
                if port_type.as_deref() != Some(row.type_name.as_str()) {
                    return Ok(Err(0xC000_0024));
                }
                if from_user_mode && desired & !row.access != 0 {
                    return Ok(Err(0xC000_0022));
                }
                let live = dispatcher_objects::get(row.pointer).is_some_and(|(kind, _, _)| kind == "alpc" || kind == "port");
                let Some(port) = port_objects::port_of(row.pointer).filter(|_| live) else { return Err(KernelError::new("Live ALPC handle has no owning port")) };
                Ok(Ok(retain(port, index)))
            })?;
            Ok(found.unwrap_or(Err(0xC000_0008)))
        })();
        let _ = process_handles::release(owner);
        outcome
    })();
    let _ = critical_region::leave_critical();
    result
}
