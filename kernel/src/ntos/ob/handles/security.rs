//! Referência de objetos por handle de kernel — `system32/ntos/ob/security-handles.js`.
//!
//! Zw consulta em KernelMode: os direitos pedidos não são comparados aos
//! concedidos, mas a tabela, a codificação do handle e a vida do corpo
//! continuam verificadas. A referência sobrevive ao fechamento do handle e é
//! liberada exatamente uma vez.

use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::open_pointer::{self, Described};
use crate::ntos::ob::objects::device as device_objects;
use crate::ntos::ob::{handle_table, object_manager};
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::cm::key::{objects as key_objects, services as key_services};
use crate::ntos::ke::critical_region;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// Dono do corpo e suas operações reais de referência.
enum Owner {
    Described(Described),
    Key(u64),
    Device(u64),
}

/// Corpo retido pela consulta.
pub struct Retained {
    pub pointer: u64,
    pub object_type: ObjectType,
    pub access: u32,
    pub attributes: u32,
    owner: Owner,
    released: bool,
}

impl Retained {
    /// Política de segurança do corpo (donos genéricos de abertura por ponteiro).
    pub fn security(&self) -> Option<crate::ntos::se::model::SecurityPolicy> {
        match &self.owner {
            Owner::Described(described) => Some(described.owner.security(self.pointer)),
            _ => None,
        }
    }

    pub fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Err(KernelError::new("security object reference released twice"));
        }
        self.released = true;
        match &self.owner {
            Owner::Described(described) => described.dereference(),
            Owner::Key(pointer) => key_objects::release(*pointer)?,
            Owner::Device(pointer) => {
                device_objects::dereference(*pointer)?;
            }
        }
        Ok(())
    }
}

/// Os provedores entregam o corpo; chaves e dispositivos ficam fora do
/// provedor genérico de abertura por ponteiro.
fn describe_owned_object(pointer: u64) -> Result<(ObjectType, Owner), KernelError> {
    if let Some(described) = open_pointer::describe(pointer) {
        return Ok((described.object_type.clone(), Owner::Described(described)));
    }
    if key_objects::get(pointer).is_some() {
        return Ok((object_types::key_type(), Owner::Key(pointer)));
    }
    if device_objects::is_device(pointer) {
        return Ok((object_types::device_type(), Owner::Device(pointer)));
    }
    Err(KernelError::new("live security handle has no owning object"))
}

fn retain(pointer: u64, object_type: ObjectType, owner: Owner, access: u32, attributes: u32) -> Result<Retained, KernelError> {
    match &owner {
        Owner::Described(described) => described.reference(),
        Owner::Key(pointer) => {
            key_objects::hold(*pointer);
        }
        Owner::Device(pointer) => {
            if device_objects::reference(*pointer)?.is_none() {
                return Err(KernelError::new("security object reference failed"));
            }
        }
    }
    Ok(Retained { pointer, object_type, access, attributes, owner, released: false })
}

/// Consulta só a tabela dona da abertura; os dois bits de tag não mudam o
/// índice e bits altos arbitrários nunca são truncados para ele.
pub fn reference_kernel_handle(handle: u64) -> Result<Result<Retained, u32>, KernelError> {
    let signed = handle as i64;
    if signed == -1 || signed == -2 {
        let pointer = if signed == -1 { process::get_current_process() } else { process::get_current_thread() };
        let (object_type, owner) = describe_owned_object(pointer)?;
        return retain(pointer, object_type, owner, 0, 0).map(Ok);
    }
    let canonical_kernel = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if !canonical_kernel && handle > 0x7FFF_FFFF {
        return Ok(Err(STATUS_INVALID_HANDLE));
    }
    let index = (handle & 0x7FFF_FFFC) as u32;
    // Handles privados do registro escolhem o System pelos metadados.
    let key_metadata = key_services::close_record(index);
    let owner_process = if canonical_kernel || key_metadata.as_ref().is_some_and(|metadata| metadata.kernel_handle) { process::get_system_process() } else { process::get_current_process() };
    critical_region::enter_critical()?;
    let mut table_reference = 0;
    let result = (|| -> Result<Result<Retained, u32>, KernelError> {
        table_reference = process_handles::reference(owner_process)?;
        if table_reference == 0 {
            return Ok(Err(STATUS_INVALID_HANDLE));
        }
        if process_handles::get(owner_process) != Some(table_reference) {
            return Err(KernelError::new("security handle table ownership mismatch"));
        }
        let found = handle_table::with_entry(table_reference, index, |row| -> Result<Result<Retained, u32>, KernelError> {
            match object_manager::handle_record(index).filter(|record| record.node == row.identity) {
                Some(record) => {
                    if record.options.kernel_handle != canonical_kernel {
                        return Ok(Err(STATUS_INVALID_HANDLE));
                    }
                }
                None => {
                    if canonical_kernel {
                        return Ok(Err(STATUS_INVALID_HANDLE));
                    }
                    if key_metadata.is_some() && key_services::close_record(index).is_none_or(|current| current.owner_process != owner_process) {
                        return Ok(Err(STATUS_INVALID_HANDLE));
                    }
                }
            }
            let (object_type, owner) = describe_owned_object(row.pointer)?;
            if object_type.name != row.type_name {
                return Err(KernelError::new("security handle body identity mismatch"));
            }
            // A entrada continua travada até o dono reter o corpo.
            retain(row.pointer, object_type, owner, row.access, row.attributes).map(Ok)
        })?;
        Ok(found.unwrap_or(Err(STATUS_INVALID_HANDLE)))
    })();
    if table_reference != 0 {
        process_handles::release(owner_process)?;
    }
    critical_region::leave_critical()?;
    result
}
