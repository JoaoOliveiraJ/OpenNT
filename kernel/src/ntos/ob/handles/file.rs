//! Referência e duplicação de arquivos por handle.
//!
//! A referência é adquirida na tabela do processo que realmente possui o
//! handle, sob a trava da entrada; cada entrada mantém o mesmo FILE_OBJECT e
//! seu backing, sem reabrir o arquivo.

use alloc::sync::Arc;

use crate::ntos::ob::object_manager::{self, NativeOpen, ObjectHooks};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ob::{handle_table, object_types, open_pointer};
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ke::critical_region;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_FILE_CLOSED: u32 = 0xC000_0128;

/// Referência ao FILE_OBJECT com direitos e atributos capturados na mesma
/// trava; sobrevive ao desbloqueio e ao fechamento do handle.
pub struct FileReference {
    pub pointer: u64,
    pub access: u32,
    pub attributes: u32,
    released: bool,
}

impl FileReference {
    pub fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Err(KernelError::new("file handle reference released twice"));
        }
        // Marca antes de chamar o dono, que pode destruir o objeto.
        self.released = true;
        file_objects::dereference(self.pointer).map(|_| ())
    }
}

/// Pseudo-handles nunca são arquivos; UserMode não usa handles de kernel.
pub fn reference(handle: u64, access_mode: u8) -> Result<Result<FileReference, u32>, KernelError> {
    let signed = handle as i64;
    let user_mode = access_mode != 0;
    if signed == -1 || signed == -2 {
        return Ok(Err(STATUS_OBJECT_TYPE_MISMATCH));
    }
    let kernel_handle = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if if kernel_handle { user_mode } else { handle > 0x7FFF_FFFF } {
        return Ok(Err(STATUS_INVALID_HANDLE));
    }
    let owner = if kernel_handle { process::get_system_process() } else { process::get_current_process() };
    let index = (handle & 0x7FFF_FFFC) as u32;
    critical_region::with_critical(|| {
        let table = process_handles::reference(owner)?;
        if table == 0 {
            return Ok(Err(STATUS_INVALID_HANDLE));
        }
        let result = (|| {
            if process_handles::get(owner) != Some(table) {
                return Err(KernelError::new("file handle table ownership mismatch"));
            }
            let file_type = object_types::file_type();
            let outcome = handle_table::with_entry(table, index, |entry| {
                match object_manager::handle_record(index) {
                    // Uma cópia canônica não é acessível pelo índice baixo.
                    Some(record) if record.node == entry.identity => {
                        if record.options.kernel_handle != kernel_handle {
                            return Ok(Err(STATUS_INVALID_HANDLE));
                        }
                    }
                    _ if kernel_handle => return Ok(Err(STATUS_INVALID_HANDLE)),
                    _ => {}
                }
                if entry.type_name != file_type.name {
                    return Ok(Err(STATUS_OBJECT_TYPE_MISMATCH));
                }
                if !file_objects::is_file(entry.pointer) {
                    return Err(KernelError::new("live file handle has no owning FILE_OBJECT"));
                }
                file_objects::reference(entry.pointer)?;
                Ok(Ok(FileReference { pointer: entry.pointer, access: entry.access, attributes: entry.attributes, released: false }))
            })?;
            Ok(outcome.unwrap_or(Err(STATUS_INVALID_HANDLE)))
        })();
        process_handles::release(owner)?;
        result
    })
}

/// Cada handle duplicado possui sua própria abertura do FILE_OBJECT.
struct DuplicateHooks {
    pointer: u64,
}

impl ObjectHooks for DuplicateHooks {
    fn on_handle_open(&self) -> Result<(), KernelError> {
        // Uma mudança de vida anterior à publicação cancela a abertura.
        if file_objects::state(self.pointer).is_none_or(|(_, _, cleaned, closing)| cleaned || closing) {
            return Err(KernelError::with_status("file was cleaned before duplication", STATUS_FILE_CLOSED));
        }
        file_objects::open_handle(self.pointer)
    }

    fn on_handle_close(&self) {
        let _ = file_objects::close_handle(self.pointer);
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Duplica somente arquivos para a tabela de System, sem ampliar direitos;
/// devolve a codificação canônica de kernel.
pub fn duplicate_to_kernel(handle: u64, desired_access: u32) -> Result<Result<u64, u32>, KernelError> {
    // Bits reservados recusados antes do mapeamento genérico.
    if desired_access & 0x0CE0_0000 != 0 {
        return Ok(Err(STATUS_ACCESS_DENIED));
    }
    let mut source = match reference(handle, 0)? {
        Ok(source) => source,
        Err(status) => return Ok(Err(status)),
    };
    let result = (|| {
        let file_type = object_types::file_type();
        // ACCESS_SYSTEM_SECURITY continua sujeito à checagem de direitos.
        let granted = file_objects::access(desired_access) & (file_type.valid_access | 0x0100_0000);
        if granted & !source.access != 0 {
            return Ok(Err(STATUS_ACCESS_DENIED));
        }
        // CLEANUP encerra novas aberturas mesmo com referências vivas.
        if file_objects::state(source.pointer).is_none_or(|(_, _, cleaned, closing)| cleaned || closing) {
            return Ok(Err(STATUS_FILE_CLOSED));
        }
        let Some(description) = open_pointer::describe(source.pointer) else {
            return Err(KernelError::new("duplicated file has no owner"));
        };
        let mut data = description.data();
        data.native_pointer = description.pointer;
        data.native_open = Some(NativeOpen { record: description.pointer, node: description.owner.node(description.pointer) });
        data.owner_process = Some(process::get_system_process());
        data.kernel_handle = true;
        data.open_attributes = Some(0x200);
        // Só a auditoria é copiada; herança e proteção pertencem à origem.
        data.attributes = source.attributes & 4;
        data.access = Some(granted);
        data.hooks = Some(Arc::new(DuplicateHooks { pointer: description.pointer }));
        let node = object_manager::new_node("", "File", Some(data));
        match object_manager::open_object(node, None) {
            Ok(index) => Ok(Ok(0xFFFF_FFFF_8000_0000 | index as u64)),
            Err(error) if error.status != 0 => Ok(Err(error.status)),
            Err(error) => Err(error),
        }
    })();
    // A nova entrada tem sua própria referência; esta só encerra a consulta.
    source.release()?;
    result
}

/// Fecha uma cópia privada que ainda não foi transferida ao chamador.
pub fn close_kernel(handle: u64) -> Result<(), KernelError> {
    match open_pointer::close(handle) {
        Some(0) => Ok(()),
        status => Err(KernelError::new(alloc::format!("private file handle close failed: {status:?}"))),
    }
}
