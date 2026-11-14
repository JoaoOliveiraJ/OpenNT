//! Os objetos criados pelo ObCreateObject (os tipos dos drivers e do
//! subsistema de janelas, e os do executive que passam por ele): o dono
//! deles no Object Manager é o próprio OBJECT_HEADER (`ob/object_header`).
//! Referências mexem no PointerCount; cada handle passa pelo
//! ObpIncrementHandleCountEx na abertura e pelo ObpDecrementHandleCount no
//! fechamento, com o processo dono da tabela.

use crate::ntos::ob::object_header::{self, HandleOpen};
use crate::ntos::ob::object_manager::ObjectData;
use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::open_pointer::{ObjectOwner, QueryRecord};
use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::KernelError;

pub struct CreatedOwner;

pub static OWNER: CreatedOwner = CreatedOwner;

impl ObjectOwner for CreatedOwner {
    fn object_type(&self, pointer: u64) -> ObjectType {
        object_header::object_type_info(pointer).unwrap_or_else(object_types::meta_type)
    }

    fn reference(&self, pointer: u64) {
        object_header::reference(pointer, 1);
    }

    fn dereference(&self, pointer: u64) {
        object_header::dereference(pointer, false);
    }

    /// O handle conta no cabeçalho e retém o corpo.
    fn open_handle_for(&self, pointer: u64, open: &mut HandleOpen) -> Option<Result<(), KernelError>> {
        Some(open_handle(pointer, open))
    }

    fn close_handle_from(&self, pointer: u64, process: u64) {
        close_handle(pointer, process);
    }

    /// Sem descritor no cabeçalho o acesso não é restrito (DACL nula).
    fn security(&self, _pointer: u64) -> SecurityPolicy {
        SecurityPolicy::default()
    }

    fn exclusive_process(&self, pointer: u64) -> u64 {
        let Some(header) = object_header::header_of(pointer) else { return 0 };
        let info = object_header::info(header, object_header::INFO_PROCESS);
        if info == 0 {
            return 0;
        }
        // SAFETY: OBJECT_HEADER_PROCESS_INFO do cabeçalho vivo.
        unsafe { <crate::ntos::inc::types::extra_ob_header::ObjectHeaderProcessInfo as crate::ntos::inc::types::NtStruct>::at(info) }.exclusive_process.get()
    }

    fn data(&self, pointer: u64) -> ObjectData {
        ObjectData::pointer(pointer)
    }

    fn query_record(&self, pointer: u64) -> QueryRecord {
        let (references, handles) = object_header::counts(pointer);
        let permanent = object_header::header(pointer).is_some_and(|header| header.flags.get() & object_header::FLAG_PERMANENT_OBJECT != 0);
        let name = object_header::name_node(pointer).and_then(crate::ntos::ob::object_manager::path_of).unwrap_or_default();
        QueryRecord { handles: Some(handles as u32), references: references as u32, permanent, name }
    }
}

/// A abertura de um handle: ObpIncrementHandleCountEx e a referência do
/// handle.
pub fn open_handle(pointer: u64, open: &mut HandleOpen) -> Result<(), KernelError> {
    object_header::increment_handle_count(pointer, open, 0).map_err(|status| KernelError::with_status("object handle open refused", status))?;
    object_header::reference(pointer, 1);
    Ok(())
}

/// O fechamento: ObpDecrementHandleCount no processo dono e a referência do
/// handle solta.
pub fn close_handle(pointer: u64, process: u64) {
    object_header::decrement_handle_count(pointer, process);
    object_header::dereference(pointer, false);
}
