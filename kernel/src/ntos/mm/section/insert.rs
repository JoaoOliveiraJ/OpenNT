//! ObInsertObject de uma seção criada pelo MmCreateSection.
//!
//! O MmCreateSection devolve o SECTION ainda como objeto novo
//! (OB_FLAG_NEW_OBJECT, com os OBJECT_ATTRIBUTES capturados) e quem chama o
//! insere depois, como o NtCreateSection faz. O dxgmms2
//! (VIDMM_GLOBAL::CommitGlobalBackingStore, 0x6608B) insere a seção sem nome
//! de cada alocação com um handle que fecha logo em seguida: o
//! ObOpenObjectByPointer do CommitLocalBackingStore recusa um objeto que
//! ainda não foi inserido.
//!
//! O ObInsertObjectEx do 19041 (o mesmo contrato de `ob/object_create`):
//! - objeto já inserido (sem a informação de criação): STATUS_INVALID_PARAMETER,
//!   sem soltar referência;
//! - com Handle e sem nome: o handle de criação (ObpCreateUnnamedHandle) com
//!   o acesso pedido sem SeAccessCheck, na tabela do processo corrente (ou na
//!   de kernel com OBJ_KERNEL_HANDLE); ele recebe ObjectPointerBias + 1
//!   referências e a de criação é solta;
//! - com Handle e com nome: o nome entra no namespace e o handle é aberto; um
//!   homônimo com OBJ_OPENIF abre com STATUS_OBJECT_NAME_EXISTS, devolve o
//!   existente em NewObject e solta o novo;
//! - sem Handle: sem nome nem descritor a referência de criação é solta; os
//!   demais ficam com ela (sem nome no namespace) e NewObject recebe o objeto;
//! - falha: a referência de criação é solta.

use super::create::{self, Attributes};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::Kthread;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::process;
use crate::ntos::ps::user::sections;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// KTHREAD.PreviousMode da thread corrente (KernelMode sem thread).
fn previous_mode() -> u8 {
    let thread = process::get_current_thread();
    if thread == 0 {
        return 0;
    }
    // SAFETY: a KTHREAD corrente.
    unsafe { Kthread::at(thread) }.previous_mode.get() as u8
}

/// Saída escalar (`PVOID*`, `PHANDLE`) de um chamador de kernel.
fn out(address: u64) -> &'static Field<u64> {
    // SAFETY: ponteiro de saída fornecido por um chamador de kernel.
    unsafe { Field::<u64>::at(address) }
}

/// A referência de criação sai: uma seção sem handles, vistas nem outras
/// referências é destruída aqui.
fn release_creation(pointer: u64) -> Result<(), KernelError> {
    section_objects::dereference(pointer).map(|_| ())
}

/// ObInsertObject(Object, AccessState, DesiredAccess, ObjectPointerBias,
/// NewObject, Handle) de um corpo SECTION.
pub fn insert(pointer: u64, desired: u32, bias: u32, new_object_out: u64, handle_out: u64) -> Result<u32, KernelError> {
    let mut taken = None;
    section_objects::update(pointer, |state| taken = state.creation_attributes.take());
    let Some(creation) = taken else { return Ok(STATUS_INVALID_PARAMETER) };
    let Some(section) = sections::by_pointer(pointer) else { return Ok(STATUS_INVALID_PARAMETER) };
    let named = creation.name.is_some();
    if handle_out == 0 {
        if !named && creation.security_descriptor == 0 {
            release_creation(pointer)?;
        } else if new_object_out != 0 {
            out(new_object_out).set(pointer);
        }
        return Ok(0);
    }
    out(handle_out).set(0);
    let mode = previous_mode();
    let captured = Attributes { flags: creation.flags, security_descriptor: creation.security_descriptor, name: creation.name, root: creation.root, insensitive: creation.insensitive, ..Attributes::default() };
    let info = match create::resolve(captured) {
        Ok(info) => info,
        Err(status) => {
            release_creation(pointer)?;
            return Ok(status);
        }
    };
    if let Some(node) = info.node {
        let (status, existing) = create::open_existing(node, &info, desired, mode, handle_out)?;
        if status == 0x4000_0000 && new_object_out != 0 {
            out(new_object_out).set(existing);
        }
        release_creation(pointer)?;
        return Ok(status);
    }
    if let Some(status) = create::check_publish(&info, mode) {
        release_creation(pointer)?;
        return Ok(status);
    }
    let status = create::publish(&section, &info, desired, handle_out)?;
    if status != 0 {
        section_objects::update(pointer, |state| state.permanent = false);
        release_creation(pointer)?;
        return Ok(status);
    }
    for _ in 0..bias {
        section_objects::reference(pointer);
    }
    release_creation(pointer)?;
    if new_object_out != 0 {
        out(new_object_out).set(pointer);
    }
    Ok(0)
}
