//! Operações nativas de handle — `system32/ntos/ps/user/handles.js`.
//!
//! Duplicatas referem-se à mesma descrição aberta; acesso, herança e
//! proteção contra fechamento pertencem a cada handle. Transcrito:
//! NtDuplicateObject e NtSetInformationObject. Pendente: NtQueryObject (com
//! `ob/query-object`) e a duplicação do pseudo-handle de thread (com
//! `ps/user/threads`).

use alloc::sync::Arc;
use core::any::Any;

use super::state::{self, NativeBody, UserObject};
use crate::ntos::ob::object_manager::ObjectData;
use crate::ntos::ob::{close, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const INVALID: u32 = 0xC000_000D;
const BAD_HANDLE: u32 = 0xC000_0008;
const AV: u32 = 0xC000_0005;

fn is_pseudo_process(handle: u64) -> bool {
    handle == u64::MAX || handle == 0xFFFF_FFFF
}

fn is_pseudo_thread(handle: u64) -> bool {
    handle == u64::MAX - 1 || handle == 0xFFFF_FFFE
}

/// Handle `process` do processo para um EPROCESS (duplicação do
/// pseudo-handle): o corpo nativo é retido e contado por handle.
pub struct UserProcess {
    pub pointer: u64,
    pub process_id: u64,
}

impl UserProcess {
    fn type_name(&self) -> Option<alloc::string::String> {
        open_pointer::describe(self.pointer).map(|body| body.object_type.name.clone())
    }
}

impl UserObject for UserProcess {
    fn kind(&self) -> &'static str {
        "process"
    }
    fn wait_pointer(&self) -> Option<u64> {
        Some(self.pointer)
    }
    fn native_body(&self) -> Option<NativeBody> {
        let pointer = self.pointer;
        let body = open_pointer::describe(pointer)?;
        Some(NativeBody {
            pointer,
            type_name: body.object_type.name.clone(),
            record: pointer,
            reference: Arc::new(move || {
                if let Some(body) = open_pointer::describe(pointer) {
                    body.reference();
                }
            }),
            dereference: Arc::new(move || {
                if let Some(body) = open_pointer::describe(pointer) {
                    body.dereference();
                }
            }),
        })
    }
    fn callback_data(&self) -> ObjectData {
        ObjectData { native_pointer: self.pointer, process_id: Some(self.process_id), ..ObjectData::default() }
    }
    fn on_each_handle_open(&self) -> Result<bool, KernelError> {
        let body = open_pointer::describe(self.pointer).ok_or_else(|| KernelError::with_status("process body", BAD_HANDLE))?;
        body.reference();
        object_types::account(&body.object_type.name, 0, 1)?;
        Ok(true)
    }
    fn on_each_handle_close(&self) {
        if let Some(name) = self.type_name() {
            let _ = object_types::account(&name, 0, -1);
        }
        if let Some(body) = open_pointer::describe(self.pointer) {
            body.dereference();
        }
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// O processo de destino/origem precisa ser o processo corrente (este
/// escalonador hospeda um processo nativo por vez).
pub fn current_process(handle: u64, access: u32) -> u32 {
    if is_pseudo_process(handle) {
        return 0;
    }
    let Some(entry) = state::get_user_handle(handle) else { return BAD_HANDLE };
    if entry.kind() != "process" {
        return 0xC000_0024;
    }
    if entry.access() & access != access {
        return 0xC000_0022;
    }
    if entry.object.callback_data().process_id == Some(state::with(|state| state.current_process_id)) {
        0
    } else {
        0xC000_00BB
    }
}

/// NtDuplicateObject(sourceProcess, sourceHandle, targetProcess, target*,
/// access, attributes, options).
fn nt_duplicate_object(source_process: u64, source_handle: u64, target_process: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 24) {
        return Ok(AV);
    }
    let options = state::stack_arg32(rsp, 7);
    if options & !7 != 0 {
        return Ok(INVALID);
    }
    let status = current_process(source_process, 0x40);
    if status != 0 {
        return Ok(status);
    }
    let pseudo_process = is_pseudo_process(source_handle);
    let pseudo_thread = is_pseudo_thread(source_handle);
    let entry = state::get_user_handle(source_handle);
    if entry.is_none() && !pseudo_process {
        // O pseudo-handle de thread entra com `ps/user/threads`.
        return Ok(BAD_HANDLE);
    }
    let (source_access, source_attributes) = entry.as_ref().map_or((0x1F_FFFF, 0), |entry| (entry.access(), entry.attributes()));
    let mut new_handle: Option<u32> = None;
    let result = (|| -> Result<u32, KernelError> {
        if target_process == 0 {
            return Ok(if options & 1 != 0 { 0 } else { INVALID });
        }
        let status = current_process(target_process, 0x40);
        if status != 0 {
            return Ok(status);
        }
        if out != 0 && !state::probe_user_write(out, 8) {
            return Ok(AV);
        }
        let attributes = if options & 4 != 0 { source_attributes } else { state::stack_arg32(rsp, 6) };
        if attributes & !3 != 0 {
            return Ok(INVALID);
        }
        let access = if options & 2 != 0 { source_access } else { state::stack_arg32(rsp, 5) };
        // Direitos ausentes na origem exigem nova checagem de segurança:
        // nunca são concedidos em silêncio pela duplicação.
        if access & !source_access != 0 {
            return Ok(0xC000_0022);
        }
        let handle = match (&entry, pseudo_process) {
            (Some(entry), false) => state::duplicate_user_handle(entry, access, attributes)?,
            _ => {
                let current = process::get_current_process();
                state::alloc_user_handle(Arc::new(UserProcess { pointer: current, process_id: state::with(|state| state.current_process_id) }), access, attributes)?
            }
        };
        new_handle = Some(handle);
        if out != 0 {
            guest::write64(out, handle as u64);
        }
        Ok(0)
    })();
    let result = match result {
        Err(error) => {
            if let Some(handle) = new_handle {
                close::close_user(handle as u64, true);
            }
            if error.status != 0 {
                Ok(error.status)
            } else {
                Err(error)
            }
        }
        other => other,
    };
    // O Windows preserva uma origem protegida mesmo quando a duplicata é
    // produzida: a tentativa de fechar não sobrepõe a proteção.
    if options & 1 != 0 && !pseudo_process && !pseudo_thread {
        close::close_user(source_handle, false);
    }
    result
}

/// NtSetInformationObject(ObjectHandleFlagInformation): Inherit e
/// ProtectFromClose do handle.
fn nt_set_information_object(handle: u64, class: u64, input: u64, length: u64, _rsp: u64) -> Result<u32, KernelError> {
    if class as u32 != 4 {
        return Ok(0xC000_0003);
    }
    if length as u32 != 2 {
        return Ok(0xC000_0004);
    }
    if !state::probe_user_read(input, 2) {
        return Ok(AV);
    }
    if state::get_user_handle(handle).is_none() {
        return Ok(BAD_HANDLE);
    }
    let attributes = (if guest::read8(input) != 0 { 2 } else { 0 }) | (if guest::read8(input + 1) != 0 { 1 } else { 0 });
    state::change_user_handle_attributes(handle, attributes)
}

/// NtQueryObject: a sondagem de UserMode precede a validação do handle e
/// da classe; só as duas flags BOOLEAN (classe 4) aceitam alinhamento de
/// byte.
fn nt_query_object(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let (class, length) = (class as u32, length as u32);
    if length != 0 && class != 4 && out & 3 != 0 {
        return Ok(0x8000_0002);
    }
    if length != 0 && !state::probe_user_write(out, length as u64) {
        return Ok(AV);
    }
    let returned = state::stack_arg(rsp, 5);
    if returned != 0 && !state::probe_user_write(returned, 4) {
        return Ok(AV);
    }
    if class != 3 && handle > 0x7FFF_FFFF && handle < 0xFFFF_FFFF_FFFF_FFFE {
        return Ok(BAD_HANDLE);
    }
    crate::ntos::ob::query_object::query(handle, class, out, length, returned)
}

pub fn init() {
    state::register_handler("NtQueryObject", nt_query_object);
    state::register_handler("NtDuplicateObject", nt_duplicate_object);
    state::register_handler("NtSetInformationObject", nt_set_information_object);
}
