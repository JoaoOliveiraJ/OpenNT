//! Operações nativas de handle.
//!
//! Duplicatas referem-se à mesma descrição aberta; acesso, herança e
//! proteção contra fechamento pertencem a cada handle. Implementado:
//! NtDuplicateObject e NtSetInformationObject. Pendente: NtQueryObject (com
//! `ob/query_object`) e a duplicação do pseudo-handle de thread (com
//! `ps/user/threads`).

use alloc::sync::Arc;
use core::any::Any;

use super::state::{self, NativeBody, UserObject};
use crate::ntos::ob::object_manager::ObjectData;
use crate::ntos::ob::{close, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::ObjectHandleFlagInformation;

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

/// O processo de destino/origem precisa ser o processo corrente, o anexado
/// quando há attach (as operações entre processos ainda não existem). O
/// handle é procurado na tabela desse mesmo processo.
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
    if entry.object.callback_data().native_pointer == process::get_current_process() {
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
                state::alloc_user_handle(Arc::new(UserProcess { pointer: current, process_id: state::current_process_id() }), access, attributes)?
            }
        };
        new_handle = Some(handle);
        if out != 0 {
            // PHANDLE de saída (sondado acima).
            guest::try_write::<u64>(out, handle as u64)?;
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
    let information = state::user_struct::<ObjectHandleFlagInformation>(input).and_then(|information| Ok((information.inherit.probe_get()?, information.protect_from_close.probe_get()?)));
    let (inherit, protect) = match information {
        Ok(flags) => flags,
        Err(error) => return Ok(error.status),
    };
    let attributes = (if inherit != 0 { 2 } else { 0 }) | (if protect != 0 { 1 } else { 0 });
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
    state::register_handler("NtOpenProcess", nt_open_process);
    state::register_handler("NtGetNextProcess", nt_get_next_process);
    state::register_handler("NtGetNextThread", nt_get_next_thread);
}

// ---- NtOpenProcess / NtGetNextProcess / NtGetNextThread ----
//
// Medidos no ntoskrnl 19045:
//   NtOpenProcess -> PsOpenProcess(..., UserMode): o PHANDLE é sondado
//   primeiro; OBJECT_ATTRIBUTES é obrigatório e alinhado a 4, CLIENT_ID
//   alinhado a 4 (ProbeForRead de estrutura pequena); atributos & 0x1DF2;
//   nome (processos não têm) ou CLIENT_ID ausente ->
//   STATUS_INVALID_PARAMETER_MIX; com UniqueThread, PsLookupProcessThreadByCid
//   (a thread define o processo e precisa ser do UniqueProcess dado); senão
//   PsLookupProcessByProcessId; com SeDebugPrivilege o pedido é concedido
//   (MAXIMUM_ALLOWED vira PROCESS_ALL_ACCESS); senão ObOpenObjectByPointer
//   em UserMode decide pela DACL do EPROCESS.
//   NtGetNextProcess(process, access, attributes, flags, out*): atributos &
//   0x1DF2; a saída é sondada e zerada; Flags só aceita o bit 0 (para trás)
//   -> senão STATUS_INVALID_PARAMETER; abre o próximo da PsActiveProcessHead,
//   pulando quem nega acesso; o fim é STATUS_NO_MORE_ENTRIES.
//   NtGetNextThread(process, thread, access, attributes, flags, out*): a
//   saída é sondada e zerada; Flags != 0 -> STATUS_INVALID_PARAMETER;
//   PROCESS_QUERY_INFORMATION no processo; a thread dada precisa ser dele
//   (senão STATUS_INVALID_PARAMETER); abre a próxima thread do processo.
// Só o processo hospedado tem threads com handle de usuário (threads de
// kernel não têm objeto de usuário): nos demais, NtGetNextThread não abre
// nenhuma (STATUS_NO_MORE_ENTRIES). As threads seguem a política sem DACL do
// NtOpenThread deste kernel (direitos genéricos mapeados).

use alloc::vec::Vec;
use core::mem::offset_of;

use super::threads;
use crate::ntos::inc::types::{ClientId, Eprocess, Kthread, NtStruct, ObjectAttributes};
use crate::ntos::ob::object_access;
use crate::ntos::se::model::SecurityPolicy;
use crate::ntos::se::token::tokens;

const INVALID_CID: u32 = 0xC000_000B;
const PARAMETER_MIX: u32 = 0xC000_0030;
const MISALIGNED: u32 = 0x8000_0002;
const DENIED: u32 = 0xC000_0022;
const TYPE_MISMATCH: u32 = 0xC000_0024;
const NO_MORE_ENTRIES: u32 = 0x8000_001A;
/// Atributos de OBJECT_ATTRIBUTES aceitos de UserMode (sem OBJ_KERNEL_HANDLE).
const USER_ATTRIBUTES: u32 = 0x1DF2;
/// OBJ_EXCLUSIVE (processos e threads nunca são exclusivos) e OBJ_INHERIT
/// (o atributo de herança do handle).
const OBJ_EXCLUSIVE: u32 = 0x20;
const OBJ_INHERIT: u32 = 2;
/// PROCESS_QUERY_INFORMATION e MAXIMUM_ALLOWED.
const PROCESS_QUERY_INFORMATION: u32 = 0x400;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// SeDebugPrivilege (LUID 20) habilitado (SE_PRIVILEGE_ENABLED).
const DEBUG_PRIVILEGE: u64 = 20;
const PRIVILEGE_ENABLED: u32 = 2;

fn eprocess(pointer: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS vivo da PsActiveProcessHead ou de um handle aberto.
    unsafe { Eprocess::at(pointer) }
}

fn kthread(pointer: u64) -> &'static Kthread {
    // SAFETY: KTHREAD viva de uma thread de usuário ou referenciada.
    unsafe { Kthread::at(pointer) }
}

/// EPROCESS de um handle (o pseudo-handle incluído) com o acesso pedido.
fn process_pointer(handle: u64, access: u32) -> Result<u64, u32> {
    if is_pseudo_process(handle) {
        return Ok(process::get_current_process());
    }
    let Some(entry) = state::get_user_handle(handle) else { return Err(BAD_HANDLE) };
    if entry.kind() != "process" {
        return Err(TYPE_MISMATCH);
    }
    if entry.access() & access != access {
        return Err(DENIED);
    }
    entry.downcast::<UserProcess>().map(|object| object.pointer).ok_or(BAD_HANDLE)
}

/// Direitos de um novo handle de processo (PsOpenProcess/NtGetNextProcess +
/// ObOpenObjectByPointer em UserMode).
fn process_access(pointer: u64, requested: u32) -> Result<u32, u32> {
    let process_type = object_types::process_type();
    let token = object_access::subject();
    let debug = token.and_then(tokens::get).is_some_and(|token| token.privileges.iter().any(|privilege| privilege.id == DEBUG_PRIVILEGE && privilege.attributes & PRIVILEGE_ENABLED != 0));
    if debug {
        let mask = object_access::map_generic_access(requested, &process_type);
        let explicit = mask & !MAXIMUM_ALLOWED;
        if explicit & !(process_type.valid_access | 0x0100_0000) != 0 {
            return Err(DENIED);
        }
        return Ok(explicit | if mask & MAXIMUM_ALLOWED != 0 { process_type.valid_access } else { 0 });
    }
    let policy = process::with_record(pointer, |record| record.security.clone()).unwrap_or_default();
    object_access::check(&policy, token, requested, &process_type, false)
}

/// Publica o handle de usuário do EPROCESS (callbacks de objeto incluídos).
fn open_process_handle(pointer: u64, access: u32, attributes: u32) -> Result<Result<u32, u32>, KernelError> {
    let object = Arc::new(UserProcess { pointer, process_id: eprocess(pointer).unique_process_id.get() });
    match state::alloc_user_handle(object, access, attributes & OBJ_INHERIT) {
        Ok(handle) => Ok(Ok(handle)),
        Err(error) if error.status != 0 => Ok(Err(error.status)),
        Err(error) => Err(error),
    }
}

/// NtOpenProcess(out, access, attributes, clientId).
fn nt_open_process(out: u64, access: u64, attributes: u64, client_id: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) {
        return Ok(AV);
    }
    if attributes & 3 != 0 {
        return Ok(MISALIGNED);
    }
    // O NT só exige alinhamento 4: leituras sondadas pelos offsets do tipo,
    // sem uma referência ao OBJECT_ATTRIBUTES (alinhamento 8).
    let name_offset = offset_of!(ObjectAttributes, object_name) as u64;
    let attributes_offset = offset_of!(ObjectAttributes, attributes) as u64;
    if !state::probe_user_read(attributes, attributes_offset + 4) {
        return Ok(AV);
    }
    let (named, object_attributes) = match guest::try_read::<u64>(attributes + name_offset).and_then(|name| Ok((name != 0, guest::try_read::<u32>(attributes + attributes_offset)? & USER_ATTRIBUTES))) {
        Ok(read) => read,
        Err(error) => return Ok(error.status),
    };
    let mut ids = None;
    if client_id != 0 {
        if client_id & 3 != 0 {
            return Ok(MISALIGNED);
        }
        if !state::probe_user_read(client_id, ClientId::SIZE) {
            return Ok(AV);
        }
        let process_offset = offset_of!(ClientId, unique_process) as u64;
        let thread_offset = offset_of!(ClientId, unique_thread) as u64;
        match guest::try_read::<u64>(client_id + process_offset).and_then(|process_id| Ok((process_id, guest::try_read::<u64>(client_id + thread_offset)?))) {
            Ok(read) => ids = Some(read),
            Err(error) => return Ok(error.status),
        }
    }
    let Some((process_id, thread_id)) = ids.filter(|_| !named) else { return Ok(PARAMETER_MIX) };
    let target = if thread_id != 0 {
        let thread = process::reference_thread_by_id(thread_id);
        if thread == 0 {
            return Ok(INVALID_CID);
        }
        let owner = kthread(thread).process.get();
        process::dereference_thread(thread)?;
        if process_id != 0 && eprocess(owner).unique_process_id.get() != process_id {
            return Ok(INVALID_CID);
        }
        owner
    } else {
        match process::list_active_processes().into_iter().find(|entry| entry.pid == process_id) {
            Some(entry) => entry.address,
            None => return Ok(INVALID_CID),
        }
    };
    if object_attributes & OBJ_EXCLUSIVE != 0 {
        return Ok(INVALID);
    }
    let granted = match process_access(target, access as u32) {
        Ok(granted) => granted,
        Err(status) => return Ok(status),
    };
    match open_process_handle(target, granted, object_attributes)? {
        // PHANDLE de saída (sondado acima).
        Ok(handle) => Ok(guest::try_write::<u64>(out, handle as u64).map_or(AV, |()| 0)),
        Err(status) => Ok(status),
    }
}

/// NtGetNextProcess(process, access, attributes, flags, out*).
fn nt_get_next_process(handle: u64, access: u64, attributes: u64, flags: u64, rsp: u64) -> Result<u32, KernelError> {
    let attributes = attributes as u32 & USER_ATTRIBUTES;
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(AV);
    }
    let out = state::stack_arg(rsp, 5);
    if !state::probe_user_write(out, 8) || guest::try_write::<u64>(out, 0).is_err() {
        return Ok(AV);
    }
    let flags = flags as u32;
    if flags & !1 != 0 {
        return Ok(INVALID);
    }
    let previous = if handle == 0 {
        None
    } else {
        match process_pointer(handle, 0) {
            Ok(pointer) => Some(pointer),
            Err(status) => return Ok(status),
        }
    };
    let mut list: Vec<u64> = process::list_active_processes().into_iter().map(|entry| entry.address).collect();
    if flags & 1 != 0 {
        list.reverse();
    }
    let start = previous.map_or(0, |pointer| list.iter().position(|&address| address == pointer).map_or(list.len(), |index| index + 1));
    for &candidate in &list[start..] {
        if attributes & OBJ_EXCLUSIVE != 0 {
            return Ok(INVALID);
        }
        let granted = match process_access(candidate, access as u32) {
            Ok(granted) => granted,
            Err(DENIED) => continue,
            Err(status) => return Ok(status),
        };
        match open_process_handle(candidate, granted, attributes)? {
            Ok(opened) => return Ok(guest::try_write::<u64>(out, opened as u64).map_or(AV, |()| 0)),
            Err(DENIED) => continue,
            Err(status) => return Ok(status),
        }
    }
    Ok(NO_MORE_ENTRIES)
}

/// NtGetNextThread(process, thread, access, attributes, flags, out*).
fn nt_get_next_thread(process_handle: u64, thread_handle: u64, access: u64, attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    let attributes = attributes as u32 & USER_ATTRIBUTES;
    if !state::probe_syscall_stack(rsp, 16) {
        return Ok(AV);
    }
    let flags = state::stack_arg32(rsp, 5);
    let out = state::stack_arg(rsp, 6);
    if !state::probe_user_write(out, 8) || guest::try_write::<u64>(out, 0).is_err() {
        return Ok(AV);
    }
    if flags != 0 {
        return Ok(INVALID);
    }
    let target = match process_pointer(process_handle, PROCESS_QUERY_INFORMATION) {
        Ok(pointer) => pointer,
        Err(status) => return Ok(status),
    };
    let all = threads::all();
    let start = if thread_handle == 0 {
        0
    } else {
        let previous = match threads::resolve(thread_handle, 0) {
            Ok(thread) => thread,
            Err(status) => return Ok(status),
        };
        let pointer = previous.pointer();
        if pointer == 0 || kthread(pointer).process.get() != target {
            return Ok(INVALID);
        }
        all.iter().position(|candidate| Arc::ptr_eq(candidate, &previous)).map_or(all.len(), |index| index + 1)
    };
    let thread_type = object_types::thread_type();
    for candidate in &all[start..] {
        let pointer = candidate.pointer();
        if pointer == 0 || kthread(pointer).process.get() != target {
            continue;
        }
        if attributes & OBJ_EXCLUSIVE != 0 {
            return Ok(INVALID);
        }
        let granted = match object_access::check(&SecurityPolicy::default(), None, access as u32, &thread_type, true) {
            Ok(granted) => granted,
            Err(DENIED) => continue,
            Err(status) => return Ok(status),
        };
        match threads::thread_handle(candidate, granted, attributes & OBJ_INHERIT) {
            Ok(opened) => return Ok(guest::try_write::<u64>(out, opened).map_or(AV, |()| 0)),
            Err(error) if error.status == DENIED => continue,
            Err(error) if error.status != 0 => return Ok(error.status),
            Err(error) => return Err(error),
        }
    }
    Ok(NO_MORE_ENTRIES)
}
