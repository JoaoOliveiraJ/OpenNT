//! Handles de token.
//!
//! Publica handles de token no Object Manager (kernel) ou na tabela de
//! handles do processo (usuário) e NtOpenThreadToken(Ex).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::ntos::se::model::Ace;
use crate::ntos::se::token::{thread as thread_tokens, access as token_access, tokens};
use crate::ntos::ob::close::{self, KernelHandleOwner};
use crate::ntos::ob::object_manager::{self, ObjectData, ObjectHooks, OpenOptions};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Ethread, NtStruct};

/// OBJ_KERNEL_HANDLE canônico -> identificador interno do Object Manager.
static KERNEL_HANDLES: SpinLock<BTreeMap<u64, u32>> = SpinLock::new(BTreeMap::new());
static OWNER_REGISTERED: SpinLock<bool> = SpinLock::new(false);

/// O caminho de kernel retém uma referência por handle aberto.
struct TokenHandle {
    token: u64,
}

impl ObjectHooks for TokenHandle {
    fn on_handle_open(&self) -> Result<(), KernelError> {
        tokens::retain(self.token)?;
        tokens::account_handle(self.token, 1)
    }
    fn on_handle_close(&self) {
        let _ = tokens::account_handle(self.token, -1);
        let _ = tokens::release(self.token);
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Handle de usuário: o objeto compartilhado pelos handles retém o token e
/// devolve a referência de posse ao encerrar.
pub struct UserToken {
    pub token: u64,
}

impl crate::ntos::ps::user::state::UserObject for UserToken {
    fn kind(&self) -> &'static str {
        "token"
    }
    fn native_body(&self) -> Option<crate::ntos::ps::user::state::NativeBody> {
        let token = self.token;
        Some(crate::ntos::ps::user::state::NativeBody {
            pointer: token,
            type_name: alloc::string::String::from("Token"),
            record: token,
            // Referências por ponteiro independem dos handles abertos.
            reference: Arc::new(move || {
                let _ = tokens::retain(token);
            }),
            dereference: Arc::new(move || {
                let _ = tokens::release(token);
            }),
        })
    }
    /// Cada duplicação acrescenta um handle ao inventário do tipo Token.
    fn on_each_handle_open(&self) -> Result<bool, KernelError> {
        tokens::account_handle(self.token, 1)?;
        Ok(true)
    }
    fn on_each_handle_close(&self) {
        let _ = tokens::account_handle(self.token, -1);
    }
    fn release(&self) {
        let _ = tokens::release(self.token);
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Dono de handles de kernel do NtClose (depois de `ex/callbacks`).
fn register_owner() {
    let mut registered = OWNER_REGISTERED.lock();
    if !*registered {
        *registered = true;
        close::register_kernel_handle_owner(KernelHandleOwner {
            attributes: |handle| resolve_native(handle).map(|data| data.attributes),
            close: |handle| close_native(handle).unwrap_or(close::STATUS_INVALID_HANDLE),
        });
    }
}

/// Resolve -2 (thread corrente), um handle de thread da tabela de usuário
/// do processo corrente ou um handle de thread real do System.
fn resolve_thread(handle: u64, from_user_mode: bool) -> Result<u64, u32> {
    if handle as i64 == -2 {
        let pointer = process::get_current_thread();
        return if process::is_thread(pointer) { Ok(pointer) } else { Err(0xC000_0008) };
    }
    if handle > 0x7FFF_FFFF {
        return Err(0xC000_0008);
    }
    // A tabela de usuário atende o modo usuário e os processos comuns.
    if from_user_mode || process::get_current_process() != process::get_system_process() {
        return resolve_user_thread(handle, from_user_mode);
    }
    let Some(node) = object_manager::get_object(handle as u32).and_then(object_manager::node) else {
        return Err(0xC000_0008);
    };
    if node.type_name != "Thread" {
        return Err(0xC000_0024);
    }
    let data = node.data.unwrap_or_default();
    let pointer = data.native_pointer;
    if !process::is_thread(pointer) {
        return Err(0xC000_0008);
    }
    // A rotina 19041 pede THREAD_QUERY_LIMITED_INFORMATION (0x800);
    // QUERY_INFORMATION também satisfaz.
    if from_user_mode && data.access.unwrap_or(0) & 0x840 == 0 {
        return Err(0xC000_0022);
    }
    Ok(pointer)
}

/// Um handle de thread da tabela de usuário do processo corrente, como o
/// ObReferenceObjectByHandle do NtOpenThreadTokenEx do 19041 com
/// THREAD_QUERY_LIMITED_INFORMATION e PsThreadType: outro tipo de objeto dá
/// STATUS_OBJECT_TYPE_MISMATCH; em UserMode, um handle sem
/// THREAD_QUERY_LIMITED_INFORMATION nem THREAD_QUERY_INFORMATION dá
/// STATUS_ACCESS_DENIED. É o caminho do CsrThread->ThreadHandle que o csrss
/// passa (sxssrv BaseSrvSxsCreateActivationContextFromStructEx 0x35c1,
/// basesrv BaseSrvGetUserToken 0xae5c), que antes dava
/// STATUS_INVALID_HANDLE em toda criação de processo.
fn resolve_user_thread(handle: u64, from_user_mode: bool) -> Result<u64, u32> {
    use crate::ntos::ps::user::{state as user_state, threads as user_threads};
    let Some(entry) = user_state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "thread" {
        return Err(0xC000_0024);
    }
    if from_user_mode && entry.access() & 0x840 == 0 {
        user_state::note_denial("handle", "thread", 0x800, entry.access());
        return Err(0xC000_0022);
    }
    let pointer = user_threads::resolve(handle, 0)?.pointer();
    if !process::is_thread(pointer) {
        return Err(0xC000_0008);
    }
    Ok(pointer)
}

/// Publica um handle de kernel ligado à vida do token.
pub fn create(token: u64, access: u32, attributes: u32, from_user_mode: bool) -> Result<u64, KernelError> {
    // Um token exclusivo só ganha handles no processo dono.
    let exclusive = tokens::with(token, |record| record.exclusive_process).unwrap_or(0);
    if exclusive != 0 && exclusive != process::get_current_process() {
        return Err(KernelError::with_status("Token belongs to another exclusive process", 0xC000_0022));
    }
    if from_user_mode {
        tokens::retain(token)?;
        return match crate::ntos::ps::user::state::alloc_user_handle(Arc::new(UserToken { token }), access, attributes & 2) {
            Ok(handle) => Ok(handle as u64),
            Err(error) => {
                let _ = tokens::release(token);
                Err(error)
            }
        };
    }
    register_owner();
    let owner = if attributes & 0x200 != 0 { process::get_system_process() } else { process::get_current_process() };
    let data = ObjectData { native_pointer: token, access: Some(access), attributes, owner_process: Some(owner), hooks: Some(Arc::new(TokenHandle { token })), ..ObjectData::default() };
    let node = object_manager::new_node("", "Token", Some(data));
    let kernel = attributes & 0x200 != 0;
    let options = OpenOptions {
        access: Some(access),
        attributes: Some(attributes),
        owner_process: Some(owner),
        on_open: Some(Arc::new(move |identifier| {
            if kernel {
                KERNEL_HANDLES.lock().insert(0xFFFF_FFFF_8000_0000 | identifier as u64, identifier);
            }
        })),
        on_close: Some(Arc::new(|identifier| {
            KERNEL_HANDLES.lock().remove(&(0xFFFF_FFFF_8000_0000 | identifier as u64));
        })),
        ..OpenOptions::default()
    };
    let identifier = object_manager::open_object(node, Some(options))?;
    Ok(if kernel { 0xFFFF_FFFF_8000_0000 | identifier as u64 } else { identifier as u64 })
}

/// Um handle do token, já referenciado por quem chama, na tabela do
/// processo `target` (o ObDuplicateObject de um objeto capturado: o
/// AlpcpExposeHandleAttribute e a classe 3 do NtAlpcQueryInformationMessage
/// com o token de uma mensagem): num processo comum, um handle da tabela de
/// usuário, o mesmo que o NtOpenProcessToken ou o NtDuplicateObject dele
/// publicam, anexado ao destino; no System, um handle de kernel. Só OBJ_INHERIT
/// passa de `attributes`. Devolve o valor do handle.
pub fn insert_for(token: u64, access: u32, attributes: u32, target: u64) -> Result<u64, KernelError> {
    let exclusive = tokens::with(token, |record| record.exclusive_process).unwrap_or(0);
    if exclusive != 0 && exclusive != target {
        return Err(KernelError::with_status("Token belongs to another exclusive process", 0xC000_0022));
    }
    if target == process::get_system_process() {
        return create(token, access, (attributes & 2) | 0x200, false);
    }
    let Some(table) = crate::ntos::ps::user::process_state::get(target) else { return Err(KernelError::with_status("process handle table is closing", 0xC000_010A)) };
    tokens::retain(token)?;
    let insert = || crate::ntos::ps::user::state::alloc_user_handle_in(&table, Arc::new(UserToken { token }), access, attributes & 2, None);
    let inserted = if target == process::get_current_process() { insert() } else { crate::ntos::ps::process_context::with_process(target, insert).and_then(|inserted| inserted) };
    inserted.map(|handle| handle as u64).inspect_err(|_| {
        let _ = tokens::release(token);
    })
}

/// Token do handle pela tabela de kernel ou pela tabela do System.
pub fn resolve_native(handle: u64) -> Option<ObjectData> {
    let identifier = KERNEL_HANDLES.lock().get(&handle).copied();
    if let Some(identifier) = identifier {
        return object_manager::get_object(identifier).and_then(object_manager::node).and_then(|node| node.data);
    }
    if handle > 0x7FFF_FFFF || process::get_current_process() != process::get_system_process() {
        return None;
    }
    object_manager::get_object(handle as u32).and_then(object_manager::node).filter(|node| node.type_name == "Token").and_then(|node| node.data)
}

/// Fecha handles de kernel reconhecidos; `None` = outra tabela.
pub fn close_native(handle: u64) -> Option<u32> {
    let identifier = KERNEL_HANDLES.lock().get(&handle).copied()?;
    Some(if matches!(object_manager::close(identifier), Ok(true)) { 0 } else { 0xC000_0008 })
}

/// ZwOpenThreadTokenEx: a entrada de kernel; fora de PASSIVE_LEVEL o
/// sistema para com IRQL_NOT_LESS_OR_EQUAL (0xC4, 0x2001F).
pub fn open_thread_from_kernel(handle: u64, desired_access: u32, use_primary_identity: bool, attributes: u32, output: u64) -> Result<u32, KernelError> {
    if crate::ntos::ke::irql::get_irql() != 0 {
        crate::ntos::ke::bugcheck::raise_bug_check(0xC4, 0x2_001F, 0, 0, 0);
    }
    open_thread(handle, desired_access, use_primary_identity, attributes, output, false)
}

/// NtOpenThreadTokenEx como o ntoskrnl 19041 (rva 0x653590):
/// `use_primary_identity` (OpenAsSelf) tira a impersonação do sujeito.
/// Sem CopyOnOpen, o token da thread abre pelo ObOpenObjectByPointer, com o
/// SeAccessCheck do sujeito (um cliente abaixo de SecurityImpersonation dá
/// STATUS_BAD_IMPERSONATION_LEVEL). Com CopyOnOpen (a impersonação do
/// ALPC/LPC), o token vira uma cópia privada (SepDuplicateToken) cujo
/// handle sai do ObInsertObjectEx sem SeAccessCheck, e a thread passa a
/// impersonar a cópia (PsSwapImpersonationToken): um servidor que
/// impersona um cliente em SecurityIdentification abre o próprio token
/// assim, como o ept_insert_ex do RpcEpMap.dll.
pub fn open_thread(handle: u64, desired_access: u32, use_primary_identity: bool, attributes: u32, output: u64, from_user_mode: bool) -> Result<u32, KernelError> {
    if from_user_mode && !crate::ntos::ps::user_probe::probe_user_write(output, 8) {
        return Ok(0xC000_0005);
    }
    let target = match resolve_thread(handle, from_user_mode) {
        Ok(target) => target,
        Err(status) => return Ok(status),
    };
    let Some(state) = thread_tokens::get(target) else { return Ok(0xC000_007C) };
    if state.level == 0 {
        return Ok(0xC000_00A6);
    }
    if !from_user_mode && process::get_current_process() != process::get_system_process() && attributes & 0x200 == 0 {
        return Ok(0xC000_000D);
    }
    let attributes = attributes & if from_user_mode { 0x1DF2 } else { 0x11FF2 };
    let subject_impersonation = if use_primary_identity { None } else { thread_tokens::get(process::get_current_thread()) };
    let requires_check = from_user_mode || attributes & 0x400 != 0;
    if !state.copy_on_open && requires_check && subject_impersonation.is_some_and(|impersonation| impersonation.level < 2) {
        return Ok(0xC000_00A5);
    }
    let mut token = state.token;
    let mut private_token = None;
    let result = (|| -> Result<u32, KernelError> {
        let rights = if state.copy_on_open {
            let subject = match subject_impersonation {
                Some(impersonation) => Some((impersonation.token, Some(impersonation.level))),
                None => process::get_primary_token(process::get_current_process()).map(|primary| (primary, None)),
            };
            match token_access::creator_access(desired_access, subject, !from_user_mode) {
                Ok(rights) => rights,
                Err(status) => return Ok(status),
            }
        } else {
            match token_access::check(token, thread_tokens::effective(process::get_current_thread(), use_primary_identity), desired_access, !requires_check) {
                Ok(rights) => rights,
                Err(status) => return Ok(status),
            }
        };
        if state.copy_on_open {
            let duplicate = tokens::duplicate(token, state.level, state.effective_only, 2)?;
            private_token = Some(duplicate);
            token = duplicate;
            // O token privado também precisa admitir a identidade primária do servidor.
            // SAFETY: thread alvo resolvida e referenciada acima (ETHREAD).
            let owner_process = unsafe { Ethread::at(target) }.tcb.process.get();
            let Some(primary) = process::get_primary_token(owner_process).and_then(tokens::get) else {
                return Err(KernelError::new("impersonating thread has no owning process token"));
            };
            tokens::update(duplicate, |token| {
                if let Some(dacl) = token.security.dacl.as_mut() {
                    dacl.push(Ace::allow(primary.user.clone(), 0x1F_01FF));
                }
            });
        }
        let new_handle = create(token, rights, attributes, from_user_mode)?;
        let finish = (|| -> Result<(), KernelError> {
            if let Some(private) = private_token {
                thread_tokens::assign(target, Some(private), state.level, false, state.effective_only)?;
            }
            guest::try_write::<u64>(output, new_handle)
        })();
        if let Err(error) = finish {
            if close_native(new_handle).is_none() {
                let _ = object_manager::close(new_handle as u32);
            }
            return Err(error);
        }
        Ok(0)
    })();
    if let Some(private) = private_token {
        tokens::release(private)?;
    }
    match result {
        Err(error) if error.status != 0 => Ok(error.status),
        other => other,
    }
}
