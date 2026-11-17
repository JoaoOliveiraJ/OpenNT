//! NtNotifyChangeKey e NtNotifyChangeMultipleKeys chamados do modo usuário.
//!
//! Como o NtNotifyChangeMultipleKeys do ntoskrnl 19041 (rva 0x6dbf40; o
//! NtNotifyChangeKey é ele com Count 0):
//!   * Count acima de 1 é STATUS_INVALID_PARAMETER;
//!   * REG_NOTIFY_THREAD_AGNOSTIC exige Asynchronous, sem ApcRoutine e com
//!     Event (STATUS_INVALID_PARAMETER); sem ele, o IoStatusBlock e o Buffer
//!     são sondados para escrita e o IOSB recebe STATUS_PENDING com
//!     Information zero antes de qualquer outra coisa;
//!   * CompletionFilter fora de REG_LEGAL_CHANGE_FILTER é
//!     STATUS_INVALID_PARAMETER; a chave mestra é referenciada pelo handle
//!     com KEY_NOTIFY e a subordinada (Count 1) pelo nome, que precisa estar
//!     em outra hive (senão STATUS_INVALID_PARAMETER);
//!   * o Event de um pedido assíncrono é referenciado com
//!     EVENT_MODIFY_STATE e zerado; chave apagada: STATUS_KEY_DELETED;
//!   * o pedido entra no bloco de notificação do corpo do handle
//!     (`key/notify.rs`, o CmpNotifyChangeKey): o filtro e o WatchTree do
//!     primeiro pedido no handle valem para os seguintes, uma mudança que
//!     chegou sem pedido esperando completa o próximo na hora (o serviço
//!     devolve STATUS_SUCCESS) e, senão, o assíncrono devolve
//!     STATUS_PENDING. A subordinada espera num corpo próprio, aberto por
//!     pedido e solto quando ele completa;
//!   * na postagem, o CmpPostApc grava o IOSB no processo de quem pediu,
//!     sinaliza o Event e a rotina de APC de usuário recebe (ApcContext,
//!     IoStatusBlock, 0); o síncrono espera, alertável, e devolve o status
//!     do bloco (ou STATUS_USER_APC/STATUS_ALERTED, que desfazem o pedido);
//!   * fechar o último handle da chave completa os pedidos com
//!     STATUS_NOTIFY_CLEANUP; o fim da thread que fez um pedido assíncrono
//!     sem REG_NOTIFY_THREAD_AGNOSTIC também (CmNotifyRunDown: IOSB, Event,
//!     sem APC).
//!
//! O fim do processo desfaz os pedidos pendentes dele.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ntos::cm::hive_list;
use crate::ntos::cm::key::{notify as key_notify, objects as key_objects, services as key_services};
use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::inc::types::{Kevent, NtStruct};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::events::{self, EventObject};
use crate::ntos::ps::user::registry::parse_user_object_attributes;
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::user::{state, user_apc};
use crate::ntos::ps::user_probe::probe_user_write;
use crate::ntos::ps::{process, process_context};
use crate::rtl::{KernelError, SpinLock};

const REG_LEGAL_CHANGE_FILTER: u32 = 0x1000_000F;
const REG_NOTIFY_THREAD_AGNOSTIC: u32 = 0x1000_0000;
const KEY_NOTIFY: u32 = 0x10;
const EVENT_MODIFY_STATE: u32 = 0x2;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_NO_MEMORY: u32 = 0xC000_009A;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_PENDING: u32 = 0x103;
const STATUS_USER_APC: u32 = 0xC0;
const STATUS_ALERTED: u32 = 0x101;

/// Os argumentos do NtNotifyChangeMultipleKeys.
pub struct Request {
    pub master_key: u64,
    pub count: u32,
    pub subordinate_objects: u64,
    pub event: u64,
    pub apc_routine: u64,
    pub apc_context: u64,
    pub io_status: u64,
    pub filter: u32,
    pub watch_tree: bool,
    pub buffer: u64,
    pub buffer_size: u32,
    pub asynchronous: bool,
}

/// O tipo do bloco de postagem (CmpAllocatePostBlock).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PostKind {
    Synchronous,
    AsynchronousUser,
    ThreadAgnostic,
}

/// Um pedido de modo usuário.
struct UserPost {
    kind: PostKind,
    process: u64,
    process_id: u64,
    io_status: u64,
    event: Option<Arc<EventObject>>,
    /// KEVENT interno da espera síncrona.
    wait_event: u64,
    apc_routine: u64,
    apc_context: u64,
    thread: Option<Arc<UserThread>>,
    /// O corpo temporário da chave subordinada (Count 1), retido até o fim
    /// do pedido.
    subordinate: u64,
    status: AtomicU64,
    finished: AtomicBool,
}

/// Os pedidos assíncronos armados (o fim do processo os desfaz): o
/// identificador no bloco e o pedido.
static PENDING: SpinLock<Vec<(u64, Arc<UserPost>)>> = SpinLock::new(Vec::new());

impl UserPost {
    /// Solta o que o pedido retém (Event, thread e a subordinada), uma vez.
    fn finish(&self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(event) = &self.event {
            events::release(event);
        }
        if let Some(thread) = &self.thread {
            threads::release_thread(thread);
        }
        if self.subordinate != 0 {
            let _ = key_objects::release(self.subordinate);
        }
    }

    fn forget(&self) {
        PENDING.lock().retain(|(_, candidate)| !core::ptr::eq(Arc::as_ptr(candidate), self));
    }

    /// O IOSB pertence ao processo de quem pediu.
    fn write_io_status(&self, status: u32) {
        if self.io_status != 0 {
            let _ = process_context::with_process(self.process, || state::set_user_iosb(self.io_status, status, 0));
        }
    }
}

impl key_notify::Post for UserPost {
    /// CmpPostNotify + CmpPostApc.
    fn deliver(&self, status: u32) {
        self.status.store(status as u64, Ordering::Release);
        if self.kind == PostKind::Synchronous {
            dispatcher::set_event(self.wait_event);
            self.finish();
            return;
        }
        self.forget();
        self.write_io_status(status);
        if let Some(event) = &self.event {
            dispatcher::set_event(event.pointer);
        }
        if self.apc_routine != 0 {
            if let Some(thread) = &self.thread {
                let _ = user_apc::queue(thread, self.apc_routine, self.apc_context, self.io_status, 0, false, false);
            }
        }
        self.finish();
    }

    /// CmNotifyRunDown: IOSB = STATUS_NOTIFY_CLEANUP, Event sinalizado e a
    /// APC descartada.
    fn run_down(&self) {
        self.status.store(key_notify::STATUS_NOTIFY_CLEANUP as u64, Ordering::Release);
        self.forget();
        self.write_io_status(key_notify::STATUS_NOTIFY_CLEANUP);
        if let Some(event) = &self.event {
            dispatcher::set_event(event.pointer);
        }
        self.finish();
    }
}

/// A chave subordinada (Count 1), aberta pelo nome: o nó e o caminho.
fn subordinate_key(attributes: u64, master: NodeId) -> Result<(NodeId, alloc::string::String), u32> {
    let parsed = parse_user_object_attributes(attributes).ok_or(STATUS_INVALID_PARAMETER)?;
    let path = parsed.path;
    let node = registry::node_by_path(&path).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    // As duas chaves na mesma hive: STATUS_INVALID_PARAMETER.
    if hive_list::same_hive(&[node, master]) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok((node, path))
}

/// NtNotifyChangeMultipleKeys com PreviousMode de usuário.
pub fn notify_change_multiple_keys(request: &Request) -> Result<u32, KernelError> {
    if request.count > 1 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let kind = if request.filter & REG_NOTIFY_THREAD_AGNOSTIC != 0 {
        if !request.asynchronous || request.apc_routine != 0 || request.event == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        PostKind::ThreadAgnostic
    } else {
        if !probe_user_write(request.io_status, 16) || (request.buffer_size != 0 && !probe_user_write(request.buffer, request.buffer_size as u64)) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if state::set_user_iosb(request.io_status, STATUS_PENDING, 0).is_err() {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if request.asynchronous { PostKind::AsynchronousUser } else { PostKind::Synchronous }
    };
    if request.filter & !REG_LEGAL_CHANGE_FILTER != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let (body, node, _) = match key_services::reference_key_body(request.master_key, true, KEY_NOTIFY) {
        Ok(referenced) => referenced,
        Err(status) => return Ok(status),
    };
    let mut targets = alloc::vec![(body, node)];
    let mut subordinate = 0;
    if request.count == 1 {
        let (sub_node, sub_path) = match subordinate_key(request.subordinate_objects, node) {
            Ok(found) => found,
            Err(status) => return Ok(status),
        };
        // O CmObReferenceObjectByName da subordinada: um corpo próprio.
        let Some(sub_body) = key_objects::temporary(sub_node, &sub_path) else { return Ok(STATUS_NO_MEMORY) };
        subordinate = sub_body;
        targets.push((sub_body, sub_node));
    }
    let release_subordinate = || {
        if subordinate != 0 {
            let _ = key_objects::release(subordinate);
        }
    };
    let event = if kind != PostKind::Synchronous && request.event != 0 {
        match events::reference(request.event, EVENT_MODIFY_STATE) {
            Ok(event) => {
                dispatcher::reset_event(event.pointer);
                Some(event)
            }
            Err(status) => {
                release_subordinate();
                return Ok(status);
            }
        }
    } else {
        None
    };
    let wait_event = if kind == PostKind::Synchronous {
        let pointer = guest::alloc_bytes(Kevent::SIZE);
        if pointer == 0 {
            release_subordinate();
            return Ok(STATUS_NO_MEMORY);
        }
        dispatcher::initialize_event(pointer, 0, false);
        pointer
    } else {
        0
    };
    let thread = if kind == PostKind::AsynchronousUser && request.apc_routine != 0 { threads::current() } else { None };
    if let Some(thread) = &thread {
        threads::retain_thread(thread);
    }
    let post = Arc::new(UserPost {
        kind,
        process: process::get_current_process(),
        process_id: process::get_current_process_id(),
        io_status: if kind == PostKind::ThreadAgnostic { 0 } else { request.io_status },
        event,
        wait_event,
        apc_routine: request.apc_routine,
        apc_context: request.apc_context,
        thread,
        subordinate,
        status: AtomicU64::new(STATUS_PENDING as u64),
        finished: AtomicBool::new(false),
    });
    // Só o pedido assíncrono de modo usuário entra na PostBlockList da
    // thread (o CmNotifyRunDown dela).
    let owner = if kind == PostKind::AsynchronousUser { process::get_current_thread() } else { 0 };
    if kind != PostKind::Synchronous {
        // Na lista antes de armar: uma postagem imediata já o encontra.
        let mut pending = PENDING.lock();
        pending.push((0, post.clone()));
    }
    let (id, status) = key_notify::arm(&targets, request.filter, request.watch_tree, post.clone(), owner);
    if kind != PostKind::Synchronous {
        if let Some(entry) = PENDING.lock().iter_mut().find(|(_, candidate)| Arc::ptr_eq(candidate, &post)) {
            entry.0 = id;
        }
        return Ok(status);
    }
    let waited = threads::wait_objects(Vec::new(), alloc::vec![wait_event], 1, 0, true);
    let status = if waited == STATUS_USER_APC || waited == STATUS_ALERTED {
        // A espera interrompida desfaz o pedido sem postá-lo.
        if key_notify::cancel(id) {
            post.finish();
        }
        waited
    } else {
        post.status.load(Ordering::Acquire) as u32
    };
    if waited != STATUS_USER_APC && waited != STATUS_ALERTED {
        let _ = state::set_user_iosb(request.io_status, status, 0);
    }
    guest::free_bytes(wait_event);
    Ok(status)
}

/// Fim do processo: os pedidos pendentes dele saem sem postagem.
pub fn release_process(process_pointer: u64) {
    let pending: Vec<(u64, Arc<UserPost>)> = {
        let mut pending = PENDING.lock();
        let (theirs, others): (Vec<_>, Vec<_>) = pending.drain(..).partition(|(_, post)| post.process == process_pointer);
        *pending = others;
        theirs
    };
    for (id, post) in pending {
        if key_notify::cancel(id) {
            post.finish();
        }
    }
}

/// Pedidos assíncronos pendentes de um processo (autoteste).
pub fn pending_count(process_id: u64) -> usize {
    PENDING.lock().iter().filter(|(_, post)| post.process_id == process_id).count()
}

/// Registra a limpeza no fim do processo e o CmNotifyRunDown no fim de
/// cada thread.
pub fn init() {
    process::register_process_exit_routine(release_process);
    process::register_thread_exit_routine(key_notify::run_down_thread);
}
