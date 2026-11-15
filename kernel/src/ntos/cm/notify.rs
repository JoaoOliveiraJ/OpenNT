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
//!   * o pedido assíncrono devolve STATUS_PENDING; na mudança, o
//!     CmpPostApc grava o IOSB no processo de quem pediu, sinaliza o Event e
//!     a rotina de APC de usuário recebe (ApcContext, IoStatusBlock, 0); o
//!     síncrono espera, alertável, e devolve o status do bloco (ou
//!     STATUS_USER_APC/STATUS_ALERTED, que desfazem o pedido).
//!
//! A mudança completa com STATUS_NOTIFY_ENUM_DIR, como na versão de modo
//! kernel (`key/notify.rs`), pelos observadores de caminho do
//! `cm::registry`; sem WatchTree também conta a criação ou remoção de uma
//! subchave direta. Diferenças honestas, as mesmas do modo kernel: o
//! CompletionFilter válido vale como "qualquer mudança" e fechar o handle
//! da chave não completa o pedido com STATUS_NOTIFY_CLEANUP. O fim do
//! processo desfaz os pedidos pendentes dele.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ntos::cm::{hive_list, registry};
use crate::ntos::cm::key::services as key_services;
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
const STATUS_NOTIFY_ENUM_DIR: u32 = 0x10C;

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

/// Um pedido pendente: a postagem e as inscrições de caminho dele.
struct Post {
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
    fired: AtomicBool,
    status: AtomicU64,
    subscriptions: SpinLock<Vec<u64>>,
}

/// Os pedidos assíncronos pendentes (o fim do processo os desfaz).
static PENDING: SpinLock<Vec<Arc<Post>>> = SpinLock::new(Vec::new());

fn components(path: &str) -> Vec<String> {
    registry::split_path(path).into_iter().map(|component| component.to_lowercase()).collect()
}

/// A mudança em `changed` interessa a quem observa `watched`?
fn concerns(watched: &[String], changed: &str, watch_tree: bool) -> bool {
    let changed = components(changed);
    if changed.len() < watched.len() || changed[..watched.len()] != *watched {
        return false;
    }
    watch_tree || changed.len() <= watched.len() + 1
}

fn unsubscribe(post: &Post) {
    for subscription in post.subscriptions.lock().drain(..) {
        registry::unwatch(subscription);
    }
}

/// Solta o que o pedido retém (Event e thread).
fn release(post: &Post) {
    if let Some(event) = &post.event {
        events::release(event);
    }
    if let Some(thread) = &post.thread {
        threads::release_thread(thread);
    }
}

/// CmpPostNotify + CmpPostApc de um bloco disparado com `status`.
fn post_notify(post: &Arc<Post>, status: u32) {
    if post.fired.swap(true, Ordering::AcqRel) {
        return;
    }
    unsubscribe(post);
    post.status.store(status as u64, Ordering::Release);
    if post.kind == PostKind::Synchronous {
        dispatcher::set_event(post.wait_event);
        return;
    }
    PENDING.lock().retain(|candidate| !Arc::ptr_eq(candidate, post));
    // O IOSB pertence ao processo de quem pediu.
    if post.io_status != 0 {
        let _ = process_context::with_process(post.process, || state::set_user_iosb(post.io_status, status, 0));
    }
    if let Some(event) = &post.event {
        dispatcher::set_event(event.pointer);
    }
    if post.apc_routine != 0 {
        if let Some(thread) = &post.thread {
            let _ = user_apc::queue(thread, post.apc_routine, post.apc_context, post.io_status, 0, false, false);
        }
    }
    release(post);
}

/// O caminho da chave subordinada (Count 1), aberta pelo nome.
fn subordinate_path(attributes: u64, master: &str) -> Result<String, u32> {
    let parsed = parse_user_object_attributes(attributes).ok_or(STATUS_INVALID_PARAMETER)?;
    let path = parsed.path;
    let (Some(node), Some(master_node)) = (registry::node_by_path(&path), registry::node_by_path(master)) else { return Err(STATUS_OBJECT_NAME_NOT_FOUND) };
    // As duas chaves na mesma hive: STATUS_INVALID_PARAMETER.
    if hive_list::same_hive(&[node, master_node]) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(path)
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
    let path = match key_services::reference_key(request.master_key, true, KEY_NOTIFY) {
        Ok((_, path)) => path,
        Err(status) => return Ok(status),
    };
    let mut watched = alloc::vec![path.clone()];
    if request.count == 1 {
        match subordinate_path(request.subordinate_objects, &path) {
            Ok(subordinate) => watched.push(subordinate),
            Err(status) => return Ok(status),
        }
    }
    let event = if kind != PostKind::Synchronous && request.event != 0 {
        match events::reference(request.event, EVENT_MODIFY_STATE) {
            Ok(event) => {
                dispatcher::reset_event(event.pointer);
                Some(event)
            }
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let wait_event = if kind == PostKind::Synchronous {
        let pointer = guest::alloc_bytes(Kevent::SIZE);
        if pointer == 0 {
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
    let post = Arc::new(Post {
        kind,
        process: process::get_current_process(),
        process_id: process::get_current_process_id(),
        io_status: if kind == PostKind::ThreadAgnostic { 0 } else { request.io_status },
        event,
        wait_event,
        apc_routine: request.apc_routine,
        apc_context: request.apc_context,
        thread,
        fired: AtomicBool::new(false),
        status: AtomicU64::new(STATUS_PENDING as u64),
        subscriptions: SpinLock::new(Vec::new()),
    });
    if kind != PostKind::Synchronous {
        PENDING.lock().push(post.clone());
    }
    for watched_path in &watched {
        let target = components(watched_path);
        let watch_tree = request.watch_tree;
        let observed = post.clone();
        let observer: registry::Observer = Arc::new(move |changed: &str| {
            if concerns(&target, changed, watch_tree) {
                post_notify(&observed, STATUS_NOTIFY_ENUM_DIR);
            }
        });
        let subscription = registry::watch(watched_path, observer);
        post.subscriptions.lock().push(subscription);
        // Disparado durante a inscrição: a inscrição tardia também sai.
        if post.fired.load(Ordering::Acquire) {
            unsubscribe(&post);
        }
    }
    if kind != PostKind::Synchronous {
        return Ok(STATUS_PENDING);
    }
    let waited = threads::wait_objects(Vec::new(), alloc::vec![wait_event], 1, 0, true);
    let status = if waited == STATUS_USER_APC || waited == STATUS_ALERTED {
        // A espera interrompida desfaz o pedido sem postá-lo.
        if !post.fired.swap(true, Ordering::AcqRel) {
            unsubscribe(&post);
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
    let pending: Vec<Arc<Post>> = {
        let mut pending = PENDING.lock();
        let (theirs, others): (Vec<_>, Vec<_>) = pending.drain(..).partition(|post| post.process == process_pointer);
        *pending = others;
        theirs
    };
    for post in pending {
        if !post.fired.swap(true, Ordering::AcqRel) {
            unsubscribe(&post);
            release(&post);
        }
    }
}

/// Pedidos assíncronos pendentes de um processo (autoteste).
pub fn pending_count(process_id: u64) -> usize {
    PENDING.lock().iter().filter(|post| post.process_id == process_id).count()
}

/// Registra a limpeza no fim do processo.
pub fn init() {
    process::register_process_exit_routine(release_process);
}
