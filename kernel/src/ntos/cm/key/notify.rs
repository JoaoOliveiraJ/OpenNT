//! Notificação de mudança de chave do registro: os blocos de notificação
//! por corpo de chave (CM_NOTIFY_BLOCK), o relato das mudanças
//! (CmpReportNotify), a postagem (CmpPostNotify), a limpeza no fechamento
//! (CmpFlushNotify) e no fim da thread (CmNotifyRunDown), e o
//! ZwNotifyChangeKey de modo kernel. O NtNotifyChangeMultipleKeys de modo
//! usuário (`cm/notify.rs`) arma os mesmos blocos.
//!
//! Como no ntoskrnl 19041:
//!   - cada corpo de chave tem no máximo um bloco (CM_KEY_BODY.NotifyBlock),
//!     criado no primeiro pedido pelo handle (CmpNotifyChangeKey, rva
//!     0x6dc7b0) com CompletionFilter & 0x3FFFFFFF e o WatchTree desse
//!     pedido, que valem para os pedidos seguintes no mesmo handle;
//!   - uma mudança relatada (CmpReportNotifyHelper, rva 0x5ed390) só posta o
//!     bloco cujo filtro tem algum bit da mudança; sem WatchTree a chave
//!     mudada precisa ser a do bloco, com WatchTree ela ou um descendente.
//!     Criar ou excluir uma subchave é REG_NOTIFY_CHANGE_NAME no pai
//!     (CmpCreateChild, CmDeleteKey); gravar ou apagar um valor,
//!     REG_NOTIFY_CHANGE_LAST_SET na chave (CmSetValueKey,
//!     CmDeleteValueKey); trocar o descritor, ATTRIBUTES | SECURITY
//!     (CmpSetKeySecurity);
//!   - a postagem (CmpPostNotify, rva 0x5ed0c0) completa todos os pedidos
//!     do bloco com STATUS_NOTIFY_ENUM_DIR; sem pedido esperando, o bloco
//!     guarda a mudança (NotifyPending) e o próximo pedido no handle
//!     completa na hora, com o serviço devolvendo STATUS_SUCCESS;
//!   - o fechamento do último handle do corpo (CmpCloseKeyObject →
//!     CmpFlushNotify, rva 0x6e3b9c) e a exclusão da chave
//!     (CmpFlushNotifiesOnKeyBodyList) completam os pedidos com
//!     STATUS_NOTIFY_CLEANUP e liberam o bloco;
//!   - o fim da thread (CmNotifyRunDown, rva 0x6c5510) tira os pedidos
//!     assíncronos de modo usuário que ela fez sem
//!     REG_NOTIFY_THREAD_AGNOSTIC: IOSB = STATUS_NOTIFY_CLEANUP, Event
//!     sinalizado e a APC descartada;
//!   - no modo kernel, a postagem grava o IO_STATUS_BLOCK, sinaliza o Event
//!     (zerado no pedido) e enfileira ApcRoutine como WORK_QUEUE_ITEM no
//!     tipo de fila ApcContext (ExQueueWorkItem); o pedido síncrono espera.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::cm::key::services as key_services;
use crate::ntos::cm::registry::NodeId;
use crate::ntos::inc::types::{IoStatusBlock, Kevent, NtStruct};
use crate::ntos::io::work_items;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

pub const REG_NOTIFY_CHANGE_NAME: u32 = 1;
pub const REG_NOTIFY_CHANGE_ATTRIBUTES: u32 = 2;
pub const REG_NOTIFY_CHANGE_LAST_SET: u32 = 4;
pub const REG_NOTIFY_CHANGE_SECURITY: u32 = 8;
pub const STATUS_NOTIFY_CLEANUP: u32 = 0x10B;
pub const STATUS_NOTIFY_ENUM_DIR: u32 = 0x10C;
const REG_LEGAL_CHANGE_FILTER: u32 = 0x1000_000F;
const REG_NOTIFY_THREAD_AGNOSTIC: u32 = 0x1000_0000;
/// Os bits de classe do Filter do CM_NOTIFY_BLOCK (o bit 30 é o WatchTree e
/// o 31, o NotifyPending).
const FILTER_MASK: u32 = 0x3FFF_FFFF;
const KEY_NOTIFY: u32 = 0x10;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_009A;
pub const STATUS_PENDING: u32 = 0x103;

/// Um bloco de postagem (CM_POST_BLOCK): o que completar o pedido faz.
pub trait Post: Send + Sync {
    /// CmpPostNotify deste pedido com `status` (chamado uma vez, fora das
    /// travas do Cm).
    fn deliver(&self, status: u32);
    /// CmNotifyRunDown: o fim da thread que fez o pedido.
    fn run_down(&self) {
        self.deliver(STATUS_NOTIFY_CLEANUP);
    }
}

/// O CM_NOTIFY_BLOCK de um corpo de chave.
struct NotifyBlock {
    /// A chave do bloco (o KeyControlBlock).
    node: NodeId,
    filter: u32,
    watch_tree: bool,
    /// NotifyPending: uma mudança chegou sem pedido esperando.
    pending: bool,
    /// Os pedidos esperando, o mais novo primeiro (InsertHeadList).
    posts: Vec<u64>,
}

/// Um pedido armado e os corpos em que ele espera (a chave mestra e, no
/// NtNotifyChangeMultipleKeys com Count 1, a subordinada).
struct PostEntry {
    post: Arc<dyn Post>,
    /// A thread dona (PostBlockList) para o CmNotifyRunDown; 0 sem dona.
    thread: u64,
    bodies: Vec<u64>,
}

struct Blocks {
    blocks: BTreeMap<u64, NotifyBlock>,
    posts: BTreeMap<u64, PostEntry>,
    next_post: u64,
}

static BLOCKS: SpinLock<Blocks> = SpinLock::new(Blocks { blocks: BTreeMap::new(), posts: BTreeMap::new(), next_post: 1 });

/// Tira o pedido `id` da tabela e dos blocos em que espera.
fn remove_post(state: &mut Blocks, id: u64) -> Option<Arc<dyn Post>> {
    let entry = state.posts.remove(&id)?;
    for body in &entry.bodies {
        if let Some(block) = state.blocks.get_mut(body) {
            block.posts.retain(|&candidate| candidate != id);
        }
    }
    Some(entry.post)
}

/// CmpPostNotify do bloco de `body`: sem pedido, marca a mudança pendente;
/// com pedidos, devolve todos para a entrega.
fn take_posts(state: &mut Blocks, body: u64) -> Vec<Arc<dyn Post>> {
    let Some(block) = state.blocks.get_mut(&body) else { return Vec::new() };
    if block.posts.is_empty() {
        block.pending = true;
        return Vec::new();
    }
    block.pending = false;
    let ids = core::mem::take(&mut block.posts);
    ids.into_iter().filter_map(|id| remove_post(state, id)).collect()
}

fn deliver_all(posts: Vec<Arc<dyn Post>>, status: u32) {
    for post in posts {
        post.deliver(status);
    }
}

/// CmpNotifyChangeKey em cada corpo de `targets` (corpo, chave), na ordem:
/// cria o bloco no primeiro pedido do corpo e põe o pedido na lista; um
/// bloco com mudança pendente posta na hora. Devolve o identificador do
/// pedido (para [`cancel`]) e STATUS_PENDING, ou STATUS_SUCCESS quando ele
/// já foi completado.
pub fn arm(targets: &[(u64, NodeId)], filter: u32, watch_tree: bool, post: Arc<dyn Post>, thread: u64) -> (u64, u32) {
    let (id, fired) = {
        let mut state = BLOCKS.lock();
        let id = state.next_post;
        state.next_post += 1;
        state.posts.insert(id, PostEntry { post, thread, bodies: Vec::new() });
        let mut fired = Vec::new();
        for &(body, node) in targets {
            let block = state.blocks.entry(body).or_insert_with(|| NotifyBlock { node, filter: filter & FILTER_MASK, watch_tree, pending: false, posts: Vec::new() });
            block.posts.insert(0, id);
            let pending = block.pending;
            if let Some(entry) = state.posts.get_mut(&id) {
                entry.bodies.push(body);
            }
            if pending {
                fired = take_posts(&mut state, body);
                break;
            }
        }
        (id, fired)
    };
    let immediate = !fired.is_empty();
    deliver_all(fired, STATUS_NOTIFY_ENUM_DIR);
    (id, if immediate { 0 } else { STATUS_PENDING })
}

/// Desfaz um pedido ainda armado (a espera interrompida, o fim do
/// processo). `true` quando ele saiu sem ter sido entregue.
pub fn cancel(id: u64) -> bool {
    remove_post(&mut BLOCKS.lock(), id).is_some()
}

/// CmpReportNotify: a mudança `filter` na chave `chain[0]` (seguida dos
/// ancestrais dela) posta os blocos interessados.
pub fn report(chain: &[NodeId], filter: u32) {
    let Some(&changed) = chain.first() else { return };
    let posts = {
        let mut state = BLOCKS.lock();
        let matching: Vec<u64> = state
            .blocks
            .iter()
            .filter(|(_, block)| block.filter & filter & FILTER_MASK != 0 && (block.node == changed || (block.watch_tree && chain.contains(&block.node))))
            .map(|(&body, _)| body)
            .collect();
        let mut posts = Vec::new();
        for body in matching {
            posts.extend(take_posts(&mut state, body));
        }
        posts
    };
    deliver_all(posts, STATUS_NOTIFY_ENUM_DIR);
}

/// Tira o bloco de `body` e devolve os pedidos dele.
fn remove_block(state: &mut Blocks, body: u64) -> Vec<Arc<dyn Post>> {
    let Some(block) = state.blocks.remove(&body) else { return Vec::new() };
    block.posts.into_iter().filter_map(|id| remove_post(state, id)).collect()
}

/// CmpFlushNotify: o último handle do corpo fechou (ou o corpo foi
/// liberado); os pedidos completam com STATUS_NOTIFY_CLEANUP e o bloco sai.
pub fn flush(body: u64) {
    let posts = remove_block(&mut BLOCKS.lock(), body);
    deliver_all(posts, STATUS_NOTIFY_CLEANUP);
}

/// CmpFlushNotifiesOnKeyBodyList: a chave foi excluída; cada bloco nela
/// completa os pedidos com STATUS_NOTIFY_CLEANUP e sai.
pub fn flush_node(node: NodeId) {
    let posts = {
        let mut state = BLOCKS.lock();
        let bodies: Vec<u64> = state.blocks.iter().filter(|(_, block)| block.node == node).map(|(&body, _)| body).collect();
        let mut posts = Vec::new();
        for body in bodies {
            posts.extend(remove_block(&mut state, body));
        }
        posts
    };
    deliver_all(posts, STATUS_NOTIFY_CLEANUP);
}

/// CmNotifyRunDown (rotina de fim de thread): os pedidos da thread saem.
pub fn run_down_thread(thread: u64) {
    let posts = {
        let mut state = BLOCKS.lock();
        let ids: Vec<u64> = state.posts.iter().filter(|(_, entry)| entry.thread == thread).map(|(&id, _)| id).collect();
        ids.into_iter().filter_map(|id| remove_post(&mut state, id)).collect::<Vec<_>>()
    };
    for post in posts {
        post.run_down();
    }
}

/// Um pedido de modo kernel (PostAsyncKernel ou PostSynchronous).
struct KernelPost {
    io_status: u64,
    event: u64,
    work_item: u64,
    queue_type: u32,
    status: AtomicU32,
}

impl Post for KernelPost {
    fn deliver(&self, status: u32) {
        self.status.store(status, Ordering::Release);
        if self.io_status != 0 {
            // SAFETY: PIO_STATUS_BLOCK de um chamador de modo kernel, vivo
            // enquanto a notificação estiver postada (o contrato do
            // ZwNotifyChangeKey).
            let iosb = unsafe { IoStatusBlock::at(self.io_status) };
            iosb.status.set(status as i32);
            iosb.information.set(0);
        }
        if self.event != 0 {
            dispatcher::set_event(self.event);
        }
        if self.work_item != 0 {
            work_items::queue_ex_work_item(self.work_item, self.queue_type);
        }
    }
}

/// ZwNotifyChangeKey(KeyHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
/// CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous) em modo kernel.
#[allow(clippy::too_many_arguments)]
pub fn notify_change_key(key: u64, event: u64, apc_routine: u64, apc_context: u64, io_status: u64, filter: u32, watch_tree: bool, _buffer: u64, _buffer_size: u32, asynchronous: bool) -> u32 {
    if filter & !REG_LEGAL_CHANGE_FILTER != 0 || (filter & REG_NOTIFY_THREAD_AGNOSTIC != 0 && !asynchronous) {
        return STATUS_INVALID_PARAMETER;
    }
    let (body, node, _) = match key_services::reference_key_body(key, false, KEY_NOTIFY) {
        Ok(referenced) => referenced,
        Err(status) => return status,
    };
    // Síncrono sem evento: um KEVENT interno para a espera.
    let wait_event = if !asynchronous && event == 0 { guest::alloc_bytes(Kevent::SIZE) } else { event };
    if !asynchronous && wait_event == 0 {
        return STATUS_NO_MEMORY;
    }
    if wait_event != 0 {
        if wait_event != event {
            dispatcher::initialize_event(wait_event, 0, false);
        } else {
            dispatcher::reset_event(wait_event);
        }
    }
    let post = Arc::new(KernelPost { io_status, event: wait_event, work_item: apc_routine, queue_type: apc_context as u32, status: AtomicU32::new(STATUS_PENDING) });
    let (_, status) = arm(&[(body, node)], filter, watch_tree, post.clone(), 0);
    if asynchronous {
        return status;
    }
    dispatcher::wait_for_single_object(wait_event, 0, 0, false);
    if wait_event != event {
        guest::free_bytes(wait_event);
    }
    post.status.load(Ordering::Acquire)
}
