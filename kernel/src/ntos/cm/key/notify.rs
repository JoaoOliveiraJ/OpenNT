//! Notificação de mudança de chave do registro (NT:
//! NtNotifyChangeKey -> NtNotifyChangeMultipleKeys, CmpReportNotify,
//! CmpPostNotify).
//!
//! Semântica do ntoskrnl 19041 usada aqui:
//!   - CompletionFilter fora de REG_LEGAL_CHANGE_FILTER (0x1000000F) =
//!     STATUS_INVALID_PARAMETER (NtNotifyChangeMultipleKeys 0x6dc05c), assim como
//!     REG_NOTIFY_THREAD_AGNOSTIC sem Asynchronous;
//!   - a mudança completa o bloco com STATUS_NOTIFY_ENUM_DIR (0x10C, o status que
//!     CmpReportNotifyHelper 0x5ed547 passa ao CmpPostNotify): grava o
//!     IO_STATUS_BLOCK, sinaliza o Event (zerado na postagem) e, para chamador de
//!     modo kernel, enfileira ApcRoutine como WORK_QUEUE_ITEM no tipo de fila
//!     ApcContext (ExQueueWorkItem);
//!   - Asynchronous devolve STATUS_PENDING; síncrono espera a mudança.
//! A notificação é de disparo único (o driver reposta chamando de novo).
//!
//! Os eventos vêm dos observadores de caminho do `cm::registry`: uma mudança
//! na chave (ou, com WatchTree, em qualquer descendente) dispara; sem
//! WatchTree também conta a criação/remoção de uma subchave direta.
//! Diferenças honestas: o observador do OpenNT não distingue as classes de
//! mudança (nome, atributos, valor, segurança), então todo o CompletionFilter
//! válido é tratado como "qualquer mudança"; fechar o handle não completa o
//! bloco com STATUS_NOTIFY_CLEANUP.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ntos::cm::registry;
use crate::ntos::inc::types::{IoStatusBlock, Kevent, NtStruct};
use crate::ntos::io::work_items;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;

const REG_LEGAL_CHANGE_FILTER: u32 = 0x1000_000F;
const REG_NOTIFY_THREAD_AGNOSTIC: u32 = 0x1000_0000;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PENDING: u32 = 0x103;
const STATUS_NOTIFY_ENUM_DIR: u32 = 0x10C;

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

/// CmpPostNotify de um bloco: IO_STATUS_BLOCK, evento e work item.
fn post(io_status: u64, event: u64, work_item: u64, queue_type: u32) {
    if io_status != 0 {
        // SAFETY: PIO_STATUS_BLOCK de um chamador de modo kernel, vivo enquanto
        // a notificação estiver postada (o contrato do ZwNotifyChangeKey).
        let iosb = unsafe { IoStatusBlock::at(io_status) };
        iosb.status.set(STATUS_NOTIFY_ENUM_DIR as i32);
        iosb.information.set(0);
    }
    if event != 0 {
        dispatcher::set_event(event);
    }
    if work_item != 0 {
        work_items::queue_ex_work_item(work_item, queue_type);
    }
}

/// ZwNotifyChangeKey(KeyHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
/// CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous) em modo kernel.
#[allow(clippy::too_many_arguments)]
pub fn notify_change_key(key: u64, event: u64, apc_routine: u64, apc_context: u64, io_status: u64, filter: u32, watch_tree: bool, _buffer: u64, _buffer_size: u32, asynchronous: bool) -> u32 {
    if filter & !REG_LEGAL_CHANGE_FILTER != 0 || (filter & REG_NOTIFY_THREAD_AGNOSTIC != 0 && !asynchronous) {
        return STATUS_INVALID_PARAMETER;
    }
    if key > 0x7FFF_FFFF || registry::get_node(key as u32).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    let path = registry::get_path(key as u32).unwrap_or_default();
    let watched = components(&path);
    // Síncrono sem evento: um KEVENT interno para a espera.
    let wait_event = if !asynchronous && event == 0 { guest::alloc_bytes(Kevent::SIZE) } else { event };
    if wait_event != 0 {
        if wait_event != event {
            dispatcher::initialize_event(wait_event, 0, false);
        } else {
            dispatcher::reset_event(wait_event);
        }
    }
    let fired = Arc::new(AtomicBool::new(false));
    let subscription = Arc::new(AtomicU64::new(0));
    let observer: registry::Observer = {
        let (fired, subscription) = (fired.clone(), subscription.clone());
        Arc::new(move |changed: &str| {
            if !concerns(&watched, changed, watch_tree) || fired.swap(true, Ordering::AcqRel) {
                return;
            }
            registry::unwatch(subscription.load(Ordering::Acquire));
            post(io_status, wait_event, apc_routine, apc_context as u32);
        })
    };
    subscription.store(registry::watch(&path, observer), Ordering::Release);
    if asynchronous {
        return STATUS_PENDING;
    }
    dispatcher::wait_for_single_object(wait_event, 0, 0, false);
    if wait_event != event {
        guest::free_bytes(wait_event);
    }
    STATUS_NOTIFY_ENUM_DIR
}
