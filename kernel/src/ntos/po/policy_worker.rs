//! O trabalho de notificação do worker de política do Po (ntoskrnl 19041):
//! PopSetNotificationWork (rva 0x34aea0) e PopPolicyWorkerNotify (0x6f48e0).
//!
//! - PopSetNotificationWork(Mask): sem novidade (todos os bits já pedidos)
//!   não faz nada; senão liga os bits em PopNotifyEvents, marca o tipo de
//!   trabalho "notificação" como pendente (PopGetPolicyWorker(4)) e, se o
//!   worker de política não está na fila nem rodando, o põe na
//!   DelayedWorkQueue (PopCheckForWork: ExQueueWorkItem do PopPolicyWorker).
//! - O PopPolicyWorkerThread roda os tipos pendentes até não sobrar nenhum;
//!   o de notificação é o PopPolicyWorkerNotify: troca PopNotifyEvents por
//!   zero, chama a entrada de PopNotifyWork de cada bit, do menor para o
//!   maior, espera 10 ms (KeDelayExecutionThread de -100000) e repete até
//!   uma troca devolver zero. Um bit pedido durante a volta entra na
//!   seguinte.
//! - PopNotifyWork tem 8 entradas: 0x1 PopDispatchFullWake, 0x2
//!   PopDispatchCallback, 0x4 PopDispatchAcDcCallback, 0x8
//!   PopDispatchCallout, 0x10 PopDispatchShutdownEvent, 0x20
//!   PopDispatchPowerSettingCallbacks, 0x40 PopSetSystemAwayMode e 0x80
//!   PopDispatchNotifications. O OpenNT só pede os dois bits dos power
//!   settings (`po/power_setting.rs`): os callbacks dos drivers e a
//!   publicação WNF dos valores. Os outros eventos (sono, away mode,
//!   callouts do win32k) não existem nele.
//!
//! O worker é um work item de kernel no processo System. O PopCheckForWork
//! do 19041 também não enfileira quando quem pede é o dono da trava de
//! política (a liberação dela confere de novo); o OpenNT não tem essa trava.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::ntos::inc::types::{NtStruct, WorkQueueItem};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::power_setting;

/// Os bits de PopNotifyEvents que o OpenNT usa.
pub const NOTIFY_POWER_SETTING_CALLBACKS: u32 = 0x20;
pub const NOTIFY_SETTING_NOTIFICATIONS: u32 = 0x80;

/// A espera entre duas voltas do PopPolicyWorkerNotify (10 ms).
const NOTIFY_ROUND_DELAY: i64 = -100_000;

/// PopNotifyEvents.
static NOTIFY_EVENTS: AtomicU32 = AtomicU32::new(0);
/// O tipo "notificação" em PopWorkerPending.
static NOTIFY_PENDING: AtomicBool = AtomicBool::new(false);
/// O worker de política está na fila ou rodando (o bit 31 de
/// PopWorkerStatus desligado).
static WORKER_QUEUED: AtomicBool = AtomicBool::new(false);
/// O PopPolicyWorker: o WORK_QUEUE_ITEM e, logo depois, o intervalo da
/// espera entre voltas.
static WORKER_ITEM: AtomicU64 = AtomicU64::new(0);

/// O bloco do worker, alocado no primeiro pedido (0 sem memória).
fn worker_item() -> u64 {
    let existing = WORKER_ITEM.load(Ordering::Acquire);
    if existing != 0 {
        return existing;
    }
    let block = guest::alloc_bytes(WorkQueueItem::SIZE + 8);
    if block == 0 {
        return 0;
    }
    guest::write_bytes(block, &alloc::vec![0u8; WorkQueueItem::SIZE as usize + 8]);
    match WORKER_ITEM.compare_exchange(0, block, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => block,
        Err(winner) => {
            guest::free_bytes(block);
            winner
        }
    }
}

/// PopSetNotificationWork(Mask).
pub fn set_notification_work(mask: u32) {
    if NOTIFY_EVENTS.load(Ordering::Acquire) & mask == mask {
        return;
    }
    NOTIFY_EVENTS.fetch_or(mask, Ordering::AcqRel);
    NOTIFY_PENDING.store(true, Ordering::Release);
    check_for_work();
}

/// PopCheckForWork: enfileira o worker de política se há trabalho pendente
/// e ele está livre.
fn check_for_work() {
    if !NOTIFY_PENDING.load(Ordering::Acquire) {
        return;
    }
    let item = worker_item();
    if item == 0 || WORKER_QUEUED.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::ntos::io::work_items::queue_kernel_ex_work_item(item, policy_worker, item);
}

/// PopPolicyWorkerThread: roda o trabalho pendente; ao sair, libera o
/// worker e confere o que chegou nesse meio-tempo.
fn policy_worker(_device: u64, item: u64) {
    loop {
        while NOTIFY_PENDING.swap(false, Ordering::AcqRel) {
            notify(item);
        }
        WORKER_QUEUED.store(false, Ordering::Release);
        if !NOTIFY_PENDING.load(Ordering::Acquire) || WORKER_QUEUED.swap(true, Ordering::AcqRel) {
            return;
        }
    }
}

/// PopPolicyWorkerNotify.
fn notify(item: u64) {
    loop {
        let mut events = NOTIFY_EVENTS.swap(0, Ordering::AcqRel);
        if events == 0 {
            return;
        }
        while events != 0 {
            let bit = 1u32 << events.trailing_zeros();
            events &= !bit;
            match bit {
                // PopDispatchPowerSettingCallbacks.
                NOTIFY_POWER_SETTING_CALLBACKS => power_setting::dispatch_callbacks(),
                // PopDispatchNotifications.
                NOTIFY_SETTING_NOTIFICATIONS => power_setting::dispatch_notifications(),
                _ => {}
            }
        }
        let interval = item + WorkQueueItem::SIZE;
        guest::write64(interval, NOTIFY_ROUND_DELAY as u64);
        let _ = crate::ntos::ke::timer::delay_execution_thread(interval, 0, false);
    }
}
