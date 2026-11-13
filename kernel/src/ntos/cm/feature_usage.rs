//! Relatos de uso de funcionalidades — `system32/ntos/cm/feature-usage.js`.
//!
//! Dois bancos de relatos, work items, DPCs e o timer de reenvio. A produção
//! pode ocorrer com IRQL elevado; a entrega acontece pela fila de trabalho em
//! PASSIVE_LEVEL.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::feature_usage_buffer as buffer;
use super::feature_usage_delivery::{self as delivery, Subscription};
use crate::ntos::io::work_items;
use crate::ntos::ke::{critical_region, dpc, irql, timer};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{io_workitem, kdpc, ktimer};

/// Bloco principal; zero = ainda não inicializado.
static STORAGE: AtomicU64 = AtomicU64::new(0);
static ACTIVE_BANK: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_PRODUCERS: AtomicU32 = AtomicU32::new(0);
static DRAINING: AtomicBool = AtomicBool::new(false);
static RETRY_ARMED: AtomicBool = AtomicBool::new(false);
static SUBSCRIPTIONS: SpinLock<Vec<Subscription>> = SpinLock::new(Vec::new());

fn bank(index: usize) -> u64 {
    STORAGE.load(Ordering::Acquire) + index as u64 * buffer::SIZE
}

fn worker() -> u64 {
    STORAGE.load(Ordering::Acquire) + 2 * buffer::SIZE
}

fn retry_worker() -> u64 {
    worker() + io_workitem::SIZE
}

fn deferred_call() -> u64 {
    retry_worker() + io_workitem::SIZE
}

fn retry_deferred_call() -> u64 {
    deferred_call() + kdpc::SIZE
}

fn retry_timer() -> u64 {
    retry_deferred_call() + kdpc::SIZE
}

/// PASSIVE_LEVEL, sem produtores ativos e sem outra drenagem.
fn can_drain() -> bool {
    irql::get_irql() == 0 && ACTIVE_PRODUCERS.load(Ordering::Acquire) == 0 && !DRAINING.load(Ordering::Acquire)
}

fn queue_delivery_worker() {
    work_items::queue_kernel_work_item(worker(), run_worker, 0, Some(can_drain));
}

fn delivery_dpc(_dpc: u64, _context: u64, _first: u64, _second: u64) {
    queue_delivery_worker();
}

fn retry_dpc(_dpc: u64, _context: u64, _first: u64, _second: u64) {
    work_items::queue_kernel_work_item(retry_worker(), run_retry, 0, Some(can_drain));
}

/// Reserva de uma vez os dois bancos, dois work items, dois DPCs e o timer
/// antes de permitir produção nativa; idempotente.
pub fn init() -> bool {
    if STORAGE.load(Ordering::Acquire) != 0 {
        return true;
    }
    let length = 2 * buffer::SIZE + 2 * io_workitem::SIZE + 2 * kdpc::SIZE + ktimer::SIZE;
    let pointer = guest::alloc_bytes(length);
    if pointer == 0 {
        return false;
    }
    STORAGE.store(pointer, Ordering::Release);
    work_items::create_work_item(0, worker());
    work_items::create_work_item(0, retry_worker());
    dpc::initialize_kernel_dpc(deferred_call(), delivery_dpc, 0);
    dpc::initialize_kernel_dpc(retry_deferred_call(), retry_dpc, 0);
    timer::initialize_timer(retry_timer(), ktimer::TIMER_NOTIFICATION as u32);
    true
}

/// Registra o relato no banco ativo (com região crítica abaixo de
/// DISPATCH_LEVEL) e agenda a entrega direta ou por DPC.
pub fn notify(report: u64, effective_irql: Option<u8>) -> Result<u32, KernelError> {
    let level = effective_irql.unwrap_or_else(irql::get_irql);
    let critical = level < 2;
    if critical {
        critical_region::enter_critical()?;
    }
    let result = (|| -> Result<u32, KernelError> {
        if STORAGE.load(Ordering::Acquire) == 0 {
            return Ok(0xC000_009A);
        }
        ACTIVE_PRODUCERS.fetch_add(1, Ordering::AcqRel);
        let status = buffer::enqueue(bank(ACTIVE_BANK.load(Ordering::Acquire)), report);
        ACTIVE_PRODUCERS.fetch_sub(1, Ordering::AcqRel);
        let status = status?;
        if status != 0 {
            return Ok(status);
        }
        if level < 2 {
            queue_delivery_worker();
        } else {
            dpc::insert_queue_dpc(deferred_call(), 0, 0);
        }
        Ok(0)
    })();
    if critical {
        critical_region::leave_critical()?;
    }
    result
}

/// Troca o banco ativo antes de consumir o anterior, com uma visão estável
/// das inscrições; relatos retidos armam o timer de nova tentativa (60 s).
fn drain_bank(retry_previous: bool) {
    let drained = bank(ACTIVE_BANK.load(Ordering::Acquire));
    let snapshot = SUBSCRIPTIONS.lock().clone();
    ACTIVE_BANK.fetch_xor(1, Ordering::AcqRel);
    let retained = buffer::drain(drained, |report| delivery::send(report, &snapshot), retry_previous);
    if retained != 0 && !RETRY_ARMED.load(Ordering::Acquire) {
        timer::set_timer(retry_timer(), -600_000_000, retry_deferred_call(), 0);
        RETRY_ARMED.store(true, Ordering::Release);
    }
}

fn drain(retry_previous: bool) -> Result<(), KernelError> {
    if !can_drain() {
        return Err(KernelError::new("feature-usage worker requires PASSIVE_LEVEL and exclusive bank ownership"));
    }
    DRAINING.store(true, Ordering::Release);
    let entered = critical_region::enter_critical();
    if entered.is_ok() {
        drain_bank(retry_previous);
        if retry_previous {
            drain_bank(true);
        }
    }
    DRAINING.store(false, Ordering::Release);
    entered?;
    critical_region::leave_critical()
}

/// Entrega os relatos novos sem repetir slots que já têm tentativas.
fn run_worker(_item: u64, _context: u64) {
    if let Err(error) = drain(false) {
        debug_print!("[feature-usage] {}", error);
    }
}

/// Desarma o indicador do timer e tenta os dois bancos, incluindo retidos.
fn run_retry(_item: u64, _context: u64) {
    RETRY_ARMED.store(false, Ordering::Release);
    if let Err(error) = drain(true) {
        debug_print!("[feature-usage] {}", error);
    }
}

/// Configuração interna (não é API nativa pública); cada entrega usa o
/// snapshot publicado.
pub fn set_subscriptions(subscriptions: &[Subscription]) -> Result<(), KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("feature subscriptions require PASSIVE_LEVEL"));
    }
    *SUBSCRIPTIONS.lock() = subscriptions.to_vec();
    if STORAGE.load(Ordering::Acquire) != 0 && buffer::count(bank(ACTIVE_BANK.load(Ordering::Acquire))) != 0 {
        queue_delivery_worker();
    }
    Ok(())
}

/// Indicadores e contadores para inspeção.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub initialized: bool,
    pub active: usize,
    pub readers: u32,
    pub draining: bool,
    pub retry_armed: bool,
    pub counts: [u32; 2],
    pub dropped: [u32; 2],
    pub subscriptions: Vec<Subscription>,
}

pub fn snapshot() -> Snapshot {
    let initialized = STORAGE.load(Ordering::Acquire) != 0;
    let per_bank = |read: fn(u64) -> u32| if initialized { [read(bank(0)), read(bank(1))] } else { [0, 0] };
    Snapshot {
        initialized,
        active: ACTIVE_BANK.load(Ordering::Acquire),
        readers: ACTIVE_PRODUCERS.load(Ordering::Acquire),
        draining: DRAINING.load(Ordering::Acquire),
        retry_armed: RETRY_ARMED.load(Ordering::Acquire),
        counts: per_bank(buffer::count),
        dropped: per_bank(buffer::dropped),
        subscriptions: SUBSCRIPTIONS.lock().clone(),
    }
}
