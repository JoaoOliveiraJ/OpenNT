//! Contagem de keep-alive de um processo por um FILE_OBJECT —
//! IoIncrementKeepAliveCount e IoDecrementKeepAliveCount (ntoskrnl 19041
//! 0x506c90 e 0x506b30, sobre o IopAdjustFileObjectKeepAliveCount 0x506fd8).
//!
//! - Cada FILE_OBJECT guarda, na extensão de arquivo, um rastreador por
//!   processo com a contagem; o incremento cria o rastreador (o bit 29 de
//!   FileObject->Flags, sem o bit 3 da FileObjectExtension, escolhe o
//!   WakeCounters[1] do processo; senão vale o NoWakeCounter) e o decremento
//!   de um processo sem rastreador é STATUS_INVALID_PARAMETER.
//! - A contagem que chega a 1 cobra o processo: abaixo de DISPATCH_LEVEL na
//!   hora (ObReferenceObjectWithTag 'Dflt' + PspAdjustKeepAliveCountProcess
//!   +1); em DISPATCH_LEVEL a cobrança fica pendente para o trabalhador
//!   IopKeepAliveTracker.
//! - A contagem que chega a 0 não solta na hora: o rastreador recebe o prazo
//!   de 5 s (o tempo de interrupção do KUSER_SHARED_DATA + 50.000.000) e o
//!   trabalhador, em PASSIVE_LEVEL, aplica o -1 (e solta a referência) depois
//!   do prazo.
//!
//! Os rastreadores ficam aqui (a extensão de arquivo é privada do Io); o
//! trabalhador é um work item interno do kernel cuja prontidão é o primeiro
//! prazo vencido.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::types::{Eprocess, FileObject, NtStruct};
use crate::ntos::io::work_items;
use crate::ntos::ke::{clock, irql};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_reference;
use crate::ntos::ps::wake_counter;
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// A tag 'Dflt' da referência do processo.
const PROCESS_REFERENCE_TAG: u32 = 0x746C_6644;
/// FileObject->Flags, bit 29: o arquivo conta no contador de wake.
const FILE_OBJECT_WAKE_FLAG: u32 = 0x2000_0000;
/// O bit 3 da FileObjectExtension anula o bit acima.
const EXTENSION_NO_WAKE: u32 = 0x8;
/// Prazo da soltura: 5 s.
const RELEASE_DELAY_MS: u64 = 5_000;

struct Tracker {
    file_object: u64,
    process: u64,
    count: u32,
    /// WakeCounters[1] (verdadeiro) ou NoWakeCounter.
    wake: bool,
    /// Ajuste que o trabalhador ainda aplica.
    pending: i32,
    deadline: u64,
}

static TRACKERS: SpinLock<Vec<Tracker>> = SpinLock::new(Vec::new());
/// O work item do IopKeepAliveTracker.
static WORKER_ITEM: AtomicU64 = AtomicU64::new(0);

fn wake_flag(file_object: u64) -> bool {
    // SAFETY: o FILE_OBJECT referenciado pelo chamador de modo kernel.
    let file = unsafe { FileObject::at(file_object) };
    if file.flags.get() & FILE_OBJECT_WAKE_FLAG == 0 {
        return false;
    }
    let extension = file.file_object_extension.get();
    extension == 0 || guest::read32(extension) & EXTENSION_NO_WAKE == 0
}

/// PspAdjustKeepAliveCountProcess(Process, Amount, FileObject, Wake).
fn adjust_process(process: u64, amount: i32, wake: bool) -> Result<(), KernelError> {
    // SAFETY: o EPROCESS retido pelo rastreador.
    wake_counter::adjust_keep_alive(unsafe { Eprocess::at(process) }, wake, amount)
}

/// O trabalhador tem algo vencido para aplicar (em PASSIVE_LEVEL).
fn worker_ready() -> bool {
    let now = clock::uptime_ms();
    irql::get_irql() == 0 && TRACKERS.lock().iter().any(|tracker| tracker.pending != 0 && tracker.deadline <= now)
}

fn queue_worker() {
    let mut item = WORKER_ITEM.load(Ordering::Acquire);
    if item == 0 {
        let fresh = guest::alloc_bytes(work_items::work_item_size());
        item = match WORKER_ITEM.compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => fresh,
            Err(existing) => {
                guest::free_bytes(fresh);
                existing
            }
        };
    }
    work_items::queue_kernel_work_item(item, run_worker, 0, Some(worker_ready));
}

/// IopKeepAliveTracker: aplica os ajustes vencidos; os de prazo futuro
/// voltam à fila.
fn run_worker(_item: u64, _context: u64) {
    let now = clock::uptime_ms();
    let due: Vec<(u64, i32, bool)> = {
        let mut trackers = TRACKERS.lock();
        let due = trackers.iter_mut().filter(|tracker| tracker.pending != 0 && tracker.deadline <= now).map(|tracker| (tracker.process, core::mem::take(&mut tracker.pending), tracker.wake)).collect();
        trackers.retain(|tracker| tracker.count != 0 || tracker.pending != 0);
        due
    };
    for (process, pending, wake) in due {
        for _ in 0..pending.unsigned_abs() {
            if pending > 0 {
                let _ = object_reference::reference_with_tag(process, PROCESS_REFERENCE_TAG, false);
                let _ = adjust_process(process, 1, wake);
            } else {
                let _ = adjust_process(process, -1, wake);
                let _ = object_reference::dereference_with_tag(process, PROCESS_REFERENCE_TAG, false);
            }
        }
    }
    if TRACKERS.lock().iter().any(|tracker| tracker.pending != 0) {
        queue_worker();
    }
}

/// IoIncrementKeepAliveCount(FileObject, Process).
pub fn increment(file_object: u64, process: u64) -> Result<u32, KernelError> {
    let (first, wake) = {
        let mut trackers = TRACKERS.lock();
        let index = match trackers.iter().position(|tracker| tracker.file_object == file_object && tracker.process == process) {
            Some(index) => index,
            None => {
                trackers.push(Tracker { file_object, process, count: 0, wake: wake_flag(file_object), pending: 0, deadline: 0 });
                trackers.len() - 1
            }
        };
        let tracker = &mut trackers[index];
        tracker.count = tracker.count.wrapping_add(1);
        let first = tracker.count == 1;
        if first && irql::get_irql() >= irql::DISPATCH_LEVEL {
            tracker.pending += 1;
            drop(trackers);
            queue_worker();
            return Ok(0);
        }
        (first, tracker.wake)
    };
    if first {
        object_reference::reference_with_tag(process, PROCESS_REFERENCE_TAG, false)?;
        adjust_process(process, 1, wake)?;
    }
    Ok(0)
}

/// IoDecrementKeepAliveCount(FileObject, Process).
pub fn decrement(file_object: u64, process: u64) -> Result<u32, KernelError> {
    {
        let mut trackers = TRACKERS.lock();
        let Some(tracker) = trackers.iter_mut().find(|tracker| tracker.file_object == file_object && tracker.process == process) else {
            return Ok(STATUS_INVALID_PARAMETER);
        };
        tracker.count = tracker.count.wrapping_sub(1);
        if tracker.count != 0 {
            return Ok(0);
        }
        tracker.deadline = clock::uptime_ms() + RELEASE_DELAY_MS;
        tracker.pending -= 1;
    }
    queue_worker();
    Ok(0)
}

/// (contagem, ajuste pendente) do rastreador de um processo num arquivo.
pub fn tracker_state(file_object: u64, process: u64) -> Option<(u32, i32)> {
    TRACKERS.lock().iter().find(|tracker| tracker.file_object == file_object && tracker.process == process).map(|tracker| (tracker.count, tracker.pending))
}
