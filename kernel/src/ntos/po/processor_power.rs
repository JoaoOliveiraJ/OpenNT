//! Gerência de energia dos processadores (PPM) vista pelos drivers: o aviso
//! de buffering de mídia (PoNotifyMediaBuffering) e a consulta de
//! ociosidade de uma CPU (PoCpuIdledSinceLastCallImprecise).
//!
//! ntoskrnl 19041:
//! - PoNotifyMediaBuffering(Engaged) 0x36c240: sob a trava do
//!   PpmMediaBufferingWork (já em DISPATCH_LEVEL) grava o pedido e, se o
//!   trabalho não está na fila, marca e enfileira o work item
//!   (ExQueueWorkItem, prioridade da thread corrente + 1 até 31, ao menos 16
//!   quando desengatado). O PpmMediaBufferingWorker (0x36bf90) repete até o
//!   estado aplicado alcançar o pedido: aplica, avisa o ETW e reavalia a
//!   política de desempenho (PpmPerfPolicyLock); quando alcança, desmarca a
//!   fila. O OpenNT não tem política de desempenho de processador: o
//!   trabalho aplica o estado e conta as aplicações.
//! - PoCpuIdledSinceLastCallImprecise(Processor, LastIdleTime*) 0x36bb20:
//!   sem KPRCB (KiProcessorBlock[Processor] nulo), TRUE; senão troca
//!   *LastIdleTime pelo PowerState.IdleTimeTotal da CPU e devolve TRUE se ela
//!   está ociosa agora (IdleTimeEntry != 0) ou se o total cresceu.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::WorkQueueItem;
use crate::ntos::ke::pcr;
use crate::rtl::SpinLock;

/// O estado do PpmMediaBufferingWork.
struct MediaBuffering {
    /// O WORK_QUEUE_ITEM embutido (alocado na primeira vez).
    work_item: u64,
    queued: bool,
    requested: bool,
    applied: bool,
}

static MEDIA_BUFFERING: SpinLock<MediaBuffering> = SpinLock::new(MediaBuffering { work_item: 0, queued: false, requested: false, applied: false });
/// Quantas vezes o trabalho aplicou uma mudança de estado.
static MEDIA_BUFFERING_UPDATES: AtomicU64 = AtomicU64::new(0);

/// PpmMediaBufferingWorker.
fn media_buffering_worker(_item: u64, _parameter: u64) {
    loop {
        let mut state = MEDIA_BUFFERING.lock();
        if state.requested == state.applied {
            state.queued = false;
            return;
        }
        state.applied = state.requested;
        drop(state);
        MEDIA_BUFFERING_UPDATES.fetch_add(1, Ordering::SeqCst);
    }
}

/// PoNotifyMediaBuffering(Engaged).
pub fn notify_media_buffering(engaged: bool) {
    let item = {
        let mut state = MEDIA_BUFFERING.lock();
        state.requested = engaged;
        if state.queued {
            return;
        }
        if state.work_item == 0 {
            state.work_item = crate::ntos::mm::guest_memory::alloc_bytes(WorkQueueItem::SIZE);
            if state.work_item == 0 {
                return;
            }
        }
        state.queued = true;
        state.work_item
    };
    crate::ntos::io::work_items::queue_kernel_ex_work_item(item, media_buffering_worker, 0);
}

/// (pedido, aplicado, na fila, aplicações) do buffering de mídia.
pub fn media_buffering_state() -> (bool, bool, bool, u64) {
    let state = MEDIA_BUFFERING.lock();
    (state.requested, state.applied, state.queued, MEDIA_BUFFERING_UPDATES.load(Ordering::SeqCst))
}

/// PoCpuIdledSinceLastCallImprecise(Processor, LastIdleTime*) -> BOOLEAN.
pub fn cpu_idled_since_last_call(processor: u32, last_idle_time: &Field<u64>) -> bool {
    let Some(prcb) = pcr::processor_block(processor) else { return true };
    let power = &prcb.power_state;
    let total = power.idle_time_total.get();
    let previous = last_idle_time.get();
    last_idle_time.set(total);
    power.idle_time_entry.get() != 0 || total > previous
}

