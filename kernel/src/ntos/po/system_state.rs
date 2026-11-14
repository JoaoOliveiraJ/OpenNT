//! Estado do sistema que o subsistema de janelas informa ao Po (ntoskrnl
//! 19041): presença do usuário, a dica de sensibilidade à latência e a
//! espera de shutdown das threads que precisam saber do desligamento.
//!
//! - PoSetUserPresent(Presence): o PopSetSystemState(ES_USER_PRESENT) sob
//!   a trava da política; o último valor fica como o estado de presença.
//! - PoLatencySensitivityHint(Priority): no NT só age com um perfil PPM que
//!   peça impulso de latência; o OpenNT não tem gerenciamento de desempenho
//!   do processador, então só a última dica e o instante dela ficam
//!   registrados.
//! - PoRequestShutdownEvent(Event*): zera *Event, põe a thread corrente
//!   (referenciada) na lista de espera de shutdown e devolve o
//!   PopShutdownEvent, um KEVENT de notificação; com a lista já fechada, a
//!   referência volta e o resultado é STATUS_UNSUCCESSFUL.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{Kevent, NtStruct};
use crate::ntos::ke::{clock, dispatcher};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

static USER_PRESENCE: AtomicU32 = AtomicU32::new(0);
static LATENCY_HINT: AtomicU32 = AtomicU32::new(0);
static LATENCY_HINT_TIME: AtomicU64 = AtomicU64::new(0);

/// PoSetUserPresent: o PopUserPresentSet.
pub fn set_user_present(presence: u32) {
    USER_PRESENCE.store(presence, Ordering::Release);
}

/// O último USER_ACTIVITY_PRESENCE informado.
pub fn user_presence() -> u32 {
    USER_PRESENCE.load(Ordering::Acquire)
}

/// PoLatencySensitivityHint.
pub fn latency_sensitivity_hint(priority: u32) {
    LATENCY_HINT.store(priority, Ordering::Release);
    LATENCY_HINT_TIME.store(clock::uptime_ms(), Ordering::Release);
}

/// A última dica e o instante (ms desde o boot).
pub fn latency_hint() -> (u32, u64) {
    (LATENCY_HINT.load(Ordering::Acquire), LATENCY_HINT_TIME.load(Ordering::Acquire))
}

/// A lista de espera de shutdown (PopShutdownThreadList) e se ela ainda
/// aceita threads (PopShutdownListAvailable).
struct ShutdownList {
    threads: Vec<u64>,
    closed: bool,
}

static SHUTDOWN: SpinLock<ShutdownList> = SpinLock::new(ShutdownList { threads: Vec::new(), closed: false });
/// O PopShutdownEvent (KEVENT de notificação no pool do kernel).
static SHUTDOWN_EVENT: AtomicU64 = AtomicU64::new(0);

fn shutdown_event() -> u64 {
    let current = SHUTDOWN_EVENT.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let event = guest::alloc_bytes(Kevent::SIZE);
    if event == 0 {
        return 0;
    }
    dispatcher::initialize_event(event, 0, false);
    match SHUTDOWN_EVENT.compare_exchange(0, event, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => event,
        Err(existing) => {
            guest::free_bytes(event);
            existing
        }
    }
}

/// PoRequestShutdownEvent(Event*).
pub fn request_shutdown_event(event_out: u64) -> Result<u32, KernelError> {
    // SAFETY: o PVOID* opcional do chamador de kernel.
    let out = (event_out != 0).then(|| unsafe { Field::<u64>::at(event_out) });
    if let Some(out) = out {
        out.set(0);
    }
    let event = shutdown_event();
    if event == 0 {
        return Ok(STATUS_NO_MEMORY);
    }
    let thread = process::get_current_thread();
    process::reference_thread(thread);
    {
        let mut list = SHUTDOWN.lock();
        if !list.closed {
            list.threads.push(thread);
            drop(list);
            if let Some(out) = out {
                out.set(event);
            }
            return Ok(0);
        }
    }
    process::dereference_thread(thread)?;
    Ok(STATUS_UNSUCCESSFUL)
}

/// As threads na lista de espera de shutdown.
pub fn shutdown_waiters() -> Vec<u64> {
    SHUTDOWN.lock().threads.clone()
}
