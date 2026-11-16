//! Estado do sistema que o subsistema de janelas e os drivers informam ao Po
//! (ntoskrnl 19041): presença do usuário, a dica de sensibilidade à latência,
//! a espera de shutdown das threads que precisam saber do desligamento e, no
//! fim do arquivo, os estados legados (PoSetSystemState/PoRegisterSystemState),
//! o botão de energia segurado e as fontes fixas de wake.
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

/// O começo do PopGracefulShutdown (rva 0x9b1118): KeSetEvent no
/// PopShutdownEvent, a lista fechada (PopShutdownListAvailable = FALSE: o
/// PoRequestShutdownEvent passa a falhar) e a espera do fim de cada thread
/// da lista (KeWaitForSingleObject na ETHREAD), cuja referência volta.
/// Devolve quantas threads foram esperadas.
pub fn notify_shutdown_waiters() -> Result<usize, KernelError> {
    let event = shutdown_event();
    if event != 0 {
        dispatcher::set_event(event);
    }
    let threads = {
        let mut list = SHUTDOWN.lock();
        list.closed = true;
        core::mem::take(&mut list.threads)
    };
    for &thread in &threads {
        dispatcher::wait_for_single_object(thread, 0, 0, false);
        process::dereference_thread(thread)?;
    }
    Ok(threads.len())
}

// ---- PoSetSystemState, PoRegisterSystemState, PoUnregisterSystemState,
// ---- PoSetPowerButtonHoldState e PoSetFixedWakeSource (ntoskrnl 19041) -------
//
// - PoSetSystemState(Flags) 0x56ef30: PopSetSystemState(Flags, 7) sob a
//   trava da política. PopSetSystemState ignora Flags com bits fora de
//   ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_USER_PRESENT; o primeiro
//   zera o tempo ocioso do sistema (PopResetIdleTime) e o último é o
//   PopUserPresentSet(Fonte) do PoSetUserPresent.
// - PoRegisterSystemState(StateHandle, Flags) 0x56ee50: Flags com bits
//   fora de ES_CONTINUOUS | 7 devolve NULL; sem ES_CONTINUOUS (e Flags !=
//   0), é o PoSetSystemState e devolve NULL. Senão, sem StateHandle cria um
//   pedido de energia de kernel (PopCreateKernelPowerRequest) e aplica as
//   flags legadas: cada tipo cujo estado muda é ligado ou desligado
//   (ES_SYSTEM_REQUIRED = PowerRequestSystemRequired, ES_DISPLAY_REQUIRED =
//   PowerRequestDisplayRequired; ES_USER_PRESENT não é tipo de pedido).
//   Devolve o pedido.
// - PoUnregisterSystemState(StateHandle) 0x56ef80: PoDeletePowerRequest.
// - PoSetPowerButtonHoldState(Held) 0x568b90 (PopUpdatePowerButtonHoldState):
//   sob a trava PopPowerButtonHold, o histórico de 64 bits recebe o bit da
//   transição (índice = pressões + solturas), os contadores somam e, quando o
//   estado muda, o PopQueueWorkItem do botão é pedido (as ações de botão
//   segurado da política de energia, que o OpenNT não tem).
// - PoSetFixedWakeSource(WakeSource) 0x9b13a0: PopFixedWakeSourceMask |=
//   WakeSource.

const ES_SYSTEM_REQUIRED: u32 = 0x1;
const ES_DISPLAY_REQUIRED: u32 = 0x2;
const ES_USER_PRESENT: u32 = 0x4;
const ES_CONTINUOUS: u32 = 0x8000_0000;
/// O PopSetSystemState do PoSetSystemState informa a fonte 7.
const SYSTEM_STATE_SOURCE: u32 = 7;

/// O último PopResetIdleTime do ES_SYSTEM_REQUIRED (ms desde o boot).
static SYSTEM_IDLE_RESET: AtomicU64 = AtomicU64::new(0);

/// Pedidos de energia de kernel vivos: as flags legadas aplicadas a cada um.
static POWER_REQUESTS: SpinLock<alloc::collections::BTreeMap<u64, u32>> = SpinLock::new(alloc::collections::BTreeMap::new());

/// Estado do botão de energia segurado (PopPowerButtonHold).
struct PowerButtonHold {
    presses: u32,
    releases: u32,
    history: u64,
    held: bool,
    holds: u32,
    work_requests: u32,
}

static POWER_BUTTON: SpinLock<PowerButtonHold> = SpinLock::new(PowerButtonHold { presses: 0, releases: 0, history: 0, held: false, holds: 0, work_requests: 0 });
static FIXED_WAKE_SOURCES: AtomicU32 = AtomicU32::new(0);

/// PopSetSystemState(Flags, Source).
fn apply_system_state(flags: u32, source: u32) {
    if flags & !(ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_USER_PRESENT) != 0 {
        return;
    }
    if flags & ES_SYSTEM_REQUIRED != 0 {
        SYSTEM_IDLE_RESET.store(clock::uptime_ms(), Ordering::Release);
    }
    if flags & ES_USER_PRESENT != 0 {
        set_user_present(source);
    }
}

/// PoSetSystemState(Flags).
pub fn set_system_state(flags: u32) {
    apply_system_state(flags, SYSTEM_STATE_SOURCE);
}

/// O instante (ms desde o boot) do último ES_SYSTEM_REQUIRED.
pub fn system_idle_reset() -> u64 {
    SYSTEM_IDLE_RESET.load(Ordering::Acquire)
}

/// PoRegisterSystemState(StateHandle, Flags): o pedido (ou NULL).
pub fn register_system_state(handle: u64, flags: u32) -> u64 {
    if flags & 0x7FFF_FFF8 != 0 {
        return 0;
    }
    if flags != 0 && flags & ES_CONTINUOUS == 0 {
        set_system_state(flags);
        return 0;
    }
    let request = if handle != 0 { handle } else { guest::alloc_bytes(0x40) };
    if request == 0 {
        return 0;
    }
    let mut requests = POWER_REQUESTS.lock();
    let current = requests.entry(request).or_insert(0);
    // Só o que muda é ligado ou desligado; ES_USER_PRESENT não é tipo.
    *current = flags & (ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED);
    request
}

/// As flags legadas de um pedido vivo.
pub fn system_state_request(handle: u64) -> Option<u32> {
    POWER_REQUESTS.lock().get(&handle).copied()
}

/// PoUnregisterSystemState(StateHandle).
pub fn unregister_system_state(handle: u64) {
    if handle != 0 && POWER_REQUESTS.lock().remove(&handle).is_some() {
        guest::free_bytes(handle);
    }
}

/// PoSetPowerButtonHoldState(Held).
pub fn set_power_button_hold_state(held: bool) {
    let mut state = POWER_BUTTON.lock();
    let bit = 1u64 << (state.presses.wrapping_add(state.releases) & 63);
    if held {
        state.history |= bit;
        state.presses = state.presses.wrapping_add(1);
    } else {
        state.history &= !bit;
        state.releases = state.releases.wrapping_add(1);
    }
    if held != state.held {
        if held {
            state.holds = state.holds.wrapping_add(1);
        }
        state.held = held;
        state.work_requests = state.work_requests.wrapping_add(1);
    }
}

/// (segurado, pressões, solturas, histórico, pedidos de trabalho).
pub fn power_button_hold_state() -> (bool, u32, u32, u64, u32) {
    let state = POWER_BUTTON.lock();
    (state.held, state.presses, state.releases, state.history, state.work_requests)
}

/// PoSetFixedWakeSource(WakeSource).
pub fn set_fixed_wake_source(source: u32) {
    FIXED_WAKE_SOURCES.fetch_or(source, Ordering::AcqRel);
}

/// PopFixedWakeSourceMask.
pub fn fixed_wake_sources() -> u32 {
    FIXED_WAKE_SOURCES.load(Ordering::Acquire)
}
