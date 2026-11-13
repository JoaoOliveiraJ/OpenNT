//! Power Manager (Po*) — `system32/ntos/po/power-manager.js`.
//!
//! Estado de energia corrente de cada DEVICE_OBJECT (D0..D3), fila de power
//! IRPs pendentes por dispositivo e encaminhamento pela pilha
//! (AttachedDevice), como o Po do ntoskrnl:
//! - PoSetPowerState devolve o estado ANTERIOR (semântica do WDK);
//! - PoStartNextPowerIrp dispara o próximo power IRP enfileirado;
//! - PoCallDriver desce o power IRP pela pilha até o fundo.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{device_object, device_power_state, power_state_type};

/// Quem despacha power IRPs para baixo (registrado pelo I/O Manager, o que
/// quebra o ciclo io-manager <-> power-manager).
pub type Dispatcher = fn(u64, u64) -> u32;

struct State {
    dispatcher: Option<Dispatcher>,
    current: BTreeMap<u64, u32>,
    pending: BTreeMap<u64, VecDeque<u64>>,
    in_flight: BTreeSet<u64>,
}

static STATE: SpinLock<State> = SpinLock::new(State { dispatcher: None, current: BTreeMap::new(), pending: BTreeMap::new(), in_flight: BTreeSet::new() });

pub fn register_power_irp_dispatcher(dispatcher: Dispatcher) {
    STATE.lock().dispatcher = Some(dispatcher);
}

/// Troca o despachante e devolve o anterior (testes e reinicialização).
pub fn set_power_irp_dispatcher(dispatcher: Option<Dispatcher>) -> Option<Dispatcher> {
    core::mem::replace(&mut STATE.lock().dispatcher, dispatcher)
}

pub fn get_device_power_state(device: u64) -> u32 {
    STATE.lock().current.get(&device).copied().unwrap_or(device_power_state::D0)
}

/// PoSetPowerState(device, POWER_STATE_TYPE, POWER_STATE) -> estado anterior.
/// SystemPowerState não é rastreado por dispositivo.
pub fn set_power_state(device: u64, state_type: u32, new_state: u32) -> u32 {
    if state_type != power_state_type::DEVICE_POWER_STATE {
        return new_state;
    }
    let previous = get_device_power_state(device);
    STATE.lock().current.insert(device, new_state);
    previous
}

pub fn forget_device(device: u64) {
    let mut state = STATE.lock();
    state.current.remove(&device);
    state.pending.remove(&device);
    state.in_flight.remove(&device);
}

/// Enfileira atrás do IRP em processamento; `true` = ficou na fila.
pub fn queue_power_request(device: u64, irp: u64) -> bool {
    let mut state = STATE.lock();
    state.pending.entry(device).or_default().push_back(irp);
    state.in_flight.contains(&device)
}

pub fn mark_power_request_started(device: u64) {
    STATE.lock().in_flight.insert(device);
}

pub fn mark_power_request_done(device: u64) {
    STATE.lock().in_flight.remove(&device);
}

/// PoStartNextPowerIrp: dispara o próximo power IRP do dispositivo.
pub fn start_next_power_request(device: u64) {
    let (next, dispatcher) = {
        let mut state = STATE.lock();
        let next = state.pending.get_mut(&device).and_then(VecDeque::pop_front);
        (next, state.dispatcher)
    };
    if let (Some(irp), Some(dispatcher)) = (next, dispatcher) {
        dispatcher(device, irp);
    }
}

/// PoCallDriver: no fundo da pilha (sem dispositivo anexado) o IRP fica com
/// o status que já tem. AttachedDevice é lido como DWORD, como no original.
pub fn call_driver_down_the_stack(device: u64, irp: u64) -> u32 {
    let attached = guest::read32(device + device_object::ATTACHED_DEVICE) as u64;
    if attached == 0 {
        return 0;
    }
    let dispatcher = STATE.lock().dispatcher;
    dispatcher.map_or(0, |dispatcher| dispatcher(attached, irp))
}
