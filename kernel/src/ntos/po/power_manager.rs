//! Power Manager (Po*) — `system32/ntos/po/power-manager.js`.
//!
//! Estado de energia corrente de cada DEVICE_OBJECT (D0..D3), fila de power
//! IRPs pendentes por dispositivo e encaminhamento pela pilha
//! (AttachedDevice), como o Po do ntoskrnl:
//! - PoSetPowerState devolve o estado ANTERIOR (semântica do WDK);
//! - PoStartNextPowerIrp dispara o próximo power IRP enfileirado;
//! - PoCallDriver desce o power IRP pela pilha até o fundo;
//! - PoRequestPowerIrp constrói, despacha e conclui um power IRP real;
//! - PoQueryWatchdogTime responde que nenhum watchdog está armado.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::hal::amd64::native_call;
use crate::ntos::io::io_manager;
use crate::ntos::io::irp_builder::{self, BuildOptions, Power};
use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{device_object, device_power_state, io_stack_location, irp, power_state_type};

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

/// Dispositivo dono do IRP: CurrentStackLocation->DeviceObject.
fn device_of_irp(packet: u64) -> u64 {
    let stack = guest::read64(packet + irp::CURRENT_STACK_LOCATION);
    guest::read64(stack + io_stack_location::DEVICE_OBJECT)
}

/// PoStartNextPowerIrp(Irp): dispara o próximo power IRP do dispositivo
/// dono do IRP.
pub fn start_next_power_irp(packet: u64) {
    start_next_power_request(device_of_irp(packet));
}

/// PoRequestPowerIrp(device, minor, state, completion, context, &irp):
/// constrói e despacha um IRP de energia real (QUERY/SET) e chama a
/// conclusão com a assinatura do wdm.h (device, minor, state, contexto,
/// IO_STATUS_BLOCK).
pub fn request_power_irp(device: u64, minor: u32, state: u32, completion: u64, context: u64, irp_out: u64) {
    let stack_count = match guest::read8(device + device_object::STACK_SIZE) {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(stack_count));
    irp_builder::build(packet, &BuildOptions { major: 0x16, minor: minor as u8, device_object: device, stack_count, power: Some(Power { power_state_type: 1, device_state: state }), ..Default::default() });
    if irp_out != 0 {
        guest::write64(irp_out, packet);
    }
    io_manager::dispatch_native_power_irp(device, packet);
    if completion != 0 {
        native_call::call(completion, &[device, minor as u64, state as u64, context, packet + irp::IO_STATUS]);
    }
    guest::free_bytes(packet);
}

/// PoQueryWatchdogTime(Pdo, &seconds): nenhum watchdog armado, *seconds = 0
/// e FALSE.
pub fn query_watchdog_time(seconds_out: u64) -> bool {
    if seconds_out != 0 {
        guest::write32(seconds_out, 0);
    }
    false
}
