//! Power Manager (Po*).
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
use crate::ntos::inc::types::{DeviceObject, DevicePowerState, Field, IoStackLocation, Irp, NtStruct, PowerStateType};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// Quem despacha power IRPs para baixo (registrado pelo I/O Manager, o que
/// quebra o ciclo `io_manager` <-> `power_manager`).
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
    STATE.lock().current.get(&device).copied().unwrap_or(DevicePowerState::POWER_DEVICE_D0.0 as u32)
}

/// PoSetPowerState(device, POWER_STATE_TYPE, POWER_STATE) -> estado anterior.
/// SystemPowerState não é rastreado por dispositivo.
pub fn set_power_state(device: u64, state_type: u32, new_state: u32) -> u32 {
    if state_type != PowerStateType::DEVICE_POWER_STATE.0 as u32 {
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

/// PoCallDriver: no ntoskrnl 19041 (rva 0x39a1f0) é o IofCallDriver — o
/// IRP de energia desce para `device` (a próxima posição de pilha passa a
/// ser a corrente) e vai ao MajorFunction[IRP_MJ_POWER] do driver dele.
pub fn call_driver_down_the_stack(device: u64, irp: u64) -> u32 {
    io_manager::iof_call_driver(device, irp) as u32
}

/// Dispositivo dono do IRP: CurrentStackLocation->DeviceObject.
fn device_of_irp(packet: u64) -> u64 {
    // SAFETY: IRP vivo do chamador e sua pilha corrente.
    let stack = unsafe { Irp::at(packet) }.tail.overlay.current_stack_location.get();
    // SAFETY: IO_STACK_LOCATION corrente do IRP.
    unsafe { IoStackLocation::at(stack) }.device_object.get()
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
///
/// Como o PopRequestPowerIrp do ntoskrnl 19041: o IRP vai ao topo da pilha
/// do dispositivo (IoGetAttachedDeviceReference) com o tamanho de pilha
/// dele, IoStatus = STATUS_NOT_SUPPORTED, e desce pelo IofCallDriver; a
/// conclusão do Po chama o PREQUEST_POWER_COMPLETE (o POWER_STATE por
/// valor) e libera o IRP. Devolve STATUS_PENDING.
pub fn request_power_irp(device: u64, minor: u32, state: u32, completion: u64, context: u64, irp_out: u64) -> u32 {
    let top = crate::ntos::ob::objects::device::top(device);
    let top = if top != 0 { top } else { device };
    // SAFETY: DEVICE_OBJECT do topo da pilha.
    let stack_count = match unsafe { DeviceObject::at(top) }.stack_size.get() as u8 {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(stack_count));
    if packet == 0 {
        return 0xC000_009A;
    }
    irp_builder::build(packet, &BuildOptions { major: 0x16, minor: minor as u8, device_object: top, stack_count, power: Some(Power { power_state_type: 1, device_state: state }), ..Default::default() });
    // O IofCallDriver abaixo desce uma posição: a posição do primeiro driver
    // é a de cima, a que o build preencheu.
    // SAFETY: o IRP recém-construído.
    let irp = unsafe { Irp::at(packet) };
    irp.io_status.status.set(0xC000_00BBu32 as i32);
    if irp_out != 0 {
        // SAFETY: PIRP* opcional do chamador.
        unsafe { Field::<u64>::at(irp_out) }.set(packet);
    }
    io_manager::manage_completion(
        packet,
        alloc::boxed::Box::new(move |_, _| {
            if completion != 0 {
                // SAFETY: o IRP continua vivo até o fim desta conclusão.
                let io_status = unsafe { Irp::at(packet) }.io_status.address();
                native_call::call(completion, &[device, minor as u64, state as u64, context, io_status]);
            }
            guest::free_bytes(packet);
        }),
    );
    io_manager::iof_call_driver(top, packet);
    0x103
}

/// PoQueryWatchdogTime(Pdo, &seconds): nenhum watchdog armado, *seconds = 0
/// e FALSE.
pub fn query_watchdog_time(seconds_out: u64) -> bool {
    if seconds_out != 0 {
        // SAFETY: PULONG opcional do chamador.
        unsafe { Field::<u32>::at(seconds_out) }.set(0);
    }
    false
}

/// Os pedidos de PoDisableSleepStates vivos (a PopDisableSleepList): cada
/// um é um bloco de pool 'PoSd' de 0x18 bytes (LIST_ENTRY, Flags e
/// SleepStates) que o driver recebe como handle.
static DISABLE_SLEEP_LIST: SpinLock<alloc::vec::Vec<u64>> = SpinLock::new(alloc::vec::Vec::new());
const DISABLE_SLEEP_TAG: u32 = 0x6453_6F50;

/// PoDisableSleepStates(Flags, SleepStates, Handle) (ntoskrnl 19041 rva
/// 0x8e3b90): o pedido entra na lista e o handle vai a *Handle;
/// STATUS_SUCCESS, ou STATUS_INSUFFICIENT_RESOURCES sem pool. O OpenNT não
/// entra em estados de sono, então a lista só registra quem os bloqueia.
pub fn disable_sleep_states(flags: u32, sleep_states: u32, handle_out: u64) -> u32 {
    let block = crate::ntos::ex::pool_allocation::allocate_tagged(1, 0x18, DISABLE_SLEEP_TAG).unwrap_or(0);
    if block == 0 {
        return 0xC000_009A;
    }
    guest::write64(block, 0);
    guest::write64(block + 8, 0);
    guest::write32(block + 0x10, flags);
    guest::write32(block + 0x14, sleep_states);
    DISABLE_SLEEP_LIST.lock().push(block);
    // SAFETY: o PVOID* Handle do chamador de modo kernel.
    unsafe { Field::<u64>::at(handle_out) }.set(block);
    0
}

/// PoReenableSleepStates(Handle): o pedido sai da lista e o bloco volta ao
/// pool; um handle que não está na lista é corrupção da lista
/// (__fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY) no NT).
pub fn reenable_sleep_states(handle: u64) {
    let removed = {
        let mut list = DISABLE_SLEEP_LIST.lock();
        let position = list.iter().position(|&block| block == handle);
        position.map(|index| list.remove(index))
    };
    match removed {
        Some(block) => {
            let _ = crate::ntos::ex::pool_allocation::free(block, DISABLE_SLEEP_TAG as u64);
        }
        None => crate::ntos::ke::bugcheck::bug_check_ex(0x139, 3, handle, 0, 0),
    }
}

/// Pedidos de bloqueio de sono vivos (autoteste).
pub fn disabled_sleep_requests() -> usize {
    DISABLE_SLEEP_LIST.lock().len()
}
