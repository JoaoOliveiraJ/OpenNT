//! Exports Po* com as assinaturas do WDK — `system32/win32/ntoskrnl/po.js`.
//!
//! A lógica mora em `ntos::po::power_manager`. Os ponteiros são lidos e
//! guardados com 64 bits.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::io::irp_builder::{self, BuildOptions, Power};
use crate::hal::amd64::native_call;
use crate::ntos::io::io_manager;
use crate::ntos::po::power_manager;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{device_object, io_stack_location, irp};

/// Callback de power setting (disparado quando um setting muda; hoje
/// nenhum muda).
struct PowerSettingCallback {
    callback: u64,
    _context: u64,
    _device: u64,
    _setting_guid: u64,
}

static POWER_SETTING_CALLBACKS: SpinLock<Vec<PowerSettingCallback>> = SpinLock::new(Vec::new());
/// Contadores de ociosidade por dispositivo.
static IDLE_COUNTERS: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

/// Dispositivo dono do IRP: CurrentStackLocation->DeviceObject.
fn device_of_irp(packet: u64) -> u64 {
    let stack = guest::read64(packet + irp::CURRENT_STACK_LOCATION);
    guest::read64(stack + io_stack_location::DEVICE_OBJECT)
}

/// PoSetPowerState(device, type, state) -> POWER_STATE anterior.
fn set_power_state(call: &Call) -> Result<u64, KernelError> {
    Ok(power_manager::set_power_state(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}

fn start_next_power_irp(call: &Call) -> Result<u64, KernelError> {
    power_manager::start_next_power_request(device_of_irp(call.arg(1)));
    Ok(0)
}

fn call_driver(call: &Call) -> Result<u64, KernelError> {
    Ok(power_manager::call_driver_down_the_stack(call.arg(1), call.arg(2)) as u64)
}

/// Constrói e despacha um IRP de energia real (QUERY/SET) e chama a
/// conclusão com a assinatura do wdm.h (device, minor, state, contexto,
/// IO_STATUS_BLOCK).
fn request_power_irp(call: &Call) -> Result<u64, KernelError> {
    let device = call.arg(1);
    let minor = call.arg(2) as u32;
    let state = call.arg(3) as u32;
    let stack_count = match guest::read8(device + device_object::STACK_SIZE) {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(stack_count));
    irp_builder::build(packet, &BuildOptions { major: 0x16, minor: minor as u8, device_object: device, stack_count, power: Some(Power { power_state_type: 1, device_state: state }), ..Default::default() });
    if call.arg(6) != 0 {
        guest::write64(call.arg(6), packet);
    }
    io_manager::dispatch_native_power_irp(device, packet);
    if call.arg(4) != 0 {
        native_call::call(call.arg(4), &[device, minor as u64, state as u64, call.arg(5), packet + irp::IO_STATUS]);
    }
    guest::free_bytes(packet);
    Ok(0)
}

fn register_power_setting_callback(call: &Call) -> Result<u64, KernelError> {
    POWER_SETTING_CALLBACKS.lock().push(PowerSettingCallback { callback: call.arg(3), _context: call.arg(4), _device: call.arg(1), _setting_guid: call.arg(2) });
    if call.arg(5) != 0 {
        guest::write64(call.arg(5), call.arg(3));
    }
    Ok(0)
}

fn unregister_power_setting_callback(call: &Call) -> Result<u64, KernelError> {
    let mut callbacks = POWER_SETTING_CALLBACKS.lock();
    let Some(index) = callbacks.iter().position(|entry| entry.callback == call.arg(1)) else { return Ok(signed_status(0xC000_0225)) };
    callbacks.remove(index);
    Ok(0)
}

/// Nenhum watchdog armado: *seconds = 0.
fn query_watchdog_time(call: &Call) -> Result<u64, KernelError> {
    if call.arg(2) != 0 {
        guest::write32(call.arg(2), 0);
    }
    Ok(0)
}

/// O contador de ociosidade real do dispositivo (zerado por
/// PoSetDeviceBusyEx).
fn register_device_for_idle_detection(call: &Call) -> Result<u64, KernelError> {
    let counter = guest::alloc_bytes(4);
    IDLE_COUNTERS.lock().insert(call.arg(1), counter);
    Ok(counter)
}

fn set_device_busy_ex(call: &Call) -> Result<u64, KernelError> {
    guest::write32(call.arg(1), 0);
    Ok(0)
}

pub static GROUP: Group = Group {
    name: "po",
    names: &["PoSetPowerState", "PoStartNextPowerIrp", "PoCallDriver", "PoRequestPowerIrp", "PoRegisterPowerSettingCallback", "PoUnregisterPowerSettingCallback", "PoQueryWatchdogTime", "PoRegisterDeviceForIdleDetection", "PoSetDeviceBusyEx"],
    handlers: &[set_power_state, start_next_power_irp, call_driver, request_power_irp, register_power_setting_callback, unregister_power_setting_callback, query_watchdog_time, register_device_for_idle_detection, set_device_busy_ex],
    data_exports: &[],
};
