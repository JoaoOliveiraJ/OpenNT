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

pub mod po_fx {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    use crate::hal::amd64::native_call;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::rtl::{KernelError, SpinLock};

    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

    /// Handle (internal POHANDLE context block) offsets, per the disassembly.
    const FLAGS_OFFSET: u64 = 0x20;
    const COMPONENT_COUNT_OFFSET: u64 = 0x33c;
    const COMPONENT_ARRAY_OFFSET: u64 = 0x340;
    /// Each component sub-block is large enough to cover the active-condition
    /// pending ref (+0x88) and idle-state pending ref (+0x8c) the `Complete*`
    /// APIs `lock xadd`, so a driver poking them touches valid guest memory.
    const COMPONENT_SIZE: u64 = 0x90;
    /// Bit1 of the handle flags: "directed power not required", cleared by
    /// PoFxReportDevicePoweredOn (`and ...,0xfffffffd` @0x39f5a8).
    const DIRECTED_POWER_FLAG: u32 = 0x2;

    /// Index of the two callbacks the inert engine actually fires.
    const CB_ACTIVE_CONDITION: usize = 0; // device + 0x10
    const CB_POWER_REQUIRED: usize = 3; // device + 0x28

    struct Component {
        active_refs: u32,
    }

    struct PoFxDevice {
        device_context: u64,
        /// Snapshot of the six PO_FX_DEVICE_V1 callbacks (0x10..0x38).
        callbacks: [u64; 6],
        components: Vec<Component>,
        /// Guest component sub-blocks to free on unregister.
        component_buffers: Vec<u64>,
    }

    /// Registry keyed on the POHANDLE value we hand back to the driver.
    static DEVICES: SpinLock<BTreeMap<u64, PoFxDevice>> = SpinLock::new(BTreeMap::new());

    /// PoFxRegisterDevice(PDEVICE_OBJECT Pdo, PPO_FX_DEVICE Dev, POHANDLE* Handle).
    /// Validates Version==1, snapshots DeviceContext + 6 callbacks, allocates the
    /// opaque handle with the real internal layout, writes `*Handle`, SUCCESS.
    fn register_device(call: &Call) -> Result<u64, KernelError> {
        let device = call.arg(2);
        let handle_out = call.arg(3);
        if device == 0 {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        }
        // Only PO_FX_DEVICE_V1 is modeled; V2/V3 use a different layout.
        if guest::read32(device) != 1 {
            return Ok(signed_status(STATUS_NOT_SUPPORTED));
        }

        let component_count = guest::read32(device + 0x04);
        let device_context = guest::read64(device + 0x08);
        let callbacks = [
            guest::read64(device + 0x10), // ComponentActiveConditionCallback
            guest::read64(device + 0x18), // ComponentIdleConditionCallback
            guest::read64(device + 0x20), // ComponentIdleStateCallback
            guest::read64(device + 0x28), // DevicePowerRequiredCallback
            guest::read64(device + 0x30), // DevicePowerNotRequiredCallback
            guest::read64(device + 0x38), // PowerControlCallback
        ];

        // Opaque handle with ComponentCount @+0x33c and the component array
        // @+0x340, exactly where the real component APIs index.
        let handle = guest::alloc_bytes(COMPONENT_ARRAY_OFFSET + u64::from(component_count) * 8);
        guest::write32(handle + FLAGS_OFFSET, 0);
        guest::write32(handle + COMPONENT_COUNT_OFFSET, component_count);

        let mut components = Vec::new();
        let mut component_buffers = Vec::new();
        for index in 0..u64::from(component_count) {
            let buffer = guest::alloc_bytes(COMPONENT_SIZE);
            guest::write64(handle + COMPONENT_ARRAY_OFFSET + index * 8, buffer);
            components.push(Component { active_refs: 0 });
            component_buffers.push(buffer);
        }

        DEVICES.lock().insert(
            handle,
            PoFxDevice { device_context, callbacks, components, component_buffers },
        );

        if handle_out != 0 {
            guest::write64(handle_out, handle);
        }
        Ok(0)
    }

    /// PoFxStartDevicePowerManagement(POHANDLE): bring the device to D0 and keep
    /// it there. The inert engine fires DevicePowerRequiredCallback once (the
    /// device is always powered) and never issues DevicePowerNotRequired, so the
    /// driver's power-up handshake completes and it reaches steady state in D0.
    fn start_device_power_management(call: &Call) -> Result<u64, KernelError> {
        let handle = call.arg(1);
        let fire = DEVICES
            .lock()
            .get(&handle)
            .map(|device| (device.callbacks[CB_POWER_REQUIRED], device.device_context));
        if let Some((callback, context)) = fire {
            if callback != 0 {
                native_call::call(callback, &[context]);
            }
        }
        Ok(0)
    }

    /// PoFxActivateComponent(POHANDLE, ULONG Component, ULONG Flags): bounds-check
    /// `Component < ComponentCount`, bump the component's active ref, and on the
    /// 0->1 edge fire ComponentActiveConditionCallback so the driver's state
    /// machine advances (the component becomes active/F0). Flags ignored (inert).
    fn activate_component(call: &Call) -> Result<u64, KernelError> {
        let handle = call.arg(1);
        let component = call.arg(2) as u32;
        let fire = {
            let mut devices = DEVICES.lock();
            let Some(device) = devices.get_mut(&handle) else { return Ok(0) };
            let callback = device.callbacks[CB_ACTIVE_CONDITION];
            let context = device.device_context;
            let Some(entry) = device.components.get_mut(component as usize) else { return Ok(0) };
            entry.active_refs += 1;
            (entry.active_refs == 1).then_some((callback, context))
        };
        if let Some((callback, context)) = fire {
            if callback != 0 {
                native_call::call(callback, &[context, u64::from(component)]);
            }
        }
        Ok(0)
    }

    /// PoFxIdleComponent(POHANDLE, ULONG Component, ULONG Flags): drop the active
    /// ref. The inert engine keeps the component at F0 (never forces a real
    /// F-state drop), so no idle-condition/idle-state callbacks are fired — the
    /// driver's idle callbacks are optional and the device stays powered.
    fn idle_component(call: &Call) -> Result<u64, KernelError> {
        let handle = call.arg(1);
        let component = call.arg(2) as u32;
        if let Some(device) = DEVICES.lock().get_mut(&handle) {
            if let Some(entry) = device.components.get_mut(component as usize) {
                entry.active_refs = entry.active_refs.saturating_sub(1);
            }
        }
        Ok(0)
    }

    /// PoFxReportDevicePoweredOn(POHANDLE): the driver acks it re-powered the
    /// device; mirror ntoskrnl by clearing the directed-power flag (bit1 of the
    /// handle flags @+0x20). No PEP D0 notification to make.
    fn report_device_powered_on(call: &Call) -> Result<u64, KernelError> {
        let handle = call.arg(1);
        if DEVICES.lock().contains_key(&handle) {
            let flags = guest::read32(handle + FLAGS_OFFSET) & !DIRECTED_POWER_FLAG;
            guest::write32(handle + FLAGS_OFFSET, flags);
        }
        Ok(0)
    }

    /// PoFxUnregisterDevice(POHANDLE): drop the registry entry and free the handle
    /// and its component sub-blocks.
    fn unregister_device(call: &Call) -> Result<u64, KernelError> {
        let handle = call.arg(1);
        let removed = DEVICES.lock().remove(&handle);
        if let Some(device) = removed {
            for buffer in device.component_buffers {
                guest::free_bytes(buffer);
            }
            guest::free_bytes(handle);
        }
        Ok(0)
    }

    /// Pure bookkeeping / handshake acks with no inert effect, returning void:
    /// PoFxCompleteIdleCondition/IdleState, PoFxCompleteDevicePowerNotRequired,
    /// PoFxCompleteDirectedPowerDown (we never actually idle or power down),
    /// PoFxSetComponentLatency/Residency, PoFxSetDeviceIdleTimeout (latency/
    /// residency/timeout hints have no idle engine to feed), PoFxNotifySurprisePowerOn
    /// (device is already powered) and PoFxEnableDStateReporting (STATUS_SUCCESS;
    /// the device stays D0, so there is never a D-state change to report).
    fn inert_void(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// PoFxPowerControl(POHANDLE, LPCGUID, In, InSz, Out, OutSz, PSIZE_T): with no
    /// PEP to service the control code, Windows returns STATUS_NOT_IMPLEMENTED.
    fn power_control(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_NOT_IMPLEMENTED))
    }

    /// Perf-state (PoFxIssueComponentPerfStateChange, PoFxRegisterComponentPerfStates)
    /// and crashdump (PoFxRegisterCrashdumpDevice @0x78ea90 itself returns
    /// 0xC00000BB when no crashdump callback is present, PoFxPowerOnCrashdumpDevice):
    /// OpenNT has no PEP perf engine and no crashdump device support, so the honest
    /// inert answer is STATUS_NOT_SUPPORTED — the driver skips those features and
    /// runs the device at full perf.
    fn not_supported(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_NOT_SUPPORTED))
    }

    pub static GROUP: Group = Group {
        name: "po-fx",
        names: &[
            "PoFxRegisterDevice",
            "PoFxUnregisterDevice",
            "PoFxStartDevicePowerManagement",
            "PoFxActivateComponent",
            "PoFxIdleComponent",
            "PoFxReportDevicePoweredOn",
            "PoFxCompleteIdleCondition",
            "PoFxCompleteIdleState",
            "PoFxCompleteDevicePowerNotRequired",
            "PoFxCompleteDirectedPowerDown",
            "PoFxSetComponentLatency",
            "PoFxSetComponentResidency",
            "PoFxSetDeviceIdleTimeout",
            "PoFxNotifySurprisePowerOn",
            "PoFxEnableDStateReporting",
            "PoFxPowerControl",
            "PoFxIssueComponentPerfStateChange",
            "PoFxRegisterComponentPerfStates",
            "PoFxRegisterCrashdumpDevice",
            "PoFxPowerOnCrashdumpDevice",
        ],
        handlers: &[
            register_device,
            unregister_device,
            start_device_power_management,
            activate_component,
            idle_component,
            report_device_powered_on,
            inert_void, // PoFxCompleteIdleCondition
            inert_void, // PoFxCompleteIdleState
            inert_void, // PoFxCompleteDevicePowerNotRequired
            inert_void, // PoFxCompleteDirectedPowerDown
            inert_void, // PoFxSetComponentLatency
            inert_void, // PoFxSetComponentResidency
            inert_void, // PoFxSetDeviceIdleTimeout
            inert_void, // PoFxNotifySurprisePowerOn
            inert_void, // PoFxEnableDStateReporting (STATUS_SUCCESS)
            power_control,
            not_supported, // PoFxIssueComponentPerfStateChange
            not_supported, // PoFxRegisterComponentPerfStates
            not_supported, // PoFxRegisterCrashdumpDevice
            not_supported, // PoFxPowerOnCrashdumpDevice
        ],
        data_exports: &[],
    };
}

// =====================================================================
