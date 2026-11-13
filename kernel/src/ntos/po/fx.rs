//! PoFx — o power framework de runtime (PoFx*) com um motor inerte.
//!
//! Registra os dispositivos PO_FX_DEVICE_V1 com o layout interno real do
//! POHANDLE (ComponentCount em +0x33c, vetor de componentes em +0x340) e
//! mantém cada dispositivo em D0 e cada componente em F0: os callbacks que o
//! driver precisa para concluir o handshake de energia são disparados, os de
//! ociosidade nunca. Sem PEP, os pedidos de controle, perf-state e crashdump
//! recebem a resposta de um ntoskrnl sem esses recursos.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{Field, NtStruct, PoFxDeviceV1, PopFxDevice};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// Handle (internal POHANDLE context block) offsets, per the disassembly.

/// Each component sub-block is large enough to cover the active-condition
/// pending ref (+0x88) and idle-state pending ref (+0x8c) the `Complete*`
/// APIs `lock xadd`, so a driver poking them touches valid guest memory.
const COMPONENT_SIZE: u64 = 0x1B8; // sizeof(POP_FX_COMPONENT)
/// Bit1 of the handle flags: "directed power not required", cleared by
/// PoFxReportDevicePoweredOn (`and ...,0xfffffffd` @0x39f5a8).
const DIRECTED_POWER_FLAG: u32 = 0x2;

/// Index of the two callbacks the inert engine actually fires.
const CB_ACTIVE_CONDITION: usize = 0; // ComponentActiveConditionCallback
const CB_POWER_REQUIRED: usize = 3; // DevicePowerRequiredCallback

struct Component {
    active_refs: u32,
}

struct PoFxDevice {
    device_context: u64,
    /// Snapshot of the six PO_FX_DEVICE_V1 callbacks (0x08..0x30).
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
/// Devolve o NTSTATUS.
pub fn register_device(device: u64, handle_out: u64) -> u32 {
    if device == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: PPO_FX_DEVICE do driver.
    let description = unsafe { PoFxDeviceV1::at(device) };
    // Only PO_FX_DEVICE_V1 is modeled; V2/V3 use a different layout.
    if description.version.get() != 1 {
        return STATUS_NOT_SUPPORTED;
    }

    let component_count = description.component_count.get();
    let device_context = description.device_context.get();
    let callbacks = [
        description.component_active_condition_callback.get(),
        description.component_idle_condition_callback.get(),
        description.component_idle_state_callback.get(),
        description.device_power_required_callback.get(),
        description.device_power_not_required_callback.get(),
        description.power_control_callback.get(),
    ];

    // Opaque handle shaped like POP_FX_DEVICE: Status, ComponentCount and
    // Components (POP_FX_COMPONENT**), whose pointer array follows the body.
    let handle = guest::alloc_bytes(PopFxDevice::SIZE + u64::from(component_count) * 8);
    // SAFETY: freshly allocated block of the body plus the pointer array.
    let body = unsafe { PopFxDevice::at(handle) };
    let array = handle + PopFxDevice::SIZE;
    body.status.value.set(0);
    body.component_count.set(component_count);
    body.components.set(array);

    let mut components = Vec::new();
    let mut component_buffers = Vec::new();
    // SAFETY: the pointer array right after the body.
    let pointers = unsafe { Field::<u64>::array_at(array, component_count as usize) };
    for pointer in pointers {
        let buffer = guest::alloc_bytes(COMPONENT_SIZE);
        pointer.set(buffer);
        components.push(Component { active_refs: 0 });
        component_buffers.push(buffer);
    }

    DEVICES.lock().insert(
        handle,
        PoFxDevice { device_context, callbacks, components, component_buffers },
    );

    if handle_out != 0 {
        // SAFETY: POHANDLE* de saída do driver.
        unsafe { Field::<u64>::at(handle_out) }.set(handle);
    }
    0
}

/// PoFxStartDevicePowerManagement(POHANDLE): bring the device to D0 and keep
/// it there. The inert engine fires DevicePowerRequiredCallback once (the
/// device is always powered) and never issues DevicePowerNotRequired, so the
/// driver's power-up handshake completes and it reaches steady state in D0.
pub fn start_device_power_management(handle: u64) {
    let fire = DEVICES
        .lock()
        .get(&handle)
        .map(|device| (device.callbacks[CB_POWER_REQUIRED], device.device_context));
    if let Some((callback, context)) = fire {
        if callback != 0 {
            native_call::call(callback, &[context]);
        }
    }
}

/// PoFxActivateComponent(POHANDLE, ULONG Component, ULONG Flags): bounds-check
/// `Component < ComponentCount`, bump the component's active ref, and on the
/// 0->1 edge fire ComponentActiveConditionCallback so the driver's state
/// machine advances (the component becomes active/F0). Flags ignored (inert).
pub fn activate_component(handle: u64, component: u32) {
    let fire = {
        let mut devices = DEVICES.lock();
        let Some(device) = devices.get_mut(&handle) else { return };
        let callback = device.callbacks[CB_ACTIVE_CONDITION];
        let context = device.device_context;
        let Some(entry) = device.components.get_mut(component as usize) else { return };
        entry.active_refs += 1;
        (entry.active_refs == 1).then_some((callback, context))
    };
    if let Some((callback, context)) = fire {
        if callback != 0 {
            native_call::call(callback, &[context, u64::from(component)]);
        }
    }
}

/// PoFxIdleComponent(POHANDLE, ULONG Component, ULONG Flags): drop the active
/// ref. The inert engine keeps the component at F0 (never forces a real
/// F-state drop), so no idle-condition/idle-state callbacks are fired — the
/// driver's idle callbacks are optional and the device stays powered.
pub fn idle_component(handle: u64, component: u32) {
    if let Some(device) = DEVICES.lock().get_mut(&handle) {
        if let Some(entry) = device.components.get_mut(component as usize) {
            entry.active_refs = entry.active_refs.saturating_sub(1);
        }
    }
}

/// PoFxReportDevicePoweredOn(POHANDLE): the driver acks it re-powered the
/// device; mirror ntoskrnl by clearing bit 1 of POP_FX_DEVICE.Status
/// (LOCK AND). No PEP D0 notification to make.
pub fn report_device_powered_on(handle: u64) {
    if DEVICES.lock().contains_key(&handle) {
        // SAFETY: a handle created by `register_device`.
        let body = unsafe { PopFxDevice::at(handle) };
        body.status.value.atomic().fetch_and(!(DIRECTED_POWER_FLAG as i32), core::sync::atomic::Ordering::SeqCst);
    }
}

/// PoFxUnregisterDevice(POHANDLE): drop the registry entry and free the handle
/// and its component sub-blocks.
pub fn unregister_device(handle: u64) {
    let removed = DEVICES.lock().remove(&handle);
    if let Some(device) = removed {
        for buffer in device.component_buffers {
            guest::free_bytes(buffer);
        }
        guest::free_bytes(handle);
    }
}

/// PoFxPowerControl(POHANDLE, LPCGUID, In, InSz, Out, OutSz, PSIZE_T): with no
/// PEP to service the control code, Windows returns STATUS_NOT_IMPLEMENTED.
pub fn power_control() -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// Perf-state (PoFxIssueComponentPerfStateChange, PoFxRegisterComponentPerfStates)
/// and crashdump (PoFxRegisterCrashdumpDevice @0x78ea90 itself returns
/// 0xC00000BB when no crashdump callback is present, PoFxPowerOnCrashdumpDevice):
/// OpenNT has no PEP perf engine and no crashdump device support, so the honest
/// inert answer is STATUS_NOT_SUPPORTED — the driver skips those features and
/// runs the device at full perf.
pub fn unsupported_request() -> u32 {
    STATUS_NOT_SUPPORTED
}
