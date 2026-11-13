//! Exports Po* com as assinaturas do WDK — `system32/win32/ntoskrnl/po.js`.
//!
//! Só adaptadores: a lógica mora em `ntos::po::power_manager` (estado e
//! power IRPs), `power_setting`, `idle` e `fx` (PoFx). Os ponteiros são
//! lidos e guardados com 64 bits.

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::po::{idle, power_manager, power_setting};
use crate::rtl::KernelError;

/// PoSetPowerState(device, type, state) -> POWER_STATE anterior.
fn set_power_state(call: &Call) -> Result<u64, KernelError> {
    Ok(power_manager::set_power_state(call.arg(1), call.arg(2) as u32, call.arg(3) as u32) as u64)
}

fn start_next_power_irp(call: &Call) -> Result<u64, KernelError> {
    power_manager::start_next_power_irp(call.arg(1));
    Ok(0)
}

fn call_driver(call: &Call) -> Result<u64, KernelError> {
    Ok(power_manager::call_driver_down_the_stack(call.arg(1), call.arg(2)) as u64)
}

/// PoRequestPowerIrp(device, minor, state, completion, context, &irp).
fn request_power_irp(call: &Call) -> Result<u64, KernelError> {
    power_manager::request_power_irp(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6));
    Ok(0)
}

fn register_power_setting_callback(call: &Call) -> Result<u64, KernelError> {
    power_setting::register_callback(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5));
    Ok(0)
}

fn unregister_power_setting_callback(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(power_setting::unregister_callback(call.arg(1))))
}

fn query_watchdog_time(call: &Call) -> Result<u64, KernelError> {
    Ok(power_manager::query_watchdog_time(call.arg(2)) as u64)
}

fn register_device_for_idle_detection(call: &Call) -> Result<u64, KernelError> {
    Ok(idle::register_device(call.arg(1)))
}

fn set_device_busy_ex(call: &Call) -> Result<u64, KernelError> {
    idle::set_device_busy(call.arg(1));
    Ok(0)
}

pub static GROUP: Group = Group {
    name: "po",
    names: &["PoSetPowerState", "PoStartNextPowerIrp", "PoCallDriver", "PoRequestPowerIrp", "PoRegisterPowerSettingCallback", "PoUnregisterPowerSettingCallback", "PoQueryWatchdogTime", "PoRegisterDeviceForIdleDetection", "PoSetDeviceBusyEx"],
    handlers: &[set_power_state, start_next_power_irp, call_driver, request_power_irp, register_power_setting_callback, unregister_power_setting_callback, query_watchdog_time, register_device_for_idle_detection, set_device_busy_ex],
    data_exports: &[],
};

pub mod po_fx {
    //! Adaptadores PoFx*: o motor inerte mora em `ntos::po::fx`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::po::fx;
    use crate::rtl::KernelError;

    /// PoFxRegisterDevice(PDEVICE_OBJECT Pdo, PPO_FX_DEVICE Dev, POHANDLE* Handle).
    fn register_device(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(fx::register_device(call.arg(2), call.arg(3))))
    }

    fn start_device_power_management(call: &Call) -> Result<u64, KernelError> {
        fx::start_device_power_management(call.arg(1));
        Ok(0)
    }

    fn activate_component(call: &Call) -> Result<u64, KernelError> {
        fx::activate_component(call.arg(1), call.arg(2) as u32);
        Ok(0)
    }

    fn idle_component(call: &Call) -> Result<u64, KernelError> {
        fx::idle_component(call.arg(1), call.arg(2) as u32);
        Ok(0)
    }

    fn report_device_powered_on(call: &Call) -> Result<u64, KernelError> {
        fx::report_device_powered_on(call.arg(1));
        Ok(0)
    }

    fn unregister_device(call: &Call) -> Result<u64, KernelError> {
        fx::unregister_device(call.arg(1));
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

    fn power_control(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(fx::power_control()))
    }

    /// Perf-state e crashdump (veja `fx::unsupported_request`).
    fn not_supported(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(fx::unsupported_request()))
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
