//! Exports Ttm* do ntoskrnl; a lógica mora em `ttm/device`.

pub mod ttm_device_notifications {
    //! TtmNotifyDeviceArrival, TtmNotifyDeviceDeparture e TtmNotifyDeviceInput.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ttm::device;
    use crate::rtl::KernelError;

    /// TtmNotifyDeviceArrival(DeviceType, DeviceToken, Properties, Flags, Name).
    fn notify_device_arrival(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(device::notify_device_arrival(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5))))
    }

    /// TtmNotifyDeviceDeparture(DeviceType, DeviceToken).
    fn notify_device_departure(call: &Call) -> Result<u64, KernelError> {
        device::notify_device_departure(call.arg(1) as u32, call.arg(2));
        Ok(0)
    }

    /// TtmNotifyDeviceInput(DeviceType, DeviceToken, Flags).
    fn notify_device_input(call: &Call) -> Result<u64, KernelError> {
        device::notify_device_input(call.arg(1) as u32, call.arg(2), call.arg(3) as u32);
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ttm-device-notifications",
        names: &["TtmNotifyDeviceArrival", "TtmNotifyDeviceDeparture", "TtmNotifyDeviceInput"],
        handlers: &[notify_device_arrival, notify_device_departure, notify_device_input],
        data_exports: &[],
    };
}
