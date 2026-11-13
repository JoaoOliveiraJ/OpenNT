//! Exports Whea* do ntoskrnl (adaptadores; a lógica está em `error_source`).

pub mod whea_error_source {
    use crate::ntos::inc::types::extra_storage::{WheaErrorRecordHeader, WheaErrorSourceConfigurationDeviceDriverV1, WheaErrorSourceDescriptor};
    use crate::ntos::inc::types::NtStruct;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::whea::error_source;
    use crate::rtl::KernelError;

    fn add_error_source(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: WHEA_ERROR_SOURCE_DESCRIPTOR de um driver de modo kernel.
        let descriptor = unsafe { WheaErrorSourceDescriptor::at(call.arg(1)) };
        Ok(signed_status(error_source::add_error_source(descriptor, call.arg(2))))
    }

    fn add_error_source_device_driver_v1(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 de um driver de modo kernel.
        let configuration = unsafe { WheaErrorSourceConfigurationDeviceDriverV1::at(call.arg(2)) };
        Ok(signed_status(error_source::add_device_driver_source_v1(call.arg(1), configuration, call.arg(3) as u32, call.arg(4) as u32)))
    }

    fn configure_error_source(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(error_source::configure_error_source(call.arg(1) as u32, call.arg(2))))
    }

    fn get_error_source(call: &Call) -> Result<u64, KernelError> {
        Ok(error_source::get_error_source(call.arg(1) as u32))
    }

    fn initialize_record_header(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: WHEA_ERROR_RECORD_HEADER de um driver de modo kernel.
        let header = unsafe { WheaErrorRecordHeader::at(call.arg(1)) };
        Ok(signed_status(error_source::initialize_record_header(header)))
    }

    fn remove_error_source(call: &Call) -> Result<u64, KernelError> {
        error_source::remove_error_source(call.arg(1) as u32);
        Ok(0)
    }

    fn report_fatal_hw_error_device_driver_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(error_source::report_device_driver_error(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(7), 1, true)))
    }

    fn report_hw_error(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(error_source::report_hw_error(call.arg(1))))
    }

    fn report_hw_error_device_driver_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(error_source::report_device_driver_error(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(7), call.arg(9) as u32, false)))
    }

    fn unconfigure_error_source(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(error_source::unconfigure_error_source(call.arg(1) as u32)))
    }

    pub static GROUP: Group = Group {
        name: "whea-error-source",
        names: &[
            "WheaAddErrorSource", "WheaAddErrorSourceDeviceDriverV1", "WheaConfigureErrorSource", "WheaGetErrorSource", "WheaInitializeRecordHeader",
            "WheaRemoveErrorSource", "WheaReportFatalHwErrorDeviceDriverEx", "WheaReportHwError", "WheaReportHwErrorDeviceDriverEx", "WheaUnconfigureErrorSource",
        ],
        handlers: &[
            add_error_source, add_error_source_device_driver_v1, configure_error_source, get_error_source, initialize_record_header,
            remove_error_source, report_fatal_hw_error_device_driver_ex, report_hw_error, report_hw_error_device_driver_ex, unconfigure_error_source,
        ],
        data_exports: &[],
    };
}
