//! Exports Kse* do ntoskrnl (adaptadores; lógica em `kse/shim_engine.rs`).

pub mod kse_shim_engine {
    //! Adaptador de KseQueryDeviceFlags (lógica em `kse/shim_engine.rs`).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::kse::shim_engine;
    use crate::rtl::KernelError;

    /// (PCWSTR DeviceId, PCWSTR Category, PULONG64 Flags).
    fn query_device_flags(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(shim_engine::query_device_flags(call.arg(1), call.arg(2), call.arg(3))))
    }

    pub static GROUP: Group = Group {
        name: "kse-shim-engine",
        names: &["KseQueryDeviceFlags"],
        handlers: &[query_device_flags],
        data_exports: &[],
    };
}

pub mod kse_shim_registration {
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::kse::shim_engine;
    use crate::rtl::KernelError;

    fn register_shim(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(shim_engine::register_shim(call.arg(1), call.arg(2), call.arg(3) as u32)))
    }

    pub static GROUP: Group = Group { name: "kse-shim-registration", names: &["KseRegisterShim"], handlers: &[register_shim], data_exports: &[] };
}

pub mod kse_shim_registration_ex {
    //! KseRegisterShimEx e KseUnregisterShim (lógica em `kse/shim_engine.rs`).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::kse::shim_engine;
    use crate::rtl::KernelError;

    /// KseRegisterShimEx(Shim, Reserved, Flags, Context) -> NTSTATUS.
    fn register_shim_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(shim_engine::register_shim_ex(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4))))
    }

    /// KseUnregisterShim(Shim, Reserved1, Reserved2) -> NTSTATUS.
    fn unregister_shim(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(shim_engine::unregister_shim(call.arg(1))))
    }

    pub static GROUP: Group = Group { name: "kse-shim-registration-ex", names: &["KseRegisterShimEx", "KseUnregisterShim"], handlers: &[register_shim_ex, unregister_shim], data_exports: &[] };
}
