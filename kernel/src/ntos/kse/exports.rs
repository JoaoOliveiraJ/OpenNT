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
