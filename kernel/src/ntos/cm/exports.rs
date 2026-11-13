//! Exports do Configuration Manager (callbacks de registro).

pub mod registry_callbacks {
    //! Callbacks do registro.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::cm::callbacks;

    fn register_callback_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(callbacks::register(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))? as u64)
    }

    fn unregister_callback(call: &Call) -> Result<u64, KernelError> {
        Ok(callbacks::remove(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "registry-callbacks",
        names: &["CmRegisterCallbackEx", "CmUnRegisterCallback"],
        handlers: &[register_callback_ex, unregister_callback],
        data_exports: &[],
    };
}
