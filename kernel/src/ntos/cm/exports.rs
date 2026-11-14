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

pub mod cm_key_notify {
    use crate::ntos::cm::key::notify;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn notify_change_key(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(notify::notify_change_key(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6) as u32, call.arg(7) & 0xFF != 0, call.arg(8), call.arg(9) as u32, call.arg(10) & 0xFF != 0)))
    }

    pub static GROUP: Group = Group { name: "cm-key-notify", names: &["ZwNotifyChangeKey"], handlers: &[notify_change_key], data_exports: &[] };
}

pub mod cm_machine_hive_notify {
    //! Cm(Un)RegisterMachineHiveLoadedNotification; a lógica mora em
    //! `cm/machine_hive`.

    use crate::ntos::cm::machine_hive;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// CmRegisterMachineHiveLoadedNotification(Callback, Context, MountPoint, Handle*).
    fn register(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(machine_hive::register(call.arg(1), call.arg(2), call.arg(3), call.arg(4))?))
    }

    /// CmUnregisterMachineHiveLoadedNotification(Handle).
    fn unregister(call: &Call) -> Result<u64, KernelError> {
        machine_hive::unregister(call.arg(1))?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "cm-machine-hive-notify",
        names: &["CmRegisterMachineHiveLoadedNotification", "CmUnregisterMachineHiveLoadedNotification"],
        handlers: &[register, unregister],
        data_exports: &[],
    };
}
