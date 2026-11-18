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

pub mod cm_hive {
    //! Os serviços de hive pelo caminho Zw (PreviousMode de kernel); a lógica
    //! mora em `cm/hive_services` e `cm/hive_list`.

    use crate::ntos::cm::hive_services;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// ZwLoadKey(TargetKey, SourceFile).
    fn load_key(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hive_services::load_key(call.arg(1), call.arg(2), 0, 0, 0, 0, 0, false)))
    }

    /// ZwLoadKeyEx(TargetKey, SourceFile, Flags, TrustClassKey, Event,
    /// DesiredAccess, RootHandle, Reserved).
    fn load_key_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hive_services::load_key(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6) as u32, call.arg(7), false)))
    }

    /// ZwUnloadKey(TargetKey).
    fn unload_key(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hive_services::unload_key(call.arg(1), 0, false, 0, false)))
    }

    /// ZwUnloadKey2(TargetKey, Flags).
    fn unload_key2(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hive_services::unload_key(call.arg(1), call.arg(2) as u32, false, 0, false)))
    }

    /// ZwUnloadKeyEx(TargetKey, Event).
    fn unload_key_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hive_services::unload_key(call.arg(1), 0, true, call.arg(2), false)))
    }

    /// ZwSaveKey(KeyHandle, FileHandle).
    fn save_key(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hive_services::save_key(call.arg(1), call.arg(2), 1, false)))
    }

    /// ZwSaveKeyEx(KeyHandle, FileHandle, Format).
    fn save_key_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hive_services::save_key(call.arg(1), call.arg(2), call.arg(3) as u32, false)))
    }

    /// ZwRestoreKey(KeyHandle, FileHandle, Flags).
    fn restore_key(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hive_services::restore_key(call.arg(1), call.arg(2), call.arg(3) as u32, false)))
    }

    pub static GROUP: Group = Group {
        name: "cm-hive",
        names: &["ZwLoadKey", "ZwLoadKeyEx", "ZwUnloadKey", "ZwUnloadKey2", "ZwUnloadKeyEx", "ZwSaveKey", "ZwSaveKeyEx", "ZwRestoreKey"],
        handlers: &[load_key, load_key_ex, unload_key, unload_key2, unload_key_ex, save_key, save_key_ex, restore_key],
        data_exports: &[],
    };
}

pub mod cm_callback_objects {
    //! O CmRegisterCallback legado e as rotinas que os filtros de registro
    //! chamam sobre os objetos das notificações; a lógica mora em
    //! `cm/callbacks`.

    use crate::ntos::cm::callbacks;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// CmRegisterCallback(Function, Context, Cookie*).
    fn register_callback(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(callbacks::register_legacy(call.arg(1), call.arg(2), call.arg(3))?))
    }

    /// CmCallbackGetKeyObjectID(Cookie, Object, ObjectID*, ObjectName**).
    fn get_key_object_id(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(callbacks::get_key_object_id(call.arg(1), call.arg(2), call.arg(3), call.arg(4))))
    }

    /// CmCallbackGetKeyObjectIDEx(Cookie, Object, ObjectID*, ObjectName**, Flags).
    fn get_key_object_id_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(callbacks::get_key_object_id_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32)))
    }

    /// CmCallbackReleaseKeyObjectIDEx(ObjectName).
    fn release_key_object_id_ex(call: &Call) -> Result<u64, KernelError> {
        callbacks::release_key_object_id_ex(call.arg(1))?;
        Ok(0)
    }

    /// CmSetCallbackObjectContext(Object, Cookie*, NewContext, OldContext*).
    fn set_callback_object_context(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(callbacks::set_object_context(call.arg(1), call.arg(2), call.arg(3), call.arg(4))))
    }

    /// CmGetBoundTransaction(Cookie, Object).
    fn get_bound_transaction(call: &Call) -> Result<u64, KernelError> {
        Ok(callbacks::bound_transaction(call.arg(1), call.arg(2)))
    }

    /// CmGetCallbackVersion(Major*, Minor*).
    fn get_callback_version(call: &Call) -> Result<u64, KernelError> {
        callbacks::callback_version(call.arg(1), call.arg(2));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "cm-callback-objects",
        names: &["CmRegisterCallback", "CmCallbackGetKeyObjectID", "CmCallbackGetKeyObjectIDEx", "CmCallbackReleaseKeyObjectIDEx", "CmSetCallbackObjectContext", "CmGetBoundTransaction", "CmGetCallbackVersion"],
        handlers: &[register_callback, get_key_object_id, get_key_object_id_ex, release_key_object_id_ex, set_callback_object_context, get_bound_transaction, get_callback_version],
        data_exports: &[],
    };
}
