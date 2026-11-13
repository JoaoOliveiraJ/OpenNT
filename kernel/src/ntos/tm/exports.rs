//! Exports Tm: adaptadores finos; a lógica está nos arquivos de assunto
//! do componente (ARQUITETURA, seção 3.1).

pub mod tm_transaction_manager {
    //! Exports do KTM que o ntfs.sys importa além dos de `tm-extension`:
    //! adaptadores finos sobre `tm::extension` (slot de extensão sem tm.sys:
    //! STATUS_NOT_SUPPORTED / FALSE / nada, e as células POBJECT_TYPE NULL).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::tm::extension;
    use crate::rtl::KernelError;

    fn current_transaction(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::current_transaction(call.arg(1))))
    }

    fn dereference_enlistment_key(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::dereference_enlistment_key(call.arg(1), call.arg(2))))
    }

    fn get_transaction_id(call: &Call) -> Result<u64, KernelError> {
        extension::get_transaction_id(call.arg(1), call.arg(2));
        Ok(0)
    }

    fn is_ktm_commit_coordinator(call: &Call) -> Result<u64, KernelError> {
        Ok(extension::is_ktm_commit_coordinator(call.arg(1)) as u64)
    }

    fn is_transaction_active(call: &Call) -> Result<u64, KernelError> {
        Ok(extension::is_transaction_active(call.arg(1)) as u64)
    }

    fn recover_resource_manager(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::recover_resource_manager(call.arg(1))))
    }

    fn reference_enlistment_key(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::reference_enlistment_key(call.arg(1), call.arg(2))))
    }

    fn request_outcome_enlistment(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::request_outcome_enlistment(call.arg(1), call.arg(2))))
    }

    /// ZwOpenEnlistment / ZwOpenResourceManager(PHANDLE, ACCESS_MASK, HANDLE, LPGUID, POBJECT_ATTRIBUTES).
    fn open_object(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::open_or_create_object(call.arg(1))))
    }

    fn query_information_transaction_manager(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::query_information_transaction_manager(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5))))
    }

    /// ZwRecoverEnlistment(HANDLE, PVOID) / ZwRecoverTransactionManager(HANDLE).
    fn recover_object(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::recover_object(call.arg(1))))
    }

    pub static GROUP: Group = Group {
        name: "tm-transaction-manager",
        names: &[
            "TmCurrentTransaction",
            "TmDereferenceEnlistmentKey",
            "TmGetTransactionId",
            "TmIsKTMCommitCoordinator",
            "TmIsTransactionActive",
            "TmRecoverResourceManager",
            "TmReferenceEnlistmentKey",
            "TmRequestOutcomeEnlistment",
            "ZwOpenEnlistment",
            "ZwOpenResourceManager",
            "ZwQueryInformationTransactionManager",
            "ZwRecoverEnlistment",
            "ZwRecoverTransactionManager",
        ],
        handlers: &[
            current_transaction,
            dereference_enlistment_key,
            get_transaction_id,
            is_ktm_commit_coordinator,
            is_transaction_active,
            recover_resource_manager,
            reference_enlistment_key,
            request_outcome_enlistment,
            open_object,
            open_object,
            query_information_transaction_manager,
            recover_object,
            recover_object,
        ],
        data_exports: &[
            ("TmTransactionObjectType", extension::transaction_object_type_cell),
            ("TmResourceManagerObjectType", extension::resource_manager_object_type_cell),
            ("TmEnlistmentObjectType", extension::enlistment_object_type_cell),
        ],
    };
}

pub mod tm_extension {
    //! Adaptadores do KTM ausente — a lógica mora em `tm::extension`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::tm::extension;
    use crate::rtl::KernelError;

    /// Tm{Commit,PrePrepare,Prepare,Rollback}Complete / TmReadOnlyEnlistment /
    /// TmRollbackEnlistment(PKENLISTMENT, PLARGE_INTEGER).
    fn enlistment_notification_complete(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::enlistment_notification_complete(call.arg(1), call.arg(2))))
    }

    /// TmCreateEnlistment(PHANDLE, MODE, ACCESS, POA, RM, Transaction, ...).
    fn create_enlistment(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::create_enlistment(call.arg(1), call.arg(5), call.arg(6))))
    }

    /// TmEnableCallbacks(RM, Callback, Context).
    fn enable_callbacks(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::enable_callbacks(call.arg(1), call.arg(2), call.arg(3))))
    }

    /// ZwCreateTransactionManager / ZwCreateResourceManager(PHANDLE, ...).
    fn open_or_create_object(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension::open_or_create_object(call.arg(1))))
    }

    pub static GROUP: Group = Group {
        name: "tm-extension",
        names: &[
            "TmCommitComplete",
            "TmCreateEnlistment",
            "TmEnableCallbacks",
            "TmPrePrepareComplete",
            "TmPrepareComplete",
            "TmReadOnlyEnlistment",
            "TmRollbackComplete",
            "TmRollbackEnlistment",
            "ZwCreateTransactionManager",
            "ZwCreateResourceManager",
        ],
        handlers: &[
            enlistment_notification_complete,
            create_enlistment,
            enable_callbacks,
            enlistment_notification_complete,
            enlistment_notification_complete,
            enlistment_notification_complete,
            enlistment_notification_complete,
            enlistment_notification_complete,
            open_or_create_object,
            open_or_create_object,
        ],
        data_exports: &[],
    };
}
