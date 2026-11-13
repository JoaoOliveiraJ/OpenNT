//! Exports Ob* do ntoskrnl.
//!
//! Só os adaptadores: cada handler lê os argumentos do `Call`, chama a
//! rotina do assunto e converte o resultado. As referências e aberturas
//! moram em `object_reference` e `object_open`, a criação em
//! `object_create`, a segurança em `object_security`, o nome em
//! `query_object` e os handles dos objetos inseridos em `handles::inserted`.

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::ob::{object_manager, object_open, object_reference, object_security, reference_trace};
use crate::rtl::KernelError;

fn reference_object(call: &Call) -> Result<u64, KernelError> {
    object_reference::reference_with_tag(call.arg(1), reference_trace::DEFAULT_TAG, true)
}
fn dereference_object(call: &Call) -> Result<u64, KernelError> {
    object_reference::dereference_with_tag(call.arg(1), reference_trace::DEFAULT_TAG, true)
}

/// ObReferenceObjectByName (8 argumentos, com PACCESS_STATE opcional).
fn reference_object_by_name(call: &Call) -> Result<u64, KernelError> {
    object_reference::reference_by_name(call.arg(1), call.arg(2) as u32, call.arg(4) as u32, call.arg(5), call.arg(6) as u8, call.arg(8))
}

/// ObOpenObjectByName (7 argumentos).
fn open_object_by_name(call: &Call) -> Result<u64, KernelError> {
    object_open::open_by_name(call.arg(1), call.arg(2), call.arg(3) as u8, call.arg(5) as u32, call.arg(7))
}

/// ObReferenceObjectByHandle(handle, access, type, mode, out, info).
fn reference_object_by_handle(call: &Call) -> Result<u64, KernelError> {
    object_reference::reference_by_handle(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u8, call.arg(5), call.arg(6))
}

/// ObReferenceObjectByPointer(object, access, type, mode).
fn reference_object_by_pointer(call: &Call) -> Result<u64, KernelError> {
    object_reference::reference_by_pointer(call.arg(1), call.arg(3), call.arg(4) as u8)
}

/// ObQueryNameString(object, buffer, length, returned).
fn query_name_string(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(crate::ntos::ob::query_object::query_name_string(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4))))
}

fn is_dos_device_locally_mapped(_: &Call) -> Result<u64, KernelError> {
    Ok(object_manager::is_dos_device_locally_mapped() as u64)
}

fn set_security_object_by_pointer(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(object_security::set_security_object_by_pointer(call.arg(1), call.arg(2))))
}

pub static GROUP: Group = Group {
    name: "ob",
    names: &["ObReferenceObject", "ObDereferenceObject", "ObfReferenceObject", "ObfDereferenceObject", "ObReferenceObjectByName", "ObOpenObjectByName", "ObReferenceObjectByHandle", "ObReferenceObjectByPointer", "ObQueryNameString", "ObIsDosDeviceLocallyMapped", "ObSetSecurityObjectByPointer"],
    handlers: &[reference_object, dereference_object, reference_object, dereference_object, reference_object_by_name, open_object_by_name, reference_object_by_handle, reference_object_by_pointer, query_name_string, is_dos_device_locally_mapped, set_security_object_by_pointer],
    data_exports: &[],
};

pub mod find_handle {
    //! ObFindHandleForObject — `ntos/ob/find_handle` (o resolvedor entrega o corpo
    //! nativo; o trampolim usa a busca do kernel).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ob::find_handle;
    use crate::rtl::KernelError;

    fn find(call: &Call) -> Result<u64, KernelError> {
        find_handle::find(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5))
    }

    pub static GROUP: Group = Group { name: "find-handle", names: &["ObFindHandleForObject"], handlers: &[find], data_exports: &[] };
}

pub mod get_object_type {
    //! ObGetObjectType.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::get_object_type;

    fn ob_get_object_type(call: &Call) -> Result<u64, KernelError> {
        get_object_type::get(call.arg(1))
    }

    pub static GROUP: Group = Group {
        name: "get-object-type",
        names: &["ObGetObjectType"],
        handlers: &[ob_get_object_type],
        data_exports: &[],
    };
}

pub mod object_callbacks {
    //! ObRegisterCallbacks/ObUnRegisterCallbacks.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::callbacks;

    fn register_callbacks(call: &Call) -> Result<u64, KernelError> {
        Ok(callbacks::register(call.arg(1), call.arg(2))? as u64)
    }

    fn unregister_callbacks(call: &Call) -> Result<u64, KernelError> {
        Ok(callbacks::unregister(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "object-callbacks",
        names: &["ObRegisterCallbacks", "ObUnRegisterCallbacks"],
        handlers: &[register_callbacks, unregister_callbacks],
        data_exports: &[],
    };
}

pub mod open_pointer_exports {
    //! ObOpenObjectByPointer.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::open_pointer;

    fn open_object_by_pointer(call: &Call) -> Result<u64, KernelError> {
        Ok(open_pointer::open(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u8, call.arg(7))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "open-pointer",
        names: &["ObOpenObjectByPointer"],
        handlers: &[open_object_by_pointer],
        data_exports: &[],
    };
}

pub mod tagged_dereference {
    //! ObfDereferenceObjectWithTag — a desreferência com tag do grupo `ob`; falha
    //! interna interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::init::exports::fatal_unless_transfer;
    use crate::ntos::ob::object_reference;
    use crate::rtl::KernelError;

    fn dereference_with_tag(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("tagged-dereference", object_reference::dereference_with_tag(call.arg(1), call.arg(2) as u32, false))
    }

    pub static GROUP: Group = Group { name: "tagged-dereference", names: &["ObfDereferenceObjectWithTag"], handlers: &[dereference_with_tag], data_exports: &[] };
}

pub mod tagged_reference {
    //! ObfReferenceObjectWithTag — a referência com tag do grupo `ob`; falha
    //! interna interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::init::exports::fatal_unless_transfer;
    use crate::ntos::ob::object_reference;
    use crate::rtl::KernelError;

    fn reference_with_tag(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("tagged-reference", object_reference::reference_with_tag(call.arg(1), call.arg(2) as u32, false))
    }

    pub static GROUP: Group = Group { name: "tagged-reference", names: &["ObfReferenceObjectWithTag"], handlers: &[reference_with_tag], data_exports: &[] };
}

pub mod close {
    //! NtClose.
    //!
    //! Fecha com o modo anterior da thread.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ob::close;

    fn nt_close(call: &Call) -> Result<u64, KernelError> {
        Ok(close::close(call.arg(1), None)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "close",
        names: &["NtClose"],
        handlers: &[nt_close],
        data_exports: &[],
    };
}

pub mod query_object {
    //! ZwQueryObject: a consulta de objetos
    //! dos provedores reais.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ob::query_object;
    use crate::rtl::KernelError;

    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(query_object::query(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5))?))
    }

    pub static GROUP: Group = Group { name: "query-object", names: &["ZwQueryObject"], handlers: &[query], data_exports: &[] };
}

pub mod query_security {
    //! ZwQuerySecurityObject — `ntos/ob/query_security`; falha interna interrompe
    //! o sistema.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::ntos::ob::query_security;
    use crate::rtl::KernelError;

    fn query(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("query-security", query_security::query(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5))).map(|status| status as u64)
    }

    pub static GROUP: Group = Group { name: "query-security", names: &["ZwQuerySecurityObject"], handlers: &[query], data_exports: &[] };
}

pub mod ob_object_lifecycle {
    //! Criação, inserção, segurança e handles de objetos — adaptadores de
    //! `object_types`, `object_create`, `object_reference`, `object_security`
    //! e `handles::inserted`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ob::handles::inserted;
    use crate::ntos::ob::{object_create, object_reference, object_security, object_types};
    use crate::rtl::KernelError;

    /// ObCreateObjectType(Name, Initializer, Sd, Type).
    fn create_object_type(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(object_types::create_from_initializer(call.arg(1), call.arg(2), call.arg(4))))
    }

    /// ObCreateObject(ProbeMode, Type, Attr, OwnerMode, Reserved, BodySize,
    /// PagedCharge, NonPagedCharge, Object).
    fn create_object(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(object_create::create(call.arg(2), call.arg(3), call.arg(6) as u32, call.arg(9))))
    }

    /// ObInsertObject(Object, AccessState, DesiredAccess, Bias, NewObject, Handle).
    fn insert_object(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(object_create::insert(call.arg(1), call.arg(3) as u32, call.arg(5), call.arg(6))?))
    }

    fn delete_captured_insert_info(call: &Call) -> Result<u64, KernelError> {
        object_create::delete_captured_insert_info(call.arg(1));
        Ok(0)
    }

    /// ObReferenceObjectByHandleWithTag(Handle, Access, Type, Mode, Tag, Object, Info).
    fn reference_object_by_handle_with_tag(call: &Call) -> Result<u64, KernelError> {
        object_reference::reference_by_handle_with_tag(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u8, call.arg(5) as u32, call.arg(6), call.arg(7))
    }

    /// ObCheckObjectAccess(Object, SubjectContext, LockHeld, Mode, GrantedAccess, Status).
    fn check_object_access(call: &Call) -> Result<u64, KernelError> {
        Ok(object_security::check_object_access(call.arg(1), call.arg(4) as u8, call.arg(5), call.arg(6)) as u64)
    }

    fn get_object_security(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(object_security::get_object_security(call.arg(1), call.arg(2), call.arg(3))))
    }

    fn release_object_security(call: &Call) -> Result<u64, KernelError> {
        object_security::release_object_security(call.arg(1), call.arg(2) as u8 != 0);
        Ok(0)
    }

    /// ObDuplicateObject(Source, SourceHandle, Target, TargetHandle,
    /// DesiredAccess, HandleAttributes, Options, Mode).
    fn duplicate_object(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(inserted::duplicate(call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(6) as u32, call.arg(7) as u32)?))
    }

    fn is_kernel_handle(call: &Call) -> Result<u64, KernelError> {
        Ok(inserted::is_kernel_handle(call.arg(1)) as u64)
    }

    /// ObCloseHandle(Handle, Mode).
    fn close_handle(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(inserted::close(call.arg(1), call.arg(2) as u8)?))
    }

    // --- object-type pointer DATA exports (heap-populated kdata cells) ---------
    fn io_device_object_type() -> u64 {
        object_types::exported_cell("IoDeviceObjectType")
    }
    fn ex_semaphore_object_type() -> u64 {
        object_types::exported_cell("ExSemaphoreObjectType")
    }
    fn lpc_port_object_type() -> u64 {
        object_types::exported_cell("LpcPortObjectType")
    }

    pub static GROUP: Group = Group {
        name: "ob-object-lifecycle",
        names: &[
            "ObCreateObjectType",
            "ObCreateObject",
            "ObInsertObject",
            "ObDeleteCapturedInsertInfo",
            "ObReferenceObjectByHandleWithTag",
            "ObCheckObjectAccess",
            "ObGetObjectSecurity",
            "ObReleaseObjectSecurity",
            "ObDuplicateObject",
            "ObIsKernelHandle",
            "ObCloseHandle",
        ],
        handlers: &[
            create_object_type,
            create_object,
            insert_object,
            delete_captured_insert_info,
            reference_object_by_handle_with_tag,
            check_object_access,
            get_object_security,
            release_object_security,
            duplicate_object,
            is_kernel_handle,
            close_handle,
        ],
        data_exports: &[
            ("IoDeviceObjectType", io_device_object_type),
            ("ExSemaphoreObjectType", ex_semaphore_object_type),
            ("LpcPortObjectType", lpc_port_object_type),
        ],
    };
}

// =============================================================================

pub mod ob_security_cache {
    //! Cache de descritores de segurança do Ob (tcpip) — lógica em
    //! `ob/object_security.rs`.

    use crate::ntos::inc::field::{Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ob::object_security;
    use crate::rtl::KernelError;

    /// ObLogSecurityDescriptor(InputSD, OutputSD*, RefBias).
    fn log_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PSECURITY_DESCRIPTOR* de saída do chamador (modo kernel).
        let output = unsafe { Field::<u64>::at(call.arg(2)) };
        Ok(signed_status(object_security::log_security_descriptor(call.arg(1), output, call.arg(3) as u32)?))
    }

    /// ObReferenceSecurityDescriptor(SD, Count).
    fn reference_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        object_security::reference_security_descriptor(call.arg(1), call.arg(2) as u32)?;
        Ok(0)
    }

    /// ObDereferenceSecurityDescriptor(SD, Count).
    fn dereference_security_descriptor(call: &Call) -> Result<u64, KernelError> {
        object_security::dereference_security_descriptor(call.arg(1), call.arg(2) as u32)?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ob-security-cache",
        names: &["ObLogSecurityDescriptor", "ObReferenceSecurityDescriptor", "ObDereferenceSecurityDescriptor"],
        handlers: &[log_security_descriptor, reference_security_descriptor, dereference_security_descriptor],
        data_exports: &[],
    };
}
