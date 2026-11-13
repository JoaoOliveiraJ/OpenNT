//! Exports Ps* — `system32/win32/ntoskrnl/ps.js`.
//!
//! Threads de sistema sobre o escalonador cooperativo, identificadores do
//! processo e da thread correntes, notificações de criação de processo,
//! silos (o hospedeiro é NULL na ABI) e contextos de silo, e as células de
//! dado dos tipos Process/Thread/Job e do processo inicial.

use crate::ntos::init::exports::{Call, Group};
use crate::ntos::ps::notify::process as process_notify;
use crate::ntos::ps::silo::{contexts as silo_contexts, query as silo_query};
use crate::ntos::ps::{kernel_threads, process, process_accessors, thread_accessors};
use crate::rtl::KernelError;

/// PsCreateSystemThread(handle*, access, oa, process, clientId*, start, context).
fn create_system_thread(call: &Call) -> Result<u64, KernelError> {
    kernel_threads::create_system_thread_with_attributes(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(5), call.arg(6), call.arg(7))?;
    Ok(0)
}

fn terminate_system_thread(call: &Call) -> Result<u64, KernelError> {
    Ok(kernel_threads::terminate_current_thread(call.arg(1) as u32)? as u64)
}

fn get_current_thread_id(_call: &Call) -> Result<u64, KernelError> {
    Ok(process::get_current_thread_id())
}

fn get_current_process_id(_call: &Call) -> Result<u64, KernelError> {
    Ok(process::get_current_process_id())
}

fn set_create_process_notify_routine(call: &Call) -> Result<u64, KernelError> {
    Ok(process_notify::set(call.arg(1), call.arg(2) as u8, false)? as u64)
}

fn remove_create_process_notify_routine(call: &Call) -> Result<u64, KernelError> {
    Ok(process_notify::set(call.arg(1), 1, false)? as u64)
}

fn lookup_process_by_process_id(call: &Call) -> Result<u64, KernelError> {
    Ok(process::lookup_process_by_id(call.arg(1), call.arg(2)) as u64)
}

fn get_process_id(call: &Call) -> Result<u64, KernelError> {
    Ok(process_accessors::id(call.arg(1)))
}

fn get_job_silo(call: &Call) -> Result<u64, KernelError> {
    Ok(silo_query::get_job_silo(call.arg(1), call.arg(2)) as u64)
}

fn get_host_silo(_call: &Call) -> Result<u64, KernelError> {
    Ok(silo_query::host_silo())
}

fn is_host_silo(call: &Call) -> Result<u64, KernelError> {
    Ok(silo_query::is_host_silo(call.arg(1)) as u64)
}

fn get_thread_hard_errors_are_disabled(_call: &Call) -> Result<u64, KernelError> {
    Ok(thread_accessors::hard_errors_are_disabled() as u64)
}

fn set_thread_hard_errors_are_disabled(call: &Call) -> Result<u64, KernelError> {
    Ok(thread_accessors::set_hard_errors_are_disabled(call.arg(1) != 0) as u64)
}

/// PsAllocSiloContextSlot(Reserved, slot*): o reservado é ignorado.
fn alloc_silo_context_slot(call: &Call) -> Result<u64, KernelError> {
    Ok(silo_contexts::alloc_slot(call.arg(2)) as u64)
}

fn create_silo_context(call: &Call) -> Result<u64, KernelError> {
    Ok(silo_contexts::create(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5))? as u64)
}

/// Contexto permanente: o NT não deixa removê-lo depois.
fn insert_permanent_silo_context(call: &Call) -> Result<u64, KernelError> {
    Ok(silo_contexts::insert(call.arg(1), call.arg(2) as u32, call.arg(3), true)? as u64)
}

fn dereference_silo_context(call: &Call) -> Result<u64, KernelError> {
    silo_contexts::dereference_existing(call.arg(1))?;
    Ok(0)
}

fn free_silo_context_slot(call: &Call) -> Result<u64, KernelError> {
    Ok(silo_contexts::free_slot(call.arg(1) as u32)? as u64)
}

fn attach_silo_to_current_thread(call: &Call) -> Result<u64, KernelError> {
    Ok(silo_query::attach(call.arg(1)))
}

fn detach_silo_from_current_thread(call: &Call) -> Result<u64, KernelError> {
    silo_query::detach(call.arg(1));
    Ok(0)
}

/// KTHREAD.ApcState.Process da thread corrente.
fn get_current_process(_call: &Call) -> Result<u64, KernelError> {
    Ok(process::get_current_process())
}

fn get_process_create_time_quad_part(call: &Call) -> Result<u64, KernelError> {
    Ok(process_accessors::create_time(call.arg(1)))
}

fn release_process_exit_synchronization(call: &Call) -> Result<u64, KernelError> {
    process::release_exit_synchronization(call.arg(1))?;
    Ok(0)
}

fn initial_system_process() -> u64 {
    process::initial_system_process_cell()
}

fn process_type() -> u64 {
    process::process_type_cell()
}

fn thread_type() -> u64 {
    process::thread_type_cell()
}

fn job_type() -> u64 {
    process::job_type_cell()
}

pub static GROUP: Group = Group {
    name: "ps",
    names: &[
        "PsCreateSystemThread",
        "PsTerminateSystemThread",
        "PsGetCurrentThreadId",
        "PsGetCurrentProcessId",
        "PsSetCreateProcessNotifyRoutine",
        "PsRemoveCreateProcessNotifyRoutine",
        "PsLookupProcessByProcessId",
        "PsGetProcessId",
        "PsGetJobSilo",
        "PsGetHostSilo",
        "PsIsHostSilo",
        "PsGetThreadHardErrorsAreDisabled",
        "PsSetThreadHardErrorsAreDisabled",
        "PsAllocSiloContextSlot",
        "PsCreateSiloContext",
        "PsInsertPermanentSiloContext",
        "PsDereferenceSiloContext",
        "PsFreeSiloContextSlot",
        "PsAttachSiloToCurrentThread",
        "PsDetachSiloFromCurrentThread",
        "PsGetCurrentProcess",
        "PsGetProcessCreateTimeQuadPart",
        "PsReleaseProcessExitSynchronization",
    ],
    handlers: &[
        create_system_thread,
        terminate_system_thread,
        get_current_thread_id,
        get_current_process_id,
        set_create_process_notify_routine,
        remove_create_process_notify_routine,
        lookup_process_by_process_id,
        get_process_id,
        get_job_silo,
        get_host_silo,
        is_host_silo,
        get_thread_hard_errors_are_disabled,
        set_thread_hard_errors_are_disabled,
        alloc_silo_context_slot,
        create_silo_context,
        insert_permanent_silo_context,
        dereference_silo_context,
        free_silo_context_slot,
        attach_silo_to_current_thread,
        detach_silo_from_current_thread,
        get_current_process,
        get_process_create_time_quad_part,
        release_process_exit_synchronization,
    ],
    data_exports: &[("PsInitialSystemProcess", initial_system_process), ("PsProcessType", process_type), ("PsJobType", job_type), ("PsThreadType", thread_type)],
};

pub mod image_notify {
    //! Notificações de carga de imagem — `system32/win32/ntoskrnl/image-notify.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::notify::image as image_notify;

    fn set_load_image_notify_routine(call: &Call) -> Result<u64, KernelError> {
        Ok(image_notify::register(call.arg(1))? as u64)
    }

    fn remove_load_image_notify_routine(call: &Call) -> Result<u64, KernelError> {
        Ok(image_notify::remove(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "image-notify",
        names: &["PsSetLoadImageNotifyRoutine", "PsRemoveLoadImageNotifyRoutine"],
        handlers: &[set_load_image_notify_routine, remove_load_image_notify_routine],
        data_exports: &[],
    };
}

pub mod lookup_thread {
    //! PsLookupThreadByThreadId — `system32/win32/ntoskrnl/lookup-thread.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::lookup_thread;

    fn lookup_thread_by_thread_id(call: &Call) -> Result<u64, KernelError> {
        Ok(lookup_thread::lookup(call.arg(1), call.arg(2))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "lookup-thread",
        names: &["PsLookupThreadByThreadId"],
        handlers: &[lookup_thread_by_thread_id],
        data_exports: &[],
    };
}

pub mod previous_mode {
    //! PsGetCurrentThreadPreviousMode — `system32/win32/ntoskrnl/previous-mode.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ps::previous_mode;
    use crate::rtl::KernelError;

    fn get_previous_mode(_: &Call) -> Result<u64, KernelError> {
        Ok(previous_mode::get()? as u64)
    }

    pub static GROUP: Group = Group { name: "previous-mode", names: &["PsGetCurrentThreadPreviousMode"], handlers: &[get_previous_mode], data_exports: &[] };
}

pub mod process_debug {
    //! PsGetProcessDebugPort — `system32/win32/ntoskrnl/process-debug.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::session;

    fn get_process_debug_port(call: &Call) -> Result<u64, KernelError> {
        Ok(session::debug_port(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "process-debug",
        names: &["PsGetProcessDebugPort"],
        handlers: &[get_process_debug_port],
        data_exports: &[],
    };
}

pub mod process_exit {
    //! PsGetProcessExitStatus — `system32/win32/ntoskrnl/process-exit.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::process_accessors;

    fn get_process_exit_status(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::exit_status(call.arg(1)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "process-exit",
        names: &["PsGetProcessExitStatus"],
        handlers: &[get_process_exit_status],
        data_exports: &[],
    };
}

pub mod process_exit_called {
    //! PsGetProcessExitProcessCalled — `system32/win32/ntoskrnl/process-exit-called.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::process_accessors;

    fn get_process_exit_process_called(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::exit_process_called(call.arg(1)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "process-exit-called",
        names: &["PsGetProcessExitProcessCalled"],
        handlers: &[get_process_exit_process_called],
        data_exports: &[],
    };
}

pub mod process_image {
    //! PsReferenceProcessFilePointer/SeLocateProcessImageName — `system32/win32/ntoskrnl/process-image.js`.
    //!
    //! Os NTSTATUS de erro voltam com sinal estendido.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::process_image;

    fn reference_process_file_pointer(call: &Call) -> Result<u64, KernelError> {
        process_image::reference_file(call.arg(1), call.arg(2)).map(signed_status)
    }

    fn locate_process_image_name(call: &Call) -> Result<u64, KernelError> {
        process_image::locate_name(call.arg(1), call.arg(2)).map(signed_status)
    }

    pub static GROUP: Group = Group {
        name: "process-image",
        names: &["PsReferenceProcessFilePointer", "SeLocateProcessImageName"],
        handlers: &[reference_process_file_pointer, locate_process_image_name],
        data_exports: &[],
    };
}

pub mod process_image_name {
    //! PsGetProcessImageFileName — `system32/win32/ntoskrnl/process-image-name.js`.
    //!
    //! Devolve o endereço do campo ImageFileName do EPROCESS.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::process_accessors;

    fn get_process_image_file_name(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::image_file_name(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "process-image-name",
        names: &["PsGetProcessImageFileName"],
        handlers: &[get_process_image_file_name],
        data_exports: &[],
    };
}

pub mod process_notify_exports {
    //! PsSetCreateProcessNotifyRoutineEx — `system32/win32/ntoskrnl/process-notify.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::notify::process as process_notify;

    fn set_create_process_notify_routine_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(process_notify::set(call.arg(1), call.arg(2) as u8, true)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "process-notify",
        names: &["PsSetCreateProcessNotifyRoutineEx"],
        handlers: &[set_create_process_notify_routine_ex],
        data_exports: &[],
    };
}

pub mod process_peb {
    //! PsGetProcessPeb — `system32/win32/ntoskrnl/process-peb.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::process_accessors;

    fn get_process_peb(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::peb(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "process-peb",
        names: &["PsGetProcessPeb"],
        handlers: &[get_process_peb],
        data_exports: &[],
    };
}

pub mod process_query {
    //! Consultas do EPROCESS — `system32/win32/ntoskrnl/process-query.js`.
    //!
    //! Leem a imagem, a proteção e os níveis de assinatura pelo layout da ABI;
    //! uma referência válida mantém o objeto consultável depois da saída.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::process_accessors;

    fn get_process_section_base_address(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::section_base_address(call.arg(1)))
    }

    /// Type, Audit e Signer no retorno.
    fn get_process_protection(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::protection(call.arg(1)) as u64)
    }

    fn get_process_signature_level(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::signature_level(call.arg(1), call.arg(2)) as u64)
    }

    fn is_protected_process(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::is_protected(call.arg(1)) as u64)
    }

    fn is_protected_process_light(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::is_protected_light(call.arg(1)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "process-query",
        names: &["PsGetProcessSectionBaseAddress", "PsGetProcessProtection", "PsGetProcessSignatureLevel", "PsIsProtectedProcess", "PsIsProtectedProcessLight"],
        handlers: &[get_process_section_base_address, get_process_protection, get_process_signature_level, is_protected_process, is_protected_process_light],
        data_exports: &[],
    };
}

pub mod process_session {
    //! PsGetProcessSessionId — `system32/win32/ntoskrnl/process-session.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::session;

    fn get_process_session_id(call: &Call) -> Result<u64, KernelError> {
        Ok(session::query(call.arg(1)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "process-session",
        names: &["PsGetProcessSessionId"],
        handlers: &[get_process_session_id],
        data_exports: &[],
    };
}

pub mod process_win32 {
    //! PsGetProcessWin32Process — `system32/win32/ntoskrnl/process-win32.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::process_accessors;

    fn get_process_win32_process(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::win32_process(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "process-win32",
        names: &["PsGetProcessWin32Process"],
        handlers: &[get_process_win32_process],
        data_exports: &[],
    };
}

pub mod process_wow64 {
    //! Consultas WOW64 — `system32/win32/ntoskrnl/process-wow64.js`.
    //!
    //! Leem os campos reais do EPROCESS (EWOW64PROCESS) e da thread atual.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::process_accessors;

    fn get_process_wow64_process(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::wow64_process(call.arg(1)))
    }

    fn get_current_process_wow64_process(_: &Call) -> Result<u64, KernelError> {
        process_accessors::current_wow64_process()
    }

    pub static GROUP: Group = Group {
        name: "process-wow64",
        names: &["PsGetProcessWow64Process", "PsGetCurrentProcessWow64Process"],
        handlers: &[get_process_wow64_process, get_current_process_wow64_process],
        data_exports: &[],
    };
}

pub mod security_tokens {
    //! Adaptadores nativos de segurança — `system32/win32/ntoskrnl/security-tokens.js`.
    //!
    //! Usam os tokens e as referências mantidos pelo kernel; o gerenciador de
    //! processos fornece o token primário de cada EPROCESS e o serializador de
    //! atributos calcula o layout nativo da resposta.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ps::security;
    use crate::rtl::KernelError;

    fn reference_primary_token(call: &Call) -> Result<u64, KernelError> {
        security::reference_primary_token(call.arg(1))
    }

    fn dereference_primary_token(call: &Call) -> Result<u64, KernelError> {
        security::dereference_primary_token(call.arg(1))?;
        Ok(0)
    }

    fn query_security_attributes_token(call: &Call) -> Result<u64, KernelError> {
        Ok(security::query_attributes(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6))? as u64)
    }

    fn query_process_attributes_by_token(call: &Call) -> Result<u64, KernelError> {
        security::process_attributes(call.arg(1), call.arg(2), call.arg(3))
    }

    fn token_object_type_address() -> u64 {
        security::token_object_type_cell()
    }

    fn exports_address() -> u64 {
        security::exports_cell()
    }

    pub static GROUP: Group = Group {
        name: "security-tokens",
        names: &["PsReferencePrimaryToken", "PsDereferencePrimaryToken", "SeQuerySecurityAttributesToken", "PsQueryProcessAttributesByToken"],
        handlers: &[reference_primary_token, dereference_primary_token, query_security_attributes_token, query_process_attributes_by_token],
        data_exports: &[("SeTokenObjectType", token_object_type_address), ("SeExports", exports_address)],
    };
}

pub mod silo_contexts_exports {
    //! Contextos de silo — `system32/win32/ntoskrnl/silo-contexts.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::silo::contexts as silo_contexts;

    fn get_permanent_silo_context(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_contexts::get_context(call.arg(1), call.arg(2) as u32, call.arg(3), true)? as u64)
    }

    fn get_silo_context(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_contexts::get_context(call.arg(1), call.arg(2) as u32, call.arg(3), false)? as u64)
    }

    fn insert_silo_context(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_contexts::insert(call.arg(1), call.arg(2) as u32, call.arg(3), false)? as u64)
    }

    fn replace_silo_context(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_contexts::replace(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4))? as u64)
    }

    fn remove_silo_context(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_contexts::remove(call.arg(1), call.arg(2) as u32, call.arg(3), false)? as u64)
    }

    fn make_silo_context_permanent(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_contexts::make_permanent(call.arg(1), call.arg(2) as u32)? as u64)
    }

    fn reference_silo_context(call: &Call) -> Result<u64, KernelError> {
        silo_contexts::reference_existing(call.arg(1))?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "silo-contexts",
        names: &["PsGetPermanentSiloContext", "PsGetSiloContext", "PsInsertSiloContext", "PsReplaceSiloContext", "PsRemoveSiloContext", "PsMakeSiloContextPermanent", "PsReferenceSiloContext"],
        handlers: &[get_permanent_silo_context, get_silo_context, insert_silo_context, replace_silo_context, remove_silo_context, make_silo_context_permanent, reference_silo_context],
        data_exports: &[],
    };
}

pub mod silo_monitors {
    //! Monitores de silo — `system32/win32/ntoskrnl/silo-monitors.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::silo::monitors as silo_monitors;

    fn register_silo_monitor(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_monitors::register(call.arg(1), call.arg(2))? as u64)
    }

    fn get_silo_monitor_context_slot(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_monitors::get_slot(call.arg(1))? as u64)
    }

    fn start_silo_monitor(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_monitors::start(call.arg(1))? as u64)
    }

    fn unregister_silo_monitor(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_monitors::unregister(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "silo-monitors",
        names: &["PsRegisterSiloMonitor", "PsGetSiloMonitorContextSlot", "PsStartSiloMonitor", "PsUnregisterSiloMonitor"],
        handlers: &[register_silo_monitor, get_silo_monitor_context_slot, start_silo_monitor, unregister_silo_monitor],
        data_exports: &[],
    };
}

pub mod silo_query_exports {
    //! Exports de consulta de silo — `system32/win32/ntoskrnl/silo-query.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ps::silo::query as silo_query;
    use crate::ntos::ps::thread_accessors;
    use crate::rtl::KernelError;

    fn current_server_silo(_: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::current_server_silo())
    }

    fn process_server_silo(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::process_server_silo(call.arg(1)))
    }

    fn is_current_thread_in_server_silo(_: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::is_current_thread_in_server_silo() as u64)
    }

    fn current_silo(_: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::current_silo())
    }

    fn thread_server_silo(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::thread_server_silo(call.arg(1)))
    }

    fn effective_server_silo(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::effective_server_silo(call.arg(1)))
    }

    fn job_server_silo(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::get_job_server_silo(call.arg(1), call.arg(2)) as u64)
    }

    fn is_prefetching(_: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::is_prefetching() as u64)
    }

    fn is_executing_dpc(_: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::is_executing_dpc() as u64)
    }

    pub static GROUP: Group = Group {
        name: "silo-query",
        names: &[
            "PsGetCurrentServerSilo",
            "PsGetProcessServerSilo",
            "PsIsCurrentThreadInServerSilo",
            "PsGetCurrentSilo",
            "PsGetThreadServerSilo",
            "PsGetEffectiveServerSilo",
            "PsGetJobServerSilo",
            "PsIsCurrentThreadPrefetching",
            "KeIsExecutingDpc",
        ],
        handlers: &[current_server_silo, process_server_silo, is_current_thread_in_server_silo, current_silo, thread_server_silo, effective_server_silo, job_server_silo, is_prefetching, is_executing_dpc],
        data_exports: &[],
    };
}

pub mod thread_context {
    //! PsSetContextThread — `win32/ntoskrnl/thread-context.js`.
    //!
    //! O export tem corpo x64 próprio (`ps_set_context_thread`): encaminha o
    //! modo de entrada como modo de contexto e chama PspSetContextThreadInternal.
    //! Este handler atende a chamada pelo despachante comum.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ps::context::set as set_thread_context;
    use crate::rtl::KernelError;

    fn set_context_thread(call: &Call) -> Result<u64, KernelError> {
        let mode = call.arg(3) as u8;
        set_thread_context::execute(call.arg(1), call.arg(2), mode, mode, 1).map(signed_status)
    }

    pub static GROUP: Group = Group { name: "thread-context", names: &["PsSetContextThread"], handlers: &[set_context_thread], data_exports: &[] };
}

pub mod thread_exit {
    //! PsGetThreadExitStatus — `system32/win32/ntoskrnl/thread-exit.js`.
    //!
    //! Enquanto a proteção de rundown ainda pode ser adquirida, a thread não
    //! terminou: STATUS_PENDING.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::thread_accessors;

    fn get_thread_exit_status(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::exit_status(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "thread-exit",
        names: &["PsGetThreadExitStatus"],
        handlers: &[get_thread_exit_status],
        data_exports: &[],
    };
}

pub mod thread_id {
    //! PsGetThreadId — `system32/win32/ntoskrnl/thread-id.js`.
    //!
    //! Consulta o ETHREAD dado, inclusive um objeto retido depois da saída da
    //! thread; não referencia nem substitui o chamador.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::thread_accessors;

    fn get_thread_id(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::id(call.arg(1)))
    }

    pub static GROUP: Group = Group { name: "thread-id", names: &["PsGetThreadId"], handlers: &[get_thread_id], data_exports: &[] };
}

pub mod thread_notify {
    //! Notificações de criação de thread — `system32/win32/ntoskrnl/thread-notify.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::notify::thread as thread_notify;

    fn set_create_thread_notify_routine(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_notify::register(call.arg(1))? as u64)
    }

    fn remove_create_thread_notify_routine(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_notify::remove(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "thread-notify",
        names: &["PsSetCreateThreadNotifyRoutine", "PsRemoveCreateThreadNotifyRoutine"],
        handlers: &[set_create_thread_notify_routine, remove_create_thread_notify_routine],
        data_exports: &[],
    };
}

pub mod thread_process {
    //! PsGetThreadProcess/PsGetThreadProcessId — `system32/win32/ntoskrnl/thread-process.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::thread_accessors;

    fn get_thread_process(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::process(call.arg(1)))
    }

    fn get_thread_process_id(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::process_id(call.arg(1)))
    }

    pub static GROUP: Group = Group {
        name: "thread-process",
        names: &["PsGetThreadProcess", "PsGetThreadProcessId"],
        handlers: &[get_thread_process, get_thread_process_id],
        data_exports: &[],
    };
}

pub mod nt_query_thread {
    //! NtQueryInformationThread — `system32/win32/ntoskrnl/nt-query-thread.js`.
    //!
    //! Usa o modo anterior da thread; falha interna interrompe o sistema.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::{previous_mode, query_thread};

    fn query_information_thread(call: &Call) -> Result<u64, KernelError> {
        let mode = previous_mode::get()?;
        Ok(fatal_unless_transfer("nt-query-thread", query_thread::query(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), mode))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "nt-query-thread",
        names: &["NtQueryInformationThread"],
        handlers: &[query_information_thread],
        data_exports: &[],
    };
}

pub mod query_thread {
    //! ZwQueryInformationThread — `system32/win32/ntoskrnl/query-thread.js`.
    //!
    //! Parâmetros de kernel (modo 0); falha interna interrompe o sistema.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::query_thread;

    fn query_information_thread(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("query-thread", query_thread::query(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), 0))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "query-thread",
        names: &["ZwQueryInformationThread"],
        handlers: &[query_information_thread],
        data_exports: &[],
    };
}

pub mod set_thread_information {
    //! ZwSetInformationThread — `system32/win32/ntoskrnl/set-thread-information.js`.
    //!
    //! Parâmetros de kernel (modo 0); falha interna interrompe o sistema.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::set_thread_information;

    fn set_information_thread(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("set-thread-information", set_thread_information::set(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, 0))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "set-thread-information",
        names: &["ZwSetInformationThread"],
        handlers: &[set_information_thread],
        data_exports: &[],
    };
}

pub mod nt_set_thread_information {
    //! NtSetInformationThread — `system32/win32/ntoskrnl/nt-set-thread-information.js`.
    //!
    //! Usa o modo anterior da thread; falha interna interrompe o sistema.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::{previous_mode, set_thread_information};

    fn set_information_thread(call: &Call) -> Result<u64, KernelError> {
        let mode = previous_mode::get()?;
        Ok(fatal_unless_transfer("nt-set-thread-information", set_thread_information::set(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, mode))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "nt-set-thread-information",
        names: &["NtSetInformationThread"],
        handlers: &[set_information_thread],
        data_exports: &[],
    };
}

pub mod open_process_thread {
    //! ZwOpenProcess/ZwOpenThread em KernelMode, como o NtOpenProcess/
    //! NtOpenThread do NT: pelo CLIENT_ID (PsLookup*, com a thread conferida
    //! contra o processo pedido) ou pelo nome (ObOpenObjectByName); nunca os
    //! dois nem nenhum.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ps::open;
    use crate::rtl::KernelError;

    fn open_process(call: &Call) -> Result<u64, KernelError> {
        open::open_process(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4))
    }

    fn open_thread(call: &Call) -> Result<u64, KernelError> {
        open::open_thread(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4))
    }

    pub static GROUP: Group = Group {
        name: "open-process-thread",
        names: &["ZwOpenProcess", "ZwOpenThread"],
        handlers: &[open_process, open_thread],
        data_exports: &[],
    };
}

pub mod next_process_thread {
    //! ZwGetNextProcess/ZwGetNextThread em KernelMode, como o NtGetNextProcess/
    //! NtGetNextThread do NT: a partir do handle dado (ou do começo), abre o
    //! próximo processo da PsActiveProcessHead (para trás com o bit 0 de
    //! Flags) ou a próxima thread do processo; quem não abre é pulado, e o fim
    //! da lista é STATUS_NO_MORE_ENTRIES.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ps::enum_process_threads;
    use crate::rtl::KernelError;

    fn get_next_process(call: &Call) -> Result<u64, KernelError> {
        enum_process_threads::open_next_process(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32, call.arg(5)).map(signed_status)
    }

    fn get_next_thread(call: &Call) -> Result<u64, KernelError> {
        enum_process_threads::open_next_thread(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, call.arg(5) as u32, call.arg(6)).map(signed_status)
    }

    pub static GROUP: Group = Group {
        name: "next-process-thread",
        names: &["ZwGetNextProcess", "ZwGetNextThread"],
        handlers: &[get_next_process, get_next_thread],
        data_exports: &[],
    };
}

pub mod exit_synchronization {
    //! PsAcquireProcessExitSynchronization: a RundownProtect do EPROCESS, que
    //! o término do processo espera esvaziar; com o processo já saindo,
    //! STATUS_PROCESS_IS_TERMINATING (a liberação está no grupo `ps`). PsAcquire/ReleaseSiloHardReference:
    //! o host (NULL) está sempre presente; um silo de verdade (job com o bit de
    //! silo) conta as referências fortes.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ps::process;
    use crate::ntos::ps::silo::hard_references;
    use crate::rtl::KernelError;

    fn acquire_process_exit_synchronization(call: &Call) -> Result<u64, KernelError> {
        process::acquire_exit_synchronization(call.arg(1)).map(signed_status)
    }

    fn acquire_silo_hard_reference(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hard_references::acquire(call.arg(1))))
    }

    fn release_silo_hard_reference(call: &Call) -> Result<u64, KernelError> {
        hard_references::release(call.arg(1))?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "exit-synchronization",
        names: &["PsAcquireProcessExitSynchronization", "PsAcquireSiloHardReference", "PsReleaseSiloHardReference"],
        handlers: &[acquire_process_exit_synchronization, acquire_silo_hard_reference, release_silo_hard_reference],
        data_exports: &[],
    };
}

pub mod thread_process_queries {
    //! Acessores de ETHREAD/EPROCESS e da thread/processo correntes, lendo os
    //! campos do layout 19041 que o OpenNT mantém (o processo corrente é o
    //! anexado, como o PsGetCurrentProcess).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ps::{process, process_accessors, session, thread_accessors};
    use crate::rtl::KernelError;

    fn get_thread_teb(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::teb(call.arg(1)))
    }
    fn get_current_thread_teb(_: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::current_teb())
    }
    fn get_thread_win32_thread(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::win32_thread(call.arg(1)))
    }
    fn get_current_thread_win32_thread(_: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::current_win32_thread())
    }
    fn get_thread_create_time(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::create_time(call.arg(1)))
    }
    fn is_system_thread(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::is_system_thread(call.arg(1)) as u64)
    }
    fn is_thread_terminating(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::is_terminating(call.arg(1)) as u64)
    }
    fn is_thread_impersonating(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::is_impersonating(call.arg(1)) as u64)
    }
    fn get_current_thread(_: &Call) -> Result<u64, KernelError> {
        Ok(process::get_current_thread())
    }
    fn get_current_thread_process(_: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::current_process())
    }
    fn get_current_thread_process_id(_: &Call) -> Result<u64, KernelError> {
        Ok(thread_accessors::current_process_id())
    }
    fn get_thread_session_id(call: &Call) -> Result<u64, KernelError> {
        Ok(session::thread_session_id(call.arg(1)) as u64)
    }
    fn get_process_inherited_from_unique_process_id(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::inherited_from_unique_process_id(call.arg(1)))
    }
    fn get_process_job(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::job(call.arg(1)))
    }
    fn get_process_sequence_number(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::sequence_number(call.arg(1)))
    }
    fn get_process_priority_class(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::priority_class(call.arg(1)) as u64)
    }
    fn get_process_win32_window_station(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::win32_window_station(call.arg(1)))
    }
    fn get_process_security_port(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::security_port(call.arg(1)))
    }
    fn get_process_dxg_process(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::dxg_process(call.arg(1)))
    }
    fn is_system_process(call: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::is_system_process(call.arg(1)) as u64)
    }
    fn is_process_being_debugged(call: &Call) -> Result<u64, KernelError> {
        Ok(session::is_being_debugged(call.arg(1)) as u64)
    }
    fn get_current_process_win32_process(_: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::current_win32_process())
    }
    fn get_current_process_session_id(_: &Call) -> Result<u64, KernelError> {
        Ok(session::current_process_session_id() as u64)
    }
    fn get_process_session_id_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(session::query_ex(call.arg(1)) as u64)
    }
    fn get_process_exit_time(_: &Call) -> Result<u64, KernelError> {
        Ok(process_accessors::current_exit_time())
    }

    pub static GROUP: Group = Group {
        name: "thread-process-queries",
        names: &[
            "PsGetThreadTeb", "PsGetCurrentThreadTeb", "PsGetThreadWin32Thread", "PsGetCurrentThreadWin32Thread", "PsGetThreadCreateTime",
            "PsIsSystemThread", "PsIsThreadTerminating", "PsIsThreadImpersonating", "PsGetCurrentThread", "PsGetCurrentThreadProcess",
            "PsGetCurrentThreadProcessId", "PsGetThreadSessionId", "PsGetProcessInheritedFromUniqueProcessId", "PsGetProcessJob",
            "PsGetProcessSequenceNumber", "PsGetProcessPriorityClass", "PsGetProcessWin32WindowStation", "PsGetProcessSecurityPort",
            "PsGetProcessDxgProcess", "PsIsSystemProcess", "PsIsProcessBeingDebugged", "PsGetCurrentProcessWin32Process",
            "PsGetCurrentProcessSessionId", "PsGetProcessSessionIdEx", "PsGetProcessExitTime",
        ],
        handlers: &[
            get_thread_teb, get_current_thread_teb, get_thread_win32_thread, get_current_thread_win32_thread, get_thread_create_time,
            is_system_thread, is_thread_terminating, is_thread_impersonating, get_current_thread, get_current_thread_process,
            get_current_thread_process_id, get_thread_session_id, get_process_inherited_from_unique_process_id, get_process_job,
            get_process_sequence_number, get_process_priority_class, get_process_win32_window_station, get_process_security_port,
            get_process_dxg_process, is_system_process, is_process_being_debugged, get_current_process_win32_process,
            get_current_process_session_id, get_process_session_id_ex, get_process_exit_time,
        ],
        data_exports: &[],
    };
}
