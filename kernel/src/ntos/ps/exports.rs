//! Exports Ps* — `system32/win32/ntoskrnl/ps.js`.
//!
//! Threads de sistema sobre o escalonador cooperativo, identificadores do
//! processo e da thread correntes, notificações de criação de processo,
//! silos (o hospedeiro é NULL na ABI) e contextos de silo, e as células de
//! dado dos tipos Process/Thread/Job e do processo inicial.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::init::exports::{Call, Group};
use crate::ntos::mm::kernel_data;
use crate::ntos::ps::kernel_threads::{self, HandleOptions};
use crate::ntos::ps::process;
use crate::ntos::ps::notify::process as process_notify;
use crate::ntos::ps::silo::{contexts as silo_contexts, query as silo_query};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::eprocess;

/// O silo hospedeiro é representado por NULL na ABI.
const HOST_SILO: u64 = 0;

/// Estado compartilhado dos erros graves (a representação usa um único campo).
static THREAD_HARD_ERRORS_DISABLED: AtomicU32 = AtomicU32::new(0);

/// A célula PsJobType, publicada no primeiro acesso.
static JOB_TYPE: AtomicU64 = AtomicU64::new(0);

/// PsCreateSystemThread(handle*, access, oa, process, clientId*, start, context):
/// OBJ_KERNEL_HANDLE escolhe a tabela do System; senão, a do processo corrente.
fn create_system_thread(call: &Call) -> Result<u64, KernelError> {
    let attributes = call.arg(3);
    let flags = if attributes != 0 { guest::read32(attributes + 24) } else { 0 };
    let owner = if flags & 0x200 != 0 { process::get_system_process() } else { process::get_current_process() };
    kernel_threads::create_system_thread(call.arg(1), call.arg(6), call.arg(7), call.arg(2) as u32, call.arg(5), Some(HandleOptions { owner_process: Some(owner), attributes: flags }))?;
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

/// Anda a lista de processos ativos procurando o PID.
fn lookup_process_by_process_id(call: &Call) -> Result<u64, KernelError> {
    let pid = call.arg(1);
    let Some(found) = process::list_active_processes().into_iter().find(|entry| entry.pid == pid) else {
        return Ok(0xC000_000B); // STATUS_INVALID_CID
    };
    process::reference(found.address);
    guest::write64(call.arg(2), found.address);
    Ok(0)
}

fn get_process_id(call: &Call) -> Result<u64, KernelError> {
    Ok(guest::read64(call.arg(1) + eprocess::UNIQUE_PROCESS_ID))
}

fn get_job_silo(call: &Call) -> Result<u64, KernelError> {
    Ok(silo_query::get_job_silo(call.arg(1), call.arg(2)) as u64)
}

fn get_host_silo(_call: &Call) -> Result<u64, KernelError> {
    Ok(HOST_SILO)
}

fn is_host_silo(call: &Call) -> Result<u64, KernelError> {
    Ok((call.arg(1) == HOST_SILO) as u64)
}

/// Padrão do NT: erros graves habilitados (0).
fn get_thread_hard_errors_are_disabled(_call: &Call) -> Result<u64, KernelError> {
    Ok(THREAD_HARD_ERRORS_DISABLED.load(Ordering::Acquire) as u64)
}

/// Devolve o valor anterior.
fn set_thread_hard_errors_are_disabled(call: &Call) -> Result<u64, KernelError> {
    Ok(THREAD_HARD_ERRORS_DISABLED.swap((call.arg(1) != 0) as u32, Ordering::AcqRel) as u64)
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

/// Contagem real; no zero roda o cleanup registrado e libera.
fn dereference_silo_context(call: &Call) -> Result<u64, KernelError> {
    if silo_contexts::dereference(call.arg(1))?.is_none() {
        return Err(KernelError::new("invalid silo-context reference"));
    }
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

/// EPROCESS.CreateTime, separado do RundownProtect (+0x458).
fn get_process_create_time_quad_part(call: &Call) -> Result<u64, KernelError> {
    Ok(guest::read64(call.arg(1) + eprocess::CREATE_TIME))
}

/// ExReleaseRundownProtection em EPROCESS+0x458: a referência adquirida ao
/// consultar a tabela de handles pertence ao chamador.
/// PsReleaseProcessExitSynchronization: devolve a RundownProtect do EPROCESS
/// retida por PsAcquireProcessExitSynchronization.
fn release_process_exit_synchronization(call: &Call) -> Result<u64, KernelError> {
    crate::ntos::ex::rundown::release(call.arg(1) + crate::ntos::inc::nt_abi::eprocess::RUNDOWN_PROTECT)?;
    Ok(0)
}

fn initial_system_process() -> u64 {
    kernel_data::address("PsInitialSystemProcess").unwrap_or(0)
}

fn process_type() -> u64 {
    kernel_data::address("PsProcessType").unwrap_or(0)
}

fn thread_type() -> u64 {
    kernel_data::address("PsThreadType").unwrap_or(0)
}

/// O corpo do tipo Job e a célula que aponta para ele têm alocações distintas.
fn job_type() -> u64 {
    let current = JOB_TYPE.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let body = guest::alloc_bytes(0x40);
    let cell = guest::alloc_bytes(8);
    guest::write64(cell, body);
    match JOB_TYPE.compare_exchange(0, cell, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => cell,
        Err(existing) => {
            guest::free_bytes(cell);
            guest::free_bytes(body);
            existing
        }
    }
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
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::eprocess;

    fn get_process_exit_status(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read32(call.arg(1) + eprocess::EXIT_STATUS) as u64)
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
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::eprocess;

    fn get_process_exit_process_called(call: &Call) -> Result<u64, KernelError> {
        Ok(((guest::read32(call.arg(1) + eprocess::FLAGS) >> 2) & 1) as u64)
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

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::process_image;

    /// Os `0xC0000001 | 0` do original voltam com sinal estendido.
    fn widen(status: u32) -> u64 {
        if status & 0x8000_0000 != 0 {
            signed_status(status)
        } else {
            status as u64
        }
    }

    fn reference_process_file_pointer(call: &Call) -> Result<u64, KernelError> {
        Ok(widen(process_image::reference_file(call.arg(1), call.arg(2))?))
    }

    fn locate_process_image_name(call: &Call) -> Result<u64, KernelError> {
        Ok(widen(process_image::locate_name(call.arg(1), call.arg(2))?))
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
    use crate::ntos::inc::nt_abi::eprocess;

    fn get_process_image_file_name(call: &Call) -> Result<u64, KernelError> {
        Ok(call.arg(1).wrapping_add(eprocess::IMAGE_FILE_NAME))
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
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::eprocess;

    fn get_process_peb(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + eprocess::PEB))
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
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::eprocess;

    /// PS_PROTECTION completo; os testes de tipo usam só os três bits baixos.
    fn protection(process: u64) -> u8 {
        guest::read8(process + eprocess::PROTECTION)
    }

    fn get_process_section_base_address(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + eprocess::SECTION_BASE_ADDRESS))
    }

    /// Type, Audit e Signer no retorno.
    fn get_process_protection(call: &Call) -> Result<u64, KernelError> {
        Ok(protection(call.arg(1)) as u64)
    }

    /// Escreve o nível da seção (se houver saída) antes de ler o da imagem,
    /// preservando o resultado quando a saída aponta para um dos campos.
    fn get_process_signature_level(call: &Call) -> Result<u64, KernelError> {
        let process = call.arg(1);
        if call.arg(2) != 0 {
            guest::write8(call.arg(2), guest::read8(process + eprocess::SECTION_SIGNATURE_LEVEL));
        }
        Ok(guest::read8(process + eprocess::SIGNATURE_LEVEL) as u64)
    }

    fn is_protected_process(call: &Call) -> Result<u64, KernelError> {
        Ok((protection(call.arg(1)) & 7 != 0) as u64)
    }

    fn is_protected_process_light(call: &Call) -> Result<u64, KernelError> {
        Ok((protection(call.arg(1)) & 7 == 1) as u64)
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
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::eprocess;

    fn get_process_win32_process(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + eprocess::WIN32_PROCESS))
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
    use crate::ntos::ke::pcr;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::{eprocess, kthread};

    /// PEB do EWOW64PROCESS; sem ele o processo não tem ambiente WOW64.
    fn query_process(process: u64) -> u64 {
        let wow64_process = guest::read64(process + eprocess::WOW64_PROCESS);
        if wow64_process == 0 {
            0
        } else {
            guest::read64(wow64_process)
        }
    }

    fn get_process_wow64_process(call: &Call) -> Result<u64, KernelError> {
        Ok(query_process(call.arg(1)))
    }

    /// Processo da thread atual pela região de controle do processador.
    fn get_current_process_wow64_process(_: &Call) -> Result<u64, KernelError> {
        let region = pcr::get_pcr_address();
        if region == 0 {
            return Err(KernelError::new("current WOW64 query requires an initialized KPCR"));
        }
        let thread = guest::read64(region + pcr::layout::PRCB_CURRENT_THREAD);
        Ok(query_process(guest::read64(thread + kthread::APC_STATE_PROCESS)))
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

    use alloc::string::String;
    use alloc::vec::Vec;

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::mm::kernel_data;
    use crate::ntos::ps::process;
    use crate::ntos::se::security_attributes::{self, OutputWriter};
    use crate::ntos::se::token::tokens::{self, Token};
    use crate::rtl::KernelError;
    use crate::ntos::mm::guest_memory as guest;

    /// Token do kernel; o nome da operação identifica o erro de uso.
    fn owned_token(pointer: u64, operation: &str) -> Result<Token, KernelError> {
        tokens::get(pointer).ok_or_else(|| KernelError::new(alloc::format!("{operation}: invalid token")))
    }

    struct GuestWriter {
        base: u64,
    }

    impl OutputWriter for GuestWriter {
        fn u8(&mut self, offset: u64, value: u8) {
            guest::write8(self.base + offset, value);
        }
        fn u16(&mut self, offset: u64, value: u16) {
            guest::write16(self.base + offset, value);
        }
        fn u32(&mut self, offset: u64, value: u32) {
            guest::write32(self.base + offset, value);
        }
        fn u64(&mut self, offset: u64, value: u64) {
            guest::write64(self.base + offset, value);
        }
    }

    /// SeQuerySecurityAttributesToken: filtra os atributos do token e os copia
    /// para o buffer no layout nativo. Também usado por consumidores internos.
    pub fn query_attributes(token_pointer: u64, names_pointer: u64, name_count: u32, output: u64, output_length: u32, returned_length: u64) -> Result<u32, KernelError> {
        if (output != 0) != (output_length != 0) {
            return Ok(0xC000_000D);
        }
        let token = owned_token(token_pointer, "SeQuerySecurityAttributesToken")?;
        guest::write32(returned_length, 0);
        // A seleção começa com todos; os filtros só valem para a lista não vazia.
        let all = &token.security_attributes;
        let mut selected = all.clone();
        if !all.is_empty() && names_pointer != 0 {
            // Valida todos os UNICODE_STRING antes de ler os nomes.
            let mut descriptors = Vec::new();
            let mut odd_length = false;
            for index in 0..name_count as u64 {
                let descriptor = names_pointer + index * 16;
                let length = guest::read16(descriptor);
                let maximum = guest::read16(descriptor + 2);
                let text = guest::read64(descriptor + 8);
                if length == 0 || maximum == 0 || length > maximum || text == 0 {
                    return Ok(0xC000_000D);
                }
                descriptors.push((text, length));
                if length & 1 != 0 {
                    odd_length = true;
                }
            }
            // Só pares completos de bytes viram unidades UTF-16.
            let names: Vec<String> = descriptors
                .iter()
                .map(|&(text, length)| {
                    let units: Vec<u16> = (0..length as u64 / 2).map(|unit| guest::read16(text + unit * 2)).collect();
                    String::from_utf16_lossy(&units)
                })
                .collect();
            // Os nomes dos tokens têm comprimento par: um filtro ímpar não casa.
            let filtered = if odd_length { None } else { security_attributes::select(all, Some(&names))? };
            match filtered {
                Some(attributes) => selected = attributes,
                None => return Ok(0xC000_0225),
            }
        } else if !all.is_empty() && name_count != 0 {
            return Err(KernelError::new("SeQuerySecurityAttributesToken: null filter array"));
        }
        // Mede antes de escrever: buffer curto recebe só o tamanho necessário.
        let size = match security_attributes::measure(&selected) {
            Ok(size) => size,
            Err(status) => return Ok(status),
        };
        if (output_length as u64) < size {
            guest::write32(returned_length, size as u32);
            return Ok(0xC000_0023);
        }
        // Lista não vazia zera o buffer todo; a vazia toca só o cabeçalho.
        let clear = if all.is_empty() { 16 } else { output_length as u64 };
        for offset in 0..clear {
            guest::write8(output + offset, 0);
        }
        let status = security_attributes::copy_out(&selected, output, output_length as u64, &mut GuestWriter { base: output }, !all.is_empty());
        guest::write32(returned_length, size as u32);
        Ok(status)
    }

    /// Presença dos atributos de aplicativo do sistema e de identidade de
    /// pacote, independente de flags e valores (nada é deduzido do nome).
    fn process_attributes(token_pointer: u64, system_application: u64, package_identity: u64) -> Result<u64, KernelError> {
        if system_application == 0 && package_identity == 0 {
            return Ok(0);
        }
        let token = owned_token(token_pointer, "PsQueryProcessAttributesByToken")?;
        let present = |name: &str| -> Result<u8, KernelError> { Ok(security_attributes::select(&token.security_attributes, Some(&[String::from(name)]))?.is_some() as u8) };
        if system_application != 0 {
            guest::write8(system_application, present("WIN://SYSAPPID")?);
        }
        if package_identity != 0 {
            guest::write8(package_identity, present("WIN://PKG")?);
        }
        Ok(0)
    }

    /// Retém o token primário antes de entregar seu endereço.
    fn reference_primary_token(call: &Call) -> Result<u64, KernelError> {
        let token = process::get_primary_token(call.arg(1)).ok_or_else(|| KernelError::new("PsReferencePrimaryToken: invalid process"))?;
        tokens::retain(token)?;
        Ok(token)
    }

    /// Devolve exatamente uma referência adquirida pelo chamador.
    fn dereference_primary_token(call: &Call) -> Result<u64, KernelError> {
        if tokens::get(call.arg(1)).is_none() {
            return Err(KernelError::new("PsDereferencePrimaryToken: invalid token"));
        }
        tokens::release(call.arg(1))?;
        Ok(0)
    }

    fn query_security_attributes_token(call: &Call) -> Result<u64, KernelError> {
        Ok(query_attributes(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6))? as u64)
    }

    fn query_process_attributes_by_token(call: &Call) -> Result<u64, KernelError> {
        process_attributes(call.arg(1), call.arg(2), call.arg(3))
    }

    /// O valor é o endereço da célula exportada, não uma cópia.
    fn token_object_type_address() -> u64 {
        kernel_data::address("SeTokenObjectType").unwrap_or_else(|error| panic!("SeTokenObjectType: {error}"))
    }

    fn exports_address() -> u64 {
        kernel_data::address("SeExports").unwrap_or_else(|error| panic!("SeExports: {error}"))
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
        if silo_contexts::reference(call.arg(1))?.is_none() {
            return Err(KernelError::new("invalid silo-context reference"));
        }
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
    use crate::ntos::ke::pcr;
    use crate::ntos::ps::silo::query as silo_query;
    use crate::rtl::KernelError;

    fn current_server_silo(_: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::current_server_silo())
    }

    fn process_server_silo(call: &Call) -> Result<u64, KernelError> {
        Ok(silo_query::process_server_silo(call.arg(1)))
    }

    fn is_current_thread_in_server_silo(_: &Call) -> Result<u64, KernelError> {
        Ok((silo_query::current_server_silo() != 0) as u64)
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

    /// A máscara seleciona os indicadores de execução de KeIsExecutingDpc.
    fn is_executing_dpc(_: &Call) -> Result<u64, KernelError> {
        Ok((pcr::get_dpc_request_summary() & 0x10001) as u64)
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
    use crate::ntos::ex::rundown;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::kthread;

    fn get_thread_exit_status(call: &Call) -> Result<u64, KernelError> {
        let thread = call.arg(1);
        let protection = thread + kthread::RUNDOWN_PROTECT;
        if rundown::acquire(protection)? {
            rundown::release(protection)?;
            return Ok(0x103);
        }
        Ok(guest::read32(thread + kthread::EXIT_STATUS) as u64)
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
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::kthread;

    fn get_thread_id(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + kthread::CID_UNIQUE_THREAD))
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
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::inc::nt_abi::kthread;

    fn get_thread_process(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + kthread::PROCESS))
    }

    fn get_thread_process_id(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + kthread::CID_UNIQUE_PROCESS))
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

    use crate::ntos::init::exports::{invoke_handler, signed_status, Call, Group};
    use crate::ntos::inc::nt_abi::kthread;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ob::{object_types, open_pointer};
    use crate::rtl::KernelError;

    const STATUS_INVALID_PARAMETER_MIX: u32 = 0xC000_0030;
    const STATUS_INVALID_CID: u32 = 0xC000_000B;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

    fn open(call: &Call, thread: bool) -> Result<u64, KernelError> {
        let (output, access, attributes, client_id) = (call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4));
        // OBJECT_ATTRIBUTES: ObjectName @0x10, Attributes @0x18.
        let (name, flags) = if attributes != 0 { (guest::read64(attributes + 0x10), guest::read32(attributes + 0x18)) } else { (0, 0) };
        let object_type = if thread { object_types::thread_type().pointer } else { object_types::process_type().pointer };
        if (name != 0) == (client_id != 0) {
            return Ok(signed_status(STATUS_INVALID_PARAMETER_MIX));
        }
        if name != 0 {
            return invoke_handler("ObOpenObjectByName", &[attributes, object_type, 0, 0, access as u64, 0, output]);
        }
        let (process_id, thread_id) = (guest::read64(client_id), guest::read64(client_id + 8));
        let slot = guest::alloc_bytes(8);
        if slot == 0 {
            return Ok(signed_status(STATUS_INSUFFICIENT_RESOURCES));
        }
        let lookup = if thread { invoke_handler("PsLookupThreadByThreadId", &[thread_id, slot]) } else { invoke_handler("PsLookupProcessByProcessId", &[process_id, slot]) };
        let object = guest::read64(slot);
        guest::free_bytes(slot);
        let status = lookup? as u32;
        if status != 0 {
            return Ok(signed_status(status));
        }
        if thread && process_id != 0 && guest::read64(object + kthread::CID_UNIQUE_PROCESS) != process_id {
            invoke_handler("ObfDereferenceObject", &[object])?;
            return Ok(signed_status(STATUS_INVALID_CID));
        }
        let opened = open_pointer::open(object, flags, 0, access, object_type, 0, output);
        invoke_handler("ObfDereferenceObject", &[object])?;
        Ok(signed_status(opened?))
    }

    fn open_process(call: &Call) -> Result<u64, KernelError> {
        open(call, false)
    }

    fn open_thread(call: &Call) -> Result<u64, KernelError> {
        open(call, true)
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

    use crate::ntos::init::exports::{invoke_handler, signed_status, Call, Group};
    use crate::ntos::inc::nt_abi::kthread;
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ob::{object_types, open_pointer};
    use crate::ntos::ps::{enum_process_threads, process};
    use crate::rtl::KernelError;

    const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
    const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

    /// ObReferenceObjectByHandle em KernelMode: Ok(objeto) ou Err(status).
    fn reference(handle: u64, object_type: u64) -> Result<Result<u64, u32>, KernelError> {
        let slot = guest::alloc_bytes(8);
        if slot == 0 {
            return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
        }
        let status = invoke_handler("ObReferenceObjectByHandle", &[handle, 0, object_type, 0, slot, 0]);
        let object = guest::read64(slot);
        guest::free_bytes(slot);
        let status = status? as u32;
        Ok(if status == 0 { Ok(object) } else { Err(status) })
    }

    fn dereference(object: u64) -> Result<(), KernelError> {
        invoke_handler("ObfDereferenceObject", &[object]).map(|_| ())
    }

    fn get_next_process(call: &Call) -> Result<u64, KernelError> {
        let (handle, access, attributes, flags, output) = (call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32, call.arg(5));
        if flags & !1 != 0 {
            return Ok(signed_status(STATUS_INVALID_PARAMETER_4));
        }
        let backward = flags & 1 != 0;
        let process_type = object_types::process_type().pointer;
        let current = if handle == 0 {
            None
        } else {
            match reference(handle, process_type)? {
                Ok(object) => Some(object),
                Err(status) => return Ok(signed_status(status)),
            }
        };
        let mut list: alloc::vec::Vec<u64> = process::list_active_processes().into_iter().map(|entry| entry.address).collect();
        if backward {
            list.reverse();
        }
        let start = match current {
            Some(object) => list.iter().position(|&address| address == object).map_or(list.len(), |index| index + 1),
            None => 0,
        };
        if let Some(object) = current {
            dereference(object)?;
        }
        for &candidate in &list[start.min(list.len())..] {
            if open_pointer::open(candidate, attributes, 0, access, process_type, 0, output)? == 0 {
                return Ok(0);
            }
        }
        Ok(signed_status(STATUS_NO_MORE_ENTRIES))
    }

    fn get_next_thread(call: &Call) -> Result<u64, KernelError> {
        let (process_handle, thread_handle, access, attributes, flags, output) = (call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, call.arg(5) as u32, call.arg(6));
        if flags != 0 {
            return Ok(signed_status(STATUS_INVALID_PARAMETER_5));
        }
        let target = match reference(process_handle, object_types::process_type().pointer)? {
            Ok(object) => object,
            Err(status) => return Ok(signed_status(status)),
        };
        let thread_type = object_types::thread_type().pointer;
        // A referência da thread anterior passa para PsGetNextProcessThread.
        let mut previous = 0;
        if thread_handle != 0 {
            match reference(thread_handle, thread_type)? {
                Ok(thread) if guest::read64(thread + kthread::PROCESS) == target => previous = thread,
                Ok(thread) => {
                    dereference(thread)?;
                    dereference(target)?;
                    return Ok(signed_status(STATUS_INVALID_PARAMETER));
                }
                Err(status) => {
                    dereference(target)?;
                    return Ok(signed_status(status));
                }
            }
        }
        let status = loop {
            let next = enum_process_threads::get_next(target, previous)?;
            if next == 0 {
                break STATUS_NO_MORE_ENTRIES;
            }
            if open_pointer::open(next, attributes, 0, access, thread_type, 0, output)? == 0 {
                dereference(next)?;
                break 0;
            }
            previous = next;
        };
        dereference(target)?;
        Ok(signed_status(status))
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

    use alloc::collections::BTreeMap;

    use crate::ntos::ex::rundown;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::nt_abi::eprocess;
    use crate::ntos::ps::silo::query as silo_query;
    use crate::rtl::{KernelError, SpinLock};

    const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

    static SILO_HARD_REFERENCES: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

    fn acquire_process_exit_synchronization(call: &Call) -> Result<u64, KernelError> {
        if rundown::acquire(call.arg(1) + eprocess::RUNDOWN_PROTECT)? {
            Ok(0)
        } else {
            Ok(signed_status(STATUS_PROCESS_IS_TERMINATING))
        }
    }

    fn acquire_silo_hard_reference(call: &Call) -> Result<u64, KernelError> {
        let silo = call.arg(1);
        if silo == 0 {
            return Ok(0);
        }
        if silo_query::job_silo(silo) != silo {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        }
        *SILO_HARD_REFERENCES.lock().entry(silo).or_insert(0) += 1;
        Ok(0)
    }

    fn release_silo_hard_reference(call: &Call) -> Result<u64, KernelError> {
        let silo = call.arg(1);
        if silo == 0 {
            return Ok(0);
        }
        let mut references = SILO_HARD_REFERENCES.lock();
        match references.get_mut(&silo) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                references.remove(&silo);
            }
            None => return Err(KernelError::new("PsReleaseSiloHardReference sem referencia")),
        }
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
    use crate::ntos::inc::nt_abi::{eprocess, kthread};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ps::{process, session};
    use crate::ntos::se::token::thread as thread_tokens;
    use crate::rtl::KernelError;

    fn current_thread() -> u64 {
        process::get_current_thread()
    }
    fn current_process() -> u64 {
        process::get_current_process()
    }

    fn get_thread_teb(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + kthread::TEB))
    }
    fn get_current_thread_teb(_: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(current_thread() + kthread::TEB))
    }
    fn get_thread_win32_thread(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + kthread::WIN32_THREAD))
    }
    fn get_current_thread_win32_thread(_: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(current_thread() + kthread::WIN32_THREAD))
    }
    fn get_thread_create_time(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + kthread::CREATE_TIME))
    }
    /// MiscFlags.SystemThread (bit 10).
    fn is_system_thread(call: &Call) -> Result<u64, KernelError> {
        Ok((guest::read32(call.arg(1) + kthread::MISC_FLAGS) >> 10) as u64 & 1)
    }
    /// CrossThreadFlags.Terminated (bit 0).
    fn is_thread_terminating(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read32(call.arg(1) + kthread::CROSS_THREAD_FLAGS) as u64 & 1)
    }
    /// Há um token de personificação ativo na thread.
    fn is_thread_impersonating(call: &Call) -> Result<u64, KernelError> {
        Ok(thread_tokens::get(call.arg(1)).is_some() as u64)
    }
    fn get_current_thread(_: &Call) -> Result<u64, KernelError> {
        Ok(current_thread())
    }
    fn get_current_thread_process(_: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(current_thread() + kthread::PROCESS))
    }
    fn get_current_thread_process_id(_: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(current_thread() + kthread::CID_UNIQUE_PROCESS))
    }
    fn get_thread_session_id(call: &Call) -> Result<u64, KernelError> {
        Ok(session::query(guest::read64(call.arg(1) + kthread::PROCESS)) as u64)
    }
    fn get_process_inherited_from_unique_process_id(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + eprocess::INHERITED_FROM_UNIQUE_PROCESS_ID))
    }
    fn get_process_job(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + eprocess::JOB))
    }
    fn get_process_sequence_number(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + eprocess::SEQUENCE_NUMBER))
    }
    fn get_process_priority_class(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read8(call.arg(1) + eprocess::PRIORITY_CLASS) as u64)
    }
    fn get_process_win32_window_station(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + eprocess::WIN32_WINDOW_STATION))
    }
    fn get_process_security_port(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + eprocess::SECURITY_PORT))
    }
    fn get_process_dxg_process(call: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(call.arg(1) + eprocess::DXG_PROCESS))
    }
    /// Flags3.SystemProcess.
    fn is_system_process(call: &Call) -> Result<u64, KernelError> {
        Ok((guest::read32(call.arg(1) + eprocess::FLAGS3) & eprocess::SYSTEM_PROCESS_FLAG != 0) as u64)
    }
    fn is_process_being_debugged(call: &Call) -> Result<u64, KernelError> {
        Ok((guest::read64(call.arg(1) + eprocess::DEBUG_PORT) != 0) as u64)
    }
    fn get_current_process_win32_process(_: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(current_process() + eprocess::WIN32_PROCESS))
    }
    fn get_current_process_session_id(_: &Call) -> Result<u64, KernelError> {
        Ok(session::query(current_process()) as u64)
    }
    /// (ULONG)-1 para quem não pertence a uma sessão (o processo de sistema).
    fn get_process_session_id_ex(call: &Call) -> Result<u64, KernelError> {
        let process = call.arg(1);
        if guest::read32(process + eprocess::FLAGS3) & eprocess::SYSTEM_PROCESS_FLAG != 0 {
            return Ok(0xFFFF_FFFF);
        }
        Ok(session::query(process) as u64)
    }
    /// LARGE_INTEGER PsGetProcessExitTime(VOID): o ExitTime do processo corrente.
    fn get_process_exit_time(_: &Call) -> Result<u64, KernelError> {
        Ok(guest::read64(current_process() + eprocess::EXIT_TIME))
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
