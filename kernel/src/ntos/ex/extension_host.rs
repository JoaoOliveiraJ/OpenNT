//! Hosts e extensões do Executive: ExRegisterHost (interno),
//! ExRegisterExtension, ExUnregisterExtension e o par interno
//! ExGetExtensionTable/ExReleaseExtensionTable.
//!
//! Um componente do kernel registra um host (id, versão, número mínimo de
//! funções, a tabela de funções que o kernel oferece e uma rotina de
//! notificação); um driver registra a extensão desse host (a tabela de
//! funções dele) e recebe o próprio EX_HOST como EX_EXTENSION. O kernel usa
//! a tabela do driver entre ExGetExtensionTable e ExReleaseExtensionTable,
//! sob o rundown do host; a remoção espera esses usos terminarem.
//!
//! Conferido contra o ntoskrnl 19041: ExRegisterHost (rva 0x79dd70),
//! ExRegisterExtension (0x79db50), ExUnregisterExtension (0x956970),
//! ExpFindHost (0x79dec8), ExpDereferenceHost (0x956a5c),
//! ExGetExtensionTable (0x2f7618) e ExReleaseExtensionTable (0x2f75fc). A
//! lista de hosts (ExpHostList, sob ExpHostListLock) é o vetor `HOSTS`.

use alloc::vec::Vec;
use core::sync::atomic::Ordering::SeqCst;

use crate::hal::amd64::native_call;
use crate::ntos::ex::{pool_allocation, push_lock, rundown};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{ExPushLock, ExRundownRef, ListEntry};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::system_info;
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;

/// 'ExHE', a tag do EX_HOST.
const HOST_TAG: u32 = 0x4845_7845;
/// EX_EXTENSION_REGISTRATION_1: a versão de registro aceita (palavra alta).
const REGISTRATION_VERSION_1: u32 = 0x1_0000;

/// Razões passadas à rotina de notificação do host (ecx).
const NOTIFY_REGISTERING: u64 = 0;
const NOTIFY_REGISTERED: u64 = 1;
const NOTIFY_UNREGISTERING: u64 = 2;
const NOTIFY_UNREGISTERED: u64 = 3;

/// EX_HOST (0x60 bytes, 'ExHE'), o registro do host e, para o driver, o
/// EX_EXTENSION opaco. O EX_HOST_PARAMS copiado ocupa 0x18..0x40.
#[repr(C)]
pub struct ExHost {
    pub host_list_entry: ListEntry,
    pub ref_counter: Field<i32>,
    _pad_14: Reserved<0x4>,
    pub extension_id: Field<u16>,
    pub extension_version: Field<u16>,
    pub function_count: Field<u16>,
    _pad_1e: Reserved<0x2>,
    pub pool_type: Field<u32>,
    _pad_24: Reserved<0x4>,
    pub host_table: Field<u64>,
    pub notification_routine: Field<u64>,
    pub notification_context: Field<u64>,
    pub rundown_protection: ExRundownRef,
    pub push_lock: ExPushLock,
    pub function_table: Field<u64>,
    pub flags: Field<u32>,
    _pad_5c: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células e de estruturas do NT.
unsafe impl NtStruct for ExHost {}

const _: () = {
    assert!(core::mem::size_of::<ExHost>() == 0x60);
    assert!(core::mem::offset_of!(ExHost, ref_counter) == 0x10);
    assert!(core::mem::offset_of!(ExHost, extension_id) == 0x18);
    assert!(core::mem::offset_of!(ExHost, function_count) == 0x1C);
    assert!(core::mem::offset_of!(ExHost, pool_type) == 0x20);
    assert!(core::mem::offset_of!(ExHost, host_table) == 0x28);
    assert!(core::mem::offset_of!(ExHost, notification_routine) == 0x30);
    assert!(core::mem::offset_of!(ExHost, notification_context) == 0x38);
    assert!(core::mem::offset_of!(ExHost, rundown_protection) == 0x40);
    assert!(core::mem::offset_of!(ExHost, push_lock) == 0x48);
    assert!(core::mem::offset_of!(ExHost, function_table) == 0x50);
    assert!(core::mem::offset_of!(ExHost, flags) == 0x58);
};

/// EX_EXTENSION_REGISTRATION_1 (0x20 bytes) do driver.
#[repr(C)]
pub struct ExExtensionRegistration1 {
    pub extension_id: Field<u16>,
    pub extension_version: Field<u16>,
    pub function_count: Field<u16>,
    _pad_6: Reserved<0x2>,
    pub function_table: Field<u64>,
    /// PVOID *HostInterface: recebe a tabela de funções do host.
    pub host_interface: Field<u64>,
    pub driver_object: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ExExtensionRegistration1 {}

const _: () = {
    assert!(core::mem::size_of::<ExExtensionRegistration1>() == 0x20);
    assert!(core::mem::offset_of!(ExExtensionRegistration1, function_table) == 0x8);
    assert!(core::mem::offset_of!(ExExtensionRegistration1, host_interface) == 0x10);
};

/// EX_HOST_PARAMS de quem registra o host.
#[derive(Clone, Copy)]
pub struct HostParameters {
    pub extension_id: u16,
    pub extension_version: u16,
    /// Mínimo de funções que a extensão precisa oferecer.
    pub function_count: u16,
    pub pool_type: u32,
    pub host_table: u64,
    pub notification_routine: u64,
    pub notification_context: u64,
}

/// ExpHostList: os EX_HOST registrados, na ordem de registro.
static HOSTS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

fn host_at(host: u64) -> &'static ExHost {
    // SAFETY: só endereços de EX_HOST alocados por `register_host` (ou o
    // EX_EXTENSION devolvido ao driver, que é o mesmo bloco).
    unsafe { ExHost::at(host) }
}

/// ExpFindHost: o host do id e da versão, com uma referência a mais.
fn find_host(hosts: &[u64], extension_id: u16, extension_version: u16) -> Option<u64> {
    let host = hosts.iter().copied().find(|&host| host_at(host).extension_id.get() == extension_id && host_at(host).extension_version.get() == extension_version)?;
    host_at(host).ref_counter.atomic().fetch_add(1, SeqCst);
    Some(host)
}

/// ExpDereferenceHost: a última referência devolve o bloco ao pool.
fn dereference_host(host: u64) -> Result<(), KernelError> {
    if host_at(host).ref_counter.atomic().fetch_sub(1, SeqCst) == 1 {
        HOSTS.lock().retain(|&candidate| candidate != host);
        pool_allocation::free(host, 0)?;
    }
    Ok(())
}

/// A rotina de notificação do host, se houver: (razão, contexto).
fn notify(host: &ExHost, reason: u64) {
    let routine = host.notification_routine.get();
    if routine != 0 {
        native_call::call(routine, &[reason, host.notification_context.get()]);
    }
}

/// O push lock do host, exclusivo, numa região crítica (o par
/// KeEnterCriticalRegion/ExAcquirePushLockExclusive do NT).
fn with_host_locked<T>(host: &ExHost, body: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    critical_region::with_critical(|| {
        let lock = host.push_lock.address();
        push_lock::acquire_exclusive(lock, 0)?;
        let result = body();
        push_lock::release_exclusive(lock, 0)?;
        result
    })
}

/// ExRegisterHost: aloca o EX_HOST no pool pedido, com o rundown já
/// encerrado (sem extensão, ExGetExtensionTable falha) e o insere na lista.
/// Um id/versão já registrado devolve STATUS_OBJECT_NAME_COLLISION.
pub fn register_host(parameters: &HostParameters) -> Result<Result<u64, u32>, KernelError> {
    let host = pool_allocation::allocate_tagged(parameters.pool_type, ExHost::SIZE, HOST_TAG).unwrap_or(0);
    if host == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    let body = host_at(host);
    body.flags.set(body.flags.get() & !1);
    body.ref_counter.set(1);
    body.function_table.set(0);
    body.extension_id.set(parameters.extension_id);
    body.extension_version.set(parameters.extension_version);
    body.function_count.set(parameters.function_count);
    body.pool_type.set(parameters.pool_type);
    body.host_table.set(parameters.host_table);
    body.notification_routine.set(parameters.notification_routine);
    body.notification_context.set(parameters.notification_context);
    body.push_lock.value.set(0);
    body.host_list_entry.flink.set(0);
    body.host_list_entry.blink.set(0);
    let rundown_pointer = body.rundown_protection.address();
    rundown::initialize(rundown_pointer)?;
    rundown::wait(rundown_pointer)?;
    let mut hosts = HOSTS.lock();
    if let Some(existing) = find_host(&hosts, parameters.extension_id, parameters.extension_version) {
        drop(hosts);
        dereference_host(host)?;
        dereference_host(existing)?;
        return Ok(Err(STATUS_OBJECT_NAME_COLLISION));
    }
    hosts.push(host);
    Ok(Ok(host))
}

/// ExRegisterExtension(Extension*, RegistrationVersion, RegistrationInfo):
/// liga a tabela de funções do driver ao host do id/versão. A referência
/// tomada na busca fica com a extensão até o ExUnregisterExtension.
pub fn register_extension(extension: &Field<u64>, registration_version: u32, info: &ExExtensionRegistration1) -> Result<u32, KernelError> {
    if registration_version & 0xFFFF_0000 != REGISTRATION_VERSION_1 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let function_table = info.function_table.get();
    let function_count = info.function_count.get();
    if function_table == 0 && function_count != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let Some(host) = find_host(&HOSTS.lock(), info.extension_id.get(), info.extension_version.get()) else {
        return Ok(STATUS_NOT_FOUND);
    };
    let body = host_at(host);
    let refused = if function_count < body.function_count.get() {
        Some(STATUS_INVALID_PARAMETER)
    } else if (0..function_count as u64).any(|index| guest::read64(function_table + index * 8) == 0) {
        Some(STATUS_ACCESS_DENIED)
    } else {
        None
    };
    if let Some(status) = refused {
        dereference_host(host)?;
        return Ok(status);
    }
    let installed = with_host_locked(body, || {
        if body.function_table.get() != 0 || body.flags.get() & 1 != 0 {
            return Ok(false);
        }
        notify(body, NOTIFY_REGISTERING);
        // Sem tabela, o host recebe MmBadPointer (nunca NULL).
        body.function_table.set(if function_table != 0 { function_table } else { guest::read64(system_info::bad_pointer_cell()) });
        body.rundown_protection.count.atomic().swap(0, SeqCst);
        notify(body, NOTIFY_REGISTERED);
        Ok(true)
    })?;
    if !installed {
        dereference_host(host)?;
        return Ok(STATUS_OBJECT_NAME_COLLISION);
    }
    let host_interface = info.host_interface.get();
    if host_interface != 0 {
        // SAFETY: o PVOID* HostInterface do registro do driver (modo kernel).
        unsafe { Field::<u64>::at(host_interface) }.set(body.host_table.get());
    }
    extension.set(host);
    Ok(0)
}

/// ExUnregisterExtension(Extension): avisa o host, espera os usos da tabela
/// (o rundown), desliga a tabela, avisa de novo e solta a referência da
/// extensão.
pub fn unregister_extension(host: u64) -> Result<(), KernelError> {
    let body = host_at(host);
    with_host_locked(body, || {
        notify(body, NOTIFY_UNREGISTERING);
        rundown::wait(body.rundown_protection.address())?;
        body.function_table.set(0);
        notify(body, NOTIFY_UNREGISTERED);
        Ok(())
    })?;
    dereference_host(host)
}

/// ExGetExtensionTable: a tabela da extensão sob o rundown do host, ou 0
/// sem extensão (host nulo ou rundown encerrado).
pub fn get_extension_table(host: u64) -> Result<u64, KernelError> {
    if host == 0 || !rundown::acquire(host_at(host).rundown_protection.address())? {
        return Ok(0);
    }
    Ok(host_at(host).function_table.get())
}

/// ExReleaseExtensionTable.
pub fn release_extension_table(host: u64) -> Result<(), KernelError> {
    rundown::release(host_at(host).rundown_protection.address())
}
