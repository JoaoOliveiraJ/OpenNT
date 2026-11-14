//! Contadores de desempenho (PCW) vistos do ntoskrnl — PcwRegister 0x781700,
//! PcwUnregister 0x956d00, PcwAddInstance 0x667bc0, PcwCreateInstance
//! 0x666980, PcwCloseInstance 0x666940, ExpPcwDisabledStatus 0x956c28
//! (ntoskrnl 19041).
//!
//! No Windows 10 a implementação dos conjuntos de contadores não mora no
//! ntoskrnl: ela é o pcw.sys (driver de boot, grupo "System Reserved"), que
//! se registra no host de extensão ExpPcwExtensionHost — criado no
//! ExpInitSystemPhase1 por ExRegisterHost com ExtensionId 1, ExtensionVersion
//! 1, FunctionCount 5, PagedPool, sem tabela do host e com a notificação
//! ExpPcwHostCallback. Cada export Pcw* é só um despachante:
//!     table = ExGetExtensionTable(ExpPcwExtensionHost)
//!     table != NULL -> table[i](...) e ExReleaseExtensionTable
//!     table == NULL -> ExpPcwDisabledStatus()
//! com i = 0 Register, 1 Unregister, 2 CreateInstance, 3 CloseInstance,
//! 4 AddInstance. Sem extensão, PcwRegister/PcwCreateInstance zeram o handle
//! de saída e PcwUnregister/PcwCloseInstance não fazem nada.
//!
//! O OpenNT registra o host e despacha para o pcw.sys real quando ele está
//! carregado; reimplementar os conjuntos de contadores aqui seria reescrever
//! o pcw.sys. Diferença: o ExpPcwHostCallback, que ao chegar a extensão
//! registra os conjuntos de contadores do próprio kernel (sincronização,
//! processador, ...), não existe ainda; o host fica sem notificação.
//!
//! ExpPcwDisabledStatus calcula uma vez ExpPcwEnableState a partir de
//! HKLM\...\Services\pcw\Start (RtlQueryRegistryValues RTL_REGISTRY_SERVICES,
//! DIRECT|TYPECHECK, REG_DWORD, default 0xFFFFFFFF quando só o valor falta;
//! chave ausente = OBJECT_NAME_NOT_FOUND tratado como sucesso com 0):
//!     Start != 0 -> estado 1: o pcw foi desligado de propósito, e os Pcw*
//!                   devolvem STATUS_SUCCESS com handle NULL;
//!     Start == 0 -> estado 2: o pcw deveria estar carregado (boot), e os Pcw*
//!                   devolvem STATUS_NOT_IMPLEMENTED.
//! Um erro da consulta (tipo errado) volta sem gravar o estado.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::cm::registry;
use crate::ntos::ex::extension_host::{self, HostParameters};
use crate::ntos::inc::types::Field;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const REG_DWORD: u32 = 4;
const PCW_SERVICE_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\pcw";

/// ExpPcwEnableState: 0 = ainda não consultado, 1 = desligado, 2 = esperado.
static ENABLE_STATE: AtomicU32 = AtomicU32::new(0);

/// Valor de Start como o RtlQueryRegistryValues DIRECT o deixaria no DWORD.
fn query_start() -> Result<u32, u32> {
    if registry::node_by_path(PCW_SERVICE_KEY).is_none() {
        return Ok(0);
    }
    match registry::read_value_by_path(PCW_SERVICE_KEY, "Start") {
        None => Ok(0xFFFF_FFFF),
        Some(value) if value.value_type != REG_DWORD => Err(STATUS_OBJECT_TYPE_MISMATCH),
        Some(value) => {
            let mut start = 0u32;
            for (index, &byte) in value.data.iter().take(4).enumerate() {
                start |= (byte as u32) << (index * 8);
            }
            Ok(start)
        }
    }
}

/// ExpPcwDisabledStatus.
pub fn disabled_status() -> u32 {
    let mut state = ENABLE_STATE.load(Ordering::Acquire);
    if state == 0 {
        state = match query_start() {
            Ok(start) => if start != 0 { 1 } else { 2 },
            Err(status) => return status,
        };
        ENABLE_STATE.store(state, Ordering::Release);
    }
    if state == 1 { 0 } else { STATUS_NOT_IMPLEMENTED }
}

/// ExpPcwExtensionHost.
static HOST: AtomicU64 = AtomicU64::new(0);

const PCW_HOST: HostParameters = HostParameters { extension_id: 1, extension_version: 1, function_count: 5, pool_type: 1, host_table: 0, notification_routine: 0, notification_context: 0 };

/// Posições da tabela de funções do pcw.sys.
const REGISTER: u64 = 0;
const UNREGISTER: u64 = 1;
const ADD_INSTANCE: u64 = 4;

/// O ExRegisterHost do ExpInitSystemPhase1; uma falha deixa o host nulo.
pub fn initialize() -> Result<(), KernelError> {
    HOST.store(extension_host::register_host(&PCW_HOST)?.unwrap_or(0), Ordering::Release);
    Ok(())
}

/// O host do PCW (0 sem registro).
pub fn host() -> u64 {
    HOST.load(Ordering::Acquire)
}

/// A rotina `index` da extensão (o pcw.sys), chamada sob o rundown do host;
/// `None` sem extensão.
fn with_extension<T>(index: u64, body: impl FnOnce(u64) -> T) -> Option<T> {
    let host = host();
    let table = extension_host::get_extension_table(host).unwrap_or(0);
    if table == 0 {
        return None;
    }
    let result = body(guest::read64(table + index * 8));
    let _ = extension_host::release_extension_table(host);
    Some(result)
}

/// O pcw.sys registrou a extensão.
pub fn extension_registered() -> bool {
    with_extension(REGISTER, |_| ()).is_some()
}

/// PcwRegister(Registration*, Info): pelo pcw.sys; sem extensão,
/// *Registration = NULL e o status de ExpPcwDisabledStatus.
pub fn register(registration: &Field<u64>, info: u64) -> u32 {
    if let Some(status) = with_extension(REGISTER, |routine| native_call::call(routine, &[registration.address(), info]) as u32) {
        return status;
    }
    registration.set(0);
    disabled_status()
}

/// PcwUnregister(Registration): pelo pcw.sys; sem extensão, nada a desfazer.
pub fn unregister(registration: u64) {
    with_extension(UNREGISTER, |routine| native_call::call(routine, &[registration]));
}

/// PcwAddInstance(Buffer, Name, Id, Count, Data): pelo pcw.sys; sem
/// extensão, o status de ExpPcwDisabledStatus (os argumentos não são lidos).
pub fn add_instance(buffer: u64, name: u64, id: u32, count: u32, data: u64) -> u32 {
    with_extension(ADD_INSTANCE, |routine| native_call::call(routine, &[buffer, name, id as u64, count as u64, data]) as u32).unwrap_or_else(disabled_status)
}

/// PcwCreateInstance(Instance*, Registration, Name, Count, Data) (0x666980):
/// sem tabela de extensão, *Instance = NULL e o status de
/// ExpPcwDisabledStatus.
pub fn create_instance(instance: &Field<u64>, _registration: u64, _name: u64, _count: u32, _data: u64) -> u32 {
    instance.set(0);
    disabled_status()
}

/// PcwCloseInstance(Instance) (0x666940): sem tabela de extensão, nada a
/// fechar (o argumento não é lido).
pub fn close_instance(_instance: u64) {}

/// Esquece o estado calculado (o teste de fase 6 reconsulta o Registro).
pub fn reset_enable_state_for_test() {
    ENABLE_STATE.store(0, Ordering::Release);
}
