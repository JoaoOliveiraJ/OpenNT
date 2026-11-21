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
//! o pcw.sys.
//!
//! ExpPcwHostCallback (rva 0x7cc250), a notificação do host: com a extensão
//! registrada (razão 1) o kernel registra os próprios conjuntos de
//! contadores no pcw.sys pelo PcwRegister, cada um com o
//! PCW_REGISTRATION_INFORMATION (versão 0x100, o nome, os descritores, a
//! rotina de callback e contexto NULL); com a extensão saindo (razão 2),
//! PcwUnregister de cada um que ficou registrado, e o handle volta a NULL.
//! O 19041 registra, nesta ordem, os dois do ETW (EtwRegisterCounters),
//! Synchronization, SynchronizationNuma, Processor Information
//! (`ex/processor_counter_set`), FileSystem Disk Activity
//! (`fsrtl/volume_support`, só com o PsIsDiskCountersEnabled) e Thermal
//! Zone Information. Diferença: o OpenNT registra só Processor Information
//! e FileSystem Disk Activity, os dois que o Gerenciador de Tarefas
//! consulta.
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
use crate::hal::amd64::routine_stubs::{self, Routine};
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

/// O EX_HOST_PARAMS do ExpInitSystemPhase1, com a notificação
/// ExpPcwHostCallback.
fn host_parameters() -> HostParameters {
    let notification_routine = routine_stubs::address("ExpPcwHostCallback").unwrap_or(0);
    HostParameters { extension_id: 1, extension_version: 1, function_count: 5, pool_type: 1, host_table: 0, notification_routine, notification_context: 0 }
}

/// Posições da tabela de funções do pcw.sys.
const REGISTER: u64 = 0;
const UNREGISTER: u64 = 1;
const CREATE_INSTANCE: u64 = 2;
const CLOSE_INSTANCE: u64 = 3;
const ADD_INSTANCE: u64 = 4;

/// O ExRegisterHost do ExpInitSystemPhase1; uma falha deixa o host nulo.
pub fn initialize() -> Result<(), KernelError> {
    HOST.store(extension_host::register_host(&host_parameters())?.unwrap_or(0), Ordering::Release);
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
/// pela rotina 2 do pcw.sys (os cinco argumentos como vieram); sem tabela
/// de extensão, *Instance = NULL e o status de ExpPcwDisabledStatus.
pub fn create_instance(instance: &Field<u64>, registration: u64, name: u64, count: u32, data: u64) -> u32 {
    if let Some(status) = with_extension(CREATE_INSTANCE, |routine| native_call::call(routine, &[instance.address(), registration, name, count as u64, data]) as u32) {
        return status;
    }
    instance.set(0);
    disabled_status()
}

/// PcwCloseInstance(Instance) (0x666940): pela rotina 3 do pcw.sys; sem
/// tabela de extensão, nada a fechar (o argumento não é lido).
pub fn close_instance(instance: u64) {
    with_extension(CLOSE_INSTANCE, |routine| native_call::call(routine, &[instance]));
}

/// Esquece o estado calculado (o teste de fase 6 reconsulta o Registro).
pub fn reset_enable_state_for_test() {
    ENABLE_STATE.store(0, Ordering::Release);
}

// ---- ExpPcwHostCallback: os conjuntos de contadores do kernel -------------

/// Um conjunto de contadores do kernel: o nome, os PCW_COUNTER_DESCRIPTOR
/// (Id, StructIndex, Offset, Size), a rotina de callback e o bloco
/// permanente com a célula do handle (o Pcwp*CounterSet) e o registro.
struct KernelCounterSet {
    name: &'static str,
    descriptors: &'static [(u16, u16, u16, u16)],
    routine: &'static str,
    block: AtomicU64,
}

/// PcwpProcessorCounterSet e PcwpFileSystemDiskIOCounterSet.
static PROCESSOR_COUNTER_SET: KernelCounterSet = KernelCounterSet { name: crate::ntos::ex::processor_counter_set::NAME, descriptors: &crate::ntos::ex::processor_counter_set::DESCRIPTORS, routine: "ExProcessorCounterSetCallback", block: AtomicU64::new(0) };
static FILE_SYSTEM_DISK_IO_COUNTER_SET: KernelCounterSet = KernelCounterSet { name: crate::ntos::fsrtl::volume_support::DISK_IO_COUNTER_SET_NAME, descriptors: &crate::ntos::fsrtl::volume_support::DISK_IO_COUNTER_DESCRIPTORS, routine: "FsRtlDiskIOCounterSetCallback", block: AtomicU64::new(0) };

/// PCW_VERSION_1.
const PCW_VERSION_1: u32 = 0x100;
/// O bloco de um conjunto: o handle (+0), o PCW_REGISTRATION_INFORMATION
/// (+0x10), o UNICODE_STRING do nome (+0x40), o texto (+0x50) e os
/// descritores.
const REGISTRATION_AT: u64 = 0x10;
const NAME_AT: u64 = 0x40;
const TEXT_AT: u64 = 0x50;

/// O bloco de um conjunto, em memória que o pcw.sys lê; montado uma vez.
fn counter_set_block(set: &KernelCounterSet) -> u64 {
    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::{PcwCounterDescriptor, PcwRegistrationInformation, UnicodeString};
    let existing = set.block.load(Ordering::Acquire);
    if existing != 0 {
        return existing;
    }
    let units: alloc::vec::Vec<u8> = set.name.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    let descriptors = (TEXT_AT + units.len() as u64 + 2).div_ceil(8) * 8;
    let size = descriptors + set.descriptors.len() as u64 * PcwCounterDescriptor::SIZE;
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return 0;
    }
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    guest::write_bytes(block + TEXT_AT, &units);
    // SAFETY: o UNICODE_STRING dentro do bloco recém-alocado.
    let name = unsafe { UnicodeString::at(block + NAME_AT) };
    name.length.set(units.len() as u16);
    name.maximum_length.set(units.len() as u16 + 2);
    name.buffer.set(block + TEXT_AT);
    for (index, &(id, struct_index, offset, length)) in set.descriptors.iter().enumerate() {
        // SAFETY: o descritor `index` dentro do bloco.
        let descriptor = unsafe { PcwCounterDescriptor::at(block + descriptors + index as u64 * PcwCounterDescriptor::SIZE) };
        descriptor.id.set(id);
        descriptor.struct_index.set(struct_index);
        descriptor.offset.set(offset);
        descriptor.size.set(length);
    }
    // SAFETY: o PCW_REGISTRATION_INFORMATION dentro do bloco.
    let information = unsafe { PcwRegistrationInformation::at(block + REGISTRATION_AT) };
    information.version.set(PCW_VERSION_1);
    information.name.set(block + NAME_AT);
    information.counter_count.set(set.descriptors.len() as u32);
    information.counters.set(block + descriptors);
    information.callback.set(routine_stubs::address(set.routine).unwrap_or(0));
    information.callback_context.set(0);
    match set.block.compare_exchange(0, block, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => block,
        Err(winner) => {
            guest::free_bytes(block);
            winner
        }
    }
}

/// A célula do handle de registro de um conjunto (no começo do bloco).
fn handle_cell(block: u64) -> &'static Field<u64> {
    // SAFETY: a célula de 8 bytes no começo do bloco permanente.
    unsafe { <Field<u64> as crate::ntos::inc::field::NtStruct>::at(block) }
}

/// PcwRegister(&Pcwp*CounterSet, &Info) de um conjunto do kernel.
fn register_counter_set(set: &KernelCounterSet) {
    let block = counter_set_block(set);
    if block == 0 {
        return;
    }
    let status = register(handle_cell(block), block + REGISTRATION_AT);
    crate::debug_print!("[pcw] PcwRegister de {}: {:#x} (registro {:#x})", set.name, status, handle_cell(block).get());
}

/// PcwUnregister do handle, se houver, e o handle volta a NULL.
fn unregister_counter_set(set: &KernelCounterSet) {
    let block = set.block.load(Ordering::Acquire);
    if block == 0 {
        return;
    }
    let handle = handle_cell(block);
    let registration = handle.get();
    if registration != 0 {
        unregister(registration);
        handle.set(0);
    }
}

/// ExpPcwHostCallback(Reason, Context).
pub fn host_callback(reason: u32) {
    match reason {
        1 => {
            register_counter_set(&PROCESSOR_COUNTER_SET);
            if crate::ntos::ps::process_accessors::disk_counters_enabled() {
                register_counter_set(&FILE_SYSTEM_DISK_IO_COUNTER_SET);
            }
        }
        2 => {
            unregister_counter_set(&PROCESSOR_COUNTER_SET);
            unregister_counter_set(&FILE_SYSTEM_DISK_IO_COUNTER_SET);
        }
        _ => {}
    }
}

fn host_callback_routine(call: &crate::ntos::init::exports::Call) -> Result<u64, KernelError> {
    host_callback(call.arg(1) as u32);
    Ok(0)
}

/// A notificação do host, entregue ao ExRegisterHost.
pub const ROUTINES: &[Routine] = &[Routine { name: "ExpPcwHostCallback", handler: host_callback_routine }];
