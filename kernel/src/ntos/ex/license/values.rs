//! Seleção do contexto de licenciamento.
//!
//! O ProductPolicy é capturado no CmGetSystemControlValues, logo depois de a
//! hive SYSTEM ser ligada (`cm/hive_init.rs`, na fase 1: antes disso só a
//! semente em memória responde, sem a política); o contexto do host é criado
//! e a política publicada em seguida (`init/phase1.rs`), já com os exports
//! de seção do kernel e antes do primeiro driver.

use alloc::vec::Vec;

use crate::ntos::ex::license::boot::{self as license_boot, BootProviders};
use crate::ntos::ex::license::service as license_service;
use crate::ntos::ex::license::registry as license_registry;
use crate::ntos::ex::license::special::Providers;
use crate::ntos::cm::registry;
use crate::ntos::ps::silo::query as silo_query;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Ejob, EserversiloGlobals};

pub const PRODUCT_OPTIONS: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions";

struct Values {
    captured: bool,
    policy: Option<(u32, Vec<u8>)>,
    host_context: u64,
}

static VALUES: SpinLock<Values> = SpinLock::new(Values { captured: false, policy: None, host_context: 0 });

/// Cópia própria deste boot, da hive SYSTEM já ligada: mudanças posteriores
/// da hive não trocam o que foi entregue ao contexto nativo.
pub fn init() {
    let mut values = VALUES.lock();
    if values.captured {
        return;
    }
    values.policy = registry::read_value_by_path(PRODUCT_OPTIONS, "ProductPolicy").map(|value| (value.value_type, value.data));
    values.captured = true;
}

pub fn init_runtime(providers: &BootProviders) -> Result<(), KernelError> {
    // Os callbacks Cloudbook do ProductOptions (os nomes de dispositivo do
    // SLQueryLicenseValueInternal) leem a classe 0xBE pelo
    // ZwQuerySystemInformation de modo kernel.
    license_registry::set_system_information(Some(query_system_information));
    let policy = {
        let values = VALUES.lock();
        if values.host_context != 0 {
            return Ok(());
        }
        if !values.captured {
            return Err(KernelError::new("ProductPolicy: boot capture not initialized"));
        }
        values.policy.clone()
    };
    let created = license_boot::create(policy.as_ref().map(|(value_type, data)| (*value_type, data.as_slice())), providers)?;
    let (context, _) = created.map_err(|status| KernelError::with_status("ProductPolicy: could not allocate boot context", status))?;
    let mut values = VALUES.lock();
    values.host_context = context;
    values.policy = None;
    Ok(())
}

/// O ZwQuerySystemInformation de modo kernel (`ex/system_information`) com
/// o status de uma falha interna no lugar do erro.
fn query_system_information(class: u32, buffer: u64, length: u32, returned: u64) -> u32 {
    crate::ntos::ex::system_information::query(class, buffer, length, returned).unwrap_or_else(|error| error.status)
}

/// Um server silo empresta o contexto de SILO_GLOBALS; ausência ou
/// corrupção nunca autoriza consultar a política do hospedeiro.
pub fn current_context() -> Result<u64, KernelError> {
    let host = VALUES.lock().host_context;
    if host == 0 {
        return Err(KernelError::new("ProductPolicy: native boot context not initialized"));
    }
    let silo = silo_query::current_server_silo();
    if silo == 0 {
        return Ok(host);
    }
    // SAFETY: o silo de servidor corrente e seus globais vivos.
    let globals = unsafe { Ejob::at(silo) }.server_silo_globals.get();
    Ok(unsafe { EserversiloGlobals::at(globals) }.exp_license_state.get())
}

/// ZwQueryLicenseValue pelo contexto do silo corrente.
pub fn query(name: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64) -> Result<u32, KernelError> {
    let mut selected: Result<u64, KernelError> = Ok(0);
    let status = license_service::query_kernel(|| {
        selected = current_context();
        *selected.as_ref().unwrap_or(&0)
    }, name, type_pointer, buffer, capacity, length, &Providers::default())?;
    selected?;
    Ok(status)
}

/// O g_kernelCallbacks+0x128 do 19041 (rva 0x71f3c0, posto pelo
/// ClipInitHandles), por onde o SystemPolicyInformation lê os valores: o
/// contexto de licença do server silo corrente e o
/// SLQueryLicenseValueInternal (o provedor do ClipSp, quando registrado,
/// responde no lugar dele), sem as guardas de argumento do
/// ZwQueryLicenseValue.
pub fn query_silo(name: u64, type_pointer: u64, buffer: u64, capacity: u32, length: u64) -> Result<u32, KernelError> {
    let context = current_context()?;
    let providers = Providers::default();
    if let Some(query_license) = providers.query_license {
        return Ok(query_license(context, name, type_pointer, buffer, capacity, length));
    }
    license_service::query(context, name, type_pointer, buffer, capacity, length, &providers)
}

pub fn host_context() -> u64 {
    VALUES.lock().host_context
}

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
/// O maior DataSize aceito pelo NtQueryLicenseValue.
const MAXIMUM_DATA_SIZE: u32 = 0x80_0000;

/// NtQueryLicenseValue(ValueName, Type, Data, DataSize, ResultDataSize) com
/// PreviousMode de usuário, como o ntoskrnl 19041 (rva 0x71f450): sem nome
/// ou sem ResultDataSize, ou Data nulo com DataSize, é
/// STATUS_INVALID_PARAMETER; DataSize acima de 8 MB, STATUS_NO_MEMORY. O
/// nome (Length par e não nulo, buffer alinhado) e os buffers de saída são
/// sondados e o nome é copiado; a consulta roda sobre cópias do kernel e
/// devolve Type e ResultDataSize mesmo na falha; os dados só vão ao usuário
/// no sucesso, e STATUS_BUFFER_TOO_SMALL quando não cabem.
pub fn query_user(name: u64, type_pointer: u64, data: u64, data_size: u32, result_pointer: u64) -> Result<u32, KernelError> {
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ps::user_probe::{probe_user_read, probe_user_write};
    use crate::ntos::rtl::guest_strings;
    if name == 0 || result_pointer == 0 || (data == 0 && data_size != 0) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if data_size > MAXIMUM_DATA_SIZE {
        return Ok(STATUS_NO_MEMORY);
    }
    // UNICODE_STRING de usuário capturada (Length, Buffer).
    if !probe_user_read(name, 16) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let (Ok(length), Ok(buffer)) = (guest::try_read::<u16>(name), guest::try_read::<u64>(name + 8)) else { return Ok(STATUS_ACCESS_VIOLATION) };
    if buffer == 0 || length == 0 || length & 1 != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if buffer & 1 != 0 {
        return Ok(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !probe_user_read(buffer, length as u64) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let Ok(units) = guest::try_read_bytes(buffer, length as usize) else { return Ok(STATUS_ACCESS_VIOLATION) };
    if (type_pointer != 0 && !probe_user_write(type_pointer, 4)) || (data != 0 && data_size != 0 && !probe_user_write(data, data_size as u64)) || !probe_user_write(result_pointer, 4) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let initial_type = if type_pointer != 0 { guest::try_read::<u32>(type_pointer) } else { Ok(0) };
    let (Ok(initial_type), Ok(initial_result)) = (initial_type, guest::try_read::<u32>(result_pointer)) else { return Ok(STATUS_ACCESS_VIOLATION) };
    // Cópias do kernel: a UNICODE_STRING com o nome, Type, ResultDataSize e
    // os dados.
    let frame = guest::alloc_bytes(16 + length as u64 + 16);
    let kernel_data = if data != 0 && data_size != 0 { guest::alloc_bytes(data_size as u64) } else { 0 };
    if frame == 0 || (data != 0 && data_size != 0 && kernel_data == 0) {
        guest::free_bytes(frame);
        guest::free_bytes(kernel_data);
        return Ok(STATUS_NO_MEMORY);
    }
    let kernel_name = frame + 16;
    let kernel_type = (kernel_name + length as u64 + 3) & !3;
    let kernel_result = kernel_type + 4;
    guest::write_bytes(kernel_name, &units);
    guest_strings::write_string_fields(frame, length, length, kernel_name);
    guest::write32(kernel_type, initial_type);
    guest::write32(kernel_result, initial_result);
    let mut status = query(frame, kernel_type, kernel_data, data_size, kernel_result)?;
    let result_size = guest::read32(kernel_result);
    let written = (|| -> Result<(), KernelError> {
        if type_pointer != 0 {
            guest::try_write::<u32>(type_pointer, guest::read32(kernel_type))?;
        }
        guest::try_write::<u32>(result_pointer, result_size)?;
        if status & 0x8000_0000 == 0 && data != 0 {
            if data_size >= result_size {
                guest::try_write_bytes(data, &guest::read_bytes(kernel_data, result_size as usize))?;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
        }
        Ok(())
    })();
    if written.is_err() {
        status = STATUS_ACCESS_VIOLATION;
    }
    guest::free_bytes(frame);
    guest::free_bytes(kernel_data);
    Ok(status)
}
