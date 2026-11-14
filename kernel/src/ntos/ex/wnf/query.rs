//! Consulta WNF Nt/Zw.
//!
//! Nomes definidos sem instância e sem dados permanentes devolvem vazio sem
//! criar uma instância só para a leitura. O caminho de usuário entra com as
//! capturas de `ps/user/state` (fase 7) por [`UserQuery`].

use crate::ntos::ex::wnf::data_block as state_data;
use crate::ntos::ex::wnf::name::{self as wnf_name, DecodedName, SuppliedType};
use crate::ntos::ex::wnf::namespace::{self, NameDefinition};
use crate::ntos::ex::wnf::scope_capture::{self, Captured};
use crate::ntos::ke::critical_region;
use crate::ntos::ps::{previous_mode, process};
use crate::rtl::KernelError;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::status::STATUS_ACCESS_VIOLATION;
use crate::ntos::mm::guest_memory as guest;

/// Entradas capturadas do modo usuário: capacidade e TypeId copiado.
pub struct UserInputs {
    pub capacity: u32,
    pub type_identifier: SuppliedType,
}

/// Capturas e verificações do caminho de usuário.
#[derive(Clone, Copy)]
pub struct UserQuery {
    pub probe_read: fn(u64, u64) -> bool,
    pub capture_inputs: fn(u64, u64, u64, u64) -> Result<UserInputs, u32>,
    pub check_access: fn(u64, u32) -> u32,
    pub check_cross_scope: fn(&DecodedName) -> Result<u32, KernelError>,
}

#[allow(clippy::too_many_arguments)]
fn query_captured(name: &DecodedName, type_identifier: SuppliedType, captured: &Captured, change_stamp: u64, buffer: u64, capacity: u32, returned_length: u64, user: Option<UserQuery>) -> Result<u32, KernelError> {
    let process = if user.is_some() { process::get_current_process() } else { process::get_system_process() };
    let resolved = if user.is_some() { namespace::resolve_user_scope(process, name.scope, captured.identity)? } else { namespace::resolve_kernel_scope(process, name.scope, captured.identity)? };
    let scope = match resolved {
        Ok(scope) => scope,
        Err(status) => return Ok(status),
    };
    let check_access = user.map(|user| user.check_access);
    let checker = |descriptor: u64, desired: u32| check_access.map_or(0, |check| check(descriptor, desired));
    let check: Option<&dyn Fn(u64, u32) -> u32> = if user.is_some() { Some(&checker) } else { None };
    let mut state = None;
    let result = (|| -> Result<u32, KernelError> {
        match namespace::lookup_name(scope, name.decoded_name)? {
            Err(0xC000_0034) => {
                if name.lifetime == 3 {
                    return Ok(0xC000_0034);
                }
                let definition = match namespace::lookup_definition(name.decoded_name)? {
                    Ok(definition) => definition,
                    Err(status) => return Ok(status),
                };
                // Consulta valida GUID e leitura com comprimento zero; o modo
                // kernel dispensa a avaliação do sujeito.
                let status = wnf_name::validate(&definition.description(), 0, type_identifier, user.is_none(), check, 1);
                if status & 0x8000_0000 != 0 {
                    return Ok(status);
                }
                if name.permanent_data || name.scope == 5 {
                    let created = namespace::create_name(scope, name.decoded_name, NameDefinition::from(&definition), process)?;
                    definition.release();
                    match created {
                        Ok(created) => state = Some(created),
                        Err(status) => return Ok(status),
                    }
                }
            }
            Err(status) => return Ok(status),
            Ok(found) => {
                state = Some(found);
                let status = wnf_name::validate(&found.description(), 0, type_identifier, user.is_none(), check, 1);
                if status & 0x8000_0000 != 0 {
                    return Ok(status);
                }
            }
        }
        if let Some(state) = &state {
            return state_data::read(state, change_stamp, buffer, capacity, returned_length);
        }
        // A ordem é observável quando as saídas se sobrepõem. As saídas de
        // modo usuário já foram sondadas; a escrita sondada cobre a perda do
        // mapeamento entre a sonda e aqui.
        if guest::try_write::<u32>(change_stamp, 0).is_err() || guest::try_write::<u32>(returned_length, 0).is_err() {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        Ok(0)
    })();
    if let Some(state) = state {
        namespace::release_name(&state)?;
    }
    namespace::release_scope(scope)?;
    result
}

/// NtQueryWnfStateData/ZwQueryWnfStateData: o tamanho de entrada é lido
/// depois do nome e antes do escopo.
pub fn query(state_name: u64, type_identifier: u64, explicit_scope: u64, change_stamp: u64, buffer: u64, returned_length: u64, user: Option<UserQuery>) -> Result<u32, KernelError> {
    let execute = || -> Result<u32, KernelError> {
        critical_region::enter_critical()?;
        let mut captured = None;
        let result = (|| -> Result<u32, KernelError> {
            if let Some(user) = user {
                if !(user.probe_read)(state_name, 8) {
                    return Ok(0xC000_0005);
                }
            }
            let Ok(encoded) = guest::try_read::<u64>(state_name) else { return Ok(STATUS_ACCESS_VIOLATION) };
            let name = wnf_name::decode(encoded);
            if name.status != 0 {
                return Ok(name.status);
            }
            let inputs = match user {
                Some(user) => match (user.capture_inputs)(type_identifier, change_stamp, buffer, returned_length) {
                    Ok(inputs) => inputs,
                    Err(status) => return Ok(status),
                },
                // SAFETY: o PULONG BufferSize de um chamador de modo kernel.
                None => UserInputs { capacity: unsafe { Field::<u32>::at(returned_length) }.get(), type_identifier: if type_identifier != 0 { SuppliedType::Pointer(type_identifier) } else { SuppliedType::None } },
            };
            let capture = if user.is_some() { scope_capture::capture_user(name.scope, explicit_scope)? } else { scope_capture::capture_kernel(name.scope, explicit_scope)? };
            let capture = match capture {
                Ok(capture) => captured.insert(capture),
                Err(status) => return Ok(status),
            };
            if let Some(user) = user {
                if explicit_scope != 0 {
                    let status = (user.check_cross_scope)(&name)?;
                    if status & 0x8000_0000 != 0 {
                        return Ok(status);
                    }
                }
            }
            query_captured(&name, inputs.type_identifier, capture, change_stamp, buffer, inputs.capacity, returned_length, user)
        })();
        let left = critical_region::leave_critical();
        if let Some(captured) = captured {
            captured.release()?;
        }
        let result = result?;
        left?;
        Ok(result)
    };
    if user.is_some() { execute() } else { previous_mode::with_kernel(execute)? }
}

// ---- ZwQueryWnfStateNameInformation ---------------------------------------
//
// NtQueryWnfStateNameInformation do 19041 em KernelMode: o nome é capturado
// e decodificado, o escopo explícito capturado, e só então a classe (acima
// de WnfInfoIsQuiescent = STATUS_INVALID_INFO_CLASS) e o tamanho (menos de
// um ULONG = STATUS_INVALID_PARAMETER) são conferidos. O escopo resolve
// pelo System; a instância do nome é procurada na árvore do escopo e, se não
// há instância de um nome não temporário, a definição permanente responde
// por ele. KernelMode dispensa o ExpWnfCheckCallerAccess. O ULONG de saída:
// - WnfInfoStateNameExist (0): 1 com instância ou definição; um nome sem
//   nenhuma das duas dá 0 com STATUS_SUCCESS;
// - WnfInfoSubscribersPresent (1): DataSubscribersCount != 0 (0 sem
//   instância);
// - WnfInfoIsQuiescent (2): CurrentDeliveryCount == 0 (1 sem instância).
// Nas classes 1 e 2 um nome sem instância nem definição devolve
// STATUS_OBJECT_NAME_NOT_FOUND sem gravar a saída.

/// WNF_STATE_NAME_INFORMATION.
const WNF_INFO_STATE_NAME_EXIST: u32 = 0;
const WNF_INFO_SUBSCRIBERS_PRESENT: u32 = 1;
const WNF_INFO_IS_QUIESCENT: u32 = 2;

/// A resposta de uma classe para a instância (ou só a definição) achada.
fn name_information(class: u32, instance: Option<&state_data::NameState>) -> u32 {
    match (class, instance) {
        (WNF_INFO_SUBSCRIBERS_PRESENT, Some(state)) => (state.data_subscribers_count() != 0) as u32,
        (WNF_INFO_SUBSCRIBERS_PRESENT, None) => 0,
        (WNF_INFO_IS_QUIESCENT, Some(state)) => (state.current_delivery_count() == 0) as u32,
        _ => 1,
    }
}

fn query_name_information_captured(name: &DecodedName, class: u32, captured: &Captured) -> Result<Result<u32, u32>, KernelError> {
    let scope = match namespace::resolve_kernel_scope(process::get_system_process(), name.scope, captured.identity)? {
        Ok(scope) => scope,
        Err(status) => return Ok(Err(status)),
    };
    let result = (|| -> Result<Result<u32, u32>, KernelError> {
        match namespace::lookup_name(scope, name.decoded_name)? {
            Ok(found) => {
                let value = name_information(class, Some(&found));
                namespace::release_name(&found)?;
                Ok(Ok(value))
            }
            Err(0xC000_0034) if name.lifetime != 3 => match namespace::lookup_definition(name.decoded_name)? {
                Ok(definition) => {
                    definition.release();
                    Ok(Ok(name_information(class, None)))
                }
                Err(status) => Ok(Err(status)),
            },
            Err(status) => Ok(Err(status)),
        }
    })();
    namespace::release_scope(scope)?;
    result
}

/// ZwQueryWnfStateNameInformation(StateName, NameInfoClass, ExplicitScope,
/// InfoBuffer, InfoBufferLength). Devolve o NTSTATUS.
pub fn query_name_information(state_name: u64, class: u32, explicit_scope: u64, buffer: u64, length: u32) -> Result<u32, KernelError> {
    let execute = || -> Result<u32, KernelError> {
        critical_region::enter_critical()?;
        let mut captured = None;
        let result = (|| -> Result<u32, KernelError> {
            // SAFETY: PCWNF_STATE_NAME de um chamador de modo kernel.
            let name = wnf_name::decode(unsafe { Field::<u64>::at(state_name) }.get());
            if name.status != 0 {
                return Ok(name.status);
            }
            let capture = match scope_capture::capture_kernel(name.scope, explicit_scope)? {
                Ok(capture) => captured.insert(capture),
                Err(status) => return Ok(status),
            };
            if class > WNF_INFO_IS_QUIESCENT {
                return Ok(0xC000_0003);
            }
            if length < 4 {
                return Ok(0xC000_000D);
            }
            let value = match query_name_information_captured(&name, class, capture)? {
                Ok(value) => value,
                Err(0xC000_0034) if class == WNF_INFO_STATE_NAME_EXIST => 0,
                Err(status) => return Ok(status),
            };
            // SAFETY: o PULONG InfoBuffer de um chamador de modo kernel.
            unsafe { Field::<u32>::at(buffer) }.set(value);
            Ok(0)
        })();
        let left = critical_region::leave_critical();
        if let Some(captured) = captured {
            captured.release()?;
        }
        let result = result?;
        left?;
        Ok(result)
    };
    previous_mode::with_kernel(execute)?
}
