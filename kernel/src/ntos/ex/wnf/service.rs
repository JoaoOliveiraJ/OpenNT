//! Serviço WNF compartilhado, também usado pela atualização de estado.
//!
//! Captura, resolução, definição, dados e notificação. A instância só entra
//! na árvore depois da carga válida; toda referência adquirida pela operação
//! é devolvida em qualquer saída. Os pontos de entrada de usuário (consulta,
//! inscrição e evento de processo) entram com `ps/user/state` na fase 7.

use crate::ntos::ex::wnf::data_block as state_data;
use crate::ntos::ex::wnf::name::{self as wnf_name, DecodedName, SuppliedType};
use crate::ntos::ex::wnf::namespace::{self, Lifecycle, NameDefinition};
use crate::ntos::ex::wnf::notifications;
use crate::ntos::ex::wnf::scope_capture::{self, Captured};
use crate::ntos::ex::push_lock;
use crate::ntos::ex::wnf::{physical as wnf_physical, query as wnf_query};
use crate::ntos::ke::critical_region;
use crate::ntos::ps::{previous_mode, process};
use crate::rtl::{KernelError, SpinLock};
use super::objects::state_data_at;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::WnfStateData;

static SERVICE: SpinLock<bool> = SpinLock::new(false);

/// Cria notificações e namespace; `false` sem memória.
fn ensure_service() -> Result<bool, KernelError> {
    let mut service = SERVICE.lock();
    if *service {
        return Ok(true);
    }
    if !notifications::create()? {
        return Ok(false);
    }
    if let Err(error) = namespace::create(Lifecycle { delete_name_subscriptions: notifications::detach_name_hook, delete_process_subscriptions: notifications::delete_process_subscriptions_hook }) {
        let _ = notifications::dispose();
        return Err(error);
    }
    *service = true;
    Ok(true)
}

pub fn exists() -> bool {
    *SERVICE.lock()
}

#[allow(clippy::too_many_arguments)]
fn update_captured(name: &DecodedName, buffer: u64, length: u32, type_identifier: u64, captured: &Captured, matching_stamp: u32, check_stamp: bool) -> Result<u32, KernelError> {
    if name.scope == 5 {
        if check_stamp {
            return Ok(0xC000_000D);
        }
        let remote = wnf_physical::push(1, name.decoded_name ^ wnf_name::NAME_MASK, 0xFFFF_FFFF, buffer, length);
        if remote != 0xC000_0002 {
            return Ok(remote);
        }
    }
    let system = process::get_system_process();
    let scope = match namespace::resolve_kernel_scope(system, name.scope, captured.identity)? {
        Ok(scope) => scope,
        Err(status) => return Ok(status),
    };
    let supplied = if type_identifier != 0 { SuppliedType::Pointer(type_identifier) } else { SuppliedType::None };
    let mut state = None;
    let result = (|| -> Result<u32, KernelError> {
        let current = match namespace::lookup_name(scope, name.decoded_name)? {
            Err(0xC000_0034) => {
                if name.lifetime == 3 {
                    return Ok(0xC000_0034);
                }
                let definition = match namespace::lookup_definition(name.decoded_name)? {
                    Ok(definition) => definition,
                    Err(status) => return Ok(status),
                };
                let status = wnf_name::validate(&definition.description(), length, supplied, true, None, 2);
                if status & 0x8000_0000 != 0 {
                    return Ok(status);
                }
                let created = namespace::create_name(scope, name.decoded_name, NameDefinition::from(&definition), system)?;
                definition.release();
                match created {
                    Ok(created) => created,
                    Err(status) => return Ok(status),
                }
            }
            Err(status) => return Ok(status),
            Ok(found) => {
                state = Some(found);
                let status = wnf_name::validate(&found.description(), length, supplied, true, None, 2);
                if status & 0x8000_0000 != 0 {
                    return Ok(status);
                }
                found
            }
        };
        state = Some(current);
        let status = state_data::write(&current, buffer, length, matching_stamp, check_stamp)?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        if name.scope == 5 {
            // O anúncio do conteúdo corrente ignora o status.
            push_lock::acquire_shared(current.lock_pointer(), 0)?;
            let data = if current.data_pointer() > 1 { current.data_pointer() } else { 0 };
            wnf_physical::push(0, name.decoded_name ^ wnf_name::NAME_MASK, current.change_stamp(), if data != 0 { data + WnfStateData::SIZE } else { 0 }, if data != 0 { state_data_at(data).data_size.get() } else { 0 });
            push_lock::release_shared(current.lock_pointer(), 0)?;
        }
        notifications::notify_name(current.pointer, 1, true, false)?;
        Ok(0)
    })();
    if let Some(state) = state {
        namespace::release_name(&state)?;
    }
    namespace::release_scope(scope)?;
    result
}

/// ZwUpdateWnfStateData (KernelMode).
pub fn update(state_name: u64, buffer: u64, length: u32, type_identifier: u64, explicit_scope: u64, matching_stamp: u32, check_stamp: bool) -> Result<u32, KernelError> {
    if !ensure_service()? {
        return Ok(0xC000_009A);
    }
    previous_mode::with_kernel(|| -> Result<u32, KernelError> {
        critical_region::enter_critical()?;
        let mut captured = None;
        let result = (|| -> Result<u32, KernelError> {
            // SAFETY: ZwUpdateWnfStateData recebe PCWNF_STATE_NAME de modo kernel.
            let name = wnf_name::decode(unsafe { Field::<u64>::at(state_name) }.get());
            if name.status != 0 {
                return Ok(name.status);
            }
            let capture = match scope_capture::capture_kernel(name.scope, explicit_scope)? {
                Ok(capture) => captured.insert(capture),
                Err(status) => return Ok(status),
            };
            update_captured(&name, buffer, length, type_identifier, capture, matching_stamp, check_stamp)
        })();
        let left = critical_region::leave_critical();
        if let Some(captured) = captured {
            captured.release()?;
        }
        let result = result?;
        left?;
        Ok(result)
    })?
}

/// ZwQueryWnfStateData: a leitura reutiliza o dono do namespace da escrita.
pub fn query(state_name: u64, type_identifier: u64, explicit_scope: u64, change_stamp: u64, buffer: u64, returned_length: u64) -> Result<u32, KernelError> {
    if !ensure_service()? {
        return Ok(0xC000_009A);
    }
    wnf_query::query(state_name, type_identifier, explicit_scope, change_stamp, buffer, returned_length, None)
}

/// NtQueryWnfStateData: a captura de usuário com o mesmo fluxo da consulta Zw.
pub fn query_user(state_name: u64, type_identifier: u64, explicit_scope: u64, change_stamp: u64, buffer: u64, returned_length: u64) -> Result<u32, KernelError> {
    if !ensure_service()? {
        return Ok(0xC000_009A);
    }
    wnf_query::query(state_name, type_identifier, explicit_scope, change_stamp, buffer, returned_length, Some(crate::ntos::ex::wnf::user::user_query()))
}

/// A inscrição compartilha o namespace das consultas e atualizações: as
/// filas existentes sinalizam o mesmo evento retido para o processo.
pub fn set_process_notification_event(handle: u64) -> Result<u32, KernelError> {
    if !ensure_service()? {
        return Ok(0xC000_009A);
    }
    crate::ntos::ex::wnf::user::set_process_notification_event(handle)
}

/// NtSubscribeWnfStateChange: o serviço é criado depois das validações.
pub fn subscribe_user(state_name: u64, change_stamp: u32, event_mask: u32, identifier: u64) -> Result<u32, KernelError> {
    crate::ntos::ex::wnf::user::subscribe(state_name, change_stamp, event_mask, identifier, ensure_service)
}

/// ExSubscribeWnfStateChange(Subscription, StateName, DeliveryOption,
/// CurrentChangeStamp, Callback, CallbackContext): a inscrição de kernel do
/// System, dentro de uma região crítica. O nome é capturado e validado antes
/// da máscara (só os bits 0..4); o PWNF_SUBSCRIPTION só é gravado no sucesso.
pub fn subscribe_kernel(subscription_output: u64, state_name: u64, delivery_option: u32, change_stamp: u32, callback: u64, context: u64) -> Result<u32, KernelError> {
    critical_region::enter_critical()?;
    let result = (|| -> Result<u32, KernelError> {
        // SAFETY: PCWNF_STATE_NAME de um chamador de modo kernel.
        let name = wnf_name::decode(unsafe { Field::<u64>::at(state_name) }.get());
        if name.status != 0 {
            return Ok(name.status);
        }
        if delivery_option & !0x1F != 0 {
            return Ok(0xC000_000D);
        }
        if !ensure_service()? {
            return Ok(0xC000_009A);
        }
        match crate::ntos::ex::wnf::subscriptions::subscribe_kernel(&name, change_stamp, delivery_option, callback, context)? {
            Ok(subscription) => {
                // SAFETY: PWNF_SUBSCRIPTION* de saída do chamador de modo kernel.
                unsafe { Field::<u64>::at(subscription_output) }.set(subscription);
                Ok(0)
            }
            Err(status) => Ok(status),
        }
    })();
    let left = critical_region::leave_critical();
    let result = result?;
    left?;
    Ok(result)
}

/// ExUnsubscribeWnfStateChange(Subscription): remove a inscrição de kernel e
/// libera o bloco depois dos callbacks em curso.
pub fn unsubscribe_kernel(subscription: u64) -> Result<(), KernelError> {
    critical_region::enter_critical()?;
    let result = notifications::delete_kernel_subscription(subscription);
    let left = critical_region::leave_critical();
    result?;
    left
}

/// Encerra o serviço (os chamadores já devolveram seus empréstimos).
pub fn shutdown() -> Result<(), KernelError> {
    let mut service = SERVICE.lock();
    if !*service {
        return Ok(());
    }
    namespace::dispose()?;
    notifications::dispose()?;
    *service = false;
    Ok(())
}
