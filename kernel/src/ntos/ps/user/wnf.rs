//! Adaptador das syscalls WNF.
//!
//! Os argumentos chegam com 64 bits (inclusive ExplicitScope, que também
//! pode ser um handle de processo); stamp e máscara usam os ULONGs baixos.

use super::state;
use crate::ntos::ex::wnf::service as wnf_service;
use crate::rtl::KernelError;

fn nt_query_wnf_state_data(state_name: u64, type_identifier: u64, explicit_scope: u64, change_stamp: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 16) {
        return Ok(0xC000_0005);
    }
    wnf_service::query_user(state_name, type_identifier, explicit_scope, change_stamp, state::stack_arg(rsp, 5), state::stack_arg(rsp, 6))
}

fn nt_set_wnf_process_notification_event(handle: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    wnf_service::set_process_notification_event(handle)
}

fn nt_subscribe_wnf_state_change(state_name: u64, change_stamp: u64, event_mask: u64, identifier: u64, _rsp: u64) -> Result<u32, KernelError> {
    wnf_service::subscribe_user(state_name, change_stamp as u32, event_mask as u32, identifier)
}

/// NtUpdateWnfStateData(StateName, Buffer, Length, TypeId, ExplicitScope,
/// MatchingChangeStamp, CheckStamp): os três últimos na pilha.
fn nt_update_wnf_state_data(state_name: u64, buffer: u64, length: u64, type_identifier: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 24) {
        return Ok(0xC000_0005);
    }
    let check_stamp = state::stack_arg32(rsp, 7) != 0;
    let explicit_scope = state::stack_arg(rsp, 5);
    let status = wnf_service::update_user(state_name, buffer, length as u32, type_identifier, explicit_scope, state::stack_arg32(rsp, 6), check_stamp)?;
    if status == 0 {
        update_observed(state_name, explicit_scope);
    }
    Ok(status)
}

/// Os marcadores do logon do usuário que saem de uma publicação
/// (`initial_process::wnf_updated`): o nome e, com ExplicitScope, o ULONG do
/// escopo (a sessão de um nome de escopo de sessão). Só observação: uma
/// leitura que falha não muda o resultado do serviço.
fn update_observed(state_name: u64, explicit_scope: u64) {
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ps::user_probe;
    if !user_probe::probe_user_read(state_name, 8) {
        return;
    }
    let Ok(name) = guest::try_read::<u64>(state_name) else { return };
    let scope = if explicit_scope != 0 && user_probe::probe_user_read(explicit_scope, 4) { guest::try_read::<u32>(explicit_scope).ok() } else { None };
    crate::ntos::init::initial_process::wnf_updated(name, scope);
}

/// NtCreateWnfStateName(StateName, NameLifetime, DataScope, PersistData,
/// TypeId, MaximumStateSize, SecurityDescriptor): os três últimos na pilha.
fn nt_create_wnf_state_name(output: u64, lifetime: u64, scope: u64, persist: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 24) {
        return Ok(0xC000_0005);
    }
    let request = wnf_service::CreateName {
        output,
        lifetime: lifetime as u32,
        scope: scope as u32,
        persist: persist as u8 != 0,
        type_identifier: state::stack_arg(rsp, 5),
        maximum_size: state::stack_arg32(rsp, 6),
        security_descriptor: state::stack_arg(rsp, 7),
    };
    wnf_service::create_state_name_user(&request)
}

/// NtQueryWnfStateNameInformation(StateName, NameInfoClass, ExplicitScope,
/// InfoBuffer, InfoBufferLength): o último na pilha.
fn nt_query_wnf_state_name_information(state_name: u64, class: u64, explicit_scope: u64, buffer: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(0xC000_0005);
    }
    wnf_service::query_name_information_user(state_name, class as u32, explicit_scope, buffer, state::stack_arg32(rsp, 5))
}

/// NtDeleteWnfStateName(StateName).
fn nt_delete_wnf_state_name(state_name: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    wnf_service::delete_state_name_user(state_name)
}

/// NtUnsubscribeWnfStateChange(StateName).
fn nt_unsubscribe_wnf_state_change(state_name: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    wnf_service::unsubscribe_user(state_name)
}

/// NtDeleteWnfStateData(StateName, ExplicitScope).
fn nt_delete_wnf_state_data(state_name: u64, explicit_scope: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    wnf_service::delete_state_data_user(state_name, explicit_scope)
}

/// NtGetCompleteWnfStateSubscription(OldDescriptorStateName,
/// OldSubscriptionId, OldDescriptorEventMask, OldDescriptorStatus,
/// NewDeliveryDescriptor, DescriptorSize).
fn nt_get_complete_wnf_state_subscription(old_name: u64, old_id: u64, old_mask: u64, old_status: u64, rsp: u64) -> Result<u32, KernelError> {
    wnf_service::get_complete_subscription_user(old_name, old_id, old_mask as u32, old_status as u32, state::stack_arg(rsp, 5), state::stack_arg32(rsp, 6))
}

pub fn init() {
    state::register_handler("NtGetCompleteWnfStateSubscription", nt_get_complete_wnf_state_subscription);
    state::register_handler("NtDeleteWnfStateData", nt_delete_wnf_state_data);
    state::register_handler("NtUnsubscribeWnfStateChange", nt_unsubscribe_wnf_state_change);
    state::register_handler("NtDeleteWnfStateName", nt_delete_wnf_state_name);
    state::register_handler("NtQueryWnfStateNameInformation", nt_query_wnf_state_name_information);
    state::register_handler("NtUpdateWnfStateData", nt_update_wnf_state_data);
    state::register_handler("NtCreateWnfStateName", nt_create_wnf_state_name);
    state::register_handler("NtQueryWnfStateData", nt_query_wnf_state_data);
    state::register_handler("NtSetWnfProcessNotificationEvent", nt_set_wnf_process_notification_event);
    state::register_handler("NtSubscribeWnfStateChange", nt_subscribe_wnf_state_change);
}
