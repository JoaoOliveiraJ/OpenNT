//! Adaptador das syscalls WNF — `system32/ntos/ps/user/wnf.js`.
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

pub fn init() {
    state::register_handler("NtQueryWnfStateData", nt_query_wnf_state_data);
    state::register_handler("NtSetWnfProcessNotificationEvent", nt_set_wnf_process_notification_event);
    state::register_handler("NtSubscribeWnfStateChange", nt_subscribe_wnf_state_change);
}
