//! Os serviços de sessão do modo usuário: adaptadores do PreviousMode
//! UserMode para o NtOpenSession (`mm/session_object.rs`) e o
//! NtNotifyChangeSession (`io/session_notification.rs`), que o Local
//! Session Manager (lsm.dll) chama.

use super::state;
use crate::ntos::io::session_notification;
use crate::ntos::mm::session_object;
use crate::rtl::KernelError;

const USER_MODE: u8 = 1;

/// NtOpenSession(SessionHandle*, DesiredAccess, ObjectAttributes*).
fn nt_open_session(handle: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    session_object::open(handle, access as u32, attributes, USER_MODE)
}

/// NtNotifyChangeSession(SessionHandle, ChangeSequenceNumber,
/// ChangeTimeStamp*, Event, e na pilha NewState, PreviousState, Payload* e
/// PayloadSize).
fn nt_notify_change_session(handle: u64, sequence: u64, time_stamp: u64, event: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 0x20) {
        return Ok(0xC000_0005);
    }
    let (new_state, previous_state) = (state::stack_arg32(rsp, 5), state::stack_arg32(rsp, 6));
    let (payload, payload_size) = (state::stack_arg(rsp, 7), state::stack_arg32(rsp, 8));
    session_notification::notify_change_session(handle, sequence as u32, time_stamp, event as u32, new_state, previous_state, payload, payload_size, USER_MODE)
}

pub fn init() {
    state::register_handler("NtOpenSession", nt_open_session);
    state::register_handler("NtNotifyChangeSession", nt_notify_change_session);
}
