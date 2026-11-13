//! ProcessDebugPort do NtQueryInformationProcess.
//!
//! O modo usuário recebe uma indicação, nunca o ponteiro do objeto de
//! kernel.

use super::{state, syscalls_core};
use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
use crate::ntos::ps::{process, session};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

fn argument(user_rsp: u64, index: u64) -> u64 {
    let words = state::syscall_arg_words(user_rsp, index);
    words[0] as u64 | (words[1] as u64) << 32
}

/// Ordem nativa das sondagens: alinhamento/faixa, ReturnLength opcional,
/// comprimento exato, handle/acesso e então a escrita da saída.
fn query(user_rsp: u64, returned: u64) -> Result<u32, KernelError> {
    let handle = argument(user_rsp, 1);
    let out = argument(user_rsp, 3);
    let length = state::syscall_arg_words(user_rsp, 4)[0];
    if length != 0 {
        if out & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if out.checked_add(length as u64).is_none_or(|end| end > USER_ADDRESS_LIMIT) {
            return Ok(0xC000_0005);
        }
    }
    if returned != 0 && !state::probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    if length != 8 {
        return Ok(0xC000_0004);
    }
    let target = if handle == u64::MAX {
        process::get_current_process()
    } else {
        if handle == u64::MAX - 1 {
            return Ok(0xC000_0024);
        }
        if handle > 0xFFFF_FFFF {
            return Ok(0xC000_0008);
        }
        let Some(entry) = state::get_user_handle(handle) else { return Ok(0xC000_0008) };
        if entry.kind() != "process" {
            return Ok(0xC000_0024);
        }
        if entry.access() & 0x400 == 0 {
            return Ok(0xC000_0022);
        }
        entry.object.callback_data().native_pointer
    };
    if !process::is_process(target) || process::reference(target).is_none() {
        return Ok(0xC000_0008);
    }
    let status = if !state::probe_user_write(out, 8) {
        0xC000_0005
    } else {
        guest::write64(out, if session::debug_port(target) != 0 { u64::MAX } else { 0 });
        if returned != 0 {
            guest::write32(returned, 8);
        }
        0
    };
    let _ = process::dereference(target);
    Ok(status)
}

pub fn init() {
    syscalls_core::set_process_debug_query(query);
}
