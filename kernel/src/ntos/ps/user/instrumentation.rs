//! ProcessInstrumentationCallback x64 versão 0 — `system32/ntos/ps/user/instrumentation.js`.
//!
//! O retorno de syscall transfere o controle no anel 3, com o PC anterior
//! em R10 e o resultado original em RAX; o callback cuida da contabilidade
//! no TEB e da recursão. A célula é consumida pela HAL de modo usuário.

use super::{state, syscalls_core};
use crate::hal::amd64::usermode::INSTRUMENTATION_CALLBACK;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Só o processo corrente.
fn set_information(process: u64, input: u64, length: u64) -> Result<u32, KernelError> {
    if process != u64::MAX {
        return Ok(0xC000_0008);
    }
    if length != 16 && length != 8 {
        return Ok(0xC000_0004);
    }
    if !state::probe_user_read(input, length) {
        return Ok(0xC000_0005);
    }
    if length == 16 && (guest::read32(input) != 0 || guest::read32(input + 4) != 0) {
        return Ok(0xC000_000D);
    }
    let callback = guest::read64(input + if length == 16 { 8 } else { 0 });
    if callback != 0 && !state::probe_user_read(callback, 1) {
        return Ok(0xC000_0005);
    }
    let process_id = state::with(|state| {
        state.instrumentation_callback = callback;
        state.current_process_id
    });
    guest::write64(INSTRUMENTATION_CALLBACK, callback);
    crate::debug_print!("[instrumentation] pid={} callback=0x{:x}", process_id, callback);
    Ok(0)
}

pub fn release_process() {
    state::with(|state| state.instrumentation_callback = 0);
    guest::write64(INSTRUMENTATION_CALLBACK, 0);
}

pub fn init() {
    syscalls_core::set_instrumentation_setter(set_information);
}
