//! Anexação de processo com escopo para callbacks — `system32/ntos/ps/process-context.js`.
//!
//! O Mm compartilha um CR3: troca-se o estado real de APC e isola-se a fila
//! pendente, preservando o KPROCESS/CID dono e o ETHREAD.Silo. Não é um
//! espaço de endereço novo.

use super::process;
use crate::ntos::ke::apc;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

/// ApcStateIndex do KTHREAD.
const APC_STATE_INDEX: u64 = 0x24A;

pub fn with_process<T>(target: u64, body: impl FnOnce() -> T) -> Result<T, KernelError> {
    let thread = process::get_current_thread();
    let state = thread + kthread::APC_STATE;
    if guest::read64(state + 0x20) == target {
        return Ok(body());
    }
    let index = guest::read8(thread + APC_STATE_INDEX);
    let depth = apc::begin_attachment(thread, None, None)?;
    for offset in (0..0x30).step_by(8) {
        guest::write64(state + offset, 0);
    }
    for offset in [0u64, 0x10] {
        guest::write64(state + offset, state + offset);
        guest::write64(state + offset + 8, state + offset);
    }
    guest::write64(state + 0x20, target);
    guest::write8(thread + APC_STATE_INDEX, 1);
    let result = body();
    let ended = apc::end_attachment(thread, depth, None);
    guest::write8(thread + APC_STATE_INDEX, index);
    ended.map(|_| result)
}
