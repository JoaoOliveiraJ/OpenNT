//! Anexação de processo com escopo para callbacks.
//!
//! O Mm compartilha um CR3: troca-se o estado real de APC e isola-se a fila
//! pendente, preservando o KPROCESS/CID dono e o ETHREAD.Silo. Não é um
//! espaço de endereço novo.

use super::process;
use crate::ntos::ke::apc;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Ethread, KapcState};

/// KAPC_STATE_INDEX: AttachedApcEnvironment.
const ATTACHED_APC_ENVIRONMENT: u8 = 1;

pub fn with_process<T>(target: u64, body: impl FnOnce() -> T) -> Result<T, KernelError> {
    let thread = process::get_current_thread();
    // SAFETY: a thread corrente do Process Manager.
    let tcb = &unsafe { Ethread::at(thread) }.tcb;
    let state = &tcb.apc_state;
    if state.process.get() == target {
        return Ok(body());
    }
    let index = tcb.apc_state_index.get();
    let depth = apc::begin_attachment(thread, None, None)?;
    guest::write_bytes(state.address(), &[0; KapcState::SIZE as usize]);
    for head in &state.apc_list_head {
        head.flink.set(head.address());
        head.blink.set(head.address());
    }
    state.process.set(target);
    tcb.apc_state_index.set(ATTACHED_APC_ENVIRONMENT);
    let result = body();
    let ended = apc::end_attachment(thread, depth, None);
    tcb.apc_state_index.set(index);
    ended.map(|_| result)
}
