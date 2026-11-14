//! Anexação de processo com escopo para callbacks.
//!
//! O papel do KeStackAttachProcess/KeUnstackDetachProcess em volta de um
//! corpo: troca-se o estado real de APC e isola-se a fila pendente,
//! preservando o KPROCESS/CID dono e o ETHREAD.Silo, e a CPU carrega a raiz
//! do processo alvo enquanto o corpo roda (`ke::context_switch`, como no
//! attach), voltando à do processo restaurado no fim. É assim que o kernel
//! toca a memória de usuário de um processo que não é o da thread corrente
//! (o modo estrito de posse de `mm::guest_memory` exige o dono corrente).

use super::process;
use crate::ntos::ke::{apc, context_switch};
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
    let previous = state.process.get();
    if previous == target {
        return Ok(body());
    }
    // A raiz do alvo tem de poder ser carregada antes de o KAPC_STATE mudar.
    context_switch::require_loadable(target)?;
    let index = tcb.apc_state_index.get();
    let depth = apc::begin_attachment(thread, None, None)?;
    guest::write_bytes(state.address(), &[0; KapcState::SIZE as usize]);
    for head in &state.apc_list_head {
        head.flink.set(head.address());
        head.blink.set(head.address());
    }
    state.process.set(target);
    tcb.apc_state_index.set(ATTACHED_APC_ENVIRONMENT);
    let result = context_switch::swap_process(previous, target).map(|()| body());
    let ended = apc::end_attachment(thread, depth, None);
    tcb.apc_state_index.set(index);
    // A raiz volta a ser a do processo que o KAPC_STATE restaurado devolve.
    let restored = context_switch::swap_process(target, state.process.get());
    let value = result?;
    ended?;
    restored?;
    Ok(value)
}
