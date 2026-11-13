//! KeTestAlertThread.
//!
//! Consulta o estado de alerta da thread publicada na PCR e atualiza seus
//! flags sob KTHREAD.ThreadLock.

use super::{pcr, thread_lock};
use crate::ntos::inc::types::{Kpcr, Kthread, NtStruct};
use crate::rtl::KernelError;

/// KAPC_STATE.UserApcPendingAll bit 1: UserApcPending.
const USER_APC_PENDING: u8 = 2;

/// O modo é um byte com sinal. Consome o flag Alerted do modo; sem alerta
/// de usuário, publica a pendência de APC de usuário se a fila não está
/// vazia.
pub fn test(processor_mode: u64) -> Result<u8, KernelError> {
    let region = pcr::get_pcr_address();
    if region == 0 {
        return Err(KernelError::new("KeTestAlertThread requires an initialized KPCR"));
    }
    // A identidade vem de PRCB.CurrentThread, a mesma que o código nativo lê por GS.
    // SAFETY: a KPCR está mapeada desde `pcr::init`.
    let thread = unsafe { Kpcr::at(region) }.prcb.current_thread.get();
    // SAFETY: a thread corrente.
    let current = unsafe { Kthread::at(thread) };
    let mode = processor_mode as u8 as i8 as i64;
    Ok(thread_lock::with_lock(thread, || {
        let alerted = &current.alerted[mode as usize];
        let previous = alerted.get();
        if previous != 0 {
            alerted.set(0);
        } else if mode == 1 {
            // A segunda LIST_ENTRY do ApcState é a fila de usuário.
            let state = &current.apc_state;
            let user_queue = &state.apc_list_head[1];
            if user_queue.flink.get() != user_queue.address() {
                state.user_apc_pending_all.set(state.user_apc_pending_all.get() | USER_APC_PENDING);
            }
        }
        previous
    }))
}
