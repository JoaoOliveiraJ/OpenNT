//! KeTestAlertThread — `system32/ntos/ke/test-alert.js`.
//!
//! Consulta o estado de alerta da thread publicada na PCR e atualiza seus
//! flags sob KTHREAD.ThreadLock.

use super::{pcr, thread_lock};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

/// O modo é um byte com sinal. Consome o flag Alerted do modo; sem alerta
/// de usuário, publica a pendência de APC de usuário se a fila não está
/// vazia.
pub fn test(processor_mode: u64) -> Result<u8, KernelError> {
    let region = pcr::get_pcr_address();
    if region == 0 {
        return Err(KernelError::new("KeTestAlertThread requires an initialized KPCR"));
    }
    // A identidade vem de PRCB.CurrentThread, a mesma que o código nativo lê por GS.
    let thread = guest::read64(region + pcr::layout::PRCB_CURRENT_THREAD);
    let mode = processor_mode as u8 as i8 as i64;
    Ok(thread_lock::with_lock(thread, || {
        let alerted = thread.wrapping_add(kthread::ALERTED).wrapping_add(mode as u64);
        let previous = guest::read8(alerted);
        if previous != 0 {
            guest::write8(alerted, 0);
        } else if mode == 1 {
            // A segunda LIST_ENTRY do ApcState é a fila de usuário.
            let user_queue = thread + kthread::APC_STATE + 0x10;
            if guest::read64(user_queue) != user_queue {
                let pending = thread + kthread::APC_STATE + 0x2A;
                guest::write8(pending, guest::read8(pending) | 2);
            }
        }
        previous
    }))
}
