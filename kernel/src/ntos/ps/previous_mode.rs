//! KTHREAD.PreviousMode.

use super::process;
use crate::ntos::ke::pcr;
use crate::rtl::KernelError;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Ethread, Kpcr};

/// Prcb.CurrentThread lido da KPCR (o gs:[0x188] visto pelos drivers).
fn current_thread() -> Result<u64, KernelError> {
    let base = pcr::get_pcr_address();
    if base == 0 {
        return Err(KernelError::new("PreviousMode requires an initialized KPCR"));
    }
    // SAFETY: a KPCR inicializada do processador corrente.
    Ok(unsafe { Kpcr::at(base) }.prcb.current_thread.get())
}

/// ExGetPreviousMode.
pub fn get() -> Result<u8, KernelError> {
    // SAFETY: Prcb.CurrentThread é o ETHREAD em execução.
    Ok(unsafe { Ethread::at(current_thread()?) }.tcb.previous_mode.get() as u8)
}

/// Executa `body` com PreviousMode = KernelMode, retendo a thread.
pub fn with_kernel<T>(body: impl FnOnce() -> T) -> Result<T, KernelError> {
    let thread = current_thread()?;
    // SAFETY: Prcb.CurrentThread é o ETHREAD em execução.
    let field = &unsafe { Ethread::at(thread) }.tcb.previous_mode;
    let saved = field.get();
    let owned = process::is_thread(thread);
    if owned {
        process::reference_thread(thread);
    }
    field.set(0);
    let result = body();
    field.set(saved);
    if owned {
        process::dereference_thread(thread)?;
    }
    Ok(result)
}
