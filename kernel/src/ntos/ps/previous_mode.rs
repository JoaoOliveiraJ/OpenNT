//! KTHREAD.PreviousMode.

use super::process;
use crate::ntos::ke::pcr;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

/// Prcb.CurrentThread lido da KPCR (o gs:[0x188] visto pelos drivers).
fn current_thread() -> Result<u64, KernelError> {
    let base = pcr::get_pcr_address();
    if base == 0 {
        return Err(KernelError::new("PreviousMode requires an initialized KPCR"));
    }
    Ok(guest::read64(base + pcr::layout::PRCB_CURRENT_THREAD))
}

/// ExGetPreviousMode.
pub fn get() -> Result<u8, KernelError> {
    Ok(guest::read8(current_thread()? + kthread::PREVIOUS_MODE))
}

/// Executa `body` com PreviousMode = KernelMode, retendo a thread.
pub fn with_kernel<T>(body: impl FnOnce() -> T) -> Result<T, KernelError> {
    let thread = current_thread()?;
    let field = thread + kthread::PREVIOUS_MODE;
    let saved = guest::read8(field);
    let owned = process::is_thread(thread);
    if owned {
        process::reference_thread(thread);
    }
    guest::write8(field, 0);
    let result = body();
    guest::write8(field, saved);
    if owned {
        process::dereference_thread(thread)?;
    }
    Ok(result)
}
