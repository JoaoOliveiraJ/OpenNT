//! NtAlertThread / ZwAlertThread — `system32/ntos/ps/alert-thread.js`.
//!
//! Nt usa o PreviousMode; a entrada Zw fixa KernelMode para o acesso e para
//! o modo do alerta.

use crate::ntos::ke::thread_alert;
use crate::ntos::ob::handles::thread as thread_handles;
use crate::rtl::KernelError;

const THREAD_ALERT: u32 = 4;

pub fn alert(thread_handle: u64, access_mode: u8) -> Result<u32, KernelError> {
    let mut reference = match thread_handles::reference(thread_handle, THREAD_ALERT, access_mode)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let alerted = thread_alert::alert(reference.pointer, access_mode);
    reference.release()?;
    alerted.map(|_| 0)
}
