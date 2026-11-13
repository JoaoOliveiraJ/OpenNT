//! Exports do Dbgk.
//!
//! Só adaptadores: a lógica mora em `ntos::dbgk::wer`.

use crate::ntos::dbgk::wer;
use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::rtl::KernelError;

fn wer_capture_live_kernel_dump(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(wer::capture_live_kernel_dump(call.arg(1))?))
}

pub static GROUP: Group = Group {
    name: "dbgk",
    names: &["DbgkWerCaptureLiveKernelDump"],
    handlers: &[wer_capture_live_kernel_dump],
    data_exports: &[],
};
