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

pub mod dbgk_live_dump {
    //! DbgkLkmdRegisterCallback; a lógica mora em `dbgk/live_dump`.

    use crate::ntos::dbgk::live_dump;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn register_callback(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(live_dump::register(call.arg(1), call.arg(2), call.arg(3) as u32)))
    }

    pub static GROUP: Group = Group { name: "dbgk-live-dump", names: &["DbgkLkmdRegisterCallback"], handlers: &[register_callback], data_exports: &[] };
}
