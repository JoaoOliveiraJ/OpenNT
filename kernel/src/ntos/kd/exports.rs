//! Família Kd* (depurador do kernel).
//!
//! Só adaptadores: o estado de um boot sem /DEBUG mora em
//! `ntos::kd::debugger`. Os slots históricos de dado mantêm os ids; o EAT
//! publica as variáveis reais.

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::kd::debugger;
use crate::rtl::KernelError;

fn data_slot_called(_: &Call) -> Result<u64, KernelError> {
    Err(KernelError::new("KD data symbol called as a function"))
}

fn enable_debugger(_: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(debugger::enable_debugger()))
}

fn refresh_debugger_not_present(_: &Call) -> Result<u64, KernelError> {
    Ok(debugger::refresh_debugger_not_present())
}

fn change_option(_: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(debugger::change_option()))
}

fn break_point_with_status(call: &Call) -> Result<u64, KernelError> {
    debugger::break_point_with_status(call.arg(1) as u32)
}

pub static GROUP: Group = Group {
    name: "kd",
    names: &["KdDebuggerEnabled", "KdEnableDebugger", "KdRefreshDebuggerNotPresent", "KdChangeOption", "DbgBreakPointWithStatus", "KdDebuggerNotPresent"],
    handlers: &[data_slot_called, enable_debugger, refresh_debugger_not_present, change_option, break_point_with_status, data_slot_called],
    data_exports: &[("KdDebuggerEnabled", debugger::debugger_enabled_address), ("KdDebuggerNotPresent", debugger::debugger_not_present_address), ("KdEnteredDebugger", debugger::entered_debugger_address)],
};

pub mod debug_prompt {
    //! DbgPrompt.
    //!
    //! A resolução de exports publica o corpo nativo com `int 0x2D`; a chamada
    //! pela tabela entra nesse mesmo corpo (`ntos::kd::debugger::prompt`).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::kd::debugger;
    use crate::rtl::KernelError;

    fn prompt(call: &Call) -> Result<u64, KernelError> {
        Ok(debugger::prompt(call.arg(1), call.arg(2), call.arg(3))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "debug-prompt",
        names: &["DbgPrompt"],
        handlers: &[prompt],
        data_exports: &[],
    };
}
