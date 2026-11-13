//! Família Kd* (depurador do kernel) — `system32/win32/ntoskrnl/kd.js`.
//!
//! Sem depurador anexado nem transporte KD: os valores são os de um boot sem
//! /DEBUG (KdDebuggerEnabled=FALSE, KdEnableDebugger=ACCESS_DENIED,
//! KdChangeOption=DEBUGGER_INACTIVE). Os slots históricos de dado mantêm os
//! ids; o EAT publica as variáveis reais.

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::mm::kernel_data;
use crate::rtl::KernelError;

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_DEBUGGER_INACTIVE: u32 = 0xC000_0354;

fn data_slot_called(_: &Call) -> Result<u64, KernelError> {
    Err(KernelError::new("KD data symbol called as a function"))
}

/// Num boot sem /DEBUG o NT recusa ligar o KD.
fn enable_debugger(_: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(STATUS_ACCESS_DENIED))
}

/// Sem transporte KD que estabeleça sessão: atualiza a variável real e
/// devolve o valor dela.
fn refresh_debugger_not_present(_: &Call) -> Result<u64, KernelError> {
    kernel_data::write("KdDebuggerNotPresent", 1);
    Ok(kernel_data::read("KdDebuggerNotPresent"))
}

fn change_option(_: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(STATUS_DEBUGGER_INACTIVE))
}

/// Sem KD, um INT 3 não tratado vira KMODE_EXCEPTION_NOT_HANDLED.
fn break_point_with_status(call: &Call) -> Result<u64, KernelError> {
    debug_print!("[kd] DbgBreakPointWithStatus status={:#x} sem debugger — KMODE_EXCEPTION_NOT_HANDLED", call.arg(1) as u32);
    crate::hal::cpu::halt_forever()
}

fn data_address(name: &str) -> u64 {
    kernel_data::address(name).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn debugger_enabled_address() -> u64 {
    data_address("KdDebuggerEnabled")
}

fn debugger_not_present_address() -> u64 {
    data_address("KdDebuggerNotPresent")
}

fn entered_debugger_address() -> u64 {
    data_address("KdEnteredDebugger")
}

pub static GROUP: Group = Group {
    name: "kd",
    names: &["KdDebuggerEnabled", "KdEnableDebugger", "KdRefreshDebuggerNotPresent", "KdChangeOption", "DbgBreakPointWithStatus", "KdDebuggerNotPresent"],
    handlers: &[data_slot_called, enable_debugger, refresh_debugger_not_present, change_option, break_point_with_status, data_slot_called],
    data_exports: &[("KdDebuggerEnabled", debugger_enabled_address), ("KdDebuggerNotPresent", debugger_not_present_address), ("KdEnteredDebugger", entered_debugger_address)],
};

pub mod debug_prompt {
    //! DbgPrompt — `system32/win32/ntoskrnl/debug-prompt.js`.
    //!
    //! A resolução de exports publica o corpo nativo com `int 0x2D`; a chamada
    //! pela tabela entra nesse mesmo corpo e no tratamento real de exceções.

    use crate::ntos::init::exports::{Call, Group};
    use crate::hal::amd64::{native_call, private_entries};
    use crate::ntos::mm::kernel_address;
    use crate::rtl::KernelError;

    /// Os três argumentos de DbgPrompt; devolve o resultado de 32 bits.
    fn prompt(call: &Call) -> Result<u64, KernelError> {
        let entry = private_entries::entry("dbg_prompt").ok_or_else(|| KernelError::new("DbgPrompt native body is missing"))?;
        let address = kernel_address::virtual_address(entry)?;
        Ok(native_call::call(address, &[call.arg(1), call.arg(2), call.arg(3)]) & 0xFFFF_FFFF)
    }

    pub static GROUP: Group = Group {
        name: "debug-prompt",
        names: &["DbgPrompt"],
        handlers: &[prompt],
        data_exports: &[],
    };
}
