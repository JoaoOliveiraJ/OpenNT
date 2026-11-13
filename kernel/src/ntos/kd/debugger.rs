//! Depurador do kernel num boot sem /DEBUG.
//!
//! Sem depurador anexado nem transporte KD: os valores são os de um boot sem
//! /DEBUG (KdDebuggerEnabled=FALSE, KdEnableDebugger=ACCESS_DENIED,
//! KdChangeOption=DEBUGGER_INACTIVE). KdDebuggerEnabled, KdDebuggerNotPresent
//! e KdEnteredDebugger são as células reais da imagem do kernel. O DbgPrompt
//! entra no corpo nativo com `int 0x2D` e no tratamento real de exceções.

use crate::hal::amd64::{native_call, private_entries};
use crate::ntos::mm::{kernel_address, kernel_data};
use crate::rtl::KernelError;

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_DEBUGGER_INACTIVE: u32 = 0xC000_0354;

/// KdEnableDebugger: num boot sem /DEBUG o NT recusa ligar o KD.
pub fn enable_debugger() -> u32 {
    STATUS_ACCESS_DENIED
}

/// KdRefreshDebuggerNotPresent: sem transporte KD que estabeleça sessão,
/// atualiza a variável real e devolve o valor dela.
pub fn refresh_debugger_not_present() -> u64 {
    kernel_data::write("KdDebuggerNotPresent", 1);
    kernel_data::read("KdDebuggerNotPresent")
}

/// KdChangeOption: sem depurador ativo.
pub fn change_option() -> u32 {
    STATUS_DEBUGGER_INACTIVE
}

/// DbgBreakPointWithStatus: sem KD, um INT 3 não tratado vira
/// KMODE_EXCEPTION_NOT_HANDLED.
pub fn break_point_with_status(status: u32) -> ! {
    debug_print!("[kd] DbgBreakPointWithStatus status={:#x} sem debugger — KMODE_EXCEPTION_NOT_HANDLED", status);
    crate::hal::cpu::halt_forever()
}

fn data_address(name: &str) -> u64 {
    kernel_data::address(name).unwrap_or_else(|error| panic!("{name}: {error}"))
}

/// Célula do export de dados KdDebuggerEnabled.
pub fn debugger_enabled_address() -> u64 {
    data_address("KdDebuggerEnabled")
}

/// Célula do export de dados KdDebuggerNotPresent.
pub fn debugger_not_present_address() -> u64 {
    data_address("KdDebuggerNotPresent")
}

/// Célula do export de dados KdEnteredDebugger.
pub fn entered_debugger_address() -> u64 {
    data_address("KdEnteredDebugger")
}

/// DbgPrompt(Prompt, Response, Length): os três argumentos vão ao corpo
/// nativo; devolve o resultado de 32 bits.
pub fn prompt(prompt: u64, response: u64, length: u64) -> Result<u32, KernelError> {
    let entry = private_entries::entry("dbg_prompt").ok_or_else(|| KernelError::new("DbgPrompt native body is missing"))?;
    let address = kernel_address::image_address(entry)?;
    Ok(native_call::call(address, &[prompt, response, length]) as u32)
}
