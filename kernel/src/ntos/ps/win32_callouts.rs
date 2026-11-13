//! Threads GUI e os callouts do win32k (PsConvertToGuiThread).
//!
//! O win32k real publica a tabela de serviços gráfica
//! (KeAddSystemServiceTable) e os callouts de processo e thread
//! (PsEstablishWin32Callouts). Uma thread vira GUI na primeira syscall da
//! tabela 1: o KiSystemCall64 chama o PsConvertToGuiThread, que invoca o
//! callout de processo e depois o de thread e só então liga
//! KTHREAD.GuiThread. Sem o win32k não existe bloco de callouts: o
//! PsInvokeWin32Callout devolve STATUS_INVALID_PARAMETER e a thread continua
//! não-GUI.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Ethread};
use crate::ntos::ps::process;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_ALREADY_WIN32: u32 = 0x4000_001B;

fn current_thread() -> Option<&'static Ethread> {
    let thread = process::get_current_thread();
    // SAFETY: Prcb.CurrentThread é o ETHREAD em execução.
    (thread != 0).then(|| unsafe { Ethread::at(thread) })
}

/// KTHREAD.GuiThread da thread corrente: o KiSystemCall64 usa o
/// KeServiceDescriptorTableShadow só para threads GUI.
pub fn is_gui_thread() -> bool {
    current_thread().is_some_and(|thread| thread.tcb.gui_thread() != 0)
}

/// PsConvertToGuiThread da thread corrente, na ordem do ntoskrnl 19041:
/// chamada de KernelMode, thread já GUI, processo com
/// DisallowWin32kSystemCalls e, por fim, o callout de processo.
pub fn convert_to_gui_thread() -> u32 {
    let Some(thread) = current_thread() else { return STATUS_INVALID_PARAMETER };
    if thread.tcb.previous_mode.get() == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if thread.tcb.gui_thread() != 0 {
        return STATUS_ALREADY_WIN32;
    }
    // SAFETY: o EPROCESS da thread corrente.
    if unsafe { Eprocess::at(process::get_current_process()) }.mitigation_flags_values.disallow_win32k_system_calls() != 0 {
        return STATUS_ACCESS_DENIED;
    }
    // W32ProcessCallout: o ExReferenceCallBackBlock não acha a rotina sem o
    // PsEstablishWin32Callouts do win32k.
    STATUS_INVALID_PARAMETER
}
