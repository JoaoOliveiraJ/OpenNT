//! Supressão das APCs de stack walk do ETW na thread corrente
//! (EtwpDisableStackWalkApc / EtwpReenableStackWalkApc).
//!
//! O ETW marca em KTHREAD.ThreadFlags.EtwStackTraceApcInserted (bits 24..31)
//! as APCs de captura de pilha já inseridas na thread; com o byte em 0xFF
//! nenhuma nova é inserida. Como no ntoskrnl 19041, desligar grava 0xFF no
//! byte por LOCK CMPXCHG e devolve o valor anterior; religar recebe esse
//! valor e limpa os bits que ele não tinha (AND com `valor << 24 | 0xFFFFFF`),
//! sem tocar nos outros 24 bits.

use core::sync::atomic::Ordering;

use crate::ntos::inc::types::{Kthread, NtStruct};
use crate::ntos::ps::process;

fn current_thread() -> &'static Kthread {
    // SAFETY: a KTHREAD corrente (KPRCB.CurrentThread), viva enquanto roda.
    unsafe { Kthread::at(process::get_current_thread()) }
}

/// EtwpDisableStackWalkApc: devolve o byte anterior e deixa 0xFF.
pub fn disable_stack_walk_apc() -> u32 {
    let previous = current_thread().thread_flags.atomic().fetch_or(Kthread::ETW_STACK_TRACE_APC_INSERTED_MASK as i32, Ordering::SeqCst);
    (previous as u32) >> Kthread::ETW_STACK_TRACE_APC_INSERTED_SHIFT
}

/// EtwpReenableStackWalkApc(PreviousValue): restaura o byte devolvido pelo
/// EtwpDisableStackWalkApc.
pub fn reenable_stack_walk_apc(previous: u32) {
    let mask = (previous << Kthread::ETW_STACK_TRACE_APC_INSERTED_SHIFT) | !Kthread::ETW_STACK_TRACE_APC_INSERTED_MASK;
    current_thread().thread_flags.atomic().fetch_and(mask as i32, Ordering::SeqCst);
}
