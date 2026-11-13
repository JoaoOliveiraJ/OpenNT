//! KTHREAD.ThreadLock — `system32/ntos/ke/thread-lock.js`.
//!
//! Compartilhado pelas consultas de alerta e pelas filas de APC.

use super::irql;
use crate::hal::cpu;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

/// Eleva a DISPATCH_LEVEL, adquire a palavra nativa da thread e executa o
/// corpo; libera a posse e restaura o IRQL depois.
pub fn with_lock<T>(thread: u64, body: impl FnOnce() -> T) -> T {
    let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
    let lock = thread + kthread::THREAD_LOCK;
    while guest::compare_exchange64(lock, 0, 1).unwrap_or(1) != 0 {
        cpu::pause();
    }
    let result = body();
    let _ = guest::compare_exchange64(lock, 1, 0);
    irql::lower_irql(previous as u64);
    result
}
