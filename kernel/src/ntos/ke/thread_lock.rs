//! KTHREAD.ThreadLock.
//!
//! Compartilhado pelas consultas de alerta e pelas filas de APC.

use core::sync::atomic::Ordering;

use super::irql;
use crate::hal::cpu;
use crate::ntos::inc::types::{Kthread, NtStruct};

/// Eleva a DISPATCH_LEVEL, adquire a palavra nativa da thread e executa o
/// corpo; libera a posse e restaura o IRQL depois.
pub fn with_lock<T>(thread: u64, body: impl FnOnce() -> T) -> T {
    let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
    // SAFETY: KTHREAD viva do chamador.
    let lock = unsafe { Kthread::at(thread) }.thread_lock.atomic();
    while lock.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        cpu::pause();
    }
    let result = body();
    let _ = lock.compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst);
    irql::lower_irql(previous as u64);
    result
}
