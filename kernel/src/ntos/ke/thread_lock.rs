//! KTHREAD.ThreadLock.
//!
//! Compartilhado pelas consultas de alerta, pelas filas de APC e pelo ajuste
//! de prioridade de quem sai de uma espera.

use core::sync::atomic::Ordering;

use super::irql;
use crate::hal::cpu;
use crate::ntos::inc::types::{Kthread, NtStruct};

/// Eleva a DISPATCH_LEVEL, adquire a palavra nativa da thread e executa o
/// corpo; libera a posse e restaura o IRQL depois.
pub fn with_lock<T>(thread: u64, body: impl FnOnce() -> T) -> T {
    let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
    let result = with_word(thread, body);
    irql::lower_irql(previous as u64);
    result
}

/// O KiAcquireThreadLock de quem pode já estar acima de DISPATCH_LEVEL (o
/// KiDeferredReadySingleThread roda no IRQL de quem sinalizou): eleva a
/// DISPATCH_LEVEL só de baixo, adquire a palavra da thread e executa o corpo.
pub fn with_lock_raised<T>(thread: u64, body: impl FnOnce() -> T) -> T {
    if irql::get_irql() >= irql::DISPATCH_LEVEL {
        return with_word(thread, body);
    }
    with_lock(thread, body)
}

/// A posse da palavra KTHREAD.ThreadLock em torno do corpo.
fn with_word<T>(thread: u64, body: impl FnOnce() -> T) -> T {
    // SAFETY: KTHREAD viva do chamador.
    let lock = unsafe { Kthread::at(thread) }.thread_lock.atomic();
    while lock.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        cpu::pause();
    }
    let result = body();
    let _ = lock.compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst);
    result
}
