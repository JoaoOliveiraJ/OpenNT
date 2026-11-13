//! Lock de rotação com interrupções desligadas durante a posse — o papel do
//! KSPIN_LOCK adquirido em DISPATCH_LEVEL. Cada estado global de módulo fica
//! atrás de um destes.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::cpu;

pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// O lock serializa o acesso; o valor precisa poder mudar de contexto.
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    /// Desliga as interrupções e adquire o lock. O guard restaura o estado
    /// anterior de IF ao ser descartado.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let flags = cpu::save_and_disable_interrupts();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinLockGuard { lock: self, flags }
    }

    /// Tenta adquirir sem esperar: `None` se o lock já tem dono (no BSP,
    /// isso só acontece por reentrância).
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let flags = cpu::save_and_disable_interrupts();
        if self.locked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            Some(SpinLockGuard { lock: self, flags })
        } else {
            cpu::restore_interrupts(flags);
            None
        }
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    flags: u64,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        cpu::restore_interrupts(self.flags);
    }
}
