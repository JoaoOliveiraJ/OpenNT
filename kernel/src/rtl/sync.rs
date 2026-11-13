//! Lock de rotação com interrupções desligadas durante a posse — o papel do
//! KSPIN_LOCK adquirido em DISPATCH_LEVEL. Cada estado global de módulo fica
//! atrás de um destes. Para estado lido muito e mudado em operações longas
//! (o volume de um sistema de arquivos), [`SharedLock`] faz o papel do
//! ERESOURCE: donos compartilhados ou um dono exclusivo.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

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

/// APIC ids do xAPIC (oito bits).
const MAX_PROCESSORS: usize = 256;
const EXCLUSIVE_OWNED: u64 = 1 << 63;
const EXCLUSIVE_WAITER: u64 = 1 << 32;
const EXCLUSIVE_WAITERS: u64 = 0x7FFF_FFFF << 32;
const SHARED_OWNERS: u64 = 0xFFFF_FFFF;

/// APIC id inicial do processador corrente (CPUID.01h:EBX[31:24]).
fn current_processor() -> usize {
    (cpu::cpuid(1)[1] >> 24) as usize
}

/// Recurso compartilhado/exclusivo — o ERESOURCE para estado do próprio
/// kernel: vários donos compartilhados ou um dono exclusivo. Como nas
/// rotinas ExAcquireResource*Lite, quem já possui o recurso o readquire sem
/// esperar (a posse é contada por processador, então as rotinas de leitura
/// se aninham e o dono exclusivo chama as de leitura); pedir a posse
/// exclusiva tendo a compartilhada trava no NT e aqui para o sistema. Um
/// pedido exclusivo em espera barra novos donos compartilhados, para que
/// leitores contínuos não deixem o escritor sem vez. A espera é ativa
/// (contextos Rust do kernel não bloqueiam) e não mexe em IF: os trampolins
/// de interrupção não tocam no estado protegido.
pub struct SharedLock {
    /// Bit 63: posse exclusiva; bits 32-62: pedidos exclusivos em espera;
    /// bits 0-31: donos compartilhados.
    state: AtomicU64,
    /// APIC id + 1 do dono exclusivo (0 = nenhum).
    owner: AtomicU32,
    /// Aquisições em posse de cada processador; só o próprio as altera.
    depth: [AtomicU32; MAX_PROCESSORS],
}

impl SharedLock {
    pub const fn new() -> Self {
        Self { state: AtomicU64::new(0), owner: AtomicU32::new(0), depth: [const { AtomicU32::new(0) }; MAX_PROCESSORS] }
    }

    /// ExAcquireResourceSharedLite com espera.
    pub fn acquire_shared(&self) -> SharedLockGuard<'_> {
        let processor = current_processor();
        if self.depth[processor].load(Ordering::Relaxed) != 0 {
            self.depth[processor].fetch_add(1, Ordering::Relaxed);
            return SharedLockGuard { lock: self, processor, release: Release::Nested };
        }
        loop {
            let state = self.state.load(Ordering::Relaxed);
            if state & (EXCLUSIVE_OWNED | EXCLUSIVE_WAITERS) == 0 && self.state.compare_exchange_weak(state, state + 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                break;
            }
            core::hint::spin_loop();
        }
        self.depth[processor].store(1, Ordering::Relaxed);
        SharedLockGuard { lock: self, processor, release: Release::Shared }
    }

    /// ExAcquireResourceExclusiveLite com espera.
    pub fn acquire_exclusive(&self) -> SharedLockGuard<'_> {
        let processor = current_processor();
        if self.depth[processor].load(Ordering::Relaxed) != 0 {
            assert!(self.owner.load(Ordering::Relaxed) == processor as u32 + 1, "SharedLock: posse exclusiva pedida com a compartilhada");
            self.depth[processor].fetch_add(1, Ordering::Relaxed);
            return SharedLockGuard { lock: self, processor, release: Release::Nested };
        }
        self.state.fetch_add(EXCLUSIVE_WAITER, Ordering::Relaxed);
        loop {
            let state = self.state.load(Ordering::Relaxed);
            if state & (EXCLUSIVE_OWNED | SHARED_OWNERS) == 0 && self.state.compare_exchange_weak(state, (state - EXCLUSIVE_WAITER) | EXCLUSIVE_OWNED, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                break;
            }
            core::hint::spin_loop();
        }
        self.owner.store(processor as u32 + 1, Ordering::Relaxed);
        self.depth[processor].store(1, Ordering::Relaxed);
        SharedLockGuard { lock: self, processor, release: Release::Exclusive }
    }
}

impl Default for SharedLock {
    fn default() -> Self {
        Self::new()
    }
}

enum Release {
    /// Readquirido por quem já o possuía: só a contagem do processador.
    Nested,
    Shared,
    Exclusive,
}

/// Posse de um [`SharedLock`] (ExReleaseResourceLite ao descartar); é
/// liberada no processador que a adquiriu.
pub struct SharedLockGuard<'a> {
    lock: &'a SharedLock,
    processor: usize,
    release: Release,
}

impl Drop for SharedLockGuard<'_> {
    fn drop(&mut self) {
        let depth = &self.lock.depth[self.processor];
        match self.release {
            Release::Nested => {
                depth.fetch_sub(1, Ordering::Relaxed);
            }
            Release::Shared => {
                depth.store(0, Ordering::Relaxed);
                self.lock.state.fetch_sub(1, Ordering::Release);
            }
            Release::Exclusive => {
                depth.store(0, Ordering::Relaxed);
                self.lock.owner.store(0, Ordering::Relaxed);
                self.lock.state.fetch_and(!EXCLUSIVE_OWNED, Ordering::Release);
            }
        }
    }
}
