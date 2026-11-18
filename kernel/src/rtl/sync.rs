//! Lock de rotação com interrupções desligadas durante a posse — o papel do
//! KSPIN_LOCK adquirido em DISPATCH_LEVEL. Cada estado global de módulo fica
//! atrás de um destes. Para estado lido muito e mudado em operações longas
//! (o volume de um sistema de arquivos), [`SharedLock`] faz o papel do
//! ERESOURCE: donos compartilhados ou um dono exclusivo.
//!
//! Cada CPU conta as posses que tem de cada um ([`spin_locks_held`],
//! [`shared_locks_held`]), em células da sua reserva de KPCR endereçadas
//! pelo GS: uma thread que bloqueia deixa a CPU para outra. A posse de um
//! SpinLock nunca atravessa essa troca (é um erro, como esperar com um
//! KSPIN_LOCK); a de um SharedLock é da thread, que a leva consigo
//! ([`swap_shared_locks_held`]).

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::hal::cpu;

/// Deslocamentos, a partir da base do GS, dos contadores de posse da CPU
/// (SpinLock, SharedLock). Zero até o Ke publicá-los, quando toda CPU que
/// executa o kernel tem o GS na própria KPCR; antes disso nada é contado.
static SPIN_COUNTER: AtomicU64 = AtomicU64::new(0);
static SHARED_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Publica as células dos contadores (`ke::pcr::init`, logo depois de o GS
/// do BSP apontar a KPCR; os APs carregam o GS antes de executar o kernel).
pub fn publish_lock_counters(spin: u64, shared: u64) {
    SHARED_COUNTER.store(shared, Ordering::Release);
    SPIN_COUNTER.store(spin, Ordering::Release);
}

/// Soma `delta` à célula da CPU corrente; `false` se os contadores ainda
/// não existem.
#[inline]
fn count(counter: &AtomicU64, delta: i32) -> bool {
    let offset = counter.load(Ordering::Relaxed);
    if offset == 0 {
        return false;
    }
    // SAFETY: a célula fica na reserva da KPCR desta CPU, mapeada por toda a
    // vida do sistema; só esta CPU a altera, e as posses que ela conta
    // começam e terminam nela.
    unsafe { core::arch::asm!("add dword ptr gs:[{}], {:e}", in(reg) offset, in(reg) delta, options(nostack)) };
    true
}

fn read(counter: &AtomicU64) -> u32 {
    let offset = counter.load(Ordering::Acquire);
    if offset == 0 {
        return 0;
    }
    let value: u32;
    // SAFETY: como em `count`.
    unsafe { core::arch::asm!("mov {:e}, dword ptr gs:[{}]", out(reg) value, in(reg) offset, options(nostack, readonly, preserves_flags)) };
    value
}

/// SpinLocks que a CPU corrente possui.
pub fn spin_locks_held() -> u32 {
    read(&SPIN_COUNTER)
}

/// Posses de SharedLock da CPU corrente.
pub fn shared_locks_held() -> u32 {
    read(&SHARED_COUNTER)
}

/// Troca a contagem de posses de SharedLock da CPU corrente e devolve a
/// anterior: uma thread que deixa a CPU leva as dela, e a que entra recoloca
/// as suas (`ke::context_switch`).
pub fn swap_shared_locks_held(value: u32) -> u32 {
    let offset = SHARED_COUNTER.load(Ordering::Acquire);
    if offset == 0 {
        return 0;
    }
    let previous: u32;
    // SAFETY: como em `count`; a troca é da célula desta CPU.
    unsafe { core::arch::asm!("xchg dword ptr gs:[{}], {:e}", in(reg) offset, inout(reg) value => previous, options(nostack)) };
    previous
}

/// Quem espera um SharedLock com dono cede a CPU por aqui a cada volta (o Ke
/// registra: uma thread de kernel deixa a CPU, o contexto de boot roda o
/// despacho, um AP gira), em vez de girar enquanto o dono, que pode ter
/// deixado a CPU numa espera, não anda.
static CONTENTION_YIELD: AtomicU64 = AtomicU64::new(0);

/// Registra a rotina de cessão da espera por um SharedLock.
pub fn set_contention_yield(routine: fn()) {
    CONTENTION_YIELD.store(routine as usize as u64, Ordering::Release);
}

fn contention_yield() {
    let routine = CONTENTION_YIELD.load(Ordering::Acquire);
    if routine == 0 {
        core::hint::spin_loop();
        return;
    }
    // SAFETY: só `set_contention_yield` grava a célula, com um `fn()`.
    let routine: fn() = unsafe { core::mem::transmute(routine as usize) };
    routine();
}

/// O dono de uma posse de SharedLock: a thread corrente da CPU
/// (KPRCB.CurrentThread, gs:[188h]); antes de haver thread, o processador.
fn owner_identity() -> u64 {
    if SPIN_COUNTER.load(Ordering::Relaxed) != 0 {
        let thread: u64;
        // SAFETY: com os contadores publicados o GS de toda CPU é a KPCR dela.
        unsafe { core::arch::asm!("mov {}, gs:[0x188]", out(reg) thread, options(nostack, readonly, preserves_flags)) };
        if thread != 0 {
            return thread;
        }
    }
    current_processor() as u64 + 1
}

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
        SpinLockGuard { lock: self, flags, counted: count(&SPIN_COUNTER, 1) }
    }

    /// Tenta adquirir sem esperar: `None` se o lock já tem dono (no BSP,
    /// isso só acontece por reentrância).
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let flags = cpu::save_and_disable_interrupts();
        if self.locked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            Some(SpinLockGuard { lock: self, flags, counted: count(&SPIN_COUNTER, 1) })
        } else {
            cpu::restore_interrupts(flags);
            None
        }
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    flags: u64,
    /// A posse entrou no contador da CPU (adquirida depois da publicação).
    counted: bool,
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
        if self.counted {
            count(&SPIN_COUNTER, -1);
        }
        cpu::restore_interrupts(self.flags);
    }
}

const EXCLUSIVE_OWNED: u64 = 1 << 63;
const EXCLUSIVE_WAITER: u64 = 1 << 32;
const EXCLUSIVE_WAITERS: u64 = 0x7FFF_FFFF << 32;
const SHARED_OWNERS: u64 = 0xFFFF_FFFF;
/// Donos distintos que um SharedLock acompanha ao mesmo tempo.
const OWNER_SLOTS: usize = 64;

/// APIC id inicial do processador corrente (CPUID.01h:EBX[31:24]).
fn current_processor() -> usize {
    (cpu::cpuid(1)[1] >> 24) as usize
}

/// As aquisições em posse de um dono (a identidade de [`owner_identity`]).
struct OwnerSlot {
    identity: AtomicU64,
    depth: AtomicU32,
}

/// Recurso compartilhado/exclusivo — o ERESOURCE para estado do próprio
/// kernel: vários donos compartilhados ou um dono exclusivo. Como no
/// ERESOURCE, o dono é a thread (a corrente da CPU), não o processador: uma
/// thread que deixa a CPU numa espera continua dona, e a que entra não herda
/// a posse. Como nas rotinas ExAcquireResource*Lite, quem já possui o
/// recurso o readquire sem esperar (as rotinas de leitura se aninham e o
/// dono exclusivo chama as de leitura); pedir a posse exclusiva tendo a
/// compartilhada trava no NT e aqui para o sistema. Um pedido exclusivo em
/// espera barra novos donos compartilhados, para que leitores contínuos não
/// deixem o escritor sem vez. Quem espera cede a CPU a cada volta (a rotina
/// registrada pelo Ke) e não mexe em IF: os trampolins de interrupção não
/// tocam no estado protegido.
pub struct SharedLock {
    /// Bit 63: posse exclusiva; bits 32-62: pedidos exclusivos em espera;
    /// bits 0-31: donos compartilhados.
    state: AtomicU64,
    /// Identidade do dono exclusivo (0 = nenhum).
    owner: AtomicU64,
    /// Aquisições de cada dono; só o próprio dono altera a sua contagem.
    owners: [OwnerSlot; OWNER_SLOTS],
}

impl SharedLock {
    pub const fn new() -> Self {
        Self { state: AtomicU64::new(0), owner: AtomicU64::new(0), owners: [const { OwnerSlot { identity: AtomicU64::new(0), depth: AtomicU32::new(0) } }; OWNER_SLOTS] }
    }

    /// A entrada de `identity`, se ela possui o recurso.
    fn slot_of(&self, identity: u64) -> Option<usize> {
        self.owners.iter().position(|slot| slot.identity.load(Ordering::Acquire) == identity && slot.depth.load(Ordering::Relaxed) != 0)
    }

    /// Ocupa uma entrada livre para `identity` (com profundidade 1).
    fn claim_slot(&self, identity: u64) -> usize {
        loop {
            for (index, slot) in self.owners.iter().enumerate() {
                if slot.identity.compare_exchange(0, identity, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                    slot.depth.store(1, Ordering::Release);
                    return index;
                }
            }
            contention_yield();
        }
    }

    /// ExAcquireResourceSharedLite com espera.
    pub fn acquire_shared(&self) -> SharedLockGuard<'_> {
        let identity = owner_identity();
        if let Some(slot) = self.slot_of(identity) {
            self.owners[slot].depth.fetch_add(1, Ordering::Relaxed);
            return SharedLockGuard { lock: self, slot, release: Release::Nested, counted: count(&SHARED_COUNTER, 1) };
        }
        loop {
            let state = self.state.load(Ordering::Relaxed);
            if state & (EXCLUSIVE_OWNED | EXCLUSIVE_WAITERS) == 0 && self.state.compare_exchange_weak(state, state + 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                break;
            }
            contention_yield();
        }
        let slot = self.claim_slot(identity);
        SharedLockGuard { lock: self, slot, release: Release::Shared, counted: count(&SHARED_COUNTER, 1) }
    }

    /// ExAcquireResourceExclusiveLite com espera.
    pub fn acquire_exclusive(&self) -> SharedLockGuard<'_> {
        let identity = owner_identity();
        if let Some(slot) = self.slot_of(identity) {
            assert!(self.owner.load(Ordering::Relaxed) == identity, "SharedLock: posse exclusiva pedida com a compartilhada");
            self.owners[slot].depth.fetch_add(1, Ordering::Relaxed);
            return SharedLockGuard { lock: self, slot, release: Release::Nested, counted: count(&SHARED_COUNTER, 1) };
        }
        self.state.fetch_add(EXCLUSIVE_WAITER, Ordering::Relaxed);
        loop {
            let state = self.state.load(Ordering::Relaxed);
            if state & (EXCLUSIVE_OWNED | SHARED_OWNERS) == 0 && self.state.compare_exchange_weak(state, (state - EXCLUSIVE_WAITER) | EXCLUSIVE_OWNED, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                break;
            }
            contention_yield();
        }
        self.owner.store(identity, Ordering::Relaxed);
        let slot = self.claim_slot(identity);
        SharedLockGuard { lock: self, slot, release: Release::Exclusive, counted: count(&SHARED_COUNTER, 1) }
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
/// liberada pelo dono que a adquiriu.
pub struct SharedLockGuard<'a> {
    lock: &'a SharedLock,
    slot: usize,
    release: Release,
    /// A posse entrou no contador da CPU.
    counted: bool,
}

impl Drop for SharedLockGuard<'_> {
    fn drop(&mut self) {
        if self.counted {
            count(&SHARED_COUNTER, -1);
        }
        let slot = &self.lock.owners[self.slot];
        let release_slot = || {
            slot.depth.store(0, Ordering::Relaxed);
            slot.identity.store(0, Ordering::Release);
        };
        match self.release {
            Release::Nested => {
                slot.depth.fetch_sub(1, Ordering::Relaxed);
            }
            Release::Shared => {
                release_slot();
                self.lock.state.fetch_sub(1, Ordering::Release);
            }
            Release::Exclusive => {
                release_slot();
                self.lock.owner.store(0, Ordering::Relaxed);
                self.lock.state.fetch_and(!EXCLUSIVE_OWNED, Ordering::Release);
            }
        }
    }
}
