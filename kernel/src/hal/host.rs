//! Camada hospedeira bare metal — `hal/core/host.c`.
//!
//! Inicializa a serial e o heap, e reserva a arena de 16 MB do heap dos
//! drivers convidados (sub-alocada mais tarde pelo `ntos::mm::guest_memory`).

use core::sync::atomic::{AtomicU64, Ordering};

use super::{kmalloc, serial};

static GUEST_ARENA_BASE: AtomicU64 = AtomicU64::new(0);

/// Tamanho da arena de convidados (16 MB, como no original).
pub const GUEST_ARENA_SIZE: usize = 16 << 20;

pub fn init() {
    serial::init();
    kmalloc::init();
    // A arena fica dentro do heap do kernel, que começa em 32 MB.
    let arena = kmalloc::kmalloc(GUEST_ARENA_SIZE);
    if arena.is_null() {
        panic!("arena de convidado falhou");
    }
    GUEST_ARENA_BASE.store(arena as u64, Ordering::Relaxed);
}

/// `os.getGuestArenaBase()`.
pub fn guest_arena() -> u64 {
    GUEST_ARENA_BASE.load(Ordering::Relaxed)
}
