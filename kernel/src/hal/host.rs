//! Camada hospedeira bare metal.
//!
//! Inicializa a serial e o heap, e monta a arena de 16 MB dos drivers
//! convidados (sub-alocada mais tarde pelo `ntos::mm::guest_memory`).

use core::sync::atomic::{AtomicU64, Ordering};

use super::{kmalloc, serial};
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::paging;

static GUEST_ARENA_BASE: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    serial::init();
    kmalloc::init();
    // A arena tem frames próprios fora do PFN e do heap do kernel
    // (`memory_map::GUEST_ARENA_PHYS_BASE`), na janela do heap: VA da metade
    // de sistema, fisicamente contígua e sem execução. Sem RAM ali (uma
    // máquina de menos de 272 MB), ela sai do heap do kernel, como um bloco
    // dele na mesma janela.
    let arena = if kmalloc::usable_range(map::GUEST_ARENA_PHYS_BASE, map::GUEST_ARENA_PHYS_TOP) {
        paging::map_guest_arena_window();
        map::GUEST_ARENA_BASE
    } else {
        let arena = kmalloc::kmalloc(map::GUEST_ARENA_SIZE as usize);
        if arena.is_null() {
            panic!("arena de convidado falhou");
        }
        arena as u64
    };
    GUEST_ARENA_BASE.store(arena, Ordering::Relaxed);
}

/// Base da arena de convidados (VA da janela do heap).
pub fn guest_arena() -> u64 {
    GUEST_ARENA_BASE.load(Ordering::Relaxed)
}

/// O fim físico exclusivo da arena de convidados (o limite dos buffers
/// comuns de DMA que saem dela).
pub fn guest_arena_physical_top() -> u64 {
    map::kernel_heap_physical(guest_arena()) + map::GUEST_ARENA_SIZE
}
