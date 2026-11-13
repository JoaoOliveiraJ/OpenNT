//! NonPagedPoolLock da PCR nativa, usado pela arena NT de convidados.
//! O heap do kernel (kmalloc) é separado.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::ke::irql;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory;

static POINTER: AtomicU64 = AtomicU64::new(0);

fn acquire() -> u64 {
    let previous = irql::get_irql();
    irql::raise_irql(previous.max(irql::DISPATCH_LEVEL));
    let pointer = POINTER.load(Ordering::Relaxed);
    // A célula é um static da imagem do kernel: atômico pela VA.
    while guest_memory::atomic_u64(pointer).compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        core::hint::spin_loop();
    }
    previous as u64
}

fn release(previous: u64) {
    let pointer = POINTER.load(Ordering::Relaxed);
    assert!(guest_memory::atomic_u64(pointer).compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok(), "NonPagedPoolLock ownership corrupted");
    irql::lower_irql(previous);
}

pub fn init() -> Result<(), KernelError> {
    if POINTER.load(Ordering::Relaxed) != 0 {
        return Ok(());
    }
    let pointer = native_call::non_paged_pool_lock_address();
    if pointer == 0 || pointer % 8 != 0 {
        return Err(KernelError::new("NonPagedPoolLock storage unavailable"));
    }
    POINTER.store(pointer, Ordering::Relaxed);
    guest_memory::set_pool_lock(Some((acquire, release)));
    Ok(())
}
