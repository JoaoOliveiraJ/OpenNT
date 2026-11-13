//! IO_REMOVE_LOCK — IoInitializeRemoveLockEx, IoAcquire/ReleaseRemoveLockEx e
//! IoReleaseRemoveLockAndWaitEx, sobre o bloco comum do wdm.h. O IoCount
//! muda por InterlockedIncrement/InterlockedDecrement.

use core::sync::atomic::Ordering;

use crate::ntos::ke::dispatcher;

use crate::ntos::inc::types::{IoRemoveLock, NtStruct};

/// IO_REMOVE_LOCK do driver (o bloco comum do wdm.h: Removed, IoCount e o
/// KEVENT RemoveEvent).
fn lock_at(lock: u64) -> &'static IoRemoveLock {
    // SAFETY: IO_REMOVE_LOCK na extensão do dispositivo do driver.
    unsafe { IoRemoveLock::at(lock) }
}

/// IoInitializeRemoveLockEx.
pub fn initialize(lock: u64) {
    let common = &lock_at(lock).common;
    common.removed.set(0);
    common.io_count.set(0);
    dispatcher::initialize_event(common.remove_event.address(), 0, false);
}

/// IoAcquireRemoveLockEx: STATUS_DELETE_PENDING depois da remoção.
pub fn acquire(lock: u64) -> u32 {
    let common = &lock_at(lock).common;
    if common.removed.get() != 0 {
        return 0xC000_0056;
    }
    common.io_count.atomic().fetch_add(1, Ordering::SeqCst);
    0
}

/// InterlockedDecrement do IoCount: devolve o valor novo.
fn decrement(lock: u64) -> u32 {
    lock_at(lock).common.io_count.atomic().fetch_sub(1, Ordering::SeqCst).wrapping_sub(1) as u32
}

/// IoReleaseRemoveLockEx: a última referência de um lock removido acorda o
/// IoReleaseRemoveLockAndWaitEx.
pub fn release(lock: u64) {
    let remaining = decrement(lock);
    let common = &lock_at(lock).common;
    if remaining == 0 && common.removed.get() != 0 {
        dispatcher::set_event(common.remove_event.address());
    }
}

/// Marca removido, solta a referência do chamador e espera as pendentes.
pub fn release_and_wait(lock: u64) {
    let common = &lock_at(lock).common;
    common.removed.set(1);
    let remaining = decrement(lock);
    if remaining as i32 > 0 {
        dispatcher::wait_for_single_object(common.remove_event.address(), 0, 0, false);
    }
}
