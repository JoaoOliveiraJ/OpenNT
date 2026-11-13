//! IO_REMOVE_LOCK — IoInitializeRemoveLockEx, IoAcquire/ReleaseRemoveLockEx e
//! IoReleaseRemoveLockAndWaitEx, sobre o bloco comum do wdm.h. O IoCount
//! muda por InterlockedIncrement/InterlockedDecrement.

use core::sync::atomic::Ordering;

use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;

/// IO_REMOVE_LOCK (bloco comum do wdm.h): Removed @0, IoCount @4, WaitEvent @0x10.
const REMOVE_LOCK_REMOVED: u64 = 0;
const REMOVE_LOCK_IO_COUNT: u64 = 4;
const REMOVE_LOCK_WAIT_EVENT: u64 = 0x10;

/// IoInitializeRemoveLockEx.
pub fn initialize(lock: u64) {
    guest::write8(lock + REMOVE_LOCK_REMOVED, 0);
    guest::write32(lock + REMOVE_LOCK_IO_COUNT, 0);
    dispatcher::initialize_event(lock + REMOVE_LOCK_WAIT_EVENT, 0, false);
}

/// IoAcquireRemoveLockEx: STATUS_DELETE_PENDING depois da remoção.
pub fn acquire(lock: u64) -> u32 {
    if guest::read8(lock + REMOVE_LOCK_REMOVED) != 0 {
        return 0xC000_0056;
    }
    guest::atomic_u32(lock + REMOVE_LOCK_IO_COUNT).fetch_add(1, Ordering::SeqCst);
    0
}

/// InterlockedDecrement do IoCount: devolve o valor novo.
fn decrement(lock: u64) -> u32 {
    guest::atomic_u32(lock + REMOVE_LOCK_IO_COUNT).fetch_sub(1, Ordering::SeqCst).wrapping_sub(1)
}

/// IoReleaseRemoveLockEx: a última referência de um lock removido acorda o
/// IoReleaseRemoveLockAndWaitEx.
pub fn release(lock: u64) {
    let remaining = decrement(lock);
    if remaining == 0 && guest::read8(lock + REMOVE_LOCK_REMOVED) != 0 {
        dispatcher::set_event(lock + REMOVE_LOCK_WAIT_EVENT);
    }
}

/// Marca removido, solta a referência do chamador e espera as pendentes.
pub fn release_and_wait(lock: u64) {
    guest::write8(lock + REMOVE_LOCK_REMOVED, 1);
    let remaining = decrement(lock);
    if remaining as i32 > 0 {
        dispatcher::wait_for_single_object(lock + REMOVE_LOCK_WAIT_EVENT, 0, 0, false);
    }
}
