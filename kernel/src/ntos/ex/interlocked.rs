//! Operações ExInterlocked* aritméticas sob KSPIN_LOCK — ntoskrnl 19041
//! ExInterlockedAddLargeInteger 0x5b6da0, ExInterlockedAddUlong 0x3795b0.
//!
//! As duas tomam o spin lock do chamador com ExpAcquireSpinLockDisabled
//! (0x2f8814): salva RFLAGS, `cli`, `lock bts [Lock], 0`; em disputa reabilita
//! as interrupções (se estavam ligadas) enquanto espera o lock zerar e volta a
//! `cli` antes de tentar de novo. Não há elevação de IRQL. A soma não é
//! atômica por si: a exclusão vem só do lock (um `mov` de leitura e um de
//! escrita do Addend). ExpReleaseSpinLockDisabled (0x2f8744) zera o lock
//! (`lock and [Lock], 0`) e restaura as interrupções.

use core::sync::atomic::Ordering;

use crate::hal::cpu;
use crate::ntos::inc::types::Field;
use crate::ntos::ke::spin_lock;
use crate::ntos::mm::guest_memory as guest;

/// ExpAcquireSpinLockDisabled + corpo + ExpReleaseSpinLockDisabled. A posse
/// é o mesmo bit 0 do KSPIN_LOCK de `ke::spin_lock` (LOCK BTS).
fn with_spin_lock_disabled<T>(lock: u64, body: impl FnOnce() -> T) -> T {
    let mut flags = cpu::save_and_disable_interrupts();
    while !spin_lock::try_to_acquire_at_dpc_level(lock) {
        cpu::restore_interrupts(flags);
        while guest::atomic_u64(lock).load(Ordering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
        flags = cpu::save_and_disable_interrupts();
    }
    let result = body();
    spin_lock::release_from_dpc_level(lock);
    cpu::restore_interrupts(flags);
    result
}

/// ExInterlockedAddLargeInteger(Addend, Increment, Lock): devolve o valor
/// anterior; a soma de 64 bits dá a volta (lea rdx, [rbx + rdi]).
pub fn add_large_integer(addend: &Field<i64>, increment: i64, lock: u64) -> i64 {
    with_spin_lock_disabled(lock, || {
        let previous = addend.get();
        addend.set(previous.wrapping_add(increment));
        previous
    })
}

/// ExInterlockedAddUlong(Addend, Increment, Lock): ULONG anterior; soma de
/// 32 bits com volta.
pub fn add_ulong(addend: &Field<u32>, increment: u32, lock: u64) -> u32 {
    with_spin_lock_disabled(lock, || {
        let previous = addend.get();
        addend.set(previous.wrapping_add(increment));
        previous
    })
}

/// ExInterlockedInsertHeadList(ListHead, ListEntry, Lock) (ntoskrnl 19041 rva
/// 0x2f8650): sob ExpAcquireSpinLockDisabled, confere Flink->Blink == ListHead
/// (senão __fastfail(FAST_FAIL_CORRUPT_LIST_ENTRY = 3), que no kernel é
/// KERNEL_SECURITY_CHECK_FAILURE 0x139), insere na cabeça e devolve a entrada
/// que era a primeira, ou NULL se a lista estava vazia.
pub fn insert_head_list(head: &crate::ntos::inc::types::ListEntry, entry: &crate::ntos::inc::types::ListEntry, lock: u64) -> u64 {
    use crate::ntos::inc::types::{ListEntry, NtStruct};
    let head_address = head.address();
    let first = with_spin_lock_disabled(lock, || {
        let first = head.flink.get();
        // SAFETY: Flink de uma lista do chamador protegida pelo lock.
        let next = unsafe { ListEntry::at(first) };
        if next.blink.get() != head_address {
            crate::ntos::ke::bugcheck::bug_check_ex(0x139, 3, 0, 0, 0);
        }
        entry.flink.set(first);
        entry.blink.set(head_address);
        next.blink.set(entry.address());
        head.flink.set(entry.address());
        first
    });
    if first == head_address { 0 } else { first }
}
