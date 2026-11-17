//! LARGE_MCB do FsRtl: as rotinas FsRtl*LargeMcb* são as do
//! BASE_MCB (`fsrtl::mcb`, o motor compartilhado) sob a mutex do LARGE_MCB.
//!
//! ntoskrnl 10.0.19045: FsRtlInitializeLargeMcb 0x2f25c0 (FAST_MUTEX do
//! lookaside FsRtlFastMutexLookasideList com Count=1, evento de
//! sincronização; FsRtlInitializeBaseMcbEx(&Large->BaseMcb, PoolType, 1)),
//! FsRtlUninitializeLargeMcb 0x2f6080 (só com a mutex presente; zera o
//! ponteiro), FsRtlResetLargeMcb 0x4ef300 (sem a mutex se SelfSynchronized),
//! e os demais "ExAcquireFastMutex; FsRtlXxxBaseMcbEntry; ExReleaseFastMutex"
//! (Add 0x2f5380, Remove 0x4ef260, Lookup 0x4eef50, LookupLastAndIndex
//! 0x4ef080, GetNext 0x4eee60, NumberOfRuns 0x4ef200, Truncate 0x2f53f0).
//! LARGE_MCB = { PFAST_MUTEX GuardedMutex (+0); BASE_MCB BaseMcb (+8) }. O
//! MCB de 32 bits (FsRtlInitializeMcb, FsRtlUninitializeMcb, FsRtlAddMcbEntry)
//! é o mesmo objeto (seção no fim do arquivo).

use crate::ntos::fsrtl::mcb;
use crate::ntos::inc::types::extra_fs_fat::LargeMcb;
use crate::ntos::inc::types::extra_fs_ntfs::BaseMcb;
use crate::ntos::inc::types::{FastMutex, NtStruct};
use crate::ntos::ke::fast_mutex;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

fn with_mutex<T>(large: &LargeMcb, body: impl FnOnce(&BaseMcb) -> Result<T, KernelError>) -> Result<T, KernelError> {
    let mutex = large.guarded_mutex.get();
    fast_mutex::acquire(mutex)?;
    let result = body(&large.base_mcb);
    fast_mutex::release(mutex)?;
    result
}

/// FsRtlInitializeLargeMcb(Mcb, PoolType). O NT tira a FAST_MUTEX de um
/// lookaside de pool não paginado; aqui ela vem da arena do convidado.
pub fn initialize(large: &LargeMcb, pool: u32) -> Result<(), KernelError> {
    let mutex = guest::alloc_bytes(FastMutex::SIZE);
    if mutex == 0 {
        return Err(KernelError::with_status("FsRtlInitializeLargeMcb: no memory", mcb::STATUS_INSUFFICIENT_RESOURCES));
    }
    fast_mutex::initialize(mutex);
    large.guarded_mutex.set(mutex);
    mcb::initialize(&large.base_mcb, pool, mcb::FLAG_RAISE_ON_ALLOCATION_FAILURE).map(|_| ())
}

/// FsRtlUninitializeLargeMcb.
pub fn uninitialize(large: &LargeMcb) -> Result<(), KernelError> {
    let mutex = large.guarded_mutex.get();
    if mutex == 0 {
        return Ok(());
    }
    guest::free_bytes(mutex);
    large.guarded_mutex.set(0);
    mcb::uninitialize(&large.base_mcb)
}

/// FsRtlAddLargeMcbEntry -> BOOLEAN.
pub fn add_entry(large: &LargeMcb, vbn: u64, lbn: u64, count: u64) -> Result<bool, KernelError> {
    with_mutex(large, |base| mcb::add_entry_boolean(base, vbn, lbn, count))
}

/// FsRtlRemoveLargeMcbEntry -> VOID.
pub fn remove_entry(large: &LargeMcb, vbn: u64, count: u64) -> Result<(), KernelError> {
    with_mutex(large, |base| mcb::remove(base, vbn, count).map(|_| ()))
}

/// FsRtlLookupLargeMcbEntry(Mcb, Vbn, *Lbn, *SectorCountFromLbn, *StartingLbn,
/// *SectorCountFromStartingLbn, *Index) -> BOOLEAN. As saídas opcionais
/// seguem como endereços (0 = ausente), como o motor `mcb::lookup` as recebe.
#[allow(clippy::too_many_arguments)]
pub fn lookup_entry(large: &LargeMcb, vbn: u64, lbn: u64, sector_count_from_lbn: u64, starting_lbn: u64, sector_count_from_starting_lbn: u64, index: u64) -> Result<bool, KernelError> {
    let outputs = mcb::LookupOutputs { lbn, sector_count_from_lbn, starting_lbn, sector_count_from_starting_lbn, index };
    with_mutex(large, |base| Ok(mcb::lookup(base, vbn, &outputs)))
}

/// FsRtlLookupLastLargeMcbEntryAndIndex(Mcb, *LargeVbn, *LargeLbn, *Index) -> BOOLEAN.
pub fn lookup_last_entry(large: &LargeMcb, vbn: u64, lbn: u64, index: u64) -> Result<bool, KernelError> {
    with_mutex(large, |base| Ok(mcb::lookup_last_and_index(base, vbn, lbn, index)))
}

/// FsRtlGetNextLargeMcbEntry(Mcb, RunIndex, *Vbn, *Lbn, *SectorCount) -> BOOLEAN.
pub fn next_entry(large: &LargeMcb, run_index: u32, vbn: u64, lbn: u64, count: u64) -> Result<bool, KernelError> {
    with_mutex(large, |base| Ok(mcb::get_next_entry(base, run_index, vbn, lbn, count)))
}

/// FsRtlNumberOfRunsInLargeMcb.
pub fn number_of_runs(large: &LargeMcb) -> Result<u32, KernelError> {
    with_mutex(large, |base| Ok(mcb::number_of_runs(base)))
}

/// FsRtlTruncateLargeMcb.
pub fn truncate(large: &LargeMcb, vbn: u64) -> Result<(), KernelError> {
    with_mutex(large, |base| mcb::truncate(base, vbn))
}

/// FsRtlResetLargeMcb(Mcb, SelfSynchronized).
pub fn reset(large: &LargeMcb, self_synchronized: bool) -> Result<(), KernelError> {
    if self_synchronized {
        mcb::reset(&large.base_mcb);
        return Ok(());
    }
    with_mutex(large, |base| {
        mcb::reset(base);
        Ok(())
    })
}

/// FsRtlLookupLastLargeMcbEntry(Mcb, *LargeVbn, *LargeLbn) -> BOOLEAN (RVA
/// 0x4ef000): o FsRtlLookupLastBaseMcbEntry sob a mutex do LARGE_MCB.
pub fn lookup_last(large: &LargeMcb, vbn: u64, lbn: u64) -> Result<bool, KernelError> {
    with_mutex(large, |base| Ok(mcb::lookup_last(base, vbn, lbn)))
}

// ---- MCB de 32 bits ------------------------------------------------------------
//
// O MCB antigo do ntifs.h é `{ LARGE_MCB DummyFieldThatSizesThisStructureSmallerThanALargeMcb; }`:
// as rotinas FsRtl*Mcb* são as do LARGE_MCB sobre o mesmo objeto, com os
// argumentos ULONG estendidos com zero. FsRtlInitializeMcb (RVA 0x88b620) e
// FsRtlUninitializeMcb (RVA 0x88b640) são chamadas diretas de
// FsRtlInitializeLargeMcb e FsRtlUninitializeLargeMcb (`initialize` e
// `uninitialize` acima); FsRtlAddMcbEntry (RVA 0x4eee40) é a abaixo.

/// FsRtlAddMcbEntry(Mcb, Vbn, Lbn, SectorCount) -> BOOLEAN: os três ULONG
/// estendidos com zero (`mov r9d, r9d; mov r8d, r8d; mov edx, edx`) e o
/// FsRtlAddLargeMcbEntry.
pub fn add_mcb_entry(large: &LargeMcb, vbn: u32, lbn: u32, sector_count: u32) -> Result<bool, KernelError> {
    add_entry(large, vbn as u64, lbn as u64, sector_count as u64)
}
