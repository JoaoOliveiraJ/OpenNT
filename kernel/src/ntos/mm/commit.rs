//! A cobrança de commit do sistema: os contadores da partição do sistema do
//! ntoskrnl 19041 (MI_VISIBLE_PARTITION.TotalCommittedPages e
//! TotalCommitLimit, MI_PARTITION_COMMIT.TotalCommitLimitMaximum e
//! PeakCommitment), em páginas.
//!
//! - MiInitializeCommitment (rva 0x3bf284): o limite e o limite máximo
//!   começam no número de páginas físicas da partição
//!   (MiIncreaseCommitLimits com NumberOfPhysicalPages nos dois) e o que o
//!   boot já ocupa entra cobrado (MiChargeCommit de NumberOfPhysicalPages
//!   menos as páginas disponíveis). Aqui a partição é o banco de frames
//!   (`pfn`), e a inicialização acontece na primeira cobrança ou consulta,
//!   depois do boot do kernel.
//! - MiIncreaseCommitLimits (rva 0x3bf408): o limite sobe com o tamanho do
//!   arquivo de paginação e o limite máximo com o máximo dele; a inserção do
//!   arquivo cobra as duas páginas que ele reserva no começo.
//! - MiChargeCommit (rva 0x21aa90): passar do limite falha (o pedido volta
//!   com STATUS_COMMITMENT_LIMIT); o pico acompanha o maior total cobrado.
//!   O NT tenta antes crescer um arquivo de paginação até o máximo dele
//!   (MiAttemptPageFileExtension); o OpenNT ainda não estende arquivos de
//!   paginação, então a cobrança acima do limite atual falha.
//!
//! Cobram aqui as páginas privadas comitadas dos processos (o mesmo ponto
//! do commit do processo, `process_commit`) e as reservas dos arquivos de
//! paginação.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::pfn;
use crate::rtl::SpinLock;

/// Os contadores, em páginas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Commitment {
    pub committed: u64,
    pub limit: u64,
    pub limit_maximum: u64,
    pub peak: u64,
}

struct State {
    initialized: bool,
    counters: Commitment,
}

static STATE: SpinLock<State> = SpinLock::new(State { initialized: false, counters: Commitment { committed: 0, limit: 0, limit_maximum: 0, peak: 0 } });
/// Cobranças recusadas (MI_VISIBLE_PARTITION.ChargeCommitmentFailures).
static FAILURES: AtomicU64 = AtomicU64::new(0);
static REPORTED: AtomicBool = AtomicBool::new(false);

/// MiInitializeCommitment, uma vez.
fn ensure_initialized(state: &mut State) {
    if state.initialized {
        return;
    }
    let partition = pfn::partition();
    let in_use = partition.total.saturating_sub(partition.available);
    state.counters = Commitment { committed: in_use, limit: partition.total, limit_maximum: partition.total, peak: in_use };
    state.initialized = true;
}

/// MiChargeCommit(Partition, Pages): `false` se passa do limite.
pub fn charge(pages: u64) -> bool {
    if pages == 0 {
        return true;
    }
    let mut state = STATE.lock();
    ensure_initialized(&mut state);
    let counters = &mut state.counters;
    let Some(charged) = counters.committed.checked_add(pages).filter(|&charged| charged <= counters.limit) else {
        drop(state);
        FAILURES.fetch_add(1, Ordering::Relaxed);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            let now = snapshot();
            crate::debug_print!("[mm] commit acima do limite: {} paginas pedidas, {} cobradas, limite {}", pages, now.committed, now.limit);
        }
        return false;
    };
    counters.committed = charged;
    counters.peak = counters.peak.max(charged);
    true
}

/// MiReturnCommit(Partition, Pages).
pub fn release(pages: u64) {
    if pages == 0 {
        return;
    }
    let mut state = STATE.lock();
    ensure_initialized(&mut state);
    state.counters.committed = state.counters.committed.saturating_sub(pages);
}

/// MiIncreaseCommitLimits(Partition, Limit, Maximum, ...): `false` se o
/// limite máximo daria a volta.
pub fn increase_limits(limit: u64, maximum: u64) -> bool {
    let mut state = STATE.lock();
    ensure_initialized(&mut state);
    let counters = &mut state.counters;
    let Some(new_maximum) = counters.limit_maximum.checked_add(maximum) else { return false };
    counters.limit_maximum = new_maximum;
    counters.limit += limit;
    true
}

/// MiReduceCommitLimits(Partition, Limit, Maximum).
pub fn reduce_limits(limit: u64, maximum: u64) {
    let mut state = STATE.lock();
    ensure_initialized(&mut state);
    state.counters.limit = state.counters.limit.saturating_sub(limit);
    state.counters.limit_maximum = state.counters.limit_maximum.saturating_sub(maximum);
}

/// Cobra sem conferir o limite (o lock xadd de 2 páginas do
/// MiIncreaseCommitLimits para a reserva do arquivo de paginação).
pub fn charge_unchecked(pages: u64) {
    let mut state = STATE.lock();
    ensure_initialized(&mut state);
    state.counters.committed += pages;
    state.counters.peak = state.counters.peak.max(state.counters.committed);
}

/// MmGetTotalCommittedPages, MmGetTotalCommitLimit, o limite máximo e
/// MmGetPeakCommitment.
pub fn snapshot() -> Commitment {
    let mut state = STATE.lock();
    ensure_initialized(&mut state);
    state.counters
}

/// Cobranças recusadas desde o boot.
pub fn failures() -> u64 {
    FAILURES.load(Ordering::Relaxed)
}
