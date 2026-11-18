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
//! - MiChargeCommit (rva 0x21aa90): o pico acompanha o maior total cobrado.
//!   Passar do limite, com o limite abaixo do limite máximo, pede a
//!   extensão dos arquivos de paginação e espera
//!   (MiIssuePageExtendRequest com qualquer arquivo, `paging_file::extend`);
//!   se algum cresceu, a cobrança recomeça, senão falha (o pedido volta com
//!   STATUS_COMMITMENT_LIMIT). No limite máximo, falha direto. Uma cobrança
//!   que deixa o total em 90% do limite ou mais, ainda dentro dele e abaixo
//!   do máximo, pede sem esperar a extensão do que levaria o limite a
//!   passar o total em um décimo do limite (no máximo 0x40000 páginas e o
//!   que falta até o máximo), pelo pedido estático.
//! - SystemCommitReserve (MiInitializeCommitment): 0x500 páginas, ou 0x100
//!   com menos de 0x4000 páginas físicas; o MiExtendPagingFiles a soma ao
//!   que precisa caber no limite.
//!
//! Cobram aqui as páginas privadas comitadas dos processos (o mesmo ponto
//! do commit do processo, `process_commit`) e as reservas dos arquivos de
//! paginação. Diferenças declaradas: o MiApplyCommitDelay (acima de 95%), a
//! reserva do sistema na própria cobrança e a remoção de segmentos sem uso
//! no limite máximo não existem.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::paging_file::extend;
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

/// Páginas físicas abaixo das quais a reserva do sistema é menor.
const SMALL_PARTITION_PAGES: u64 = 0x4000;
/// O teto do décimo do limite no pedido de extensão a 90%.
const PROACTIVE_MAXIMUM: u64 = 0x40000;

/// MI_PARTITION_COMMIT.SystemCommitReserve.
pub fn system_commit_reserve() -> u64 {
    if pfn::partition().total < SMALL_PARTITION_PAGES { 0x100 } else { 0x500 }
}

/// O pedido de extensão da cobrança que deixa `charged` em 90% do limite
/// ou mais.
fn proactive_request(counters: &Commitment, charged: u64) -> Option<u64> {
    let (limit, maximum) = (counters.limit, counters.limit_maximum);
    let tenth = limit / 10;
    if charged < tenth * 9 || charged > limit || limit >= maximum || charged >= maximum {
        return None;
    }
    if charged < limit && limit - charged >= 0x40_0000 {
        return None;
    }
    Some((maximum - limit).min(limit + tenth.min(PROACTIVE_MAXIMUM) - charged))
}

/// MiChargeCommit(Partition, Pages, 0): `false` se passa do limite e
/// nenhum arquivo de paginação cresce.
pub fn charge(pages: u64) -> bool {
    if pages == 0 {
        return true;
    }
    loop {
        let mut state = STATE.lock();
        ensure_initialized(&mut state);
        let counters = &mut state.counters;
        let Some(sum) = counters.committed.checked_add(pages) else { break };
        if sum <= counters.limit {
            counters.committed = sum;
            counters.peak = counters.peak.max(sum);
            let request = proactive_request(counters, sum);
            drop(state);
            if let Some(request) = request {
                extend::issue_request(request, extend::STATIC_REQUEST, extend::ANY_PAGE_FILE);
            }
            return true;
        }
        let extensible = counters.limit != counters.limit_maximum;
        drop(state);
        if !extensible || !extend::issue_request(pages, 0, extend::ANY_PAGE_FILE) {
            break;
        }
    }
    FAILURES.fetch_add(1, Ordering::Relaxed);
    if !REPORTED.swap(true, Ordering::Relaxed) {
        let now = snapshot();
        crate::debug_print!("[mm] commit acima do limite: {} paginas pedidas, {} cobradas, limite {}", pages, now.committed, now.limit);
    }
    false
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
