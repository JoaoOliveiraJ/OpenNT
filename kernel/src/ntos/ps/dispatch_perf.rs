//! Contadores de desempenho do despachante, na serial como linhas `[perf]`.
//!
//! Medem, pelo TSC, onde o processador de boot passa o tempo entre os
//! intervalos: dormindo no HLT do laço ocioso, girando nele à espera de um
//! KTIMER que vence antes do próximo tique, nas sondagens das esperas de
//! usuário (`threads::refresh_ready_user_threads`, com as esperas sondadas e
//! as trocas de processo, cada uma uma carga de CR3) e no despacho de
//! usuário fora do intervalo da thread. A cada [`REPORT_INTERVAL_MS`] de
//! uptime o tique escreve uma linha com o que mudou desde a anterior; o
//! xtask anota nela a hora do hospedeiro (`[xtask] [perf] aos N s`).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::cpu;
use crate::ntos::ke::clock;

/// O intervalo entre duas linhas `[perf]`, em ms de uptime.
pub const REPORT_INTERVAL_MS: u64 = 5_000;

/// Um trecho medido: TSC acumulado e quantas vezes rodou.
pub struct Section {
    tsc: AtomicU64,
    count: AtomicU64,
}

impl Section {
    const fn new() -> Self {
        Self { tsc: AtomicU64::new(0), count: AtomicU64::new(0) }
    }

    /// Conta um trecho que começou no TSC `started`.
    pub fn add_since(&self, started: u64) {
        self.tsc.fetch_add(cpu::rdtsc().wrapping_sub(started), Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn take(&self) -> (u64, u64) {
        (self.tsc.load(Ordering::Relaxed), self.count.load(Ordering::Relaxed))
    }
}

/// O HLT do laço ocioso.
pub static IDLE_HALT: Section = Section::new();
/// O giro do laço ocioso à espera de um KTIMER que vence antes do tique.
pub static IDLE_SPIN: Section = Section::new();
/// As sondagens das esperas de usuário.
pub static REFRESH: Section = Section::new();
/// O despacho de usuário fora do intervalo da thread (sondagens, pumps,
/// fins de processo, escolha).
pub static DISPATCH: Section = Section::new();
/// Os intervalos de usuário.
pub static SLICE: Section = Section::new();
/// Esperas de usuário sondadas.
pub static POLLS: AtomicU64 = AtomicU64::new(0);
/// Trocas de processo (cargas de CR3) nas sondagens.
pub static SWITCHES: AtomicU64 = AtomicU64::new(0);
/// Todas as cargas de CR3 (`context_switch::load_root`).
pub static CR3_LOADS: AtomicU64 = AtomicU64::new(0);
/// O TSC da última volta do laço ocioso que girou (0 = não girava).
static SPIN_SINCE: AtomicU64 = AtomicU64::new(0);

/// O laço ocioso gira mais uma volta: a volta desde a anterior conta.
pub fn spinning() {
    let now = cpu::rdtsc();
    let previous = SPIN_SINCE.swap(now, Ordering::Relaxed);
    if previous != 0 {
        IDLE_SPIN.tsc.fetch_add(now.wrapping_sub(previous), Ordering::Relaxed);
        IDLE_SPIN.count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Quantas vezes o laço ocioso dormiu no HLT.
pub fn halts() -> u64 {
    IDLE_HALT.count.load(Ordering::Relaxed)
}

/// O laço ocioso deixou de girar.
pub fn not_spinning() {
    SPIN_SINCE.store(0, Ordering::Relaxed);
}

const VALUES: usize = 13;

/// O uptime da próxima linha e os totais da anterior.
struct Last {
    due_ms: u64,
    values: [u64; VALUES],
}

static LAST: crate::rtl::SpinLock<Last> = crate::rtl::SpinLock::new(Last { due_ms: REPORT_INTERVAL_MS, values: [0; VALUES] });

fn milliseconds(tsc: u64) -> u64 {
    tsc / (clock::tsc_frequency_hz() / 1000).max(1)
}

/// Escreve a linha `[perf]` quando o intervalo venceu (chamado pelo tique).
pub fn report_if_due() {
    let now = clock::uptime_ms();
    let values = {
        let mut last = LAST.lock();
        if now < last.due_ms {
            return;
        }
        last.due_ms = now + REPORT_INTERVAL_MS;
        let (halt, halts) = IDLE_HALT.take();
        let (spin, spins) = IDLE_SPIN.take();
        let (refresh, refreshes) = REFRESH.take();
        let (dispatch, dispatches) = DISPATCH.take();
        let (slice, slices) = SLICE.take();
        let current = [halt, halts, spin, spins, refresh, refreshes, dispatch, dispatches, slice, slices, POLLS.load(Ordering::Relaxed), SWITCHES.load(Ordering::Relaxed), CR3_LOADS.load(Ordering::Relaxed)];
        let mut delta = [0u64; VALUES];
        for (index, value) in current.iter().enumerate() {
            delta[index] = value.wrapping_sub(last.values[index]);
        }
        last.values = current;
        delta
    };
    // O despacho sem os intervalos: as sondagens dele, os pumps, os fins de
    // processo e a escolha.
    crate::debug_print!(
        "[perf] t={} ms: hlt {} ms ({}x), giro {} ms ({}x), sondagem {} ms ({}x, {} esperas, {} de {} cargas de CR3), despacho fora dos intervalos {} ms ({}x), intervalos {} ms ({}x)",
        now,
        milliseconds(values[0]),
        values[1],
        milliseconds(values[2]),
        values[3],
        milliseconds(values[4]),
        values[5],
        values[10],
        values[11],
        values[12],
        milliseconds(values[6].saturating_sub(values[8])),
        values[7],
        milliseconds(values[8]),
        values[9]
    );
}
