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
/// Dentro do despacho: os pumps do kernel e dos objetos de usuário (ISRs
/// adiadas, timers, DPCs, conclusões, ALPC, E/S de dispositivo, fábricas de
/// workers, pacotes de espera).
pub static PUMPS: Section = Section::new();
/// Dentro do despacho: as threads terminadas retomadas e os fins de processo
/// adiados.
pub static EXITS: Section = Section::new();
/// Os passos das threads de kernel (`scheduler::run_step`), fora do despacho
/// de usuário.
pub static KERNEL_STEPS: Section = Section::new();
/// As sondagens das esperas de usuário que o despacho dispensou: nada que
/// conclua uma espera andou desde a anterior (a época de despertar e o
/// tique do relógio).
pub static POLLS_SKIPPED: AtomicU64 = AtomicU64::new(0);
/// Os intervalos de usuário dados pelos APs (`threads::dispatch_on_processor`),
/// somados de todos eles.
pub static PROCESSOR_SLICES: Section = Section::new();
/// O HLT do laço ocioso dos APs, somado de todos eles.
pub static PROCESSOR_HALT: Section = Section::new();
/// As threads que a sondagem do BSP deixou para depois porque outra CPU era
/// dona delas (`thread_dispatch::try_borrow`).
pub static BORROWS_REFUSED: AtomicU64 = AtomicU64::new(0);
/// Os IPIs de reescalonamento enviados.
pub static RESCHEDULE_IPIS: AtomicU64 = AtomicU64::new(0);
/// Os shootdowns de TLB de um espaço de usuário pedidos por uma mudança de
/// PTE, com o tempo de espera das confirmações.
pub static SHOOTDOWNS: Section = Section::new();
/// Os da metade de sistema.
pub static KERNEL_SHOOTDOWNS: Section = Section::new();
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

/// Quantos intervalos de usuário rodaram.
pub fn slices() -> u64 {
    SLICE.count.load(Ordering::Relaxed)
}

/// Quantas vezes o laço ocioso dormiu no HLT.
pub fn halts() -> u64 {
    IDLE_HALT.count.load(Ordering::Relaxed)
}

/// O laço ocioso deixou de girar.
pub fn not_spinning() {
    SPIN_SINCE.store(0, Ordering::Relaxed);
}

/// Os serviços que voltaram direto ao anel 3, no mesmo intervalo.
pub static FAST_RETURNS: AtomicU64 = AtomicU64::new(0);

/// Os motivos de uma saída de serviço pelo despachante
/// (`threads::may_return_to_user`), na ordem da linha `[perf]`.
pub mod slow {
    pub const NOT_DISPATCHED: usize = 0;
    pub const CALLBACK: usize = 1;
    pub const STATE: usize = 2;
    pub const THREAD: usize = 3;
    pub const USER_APC: usize = 4;
    pub const KERNEL_APC: usize = 5;
    pub const YIELD: usize = 6;
    pub const PREEMPT: usize = 7;
    pub const TICK: usize = 8;
    pub const INTERRUPT: usize = 9;
    pub const WAKE: usize = 10;
    pub const DEBUG: usize = 11;
    pub const CONTEXT: usize = 12;
    pub const DISABLED: usize = 13;
    pub const COUNT: usize = 14;
    pub const NAMES: [&str; COUNT] = ["fora do despacho", "callback", "estado", "espera/thread", "APC de usuario", "APC de kernel", "cessao", "preempcao", "tique", "interrupcao", "despertar", "depurador", "CONTEXT", "desligada"];
}

/// As saídas de serviço pelo despachante, por motivo.
static SLOW_EXITS: [AtomicU64; slow::COUNT] = [const { AtomicU64::new(0) }; slow::COUNT];

/// Uma saída de serviço pelo despachante, pelo motivo `reason`.
pub fn note_slow(reason: usize) {
    if let Some(counter) = SLOW_EXITS.get(reason) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// O que andou desde a linha anterior nos retornos diretos e nas saídas
/// lentas.
static LAST_EXITS: crate::rtl::SpinLock<[u64; slow::COUNT + 1]> = crate::rtl::SpinLock::new([0; slow::COUNT + 1]);

fn report_exits() {
    let mut last = LAST_EXITS.lock();
    let fast = FAST_RETURNS.load(Ordering::Relaxed);
    let mut line = alloc::format!("[perf] servicos: {} retornos diretos; saidas lentas:", fast.wrapping_sub(last[slow::COUNT]));
    last[slow::COUNT] = fast;
    for (index, counter) in SLOW_EXITS.iter().enumerate() {
        let value = counter.load(Ordering::Relaxed);
        let delta = value.wrapping_sub(last[index]);
        last[index] = value;
        if delta != 0 {
            line.push_str(&alloc::format!(" {} {},", slow::NAMES[index], delta));
        }
    }
    drop(last);
    crate::debug_print!("{}", line.trim_end_matches(','));
}

const VALUES: usize = 23;

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
        let (pumps, _) = PUMPS.take();
        let (exits, _) = EXITS.take();
        let (steps, step_count) = KERNEL_STEPS.take();
        let current = [
            halt,
            halts,
            spin,
            spins,
            refresh,
            refreshes,
            dispatch,
            dispatches,
            slice,
            slices,
            POLLS.load(Ordering::Relaxed),
            SWITCHES.load(Ordering::Relaxed),
            CR3_LOADS.load(Ordering::Relaxed),
            pumps,
            exits,
            steps,
            step_count,
            POLLS_SKIPPED.load(Ordering::Relaxed),
            crate::hal::serial::cost().0,
            crate::hal::serial::cost().1,
            crate::drivers::storage::ata_pio::dma_cost().0,
            crate::drivers::storage::ata_pio::dma_cost().1,
            crate::drivers::storage::ata_pio::dma_cost().2,
        ];
        let mut delta = [0u64; VALUES];
        for (index, value) in current.iter().enumerate() {
            delta[index] = value.wrapping_sub(last.values[index]);
        }
        last.values = current;
        delta
    };
    // O despacho sem os intervalos: as sondagens dele, os pumps, os fins de
    // processo e a escolha; os passos de kernel ficam fora do despacho.
    crate::debug_print!(
        "[perf] t={} ms: hlt {} ms ({}x), giro {} ms ({}x), sondagem {} ms ({}x, {} dispensadas, {} esperas, {} de {} cargas de CR3), despacho fora dos intervalos {} ms ({}x; pumps {} ms, fins {} ms), intervalos {} ms ({}x), passos de kernel {} ms ({}x), serial {} ms ({} bytes), DMA {} ms ({}x, {} setores)",
        now,
        milliseconds(values[0]),
        values[1],
        milliseconds(values[2]),
        values[3],
        milliseconds(values[4]),
        values[5],
        values[17],
        values[10],
        values[11],
        values[12],
        milliseconds(values[6].saturating_sub(values[8])),
        values[7],
        milliseconds(values[13]),
        milliseconds(values[14]),
        milliseconds(values[8]),
        values[9],
        milliseconds(values[15]),
        values[16],
        milliseconds(values[18]),
        values[19],
        milliseconds(values[20]),
        values[21],
        values[22]
    );
    report_processors(now, milliseconds(values[0]) + milliseconds(values[2]), milliseconds(values[8]));
    report_exits();
    report_threads();
    crate::ntos::kd::sampler::report_images();
    crate::ntos::kd::sampler::report();
}

/// O que andou nos APs desde a linha anterior.
static LAST_PROCESSORS: crate::rtl::SpinLock<[u64; 8]> = crate::rtl::SpinLock::new([0; 8]);

/// As linhas seguidas em que o sistema ficou parado (o BSP ocioso, no HLT ou
/// girando, e nenhum intervalo de usuário), e se a lista das threads já saiu
/// nesta parada.
static QUIET: crate::rtl::SpinLock<(u32, bool)> = crate::rtl::SpinLock::new((0, false));

/// As linhas paradas seguidas antes da lista das threads (15 s).
const QUIET_REPORTS: u32 = 3;

/// A linha dos APs (`[perf] t=N ms aps: ...`), com o despacho em várias CPUs.
/// Parado por [`QUIET_REPORTS`] linhas seguidas, lista uma vez as threads de
/// usuário (`threads::report_stalled_threads`): uma espera ou uma retomada
/// perdida entre CPUs aparece ali.
fn report_processors(now: u64, bootstrap_idle_ms: u64, bootstrap_slice_ms: u64) {
    if !crate::ntos::ke::thread_dispatch::concurrent() {
        return;
    }
    let (slice, slices) = PROCESSOR_SLICES.take();
    let (halt, halts) = PROCESSOR_HALT.take();
    let (shootdown, shootdowns) = SHOOTDOWNS.take();
    let (kernel_shootdown, kernel_shootdowns) = KERNEL_SHOOTDOWNS.take();
    let current = [slice, slices, halt, halts, BORROWS_REFUSED.load(Ordering::Relaxed), RESCHEDULE_IPIS.load(Ordering::Relaxed), shootdowns, kernel_shootdowns];
    let delta = {
        let mut last = LAST_PROCESSORS.lock();
        let mut delta = [0u64; 8];
        for (index, value) in current.iter().enumerate() {
            delta[index] = value.wrapping_sub(last[index]);
        }
        *last = current;
        delta
    };
    static LAST_SHOOTDOWN_TSC: AtomicU64 = AtomicU64::new(0);
    static LAST_KERNEL_SHOOTDOWN_TSC: AtomicU64 = AtomicU64::new(0);
    let shootdown_delta = shootdown.wrapping_sub(LAST_SHOOTDOWN_TSC.swap(shootdown, Ordering::Relaxed));
    let kernel_shootdown_delta = kernel_shootdown.wrapping_sub(LAST_KERNEL_SHOOTDOWN_TSC.swap(kernel_shootdown, Ordering::Relaxed));
    let quiet = bootstrap_idle_ms * 10 >= REPORT_INTERVAL_MS * 9 && bootstrap_slice_ms < 50 && milliseconds(delta[0]) < 50;
    let report = {
        let mut state = QUIET.lock();
        if quiet {
            state.0 += 1;
        } else {
            *state = (0, false);
        }
        let due = state.0 >= QUIET_REPORTS && !state.1;
        state.1 |= due;
        due
    };
    if report {
        crate::ntos::ps::user::threads::report_stalled_threads();
    }
    crate::debug_print!(
        "[perf] t={} ms aps: intervalos {} ms ({}x), hlt {} ms ({}x), emprestimos recusados {}, IPIs de reescalonamento {}, shootdowns de usuario {} ({} us), de sistema {} ({} us)",
        now,
        milliseconds(delta[0]),
        delta[1],
        milliseconds(delta[2]),
        delta[3],
        delta[4],
        delta[5],
        delta[6],
        milliseconds(shootdown_delta.saturating_mul(1000)),
        delta[7],
        milliseconds(kernel_shootdown_delta.saturating_mul(1000))
    );
}

/// Os intervalos de uma thread de usuário no intervalo da linha `[perf]`.
struct ThreadSlices {
    /// O ImageFileName do processo, lido no primeiro intervalo.
    name: [u8; 15],
    process_id: u64,
    slices: u64,
    tsc: u64,
    /// Os serviços que voltaram ao anel 3 sem fim de intervalo.
    returns: u64,
}

static THREADS: crate::rtl::SpinLock<alloc::collections::BTreeMap<u64, ThreadSlices>> = crate::rtl::SpinLock::new(alloc::collections::BTreeMap::new());

/// O começo de um intervalo da thread `thread_id` do processo `process`
/// (vivo aqui): a entrada dela, com o nome e o PID.
pub fn slice_begin(thread_id: u64, process: u64) {
    let mut threads = THREADS.lock();
    if threads.contains_key(&thread_id) {
        return;
    }
    let mut name = [0u8; 15];
    name.copy_from_slice(&crate::ntos::mm::guest_memory::read_bytes(crate::ntos::ps::process_accessors::image_file_name(process), 15));
    threads.insert(thread_id, ThreadSlices { name, process_id: crate::ntos::ps::process_accessors::id(process), slices: 0, tsc: 0, returns: 0 });
}

/// Um intervalo mais longo que isto (ms) vai para a serial na hora: o
/// código de kernel não é preemptado, então nenhuma outra thread roda
/// enquanto o serviço não volta ao despachante, e um trecho acima do
/// timeout de controle do services.exe (30 s) derruba a partida do serviço
/// que esperava.
const LONG_SLICE_MS: u64 = 2_000;

/// O fim do intervalo da thread `thread_id`, que começou no TSC `started`.
pub fn slice_end(thread_id: u64, started: u64) {
    let tsc = cpu::rdtsc().wrapping_sub(started);
    let long = {
        let mut threads = THREADS.lock();
        let Some(entry) = threads.get_mut(&thread_id) else { return };
        entry.slices += 1;
        entry.tsc += tsc;
        (milliseconds(tsc) >= LONG_SLICE_MS).then_some((entry.process_id, entry.name))
    };
    if let Some((process_id, name)) = long {
        let name: alloc::string::String = name.iter().take_while(|&&byte| byte != 0).map(|&byte| byte as char).collect();
        crate::debug_print!("[sched] intervalo longo: thread {}:{} ({}) {} ms sem voltar ao despachante", process_id, thread_id, name, milliseconds(tsc));
    }
}

/// Um serviço da thread `thread_id` voltou direto ao anel 3, no mesmo
/// intervalo.
pub fn thread_return(thread_id: u64) {
    if let Some(entry) = THREADS.lock().get_mut(&thread_id) {
        entry.returns += 1;
    }
}

/// As cinco threads de usuário com mais tempo de intervalo desde a linha
/// anterior (`[perf] threads:`), com o nome da imagem do processo, os
/// intervalos e os serviços que voltaram sem fim de intervalo.
fn report_threads() {
    let mut taken: alloc::vec::Vec<(u64, ThreadSlices)> = core::mem::take(&mut *THREADS.lock()).into_iter().collect();
    if taken.is_empty() {
        return;
    }
    taken.sort_by_key(|(_, entry)| core::cmp::Reverse(entry.tsc));
    let mut line = alloc::string::String::from("[perf] threads:");
    for (thread_id, entry) in taken.iter().take(5) {
        let name: alloc::string::String = entry.name.iter().take_while(|&&byte| byte != 0).map(|&byte| byte as char).collect();
        line.push_str(&alloc::format!(" {} {}:{} {} ms ({}x, {} sem fim);", name, entry.process_id, thread_id, milliseconds(entry.tsc), entry.slices, entry.returns));
    }
    crate::debug_print!("{}", line);
}
