//! Estado de despacho.
//!
//! Filas nativas de 32 prioridades na KPRCB do processador que despacha, a
//! contagem de ciclos próprios e a entrega de contextos. No M0 um processador
//! só despacha threads (o de boot): as filas prontas, a NextThread e o
//! PrcbLock que as protege são os da KPRCB dele, de onde quer que venha a
//! prontidão (o sinal de outra CPU entra na mesma fila). A execução em curso
//! — o contexto ativo, a pilha de execuções aninhadas e o início da contagem
//! de ciclos — é de cada CPU, como a KPRCB.CurrentThread: o que roda numa CPU
//! não muda o que outra vê. As filas não possuem a ETHREAD: o runtime dono a
//! retém (aqui identificado por um número opaco, como o pid do escalonador).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::{clock, pcr};
use crate::hal::cpu;
use crate::ntos::inc::types::{Ethread, Field, Kprcb, Kthread, ListEntry, NtStruct};
use crate::ntos::mm::memory_map as map;
use crate::rtl::{KernelError, SpinLock};

pub mod state {
    pub const INITIALIZED: u8 = 0;
    pub const READY: u8 = 1;
    pub const RUNNING: u8 = 2;
    pub const STANDBY: u8 = 3;
    pub const TERMINATED: u8 = 4;
    pub const WAITING: u8 = 5;
    pub const DEFERRED_READY: u8 = 7;
}

/// KTHREAD.WaitListEntry: o vínculo das filas prontas (KiReadyThread).
const WAIT_LIST_ENTRY: u64 = core::mem::offset_of!(Kthread, wait_list_entry) as u64;

/// Runtime das threads de usuário (`domain: 'user'`); os demais são
/// processos do escalonador de kernel.
pub const USER_RUNTIME: u64 = 1 << 63;

/// Dono executável de uma thread.
#[derive(Clone, Copy, Debug)]
pub struct Owner {
    pub runtime: u64,
    pub yield_requested: bool,
    /// O pedido veio do KeYieldExecution (NtYieldExecution, ZwYieldExecution
    /// ou o Sleep(0) de usuário): o fim da execução escolhe a sucessora como
    /// o KiSelectReadyThreadEx(Prcb, NULL, 1).
    pub yield_execution: bool,
    /// Porta de conclusão de I/O associada (worker factories, fase 7).
    pub io_completion_port: Option<u64>,
}

struct Execution {
    pointer: u64,
    started: u64,
}

/// A execução em curso de uma CPU.
struct CpuExecution {
    active: Option<Execution>,
    stack: Vec<Option<Execution>>,
}

struct Dispatch {
    owners: BTreeMap<u64, Owner>,
    cpus: [CpuExecution; map::MAX_CPUS],
    queues_initialized: bool,
    priority_observer: Option<fn()>,
    /// Notificação de atividade da porta de conclusão (porta, runtime, ativo).
    port_activity: Option<fn(u64, u64, bool)>,
}

static STATE: SpinLock<Dispatch> = SpinLock::new(Dispatch {
    owners: BTreeMap::new(),
    cpus: [const { CpuExecution { active: None, stack: Vec::new() } }; map::MAX_CPUS],
    queues_initialized: false,
    priority_observer: None,
    port_activity: None,
});

/// O PrcbLock das filas prontas: toda mudança nas listas, no ReadySummary,
/// nas contagens e na NextThread passa por ele, inclusive a prontidão vinda
/// de outra CPU.
static QUEUES: SpinLock<()> = SpinLock::new(());

/// A NextThread que um KeYieldExecution reservou para uma thread de
/// prioridade menor que a da thread que cedeu (YIELD_TARGET) e a thread que
/// cedeu (YIELDER). No NT a escolhida entra direto pelo KiSwapContext e a
/// que cedeu vai à fila pelo KiQueueReadyThread, sem preempção; aqui a
/// reserva vale enquanto a única concorrente mais prioritária na fila é a
/// thread que cedeu. Mudam só sob o PrcbLock (`QUEUES`).
static YIELD_TARGET: AtomicU64 = AtomicU64::new(0);
static YIELDER: AtomicU64 = AtomicU64::new(0);

/// A reserva do KeYieldExecution acaba quando `thread` (a escolhida) sai da
/// NextThread. Sob o PrcbLock.
fn end_yield_reservation_locked(thread: u64) {
    if YIELD_TARGET.load(Ordering::Relaxed) == thread {
        YIELD_TARGET.store(0, Ordering::Relaxed);
        YIELDER.store(0, Ordering::Relaxed);
    }
}

/// O número da CPU corrente (KPRCB.Number pelo GS; 0 antes da KPCR).
fn cpu_index() -> usize {
    if pcr::get_pcr_address() == 0 {
        return 0;
    }
    (pcr::current().prcb.number.get() as usize).min(map::MAX_CPUS - 1)
}

/// A KPRCB do processador que despacha as threads (o de boot no M0): dona
/// das filas prontas e da NextThread.
pub fn processor_address() -> u64 {
    let address = pcr::get_pcr_address();
    assert!(address != 0, "thread dispatch requires initialized PCR");
    address + core::mem::offset_of!(crate::ntos::inc::types::Kpcr, prcb) as u64
}

/// A KPRCB das filas prontas.
fn processor() -> &'static Kprcb {
    // SAFETY: a KPCR do processador de boot está mapeada desde `pcr::init`.
    unsafe { Kprcb::at(processor_address()) }
}

/// A KPRCB da CPU corrente (pelo GS).
fn current_processor() -> &'static Kprcb {
    &pcr::current().prcb
}

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: as filas só recebem KTHREADs vivas.
    unsafe { Kthread::at(thread) }
}

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: toda KTHREAD do escalonador é o Tcb de uma ETHREAD.
    unsafe { Ethread::at(thread) }
}

fn list_entry(address: u64) -> &'static ListEntry {
    // SAFETY: vínculos de uma fila pronta conferida.
    unsafe { ListEntry::at(address) }
}

pub fn priority(thread: u64) -> u8 {
    kthread(thread).priority.get() as u8
}

pub fn thread_state(thread: u64) -> u8 {
    kthread(thread).state.get()
}

/// Mesma unidade de ms de KUSER_SHARED_DATA.TickCount e KeQueryTickCount.
pub fn tick_count() -> u32 {
    clock::uptime_ms() as u32
}

/// Três unidades de quantum por tick, pela frequência TSC calibrada.
pub fn cycles_per_quantum() -> u32 {
    let frequency = clock::tsc_frequency_hz();
    assert!(frequency > 0, "uncalibrated scheduler clock");
    (frequency / 300).max(1) as u32
}

pub fn initialize_queues() {
    if STATE.lock().queues_initialized {
        return;
    }
    {
        let _queues = QUEUES.lock();
        let processor = processor();
        for head in &processor.dispatcher_ready_list_head {
            head.flink.set(head.address());
            head.blink.set(head.address());
        }
        processor.ready_summary.set(0);
        processor.ready_thread_count.set(0);
        processor.ready_queue_expected_run_time.set(0);
    }
    STATE.lock().queues_initialized = true;
}

/// Confere os dois vínculos antes de remover; corrupção nunca vira sucesso.
fn remove_ready_locked(thread: u64) -> Result<(), KernelError> {
    let processor = processor();
    let entry = &kthread(thread).wait_list_entry;
    let next = entry.flink.get();
    let previous = entry.blink.get();
    if next == 0 || previous == 0 || list_entry(next).blink.get() != entry.address() || list_entry(previous).flink.get() != entry.address() {
        return Err(KernelError::new("corrupt native ready queue"));
    }
    list_entry(previous).flink.set(next);
    list_entry(next).blink.set(previous);
    if next == previous {
        processor.ready_summary.set(processor.ready_summary.get() & !(1u32 << priority(thread)));
    }
    let count = processor.ready_thread_count.get();
    if count == 0 {
        return Err(KernelError::new("native ready count underflow"));
    }
    processor.ready_thread_count.set(count - 1);
    let expected = &processor.ready_queue_expected_run_time;
    expected.set(expected.get().wrapping_sub(ethread(thread).last_expected_run_time.get() as u64));
    Ok(())
}

/// Tira a thread da fila pronta (sob o PrcbLock).
pub fn remove_ready(thread: u64) -> Result<(), KernelError> {
    let _queues = QUEUES.lock();
    remove_ready_locked(thread)
}

/// A varredura anti-inanição do KiQuantumEnd 19041 (0x257550): o instante da
/// próxima (PRCB+0x313c, TickCount + 0x4b em 0x257add) e o nível em que ela
/// recomeça (PRCB+0x7c20, 0x257b04/0x257bda). Em ms do tick_count (o tick do
/// 19041 é 15,625 ms: 75 ticks = 1172 ms, 300 ticks = 4688 ms).
static STARVATION_NEXT_SCAN: AtomicU32 = AtomicU32::new(0);
static STARVATION_LEVEL: AtomicU32 = AtomicU32::new(1);
const STARVATION_SCAN_PERIOD_MS: u32 = 1172;
/// TickCount - 0x12c (0x257b16).
pub(crate) const STARVATION_READY_MS: u32 = 4688;
/// Threads olhadas por varredura (r12d, 0x2575bf).
const STARVATION_SCAN_LIMIT: u32 = 16;
/// Threads impulsionadas por varredura (esi, 0x25760b).
const STARVATION_BOOST_LIMIT: usize = 10;
/// Prioridades 1 a 14 (0x257ae7).
const STARVATION_LEVELS: u32 = 0x7FFE;
/// A prioridade do impulso (0x257f2e).
const STARVATION_PRIORITY: u8 = 15;

/// KiQuantumEnd 0x2575c3..0x257f75, sob o PrcbLock (QUEUES): a pronta há mais
/// de 300 ticks com prioridade menor que 15 sai da fila e volta com 15
/// (KiSetPriorityBoost 0x315db0: PriorityDecrement += (15 - Priority) << 4,
/// desfeito pelo compute_quantum_end_priority do próximo fim de quantum dela).
/// Devolve (thread, prioridade anterior, ms na fila) para o log fora da trava.
fn boost_starved_threads_locked() -> Vec<(u64, u8, u32)> {
    let now = tick_count();
    if (STARVATION_NEXT_SCAN.load(Ordering::Relaxed).wrapping_sub(now) as i32) >= 0 {
        return Vec::new();
    }
    STARVATION_NEXT_SCAN.store(now.wrapping_add(STARVATION_SCAN_PERIOD_MS), Ordering::Relaxed);
    let processor = processor();
    let summary = processor.ready_summary.get() & STARVATION_LEVELS;
    if summary == 0 {
        return Vec::new();
    }
    let threshold = now.wrapping_sub(STARVATION_READY_MS);
    let start = STARVATION_LEVEL.load(Ordering::Relaxed) & 31;
    let mut levels = summary.rotate_right(start);
    let (mut scanned, mut starved, mut level) = (0u32, Vec::new(), start);
    let mut cut = false;
    'levels: while levels != 0 {
        level = (levels.trailing_zeros() + start) & 31;
        levels &= levels - 1;
        let head = &processor.dispatcher_ready_list_head[level as usize];
        let mut link = head.flink.get();
        while link != head.address() && link != 0 {
            let thread = link - WAIT_LIST_ENTRY;
            link = list_entry(link).flink.get();
            scanned += 1;
            if (threshold.wrapping_sub(kthread(thread).wait_time.get()) as i32) > 0 {
                starved.push(thread);
            }
            if scanned >= STARVATION_SCAN_LIMIT || starved.len() >= STARVATION_BOOST_LIMIT {
                cut = true;
                break 'levels;
            }
        }
    }
    // Cortada por um limite, a próxima varredura recomeça no nível seguinte
    // (0x257d1a); senão, no 1.
    STARVATION_LEVEL.store(if cut && level < 14 { level + 1 } else { 1 }, Ordering::Relaxed);
    let mut boosted = Vec::new();
    for thread in starved {
        let kthread = kthread(thread);
        let priority = kthread.priority.get() as u8;
        if priority >= STARVATION_PRIORITY || remove_ready_locked(thread).is_err() {
            continue;
        }
        let waited = now.wrapping_sub(kthread.wait_time.get());
        // Aritmética de byte, como o `sub r10b; shl r10b,4; add [+0x234]`.
        let delta = STARVATION_PRIORITY.wrapping_sub(priority).wrapping_shl(4);
        kthread.priority_decrement.set((kthread.priority_decrement.get() as u8).wrapping_add(delta) as i8);
        kthread.priority.set(STARVATION_PRIORITY as i8);
        // KiSetPriorityBoost -> KiSetLockOwnershipQuantum (0x315df0): o
        // impulso leva ao menos um tique de quantum.
        ensure_minimum_quantum(thread);
        enqueue_ready_locked(thread, false, false);
        boosted.push((thread, priority, waited));
    }
    boosted
}

/// Vence a próxima varredura anti-inanição (autoteste).
pub fn force_starvation_scan() {
    STARVATION_NEXT_SCAN.store(tick_count().wrapping_sub(1), Ordering::Relaxed);
}

fn enqueue_ready_locked(thread: u64, at_front: bool, preserve_wait_time: bool) {
    let processor = processor();
    let kthread = kthread(thread);
    let head = &processor.dispatcher_ready_list_head[priority(thread) as usize];
    let entry = &kthread.wait_list_entry;
    let next = if at_front { head.flink.get() } else { head.address() };
    let previous = if at_front { head.address() } else { head.blink.get() };
    entry.flink.set(next);
    entry.blink.set(previous);
    list_entry(previous).flink.set(entry.address());
    list_entry(next).blink.set(entry.address());
    processor.ready_summary.set(processor.ready_summary.get() | (1u32 << priority(thread)));
    processor.ready_thread_count.set(processor.ready_thread_count.get() + 1);
    let expected = &processor.ready_queue_expected_run_time;
    expected.set(expected.get().wrapping_add(ethread(thread).last_expected_run_time.get() as u64));
    kthread.state.set(state::READY);
    if !preserve_wait_time {
        kthread.wait_time.set(tick_count());
    }
}

pub fn enqueue_ready(thread: u64, at_front: bool, preserve_wait_time: bool) {
    initialize_queues();
    let _queues = QUEUES.lock();
    enqueue_ready_locked(thread, at_front, preserve_wait_time);
}

fn highest_ready_locked() -> Result<u64, KernelError> {
    let processor = processor();
    let summary = processor.ready_summary.get();
    if summary == 0 {
        return Ok(0);
    }
    let highest = 31 - summary.leading_zeros() as usize;
    let head = &processor.dispatcher_ready_list_head[highest];
    let entry = head.flink.get();
    if entry == head.address() || entry == 0 {
        return Err(KernelError::new("ready summary disagrees with native list"));
    }
    Ok(entry - WAIT_LIST_ENTRY)
}

pub fn highest_ready() -> Result<u64, KernelError> {
    let _queues = QUEUES.lock();
    highest_ready_locked()
}

pub fn take_ready_above(minimum_priority: i32) -> Result<u64, KernelError> {
    let _queues = QUEUES.lock();
    let thread = highest_ready_locked()?;
    if thread == 0 || priority(thread) as i32 <= minimum_priority {
        return Ok(0);
    }
    remove_ready_locked(thread)?;
    Ok(thread)
}

pub fn next_thread() -> u64 {
    processor().next_thread.get()
}

/// O KiSystemServiceExit não testa preempção: no 19041 a pronta acima da
/// corrente já tomou a CPU dentro do serviço (KiExitDispatcher 0x2c4150:
/// NextThread -> KiSwapThread, ou o pedido de DISPATCH_LEVEL). Aqui, na
/// saída do serviço: uma NextThread reservada para outra, ou uma pronta
/// estritamente acima da corrente (o KiReadyThread só preempta prioridade
/// menor).
pub fn preemption_pending(thread: u64) -> bool {
    if pcr::get_pcr_address() == 0 {
        return false;
    }
    let _queues = QUEUES.lock();
    let processor = processor();
    let next = processor.next_thread.get();
    if next != 0 && next != thread {
        return true;
    }
    let summary = processor.ready_summary.get();
    summary != 0 && 31 - summary.leading_zeros() > priority(thread) as u32
}

/// Um KeYieldExecution pedido no serviço (NtYieldExecution, o atraso zero):
/// a troca é do `end_execution`.
pub fn yield_pending(thread: u64) -> bool {
    STATE.lock().owners.get(&thread).is_some_and(|owner| owner.yield_requested || owner.yield_execution)
}

/// Há thread pronta ou reservada (ReadySummary ou NextThread).
pub fn has_ready_threads() -> bool {
    pcr::get_pcr_address() != 0 && (processor().ready_summary.get() != 0 || processor().next_thread.get() != 0)
}

fn reserve_next_locked(thread: u64) {
    let kthread = kthread(thread);
    if kthread.state.get() == state::READY {
        let waited = tick_count().wrapping_sub(kthread.wait_time.get());
        kthread.ready_time.set(kthread.ready_time.get().wrapping_add(waited));
    }
    kthread.state.set(state::STANDBY);
    processor().next_thread.set(thread);
    // Outra reserva encerra a de um KeYieldExecution.
    if YIELD_TARGET.load(Ordering::Relaxed) != thread {
        YIELD_TARGET.store(0, Ordering::Relaxed);
        YIELDER.store(0, Ordering::Relaxed);
    }
}

pub fn reserve_next(thread: u64) {
    let _queues = QUEUES.lock();
    reserve_next_locked(thread);
}

pub fn defer_ready(thread: u64, deferred: &mut Vec<u64>) {
    let kthread = kthread(thread);
    if kthread.state.get() == state::READY {
        // MiscFlags.ReadyTransition: CAS atômico (outros bits do mesmo
        // DWORD mudam por outros caminhos).
        kthread.set_ready_transition(1);
    }
    kthread.state.set(state::DEFERRED_READY);
    let previous = deferred.last().map_or(0, |&last| last + WAIT_LIST_ENTRY);
    kthread.wait_list_entry.flink.set(previous);
    deferred.push(thread);
}

pub fn ensure_minimum_quantum(thread: u64) {
    let kthread = kthread(thread);
    let cycles = kthread.cycle_time.get();
    let target = kthread.quantum_target.get();
    // KiLockQuantumTarget: três unidades de quantum, um tique (KeInitSystem
    // 0xa4c603).
    let minimum = 3 * cycles_per_quantum() as u64;
    if cycles > target || target - cycles < minimum {
        kthread.quantum_target.set(cycles.wrapping_add(minimum));
    }
}

/// O dono do contexto decide o momento seguro da entrega.
pub fn complete_priority_change(deferred: &[u64]) {
    for &thread in deferred.iter().rev() {
        let kthread = kthread(thread);
        enqueue_ready(thread, false, kthread.ready_transition() != 0);
        kthread.set_ready_transition(0);
    }
    let observer = STATE.lock().priority_observer;
    if let Some(observer) = observer {
        observer();
    }
}

/// Soma só os intervalos em que o contexto esteve ativo nesta CPU.
fn account_active_cycles(execution: &mut CpuExecution) {
    let Some(active) = execution.active.as_mut() else { return };
    let now = cpu::rdtsc();
    let elapsed = now.wrapping_sub(active.started);
    let cycles = &kthread(active.pointer).cycle_time;
    cycles.set(cycles.get().wrapping_add(elapsed));
    active.started = now;
}

pub fn sample_cycles(thread: u64) -> u64 {
    let cpu = cpu_index();
    let mut dispatch = STATE.lock();
    let nesting = current_processor().nesting_level.get();
    let execution = &mut dispatch.cpus[cpu];
    if execution.active.as_ref().is_some_and(|active| active.pointer == thread) && nesting == 0 {
        account_active_cycles(execution);
    }
    kthread(thread).cycle_time.get()
}

/// KeUpdateThreadTag(Thread, Tag) (ntoskrnl 19041 rva 0x36b8a0): em
/// DISPATCH_LEVEL, com a ThreadLock, troca KTHREAD.Tag quando muda e liga ou
/// desliga o Header.Tagged (bit 20 da palavra do cabeçalho, LOCK BTS/BTR).
/// Na thread corrente a troca fecha a contagem de ciclos do tag antigo
/// (KiEndThreadCycleAccumulation) e abre a do novo; numa thread em execução
/// em outra CPU o NT manda a troca por IPI (KiIpiUpdateThreadTag) para que a
/// contagem feche lá. O OpenNT soma os ciclos só por thread
/// (`sample_cycles`), sem divisão por tag: o fechamento é a amostra da
/// thread corrente e, nas outras, a troca direta sob a trava.
pub fn update_thread_tag(thread: u64, tag: u8) {
    const TAGGED: i32 = (crate::ntos::inc::types::DispatcherHeader::TAGGED_MASK as i32) << 16;
    // A amostra vem antes da ThreadLock: o `sample_cycles` toma a trava do
    // despacho, que nunca é pedida com a ThreadLock na mão.
    if thread == pcr::current_thread() && kthread(thread).tag.get() != tag {
        sample_cycles(thread);
    }
    super::thread_lock::with_lock(thread, || {
        let target = kthread(thread);
        if target.tag.get() == tag {
            return;
        }
        let header = target.header.lock.atomic();
        if tag != 0 {
            header.fetch_or(TAGGED, core::sync::atomic::Ordering::SeqCst);
        } else {
            header.fetch_and(!TAGGED, core::sync::atomic::Ordering::SeqCst);
        }
        target.tag.set(tag);
    });
}

/// KeQueryRuntimeThread: tempo de kernel devolvido e de usuário gravado na
/// saída opcional, em ticks do relógio (KeQueryTimeIncrement).
pub fn query_runtime_thread(thread: u64, user_time: u64) -> u64 {
    let (kernel, user) = crate::ntos::ps::process::thread_record(thread).map_or((0, 0), |record| (record.kernel_time, record.user_time));
    if user_time != 0 {
        // SAFETY: PULONG UserTime opcional do chamador.
        unsafe { Field::<u32>::at(user_time) }.set((user / clock::MAXIMUM_INCREMENT as u64) as u32);
    }
    kernel / clock::MAXIMUM_INCREMENT as u64 & 0xFFFF_FFFF
}

/// A thread de boot do System não é o processo Idle.
pub fn is_idle_thread(thread: u64) -> bool {
    let idle = current_processor().idle_thread.get();
    idle != 0 && kthread(idle).process.get() == kthread(thread).process.get()
}

pub fn register(thread: u64, runtime: u64) -> Result<(), KernelError> {
    {
        let mut dispatch = STATE.lock();
        if dispatch.owners.contains_key(&thread) {
            return Err(KernelError::new("thread already has scheduler owner"));
        }
        dispatch.owners.insert(thread, Owner { runtime, yield_requested: false, yield_execution: false, io_completion_port: None });
    }
    make_ready(thread)
}

/// KiReadyThread: põe na fila pronta uma thread que espera (ou recém-criada).
/// Uma thread já pronta ou reservada fica onde está; uma em execução também
/// (ela volta à fila, se for o caso, no fim da execução: nunca há duas
/// entradas da mesma thread na fila).
pub fn make_ready(thread: u64) -> Result<(), KernelError> {
    initialize_queues();
    let _queues = QUEUES.lock();
    let current = thread_state(thread);
    if current == state::READY || current == state::STANDBY || current == state::RUNNING {
        return Ok(());
    }
    if current == state::TERMINATED {
        return Err(KernelError::new("cannot ready a terminated thread"));
    }
    enqueue_ready_locked(thread, false, false);
    Ok(())
}

/// KTHREAD.AdjustReason (KADJUST_REASON): AdjustUnwait, o que o
/// KiExitDispatcher grava nas threads que o sinal tirou da espera.
pub const ADJUST_UNWAIT: u8 = 1;

/// O incremento do KeAlertThread (19041 0x35beb1: r13d = 2, o Increment do
/// KiExitDispatcher em 0x35bf26).
pub const ALERT_INCREMENT: i8 = 2;

/// Dois ticks do relógio do 19041 (KeMaximumIncrement, 15,625 ms) no tick em
/// ms do OpenNT, arredondado para cima como o [`STARVATION_READY_MS`]: a
/// espera mais curta que isso ainda ganha o impulso por cima da prioridade
/// corrente (0x2c4657 `cmp eax, 2`).
const UNWAIT_LONG_WAIT_MS: u32 = ((2 * super::clock::MAXIMUM_INCREMENT as u64).div_ceil(10_000)) as u32;

/// O KiReadyThread de uma thread que um sinal tirou da espera: o
/// KiExitDispatcher (0x2c4150) drena a DeferredReadyListHead gravando
/// AdjustReason = AdjustUnwait e AdjustIncrement = o Increment do sinal
/// (0x2c4231/0x2c4238), e o KiDeferredReadySingleThread aplica o ajuste sob a
/// ThreadLock antes da fila ([`adjust_unwait_locked`]). Só a thread que estava
/// Waiting é ajustada (o KiTryUnwaitThread só põe na lista uma thread
/// Waiting, 0x2c2f14); uma já pronta, reservada ou em execução fica onde
/// está, como no [`make_ready`].
pub fn ready_after_wait(thread: u64, increment: i8) -> Result<(), KernelError> {
    initialize_queues();
    super::thread_lock::with_lock_raised(thread, || {
        let _queues = QUEUES.lock();
        let current = thread_state(thread);
        if current == state::READY || current == state::STANDBY || current == state::RUNNING {
            return Ok(());
        }
        if current == state::TERMINATED {
            return Err(KernelError::new("cannot ready a terminated thread"));
        }
        if current == state::WAITING {
            adjust_unwait_locked(thread, increment);
        }
        enqueue_ready_locked(thread, false, false);
        Ok(())
    })
}

/// O ramo AdjustUnwait do KiDeferredReadySingleThread do 19041
/// (0x2c45f8..0x2c4721, 0x2c4b02..0x2c4bd3, 0x2c4e28..0x2c4ef1,
/// 0x2c50ff..0x2c5133), sob a ThreadLock e o PrcbLock, antes da fila:
///
/// - prioridade de tempo real (16 ou mais): nada muda;
/// - com o quantum gasto (CycleTime >= QuantumTarget), com a base em 14 ou
///   mais, ou depois de uma espera de dois ticks ou mais sem impulso em curso
///   (PriorityDecrement zero), a prioridade decai como no fim de quantum
///   ([`compute_quantum_end_priority`]: um ponto e os impulsos, sem baixar da
///   base nem do piso) e o quantum renova no fim;
/// - o impulso: sem DisableBoost, sem quantum gasto numa espera curta, com
///   prioridade acima de zero e sem impulso em curso (ou só o de primeiro
///   plano, num processo de primeiro plano), a prioridade vai a
///   Base + Increment, mais o PsPrioritySeparation no processo de primeiro
///   plano (MemoryPriority 2 no working set, 0x2c4667), até 15, quando isso a
///   sobe; a parte do primeiro plano fica no ForegroundBoost
///   (PriorityDecrement bits 0..3), que o fim de quantum desfaz.
///
/// Os impulsos de primeiro plano agendados (KiScheduleNextForegroundBoost) e
/// o autoboost de locks (AbWaitEntryCount) não existem no OpenNT.
fn adjust_unwait_locked(thread: u64, increment: i8) {
    let target = kthread(thread);
    // 0x2c4231..0x2c4238 e o `mov word [+0x235], 0` de 0x2c470c: o
    // AdjustIncrement fica, Preempted e AdjustReason voltam a zero.
    target.adjust_increment.set(increment);
    target.preempted.set(0);
    target.adjust_reason.set(0);
    if target.priority.get() >= 16 {
        return;
    }
    let waited = tick_count().wrapping_sub(target.wait_time.get());
    let long_wait = waited >= UNWAIT_LONG_WAIT_MS;
    // Os bits do `dil` do 19041: 1 quantum gasto numa espera curta, 2
    // processo de primeiro plano, 4 quantum gasto, 8 o quantum renova.
    let mut flags = 0u8;
    let cycles = target.cycle_time.get();
    if cycles >= target.quantum_target.get() {
        flags = if long_wait { 4 } else { 5 };
    }
    if flags >= 4 || target.base_priority.get() >= 14 || (long_wait && target.priority_decrement.get() == 0) {
        flags |= 8;
        target.priority.set(compute_quantum_end_priority(thread) as i8);
    }
    // SAFETY: o processo dono de uma thread viva.
    let process = unsafe { crate::ntos::inc::types::Eprocess::at(target.process.get()) };
    if process.vm.instance.flags.memory_priority.get() == 2 {
        flags |= 2;
    }
    let priority = target.priority.get() as i32;
    let decrement = target.priority_decrement.get() as u8;
    let eligible = decrement == 0 || (decrement & 0xF0 == 0 && flags & 2 != 0);
    if target.disable_boost() == 0 && flags & 1 == 0 && priority > 0 && eligible {
        let unwait = target.base_priority.get() as i32 + increment as i32;
        let mut boosted = unwait;
        if flags & 2 != 0 {
            boosted += crate::ntos::ps::quantum::priority_separation() as i32;
        }
        boosted = boosted.min(15);
        if boosted > priority {
            // 0x2c4ef1..0x2c4f07: o que passou da base + incremento é do
            // primeiro plano (aritmética de byte).
            let foreground = if boosted > unwait { (boosted - unwait) as u8 } else { 0 };
            target.priority_decrement.set(((decrement & 0xF0) | (foreground & 0x0F)) as i8);
            target.priority.set(boosted as i8);
        }
    }
    // 0x2c4b02..0x2c4b1e: CycleTime + QuantumReset * KiCyclesPerClockQuantum,
    // sem a doação de quantum.
    if flags & 8 != 0 {
        let reset = target.quantum_reset.get() as u32;
        target.quantum_target.set(cycles.wrapping_add(reset.wrapping_mul(cycles_per_quantum()) as u64));
        if target.quantum_donation() != 0 {
            target.set_quantum_donation(0);
        }
    }
}

pub fn suspend(thread: u64, new_state: u8) -> Result<(), KernelError> {
    {
        let _queues = QUEUES.lock();
        if thread_state(thread) == state::READY {
            remove_ready_locked(thread)?;
        }
        if next_thread() == thread {
            processor().next_thread.set(0);
            end_yield_reservation_locked(thread);
        }
        let kthread = kthread(thread);
        kthread.state.set(new_state);
        kthread.wait_time.set(tick_count());
    }
    let (owner, notify) = {
        let dispatch = STATE.lock();
        (dispatch.owners.get(&thread).copied(), dispatch.port_activity)
    };
    if new_state == state::WAITING {
        if let (Some(Owner { runtime, io_completion_port: Some(port), .. }), Some(notify)) = (owner, notify) {
            notify(port, runtime, false);
        }
    }
    Ok(())
}

pub fn unregister(thread: u64) -> Result<(), KernelError> {
    suspend(thread, state::TERMINATED)?;
    STATE.lock().owners.remove(&thread);
    Ok(())
}

/// NextThread é uma reserva real: uma thread de prioridade maior a substitui.
pub fn peek() -> Result<Option<(u64, Owner)>, KernelError> {
    initialize_queues();
    let reserved = {
        let _queues = QUEUES.lock();
        let mut reserved = next_thread();
        let ready = highest_ready_locked()?;
        // A reserva de um KeYieldExecution não perde para a thread que cedeu.
        let yielded = reserved != 0 && reserved == YIELD_TARGET.load(Ordering::Relaxed) && ready == YIELDER.load(Ordering::Relaxed);
        if ready != 0 && !yielded && (reserved == 0 || priority(ready) > priority(reserved)) {
            if reserved != 0 {
                end_yield_reservation_locked(reserved);
                enqueue_ready_locked(reserved, true, false);
            }
            remove_ready_locked(ready)?;
            reserve_next_locked(ready);
            reserved = ready;
        }
        reserved
    };
    if reserved == 0 {
        return Ok(None);
    }
    let owner = STATE.lock().owners.get(&reserved).copied();
    owner.map(|owner| Some((reserved, owner))).ok_or_else(|| KernelError::new("ready thread has no executable owner"))
}

pub fn begin_execution(thread: u64) -> Result<(), KernelError> {
    let cpu = cpu_index();
    let (owner, notify) = {
        let mut dispatch = STATE.lock();
        let execution = &mut dispatch.cpus[cpu];
        account_active_cycles(execution);
        let previous = execution.active.take();
        execution.stack.push(previous);
        execution.active = Some(Execution { pointer: thread, started: cpu::rdtsc() });
        (dispatch.owners.get(&thread).copied(), dispatch.port_activity)
    };
    if let (Some(Owner { runtime, io_completion_port: Some(port), .. }), Some(notify)) = (owner, notify) {
        notify(port, runtime, true);
    }
    {
        let _queues = QUEUES.lock();
        if thread_state(thread) == state::READY {
            remove_ready_locked(thread)?;
        }
        if next_thread() == thread {
            processor().next_thread.set(0);
            end_yield_reservation_locked(thread);
        }
        let kthread = kthread(thread);
        kthread.state.set(state::RUNNING);
        kthread.running.set(1);
    }
    let kthread = kthread(thread);
    let cycles = kthread.cycle_time.get();
    if cycles >= kthread.quantum_target.get() {
        let reset = kthread.quantum_reset.get() as u32;
        kthread.quantum_target.set(cycles.wrapping_add(reset.wrapping_mul(cycles_per_quantum()) as u64));
    }
    Ok(())
}

/// KiComputeNewPriority, com separação de foreground desligada. O fim do
/// quantum retira o boost sem baixar da base nem dos pisos ativos.
pub fn compute_quantum_end_priority(thread: u64) -> u8 {
    let previous = priority(thread) as i32;
    if previous >= 16 {
        return previous as u8;
    }
    let kthread = kthread(thread);
    let decrement = kthread.priority_decrement.get() as u8 as i32;
    let base = kthread.base_priority.get() as i32;
    let candidate = ((previous - (decrement >> 4) - (decrement & 15) - 1) as i8) as i32;
    if decrement & 15 != 0 {
        kthread.foreground_loss_time.set(tick_count());
    }
    if decrement != 0 {
        kthread.priority_decrement.set(0);
    }
    let floor = kthread.priority_floor_summary.get();
    let floor_priority = if floor != 0 { 31 - floor.leading_zeros() as i32 } else { 0 };
    base.max(candidate).max(floor_priority) as u8
}

pub fn end_execution(thread: u64, new_state: u8) -> Result<(), KernelError> {
    let cpu = cpu_index();
    let (voluntary_yield, yield_execution) = {
        let mut dispatch = STATE.lock();
        let execution = &mut dispatch.cpus[cpu];
        if execution.active.as_ref().map(|active| active.pointer) != Some(thread) {
            return Err(KernelError::new("thread execution stack mismatch"));
        }
        account_active_cycles(execution);
        match dispatch.owners.get_mut(&thread) {
            Some(owner) => (core::mem::replace(&mut owner.yield_requested, false), core::mem::replace(&mut owner.yield_execution, false)),
            None => (false, false),
        }
    };
    let kthread = kthread(thread);
    kthread.running.set(0);
    let cycles = kthread.cycle_time.get();
    let quantum_disabled = kthread.disable_quantum() != 0;
    let expired = !quantum_disabled && cycles >= kthread.quantum_target.get();
    // O KiQuantumEnd (0x25769d..0x25779c) roda no tique em que o quantum
    // acaba, também dentro de um serviço: quem sai bloqueada com o quantum
    // gasto perde o impulso como quem volta à fila, e o quantum renova ali
    // mesmo (CycleTime + QuantumReset * KiCyclesPerClockQuantum, 0x257783).
    // O KeYieldExecution recalcula como o fim do quantum (ajuste 1), mesmo
    // com quantum restante.
    if (expired && new_state != state::TERMINATED) || (yield_execution && new_state == state::READY) {
        kthread.priority.set(compute_quantum_end_priority(thread) as i8);
    }
    if expired {
        let reset = kthread.quantum_reset.get() as u8 as u32;
        kthread.quantum_target.set(cycles.wrapping_add(reset.wrapping_mul(cycles_per_quantum()) as u64));
    }
    // Yield explícito entrega a vez mesmo com quantum restante.
    if voluntary_yield {
        kthread.quantum_target.set(cycles);
    }
    let mut boosted = Vec::new();
    if new_state == state::READY {
        // A thread ainda consta como em execução: sai dela direto para a fila.
        initialize_queues();
        let _queues = QUEUES.lock();
        if yield_execution {
            reserve_yield_target_locked(thread)?;
        }
        enqueue_ready_locked(thread, !expired && !voluntary_yield, false);
        // KiQuantumEnd: o fim de quantum varre as prontas famintas.
        if expired {
            boosted = boost_starved_threads_locked();
        }
    } else {
        suspend(thread, new_state)?;
        // O KiQuantumEnd varre as prontas famintas em todo fim de quantum.
        if expired && new_state != state::TERMINATED {
            initialize_queues();
            let _queues = QUEUES.lock();
            boosted = boost_starved_threads_locked();
        }
    }
    for (starved, priority, waited) in boosted {
        let cid = &ethread(starved).cid;
        crate::debug_print!("[sched] anti-inanicao: thread {}:{} prioridade {} pronta ha {} ms -> 15", cid.unique_process.get(), cid.unique_thread.get(), priority, waited);
    }
    let mut dispatch = STATE.lock();
    let execution = &mut dispatch.cpus[cpu];
    execution.active = execution.stack.pop().flatten();
    if let Some(active) = execution.active.as_mut() {
        active.started = cpu::rdtsc();
    }
    Ok(())
}

/// A troca de uma thread de kernel que cede no próprio laço (o
/// SwitchReason::Yield do escalonador): só para uma pronta de prioridade
/// igual ou maior, como a rodada do fim de quantum.
pub fn request_yield(thread: u64) -> Result<bool, KernelError> {
    if !STATE.lock().owners.contains_key(&thread) {
        return Ok(false);
    }
    let candidates = [next_thread(), highest_ready()?];
    let contested = candidates.iter().any(|&candidate| candidate != 0 && candidate != thread && priority(candidate) >= priority(thread));
    if !contested {
        return Ok(false);
    }
    if let Some(owner) = STATE.lock().owners.get_mut(&thread) {
        owner.yield_requested = true;
    }
    Ok(true)
}

/// A sucessora do KiSelectReadyThreadEx(Prcb, NULL, 1) do KeYieldExecution
/// (rva 0x2f64d0 do 19041): a NextThread reservada ou a pronta de maior
/// prioridade a partir de 1 (KiSelectReadyThread(1, Prcb)), qualquer que
/// seja a prioridade de quem cede. Sob o PrcbLock; 0 sem nenhuma.
fn select_yield_target_locked(thread: u64) -> Result<u64, KernelError> {
    let next = next_thread();
    if next != 0 && next != thread {
        return Ok(next);
    }
    let ready = highest_ready_locked()?;
    Ok(if ready != 0 && ready != thread && priority(ready) >= 1 { ready } else { 0 })
}

/// No fim da execução de quem cedeu pelo KeYieldExecution, antes de ela ir
/// à fila: a sucessora de prioridade menor fica reservada na NextThread
/// (uma de prioridade igual ou maior já é a escolha do despacho).
fn reserve_yield_target_locked(thread: u64) -> Result<(), KernelError> {
    let target = select_yield_target_locked(thread)?;
    if target == 0 || priority(target) >= priority(thread) {
        return Ok(());
    }
    if next_thread() != target {
        remove_ready_locked(target)?;
        reserve_next_locked(target);
    }
    YIELD_TARGET.store(target, Ordering::Relaxed);
    YIELDER.store(thread, Ordering::Relaxed);
    Ok(())
}

/// KeYieldExecution(0): o NtYieldExecution, o ZwYieldExecution e o atraso
/// zero não alertável de UserMode do KeDelayExecutionThread (rva 0x256e39,
/// a mesma escolha pelo KiSelectReadyThreadEx(Prcb, NULL, 1)). Havendo
/// NextThread ou uma pronta de prioridade a partir de 1, de qualquer
/// prioridade relativa à da thread corrente, ela cede a CPU (`true`,
/// STATUS_SUCCESS); senão STATUS_NO_YIELD_PERFORMED. A troca acontece no fim
/// da execução (`end_execution`): a prioridade de quem cede recebe o ajuste
/// do fim de quantum e uma sucessora de prioridade menor fica reservada.
pub fn request_yield_execution(thread: u64) -> Result<bool, KernelError> {
    if !STATE.lock().owners.contains_key(&thread) {
        return Ok(false);
    }
    initialize_queues();
    let target = {
        let _queues = QUEUES.lock();
        select_yield_target_locked(thread)?
    };
    if target == 0 {
        return Ok(false);
    }
    if let Some(owner) = STATE.lock().owners.get_mut(&thread) {
        owner.yield_requested = true;
        owner.yield_execution = true;
    }
    Ok(true)
}

/// ZwYieldExecution fora de uma thread de sistema (o KeYieldExecution(0)):
/// a thread corrente cede a CPU quando há outra pronta
/// ([`request_yield_execution`], STATUS_SUCCESS); senão
/// STATUS_NO_YIELD_PERFORMED. As threads de kernel com pilha própria cedem
/// de fato (`context_switch`).
pub fn yield_execution() -> Result<u32, KernelError> {
    let thread = crate::ntos::ps::process::get_current_thread();
    if !request_yield_execution(thread)? {
        return Ok(0x4000_0024);
    }
    if super::context_switch::on_kernel_thread_stack() == Some(thread) && super::context_switch::kernel_thread_can_block() {
        super::context_switch::yield_kernel_thread(false);
    }
    Ok(0)
}

pub fn register_priority_change_observer(observer: fn()) -> Result<(), KernelError> {
    let mut dispatch = STATE.lock();
    if dispatch.priority_observer.is_some() {
        return Err(KernelError::new("priority change observer already registered"));
    }
    dispatch.priority_observer = Some(observer);
    Ok(())
}

pub fn set_port_activity_observer(observer: Option<fn(u64, u64, bool)>) {
    STATE.lock().port_activity = observer;
}

pub fn set_io_completion_port(thread: u64, port: Option<u64>) {
    if let Some(owner) = STATE.lock().owners.get_mut(&thread) {
        owner.io_completion_port = port;
    }
}

pub fn owner(thread: u64) -> Option<Owner> {
    STATE.lock().owners.get(&thread).copied()
}

/// A thread da execução em curso nesta CPU (o topo da pilha de execuções
/// dela), se há uma.
pub fn active_thread() -> Option<u64> {
    let cpu = cpu_index();
    STATE.lock().cpus[cpu].active.as_ref().map(|active| active.pointer)
}

/// A thread está numa CPU: é a execução ativa de alguma CPU ou uma execução
/// suspensa sob outra na mesma CPU (um pump aninhado no intervalo dela). Uma
/// thread de usuário que deixou a CPU numa espera
/// (`context_switch::block_current`, o `end_execution` já a tirou) não está
/// em nenhuma. Toma só o STATE: não chamar com o QUEUES tomado.
pub fn on_processor(thread: u64) -> bool {
    STATE.lock().cpus.iter().any(|execution| execution.active.as_ref().is_some_and(|active| active.pointer == thread) || execution.stack.iter().flatten().any(|suspended| suspended.pointer == thread))
}

// ---- ciclos de thread e cessão do processador -----------------------------
//
// (append de `ke-processors` ao ke/thread_dispatch.rs. Usa o que o arquivo
// já tem — `pcr`, `cpu`, `current_processor()`, `kthread()`, `sample_cycles` —
// sem linhas `use` novas.)

/// DpcTimeCount e DpcWatchdogCount acima disto pesam no KeShouldYieldProcessor.
const YIELD_WATCHDOG_THRESHOLD: u32 = 7;

/// KeQueryTotalCycleTimeThread: KTHREAD.CycleTime atualizado pelo despacho
/// (o acúmulo TSC do KiStartThreadCycleAccumulation); o carimbo opcional
/// recebe o TSC da amostra.
pub fn query_total_cycle_time(thread: u64, stamp: Option<&crate::ntos::inc::types::Field<u64>>) -> u64 {
    let cycles = if pcr::get_pcr_address() != 0 { sample_cycles(thread) } else { kthread(thread).cycle_time.get() };
    if let Some(stamp) = stamp {
        stamp.set(cpu::rdtsc());
    }
    cycles
}

/// Zera os contadores do watchdog de DPC (sem o perfilador global, que o
/// OpenNT não tem).
fn reset_dpc_watchdog(prcb: &Kprcb) {
    prcb.dpc_watchdog_count.set(0);
    prcb.dpc_time_count.set(0);
}

/// KeShouldYieldProcessor: a árvore de decisão do binário sobre a KPRCB da
/// CPU corrente. Fora de DPC: DPC pedida, fim de quantum ou próxima thread
/// escolhida. Dentro de DPC: só com DpcTimeCount ou DpcWatchdogCount acima de
/// 7. A fila do `ke::dpc` entra como DpcNormalDpcPresent (ela não publica o
/// bit).
pub fn should_yield_processor() -> bool {
    if pcr::get_pcr_address() == 0 {
        return false;
    }
    let prcb = current_processor();
    let summary = prcb.dpc_request_summary.get() as u32;
    let requested = summary & 0x1E != 0 || super::dpc::pending() != 0;
    let watchdog = prcb.dpc_watchdog_count.get() as u32;
    let dpc_time = prcb.dpc_time_count.get();
    let quantum_end = prcb.quantum_end.get() != 0;
    let current = prcb.current_thread.get();
    let other_work = || -> bool {
        if requested {
            return true;
        }
        if prcb.idle_thread.get() == current {
            reset_dpc_watchdog(prcb);
            return false;
        }
        true
    };
    if summary & 1 != 0 {
        if dpc_time > YIELD_WATCHDOG_THRESHOLD {
            return quantum_end || other_work();
        }
        return watchdog > YIELD_WATCHDOG_THRESHOLD && other_work();
    }
    if requested || quantum_end {
        return true;
    }
    let next = prcb.next_thread.get();
    if next != 0 && next != current {
        return true;
    }
    if watchdog > YIELD_WATCHDOG_THRESHOLD {
        reset_dpc_watchdog(prcb);
    }
    false
}
