//! A resolução do relógio: ExQueryTimerResolution, ExSetTimerResolution,
//! NtQueryTimerResolution, NtSetTimerResolution e o cancelamento na saída do
//! processo (ExCleanTimerResolutionRequest).
//!
//! Como o ntoskrnl 19041:
//!
//! - NtQueryTimerResolution (rva 0x6a15c0) e ExQueryTimerResolution (rva
//!   0x3cf850) devolvem KeMaximumIncrement, KeMinimumIncrement e
//!   KeTimeIncrement (156250, 5000 e o incremento corrente, em 100 ns).
//! - ExSetTimerResolution (rva 0x5b22d0) conta os pedidos do kernel sob o
//!   ExpKernelResolutionLock: o primeiro pedido (ou um mais fino que o
//!   vigente) grava KeNonHrTimeIncrement e ExpKernelRequestedTimerResolution
//!   e chama o ExpUpdateTimerResolution; o último cancelamento volta
//!   KeNonHrTimeIncrement a KeMaximumIncrement e pede a resolução padrão; os
//!   demais só devolvem KeTimeIncrement.
//! - NtSetTimerResolution (rva 0x709f10) é por processo: o pedido liga
//!   EPROCESS.Flags.SetTimerResolution e, na primeira vez,
//!   SetTimerResolutionLink com o EPROCESS.TimerResolutionLink na
//!   ExpTimerResolutionListHead (ExpInsertTimerResolutionEntry); conta
//!   ExpTimerResolutionCount no primeiro pedido do processo; grava
//!   RequestedTimerResolution e chama o ExpUpdateTimerResolution (que só
//!   afina quando o pedido é o primeiro ou não é mais grosso que o
//!   anterior), a menos que Flags3.TimerResolutionIgnore. O cancelamento
//!   sem pedido é STATUS_TIMER_RESOLUTION_NOT_SET; com pedido, desliga o bit,
//!   zera RequestedTimerResolution, desconta e recalcula. ActualTime recebe o
//!   KeTimeIncrement resultante. A trilha de diagnóstico do PoDiag
//!   (TimerResolutionStackRecord, SmallestTimerResolution) não é mantida.
//! - O ExpUpdateTimerResolution (rva 0x35defc): um pedido só vale abaixo de
//!   ExpLastRequestedTime e de KeMaximumIncrement; um cancelamento recalcula
//!   o menor pedido em vigor (KeMaximumIncrement, o do kernel e o de cada
//!   processo da lista com SetTimerResolution e sem TimerResolutionIgnore);
//!   o valor sobe a KeMinimumIncrement e, diferente de ExpLastRequestedTime,
//!   reprograma o relógio (ExpUpdateTimerConfiguration: o KeTimeIncrement
//!   novo é o incremento do tick de `ke::clock`).
//! - ExCleanTimerResolutionRequest (rva 0x36c734), da saída do processo:
//!   com SetTimerResolution, o ZwSetTimerResolution(KeMaximumIncrement,
//!   FALSE); depois o EPROCESS sai da lista.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::types::{Eprocess, Field, ListEntry, NtStruct};
use crate::ntos::ke::clock::{self, MAXIMUM_INCREMENT, MINIMUM_INCREMENT};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// STATUS_TIMER_RESOLUTION_NOT_SET.
pub const STATUS_TIMER_RESOLUTION_NOT_SET: u32 = 0xC000_0245;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// O estado sob o ExpKernelResolutionLock.
struct Resolution {
    /// ExpKernelResolutionCount.
    kernel_count: u32,
    /// ExpKernelRequestedTimerResolution.
    kernel_requested: u32,
    /// KeNonHrTimeIncrement.
    non_hr_increment: u32,
    /// ExpLastRequestedTime.
    last_requested: u32,
    /// ExpTimerResolutionCount: processos com pedido.
    process_count: u32,
}

static RESOLUTION: SpinLock<Resolution> = SpinLock::new(Resolution { kernel_count: 0, kernel_requested: 0, non_hr_increment: MAXIMUM_INCREMENT, last_requested: MAXIMUM_INCREMENT, process_count: 0 });
/// ExpTimerResolutionListHead (16 bytes do kernel, criada no primeiro uso).
static LIST_HEAD: AtomicU64 = AtomicU64::new(0);
/// ExpTimeRefreshLock dos serviços.
static REFRESH_LOCK: SpinLock<()> = SpinLock::new(());

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS vivo (o corrente ou o que está saindo).
    unsafe { Eprocess::at(process) }
}

fn list_head() -> Option<&'static ListEntry> {
    let mut head = LIST_HEAD.load(Ordering::Acquire);
    if head == 0 {
        let block = guest::alloc_bytes(ListEntry::SIZE);
        if block == 0 {
            return None;
        }
        // SAFETY: bloco recém-alocado do tamanho de uma LIST_ENTRY.
        crate::ntos::ex::list_entry::initialize(unsafe { ListEntry::at(block) });
        head = match LIST_HEAD.compare_exchange(0, block, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => block,
            Err(existing) => {
                guest::free_bytes(block);
                existing
            }
        };
    }
    // SAFETY: a cabeça permanente da lista.
    Some(unsafe { ListEntry::at(head) })
}

/// ExQueryTimerResolution(MaximumTime*, MinimumTime*, CurrentTime*).
pub fn query_timer_resolution(maximum: &Field<u32>, minimum: &Field<u32>, current: &Field<u32>) {
    maximum.set(MAXIMUM_INCREMENT);
    minimum.set(MINIMUM_INCREMENT);
    current.set(clock::time_increment());
}

/// (KeMaximumIncrement, KeMinimumIncrement, KeTimeIncrement).
pub fn resolution() -> (u32, u32, u32) {
    (MAXIMUM_INCREMENT, MINIMUM_INCREMENT, clock::time_increment())
}

/// ExpUpdateTimerResolution sob o lock: o KeTimeIncrement resultante.
fn update_locked(state: &mut Resolution, set: bool, desired: u32) -> u32 {
    let wanted = if set {
        if desired >= state.last_requested || desired >= MAXIMUM_INCREMENT {
            return clock::time_increment();
        }
        desired
    } else {
        let mut wanted = MAXIMUM_INCREMENT;
        if state.kernel_count != 0 {
            wanted = wanted.min(state.kernel_requested);
        }
        if let Some(head) = list_head() {
            let mut link = head.flink.get();
            while link != head.address() {
                let process = link - core::mem::offset_of!(Eprocess, timer_resolution_link) as u64;
                let object = eprocess(process);
                let requested = object.requested_timer_resolution.get();
                if object.flags.get() & Eprocess::SET_TIMER_RESOLUTION_MASK != 0 && requested < wanted && object.flags3.get() & Eprocess::TIMER_RESOLUTION_IGNORE_MASK == 0 {
                    wanted = requested;
                }
                // SAFETY: a lista liga TimerResolutionLinks de EPROCESS vivos.
                link = unsafe { ListEntry::at(link) }.flink.get();
            }
        }
        wanted
    };
    let wanted = wanted.max(MINIMUM_INCREMENT);
    if wanted == state.last_requested {
        return clock::time_increment();
    }
    state.last_requested = wanted;
    // ExpUpdateTimerConfiguration: o relógio no incremento novo.
    clock::set_time_increment(wanted)
}

/// ExSetTimerResolution(DesiredTime, SetResolution): a resolução do relógio
/// em vigor, em 100 ns.
pub fn set_timer_resolution(desired: u32, set: bool) -> u32 {
    let mut state = RESOLUTION.lock();
    if !set {
        if state.kernel_count == 0 {
            return clock::time_increment();
        }
        state.kernel_count -= 1;
        if state.kernel_count != 0 {
            return clock::time_increment();
        }
        state.non_hr_increment = MAXIMUM_INCREMENT;
        state.kernel_requested = 0;
        return update_locked(&mut state, false, 0);
    }
    state.kernel_count += 1;
    if state.kernel_count != 1 && desired >= state.kernel_requested {
        return clock::time_increment();
    }
    state.non_hr_increment = desired;
    state.kernel_requested = desired;
    update_locked(&mut state, true, desired)
}

/// Pedidos de resolução do kernel em vigor, o último valor pedido e o
/// KeNonHrTimeIncrement (ExpKernelResolutionCount,
/// ExpKernelRequestedTimerResolution, KeNonHrTimeIncrement).
pub fn kernel_resolution_requests() -> (u32, u32, u32) {
    let state = RESOLUTION.lock();
    (state.kernel_count, state.kernel_requested, state.non_hr_increment)
}

/// ExpTimerResolutionCount.
pub fn process_request_count() -> u32 {
    RESOLUTION.lock().process_count
}

/// O núcleo do NtSetTimerResolution para `process`: (NTSTATUS, ActualTime).
pub fn set_process_timer_resolution(process: u64, desired: u32, set: bool) -> (u32, u32) {
    let _held = REFRESH_LOCK.lock();
    let object = eprocess(process);
    let flags = object.flags.atomic();
    if !set {
        let previous = flags.fetch_and(!Eprocess::SET_TIMER_RESOLUTION_MASK, Ordering::SeqCst);
        if previous & Eprocess::SET_TIMER_RESOLUTION_MASK == 0 {
            return (STATUS_TIMER_RESOLUTION_NOT_SET, clock::time_increment());
        }
        let mut state = RESOLUTION.lock();
        state.process_count = state.process_count.saturating_sub(1);
        object.requested_timer_resolution.set(0);
        return (0, update_locked(&mut state, false, 0));
    }
    let previous = flags.fetch_or(Eprocess::SET_TIMER_RESOLUTION_LINK_MASK | Eprocess::SET_TIMER_RESOLUTION_MASK, Ordering::SeqCst);
    let mut state = RESOLUTION.lock();
    if previous & Eprocess::SET_TIMER_RESOLUTION_LINK_MASK == 0 {
        if let Some(head) = list_head() {
            crate::ntos::ex::list_entry::insert_tail(head, &object.timer_resolution_link);
        }
    }
    let finer = if previous & Eprocess::SET_TIMER_RESOLUTION_MASK == 0 {
        state.process_count += 1;
        true
    } else {
        desired <= object.requested_timer_resolution.get()
    };
    object.requested_timer_resolution.set(desired);
    let actual = if object.flags3.get() & Eprocess::TIMER_RESOLUTION_IGNORE_MASK != 0 { clock::time_increment() } else { update_locked(&mut state, finer, desired) };
    (0, actual)
}

/// NtSetTimerResolution(DesiredTime, SetResolution, ActualTime*) do
/// processo corrente; ActualTime sondado para escrita do modo usuário.
pub fn nt_set_timer_resolution(desired: u32, set: bool, actual: u64, from_user_mode: bool) -> u32 {
    if from_user_mode && !crate::ntos::ps::user_probe::probe_user_write(actual, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let (status, increment) = set_process_timer_resolution(crate::ntos::ps::process::get_current_process(), desired, set);
    if guest::try_write::<u32>(actual, increment).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    status
}

/// NtQueryTimerResolution(MaximumTime*, MinimumTime*, CurrentTime*): as três
/// saídas sondadas para escrita do modo usuário.
pub fn nt_query_timer_resolution(maximum: u64, minimum: u64, current: u64, from_user_mode: bool) -> u32 {
    if from_user_mode && [maximum, minimum, current].iter().any(|&pointer| !crate::ntos::ps::user_probe::probe_user_write(pointer, 4)) {
        return STATUS_ACCESS_VIOLATION;
    }
    let (max, min, now) = resolution();
    let written = guest::try_write::<u32>(maximum, max).and_then(|()| guest::try_write::<u32>(minimum, min)).and_then(|()| guest::try_write::<u32>(current, now));
    written.map_or(STATUS_ACCESS_VIOLATION, |()| 0)
}

/// ExCleanTimerResolutionRequest: o pedido do processo que sai é cancelado
/// e o EPROCESS deixa a lista.
pub fn clean_timer_resolution_request(process: u64) {
    let object = eprocess(process);
    if object.flags.get() & Eprocess::SET_TIMER_RESOLUTION_MASK != 0 {
        set_process_timer_resolution(process, MAXIMUM_INCREMENT, false);
    }
    let _held = REFRESH_LOCK.lock();
    let _state = RESOLUTION.lock();
    if object.flags.atomic().fetch_and(!Eprocess::SET_TIMER_RESOLUTION_LINK_MASK, Ordering::SeqCst) & Eprocess::SET_TIMER_RESOLUTION_LINK_MASK != 0 {
        let _ = crate::ntos::ex::list_entry::remove(&object.timer_resolution_link);
    }
}

/// Registra o cancelamento na saída dos processos.
pub fn initialize() {
    crate::ntos::ps::process::register_process_exit_routine(clean_timer_resolution_request);
}
