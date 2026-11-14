//! KTIMER2: KeInitializeTimer2, KeSetTimer2 e KeCancelTimer2.
//!
//! O objeto é o `_KTIMER2` real (0x88 bytes, do chamador): Header.Type
//! Timer2NotificationObject (0x18) com o bit 31 dos atributos, senão
//! Timer2SynchronizationObject (0x19); Callback, CallbackContext,
//! DisableCallback e DisableContext guardados codificados com os segredos
//! do boot (o par KiWaitNever/KiWaitAlways); TypeFlags e CollectionIndex
//! da tabela KiTimer2Combinations; DueTime[0] em tempo de interrupção
//! absoluto, DueTime[1] com a tolerância do EXT_SET_PARAMETERS; Period em
//! 100 ns, no mínimo KeMinimumIncrement. O byte 1 do Header são as
//! bandeiras do timer: Inserted (0x01), Running (0x10, durante o callback)
//! e Disabled (0x20, que faz Set e Cancel não mexerem em nada).
//!
//! As coleções de árvores do NT (KiTimer2Collections) viram a fila de
//! endereços inseridos deste módulo; o pump dos timers
//! (`ke/timer.rs::check_timers`) expira os vencidos em DueTime[0]:
//! SignalState = 1 (as esperas tratam os dois tipos em `ke/dispatcher.rs`),
//! o periódico volta para agora + Period e o callback decodificado roda em
//! DISPATCH_LEVEL com (Timer, CallbackContext), como no KiExpireTimer2.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{clock, irql, pcr};
use crate::hal::amd64::native_call;
use crate::hal::cpu;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_ke_misc::Ktimer2;
use crate::ntos::ke::bugcheck;
use crate::rtl::SpinLock;

const TIMER2_NOTIFICATION_OBJECT: u8 = 0x18;
const TIMER2_SYNCHRONIZATION_OBJECT: u8 = 0x19;
/// Bandeiras do byte 1 do Header (Timer2Flags).
const TIMER2_INSERTED: i32 = 0x01 << 8;
const TIMER2_RUNNING: i32 = 0x10 << 8;
const TIMER2_DISABLED: i32 = 0x20 << 8;
/// `KTIMER2.TypeFlags` aceitos (IdleResilient 2, HighResolution 4,
/// NoWake 8, PseudoHighRes 0x10) e os dois bytes de CollectionIndex de
/// cada combinação (KiTimer2Combinations).
const COMBINATIONS: [(u8, u8, u8); 6] = [(8, 32, 35), (0, 21, 3), (16, 21, 2), (4, 1, 35), (2, 32, 36), (6, 1, 36)];
/// CollectionIndex cuja tolerância é ignorada pelo KeSetTimer2.
const COLLECTION_WITHOUT_TOLERANCE: u8 = 0x15;
/// FAST_FAIL_INVALID_ARG.
const FAST_FAIL_INVALID_ARG: u64 = 5;
/// EX_TIMER_UNLIMITED_TOLERANCE no EXT_SET_PARAMETERS.NoWakeTolerance.
const UNLIMITED_TOLERANCE: u64 = u64::MAX;
/// Prazo saturado (o -2 do original).
const SATURATED_DUE_TIME: u64 = u64::MAX - 1;

/// Os segredos do boot (KiWaitNever, KiWaitAlways).
static SECRETS: SpinLock<Option<(u64, u64)>> = SpinLock::new(None);
/// Os KTIMER2 inseridos (o papel das coleções do KiTimer2Collections).
static INSERTED: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

fn timer_at(address: u64) -> &'static Ktimer2 {
    // SAFETY: o KTIMER2 vivo do chamador.
    unsafe { Ktimer2::at(address) }
}

fn secrets() -> (u64, u64) {
    *SECRETS.lock().get_or_insert_with(|| {
        let mix = |salt: u64| cpu::hardware_random_u64().unwrap_or_else(|| cpu::rdtsc().rotate_left(17) ^ salt);
        (mix(0x9E37_79B9_7F4A_7C15), mix(0xC2B2_AE3D_27D4_EB4F))
    })
}

/// A codificação de ponteiro do KiInitializeTimer2.
fn encode(value: u64, timer: u64) -> u64 {
    let (never, always) = secrets();
    ((always ^ value).swap_bytes() ^ timer).rotate_right((never & 63) as u32) ^ never
}

/// A decodificação do KiExpireTimer2.
fn decode(value: u64, timer: u64) -> u64 {
    let (never, always) = secrets();
    ((value ^ never).rotate_left((never & 63) as u32) ^ timer).swap_bytes() ^ always
}

fn flags(timer: &Ktimer2) -> i32 {
    timer.header.lock.get()
}

/// KeInitializeTimer2(Timer, Callback, CallbackContext, Attributes).
pub fn initialize(timer: &Ktimer2, callback: u64, context: u64, attributes: u32) {
    let address = timer.address();
    timer.header.lock.set(0);
    timer.header.signal_state.set(0);
    let kind = if (attributes as i32) < 0 { TIMER2_NOTIFICATION_OBJECT } else { TIMER2_SYNCHRONIZATION_OBJECT };
    timer.header.lock.set(kind as i32);
    let wait_list = &timer.header.wait_list_head;
    wait_list.flink.set(wait_list.address());
    wait_list.blink.set(wait_list.address());
    timer.callback.set(encode(callback, address));
    timer.callback_context.set(encode(context, address));
    timer.disable_callback.set(encode(0, address));
    timer.disable_context.set(encode(0, address));
    // Sem atributos de tipo, o NT usaria PseudoHighRes para um processo com
    // resolução de timer pedida (PsTimerResolutionActive); o OpenNT não
    // guarda esse pedido por processo.
    let type_flags = (attributes & 0xE) as u8;
    timer.type_flags.set(type_flags);
    let Some(&(_, first, second)) = COMBINATIONS.iter().find(|&&(candidate, _, _)| candidate == type_flags) else {
        bugcheck::bug_check_ex(0x139, FAST_FAIL_INVALID_ARG, 0, 0, 0);
    };
    timer.collection_index[0].set(first);
    timer.collection_index[1].set(second);
}

/// O prazo absoluto em tempo de interrupção, saturado como no original.
fn absolute_due(now: u64, interval: u64) -> u64 {
    match now.checked_add(interval) {
        Some(due) if due != u64::MAX => due,
        _ => SATURATED_DUE_TIME,
    }
}

/// KeSetTimer2(Timer, DueTime, Period, Parameters): TRUE se o timer já
/// estava inserido.
pub fn set(timer: &Ktimer2, due_time: i64, period: i64, parameters: u64) -> bool {
    let period = if period != 0 && period < clock::CLOCK_TIME_INCREMENT as i64 { clock::CLOCK_TIME_INCREMENT as i64 } else { period };
    let absolute = due_time > 0;
    // Prazo absoluto: o intervalo até ele na hora do sistema (0 se passou).
    let interval = if absolute {
        let system_now = clock::system_time_100ns() as i64;
        if due_time > system_now { (due_time - system_now) as u64 } else { 0 }
    } else {
        due_time.unsigned_abs()
    };
    let due = absolute_due(clock::uptime_100ns(), interval);
    let mut latest = due;
    if parameters != 0 && timer.collection_index[0].get() != COLLECTION_WITHOUT_TOLERANCE {
        // SAFETY: o EXT_SET_PARAMETERS do chamador (NoWakeTolerance em +8).
        let tolerance = unsafe { crate::ntos::inc::field::Field::<u64>::at(parameters + 8) }.get();
        latest = if tolerance == UNLIMITED_TOLERANCE { UNLIMITED_TOLERANCE } else { absolute_due(due, tolerance) };
    }
    let mut inserted = INSERTED.lock();
    if flags(timer) & TIMER2_DISABLED != 0 {
        return false;
    }
    let was_set = remove_locked(&mut inserted, timer);
    timer.due_time[0].set(due);
    timer.due_time[1].set(latest);
    timer.header.signal_state.set(0);
    timer.period.set(period);
    timer.absolute_system_time.set(absolute as u8);
    insert_locked(&mut inserted, timer);
    was_set
}

fn insert_locked(inserted: &mut Vec<u64>, timer: &Ktimer2) {
    inserted.push(timer.address());
    timer.header.lock.atomic().fetch_or(TIMER2_INSERTED, Ordering::SeqCst);
}

fn remove_locked(inserted: &mut Vec<u64>, timer: &Ktimer2) -> bool {
    if flags(timer) & TIMER2_INSERTED == 0 {
        return false;
    }
    inserted.retain(|&address| address != timer.address());
    timer.header.lock.atomic().fetch_and(!TIMER2_INSERTED, Ordering::SeqCst);
    true
}

/// KeCancelTimer2(Timer, Parameters): TRUE se o timer estava inserido. O
/// EXT_CANCEL_PARAMETERS não é lido (o original também não o usa).
pub fn cancel(timer: &Ktimer2) -> bool {
    let mut inserted = INSERTED.lock();
    if flags(timer) & TIMER2_DISABLED != 0 {
        return false;
    }
    remove_locked(&mut inserted, timer)
}

/// Expira os KTIMER2 vencidos (chamado pelo pump dos timers).
pub fn expire_due() {
    if irql::get_irql() > irql::DISPATCH_LEVEL {
        return;
    }
    let now = clock::uptime_100ns();
    let expired: Vec<u64> = {
        let mut inserted = INSERTED.lock();
        let due: Vec<u64> = inserted.iter().copied().filter(|&address| timer_at(address).due_time[0].get() <= now).collect();
        for &address in &due {
            let timer = timer_at(address);
            remove_locked(&mut inserted, timer);
            let period = timer.period.get() as u64;
            if period != 0 {
                let next = absolute_due(now, period);
                let latest = timer.due_time[1].get();
                let slack = latest.wrapping_sub(timer.due_time[0].get());
                timer.due_time[0].set(next);
                timer.due_time[1].set(if latest == UNLIMITED_TOLERANCE { latest } else { absolute_due(next, slack) });
                insert_locked(&mut inserted, timer);
            }
        }
        due
    };
    for address in expired {
        let timer = timer_at(address);
        timer.header.signal_state.set(1);
        let callback = decode(timer.callback.get(), address);
        if callback == 0 {
            continue;
        }
        let context = decode(timer.callback_context.get(), address);
        timer.header.lock.atomic().fetch_or(TIMER2_RUNNING, Ordering::SeqCst);
        let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
        if let Ok(state) = pcr::enter_dpc() {
            native_call::call(callback, &[address, context]);
            pcr::leave_dpc(state);
        }
        irql::lower_irql(previous as u64);
        timer.header.lock.atomic().fetch_and(!TIMER2_RUNNING, Ordering::SeqCst);
    }
}

/// Quantos KTIMER2 estão inseridos (diagnóstico dos autotestes).
pub fn inserted_count() -> usize {
    INSERTED.lock().len()
}

/// O callback decodificado de um KTIMER2 (autotestes).
pub fn decoded_callback(timer: &Ktimer2) -> (u64, u64) {
    (decode(timer.callback.get(), timer.address()), decode(timer.callback_context.get(), timer.address()))
}
