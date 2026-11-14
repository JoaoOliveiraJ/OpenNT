//! KeBugCheckEx do kernel e os callbacks de bugcheck dos drivers.
//!
//! Todo bugcheck passa pelo handler instalado por [`init`] ([`raise_bug_check`]),
//! que grava KiBugCheckData, executa os callbacks registrados pelos drivers
//! (KeRegisterBugCheckCallback) e publica os dados secundários e o black box.
//! Antes de o handler ser instalado (início do boot) o bugcheck só imprime o
//! código STOP e os quatro parâmetros e para a CPU.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::bugcheck_reason;
use crate::hal::amd64::native_call;
use crate::hal::cpu;
use crate::ntos::inc::types::extra_ke_misc::KbugcheckCallbackRecord;
use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::mm::kernel_data;
use crate::ntos::po::black_box;
use crate::rtl::SpinLock;

static HANDLER: AtomicUsize = AtomicUsize::new(0);

/// KBUGCHECK_BUFFER_DUMP_STATE.
const BUFFER_EMPTY: u8 = 0;
const BUFFER_INSERTED: u8 = 1;
const BUFFER_STARTED: u8 = 2;
const BUFFER_FINISHED: u8 = 3;

/// Os KBUGCHECK_CALLBACK_RECORD inseridos por KeRegisterBugCheckCallback
/// (memória do chamador, como a KeBugCheckCallbackListHead do NT).
static BUG_CHECK_CALLBACKS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// KiBugCheckData: ULONG_PTR[5] (código e os quatro parâmetros).
const BUG_CHECK_DATA_COUNT: usize = 5;

fn callback_record(record: u64) -> &'static KbugcheckCallbackRecord {
    // SAFETY: o registro pertence ao driver enquanto estiver inserido.
    unsafe { KbugcheckCallbackRecord::at(record) }
}
/// Instalado por [`init`].
pub fn set_handler(handler: fn(u32, u64, u64, u64, u64) -> !) {
    HANDLER.store(handler as usize, Ordering::Release);
}

pub fn bug_check_ex(code: u32, first: u64, second: u64, third: u64, fourth: u64) -> ! {
    let handler = HANDLER.load(Ordering::Acquire);
    if handler != 0 {
        let handler: fn(u32, u64, u64, u64, u64) -> ! = unsafe { core::mem::transmute(handler) };
        handler(code, first, second, third, fourth);
    }
    debug_print!(
        "*** STOP: {:#010x} ({:#018x}, {:#018x}, {:#018x}, {:#018x})",
        code,
        first,
        second,
        third,
        fourth
    );
    cpu::halt_forever()
}

/// KiBugCheckData: o export de dados da `.kdata`, ULONG_PTR[5] (o EAT e a
/// IAT dos drivers recebem o mesmo endereço).
pub fn bug_check_data() -> u64 {
    kernel_data::required_address("KiBugCheckData")
}

/// Parada fatal comum (KeBugCheckEx): grava KiBugCheckData, roda os
/// callbacks registrados, publica os dados secundários e o black box e para
/// a máquina.
pub fn raise_bug_check(code: u32, first: u64, second: u64, third: u64, fourth: u64) -> ! {
    // SAFETY: célula própria de KiBugCheckData.
    let data = unsafe { Field::<u64>::array_at(bug_check_data(), BUG_CHECK_DATA_COUNT) };
    for (cell, value) in data.iter().zip([code as u64, first, second, third, fourth]) {
        cell.set(value);
    }
    debug_print!("");
    debug_print!("*** STOP (KeBugCheckEx): {:#010x} ({:#x}, {:#x}, {:#x}, {:#x})", code, first, second, third, fourth);
    let callbacks = BUG_CHECK_CALLBACKS.lock().clone();
    for record in callbacks {
        // KBUGCHECK_CALLBACK_ROUTINE(Buffer, Length).
        let entry = callback_record(record);
        let routine = entry.callback_routine.get();
        if routine != 0 {
            entry.state.set(BUFFER_STARTED);
            native_call::call(routine, &[entry.buffer.get(), entry.length.get() as u64]);
            entry.state.set(BUFFER_FINISHED);
        }
    }
    if let Err(error) = bugcheck_reason::publish_secondary_data(0) {
        debug_print!("[bugcheck] dados secundarios: {}", error);
    }
    black_box::publish_crash_records();
    cpu::halt_forever()
}

/// KeRegisterBugCheckCallback(CallbackRecord, CallbackRoutine, Buffer,
/// Length, Component): preenche o KBUGCHECK_CALLBACK_RECORD do chamador e o
/// insere (FALSE se ele já estiver inserido); a rotina roda no KeBugCheckEx
/// com (Buffer, Length).
pub fn register_callback(record: u64, routine: u64, buffer: u64, length: u32, component: u64) -> bool {
    let entry = callback_record(record);
    let mut callbacks = BUG_CHECK_CALLBACKS.lock();
    if entry.state.get() != BUFFER_EMPTY || callbacks.contains(&record) {
        return false;
    }
    entry.callback_routine.set(routine);
    entry.buffer.set(buffer);
    entry.length.set(length);
    entry.component.set(component);
    entry.checksum.set(routine.wrapping_add(buffer).wrapping_add(length as u64).wrapping_add(component));
    entry.state.set(BUFFER_INSERTED);
    callbacks.push(record);
    true
}

/// KeDeregisterBugCheckCallback: FALSE quando o registro não está inserido.
pub fn deregister_callback(record: u64) -> bool {
    let mut callbacks = BUG_CHECK_CALLBACKS.lock();
    let Some(index) = callbacks.iter().position(|&candidate| candidate == record) else { return false };
    callbacks.remove(index);
    drop(callbacks);
    callback_record(record).state.set(BUFFER_EMPTY);
    true
}

/// Confere a célula de KiBugCheckData e liga o bugcheck interno do kernel a
/// [`raise_bug_check`].
pub fn init() {
    bug_check_data();
    set_handler(raise_bug_check);
}
