//! KeBugCheckEx do kernel e os callbacks de bugcheck dos drivers.
//!
//! Todo bugcheck passa pelo handler instalado por [`init`] ([`raise_bug_check`]),
//! que grava KiBugCheckData, executa os callbacks registrados pelos drivers
//! (KeRegisterBugCheckCallback) e publica os dados secundários e o black box.
//! Antes de o handler ser instalado (início do boot) o bugcheck só imprime o
//! código STOP e os quatro parâmetros e para a CPU.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::bugcheck_reason;
use crate::hal::amd64::native_call;
use crate::hal::cpu;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::black_box;
use crate::rtl::SpinLock;

static HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Registros de KeRegisterBugCheckCallback (rotina, componente, contexto).
static BUG_CHECK_CALLBACKS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
/// KiBugCheckData: código e quatro parâmetros do último bugcheck.
static BUG_CHECK_DATA: AtomicU64 = AtomicU64::new(0);

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

/// KiBugCheckData: célula de 5 × 8 bytes alocada no primeiro acesso.
pub fn bug_check_data() -> u64 {
    let current = BUG_CHECK_DATA.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let pointer = guest::alloc_bytes(5 * 8);
    match BUG_CHECK_DATA.compare_exchange(0, pointer, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => pointer,
        Err(existing) => {
            guest::free_bytes(pointer);
            existing
        }
    }
}

/// Parada fatal comum (KeBugCheckEx): grava KiBugCheckData, roda os
/// callbacks registrados, publica os dados secundários e o black box e para
/// a máquina.
pub fn raise_bug_check(code: u32, first: u64, second: u64, third: u64, fourth: u64) -> ! {
    let data = bug_check_data();
    guest::write64(data, code as u64);
    guest::write64(data + 8, first);
    guest::write64(data + 16, second);
    guest::write64(data + 24, third);
    guest::write64(data + 32, fourth);
    debug_print!("");
    debug_print!("*** STOP (KeBugCheckEx): {:#010x} ({:#x}, {:#x}, {:#x}, {:#x})", code, first, second, third, fourth);
    let callbacks = BUG_CHECK_CALLBACKS.lock().clone();
    for record in callbacks {
        let routine = guest::read64(record);
        if routine != 0 {
            native_call::call(routine, &[record, 0]);
        }
    }
    if let Err(error) = bugcheck_reason::publish_secondary_data(0) {
        debug_print!("[bugcheck] dados secundarios: {}", error);
    }
    black_box::publish_crash_records();
    cpu::halt_forever()
}

/// KeRegisterBugCheckCallback: registro real (rotina, componente, contexto);
/// os callbacks rodam no KeBugCheckEx. O estado do registro, quando pedido,
/// fica em 1.
pub fn register_callback(routine: u64, context: u64, component: u64, record_state: u64) -> bool {
    let record = guest::alloc_bytes(0x20);
    guest::write64(record, routine);
    guest::write64(record + 8, component);
    guest::write64(record + 16, context);
    BUG_CHECK_CALLBACKS.lock().push(record);
    if record_state != 0 {
        guest::write32(record_state, 1);
    }
    true
}

/// KeDeregisterBugCheckCallback: FALSE quando o registro não existe.
pub fn deregister_callback(record: u64) -> bool {
    let mut callbacks = BUG_CHECK_CALLBACKS.lock();
    let Some(index) = callbacks.iter().position(|&candidate| candidate == record) else { return false };
    callbacks.remove(index);
    drop(callbacks);
    guest::free_bytes(record);
    true
}

/// Aloca KiBugCheckData e liga o bugcheck interno do kernel a
/// [`raise_bug_check`].
pub fn init() {
    bug_check_data();
    set_handler(raise_bug_check);
}
