//! KeBugCheckEx do kernel.
//!
//! Todo bugcheck passa pelo handler do grupo `ke` dos exports
//! (`ntos::ke::exports`), que grava KiBugCheckData, executa os callbacks
//! registrados pelos drivers e publica os dados secundários e o black box.
//! Antes de o grupo registrar o handler (início do boot) o bugcheck só
//! imprime o código STOP e os quatro parâmetros e para a CPU.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::hal::cpu;

static HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Instalado pelo grupo `ke` dos exports.
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
