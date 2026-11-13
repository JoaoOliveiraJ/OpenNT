//! Regiões críticas e guardadas.
//!
//! Contadores SHORT com sinal em KTHREAD (KernelApcDisable e
//! SpecialApcDisable). O aninhamento acompanha a thread, não a CPU.

use super::{apc, irql};
use crate::ntos::inc::types::{Field, Kthread, NtStruct};
use crate::ntos::ps::process;
use crate::rtl::KernelError;

/// Os dois contadores de desabilitação de APC da KTHREAD.
#[derive(Clone, Copy)]
enum Counter {
    /// KernelApcDisable (regiões críticas).
    Kernel,
    /// SpecialApcDisable (regiões guardadas).
    Special,
}

fn counter(thread: u64, which: Counter) -> &'static Field<i16> {
    // SAFETY: a thread corrente (não nula).
    let thread = unsafe { Kthread::at(thread) };
    match which {
        Counter::Kernel => &thread.kernel_apc_disable,
        Counter::Special => &thread.special_apc_disable,
    }
}

fn read_count(which: Counter, thread: u64) -> i16 {
    if thread == 0 { 0 } else { counter(thread, which).get() }
}

/// Entradas decrementam o SHORT; saídas incrementam. Recusa saída sem
/// entrada e estouro do aninhamento negativo. Só a própria thread altera
/// seus contadores (como no NT).
fn change_count(which: Counter, delta: i16) -> Result<i16, KernelError> {
    let thread = process::get_current_thread();
    if thread == 0 {
        return Err(KernelError::new("APC region requires a current KTHREAD"));
    }
    let previous = read_count(which, thread);
    if (delta > 0 && previous >= 0) || (delta < 0 && previous == i16::MIN) {
        return Err(KernelError::new("unbalanced APC region"));
    }
    let next = previous + delta;
    counter(thread, which).set(next);
    Ok(next)
}

fn leave(which: Counter) -> Result<(), KernelError> {
    if change_count(which, 1)? == 0 {
        apc::deliver_all_queued()?;
    }
    Ok(())
}

/// KeEnterCriticalRegion.
pub fn enter_critical() -> Result<(), KernelError> {
    change_count(Counter::Kernel, -1).map(|_| ())
}

/// KeLeaveCriticalRegion.
pub fn leave_critical() -> Result<(), KernelError> {
    leave(Counter::Kernel)
}

/// KeEnterGuardedRegion.
pub fn enter_guarded() -> Result<(), KernelError> {
    change_count(Counter::Special, -1).map(|_| ())
}

/// KeLeaveGuardedRegion.
pub fn leave_guarded() -> Result<(), KernelError> {
    leave(Counter::Special)
}

/// Algum contador bloqueia a entrega normal de APCs.
pub fn disabled() -> bool {
    let thread = process::get_current_thread();
    read_count(Counter::Kernel, thread) != 0 || read_count(Counter::Special, thread) != 0
}

/// IRQL ou região guardada bloqueiam também as APCs especiais.
pub fn all_disabled() -> bool {
    irql::get_irql() >= 1 || read_count(Counter::Special, process::get_current_thread()) != 0
}

/// Região crítica com saída garantida, mesmo quando o corpo falha.
pub fn with_critical<T>(body: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    enter_critical()?;
    let result = body();
    leave_critical()?;
    result
}

/// Instala a consulta de desabilitação usada pela entrega de APCs.
pub fn init() {
    apc::register_disabled_provider(|special| if special { all_disabled() } else { disabled() });
}
