//! Regiões críticas e guardadas.
//!
//! Contadores SHORT com sinal em KTHREAD (KernelApcDisable e
//! SpecialApcDisable). O aninhamento acompanha a thread, não a CPU.

use super::{apc, irql};
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

fn read_count(offset: u64, thread: u64) -> i16 {
    if thread == 0 { 0 } else { guest::read16(thread + offset) as i16 }
}

/// Entradas decrementam o SHORT; saídas incrementam. Recusa saída sem
/// entrada e estouro do aninhamento negativo.
fn change_count(offset: u64, delta: i16) -> Result<i16, KernelError> {
    let thread = process::get_current_thread();
    if thread == 0 {
        return Err(KernelError::new("APC region requires a current KTHREAD"));
    }
    let previous = read_count(offset, thread);
    if (delta > 0 && previous >= 0) || (delta < 0 && previous == i16::MIN) {
        return Err(KernelError::new("unbalanced APC region"));
    }
    let next = previous + delta;
    guest::write16(thread + offset, next as u16);
    Ok(next)
}

fn leave(offset: u64) -> Result<(), KernelError> {
    if change_count(offset, 1)? == 0 {
        apc::deliver_all_queued()?;
    }
    Ok(())
}

/// KeEnterCriticalRegion.
pub fn enter_critical() -> Result<(), KernelError> {
    change_count(kthread::KERNEL_APC_DISABLE, -1).map(|_| ())
}

/// KeLeaveCriticalRegion.
pub fn leave_critical() -> Result<(), KernelError> {
    leave(kthread::KERNEL_APC_DISABLE)
}

/// KeEnterGuardedRegion.
pub fn enter_guarded() -> Result<(), KernelError> {
    change_count(kthread::SPECIAL_APC_DISABLE, -1).map(|_| ())
}

/// KeLeaveGuardedRegion.
pub fn leave_guarded() -> Result<(), KernelError> {
    leave(kthread::SPECIAL_APC_DISABLE)
}

/// Algum contador bloqueia a entrega normal de APCs.
pub fn disabled() -> bool {
    let thread = process::get_current_thread();
    read_count(kthread::KERNEL_APC_DISABLE, thread) != 0 || read_count(kthread::SPECIAL_APC_DISABLE, thread) != 0
}

/// IRQL ou região guardada bloqueiam também as APCs especiais.
pub fn all_disabled() -> bool {
    irql::get_irql() >= 1 || read_count(kthread::SPECIAL_APC_DISABLE, process::get_current_thread()) != 0
}

/// Região crítica com saída garantida (o try/finally do original).
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
