//! Spin lock de cancelamento compartilhado e IoCancelIrp — `system32/ntos/io/cancel.js`.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::ke::irql;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{io_stack_location as stack, irp};

static HELD: AtomicBool = AtomicBool::new(false);

/// IoAcquireCancelSpinLock: eleva a DISPATCH_LEVEL e devolve o IRQL anterior.
pub fn acquire() -> Result<u8, KernelError> {
    if HELD.load(Ordering::Acquire) {
        return Err(KernelError::new("Recursive acquisition of the cancel spin lock"));
    }
    let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
    HELD.store(true, Ordering::Release);
    Ok(previous)
}

/// IoReleaseCancelSpinLock.
pub fn release(previous: u8) -> Result<(), KernelError> {
    if !HELD.load(Ordering::Acquire) {
        return Err(KernelError::new("Cancel spin lock is not held"));
    }
    HELD.store(false, Ordering::Release);
    irql::lower_irql(previous as u64);
    Ok(())
}

pub fn is_held() -> bool {
    HELD.load(Ordering::Acquire)
}

/// IoCancelIrp: marca Cancel e, havendo rotina, a entrega com o lock retido;
/// a rotina do driver chama IoReleaseCancelSpinLock(Irp->CancelIrql) antes
/// de completar o IRP. Devolve 1 quando uma rotina foi chamada.
pub fn irp(pointer: u64) -> Result<u8, KernelError> {
    let previous = acquire()?;
    guest::write8(pointer + irp::CANCEL, 1);
    let routine = guest::read64(pointer + irp::CANCEL_ROUTINE);
    if routine == 0 {
        release(previous)?;
        return Ok(0);
    }
    let location = guest::read64(pointer + irp::CURRENT_STACK_LOCATION);
    let device = guest::read64(location + stack::DEVICE_OBJECT);
    guest::write64(pointer + irp::CANCEL_ROUTINE, 0);
    guest::write8(pointer + irp::CANCEL_IRQL, previous);
    native_call::call(routine, &[device, pointer]);
    Ok(1)
}
